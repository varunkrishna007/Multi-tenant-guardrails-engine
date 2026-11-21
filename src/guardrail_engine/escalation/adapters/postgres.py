"""Postgres for the escalation queue (M4-05): migrations 034 to 037.

Two classes over two pools, because they connect as two different roles:

* :class:`PostgresEscalationStore` takes the **service's** pool (``035``: SELECT and INSERT on
  ``escalation_items`` and ``escalation_audit``, and UPDATE on the resolution and label columns of
  the items only). Every call runs in a transaction with ``app.tenant_id`` set from the
  :class:`~guardrail_engine.tenant_scope.TenantScope` (forced row-level security, 034); an
  operator scope uses the operator pool. It has no delete.
* :class:`PostgresClassDStore` takes the **retention role's** pool (``037``: EXECUTE on
  ``retention_delete_class_d``, SELECT on ``escalation_items.tenant_id`` through its own policy,
  and read of the receipts, ``030``). The function runs as the table owner, deletes the batch and
  appends the class D receipt in one transaction.

Neither imports the driver itself: each is handed an asyncpg pool by the caller.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from guardrail_engine.escalation.model import (
    STATUS_OPEN,
    STATUS_RESOLVED,
    AlreadyResolvedError,
    EscalationAuditEvent,
    EscalationItem,
    EscalationNotFoundError,
    ItemFilter,
    Resolution,
    RuleRef,
)
from guardrail_engine.escalation.store import (
    ClassDBatch,
    ClassDReceipt,
    EscalationStore,
    check_class_d_bounds,
)
from guardrail_engine.retention.store import RetentionError
from guardrail_engine.store.adapters.postgres import tenant_connection
from guardrail_engine.store.port import ScopeMismatchError
from guardrail_engine.tenant_scope import TenantScope

_INVALID_PARAMETER = "22023"  # invalid_parameter_value, raised by the function's own bounds

_COLUMNS = (
    "seq, tenant_id, id, request_id, guard_point, created_at, target, reason, bundle_version, "
    "rules, content_sha256, store_content, retention_mode, content, content_truncated, "
    "triggered_by, status, "
    "decision, resolution_reason, resolved_by, resolved_at, label_set_id, label_mode"
)


def _item(row: Any) -> EscalationItem:
    return EscalationItem(
        id=row["id"],
        tenant_id=row["tenant_id"],
        request_id=row["request_id"],
        guard_point=row["guard_point"],
        created_at=row["created_at"],
        target=row["target"],
        reason=row["reason"],
        bundle_version=row["bundle_version"],
        rules=tuple(RuleRef(**r) for r in json.loads(row["rules"])),
        content_sha256=row["content_sha256"],
        store_content=row["store_content"],
        retention_mode=row["retention_mode"],
        content=row["content"],
        content_truncated=row["content_truncated"],
        triggered_by=row["triggered_by"],
        seq=row["seq"],
        status=row["status"],
        decision=row["decision"],
        resolution_reason=row["resolution_reason"],
        resolved_by=row["resolved_by"],
        resolved_at=row["resolved_at"],
        label_set_id=row["label_set_id"],
        label_mode=row["label_mode"],
    )


def _rules_json(item: EscalationItem) -> str:
    return json.dumps(
        [{"key": r.key, "action": r.action, "mode": r.mode, "layer": r.layer} for r in item.rules]
    )


async def _audit(conn: Any, event: EscalationAuditEvent) -> None:
    await conn.execute(
        "INSERT INTO escalation_audit (tenant_id, at, item_id, action, actor, decision, "
        "reason_sha256, label_set_id, label_mode, cross_tenant, operator) "
        "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
        event.tenant_id, event.at, event.item_id, event.action, event.actor, event.decision,
        event.reason_sha256, event.label_set_id, event.label_mode, event.cross_tenant,
        event.operator,
    )  # fmt: skip


class PostgresEscalationStore:
    def __init__(self, pool: Any, operator_pool: Any = None) -> None:
        self._pool = pool
        self._operator_pool = operator_pool

    def scoped(self, scope: TenantScope) -> EscalationStore:
        if not isinstance(scope, TenantScope):
            raise TypeError("scoped() takes a TenantScope")
        return _ScopedPostgresEscalations(self._pool, scope, self._operator_pool)


class _ScopedPostgresEscalations:
    def __init__(self, pool: Any, scope: TenantScope, operator_pool: Any) -> None:
        self._pool = pool
        self._scope = scope
        self._operator_pool = operator_pool

    def _check(self, tenant_id: str) -> None:
        if tenant_id != self._scope.tenant_id:
            raise ScopeMismatchError()

    def _conn(self) -> Any:
        return tenant_connection(self._pool, self._scope, self._operator_pool)

    async def insert(self, item: EscalationItem) -> bool:
        self._check(item.tenant_id)
        async with self._conn() as conn:
            row = await conn.fetchrow(
                "INSERT INTO escalation_items (tenant_id, id, request_id, guard_point, created_at, "
                "target, reason, bundle_version, rules, content_sha256, store_content, content, "
                "content_truncated, triggered_by, retention_mode) "
                "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb, $10, $11, $12, $13, $14, $15) "
                "ON CONFLICT (tenant_id, id) DO NOTHING RETURNING seq",
                item.tenant_id, item.id, item.request_id, item.guard_point, item.created_at,
                item.target, item.reason, item.bundle_version, _rules_json(item),
                item.content_sha256, item.store_content, item.content, item.content_truncated,
                item.triggered_by, item.retention_mode,
            )  # fmt: skip
        return row is not None

    async def get(self, tenant_id: str, item_id: str) -> EscalationItem | None:
        self._check(tenant_id)
        async with self._conn() as conn:
            row = await conn.fetchrow(
                f"SELECT {_COLUMNS} FROM escalation_items WHERE tenant_id = $1 AND id = $2",
                tenant_id,
                item_id,
            )
        return None if row is None else _item(row)

    async def same_check_count(self, tenant_id: str, request_id: str, guard_point: str) -> int:
        self._check(tenant_id)
        async with self._conn() as conn:
            n = await conn.fetchval(
                "SELECT count(*) FROM escalation_items "
                "WHERE tenant_id = $1 AND request_id = $2 AND guard_point = $3",
                tenant_id,
                request_id,
                guard_point,
            )
        return int(n)

    async def list(
        self, tenant_id: str, filt: ItemFilter, *, after: int | None, limit: int
    ) -> list[EscalationItem]:
        self._check(tenant_id)
        rule = None if filt.rule is None else json.dumps([{"key": filt.rule}])
        async with self._conn() as conn:
            rows = await conn.fetch(
                f"SELECT {_COLUMNS} FROM escalation_items WHERE tenant_id = $1 "
                "AND ($2::bigint IS NULL OR seq > $2) "
                "AND ($3::text IS NULL OR status = $3) "
                "AND ($4::text IS NULL OR guard_point = $4) "
                "AND ($5::jsonb IS NULL OR rules @> $5::jsonb) "
                "AND ($6::timestamptz IS NULL OR created_at >= $6) "
                "AND ($7::timestamptz IS NULL OR created_at < $7) "
                "ORDER BY seq LIMIT $8",
                tenant_id, after, filt.status, filt.guard_point, rule, filt.since, filt.until,
                limit,
            )  # fmt: skip
        return [_item(r) for r in rows]

    async def resolve(
        self, tenant_id: str, item_id: str, resolution: Resolution, event: EscalationAuditEvent
    ) -> EscalationItem:
        self._check(tenant_id)
        if event.tenant_id != tenant_id or event.item_id != item_id:
            raise ScopeMismatchError()
        async with self._conn() as conn:
            row = await conn.fetchrow(
                "UPDATE escalation_items SET status = $3, decision = $4, resolution_reason = $5, "
                "resolved_by = $6, resolved_at = $7 "
                "WHERE tenant_id = $1 AND id = $2 AND status = $8 "
                f"RETURNING {_COLUMNS}",
                tenant_id, item_id, STATUS_RESOLVED, resolution.decision, resolution.reason,
                resolution.actor, resolution.at, STATUS_OPEN,
            )  # fmt: skip
            if row is None:
                exists = await conn.fetchval(
                    "SELECT 1 FROM escalation_items WHERE tenant_id = $1 AND id = $2",
                    tenant_id,
                    item_id,
                )
                raise AlreadyResolvedError() if exists else EscalationNotFoundError()
            await _audit(conn, event)
        return _item(row)

    async def attach_label(
        self,
        tenant_id: str,
        item_id: str,
        label_set_id: str,
        label_mode: str,
        event: EscalationAuditEvent,
    ) -> EscalationItem:
        self._check(tenant_id)
        if event.tenant_id != tenant_id or event.item_id != item_id:
            raise ScopeMismatchError()
        async with self._conn() as conn:
            row = await conn.fetchrow(
                "UPDATE escalation_items SET label_set_id = $3, label_mode = $4 "
                "WHERE tenant_id = $1 AND id = $2 AND status = $5 AND label_set_id IS NULL "
                f"RETURNING {_COLUMNS}",
                tenant_id, item_id, label_set_id, label_mode, STATUS_RESOLVED,
            )  # fmt: skip
            if row is not None:
                await _audit(conn, event)
                return _item(row)
            current = await conn.fetchrow(
                f"SELECT {_COLUMNS} FROM escalation_items WHERE tenant_id = $1 AND id = $2",
                tenant_id,
                item_id,
            )
        if current is None:
            raise EscalationNotFoundError()
        if current["status"] != STATUS_RESOLVED:
            raise AlreadyResolvedError()  # not resolved: a label can't be attached yet
        return _item(current)

    async def audit_events(self, tenant_id: str) -> list[EscalationAuditEvent]:
        self._check(tenant_id)
        async with self._conn() as conn:
            rows = await conn.fetch(
                "SELECT at, tenant_id, item_id, action, actor, decision, reason_sha256, "
                "label_set_id, label_mode, cross_tenant, operator FROM escalation_audit "
                "WHERE tenant_id = $1 ORDER BY id",
                tenant_id,
            )
        return [EscalationAuditEvent(**dict(r)) for r in rows]


class PostgresClassDStore:
    def __init__(self, pool: Any) -> None:
        self._pool = pool

    async def class_d_tenants(self) -> list[str]:
        rows = await self._pool.fetch(
            "SELECT DISTINCT tenant_id FROM escalation_items ORDER BY tenant_id"
        )
        return [r["tenant_id"] for r in rows]

    async def delete_class_d_batch(
        self,
        *,
        run_id: str,
        tenant_id: str,
        now: datetime,
        mode: str,
        days: int,
        source: str,
        limit: int,
        batch: int,
    ) -> ClassDBatch:
        check_class_d_bounds(mode=mode, days=days, source=source, limit=limit)  # same refusals
        try:
            row = await self._pool.fetchrow(
                "SELECT deleted, expired FROM retention_delete_class_d($1, $2, $3, $4, $5, $6, "
                "$7, $8)",
                run_id, tenant_id, now, mode, days, source, limit, batch,
            )  # fmt: skip
        except Exception as exc:
            if getattr(exc, "sqlstate", None) == _INVALID_PARAMETER:
                raise RetentionError("the database refused the deletion's bounds") from None
            raise
        return ClassDBatch(int(row["deleted"]), int(row["expired"]))

    async def receipts(self, run_id: str | None = None) -> list[ClassDReceipt]:
        rows = await self._pool.fetch(
            "SELECT run_id, at, tenant_id, retention_class, cutoff, deleted_count, batch, "
            "retention_days, source, expired_unresolved FROM retention_receipts "
            "WHERE retention_class = 'D' AND ($1::text IS NULL OR run_id = $1) ORDER BY id",
            run_id,
        )
        return [
            ClassDReceipt(
                run_id=r["run_id"],
                at=r["at"],
                tenant_id=r["tenant_id"],
                retention_class=r["retention_class"],
                cutoff=r["cutoff"],
                deleted_count=r["deleted_count"],
                batch=r["batch"],
                retention_days=r["retention_days"],
                source=r["source"],
                expired_unresolved=r["expired_unresolved"],
            )
            for r in rows
        ]
