"""Stored content on Postgres (M5-03): the writer's batch insert, the audit read and the class C
deletion path, over ``stored_content`` (047).

* :class:`PostgresStoredContent` takes the **service's** pool (048: SELECT and INSERT only) and
  the operator pool for an operator scope. A batch is written one tenant at a time, each in its
  own transaction with ``app.tenant_id`` made from the row's own verified tenant (the same
  ``record_connection`` as the decision records, with its leak check); a read goes through
  :func:`~guardrail_engine.store.adapters.postgres.tenant_connection` and **also** filters
  ``tenant_id = $1``, because the operator's policy would otherwise show every tenant, and never
  returns a row whose own ``retain_until`` has passed.
* :class:`PostgresClassCStore` takes the **retention role's** pool (049: EXECUTE on
  ``retention_delete_class_c``, SELECT on ``stored_content.tenant_id`` through its own policy; it
  can read no content and delete nothing directly).
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from typing import Any

from guardrail_engine.audit.adapters.postgres import record_connection
from guardrail_engine.content.model import (
    SOURCE_ROW,
    ClassCReceipt,
    ContentReadEvent,
    StoredContent,
)
from guardrail_engine.content.store import MAX_READ, check_class_c_bounds
from guardrail_engine.retention.store import RetentionError
from guardrail_engine.store.adapters.postgres import tenant_connection
from guardrail_engine.tenant_scope import TenantScope

_INVALID_PARAMETER = "22023"

_INSERT = (
    "INSERT INTO stored_content (tenant_id, request_id, guard_point, ts, retain_until, content, "
    "truncated, content_sha256, bundle_version) "
    "SELECT $1, req, gp, ts, ru, c, tr, sha, ver "
    "FROM unnest($2::text[], $3::text[], $4::timestamptz[], $5::timestamptz[], $6::text[], "
    "$7::boolean[], $8::text[], $9::bigint[]) AS u(req, gp, ts, ru, c, tr, sha, ver)"
)


class PostgresStoredContent:
    def __init__(self, pool: Any, operator_pool: Any | None = None) -> None:
        self._pool = pool
        self._operator_pool = operator_pool

    async def append_many(self, items: Sequence[StoredContent]) -> None:
        """One transaction per tenant. A failure part-way leaves earlier tenants' rows written,
        so a caller that retries hands over **one tenant's rows at a time** (the writer does)."""
        groups: dict[str, list[StoredContent]] = {}
        for item in items:
            groups.setdefault(item.tenant_id, []).append(item)
        for tenant_id, group in groups.items():
            async with record_connection(self._pool, tenant_id) as conn:
                await conn.execute(
                    _INSERT,
                    tenant_id,
                    [r.request_id for r in group],
                    [r.guard_point for r in group],
                    [r.ts for r in group],
                    [r.retain_until for r in group],
                    [r.content for r in group],
                    [r.truncated for r in group],
                    [r.content_sha256 for r in group],
                    [r.bundle_version for r in group],
                )

    async def record_read(self, event: ContentReadEvent) -> None:
        """Append the class A event of a read (047, ``stored_content_audit``), under the
        event's own verified tenant."""
        async with record_connection(self._pool, event.tenant_id) as conn:
            await conn.execute(
                "INSERT INTO stored_content_audit (tenant_id, at, actor, request_id, guard_point, "
                "items, cross_tenant, operator) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
                event.tenant_id, event.at, event.actor, event.request_id, event.guard_point,
                event.items, event.cross_tenant, event.operator,
            )  # fmt: skip

    async def get(
        self, scope: TenantScope, request_id: str, guard_point: str | None
    ) -> list[StoredContent]:
        async with tenant_connection(self._pool, scope, self._operator_pool) as conn:
            rows = await conn.fetch(
                "SELECT tenant_id, request_id, guard_point, ts, retain_until, content, truncated, "
                "content_sha256, bundle_version FROM stored_content "
                "WHERE tenant_id = $1 AND request_id = $2 "
                "AND ($3::text IS NULL OR guard_point = $3) AND retain_until > clock_timestamp() "
                "ORDER BY ts DESC, seq DESC LIMIT $4",
                scope.tenant_id,
                request_id,
                guard_point,
                MAX_READ,
            )
        return [StoredContent(**dict(r)) for r in rows]


class PostgresClassCStore:
    def __init__(self, pool: Any) -> None:
        self._pool = pool

    async def class_c_tenants(self) -> list[str]:
        rows = await self._pool.fetch(
            "SELECT DISTINCT tenant_id FROM stored_content ORDER BY tenant_id"
        )
        return [r["tenant_id"] for r in rows]

    async def delete_class_c_batch(
        self, *, run_id: str, tenant_id: str, now: datetime, limit: int, batch: int
    ) -> int:
        check_class_c_bounds(limit=limit)  # the same refusal as the in-memory store
        try:
            n = await self._pool.fetchval(
                "SELECT retention_delete_class_c($1, $2, $3, $4, $5)",
                run_id, tenant_id, now, limit, batch,
            )  # fmt: skip
        except Exception as exc:
            if getattr(exc, "sqlstate", None) == _INVALID_PARAMETER:
                raise RetentionError("the database refused the deletion's bounds") from None
            raise
        return int(n)

    async def receipts(self, run_id: str | None = None) -> list[ClassCReceipt]:
        rows = await self._pool.fetch(
            "SELECT run_id, at, tenant_id, retention_class, cutoff, deleted_count, batch, "
            "retention_days, source FROM retention_receipts "
            "WHERE retention_class = 'C' AND ($1::text IS NULL OR run_id = $1) ORDER BY id",
            run_id,
        )
        return [ClassCReceipt(**dict(r)) for r in rows if r["source"] == SOURCE_ROW]
