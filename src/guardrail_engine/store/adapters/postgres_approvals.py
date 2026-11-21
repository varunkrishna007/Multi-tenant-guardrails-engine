"""Two-person approval on Postgres (M5-02; schema ``040_approvals.sql``).

``scoped(scope)`` returns a view whose every operation runs in one transaction with
``app.tenant_id`` set from the scope (forced row-level security), like the lifecycle store. Every
write that changes a status takes the tenant's lifecycle advisory lock, so an approval is never
approved, cancelled or expired while a publish is consuming it, and appends its class A event in
the same transaction. An approval is **consumed** by the lifecycle store, in the publish's own
transaction (:func:`guardrail_engine.store.adapters.approval_sql.consume`), not here.
"""

from __future__ import annotations

import contextlib
from datetime import datetime
from typing import Any

from guardrail_engine.admin.approvals import (
    DEFAULT_LIST_LIMIT,
    Approval,
    ApprovalEvent,
    ApprovalEventFactory,
    ApprovalNotFoundError,
    ApprovalPosition,
    ApprovalStore,
    SelfApprovalError,
    check_approvable,
)
from guardrail_engine.store.adapters.approval_sql import (
    APPROVAL_COLUMNS,
    EVENT_COLUMNS,
    LIFECYCLE_LOCK_SQL,
    append_event,
    approval_from,
    event_from,
    lock_and_get,
)
from guardrail_engine.store.adapters.postgres import tenant_connection
from guardrail_engine.store.port import ScopeMismatchError
from guardrail_engine.tenant_scope import TenantScope


class PostgresApprovalStore:
    def __init__(self, pool: Any, operator_pool: Any | None = None) -> None:
        self._pool = pool
        self._operator_pool = operator_pool

    def scoped(self, scope: TenantScope) -> ApprovalStore:
        if not isinstance(scope, TenantScope):
            raise TypeError("scoped() takes a TenantScope")
        return _ScopedPostgresApprovals(self._pool, scope, self._operator_pool)


class _ScopedPostgresApprovals:
    def __init__(self, pool: Any, scope: TenantScope, operator_pool: Any | None) -> None:
        self._pool = pool
        self._operator_pool = operator_pool
        self._scope = scope

    def _check(self, tenant_id: str, event: ApprovalEvent | None = None) -> None:
        if tenant_id != self._scope.tenant_id or (
            event is not None and event.tenant_id != tenant_id
        ):
            raise ScopeMismatchError()

    def _conn(self) -> contextlib.AbstractAsyncContextManager[Any]:
        return tenant_connection(self._pool, self._scope, self._operator_pool)

    async def get(self, tenant_id: str, approval_id: str) -> Approval | None:
        self._check(tenant_id)
        async with self._conn() as conn:
            row = await conn.fetchrow(
                f"SELECT {APPROVAL_COLUMNS} FROM tenant_approvals "
                "WHERE tenant_id = $1 AND id = $2",
                tenant_id, approval_id,
            )  # fmt: skip
        return None if row is None else approval_from(row)

    async def request(self, tenant_id: str, approval: Approval, event: ApprovalEvent) -> None:
        self._check(tenant_id, event)
        if approval.tenant_id != tenant_id:
            raise ScopeMismatchError()
        async with self._conn() as conn:
            await conn.execute(
                "INSERT INTO tenant_approvals (tenant_id, id, action, draft_hash, version, "
                "requested_by, requested_at, expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
                tenant_id, approval.id, approval.action, approval.draft_hash, approval.version,
                approval.requested_by, approval.requested_at, approval.expires_at,
            )  # fmt: skip
            await append_event(conn, event)

    async def approve(
        self,
        tenant_id: str,
        approval_id: str,
        *,
        approver: str,
        at: datetime,
        expires_at: datetime,
        event: ApprovalEvent,
    ) -> Approval:
        self._check(tenant_id, event)
        async with self._conn() as conn:
            row = await lock_and_get(conn, tenant_id, approval_id)
            check_approvable(row, at)
            if approver == row.requested_by:
                raise SelfApprovalError()
            updated = await conn.fetchrow(
                "UPDATE tenant_approvals SET status = 'approved', approved_by = $3, "
                "approved_at = $4, expires_at = $5 WHERE tenant_id = $1 AND id = $2 "
                f"AND status = 'pending' RETURNING {APPROVAL_COLUMNS}",
                tenant_id, approval_id, approver, at, expires_at,
            )  # fmt: skip
            if updated is None:
                raise ApprovalNotFoundError()
            await append_event(conn, event)
        return approval_from(updated)

    async def expire(
        self, tenant_id: str, approval_id: str, *, at: datetime, event: ApprovalEvent
    ) -> bool:
        self._check(tenant_id, event)
        async with self._conn() as conn:
            try:
                row = await lock_and_get(conn, tenant_id, approval_id)
            except ApprovalNotFoundError:
                return False
            if row.status not in ("pending", "approved") or at < row.expires_at:
                return False
            await conn.execute(
                "UPDATE tenant_approvals SET status = 'expired', closed_at = $3, "
                "close_reason = 'expired' WHERE tenant_id = $1 AND id = $2",
                tenant_id, approval_id, at,
            )  # fmt: skip
            await append_event(conn, event)
        return True

    async def cancel(
        self, tenant_id: str, approval_id: str, *, at: datetime, reason: str, event: ApprovalEvent
    ) -> bool:
        self._check(tenant_id, event)
        async with self._conn() as conn:
            try:
                row = await lock_and_get(conn, tenant_id, approval_id)
            except ApprovalNotFoundError:
                return False
            if row.status not in ("pending", "approved"):
                return False
            await conn.execute(
                "UPDATE tenant_approvals SET status = 'cancelled', closed_at = $3, "
                "close_reason = $4 WHERE tenant_id = $1 AND id = $2",
                tenant_id, approval_id, at, reason,
            )  # fmt: skip
            await append_event(conn, event)
        return True

    async def cancel_publish_approvals(
        self,
        tenant_id: str,
        *,
        keep_draft_hash: str,
        at: datetime,
        reason: str,
        event_for: ApprovalEventFactory,
    ) -> list[Approval]:
        self._check(tenant_id)
        async with self._conn() as conn:
            await conn.execute(LIFECYCLE_LOCK_SQL, "lifecycle:" + tenant_id)
            rows: list[Any] = await conn.fetch(
                "UPDATE tenant_approvals SET status = 'cancelled', closed_at = $3, "
                "close_reason = $4 WHERE tenant_id = $1 AND action = 'publish' "
                "AND status IN ('pending', 'approved') AND draft_hash <> $2 "
                f"RETURNING {APPROVAL_COLUMNS}",
                tenant_id, keep_draft_hash, at, reason,
            )  # fmt: skip
            cancelled = [approval_from(r) for r in rows]
            for approval in cancelled:
                await append_event(conn, event_for(approval))
        return cancelled

    async def record(self, tenant_id: str, event: ApprovalEvent) -> None:
        self._check(tenant_id, event)
        async with self._conn() as conn:
            await append_event(conn, event)

    async def events(self, tenant_id: str) -> list[ApprovalEvent]:
        self._check(tenant_id)
        async with self._conn() as conn:
            rows = await conn.fetch(
                f"SELECT {EVENT_COLUMNS} FROM tenant_approval_audit WHERE tenant_id = $1 "
                "ORDER BY id",
                tenant_id,
            )
        return [event_from(r) for r in rows]

    async def list_approvals(
        self,
        tenant_id: str,
        *,
        status: str | None = None,
        after: ApprovalPosition | None = None,
        limit: int = DEFAULT_LIST_LIMIT,
    ) -> list[Approval]:
        self._check(tenant_id)
        async with self._conn() as conn:
            rows = await conn.fetch(
                f"SELECT {APPROVAL_COLUMNS} FROM tenant_approvals WHERE tenant_id = $1 "
                "AND ($2::text IS NULL OR status = $2) "
                "AND ($3::timestamptz IS NULL OR (requested_at, id) < ($3, $4)) "
                "ORDER BY requested_at DESC, id DESC LIMIT $5",
                tenant_id, status,
                None if after is None else after.requested_at,
                None if after is None else after.id,
                limit,
            )  # fmt: skip
        return [approval_from(r) for r in rows]
