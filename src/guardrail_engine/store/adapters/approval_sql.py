"""The SQL steps of two-person approval (M5-02, 040) that run on a connection the caller already
holds, inside its transaction and, for a write, under the tenant's lifecycle advisory lock.

Kept apart from :mod:`guardrail_engine.store.adapters.postgres_approvals` (the approval store)
because the lifecycle store, in ``postgres.py``, consumes an approval in the publish's own
transaction, and the store imports the connection helper from ``postgres.py``: this module
imports neither, so there is no cycle.
"""

from __future__ import annotations

from typing import Any

from guardrail_engine.admin.approvals import (
    Approval,
    ApprovalEvent,
    ApprovalNotFoundError,
    ApprovalUse,
    ApprovalUsedError,
    check_usable,
)

LIFECYCLE_LOCK_SQL = "SELECT pg_advisory_xact_lock(hashtext($1))"
"""The same lock every lifecycle write takes (``"lifecycle:" + tenant_id``)."""

APPROVAL_COLUMNS = (
    "id, tenant_id, action, draft_hash, version, requested_by, requested_at, expires_at, status, "
    "approved_by, approved_at, consumed_by, consumed_at, closed_at, close_reason"
)
EVENT_COLUMNS = (
    "tenant_id, at, approval_id, action, actor, draft_hash, version, detail, cross_tenant, operator"
)


def approval_from(row: Any) -> Approval:
    return Approval(
        id=row["id"], tenant_id=row["tenant_id"], action=row["action"],
        draft_hash=row["draft_hash"], version=row["version"], requested_by=row["requested_by"],
        requested_at=row["requested_at"], expires_at=row["expires_at"], status=row["status"],
        approved_by=row["approved_by"], approved_at=row["approved_at"],
        consumed_by=row["consumed_by"], consumed_at=row["consumed_at"],
        closed_at=row["closed_at"], close_reason=row["close_reason"],
    )  # fmt: skip


def event_from(row: Any) -> ApprovalEvent:
    return ApprovalEvent(
        at=row["at"], actor=row["actor"], tenant_id=row["tenant_id"], action=row["action"],
        approval_id=row["approval_id"], draft_hash=row["draft_hash"], version=row["version"],
        detail=row["detail"], cross_tenant=row["cross_tenant"], operator=row["operator"],
    )  # fmt: skip


async def append_event(conn: Any, event: ApprovalEvent) -> None:
    await conn.execute(
        f"INSERT INTO tenant_approval_audit ({EVENT_COLUMNS}) "
        "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
        event.tenant_id, event.at, event.approval_id, event.action, event.actor,
        event.draft_hash, event.version, event.detail, event.cross_tenant, event.operator,
    )  # fmt: skip


async def lock_and_get(conn: Any, tenant_id: str, approval_id: str) -> Approval:
    """Take the tenant's lifecycle lock, then read the approval's row ``FOR UPDATE``."""
    await conn.execute(LIFECYCLE_LOCK_SQL, "lifecycle:" + tenant_id)
    row = await conn.fetchrow(
        f"SELECT {APPROVAL_COLUMNS} FROM tenant_approvals WHERE tenant_id = $1 AND id = $2 "
        "FOR UPDATE",
        tenant_id, approval_id,
    )  # fmt: skip
    if row is None:
        raise ApprovalNotFoundError()
    return approval_from(row)


async def consume(conn: Any, tenant_id: str, use: ApprovalUse) -> None:
    """Spend the approval for ``use``: read its row ``FOR UPDATE`` (the caller holds the lifecycle
    lock), check it is approved, in time, unused and for exactly what ``use`` names, then move
    it ``approved -> consumed`` and append the ``consumed`` event. Raises the approval's own error
    otherwise, which rolls back the caller's whole transaction: a publish that fails after this
    does not spend the approval."""
    row = await conn.fetchrow(
        f"SELECT {APPROVAL_COLUMNS} FROM tenant_approvals WHERE tenant_id = $1 AND id = $2 "
        "FOR UPDATE",
        tenant_id, use.approval_id,
    )  # fmt: skip
    if row is None:
        raise ApprovalNotFoundError()
    approval = approval_from(row)
    check_usable(approval, use)
    status = await conn.execute(
        "UPDATE tenant_approvals SET status = 'consumed', consumed_by = $3, consumed_at = $4 "
        "WHERE tenant_id = $1 AND id = $2 AND status = 'approved'",
        tenant_id, use.approval_id, use.actor, use.at,
    )  # fmt: skip
    if status != "UPDATE 1":
        raise ApprovalUsedError()
    await append_event(
        conn,
        ApprovalEvent(
            use.at, use.actor, tenant_id, "consumed", approval.id, approval.draft_hash,
            use.for_version if use.for_version is not None else approval.version,
            f"used by {use.action}", use.cross_tenant, use.operator,
        ),
    )  # fmt: skip
