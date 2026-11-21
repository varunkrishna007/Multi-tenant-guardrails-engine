"""In-memory directory store and event bus: the contract's reference implementation, and the
test double."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import replace
from datetime import UTC, datetime

from guardrail_engine.directory.model import (
    TERMINATION_STATUSES,
    DirectoryAuditEvent,
    TenantChanged,
    TenantExists,
    TenantNotFound,
    TenantRecord,
    VersionConflict,
)


class InMemoryDirectoryStore:
    def __init__(self) -> None:
        self._records: dict[str, TenantRecord] = {}
        self._audit: list[DirectoryAuditEvent] = []
        self.reads = 0
        """``get`` calls so far (for cache tests)."""

    def _project_taken(self, record: TenantRecord) -> bool:
        """One tenant per dedicated project, as the database's partial unique index says:
        terminating and terminated tenants give theirs up."""
        return (
            record.project is not None
            and record.status not in TERMINATION_STATUSES
            and any(
                r.project == record.project
                and r.tenant_id != record.tenant_id
                and r.status not in TERMINATION_STATUSES
                for r in self._records.values()
            )
        )

    async def insert(self, record: TenantRecord, event: DirectoryAuditEvent) -> TenantRecord:
        if (
            record.tenant_id in self._records
            or any(r.slug == record.slug for r in self._records.values())
            or self._project_taken(record)
        ):
            raise TenantExists
        now = datetime.now(UTC)
        stored = replace(record, created_at=now, updated_at=now)
        self._records[stored.tenant_id] = stored
        self._audit.append(event)
        return stored

    async def replace(
        self, record: TenantRecord, expected_version: int, event: DirectoryAuditEvent
    ) -> TenantRecord:
        current = self._records.get(record.tenant_id)
        if current is None:
            raise TenantNotFound
        if current.version != expected_version or record.version != expected_version + 1:
            raise VersionConflict
        if self._project_taken(record) or any(
            r.slug == record.slug and r.tenant_id != record.tenant_id
            for r in self._records.values()
        ):
            raise TenantExists
        stored = replace(record, created_at=current.created_at, updated_at=datetime.now(UTC))
        self._records[stored.tenant_id] = stored
        self._audit.append(event)
        return stored

    async def get(self, tenant_id: str) -> TenantRecord | None:
        self.reads += 1
        return self._records.get(tenant_id)

    async def list(self) -> list[TenantRecord]:
        return sorted(self._records.values(), key=lambda r: r.tenant_id)

    async def audit_events(self, tenant_id: str) -> list[DirectoryAuditEvent]:
        return [e for e in self._audit if e.tenant_id == tenant_id]


class InMemoryEventBus:
    """Subscribers are called in order; one that raises does not stop the others."""

    def __init__(self) -> None:
        self.published: list[TenantChanged] = []
        self._subscribers: list[Callable[[TenantChanged], Awaitable[None] | None]] = []

    def subscribe(self, fn: Callable[[TenantChanged], Awaitable[None] | None]) -> None:
        self._subscribers.append(fn)

    async def publish(self, event: TenantChanged) -> None:
        self.published.append(event)
        for fn in self._subscribers:
            try:
                result = fn(event)
                if result is not None:
                    await result
            except Exception:
                continue
