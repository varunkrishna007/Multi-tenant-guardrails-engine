"""Ports for stored content (M5-03): where the writer puts a check's content, where the audit
read route gets it, and the one deletion path the class C job holds.

``ContentSink.append_many`` takes rows the writer has already stamped with their deletion time.
``ContentReader.get`` is scoped: it returns only the tenant of the
:class:`~guardrail_engine.tenant_scope.TenantScope` it is given (row-level security on Postgres)
and never a row whose own deletion time has passed, even before the job has deleted it.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from typing import Protocol

from guardrail_engine.content.model import (
    MAX_BATCH_SIZE,
    SOURCE_ROW,
    ClassCReceipt,
    ContentReadEvent,
    StoredContent,
)
from guardrail_engine.retention.store import RetentionError
from guardrail_engine.tenant_scope import TenantScope

MAX_READ = 20


class ContentSink(Protocol):
    async def append_many(self, items: Sequence[StoredContent]) -> None: ...


class ContentReader(Protocol):
    async def get(
        self, scope: TenantScope, request_id: str, guard_point: str | None
    ) -> list[StoredContent]:
        """The scope's tenant's unexpired content for ``request_id`` (every guard point, or the
        one named), newest first, at most :data:`MAX_READ`."""
        ...


class ContentReadAudit(Protocol):
    async def record_read(self, event: ContentReadEvent) -> None:
        """Append the class A event of a read. Raises if it can't: a read that can't leave its
        trail is refused."""
        ...


class ClassCStore(Protocol):
    """What the class C job holds: the one deletion path for stored content."""

    async def class_c_tenants(self) -> list[str]:
        """The tenants that have stored content."""
        ...

    async def delete_class_c_batch(
        self, *, run_id: str, tenant_id: str, now: datetime, limit: int, batch: int
    ) -> int:
        """Delete at most ``limit`` of the tenant's rows whose own ``retain_until`` is before
        ``now`` (strictly: a row exactly at the cutoff is kept, and ``now`` is clamped to the
        database's clock), and any row stored more than 90 days before it, and append the class C
        receipt in the same step. A receipt is written for batch 1 even if nothing was deleted,
        and for a later batch only if it deleted something. Raises :class:`RetentionError` for a
        ``limit`` out of bounds."""
        ...

    async def receipts(self, run_id: str | None = None) -> list[ClassCReceipt]: ...


def check_class_c_bounds(*, limit: int) -> None:
    """The bound the Postgres function enforces too, so both stores refuse the same calls."""
    if not 1 <= limit <= MAX_BATCH_SIZE:
        raise RetentionError(f"batch size must be 1..{MAX_BATCH_SIZE}")


class InMemoryStoredContent:
    """Both ports and the deletion path in memory, for tests and an engine without Postgres.
    Isolates by tenant the way row-level security does."""

    def __init__(self, clock: Callable[[], datetime] = lambda: datetime.now(UTC)) -> None:
        self._rows: list[StoredContent] = []
        self._receipts: list[ClassCReceipt] = []
        self._reads: list[ContentReadEvent] = []
        self._clock = clock
        self.retention: ClassCStore = _InMemoryClassC(self)
        """The deletion port. Hand it to the class C job only."""

    async def append_many(self, items: Sequence[StoredContent]) -> None:
        self._rows.extend(items)

    def all(self) -> list[StoredContent]:
        """For tests: every row, whatever its tenant or term."""
        return list(self._rows)

    async def get(
        self, scope: TenantScope, request_id: str, guard_point: str | None
    ) -> list[StoredContent]:
        now = self._clock()
        found = [
            r
            for r in self._rows
            if r.tenant_id == scope.tenant_id
            and r.request_id == request_id
            and (guard_point is None or r.guard_point == guard_point)
            and r.retain_until > now
        ]
        found.sort(key=lambda r: r.ts, reverse=True)
        return found[:MAX_READ]

    async def record_read(self, event: ContentReadEvent) -> None:
        self._reads.append(event)

    def read_events(self, tenant_id: str) -> list[ContentReadEvent]:
        """For tests: the class A read events of a tenant, oldest first."""
        return [e for e in self._reads if e.tenant_id == tenant_id]

    offboard_tables = ("stored_content",)

    def offboard_tenant(
        self, tenant_id: str, table: str, limit: int, *, count_only: bool = False
    ) -> dict[str, int]:
        """M5-07: delete (or count) a terminated tenant's rows (see ``TenantDataHolder``)."""
        mine = [i for i, r in enumerate(self._rows) if r.tenant_id == tenant_id]
        if count_only:
            return {table: len(mine)}
        for i in reversed(mine[:limit]):
            del self._rows[i]
        return {table: len(mine[:limit])}


class _InMemoryClassC:
    def __init__(self, owner: InMemoryStoredContent) -> None:
        self._owner = owner

    async def class_c_tenants(self) -> list[str]:
        return sorted({r.tenant_id for r in self._owner._rows})

    async def delete_class_c_batch(
        self, *, run_id: str, tenant_id: str, now: datetime, limit: int, batch: int
    ) -> int:
        check_class_c_bounds(limit=limit)
        from datetime import timedelta

        cutoff = now
        due = [
            r
            for r in self._owner._rows
            if r.tenant_id == tenant_id
            and (r.retain_until < cutoff or r.ts < cutoff - timedelta(days=90))
        ][:limit]
        for r in due:
            self._owner._rows.remove(r)
        if due or batch == 1:
            self._owner._receipts.append(
                ClassCReceipt(
                    run_id, cutoff, tenant_id, "C", cutoff, len(due), batch, 90, SOURCE_ROW
                )
            )
        return len(due)

    async def receipts(self, run_id: str | None = None) -> list[ClassCReceipt]:
        return [r for r in self._owner._receipts if run_id is None or r.run_id == run_id]
