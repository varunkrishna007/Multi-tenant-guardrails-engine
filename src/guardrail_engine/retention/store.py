"""The stores behind the retention engine (M4-09): the class B decision-record store, the class A
deletion receipts, and the narrow deletion port the retention job uses.

Two ports, deliberately separate so that ordinary code can't delete:

* :class:`DecisionRecordStore` is what the service holds: ``append`` and reads. No delete.
* :class:`RetentionStore` is what the retention job holds: list the tenants to sweep, delete one
  bounded batch (writing its receipt in the same step), read the receipts.

:class:`InMemoryDecisionStore` implements the first and hands out the second as ``.retention``,
over the same data. The Postgres pair is in ``retention/adapters/postgres.py``; the database
refuses what these ports don't offer (insert-only records, append-only receipts).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Final, Literal, Protocol

from guardrail_engine.guard.audit import AuditRecord

MIN_RETENTION_DAYS: Final = 90
"""The shortest class B term R3 allows (the standard tier's minimum). A deletion whose cutoff is
newer than ``now - 90 days`` is refused by the store, whatever the caller computed."""
MAX_RETENTION_DAYS: Final = 36_500
"""The longest term the deletion function accepts (100 years); the resolver stays far below."""
MAX_BATCH_SIZE: Final = 100_000
_SOURCE_SHAPE: Final = re.compile(r"[a-z]{1,16}")

Source = Literal["bundle", "default", "clamped", "fallback"]
"""Where a tenant's retention came from: its bundle's ``audit.records_days``; the R3 default for
its packs; a bundle value moved into the R3 bounds; or the longest permitted term, used when the
tenant couldn't be resolved (so nothing is ever deleted early)."""


@dataclass(frozen=True, slots=True)
class RetentionReceipt:
    """A class A deletion receipt: one deletion batch. Tenant, class, cutoff, count and run id;
    never content. A run's receipt for a tenant is the rows sharing its ``run_id``."""

    run_id: str
    at: datetime
    tenant_id: str | None
    retention_class: str
    cutoff: datetime
    deleted_count: int
    batch: int
    retention_days: int
    source: str


class RetentionError(Exception):
    """The store refused a deletion (a bound, or a database error). The message is fixed text."""


class DecisionRecordStore(Protocol):
    """What the service holds for class B: append and read. No delete."""

    async def append(self, record: AuditRecord) -> None: ...

    async def count(self, tenant_id: str | None) -> int: ...


class RetentionStore(Protocol):
    """What the retention job holds: the one deletion path for class B."""

    async def class_b_tenants(self) -> list[str | None]:
        """The tenants that have decision records (None: records with no verified tenant)."""
        ...

    async def delete_class_b_batch(
        self,
        *,
        run_id: str,
        tenant_id: str | None,
        cutoff: datetime,
        now: datetime,
        limit: int,
        retention_days: int,
        source: str,
        batch: int,
    ) -> int:
        """Delete at most ``limit`` of the tenant's records that are older than ``cutoff``
        (``ts < cutoff``) **and** past their own ``retain_until`` (``< now``), skipping any a
        concurrent run holds, and append the receipt in the same step. Returns the count. A
        receipt is written for batch 1 even if nothing was deleted, and for a later batch only
        if it deleted something.

        Raises :class:`RetentionError` for a ``limit`` outside ``1..MAX_BATCH_SIZE`` or a
        ``cutoff`` that isn't exactly ``now - retention_days`` (a term under 90 days is refused
        with it), a ``retention_days`` outside 90..36,500 or a malformed ``source``. The Postgres
        receipt's ``at`` is the database's clock; the in-memory one's is ``now``."""
        ...

    async def receipts(self, run_id: str | None = None) -> list[RetentionReceipt]: ...


def check_batch_bounds(
    *, cutoff: datetime, now: datetime, limit: int, retention_days: int, source: str
) -> None:
    """The bounds the Postgres function enforces too, so both stores refuse the same calls:
    the batch size, a term of 90..36,500 days, a ``source`` of 1..16 lowercase letters, and a
    ``cutoff`` that is exactly ``now`` minus ``retention_days`` (so a receipt's figure can't
    disagree with what was deleted)."""
    if not 1 <= limit <= MAX_BATCH_SIZE:
        raise RetentionError(f"batch size must be 1..{MAX_BATCH_SIZE}")
    if not MIN_RETENTION_DAYS <= retention_days <= MAX_RETENTION_DAYS:
        raise RetentionError(f"retention days must be {MIN_RETENTION_DAYS}..{MAX_RETENTION_DAYS}")
    if _SOURCE_SHAPE.fullmatch(source) is None:
        raise RetentionError("source must be 1..16 lowercase letters")
    if cutoff != now - timedelta(days=retention_days):
        raise RetentionError("cutoff is not the clock minus the retention days")


class InMemoryDecisionStore:
    """Class B records and class A receipts in memory. For tests and local runs."""

    def __init__(self) -> None:
        self._records: list[AuditRecord] = []
        self._receipts: list[RetentionReceipt] = []
        self.retention: RetentionStore = _InMemoryRetention(self)
        """The deletion port. Hand it to the retention job only."""

    async def append(self, record: AuditRecord) -> None:
        self._records.append(record)

    async def count(self, tenant_id: str | None) -> int:
        return sum(1 for r in self._records if r.tenant_id == tenant_id)

    def records(self, tenant_id: str | None) -> list[AuditRecord]:
        return [r for r in self._records if r.tenant_id == tenant_id]

    offboard_tables = ("decision_records",)

    def offboard_tenant(
        self, tenant_id: str, table: str, limit: int, *, count_only: bool = False
    ) -> dict[str, int]:
        """M5-07: delete (or count) a terminated tenant's records (see ``TenantDataHolder``)."""
        mine = [i for i, r in enumerate(self._records) if r.tenant_id == tenant_id]
        if count_only:
            return {table: len(mine)}
        for i in reversed(mine[:limit]):
            del self._records[i]
        return {table: len(mine[:limit])}


class _InMemoryRetention:
    def __init__(self, store: InMemoryDecisionStore) -> None:
        self._store = store

    async def class_b_tenants(self) -> list[str | None]:
        seen: dict[str | None, None] = {}
        for r in self._store._records:
            seen.setdefault(r.tenant_id)
        return sorted(seen, key=lambda t: (t is None, t or ""))

    async def delete_class_b_batch(
        self,
        *,
        run_id: str,
        tenant_id: str | None,
        cutoff: datetime,
        now: datetime,
        limit: int,
        retention_days: int,
        source: str,
        batch: int,
    ) -> int:
        check_batch_bounds(
            cutoff=cutoff, now=now, limit=limit, retention_days=retention_days, source=source
        )
        # No await below: the whole batch is one atomic step on the event loop.
        doomed = [
            i
            for i, r in enumerate(self._store._records)
            if r.tenant_id == tenant_id and r.ts < cutoff and r.retain_until < now
        ][:limit]
        for i in reversed(doomed):
            del self._store._records[i]
        n = len(doomed)
        if n > 0 or batch == 1:
            self._store._receipts.append(
                RetentionReceipt(
                    run_id=run_id,
                    at=now,
                    tenant_id=tenant_id,
                    retention_class="B",
                    cutoff=cutoff,
                    deleted_count=n,
                    batch=batch,
                    retention_days=retention_days,
                    source=source,
                )
            )
        return n

    async def receipts(self, run_id: str | None = None) -> list[RetentionReceipt]:
        return [r for r in self._store._receipts if run_id is None or r.run_id == run_id]
