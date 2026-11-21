"""The offboarding job's one deletion port, and its in-memory implementation (M5-07).

:class:`OffboardingStore` is all the job holds: list the tenants waiting to be offboarded,
delete **one bounded batch of one table** of a tenant (writing its receipt in the same step),
ask whether the tenant is done, read the receipts. The Postgres implementation
(``adapters/postgres.py``) calls SECURITY DEFINER functions that check, in the database, that the
tenant is ``terminated``. The in-memory one applies the same rules over the in-memory stores.

The in-memory stores that hold tenant data each implement :class:`TenantDataHolder`: they name
the tables they own and delete or count a tenant's rows of one. :class:`InMemoryOffboardingStore`
is handed the holders and a directory store, and dispatches a table to whoever owns it.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from decimal import Decimal
from typing import Literal, Protocol

from guardrail_engine.delivery.events import USAGE_ANSWERED, UsageEvent
from guardrail_engine.directory.memory import InMemoryDirectoryStore
from guardrail_engine.offboarding.model import (
    CLASSES,
    CONTENT_RECEIPT,
    DEFAULT_PRICE_PER_MILLION_INPUT_TOKENS_USD,
    DELETION_DEADLINE,
    MAX_BATCH_SIZE,
    OFFBOARD_TABLES,
    RECEIPT_TABLES,
    RESWEEP_DAYS,
    RESWEEP_INTERVAL,
    TABLE_CLASS,
    CompletionReceipt,
    OffboardingRefused,
    OffboardReceipt,
    PendingTenant,
    ResweepDue,
    SweepRecord,
    UsageSummaryRow,
    sum_receipts,
)
from guardrail_engine.tenant_ids import is_valid_tenant_id

CompleteOutcome = Literal["completed", "already_complete", "remaining"]


class TenantDataHolder(Protocol):
    """An in-memory store that holds a tenant's rows (the stand-in for a table)."""

    offboard_tables: tuple[str, ...]
    """The tables (names from ``OFFBOARD_TABLES``) this store holds."""

    def offboard_tenant(
        self, tenant_id: str, table: str, limit: int, *, count_only: bool = False
    ) -> Mapping[str, int]:
        """Delete at most ``limit`` of the tenant's rows of ``table`` (or only count them all
        with ``count_only``) and return the counts: ``{table: n}``, plus
        ``{CONTENT_RECEIPT: k}`` for ``escalation_items``. Synchronous and atomic."""
        ...


class UsageRowHolder(Protocol):
    """An in-memory store of usage rows. Deleting usage needs the rows themselves, to
    summarise them, not only a count: a holder with this method is asked for the rows (it deletes
    at most ``limit`` and returns them) instead of ``offboard_tenant``."""

    def offboard_usage_rows(self, tenant_id: str, limit: int) -> Sequence[UsageEvent]: ...


class OffboardingStore(Protocol):
    async def pending(self) -> list[PendingTenant]:
        """Tenants that are ``terminating`` or ``terminated`` and have no completion receipt,
        oldest first."""
        ...

    async def delete_batch(
        self, *, run_id: str, tenant_id: str, table: str, now: datetime, limit: int, batch: int
    ) -> int:
        """Delete at most ``limit`` of the tenant's rows of ``table``, skipping any a concurrent
        run holds, and append the receipt in the same step (batch 1 always, a later batch only
        if it deleted something; for a tenant that already has its completion receipt, a re-sweep,
        only if it deleted something). Returns the count.

        For ``usage_events`` the same step also appends the billing summary of the rows it
        deleted: per UTC month and usage class, the events, answered calls, input
        tokens and cost at the store's configured price.

        Raises :class:`OffboardingRefused` if the tenant is not ``terminated`` (the check is the
        store's, in Postgres the database's), the table is not a deletable one, or a bound is
        out of range. Nothing is deleted then."""
        ...

    async def complete(self, *, run_id: str, tenant_id: str, now: datetime) -> CompleteOutcome:
        """If none of the tenant's rows remain in any deletable table, write the class A
        "offboarding complete" receipt once and return ``completed``; ``already_complete`` if it
        exists; ``remaining`` if rows are left (or locked by another run). Refused for a tenant
        that is not ``terminated``."""
        ...

    async def resweep_due(self, now: datetime) -> list[ResweepDue]:
        """Completed tenants whose daily re-sweep is due at ``now``: day N is due N days
        after the completion receipt, N = 1 to 7, and the day reported is the latest due. A
        tenant whose day-7 sweep is logged is final and is never listed."""
        ...

    async def log_sweep(
        self, *, run_id: str, tenant_id: str, day: int, deleted: int, now: datetime
    ) -> bool:
        """Record that the tenant's re-sweep for ``day`` ran (found something or not). True if
        recorded, False if that day was already logged. Refused for a tenant without a completion
        receipt or a day not yet due."""
        ...

    async def receipts(
        self, tenant_id: str | None = None, run_id: str | None = None
    ) -> list[OffboardReceipt]: ...

    async def completion(self, tenant_id: str) -> CompletionReceipt | None: ...

    async def usage_summary(self, tenant_id: str) -> list[UsageSummaryRow]:
        """The billing summary rows written when the tenant's usage rows were deleted."""
        ...

    async def sweeps(self, tenant_id: str) -> list[SweepRecord]: ...


def check_bounds(*, tenant_id: str, table: str, limit: int, batch: int) -> None:
    """The bounds the Postgres function enforces too."""
    if not is_valid_tenant_id(tenant_id):
        raise OffboardingRefused("the tenant id is not valid")
    if table not in TABLE_CLASS or table == CONTENT_RECEIPT:
        raise OffboardingRefused("that table is not an offboarding table")
    if not 1 <= limit <= MAX_BATCH_SIZE:
        raise OffboardingRefused(f"batch size must be 1..{MAX_BATCH_SIZE}")
    if batch < 1:
        raise OffboardingRefused("batch must be at least 1")


@dataclass
class InMemoryOffboardingStore:
    """The offboarding port over the in-memory directory and data holders. Single event loop:
    a batch and its receipt are one step with no await, which is the same guarantee as one
    transaction. For tests and local runs."""

    directory: InMemoryDirectoryStore
    holders: Iterable[TenantDataHolder]
    price_per_million_input_tokens_usd: Decimal = field(
        default=DEFAULT_PRICE_PER_MILLION_INPUT_TOKENS_USD
    )
    """The price the usage summary's cost is computed at."""

    def __post_init__(self) -> None:
        self.holders = tuple(self.holders)
        self.price_per_million_input_tokens_usd = Decimal(self.price_per_million_input_tokens_usd)
        if not 0 <= self.price_per_million_input_tokens_usd <= 1_000_000:
            raise ValueError("the price must be 0..1,000,000 USD per million tokens")
        self._receipts: list[OffboardReceipt] = []
        self._completions: dict[str, CompletionReceipt] = {}
        self._usage: list[UsageSummaryRow] = []
        self._sweeps: dict[tuple[str, int], SweepRecord] = {}

    # -- the directory side

    def _times(self, tenant_id: str) -> tuple[datetime, datetime | None]:
        terminating = terminated = None
        record = self.directory._records.get(tenant_id)
        for e in self.directory._audit:
            if e.tenant_id != tenant_id:
                continue
            if e.action == "terminating" and terminating is None:
                terminating = datetime.fromtimestamp(e.at, UTC)
            if e.action == "terminated" and terminated is None:
                terminated = datetime.fromtimestamp(e.at, UTC)
        if terminating is None:
            fallback = record.updated_at if record is not None else None
            terminating = fallback or datetime.now(UTC)
        return terminating, terminated

    async def pending(self) -> list[PendingTenant]:
        out = []
        for r in await self.directory.list():
            if r.status not in ("terminating", "terminated") or r.tenant_id in self._completions:
                continue
            terminating, terminated = self._times(r.tenant_id)
            out.append(PendingTenant(r.tenant_id, r.status, terminating, terminated))
        return sorted(out, key=lambda p: (p.terminating_at, p.tenant_id))

    def _require_terminated(self, tenant_id: str) -> None:
        record = self.directory._records.get(tenant_id)
        if record is None or record.status != "terminated":
            raise OffboardingRefused("the tenant is not terminated")

    # -- deletion

    async def delete_batch(
        self, *, run_id: str, tenant_id: str, table: str, now: datetime, limit: int, batch: int
    ) -> int:
        check_bounds(tenant_id=tenant_id, table=table, limit=limit, batch=batch)
        self._require_terminated(tenant_id)
        resweep = tenant_id in self._completions
        counts: dict[str, int] = {}
        remaining = limit
        usage_rows: list[UsageEvent] = []
        for holder in self.holders:
            if table not in holder.offboard_tables or remaining < 1:
                continue
            if table == "usage_events" and hasattr(holder, "offboard_usage_rows"):
                rows = holder.offboard_usage_rows(tenant_id, remaining)
                usage_rows += rows
                got: Mapping[str, int] = {table: len(rows)}
            else:
                got = holder.offboard_tenant(tenant_id, table, remaining)
            for name, n in got.items():
                counts[name] = counts.get(name, 0) + n
            remaining -= got.get(table, 0)
        n = counts.get(table, 0)
        if usage_rows:  # the summary of exactly the rows just deleted, in the same step
            self._usage += self._summarise(run_id, now, tenant_id, usage_rows)
        if n > 0 or (batch == 1 and not resweep):
            self._receipts.append(
                OffboardReceipt(
                    run_id, now, tenant_id, table, TABLE_CLASS[table], n, batch, resweep
                )
            )
            if table == "escalation_items":
                self._receipts.append(
                    OffboardReceipt(
                        run_id,
                        now,
                        tenant_id,
                        CONTENT_RECEIPT,
                        "C",
                        counts.get(CONTENT_RECEIPT, 0),
                        batch,
                        resweep,
                    )
                )
        return n

    def _summarise(
        self, run_id: str, now: datetime, tenant_id: str, rows: Sequence[UsageEvent]
    ) -> list[UsageSummaryRow]:
        price = self.price_per_million_input_tokens_usd
        groups: dict[tuple[str, str], list[UsageEvent]] = {}
        for e in rows:
            month = datetime.fromtimestamp(e.at, UTC).strftime("%Y-%m")
            groups.setdefault((month, e.kind), []).append(e)
        out = []
        for (month, kind), events in sorted(groups.items()):
            tokens = sum(e.input_tokens or 0 for e in events)
            out.append(
                UsageSummaryRow(
                    run_id=run_id,
                    at=now,
                    tenant_id=tenant_id,
                    month=month,
                    usage_class=kind,
                    events=len(events),
                    answered_calls=sum(1 for e in events if e.kind == USAGE_ANSWERED),
                    input_tokens=tokens,
                    price_per_million_usd=price,
                    cost_usd=Decimal(tokens) * price / 1_000_000,
                )
            )
        return out

    async def resweep_due(self, now: datetime) -> list[ResweepDue]:
        due = []
        for tenant_id, done in self._completions.items():
            record = self.directory._records.get(tenant_id)
            if record is None or record.status != "terminated":
                continue
            day = min(RESWEEP_DAYS, (now - done.at) // RESWEEP_INTERVAL)
            last = max((d for (t, d) in self._sweeps if t == tenant_id), default=0)
            if day >= 1 and day > last:
                due.append(ResweepDue(tenant_id, int(day), done.at))
        return sorted(due, key=lambda d: (d.completed_at, d.tenant_id))

    async def log_sweep(
        self, *, run_id: str, tenant_id: str, day: int, deleted: int, now: datetime
    ) -> bool:
        if not is_valid_tenant_id(tenant_id):
            raise OffboardingRefused("the tenant id is not valid")
        if not 1 <= day <= RESWEEP_DAYS or deleted < 0:
            raise OffboardingRefused("the sweep's day or count is out of range")
        done = self._completions.get(tenant_id)
        if done is None or now < done.at + day * RESWEEP_INTERVAL:
            raise OffboardingRefused("that sweep is not due")
        if (tenant_id, day) in self._sweeps:
            return False
        self._sweeps[(tenant_id, day)] = SweepRecord(tenant_id, day, run_id, now, deleted)
        return True

    async def complete(self, *, run_id: str, tenant_id: str, now: datetime) -> CompleteOutcome:
        if not is_valid_tenant_id(tenant_id):
            raise OffboardingRefused("the tenant id is not valid")
        self._require_terminated(tenant_id)
        if tenant_id in self._completions:
            return "already_complete"
        for t in OFFBOARD_TABLES:
            for holder in self.holders:
                if t.name in holder.offboard_tables and any(
                    holder.offboard_tenant(tenant_id, t.name, 1, count_only=True).values()
                ):
                    return "remaining"
        terminating, terminated = self._times(tenant_id)
        by_class, by_table = sum_receipts(await self.receipts(tenant_id))
        self._completions[tenant_id] = CompletionReceipt(
            tenant_id=tenant_id,
            run_id=run_id,
            at=now,
            terminating_at=terminating,
            terminated_at=terminated,
            deadline=terminating + DELETION_DEADLINE,
            within_deadline=now <= terminating + DELETION_DEADLINE,
            counts_by_class={c: by_class.get(c, 0) for c in CLASSES},
            counts_by_table=dict(sorted(by_table.items())),
        )
        return "completed"

    async def receipts(
        self, tenant_id: str | None = None, run_id: str | None = None
    ) -> list[OffboardReceipt]:
        return [
            r
            for r in self._receipts
            if (tenant_id is None or r.tenant_id == tenant_id)
            and (run_id is None or r.run_id == run_id)
        ]

    async def completion(self, tenant_id: str) -> CompletionReceipt | None:
        return self._completions.get(tenant_id)

    async def usage_summary(self, tenant_id: str) -> list[UsageSummaryRow]:
        return [r for r in self._usage if r.tenant_id == tenant_id]

    async def sweeps(self, tenant_id: str) -> list[SweepRecord]:
        return sorted(
            (r for (t, _), r in self._sweeps.items() if t == tenant_id), key=lambda r: r.day
        )


__all__ = [
    "RECEIPT_TABLES",
    "CompleteOutcome",
    "InMemoryOffboardingStore",
    "OffboardingStore",
    "TenantDataHolder",
    "UsageRowHolder",
    "check_bounds",
]
