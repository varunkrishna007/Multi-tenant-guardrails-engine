"""The offboarding job (M5-07, R3): delete a terminated tenant's classes B, C, D and E, its golden
sets, drafts, candidates, calibration data, escalation items and usage rows within 30 days, keep
class A, and write the receipts.

:meth:`OffboardingJob.run_once` takes the injected clock once, then for each tenant the store
lists as waiting (status ``terminating`` or ``terminated``, no completion yet):

1. **Overdue check.** A tenant whose 30 days (from the termination request) have passed
   **strictly** and that isn't done raises one ``offboarding_overdue`` page. At exactly day 30
   it is still in time; one second later it is not. A tenant that is still ``terminating`` is
   listed in the report as waiting, and alerts the same way (a termination stuck half-way is
   as late as one whose deletion is).
2. **Delete**, for a ``terminated`` tenant only (the database checks the status itself, on every
   call, so this is a courtesy and not the guard): each table in ``OFFBOARD_TABLES`` order, in
   bounded batches of ``batch_size`` rows, at most ``max_batches_per_table`` per run. A table
   that hits the cap ends the run for that tenant (``more_to_do``; its parents wait for it) and
   the next run continues. Every batch writes a class A receipt in the same transaction.
3. **Complete**, when nothing is left **and** the tenant has been terminated for at least
   ``quiesce`` (default one hour): the store writes the class A "offboarding complete" receipt,
   once, with the counts per class. Until then the data is already gone and every run looks
   again (an in-flight check, a write-behind queue or an outbox retry that was admitted before
   the termination may still land a row after the first sweep; it is swept by the next run, and
   the receipt is written only when a sweep after the quiet period finds nothing).
4. **Re-sweep.** After the completion receipt, a late row (a write-behind backlog, an
   outbox retry) would otherwise stay for good. So once a day for 7 days (day N is due N days
   after the completion receipt) the job runs the same delete pass again for the tenant, and
   records the sweep (``offboarding_sweeps``, whether or not it found anything). A sweep that
   deleted something has its receipts (``resweep`` true) and, for usage rows, its billing
   summary; one that found nothing writes no deletion receipt. After the day-7 sweep the tenant
   is final: nothing looks at it again. A job that was down catches up with one sweep for the
   latest day due.

**Usage rows are billing evidence.** The store writes, in the same step that deletes
usage rows, a class A summary of exactly those rows: per UTC calendar month and usage class, the
events, answered calls, input tokens and the cost in USD at the store's configured price
(``price_per_million_input_tokens_usd``). Read it with ``store.usage_summary(tenant_id)``.

**Replicas.** Any number of runs may go at once. A batch takes its rows with
``FOR UPDATE SKIP LOCKED``, so two runs never delete or count one row twice; completion is
decided by the database under a lock on the tenant's row and written once. **Idempotent:** a run
on a finished tenant finds it no longer waiting and does nothing; a run on a half-finished one
continues from where the data is.

The job holds no tenant data and reads none; it reaches the data only through the store.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from guardrail_engine.gateway.sinks import (
    ALERT_OFFBOARDING_OVERDUE,
    Alert,
    AlertSeverity,
    AlertSink,
)
from guardrail_engine.offboarding.model import (
    MAX_BATCH_SIZE,
    OFFBOARD_TABLES,
    PendingTenant,
    ResweepDue,
)
from guardrail_engine.offboarding.store import OffboardingStore

logger = logging.getLogger(__name__)

DEFAULT_BATCH_SIZE = 1000
DEFAULT_MAX_BATCHES = 1000
DEFAULT_QUIESCE = timedelta(hours=1)


@dataclass(frozen=True, slots=True)
class TenantOffboarding:
    tenant_id: str
    status: str
    deleted: dict[str, int] = field(default_factory=dict)
    """Rows deleted by this run, by table."""
    more_to_do: bool = False
    """A table hit the per-run batch cap with full batches: the next run continues."""
    completed: bool = False
    """This run wrote the completion receipt."""
    quiescing: bool = False
    """Everything is deleted but the quiet period after termination hasn't passed: no completion
    receipt yet (the next run after it writes it)."""
    waiting: bool = False
    """The tenant is ``terminating``, not yet ``terminated``: nothing may be deleted yet."""
    overdue: bool = False
    deadline: datetime | None = None


@dataclass(frozen=True, slots=True)
class TenantResweep:
    """One daily re-sweep of a completed tenant."""

    tenant_id: str
    day: int
    deleted: dict[str, int] = field(default_factory=dict)
    """Late rows this sweep deleted, by table."""
    more_to_do: bool = False
    """A table hit the per-run batch cap: the sweep isn't logged, the next run continues it."""
    logged: bool = False
    """The sweep for ``day`` was recorded (it ran to the end)."""

    @property
    def found(self) -> int:
        return sum(self.deleted.values())


@dataclass(frozen=True, slots=True)
class OffboardingReport:
    run_id: str
    at: datetime
    tenants: tuple[TenantOffboarding, ...]
    failed: tuple[str, ...] = ()
    """Tenants whose run raised. Their earlier batches' receipts stand; the next run retries."""
    overdue: tuple[str, ...] = ()
    """Tenants past day 30 and not finished when this run began (an alert was raised for each)."""
    resweeps: tuple[TenantResweep, ...] = ()
    """The daily re-sweeps of completed tenants that were due."""

    @property
    def deleted(self) -> int:
        return sum(sum(t.deleted.values()) for t in self.tenants) + sum(
            r.found for r in self.resweeps
        )


class OffboardingJob:
    def __init__(
        self,
        store: OffboardingStore,
        *,
        clock: Callable[[], datetime],
        alerts: AlertSink | None = None,
        batch_size: int = DEFAULT_BATCH_SIZE,
        max_batches_per_table: int = DEFAULT_MAX_BATCHES,
        quiesce: timedelta = DEFAULT_QUIESCE,
        run_id_factory: Callable[[], str] = lambda: uuid.uuid4().hex,
    ) -> None:
        if not 1 <= batch_size <= MAX_BATCH_SIZE:
            raise ValueError(f"batch_size must be 1..{MAX_BATCH_SIZE}")
        if max_batches_per_table < 1:
            raise ValueError("max_batches_per_table must be at least 1")
        if quiesce < timedelta(0):
            raise ValueError("quiesce can't be negative")
        self._store = store
        self._clock = clock
        self._alerts = alerts
        self._batch_size = batch_size
        self._max_batches = max_batches_per_table
        self._quiesce = quiesce
        self._run_id = run_id_factory

    async def check_overdue(self) -> tuple[str, ...]:
        """Only the 30-day check, deleting nothing: page for each waiting tenant that is past
        day 30. For a watcher that runs on its own schedule (or on another replica, or when the
        deletion job itself is what is broken); :meth:`run_once` does the same check first."""
        now = self._clock()
        if now.tzinfo is None:
            raise ValueError("the clock must return an aware datetime")
        late = []
        for pending in await self._store.pending():
            if pending.overdue(now):
                late.append(pending.tenant_id)
                await self._alert(pending.tenant_id, now, now - pending.deadline)
        return tuple(late)

    async def run_once(self) -> OffboardingReport:
        now = self._clock()
        if now.tzinfo is None:
            raise ValueError("the clock must return an aware datetime")
        run_id = self._run_id()
        done: list[TenantOffboarding] = []
        failed: list[str] = []
        overdue: list[str] = []
        for pending in await self._store.pending():
            is_overdue = pending.overdue(now)
            if is_overdue:
                overdue.append(pending.tenant_id)
                await self._alert(pending.tenant_id, now, now - pending.deadline)
            if pending.status != "terminated":
                done.append(
                    TenantOffboarding(
                        pending.tenant_id,
                        pending.status,
                        waiting=True,
                        overdue=is_overdue,
                        deadline=pending.deadline,
                    )
                )
                continue
            try:
                result = await self._offboard(run_id, now, pending)
            except Exception as exc:
                logger.error("offboarding failed: %s", type(exc).__name__)
                failed.append(pending.tenant_id)
                continue
            done.append(
                TenantOffboarding(
                    pending.tenant_id,
                    pending.status,
                    result.deleted,
                    result.more_to_do,
                    result.completed,
                    result.quiescing,
                    False,
                    is_overdue,
                    pending.deadline,
                )
            )
        swept: list[TenantResweep] = []
        for due in await self._store.resweep_due(now):
            try:
                swept.append(await self._resweep(run_id, now, due))
            except Exception as exc:
                logger.error("offboarding re-sweep failed: %s", type(exc).__name__)
                failed.append(due.tenant_id)
        return OffboardingReport(
            run_id, now, tuple(done), tuple(failed), tuple(overdue), tuple(swept)
        )

    async def _sweep_tables(
        self, run_id: str, now: datetime, tenant_id: str
    ) -> tuple[dict[str, int], bool]:
        """One pass over every table in order, in bounded batches: (rows deleted by table,
        whether a table hit the batch cap and the pass stopped there)."""
        deleted: dict[str, int] = {}
        more = False
        for table in OFFBOARD_TABLES:
            total = 0
            for batch in range(1, self._max_batches + 1):
                n = await self._store.delete_batch(
                    run_id=run_id,
                    tenant_id=tenant_id,
                    table=table.name,
                    now=now,
                    limit=self._batch_size,
                    batch=batch,
                )
                total += n
                if n < self._batch_size:
                    break
                if batch == self._max_batches:
                    more = True
                await asyncio.sleep(0)  # let a concurrent run take its turn between batches
            deleted[table.name] = total
            if more:
                break  # a table is not finished: stop here (a parent waits for its children)
        return deleted, more

    async def _resweep(self, run_id: str, now: datetime, due: ResweepDue) -> TenantResweep:
        deleted, more = await self._sweep_tables(run_id, now, due.tenant_id)
        if more:
            return TenantResweep(due.tenant_id, due.day, deleted, more_to_do=True)
        await self._store.log_sweep(
            run_id=run_id,
            tenant_id=due.tenant_id,
            day=due.day,
            deleted=sum(deleted.values()),
            now=now,
        )
        return TenantResweep(due.tenant_id, due.day, deleted, logged=True)

    async def _offboard(
        self, run_id: str, now: datetime, pending: PendingTenant
    ) -> TenantOffboarding:
        tenant_id = pending.tenant_id
        deleted, more = await self._sweep_tables(run_id, now, tenant_id)
        completed = quiescing = False
        if not more:
            since = pending.terminated_at or pending.terminating_at
            if now - since >= self._quiesce:
                outcome = await self._store.complete(run_id=run_id, tenant_id=tenant_id, now=now)
                completed = outcome == "completed"
            else:
                quiescing = True
        return TenantOffboarding(tenant_id, "terminated", deleted, more, completed, quiescing)

    async def _alert(self, tenant_id: str, now: datetime, late: timedelta) -> None:
        """One page per overdue tenant per run. ``tenant_id`` on the alert is empty (a platform
        alert) on purpose: the tenant's own alert rows are among the data being deleted."""
        if self._alerts is None:
            logger.error("offboarding overdue for %s", tenant_id)
            return
        alert = Alert(
            severity=AlertSeverity.PAGE,
            kind=ALERT_OFFBOARDING_OVERDUE,
            message=(
                f"offboarding of tenant {tenant_id} is {late.days} day(s) past its 30-day "
                "deadline and is not finished"
            ),
            key_id="",
            tenant_id="",
            guard_point="",
            reason="overdue",
            dedupe_key=f"offboarding_overdue:{tenant_id}:{now.date().isoformat()}",
        )
        try:
            await asyncio.to_thread(self._alerts.emit, alert)
        except Exception as exc:
            logger.error("offboarding overdue alert failed: %s", type(exc).__name__)
