"""The daily retention job for classes A and B (M4-09, R3).

:meth:`RetentionJob.run_once` takes the injected clock once, then for each tenant that has
decision records works out the tenant's class B term (:mod:`~guardrail_engine.retention.resolver`),
computes ``cutoff = now - term`` and deletes the records older than it in **bounded batches**
(``batch_size`` rows per statement, at most ``max_batches_per_tenant`` per run; the rest wait for
tomorrow). A record is deleted only when it is past the tenant's cutoff **and** its own
``retain_until``, so shortening a tenant's term never reaches back to records written under a
longer one, while lengthening it protects the older ones too. The comparison is strict: a record
exactly at the cutoff is kept, one second older is deleted.

Each batch writes a class A deletion receipt in the same step as the delete (tenant, class,
cutoff, count, run id; never content), so there is never a deletion without its receipt.

**Replicas.** Any number of replicas may run it at once. The store's delete takes rows with
``FOR UPDATE SKIP LOCKED``, so two runs never delete or count the same row; a run that finds the
rest locked by another simply stops early, and the other run finishes them. **Idempotent:** a
second run at the same time deletes nothing more.

**Class A.** R3 keeps class A for seven years, immutable, and offboarding keeps it for its full
term. Nothing in the engine is seven years old yet and no class A table has a delete path, so
this job deletes no class A row. Class A is covered here only as the home of the receipts, which
are themselves class A and are never deleted.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from guardrail_engine.retention.resolver import RetentionResolver
from guardrail_engine.retention.store import MAX_BATCH_SIZE, RetentionStore

logger = logging.getLogger(__name__)

DEFAULT_BATCH_SIZE = 1000
DEFAULT_MAX_BATCHES = 1000


@dataclass(frozen=True, slots=True)
class TenantSweep:
    tenant_id: str | None
    retention_days: int
    source: str
    cutoff: datetime
    deleted: int
    batches: int
    more_to_do: bool
    """The per-run batch cap was reached with full batches: the next run continues."""


@dataclass(frozen=True, slots=True)
class RunReport:
    run_id: str
    at: datetime
    sweeps: tuple[TenantSweep, ...]
    failed: tuple[str | None, ...] = field(default=())
    """Tenants whose sweep raised. Their other batches' receipts stand; the next run retries."""

    @property
    def deleted(self) -> int:
        return sum(s.deleted for s in self.sweeps)


class RetentionJob:
    def __init__(
        self,
        store: RetentionStore,
        resolver: RetentionResolver,
        *,
        clock: Callable[[], datetime],
        batch_size: int = DEFAULT_BATCH_SIZE,
        max_batches_per_tenant: int = DEFAULT_MAX_BATCHES,
        run_id_factory: Callable[[], str] = lambda: uuid.uuid4().hex,
    ) -> None:
        if not 1 <= batch_size <= MAX_BATCH_SIZE:
            raise ValueError(f"batch_size must be 1..{MAX_BATCH_SIZE}")
        if max_batches_per_tenant < 1:
            raise ValueError("max_batches_per_tenant must be at least 1")
        self._store = store
        self._resolver = resolver
        self._clock = clock
        self._batch_size = batch_size
        self._max_batches = max_batches_per_tenant
        self._run_id = run_id_factory

    async def run_once(self) -> RunReport:
        now = self._clock()
        if now.tzinfo is None:
            raise ValueError("the clock must return an aware datetime")
        run_id = self._run_id()
        sweeps: list[TenantSweep] = []
        failed: list[str | None] = []
        for tenant_id in await self._store.class_b_tenants():
            try:
                sweeps.append(await self._sweep(run_id, now, tenant_id))
            except Exception as exc:
                logger.error("retention sweep failed: %s", type(exc).__name__)
                failed.append(tenant_id)
        return RunReport(run_id=run_id, at=now, sweeps=tuple(sweeps), failed=tuple(failed))

    async def _sweep(self, run_id: str, now: datetime, tenant_id: str | None) -> TenantSweep:
        term = await self._resolver.resolve(tenant_id)
        cutoff = now - timedelta(days=term.days)
        deleted = batches = 0
        more = False
        for batch in range(1, self._max_batches + 1):
            n = await self._store.delete_class_b_batch(
                run_id=run_id,
                tenant_id=tenant_id,
                cutoff=cutoff,
                now=now,
                limit=self._batch_size,
                retention_days=term.days,
                source=term.source,
                batch=batch,
            )
            deleted += n
            batches = batch
            if n < self._batch_size:
                break
            if batch == self._max_batches:
                more = True
            await asyncio.sleep(0)  # let a concurrent run take its turn between batches
        return TenantSweep(
            tenant_id=tenant_id,
            retention_days=term.days,
            source=term.source,
            cutoff=cutoff,
            deleted=deleted,
            batches=batches,
            more_to_do=more,
        )
