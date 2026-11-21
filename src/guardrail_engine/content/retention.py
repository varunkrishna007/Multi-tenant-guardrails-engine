"""The class C deletion job (M5-03, R3): stored content.

R3 class C: content is kept for the term it was stored under (30 days by default, 90 at most;
30 at most for a tenant whose packs need a BAA) and no longer. Each row carries its **own**
``retain_until``, stamped when it was written from the tenant's term then in force, clamped to
the R3 cap then in force. So, unlike class B and class D, this job needs no tenant term
resolver: shortening a tenant's ``content_days`` never reaches back to rows written under a
longer one, and lengthening it never keeps a row past its own time. The database applies the rule
(``retention_delete_class_c``): a row goes when its ``retain_until`` is before the cutoff, or, as
a ceiling no wrong ``retain_until`` can outlive, when it was stored more than 90 days before it.

The comparison is **strict** (a row exactly at the cutoff is kept) and the time is the job's
**injected clock**, an aware ``datetime`` taken once per run. Deletion is bounded batches through
the store's one deletion path (:class:`~guardrail_engine.content.store.ClassCStore`), which writes
the class A receipt (tenant, class ``C``, cutoff, count, run id; never content) **in the same
step** as the delete. Any number of replicas may run it: the delete skips rows another run holds.
The same shape as :class:`~guardrail_engine.retention.job.RetentionJob`.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime

from guardrail_engine.content.model import MAX_BATCH_SIZE
from guardrail_engine.content.store import ClassCStore

logger = logging.getLogger(__name__)

DEFAULT_BATCH_SIZE = 1000
DEFAULT_MAX_BATCHES = 1000


@dataclass(frozen=True, slots=True)
class ClassCSweep:
    tenant_id: str
    cutoff: datetime
    deleted: int
    batches: int
    more_to_do: bool
    """The per-run batch cap was reached with full batches: the next run continues."""


@dataclass(frozen=True, slots=True)
class ClassCReport:
    run_id: str
    at: datetime
    sweeps: tuple[ClassCSweep, ...]
    failed: tuple[str, ...] = field(default=())
    """Tenants whose sweep raised. Their other batches' receipts stand; the next run retries."""

    @property
    def deleted(self) -> int:
        return sum(s.deleted for s in self.sweeps)


class ClassCJob:
    def __init__(
        self,
        store: ClassCStore,
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
        self._clock = clock
        self._batch_size = batch_size
        self._max_batches = max_batches_per_tenant
        self._run_id = run_id_factory

    async def run_once(self) -> ClassCReport:
        now = self._clock()
        if now.tzinfo is None:
            raise ValueError("the clock must return an aware datetime")
        run_id = self._run_id()
        sweeps: list[ClassCSweep] = []
        failed: list[str] = []
        for tenant_id in await self._store.class_c_tenants():
            try:
                sweeps.append(await self._sweep(run_id, now, tenant_id))
            except Exception as exc:
                logger.error("class C sweep failed: %s", type(exc).__name__)
                failed.append(tenant_id)
        return ClassCReport(run_id=run_id, at=now, sweeps=tuple(sweeps), failed=tuple(failed))

    async def _sweep(self, run_id: str, now: datetime, tenant_id: str) -> ClassCSweep:
        deleted = batches = 0
        more = False
        for batch in range(1, self._max_batches + 1):
            n = await self._store.delete_class_c_batch(
                run_id=run_id, tenant_id=tenant_id, now=now, limit=self._batch_size, batch=batch
            )
            deleted += n
            batches = batch
            if n < self._batch_size:
                break
            if batch == self._max_batches:
                more = True
            await asyncio.sleep(0)
        return ClassCSweep(tenant_id, now, deleted, batches, more)
