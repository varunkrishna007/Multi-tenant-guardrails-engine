"""The class D deletion job (M4-05, R3): escalation items, the content held for a reviewer.

R3 class D: **until resolved, plus 30 days** for every tier but healthcare, and **30 days total**
for healthcare, where an unresolved item expires and the expiry is logged. So:

* standard, finance and no-pack tenants: an item is deleted once it was resolved more than 30 days
  ago (``resolved_at < now - 30 days``). An item nobody resolves is kept: until resolved.
* a tenant whose packs need a BAA (the healthcare profile): an item is deleted once it was created
  more than 30 days ago, resolved or not (``created_at < now - 30 days``). Each unresolved item
  that goes this way is counted in the receipt (``expired_unresolved``) and logged (a count per
  tenant, never an item or its content).
* a tenant that can't be resolved (not in the directory, an unreadable bundle, a missing pack) gets
  the standard rule, which keeps items longer: deleting early can't be undone.

Which of the two rules applies to an item is **the item's own** ``retention_mode``, fixed when it
was routed from the tenant's profile; the database applies it, so a term resolved wrongly
here can't make an unresolved item of a standard tenant go early. The term below sets the days
(R3's 30, never fewer) and the receipt's source label.

The comparison is **strict**: an item exactly 30 days old is kept; one second older is deleted.
The time is the job's **injected clock** (an aware ``datetime``), taken once per run.

Deletion is bounded batches through the store's one deletion path
(:class:`~guardrail_engine.escalation.store.ClassDStore`; in Postgres a ``SECURITY DEFINER``
function the job's own role may execute, ``retention_delete_class_d``), which writes the class A
receipt (tenant, class ``D``, cutoff, count, expired count, run id; never content) **in the same
step** as the delete, so there is no deletion without its receipt. Any number of replicas may run
it: the delete skips rows another run holds. The same shape as the M4-09 job
(:class:`~guardrail_engine.retention.job.RetentionJob`).
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Protocol

from guardrail_engine.escalation.model import CLASS_D_DAYS
from guardrail_engine.escalation.store import (
    MAX_BATCH_SIZE,
    MODE_AFTER_RESOLUTION,
    MODE_FROM_CREATION,
    ClassDStore,
)
from guardrail_engine.retention.resolver import CatalogRetentionResolver

logger = logging.getLogger(__name__)

DEFAULT_BATCH_SIZE = 1000
DEFAULT_MAX_BATCHES = 1000


@dataclass(frozen=True, slots=True)
class ClassDTerm:
    days: int
    mode: str
    source: str
    """``default`` (the standard rule), ``healthcare`` or ``fallback`` (the tenant couldn't be
    resolved: the standard rule)."""


STANDARD_TERM = ClassDTerm(CLASS_D_DAYS, MODE_AFTER_RESOLUTION, "default")
HEALTHCARE_TERM = ClassDTerm(CLASS_D_DAYS, MODE_FROM_CREATION, "healthcare")
FALLBACK_TERM = ClassDTerm(CLASS_D_DAYS, MODE_AFTER_RESOLUTION, "fallback")


class ClassDResolver(Protocol):
    async def resolve(self, tenant_id: str) -> ClassDTerm: ...


class CatalogClassDResolver:
    """Healthcare is what R3 calls the profile whose packs need a BAA to store content
    (``content_requires_baa``), worked out from the same tenant profile as the class B term."""

    def __init__(self, retention: CatalogRetentionResolver) -> None:
        self._retention = retention

    async def resolve(self, tenant_id: str) -> ClassDTerm:
        try:
            found = await self._retention.profile_for(tenant_id)
        except Exception as exc:
            logger.warning("class D term fallback for a tenant: %s", type(exc).__name__)
            return FALLBACK_TERM
        if found is None:
            return FALLBACK_TERM
        return HEALTHCARE_TERM if found[0].content_requires_baa else STANDARD_TERM

    async def needs_deidentification(self, tenant_id: str) -> bool:
        """For the resolve endpoint: must promoted content be de-identified first (R3,
        healthcare)? An unresolvable tenant is treated as healthcare (the stricter answer)."""
        try:
            found = await self._retention.profile_for(tenant_id)
        except Exception:
            return True
        return found is None or found[0].content_requires_baa


@dataclass(frozen=True, slots=True)
class ClassDSweep:
    tenant_id: str
    days: int
    mode: str
    source: str
    cutoff: datetime
    deleted: int
    expired_unresolved: int
    batches: int
    more_to_do: bool


@dataclass(frozen=True, slots=True)
class ClassDReport:
    run_id: str
    at: datetime
    sweeps: tuple[ClassDSweep, ...]
    failed: tuple[str, ...] = field(default=())

    @property
    def deleted(self) -> int:
        return sum(s.deleted for s in self.sweeps)


class ClassDJob:
    def __init__(
        self,
        store: ClassDStore,
        resolver: ClassDResolver,
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

    async def run_once(self) -> ClassDReport:
        now = self._clock()
        if now.tzinfo is None:
            raise ValueError("the clock must return an aware datetime")
        run_id = self._run_id()
        sweeps: list[ClassDSweep] = []
        failed: list[str] = []
        for tenant_id in await self._store.class_d_tenants():
            try:
                sweeps.append(await self._sweep(run_id, now, tenant_id))
            except Exception as exc:
                logger.error("class D sweep failed: %s", type(exc).__name__)
                failed.append(tenant_id)
        return ClassDReport(run_id=run_id, at=now, sweeps=tuple(sweeps), failed=tuple(failed))

    async def _sweep(self, run_id: str, now: datetime, tenant_id: str) -> ClassDSweep:
        term = await self._resolver.resolve(tenant_id)
        deleted = expired = batches = 0
        more = False
        for batch in range(1, self._max_batches + 1):
            result = await self._store.delete_class_d_batch(
                run_id=run_id,
                tenant_id=tenant_id,
                now=now,
                mode=term.mode,
                days=term.days,
                source=term.source,
                limit=self._batch_size,
                batch=batch,
            )
            deleted += result.deleted
            expired += result.expired_unresolved
            batches = batch
            if result.deleted < self._batch_size:
                break
            if batch == self._max_batches:
                more = True
            await asyncio.sleep(0)  # let a concurrent run take its turn between batches
        if expired:
            # The expiry is logged: a count for the tenant, never an item or its content.
            logger.info(
                "class D: %d unresolved escalation item(s) of tenant %s expired (healthcare, "
                "%d days from creation)",
                expired,
                tenant_id,
                term.days,
            )
        return ClassDSweep(
            tenant_id=tenant_id,
            days=term.days,
            mode=term.mode,
            source=term.source,
            cutoff=now - timedelta(days=term.days),
            deleted=deleted,
            expired_unresolved=expired,
            batches=batches,
            more_to_do=more,
        )
