"""The escalation stores (M4-05): the tenant-scoped item store and the class D deletion port.

Two ports, deliberately separate so ordinary code can't delete:

* :class:`EscalationStore` is what the router and the service hold, one verified tenant at a
  time (``store.scoped(scope)``). It inserts items, reads them, **resolves** them (the one
  update, narrow: ``open`` to ``resolved`` once) and attaches the golden label to a resolved
  item. It has no delete.
* :class:`ClassDStore` is what the class D job holds: list the tenants to sweep, delete one
  bounded batch (writing the class A receipt in the same step), read the receipts.

:class:`InMemoryEscalationStore` implements the first and hands the second out as ``.retention``
over the same data. The Postgres pair is in ``escalation/adapters/postgres.py`` and the database
refuses what these ports don't offer.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from typing import Final, Protocol

from guardrail_engine.escalation.model import (
    CLASS_D_DAYS,
    RETENTION_AFTER_RESOLUTION,
    RETENTION_FROM_CREATION,
    RETENTION_MODES,
    STATUS_OPEN,
    STATUS_RESOLVED,
    AlreadyResolvedError,
    EscalationAuditEvent,
    EscalationItem,
    EscalationNotFoundError,
    ItemFilter,
    Resolution,
    matches,
    resolved_copy,
)
from guardrail_engine.retention.store import RetentionError
from guardrail_engine.store.port import ScopeMismatchError
from guardrail_engine.tenant_scope import TenantScope

MODE_AFTER_RESOLUTION: Final = RETENTION_AFTER_RESOLUTION
MODE_FROM_CREATION: Final = RETENTION_FROM_CREATION
MODES: Final = RETENTION_MODES
MAX_BATCH_SIZE: Final = 100_000
MIN_CLASS_D_DAYS: Final = CLASS_D_DAYS
"""The shortest term the deletion accepts: R3's class D 30 days, not a day less."""
MAX_CLASS_D_DAYS: Final = 400
CLASS_D_SOURCES: Final = ("default", "healthcare", "fallback")


class EscalationStore(Protocol):
    """A tenant-scoped escalation store. ``tenant_id`` must be the scope's tenant (else
    :class:`ScopeMismatchError`). Another tenant's item is indistinguishable from none."""

    async def insert(self, item: EscalationItem) -> bool:
        """Store a new open item. False if the id is already stored (the same check routed
        twice): nothing changes."""
        ...

    async def get(self, tenant_id: str, item_id: str) -> EscalationItem | None: ...

    async def same_check_count(self, tenant_id: str, request_id: str, guard_point: str) -> int:
        """How many items the tenant holds for this request id at this guard point. More than
        one means a caller reused a request id for different content."""
        ...

    async def list(
        self, tenant_id: str, filt: ItemFilter, *, after: int | None, limit: int
    ) -> list[EscalationItem]:
        """Up to ``limit`` items matching ``filt`` with ``seq`` above ``after``, oldest first."""
        ...

    async def resolve(
        self, tenant_id: str, item_id: str, resolution: Resolution, event: EscalationAuditEvent
    ) -> EscalationItem:
        """Resolve an open item and write ``event`` (class A) in the same step. Raises
        :class:`EscalationNotFoundError` or :class:`AlreadyResolvedError`."""
        ...

    async def attach_label(
        self,
        tenant_id: str,
        item_id: str,
        label_set_id: str,
        label_mode: str,
        event: EscalationAuditEvent,
    ) -> EscalationItem:
        """Record the golden set made from a resolved item, once, with its class A event.
        A second call for an item that already has a label changes nothing and returns it."""
        ...

    async def audit_events(self, tenant_id: str) -> list[EscalationAuditEvent]: ...


class ScopedEscalationStores(Protocol):
    def scoped(self, scope: TenantScope) -> EscalationStore: ...


@dataclass(frozen=True, slots=True)
class ClassDBatch:
    deleted: int
    expired_unresolved: int
    """Of ``deleted``, the items nobody had resolved (only under :data:`MODE_FROM_CREATION`)."""


@dataclass(frozen=True, slots=True)
class ClassDReceipt:
    """A class A deletion receipt for one class D batch (the M4-09 receipt's shape, plus how
    many of the deleted items were unresolved). Tenant, class, cutoff, counts and run id; never
    content. In Postgres these are rows of ``retention_receipts`` with class ``D``."""

    run_id: str
    at: datetime
    tenant_id: str
    retention_class: str
    cutoff: datetime
    deleted_count: int
    batch: int
    retention_days: int
    source: str
    expired_unresolved: int = 0


class ClassDStore(Protocol):
    """What the class D job holds: the one deletion path for escalation items."""

    async def class_d_tenants(self) -> list[str]:
        """The tenants that have escalation items."""
        ...

    async def delete_class_d_batch(
        self,
        *,
        run_id: str,
        tenant_id: str,
        now: datetime,
        mode: str,
        days: int,
        source: str,
        limit: int,
        batch: int,
    ) -> ClassDBatch:
        """Delete at most ``limit`` of the tenant's items older than ``now - days`` (strictly:
        an item exactly at the cutoff is kept), by resolution time for an item whose own
        ``retention_mode`` is :data:`MODE_AFTER_RESOLUTION` and by creation time for
        :data:`MODE_FROM_CREATION`, and append the class D receipt in the same step. The mode is
        the **item's**, fixed when it was routed; ``mode`` here is only validated (a caller
        can't make an unresolved item go early by naming another mode), and ``days`` is at
        least :data:`MIN_CLASS_D_DAYS`. A receipt is written for batch 1 even if nothing was
        deleted, and for a later batch only if it deleted something. Raises
        :class:`RetentionError` for a mode, a ``days``, a ``source`` or a ``limit`` out of
        bounds."""
        ...

    async def receipts(self, run_id: str | None = None) -> list[ClassDReceipt]: ...


def check_class_d_bounds(*, mode: str, days: int, source: str, limit: int) -> None:
    """The bounds the Postgres function enforces too, so both stores refuse the same calls."""
    if mode not in MODES:
        raise RetentionError("mode must be resolved_plus or total")
    if not MIN_CLASS_D_DAYS <= days <= MAX_CLASS_D_DAYS:
        raise RetentionError(f"days must be {MIN_CLASS_D_DAYS}..{MAX_CLASS_D_DAYS}")
    if source not in CLASS_D_SOURCES:
        raise RetentionError("source must be default, healthcare or fallback")
    if not 1 <= limit <= MAX_BATCH_SIZE:
        raise RetentionError(f"batch size must be 1..{MAX_BATCH_SIZE}")


class InMemoryEscalationStore:
    """Items, class A events and class D receipts in memory. For tests and local runs."""

    def __init__(self) -> None:
        self._items: dict[tuple[str, str], EscalationItem] = {}
        self._events: list[EscalationAuditEvent] = []
        self._receipts: list[ClassDReceipt] = []
        self._seq = 0
        self.retention: ClassDStore = _InMemoryClassD(self)
        """The deletion port. Hand it to the class D job only."""

    def scoped(self, scope: TenantScope) -> EscalationStore:
        if not isinstance(scope, TenantScope):
            raise TypeError("scoped() takes a TenantScope")
        return _ScopedMemoryEscalations(self, scope)

    def items(self, tenant_id: str) -> list[EscalationItem]:
        """For tests: every item of a tenant, oldest first."""
        return sorted((i for (t, _), i in self._items.items() if t == tenant_id), key=_by_seq)

    offboard_tables = ("escalation_items",)

    def offboard_tenant(
        self, tenant_id: str, table: str, limit: int, *, count_only: bool = False
    ) -> dict[str, int]:
        """M5-07: delete (or count) a terminated tenant's rows (see ``TenantDataHolder``)."""
        mine = self.items(tenant_id)
        if not count_only:
            mine = mine[:limit]
            for i in mine:
                del self._items[(tenant_id, i.id)]
        held = sum(1 for i in mine if i.content is not None and i.store_content == "full")
        return {table: len(mine), "escalation_items.content": held}


def _by_seq(item: EscalationItem) -> int:
    return item.seq


class _ScopedMemoryEscalations:
    def __init__(self, store: InMemoryEscalationStore, scope: TenantScope) -> None:
        self._store = store
        self._scope = scope

    def _check(self, tenant_id: str) -> None:
        if tenant_id != self._scope.tenant_id:
            raise ScopeMismatchError()

    async def insert(self, item: EscalationItem) -> bool:
        self._check(item.tenant_id)
        key = (item.tenant_id, item.id)
        if key in self._store._items:
            return False
        self._store._seq += 1
        self._store._items[key] = replace(item, seq=self._store._seq)
        return True

    async def get(self, tenant_id: str, item_id: str) -> EscalationItem | None:
        self._check(tenant_id)
        return self._store._items.get((tenant_id, item_id))

    async def same_check_count(self, tenant_id: str, request_id: str, guard_point: str) -> int:
        self._check(tenant_id)
        return sum(
            1
            for i in self._store.items(tenant_id)
            if i.request_id == request_id and i.guard_point == guard_point
        )

    async def list(
        self, tenant_id: str, filt: ItemFilter, *, after: int | None, limit: int
    ) -> list[EscalationItem]:
        self._check(tenant_id)
        rows = [
            i
            for i in self._store.items(tenant_id)
            if (after is None or i.seq > after) and matches(i, filt)
        ]
        return rows[:limit]

    async def resolve(
        self, tenant_id: str, item_id: str, resolution: Resolution, event: EscalationAuditEvent
    ) -> EscalationItem:
        self._check(tenant_id)
        if event.tenant_id != tenant_id or event.item_id != item_id:
            raise ScopeMismatchError()
        item = self._store._items.get((tenant_id, item_id))
        if item is None:
            raise EscalationNotFoundError()
        if item.status != STATUS_OPEN:
            raise AlreadyResolvedError()
        done = resolved_copy(item, resolution)
        self._store._items[(tenant_id, item_id)] = done
        self._store._events.append(event)
        return done

    async def attach_label(
        self,
        tenant_id: str,
        item_id: str,
        label_set_id: str,
        label_mode: str,
        event: EscalationAuditEvent,
    ) -> EscalationItem:
        self._check(tenant_id)
        if event.tenant_id != tenant_id or event.item_id != item_id:
            raise ScopeMismatchError()
        item = self._store._items.get((tenant_id, item_id))
        if item is None:
            raise EscalationNotFoundError()
        if item.status != STATUS_RESOLVED:
            raise AlreadyResolvedError()  # not resolved: a label can't be attached yet
        if item.label_set_id is not None:
            return item
        done = replace(item, label_set_id=label_set_id, label_mode=label_mode)
        self._store._items[(tenant_id, item_id)] = done
        self._store._events.append(event)
        return done

    async def audit_events(self, tenant_id: str) -> list[EscalationAuditEvent]:
        self._check(tenant_id)
        return [e for e in self._store._events if e.tenant_id == tenant_id]


class _InMemoryClassD:
    def __init__(self, store: InMemoryEscalationStore) -> None:
        self._store = store

    async def class_d_tenants(self) -> list[str]:
        return sorted({t for (t, _) in self._store._items})

    async def delete_class_d_batch(
        self,
        *,
        run_id: str,
        tenant_id: str,
        now: datetime,
        mode: str,
        days: int,
        source: str,
        limit: int,
        batch: int,
    ) -> ClassDBatch:
        check_class_d_bounds(mode=mode, days=days, source=source, limit=limit)
        cutoff = now - timedelta(days=days)
        # No await below: the whole batch is one atomic step on the event loop.
        doomed: list[EscalationItem] = []
        for item in self._store.items(tenant_id):
            # Each item's own mode decides, whatever the caller passed as ``mode``.
            if item.retention_mode == MODE_FROM_CREATION:
                due = item.created_at < cutoff
            else:
                due = (
                    item.status == STATUS_RESOLVED
                    and item.resolved_at is not None
                    and item.resolved_at < cutoff
                )
            if due:
                doomed.append(item)
            if len(doomed) == limit:
                break
        for item in doomed:
            del self._store._items[(tenant_id, item.id)]
        n = len(doomed)
        expired = sum(1 for i in doomed if i.status == STATUS_OPEN)
        if n > 0 or batch == 1:
            self._store._receipts.append(
                ClassDReceipt(
                    run_id=run_id,
                    at=now,
                    tenant_id=tenant_id,
                    retention_class="D",
                    cutoff=cutoff,
                    deleted_count=n,
                    batch=batch,
                    retention_days=days,
                    source=source,
                    expired_unresolved=expired,
                )
            )
        return ClassDBatch(n, expired)

    async def receipts(self, run_id: str | None = None) -> list[ClassDReceipt]:
        return [r for r in self._store._receipts if run_id is None or r.run_id == run_id]


__all__ = [
    "CLASS_D_DAYS",
    "CLASS_D_SOURCES",
    "MIN_CLASS_D_DAYS",
    "MODES",
    "MODE_AFTER_RESOLUTION",
    "MODE_FROM_CREATION",
    "ClassDBatch",
    "ClassDReceipt",
    "ClassDStore",
    "EscalationStore",
    "InMemoryEscalationStore",
    "ScopedEscalationStores",
    "check_class_d_bounds",
]  # fmt: skip
