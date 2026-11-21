"""The draft store (M2-02): one mutable draft bundle per tenant, with an ETag.

A draft is the tenant's working copy of its policy bundle. It is replaced whole (``PUT``) or
changed one rule at a time (``PATCH``, ``DELETE``), and only a document the compiler accepts is
ever stored. Every write is a compare-and-set on the draft's ETag, and **the class A audit event
is written in the same step** (AC-A2): the store takes the event with the write, so there is no
write without its event and no event for a write that lost the race.

The port, like the policy store's, hands out a view for one verified tenant:
``store.scoped(scope)``. Nothing here takes a tenant id from a request.

**The ETag** is ``"sha256:<hex>"`` (quoted, a strong validator) over the canonical JSON of the
draft document. The draft hash in the audit event is the same value without the quotes. The
bundle hash of a *published* version (which also covers the catalog versions it extends) is made
at publish, M2-07.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol

from guardrail_engine.policy.canonical import sha256_of
from guardrail_engine.policy.diff import DiffEntry
from guardrail_engine.store.port import PolicyStoreError, ScopeMismatchError
from guardrail_engine.tenant_scope import TenantScope

MAX_DRAFT_BYTES = 256 * 1024
"""The largest draft document the API accepts (canonical JSON)."""

ACTIONS = ("draft.put", "draft.rule.put", "draft.rule.delete", "draft.thresholds")


def etag_of(document: object) -> str:
    """The quoted strong ETag of a draft document (a JSON value)."""
    return '"' + sha256_of(document) + '"'


@dataclass(frozen=True, slots=True)
class StoredDraft:
    tenant_id: str
    document: bytes
    """The canonical JSON of the draft document."""
    etag: str
    updated_at: datetime
    updated_by: str
    created: bool = field(default=False, compare=False)
    """True on the value a write returns when that write created the first draft (HTTP 201);
    False for a read and for a replace. Not part of what is stored."""


@dataclass(frozen=True, slots=True)
class DraftAuditEvent:
    """A class A event for one draft write: who, what changed, and the resulting hash."""

    at: datetime
    actor: str
    """``<issuer>#<subject>`` (:attr:`Principal.actor`): the same subject from two issuers is
    two actors."""
    tenant_id: str
    action: str
    before_hash: str | None
    """The draft hash before the write, None for the first draft."""
    resulting_hash: str
    diff: tuple[DiffEntry, ...]
    cross_tenant: bool = False
    """The write was made by a platform operator into a tenant other than their own."""
    operator: bool = False
    """The actor acted as a platform operator."""
    detail: dict[str, Any] | None = None
    """For ``draft.thresholds`` (M4-01): the decisions the write applied, one per rule, written
    in this same event so a decision and its draft write commit together."""

    def __post_init__(self) -> None:
        if self.action not in ACTIONS:
            raise ValueError(f"unknown draft action {self.action!r}")


class DraftConflictError(PolicyStoreError):
    """The draft is not at the ETag the write expected (HTTP 412). ``current`` is the ETag now,
    None when there is no draft."""

    def __init__(self, current: str | None) -> None:
        self.current = current
        super().__init__("the draft is not at the expected ETag")


class DraftStore(Protocol):
    """A tenant-scoped draft store. ``tenant_id`` must be the scope's tenant (else
    :class:`ScopeMismatchError`)."""

    async def get(self, tenant_id: str) -> StoredDraft | None: ...

    async def replace(
        self,
        tenant_id: str,
        document: bytes,
        *,
        expected_etag: str | None,
        event: DraftAuditEvent,
    ) -> StoredDraft:
        """Store ``document`` as the draft and the event, together, if the draft is at
        ``expected_etag`` (None: only if there is no draft yet). Raises
        :class:`DraftConflictError` otherwise, and stores neither."""
        ...

    async def audit_events(self, tenant_id: str) -> list[DraftAuditEvent]: ...


class ScopedDraftStores(Protocol):
    def scoped(self, scope: TenantScope) -> DraftStore: ...


@dataclass
class InMemoryDraftStore:
    """For tests and local runs. Holds every tenant's draft; hands out scoped views."""

    _drafts: dict[str, StoredDraft] = field(default_factory=dict)
    _events: list[DraftAuditEvent] = field(default_factory=list)
    fail_audit: bool = False
    """Test hook: make every write fail as if the audit write failed (nothing is stored)."""

    offboard_tables = ("tenant_drafts",)

    def offboard_tenant(
        self, tenant_id: str, table: str, limit: int, *, count_only: bool = False
    ) -> dict[str, int]:
        """M5-07: delete (or count) a terminated tenant's rows (see ``TenantDataHolder``)."""
        n = int(tenant_id in self._drafts)
        if not count_only and n:
            del self._drafts[tenant_id]
        return {table: n}

    def scoped(self, scope: TenantScope) -> DraftStore:
        if not isinstance(scope, TenantScope):
            raise TypeError("scoped() takes a TenantScope")
        return _ScopedMemoryDrafts(self, scope)


class _ScopedMemoryDrafts:
    def __init__(self, store: InMemoryDraftStore, scope: TenantScope) -> None:
        self._store = store
        self._scope = scope

    def _check(self, tenant_id: str) -> None:
        if tenant_id != self._scope.tenant_id:
            raise ScopeMismatchError()

    async def get(self, tenant_id: str) -> StoredDraft | None:
        self._check(tenant_id)
        return self._store._drafts.get(tenant_id)

    async def replace(
        self,
        tenant_id: str,
        document: bytes,
        *,
        expected_etag: str | None,
        event: DraftAuditEvent,
    ) -> StoredDraft:
        self._check(tenant_id)
        if event.tenant_id != tenant_id:
            raise ScopeMismatchError()
        current = self._store._drafts.get(tenant_id)
        if (current.etag if current else None) != expected_etag:
            raise DraftConflictError(current.etag if current else None)
        if self._store.fail_audit:
            raise ConnectionError("audit store down")
        stored = StoredDraft(
            tenant_id, document, '"' + event.resulting_hash + '"', datetime.now(UTC), event.actor,
            created=current is None,
        )  # fmt: skip
        # No await between the comparison and the writes: atomic on one loop.
        self._store._drafts[tenant_id] = stored
        self._store._events.append(event)
        return stored

    async def audit_events(self, tenant_id: str) -> list[DraftAuditEvent]:
        self._check(tenant_id)
        return [e for e in self._store._events if e.tenant_id == tenant_id]
