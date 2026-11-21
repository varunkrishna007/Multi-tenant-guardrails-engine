"""The version lifecycle's state, events and storage port (M2-07).

A tenant has at most one **active** version and at most one **candidate** (PF-7). Versions are
immutable and numbered per tenant. The state machine, in full:

* ``publish`` makes a new version from the draft. It becomes the candidate with a ``mode``
  (``shadow`` or ``enforce``) and a ``rollout_percent``. **Exception, the first publish of a
  tenant** (no active version): it must be ``enforce`` at 100% and becomes active directly,
  because with no active version every check is ``policy_unavailable``. A shadow first publish is
  refused (``NoActiveVersionError``): there is nothing to shadow.
* A publish while a candidate exists is refused (``CandidateExistsError``): promote or abandon it.
* ``set_percent`` changes the candidate's share of conversations (1 to 100).
* ``promote`` makes the candidate the active version at 100%. A shadow candidate is promoted to
  ``enforce``, so the enforce gates run.
* ``abandon`` drops the candidate; its version stays stored.
* ``rollback`` makes an earlier stored version active **and abandons any candidate**.

Every transition is one atomic step in the store together with its class A event
(:class:`PublishEvent`), by compare-and-set on the state the caller saw
(:class:`StateConflictError` when it moved). The runtime half, a candidate deciding or shadowing
a share of conversations, is M4-03: the Guard Service reads only the active version.

After a commit the service publishes ``guardrail.published`` on a :class:`PublishBus`; replicas
invalidate their policy caches on it, and the pointer TTL bounds staleness if it is dropped.
"""

from __future__ import annotations

import contextlib
import logging
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Protocol

from guardrail_engine.admin.approvals import ApprovalUse, InMemoryApprovalStore
from guardrail_engine.admin.service import DraftServiceError
from guardrail_engine.policy.canonical import sha256_of
from guardrail_engine.policy.diff import DiffEntry
from guardrail_engine.policy.document import ParsedBundle
from guardrail_engine.store.port import PolicyStore, ScopedPolicyStores, ScopeMismatchError
from guardrail_engine.tenant_scope import TenantScope

logger = logging.getLogger(__name__)

MODES = ("shadow", "enforce")
ACTIONS = ("publish", "set_percent", "promote", "abandon", "rollback")
EVENT_ACTIONS = (*ACTIONS, "tools", "floor")
"""What a ``guardrail.published`` event may carry: a lifecycle action, ``tools`` (the tenant's
tool registry changed, M2-03) or ``floor`` (the platform's floor releases or minimum changed,
M2-09; the tenant is ``t_platform``): both with version 0."""
MAX_NOTE_CHARS = 500


# --------------------------------------------------------------------------- state


@dataclass(frozen=True, slots=True)
class Candidate:
    version: int
    mode: str
    rollout_percent: int
    at: datetime
    actor: str


@dataclass(frozen=True, slots=True)
class LifecycleState:
    active: int | None = None
    candidate: Candidate | None = None


@dataclass(frozen=True, slots=True)
class RuleSnapshot:
    """One tenant rule of a published version, for the shadow soak: its id, its own mode and a
    fingerprint of what it says. An edit changes the fingerprint and so restarts the soak."""

    id: str
    mode: str
    fingerprint: str


def rule_snapshots(document: dict[str, Any]) -> tuple[RuleSnapshot, ...]:
    out = []
    for rule in document.get("rules", []):
        if not isinstance(rule, dict) or not isinstance(rule.get("id"), str):
            continue
        out.append(
            RuleSnapshot(
                rule["id"],
                str(rule.get("mode", "enforce")),
                sha256_of(
                    {
                        "question": rule.get("question"),
                        "true_description": rule.get("true_description"),
                        "false_description": rule.get("false_description"),
                        "block_at": rule.get("block_at"),
                        "escalate_at": rule.get("escalate_at"),
                        "guard_points": sorted(rule.get("guard_points", [])),
                    }
                ),
            )
        )
    return tuple(out)


@dataclass(frozen=True, slots=True)
class PublishEvent:
    """A class A event for one lifecycle transition (AC-A2): who, what changed, the hashes."""

    at: datetime
    actor: str
    tenant_id: str
    action: str
    version: int
    """The version acted on: the new one for ``publish``, the candidate for the candidate
    actions, the target for ``rollback``."""
    from_version: int | None = None
    """The active version before the transition (``publish`` that goes active, ``promote``,
    ``rollback``)."""
    mode: str | None = None
    rollout_percent: int | None = None
    bundle_hash: str | None = None
    draft_hash: str | None = None
    diff: tuple[DiffEntry, ...] = ()
    note: str = ""
    rules: tuple[RuleSnapshot, ...] = ()
    cross_tenant: bool = False
    operator: bool = False
    becomes_active: bool = False
    abandoned_candidate: int | None = None
    """A ``rollback`` also drops the candidate: its version, if there was one."""
    repin_floor: int | None = None
    """Set only by the floor re-pin code path (M2-09): this version moves the bundle to that
    floor version (a platform re-pin candidate, its promotion, or a rollback that was re-pinned
    on the fly). No tenant route can set it."""
    repin_drops: tuple[dict[str, Any], ...] = ()
    """The floor overrides the re-pin dropped, with the old and the new floor value."""

    def __post_init__(self) -> None:
        if self.action not in ACTIONS:
            raise ValueError(f"unknown lifecycle action {self.action!r}")
        if self.mode is not None and self.mode not in MODES:
            raise ValueError(f"unknown mode {self.mode!r}")


@dataclass(frozen=True, slots=True)
class VersionEntry:
    version: int
    bundle_hash: str
    created_at: datetime


@dataclass(frozen=True, slots=True)
class GuardrailPublished:
    """The ``guardrail.published`` event: published after a lifecycle write commits."""

    tenant_id: str
    version: int
    action: str
    mode: str | None = None
    """``shadow`` or ``enforce`` for a ``publish``; None when the action has no mode."""
    active: bool | None = None
    """Whether the version became the tenant's active one: True for a first publish, a promote
    and a rollback, False for a candidate. None when unknown or not meaningful, so the
    block-rate detector (which reads this) treats None as "can't tell", never as shadow."""
    at: float | None = None
    """When the change committed, epoch seconds, so every replica agrees on a watch window."""


# --------------------------------------------------------------------------- errors


class CandidateExistsError(DraftServiceError):
    """A candidate is already waiting: promote or abandon it first (HTTP 409)."""


class NoCandidateError(DraftServiceError):
    """There is no candidate to change (HTTP 409)."""


class NoActiveVersionError(DraftServiceError):
    """The tenant has no active version, so its first publish must be ``enforce`` at 100%
    (HTTP 409)."""


class AlreadyActiveError(DraftServiceError):
    """The version is already the active one (HTTP 409)."""


class NotPreviouslyActiveError(DraftServiceError):
    """A rollback to a version that has never been active (HTTP 409): it never passed the
    enforce gates, so only promotion (which runs them) can make it active."""


class StateConflictError(DraftServiceError):
    """The tenant's lifecycle state moved since it was read (HTTP 409): read it again."""


class ApprovalRequiredError(DraftServiceError):
    """Enforcing needs two-person approval for this tenant, which does not exist yet (M5-02), so
    it is refused rather than let through (HTTP 409)."""


class GoldenUnavailableError(DraftServiceError):
    """The evidence gate needs the golden sets and none are configured (HTTP 503)."""


# --------------------------------------------------------------------------- the port


class LifecycleStore(Protocol):
    """A tenant-scoped lifecycle store. ``tenant_id`` must be the scope's tenant (else
    :class:`ScopeMismatchError`). Every write is atomic with its event and is a compare-and-set
    on ``expected`` (raising :class:`StateConflictError`)."""

    async def state(self, tenant_id: str) -> LifecycleState: ...

    async def versions(self, tenant_id: str) -> list[VersionEntry]:
        """Every stored version, oldest first."""
        ...

    async def document(self, tenant_id: str, version: int) -> dict[str, Any] | None: ...

    def exclusive(self, tenant_id: str) -> AbstractAsyncContextManager[None]:
        """Hold the tenant's lifecycle lock (the one every lifecycle write takes) for the
        block: no publish, promotion or rollback commits meanwhile. For a check-then-act that
        must not race one, such as deleting a tool no published version names. The Postgres
        store holds the advisory lock in a transaction; the in-memory store is single-process
        and serialises nothing here."""
        ...

    async def events(self, tenant_id: str) -> list[PublishEvent]:
        """The tenant's class A lifecycle events, oldest first."""
        ...

    async def publish(
        self,
        tenant_id: str,
        parsed: ParsedBundle,
        bundle_hash: str,
        *,
        candidate: Candidate | None,
        expected: LifecycleState,
        event: PublishEvent,
        approval: ApprovalUse | None = None,
    ) -> None:
        """Store the version and either make it the candidate or (``candidate`` None and
        ``event.becomes_active``) the active version. With ``approval`` (M5-02) the approval is
        checked and consumed in the same transaction, under the same lock: a publish that fails
        does not spend it, and two publishes can't both use it."""
        ...

    async def set_percent(
        self, tenant_id: str, percent: int, *, expected: LifecycleState, event: PublishEvent
    ) -> None: ...

    async def promote(
        self,
        tenant_id: str,
        *,
        expected: LifecycleState,
        event: PublishEvent,
        approval: ApprovalUse | None = None,
    ) -> None:
        """As :meth:`publish` for the approval (M5-02)."""
        ...

    async def abandon(
        self, tenant_id: str, *, expected: LifecycleState, event: PublishEvent
    ) -> None: ...

    async def rollback(
        self, tenant_id: str, target: int, *, expected: LifecycleState, event: PublishEvent
    ) -> None: ...

    async def activate_new(
        self,
        tenant_id: str,
        parsed: ParsedBundle,
        bundle_hash: str,
        *,
        expected: LifecycleState,
        event: PublishEvent,
    ) -> None:
        """Store ``parsed`` as a new version, make it the active one and drop any candidate, in
        one step with ``event``: a rollback that had to be re-pinned (M2-09, R5.6)."""
        ...


class ScopedLifecycleStores(Protocol):
    def scoped(self, scope: TenantScope) -> LifecycleStore: ...


class PublishBus(Protocol):
    async def publish(self, event: GuardrailPublished) -> None: ...


class InMemoryPublishBus:
    """Subscribers are called in order; one that raises does not stop the others."""

    def __init__(self) -> None:
        self.published: list[GuardrailPublished] = []
        self._subscribers: list[Callable[[GuardrailPublished], Awaitable[None] | None]] = []
        self.drop = False
        """Test hook: lose every event, as a real transport can."""

    def subscribe(self, fn: Callable[[GuardrailPublished], Awaitable[None] | None]) -> None:
        self._subscribers.append(fn)

    async def publish(self, event: GuardrailPublished) -> None:
        self.published.append(event)
        if self.drop:
            return
        for fn in self._subscribers:
            try:
                result = fn(event)
                if result is not None:
                    await result
            except Exception:
                logger.exception("a guardrail.published subscriber failed")


# --------------------------------------------------------------------------- memory store


@dataclass
class InMemoryLifecycleStore:
    """For tests and local runs. Bundles and the active pointer live in the given policy store,
    so a Guard Service built on that store sees what is published."""

    policies: ScopedPolicyStores
    _candidates: dict[str, Candidate] = field(default_factory=dict)
    _events: list[PublishEvent] = field(default_factory=list)
    approvals: InMemoryApprovalStore | None = None
    """Where a publish or promotion consumes its two-person approval (M5-02); required to pass
    one."""

    offboard_tables = ("tenant_candidates",)

    def offboard_tenant(
        self, tenant_id: str, table: str, limit: int, *, count_only: bool = False
    ) -> dict[str, int]:
        """M5-07: delete (or count) a terminated tenant's rows (see ``TenantDataHolder``)."""
        n = int(tenant_id in self._candidates)
        if not count_only and n:
            del self._candidates[tenant_id]
        return {table: n}

    def scoped(self, scope: TenantScope) -> LifecycleStore:
        if not isinstance(scope, TenantScope):
            raise TypeError("scoped() takes a TenantScope")
        return _ScopedMemoryLifecycle(self, scope)


class _ScopedMemoryLifecycle:
    def __init__(self, store: InMemoryLifecycleStore, scope: TenantScope) -> None:
        self._store = store
        self._scope = scope
        self._policies: PolicyStore = store.policies.scoped(scope)

    def _check(self, tenant_id: str) -> None:
        if tenant_id != self._scope.tenant_id:
            raise ScopeMismatchError()

    async def state(self, tenant_id: str) -> LifecycleState:
        self._check(tenant_id)
        return LifecycleState(
            await self._policies.get_active_version(tenant_id),
            self._store._candidates.get(tenant_id),
        )

    async def _expect(self, tenant_id: str, expected: LifecycleState) -> None:
        if await self.state(tenant_id) != expected:
            raise StateConflictError()

    async def versions(self, tenant_id: str) -> list[VersionEntry]:
        self._check(tenant_id)
        return [
            VersionEntry(v.version, v.bundle_hash, v.created_at)
            for v in await self._policies.list_versions(tenant_id)
        ]

    async def document(self, tenant_id: str, version: int) -> dict[str, Any] | None:
        self._check(tenant_id)
        try:
            return (await self._policies.get_version(tenant_id, version)).document
        except Exception:
            return None

    @contextlib.asynccontextmanager
    async def exclusive(self, tenant_id: str) -> AsyncIterator[None]:
        self._check(tenant_id)
        yield

    async def events(self, tenant_id: str) -> list[PublishEvent]:
        self._check(tenant_id)
        return [e for e in self._store._events if e.tenant_id == tenant_id]

    def _record(self, tenant_id: str, event: PublishEvent) -> None:
        if event.tenant_id != tenant_id:
            raise ScopeMismatchError()
        self._store._events.append(event)

    async def _spend(self, tenant_id: str, approval: ApprovalUse | None) -> Any:
        """Consume the approval before the write and give it back if the write fails (the
        Postgres store does this with one transaction)."""
        if approval is None:
            return None
        approvals = self._store.approvals
        if approvals is None:
            raise RuntimeError("this lifecycle store was built without an approval store")
        return approvals.consume(tenant_id, approval)

    def _give_back(self, tenant_id: str, previous: Any) -> None:
        if previous is not None and self._store.approvals is not None:
            self._store.approvals.restore(tenant_id, previous)

    async def publish(
        self,
        tenant_id: str,
        parsed: ParsedBundle,
        bundle_hash: str,
        *,
        candidate: Candidate | None,
        expected: LifecycleState,
        event: PublishEvent,
        approval: ApprovalUse | None = None,
    ) -> None:
        self._check(tenant_id)
        previous = await self._spend(tenant_id, approval)
        try:
            await self._publish(
                tenant_id, parsed, bundle_hash,
                candidate=candidate, expected=expected, event=event,
            )  # fmt: skip
        except BaseException:
            self._give_back(tenant_id, previous)
            raise

    async def promote(
        self,
        tenant_id: str,
        *,
        expected: LifecycleState,
        event: PublishEvent,
        approval: ApprovalUse | None = None,
    ) -> None:
        self._check(tenant_id)
        previous = await self._spend(tenant_id, approval)
        try:
            await self._promote(tenant_id, expected=expected, event=event)
        except BaseException:
            self._give_back(tenant_id, previous)
            raise

    async def _publish(
        self,
        tenant_id: str,
        parsed: ParsedBundle,
        bundle_hash: str,
        *,
        candidate: Candidate | None,
        expected: LifecycleState,
        event: PublishEvent,
    ) -> None:
        self._check(tenant_id)
        await self._expect(tenant_id, expected)
        version = parsed.bundle.version
        if any(v.version == version for v in await self._policies.list_versions(tenant_id)):
            raise StateConflictError()  # another publish took the number
        await self._policies.put_version(tenant_id, parsed, bundle_hash=bundle_hash)
        if candidate is not None:
            self._store._candidates[tenant_id] = candidate
        else:
            await self._policies.set_active_version(
                tenant_id, version, expected_current=expected.active
            )
        self._record(tenant_id, event)

    async def set_percent(
        self, tenant_id: str, percent: int, *, expected: LifecycleState, event: PublishEvent
    ) -> None:
        self._check(tenant_id)
        await self._expect(tenant_id, expected)
        assert expected.candidate is not None
        c = expected.candidate
        self._store._candidates[tenant_id] = Candidate(c.version, c.mode, percent, c.at, c.actor)
        self._record(tenant_id, event)

    async def _promote(
        self, tenant_id: str, *, expected: LifecycleState, event: PublishEvent
    ) -> None:
        self._check(tenant_id)
        await self._expect(tenant_id, expected)
        assert expected.candidate is not None
        await self._policies.set_active_version(
            tenant_id, expected.candidate.version, expected_current=expected.active
        )
        del self._store._candidates[tenant_id]
        self._record(tenant_id, event)

    async def abandon(
        self, tenant_id: str, *, expected: LifecycleState, event: PublishEvent
    ) -> None:
        self._check(tenant_id)
        await self._expect(tenant_id, expected)
        self._store._candidates.pop(tenant_id, None)
        self._record(tenant_id, event)

    async def rollback(
        self, tenant_id: str, target: int, *, expected: LifecycleState, event: PublishEvent
    ) -> None:
        self._check(tenant_id)
        await self._expect(tenant_id, expected)
        await self._policies.set_active_version(
            tenant_id, target, expected_current=expected.active
        )  # verifies the target loads before the pointer moves
        self._store._candidates.pop(tenant_id, None)
        self._record(tenant_id, event)

    async def activate_new(
        self,
        tenant_id: str,
        parsed: ParsedBundle,
        bundle_hash: str,
        *,
        expected: LifecycleState,
        event: PublishEvent,
    ) -> None:
        self._check(tenant_id)
        await self._expect(tenant_id, expected)
        version = parsed.bundle.version
        if any(v.version == version for v in await self._policies.list_versions(tenant_id)):
            raise StateConflictError()
        await self._policies.put_version(tenant_id, parsed, bundle_hash=bundle_hash)
        await self._policies.set_active_version(
            tenant_id, version, expected_current=expected.active
        )
        self._store._candidates.pop(tenant_id, None)
        self._record(tenant_id, event)
