"""The tenant-managed tool registry and tool-description screening (M2-03).

A tenant's tools (name, description, read-only flag) are what the guard renders in the
untrusted tool section and what ``tool_call`` allows. The description is tenant-written free
text that later reaches the model as context, which is never re-judged, so it is screened **once,
when it is registered or edited** (R7.3(b) condition).

* **Names** are the registry's key and are printed on a trusted line of the rendered prompt, so
  a name with an instruction-like part (the slug denylist, split at ``.``, ``_`` and ``-``) is
  refused at registration (422) and filtered from the profile; screening sends ``<name>:
  <description>``.
* **Who.** ``PUT``/``DELETE`` ``/tools/{name}`` are guardrail_admin, ``GET /tools`` is viewer,
  ``POST /tools/{name}/review`` is guardrail_reviewer and approves or rejects a **held** entry. The
  submitter can't approve their own entry.
* **What is screened.** The description, as content at guard point ``tool_result``, against the
  floor's ``p__inj_direct``, ``p__inj_indirect`` and ``p__ai_addressed`` of the **newest
  released floor version in the catalog** (M7-05: a floor staged in the catalog but not released
  is not used), with the floor's own thresholds, through the same pipeline as the test
  endpoint (redaction, render, one decision call, fusion). The three questions are taken from the
  catalog, not from the tenant's bundle, so a tenant's overrides can't loosen them.
* **When.** Synchronously inside the ``PUT``, on create and when the description changes. An
  unchanged description is not screened again (a change of the read-only flag alone is saved).
* **Outcomes.** A **block** (any of the three at its block threshold, or the provider refusing
  the content) is refused with 422 ``tool_description_rejected``: the rule keys and actions, never
  a score, nothing stored but a class A row recording the attempt. An **escalate** saves the entry
  ``held`` (202 ``held_for_review``): it is not in the tenant's tool profile until a reviewer
  approves it. An **allow** saves it ``accepted``. A description that trips the harm-vocabulary
  tripwire is saved ``held`` (reason ``vocabulary``) **with no model call**.
* **Fail closed.** Any other outcome (the call failed, timed out, was rate-limited or refused
  by the gateway, the answer broke the contract, the engine is shutting down) is 503
  ``screening_unavailable`` with ``Retry-After``: nothing is saved or changed.
* **Cost and metering.** About 700 input tokens a screening (about $0.00007). Metered as usage
  class ``screen`` (``screen:tool_result``), lowest priority, and a consumer of the ``test``
  allowance (the gateway counts any non-production label other than the named consumers as
  ``test``), so non-production stays within 40%. Per tenant: one screening in flight (429
  ``screening_busy``) and at most 30 an hour (429 ``screening_rate``), per replica.
* **Only accepted entries reach the profile.** :class:`RegistryTools` is the directory's tool
  provider; a registry change announces ``guardrail.published`` (action ``tools``) so replicas
  reload the profile.

**Residual.** The limiter is per replica, so a tenant's ceiling is 30 an hour times the number
of replicas. A description is judged once: a tool whose server later changes what it returns is
the tool-result guard's business, not this screening's.
"""

from __future__ import annotations

import asyncio
import re
import time
from collections.abc import Callable, Sequence
from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from typing import Any, Protocol

from guardrail_engine.admin.service import (
    DecisionError,
    DraftError,
    DraftInvalidError,
    DraftServiceError,
    TenantUnavailableError,
    _scope_of,
)
from guardrail_engine.admin.tools import DraftEvaluator, EvaluatorUnavailableError
from guardrail_engine.admin.vocabulary import strings_tripwire
from guardrail_engine.authz.authorizer import AuthzDecision
from guardrail_engine.authz.model import Principal
from guardrail_engine.guard.policy_cache import FloorSpec, GuardPointPolicy
from guardrail_engine.guard.tenants import (
    TenantDirectory,
    TenantProfile,
    ToolInfo,
    denied_name_parts,
)
from guardrail_engine.guard.verdict import Decision, Reason
from guardrail_engine.policy.canonical import sha256_of
from guardrail_engine.policy.catalog import Catalog, PlatformSettings
from guardrail_engine.policy.compiler import CompiledRule
from guardrail_engine.policy.json_document import parse_json_text
from guardrail_engine.tenant_scope import TenantScope, issue_scope

PUT_TOOL = ("PUT", "/v1/tenants/{tid}/guardrails/tools/{name}")
DELETE_TOOL = ("DELETE", "/v1/tenants/{tid}/guardrails/tools/{name}")
LIST_TOOLS = ("GET", "/v1/tenants/{tid}/guardrails/tools")
REVIEW_TOOL = ("POST", "/v1/tenants/{tid}/guardrails/tools/{name}/review")

NAME_PATTERN = re.compile(r"[a-z0-9_.-]{1,64}")
MAX_DESCRIPTION_CHARS = 1_000
MAX_TOOLS = 200
MAX_BODY_BYTES = 4_000
SCREEN_RULES = ("p__inj_direct", "p__inj_indirect", "p__ai_addressed")
SCREEN_GUARD_POINT = "tool_result"
SCREEN_USAGE_CLASS = "screen"
SCREENS_PER_HOUR = 30
RETRY_AFTER_S = 30

ACCEPTED, HELD, REJECTED = "accepted", "held", "rejected"
STATUSES = (ACCEPTED, HELD, REJECTED)
HOLD_SCREENING, HOLD_VOCABULARY = "screening", "vocabulary"
ACTIONS = ("put", "delete", "screen_block", "approve", "reject")


# --------------------------------------------------------------------------- model


@dataclass(frozen=True, slots=True)
class PendingEdit:
    """An edit to an **approved** tool that is held for review. The approved description stays
    in force, and the tool stays registered, until the edit is approved (it replaces the
    description) or rejected (it is dropped): a tenant's edit never unregisters a tool its
    active version may name."""

    description: str
    read_only: bool
    description_hash: str
    hold_reason: str
    submitted_by: str
    submitted_at: datetime

    def __post_init__(self) -> None:
        if self.hold_reason not in (HOLD_SCREENING, HOLD_VOCABULARY):
            raise ValueError("not a valid hold reason")


@dataclass(frozen=True, slots=True)
class ToolEntry:
    name: str
    description: str
    read_only: bool
    status: str
    description_hash: str
    submitted_by: str
    submitted_at: datetime
    version: int = 1
    hold_reason: str | None = None
    reviewed_by: str | None = None
    reviewed_at: datetime | None = None
    pending: PendingEdit | None = None
    """A held edit waiting for review; only on an ``accepted`` entry."""

    def __post_init__(self) -> None:
        if not NAME_PATTERN.fullmatch(self.name) or self.status not in STATUSES:
            raise ValueError("not a valid tool entry")
        if self.pending is not None and self.status != ACCEPTED:
            raise ValueError("only an accepted tool has a pending edit")
        if self.hold_reason not in (None, HOLD_SCREENING, HOLD_VOCABULARY):
            raise ValueError("not a valid hold reason")

    def info(self) -> ToolInfo:
        return ToolInfo(self.name, self.description, self.read_only)


@dataclass(frozen=True, slots=True)
class ToolEvent:
    """A class A row for one change, or one refused attempt (AC-A2)."""

    at: datetime
    actor: str
    tenant_id: str
    action: str
    name: str
    description_hash: str | None = None
    status: str | None = None
    """The entry's status after the change (``None`` for a delete or a refused attempt)."""
    reason: str | None = None
    fired: tuple[tuple[str, str], ...] = ()
    """For a refused attempt: the (rule key, action) pairs that blocked it."""
    cross_tenant: bool = False
    operator: bool = False

    def __post_init__(self) -> None:
        if self.action not in ACTIONS:
            raise ValueError(f"unknown tool action {self.action!r}")


class ToolConflictError(DraftServiceError):
    """The entry changed since it was read (HTTP 409)."""


class ToolNotFoundError(DraftServiceError):
    """(HTTP 404)"""


class ToolNotHeldError(DraftServiceError):
    """Only a held entry, or an approved one with a held edit, is reviewed (HTTP 409)."""


class ToolInUseError(DraftServiceError):
    """The active version or a candidate names the tool in a tool allow-list: deleting it would
    leave that version unable to compile (HTTP 409). ``versions`` lists them as
    ``(version, "active" | "candidate")``."""

    def __init__(self, versions: Sequence[tuple[int, str]]) -> None:
        self.versions = tuple(versions)
        super().__init__("the tool is named by " + ", ".join(f"{r} v{v}" for v, r in versions))


class ToolUsage(Protocol):
    """Which published versions of a tenant name a tool (in a ``tool_allowlist``)."""

    async def versions_naming(self, scope: TenantScope, name: str) -> list[tuple[int, str]]: ...

    def exclusive(self, scope: TenantScope) -> AbstractAsyncContextManager[None]:
        """Hold off lifecycle writes for the block."""
        ...


class LifecycleToolUsage:
    """:class:`ToolUsage` over the lifecycle store: the active version and the candidate."""

    def __init__(self, lifecycle: Any) -> None:
        self._lifecycle = lifecycle  # ScopedLifecycleStores

    def exclusive(self, scope: TenantScope) -> AbstractAsyncContextManager[None]:
        return self._lifecycle.scoped(scope).exclusive(scope.tenant_id)

    async def versions_naming(self, scope: TenantScope, name: str) -> list[tuple[int, str]]:
        store = self._lifecycle.scoped(scope)
        state = await store.state(scope.tenant_id)
        roles = [(state.active, "active")] if state.active is not None else []
        if state.candidate is not None:
            roles.append((state.candidate.version, "candidate"))
        found: list[tuple[int, str]] = []
        for version, role in roles:
            document = await store.document(scope.tenant_id, version) or {}
            for config in (document.get("guard_points") or {}).values():
                if isinstance(config, dict) and name in (config.get("tool_allowlist") or ()):
                    found.append((version, role))
                    break
        return found


class ToolDescriptionChangedError(DraftServiceError):
    """The review named a description other than the entry's current one (HTTP 409)."""


class ToolVocabularyHoldError(DraftServiceError):
    """A vocabulary hold can't be approved by anyone: it was never screened (HTTP 409). It can
    be rejected, or replaced by an edit that passes screening."""


class ToolOperatorReviewError(DraftServiceError):
    """A platform operator can't approve a tenant's tool (HTTP 403)."""


class ToolSelfReviewError(DraftServiceError):
    """The submitter can't approve their own entry (HTTP 403)."""


class TooManyToolsError(DraftServiceError):
    """The tenant is at :data:`MAX_TOOLS` (HTTP 409)."""


class ToolDescriptionRejectedError(DraftServiceError):
    """Screening blocked the description (HTTP 422). ``rules`` are (key, action) pairs."""

    def __init__(self, rules: tuple[tuple[str, str], ...]) -> None:
        super().__init__("tool description rejected")
        self.rules = rules


class ScreeningUnavailableError(DraftServiceError):
    """The description could not be screened, so nothing was saved (HTTP 503)."""


class ScreeningLimitError(DraftServiceError):
    """Too many screenings (HTTP 429): ``code`` is ``screening_busy`` or ``screening_rate``."""

    def __init__(self, code: str, retry_after_s: int) -> None:
        super().__init__(code)
        self.code = code
        self.retry_after_s = retry_after_s


# --------------------------------------------------------------------------- store port


class ToolStore(Protocol):
    async def get(self, tenant_id: str, name: str) -> ToolEntry | None: ...

    async def list(self, tenant_id: str) -> list[ToolEntry]:
        """The tenant's entries, by name."""
        ...

    async def save(
        self, tenant_id: str, entry: ToolEntry, event: ToolEvent, *, expected_version: int | None
    ) -> None:
        """Insert (``expected_version`` None: the entry must not exist) or replace (the stored
        entry must be at ``expected_version``), with the class A event in the same step.
        Raises :class:`ToolConflictError`."""
        ...

    async def delete(
        self, tenant_id: str, name: str, event: ToolEvent, *, expected_version: int
    ) -> None: ...

    async def record(self, tenant_id: str, event: ToolEvent) -> None:
        """Append a class A event that changes no entry (a refused attempt)."""
        ...

    async def events(self, tenant_id: str) -> list[ToolEvent]: ...


class ScopedToolStores(Protocol):
    def scoped(self, scope: TenantScope) -> ToolStore: ...


@dataclass
class InMemoryToolStore:
    _entries: dict[tuple[str, str], ToolEntry] = field(default_factory=dict)
    _events: list[ToolEvent] = field(default_factory=list)
    fail_audit: bool = False
    """Test hook: the class A append fails, and the change must not happen."""

    offboard_tables = ("tenant_tools",)

    def offboard_tenant(
        self, tenant_id: str, table: str, limit: int, *, count_only: bool = False
    ) -> dict[str, int]:
        """M5-07: delete (or count) a terminated tenant's rows (see ``TenantDataHolder``)."""
        mine = [k for k in self._entries if k[0] == tenant_id]
        if not count_only:
            mine = mine[:limit]
            for k in mine:
                del self._entries[k]
        return {table: len(mine)}

    def scoped(self, scope: TenantScope) -> ToolStore:
        if not isinstance(scope, TenantScope):
            raise TypeError("scoped() takes a TenantScope")
        return _ScopedMemoryTools(self, scope)


class _ScopedMemoryTools:
    def __init__(self, store: InMemoryToolStore, scope: TenantScope) -> None:
        self._store = store
        self._scope = scope

    def _check(self, tenant_id: str) -> None:
        from guardrail_engine.store.port import ScopeMismatchError

        if tenant_id != self._scope.tenant_id:
            raise ScopeMismatchError()

    async def get(self, tenant_id: str, name: str) -> ToolEntry | None:
        self._check(tenant_id)
        return self._store._entries.get((tenant_id, name))

    async def list(self, tenant_id: str) -> list[ToolEntry]:
        self._check(tenant_id)
        return sorted(
            (e for (t, _), e in self._store._entries.items() if t == tenant_id),
            key=lambda e: e.name,
        )

    def _append(self, event: ToolEvent) -> None:
        if self._store.fail_audit:
            raise RuntimeError("class A append failed")
        self._store._events.append(event)

    async def save(
        self, tenant_id: str, entry: ToolEntry, event: ToolEvent, *, expected_version: int | None
    ) -> None:
        self._check(tenant_id)
        current = self._store._entries.get((tenant_id, entry.name))
        if (current is None) != (expected_version is None) or (
            current is not None and current.version != expected_version
        ):
            raise ToolConflictError("the tool changed")
        self._append(event)
        self._store._entries[(tenant_id, entry.name)] = entry

    async def delete(
        self, tenant_id: str, name: str, event: ToolEvent, *, expected_version: int
    ) -> None:
        self._check(tenant_id)
        current = self._store._entries.get((tenant_id, name))
        if current is None or current.version != expected_version:
            raise ToolConflictError("the tool changed")
        self._append(event)
        del self._store._entries[(tenant_id, name)]

    async def record(self, tenant_id: str, event: ToolEvent) -> None:
        self._check(tenant_id)
        self._append(event)

    async def events(self, tenant_id: str) -> list[ToolEvent]:
        self._check(tenant_id)
        return [e for e in self._store._events if e.tenant_id == tenant_id]


class RegistryTools:
    """The directory's tool provider: the tenant's **accepted** tools. A held or rejected entry
    is never in a profile. The tenant id is the one the directory is asked about, which every
    caller took from a verified context or an authorizer decision; this is the platform's read
    for that tenant (one of the modules allowed to issue a scope)."""

    def __init__(self, store: ScopedToolStores) -> None:
        self._store = store

    async def __call__(self, tenant_id: str) -> tuple[ToolInfo, ...]:
        scope = issue_scope(tenant_id)
        entries = await self._store.scoped(scope).list(tenant_id)
        return tuple(
            e.info() for e in entries if e.status == ACCEPTED and not denied_name_parts(e.name)
        )


# --------------------------------------------------------------------------- screening


@dataclass(frozen=True, slots=True)
class ScreenResult:
    outcome: str
    """``allow``, ``escalate``, ``block`` or ``unavailable``."""
    fired: tuple[tuple[str, str], ...] = ()


class ToolScreener:
    """Runs a description through the three floor questions. Never raises: anything that is
    not a clean allow, escalate or block is ``unavailable``."""

    def __init__(
        self, evaluator: DraftEvaluator, catalog: Catalog, settings: PlatformSettings
    ) -> None:
        self._evaluator = evaluator
        self._catalog = catalog
        self._settings = settings

    def policy(self, profile: TenantProfile) -> GuardPointPolicy | None:
        versions = [v for v in self._catalog.floor_versions() if self._catalog.is_released(v)]
        floor = self._catalog.floor(max(versions)) if versions else None
        if floor is None:
            return None
        rules = {r.key: r for r in floor.rules if r.key in SCREEN_RULES}
        if set(rules) != set(SCREEN_RULES):
            return None
        return GuardPointPolicy(
            tenant_id=profile.tenant_id,
            version=floor.version,
            bundle_hash=floor.content_hash(),
            guard_point=SCREEN_GUARD_POINT,
            questions={k: r.question for k, r in rules.items()},
            rules={
                k: CompiledRule(
                    key=k,
                    layer="floor",
                    source=floor.ref,
                    question_type=r.question.type,
                    block_at=r.block_at,
                    escalate_at=r.escalate_at,
                    mode="enforce",
                    severity="high",
                    fail_mode=self._settings.floor_fail_mode,
                    provisional=r.provisional,
                )
                for k, r in rules.items()
            },
            max_content_tokens=self._settings.default_max_content_tokens,
            profile=profile,
            floor_specs={
                k: FloorSpec(k, r.question, r.question.type, r.block_at, r.escalate_at)
                for k, r in rules.items()
            },
        )

    async def screen(self, scope: TenantScope, profile: TenantProfile, text: str) -> ScreenResult:
        policy = self.policy(profile)
        if policy is None:
            return ScreenResult("unavailable")
        try:
            verdict = await self._evaluator.evaluate(
                scope, policy, text, usage_class=SCREEN_USAGE_CLASS
            )
        except EvaluatorUnavailableError:
            return ScreenResult("unavailable")
        except asyncio.CancelledError:
            raise
        except Exception:
            return ScreenResult("unavailable")
        return classify(verdict)


def classify(verdict: Any) -> ScreenResult:
    if verdict.reason is Reason.PROVIDER_SAFETY:
        return ScreenResult("block", (("provider_safety", "block"),))
    if verdict.reason not in (Reason.POLICY, Reason.DETERMINISTIC, Reason.NO_QUESTIONS):
        return ScreenResult("unavailable")
    if verdict.reason is Reason.NO_QUESTIONS:
        return ScreenResult("unavailable")  # the three questions were not asked
    fired = tuple((f.key, str(f.action)) for f in verdict.fired if f.mode == "enforce")
    fired += tuple((h.rule, str(h.action)) for h in verdict.deterministic)
    if verdict.decision is Decision.BLOCK:
        return ScreenResult("block", fired)
    if verdict.decision is Decision.ESCALATE:
        return ScreenResult("escalate", fired)
    if verdict.decision is Decision.ALLOW:
        return ScreenResult("allow")
    return ScreenResult("unavailable")


class ScreeningLimiter:
    """Per tenant: one screening in flight and at most ``per_hour`` an hour (sliding window)."""

    def __init__(
        self, per_hour: int = SCREENS_PER_HOUR, clock: Callable[[], float] = time.monotonic
    ) -> None:
        self._per_hour = per_hour
        self._clock = clock
        self._inflight: set[str] = set()
        self._starts: dict[str, list[float]] = {}

    def acquire(self, tenant_id: str) -> None:
        if tenant_id in self._inflight:
            raise ScreeningLimitError("screening_busy", 5)
        now = self._clock()
        recent = [t for t in self._starts.get(tenant_id, []) if now - t < 3600]
        if len(recent) >= self._per_hour:
            raise ScreeningLimitError("screening_rate", max(1, int(3600 - (now - recent[0])) + 1))
        recent.append(now)
        self._starts[tenant_id] = recent
        self._inflight.add(tenant_id)

    def release(self, tenant_id: str) -> None:
        self._inflight.discard(tenant_id)


# --------------------------------------------------------------------------- the service


def parse_put(body: bytes) -> tuple[str, bool]:
    if len(body) > MAX_BODY_BYTES:
        raise DraftInvalidError([DraftError("tool.too_large", "$", "the body is too large")])
    doc, problems = parse_json_text(body)
    if problems:
        raise DraftInvalidError([DraftError(str(p.code), p.path, p.message) for p in problems])
    if not isinstance(doc, dict):
        raise DraftInvalidError([DraftError("tool.not_object", "$", "the body is an object")])
    errors = [
        DraftError("tool.unknown_field", f"$.{k}", "not a field of a tool")
        for k in sorted(set(doc) - {"description", "read_only"})
    ]
    description, read_only = doc.get("description"), doc.get("read_only", False)
    if (
        not isinstance(description, str)
        or not description.strip()
        or len(description) > MAX_DESCRIPTION_CHARS
    ):
        errors.append(
            DraftError(
                "tool.description",
                "$.description",
                f"text of 1 to {MAX_DESCRIPTION_CHARS} characters",
            )
        )
    if not isinstance(read_only, bool):
        errors.append(DraftError("tool.read_only", "$.read_only", "true or false"))
    if errors:
        raise DraftInvalidError(errors)
    return description, read_only


def parse_review(body: bytes) -> tuple[str, str]:
    doc, problems = parse_json_text(body)
    if problems or not isinstance(doc, dict) or len(body) > MAX_BODY_BYTES:
        raise DraftInvalidError([DraftError("tool.review", "$", "an object {decision, hash}")])
    errors = [
        DraftError("tool.unknown_field", f"$.{k}", "not a field of a review")
        for k in sorted(set(doc) - {"decision", "description_hash"})
    ]
    if doc.get("decision") not in ("approve", "reject"):
        errors.append(DraftError("tool.decision", "$.decision", "approve or reject"))
    digest = doc.get("description_hash")
    if not isinstance(digest, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        errors.append(DraftError("tool.description_hash", "$.description_hash", "a sha256 hash"))
    if errors:
        raise DraftInvalidError(errors)
    return doc["decision"], digest


def tool_name(name: str) -> str:
    if not isinstance(name, str) or not NAME_PATTERN.fullmatch(name):
        raise ToolNotFoundError()
    return name


def new_tool_name(name: str) -> str:
    """A name for a tool being registered: the pattern, and no instruction-like part, because
    the name is printed on a trusted line of the rendered prompt."""
    name = tool_name(name)
    if denied := denied_name_parts(name):
        raise DraftInvalidError(
            [DraftError("tool.name", "$.name", f"the name has instruction-like part(s) {denied}")]
        )
    return name


class ToolService:
    def __init__(
        self,
        store: ScopedToolStores,
        tenants: TenantDirectory,
        screener: ToolScreener,
        *,
        announce: Callable[[str], Any] | None = None,
        usage: ToolUsage | None = None,
        limiter: ScreeningLimiter | None = None,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        require_issuer: bool = False,
    ) -> None:
        self._store = store
        self._tenants = tenants
        self._screener = screener
        self._announce = announce
        self._usage = usage
        self._limiter = limiter or ScreeningLimiter()
        self._clock = clock
        self._require_issuer = require_issuer

    def _begin(self, decision: AuthzDecision, principal: Principal, endpoint: Any) -> TenantScope:
        scope = _scope_of(decision, endpoint)
        if self._require_issuer and principal.issuer is None:
            raise DecisionError("the principal has no issuer; the audit actor needs one")
        return scope

    def _event(
        self, scope: TenantScope, decision: AuthzDecision, principal: Principal, action: str,
        name: str, **fields: Any,
    ) -> ToolEvent:  # fmt: skip
        return ToolEvent(
            at=self._clock(),
            actor=principal.actor,
            tenant_id=scope.tenant_id,
            action=action,
            name=name,
            cross_tenant=decision.cross_tenant,
            operator=principal.platform_operator,
            **fields,
        )

    async def _changed(self, tenant_id: str) -> None:
        """After the commit: replicas reload the tenant's profile. Best effort; the directory
        cache TTL bounds it."""
        if self._announce is None:
            return
        try:
            result = self._announce(tenant_id)
            if asyncio.iscoroutine(result):
                await result
        except Exception:
            import logging

            logging.getLogger(__name__).exception("the tool change could not be announced")

    async def list(self, decision: AuthzDecision) -> list[ToolEntry]:
        scope = _scope_of(decision, LIST_TOOLS)
        return await self._store.scoped(scope).list(scope.tenant_id)

    async def put(
        self, decision: AuthzDecision, principal: Principal, name: str, body: bytes
    ) -> tuple[ToolEntry, bool]:
        """Register or edit a tool. Returns the entry and whether it was created. Raises
        :class:`ToolDescriptionRejectedError`, :class:`ScreeningUnavailableError` or
        :class:`ScreeningLimitError` as described in the module docstring."""
        scope = self._begin(decision, principal, PUT_TOOL)
        name = new_tool_name(name)
        description, read_only = parse_put(body)
        store = self._store.scoped(scope)
        existing = await store.get(scope.tenant_id, name)
        digest = sha256_of(description)
        now = self._clock()
        if existing is not None and existing.description_hash == digest:
            if existing.read_only == read_only and existing.pending is None:
                return existing, False  # nothing to change, nothing to screen
            # The approved description again: it also withdraws a held edit.
            entry = replace(
                existing, read_only=read_only, pending=None, version=existing.version + 1
            )
            event = self._event(
                scope, decision, principal, "put", name, description_hash=digest,
                status=entry.status, reason=entry.hold_reason,
            )  # fmt: skip
            await store.save(scope.tenant_id, entry, event, expected_version=existing.version)
            await self._changed(scope.tenant_id)
            return entry, False
        if existing is None and len(await store.list(scope.tenant_id)) >= MAX_TOOLS:
            raise TooManyToolsError()
        status, hold, fired = ACCEPTED, None, ()
        if strings_tripwire(description):
            status, hold = HELD, HOLD_VOCABULARY  # no model call: it would be sent to the provider
        else:
            profile = await self._tenants.get(scope.tenant_id)
            if profile is None:
                raise TenantUnavailableError()
            self._limiter.acquire(scope.tenant_id)
            try:
                result = await self._screener.screen(scope, profile, f"{name}: {description}")
            finally:
                self._limiter.release(scope.tenant_id)
            if result.outcome == "unavailable":
                raise ScreeningUnavailableError()
            if result.outcome == "block":
                await store.record(
                    scope.tenant_id,
                    self._event(
                        scope,
                        decision,
                        principal,
                        "screen_block",
                        name,
                        description_hash=digest,
                        fired=result.fired,
                    ),
                )
                raise ToolDescriptionRejectedError(result.fired)
            if result.outcome == "escalate":
                status, hold = HELD, HOLD_SCREENING
        if existing is not None and existing.status == ACCEPTED and status == HELD:
            # An edit to an approved tool is held for review: the approved description stays in
            # force and the tool stays registered (the active version may name it). Only a
            # brand-new tool, or one that was never approved, is held unregistered.
            assert hold is not None
            entry = replace(
                existing,
                pending=PendingEdit(description, read_only, digest, hold, principal.actor, now),
                version=existing.version + 1,
            )
        else:
            entry = ToolEntry(
                name=name, description=description, read_only=read_only, status=status,
                description_hash=digest, submitted_by=principal.actor, submitted_at=now,
                version=1 if existing is None else existing.version + 1, hold_reason=hold,
            )  # fmt: skip
        event = self._event(
            scope, decision, principal, "put", name, description_hash=digest, status=status,
            reason=hold, fired=fired,
        )  # fmt: skip
        await store.save(
            scope.tenant_id, entry, event,
            expected_version=None if existing is None else existing.version,
        )  # fmt: skip
        await self._changed(scope.tenant_id)
        return entry, existing is None

    async def delete(self, decision: AuthzDecision, principal: Principal, name: str) -> None:
        scope = self._begin(decision, principal, DELETE_TOOL)
        name = tool_name(name)
        store = self._store.scoped(scope)
        existing = await store.get(scope.tenant_id, name)
        if existing is None:
            raise ToolNotFoundError()
        event = self._event(
            scope, decision, principal, "delete", name, description_hash=existing.description_hash
        )
        if self._usage is None:
            await store.delete(scope.tenant_id, name, event, expected_version=existing.version)
            await self._changed(scope.tenant_id)
            return
        # The usage check and the delete happen under the tenant's lifecycle lock, so no publish
        # or promotion commits between them. After the delete the check is made again:
        # a lifecycle write that got in anyway (the in-memory store holds no lock) puts the tool
        # back and the delete is refused. A publish that validated its allow-list before the
        # delete and commits after it is the residual: the engine goes on serving the compiled
        # version, and registering the tool again restores the profile.
        async with self._usage.exclusive(scope):
            if named := await self._usage.versions_naming(scope, name):
                raise ToolInUseError(named)
            await store.delete(scope.tenant_id, name, event, expected_version=existing.version)
            if named := await self._usage.versions_naming(scope, name):
                restored = replace(existing, version=existing.version + 1)
                await store.save(
                    scope.tenant_id,
                    restored,
                    self._event(
                        scope, decision, principal, "put", name,
                        description_hash=existing.description_hash, status=existing.status,
                    ),
                    expected_version=None,
                )  # fmt: skip
                await self._changed(scope.tenant_id)
                raise ToolInUseError(named)
        await self._changed(scope.tenant_id)

    async def review(
        self, decision: AuthzDecision, principal: Principal, name: str, body: bytes
    ) -> ToolEntry:
        scope = self._begin(decision, principal, REVIEW_TOOL)
        name = tool_name(name)
        verdict, digest = parse_review(body)
        store = self._store.scoped(scope)
        entry = await store.get(scope.tenant_id, name)
        if entry is None:
            raise ToolNotFoundError()
        pending = entry.pending
        if pending is None and entry.status != HELD:
            raise ToolNotHeldError()
        # What is under review: the held edit of an approved tool, or a tool never approved.
        held_hash = pending.description_hash if pending is not None else entry.description_hash
        hold_reason = pending.hold_reason if pending is not None else entry.hold_reason
        submitted_by = pending.submitted_by if pending is not None else entry.submitted_by
        if held_hash != digest:
            raise ToolDescriptionChangedError()
        if verdict == "approve":
            if hold_reason == HOLD_VOCABULARY:
                raise ToolVocabularyHoldError()  # never screened: an edit must pass screening
            if principal.platform_operator:
                raise ToolOperatorReviewError()  # R2's rule: no operator approval of tenant content
            if submitted_by == principal.actor:
                raise ToolSelfReviewError()
        now = self._clock()
        if pending is not None:
            # An approved tool's held edit: approving replaces the description; rejecting drops
            # the edit and the approved description goes on. The tool is registered throughout.
            if verdict == "approve":
                updated = replace(
                    entry, description=pending.description, read_only=pending.read_only,
                    description_hash=pending.description_hash, submitted_by=pending.submitted_by,
                    submitted_at=pending.submitted_at, pending=None, reviewed_by=principal.actor,
                    reviewed_at=now, version=entry.version + 1,
                )  # fmt: skip
            else:
                updated = replace(
                    entry, pending=None, reviewed_by=principal.actor, reviewed_at=now,
                    version=entry.version + 1,
                )  # fmt: skip
        else:
            updated = replace(
                entry, status=ACCEPTED if verdict == "approve" else REJECTED, hold_reason=None,
                reviewed_by=principal.actor, reviewed_at=now, version=entry.version + 1,
            )  # fmt: skip
        event = self._event(
            scope, decision, principal, "approve" if verdict == "approve" else "reject", name,
            description_hash=digest, status=updated.status, reason=hold_reason,
        )  # fmt: skip
        await store.save(scope.tenant_id, updated, event, expected_version=entry.version)
        await self._changed(scope.tenant_id)
        return updated


def entry_json(e: ToolEntry) -> dict[str, Any]:
    return {
        "name": e.name,
        "description": e.description,
        "read_only": e.read_only,
        "status": e.status,
        "hold_reason": e.hold_reason,
        "description_hash": e.description_hash,
        "submitted_by": e.submitted_by,
        "submitted_at": e.submitted_at.isoformat(),
        "reviewed_by": e.reviewed_by,
        "reviewed_at": None if e.reviewed_at is None else e.reviewed_at.isoformat(),
        "version": e.version,
        "pending": None
        if e.pending is None
        else {
            "description": e.pending.description,
            "read_only": e.pending.read_only,
            "description_hash": e.pending.description_hash,
            "hold_reason": e.pending.hold_reason,
            "submitted_by": e.pending.submitted_by,
            "submitted_at": e.pending.submitted_at.isoformat(),
        },
    }


__all__ = [
    "ACCEPTED",
    "DELETE_TOOL",
    "HELD",
    "LIST_TOOLS",
    "MAX_TOOLS",
    "PUT_TOOL",
    "REJECTED",
    "REVIEW_TOOL",
    "SCREEN_RULES",
    "InMemoryToolStore",
    "LifecycleToolUsage",
    "PendingEdit",
    "RegistryTools",
    "ScopedToolStores",
    "ScreenResult",
    "ScreeningLimitError",
    "ScreeningLimiter",
    "ScreeningUnavailableError",
    "TooManyToolsError",
    "ToolConflictError",
    "ToolDescriptionChangedError",
    "ToolDescriptionRejectedError",
    "ToolEntry",
    "ToolEvent",
    "ToolInUseError",
    "ToolNotFoundError",
    "ToolNotHeldError",
    "ToolScreener",
    "ToolSelfReviewError",
    "ToolService",
    "ToolStore",
    "ToolUsage",
    "classify",
    "entry_json",
]  # fmt: skip
