"""Compiled policy, cached per ``(tenant, version, guard_point)`` (AC-C3), with a
last-known-good fallback (AC-G4, design §Ops, Failure modes).

**Layout.** Entries are indexed by tenant: each tenant holds one compiled version (the
newest one that loaded and compiled) with one entry per guard point. A lookup is
``tenant -> version -> guard_point``, and a refresh touches only its own tenant's entry (no
scan over other tenants).

**Lookup.** For a check on ``(tenant, guard_point)``:

1. **Fresh** (within ``pointer_ttl_s`` of the last refresh): the cached entry is returned
   with no store call and **no compile work** (``compiles`` doesn't move).
2. **Stale** (the TTL expired) with an entry cached: the entry is returned **at once**, and
   one background refresh per tenant is started (stale-while-revalidate). So a slow or
   hanging store never adds latency to checks once a tenant has a policy.
3. **Cold** (nothing cached yet) or **invalidated**: the check refreshes synchronously,
   under a per-tenant lock, so concurrent misses compile once. A check that waited for the
   lock while another check's refresh ran takes that refresh's outcome instead of starting
   its own (unless ``invalidate`` was called meanwhile), so concurrent checks share one
   refresh whether it found a policy, an absence or a failure.

**A refresh** reads the active-version pointer and the tenant's profile from the directory.
If the version and profile are the ones already compiled, nothing more happens. Otherwise
the version is loaded (``get_version`` re-verifies its hash) and compiled, so a platform-ops
change to the tenant's domain or tool registry takes effect at the next refresh, without a
publish. Every store and directory call is bounded by ``store_timeout_s``.

``invalidate(tenant)`` makes the next check refresh synchronously; it is what a
``guardrail.published`` event will call (M2-07). Without it a publish or rollback takes
effect within ``pointer_ttl_s`` plus one refresh (PF-13 bounds the TTL at 60 s).

**Expected floor.** With each version the cache records, per guard point,
the floor rules that cover it as the catalog defines them (question, question type,
``block_at``, ``escalate_at``), derived from the floor version named in the bundle's own
``extends`` and the catalog, independently of the compiler's output. The Guard Service checks
every compiled floor rule against them (and its fail mode against the platform's
``floor_fail_mode``) and fails closed on any mismatch.

**Last-known-good.** If a refresh fails (the store or directory raises or times out, the
active version fails verification, the pointer names a missing version, or the version
doesn't compile) and the tenant has a compiled version, that version is served, marked
``LAST_KNOWN_GOOD`` with the error, and the refresh is retried after ``pointer_ttl_s``. If
there is none, :class:`PolicyUnavailable` is raised, naming the failure, and the Guard
Service blocks without calling the model. A failure with nothing compiled is not remembered:
the next check (or group of concurrent checks) tries the store again, so a tenant is served
as soon as the store recovers.

**Authoritative absence is not an outage.** When the store answers that the tenant
has no active version, or the directory answers that the tenant doesn't exist (suspended,
offboarded), the tenant's compiled policy is dropped, last-known-good included, and its
checks get ``policy_unavailable`` until a refresh finds a policy again. The answer is
remembered for ``pointer_ttl_s``, so those checks don't each hit the store. Only a failure
(a timeout, an error, a failed verification or compile) falls back to last-known-good. A
failure while the tenant is remembered as absent replaces that answer: the store
no longer says the tenant is absent, it says nothing, so the tenant is treated like any
tenant with nothing compiled during an outage (``policy_unavailable`` naming the failure,
retried at the next check), not as still suspended.

Known limits of last-known-good, during an outage only:

* It lives in this process's memory: a restart while the store is down starts with none.
* **It can serve a version that was just rolled back.** If v2 is cached, an operator rolls
  back to v1, and v1 can't be loaded (store down, verification fails), v2 keeps being
  served until a refresh succeeds. This is an availability trade-off, not a floor loss: the
  floor is platform content and every served version carries it. It is logged at error
  level, naming both the served version and the pointer's, whenever they differ.
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Protocol, TypeVar

from guardrail_engine.decision.types import Question
from guardrail_engine.deterministic.rules import NO_CHECKS, GuardPointChecks
from guardrail_engine.guard.tenants import TenantDirectory, TenantProfile, profile_problem
from guardrail_engine.guard.verdict import PolicySource
from guardrail_engine.policy.catalog import (
    Catalog,
    PlatformSettings,
    TenantAttributes,
    ToolRegistry,
)
from guardrail_engine.policy.compiler import CompiledPolicy, CompiledRule, PolicyCompiler
from guardrail_engine.policy.document import EXTENDS_REF_PATTERN, ParsedBundle
from guardrail_engine.policy.errors import PolicyInvalidError
from guardrail_engine.store.port import BundleIntegrityError, PolicyStore, ScopedPolicyStores
from guardrail_engine.tenant_scope import TenantScope

logger = logging.getLogger(__name__)

DEFAULT_POINTER_TTL_S = 5.0
DEFAULT_STORE_TIMEOUT_S = 0.25

T = TypeVar("T")


class Compiler(Protocol):
    def compile(self, bundle: ParsedBundle, tenant: TenantAttributes) -> CompiledPolicy: ...


CompilerFactory = Callable[[Catalog, ToolRegistry, PlatformSettings], Compiler]


@dataclass(frozen=True, slots=True)
class GuardPointPolicy:
    """What one cache entry holds: one guard point of one compiled version."""

    tenant_id: str
    version: int
    bundle_hash: str
    guard_point: str
    questions: Mapping[str, Question]
    rules: Mapping[str, CompiledRule]
    max_content_tokens: int
    profile: TenantProfile
    """The tenant's profile this version was compiled with."""
    floor_specs: Mapping[str, FloorSpec]
    """The floor rules covering this guard point, as the catalog's floor version (the one the
    bundle extends) defines them, not as compiled. Every one must be compiled and sent, and
    match its spec."""
    records_days: int | None = None
    """The version's effective decision-record retention (R3 class B, AC-C1.13), in days."""
    packs: tuple[str, ...] = ()
    """The domain packs the version extends, as ``domain/<name>@<version>`` (the decision-record
    writer clamps the retention term against their bounds, M4-07)."""
    checks: GuardPointChecks = NO_CHECKS
    """The deterministic rules that apply at this guard point (M3-01): the bundle's compiled
    deny patterns and, at ``tool_call``, the tool allow-list."""
    escalation_target: str = "queue"
    """M4-05: where this version's ``escalate`` verdicts go (the bundle's ``escalation.target``)."""
    escalation_url: str | None = None
    """The webhook url of target ``webhook``."""
    store_content: str = "hash_only"
    """The version's ``audit.store_content`` (R3 class C): what content an escalation may carry."""
    content_days: int | None = None
    """The version's ``audit.content_days`` as compiled (R3 class C): None when the version stores
    no content. The stored-content writer clamps it again against the caps in force when it
    writes."""
    class_d_total: bool = False
    """True for the healthcare profile (packs that need a BAA): an escalation item routed under
    this version expires 30 days from creation, resolved or not (R3 class D). Otherwise
    it goes 30 days after it is resolved."""

    @property
    def floor_keys(self) -> frozenset[str]:
        return frozenset(self.floor_specs)


@dataclass(frozen=True, slots=True)
class FloorSpec:
    """One floor rule as the catalog defines it. The compiled rule must ask exactly this
    question, with thresholds no higher than these (a tenant override may only lower them)."""

    key: str
    question: Question
    question_type: str
    block_at: float | None
    escalate_at: float | None


@dataclass(frozen=True, slots=True)
class PolicyLookup:
    policy: GuardPointPolicy
    source: PolicySource
    error: str | None = None
    """Why the last-known-good version was served instead of a fresh one."""


class PolicyUnavailable(Exception):
    """No policy can be served for the tenant."""

    def __init__(self, tenant_id: str, detail: str) -> None:
        self.tenant_id = tenant_id
        self.detail = detail
        super().__init__(f"no policy for tenant {tenant_id!r}: {detail}")


class _RefreshFailed(Exception):
    pass


class _Absent(_RefreshFailed):
    """An authoritative "none": the store says the tenant has no active version, or the
    directory says the tenant doesn't exist. Not an outage, so never last-known-good."""


class _RefreshError(Exception):
    """A refresh failed after the pointer was read; carries the pointer's version."""

    def __init__(self, pointer_version: int, cause: BaseException) -> None:
        self.pointer_version = pointer_version
        self.cause = cause
        super().__init__(str(cause))


@dataclass(frozen=True, slots=True)
class _Compiled:
    """The one compiled version a tenant holds."""

    version: int
    profile: TenantProfile
    guard_points: dict[str, GuardPointPolicy]


@dataclass(frozen=True, slots=True)
class _Built:
    entry: _Compiled
    bundle_hash: str


class DraftCompileError(ValueError):
    """A draft compiled, but can't be tied to the catalog's floor the way a stored version is."""


@dataclass(slots=True)
class _TenantState:
    scope: TenantScope
    """The verified tenant this state serves; the store is only asked through it."""
    compiled: _Compiled | None = None
    """The version being served (the active one, or the last-known-good one)."""
    source: PolicySource = PolicySource.ACTIVE
    error: str | None = None
    """The last refresh's failure (not an absence): why last-known-good is served or, with
    nothing compiled, why there is no policy."""
    fresh_until: float = float("-inf")
    forced: bool = False
    """Set by ``invalidate``: the next check refreshes synchronously."""
    generation: int = 0
    """Bumped by ``invalidate``, so a refresh that started before it doesn't clear it."""
    absent: str | None = None
    """Why the store or directory said, authoritatively, that the tenant has no policy.
    Remembered until ``fresh_until``, so a suspended tenant doesn't hit the store per check.
    Cleared by a refresh that succeeds or fails."""
    refreshes: int = 0
    """Bumped by every refresh, so a check that waited for the lock can tell that a refresh
    finished meanwhile and take its outcome."""
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)


def _checks_of(compiled: CompiledPolicy, guard_point: str) -> GuardPointChecks:
    """A compiled policy's deterministic rules for one guard point. A compiler double that
    returns something without them (``checks_for``) has none."""
    checks_for = getattr(compiled, "checks_for", None)
    return NO_CHECKS if checks_for is None else checks_for(guard_point)


def describe(exc: BaseException) -> str:
    """What a verdict's ``policy_error`` says about a failed refresh: engine wording, error
    codes and exception type names only. An exception's own text (a driver message can
    carry hosts, users or query fragments) never goes into a verdict or audit record;
    :func:`log_note` puts a truncated copy in the service log instead."""
    if isinstance(exc, _RefreshError):
        return describe(exc.cause)
    if isinstance(exc, BundleIntegrityError):
        return f"bundle verification failed ({exc.reason.value})"
    if isinstance(exc, TimeoutError):
        return "policy store or tenant directory timed out"
    if isinstance(exc, _RefreshFailed):
        return str(exc)  # engine-authored
    if isinstance(exc, PolicyInvalidError):
        codes = sorted({str(e.code.value) for e in exc.errors})
        return f"the stored version does not compile ({', '.join(codes[:5])})"
    return type(exc).__name__


_URL_USERINFO = re.compile(r"(://)(?:(?!://)[^\r\n])*@")
"""After ``://``, everything up to the last ``@`` on the line, whitespace included (a raw
space in the password is a working DSN), but never across another ``://``."""
_PASSWORD_PAIR = re.compile(
    r"""(?i)\b(\w*pass(?:word|wd)?|pwd)(\s*[=:]\s*)('[^']*'|"[^"]*"|[^\s,;)'"]+)"""
)
"""A key ending in ``pass``, ``password`` or ``passwd`` in any case (``PGPASSWORD``,
``sslpassword``, ``pass``), or ``pwd``, then ``=`` or ``:`` and the value."""


def mask_secrets(text: str) -> str:
    """``text`` with what could be a credential masked, for logs: URL user
    information (``postgresql://user:pass@host`` becomes ``postgresql://***@host``; up to the
    last ``@`` on the line, so a password holding ``/``, ``@`` or a space is covered) and
    ``password=...`` pairs (libpq keyword form, quoted or not; any key ending in ``pass``,
    ``password`` or ``passwd``, such as ``PGPASSWORD``). Masks more than needed rather than
    less: text between the URL and a later ``@`` on the same line is masked too."""
    text = _URL_USERINFO.sub(r"\1***@", text)
    return _PASSWORD_PAIR.sub(r"\1\2***", text)


def log_note(exc: BaseException) -> str:
    """The exception's own text for the service log, credentials masked
    (:func:`mask_secrets`) before it is truncated to 200 characters: empty for
    engine-authored failures, whose :func:`describe` already says everything."""
    cause = exc.cause if isinstance(exc, _RefreshError) else exc
    if isinstance(cause, BundleIntegrityError | TimeoutError | _RefreshFailed):
        return ""
    return f" ({mask_secrets(str(cause))!r:.200})"


class PolicyCache:
    def __init__(
        self,
        store: ScopedPolicyStores,
        tenants: TenantDirectory,
        catalog: Catalog,
        settings: PlatformSettings,
        *,
        pointer_ttl_s: float = DEFAULT_POINTER_TTL_S,
        store_timeout_s: float = DEFAULT_STORE_TIMEOUT_S,
        clock: Callable[[], float] = time.monotonic,
        compiler_factory: CompilerFactory = PolicyCompiler,
    ) -> None:
        if pointer_ttl_s < 0 or store_timeout_s <= 0:
            raise ValueError("pointer_ttl_s must be >= 0 and store_timeout_s > 0")
        self._store = store
        self._tenants = tenants
        self._catalog = catalog
        self._settings = settings
        self._pointer_ttl_s = pointer_ttl_s
        self._store_timeout_s = store_timeout_s
        self._clock = clock
        self._compiler_factory = compiler_factory
        self._state: dict[str, _TenantState] = {}
        self._background: dict[str, asyncio.Future[None]] = {}
        self._closed = False
        self.compiles = 0
        """How many times a bundle has been compiled. A cache hit never adds to it."""

    # ------------------------------------------------------------------ public

    def invalidate(self, tenant_id: str) -> None:
        """Make the tenant's next check re-read its pointer synchronously (a publish or
        rollback event)."""
        state = self._state.get(tenant_id)
        if state is not None:
            state.forced = True
            state.generation += 1
            state.fresh_until = float("-inf")

    async def get(self, scope: TenantScope, guard_point: str) -> PolicyLookup:
        """The compiled policy for one guard point of the verified tenant ``scope``. The store
        is asked only through that scope. Raises :class:`PolicyUnavailable`."""
        tenant_id = scope.tenant_id
        state = self._state.get(tenant_id)
        if (
            state is not None
            and not state.forced
            and state.absent is not None
            and self._clock() < state.fresh_until
        ):
            raise PolicyUnavailable(tenant_id, state.absent)
        if state is not None and not state.forced and state.compiled is not None:
            if self._clock() >= state.fresh_until:
                self._revalidate_in_background(tenant_id, state)
            return self._lookup(tenant_id, state, guard_point)

        state = self._state.setdefault(tenant_id, _TenantState(scope=scope))
        seen = state.refreshes
        async with state.lock:
            # A refresh that finished while this check waited serves it too, unless
            # ``invalidate`` asked for a new one since.
            if state.forced or (state.compiled is None and state.refreshes == seen):
                await self._refresh_locked(tenant_id, state)
            if state.compiled is None:
                raise PolicyUnavailable(
                    tenant_id, state.absent or state.error or "no compiled policy"
                )
            return self._lookup(tenant_id, state, guard_point)

    async def drain(self) -> None:
        """Wait for the background refreshes in flight. For tests."""
        while self._background:
            await asyncio.wait(list(self._background.values()))

    async def aclose(self) -> None:
        """Cancel background refreshes and wait for them to stop."""
        self._closed = True
        tasks = list(self._background.values())
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.wait(tasks)

    # ------------------------------------------------------------------ internals

    def _lookup(self, tenant_id: str, state: _TenantState, guard_point: str) -> PolicyLookup:
        assert state.compiled is not None
        entry = state.compiled.guard_points.get(guard_point)
        if entry is None:  # not reachable: every guard point is cached with its version
            raise PolicyUnavailable(tenant_id, f"no compiled guard point {guard_point!r}")
        return PolicyLookup(entry, state.source, state.error)

    def _revalidate_in_background(self, tenant_id: str, state: _TenantState) -> None:
        if self._closed or tenant_id in self._background:
            return  # one refresh in flight per tenant
        task = asyncio.ensure_future(self._revalidate(tenant_id, state))
        self._background[tenant_id] = task
        task.add_done_callback(lambda t: self._background_done(tenant_id, t))

    def _background_done(self, tenant_id: str, task: asyncio.Future[None]) -> None:
        if self._background.get(tenant_id) is task:
            del self._background[tenant_id]
        if not task.cancelled() and (exc := task.exception()) is not None:
            # No traceback: its last line is the exception's own text, which a driver may
            # fill with a DSN. The type and the masked text say what failed.
            logger.error(
                "background policy refresh for %s failed: %s%s",
                tenant_id,
                type(exc).__name__,
                log_note(exc),
            )

    async def _revalidate(self, tenant_id: str, state: _TenantState) -> None:
        async with state.lock:
            if state.forced or self._clock() < state.fresh_until:
                return  # a synchronous refresh got there first
            await self._refresh_locked(tenant_id, state)

    async def _refresh_locked(self, tenant_id: str, state: _TenantState) -> None:
        """Refresh under the tenant's lock and update ``state``. Never raises except
        cancellation."""
        generation = state.generation
        try:
            state.compiled = await self._refresh(state.scope, state.compiled)
            state.source, state.error, state.absent = PolicySource.ACTIVE, None, None
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            error = describe(exc)
            note = log_note(exc)  # the exception's text: logs only, never the verdict
            cause = exc.cause if isinstance(exc, _RefreshError) else exc
            if isinstance(cause, _Absent):
                # Authoritative: the tenant is suspended, removed or has no policy. Stop
                # serving anything for it, last-known-good included.
                if state.compiled is not None or state.absent != error:
                    logger.warning(
                        "tenant %s: %s; its policy is no longer served", tenant_id, error
                    )
                state.compiled, state.source, state.error = None, PolicySource.ACTIVE, None
                state.absent = error
            elif state.compiled is None:
                # An outage with nothing to serve, possibly after an absence: report this
                # failure, not the old absence, and don't remember it, so the next check
                # tries again.
                if state.error != error:
                    logger.error(
                        "policy refresh failed for tenant %s with no policy to serve: %s%s",
                        tenant_id,
                        error,
                        note,
                    )
                state.absent, state.error = None, error
            else:
                served = state.compiled.version
                pointer = exc.pointer_version if isinstance(exc, _RefreshError) else None
                if pointer is not None and pointer != served:
                    error += (
                        f"; serving version {served} although the active pointer names "
                        f"version {pointer}"
                    )
                    logger.error(
                        "tenant %s: serving last-known-good version %s, but the active "
                        "pointer names version %s (for example a rollback): %s%s",
                        tenant_id,
                        served,
                        pointer,
                        describe(exc),
                        note,
                    )
                elif state.source is PolicySource.ACTIVE or state.error != error:
                    logger.error(
                        "policy refresh failed for tenant %s; serving last-known-good version "
                        "%s: %s%s",
                        tenant_id,
                        served,
                        error,
                        note,
                    )
                state.source, state.error = PolicySource.LAST_KNOWN_GOOD, error
        if state.generation == generation:
            state.forced = False
        state.fresh_until = self._clock() + self._pointer_ttl_s
        state.refreshes += 1

    async def _bounded(self, call: Awaitable[T]) -> T:
        async with asyncio.timeout(self._store_timeout_s):
            return await call

    async def _refresh(self, scope: TenantScope, current: _Compiled | None) -> _Compiled:
        """Read the pointer and profile; compile when either changed."""
        tenant_id = scope.tenant_id
        store = self._store.scoped(scope)
        version = await self._bounded(store.get_active_version(tenant_id))
        if version is None:
            raise _Absent("the tenant has no active policy version")
        try:
            profile: Any = await self._bounded(self._tenants.get(tenant_id))
            if profile is None:
                raise _Absent("the tenant is not in the tenant directory")
            if (problem := profile_problem(profile)) is not None:
                raise _RefreshFailed(
                    f"the tenant directory returned an invalid profile or domain: {problem}"
                )
            if profile.tenant_id != tenant_id:
                raise _RefreshFailed("the tenant directory returned another tenant's profile")
            if current is not None and current.version == version and current.profile == profile:
                return current
            return await self._compile(store, tenant_id, version, profile)
        except Exception as exc:
            raise _RefreshError(version, exc) from exc

    async def _compile(
        self, store: PolicyStore, tenant_id: str, version: int, profile: TenantProfile
    ) -> _Compiled:
        stored = await self._bounded(store.get_version(tenant_id, version))
        if stored.tenant_id != tenant_id:
            raise _RefreshFailed("the store returned another tenant's version")
        compiled = self._build(tenant_id, version, stored.parsed, profile)
        self.compiles += 1
        if compiled.bundle_hash != stored.bundle_hash:
            raise _RefreshFailed("the compiled bundle hash differs from the stored one")
        return compiled.entry

    async def candidate_policies(
        self, scope: TenantScope, version: int
    ) -> Mapping[str, GuardPointPolicy]:
        """The per-guard-point policies of stored version ``version`` of the verified tenant
        ``scope`` (M4-03: a candidate), loaded through the same verified path as the active
        version (``get_version`` re-verifies the hash) and compiled with the tenant's profile.
        Not cached here (the rollout caches it) and never touches the active entry. Raises on
        any failure: the caller falls back to the active version."""
        tenant_id = scope.tenant_id
        store = self._store.scoped(scope)
        profile: Any = await self._bounded(self._tenants.get(tenant_id))
        if profile is None:
            raise _Absent("the tenant is not in the tenant directory")
        if (problem := profile_problem(profile)) is not None:
            raise _RefreshFailed(
                f"the tenant directory returned an invalid profile or domain: {problem}"
            )
        if profile.tenant_id != tenant_id:
            raise _RefreshFailed("the tenant directory returned another tenant's profile")
        return (await self._compile(store, tenant_id, version, profile)).guard_points

    def compile_draft(
        self, tenant_id: str, parsed: ParsedBundle, profile: TenantProfile
    ) -> Mapping[str, GuardPointPolicy]:
        """The per-guard-point policies a draft would serve if it were published as it is
        (M2-05: the test endpoint evaluates them). Nothing is cached or counted in
        :attr:`compiles`. Raises :class:`PolicyInvalidError` for a draft the compiler refuses,
        and :class:`DraftCompileError` when it can't be tied to the catalog's floor."""
        try:
            built = self._build(tenant_id, parsed.bundle.version, parsed, profile, replay=False)
        except _RefreshFailed as e:
            raise DraftCompileError(str(e)) from None
        return built.entry.guard_points

    def _build(
        self,
        tenant_id: str,
        version: int,
        parsed: ParsedBundle,
        profile: TenantProfile,
        *,
        replay: bool = True,
    ) -> _Built:
        """``replay``: ``parsed`` is a version that was already published (the default: the
        active or candidate version being loaded), so the tier's required packs and rules are
        not checked again (M5-01: a tier raised on a live tenant takes effect at its next
        publish, and the running version keeps running, after a restart too). A draft is not a
        replay."""
        floor_specs = self._expected_floor_specs(parsed)
        compiler = self._compiler_factory(self._catalog, profile, self._settings)
        if replay and isinstance(compiler, PolicyCompiler):
            compiler.enforce_tier_requirements = False
        compiled = compiler.compile(parsed, profile.attributes)
        if compiled.tenant_id != tenant_id or compiled.version != version:
            raise _RefreshFailed(
                f"version {version} compiled as {compiled.tenant_id}@{compiled.version}"
            )
        entry = _Compiled(
            version=version,
            profile=profile,
            guard_points={
                name: GuardPointPolicy(
                    tenant_id=tenant_id,
                    version=version,
                    bundle_hash=compiled.bundle_hash,
                    guard_point=name,
                    questions=gp.questions,
                    rules=gp.rules,
                    max_content_tokens=gp.max_content_tokens,
                    profile=profile,
                    floor_specs=MappingProxyType(floor_specs.get(name, {})),
                    records_days=compiled.audit.records_days,
                    packs=compiled.packs,
                    checks=_checks_of(compiled, name),
                    escalation_target=compiled.escalation.target,
                    escalation_url=compiled.escalation.url,
                    store_content=compiled.audit.store_content,
                    content_days=compiled.audit.content_days,
                    class_d_total=compiled.audit.content_requires_baa,
                )
                for name, gp in compiled.guard_points.items()
            },
        )
        return _Built(entry, compiled.bundle_hash)

    def _expected_floor_specs(self, parsed: ParsedBundle) -> dict[str, dict[str, FloorSpec]]:
        """Per guard point, the floor rules the bundle's floor version requires, as the
        catalog defines them, read from the bundle's own ``extends`` and the catalog, not
        from the compiled output."""
        floors = []
        for ref in parsed.bundle.extends:
            m = EXTENDS_REF_PATTERN.fullmatch(ref)
            if m is not None and m.group(1):
                floors.append(int(m.group(3)))
        if len(floors) != 1:
            raise _RefreshFailed("the bundle does not extend exactly one floor version")
        floor = self._catalog.floor(floors[0])
        if floor is None:
            raise _RefreshFailed(f"the catalog has no floor@{floors[0]}")
        specs: dict[str, dict[str, FloorSpec]] = {}
        for rule in floor.rules:
            spec = FloorSpec(
                key=rule.key,
                question=rule.question,
                question_type=rule.question.type,
                block_at=rule.block_at,
                escalate_at=rule.escalate_at,
            )
            for gp in rule.guard_points:
                specs.setdefault(gp, {})[rule.key] = spec
        return specs
