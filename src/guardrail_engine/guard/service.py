"""The Guard Service check pipeline (M1-05; design §Runtime evaluation flow, corrected by the
backlog's B1, B3, PF-6, PF-12 and S4).

    async with GuardService(model=..., key_id=..., verifier=..., store=..., tenants=...,
                            catalog=..., audit=...) as guard:
        verdict = await guard.check(ctx, "output", content)

One check, in order:

1. **Tenant.** Verify ``ctx.signed_context``; the tenant comes from it and nowhere else. A
   context that doesn't verify, or a payload tenant id that differs from the verified one,
   gets a ``forbidden`` verdict with no further work (AC-T1).
2. **Request shape.** An unknown guard point, non-text content or a malformed context item
   is blocked as ``invalid_request``.
3. **Policy.** The compiled questions and rules for ``(tenant, active version, guard point)``
   from the :class:`PolicyCache` (AC-C3), or the last-known-good version when the store is
   down or the active version fails verification. With neither: block,
   ``policy_unavailable``, no model call.
4. **Deterministic checks** (M3-01, AC-G1; :mod:`guardrail_engine.guard.deterministic`),
   none of which depends on the model, in this order:

   * the **size limit**: content over the guard point's max content tokens is a block,
     ``content_too_large``. It is never truncated. ``tool_result`` is the exception (M3-04,
     AC-G5): its limit is a number of **chunks** (``max_chunks_per_result``, each
     ``chunk_tokens`` long) and content over one chunk is split, not refused; see step 6.
     It is checked on the **raw** content, so oversized input is refused before any work is
     done on it (M1-14);
   * at ``tool_call``, the **tool arguments' schema** first (M3-03: the registry's JSON
     Schema for the tool, rule ``tool_schema``); then the **tool allow-list** at ``tool_call``
     and at ``plan`` (there against the tools the plan names, M3-03), the tenant's **deny
     patterns** (RE2) on the content as submitted, and at ``tool_result`` and ``output`` the
     floor's **cross-tenant identifier scan**. A deterministic ``block`` ends the check here: reason
     ``deterministic``, **no model call**. An ``escalate`` lets the check go on to the model,
     and the more severe result wins. ``redact`` patterns are applied with step 5, and
     ``log`` ones are only recorded. Each rule that fires is on the verdict, the audit
     record and the span **by rule id only, never the matched text**.
   * **``skip_model``** (M3-03): at ``tool_call``, when the tool's
     registry entry says so (read-only tools only), the **tenant's and packs' questions are
     not asked**; **the floor's questions always are** (they are what stops exfiltration and
     cross-tenant probing in a read-only tool's arguments), so there is no full skip and a
     tenant can't loosen the floor with a flag. The call is cheaper, not free: it is the
     ordinary call (redaction, render, gateway, fusion) with the floor's questions alone.
     ``Verdict.model_skipped`` is set, and the span and the usage meter count it. A guard
     point whose floor has no questions ends here instead, allowed with no model call.
5. **Redact, then render.** Redaction (M1-14, AC-G2): PII in the content and every context
   section is replaced by typed placeholders
   (:func:`~guardrail_engine.guard.redaction.redact_request`). If the detector fails, nothing
   is sent: block, ``internal_error``, ``redaction: failed``. Token estimates from here on
   are made on the redacted text, because that is what is sent. Render (B3): trusted
   ``TENANT DOMAIN``, ``TENANT`` and ``GUARD POINT`` headers, then nonce-delimited untrusted
   sections; context cut oldest first to fit.
6. **One** gateway call with the guard point's compiled questions, **or one per chunk** at
   ``tool_result`` (M3-04, :mod:`guardrail_engine.guard.chunking`): content over
   ``chunk_tokens`` is cut, **after** the deterministic checks and redaction have run once on
   the whole content, into chunks overlapping by 256 tokens. The chunk calls are submitted
   together and each goes through the gateway's admission control on its own. Their answers
   are merged, **maximum p per question key**, before fusion; if any chunk's call fails, the
   guard point is a model failure resolved by layer (B1). Cost: one call (carrying every
   question) per chunk.
7. **Resolve** and **fuse**: provider safety blocks (PF-12); a failed call resolves every
   rule by its own fail mode (B1); per-key answer problems resolve that key by its fail mode
   (PF-6); thresholds and most-severe-wins otherwise (AC-G3). Shadow rules never act.
8. **Audit.** The verdict goes to the audit sink, whatever the outcome, then to the caller.

**Telemetry** (M1-06, AC-O2): each check opens a span through the telemetry port when it
starts and ends it with the verdict's attributes; the decision call gets a child model-call
span. The default port records nothing.

No exception escapes ``check()`` for any model, gateway, store, directory, cache, sink or
telemetry failure: each ends in a defined verdict, and an unexpected error fails closed as
``internal_error``. Audit and telemetry failures are logged and never change the verdict.
Only cancellation of the caller propagates.

The service owns its :class:`DecisionGateway` (which runs background tasks): use it with
``async with`` or call :meth:`GuardService.aclose` on shutdown.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import math
import time
import uuid
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol

from guardrail_engine.decision.port import (
    Answered,
    DecisionModel,
    Failed,
    FailureKind,
    SafetyBlocked,
)
from guardrail_engine.deterministic.identifiers import (
    NoOtherTenantIdentifiers,
    OtherTenantIdentifiers,
)
from guardrail_engine.deterministic.regex import RegexEngine, default_regex_engine
from guardrail_engine.deterministic.rules import DeterministicAction
from guardrail_engine.gateway.gateway import (
    USAGE_CHECK,
    CheckTiming,
    DecisionGateway,
    GatewayConfig,
    TimedDecision,
)
from guardrail_engine.gateway.sinks import AlertSink, UsageMeter
from guardrail_engine.guard.audit import AuditSink, NullAuditSink
from guardrail_engine.guard.chunking import combine, split_chunks
from guardrail_engine.guard.context import ContextVerificationError, ContextVerifier
from guardrail_engine.guard.deterministic import (
    CROSS_TENANT_GUARD_POINTS,
    MAX_STALE_S,
    CrossTenantScanner,
    check_plan_allowlist,
    check_tool_allowlist,
    check_tool_mismatch,
    check_tool_schema,
    redact_deny_patterns,
    redact_hits,
    scan_deny_patterns,
    size_limit_hit,
)
from guardrail_engine.guard.fusion import evaluate_answered, evaluate_failed, fuse
from guardrail_engine.guard.pii import DEFAULT_PII_DETECTOR, PiiDetector
from guardrail_engine.guard.policy_cache import (
    DEFAULT_POINTER_TTL_S,
    DEFAULT_STORE_TIMEOUT_S,
    CompilerFactory,
    FloorSpec,
    GuardPointPolicy,
    PolicyCache,
    PolicyUnavailable,
)
from guardrail_engine.guard.redaction import (
    REDACT_OFF_LOOP_CHARS,
    RedactedRequest,
    redact_request,
    request_chars,
)
from guardrail_engine.guard.render import NonceSource, count_tokens, new_nonce, render_input
from guardrail_engine.guard.request import CheckContext, context_item_problem
from guardrail_engine.guard.rollout import (
    ACTIVE as ACTIVE_ASSIGNMENT,
)
from guardrail_engine.guard.rollout import (
    MAX_CONVERSATION_ID_CHARS,
    CandidateSource,
    Rollout,
)
from guardrail_engine.guard.shadow import ShadowSink, observe
from guardrail_engine.guard.telemetry import (
    cancelled_attributes,
    check_attributes,
    check_failed,
    model_call_attributes,
)
from guardrail_engine.guard.tenants import TenantDirectory, ToolInfo
from guardrail_engine.guard.verdict import (
    Decision,
    DeterministicHit,
    PolicySource,
    Reason,
    RedactionStatus,
    RuleEvaluation,
    Verdict,
    escalated_by_deterministic,
    recorded_code,
)
from guardrail_engine.policy.catalog import Catalog, PlatformSettings
from guardrail_engine.policy.compiler import PolicyCompiler
from guardrail_engine.policy.schema import GUARD_POINTS
from guardrail_engine.store.port import ScopedPolicyStores
from guardrail_engine.telemetry.port import NULL_TRACE, CheckTrace, NullTelemetry, Telemetry
from guardrail_engine.tenant_scope import TenantScope

logger = logging.getLogger(__name__)

MAX_REQUEST_ID_CHARS = 128
CHUNKED_GUARD_POINT = "tool_result"
"""The one guard point whose content is split into chunks rather than refused when it is
over the cap (M3-04, AC-G5)."""


@dataclass(frozen=True)
class GuardConfig:
    pointer_ttl_s: float = DEFAULT_POINTER_TTL_S
    """How long a tenant's active-version pointer is trusted before it is re-read."""
    store_timeout_s: float = DEFAULT_STORE_TIMEOUT_S
    """Upper bound on each policy store or tenant directory call."""
    gateway: GatewayConfig = field(default_factory=GatewayConfig)
    shadow_wait_s: float = 0.2
    """How long a check waits, after its own decision is ready, for a shadow candidate's
    evaluation to finish so the audit record can hold its decision (M4-03). They run
    concurrently, so this only matters when the candidate is the slower one; the comparison is
    counted when it finishes either way, and the check's verdict never depends on it."""
    identifier_max_stale_s: float = MAX_STALE_S
    """How long the cross-tenant scan may go on with its previous identifier set while a rebuild
    runs; 0 makes a check wait for the rebuild, as it did before."""


@dataclass(frozen=True)
class ProjectBackend:
    """One dedicated Gemini project (M5-06): its model (which holds its key), the non-secret
    id of that key, and the gateway settings with the project's own limiter. The Guard Service
    builds one gateway of its own from it, so the project has its own admission queue, token
    bucket, daily count and monthly spend, and its own usage rows."""

    model: DecisionModel
    key_id: Callable[[], str]
    gateway: GatewayConfig


def _meter_for_project(meter: UsageMeter | None, project: str) -> UsageMeter | None:
    """The meter a dedicated project's gateway reports to: the same sink, with the project's
    label on every usage record (M5-06), when the meter can do it (``with_project``, which the
    durable and Postgres usage meters have). A meter that can't is shared as it is: its usage
    is then not attributed to the project."""
    with_project = getattr(meter, "with_project", None)
    return with_project(project) if callable(with_project) else meter


def content_sha256(content: str) -> str:
    """``sha256:<hex>`` of the **pre-redaction** content's UTF-8 bytes: call it on the content as
    submitted, before any redaction step (PF-14, R3). Lone surrogates (possible in text
    decoded from JSON) are encoded as-is rather than raising."""
    return "sha256:" + hashlib.sha256(content.encode("utf-8", "surrogatepass")).hexdigest()


def _floor_problems(
    specs: Mapping[str, FloorSpec],
    questions: Mapping[str, Any],
    rules: Mapping[str, Any],
    floor_fail_mode: str,
) -> list[str]:
    """Every way the compiled floor differs from the catalog's floor, one
    ``"<key>: <what differed>"`` per problem. Each floor rule must be compiled, ask exactly
    the catalog's question, keep finite thresholds no higher than the catalog's (an override may
    only lower them), be an enforce floor rule, and fail as the platform setting says."""
    problems = []
    for key, spec in sorted(specs.items()):
        question, rule = questions.get(key), rules.get(key)
        if question is None or rule is None:
            problems.append(f"{key}: missing")
            continue
        if question != spec.question or rule.question_type != spec.question_type:
            problems.append(f"{key}: question differs from the catalog's")
        for name in ("block_at", "escalate_at"):
            compiled, catalog = getattr(rule, name), getattr(spec, name)
            if catalog is None:
                continue
            # Written so that anything that isn't a finite number at or below the catalog's
            # fails, NaN included: every comparison with NaN is false.
            if not (_finite(compiled) and _finite(catalog)):
                problems.append(
                    f"{key}: {name} {compiled} is not a finite number at or below the "
                    f"catalog's {catalog}"
                )
            elif not (compiled <= catalog):
                problems.append(f"{key}: {name} {compiled} is above the catalog's {catalog}")
        if rule.layer != "floor":
            problems.append(f"{key}: layer {rule.layer!r}, not 'floor'")
        if rule.mode != "enforce":
            problems.append(f"{key}: mode {rule.mode!r}, not 'enforce'")
        if rule.fail_mode != floor_fail_mode:
            problems.append(
                f"{key}: fail_mode {rule.fail_mode!r}, but the platform floor_fail_mode is "
                f"{floor_fail_mode!r}"
            )
    return problems


def _finite(value: object) -> bool:
    return isinstance(value, int | float) and not isinstance(value, bool) and math.isfinite(value)


def _sent_floor_problems(specs: Mapping[str, FloorSpec], sent: Mapping[str, Any]) -> list[str]:
    """The floor questions actually handed to the gateway, against the catalog's."""
    return [
        f"{key}: {'not sent' if key not in sent else 'sent question differs'}"
        for key, spec in sorted(specs.items())
        if sent.get(key) != spec.question
    ]


def _unevaluated_floor_keys(
    specs: Mapping[str, FloorSpec], evaluations: Iterable[RuleEvaluation]
) -> list[str]:
    evaluated = {ev.key for ev in evaluations if ev.layer == "floor"}
    return [f"{key}: not evaluated" for key in sorted(specs) if key not in evaluated]


def _label(value: object, limit: int = 64) -> str:
    return value[:limit] if isinstance(value, str) else f"<{type(value).__name__}>"


def _registered_tool(policy: GuardPointPolicy, tenant_id: str, tool: str | None) -> ToolInfo | None:
    """The registry entry of ``tool`` in **this tenant's** profile, or None: no tool named,
    one the registry doesn't know, or a profile that isn't the tenant's (the check blocks
    that case itself before any model call)."""
    if tool is None or policy.profile.tenant_id != tenant_id:
        return None
    return policy.profile.tools.get(tool)


@dataclass(frozen=True, slots=True)
class _DraftContext:
    """The only attribute of a check context that a draft evaluation has."""

    request_id: str | None


def _chunk_answered(task: asyncio.Future[Any]) -> bool:
    """Whether a finished chunk call came back with an answer (not a failure, a refusal, an
    exception or a cancellation)."""
    if task.cancelled() or task.exception() is not None:
        return False
    outcome = task.result()
    return isinstance(outcome, TimedDecision) and isinstance(outcome.result, Answered)


class EscalationSink(Protocol):
    """Where an ``escalate`` verdict goes (M4-05): the router. ``submit`` must not block or
    raise (a full queue is the router's to drop and alert on); the service calls it after the
    audit record, and a failure there never changes the verdict."""

    def submit(self, request: Any) -> bool: ...


class ContentSubmitter(Protocol):
    """Where a check's post-redaction content goes when its tenant stores content (M5-03, R3
    class C): the write-behind writer. ``submit`` must not block or raise; the service calls it
    after the audit record, and a failure there never changes the verdict."""

    def submit(self, request: Any) -> None: ...


class _Run:
    """The verdict fields of one check, gathered as the pipeline goes."""

    def __init__(self, service: GuardService, ctx: Any, guard_point: Any) -> None:
        self.scope: TenantScope | None = None
        """The verified tenant (M4-05: an escalation is routed under it)."""
        self.policy: GuardPointPolicy | None = None
        """The policy that decided the check (its escalation target and content setting)."""
        self.held_content: str | None = None
        """The post-redaction content the model saw, kept for an escalation (class D). Never on
        the verdict or in the audit record."""
        self.clock = service._clock
        self.start = self.clock()
        self.trace: CheckTrace = NULL_TRACE
        request_id = getattr(ctx, "request_id", None)
        if not (
            isinstance(request_id, str)
            and 1 <= len(request_id) <= MAX_REQUEST_ID_CHARS
            and request_id.isprintable()
        ):
            request_id = uuid.uuid4().hex
        self.fields: dict[str, Any] = {
            "request_id": request_id,
            "tenant_id": None,
            "guard_point": _label(guard_point),
            "checked_at": service._wall_clock(),
            "floor_fail_mode": service._settings.floor_fail_mode,
            # Until a policy says otherwise: the longest class B term (R3), never shorter.
            "retention_days": service._settings.standard_retention.records_max_days,
        }

    def finish(self, decision: Decision, reason: Reason, **fields: Any) -> Verdict:
        self.fields.update(fields)
        # A deterministic ``escalate`` is not overridden by a less severe result.
        decision, reason = escalated_by_deterministic(
            decision, reason, self.fields.get("deterministic", ())
        )
        return Verdict(
            decision=decision,
            reason=reason,
            latency_ms=(self.clock() - self.start) * 1000,
            **self.fields,
        )

    def fail_closed(self, detail: str) -> Verdict:
        """An ``internal_error`` block, falling back to the bare minimum of fields if the
        gathered ones can't be used."""
        try:
            return self.finish(Decision.BLOCK, Reason.INTERNAL_ERROR, detail=detail)
        except Exception:
            logger.exception("could not build a full verdict; returning a minimal one")
            return Verdict(
                request_id=self.fields["request_id"],
                tenant_id=None,
                guard_point=self.fields["guard_point"],
                decision=Decision.BLOCK,
                reason=Reason.INTERNAL_ERROR,
                detail=detail,
                checked_at=datetime.now(UTC),
                latency_ms=0.0,
            )


def _minimal_closed_verdict(run: _Run, detail: str) -> Verdict:
    """``block``/``engine_closed`` with the bare minimum of fields."""
    return Verdict(
        request_id=run.fields["request_id"],
        tenant_id=None,
        guard_point=run.fields["guard_point"],
        decision=Decision.BLOCK,
        reason=Reason.ENGINE_CLOSED,
        detail=detail,
        checked_at=datetime.now(UTC),
        latency_ms=0.0,
    )


class GuardService:
    def __init__(
        self,
        *,
        model: DecisionModel,
        key_id: Callable[[], str],
        verifier: ContextVerifier,
        store: ScopedPolicyStores,
        tenants: TenantDirectory,
        catalog: Catalog,
        settings: PlatformSettings | None = None,
        audit: AuditSink | None = None,
        telemetry: Telemetry | None = None,
        config: GuardConfig | None = None,
        meter: UsageMeter | None = None,
        alerts: AlertSink | None = None,
        nonce_source: NonceSource = new_nonce,
        clock: Callable[[], float] = time.perf_counter,
        wall_clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        cache_clock: Callable[[], float] = time.monotonic,
        compiler_factory: CompilerFactory = PolicyCompiler,
        pii_detector: PiiDetector | None = None,
        other_tenants: OtherTenantIdentifiers | None = None,
        regex: RegexEngine | None = None,
        candidates: CandidateSource | None = None,
        shadow: ShadowSink | None = None,
        escalations: EscalationSink | None = None,
        projects: Mapping[str, ProjectBackend] | None = None,
        content: ContentSubmitter | None = None,
    ) -> None:
        """``projects`` (M5-06) maps a dedicated project's label to its backend. A check of a
        tenant whose directory entry names a project (``attributes.project``) goes to that
        project's gateway and no other; a tenant with none goes to the shared gateway built from
        ``model``. A tenant named for a project that has no backend **fails closed** (a model
        failure, resolved by layer: the floor blocks): it is never served from the shared
        pool, which would defeat the isolation it was given the project for.

        ``key_id`` returns a non-secret identifier of the API key the model uses now,
        e.g. the secret's version in the secret store. It must change when the key is
        replaced, so the gateway's auth breaker can close on rotation (M1-04). Required:
        the gateway's constant default would only ever close the breaker by probe.

        ``settings`` must be the platform settings the policy store's bundles are compiled
        under. Its ``floor_fail_mode`` (B1) is the authority on how the floor fails: every
        compiled floor rule must carry it, and it gates ``allow``/``model_failure``.

        ``telemetry`` receives one span per check (AC-O2); the default records nothing.

        ``pii_detector`` finds the PII redacted before the model call (M1-14). It defaults to
        the engine's deterministic detector; there is no way to turn redaction off. Another
        detector is for tests, like the model override, and the engine's factory refuses one
        when ``environment`` is ``production``.

        ``other_tenants`` is the cross-tenant identifier scan's source (M3-01): given the
        caller's tenant id, the patterns of every other tenant's identifiers. The scan runs at
        ``tool_result`` and ``output`` and can't be turned off by a tenant. The default scans
        for nothing, so **until a composition root passes a real source** (after M2-01's
        tenant directory) no cross-tenant identifier is found. A source that raises fails the
        check closed; a tenant whose patterns don't compile is dropped from the scan with a
        fixed-word alert (a log line and a meter) and the other tenants' checks go on; a
        combined set too big to build is split into shards, with a fixed-word alert, and the
        scan goes on.
        ``regex`` is the RE2 engine the scan compiles its patterns with (default: the
        platform's adapter).

        ``candidates`` reads the tenant's candidate version (M4-03, PF-7). With it, a check
        that carries a ``conversation_id`` is assigned by ``hash(tenant_id, conversation_id)``:
        a sampled conversation is decided by an ``enforce`` candidate, or evaluated alongside the
        active version under a ``shadow`` one (never acting, logged in the audit record and
        counted into ``shadow``, which receives one observation per compared check). Without
        it the active version decides everything.

        ``escalations`` receives every ``escalate`` verdict after its audit record (M4-05): a
        non-blocking ``submit``, so routing to the human queue or the webhook is never on the
        check's path and never changes its verdict.
        """
        if not callable(key_id):
            raise TypeError("key_id must be a callable returning the current key's id")
        self._config = config or GuardConfig()
        self._scanner = CrossTenantScanner(
            other_tenants if other_tenants is not None else NoOtherTenantIdentifiers(),
            regex if regex is not None else default_regex_engine(),
            self._identifier_patterns_dropped,
            self._identifier_scan_sharded,
            max_stale_s=self._config.identifier_max_stale_s,
        )
        self._pii_detector = DEFAULT_PII_DETECTOR if pii_detector is None else pii_detector
        self._settings = settings or PlatformSettings()
        self._verifier = verifier
        self._audit = audit or NullAuditSink()
        self._ended = getattr(tenants, "ended", None)
        """M5-07: ``async ended(tenant_id) -> bool`` on the tenant directory, when it has one
        (the cached directory does): True once the tenant is terminating or terminated."""
        self._escalations = escalations
        self._content = content
        self._telemetry = telemetry or NullTelemetry()
        self._nonce_source = nonce_source
        self._clock = clock
        self._wall_clock = wall_clock
        self._gateway = DecisionGateway(
            model, config=self._config.gateway, meter=meter, alerts=alerts, key_id=key_id
        )
        self._project_gateways: dict[str, DecisionGateway] = {
            label: DecisionGateway(
                backend.model,
                config=backend.gateway,
                meter=_meter_for_project(meter, label),
                alerts=alerts,
                key_id=backend.key_id,
            )
            for label, backend in (projects or {}).items()
        }
        self._cache = PolicyCache(
            store,
            tenants,
            catalog,
            self._settings,
            pointer_ttl_s=self._config.pointer_ttl_s,
            store_timeout_s=self._config.store_timeout_s,
            clock=cache_clock,
            compiler_factory=compiler_factory,
        )
        self._cache_clock = cache_clock
        self._rollout: Rollout | None = None
        self._shadow = shadow
        if candidates is not None:
            self.attach_rollout(candidates, shadow)
        self._shadow_tasks: set[asyncio.Future[Any]] = set()

    @property
    def gateway(self) -> DecisionGateway:
        """The shared pool's gateway (the engine's own project)."""
        return self._gateway

    @property
    def gateways(self) -> Mapping[str | None, DecisionGateway]:
        """Every gateway: ``None`` is the shared pool's, each other key a dedicated project's
        label (M5-06)."""
        return {None: self._gateway, **self._project_gateways}

    def gateway_for(self, project: str | None) -> DecisionGateway:
        """The gateway that serves a tenant assigned to ``project`` (None: the shared pool).
        Raises ``LookupError`` for a project this service has no backend for: the caller
        resolves it as a model failure, never as the shared pool."""
        if project is None:
            return self._gateway
        try:
            return self._project_gateways[project]
        except KeyError:
            raise LookupError("no backend is configured for the tenant's project") from None

    @property
    def policy_cache(self) -> PolicyCache:
        return self._cache

    def attach_rollout(self, candidates: CandidateSource, shadow: ShadowSink | None) -> None:
        """Give the service its candidate source and shadow sink after construction (the
        engine factory builds the lifecycle store after the service, M4-03). Replaces any
        earlier ones."""
        self._rollout = Rollout(
            self._cache,
            candidates,
            pointer_ttl_s=self._config.pointer_ttl_s,
            clock=self._cache_clock,
        )
        self._shadow = shadow

    @property
    def rollout(self) -> Rollout | None:
        """The candidate assignment (M4-03); None when no candidate source was given."""
        return self._rollout

    async def aclose(self) -> None:
        """Stop the policy cache's background refreshes, then close the gateway: flush its
        alert and metering events and stop orphaned calls."""
        try:
            await self._cache.aclose()
            await self.drain_shadow(cancel=True)
        finally:
            for gateway in (self._gateway, *self._project_gateways.values()):
                try:
                    await gateway.aclose()
                except Exception:
                    logger.exception("a gateway did not close cleanly")

    async def drain_shadow(self, *, cancel: bool = False) -> None:
        """Wait for the shadow evaluations in flight (``cancel``: stop them instead). For tests
        and shutdown: a shadow evaluation never delays or changes a check."""
        tasks = list(self._shadow_tasks)
        if cancel:
            for task in tasks:
                task.cancel()
        if tasks:
            await asyncio.wait(tasks)

    @staticmethod
    def _floor_lost(
        run: _Run, tenant_id: str, guard_point: str, problems: list[str], where: str
    ) -> Verdict:
        """The floor the bundle requires is missing or weakened. Fail closed;
        the error log names each key and what differed (page-worthy)."""
        listed = "; ".join(problems)
        logger.error(
            "FLOOR LOST tenant=%s guard_point=%s: the %s does not carry the catalog's floor: "
            "%s; blocking",
            tenant_id,
            guard_point,
            where,
            listed,
        )
        return run.finish(
            Decision.BLOCK,
            Reason.INTERNAL_ERROR,
            detail=f"floor mismatch in the {where}: {listed}",
        )

    async def __aenter__(self) -> GuardService:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()

    # ------------------------------------------------------------------ the check

    async def check(self, ctx: CheckContext, guard_point: str, content: str) -> Verdict:
        """Check ``content`` at ``guard_point`` for the tenant named by ``ctx``'s verified
        signed context. Returns a verdict and never raises, except ``CancelledError`` when the
        caller is cancelled. There is deliberately no tenant parameter."""
        run = _Run(self, ctx, guard_point)
        run.trace = self._start_trace()
        verdict: Verdict | None = None
        try:
            try:
                verdict = await self._check(run, ctx, guard_point, content)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.exception("guard check failed; failing closed")
                verdict = run.fail_closed(f"unexpected {type(exc).__name__}")
            try:
                self._audit.record(verdict)
            except Exception:
                logger.exception("audit sink failed for request %s", verdict.request_id)
            if self._escalations is not None and verdict.decision is Decision.ESCALATE:
                self._route_escalation(run, verdict)
            if self._content is not None:
                self._store_content(run, verdict)
            return verdict
        finally:
            self._end_trace(run.trace, verdict)

    def attach_escalations(self, escalations: EscalationSink | None) -> None:
        """Set where ``escalate`` verdicts go (M4-05), for a composition root that builds the
        router after the service (the router needs the stores, the service needs neither)."""
        self._escalations = escalations

    def attach_content(self, content: ContentSubmitter | None) -> None:
        """Set where stored content goes (M5-03), for a composition root that builds the writer
        after the service."""
        self._content = content

    def _store_content(self, run: _Run, verdict: Verdict) -> None:
        """Hand a check's content to the class C writer, **only** if the version that decided it
        says ``store_content: full`` and the check got as far as redaction: what is handed over
        is ``run.held_content``, the post-redaction text the model saw, and never the raw
        content. Never raises, never waits."""
        try:
            policy = run.policy
            if (
                run.scope is None
                or policy is None
                or self._content is None
                or policy.store_content != "full"
                or run.held_content is None
                or verdict.content_sha256 is None
            ):
                return
            from guardrail_engine.content.writer import ContentRequest

            self._content.submit(
                ContentRequest(
                    tenant_id=run.scope.tenant_id,
                    request_id=verdict.request_id,
                    guard_point=verdict.guard_point,
                    ts=verdict.checked_at,
                    content=run.held_content,
                    content_sha256=verdict.content_sha256,
                    bundle_version=verdict.bundle_version,
                    requested_days=policy.content_days,
                    packs=tuple(verdict.retention_packs),
                )
            )
        except Exception:
            logger.exception("stored content could not be handed over for %s", verdict.request_id)

    def _route_escalation(self, run: _Run, verdict: Verdict) -> None:
        """Hand an ``escalate`` verdict to the router (M4-05). Never raises, never waits."""
        try:
            from guardrail_engine.escalation.router import request_from_check

            policy = run.policy
            if run.scope is None or policy is None or self._escalations is None:
                return
            self._escalations.submit(
                request_from_check(
                    run.scope,
                    verdict,
                    target=policy.escalation_target,
                    url=policy.escalation_url,
                    store_content=policy.store_content,
                    class_d_total=policy.class_d_total,
                    content=run.held_content,
                )
            )
        except Exception:
            logger.exception("escalation routing failed for request %s", verdict.request_id)

    async def evaluate_draft(
        self,
        scope: TenantScope,
        policy: GuardPointPolicy,
        content: str,
        *,
        tool: str | None = None,
        request_id: str | None = None,
        usage_class: str = "test",
        conversation: tuple[Any, ...] = (),
    ) -> Verdict:
        """Run ``content`` through a draft's compiled ``policy`` exactly as a check would
        (size limit, redaction, render, one decision call, fusion), for the Admin API's test
        endpoint (M2-05). Differences, all deliberate: the tenant is the verified ``scope``
        (the policy must be that tenant's), the policy is the one given instead of the cached
        one, **nothing is written to the audit sink** (it is not production traffic), and the
        model call is metered under the usage class ``usage_class`` (``test`` for the test
        endpoint, ``screen`` for tool-description screening) so production figures are
        untouched. Returns a verdict and never raises, except ``CancelledError``."""
        guard_point = policy.guard_point
        run = _Run(self, _DraftContext(request_id), guard_point)
        run.fields["tenant_id"] = scope.tenant_id
        if policy.tenant_id != scope.tenant_id:  # a caller bug: refuse rather than cross over
            return run.fail_closed("the policy is another tenant's")
        run.fields.update(
            bundle_version=policy.version,
            bundle_hash=policy.bundle_hash,
            policy_source=PolicySource.ACTIVE,
            policy_error=None,
        )
        try:
            return await self._evaluate(
                run,
                scope.tenant_id,
                guard_point,
                content,
                conversation,
                tool,
                policy,
                usage_class=usage_class,
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.exception("draft evaluation failed; failing closed")
            return run.fail_closed(f"unexpected {type(exc).__name__}")

    def refuse_closed(self, ctx: Any, guard_point: Any, content: Any) -> Verdict:
        """The verdict for a check that arrives once the engine has started shutting down
        (M1-11, decided 2026-11-17): ``block``, reason ``engine_closed``, retryable, with no
        policy lookup, no model call and nothing sent to the provider. It is built through
        the same :class:`Verdict` validation as any other, sent to the audit sink, and gets a
        check span (no model-call span).

        Safe to call after :meth:`aclose`: it uses only the verifier, the audit sink and the
        telemetry port. Never raises. The tenant id is recorded only when the signed context
        verifies; otherwise it is None, as for any record of an unverified request."""
        run = _Run(self, ctx, guard_point)
        run.trace = self._start_trace()
        verdict: Verdict | None = None
        try:
            try:
                verdict = self._refuse_closed(run, ctx, content)
            except Exception as exc:
                logger.exception("could not build the engine_closed verdict; minimal one used")
                verdict = _minimal_closed_verdict(run, f"unexpected {type(exc).__name__}")
            try:
                self._audit.record(verdict)
            except Exception:
                logger.exception("audit sink failed for request %s", verdict.request_id)
            return verdict
        finally:
            self._end_trace(run.trace, verdict)

    def _refuse_closed(self, run: _Run, ctx: Any, content: Any) -> Verdict:
        try:
            verified = self._verifier.verify(getattr(ctx, "signed_context", None))
        except Exception:  # unverified: no tenant is recorded, and the refusal stands
            verified = None
        if verified is not None:
            run.fields["tenant_id"] = verified.tenant_id
        if isinstance(content, str):
            run.fields["content_sha256"] = content_sha256(content)
        return run.finish(
            Decision.BLOCK,
            Reason.ENGINE_CLOSED,
            detail="the engine is shutting down and accepts no new checks",
        )

    # ------------------------------------------------------------------ telemetry
    # Telemetry never raises into the check path and never changes a verdict (AC-O2).

    # ------------------------------------------------------------------ the shadow candidate

    def _start_shadow(
        self,
        scope: TenantScope,
        guard_point: str,
        content: str,
        conversation: Any,
        tool: str | None,
        candidate: GuardPointPolicy,
        run: _Run,
    ) -> asyncio.Future[Verdict]:
        """Evaluate the candidate beside the active version (M4-03): the same content and
        context through its own compiled policy, metered under the ``shadow`` usage class, with
        nothing written to the audit sink. It runs concurrently with the active evaluation, so a
        check isn't made slower by it beyond :attr:`GuardConfig.shadow_wait_s`, and it never
        acts."""
        task = asyncio.ensure_future(
            self.evaluate_draft(
                scope,
                candidate,
                content,
                tool=tool,
                request_id=run.fields["request_id"],
                usage_class="shadow",
                conversation=tuple(conversation),
            )
        )
        self._shadow_tasks.add(task)
        task.add_done_callback(self._shadow_tasks.discard)
        return task

    async def _finish_shadow(
        self,
        verdict: Verdict,
        task: asyncio.Future[Verdict],
        scope: TenantScope,
        guard_point: str,
        active_version: int,
    ) -> Verdict:
        """Put the candidate's decision into the active verdict (so the audit record holds
        it) if it is ready within the wait, and count the comparison when it is. The active
        verdict is the verdict: the candidate changes nothing about it."""
        task.add_done_callback(
            lambda t: self._count_shadow(t, verdict, scope, guard_point, active_version)
        )
        if not task.done() and verdict.model_called:
            # No wait after a verdict that took no model call (a deterministic block, an empty
            # guard point): the caller isn't held for a candidate the verdict didn't need. The
            # comparison is counted when it finishes, as always.
            await asyncio.wait({task}, timeout=self._config.shadow_wait_s)
        if task.done() and not task.cancelled() and task.exception() is None:
            candidate = task.result()
            return verdict.model_copy(
                update={
                    "candidate_decision": str(candidate.decision),
                    "candidate_reason": str(candidate.reason),
                }
            )
        return verdict

    def _count_shadow(
        self,
        task: asyncio.Future[Verdict],
        active: Verdict,
        scope: TenantScope,
        guard_point: str,
        active_version: int,
    ) -> None:
        tenant_id = scope.tenant_id
        if task.cancelled() or task.exception() is not None:
            return
        candidate = task.result()
        if candidate.reason is Reason.PROVIDER_SAFETY:
            # PF-12: a provider refusal of a candidate call is only logged.
            logger.info(
                "candidate version %s of tenant %s was refused by the provider at %s; logged only",
                candidate.bundle_version,
                tenant_id,
                guard_point,
            )
        if self._shadow is None or candidate.bundle_version is None:
            return
        try:
            self._shadow.record(
                observe(
                    tenant_id,
                    guard_point,
                    active,
                    candidate,
                    active_version,
                    candidate.bundle_version,
                    scope,
                )
            )
        except Exception:
            logger.exception("shadow sink failed; ignored")

    def _start_trace(self) -> CheckTrace:
        try:
            return self._telemetry.start_check()
        except Exception:
            logger.exception("telemetry failed to start a check span; ignored")
            return NULL_TRACE

    @staticmethod
    def _end_trace(trace: CheckTrace, verdict: Verdict | None) -> None:
        try:
            attributes = cancelled_attributes() if verdict is None else check_attributes(verdict)
            trace.end(attributes, error=check_failed(verdict))
        except Exception:
            logger.exception("telemetry failed to end a check span; ignored")

    @staticmethod
    def _trace_model_call_started(trace: CheckTrace) -> None:
        try:
            trace.model_call_started()
        except Exception:
            logger.exception("telemetry failed to start a model-call span; ignored")

    @staticmethod
    def _trace_model_call_ended(
        trace: CheckTrace, model_id: str | None, result: object, timing: CheckTiming | None
    ) -> None:
        try:
            trace.model_call_ended(
                model_call_attributes(model_id=model_id, result=result, timing=timing)
            )
        except Exception:
            logger.exception("telemetry failed to end a model-call span; ignored")

    def report_identifier_patterns_dropped(self, tenant_id: str) -> None:
        """Report that some of ``tenant_id``'s identifier patterns are left out of the scan
        (the directory's source calls this): the log line, the meter and the alert."""
        self._identifier_patterns_dropped(tenant_id)

    def _gateway_or_shared(self, project: str | None) -> DecisionGateway:
        """For metering and labels only: the project's gateway, or the shared one when the
        project has none (the check itself fails closed in :meth:`_decide`)."""
        return self._project_gateways.get(project, self._gateway) if project else self._gateway

    def _identifier_patterns_dropped(self, tenant_id: str) -> None:
        """The scan left ``tenant_id``'s identifier patterns out: a fixed-word log
        line, and the gateway's meter and alert. Never the patterns."""
        logger.error(
            "cross-tenant identifier patterns of tenant %s did not compile or failed validation "
            "and are dropped from the scan",
            tenant_id,
        )
        self._gateway.identifier_patterns_dropped(tenant_id)

    def _identifier_scan_sharded(self) -> None:
        """The combined identifier set couldn't be built and the scan now matches over shards: a
        fixed-word log line and the gateway's warning. Nothing is dropped."""
        logger.error(
            "the combined cross-tenant identifier set could not be built; "
            "the scan now matches over shards"
        )
        self._gateway.identifier_scan_sharded()

    async def _deterministic_checks(
        self,
        run: _Run,
        tenant_id: str,
        guard_point: str,
        content: str,
        tool: str | None,
        policy: GuardPointPolicy,
    ) -> list[DeterministicHit] | Verdict:
        """Step 4's rules, all of them (so the record shows every rule that fired, not only
        the first): the hits, or a fail-closed verdict if the cross-tenant scan couldn't run.
        Only rule ids and counts are kept, never what matched."""
        checks = policy.checks
        hits: list[DeterministicHit] = []
        if guard_point == "tool_call":
            # M3-03: the arguments' schema first, then the allow-list and the mismatch check.
            info = _registered_tool(policy, tenant_id, tool)
            if info is not None and (hit := check_tool_schema(info.arguments_schema, content)):
                hits.append(hit)
            if (hit := check_tool_allowlist(checks, tool)) is not None:
                hits.append(hit)
            if (hit := check_tool_mismatch(content, tool)) is not None:
                hits.append(hit)
        if guard_point == "plan" and (hit := check_plan_allowlist(checks, content)) is not None:
            hits.append(hit)
        if checks.deny_rules:
            if len(content) > REDACT_OFF_LOOP_CHARS:  # a worker thread, as for redaction
                hits += await asyncio.to_thread(scan_deny_patterns, checks, content)
            else:
                hits += scan_deny_patterns(checks, content)
        if guard_point in CROSS_TENANT_GUARD_POINTS:
            try:
                hit = await self._scanner.scan(tenant_id, content)
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # a floor scan that can't run must not become an allow
                logger.error(
                    "cross-tenant identifier scan failed (%s) for request %s; blocking",
                    type(exc).__name__,
                    run.fields["request_id"],
                )
                return run.finish(
                    Decision.BLOCK,
                    Reason.INTERNAL_ERROR,
                    detail=f"cross-tenant identifier scan failed: {type(exc).__name__}",
                )
            if hit is not None:
                hits.append(hit)
        return hits

    async def _tenant_ended(self, tenant_id: str) -> bool | None:
        """True if ended, False if not, None if the status can't be read. The
        directory itself decides how long "can't be read" may still count as "not ended" (its
        last successful read of the tenant must be under ``max_unknown_s`` old); what raises
        here is past that, and the check fails closed."""
        assert self._ended is not None
        try:
            return bool(
                await asyncio.wait_for(self._ended(tenant_id), self._config.store_timeout_s)
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.error("tenant status unavailable (%s); failing closed", type(exc).__name__)
            return None

    async def _check(self, run: _Run, ctx: Any, guard_point: Any, content: Any) -> Verdict:
        # 1. The tenant comes from the verified signed context only (AC-T1).
        try:
            verified = self._verifier.verify(getattr(ctx, "signed_context", None))
        except ContextVerificationError as e:
            logger.warning("signed tenant context rejected: %s", e.reason)
            return run.finish(
                Decision.FORBIDDEN, Reason.CONTEXT_INVALID, detail=recorded_code(e.reason)
            )
        tenant_id = verified.tenant_id
        run.fields["tenant_id"] = tenant_id
        run.scope = verified.scope
        claimed = getattr(ctx, "payload_tenant_id", None)
        if claimed is not None and claimed != tenant_id:
            logger.warning(
                "request %s: payload tenant %r differs from the signed context's %r; forbidden",
                run.fields["request_id"],
                _label(claimed, 128),
                tenant_id,
            )
            return run.finish(
                Decision.FORBIDDEN,
                Reason.TENANT_MISMATCH,
                claimed_tenant_id=_label(claimed, 128),
                detail="the payload's tenant id differs from the signed context's",
            )

        # 1b. A terminating or terminated tenant is refused with its own code (M5-07), before
        # any policy is read and with no tenant id on the verdict or its audit record, so a
        # refused check writes nothing under the tenant that offboarding is deleting. If the
        # directory can't answer, the check goes on only while the directory's last successful
        # read of this tenant is recent (5 minutes by default); after that, or for a
        # tenant it never read, the check fails closed as ``policy_unavailable`` (retryable),
        # so a last-known-good policy can't keep serving a tenant whose status is unconfirmed.
        if self._ended is not None:
            ended = await self._tenant_ended(tenant_id)
            if ended is None:
                return run.finish(
                    Decision.BLOCK,
                    Reason.POLICY_UNAVAILABLE,
                    policy_error="the tenant's status could not be confirmed",
                )
            if ended:
                run.fields["tenant_id"] = None
                run.scope = None
                return run.finish(
                    Decision.FORBIDDEN,
                    Reason.TENANT_TERMINATED,
                    detail="the tenant has been terminated",
                )

        # 2. Request shape.
        if not isinstance(guard_point, str) or guard_point not in GUARD_POINTS:
            return run.finish(Decision.BLOCK, Reason.INVALID_REQUEST, detail="unknown guard point")
        if not isinstance(content, str):
            return run.finish(Decision.BLOCK, Reason.INVALID_REQUEST, detail="content is not text")
        conversation = getattr(ctx, "conversation", ())
        if not isinstance(conversation, tuple | list):
            return run.finish(
                Decision.BLOCK, Reason.INVALID_REQUEST, detail="conversation is not a sequence"
            )
        for i, item in enumerate(conversation):
            if (problem := context_item_problem(item)) is not None:
                return run.finish(
                    Decision.BLOCK, Reason.INVALID_REQUEST, detail=f"conversation[{i}]: {problem}"
                )
        tool = getattr(ctx, "tool", None)
        if tool is not None and not isinstance(tool, str):
            return run.finish(Decision.BLOCK, Reason.INVALID_REQUEST, detail="tool is not text")
        conversation_id = getattr(ctx, "conversation_id", None)
        if conversation_id is not None and not (
            isinstance(conversation_id, str)
            and 1 <= len(conversation_id) <= MAX_CONVERSATION_ID_CHARS
            and conversation_id.isprintable()
        ):
            return run.finish(
                Decision.BLOCK, Reason.INVALID_REQUEST, detail="conversation_id is not valid"
            )
        run.fields["context_items"] = len(conversation)

        # 3. The candidate (M4-03, PF-7): which version decides this conversation. Read first:
        # a candidate that changed makes the cache read the active pointer again.
        assignment = ACTIVE_ASSIGNMENT
        if self._rollout is not None:
            assignment = await self._rollout.assign(
                verified.scope, getattr(ctx, "conversation_id", None)
            )
        # 4. Policy: cached per (tenant, version, guard point), or last-known-good.
        try:
            lookup = await self._cache.get(verified.scope, guard_point)
        except PolicyUnavailable as e:
            return run.finish(Decision.BLOCK, Reason.POLICY_UNAVAILABLE, policy_error=e.detail)
        policy = lookup.policy
        shadow_task: asyncio.Future[Verdict] | None = None
        if self._rollout is not None and assignment.ref is not None:
            candidate = await self._rollout.policy(verified.scope, assignment.ref, guard_point)
            if candidate is None:
                pass  # it can't be served: the active version decides (logged, counted)
            elif assignment.role == "candidate":
                policy = candidate  # an enforce candidate decides this conversation
                run.fields["candidate_version"] = candidate.version
            else:
                run.fields["candidate_version"] = candidate.version
                shadow_task = self._start_shadow(
                    verified.scope, guard_point, content, conversation, tool, candidate, run
                )
        run.fields.update(
            bundle_version=policy.version,
            bundle_hash=policy.bundle_hash,
            policy_source=lookup.source if policy is lookup.policy else PolicySource.ACTIVE,
            policy_error=lookup.error if policy is lookup.policy else None,
        )
        run.policy = policy
        verdict = await self._evaluate(
            run, tenant_id, guard_point, content, conversation, tool, policy
        )
        if shadow_task is not None:
            verdict = await self._finish_shadow(
                verdict, shadow_task, verified.scope, guard_point, lookup.policy.version
            )
        return verdict

    async def _decide(
        self,
        tenant_id: str,
        guard_point: str,
        texts: list[str],
        questions: Mapping[str, Any],
        usage_class: str,
        tier: str | None,
        project: str | None = None,
    ) -> Any:
        """The decision call(s) of a check: the gateway's outcome for one rendered input, or,
        for a chunked ``tool_result`` (M3-04), one call per chunk **submitted together**, each
        going through the gateway's admission control as any call does, then combined
        (:func:`~guardrail_engine.guard.chunking.combine`): the merged answer, or the failure
        of any chunk. Nothing here assumes the calls run in parallel on one key."""
        extra = {} if usage_class == USAGE_CHECK else {"usage_class": usage_class}
        gateway = self.gateway_for(project)  # LookupError: no backend, a model failure (M5-06)

        def call(text: str, **more: Any) -> Any:
            return gateway.decide_timed(
                tenant_id=tenant_id,
                guard_point=guard_point,
                input=text,
                questions=questions,
                tier=tier,
                **extra,
                **more,
            )

        if len(texts) == 1:
            return await call(texts[0])
        # Chunks: submitted together; the first chunk to fail (or be refused) ends the check as
        # a model failure whatever the others say, so the chunk calls still **queued** for a
        # slot are cancelled, to spend no more admissions on an answer that can't change
        # . Calls already in flight are left to end: cancelling them
        # mid-flight would leave orphans holding slots. (A chunk admitted in the instant the
        # failed call freed its slot may already be sent; the queue behind it is cancelled.)
        admitted = [asyncio.Event() for _ in texts]
        # M3-09: the chunks of one check are charged to the tenant together (all or none) and
        # take one place in the fair queue; each still needs its own in-flight slot.
        group = gateway.check_group(texts, questions)
        tasks = [
            asyncio.ensure_future(call(text, on_admitted=event.set, group=group, group_index=i))
            for i, (text, event) in enumerate(zip(texts, admitted, strict=True))
        ]
        failed = False
        try:
            pending = set(tasks)
            while pending:
                done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
                if not failed and any(not _chunk_answered(t) for t in done):
                    failed = True
                    for task, event in zip(tasks, admitted, strict=True):
                        if task in pending and not event.is_set():
                            task.cancel()
        finally:  # the caller was cancelled (or something broke): leave nothing running
            for task in tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
        settled = [t for t in tasks if not t.cancelled()]
        for task in settled:
            if task.exception() is not None:
                raise task.exception()  # resolved by the caller like a raising gateway
        outcomes = [t.result() for t in settled]
        if not all(isinstance(outcome, TimedDecision) for outcome in outcomes):
            return outcomes[0]  # not what the gateway promises: resolved like any garbage
        return combine(outcomes)

    async def _evaluate(
        self,
        run: _Run,
        tenant_id: str,
        guard_point: str,
        content: str,
        conversation: Any,
        tool: str | None,
        policy: GuardPointPolicy,
        usage_class: str = USAGE_CHECK,
    ) -> Verdict:
        """Steps 4 to 7 of a check, on a policy already chosen: the size limit, redaction,
        rendering, the one decision call and the fusion. ``usage_class`` is
        :data:`~guardrail_engine.gateway.gateway.USAGE_CHECK` for production traffic; a draft
        test passes ``"test"`` and is metered apart (M2-05)."""
        if policy.records_days is not None:  # R3 class B retention for this version
            run.fields["retention_days"] = policy.records_days
            run.fields["retention_packs"] = policy.packs
        # The compiled set must carry every floor rule the bundle's floor version requires at
        # this guard point, unweakened: a lost or weakened floor must never
        # become a silent allow.
        if problems := _floor_problems(
            policy.floor_specs, policy.questions, policy.rules, self._settings.floor_fail_mode
        ):
            return self._floor_lost(run, tenant_id, guard_point, problems, "compiled policy")

        # 4. Deterministic checks (M3-01, AC-G1). The size limit first, on the raw content,
        # never truncated; then the allow-list, the deny patterns and the cross-tenant scan.
        # A deterministic block makes no model call.
        tokens = count_tokens(content)
        run.fields.update(content_sha256=content_sha256(content), content_tokens=tokens)
        # M3-04: ``tool_result`` is chunked, so its size limit is the most chunks one result
        # may need; the exact count is taken on the redacted content, which is what is cut.
        chunked = guard_point == CHUNKED_GUARD_POINT
        cap = policy.max_content_tokens
        if chunked:
            cap *= self._settings.max_chunks_per_result
        if tokens > cap:
            return run.finish(
                Decision.BLOCK,
                Reason.CONTENT_TOO_LARGE,
                deterministic=(size_limit_hit(),),
                detail=f"content is {tokens} tokens; the cap is {cap}"
                + (f" ({self._settings.max_chunks_per_result} chunks)" if chunked else ""),
            )
        found = await self._deterministic_checks(run, tenant_id, guard_point, content, tool, policy)
        if isinstance(found, Verdict):
            return found
        hits = found
        run.fields["deterministic"] = tuple(hits)
        if any(h.action is DeterministicAction.BLOCK for h in hits):
            return run.finish(Decision.BLOCK, Reason.DETERMINISTIC)
        # M3-03: a read-only tool the registry marks ``skip_model`` skips the
        # tenant's and packs' questions only: the floor's are still asked. Every deterministic
        # check above has run; a block already ended the check.
        rules, all_questions, skipped = policy.rules, policy.questions, False
        if guard_point == "tool_call":
            info = _registered_tool(policy, tenant_id, tool)
            if info is not None and info.skip_model:
                skipped = True
                rules = {k: r for k, r in policy.rules.items() if r.layer == "floor"}
                all_questions = {k: q for k, q in policy.questions.items() if k in rules}
                run.fields["model_skipped"] = True
                if usage_class == USAGE_CHECK:
                    self._gateway_or_shared(policy.profile.attributes.project).model_skipped(
                        tenant_id, guard_point
                    )
        if not all_questions:  # only reachable when the floor doesn't cover this point
            if skipped:
                return run.finish(Decision.ALLOW, Reason.POLICY)
            return run.finish(Decision.ALLOW, Reason.NO_QUESTIONS)

        # 5. Redact, then render (B3). The TENANT header's id is the verified tenant id; the
        # slug is from that tenant's directory entry. The policy cache only compiles an entry
        # whose id is the tenant's, and this re-checks it, so the header can't name another
        # tenant.
        if policy.profile.tenant_id != tenant_id:
            logger.error(
                "tenant %s: the compiled policy carries the directory entry of %r; blocking",
                tenant_id,
                _label(policy.profile.tenant_id, 128),
            )
            return run.finish(
                Decision.BLOCK,
                Reason.INTERNAL_ERROR,
                detail="the tenant directory entry is another tenant's",
            )

        # Redaction (M1-14, AC-G2): after the raw size bound, before anything is rendered or
        # sized for sending. A failure sends nothing. Only the exception's type is logged: its
        # text could quote the content. A large request is redacted in a worker thread, so a
        # crafted input can't hold the event loop.
        deny_rules = policy.checks.deny_rules
        has_redact_rules = any(r.action is DeterministicAction.REDACT for r in deny_rules)

        def redact() -> RedactedRequest:
            return redact_request(
                content=content,
                conversation=conversation,
                tools=policy.profile.tools,
                detector=self._pii_detector,
                # M3-01: a tenant's ``redact`` deny patterns, before the PII detector.
                deny_redactor=(lambda text: redact_deny_patterns(deny_rules, text))
                if has_redact_rules
                else None,
            )

        try:
            if request_chars(content, conversation) > REDACT_OFF_LOOP_CHARS:
                redacted = await asyncio.to_thread(redact)
            else:
                redacted = redact()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.error(
                "PII redaction failed (%s) for request %s; blocking, nothing sent",
                type(exc).__name__,
                run.fields["request_id"],
            )
            return run.finish(
                Decision.BLOCK,
                Reason.INTERNAL_ERROR,
                redaction=RedactionStatus.FAILED,
                detail=f"PII redaction failed: {type(exc).__name__}",
            )
        run.fields.update(redaction=RedactionStatus.APPLIED, pii_redacted=dict(redacted.counts))
        run.held_content = redacted.content
        if redacted.deny_counts:
            hits = [*hits, *redact_hits(deny_rules, redacted.deny_counts)]
            run.fields["deterministic"] = tuple(hits)
        sent_tokens = count_tokens(redacted.content)
        if chunked:  # M3-04: cut the redacted content, once, after everything whole-content
            if len(redacted.content) > REDACT_OFF_LOOP_CHARS:  # a worker thread, as for redaction
                pieces = await asyncio.to_thread(
                    split_chunks, redacted.content, policy.max_content_tokens
                )
            else:
                pieces = split_chunks(redacted.content, policy.max_content_tokens)
            if len(pieces) > self._settings.max_chunks_per_result:
                return run.finish(
                    Decision.BLOCK,
                    Reason.CONTENT_TOO_LARGE,
                    detail=(
                        f"content needs {len(pieces)} chunks after redaction; "
                        f"the cap is {self._settings.max_chunks_per_result}"
                    ),
                )
        else:
            pieces = [redacted.content]
            if sent_tokens > policy.max_content_tokens:  # placeholders can outgrow short PII
                return run.finish(
                    Decision.BLOCK,
                    Reason.CONTENT_TOO_LARGE,
                    detail=(
                        f"content is {sent_tokens} tokens after redaction; "
                        f"the cap is {policy.max_content_tokens}"
                    ),
                )
        rendered_inputs = [
            render_input(
                domain=policy.profile.domain,
                tenant_slug=policy.profile.slug,
                tenant_id=tenant_id,
                guard_point=guard_point,
                content=piece,
                conversation=redacted.conversation,
                tools=redacted.tools,
                max_content_tokens=policy.max_content_tokens,
                nonce_source=self._nonce_source,
                content_tokens=sent_tokens if len(pieces) == 1 else count_tokens(piece),
            )
            for piece in pieces
        ]
        run.fields.update(
            context_items_dropped=max(r.context_items_dropped for r in rendered_inputs),
            chunks=len(rendered_inputs),
        )

        # 6. One decision call. ``model_called``: the engine took the model path, whether or
        # not the gateway then sent anything; ``provider_calls`` says what was sent,
        # unknown (None) until the gateway reports its timing.
        model_id = self._gateway_or_shared(policy.profile.attributes.project).model_id
        run.fields.update(model_called=True, model_id=model_id, provider_calls=None)
        questions = dict(all_questions)  # exactly what is handed to the gateway
        result: Any = None
        timing: CheckTiming | None = None
        capacity: tuple[int | None, bool] = (None, False)  # R8, from the gateway only
        engine_detail: str | None = None  # the only detail a model failure records
        self._trace_model_call_started(run.trace)
        started = self._clock()
        try:
            timed = await self._decide(
                tenant_id,
                guard_point,
                [r.text for r in rendered_inputs],
                questions,
                usage_class,
                policy.profile.attributes.tier,  # M3-07: the tenant's share and weight
                policy.profile.attributes.project,  # M5-06: the tenant's Gemini project
            )
            if isinstance(timed, TimedDecision):
                result, timing = timed.result, timed.timing
                # M1-04 metering: queue wait and provider time, and how many requests were
                # actually sent (0 for an admission refusal, orphan cap or open breaker).
                run.fields.update(
                    queue_wait_ms=timing.queue_wait_ms,
                    provider_latency_ms=timing.provider_latency_ms,
                    provider_calls=timing.provider_calls,
                    in_flight_at_start=timing.in_flight_at_start,
                )
                capacity = (timed.retry_after_ms, timed.capacity_limited)
            else:  # not what the gateway promises: resolved below like any garbage result
                result = timed
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # the gateway promises not to raise; resolve it as B1 anyway
            logger.exception("decision gateway raised")
            engine_detail = f"gateway raised {type(exc).__name__}"
            result = Failed(kind=FailureKind.OTHER, message=engine_detail)
        finally:
            run.fields["model_latency_ms"] = (self._clock() - started) * 1000
            self._trace_model_call_ended(run.trace, model_id, result, timing)
        if not isinstance(result, Answered | SafetyBlocked | Failed):
            engine_detail = f"gateway returned {type(result).__name__}"
            result = Failed(kind=FailureKind.OTHER, message=engine_detail)
            capacity = (None, False)  # whatever came with a broken result means nothing
        elif isinstance(result, SafetyBlocked | Failed) and result.message:
            # Provider (or gateway) free text: debug logs only, truncated, never the verdict,
            # the audit record or a span. It may echo the request.
            logger.debug(
                "decision call for tenant=%s guard_point=%s ended %s; message: %.200r",
                tenant_id,
                guard_point,
                result.outcome,
                result.message,
            )

        # Every floor question went into the call exactly as the catalog defines it.
        if problems := _sent_floor_problems(policy.floor_specs, questions):
            return self._floor_lost(run, tenant_id, guard_point, problems, "decision call")

        # 7. Resolve and fuse.
        if isinstance(result, SafetyBlocked):  # PF-12: whatever the modes and fail modes
            return run.finish(
                Decision.BLOCK,
                Reason.PROVIDER_SAFETY,
                failure_reason=recorded_code(result.reason),
            )

        if isinstance(result, Failed):  # B1: every rule by its own fail mode
            evaluated = evaluate_failed(rules)
            if problems := _unevaluated_floor_keys(policy.floor_specs, evaluated.rules):
                return self._floor_lost(run, tenant_id, guard_point, problems, "resolution")
            fused = fuse(evaluated.rules, call_failed=True)
            decision = Decision(fused.action.value)
            # R8: the retry hint and capacity flag only where the content was withheld.
            retry_after_ms, capacity_limited = (
                capacity if decision is not Decision.ALLOW else (None, False)
            )
            return run.finish(
                decision,
                fused.reason,
                rules=evaluated.rules,
                fired=fused.fired,
                failure_kind=result.kind,
                failure_reason=recorded_code(result.reason),
                detail=engine_detail,
                retry_after_ms=retry_after_ms,
                capacity_limited=capacity_limited,
            )

        evaluated = evaluate_answered(rules, all_questions, result)
        if problems := _unevaluated_floor_keys(policy.floor_specs, evaluated.rules):
            return self._floor_lost(run, tenant_id, guard_point, problems, "resolution")
        fused = fuse(evaluated.rules)
        if evaluated.violations:
            logger.warning(
                "contract_violation tenant=%s guard_point=%s keys=%s",
                tenant_id,
                guard_point,
                ",".join(f"{v.key}:{v.kind.value}" for v in evaluated.violations),
            )
        return run.finish(
            Decision(fused.action.value),
            fused.reason,
            rules=evaluated.rules,
            fired=fused.fired,
            probabilities=fused.probabilities,
            probabilities_raw=evaluated.probabilities_raw,
            contract_violations=evaluated.violations,
            usage=result.usage,
        )
