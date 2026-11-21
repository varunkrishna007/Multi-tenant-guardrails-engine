"""The verdict of one guard check: what the Guard Service returns and what it audits.

A verdict carries everything a later audit record (M1-06) needs, so that story never has to
reach back into the service: the decision and a machine-readable reason, every rule's
evaluation (probability, action, mode, layer, provisional flag, and why it got its action),
the fired rules, the bundle version and hash, the model id, usage, latency, the content hash
and, for a model failure, the failure kind.

**Decision vs reason.** ``decision`` says what happens to the content; ``reason`` says why.
Several reasons share a decision. In particular a policy block and a block caused by the
model failing look the same to the caller (``decision == BLOCK``, ``released`` is False) but
differ in ``reason``:

* ``Reason.POLICY``: the model answered and the tenant's rules decided.
* ``Reason.MODEL_FAILURE``: the decision call failed (timeout, 429, auth...). Every rule was
  resolved by its layer's fail mode (B1). ``failure_kind`` says how the call failed.
* ``Reason.PROVIDER_SAFETY``: the provider refused the content (PF-12).
* ``Reason.CONTRACT_VIOLATION``: the model answered, but the decision rests on rules whose
  answers were unusable and were resolved by fail mode (PF-6).

So "content blocked because the provider was down" can always be told apart from "content
blocked by policy", and a later product decision can treat them differently.

**Canonical pairs** (backlog B1, "How model failures are recorded and shown", amended at the
Guard Service review) are enforced when a verdict is built, see :data:`CANONICAL`. A pair
outside the table raises, and ``GuardService.check`` turns that into a fail-closed
``block``/``internal_error``, so a pipeline bug can never become a mislabelled release.
``allow``/``model_failure`` is valid only when every floor rule evaluated has fail mode
``open`` (B1's ``floor_fail_mode`` setting); with the default closed floor it can't occur.
``retryable`` is true for a verdict that didn't release the content and whose reason is
``model_failure``, ``policy_unavailable`` or ``engine_closed``, and false otherwise.
"""

from __future__ import annotations

import math
from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, model_validator

from guardrail_engine.decision.port import UNRECOGNISED_CODE as UNRECOGNISED_CODE
from guardrail_engine.decision.port import FailureKind, ProblemKind
from guardrail_engine.decision.port import recorded_code as recorded_code
from guardrail_engine.decision.types import Answer, Usage
from guardrail_engine.deterministic.rules import DeterministicAction, DeterministicKind
from guardrail_engine.guard.pii import PiiKind


class _Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class Decision(StrEnum):
    """What happens to the content. Only ``ALLOW`` releases it."""

    ALLOW = "allow"
    ESCALATE = "escalate"
    """Hold for a human or a supportive flow. M1 only returns it; dispatch is M4-05."""
    BLOCK = "block"
    FORBIDDEN = "forbidden"
    """The request was refused before any evaluation: its signed tenant context didn't
    verify, or its payload named another tenant (AC-T1). The HTTP layer maps it to 403."""


class Action(StrEnum):
    """What one rule calls for. Ordered by severity: allow < escalate < block."""

    ALLOW = "allow"
    ESCALATE = "escalate"
    BLOCK = "block"


SEVERITY: dict[Action, int] = {Action.ALLOW: 0, Action.ESCALATE: 1, Action.BLOCK: 2}


def most_severe(*actions: Action) -> Action:
    return max(actions, key=SEVERITY.__getitem__, default=Action.ALLOW)


class Reason(StrEnum):
    """Why the verdict is what it is. Stable strings: audit queries and the SDK use them."""

    POLICY = "policy"
    """The model answered and fusion over the tenant's rules decided (allow, escalate or
    block). Also the reason of an allow whose model call was skipped on purpose (M3-03: the
    tool's registry entry says ``skip_model``): the registry's policy decided, and
    ``Verdict.model_skipped`` says no model was asked. The canonical table (B1) is unchanged."""
    NO_QUESTIONS = "no_questions"
    """The guard point compiles to no questions (a disabled guard point the floor doesn't
    cover). Allowed without a model call, after the deterministic checks."""
    CONTENT_TOO_LARGE = "content_too_large"
    """Deterministic block: the content alone exceeds the guard point's max content tokens.
    Never truncated; no model call."""
    PROVIDER_SAFETY = "provider_safety"
    """The provider refused the content (HTTP 400 ``safety``). Always a block (PF-12)."""
    MODEL_FAILURE = "model_failure"
    """The decision call failed; each rule was resolved by its fail mode (B1). See
    ``failure_kind``. The decision is usually block (the floor fails closed)."""
    CONTRACT_VIOLATION = "contract_violation"
    """The decision rests on rules whose answers were missing, of the wrong type or out of
    range, resolved by their fail mode (PF-6)."""
    POLICY_UNAVAILABLE = "policy_unavailable"
    """No policy could be loaded for the tenant and there is no last-known-good one. Block,
    no model call: the floor can't be evaluated, so the content is not released."""
    TENANT_MISMATCH = "tenant_mismatch"
    """Forbidden: the payload's tenant id differs from the verified context's (AC-T1)."""
    CONTEXT_INVALID = "context_invalid"
    """Forbidden: the signed tenant context is missing, malformed, forged or expired."""
    TENANT_TERMINATED = "tenant_terminated"
    """Forbidden: the tenant is terminating or terminated (M5-07, R3 offboarding). Refused before
    any evaluation and before any policy is read; the verdict and its audit record carry no
    tenant id, so a refused check leaves nothing of the tenant behind. Not retryable."""
    INVALID_REQUEST = "invalid_request"
    """Block: the request itself is malformed (unknown guard point, content not text...)."""
    INTERNAL_ERROR = "internal_error"
    """Block: an unexpected error inside the Guard Service, or a compiled policy that has lost
    a floor rule the bundle's floor version requires. Fails closed."""
    DETERMINISTIC = "deterministic"
    """A deterministic rule (M3-01) decided: a ``block`` (deny pattern, tool outside the
    allow-list, another tenant's identifier) made before and without the model, or an
    ``escalate`` that the model's result, if it was less severe, didn't override. The rule is
    in ``Verdict.deterministic``, by id."""
    ENGINE_CLOSED = "engine_closed"
    """Block: the engine is shutting down and made no check (M1-11, decided 2026-11-17).
    Retryable (on another instance); no model or provider call. Not a provider failure, so
    it doesn't count towards provider-health alerting."""


CANONICAL: dict[Decision, frozenset[Reason]] = {
    Decision.ALLOW: frozenset({Reason.POLICY, Reason.NO_QUESTIONS, Reason.MODEL_FAILURE}),
    Decision.ESCALATE: frozenset({Reason.POLICY, Reason.DETERMINISTIC}),
    Decision.BLOCK: frozenset(
        {
            Reason.POLICY,
            Reason.DETERMINISTIC,
            Reason.MODEL_FAILURE,
            Reason.PROVIDER_SAFETY,
            Reason.CONTENT_TOO_LARGE,
            Reason.CONTRACT_VIOLATION,
            Reason.POLICY_UNAVAILABLE,
            Reason.INTERNAL_ERROR,
            Reason.ENGINE_CLOSED,
            Reason.INVALID_REQUEST,
        }
    ),
    Decision.FORBIDDEN: frozenset(
        {Reason.TENANT_MISMATCH, Reason.CONTEXT_INVALID, Reason.TENANT_TERMINATED}
    ),
}
"""The canonical (decision, reason) pairs. ``allow``/``model_failure`` carries an extra
condition: every floor rule evaluated has fail mode ``open``."""

RETRYABLE_REASONS = frozenset(
    {Reason.MODEL_FAILURE, Reason.POLICY_UNAVAILABLE, Reason.ENGINE_CLOSED}
)
"""The backlog's retryable reasons (B1 canonical list, M1-07; ``engine_closed`` added by
M1-11's shutdown decision)."""
RETRY_AFTER_MIN_MS = 100
RETRY_AFTER_MAX_MS = 10_000
"""R8's clamp on ``retry_after_ms``. The gateway applies it; the verdict refuses anything
outside it. (Kept here, not imported from the gateway, so the verdict model stays free of
gateway imports; a test asserts the two agree.)"""
QUOTA_EXHAUSTED = "quota_exhausted"
"""The failure reason of a refusal at the daily request cap or the monthly spend cap.
Its ``retry_after_ms`` is exempt from that ceiling."""

# ``recorded_code`` and ``UNRECOGNISED_CODE`` live in ``decision.port`` since M1-13,
# so the gateway bounds provider codes with the same rule; imported above and re-exported.


class RedactionStatus(StrEnum):
    """Whether the check's PII redaction ran (M1-14). Unset when the check ended before it
    (it runs only when content is about to be sent)."""

    APPLIED = "applied"
    """Every untrusted text was redacted; ``pii_redacted`` counts what was replaced."""
    FAILED = "failed"
    """The detector raised or returned unusable spans. Nothing was sent: the check failed
    closed with ``internal_error``."""


class DeterministicHit(_Frozen):
    """A deterministic rule (M3-01) that fired in one check: which one, by id, and what it
    did. **Never the text it matched**, nor a position or a length: a deny pattern's
    ``rule`` is ``deny__<id>``, and the other rules have fixed ids (see
    :mod:`guardrail_engine.deterministic.rules`)."""

    rule: str
    kind: DeterministicKind
    action: DeterministicAction
    layer: str
    """``tenant`` for a tenant's deny pattern or allow-list; ``floor`` for the platform's
    checks (the cross-tenant scan and the size limit), which no tenant can disable."""
    count: int = 1
    """How many matches the rule had (deny patterns); 1 for the others."""


def escalated_by_deterministic(
    decision: Decision, reason: Reason, hits: tuple[DeterministicHit, ...]
) -> tuple[Decision, Reason]:
    """The more severe of a result and the deterministic rules' ``escalate``. A
    deterministic ``block`` never gets here (it ends the check before the model). So only an
    ``allow`` changes, to ``escalate`` with reason ``deterministic``; a model escalate or
    block stands, with its own reason."""
    if decision is Decision.ALLOW and any(h.action is DeterministicAction.ESCALATE for h in hits):
        return Decision.ESCALATE, Reason.DETERMINISTIC
    return decision, reason


class Basis(StrEnum):
    """How a rule got its action."""

    ANSWER = "answer"
    """From the model's answer: thresholds for a ``noul`` rule; routers and scorers never
    act on their own."""
    FAIL_MODE = "fail_mode"
    """From the rule's fail mode: the call failed, or this rule's answer was unusable."""


class PolicySource(StrEnum):
    ACTIVE = "active"
    """The tenant's active version, as the policy store reports it now (within the cache's
    pointer TTL)."""
    LAST_KNOWN_GOOD = "last_known_good"
    """The store was unavailable, or the active version failed verification or compilation,
    so the last version that loaded and compiled for this tenant was used."""


class RuleEvaluation(_Frozen):
    """One compiled rule, evaluated in one check. Every rule of the guard point gets one,
    shadow rules included, unless the call never produced answers to evaluate
    (``PROVIDER_SAFETY``, or no model call at all)."""

    key: str
    layer: str
    """``floor``, ``pack`` or ``tenant``."""
    source: str
    """``platform/floor@1``, ``domain/insurance@3`` or ``tenant``."""
    question_type: str
    mode: str
    """``enforce`` or ``shadow``. A shadow rule is evaluated and recorded but never acts."""
    severity: str
    provisional: bool
    block_at: float | None
    escalate_at: float | None
    fail_mode: str
    max_action: str | None = None
    """``escalate`` for a rule capped at escalate (M4-10); None: no cap. Recorded so replay
    under new thresholds applies the same cap. Defaulted so records written earlier still
    load."""
    p: float | None
    """The (recalibrated) ``noul`` probability, or None for a router, a scorer, or a rule
    without a usable answer."""
    answer: Answer | None = None
    """The parsed answer, any question type, when there was a valid one."""
    action: Action
    """What the rule calls for. For a shadow rule, what it would have called for."""
    basis: Basis
    problem: ProblemKind | None = None
    """Set when the rule's answer was unusable (a contract violation, PF-6)."""

    @model_validator(mode="after")
    def _probability_matches_basis(self) -> RuleEvaluation:
        """An answered ``noul`` rule has a probability in [0, 1]; a rule resolved by
        its fail mode has none. A stored record edited or corrupted otherwise is refused on
        load, rather than replaying a block as an allow."""
        if self.basis is Basis.ANSWER and self.question_type == "noul":
            if not (
                isinstance(self.p, int | float)
                and not isinstance(self.p, bool)
                and math.isfinite(self.p)
                and 0.0 <= self.p <= 1.0
            ):
                raise ValueError(
                    f"rule {self.key!r}: an answered noul rule needs a probability in [0, 1], "
                    f"got {self.p!r}"
                )
        elif self.basis is Basis.FAIL_MODE and self.p is not None:
            raise ValueError(f"rule {self.key!r}: a rule resolved by fail mode has no probability")
        return self

    @property
    def acts(self) -> bool:
        """Whether this rule takes part in the decision (enforce, and not allow)."""
        return self.mode == "enforce" and self.action is not Action.ALLOW


class FiredRule(_Frozen):
    """A rule whose action is escalate or block, whether it acted (enforce) or was only
    recorded (shadow). ``p`` is None when the action came from the fail mode."""

    key: str
    p: float | None
    action: Action
    mode: str
    layer: str
    provisional: bool
    basis: Basis


class ContractViolation(_Frozen):
    """An unusable answer for one key (PF-6). Recorded for enforce and shadow rules alike;
    only an enforce rule's ``resolved_action`` takes part in the decision."""

    key: str
    kind: ProblemKind
    detail: str
    mode: str
    layer: str
    resolved_action: Action


class Verdict(_Frozen):
    """The outcome of one ``GuardService.check``. Exactly one per check, also sent to the
    audit sink."""

    request_id: str
    tenant_id: str | None
    """The tenant from the verified signed context; None if it didn't verify."""
    claimed_tenant_id: str | None = None
    """The tenant id the request payload claimed, when it differs from the verified one."""
    guard_point: str
    decision: Decision
    reason: Reason
    detail: str | None = None
    """Engine-authored detail for operators: fixed wording plus identifiers, numbers and type
    names. Never provider or exception free text. Never parsed; use ``reason``."""

    fired: tuple[FiredRule, ...] = ()
    rules: tuple[RuleEvaluation, ...] = ()
    probabilities: dict[str, float] = Field(default_factory=dict)
    """Every ``noul`` rule's probability in this check, enforce and shadow (for replay): the
    **recalibrated** one, which the thresholds act on."""
    probabilities_raw: dict[str, float] = Field(default_factory=dict)
    """The same rules' probabilities **as the model gave them**, before recalibration (review
    23 §5): numbers only. A v1.1 recalibration map is fitted on these, while thresholds act
    on ``probabilities``. ``recalibrate`` is the identity in v1, so the two are equal today."""
    contract_violations: tuple[ContractViolation, ...] = ()
    deterministic: tuple[DeterministicHit, ...] = ()
    """The deterministic rules that fired (M3-01), by id: block, escalate, redact and log
    alike. Empty when none did, or the check ended before they ran."""

    bundle_version: int | None = None
    bundle_hash: str | None = None
    candidate_version: int | None = None
    """M4-03 (PF-7): the candidate version involved in this check: evaluated alongside the
    active version (shadow), or the version that decided (enforce, then equal to
    ``bundle_version``). None when no candidate was involved."""
    candidate_decision: str | None = None
    """The candidate's decision (``allow``, ``escalate``, ``block``) when it was evaluated
    alongside and finished in time; None otherwise (it never acts, so this is a record only)."""
    candidate_reason: str | None = None
    """The candidate's reason (``policy``, ``provider_safety``...). A ``provider_safety`` result
    on a candidate is only logged (PF-12)."""
    policy_source: PolicySource | None = None
    policy_error: str | None = None
    """Why the last-known-good version was used, or why no policy was available. Engine
    wording, error codes and exception type names only, never an exception's text."""

    model_called: bool = False
    """The engine took the model path: it handed the check to the decision gateway. True
    even when the gateway then sent nothing to the provider (an admission refusal, the
    orphan cap, an open auth breaker); see ``provider_calls``."""
    model_skipped: bool = False
    """M3-03: the tool's registry entry says ``skip_model``, so the tenant's and packs'
    questions were **not asked**; the floor's were (there is no full
    skip). ``model_called`` is True when the floor has questions at ``tool_call`` (it always
    does), and the verdict's rules are the floor's alone. Allowed, when it is, with reason
    ``policy``. Set on every verdict of a check the skip applied to, whatever the outcome;
    False on a check that ended before the skip (a deterministic block)."""
    chunks: int = 0
    """M3-04: how many chunks the content was sent as, one decision call each: 1 for content
    that fit one call, more for a ``tool_result`` over ``chunk_tokens``, 0 when no model call
    was made (a deterministic block). ``provider_calls`` and the timings are summed
    over the chunks."""
    provider_calls: int | None = 0
    """Requests actually sent to the provider for this check: 0 when the model path wasn't
    taken or the gateway refused the call itself, 1, or 2 after a retry. None only when the
    gateway broke its contract (raised, or returned something other than a timed result),
    so the count is unknown."""
    model_id: str | None = None
    usage: Usage | None = None
    failure_kind: FailureKind | None = None
    """For ``Reason.MODEL_FAILURE``: how the decision call failed."""
    failure_reason: str | None = None
    """A structured code, never free text (:func:`recorded_code`). For a model failure: the
    provider's own reason, when it gave one (e.g. ``API_KEY_INVALID``), or the gateway's when
    it refused the call itself: ``admission_wait`` or ``admission_queue_full`` (M1-04
    admission control), ``orphan_cap``. For ``provider_safety``: the provider's refusal code
    (e.g. ``safety``)."""

    content_sha256: str | None = None
    """``sha256:<hex>`` of the **pre-redaction** content: the content as submitted, before
    any redaction step (PF-14, R3; the redaction is M1-14's). Never sent to the model."""
    content_tokens: int | None = None
    """Estimated tokens of the content **as submitted**: the figure the size bound
    (``content_too_large``) is checked on, before redaction (M1-14). What is sent is sized on
    the redacted text."""
    redaction: RedactionStatus | None = None
    """Whether PII redaction ran (M1-14); None when the check ended before it."""
    pii_redacted: dict[PiiKind, int] = Field(default_factory=dict)
    """Spans replaced per PII kind, over the content and every context section (M1-14). Counts
    only: never values, positions or lengths. Kinds with none are left out."""
    context_items: int = 0
    """Conversation context items the request carried."""
    context_items_dropped: int = 0
    """How many of them (the oldest) were left out to fit the content budget."""

    checked_at: datetime
    latency_ms: float
    """Wall time of the whole check, model call included."""
    model_latency_ms: float | None = None
    """Time spent in the decision gateway (the model call, its budget and any retry),
    including ``queue_wait_ms``."""
    queue_wait_ms: float | None = None
    """Of that, time the decision call waited for admission on its API key (M1-04 admission
    control), summed over attempts. None when no decision call was made."""
    provider_latency_ms: float | None = None
    """Of that, time from sending each provider request until the gateway had its outcome,
    summed over attempts (M1-04 metering). None when no decision call was made."""
    in_flight_at_start: int | None = None
    """M1-15 (R6.3): provider calls in flight on the check's API key when the check reached
    the gateway, before any admission wait or fast failure: calls sent and not yet ended,
    orphans included; queued calls and this check's own call not counted. For the dogfood's
    in-flight-limit decision. None when no decision call was made."""
    retry_after_ms: int | None = None
    """R8: how long to wait before trying again, 100-10,000 ms, when the gateway refused or
    failed the decision call for a reason it can time (admission, the orphan cap, an open
    auth breaker). Computed by the gateway from its own state, never from the provider.
    Only on a ``model_failure`` verdict that didn't release the content; None otherwise."""
    capacity_limited: bool = False
    """R8: the gateway refused the decision call for lack of capacity (``admission_wait``,
    ``admission_queue_full``, ``orphan_cap``; ``token_rate`` with M3-10), as opposed to a
    provider failure. Set from the gateway's own signal, never from a reason string. Only
    on a ``model_failure`` verdict that didn't release the content."""
    retention_days: int | None = None
    """How long this check's decision record (R3 class B) is kept: the compiled policy's
    effective ``audit.records_days``, or, when no policy was loaded, the platform's longest
    class B term, so a record is never deleted before the tenant's real term (M1-06)."""
    retention_packs: tuple[str, ...] = ()
    """The domain packs the deciding version extends (``domain/<name>@<version>``). Not in the
    audit record; the decision-record writer uses it to clamp ``retention_days`` against the
    packs' R3 bounds (M4-07)."""
    floor_fail_mode: str | None = None
    """The platform's ``floor_fail_mode`` (B1) in force for this check, passed in from the
    platform settings, never read from compiled rules. Gates ``allow``/``model_failure``."""

    @model_validator(mode="after")
    def _raw_probabilities(self) -> Verdict:
        """Raw probabilities are numbers in [0, 1], one per rule that has a recalibrated one
        (a verdict built before they were recorded has none)."""
        for key, p in self.probabilities_raw.items():
            if key not in self.probabilities:
                raise ValueError(f"rule {key!r} has a raw probability but no recalibrated one")
            if not (
                isinstance(p, int | float)
                and not isinstance(p, bool)
                and math.isfinite(p)
                and 0.0 <= p <= 1.0
            ):
                raise ValueError(f"rule {key!r}: a raw probability must be in [0, 1]")
        return self

    @model_validator(mode="after")
    def _canonical_pair(self) -> Verdict:
        if self.reason not in CANONICAL[self.decision]:
            raise ValueError(
                f"({self.decision.value}, {self.reason.value}) is not a canonical verdict pair"
            )
        if (self.decision, self.reason) == (Decision.ALLOW, Reason.MODEL_FAILURE) and (
            self.floor_fail_mode != "open"
            or any(r.fail_mode != "open" for r in self.rules if r.layer == "floor")
        ):
            raise ValueError(
                "allow/model_failure needs the platform floor_fail_mode to be open (and every "
                "floor rule to carry it); the floor fails closed by default (B1)"
            )
        if (self.retry_after_ms is not None or self.capacity_limited) and not (
            self.reason is Reason.MODEL_FAILURE and self.decision is not Decision.ALLOW
        ):
            raise ValueError(
                "retry_after_ms and capacity_limited belong only to a model_failure verdict "
                "that didn't release the content (R8)"
            )
        if self.retry_after_ms is not None:
            # A ``quota_exhausted`` refusal carries the time until the Pacific midnight
            # or the 1st, with no ceiling.
            ceiling = None if self.failure_reason == QUOTA_EXHAUSTED else RETRY_AFTER_MAX_MS
            if self.retry_after_ms < RETRY_AFTER_MIN_MS or (
                ceiling is not None and self.retry_after_ms > ceiling
            ):
                raise ValueError(
                    f"retry_after_ms must be {RETRY_AFTER_MIN_MS}-{RETRY_AFTER_MAX_MS} "
                    f"(at least {RETRY_AFTER_MIN_MS} for quota_exhausted), "
                    f"got {self.retry_after_ms}"
                )
        return self

    @property
    def released(self) -> bool:
        """Whether the content may be released now. Only an allow releases it."""
        return self.decision is Decision.ALLOW

    @property
    def retryable(self) -> bool:
        """True only when the content was **not** released and the reason is
        ``model_failure``, ``policy_unavailable`` or ``engine_closed``: a transient platform
        problem, so the caller may show "temporarily unavailable, try again" (M1-07). Always
        False on an allow: there is nothing to retry."""
        return not self.released and self.reason in RETRYABLE_REASONS

    @property
    def provider_called(self) -> bool | None:
        """Whether at least one request was actually sent to the provider. None
        when unknown (see ``provider_calls``)."""
        return None if self.provider_calls is None else self.provider_calls > 0

    @property
    def problem_kinds(self) -> dict[str, ProblemKind]:
        """The answer-problem kind per rule whose answer was unusable (PF-6), e.g.
        ``{"p__secret": "missing"}``: the kind only, never the detail or the raw answer. Empty when
        every answer was usable or no answer came back (a failed
        call resolves rules by fail mode with no problem)."""
        return {ev.key: ev.problem for ev in self.rules if ev.problem is not None}

    @property
    def input_tokens(self) -> int | None:
        return None if self.usage is None else self.usage.total_input_tokens

    @property
    def provisional_rules(self) -> tuple[str, ...]:
        """Keys of every provisional rule evaluated in this check, fired or not (M1-06)."""
        return tuple(r.key for r in self.rules if r.provisional)

    @property
    def overhead_ms(self) -> float:
        """The service's own time: everything except the gateway call."""
        return self.latency_ms - (self.model_latency_ms or 0.0)
