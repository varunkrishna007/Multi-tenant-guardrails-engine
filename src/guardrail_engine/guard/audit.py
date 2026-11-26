"""The audit sink port and the decision record (M1-05, M1-06).

Every check produces exactly one verdict and hands it to the sink, whatever the outcome:
forbidden, deterministic block, policy unavailable, model failure or a fused decision.

``record`` is called synchronously on the request path, after the verdict is final, so it
must be quick and must not block: a real sink hands the verdict to a bounded queue (as the
gateway's sinks do). An exception from it is logged and never changes or loses the verdict
the caller receives.

**The audit record (AC-O1).** :meth:`AuditRecord.from_verdict` turns a verdict into the one
decision record kept for the check (design §Ops > Observability, extended by the backlog's
M1-06): the bundle version and hash, every evaluated rule's probability, the fired rules with
their ``action`` and ``provisional`` flag, the keys of every provisional rule evaluated, the
model-path fields and, for replay (:mod:`guardrail_engine.guard.replay`), every
rule's evaluation. It holds no content: only ``content_sha256``, the hash of the
**pre-redaction** content (as submitted, before any redaction step; PF-14, R3), and no
provider or exception free text. It is an R3 **class B** record and carries the
time it may be deleted after (``retain_until``); deletion itself is M4-09.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timedelta
from typing import Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field

from guardrail_engine.decision.port import FailureKind
from guardrail_engine.guard.pii import PiiKind
from guardrail_engine.guard.verdict import (
    Action,
    Basis,
    ContractViolation,
    Decision,
    DeterministicHit,
    PolicySource,
    Reason,
    RedactionStatus,
    RuleEvaluation,
    Verdict,
)
from guardrail_engine.policy.catalog import STANDARD_RETENTION

AUDIT_RECORD_SCHEMA_VERSION = 7
"""2: M1-14's ``redaction`` and ``pii_redacted`` and M1-15's ``in_flight_at_start``,
``capacity_limited`` and ``retry_after_ms``. 3: M3-01's ``deterministic``. 4: M3-03's
``model_skipped``. 5: M3-04's ``chunks``. 6: M4-10's ``max_action`` on each rule's evaluation.
7: M7-11's ``degraded``."""

FALLBACK_RETENTION_DAYS = STANDARD_RETENTION.records_max_days
"""Class B retention for a record whose verdict doesn't say (a verdict built outside the
Guard Service's normal path): the longest class B term the platform allows, so a record is
never deleted before its tenant's real term."""


class _Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class FiredEntry(_Frozen):
    """One ``fired[]`` entry: a rule whose action was escalate or block, whether it acted
    (enforce) or was only recorded (shadow). ``p`` is None when the action came from the
    rule's fail mode."""

    rule: str
    p: float | None
    block_at: float | None
    escalate_at: float | None
    mode: str
    action: Action
    """PF-14."""
    provisional: bool
    """The rule's thresholds were provisional when it fired (M1-08, R5)."""
    layer: str
    basis: Basis


class AuditRecord(_Frozen):
    """The decision record of one check (AC-O1). No content, ever."""

    schema_version: int = AUDIT_RECORD_SCHEMA_VERSION
    ts: datetime
    """When the check started."""
    retention_class: Literal["B"] = "B"
    """R3 class B: a decision record (hashes, every probability, verdict, latency, tokens)."""
    retain_until: datetime
    """``ts`` plus the tenant's effective class B retention (R3). The deletion job (M4-09)
    deletes the record after this time."""

    request_id: str
    tenant_id: str | None
    claimed_tenant_id: str | None
    guard_point: str

    bundle_version: int | None
    """The version that decided."""
    bundle_hash: str | None
    candidate_version: int | None = None
    """The shadow or enforce candidate version involved in this check (PF-7, M4-03): evaluated
    alongside the active version, or the version that decided. None when none was."""
    candidate_decision: str | None = None
    """The candidate's decision, when it was evaluated alongside and finished in time. A record
    only: a shadow candidate never acts (M4-03)."""
    candidate_reason: str | None = None
    """The candidate's reason; ``provider_safety`` is only logged (PF-12)."""
    policy_source: PolicySource | None
    policy_error: str | None

    model: str | None
    content_sha256: str | None
    """``sha256:<hex>`` of the **pre-redaction** content: the content as submitted, before
    any redaction step (PF-14, R3). Never sent to the model."""
    content_tokens: int | None
    """Estimated tokens of the content as submitted (the size bound's figure)."""
    context_items: int
    context_items_dropped: int
    redaction: RedactionStatus | None = None
    """M1-14: ``applied``, ``failed`` (nothing was sent; the check failed closed), or None
    when the check ended before redaction. Defaulted so records written earlier still load."""
    pii_redacted: dict[PiiKind, int] = Field(default_factory=dict)
    """M1-14: spans replaced per PII kind, e.g. ``{"email": 1, "card": 2}``. Counts only,
    never values, positions or lengths."""

    decision: Decision
    reason: Reason
    retryable: bool
    detail: str | None
    """Engine-authored only; never provider or exception free text."""

    fired: tuple[FiredEntry, ...]
    answers: dict[str, float | None]
    """Every evaluated rule's probability, enforce and shadow, keyed by rule. **Values may be
    explicit nulls**: null means "evaluated, no usable ``noul`` probability" (a router, a
    scorer, or a rule resolved by its fail mode), which is different from a key being
    absent ("not evaluated"). Consumers computing statistics must skip nulls. Empty when no
    rule was evaluated."""
    provisional_rules: tuple[str, ...]
    """Keys of every provisional rule evaluated in this check, fired or not. Empty, never
    omitted, when there were none (R5)."""
    rules: tuple[RuleEvaluation, ...]
    """Every rule's evaluation as the check made it: what replay needs."""
    contract_violations: tuple[ContractViolation, ...]
    deterministic: tuple[DeterministicHit, ...] = ()
    """M3-01: the deterministic rules that fired, by id (``deny__<id>``, ``tool_allowlist``,
    ``tool_mismatch``, ``tool_schema``, ``xtenant_identifier``, ``size_limit``, ``p__secret``)
    with their action and match count. Never the matched text. Defaulted so records written
    earlier still load."""

    model_called: bool
    """The engine took the model path (handed the check to the decision gateway)."""
    chunks: int = 0
    """M3-04: how many chunks the content was sent as (one decision call each); 0 when no
    model call was made. Defaulted so records written earlier still load."""
    model_skipped: bool = False
    """M3-03: the tool's registry entry says ``skip_model``: the tenant's and packs' questions
    were not asked, the floor's were. Defaulted so records written earlier still
    load."""
    provider_called: bool | None
    """At least one request was actually sent to the provider. False for an admission
    refusal, the orphan cap or an open auth breaker. None if unknown."""
    provider_calls: int | None
    """Requests sent to the provider: 0, 1, or 2 after a retry. None if unknown."""
    queue_wait_ms: float | None
    """Time waiting for admission on the API key, summed over attempts (M1-04)."""
    provider_latency_ms: float | None
    """Time in provider calls, summed over attempts (M1-04)."""
    in_flight_at_start: int | None
    """Provider calls in flight on the check's API key when the check reached the gateway,
    before any admission wait: calls sent and not yet ended, orphans included; queued calls
    and this check's own call not counted (M1-15, R6.3: the dogfood settles the in-flight
    limit from it). None when no decision call was made."""
    model_latency_ms: float | None
    """Time in the decision gateway, queue wait and provider latency included."""
    failure_kind: FailureKind | None
    failure_reason: str | None
    """A structured code (provider reason, gateway refusal, or provider refusal code for
    ``provider_safety``), never free text."""
    degraded: bool = False
    """M7-11: the check failed because the provider is degraded (the gateway's provider-health
    breaker refused the call at once, or it was the probe and failed). Defaulted so records
    written earlier still load."""
    capacity_limited: bool
    """R8: the gateway refused the decision call for lack of capacity (``admission_wait``,
    ``admission_queue_full``, ``orphan_cap``), never a provider failure. The live gate's
    admission fail-fast rate and R6.3's admission alerts are computed from it (M1-15)."""
    retry_after_ms: int | None
    """R8: the retry hint the caller was given, 100-10,000 ms, or None (M1-15)."""

    latency_ms: float
    input_tokens: int | None
    floor_fail_mode: str | None

    @classmethod
    def from_verdict(cls, verdict: Verdict) -> AuditRecord:
        thresholds = {ev.key: (ev.block_at, ev.escalate_at) for ev in verdict.rules}
        retention_days = (
            verdict.retention_days
            if verdict.retention_days is not None
            else FALLBACK_RETENTION_DAYS
        )
        return cls(
            ts=verdict.checked_at,
            retain_until=verdict.checked_at + timedelta(days=retention_days),
            request_id=verdict.request_id,
            tenant_id=verdict.tenant_id,
            claimed_tenant_id=verdict.claimed_tenant_id,
            guard_point=verdict.guard_point,
            bundle_version=verdict.bundle_version,
            bundle_hash=verdict.bundle_hash,
            candidate_version=verdict.candidate_version,
            candidate_decision=verdict.candidate_decision,
            candidate_reason=verdict.candidate_reason,
            policy_source=verdict.policy_source,
            policy_error=verdict.policy_error,
            model=verdict.model_id,
            content_sha256=verdict.content_sha256,
            content_tokens=verdict.content_tokens,
            context_items=verdict.context_items,
            context_items_dropped=verdict.context_items_dropped,
            redaction=verdict.redaction,
            pii_redacted=verdict.pii_redacted,
            decision=verdict.decision,
            reason=verdict.reason,
            retryable=verdict.retryable,
            detail=verdict.detail,
            fired=tuple(
                FiredEntry(
                    rule=f.key,
                    p=f.p,
                    block_at=thresholds.get(f.key, (None, None))[0],
                    escalate_at=thresholds.get(f.key, (None, None))[1],
                    mode=f.mode,
                    action=f.action,
                    provisional=f.provisional,
                    layer=f.layer,
                    basis=f.basis,
                )
                for f in verdict.fired
            ),
            answers={ev.key: ev.p for ev in verdict.rules},
            provisional_rules=verdict.provisional_rules,
            rules=verdict.rules,
            contract_violations=verdict.contract_violations,
            deterministic=verdict.deterministic,
            model_called=verdict.model_called,
            model_skipped=verdict.model_skipped,
            chunks=verdict.chunks,
            provider_called=verdict.provider_called,
            provider_calls=verdict.provider_calls,
            queue_wait_ms=verdict.queue_wait_ms,
            provider_latency_ms=verdict.provider_latency_ms,
            in_flight_at_start=verdict.in_flight_at_start,
            model_latency_ms=verdict.model_latency_ms,
            failure_kind=verdict.failure_kind,
            failure_reason=verdict.failure_reason,
            degraded=verdict.degraded,
            capacity_limited=verdict.capacity_limited,
            retry_after_ms=verdict.retry_after_ms,
            latency_ms=verdict.latency_ms,
            input_tokens=verdict.input_tokens,
            floor_fail_mode=verdict.floor_fail_mode,
        )


class AuditSink(Protocol):
    """Receives exactly one verdict per check.

    ``record`` is **called synchronously on the check path**: it must return quickly and
    must not block (no network or disk I/O inline). A real sink hands the verdict off, for
    example to a bounded queue drained in the background like the gateway's sinks. An
    exception from ``record`` is logged and never changes or loses the verdict the caller
    receives.
    """

    def record(self, verdict: Verdict) -> None: ...


class NullAuditSink:
    def record(self, verdict: Verdict) -> None:
        pass


class RecordingAuditSink:
    """Builds each check's :class:`AuditRecord` and hands it to ``write``. ``write`` runs on
    the check path, so it must be quick and non-blocking (e.g. put on a bounded queue);
    anything it raises is logged by the Guard Service and never changes the verdict."""

    def __init__(self, write: Callable[[AuditRecord], None]) -> None:
        self._write = write

    def record(self, verdict: Verdict) -> None:
        self._write(AuditRecord.from_verdict(verdict))


class InMemoryAuditSink:
    """Keeps every verdict, and its audit record, in order. For tests."""

    def __init__(self) -> None:
        self.verdicts: list[Verdict] = []
        self.records: list[AuditRecord] = []

    def record(self, verdict: Verdict) -> None:
        self.verdicts.append(verdict)
        self.records.append(AuditRecord.from_verdict(verdict))
