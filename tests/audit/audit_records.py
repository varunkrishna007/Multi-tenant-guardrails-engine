"""Decision records for the M4-07 tests: a real :class:`AuditRecord` with the fields the audit
query filters and shows."""

import uuid
from datetime import UTC, datetime, timedelta

from guardrail_engine.guard.audit import AuditRecord, FiredEntry
from guardrail_engine.guard.verdict import Action, Basis, Decision, Reason, RuleEvaluation

NOW = datetime(2026, 11, 20, 12, 0, 0, tzinfo=UTC)
ACME = "t_acmeins"
OTHER = "t_otherco"


def evaluation(key, layer, p, *, action="allow", block_at=0.8, escalate_at=0.5, mode="enforce"):
    return RuleEvaluation(
        key=key, layer=layer, source="tenant" if layer == "tenant" else "platform/floor@1",
        question_type="noul", mode=mode, severity="high", provisional=False,
        block_at=block_at, escalate_at=escalate_at, fail_mode="block", p=p,
        action=Action(action), basis=Basis.ANSWER,
    )  # fmt: skip


def fired(key, layer, p, action="block", mode="enforce", block_at=0.8, escalate_at=0.5):
    return FiredEntry(
        rule=key, p=p, block_at=block_at, escalate_at=escalate_at, mode=mode,
        action=Action(action), provisional=False, layer=layer, basis=Basis.ANSWER,
    )  # fmt: skip


def make_record(
    tenant_id,
    ts=NOW,
    *,
    guard_point="output",
    decision=Decision.ALLOW,
    fired_entries=(),
    rules=(),
    bundle_version=1,
    request_id=None,
    days=395,
) -> AuditRecord:
    return AuditRecord(
        ts=ts,
        retain_until=ts + timedelta(days=days),
        request_id=request_id or uuid.uuid4().hex,
        tenant_id=tenant_id,
        claimed_tenant_id=tenant_id,
        guard_point=guard_point,
        bundle_version=bundle_version,
        bundle_hash="sha256:" + "0" * 64,
        policy_source=None,
        policy_error=None,
        model=None,
        content_sha256="sha256:" + "1" * 64,
        content_tokens=10,
        context_items=0,
        context_items_dropped=0,
        decision=decision,
        reason=Reason.POLICY,
        retryable=False,
        detail=None,
        fired=tuple(fired_entries),
        answers={r.key: r.p for r in rules},
        provisional_rules=(),
        rules=tuple(rules),
        contract_violations=(),
        model_called=True,
        provider_called=True,
        provider_calls=1,
        queue_wait_ms=0.0,
        provider_latency_ms=1.0,
        in_flight_at_start=0,
        model_latency_ms=1.0,
        failure_kind=None,
        failure_reason=None,
        capacity_limited=False,
        retry_after_ms=None,
        latency_ms=2.0,
        input_tokens=10,
        floor_fail_mode="block",
    )
