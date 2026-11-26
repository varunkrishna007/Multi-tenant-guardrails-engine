"""The verdict enforces the canonical (decision, reason) pairs from the
backlog (B1, "How model failures are recorded and shown"), including the conditional
``allow``/``model_failure`` pair, and exposes ``retryable``."""

from datetime import UTC, datetime
from itertools import product

import pytest
from guard_fixtures import ALPHA, Env, bundle, rule
from pydantic import ValidationError

import guardrail_engine.guard.service as service_module
from guardrail_engine.decision import Failed, FailureKind
from guardrail_engine.guard import Action, Basis, Decision, Reason, RuleEvaluation, Verdict
from guardrail_engine.guard.fusion import Fused
from guardrail_engine.guard.verdict import CANONICAL
from guardrail_engine.policy import PlatformSettings

BACKLOG_PAIRS = {
    (Decision.ALLOW, Reason.POLICY),
    (Decision.ALLOW, Reason.NO_QUESTIONS),
    (Decision.ALLOW, Reason.MODEL_FAILURE),  # only with an open floor (added later)
    (Decision.ESCALATE, Reason.POLICY),
    (Decision.ESCALATE, Reason.DETERMINISTIC),  # M3-01: a deterministic escalate
    (Decision.ESCALATE, Reason.PROVIDER_SAFETY),  # M7-08: a refusal where a rule may only escalate
    *(
        (Decision.BLOCK, r)
        for r in (
            Reason.POLICY,
            Reason.DETERMINISTIC,  # M3-01: a deny pattern, the allow-list, a cross-tenant id
            Reason.MODEL_FAILURE,
            Reason.PROVIDER_SAFETY,
            Reason.CONTENT_TOO_LARGE,
            Reason.CONTRACT_VIOLATION,
            Reason.POLICY_UNAVAILABLE,
            Reason.INTERNAL_ERROR,
            Reason.ENGINE_CLOSED,  # shutdown in progress (M1-11, decided 2026-11-17)
            Reason.INVALID_REQUEST,
        )
    ),
    (Decision.FORBIDDEN, Reason.TENANT_MISMATCH),
    (Decision.FORBIDDEN, Reason.CONTEXT_INVALID),
    (Decision.FORBIDDEN, Reason.TENANT_TERMINATED),  # M5-07
}


def floor_evaluation(fail_mode: str) -> RuleEvaluation:
    return RuleEvaluation(
        key="p__inj_direct",
        layer="floor",
        source="platform/floor@1",
        question_type="noul",
        mode="enforce",
        severity="high",
        provisional=True,
        block_at=0.85,
        escalate_at=0.55,
        fail_mode=fail_mode,
        p=None,
        action=Action.ALLOW if fail_mode == "open" else Action.BLOCK,
        basis=Basis.FAIL_MODE,
    )


def verdict(decision, reason, **fields) -> Verdict:
    return Verdict(
        request_id="r",
        tenant_id=ALPHA,
        guard_point="output",
        decision=decision,
        reason=reason,
        checked_at=datetime.now(UTC),
        latency_ms=1.0,
        **fields,
    )


def test_the_table_is_the_backlogs_canonical_list():
    assert {(d, r) for d, rs in CANONICAL.items() for r in rs} == BACKLOG_PAIRS


@pytest.mark.parametrize(("decision", "reason"), sorted(product(Decision, Reason)))
def test_only_canonical_pairs_can_be_built(decision, reason):
    extra = {}
    if (decision, reason) == (Decision.ALLOW, Reason.MODEL_FAILURE):
        extra = {"rules": (floor_evaluation("open"),), "floor_fail_mode": "open"}
    if (decision, reason) in BACKLOG_PAIRS:
        assert verdict(decision, reason, **extra).decision is decision
    else:
        with pytest.raises(ValidationError, match="not a canonical verdict pair"):
            verdict(decision, reason)


def test_allow_model_failure_needs_an_open_floor():
    open_floor = (floor_evaluation("open"),)
    verdict(Decision.ALLOW, Reason.MODEL_FAILURE, rules=open_floor, floor_fail_mode="open")
    with pytest.raises(ValidationError, match="floor"):
        verdict(
            Decision.ALLOW,
            Reason.MODEL_FAILURE,
            rules=(floor_evaluation("closed"),),
            floor_fail_mode="open",
        )
    with pytest.raises(ValidationError, match="floor"):
        verdict(Decision.ALLOW, Reason.MODEL_FAILURE)


@pytest.mark.parametrize("platform", ["closed", None, "Open"])
def test_allow_model_failure_is_gated_on_the_platform_setting_not_compiled_rules(platform):
    """Compiled floor rules all claiming ``open`` (a corrupted compile) can't produce an
    allow/model_failure unless the platform's floor_fail_mode is open."""
    with pytest.raises(ValidationError, match="platform floor_fail_mode"):
        verdict(
            Decision.ALLOW,
            Reason.MODEL_FAILURE,
            rules=(floor_evaluation("open"),),
            floor_fail_mode=platform,
        )


async def test_allow_model_failure_cannot_occur_with_the_default_closed_floor():
    async with Env() as env:  # default PlatformSettings: floor_fail_mode closed
        await env.publish(bundle(ALPHA, rules=[rule("adv")], defaults={"fail_mode": "open"}))
        for kind in FailureKind:
            env.fake.always(Failed(kind=kind))
            v = await env.check(ALPHA)
            assert (v.decision, v.reason) == (Decision.BLOCK, Reason.MODEL_FAILURE)


async def test_allow_model_failure_with_the_floor_set_open():
    async with Env(settings=PlatformSettings(floor_fail_mode="open")) as env:
        await env.publish(bundle(ALPHA, rules=[rule("adv")], defaults={"fail_mode": "open"}))
        env.fake.always(Failed(kind=FailureKind.UNAVAILABLE))
        v = await env.check(ALPHA)
    assert (v.decision, v.reason) == (Decision.ALLOW, Reason.MODEL_FAILURE)
    assert v.floor_fail_mode == "open"
    assert v.released and not v.retryable  # nothing to retry once released


def test_retryable_is_false_whenever_content_was_released():
    released = verdict(
        Decision.ALLOW,
        Reason.MODEL_FAILURE,
        rules=(floor_evaluation("open"),),
        floor_fail_mode="open",
    )
    assert released.released and not released.retryable
    assert verdict(Decision.BLOCK, Reason.MODEL_FAILURE).retryable
    assert verdict(Decision.BLOCK, Reason.POLICY_UNAVAILABLE).retryable


async def test_a_pipeline_bug_producing_a_bad_pair_fails_closed(monkeypatch):
    def buggy_fuse(evaluations):
        return Fused(
            action=Action.ALLOW, reason=Reason.CONTRACT_VIOLATION, fired=(), probabilities={}
        )

    monkeypatch.setattr(service_module, "fuse", buggy_fuse)
    async with Env() as env:
        await env.publish(bundle(ALPHA))
        v = await env.check(ALPHA)
    assert (v.decision, v.reason) == (Decision.BLOCK, Reason.INTERNAL_ERROR)
    assert env.audit.verdicts == [v]


@pytest.mark.parametrize("reason", list(Reason))
def test_retryable_only_for_model_failure_policy_unavailable_and_engine_closed(reason):
    """The backlog's retryable list (B1, M1-07): ``engine_closed`` joined it with M1-11's
    shutdown decision (2026-11-17)."""
    for decision in (Decision.BLOCK, Decision.FORBIDDEN, Decision.ESCALATE, Decision.ALLOW):
        if reason in CANONICAL[decision]:
            break
    assert verdict(decision, reason).retryable is (
        reason in {Reason.MODEL_FAILURE, Reason.POLICY_UNAVAILABLE, Reason.ENGINE_CLOSED}
    )
