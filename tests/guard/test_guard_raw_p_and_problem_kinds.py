"""M1 integration: the verdict records each rule's raw probability beside the
recalibrated one (numbers only), and the answer-problem kind per rule (the kind only, never
the detail or the raw answer)."""

import json
from datetime import UTC, datetime

import pytest
from guard_fixtures import ALPHA, FLOOR_KEYS, Env, bundle

import guardrail_engine.guard.fusion as fusion
from guardrail_engine.decision import ProblemKind
from guardrail_engine.guard import Decision, Reason, Verdict

RAW_SENTINEL = "raw-answer-sentinel-do-not-record"


async def test_raw_equals_recalibrated_today_but_is_a_separate_field():
    async with Env() as env:
        await env.publish(bundle(ALPHA))
        env.fake.set_noul("p__inj_direct", 0.42)
        verdict = await env.check(ALPHA, "input")
    assert set(verdict.probabilities) >= FLOOR_KEYS
    assert verdict.probabilities_raw == verdict.probabilities  # recalibrate is the identity
    assert verdict.probabilities_raw is not verdict.probabilities
    assert verdict.probabilities_raw["p__inj_direct"] == 0.42
    assert verdict.problem_kinds == {}


async def test_raw_is_what_the_model_gave_and_thresholds_act_on_the_recalibrated(monkeypatch):
    """With a non-identity map (v1.1's isotonic one, say) the two differ: raw keeps the
    model's number; ``probabilities`` and the action use the recalibrated one."""
    monkeypatch.setattr(fusion, "recalibrate", lambda rule, p: p / 2)
    async with Env() as env:
        await env.publish(bundle(ALPHA))
        env.fake.set_noul("p__inj_direct", 0.96)
        verdict = await env.check(ALPHA, "input")
    assert verdict.probabilities_raw["p__inj_direct"] == 0.96
    assert verdict.probabilities["p__inj_direct"] == 0.48
    assert verdict.decision is Decision.ALLOW  # 0.48 is under escalate_at; 0.96 would block


async def test_problem_kind_per_rule_and_no_probability_for_those_rules():
    async with Env() as env:
        await env.publish(bundle(ALPHA))
        env.fake.malformed_next(
            missing=["p__inj_direct"],
            raw_answers={"p__ai_addressed": {"type": "noul", "noul": RAW_SENTINEL}},
        )
        verdict = await env.check(ALPHA, "input")
    assert verdict.reason is Reason.CONTRACT_VIOLATION
    kinds = verdict.problem_kinds
    assert kinds["p__inj_direct"] is ProblemKind.MISSING
    assert kinds["p__ai_addressed"] in set(ProblemKind)
    assert all(isinstance(k, ProblemKind) for k in kinds.values())
    for key in kinds:
        assert key not in verdict.probabilities
        assert key not in verdict.probabilities_raw
    # The kind only: nothing of the raw answer or the parser's detail.
    assert RAW_SENTINEL not in json.dumps(kinds)
    assert set(json.loads(json.dumps(kinds)).values()) <= {k.value for k in ProblemKind}


async def test_a_failed_call_has_no_problem_kinds_and_no_raw_probabilities():
    async with Env() as env:
        await env.publish(bundle(ALPHA))
        env.fake.timeout_next(2)
        verdict = await env.check(ALPHA, "input")
    assert verdict.reason is Reason.MODEL_FAILURE
    assert verdict.problem_kinds == {}
    assert verdict.probabilities_raw == {} and verdict.probabilities == {}


def _verdict(**fields):
    return Verdict(
        request_id="r",
        tenant_id=ALPHA,
        guard_point="input",
        decision=Decision.ALLOW,
        reason=Reason.POLICY,
        checked_at=datetime.now(UTC),
        latency_ms=1.0,
        **fields,
    )


def test_a_verdict_built_before_raw_probabilities_still_loads():
    assert _verdict(probabilities={"p__inj_direct": 0.1}).probabilities_raw == {}


@pytest.mark.parametrize(
    "fields",
    [
        {"probabilities_raw": {"p__inj_direct": 0.1}},  # no recalibrated one
        {"probabilities": {"k": 0.1}, "probabilities_raw": {"k": 1.5}},
        {"probabilities": {"k": 0.1}, "probabilities_raw": {"k": float("nan")}},
    ],
)
def test_a_raw_probability_must_be_a_number_in_range_beside_a_recalibrated_one(fields):
    with pytest.raises(ValueError, match="raw probability"):
        _verdict(**fields)
