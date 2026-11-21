"""M1-05 fusion (AC-G3, S4): thresholds, most-severe-wins, shadow rules never act,
``recalibrate`` is the identity, and the action ceiling a future ``max_action`` plugs into."""

import pytest
from guard_fixtures import ALPHA, Env, bundle, rule

from guardrail_engine.guard import (
    Action,
    Basis,
    Decision,
    Reason,
    action_ceiling,
    recalibrate,
    threshold_action,
)
from guardrail_engine.guard.fusion import capped
from guardrail_engine.policy import CompiledRule

# (rule key, p, expected action). t__adv has 0.80 / 0.50; the floor's p__inj_direct 0.85 / 0.55.
THRESHOLD_TABLE = [
    ("t__adv", 0.99, Action.BLOCK),
    ("t__adv", 0.80, Action.BLOCK),  # p == block_at
    ("t__adv", 0.79, Action.ESCALATE),  # just below block_at
    ("t__adv", 0.50, Action.ESCALATE),  # p == escalate_at
    ("t__adv", 0.49, Action.ALLOW),  # just below escalate_at
    ("t__adv", 0.01, Action.ALLOW),
    ("p__inj_direct", 0.85, Action.BLOCK),
    ("p__inj_direct", 0.84, Action.ESCALATE),
    ("p__inj_direct", 0.55, Action.ESCALATE),
    ("p__inj_direct", 0.54, Action.ALLOW),
]


@pytest.mark.parametrize(("key", "p", "expected"), THRESHOLD_TABLE)
async def test_ac_g3_threshold_table_at_and_just_below_each_threshold(key, p, expected):
    async with Env() as env:
        await env.publish(bundle(ALPHA, rules=[rule("adv", block_at=0.80, escalate_at=0.50)]))
        env.fake.set_noul(key, p)
        verdict = await env.check(ALPHA, "output", "Some content.")

    assert verdict.decision == Decision(expected.value)
    assert verdict.reason is Reason.POLICY
    evaluation = {ev.key: ev for ev in verdict.rules}[key]
    assert evaluation.p == p
    assert evaluation.action is expected
    assert evaluation.basis is Basis.ANSWER
    assert verdict.probabilities[key] == p
    fired = {f.key: f for f in verdict.fired}
    if expected is Action.ALLOW:
        assert key not in fired
    else:
        assert fired[key].action is expected
        assert fired[key].p == p


@pytest.mark.parametrize(
    ("p", "block_at", "escalate_at", "expected"),
    [
        (0.80, 0.80, 0.50, Action.BLOCK),
        (0.79, 0.80, 0.50, Action.ESCALATE),
        (0.50, 0.80, 0.50, Action.ESCALATE),
        (0.49, 0.80, 0.50, Action.ALLOW),
        (0.99, 0.99, 0.98, Action.BLOCK),
        (0.98, 0.99, 0.98, Action.ESCALATE),
        (0.97, 0.99, 0.98, Action.ALLOW),
        (0.02, 0.02, 0.01, Action.BLOCK),
        (0.01, 0.02, 0.01, Action.ESCALATE),
    ],
)
def test_ac_g3_threshold_action_unit_table(p, block_at, escalate_at, expected):
    assert threshold_action(p, block_at, escalate_at) is expected


async def test_ac_g3_most_severe_result_wins():
    async with Env() as env:
        await env.publish(bundle(ALPHA, rules=[rule("esc"), rule("blk"), rule("low")]))
        env.fake.set_noul("t__esc", 0.60).set_noul("t__blk", 0.90).set_noul("t__low", 0.20)
        verdict = await env.check(ALPHA)
        assert verdict.decision is Decision.BLOCK
        assert {f.key: f.action for f in verdict.fired} == {
            "t__esc": Action.ESCALATE,
            "t__blk": Action.BLOCK,
        }

        env.fake.set_noul("t__blk", 0.10)
        verdict = await env.check(ALPHA)
        assert verdict.decision is Decision.ESCALATE
        assert verdict.reason is Reason.POLICY


async def test_ac_g3_shadow_rule_is_evaluated_and_recorded_but_never_acts():
    async with Env() as env:
        await env.publish(bundle(ALPHA, rules=[rule("watch", mode="shadow")]))
        env.fake.set_noul("t__watch", 0.99)
        verdict = await env.check(ALPHA)

    assert verdict.decision is Decision.ALLOW
    assert verdict.released
    assert verdict.probabilities["t__watch"] == 0.99
    [fired] = verdict.fired
    assert (fired.key, fired.action, fired.mode) == ("t__watch", Action.BLOCK, "shadow")
    watch = {ev.key: ev for ev in verdict.rules}["t__watch"]
    assert watch.action is Action.BLOCK and not watch.acts


async def test_ac_g3_shadow_block_does_not_raise_an_enforce_escalate():
    async with Env() as env:
        await env.publish(bundle(ALPHA, rules=[rule("watch", mode="shadow"), rule("live")]))
        env.fake.set_noul("t__watch", 0.99).set_noul("t__live", 0.60)
        verdict = await env.check(ALPHA)
    assert verdict.decision is Decision.ESCALATE


async def test_every_rule_probability_is_recorded_including_unfired_and_shadow():
    async with Env() as env:
        await env.publish(
            bundle(ALPHA, rules=[rule("a"), rule("b", mode="shadow")], packs=["domain/claims@1"])
        )
        env.fake.set_noul("t__a", 0.30)
        verdict = await env.check(ALPHA, "output")
    assert set(verdict.probabilities) == {
        "p__inj_direct",
        "p__ai_addressed",
        "p__secret",
        "d__claim_promise",
        "t__a",
        "t__b",
    }
    assert verdict.probabilities["t__a"] == 0.30
    assert verdict.probabilities["p__secret"] == 0.01  # the fake's default


async def test_router_answer_is_recorded_and_never_acts():
    async with Env() as env:
        await env.publish(bundle(ALPHA, packs=["domain/claims@1"]))
        env.fake.set_choice("d__route", "off_domain")
        verdict = await env.check(ALPHA, "input")
    route = {ev.key: ev for ev in verdict.rules}["d__route"]
    assert route.answer is not None and route.answer.choice == "off_domain"
    assert route.p is None and route.action is Action.ALLOW
    assert verdict.decision is Decision.ALLOW
    assert "d__route" not in verdict.probabilities


@pytest.mark.parametrize("p", [0.01, 0.37, 0.5, 0.85, 0.99])
def test_s4_recalibrate_is_the_identity(p):
    meta = CompiledRule(
        key="t__x",
        layer="tenant",
        source="tenant",
        question_type="noul",
        block_at=0.8,
        escalate_at=0.5,
        mode="enforce",
        severity="medium",
        fail_mode="closed",
        provisional=False,
    )
    assert recalibrate(meta, p) == p


def test_action_ceiling_is_block_for_every_rule_today_and_caps_every_action():
    """The hook a future ``max_action`` (M4-10) fills in: one function returns a rule's
    ceiling, and ``capped`` applies it to every action, from answers and fail modes alike."""
    meta = CompiledRule(
        key="d__self_harm_risk",
        layer="pack",
        source="domain/responsible_ai@1",
        question_type="noul",
        block_at=0.8,
        escalate_at=0.5,
        mode="enforce",
        severity="high",
        fail_mode="closed",
        provisional=False,
    )
    assert action_ceiling(meta) is Action.BLOCK
    for action in Action:
        assert capped(action, meta) is action


def test_capped_enforces_a_lower_ceiling(monkeypatch):
    """Shows the cap really applies once a rule's ceiling is escalate: monkeypatching the one
    hook is all M4-10's ``max_action`` needs to change in fusion."""
    import guardrail_engine.guard.fusion as fusion

    monkeypatch.setattr(fusion, "action_ceiling", lambda rule: Action.ESCALATE)
    meta = CompiledRule(
        key="d__x",
        layer="pack",
        source="domain/x@1",
        question_type="noul",
        block_at=0.8,
        escalate_at=0.5,
        mode="enforce",
        severity="high",
        fail_mode="closed",
        provisional=False,
    )
    assert fusion.capped(Action.BLOCK, meta) is Action.ESCALATE
    assert fusion.capped(Action.ESCALATE, meta) is Action.ESCALATE
    assert fusion.capped(Action.ALLOW, meta) is Action.ALLOW
