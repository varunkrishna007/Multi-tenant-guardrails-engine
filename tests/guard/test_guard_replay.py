"""M1-06: replaying a decision record under new thresholds, with no model call.

Two properties, over generated checks covering the fixtures' verdict variety (allow,
escalate, block; floor, pack and tenant rules; routers; shadow rules; contract violations;
model failures with the floor failing closed and open; provider safety; deterministic and
policy outcomes with no rule evaluation):

1. **Identity.** With unchanged thresholds, replaying a stored record (after a JSON round
   trip, as it would be read back from storage) reproduces the stored decision, reason,
   fired rules and every rule's action exactly.
2. **Oracle.** With new thresholds, the replayed decision equals what the engine itself
   decides when the same bundle is published with those thresholds and the model gives the
   same answers.
"""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace

import pytest
from guard_fixtures import ALPHA, Env, bundle, rule
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from pydantic import ValidationError

from guardrail_engine.decision import Failed, FailureKind
from guardrail_engine.guard import (
    Action,
    AuditRecord,
    Basis,
    Decision,
    Reason,
    ReplayRefused,
    Thresholds,
    replay,
    resolve_rule,
)
from guardrail_engine.guard import fusion as fusion_module
from guardrail_engine.policy import PlatformSettings

FLOOR_KEYS = ("p__inj_direct", "p__ai_addressed", "p__secret")
GRID = [round(x * 0.05, 2) for x in range(1, 20)]  # 0.05 .. 0.95

probability = st.one_of(  # the API's noul range is [0.01, 0.99]
    st.sampled_from([0.01, 0.5, 0.55, 0.8, 0.85, 0.99, *GRID]),
    st.floats(min_value=0.01, max_value=0.99, allow_nan=False),
)


@st.composite
def threshold_pair(draw):
    block = draw(st.sampled_from(GRID[1:]))
    escalate = draw(st.sampled_from([g for g in GRID if g < block]))
    return block, escalate


tenant_rule = st.fixed_dictionaries(
    {
        "thresholds": threshold_pair(),
        "mode": st.sampled_from(["enforce", "enforce", "shadow"]),
        "p": probability,
    }
)

outcome = st.one_of(
    st.just(("answered", None)),
    st.tuples(st.just("malformed"), st.sampled_from(["missing", "wrong_type", "out_of_range"])),
    st.tuples(st.just("failed"), st.sampled_from(list(FailureKind))),
    st.just(("safety", None)),
)


@st.composite
def scenario(draw):
    rules = draw(st.lists(tenant_rule, min_size=0, max_size=3))
    return {
        "floor_fail_mode": draw(st.sampled_from(["closed", "open"])),
        "tenant_fail_mode": draw(st.sampled_from(["closed", "open"])),
        "pack": draw(st.booleans()),
        "guard_point": draw(st.sampled_from(["output", "input"])),
        "rules": rules,
        "floor_p": {k: draw(probability) for k in FLOOR_KEYS},
        "pack_p": draw(probability),
        "outcome": draw(outcome),
        "malformed_key": draw(st.integers(min_value=0, max_value=10)),
    }


def tenant_document(s, version=1, thresholds=None):
    rules = []
    for i, r in enumerate(s["rules"]):
        block, escalate = (thresholds or {}).get(f"t__r{i}", r["thresholds"])
        rules.append(
            rule(
                f"r{i}",
                gps=("output", "input"),
                block_at=block,
                escalate_at=escalate,
                mode=r["mode"],
            )
        )
    return bundle(
        ALPHA,
        version=version,
        rules=rules,
        packs=["domain/claims@1"] if s["pack"] else [],
        defaults={"fail_mode": s["tenant_fail_mode"]},
    )


def script(env, s):
    for key, p in s["floor_p"].items():
        env.fake.set_noul(key, p)
    env.fake.set_noul("d__claim_promise", s["pack_p"])
    for i, r in enumerate(s["rules"]):
        env.fake.set_noul(f"t__r{i}", r["p"])
    kind, arg = s["outcome"]
    if kind == "failed":
        env.fake.push(Failed(kind=arg), Failed(kind=arg))  # and the retry, if any
    elif kind == "safety":
        env.fake.safety_block_next()
    elif kind == "malformed":
        keys = [*FLOOR_KEYS, *(f"t__r{i}" for i in range(len(s["rules"])))]
        if s["pack"]:
            keys.append("d__route" if s["guard_point"] == "input" else "d__claim_promise")
        target = sorted(keys)[s["malformed_key"] % len(keys)]
        if target == "p__secret" and s["guard_point"] == "input":
            target = "p__inj_direct"  # p__secret isn't asked at input
        env.fake.malformed_next(**{arg: [target]})


async def run_check(s, *, version_thresholds=None):
    settings_ = PlatformSettings(floor_fail_mode=s["floor_fail_mode"])
    async with Env(settings=settings_) as env:
        await env.publish(tenant_document(s, thresholds=version_thresholds))
        script(env, s)
        verdict = await env.check(ALPHA, s["guard_point"])
        calls = len(env.fake.calls)
    [record] = env.audit.records
    return verdict, AuditRecord.model_validate_json(record.model_dump_json()), calls


def assert_same(replayed, decision, reason, fired, rules):
    assert (replayed.decision, replayed.reason) == (decision, reason)
    assert [(f.key, f.action, f.mode, f.basis, f.p) for f in replayed.fired] == [
        (f.key, f.action, f.mode, f.basis, f.p) for f in fired
    ]
    assert [(ev.key, ev.action, ev.basis, ev.p) for ev in replayed.rules] == [
        (ev.key, ev.action, ev.basis, ev.p) for ev in rules
    ]


@settings(max_examples=150, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(s=scenario())
async def test_replay_with_unchanged_thresholds_reproduces_the_stored_decision(s):
    verdict, record, _ = await run_check(s)
    replayed = replay(record)
    assert_same(replayed, verdict.decision, verdict.reason, verdict.fired, verdict.rules)
    # Naming every rule with its own recorded thresholds is the same as naming none.
    same = {ev.key: Thresholds(ev.block_at, ev.escalate_at) for ev in record.rules if ev.block_at}
    assert_same(
        replay(record, same), verdict.decision, verdict.reason, verdict.fired, verdict.rules
    )


@settings(max_examples=100, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(s=scenario(), new=st.lists(threshold_pair(), min_size=3, max_size=3))
async def test_replay_under_new_thresholds_matches_the_engine_deciding_with_them(s, new):
    new_thresholds = {f"t__r{i}": pair for i, pair in enumerate(new[: len(s["rules"])])}
    _, record, _ = await run_check(s)
    oracle, _, _ = await run_check(s, version_thresholds=new_thresholds)

    replayed = replay(
        record, {k: Thresholds(block_at=b, escalate_at=e) for k, (b, e) in new_thresholds.items()}
    )
    assert_same(replayed, oracle.decision, oracle.reason, oracle.fired, oracle.rules)
    assert [(ev.key, ev.block_at, ev.escalate_at) for ev in replayed.rules] == [
        (ev.key, ev.block_at, ev.escalate_at) for ev in oracle.rules
    ]


# ------------------------------------------------------------------ examples


def answered_scenario(**overrides):
    s = {
        "floor_fail_mode": "closed",
        "tenant_fail_mode": "closed",
        "pack": False,
        "guard_point": "output",
        "rules": [{"thresholds": (0.8, 0.5), "mode": "enforce", "p": 0.6}],
        "floor_p": dict.fromkeys(FLOOR_KEYS, 0.01),
        "pack_p": 0.01,
        "outcome": ("answered", None),
        "malformed_key": 0,
    }
    s.update(overrides)
    return s


async def test_replay_moves_an_escalation_to_a_block_and_to_an_allow():
    verdict, record, _ = await run_check(answered_scenario())
    assert verdict.decision is Decision.ESCALATE
    assert replay(record, {"t__r0": Thresholds(0.6, 0.3)}).decision is Decision.BLOCK
    assert replay(record, {"t__r0": Thresholds(0.9, 0.7)}).decision is Decision.ALLOW
    assert replay(record).decision is Decision.ESCALATE


async def test_replay_can_lower_a_floor_threshold_too():
    s = answered_scenario(floor_p={**dict.fromkeys(FLOOR_KEYS, 0.01), "p__secret": 0.7})
    s["rules"] = []
    verdict, record, _ = await run_check(s)
    assert verdict.decision is Decision.ESCALATE  # 0.5 <= 0.7 < 0.8
    replayed = replay(record, {"p__secret": Thresholds(0.65, 0.4)})
    assert replayed.decision is Decision.BLOCK
    assert [(f.key, f.action) for f in replayed.fired] == [("p__secret", Action.BLOCK)]


async def test_replay_makes_no_model_call(monkeypatch):
    s = answered_scenario()
    async with Env() as env:
        await env.publish(tenant_document(s))
        script(env, s)
        await env.check(ALPHA)
        [record] = env.audit.records
        calls = len(env.fake.calls)

        async def no_calls(*args, **kwargs):
            raise AssertionError("replay called the model")

        monkeypatch.setattr(env.fake, "decide", no_calls)
        monkeypatch.setattr(env.service.gateway, "decide_timed", no_calls)
        replayed = replay(record, {"t__r0": Thresholds(0.55, 0.3)})
        await asyncio.sleep(0)
    assert replayed.decision is Decision.BLOCK
    assert len(env.fake.calls) == calls == 1


async def test_replay_uses_the_engines_own_resolution_code(monkeypatch):
    """Replay runs ``fusion.resolve_rule`` and ``fusion.fuse``, not a copy: changing the
    engine's threshold rule changes what replay computes."""
    _, record, _ = await run_check(answered_scenario())
    assert replay(record).decision is Decision.ESCALATE
    monkeypatch.setattr(fusion_module, "threshold_action", lambda p, b, e: Action.BLOCK)
    assert replay(record).decision is Decision.BLOCK


async def test_rules_resolved_by_fail_mode_ignore_new_thresholds():
    s = answered_scenario(outcome=("failed", FailureKind.TIMEOUT))
    verdict, record, _ = await run_check(s)
    assert (verdict.decision, verdict.reason) == (Decision.BLOCK, Reason.MODEL_FAILURE)
    # Floor thresholds lowered (raising them is refused), the tenant's raised:
    # neither moves a rule that was resolved by its fail mode.
    new = {k: Thresholds(0.1, 0.05) for k in FLOOR_KEYS} | {"t__r0": Thresholds(0.99, 0.98)}
    replayed = replay(record, new)
    assert (replayed.decision, replayed.reason) == (Decision.BLOCK, Reason.MODEL_FAILURE)
    assert all(ev.basis is Basis.FAIL_MODE for ev in replayed.rules)


async def test_fail_open_model_failure_replays_as_allow():
    s = answered_scenario(
        floor_fail_mode="open", tenant_fail_mode="open", outcome=("failed", FailureKind.AUTH)
    )
    verdict, record, _ = await run_check(s)
    assert (verdict.decision, verdict.reason) == (Decision.ALLOW, Reason.MODEL_FAILURE)
    replayed = replay(record)
    assert (replayed.decision, replayed.reason) == (Decision.ALLOW, Reason.MODEL_FAILURE)
    assert replayed.recomputed


async def test_shadow_rule_never_acts_in_replay():
    s = answered_scenario(rules=[{"thresholds": (0.8, 0.5), "mode": "shadow", "p": 0.95}])
    verdict, record, _ = await run_check(s)
    assert verdict.decision is Decision.ALLOW
    replayed = replay(record, {"t__r0": Thresholds(0.1, 0.05)})
    assert replayed.decision is Decision.ALLOW
    assert [(f.key, f.mode, f.action) for f in replayed.fired] == [
        ("t__r0", "shadow", Action.BLOCK)
    ]


async def test_decisions_no_rule_produced_are_returned_as_stored():
    s = answered_scenario(outcome=("safety", None))
    verdict, record, _ = await run_check(s)
    assert verdict.reason is Reason.PROVIDER_SAFETY
    replayed = replay(record, {"t__r0": Thresholds(0.1, 0.05)})
    assert (replayed.decision, replayed.reason, replayed.recomputed) == (
        Decision.BLOCK,
        Reason.PROVIDER_SAFETY,
        False,
    )

    async with Env() as env:
        await env.publish(tenant_document(s))
        await env.check(ALPHA, content="x " * 200_000)
        await env.service.check(env.ctx(ALPHA, payload_tenant_id="t_x"), "output", "hi")
    for stored in env.audit.records:
        replayed = replay(stored, {"t__r0": Thresholds(0.1, 0.05)})
        assert (replayed.decision, replayed.reason) == (stored.decision, stored.reason)
        assert not replayed.recomputed


async def test_contract_violation_reason_follows_the_new_thresholds():
    """A block that rests only on a fail-mode rule is a contract violation; if new thresholds
    make an answered rule block too, the reason becomes policy, as the engine would say."""
    s = answered_scenario(outcome=("malformed", "missing"), malformed_key=3)  # t__r0 missing
    s["rules"].append({"thresholds": (0.8, 0.5), "mode": "enforce", "p": 0.6})
    verdict, record, _ = await run_check(s)
    assert (verdict.decision, verdict.reason) == (Decision.BLOCK, Reason.CONTRACT_VIOLATION)
    replayed = replay(record, {"t__r1": Thresholds(0.6, 0.3)})
    assert (replayed.decision, replayed.reason) == (Decision.BLOCK, Reason.POLICY)


@pytest.mark.parametrize(
    ("block_at", "escalate_at"),
    [(0.5, 0.6), (1.1, 0.5), (0.5, -0.1), (float("nan"), 0.1), (True, 0.1)],
)
def test_thresholds_are_validated(block_at, escalate_at):
    with pytest.raises(ValueError):
        Thresholds(block_at=block_at, escalate_at=escalate_at)


async def test_unknown_keys_in_the_threshold_map_are_ignored():
    verdict, record, _ = await run_check(answered_scenario())
    replayed = replay(record, {"t__not_here": Thresholds(0.1, 0.05)})
    assert replayed.decision is verdict.decision


# Named cases, so the variety the properties above draw from is guaranteed to be exercised
# (Hypothesis doesn't promise to hit any one of them). Each asserts the stored outcome, then
# the identity property.
LOW = dict.fromkeys(FLOOR_KEYS, 0.01)
VARIETY = {
    "allow": (answered_scenario(rules=[]), Decision.ALLOW, Reason.POLICY),
    "escalate (tenant)": (answered_scenario(), Decision.ESCALATE, Reason.POLICY),
    "block (floor)": (
        answered_scenario(rules=[], floor_p={**LOW, "p__inj_direct": 0.9}),
        Decision.BLOCK,
        Reason.POLICY,
    ),
    "block (tenant)": (
        answered_scenario(rules=[{"thresholds": (0.8, 0.5), "mode": "enforce", "p": 0.8}]),
        Decision.BLOCK,
        Reason.POLICY,
    ),
    "block (pack)": (
        answered_scenario(rules=[], pack=True, pack_p=0.85),
        Decision.BLOCK,
        Reason.POLICY,
    ),
    "router at input": (
        answered_scenario(rules=[], pack=True, guard_point="input"),
        Decision.ALLOW,
        Reason.POLICY,
    ),
    "shadow fires, allow": (
        answered_scenario(rules=[{"thresholds": (0.8, 0.5), "mode": "shadow", "p": 0.95}]),
        Decision.ALLOW,
        Reason.POLICY,
    ),
    "contract violation": (
        answered_scenario(rules=[], outcome=("malformed", "missing")),
        Decision.BLOCK,
        Reason.CONTRACT_VIOLATION,
    ),
    "model failure, floor closed": (
        answered_scenario(outcome=("failed", FailureKind.UNAVAILABLE), tenant_fail_mode="open"),
        Decision.BLOCK,
        Reason.MODEL_FAILURE,
    ),
    "model failure, floor open, tenant open": (
        answered_scenario(
            outcome=("failed", FailureKind.TIMEOUT), floor_fail_mode="open", tenant_fail_mode="open"
        ),
        Decision.ALLOW,
        Reason.MODEL_FAILURE,
    ),
    "model failure, floor open, tenant closed": (
        answered_scenario(outcome=("failed", FailureKind.RATE_LIMITED), floor_fail_mode="open"),
        Decision.BLOCK,
        Reason.MODEL_FAILURE,
    ),
    "provider safety": (
        answered_scenario(outcome=("safety", None)),
        Decision.BLOCK,
        Reason.PROVIDER_SAFETY,
    ),
}


@pytest.mark.parametrize("name", list(VARIETY))
async def test_replay_identity_on_each_kind_of_verdict(name):
    s, decision, reason = VARIETY[name]
    verdict, record, _ = await run_check(s)
    assert (verdict.decision, verdict.reason) == (decision, reason)
    assert_same(replay(record), verdict.decision, verdict.reason, verdict.fired, verdict.rules)


# ------------------------------------------------------------------ can't loosen the floor


def secret_block_scenario(**overrides):
    """The probe: a live block at ``output`` on ``p__secret`` (p = 0.9; recorded
    thresholds 0.80 / 0.50), plus one tenant rule at p = 0.6 and the claims pack."""
    return answered_scenario(
        **{"floor_p": {**LOW, "p__secret": 0.9}, "pack": True, "pack_p": 0.6, **overrides}
    )


async def test_the_reviewers_probe_is_refused():
    verdict, record, _ = await run_check(secret_block_scenario())
    assert (verdict.decision, verdict.reason) == (Decision.BLOCK, Reason.POLICY)
    for loosened in (Thresholds(0.99, 0.98), Thresholds(1.0, 1.0)):
        with pytest.raises(ReplayRefused, match="p__secret: floor block_at") as refused:
            replay(record, {"p__secret": loosened})
        assert "can't loosen the floor" in str(refused.value)
        assert isinstance(refused.value, ValueError)


@pytest.mark.parametrize(
    ("new", "raised"),
    [
        (Thresholds(0.9, 0.5), ["block_at"]),  # block_at alone above the record's 0.80
        (Thresholds(0.8, 0.6), ["escalate_at"]),  # escalate_at alone above the record's 0.50
        (Thresholds(0.95, 0.7), ["block_at", "escalate_at"]),
    ],
)
async def test_each_raised_floor_threshold_is_refused(new, raised):
    _, record, _ = await run_check(secret_block_scenario())
    with pytest.raises(ReplayRefused) as refused:
        replay(record, {"p__secret": new})
    assert [p.split()[2] for p in refused.value.problems] == raised


@pytest.mark.parametrize(
    "bad", [float("nan"), float("inf"), float("-inf"), None, True, "0.5"], ids=repr
)
@pytest.mark.parametrize("key", ["p__secret", "t__r0"])
async def test_thresholds_that_are_not_finite_numbers_are_refused(bad, key):
    """Written so NaN fails: duck-typed threshold objects bypass the
    ``Thresholds`` constructor's own checks, and replay refuses them for any layer."""
    _, record, _ = await run_check(secret_block_scenario())
    for new in (
        SimpleNamespace(block_at=bad, escalate_at=0.3),
        SimpleNamespace(block_at=0.7, escalate_at=bad),
    ):
        with pytest.raises(ReplayRefused, match="is not a finite number"):
            replay(record, {key: new})


async def test_lowering_a_floor_threshold_is_allowed():
    _, record, _ = await run_check(secret_block_scenario(floor_p={**LOW, "p__secret": 0.7}))
    assert replay(record).decision is Decision.ESCALATE  # tenant 0.6 and secret 0.7: escalate
    replayed = replay(record, {"p__secret": Thresholds(0.65, 0.4)})
    assert replayed.decision is Decision.BLOCK
    assert replay(record, {"p__secret": Thresholds(0.8, 0.5)}).decision is Decision.ESCALATE


async def test_a_catalog_floor_spec_is_a_further_bound():
    _, record, _ = await run_check(secret_block_scenario())
    spec = {"p__secret": Thresholds(0.7, 0.4)}
    # Below the record's 0.80 / 0.50, but above the catalog spec given.
    with pytest.raises(ReplayRefused, match=r"above the catalog's 0\.7"):
        replay(record, {"p__secret": Thresholds(0.75, 0.35)}, floor_specs=spec)
    assert replay(record, {"p__secret": Thresholds(0.7, 0.4)}, floor_specs=spec).recomputed


async def test_a_floor_bound_that_is_not_a_finite_number_refuses():
    """A NaN bound refuses rather than letting every value through
    (``value > nan`` is false)."""
    _, record, _ = await run_check(secret_block_scenario())
    spec = {"p__secret": SimpleNamespace(block_at=float("nan"), escalate_at=0.4)}
    with pytest.raises(ReplayRefused, match="above the catalog's nan"):
        replay(record, {"p__secret": Thresholds(0.7, 0.3)}, floor_specs=spec)


async def test_tenant_and_pack_rules_stay_freely_changeable():
    _, record, _ = await run_check(secret_block_scenario(floor_p=LOW))
    assert replay(record).decision is Decision.ESCALATE  # tenant 0.6, pack 0.6
    loosened = {"t__r0": Thresholds(0.99, 0.98), "d__claim_promise": Thresholds(0.99, 0.98)}
    assert replay(record, loosened).decision is Decision.ALLOW
    tightened = {"t__r0": Thresholds(0.3, 0.1)}
    assert replay(record, tightened).decision is Decision.BLOCK


# ------------------------------------------------------------------ answered noul needs p


async def test_resolve_rule_refuses_an_answered_noul_rule_without_a_probability():
    _, record, _ = await run_check(secret_block_scenario())
    secret = next(ev for ev in record.rules if ev.key == "p__secret")
    with pytest.raises(ValueError, match="answered but has no probability"):
        resolve_rule(secret, basis=Basis.ANSWER, p=None)
    # A router answered without p still resolves (it never acts on its own).
    router = secret.model_copy(update={"question_type": "choice", "p": None})
    assert resolve_rule(router, basis=Basis.ANSWER).action is Action.ALLOW


@pytest.mark.parametrize(
    ("key", "p", "problem"),
    [
        ("p__secret", None, "needs a probability"),  # answered noul, p nulled
        ("p__secret", 1.5, "needs a probability"),  # out of range
        ("p__secret", -0.1, "needs a probability"),  # below zero
    ],
)
async def test_a_stored_record_with_a_bad_answered_probability_does_not_load(key, p, problem):
    _, record, _ = await run_check(secret_block_scenario())
    data = json.loads(record.model_dump_json())
    [rule_data] = [r for r in data["rules"] if r["key"] == key]
    rule_data["p"] = p
    with pytest.raises(ValidationError, match=problem):
        AuditRecord.model_validate_json(json.dumps(data))


async def test_a_fail_mode_evaluation_with_a_probability_does_not_load():
    _, record, _ = await run_check(answered_scenario(outcome=("failed", FailureKind.TIMEOUT)))
    data = json.loads(record.model_dump_json())
    data["rules"][0]["p"] = 0.01
    with pytest.raises(ValidationError, match="resolved by fail mode has no probability"):
        AuditRecord.model_validate_json(json.dumps(data))
