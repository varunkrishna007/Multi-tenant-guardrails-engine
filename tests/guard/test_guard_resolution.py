"""M1-05 resolution: failures by layer (B1), per-key answer problems (PF-6), provider safety
(PF-12), and AC-G4's "every failure ends in a defined verdict; no exception escapes
``check()``" with fault injection through the fake."""

import asyncio

import pytest
from guard_fixtures import ALPHA, Env, bundle, rule

from guardrail_engine.decision import Failed, FailureKind, ProblemKind, SafetyBlocked
from guardrail_engine.gateway import GatewayConfig
from guardrail_engine.guard import (
    Action,
    Basis,
    Decision,
    GuardConfig,
    PolicySource,
    Reason,
)
from guardrail_engine.policy import PlatformSettings

OPEN_TENANT = {"defaults": {"fail_mode": "open"}}


def open_bundle(**kwargs):
    return bundle(ALPHA, rules=[rule("adv")], defaults={"fail_mode": "open"}, **kwargs)


# ------------------------------------------------------------------ B1: failure by layer


@pytest.mark.parametrize("kind", list(FailureKind))
async def test_b1_tenant_fail_open_still_blocks_on_model_failure_because_the_floor_fails_closed(
    kind,
):
    async with Env() as env:
        await env.publish(open_bundle())
        env.fake.always(Failed(kind=kind, message="scripted"))
        verdict = await env.check(ALPHA)

    assert verdict.decision is Decision.BLOCK
    assert verdict.reason is Reason.MODEL_FAILURE
    assert verdict.failure_kind is kind
    by_key = {ev.key: ev for ev in verdict.rules}
    assert by_key["t__adv"].fail_mode == "open"
    assert by_key["t__adv"].action is Action.ALLOW
    for floor_key in ("p__inj_direct", "p__ai_addressed", "p__secret"):
        assert by_key[floor_key].fail_mode == "closed"
        assert by_key[floor_key].action is Action.BLOCK
        assert by_key[floor_key].basis is Basis.FAIL_MODE
        assert by_key[floor_key].p is None
    assert {f.key for f in verdict.fired} == {"p__inj_direct", "p__ai_addressed", "p__secret"}
    assert all(f.p is None and f.basis is Basis.FAIL_MODE for f in verdict.fired)
    assert verdict.probabilities == {}


async def test_b1_flipping_floor_fail_mode_changes_the_outcome_with_no_code_change():
    settings = PlatformSettings(floor_fail_mode="open")
    async with Env(settings=settings) as env:
        await env.publish(open_bundle())
        env.fake.always(Failed(kind=FailureKind.UNAVAILABLE))
        verdict = await env.check(ALPHA)

    assert verdict.decision is Decision.ALLOW
    assert verdict.reason is Reason.MODEL_FAILURE  # still flagged as decided without answers
    assert verdict.failure_kind is FailureKind.UNAVAILABLE
    assert verdict.fired == ()


async def test_b1_tenant_fail_closed_blocks_on_its_own_rules_when_the_floor_is_open():
    settings = PlatformSettings(floor_fail_mode="open")
    async with Env(settings=settings) as env:
        await env.publish(bundle(ALPHA, rules=[rule("adv")]))  # S5: default closed
        env.fake.always(Failed(kind=FailureKind.RATE_LIMITED))
        verdict = await env.check(ALPHA)
    assert verdict.decision is Decision.BLOCK
    assert {f.key for f in verdict.fired} == {"t__adv"}


async def test_b1_guard_point_fail_mode_applies_to_pack_and_tenant_rules_only():
    async with Env() as env:
        await env.publish(
            bundle(
                ALPHA,
                rules=[rule("adv")],
                packs=["domain/claims@1"],
                guard_points={"output": {"fail_mode": "open"}},
            )
        )
        env.fake.always(Failed(kind=FailureKind.TIMEOUT))
        verdict = await env.check(ALPHA)
    modes = {ev.key: (ev.layer, ev.fail_mode, ev.action) for ev in verdict.rules}
    assert modes["d__claim_promise"] == ("pack", "open", Action.ALLOW)
    assert modes["t__adv"] == ("tenant", "open", Action.ALLOW)
    assert modes["p__secret"] == ("floor", "closed", Action.BLOCK)
    assert verdict.decision is Decision.BLOCK


async def test_model_failure_block_is_distinguishable_from_a_policy_block():
    """Same outcome for the caller (blocked, not released), different reason: a later
    product decision depends on telling these apart."""
    async with Env() as env:
        await env.publish(open_bundle())
        env.fake.set_noul("p__inj_direct", 0.95)
        policy = await env.check(ALPHA)
        env.fake.always(Failed(kind=FailureKind.TIMEOUT))
        failure = await env.check(ALPHA)

    assert policy.decision is failure.decision is Decision.BLOCK
    assert not policy.released and not failure.released
    assert policy.reason is Reason.POLICY and policy.failure_kind is None
    assert failure.reason is Reason.MODEL_FAILURE and failure.failure_kind is FailureKind.TIMEOUT
    assert policy.probabilities and not failure.probabilities


# ------------------------------------------------------------------ PF-12: provider safety


async def test_pf12_safety_blocked_always_blocks_whatever_modes_and_fail_modes():
    settings = PlatformSettings(floor_fail_mode="open")
    async with Env(settings=settings) as env:
        await env.publish(bundle(ALPHA, rules=[rule("adv", mode="shadow")], **OPEN_TENANT))
        env.fake.safety_block_next(message="refused")
        verdict = await env.check(ALPHA)
    assert verdict.decision is Decision.BLOCK
    assert verdict.reason is Reason.PROVIDER_SAFETY
    assert verdict.failure_kind is None
    assert verdict.model_called and len(env.fake.calls) == 1
    assert not verdict.released


# ------------------------------------------------------------------ PF-6: per-key problems


@pytest.mark.parametrize("problem", ["missing", "wrong_type", "out_of_range"])
async def test_pf6_bad_answer_for_an_enforce_rule_resolves_by_its_fail_mode_closed(problem):
    async with Env() as env:
        await env.publish(bundle(ALPHA, rules=[rule("adv")]))
        env.fake.malformed_next(**{problem: ["t__adv"]})
        verdict = await env.check(ALPHA)

    assert verdict.decision is Decision.BLOCK
    assert verdict.reason is Reason.CONTRACT_VIOLATION
    [violation] = verdict.contract_violations
    assert violation.key == "t__adv"
    assert violation.kind is ProblemKind(problem)
    assert violation.resolved_action is Action.BLOCK
    adv = {ev.key: ev for ev in verdict.rules}["t__adv"]
    assert adv.basis is Basis.FAIL_MODE and adv.problem is ProblemKind(problem) and adv.p is None
    # The other keys were answered and evaluated normally.
    assert set(verdict.probabilities) == {"p__inj_direct", "p__ai_addressed", "p__secret"}


@pytest.mark.parametrize("problem", ["missing", "wrong_type", "out_of_range"])
async def test_pf6_bad_answer_for_an_open_tenant_rule_allows_that_key_and_is_still_logged(
    problem, caplog
):
    async with Env() as env:
        await env.publish(open_bundle())
        env.fake.malformed_next(**{problem: ["t__adv"]})
        verdict = await env.check(ALPHA)
    assert verdict.decision is Decision.ALLOW
    assert verdict.reason is Reason.POLICY
    [violation] = verdict.contract_violations
    assert (violation.key, violation.resolved_action) == ("t__adv", Action.ALLOW)
    assert "contract_violation" in caplog.text and "t__adv" in caplog.text


async def test_pf6_bad_floor_answer_blocks_even_for_a_fail_open_tenant():
    async with Env() as env:
        await env.publish(open_bundle())
        env.fake.malformed_next(out_of_range={"p__ai_addressed": 1.0})
        verdict = await env.check(ALPHA)
    assert verdict.decision is Decision.BLOCK
    assert verdict.reason is Reason.CONTRACT_VIOLATION
    assert [v.key for v in verdict.contract_violations] == ["p__ai_addressed"]


async def test_pf6_bad_answer_for_a_shadow_rule_is_only_logged():
    async with Env() as env:
        await env.publish(bundle(ALPHA, rules=[rule("watch", mode="shadow")]))
        env.fake.malformed_next(missing=["t__watch"])
        verdict = await env.check(ALPHA)
    assert verdict.decision is Decision.ALLOW
    assert verdict.reason is Reason.POLICY
    [violation] = verdict.contract_violations
    assert (violation.key, violation.mode) == ("t__watch", "shadow")


async def test_pf6_problem_on_one_key_does_not_hide_a_policy_block_on_another():
    async with Env() as env:
        await env.publish(bundle(ALPHA, rules=[rule("adv"), rule("other")]))
        env.fake.set_noul("t__other", 0.95).malformed_next(missing=["t__adv"])
        verdict = await env.check(ALPHA)
    assert verdict.decision is Decision.BLOCK
    assert verdict.reason is Reason.POLICY  # an answered rule blocks on its own
    assert verdict.probabilities["t__other"] == 0.95
    assert [v.key for v in verdict.contract_violations] == ["t__adv"]


async def test_pf6_raw_response_with_garbage_for_every_key_resolves_per_key():
    async with Env() as env:
        await env.publish(open_bundle())
        env.fake.raw_response_next({"answers": {"t__adv": "nonsense"}, "usage": None})
        verdict = await env.check(ALPHA)
    assert verdict.decision is Decision.BLOCK  # floor keys missing: closed
    kinds = {v.key: v.kind for v in verdict.contract_violations}
    assert kinds["t__adv"] is ProblemKind.INVALID
    assert kinds["p__inj_direct"] is ProblemKind.MISSING


# ------------------------------------------------------------------ routers and scorers


@pytest.mark.parametrize("problem", ["missing", "wrong_type", "out_of_range"])
async def test_a_router_without_a_usable_answer_resolves_to_allow_and_is_recorded(problem):
    """A router never acts when answered, so it gains no blocking power when its answer
    fails: the floor answered cleanly, so the verdict is allow/policy, violation recorded."""
    async with Env() as env:
        await env.publish(bundle(ALPHA, packs=["domain/claims@1"]))  # d__route closed (S5)
        env.fake.malformed_next(**{problem: ["d__route"]})
        verdict = await env.check(ALPHA, "input")
    assert (verdict.decision, verdict.reason) == (Decision.ALLOW, Reason.POLICY)
    [violation] = verdict.contract_violations
    assert (violation.key, violation.resolved_action) == ("d__route", Action.ALLOW)
    route = {ev.key: ev for ev in verdict.rules}["d__route"]
    assert (route.basis, route.action, route.fail_mode) == (Basis.FAIL_MODE, Action.ALLOW, "closed")


async def test_on_a_failed_call_routers_allow_and_the_floor_still_blocks():
    async with Env() as env:
        await env.publish(bundle(ALPHA, packs=["domain/claims@1"]))
        env.fake.always(Failed(kind=FailureKind.UNAVAILABLE))
        verdict = await env.check(ALPHA, "input")
    actions = {ev.key: ev.action for ev in verdict.rules}
    assert actions["d__route"] is Action.ALLOW
    assert actions["p__inj_direct"] is Action.BLOCK
    assert (verdict.decision, verdict.reason) == (Decision.BLOCK, Reason.MODEL_FAILURE)
    assert "d__route" not in {f.key for f in verdict.fired}


# ------------------------------------------------------------------ AC-G4: fault injection


class RaisingModel:
    model_id = "raising"

    def __init__(self, exc: BaseException) -> None:
        self.exc = exc

    async def decide(self, input, questions):
        raise self.exc


class GarbageModel:
    model_id = "garbage"

    async def decide(self, input, questions):
        return {"not": "a result"}


def _defined(verdict):
    assert verdict.decision in set(Decision)
    assert verdict.reason in set(Reason)
    return verdict


AC_G4_MODEL_CASES = {
    "timeout": lambda f: f.always(Failed(kind=FailureKind.TIMEOUT)),
    "429": lambda f: f.always(Failed(kind=FailureKind.RATE_LIMITED)),
    "limit_exceeded": lambda f: f.always(Failed(kind=FailureKind.LIMIT_EXCEEDED, key="t__adv")),
    "unavailable": lambda f: f.always(Failed(kind=FailureKind.UNAVAILABLE)),
    "auth": lambda f: f.always(Failed(kind=FailureKind.AUTH, reason="API_KEY_INVALID")),
    "other": lambda f: f.always(Failed(kind=FailureKind.OTHER)),
}


@pytest.mark.parametrize("case", sorted(AC_G4_MODEL_CASES))
async def test_ac_g4_each_model_failure_ends_in_a_defined_block_verdict(case):
    async with Env() as env:
        await env.publish(open_bundle())
        AC_G4_MODEL_CASES[case](env.fake)
        verdict = _defined(await env.check(ALPHA))
    assert (verdict.decision, verdict.reason) == (Decision.BLOCK, Reason.MODEL_FAILURE)
    assert verdict.failure_kind is not None
    assert len(env.audit.verdicts) == 1


async def test_ac_g4_real_budget_timeout_ends_in_a_defined_verdict():
    config = GuardConfig(
        pointer_ttl_s=0.0, gateway=GatewayConfig(default_budget_s=0.05, expected_latency_s=0.04)
    )
    async with Env(config=config) as env:
        await env.publish(open_bundle())
        env.fake.slow_next(5.0, times=2)
        verdict = _defined(await env.check(ALPHA))
    assert verdict.reason is Reason.MODEL_FAILURE
    assert verdict.failure_kind is FailureKind.TIMEOUT
    assert verdict.decision is Decision.BLOCK
    assert verdict.latency_ms < 1000


async def test_ac_g4_safety_ends_in_a_defined_verdict():
    async with Env() as env:
        await env.publish(open_bundle())
        env.fake.always(SafetyBlocked())
        verdict = _defined(await env.check(ALPHA))
    assert verdict.reason is Reason.PROVIDER_SAFETY


async def test_ac_g4_contract_violation_ends_in_a_defined_verdict():
    async with Env() as env:
        await env.publish(bundle(ALPHA, rules=[rule("adv")]))
        env.fake.malformed_next(wrong_type=["t__adv"])
        verdict = _defined(await env.check(ALPHA))
    assert verdict.reason is Reason.CONTRACT_VIOLATION


async def test_ac_g4_store_unavailable_serves_the_last_known_good_version():
    async with Env() as env:
        await env.publish(bundle(ALPHA, rules=[rule("adv")]))
        env.fake.set_noul("t__adv", 0.95)
        first = await env.check(ALPHA)
        env.store.fail = ConnectionError("database is down")
        env.service.policy_cache.invalidate(ALPHA)  # re-read the pointer now
        verdict = _defined(await env.check(ALPHA))
    assert first.policy_source is PolicySource.ACTIVE
    assert verdict.policy_source is PolicySource.LAST_KNOWN_GOOD
    assert "ConnectionError" in verdict.policy_error
    assert (verdict.decision, verdict.reason) == (Decision.BLOCK, Reason.POLICY)
    assert verdict.bundle_version == first.bundle_version
    assert verdict.bundle_hash == first.bundle_hash


@pytest.mark.parametrize(
    "exc", [RuntimeError("adapter bug"), ValueError("bad"), KeyError("k"), TypeError("t")]
)
async def test_ac_g4_a_model_that_raises_is_resolved_by_layer(exc):
    async with Env() as env:
        await env.publish(open_bundle())
        env.service._gateway._model = RaisingModel(exc)
        verdict = _defined(await env.check(ALPHA))
    assert (verdict.decision, verdict.reason) == (Decision.BLOCK, Reason.MODEL_FAILURE)
    assert verdict.failure_kind is FailureKind.OTHER


async def test_ac_g4_a_model_returning_garbage_is_resolved_by_layer():
    async with Env() as env:
        await env.publish(open_bundle())
        env.service._gateway._model = GarbageModel()
        verdict = _defined(await env.check(ALPHA))
    assert (verdict.decision, verdict.reason) == (Decision.BLOCK, Reason.MODEL_FAILURE)


async def test_ac_g4_a_gateway_that_raises_is_resolved_by_layer(monkeypatch):
    async with Env() as env:
        await env.publish(open_bundle())

        async def broken(**kwargs):
            raise RuntimeError("gateway bug")

        monkeypatch.setattr(env.service._gateway, "decide_timed", broken)
        verdict = _defined(await env.check(ALPHA))
    assert (verdict.decision, verdict.reason) == (Decision.BLOCK, Reason.MODEL_FAILURE)
    assert verdict.failure_kind is FailureKind.OTHER


async def test_ac_g4_a_gateway_returning_garbage_is_resolved_by_layer(monkeypatch):
    async with Env() as env:
        await env.publish(open_bundle())

        async def garbage(**kwargs):
            return "garbage"

        monkeypatch.setattr(env.service._gateway, "decide_timed", garbage)
        verdict = _defined(await env.check(ALPHA))
    assert verdict.reason is Reason.MODEL_FAILURE


async def test_ac_g4_hanging_store_with_no_last_known_good_blocks_within_the_store_timeout():
    config = GuardConfig(pointer_ttl_s=0.0, store_timeout_s=0.05)
    async with Env(config=config) as env:
        await env.publish(bundle(ALPHA))
        env.store.hang = True
        verdict = _defined(await env.check(ALPHA))
    assert (verdict.decision, verdict.reason) == (Decision.BLOCK, Reason.POLICY_UNAVAILABLE)
    assert "timed out" in verdict.policy_error
    assert env.fake.calls == []


async def test_ac_g4_tenant_directory_failure_with_no_last_known_good_blocks():
    class BrokenDirectory:
        async def get(self, tenant_id):
            raise OSError("directory down")

    async with Env(directory=BrokenDirectory()) as env:
        await env.publish(bundle(ALPHA))
        verdict = _defined(await env.check(ALPHA))
    assert (verdict.decision, verdict.reason) == (Decision.BLOCK, Reason.POLICY_UNAVAILABLE)


async def test_ac_g4_compiler_crash_is_a_policy_failure_not_an_exception():
    class Crashing:
        def __init__(self, *args):
            pass

        def compile(self, bundle, tenant):
            raise RuntimeError("compiler bug")

    async with Env(compiler_factory=Crashing) as env:
        await env.publish(bundle(ALPHA))
        verdict = _defined(await env.check(ALPHA))
    assert verdict.reason is Reason.POLICY_UNAVAILABLE
    # The exception's type name is recorded; its text goes to the log only.
    assert verdict.policy_error == "RuntimeError"
    assert "compiler bug" not in repr(verdict)


async def test_ac_g4_audit_sink_failure_never_loses_the_verdict(caplog):
    class BrokenSink:
        def record(self, verdict):
            raise RuntimeError("sink down")

    async with Env(audit=BrokenSink()) as env:
        await env.publish(bundle(ALPHA))
        verdict = _defined(await env.check(ALPHA))
    assert verdict.decision is Decision.ALLOW
    assert "audit sink failed" in caplog.text


async def test_ac_g4_broken_nonce_source_fails_closed_as_internal_error():
    async with Env(nonce_source=lambda: "not-hex") as env:
        await env.publish(bundle(ALPHA))
        verdict = _defined(await env.check(ALPHA))
    assert (verdict.decision, verdict.reason) == (Decision.BLOCK, Reason.INTERNAL_ERROR)
    assert env.fake.calls == []
    assert env.audit.verdicts == [verdict]


async def test_ac_g4_broken_verifier_fails_closed_as_internal_error():
    class Boom:
        def verify(self, token):
            raise RuntimeError("verifier bug")

    async with Env() as env:
        env.service._verifier = Boom()
        verdict = _defined(await env.check(ALPHA))
    assert (verdict.decision, verdict.reason) == (Decision.BLOCK, Reason.INTERNAL_ERROR)
    assert verdict.tenant_id is None


async def test_ac_g4_caller_cancellation_propagates():
    async with Env() as env:
        await env.publish(bundle(ALPHA))
        env.fake.slow_next(5.0)
        task = asyncio.ensure_future(env.check(ALPHA))
        await asyncio.sleep(0.05)  # the model call is in flight (the fake sleeps 5 s)
        assert not task.done()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    assert env.audit.verdicts == []
    assert env.fake.calls == []  # the model call was cancelled with it


# ------------------------------------------------------------------ M1-04 admission control
# A check the gateway refuses at admission (no free slot on the key, and the predicted wait
# won't fit its budget, or the key's queue is full) makes no provider call. It must resolve
# like any other model failure: every rule by its own layer's fail mode (B1), reason
# model_failure, the gateway's refusal reason recorded, retryable unless released.

# One slot per key, a fixed 0.3 s budget and a 0.2 s expected call: while one call is in
# flight, a second check predicts 0.2 + 0.2 > 0.3 and is refused at once.
ONE_SLOT = GatewayConfig(max_in_flight_per_key=1, default_budget_s=0.3, expected_latency_s=0.2)


async def refused_while_one_call_hangs(env):
    """Hold the key's only slot with a hanging call, then check again. Returns both."""
    env.fake.slow_next(5.0)
    holder = asyncio.ensure_future(env.check(ALPHA))
    await asyncio.sleep(0.05)  # the first call is in flight
    refused = await env.check(ALPHA)
    return refused, await holder


async def test_m1_04_admission_refusal_of_a_floor_check_blocks_as_model_failure():
    async with Env(config=GuardConfig(pointer_ttl_s=60.0, gateway=ONE_SLOT)) as env:
        await env.publish(open_bundle())  # tenant rules fail open; the floor fails closed
        refused, holder = await refused_while_one_call_hangs(env)

    assert (refused.decision, refused.reason) == (Decision.BLOCK, Reason.MODEL_FAILURE)
    assert refused.failure_kind is FailureKind.UNAVAILABLE
    assert refused.failure_reason == "admission_wait"
    assert refused.retryable
    assert {f.key for f in refused.fired} == {"p__inj_direct", "p__ai_addressed", "p__secret"}
    assert all(f.basis is Basis.FAIL_MODE for f in refused.fired)
    by_key = {ev.key: ev for ev in refused.rules}
    assert (by_key["t__adv"].fail_mode, by_key["t__adv"].action) == ("open", Action.ALLOW)
    assert refused.queue_wait_ms == pytest.approx(0, abs=20)  # refused before queueing
    # Told apart from a provider timeout, which the holder got:
    assert (holder.reason, holder.failure_kind) == (Reason.MODEL_FAILURE, FailureKind.TIMEOUT)
    assert holder.failure_reason is None
    assert env.fake.calls == []  # the refused check sent nothing; the holder was cancelled
    assert [v.failure_reason for v in env.audit.verdicts] == ["admission_wait", None]


@pytest.mark.parametrize(
    ("tenant_fail_mode", "decision", "fired"),
    [("open", Decision.ALLOW, set()), ("closed", Decision.BLOCK, {"t__adv"})],
)
async def test_m1_04_admission_refusal_with_an_open_floor_follows_the_tenant_rules_fail_mode(
    tenant_fail_mode, decision, fired
):
    settings = PlatformSettings(floor_fail_mode="open")
    config = GuardConfig(pointer_ttl_s=60.0, gateway=ONE_SLOT)
    async with Env(settings=settings, config=config) as env:
        await env.publish(
            bundle(ALPHA, rules=[rule("adv")], defaults={"fail_mode": tenant_fail_mode})
        )
        refused, _ = await refused_while_one_call_hangs(env)

    assert (refused.decision, refused.reason) == (decision, Reason.MODEL_FAILURE)
    assert refused.failure_reason == "admission_wait"
    assert {f.key for f in refused.fired} == fired
    assert refused.retryable is (decision is Decision.BLOCK)  # an allow is never retryable
    for ev in refused.rules:
        if ev.layer == "floor":
            assert (ev.fail_mode, ev.action) == ("open", Action.ALLOW)


async def test_m1_04_full_admission_queue_blocks_as_model_failure():
    gateway = GatewayConfig(
        max_in_flight_per_key=1,
        max_queued_per_key=1,
        default_budget_s=5.0,
        expected_latency_s=0.1,
        queue_waits_s={"output": 5.0},  # M1-15: let the queued check wait for the slot
    )
    async with Env(config=GuardConfig(pointer_ttl_s=60.0, gateway=gateway)) as env:
        await env.publish(open_bundle())
        env.fake.slow_next(0.3)
        first = asyncio.ensure_future(env.check(ALPHA))
        await asyncio.sleep(0.05)
        queued = asyncio.ensure_future(env.check(ALPHA))
        await asyncio.sleep(0.05)
        refused = await env.check(ALPHA)
        others = await asyncio.gather(first, queued)

    assert (refused.decision, refused.reason) == (Decision.BLOCK, Reason.MODEL_FAILURE)
    assert refused.failure_reason == "admission_queue_full"
    assert refused.retryable
    assert [v.decision for v in others] == [Decision.ALLOW, Decision.ALLOW]
    assert len(env.fake.calls) == 2


async def test_m1_04_verdict_records_the_queue_wait():
    gateway = GatewayConfig(
        max_in_flight_per_key=1,
        default_budget_s=2.0,
        expected_latency_s=0.1,
        queue_waits_s={"output": 2.0},  # M1-15: let the second check wait for the slot
    )
    async with Env(config=GuardConfig(pointer_ttl_s=60.0, gateway=gateway)) as env:
        await env.publish(open_bundle())
        env.fake.slow_next(0.2)
        first = asyncio.ensure_future(env.check(ALPHA))
        await asyncio.sleep(0.05)
        second = await env.check(ALPHA)  # waits for the first call's slot
        first = await first
        no_call = await env.check(ALPHA, content="x" * 400_000)  # deterministic size block

    assert first.decision is second.decision is Decision.ALLOW
    assert first.queue_wait_ms == pytest.approx(0, abs=20)
    assert 100 <= second.queue_wait_ms <= 400  # about 150 ms of the first call left
    assert second.model_latency_ms >= second.queue_wait_ms
    assert no_call.model_called is False and no_call.queue_wait_ms is None
    audited = {v.request_id: v.queue_wait_ms for v in env.audit.verdicts}
    assert audited[second.request_id] == second.queue_wait_ms
