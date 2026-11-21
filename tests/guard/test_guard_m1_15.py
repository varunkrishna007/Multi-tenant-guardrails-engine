"""M1-15 through the Guard Service: the gateway's R8 signal (``retry_after_ms``,
``capacity_limited``) and the in-flight count at check start, as they reach the verdict and
the audit record. (The span attribute is tested with the OTel adapter in
``tests/telemetry/test_telemetry_otel.py``.)

Real time, with the fake model, as the other Guard Service admission tests: timings are
asserted with generous bounds, never exactly.
"""

import asyncio
from datetime import UTC, datetime

import pytest
from guard_fixtures import ALPHA, Env, bundle, rule

from guardrail_engine.decision import Failed, FailureKind
from guardrail_engine.gateway import RETRY_AFTER_MAX_MS, RETRY_AFTER_MIN_MS, GatewayConfig
from guardrail_engine.guard import Decision, GuardConfig, Reason, Verdict
from guardrail_engine.guard import verdict as verdict_module
from guardrail_engine.policy import PlatformSettings

# One slot per key, a fixed 0.3 s budget and a 0.2 s expected call: while one call is in
# flight, a second check predicts about 0.15 + 0.2 > 0.25 left and is refused at once.
ONE_SLOT = GatewayConfig(max_in_flight_per_key=1, default_budget_s=0.3, expected_latency_s=0.2)


async def refused_while_one_call_hangs(env):
    env.fake.slow_next(5.0)
    holder = asyncio.ensure_future(env.check(ALPHA))
    await asyncio.sleep(0.05)  # the first call is in flight
    refused = await env.check(ALPHA)
    return refused, await holder


def record_of(env, verdict):
    return next(r for r in env.audit.records if r.request_id == verdict.request_id)


async def test_admission_refusal_verdict_carries_the_hint_capacity_flag_and_in_flight_count():
    async with Env(config=GuardConfig(pointer_ttl_s=60.0, gateway=ONE_SLOT)) as env:
        await env.publish(bundle(ALPHA, rules=[rule("adv")]))
        refused, holder = await refused_while_one_call_hangs(env)

    assert (refused.decision, refused.reason) == (Decision.BLOCK, Reason.MODEL_FAILURE)
    assert refused.failure_reason == "admission_wait"
    assert refused.capacity_limited is True
    # The holder's remaining expected time: 0.2 s less the ~0.05 s it has run.
    assert RETRY_AFTER_MIN_MS <= refused.retry_after_ms <= 200
    assert refused.in_flight_at_start == 1  # the holder's call
    # The holder timed out at the provider: no hint, not a capacity refusal.
    assert holder.failure_kind is FailureKind.TIMEOUT
    assert (holder.retry_after_ms, holder.capacity_limited) == (None, False)
    assert holder.in_flight_at_start == 0
    # The audit record carries the in-flight count (M1-15's audit criterion) and, as decided
    # on the M1-15 build, the capacity signal next to failure_reason.
    record = record_of(env, refused)
    assert (record.in_flight_at_start, record.capacity_limited, record.retry_after_ms) == (
        1,
        True,
        refused.retry_after_ms,
    )
    assert record.failure_reason == "admission_wait"
    held = record_of(env, holder)
    assert (held.in_flight_at_start, held.capacity_limited, held.retry_after_ms) == (0, False, None)


async def test_open_breaker_verdict_hints_the_next_probe_and_is_not_capacity_limited():
    async with Env() as env:
        await env.publish(bundle(ALPHA))
        env.fake.always(Failed(kind=FailureKind.AUTH, reason="API_KEY_INVALID"))
        opened = await env.check(ALPHA)
        env.fake.always(None)
        refused = await env.check(ALPHA)

    for verdict in (opened, refused):
        assert (verdict.decision, verdict.reason) == (Decision.BLOCK, Reason.MODEL_FAILURE)
        assert verdict.failure_kind is FailureKind.AUTH
        assert 4_000 <= verdict.retry_after_ms <= 5_000  # the 5 s first probe, less elapsed
        assert verdict.capacity_limited is False
        record = record_of(env, verdict)
        assert (record.retry_after_ms, record.capacity_limited) == (verdict.retry_after_ms, False)


async def test_a_provider_429_with_retry_info_reaches_the_verdict_and_audit():
    """Decided on the M1-15 build: the provider's RetryInfo delay becomes the hint; the provider
    refused, not the gateway, so not capacity_limited."""
    async with Env() as env:
        await env.publish(bundle(ALPHA))
        env.fake.always(Failed(kind=FailureKind.RATE_LIMITED, reason="RATE", retry_delay_s=2.5))
        limited = await env.check(ALPHA)
        env.fake.always(Failed(kind=FailureKind.RATE_LIMITED))
        plain = await env.check(ALPHA)
    assert (limited.decision, limited.reason) == (Decision.BLOCK, Reason.MODEL_FAILURE)
    assert limited.failure_kind is FailureKind.RATE_LIMITED
    assert (limited.retry_after_ms, limited.capacity_limited) == (2_500, False)
    assert (plain.retry_after_ms, plain.capacity_limited) == (None, False)
    record = record_of(env, limited)
    assert (record.retry_after_ms, record.capacity_limited, record.failure_reason) == (
        2_500,
        False,
        "RATE",
    )


@pytest.mark.parametrize(
    "outcome",
    [Failed(kind=FailureKind.UNAVAILABLE), Failed(kind=FailureKind.OTHER, reason="admission_wait")],
    ids=["provider_unavailable", "provider_reason_spelling_a_gateway_refusal"],
)
async def test_provider_failures_carry_no_hint_and_no_capacity_flag(outcome):
    async with Env() as env:
        await env.publish(bundle(ALPHA))
        env.fake.always(outcome)
        verdict = await env.check(ALPHA)
    assert (verdict.decision, verdict.reason) == (Decision.BLOCK, Reason.MODEL_FAILURE)
    assert (verdict.retry_after_ms, verdict.capacity_limited) == (None, False)


async def test_a_released_model_failure_carries_no_hint():
    """With an open floor and open tenant rules an admission refusal is allow/model_failure:
    nothing was withheld, so there is nothing to retry (R8 applies to withheld content)."""
    settings = PlatformSettings(floor_fail_mode="open")
    config = GuardConfig(pointer_ttl_s=60.0, gateway=ONE_SLOT)
    async with Env(settings=settings, config=config) as env:
        await env.publish(bundle(ALPHA, rules=[rule("adv")], defaults={"fail_mode": "open"}))
        refused, _ = await refused_while_one_call_hangs(env)
    assert (refused.decision, refused.reason) == (Decision.ALLOW, Reason.MODEL_FAILURE)
    assert refused.failure_reason == "admission_wait"
    assert (refused.retry_after_ms, refused.capacity_limited) == (None, False)
    assert refused.in_flight_at_start == 1  # still recorded


async def test_answered_and_no_call_verdicts():
    async with Env() as env:
        await env.publish(bundle(ALPHA))
        answered = await env.check(ALPHA)
        no_call = await env.check(ALPHA, content="x" * 400_000)  # deterministic size block
    assert answered.in_flight_at_start == 0
    assert (answered.retry_after_ms, answered.capacity_limited) == (None, False)
    assert no_call.model_called is False and no_call.in_flight_at_start is None
    assert record_of(env, no_call).in_flight_at_start is None


def verdict_with(**fields) -> Verdict:
    return Verdict(
        request_id="r",
        tenant_id=ALPHA,
        guard_point="output",
        checked_at=datetime(2026, 11, 17, tzinfo=UTC),
        latency_ms=1.0,
        **fields,
    )


def test_the_verdict_takes_the_hint_only_on_a_withheld_model_failure():
    ok = verdict_with(
        decision=Decision.BLOCK, reason=Reason.MODEL_FAILURE, retry_after_ms=250,
        capacity_limited=True,
    )  # fmt: skip
    assert (ok.retry_after_ms, ok.capacity_limited, ok.retryable) == (250, True, True)
    with pytest.raises(ValueError, match="R8"):
        verdict_with(decision=Decision.BLOCK, reason=Reason.POLICY, retry_after_ms=250)
    with pytest.raises(ValueError, match="R8"):
        verdict_with(decision=Decision.BLOCK, reason=Reason.PROVIDER_SAFETY, capacity_limited=True)
    for bad in (RETRY_AFTER_MIN_MS - 1, RETRY_AFTER_MAX_MS + 1, 0, -5):
        with pytest.raises(ValueError, match="retry_after_ms"):
            verdict_with(decision=Decision.BLOCK, reason=Reason.MODEL_FAILURE, retry_after_ms=bad)


def test_the_verdicts_clamp_is_the_gateways():
    assert (verdict_module.RETRY_AFTER_MIN_MS, verdict_module.RETRY_AFTER_MAX_MS) == (
        RETRY_AFTER_MIN_MS,
        RETRY_AFTER_MAX_MS,
    )
