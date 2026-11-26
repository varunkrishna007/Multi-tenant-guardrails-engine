"""M7-11 through the Guard Service: while the provider is degraded a check fails at once,
labelled and retryable, and the decision is what the rules' fail modes give (the floor blocks):
nothing falls back to allow. The fake model's failures stand in for the provider."""

from guard_fixtures import ALPHA, Env, GuardConfig, bundle, rule

from guardrail_engine.decision import Failed, FailureKind
from guardrail_engine.gateway import REASON_PROVIDER_DEGRADED, GatewayConfig
from guardrail_engine.guard import Decision, Reason
from guardrail_engine.guard.audit import AUDIT_RECORD_SCHEMA_VERSION, AuditRecord
from guardrail_engine.guard.chunking import combine
from guardrail_engine.sdk.result import FailureReason, GuardResult

TEXT = "Move your savings into the Growth Fund."


def make_env() -> Env:
    return Env(config=GuardConfig(pointer_ttl_s=60.0, gateway=GatewayConfig()))


async def ready(env: Env) -> None:
    await env.publish(bundle(ALPHA, rules=[rule("x", gps=("input", "output"))]))


async def open_it(env: Env) -> None:
    """Five failed calls: each check makes two (the gateway's one retry), so the third check's
    retry is the fifth and opens the breaker."""
    env.fake.fail_next(FailureKind.UNAVAILABLE, 5)
    for _ in range(3):
        verdict = await env.check(ALPHA, "output", TEXT)
        assert verdict.reason is Reason.MODEL_FAILURE and verdict.degraded is False


async def test_a_degraded_check_is_labelled_retryable_and_blocks_with_no_provider_call():
    async with make_env() as env:
        await ready(env)
        await open_it(env)
        calls = len(env.fake.calls)
        v = await env.check(ALPHA, "output", TEXT)
        assert (v.decision, v.reason) == (Decision.BLOCK, Reason.MODEL_FAILURE)
        assert v.degraded is True and v.failure_reason == REASON_PROVIDER_DEGRADED
        assert v.failure_kind is FailureKind.UNAVAILABLE
        assert v.retryable and v.capacity_limited is False
        assert v.provider_calls == 0 and len(env.fake.calls) == calls
        assert v.retry_after_ms is not None and 100 <= v.retry_after_ms <= 5_000


async def test_the_audit_record_says_degraded_and_is_schema_7():
    async with make_env() as env:
        await ready(env)
        await open_it(env)
        assert env.audit.records[-1].degraded is False  # the failure that opened it
        await env.check(ALPHA, "output", TEXT)
        record = env.audit.records[-1]
        assert record.degraded is True and record.schema_version == AUDIT_RECORD_SCHEMA_VERSION == 7
        assert record.failure_reason == REASON_PROVIDER_DEGRADED


async def test_a_record_written_before_the_field_still_loads():
    async with make_env() as env:
        await ready(env)
        await env.check(ALPHA, "output", TEXT)
        old = env.audit.records[-1].model_dump(mode="json")
        del old["degraded"]
        old["schema_version"] = 6
        assert AuditRecord.model_validate(old).degraded is False


async def test_the_sdk_result_reads_it_as_provider_degraded_and_retryable():
    async with make_env() as env:
        await ready(env)
        await open_it(env)
        v = await env.check(ALPHA, "output", TEXT)
        r = GuardResult.from_verdict(v)
        assert r.failure_reason is FailureReason.PROVIDER_DEGRADED and r.degraded is True
        assert r.retryable and not r.capacity_limited and not r.released
        assert r.retry_after_ms == v.retry_after_ms
        assert r.user_message == "This service is temporarily unavailable. Please try again."


async def test_a_provider_that_sends_the_same_reason_is_not_read_as_degraded():
    async with make_env() as env:
        await ready(env)
        env.fake.push(*[Failed(kind=FailureKind.UNAVAILABLE, reason=REASON_PROVIDER_DEGRADED)] * 2)
        v = await env.check(ALPHA, "output", TEXT)
        assert v.degraded is False
        r = GuardResult.from_verdict(v)
        assert r.failure_reason is FailureReason.UNAVAILABLE and r.degraded is False


async def test_the_deterministic_checks_still_run_while_it_is_degraded():
    async with make_env() as env:
        await ready(env)
        await open_it(env)
        v = await env.check(ALPHA, "output", "x" * 400_000)  # past the size limit
        assert v.reason is not Reason.MODEL_FAILURE and v.degraded is False


async def test_no_guard_point_lets_content_through_while_it_is_degraded():
    async with make_env() as env:
        await ready(env)
        await open_it(env)
        for guard_point in ("input", "output"):
            v = await env.check(ALPHA, guard_point, TEXT)
            assert v.decision is not Decision.ALLOW and v.degraded is True


def test_chunked_checks_are_degraded_if_any_failed_chunk_was():
    from guardrail_engine.gateway import TimedDecision
    from guardrail_engine.gateway.gateway import CheckTiming

    timing = CheckTiming(0.0, 0.0, 0, None)
    failure = Failed(kind=FailureKind.UNAVAILABLE, reason=REASON_PROVIDER_DEGRADED)
    one = TimedDecision(failure, timing, retry_after_ms=3_000, degraded=True)
    two = TimedDecision(Failed(kind=FailureKind.TIMEOUT), timing)
    assert combine([two, one]).degraded is True
    assert combine([two, two]).degraded is False
