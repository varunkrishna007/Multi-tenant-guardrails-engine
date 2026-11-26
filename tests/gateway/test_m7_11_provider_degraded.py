"""M7-11: when the provider stops answering, the gateway fails checks at once, says why, and
probes until it answers again. Nothing here calls a provider: the fake model's failures stand in,
on virtual time."""

import asyncio

import pytest
from test_gateway import QUESTIONS, Harness

from guardrail_engine.decision import Failed, FailureKind
from guardrail_engine.gateway import (
    ALERT_PROVIDER_DEGRADED,
    ALERT_PROVIDER_RECOVERED,
    REASON_PROVIDER_DEGRADED,
    GatewayConfig,
)

# one attempt per check, so a check is one call and a count of calls is a count of checks
ONE = {"budget_margin_s": 60.0}


def make(**kw) -> Harness:
    return Harness(GatewayConfig(**ONE, **kw), health=True)


async def timed(h: Harness):
    result = await h.gateway.decide_timed(
        tenant_id="t_a",
        guard_point="output",
        input="Move your savings into the Growth Fund.",
        questions=QUESTIONS,
    )
    await h.gateway.drain()
    return result


async def fail(h: Harness, n: int, kind=FailureKind.UNAVAILABLE) -> None:
    h.fake.fail_next(kind, n)
    for _ in range(n):
        await h.decide()


def is_degraded(result) -> bool:
    return (
        isinstance(result, Failed)
        and result.kind is FailureKind.UNAVAILABLE
        and result.reason == REASON_PROVIDER_DEGRADED
    )


# ------------------------------------------------------------------------ opening


async def test_five_unavailable_calls_in_a_row_open_it_and_the_next_check_fails_at_once():
    h = make()
    await fail(h, 5)
    assert h.gateway.provider_degraded()
    started = h.model.started
    timed_result = await timed(h)
    assert is_degraded(timed_result.result) and timed_result.degraded is True
    assert h.model.started == started  # no provider call
    assert timed_result.timing.provider_calls == 0
    assert timed_result.capacity_limited is False  # not a capacity refusal
    assert timed_result.retry_after_ms == 5_000  # the time to the first probe
    pages = [a for a in h.alerts.pages() if a.kind == ALERT_PROVIDER_DEGRADED]
    assert len(pages) == 1 and pages[0].reason == "consecutive_failures"


async def test_four_in_a_row_then_an_answer_does_not_open_it():
    h = make()
    await fail(h, 4)
    assert not h.gateway.provider_degraded()
    await h.decide()  # an answer resets the run
    await fail(h, 4)
    assert not h.gateway.provider_degraded()


@pytest.mark.parametrize("kind", [FailureKind.RATE_LIMITED, FailureKind.OTHER])
async def test_a_429_or_an_unclassified_failure_is_not_the_provider_being_down(kind):
    h = make()
    await fail(h, 12, kind)
    assert not h.gateway.provider_degraded()


async def test_a_timeout_counts_when_the_call_ran_its_whole_attempt_deadline():
    h = Harness(GatewayConfig(), health=True)  # the default margin: attempt deadline about 1 s
    h.model.slow_next(*[30.0] * 6)  # never answers; each check cuts the call and retries once
    for _ in range(3):
        failed = await h.decide()
        assert failed.kind is FailureKind.TIMEOUT
    assert h.gateway.provider_degraded()


async def test_a_timeout_of_a_call_that_returned_at_once_does_not_count():
    h = make()
    h.fake.fail_next(FailureKind.TIMEOUT, 8)  # returned at once: it ran 0 s
    for _ in range(8):
        await h.decide()
    assert not h.gateway.provider_degraded()


async def test_more_than_half_of_the_last_twenty_calls_within_thirty_seconds_opens_it():
    h = make()
    # four failures then an answer, over and over: never five in a row, four in five overall
    for _ in range(4):
        await fail(h, 4)
        await h.decide()
    assert h.gateway.provider_degraded()
    pages = [a for a in h.alerts.pages() if a.kind == ALERT_PROVIDER_DEGRADED]
    assert [a.reason for a in pages] == ["failure_rate"]


async def test_a_failure_rate_spread_over_more_than_thirty_seconds_does_not_open_it():
    h = make()
    for _ in range(4):
        for _ in range(4):
            h.fake.fail_next(FailureKind.UNAVAILABLE)
            await h.decide()
            h.vt.advance(2.0)
        await h.decide()
        h.vt.advance(2.0)
    assert not h.gateway.provider_degraded()


async def test_a_provider_that_sends_the_gateways_reason_does_not_fake_the_signal():
    h = make()
    h.fake.push(*[Failed(kind=FailureKind.UNAVAILABLE, reason=REASON_PROVIDER_DEGRADED)] * 2)
    first = await timed(h)
    assert first.degraded is False and first.result.reason == REASON_PROVIDER_DEGRADED
    assert first.retry_after_ms is None


async def test_it_can_be_turned_off():
    h = Harness(GatewayConfig(**ONE, degraded_consecutive=0, degraded_window_calls=0), health=True)
    await fail(h, 12)
    assert not h.gateway.provider_degraded()


def test_the_settings_are_checked():
    for bad in (
        {"degraded_consecutive": -1},
        {"degraded_window_calls": 1.5},
        {"degraded_window_s": 0},
        {"degraded_window_s": float("inf")},
    ):
        with pytest.raises(ValueError):
            GatewayConfig(**bad)
    GatewayConfig(degraded_consecutive=0, degraded_window_calls=0)


# ------------------------------------------------------------------------ probing and closing


async def test_after_the_first_wait_one_check_is_the_probe_and_an_answer_closes_it():
    h = make()
    await fail(h, 5)
    h.vt.advance(5.0)
    probe = await timed(h)  # the model answers (nothing queued)
    assert not isinstance(probe.result, Failed) and probe.timing.provider_calls == 1
    assert not h.gateway.provider_degraded()
    recovered = [a for a in h.alerts.alerts if a.kind == ALERT_PROVIDER_RECOVERED]
    assert len(recovered) == 1 and recovered[0].reason == "probe"
    again = await timed(h)
    assert not isinstance(again.result, Failed)  # calls go through again


async def test_a_probe_that_fails_keeps_it_open_and_doubles_the_wait():
    h = make()
    await fail(h, 5)
    h.vt.advance(5.0)
    h.fake.fail_next(FailureKind.UNAVAILABLE)
    probe = await timed(h)
    assert probe.result.kind is FailureKind.UNAVAILABLE and probe.degraded is True
    assert probe.retry_after_ms == 10_000  # the next probe, twice the first wait
    waits = []
    for _ in range(5):
        h.vt.advance(h.gateway.degraded_status()["next_probe_in_s"])
        h.fake.fail_next(FailureKind.UNAVAILABLE)
        waits.append((await timed(h)).retry_after_ms)
    assert waits == [10_000, 10_000, 10_000, 10_000, 10_000]  # 20, 40, 60, 60, 60 s, clamped
    assert h.gateway.provider_degraded()


async def test_only_one_check_is_the_probe_and_the_others_keep_failing_fast():
    h = make()
    await fail(h, 5)
    h.vt.advance(5.0)
    h.model.slow_next(1.0)  # the probe takes a while
    results = await asyncio.gather(*[timed(h) for _ in range(5)])
    assert sum(is_degraded(r.result) for r in results) == 4
    assert sum(r.timing.provider_calls for r in results) == 1


async def test_a_retry_of_the_check_that_opened_it_is_not_sent():
    h = Harness(GatewayConfig(degraded_consecutive=2), health=True)  # retries allowed
    h.fake.fail_next(FailureKind.UNAVAILABLE, 4)
    first = await timed(h)  # call 1 fails, its retry (call 2) is the second in a row
    assert first.result.kind is FailureKind.UNAVAILABLE
    assert h.gateway.provider_degraded()
    started = h.model.started
    second = await timed(h)
    assert is_degraded(second.result) and h.model.started == started


async def test_the_auth_breaker_comes_first():
    h = make()
    await fail(h, 5)
    h.gateway._open["key-v1"] = type(
        "B", (), {"next_probe_at": h.vt.now() + 30, "delay": 5.0, "reason": "API_KEY_INVALID"}
    )()
    result = await h.decide()
    assert result.kind is FailureKind.AUTH


async def test_a_replaced_key_starts_clean():
    h = make()
    await fail(h, 5)
    h.key = "key-v2"
    assert not h.gateway.provider_degraded()
    result = await timed(h)
    assert not isinstance(result.result, Failed)


# ------------------------------------------------------------------------ the operator's hold


async def test_an_operators_hold_fails_every_check_with_no_probe_until_it_is_lifted():
    h = make()
    assert h.gateway.force_degraded(True) is True
    assert h.gateway.force_degraded(True) is False  # already held
    h.vt.advance(3600.0)  # no probe however long it is
    started = h.model.started
    held = await timed(h)
    assert is_degraded(held.result) and held.degraded and held.retry_after_ms is None
    assert h.model.started == started
    assert [a.reason for a in h.alerts.pages() if a.kind == ALERT_PROVIDER_DEGRADED] == ["operator"]
    assert h.gateway.force_degraded(False) is True
    assert not h.gateway.provider_degraded()
    assert not isinstance((await timed(h)).result, Failed)
    assert [a.reason for a in h.alerts.alerts if a.kind == ALERT_PROVIDER_RECOVERED] == ["operator"]


async def test_lifting_the_hold_also_clears_a_breaker_the_gateway_opened():
    h = make()
    await fail(h, 5)
    assert h.gateway.force_degraded(False) is True
    assert not h.gateway.provider_degraded()


async def test_the_status_says_how_it_opened_and_when_the_next_probe_is():
    h = make()
    assert h.gateway.degraded_status() == {
        "degraded": False, "forced": False, "cause": None, "next_probe_in_s": None,
    }  # fmt: skip
    await fail(h, 5)
    h.vt.advance(2.0)
    status = h.gateway.degraded_status()
    assert status["degraded"] and status["cause"] == "consecutive_failures"
    assert status["next_probe_in_s"] == pytest.approx(3.0)
    h.gateway.force_degraded(True)
    assert h.gateway.degraded_status()["cause"] == "operator"
    assert h.gateway.degraded_status()["next_probe_in_s"] is None


# ------------------------------------------------------------------------ healthy but slow


SLOW_BUT_ANSWERING = 0.83  # above the expected p50 (0.63 s), under the attempt deadline (1.03 s)


async def test_a_provider_slower_than_its_p50_but_inside_the_attempt_deadline_never_trips_it():
    h = Harness(GatewayConfig(), health=True)
    h.model.slow_next(*[SLOW_BUT_ANSWERING] * 12)
    for _ in range(12):
        assert not isinstance(await h.decide(), Failed)
    assert not h.gateway.provider_degraded()


async def test_a_tight_fixed_budget_cuts_healthy_calls_without_tripping_it():
    h = Harness(GatewayConfig(budgets_s={"output": 0.8}), health=True)
    h.model.slow_next(*[SLOW_BUT_ANSWERING] * 10)
    for _ in range(10):
        assert (await h.decide()).kind is FailureKind.TIMEOUT  # cut at 0.8 s: its own budget
    assert not h.gateway.provider_degraded()
    other = await timed(h)  # and a check at another guard point still calls the provider
    assert not isinstance(other.result, Failed) and other.timing.provider_calls == 1


async def test_a_copy_that_waited_and_has_little_budget_left_cannot_trip_it():
    h = Harness(GatewayConfig(), health=True)
    h.model.slow_next(*[SLOW_BUT_ANSWERING] * 10)
    for _ in range(10):
        result = await h.gateway.decide_timed(
            tenant_id="t_a",
            guard_point="output",
            input="Move your savings into the Growth Fund.",
            questions=QUESTIONS,
            max_budget_s=0.678,
        )
        assert result.result.kind is FailureKind.TIMEOUT
    await h.gateway.drain()
    assert not h.gateway.provider_degraded()


# ------------------------------------------------------------------------ one tenant


async def decide_as(h: Harness, tenant: str):
    result = await h.gateway.decide(
        tenant_id=tenant,
        guard_point="output",
        input="Move your savings into the Growth Fund.",
        questions=QUESTIONS,
    )
    await h.gateway.drain()
    return result


async def test_one_noisy_tenant_alone_on_a_busy_key_does_not_trip_it():
    h = make()
    for _ in range(6):  # another tenant's healthy calls are on the key all the time
        await decide_as(h, "t_other")
        h.fake.fail_next(FailureKind.UNAVAILABLE, 5)
        for _ in range(5):
            await decide_as(h, "t_noisy")  # five in a row for the key's failing tenant
        await decide_as(h, "t_other")
    assert not h.gateway.provider_degraded()


async def test_failures_from_two_tenants_trip_it():
    h = make()
    await decide_as(h, "t_other")  # both tenants have called within the window
    h.fake.fail_next(FailureKind.UNAVAILABLE, 5)
    for tenant in ("t_noisy", "t_other", "t_noisy", "t_other", "t_noisy"):
        await decide_as(h, tenant)
    assert h.gateway.provider_degraded()


async def test_a_single_tenant_on_a_quiet_key_still_trips_it():
    h = make()
    h.fake.fail_next(FailureKind.UNAVAILABLE, 5)
    for _ in range(5):
        await decide_as(h, "t_only")
    assert h.gateway.provider_degraded()


# ------------------------------------------------------------------------ a cancelled probe


async def test_a_cancelled_probe_gives_back_the_wait_it_doubled():
    h = make()
    await fail(h, 5)
    h.vt.advance(5.0)
    never = asyncio.Event()  # real time, not the virtual clock: the probe's call hangs

    async def hang(input, questions):
        await never.wait()

    h.model.decide = hang
    probe = asyncio.ensure_future(h.decide())
    for _ in range(3):  # a few turns: the probe is claimed and its call is waiting, and the
        await asyncio.sleep(0)  # virtual clock hasn't yet jumped to the end of its budget
    assert h.gateway._degraded["key-v1"].delay == 10.0  # claimed: doubled
    probe.cancel()
    with pytest.raises(asyncio.CancelledError):
        await probe
    assert h.gateway._degraded["key-v1"].delay == 5.0  # the provider told us nothing
    assert h.gateway.degraded_status()["next_probe_in_s"] == pytest.approx(5.0)
