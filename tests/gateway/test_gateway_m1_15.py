"""M1-15 in the Decision Gateway: the R6.3 queue allowance in admission, the R8 retry hint
and capacity signal, the in-flight count at check start, and the minor fixes on
unrecognised provider errors (throttled warning, bounded labels).

Everything runs on the virtual clock from ``test_gateway`` (no real sleeps): the gateway's
clock and sleep are injected, and the model's latency is spent on the same clock. The
budget table itself (R6.3's worst cases) is in ``test_gateway.TestComputedBudget``.
"""

import asyncio
import logging
from collections import deque

import pytest
from test_gateway import (  # noqa: F401  (close_gateways is an autouse fixture)
    BUDGET,
    INPUT,
    ONE_ATTEMPT,
    QUESTIONS,
    ROOMY_QUEUE,
    T0,
    Harness,
    ImmortalModel,
    VirtualTime,
    admission_failure,
    close_gateways,
    failed,
    questions,
    tokens_of_input,
)

from guardrail_engine.decision import Answered, Failed, FailureKind, FakeDecisionModel
from guardrail_engine.gateway import (
    CAPACITY_REASONS,
    FALLBACK_RETRY_AFTER_MS,
    MAX_UNRECOGNISED_CODE_LABELS,
    REASON_ADMISSION_QUEUE_FULL,
    REASON_ADMISSION_WAIT,
    REASON_ORPHAN_CAP,
    RETRY_AFTER_MAX_MS,
    RETRY_AFTER_MIN_MS,
    UNRECOGNISED_CODE_OVERFLOW,
    DecisionGateway,
    GatewayConfig,
    TimedDecision,
)

GATEWAY_LOGGER = "guardrail_engine.gateway.gateway"


@pytest.fixture
async def immortal():
    model = ImmortalModel()
    yield model
    await model.release()  # or the event loop could never shut down


class ScriptedModel:
    """A model on virtual time whose calls follow a script **in the order they start**:
    each entry is ``(latency, outcome)``; ``None`` as the outcome means answered. After the
    script, calls answer after ``latency_s``."""

    model_id = "scripted-virtual"

    def __init__(self, vt: VirtualTime, *script, latency_s: float = 0.0) -> None:
        self.vt = vt
        self.fake = FakeDecisionModel()
        self.script = deque(script)
        self.latency_s = latency_s
        self.inputs: list[str] = []

    async def decide(self, input, questions):
        self.inputs.append(input)
        latency, outcome = self.script.popleft() if self.script else (self.latency_s, None)
        if latency > 0:
            await self.vt.sleep(latency)
        if outcome is not None:
            return outcome
        return await self.fake.decide(input, questions)


def gateway_on(vt: VirtualTime, model, config: GatewayConfig | None = None, **kwargs):
    return DecisionGateway(model, config=config, clock=vt.now, sleep=vt.sleep, **kwargs)


async def timed(gateway, guard_point="output", input=INPUT, tenant_id="t_a") -> TimedDecision:
    return await gateway.decide_timed(
        tenant_id=tenant_id, guard_point=guard_point, input=input, questions=QUESTIONS
    )


def elapsed(vt: VirtualTime) -> float:
    return vt.now_s - T0


# ---------------------------------------------------------------------------- queue allowance


class TestQueueAllowance:
    """R6.3, M1-15: "a check may wait in admission up to its guard point's allowance. The
    predicted-wait check uses the same figure." Defaults: 100 ms on output, 300 ms on input,
    400 ms on tool_result."""

    async def test_a_prediction_over_the_allowance_fails_fast_even_when_the_budget_fits(self):
        # One slot, held by a hanging call. A 250 ms expected call predicts 250 ms of wait:
        # 250 + 250 fits the 1,128 ms budget, but 250 > the 100 ms output allowance.
        vt = VirtualTime()
        model = ScriptedModel(vt, (5.0, None))
        gateway = gateway_on(
            vt,
            model,
            GatewayConfig(max_in_flight_per_key=1, expected_latency_s=0.25, **ONE_ATTEMPT),
        )
        holder = asyncio.ensure_future(timed(gateway))
        await asyncio.sleep(0)
        refused = await timed(gateway)
        result = admission_failure(refused.result, REASON_ADMISSION_WAIT)
        assert "predicted queue wait 250 ms exceeds the remaining queue allowance 100 ms" in (
            result.message
        )
        assert elapsed(vt) == 0  # failed fast
        assert refused.timing.provider_calls == 0
        assert refused.timing.queue_wait_ms == 0
        failed((await holder).result, FailureKind.TIMEOUT)
        assert model.inputs == [INPUT]  # the refused check sent nothing

    @pytest.mark.parametrize(
        ("guard_point", "allowance", "queued"),
        [("output", 0.1, False), ("plan", 0.1, False), ("tool_call", 0.1, False),
         ("input", 0.3, True), ("tool_result", 0.4, True)],
    )  # fmt: skip
    async def test_the_allowance_is_the_guard_points(self, guard_point, allowance, queued):
        # A 250 ms wait fits input's 300 ms and tool_result's 400 ms, not the 100 ms of the
        # critical path. Where it fits, the check queues and is served when the slot frees.
        vt = VirtualTime()
        model = ScriptedModel(vt, (0.25, None), latency_s=0.1)
        config = GatewayConfig(max_in_flight_per_key=1, expected_latency_s=0.25, **ONE_ATTEMPT)
        gateway = gateway_on(vt, model, config)
        holder = asyncio.ensure_future(timed(gateway, guard_point="input"))
        await asyncio.sleep(0)
        second = await timed(gateway, guard_point=guard_point)
        assert isinstance((await holder).result, Answered)
        assert config.queue_wait_for(guard_point) == allowance
        if queued:
            assert isinstance(second.result, Answered)
            assert second.timing.queue_wait_ms == pytest.approx(250)
        else:
            admission_failure(second.result, REASON_ADMISSION_WAIT)
            assert second.timing.provider_calls == 0

    async def test_a_waiter_leaves_the_queue_when_its_allowance_runs_out(self):
        # A 50 ms expected call predicts 50 ms of wait and queues, but the holder hangs. At
        # 100 ms (the output allowance; the 1,128 ms budget is far off) it leaves the queue
        # with no provider call.
        vt = VirtualTime()
        model = ScriptedModel(vt, (5.0, None))
        gateway = gateway_on(
            vt,
            model,
            GatewayConfig(max_in_flight_per_key=1, expected_latency_s=0.05, **ONE_ATTEMPT),
        )
        holder = asyncio.ensure_future(timed(gateway))
        await asyncio.sleep(0)
        waiter = await timed(gateway)
        result = admission_failure(waiter.result, REASON_ADMISSION_WAIT)
        assert "queue allowance ran out while queued" in result.message
        assert elapsed(vt) == pytest.approx(0.1)
        assert waiter.timing.queue_wait_ms == pytest.approx(100)
        assert waiter.timing.provider_calls == 0
        assert gateway.queued() == 0
        failed((await holder).result, FailureKind.TIMEOUT)
        assert model.inputs == [INPUT]

    async def test_the_allowance_is_shared_by_the_first_attempt_and_the_retry(self):
        # One slot, a 50 ms expected call, 100 ms of allowance. b queues behind a for 60 ms,
        # then its own call fails (unavailable) at 70 ms. Meanwhile c has queued and takes
        # the slot (it hangs). b's retry predicts 50 ms of wait, more than the 40 ms of
        # allowance b has left, so it is refused at once and b keeps its first result.
        # With 200 ms of allowance the same retry queues until its allowance runs out.
        for allowance, b_ends_at in [(0.1, 0.07), (0.2, 0.07 + (0.2 - 0.06))]:
            vt = VirtualTime()
            model = ScriptedModel(
                vt,
                (0.06, None),  # a
                (0.01, Failed(kind=FailureKind.UNAVAILABLE)),  # b's first attempt
                (5.0, None),  # c
            )
            config = GatewayConfig(
                max_in_flight_per_key=1,
                expected_latency_s=0.05,
                queue_waits_s={"output": allowance},
                **ONE_ATTEMPT,
            )
            gateway = gateway_on(vt, model, config, rng=lambda: 0.0)
            a = asyncio.ensure_future(timed(gateway, input="a"))
            await asyncio.sleep(0)
            b = asyncio.ensure_future(timed(gateway, input="b"))
            await vt.sleep(0.065)
            c = asyncio.ensure_future(timed(gateway, input="c"))
            b_done = await b
            assert b_done.result == Failed(kind=FailureKind.UNAVAILABLE), allowance
            assert b_done.timing.provider_calls == 1
            assert elapsed(vt) == pytest.approx(b_ends_at), allowance
            assert b_done.timing.queue_wait_ms == pytest.approx((b_ends_at - 0.07 + 0.06) * 1000)
            assert isinstance((await a).result, Answered)
            failed((await c).result, FailureKind.TIMEOUT)
            assert model.inputs == ["a", "b", "c"]  # b's retry was never sent

    async def test_a_max_size_input_check_waits_at_most_its_300ms_allowance(self):
        # R6.3 after U7: the largest input check (16K, 200 questions) keeps its full 300 ms
        # of queue allowance under the 4,000 ms cap. Behind four calls just started, the
        # predicted wait (628 ms) is more, so it fails fast.
        h = Harness()
        h.model.latency_s = 5.0
        hung = [asyncio.ensure_future(h.decide(guard_point="output")) for _ in range(4)]
        await asyncio.sleep(0)
        big = await h.gateway.decide_timed(
            tenant_id="t_x", guard_point="input", input=tokens_of_input(16_000),
            questions=questions(200),
        )  # fmt: skip
        result = admission_failure(big.result, REASON_ADMISSION_WAIT)
        assert "predicted queue wait 628 ms exceeds the remaining queue allowance 300 ms" in (
            result.message
        )
        assert h.elapsed == 0
        for task in hung:
            failed(await task, FailureKind.TIMEOUT)


# ---------------------------------------------------------------------------- R8


class TestRetryHint:
    """R8 (delivered by M1-15): ``retry_after_ms`` when the gateway refuses or fails a check
    for a reason it can time, clamped to 100-10,000 ms, and absent otherwise; and
    ``capacity_limited`` for the gateway's own capacity refusals."""

    def test_r8_constants(self):
        assert (RETRY_AFTER_MIN_MS, RETRY_AFTER_MAX_MS, FALLBACK_RETRY_AFTER_MS) == (
            100,
            10_000,
            1_000,
        )
        assert {
            "admission_wait",
            "admission_queue_full",
            "orphan_cap",
            "token_rate",  # M3-10
            "quota_exhausted",  # M3-10
        } == CAPACITY_REASONS

    @pytest.mark.parametrize(("arrives_at", "hint"), [(0.0, 250), (0.1, 150), (0.24, 100)])
    async def test_admission_wait_hint_is_the_predicted_wait(self, arrives_at, hint):
        # One slot, held by a call expected to take 250 ms. The hint is the same prediction
        # admission used: the holder's remaining expected time (clamped up to 100 ms).
        vt = VirtualTime()
        model = ScriptedModel(vt, (5.0, None))
        gateway = gateway_on(
            vt,
            model,
            GatewayConfig(max_in_flight_per_key=1, expected_latency_s=0.25, **ONE_ATTEMPT),
        )
        holder = asyncio.ensure_future(timed(gateway))
        await asyncio.sleep(0)
        if arrives_at:
            await vt.sleep(arrives_at)
        refused = await timed(gateway)
        admission_failure(refused.result, REASON_ADMISSION_WAIT)
        assert refused.retry_after_ms == hint
        assert refused.capacity_limited is True
        holder_done = await holder
        failed(holder_done.result, FailureKind.TIMEOUT)
        assert (holder_done.retry_after_ms, holder_done.capacity_limited) == (None, False)

    async def test_a_waiter_removed_from_the_queue_gets_the_prediction_at_that_moment(self):
        # Queued at 0 behind a call expected to take 50 ms; removed at 100 ms, when the holder
        # is past its expected time and charged the 10% floor (5 ms): clamped up to 100 ms.
        vt = VirtualTime()
        model = ScriptedModel(vt, (5.0, None))
        gateway = gateway_on(
            vt,
            model,
            GatewayConfig(max_in_flight_per_key=1, expected_latency_s=0.05, **ONE_ATTEMPT),
        )
        holder = asyncio.ensure_future(timed(gateway))
        await asyncio.sleep(0)
        waiter = await timed(gateway)
        admission_failure(waiter.result, REASON_ADMISSION_WAIT)
        assert (waiter.retry_after_ms, waiter.capacity_limited) == (RETRY_AFTER_MIN_MS, True)
        await holder

    async def test_admission_queue_full_hint_is_the_wait_behind_the_whole_queue(self):
        # One slot (250 ms expected) and one queued call (250 ms): a third check would wait
        # (250 + 250) / 1 = 500 ms.
        vt = VirtualTime()
        model = ScriptedModel(vt, (5.0, None))
        config = GatewayConfig(
            max_in_flight_per_key=1,
            max_queued_per_key=1,
            expected_latency_s=0.25,
            queue_waits_s=ROOMY_QUEUE,
        )
        gateway = gateway_on(vt, model, config)
        holder = asyncio.ensure_future(timed(gateway))
        await asyncio.sleep(0)
        queued = asyncio.ensure_future(timed(gateway))
        await asyncio.sleep(0)
        assert gateway.queued() == 1
        refused = await timed(gateway)
        admission_failure(refused.result, REASON_ADMISSION_QUEUE_FULL)
        assert (refused.retry_after_ms, refused.capacity_limited) == (500, True)
        await asyncio.gather(holder, queued)

    async def test_orphan_cap_hint_is_1000ms(self, immortal):
        vt = VirtualTime()
        gateway = gateway_on(
            vt, immortal, GatewayConfig(max_orphans=1, max_in_flight_per_key=64, **ONE_ATTEMPT)
        )
        failed((await timed(gateway)).result, FailureKind.TIMEOUT)  # one orphan: the cap
        assert gateway.orphan_capped
        capped = await timed(gateway)
        assert failed(capped.result, FailureKind.UNAVAILABLE).reason == REASON_ORPHAN_CAP
        assert (capped.retry_after_ms, capped.capacity_limited) == (1_000, True)

    async def test_orphans_in_every_slot_get_the_1000ms_fallback_hint(self, immortal):
        # The prediction is infinite. Decided on the M1-15 build: every capacity refusal carries
        # a hint, so the 1,000 ms fallback (as for orphan_cap).
        vt = VirtualTime()
        gateway = gateway_on(vt, immortal, GatewayConfig(max_in_flight_per_key=1, **ONE_ATTEMPT))
        failed((await timed(gateway)).result, FailureKind.TIMEOUT)
        stalled = await timed(gateway)
        admission_failure(stalled.result, REASON_ADMISSION_WAIT)
        assert (stalled.retry_after_ms, stalled.capacity_limited) == (FALLBACK_RETRY_AFTER_MS, True)

    async def test_auth_hint_is_the_time_until_the_next_probe(self):
        h = Harness()
        h.fake.push(Failed(kind=FailureKind.AUTH, reason="API_KEY_INVALID"))
        opened = await h.gateway.decide_timed(
            tenant_id="t_x", guard_point="output", input=INPUT, questions=QUESTIONS
        )
        failed(opened.result, FailureKind.AUTH)
        assert (opened.retry_after_ms, opened.capacity_limited) == (5_000, False)
        h.vt.advance(2.0)
        fast = await h.gateway.decide_timed(
            tenant_id="t_x", guard_point="output", input=INPUT, questions=QUESTIONS
        )
        failed(fast.result, FailureKind.AUTH)
        assert (fast.retry_after_ms, fast.capacity_limited) == (3_000, False)
        assert fast.timing.provider_calls == 0
        # A failed probe doubles the wait: the hint follows the schedule.
        h.vt.advance(3.0)
        h.fake.push(Failed(kind=FailureKind.AUTH, reason="API_KEY_INVALID"))
        probe = await h.gateway.decide_timed(
            tenant_id="t_x", guard_point="output", input=INPUT, questions=QUESTIONS
        )
        failed(probe.result, FailureKind.AUTH)
        assert probe.retry_after_ms == 10_000

    async def test_auth_hint_is_clamped_to_10s(self):
        h = Harness(GatewayConfig(probe_initial_delay_s=60.0))
        await h.open_breaker()
        fast = await h.gateway.decide_timed(
            tenant_id="t_x", guard_point="output", input=INPUT, questions=QUESTIONS
        )
        assert fast.retry_after_ms == RETRY_AFTER_MAX_MS

    async def test_auth_on_a_replaced_key_gives_no_hint(self):
        h = Harness()
        h.model.latency_s = 0.1
        h.fake.push(Failed(kind=FailureKind.AUTH, reason="API_KEY_INVALID"))
        task = asyncio.ensure_future(
            h.gateway.decide_timed(
                tenant_id="t_x", guard_point="output", input=INPUT, questions=QUESTIONS
            )
        )
        await h.vt.sleep(0.05)
        h.key = "key-v2"
        late = await task
        failed(late.result, FailureKind.AUTH)
        assert (late.retry_after_ms, late.capacity_limited) == (None, False)

    @pytest.mark.parametrize(
        "outcome",
        [
            Failed(kind=FailureKind.TIMEOUT),
            Failed(kind=FailureKind.UNAVAILABLE),
            Failed(kind=FailureKind.OTHER),
            Failed(kind=FailureKind.RATE_LIMITED),
            Failed(kind=FailureKind.LIMIT_EXCEEDED),
            # A provider whose reason spells a gateway refusal is still a provider failure.
            Failed(kind=FailureKind.UNAVAILABLE, reason="admission_wait"),
            Failed(kind=FailureKind.UNAVAILABLE, reason="orphan_cap"),
            Failed(kind=FailureKind.OTHER, reason="admission_queue_full"),
        ],
        ids=["timeout", "unavailable", "other", "rate_limited", "limit_exceeded",
             "spoofed_admission_wait", "spoofed_orphan_cap", "spoofed_queue_full"],
    )  # fmt: skip
    async def test_no_hint_for_what_the_gateway_cant_time_or_didnt_refuse(self, outcome):
        h = Harness()
        h.fake.always(outcome)
        result = await h.gateway.decide_timed(
            tenant_id="t_x", guard_point="output", input=INPUT, questions=QUESTIONS
        )
        assert isinstance(result.result, Failed)
        assert (result.retry_after_ms, result.capacity_limited) == (None, False)
        assert result.timing.provider_calls >= 1

    @pytest.mark.parametrize(
        ("delay_s", "hint"),
        [(2.5, 2_500), (0.0, 100), (0.0004, 100), (60.0, 10_000), (1e12, 10_000), (None, None)],
    )
    async def test_a_provider_429_passes_its_retry_info_delay_through_clamped(self, delay_s, hint):
        # Decided on the M1-15 build: the provider's RetryInfo delay, clamped to 100-10,000 ms;
        # no delay, no hint. The provider refused, not the gateway: never capacity_limited.
        h = Harness()
        h.fake.always(Failed(kind=FailureKind.RATE_LIMITED, retry_delay_s=delay_s))
        result = await h.gateway.decide_timed(
            tenant_id="t_x", guard_point="output", input=INPUT, questions=QUESTIONS
        )
        assert failed(result.result, FailureKind.RATE_LIMITED)
        assert (result.retry_after_ms, result.capacity_limited) == (hint, False)
        assert result.timing.provider_calls == 1  # rate_limited is never retried

    async def test_a_retry_delay_on_any_other_failure_is_ignored(self):
        # Only RATE_LIMITED carries the provider's delay through.
        h = Harness()
        h.fake.always(Failed(kind=FailureKind.UNAVAILABLE, retry_delay_s=2.0))
        result = await h.gateway.decide_timed(
            tenant_id="t_x", guard_point="output", input=INPUT, questions=QUESTIONS
        )
        assert (result.retry_after_ms, result.capacity_limited) == (None, False)

    async def test_a_deadline_timeout_gives_no_hint(self):
        h = Harness()
        h.model.latency_s = 5.0
        result = await h.gateway.decide_timed(
            tenant_id="t_x", guard_point="output", input=INPUT, questions=QUESTIONS
        )
        failed(result.result, FailureKind.TIMEOUT)
        assert h.elapsed == pytest.approx(BUDGET)
        assert (result.retry_after_ms, result.capacity_limited) == (None, False)

    async def test_an_answer_has_no_hint(self):
        h = Harness()
        result = await h.gateway.decide_timed(
            tenant_id="t_x", guard_point="output", input=INPUT, questions=QUESTIONS
        )
        assert isinstance(result.result, Answered)
        assert (result.retry_after_ms, result.capacity_limited) == (None, False)

    async def test_a_retry_refused_by_admission_keeps_the_first_result_and_no_hint(self):
        # The first attempt's provider failure stands; the refusal of the retry isn't what
        # the caller gets, so neither is a hint or the capacity flag.
        vt = VirtualTime()
        model = ScriptedModel(vt, (0.1, Failed(kind=FailureKind.UNAVAILABLE)), (5.0, None))
        config = GatewayConfig(
            max_in_flight_per_key=1, default_budget_s=0.55, expected_latency_s=0.25,
            queue_waits_s=ROOMY_QUEUE,
        )  # fmt: skip
        gateway = gateway_on(vt, model, config, rng=lambda: 0.0)
        a = asyncio.ensure_future(timed(gateway, input="a"))
        await vt.sleep(0.05)
        b = asyncio.ensure_future(timed(gateway, input="b"))
        a_done = await a
        assert a_done.result == Failed(kind=FailureKind.UNAVAILABLE)
        assert (a_done.retry_after_ms, a_done.capacity_limited) == (None, False)
        await b


# ---------------------------------------------------------------------------- in flight


class TestInFlightAtStart:
    """M1-15: each check records the calls in flight on its key when it reached the gateway,
    before any admission wait or fast failure (orphans included, queued calls not)."""

    async def test_counts_the_calls_in_flight_on_arrival(self):
        h = Harness()
        h.model.latency_s = 0.5
        tasks = []
        for _ in range(3):
            tasks.append(
                asyncio.ensure_future(
                    h.gateway.decide_timed(
                        tenant_id="t_x", guard_point="output", input=INPUT, questions=QUESTIONS
                    )
                )
            )
            await asyncio.sleep(0)
        results = await asyncio.gather(*tasks)
        assert [r.timing.in_flight_at_start for r in results] == [0, 1, 2]
        after = await h.gateway.decide_timed(
            tenant_id="t_x", guard_point="output", input=INPUT, questions=QUESTIONS
        )
        assert after.timing.in_flight_at_start == 0

    async def test_is_taken_before_the_admission_wait_and_excludes_queued_calls(self):
        # One slot. a runs; b queues (it starts later, but arrived with 1 in flight); c
        # arrives while a runs and b waits: 1 in flight, not 2.
        vt = VirtualTime()
        model = ScriptedModel(vt, (0.05, None), (0.05, None))
        config = GatewayConfig(
            max_in_flight_per_key=1, expected_latency_s=0.05, max_queued_per_key=1
        )
        gateway = gateway_on(vt, model, config)
        a = asyncio.ensure_future(timed(gateway))
        await asyncio.sleep(0)
        b = asyncio.ensure_future(timed(gateway))
        await asyncio.sleep(0)
        assert (gateway.in_flight(), gateway.queued()) == (1, 1)
        c = await timed(gateway)
        admission_failure(c.result, REASON_ADMISSION_QUEUE_FULL)
        a, b = await asyncio.gather(a, b)
        assert isinstance(b.result, Answered) and b.timing.queue_wait_ms == pytest.approx(50)
        assert (a.timing.in_flight_at_start, b.timing.in_flight_at_start) == (0, 1)
        assert c.timing.in_flight_at_start == 1

    async def test_includes_orphans_and_is_recorded_on_fast_failures(self, immortal):
        vt = VirtualTime()
        gateway = gateway_on(
            vt, immortal, GatewayConfig(max_orphans=2, max_in_flight_per_key=8, **ONE_ATTEMPT)
        )
        for expected in (0, 1):
            first = await timed(gateway)
            failed(first.result, FailureKind.TIMEOUT)
            assert first.timing.in_flight_at_start == expected
        assert gateway.orphan_capped
        capped = await timed(gateway)
        assert capped.result.reason == REASON_ORPHAN_CAP
        assert capped.timing.in_flight_at_start == 2  # both orphans still hold their slots

    async def test_is_per_key(self):
        h = Harness()
        h.model.latency_s = 0.5
        task = asyncio.ensure_future(h.decide())
        await asyncio.sleep(0)
        h.key = "key-v2"
        other = await h.gateway.decide_timed(
            tenant_id="t_x", guard_point="output", input=INPUT, questions=QUESTIONS
        )
        assert other.timing.in_flight_at_start == 0
        await task

    async def test_unknown_when_the_key_cant_be_read(self):
        def key_id():
            raise RuntimeError("secret store down")

        gateway = DecisionGateway(FakeDecisionModel(), key_id=key_id)
        result = await timed(gateway)
        failed(result.result, FailureKind.OTHER)
        assert result.timing.in_flight_at_start is None


# ---------------------------------------------------------------------------- R19 minors


def unrecognised(code) -> Failed:
    return Failed(kind=FailureKind.OTHER, message="provider text", unrecognised_code=code)


def unrecognised_lines(caplog) -> list[str]:
    return [
        r.getMessage()
        for r in caplog.records
        if r.name == GATEWAY_LOGGER and r.getMessage().startswith("provider_error_unrecognised")
    ]


class TestUnrecognisedProviderErrors:
    async def test_the_warning_is_throttled_per_label_and_every_occurrence_is_metered(self, caplog):
        caplog.set_level(logging.WARNING, logger=GATEWAY_LOGGER)
        h = Harness(GatewayConfig(warning_interval_s=60.0))
        h.fake.always(unrecognised("brand_new"))
        for _ in range(5):
            await h.decide(tenant_id="t_x", guard_point="output")
        assert h.meter.provider_errors_unrecognised("t_x", "output", "brand_new") == 5
        assert unrecognised_lines(caplog) == [
            "provider_error_unrecognised code=brand_new tenant=t_x guard_point=output suppressed=0"
        ]
        h.vt.advance(60.0)  # the interval has passed: the next line reports the 4 suppressed
        await h.decide(tenant_id="t_x", guard_point="output")
        assert unrecognised_lines(caplog)[-1] == (
            "provider_error_unrecognised code=brand_new tenant=t_x guard_point=output suppressed=4"
        )
        assert h.meter.provider_errors_unrecognised("t_x", "output", "brand_new") == 6

    async def test_each_label_tenant_and_guard_point_has_its_own_throttle(self, caplog):
        caplog.set_level(logging.WARNING, logger=GATEWAY_LOGGER)
        h = Harness(GatewayConfig(warning_interval_s=60.0))
        for code, tenant, point in [
            ("code_a", "t_1", "output"),
            ("code_a", "t_1", "output"),  # suppressed
            ("code_b", "t_1", "output"),  # another label
            ("code_a", "t_2", "output"),  # another tenant
            ("code_a", "t_1", "input"),  # another guard point
            ("_no_code", "t_1", "output"),  # a placeholder is a label like any other
            ("_no_code", "t_1", "output"),  # suppressed
        ]:
            h.fake.push(unrecognised(code))
            await h.decide(tenant_id=tenant, guard_point=point)
        assert len(unrecognised_lines(caplog)) == 5
        assert h.meter.provider_errors_unrecognised("t_1") == 6
        assert h.meter.provider_errors_unrecognised("t_2") == 1

    async def test_a_zero_interval_logs_every_one(self, caplog):
        caplog.set_level(logging.WARNING, logger=GATEWAY_LOGGER)
        h = Harness(GatewayConfig(warning_interval_s=0))
        h.fake.always(unrecognised("brand_new"))
        for _ in range(3):
            await h.decide()
        assert len(unrecognised_lines(caplog)) == 3

    async def test_case_variants_share_one_label_and_one_place_under_the_cap(self):
        h = Harness()
        for code in ("Brand_New", "BRAND_NEW", "brand_new"):
            h.fake.push(unrecognised(code))
            await h.decide()
        assert h.meter.unrecognised_codes() == {"brand_new"}
        assert h.meter.provider_errors_unrecognised("t_a", code="brand_new") == 3
        assert h.gateway._unrecognised_labels == {"brand_new"}

    async def test_the_placeholders_never_overflow_and_take_no_place_under_the_cap(self):
        h = Harness(GatewayConfig(warning_interval_s=0))
        for i in range(MAX_UNRECOGNISED_CODE_LABELS + 1):
            h.fake.push(unrecognised(f"code_{i}"))
            await h.decide()
        for placeholder in ("_no_code", "_not_json", "_malformed"):
            h.fake.push(unrecognised(placeholder))
            await h.decide()
        labels = h.meter.unrecognised_codes()
        assert {"_no_code", "_not_json", "_malformed", UNRECOGNISED_CODE_OVERFLOW} <= labels
        assert len(labels) == MAX_UNRECOGNISED_CODE_LABELS + 4
        assert h.meter.provider_errors_unrecognised("t_a", code=UNRECOGNISED_CODE_OVERFLOW) == 1

    async def test_a_label_bounded_twice_stays_in_its_bucket(self):
        """``Failed`` bounds the label, then the gateway bounds it again: idempotent, so no
        label moves to another bucket (a placeholder stays a placeholder, a valid label
        stays itself, a malformed one stays ``_malformed``)."""
        from guardrail_engine.decision import bounded_error_label, provider_error_label

        for raw in ("Brand_New", "ns:code.v2-x", "_no_code", "a" * 65, "ok_9", "\u017fecret"):
            once = provider_error_label(raw)
            assert bounded_error_label(once) == once
            assert bounded_error_label(bounded_error_label(once)) == once
        for placeholder in ("_no_code", "_not_json", "_malformed"):
            assert bounded_error_label(placeholder) == placeholder
        assert bounded_error_label("_overflow") == "_malformed"  # the gateway's own, not a model's
        assert bounded_error_label(None) is None
        h = Harness()
        h.fake.push(unrecognised("Brand_New"))
        result = await h.decide()
        assert result.unrecognised_code == "brand_new"
        assert h.meter.unrecognised_codes() == {"brand_new"}

    async def test_not_a_failure_shape_the_guard_service_records(self):
        """The metric label never becomes the verdict's ``failure_reason``: that is still the
        provider's ``reason`` through ``recorded_code`` (unchanged)."""
        h = Harness()
        h.fake.push(
            Failed(kind=FailureKind.OTHER, reason="FAILED_PRECONDITION", unrecognised_code="X:Y")
        )
        result = await h.decide()
        assert (result.reason, result.unrecognised_code) == ("FAILED_PRECONDITION", "_malformed")
