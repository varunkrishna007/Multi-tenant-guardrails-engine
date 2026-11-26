"""DecisionGateway: the M1-04 acceptance criteria.

Most tests run on virtual time: ``VirtualTime`` is injected as the gateway's clock and sleep,
and ``VirtualModel`` (a ``FakeDecisionModel`` whose latency runs on the same virtual clock)
is the model. They take no real time and are deterministic. The ``TestRealTime`` class uses
the fake's own scripted latency against the real clock.
"""

import ast
import asyncio
import gc
import heapq
import inspect
import logging
import threading
import time
from collections import deque
from dataclasses import replace

import pytest

from guardrail_engine.decision import (
    Answered,
    DecisionModel,
    Failed,
    FailureKind,
    FakeDecisionModel,
    NoulQuestion,
    SafetyBlocked,
)
from guardrail_engine.gateway import (
    ALERT_AUTH_FAILURE,
    ALERT_CANCEL_IGNORED,
    ALERT_KEY_SATURATED_BY_ORPHANS,
    ALERT_ORPHAN_CAP,
    ALERT_USAGE_UNKNOWN,
    DEFAULT_MAX_IN_FLIGHT_PER_KEY,
    DEFAULT_MAX_QUEUED_PER_KEY,
    FALLBACK_RETRY_AFTER_MS,
    REASON_ADMISSION_QUEUE_FULL,
    REASON_ADMISSION_WAIT,
    REASON_ORPHAN_CAP,
    AlertSeverity,
    AlertSink,
    CheckTiming,
    CheckTimingMeter,
    DecisionGateway,
    GatewayConfig,
    InFlightLimit,
    InMemoryUsageMeter,
    KeyLoad,
    NullAlertSink,
    RecordingAlertSink,
    UsageMeter,
)
from guardrail_engine.tokens import estimate_question_tokens, estimate_tokens

QUESTIONS = {
    "p__ai_addressed": NoulQuestion(instructions="Does the content address an AI system?"),
    "p__harm": NoulQuestion(instructions="Does the content help someone cause harm?"),
}
INPUT = "Move your savings into the Growth Fund."
INPUT_TOKENS = estimate_tokens(INPUT) + estimate_question_tokens(QUESTIONS)
T0 = 1024.0  # virtual start; binary-exact so sums with 0.25 / 0.5 are exact
# R6.3 after U7 (M1-15) for the standard check: INPUT is a few tokens (the band up to 1K,
# 244 ms), plus the 380 ms time-window allowance, plus 2 questions (2 x 2 ms): an expected p50
# of 628 ms. Its first call's attempt deadline is 628 + max(400, 0.6 x 628) = 1,028 ms. Its
# total budget is the output cap, 3,000 ms, of which up to 100 ms may be queue wait. A timeout
# or unavailable is retried if at least 628 ms are left.
EXPECTED_P50 = 0.244 + 0.380 + 2 * 0.002
ATTEMPT_DEADLINE = EXPECTED_P50 + 0.400
OUTPUT_QUEUE = 0.100
BUDGET = 3.000
# One attempt per check: an attempt-deadline margin so large that the first call always runs
# to the end of the budget and leaves no time for a retry. For tests of other mechanisms
# (orphans, cancellation, admission) written for one call per check.
ONE_ATTEMPT = {"budget_margin_s": 60.0, "degraded_consecutive": 0, "degraded_window_calls": 0}
# Real-time tests with budgets of a few tens of ms: a matching expected call, so the budget
# passes the startup check (more than the smallest call's expected p50).
TINY_CALL = {"expected_latency_s": 0.01}


class VirtualTime:
    """A clock that only moves when every task is waiting, and then jumps straight to the
    earliest pending ``sleep``."""

    SETTLE_YIELDS = 20

    def __init__(self, start: float = T0) -> None:
        self.now_s = start
        self.sleeps: list[float] = []
        self._sleepers: list[tuple[float, int, asyncio.Future]] = []
        self._seq = 0
        self._driver: asyncio.Task | None = None
        self.real_work_pending = lambda: False
        """True while a real thread (the gateway's drainer) still has work whose result a
        waiting task needs: virtual time must not jump past it."""

    def now(self) -> float:
        return self.now_s

    def advance(self, seconds: float) -> None:
        self.now_s += seconds

    async def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        future = asyncio.get_running_loop().create_future()
        self._seq += 1
        heapq.heappush(self._sleepers, (self.now_s + seconds, self._seq, future))
        if self._driver is None or self._driver.done():
            self._driver = asyncio.ensure_future(self._drive())
        await future

    async def _drive(self) -> None:
        while self._sleepers:
            # Let every runnable task reach its next wait. A sleep added meanwhile restarts
            # the count, so it too gets the full settling time: with the gateway's sinks in
            # a worker thread, a check can start at any point of an earlier settle.
            # Settled rounds in a row with no drainer-thread work. Two, so that a callback the
            # thread scheduled just as it finished has run before time moves.
            quiet = 0
            while quiet < 2:
                settled_at = None
                while settled_at != self._seq:
                    settled_at = self._seq
                    for _ in range(self.SETTLE_YIELDS):
                        await asyncio.sleep(0)
                if self.real_work_pending():
                    quiet = 0
                    await asyncio.sleep(0.0005)  # the drainer thread is delivering
                else:
                    quiet += 1
            while self._sleepers and self._sleepers[0][2].done():  # cancelled sleeps
                heapq.heappop(self._sleepers)
            if self._sleepers:
                wake_at, _, future = heapq.heappop(self._sleepers)
                self.now_s = max(self.now_s, wake_at)
                future.set_result(None)


class VirtualModel:
    """A ``FakeDecisionModel`` whose latency is spent on virtual time. ``started`` counts
    every call the gateway made, including ones it cancelled (the fake's own ``calls`` only
    holds completed calls)."""

    model_id = "virtual-fake"

    def __init__(self, vt: VirtualTime, latency_s: float = 0.0) -> None:
        self.vt = vt
        self.fake = FakeDecisionModel()
        self.latency_s = latency_s
        self._latencies: deque[float] = deque()
        self.started = 0
        self.cancelled = 0
        self.active = 0
        self.peak = 0
        """The most calls that were ever in progress at the model at once."""
        self.inputs: list[str] = []
        """The input of every call, in the order the calls started."""

    def slow_next(self, *seconds: float) -> None:
        self._latencies.extend(seconds)

    async def decide(self, input, questions):
        self.started += 1
        self.inputs.append(input)
        self.active += 1
        self.peak = max(self.peak, self.active)
        latency = self._latencies.popleft() if self._latencies else self.latency_s
        try:
            if latency > 0:
                await self.vt.sleep(latency)
            return await self.fake.decide(input, questions)
        except asyncio.CancelledError:
            self.cancelled += 1
            raise
        finally:
            self.active -= 1


class Harness:
    def __init__(
        self,
        config: GatewayConfig | None = None,
        *,
        rng=lambda: 0.0,
        health: bool = False,
        **kwargs,
    ) -> None:
        # The provider-health breaker (M7-11) is off unless a test asks for it: many tests here
        # make runs of failing calls on purpose and are not about it.
        if not health:
            config = replace(
                config or GatewayConfig(), degraded_consecutive=0, degraded_window_calls=0
            )
        self.vt = VirtualTime()
        self.model = VirtualModel(self.vt)
        self.fake = self.model.fake
        self.meter = InMemoryUsageMeter()
        self.alerts = RecordingAlertSink()
        self.key = "key-v1"
        self.gateway = DecisionGateway(
            self.model,
            config=config,
            meter=self.meter,
            alerts=self.alerts,
            key_id=lambda: self.key,
            clock=self.vt.now,
            sleep=self.vt.sleep,
            rng=rng,
            **kwargs,
        )
        self.vt.real_work_pending = lambda: self.gateway._busy()

    async def decide(
        self,
        tenant_id: str = "t_a",
        guard_point: str = "output",
        *,
        input: str = INPUT,
        questions=None,
    ):
        """One check, then wait for its alerts and meter records to reach the sinks, so a
        test can assert on ``alerts`` and ``meter`` straight away."""
        result = await self.gateway.decide(
            tenant_id=tenant_id,
            guard_point=guard_point,
            input=input,
            questions=QUESTIONS if questions is None else questions,
        )
        await self.gateway.drain()
        return result

    @property
    def elapsed(self) -> float:
        return self.vt.now_s - T0

    async def open_breaker(self) -> None:
        self.fake.fail_next(FailureKind.AUTH)
        assert await self.decide() == Failed(kind=FailureKind.AUTH)
        assert self.gateway.breaker_open()


@pytest.fixture(autouse=True)
async def close_gateways(monkeypatch):
    """Close every gateway a test creates, so no drainer or orphan outlives its test."""
    created = []
    original = DecisionGateway.__init__

    def tracking(self, *args, **kwargs):
        original(self, *args, **kwargs)
        created.append(self)

    monkeypatch.setattr(DecisionGateway, "__init__", tracking)
    yield
    for gateway in created:
        await gateway.aclose()


async def settled() -> None:
    """Let tasks the gateway cancelled without waiting (its timers) finish."""
    for _ in range(3):
        await asyncio.sleep(0)


def failed(result, kind: FailureKind) -> Failed:
    assert isinstance(result, Failed), result
    assert result.kind is kind, result
    return result


def test_virtual_model_satisfies_the_port():
    assert isinstance(VirtualModel(VirtualTime()), DecisionModel)


# ---------------------------------------------------------------------------- budget


class TestBudget:
    def test_defaults_are_band_bases_2ms_per_question_margin_and_relaxed_caps(self):
        config = GatewayConfig()
        assert config.latency_bands == (
            (1_000, 0.244),
            (4_000, 0.271),
            (8_000, 0.326),
            (16_000, 0.400),
        )
        assert config.time_window_allowance_s == 0.380  # M1-15, R6.3
        assert config.latency_per_question_s == 0.002
        assert config.budget_margin_s == 0.400
        assert config.budget_margin_fraction == 0.6
        assert dict(config.queue_waits_s) == {
            "plan": 0.100,
            "tool_call": 0.100,
            "output": 0.100,
            "input": 0.300,
            "tool_result": 0.400,
        }
        assert config.budget_cap_s == 3.000  # R6.3 after U7
        assert config.input_budget_cap_s == 4.000
        # No fixed budget or retry threshold: both are computed per call.
        assert config.default_budget_s is None
        assert config.budgets_s == {}
        assert config.expected_latency_s is None
        size = {"input_tokens": estimate_tokens(INPUT), "question_count": len(QUESTIONS)}
        assert config.budget_for("output", **size) == pytest.approx(BUDGET)
        assert config.expected_latency_for(**size) == pytest.approx(EXPECTED_P50)

    async def test_call_inside_budget_returns_the_models_result_unchanged(self):
        h = Harness()
        h.model.latency_s = 0.3
        h.fake.set_noul("p__harm", 0.97)
        result = await h.decide()
        assert isinstance(result, Answered)
        assert result.noul("p__harm") == 0.97
        assert h.elapsed == pytest.approx(0.3)
        assert h.model.started == 1

    async def test_budget_overrun_cancels_in_flight_call_and_returns_failed_timeout(self):
        h = Harness()
        h.model.latency_s = 5.0
        result = await h.decide()
        failed(result, FailureKind.TIMEOUT)
        assert h.elapsed == pytest.approx(BUDGET)  # stopped at the budget, not at 5 s
        # R6.3 after U7: the first call was cut at its attempt deadline and retried; the
        # retry was cut when the budget ran out.
        assert h.model.cancelled == 2
        assert h.fake.calls == []  # neither call completed
        assert h.model.started == 2

    async def test_budget_is_per_guard_point(self):
        h = Harness(GatewayConfig(budgets_s={"tool_result": 0.75}))
        h.model.latency_s = 5.0
        failed(await h.decide(guard_point="tool_result"), FailureKind.TIMEOUT)
        assert h.elapsed == pytest.approx(0.75)
        failed(await h.decide(guard_point="output"), FailureKind.TIMEOUT)
        assert h.elapsed == pytest.approx(0.75 + BUDGET)  # the cap for the other guard point

    async def test_budget_is_total_across_first_attempt_and_retry(self):
        # First attempt fails after 100 ms; the retry hangs. The check must end one budget
        # (648 ms) after it started, not one budget after the retry started.
        h = Harness()
        h.model.slow_next(0.1, 5.0)
        h.fake.fail_next(FailureKind.UNAVAILABLE)
        failed(await h.decide(), FailureKind.TIMEOUT)
        assert h.model.started == 2
        assert h.elapsed == pytest.approx(BUDGET)

    async def test_no_model_call_when_budget_is_already_spent(self):
        h = Harness()
        h.model.slow_next(0.1)
        h.fake.fail_next(FailureKind.UNAVAILABLE)
        # A slow jitter sleep (misbehaving injected sleep) that eats the rest of the budget.
        real_sleep = h.vt.sleep

        async def oversleep(seconds):
            await real_sleep(seconds)
            h.vt.advance(3.0)

        gateway = DecisionGateway(h.model, clock=h.vt.now, sleep=oversleep, rng=lambda: 0.5)
        result = await gateway.decide(
            tenant_id="t_x", guard_point="output", input=INPUT, questions=QUESTIONS
        )
        failed(result, FailureKind.TIMEOUT)
        assert h.model.started == 1

    @pytest.mark.parametrize(
        "kwargs",
        [
            {"default_budget_s": 0},
            {"budgets_s": {"output": -1.0}},
            {"expected_latency_s": -0.1},
            {"budget_cap_s": 0},
            {"input_budget_cap_s": 0},
            {"budget_margin_s": -0.1},
            {"budget_margin_fraction": -0.1},
            {"time_window_allowance_s": -0.001},
            {"time_window_allowance_s": float("nan")},
            {"queue_waits_s": {"output": -0.1}},
            {"queue_waits_s": {"output": float("inf")}},
            {"queue_waits_s": {"output": float("nan")}},
            {"latency_per_question_s": -0.001},
            {"latency_bands": ()},
            {"latency_bands": ((4_000, 0.271), (1_000, 0.244))},
            {"latency_bands": ((1_000, 0.244), (1_000, 0.271))},
            {"latency_bands": ((0, 0.244),)},
            {"latency_bands": ((1_000.5, 0.244),)},
            {"latency_bands": ((1_000, 0),)},
            {"retry_jitter_s": -0.1},
            {"cancel_grace_s": -0.1},
            {"warning_interval_s": -1},
            {"probe_initial_delay_s": 0},
            {"probe_initial_delay_s": 10.0, "probe_max_delay_s": 5.0},
        ],
    )
    def test_config_rejects_nonsense_durations(self, kwargs):
        with pytest.raises(ValueError):
            GatewayConfig(**kwargs)


# ---------------------------------------------------------------------------- retry


class TestRetry:
    @pytest.mark.parametrize("kind", [FailureKind.UNAVAILABLE, FailureKind.TIMEOUT])
    async def test_fast_retryable_failure_is_retried_once_and_can_succeed(self, kind):
        h = Harness()
        h.fake.fail_next(kind)
        result = await h.decide()
        assert isinstance(result, Answered)
        assert h.model.started == 2

    @pytest.mark.parametrize("kind", [FailureKind.UNAVAILABLE, FailureKind.TIMEOUT])
    async def test_retryable_failure_is_retried_at_most_once(self, kind):
        h = Harness()
        h.fake.always(Failed(kind=kind))
        failed(await h.decide(), kind)
        assert h.model.started == 2

    @pytest.mark.parametrize(
        "kind",
        [
            FailureKind.RATE_LIMITED,
            FailureKind.LIMIT_EXCEEDED,
            FailureKind.AUTH,
            FailureKind.OTHER,
        ],
    )
    async def test_non_retryable_failure_makes_exactly_one_call(self, kind):
        h = Harness()
        h.fake.always(Failed(kind=kind))
        failed(await h.decide(), kind)
        assert h.model.started == 1
        assert h.elapsed == 0  # returned at once; no jitter sleep, no second attempt

    async def test_safety_blocked_makes_exactly_one_call(self):
        h = Harness()
        h.fake.always(SafetyBlocked(message="refused"))
        assert await h.decide() == SafetyBlocked(message="refused")
        assert h.model.started == 1

    async def test_answered_makes_exactly_one_call(self):
        h = Harness()
        assert isinstance(await h.decide(), Answered)
        assert h.model.started == 1

    async def test_deadline_timeout_is_not_retried_because_no_budget_remains(self):
        h = Harness(GatewayConfig(**ONE_ATTEMPT))  # the call runs to the end of the budget
        h.model.latency_s = 5.0
        failed(await h.decide(), FailureKind.TIMEOUT)
        assert h.model.started == 1

    async def test_no_retry_when_remaining_budget_is_below_expected_latency(self):
        # A 1.5 s override: fails at 880 ms, 620 ms remain, 628 ms (the expected p50) needed.
        # (Under the 3 s default cap any failure before the attempt deadline leaves enough.)
        h = Harness(GatewayConfig(budgets_s={"output": 1.5}))
        h.model.slow_next(0.88)
        h.fake.fail_next(FailureKind.UNAVAILABLE)
        failed(await h.decide(), FailureKind.UNAVAILABLE)
        assert h.model.started == 1
        assert h.elapsed == pytest.approx(0.88)

    async def test_retry_when_remaining_budget_equals_expected_latency(self):
        # Binary-exact numbers: budget 0.5, fails at 0.25, exactly 0.25 remains (>= 0.25).
        h = Harness(GatewayConfig(default_budget_s=0.5, expected_latency_s=0.25))
        h.model.slow_next(0.25)
        h.fake.fail_next(FailureKind.UNAVAILABLE)
        assert isinstance(await h.decide(), Answered)
        assert h.model.started == 2

    async def test_no_retry_just_below_expected_latency(self):
        h = Harness(GatewayConfig(default_budget_s=0.5, expected_latency_s=0.25))
        h.model.slow_next(0.25 + 1 / 1024)
        h.fake.fail_next(FailureKind.UNAVAILABLE)
        failed(await h.decide(), FailureKind.UNAVAILABLE)
        assert h.model.started == 1

    async def test_expected_latency_is_configurable(self):
        # A 1 s override; fails at 450 ms: 550 ms remain. That is short of the 628 ms expected
        # p50 (no retry); a fixed 100 ms expected call allows one.
        h = Harness(GatewayConfig(budgets_s={"output": 1.0}, expected_latency_s=0.1))
        h.model.slow_next(0.45)
        h.fake.fail_next(FailureKind.UNAVAILABLE)
        assert isinstance(await h.decide(), Answered)
        assert h.model.started == 2

    async def test_retry_waits_a_random_jitter_first(self):
        h = Harness(GatewayConfig(retry_jitter_s=0.02), rng=lambda: 0.5)
        h.fake.fail_next(FailureKind.UNAVAILABLE)
        assert isinstance(await h.decide(), Answered)
        assert h.elapsed == pytest.approx(0.01)  # 0.5 x 20 ms, between the two attempts
        assert 0.01 in [pytest.approx(s) for s in h.vt.sleeps]

    async def test_jitter_never_leaves_the_retry_less_than_expected_latency(self):
        # A 1.2 s override; fails at 562 ms: 638 ms remain, so only 10 ms of the 100 ms
        # jitter range is usable.
        h = Harness(
            GatewayConfig(budgets_s={"output": 1.2}, retry_jitter_s=0.1), rng=lambda: 0.999999
        )
        h.model.slow_next(0.562, EXPECTED_P50)
        h.fake.fail_next(FailureKind.UNAVAILABLE)
        result = await h.decide()
        assert isinstance(result, Answered)  # a retry of the expected 628 ms still fits
        assert h.elapsed <= 1.2 + 1e-9

    async def test_no_jitter_sleep_without_a_retry(self):
        h = Harness(rng=lambda: 0.5)
        h.fake.rate_limit_next()
        failed(await h.decide(), FailureKind.RATE_LIMITED)
        assert h.elapsed == 0


# ---------------------------------------------------------------------------- R6.3 / R6.4


def tokens_of_input(n: int) -> str:
    """An input the shared estimator counts as exactly ``n`` tokens (4 ASCII chars each)."""
    text = "abcd" * n
    assert estimate_tokens(text) == n
    return text


def questions(n: int) -> dict:
    return {f"t__q{i}": NoulQuestion(instructions=f"Is it case {i}?") for i in range(n)}


R6_3_DEFAULT_TABLE = {
    # (guard point, input tokens, questions):
    #     (expected p50, attempt deadline, queue allowance, cap, retry window) in ms
    ("output", 4_000, 12): (675, 1_080, 100, 3_000, 1_820),  # floor-sized
    ("plan", 16_000, 50): (880, 1_408, 100, 3_000, 1_492),  # critical path at maximum
    ("tool_call", 16_000, 50): (880, 1_408, 100, 3_000, 1_492),
    ("output", 16_000, 50): (880, 1_408, 100, 3_000, 1_492),
    ("tool_result", 16_000, 50): (880, 1_408, 400, 3_000, 1_192),  # per chunk
    ("input", 16_000, 200): (1_180, 1_888, 300, 4_000, 1_812),  # input at maximum
}
"""R6.3's default table after U7, as the backlog states it: the one place the expected
default numbers live in these tests. When the defaults change, this table (and the
defaults in ``gateway.py``) change; the tests below derive from it."""


class TestComputedBudget:
    """M1-15, R6.3 after U7 (relaxed): a check's total budget is its guard point's cap,
    3,000 ms (4,000 ms on ``input``). Within it the first call has an attempt deadline of
    expected p50 + max(400 ms, 0.6 x expected p50), where expected p50 = band base (244 / 271 /
    326 / 400 ms up to 1K / 4K / 8K / 16K tokens) + the 380 ms time-window allowance + 2.0 ms
    per question; after a timeout or unavailable one retry gets the rest of the budget."""

    @pytest.mark.parametrize(
        ("input_tokens", "base"),
        [
            (0, 0.244),
            (1_000, 0.244),
            (1_001, 0.271),
            (4_000, 0.271),
            (4_001, 0.326),
            (8_000, 0.326),
            (8_001, 0.400),
            (16_000, 0.400),
            (16_001, 0.400),  # above 16K: the 16K band
            (1_000_000, 0.400),
        ],
    )
    def test_band_edges(self, input_tokens, base):
        config = GatewayConfig()
        expected = base + 0.380
        got = config.budget_parts("output", input_tokens=input_tokens, question_count=0)
        assert got.expected_p50_s == pytest.approx(expected)
        assert got.attempt_deadline_s == pytest.approx(expected + max(0.4, 0.6 * expected))
        assert got.total_s == 3.000  # the cap, whatever the size

    @pytest.mark.parametrize("n", [0, 1, 12, 50, 200])
    def test_each_question_adds_2ms(self, n):
        config = GatewayConfig()
        assert config.expected_p50_for(input_tokens=4_000, question_count=n) == pytest.approx(
            0.271 + 0.380 + 0.002 * n
        )

    @pytest.mark.parametrize(("check", "row"), list(R6_3_DEFAULT_TABLE.items()))
    def test_m1_15_default_table(self, check, row):
        guard_point, input_tokens, n = check
        p50, attempt, queue, cap, window = (ms / 1000 for ms in row)
        parts = GatewayConfig().budget_parts(
            guard_point, input_tokens=input_tokens, question_count=n
        )
        assert (
            parts.expected_p50_s,
            parts.attempt_deadline_s,
            parts.queue_wait_s,
            parts.total_s,
            parts.retry_window_s,
        ) == pytest.approx((p50, attempt, queue, cap, window))
        assert not parts.override
        # The retry window is cap - queue allowance - attempt deadline, and it holds a retry
        # (at least the expected p50) on every row.
        assert parts.retry_window_s == pytest.approx(cap - queue - attempt)
        assert parts.retry_window_s >= parts.expected_p50_s

    def test_the_caps_are_3s_and_4s_on_input_whatever_the_size(self):
        config = GatewayConfig()
        for n in (1, 50, 1_000):
            size = {"input_tokens": 16_000, "question_count": n}
            assert config.budget_for("input", **size) == 4.000
            for gp in ("plan", "tool_call", "tool_result", "output"):
                assert config.budget_for(gp, **size) == 3.000
        assert config.cap_for("input") == 4.000

    def test_all_numbers_are_configuration(self):
        config = GatewayConfig(
            latency_bands=((2_000, 0.1), (10_000, 0.2)),
            time_window_allowance_s=0.05,
            latency_per_question_s=0.01,
            budget_margin_s=0.05,
            budget_margin_fraction=0.5,
            queue_waits_s={"output": 0.02, "input": 0.03},
            budget_cap_s=0.9,
            input_budget_cap_s=1.1,
        )
        # expected 0.1 + 0.05 + 0.03 = 0.18; margin max(0.05, 0.09); queue 0.02; cap 0.9
        small = config.budget_parts("output", input_tokens=2_000, question_count=3)
        assert (
            small.expected_p50_s,
            small.attempt_deadline_s,
            small.queue_wait_s,
            small.total_s,
        ) == pytest.approx((0.18, 0.27, 0.02, 0.9))
        big = config.budget_parts("input", input_tokens=50_000, question_count=3)
        assert (big.expected_p50_s, big.attempt_deadline_s, big.queue_wait_s, big.total_s) == (
            pytest.approx((0.28, 0.42, 0.03, 1.1))
        )
        # an unlisted guard point gets the smallest listed allowance
        assert config.queue_wait_for("plan") == 0.02
        assert GatewayConfig(queue_waits_s={}).queue_wait_for("output") == 0.0

    def test_a_fixed_override_replaces_the_total_budget(self):
        # Decided on the M1-15 build: an override replaces the cap. Admission may use the
        # queue allowance, never more than the budget minus the expected p50; the attempt
        # deadline is computed as usual (and limited at run time to what is left).
        config = GatewayConfig(budgets_s={"input": 2.5, "tool_result": 1.0}, default_budget_s=1.5)
        size = {"input_tokens": 16_000, "question_count": 200}
        assert config.budget_for("input", **size) == 2.5  # its own override
        assert config.budget_for("output", **size) == 1.5  # the default override
        assert GatewayConfig(budgets_s={"input": 2.5}).budget_for("output", **size) == 3.0
        parts = config.budget_parts("input", **size)
        assert parts.override
        assert (parts.queue_wait_s, parts.attempt_deadline_s) == pytest.approx((0.300, 1.888))
        # tool_result: 400 ms of allowance, but only 1.0 - 0.628 = 0.372 s is left after the
        # expected call
        small = config.budget_parts("tool_result", input_tokens=10, question_count=2)
        assert small.queue_wait_s == pytest.approx(1.0 - EXPECTED_P50)
        # The retry threshold is still the call's expected p50.
        assert config.expected_latency_for(**size) == pytest.approx(1.180)

    @pytest.mark.parametrize(
        ("kwargs", "message"),
        [
            ({"budgets_s": {"output": 10.001}}, "above the 10.0 s limit"),
            ({"default_budget_s": 12.0}, "above the 10.0 s limit"),
            ({"budgets_s": {"output": 0.5}}, "not more than the smallest call's expected p50"),
            ({"default_budget_s": 0.626}, "not more than the smallest call's expected p50"),
            ({"default_budget_s": 0.2, "expected_latency_s": 0.25}, "not more than"),
            ({"budgets_s": {"output": float("inf")}}, "must be a finite number"),
        ],
    )
    def test_m1_15_startup_refuses_an_override_out_of_bounds(self, kwargs, message):
        with pytest.raises(ValueError, match=message):
            GatewayConfig(**kwargs)

    def test_m1_15_overrides_at_the_bounds_are_accepted(self):
        assert (
            GatewayConfig(budgets_s={"output": 10.0}).budget_for(
                "output", input_tokens=0, question_count=1
            )
            == 10.0
        )
        smallest = GatewayConfig().smallest_expected_s()
        assert smallest == pytest.approx(0.244 + 0.380 + 0.002)  # first band, one question
        GatewayConfig(default_budget_s=smallest + 0.001)
        assert GatewayConfig(expected_latency_s=0.01).smallest_expected_s() == 0.01

    @pytest.mark.parametrize(
        "name",
        [
            "time_window_allowance_s",
            "budget_margin_fraction",
            "budget_cap_s",
            "input_budget_cap_s",
            "budget_margin_s",
            "latency_per_question_s",
        ],
    )
    @pytest.mark.parametrize("value", [float("inf"), float("nan")])
    def test_m1_15_number_settings_must_be_finite(self, name, value):
        with pytest.raises(ValueError, match=name):
            GatewayConfig(**{name: value})

    async def test_m1_15_a_hung_call_is_cut_at_its_attempt_deadline_and_retried(self):
        h = Harness()
        h.model.slow_next(5.0, 0.1)  # the first call hangs; the retry answers in 100 ms
        timed = await h.gateway.decide_timed(
            tenant_id="t_a", guard_point="output", input=INPUT, questions=QUESTIONS
        )
        assert isinstance(timed.result, Answered)
        assert h.elapsed == pytest.approx(ATTEMPT_DEADLINE + 0.1)
        assert (h.model.started, h.model.cancelled) == (2, 1)
        assert timed.timing.provider_calls == 2
        assert h.model.peak == 1  # never two calls of the check at once
        await h.gateway.drain()
        # The abandoned first call is metered as attempted, usage unknown.
        assert h.meter.unanswered_attempts("t_a", "output") == 1
        assert h.meter.metered_calls("t_a", "output") == 1

    @pytest.mark.parametrize(("guard_point", "input_tokens", "n"), list(R6_3_DEFAULT_TABLE))
    async def test_m1_15_the_attempt_deadline_of_each_table_row(self, guard_point, input_tokens, n):
        attempt = R6_3_DEFAULT_TABLE[(guard_point, input_tokens, n)][1] / 1000
        h = Harness()
        h.model.slow_next(60.0, 0.05)
        result = await h.decide(
            guard_point=guard_point, input=tokens_of_input(input_tokens), questions=questions(n)
        )
        assert isinstance(result, Answered)
        assert h.elapsed == pytest.approx(attempt + 0.05)
        assert h.model.started == 2

    async def test_m1_15_no_early_cut_when_the_rest_could_not_hold_a_retry(self):
        # A 1.5 s override: cutting at 1,028 ms would leave 472 ms, under the 628 ms expected
        # p50, so no retry could follow. The call keeps the whole budget instead of the check
        # ending early with a timeout ("blocks on timeout only when the budget is spent").
        h = Harness(GatewayConfig(budgets_s={"output": 1.5}))
        h.model.slow_next(1.3)
        assert isinstance(await h.decide(), Answered)
        assert (h.model.started, h.model.cancelled) == (1, 0)
        h.model.latency_s = 5.0
        start = h.elapsed
        failed(await h.decide(), FailureKind.TIMEOUT)
        assert h.elapsed - start == pytest.approx(1.5)
        assert h.model.started == 2  # one more call: no retry

    async def test_m1_15_an_abandoned_call_counts_against_the_orphan_cap(self, immortal):
        # A call that ignores cancellation is cut at its attempt deadline and kept as an
        # orphan; the retry is cut at the end of the budget and kept too. Both are metered as
        # attempted, usage unknown, and both count against the orphan cap.
        vt = VirtualTime()
        meter = InMemoryUsageMeter()
        gateway = DecisionGateway(
            immortal,
            config=GatewayConfig(max_orphans=2),
            meter=meter,
            clock=vt.now,
            sleep=vt.sleep,
        )
        first = await gateway.decide_timed(
            tenant_id="t_x", guard_point="output", input=INPUT, questions=QUESTIONS
        )
        failed(first.result, FailureKind.TIMEOUT)
        assert first.timing.provider_calls == 2
        assert vt.now_s - T0 == pytest.approx(BUDGET + 0.010)  # the budget plus one grace
        assert (gateway.orphaned_calls, gateway.orphans_in_flight) == (2, 2)
        assert gateway.orphan_capped
        await gateway.drain()
        assert meter.unanswered_attempts("t_x", "output") == 2
        capped = await gateway.decide_timed(
            tenant_id="t_x", guard_point="output", input=INPUT, questions=QUESTIONS
        )
        assert failed(capped.result, FailureKind.UNAVAILABLE).reason == REASON_ORPHAN_CAP
        assert (capped.retry_after_ms, capped.capacity_limited) == (1_000, True)
        assert immortal.started == 2

    async def test_m1_15_a_burst_of_hung_calls_never_exceeds_the_in_flight_limit(self, immortal):
        # Six checks at once on a provider that hangs and ignores cancellation. Four take the
        # slots; the other two can't queue (628 ms predicted > the 100 ms allowance) and fail
        # fast. The four are cut at their attempt deadline and become orphans holding every
        # slot, so their retries can't be admitted: each keeps its first timeout. The
        # provider never sees more than the limit, and the next check is refused with the
        # 1,000 ms fallback hint.
        vt = VirtualTime()
        gateway = DecisionGateway(immortal, clock=vt.now, sleep=vt.sleep)

        async def check():
            return await gateway.decide_timed(
                tenant_id="t_x", guard_point="output", input=INPUT, questions=QUESTIONS
            )

        results = await asyncio.gather(*(check() for _ in range(6)))
        limit = DEFAULT_MAX_IN_FLIGHT_PER_KEY
        assert immortal.started == limit
        timeouts = [r for r in results if r.result.kind is FailureKind.TIMEOUT]
        refused = [r for r in results if r.result.kind is FailureKind.UNAVAILABLE]
        assert (len(timeouts), len(refused)) == (limit, 2)
        assert all(r.timing.provider_calls == 1 for r in timeouts)
        assert all(r.result.reason == REASON_ADMISSION_WAIT for r in refused)
        assert all((r.retry_after_ms, r.capacity_limited) == (628, True) for r in refused)
        assert gateway.orphans_in_flight == limit <= gateway.config.max_orphans
        after = await check()
        admission_failure(after.result, REASON_ADMISSION_WAIT)
        assert (after.retry_after_ms, after.capacity_limited) == (FALLBACK_RETRY_AFTER_MS, True)
        assert immortal.started == limit


class TestRetryThreshold:
    """One retry, only for timeout or unavailable, only if the remaining budget is at least
    the call's expected p50. One rule with the attempt deadline: the deadline decides when the
    first call is given up, this rule decides whether a retry follows."""

    @pytest.mark.parametrize("fails_at", [0.1, 0.5, 1.0])
    async def test_defaults_retry_any_failure_before_the_attempt_deadline(self, fails_at):
        # Under the 3 s cap the retry window (1,872 ms here) always holds the expected p50.
        h = Harness()
        h.model.slow_next(fails_at)
        h.fake.fail_next(FailureKind.UNAVAILABLE)
        assert isinstance(await h.decide(), Answered)
        assert h.model.started == 2

    @pytest.mark.parametrize(("cap", "retried"), [(1.5, True), (1.5 - 1 / 1024, False)])
    async def test_retry_when_remaining_equals_the_expected_p50(self, cap, retried):
        # Binary-exact: expected p50 0.25 + 0.125 (window) + 2 x 0.0625 = 0.5; attempt
        # deadline 0.5 + 0.5 = 1.0. With a 1.5 s budget, cutting the hung call at 1.0 leaves
        # exactly 0.5: it is cut and retried. A hair less, and no retry could follow, so the
        # call keeps the whole budget.
        config = GatewayConfig(
            latency_bands=((1_000, 0.25),),
            time_window_allowance_s=0.125,
            latency_per_question_s=0.0625,
            budget_margin_s=0.5,
            queue_waits_s={"output": 0.25},
            budget_cap_s=cap,
            cancel_grace_s=0.0,
        )
        h = Harness(config)
        h.model.slow_next(5.0, 0.25)
        result = await h.decide()
        assert h.model.started == (2 if retried else 1)
        assert isinstance(result, Answered) is retried
        assert h.elapsed == pytest.approx(1.25 if retried else cap)

    async def test_threshold_grows_with_the_question_count(self):
        # A 1.5 s override. 2 questions (expected 0.628): a failure at 870 ms leaves 630 ms,
        # enough; at 880 ms, 620 ms, not. 50 questions (expected 0.724): 770 ms is retried,
        # 780 ms isn't, where 2 questions would still be.
        cases = [(2, 0.87, True), (2, 0.88, False), (50, 0.77, True), (50, 0.78, False),
                 (2, 0.78, True)]  # fmt: skip
        for n, fails_at, retried in cases:
            h = Harness(GatewayConfig(budgets_s={"output": 1.5}))
            h.model.slow_next(fails_at)
            h.fake.fail_next(FailureKind.UNAVAILABLE)
            await h.decide(questions=questions(n) if n != 2 else None)
            assert h.model.started == (2 if retried else 1), (n, fails_at)

    async def test_no_retry_when_the_expected_p50_exceeds_the_budget(self):
        # A 1.5 s override, 16K input, 600 questions: expected p50 1.98 s. Even an immediate
        # failure is not retried: the retry could not be expected to finish.
        h = Harness(GatewayConfig(budgets_s={"output": 1.5}))
        h.fake.fail_next(FailureKind.UNAVAILABLE)
        failed(
            await h.decide(input=tokens_of_input(16_000), questions=questions(600)),
            FailureKind.UNAVAILABLE,
        )
        assert h.model.started == 1

    async def test_threshold_is_the_expected_p50_under_a_fixed_budget_too(self):
        # Fixed 1 s budget; expected p50 628 ms. A failure at 370 ms leaves 630 ms: retried.
        # At 380 ms 620 ms are left: not retried.
        for fails_at, retried in [(0.37, True), (0.38, False)]:
            h = Harness(GatewayConfig(budgets_s={"output": 1.0}))
            h.model.slow_next(fails_at)
            h.fake.fail_next(FailureKind.UNAVAILABLE)
            await h.decide()
            assert h.model.started == (2 if retried else 1), fails_at


# ---------------------------------------------------------------------------- auth breaker


class TestAuthCircuitBreaker:
    async def test_auth_raises_one_page_level_alert_immediately(self):
        h = Harness()
        h.fake.push(Failed(kind=FailureKind.AUTH, reason="API_KEY_INVALID"))
        failed(await h.decide(tenant_id="t_a", guard_point="output"), FailureKind.AUTH)
        assert h.elapsed == 0
        [alert] = h.alerts.alerts
        assert alert.severity is AlertSeverity.PAGE
        assert alert.kind == ALERT_AUTH_FAILURE
        assert alert.key_id == "key-v1"
        assert alert.reason == "API_KEY_INVALID"
        assert (alert.tenant_id, alert.guard_point) == ("t_a", "output")

    async def test_other_failures_do_not_page(self):
        h = Harness()
        for kind in FailureKind:
            if kind is not FailureKind.AUTH:
                h.fake.always(Failed(kind=kind))
                await h.decide()
        assert h.alerts.pages() == []
        assert not h.gateway.breaker_open()

    async def test_auth_opens_the_breaker(self):
        h = Harness()
        assert not h.gateway.breaker_open()
        await h.open_breaker()
        assert h.gateway.breaker_open("key-v1")

    async def test_open_breaker_fails_fast_with_auth_and_does_not_call_the_model(self):
        h = Harness()
        h.model.latency_s = 0.3  # a call that reached the model would take 300 ms
        h.fake.push(Failed(kind=FailureKind.AUTH, reason="API_KEY_INVALID"))
        await h.decide()
        started, clock = h.model.started, h.vt.now_s
        for tenant in ("t_a", "t_b", "t_c"):
            result = failed(await h.decide(tenant_id=tenant), FailureKind.AUTH)
            assert result.reason == "API_KEY_INVALID"
        assert h.model.started == started  # no model calls
        assert h.vt.now_s == clock  # and no budget spent
        assert len(h.alerts.pages()) == 1  # fail-fast results don't page again

    async def test_breaker_closes_when_the_key_is_replaced(self):
        h = Harness()
        await h.open_breaker()
        h.key = "key-v2"  # replaced in the secret store
        assert not h.gateway.breaker_open()
        assert isinstance(await h.decide(), Answered)
        assert h.model.started == 2

    async def test_breaker_is_per_key(self):
        h = Harness()
        await h.open_breaker()
        h.key = "key-v2"
        assert h.gateway.breaker_open("key-v1")
        assert not h.gateway.breaker_open("key-v2")
        assert isinstance(await h.decide(), Answered)  # the new key is not affected

    async def test_breaker_entry_of_a_replaced_key_is_removed(self):
        # Keyed by secret version, entries must not pile up one per rotation.
        h = Harness()
        await h.open_breaker()
        h.key = "key-v2"
        await h.decide()
        assert not h.gateway.breaker_open("key-v1")
        await h.open_breaker()  # v2 is rejected too
        h.key = "key-v3"
        await h.decide()
        assert not h.gateway.breaker_open("key-v2")
        assert not h.gateway.breaker_open("key-v1")
        assert h.gateway._open == {}

    async def test_replacement_key_that_also_fails_auth_pages_again(self):
        h = Harness()
        await h.open_breaker()
        h.key = "key-v2"
        await h.open_breaker()
        assert [a.key_id for a in h.alerts.pages()] == ["key-v1", "key-v2"]

    def test_probe_defaults_are_5s_initial_delay_and_60s_cap(self):
        config = GatewayConfig()
        assert config.probe_initial_delay_s == 5.0
        assert config.probe_max_delay_s == 60.0

    async def test_no_probe_before_the_initial_delay_has_passed(self):
        h = Harness()
        await h.open_breaker()
        h.vt.advance(4.9)
        failed(await h.decide(), FailureKind.AUTH)
        assert h.model.started == 1

    async def test_successful_first_probe_after_5s_closes_the_breaker(self):
        h = Harness()
        await h.open_breaker()
        h.vt.advance(5.0)
        assert isinstance(await h.decide(), Answered)  # the probe
        assert not h.gateway.breaker_open()
        assert isinstance(await h.decide(), Answered)  # normal traffic again
        assert h.model.started == 3

    async def test_one_spurious_auth_result_costs_5s_not_a_minute(self):
        h = Harness()
        h.fake.fail_next(FailureKind.AUTH)  # one transient 401, then the key is fine
        results = []
        for _ in range(12):  # a check every second
            results.append(await h.decide())
            h.vt.advance(1.0)
        assert [isinstance(r, Answered) for r in results] == [False] * 5 + [True] * 7
        assert h.model.started == 1 + 7  # seconds 1-4 failed fast without a model call

    async def assert_probe_waits(self, h: Harness, waits: list[float]) -> None:
        """Each wait: no probe half a second before it ends, one probe when it ends."""
        for wait in waits:
            started = h.model.started
            h.vt.advance(wait - 0.5)
            failed(await h.decide(), FailureKind.AUTH)
            assert h.model.started == started, f"probed before {wait}s had passed"
            h.vt.advance(0.5)
            await h.decide()
            assert h.model.started == started + 1, f"no probe after {wait}s"

    async def test_failed_probes_double_the_wait_up_to_the_60s_cap(self):
        h = Harness()
        h.fake.always(Failed(kind=FailureKind.AUTH))
        await h.decide()
        await self.assert_probe_waits(h, [5, 10, 20, 40, 60, 60, 60])
        assert h.gateway.breaker_open()
        assert len(h.alerts.pages()) == 1  # one page per key, not one per probe

    async def test_inconclusive_probes_also_double_the_wait(self):
        h = Harness()
        await h.open_breaker()
        h.fake.always(Failed(kind=FailureKind.UNAVAILABLE))
        await self.assert_probe_waits(h, [5, 10, 20])

    async def test_successful_probe_resets_the_backoff_schedule(self):
        h = Harness()
        h.fake.always(Failed(kind=FailureKind.AUTH))
        await h.decide()
        await self.assert_probe_waits(h, [5, 10])
        h.fake.always(None)
        h.vt.advance(20.0)
        assert isinstance(await h.decide(), Answered)  # third probe succeeds
        assert not h.gateway.breaker_open()
        h.fake.always(Failed(kind=FailureKind.AUTH))
        await h.decide()  # opens again
        await self.assert_probe_waits(h, [5, 10, 20])  # from the start, not from 40

    async def test_probe_initial_delay_and_cap_are_configurable(self):
        h = Harness(GatewayConfig(probe_initial_delay_s=1.0, probe_max_delay_s=3.0))
        h.fake.always(Failed(kind=FailureKind.AUTH))
        await h.decide()
        await self.assert_probe_waits(h, [1, 2, 3, 3])

    async def test_only_one_probe_under_concurrency(self):
        h = Harness()
        await h.open_breaker()
        h.vt.advance(5.0)
        h.model.latency_s = 0.1
        results = await asyncio.gather(*(h.decide() for _ in range(5)))
        assert h.model.started == 2  # the auth failure, then one probe
        assert sum(isinstance(r, Answered) for r in results) == 1
        assert sum(isinstance(r, Failed) and r.kind is FailureKind.AUTH for r in results) == 4

    async def test_probe_is_never_retried(self):
        h = Harness()
        await h.open_breaker()
        h.vt.advance(5.0)
        h.fake.always(Failed(kind=FailureKind.UNAVAILABLE))
        failed(await h.decide(), FailureKind.UNAVAILABLE)
        assert h.model.started == 2

    async def test_inconclusive_probe_keeps_the_breaker_open(self):
        # An outage during the probe says nothing about the key.
        h = Harness()
        await h.open_breaker()
        h.vt.advance(5.0)
        h.fake.fail_next(FailureKind.UNAVAILABLE)
        failed(await h.decide(), FailureKind.UNAVAILABLE)
        assert h.gateway.breaker_open()
        failed(await h.decide(), FailureKind.AUTH)
        assert h.model.started == 2

    async def test_probe_is_bound_by_the_budget(self):
        h = Harness()
        await h.open_breaker()
        h.vt.advance(5.0)
        h.model.latency_s = 5.0
        before = h.vt.now_s
        failed(await h.decide(), FailureKind.TIMEOUT)
        assert h.vt.now_s - before == pytest.approx(BUDGET)
        assert h.gateway.breaker_open()

    async def test_breaker_reopens_and_pages_again_after_closing(self):
        h = Harness()
        await h.open_breaker()
        h.vt.advance(5.0)
        assert isinstance(await h.decide(), Answered)
        await h.open_breaker()
        assert len(h.alerts.pages()) == 2

    async def test_late_auth_on_a_replaced_key_does_not_open_a_breaker_or_page(self, caplog):
        # An old key is revoked during rotation; a call still in flight on it fails.
        caplog.set_level(logging.INFO, logger="guardrail_engine.gateway.gateway")
        h = Harness()
        h.model.latency_s = 0.1
        h.fake.push(Failed(kind=FailureKind.AUTH, reason="API_KEY_INVALID"))
        task = asyncio.ensure_future(h.decide())
        await h.vt.sleep(0.05)
        h.key = "key-v2"  # replaced while the call is in flight
        failed(await task, FailureKind.AUTH)  # the old call's own result is unchanged
        assert not h.gateway.breaker_open("key-v1")
        assert not h.gateway.breaker_open("key-v2")
        assert h.alerts.alerts == []
        assert isinstance(await h.decide(), Answered)  # traffic on the new key flows
        assert h.model.started == 2
        [record] = [r for r in caplog.records if "replaced key" in r.getMessage()]
        assert record.levelno == logging.INFO
        assert "key-v1" in record.getMessage()

    async def test_calls_in_flight_when_breaker_opens_page_only_once(self):
        # Admission control lets 4 (the default limit) of the 8 checks call the model; the
        # other 4 queue (a 50 ms expected call keeps their predicted waits inside the 100 ms
        # queue allowance). All 4 calls return auth, the breaker opens, and the queued checks
        # then fail with auth without a call (an open breaker sends nothing more on the key).
        h = Harness(GatewayConfig(expected_latency_s=0.05))
        h.model.latency_s = 0.05
        h.fake.always(Failed(kind=FailureKind.AUTH))
        results = await asyncio.gather(*(h.decide() for _ in range(8)))
        assert all(isinstance(r, Failed) and r.kind is FailureKind.AUTH for r in results)
        assert h.model.started == DEFAULT_MAX_IN_FLIGHT_PER_KEY == 4
        assert len(h.alerts.pages()) == 1


# ---------------------------------------------------------------------------- usage


def without_usage(fake: FakeDecisionModel) -> None:
    body = fake.build_raw_response(INPUT, QUESTIONS)
    del body["usage"]
    fake.raw_response_next(body)


class TestUsageMetering:
    async def test_records_input_tokens_against_tenant_and_guard_point(self):
        h = Harness()
        await h.decide(tenant_id="t_a", guard_point="output")
        await h.decide(tenant_id="t_a", guard_point="output")
        await h.decide(tenant_id="t_a", guard_point="input")
        await h.decide(tenant_id="t_b", guard_point="output")
        assert INPUT_TOKENS > 0
        assert h.meter.input_tokens("t_a", "output") == 2 * INPUT_TOKENS
        assert h.meter.metered_calls("t_a", "output") == 2
        assert h.meter.input_tokens("t_a", "input") == INPUT_TOKENS
        assert h.meter.input_tokens("t_b", "output") == INPUT_TOKENS
        assert h.meter.input_tokens("t_b", "input") == 0

    async def test_unknown_usage_is_counted_separately_not_as_zero_tokens(self):
        h = Harness()
        await h.decide()
        without_usage(h.fake)
        result = await h.decide()
        assert isinstance(result, Answered) and result.usage is None
        assert result.ok  # the answers are still usable
        assert h.meter.unknown_calls("t_a", "output") == 1
        assert h.meter.metered_calls("t_a", "output") == 1  # not 2: unknown is not a 0
        assert h.meter.input_tokens("t_a", "output") == INPUT_TOKENS

    async def test_meter_receives_none_for_unknown_usage(self):
        seen = []

        class Meter:
            def record(self, tenant_id, guard_point, input_tokens):
                seen.append((tenant_id, guard_point, input_tokens))

        fake = FakeDecisionModel()
        gateway = DecisionGateway(fake, meter=Meter())
        without_usage(fake)
        for _ in range(2):
            await gateway.decide(
                tenant_id="t_x", guard_point="plan", input=INPUT, questions=QUESTIONS
            )
        await gateway.drain()
        assert seen == [("t_x", "plan", None), ("t_x", "plan", INPUT_TOKENS)]

    async def test_unknown_usage_raises_a_warning_alert_not_a_page(self):
        h = Harness()
        without_usage(h.fake)
        await h.decide()
        [alert] = h.alerts.alerts
        assert alert.severity is AlertSeverity.WARNING
        assert alert.kind == ALERT_USAGE_UNKNOWN
        assert (alert.tenant_id, alert.guard_point) == ("t_a", "output")
        assert alert.reason  # the parser's usage_problem

    async def test_failed_and_safety_blocked_calls_record_no_usage(self):
        h = Harness()
        h.fake.push(SafetyBlocked(), Failed(kind=FailureKind.RATE_LIMITED))
        await h.decide()
        await h.decide()
        assert h.meter.metered_calls("t_a", "output") == 0
        assert h.meter.unknown_calls("t_a", "output") == 0

    # The unknown-usage warning is throttled; the metering is not.

    async def test_unknown_usage_warning_fires_once_per_interval_while_every_call_is_metered(self):
        h = Harness()
        for _ in range(5):
            without_usage(h.fake)
            await h.decide()
        assert h.meter.unknown_calls("t_a", "output") == 5
        assert len(h.alerts.warnings(ALERT_USAGE_UNKNOWN)) == 1
        h.vt.advance(59.0)
        without_usage(h.fake)
        await h.decide()
        assert len(h.alerts.warnings(ALERT_USAGE_UNKNOWN)) == 1
        h.vt.advance(1.0)  # 60 s after the first
        without_usage(h.fake)
        await h.decide()
        first, second = h.alerts.warnings(ALERT_USAGE_UNKNOWN)
        assert first.count == 1
        assert second.count == 6  # this one plus the five suppressed since the first
        assert h.meter.unknown_calls("t_a", "output") == 7

    async def test_unknown_usage_warning_is_throttled_per_tenant_and_guard_point(self):
        h = Harness()
        for tenant, guard_point in [("t_a", "output"), ("t_a", "input"), ("t_b", "output")] * 2:
            without_usage(h.fake)
            await h.decide(tenant_id=tenant, guard_point=guard_point)
        seen = [(a.tenant_id, a.guard_point) for a in h.alerts.warnings(ALERT_USAGE_UNKNOWN)]
        assert seen == [("t_a", "output"), ("t_a", "input"), ("t_b", "output")]

    async def test_warning_interval_is_configurable(self):
        h = Harness(GatewayConfig(warning_interval_s=10.0))
        for _ in range(3):
            without_usage(h.fake)
            await h.decide()
            h.vt.advance(10.0)
        assert len(h.alerts.warnings(ALERT_USAGE_UNKNOWN)) == 3

    async def test_page_alerts_are_never_throttled(self):
        h = Harness()
        without_usage(h.fake)
        await h.decide()
        await h.open_breaker()
        h.key = "key-v2"
        await h.open_breaker()
        assert len(h.alerts.pages()) == 2

    # Attempts that got no answer may still be billed.

    async def test_attempt_cancelled_at_the_deadline_is_recorded_as_unanswered(self):
        h = Harness()
        h.model.latency_s = 5.0
        failed(await h.decide(), FailureKind.TIMEOUT)
        # Two abandoned calls (M1-15): the first, cut at its attempt deadline, and the retry,
        # cut when the budget ran out. Each may be billed.
        assert h.meter.unanswered_attempts("t_a", "output") == 2
        assert h.meter.unanswered_attempts("t_b", "output") == 0
        # kept apart from answered calls, with known or unknown usage
        assert h.meter.unknown_calls("t_a", "output") == 0
        assert h.meter.metered_calls("t_a", "output") == 0

    async def test_each_attempt_that_times_out_at_the_provider_is_recorded_as_unanswered(self):
        h = Harness()
        h.fake.always(Failed(kind=FailureKind.TIMEOUT))
        failed(await h.decide(), FailureKind.TIMEOUT)
        assert h.model.started == 2  # first attempt and the retry
        assert h.meter.unanswered_attempts("t_a", "output") == 2

    async def test_attempt_in_flight_when_the_caller_is_cancelled_is_recorded_as_unanswered(self):
        h = Harness()
        h.model.latency_s = 0.2
        task = asyncio.ensure_future(h.decide())
        for _ in range(5):
            await asyncio.sleep(0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        await h.gateway.drain()
        assert h.meter.unanswered_attempts("t_a", "output") == 1

    async def test_answered_and_rejected_calls_are_not_recorded_as_unanswered(self):
        # SafetyBlocked left this list under the M1-13 metering decision: a refusal is recorded
        # as an attempt with usage unknown (tests/gateway/test_gateway_m1_13_refusal.py).
        h = Harness()
        h.fake.push(
            Failed(kind=FailureKind.RATE_LIMITED),
            Failed(kind=FailureKind.UNAVAILABLE),
            Failed(kind=FailureKind.LIMIT_EXCEEDED),
            Failed(kind=FailureKind.OTHER),
        )
        for _ in range(4):
            await h.decide()
        without_usage(h.fake)
        await h.decide()
        assert h.meter.unanswered_attempts("t_a", "output") == 0

    async def test_meter_without_record_unanswered_does_not_change_the_result(self):
        class OldMeter:
            def record(self, tenant_id, guard_point, input_tokens):
                pass

        h = Harness()
        h.model.latency_s = 5.0
        gateway = DecisionGateway(h.model, meter=OldMeter(), clock=h.vt.now, sleep=h.vt.sleep)
        result = await gateway.decide(
            tenant_id="t_x", guard_point="output", input=INPUT, questions=QUESTIONS
        )
        failed(result, FailureKind.TIMEOUT)

    async def test_retried_check_meters_only_the_answered_call(self):
        h = Harness()
        h.fake.fail_next(FailureKind.UNAVAILABLE)
        await h.decide()
        assert h.model.started == 2
        assert h.meter.metered_calls("t_a", "output") == 1
        assert h.meter.input_tokens("t_a", "output") == INPUT_TOKENS

    async def test_fail_fast_while_breaker_open_records_no_usage(self):
        h = Harness()
        await h.open_breaker()
        await h.decide()
        assert h.meter.metered_calls("t_a", "output") == 0
        assert h.meter.unknown_calls("t_a", "output") == 0


# ---------------------------------------------------------------------------- never raises


class TestNeverRaises:
    async def decide(self, gateway):
        return await gateway.decide(
            tenant_id="t_x", guard_point="output", input=INPUT, questions=QUESTIONS
        )

    async def test_model_that_raises_becomes_failed_other_and_is_not_retried(self):
        calls = 0

        class Broken:
            model_id = "broken"

            async def decide(self, input, questions):
                nonlocal calls
                calls += 1
                raise RuntimeError("adapter bug")

        failed(await self.decide(DecisionGateway(Broken())), FailureKind.OTHER)
        assert calls == 1

    async def test_model_that_raises_synchronously_becomes_failed_other(self):
        class Broken:
            model_id = "broken"

            def decide(self, input, questions):
                raise RuntimeError("not even a coroutine")

        failed(await self.decide(DecisionGateway(Broken())), FailureKind.OTHER)

    async def test_model_that_returns_a_non_result_becomes_failed_other(self):
        class Broken:
            model_id = "broken"

            async def decide(self, input, questions):
                return {"answers": {}}

        failed(await self.decide(DecisionGateway(Broken())), FailureKind.OTHER)

    async def test_meter_that_raises_does_not_change_the_result(self):
        class Meter:
            def record(self, tenant_id, guard_point, input_tokens):
                raise RuntimeError("meter down")

        gateway = DecisionGateway(FakeDecisionModel(), meter=Meter())
        assert isinstance(await self.decide(gateway), Answered)

    async def test_alert_sink_that_raises_does_not_change_the_result_or_the_breaker(self):
        class Sink:
            def emit(self, alert):
                raise RuntimeError("pager down")

        fake = FakeDecisionModel().fail_next(FailureKind.AUTH)
        gateway = DecisionGateway(fake, alerts=Sink())
        failed(await self.decide(gateway), FailureKind.AUTH)
        assert gateway.breaker_open()
        failed(await self.decide(gateway), FailureKind.AUTH)
        assert len(fake.calls) == 1

    async def test_key_id_that_raises_becomes_failed_other(self):
        def key_id():
            raise RuntimeError("secret store down")

        fake = FakeDecisionModel()
        failed(await self.decide(DecisionGateway(fake, key_id=key_id)), FailureKind.OTHER)
        assert fake.calls == []

    async def test_sleep_that_raises_becomes_failed_other_and_cancels_the_call(self):
        async def sleep(seconds):
            raise RuntimeError("timer bug")

        fake = FakeDecisionModel(latency_s=30)
        failed(await self.decide(DecisionGateway(fake, sleep=sleep)), FailureKind.OTHER)
        await settled()
        assert fake.calls == []
        assert len(asyncio.all_tasks()) == 1  # only this test; nothing left running

    async def test_cancelling_the_caller_propagates_and_cancels_the_model_call(self):
        fake = FakeDecisionModel(latency_s=30)
        gateway = DecisionGateway(fake)
        task = asyncio.ensure_future(self.decide(gateway))
        await asyncio.sleep(0.01)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        await settled()
        assert fake.calls == []
        assert gateway.orphaned_calls == 0
        assert len(asyncio.all_tasks()) == 1

    async def test_async_sink_or_meter_is_not_run_and_does_not_change_the_result(self, caplog):
        # Sinks are synchronous by contract. A coroutine returned by one is closed,
        # never awaited (awaiting would put sink I/O on the request path).
        ran = []

        class AsyncSink:
            async def emit(self, alert):
                ran.append(alert)

        class AsyncMeter:
            async def record(self, tenant_id, guard_point, input_tokens):
                ran.append(input_tokens)

            async def record_unanswered(self, tenant_id, guard_point):
                ran.append(None)

        fake = FakeDecisionModel()
        without_usage(fake)  # one meter record and one unknown-usage warning
        gateway = DecisionGateway(fake, alerts=AsyncSink(), meter=AsyncMeter())
        assert isinstance(await self.decide(gateway), Answered)
        await gateway.drain()
        gc.collect()  # an un-awaited coroutine would warn here, and -W error would fail
        assert ran == []
        assert sum("sinks must be synchronous" in r.message for r in caplog.records) == 2


# ---------------------------------------------------------------------------- sink contract


class TestSinkContract:
    """Sinks are synchronous and are called off the request path, in a worker thread."""

    def test_protocols_state_the_off_loop_contract(self):
        import guardrail_engine.gateway.sinks as sinks

        module_doc = " ".join(sinks.__doc__.split())
        assert "never calls them on the request path" in module_doc
        assert "dropped" in module_doc and "drain()" in module_doc
        for doc in (sinks.__doc__, AlertSink.emit.__doc__, UsageMeter.__doc__):
            text = " ".join(doc.split())
            assert "ynchronous" in text
            assert "off the event loop" in text
            assert "worker thread" in text

    def test_in_memory_sinks_are_synchronous_and_satisfy_the_protocols(self):
        meter, recording, null = InMemoryUsageMeter(), RecordingAlertSink(), NullAlertSink()
        assert isinstance(meter, UsageMeter)
        assert isinstance(recording, AlertSink) and isinstance(null, AlertSink)
        for fn in (meter.record, meter.record_unanswered, recording.emit, null.emit):
            assert not inspect.iscoroutinefunction(fn)
        assert meter.record("t_x", "output", 3) is None
        assert meter.record_unanswered("t_x", "output") is None

    def test_in_memory_sinks_import_nothing_that_does_io(self):
        import guardrail_engine.gateway.sinks as sinks

        imported = {
            node.module if isinstance(node, ast.ImportFrom) else node.names[0].name
            for node in ast.walk(ast.parse(inspect.getsource(sinks)))
            if isinstance(node, ast.Import | ast.ImportFrom)
        }
        assert imported == {"__future__", "collections", "dataclasses", "enum", "typing"}


# ----------------------------------------------------------------------------
class StubbornModel:
    """Ignores cancellation: once cancelled it carries on for ``linger_s`` and then returns
    or raises as if nothing had happened."""

    model_id = "stubborn"

    def __init__(self, sleep, linger_s: float, error: Exception | None = None) -> None:
        self.sleep = sleep
        self.linger_s = linger_s
        self.error = error
        self.started = 0
        self.finished = 0

    async def decide(self, input, questions):
        self.started += 1
        try:
            await self.sleep(3600.0)
        except asyncio.CancelledError:
            await self.sleep(self.linger_s)  # e.g. a blocking close on a pooled connection
        self.finished += 1
        if self.error is not None:
            raise self.error
        return Failed(kind=FailureKind.UNAVAILABLE)


class TestModelThatIgnoresCancellation:
    def make(self, linger_s=1.0, error=None, config=None):
        vt = VirtualTime()
        model = StubbornModel(vt.sleep, linger_s, error)
        alerts, meter = RecordingAlertSink(), InMemoryUsageMeter()
        gateway = DecisionGateway(
            model,
            config=config or GatewayConfig(**ONE_ATTEMPT),
            alerts=alerts,
            meter=meter,
            clock=vt.now,
            sleep=vt.sleep,
        )
        return vt, model, gateway, alerts, meter

    async def decide(self, gateway, tenant_id="t_x"):
        return await gateway.decide(
            tenant_id=tenant_id, guard_point="output", input=INPUT, questions=QUESTIONS
        )

    def test_cancel_grace_defaults_to_10ms(self):
        assert GatewayConfig().cancel_grace_s == 0.010

    async def test_decide_returns_timeout_within_budget_plus_grace(self):
        vt, model, gateway, _, _ = self.make(linger_s=1.0)
        failed(await self.decide(gateway), FailureKind.TIMEOUT)
        assert vt.now_s - T0 == pytest.approx(BUDGET + 0.010)  # not budget + 1 s
        assert model.started == 1  # and not retried
        assert model.finished == 0  # the call is still running

    async def test_cancel_grace_is_configurable(self):
        vt, _, gateway, _, _ = self.make(config=GatewayConfig(cancel_grace_s=0.05, **ONE_ATTEMPT))
        failed(await self.decide(gateway), FailureKind.TIMEOUT)
        assert vt.now_s - T0 == pytest.approx(BUDGET + 0.050)

    async def test_call_that_finishes_inside_the_grace_is_not_an_orphan(self):
        vt, model, gateway, alerts, _ = self.make(linger_s=0.004)
        failed(await self.decide(gateway), FailureKind.TIMEOUT)  # still a timeout
        assert vt.now_s - T0 == pytest.approx(BUDGET + 0.004)
        assert model.finished == 1
        assert gateway.orphaned_calls == 0
        await gateway.drain()
        assert alerts.alerts == []

    async def test_orphaned_call_is_kept_referenced_until_it_finishes(self):
        vt, model, gateway, _, _ = self.make(linger_s=1.0)
        await self.decide(gateway)
        assert gateway.orphaned_calls == 1
        assert gateway.orphans_in_flight == 1
        gc.collect()  # an unreferenced pending task would be destroyed here
        await vt.sleep(2.0)
        assert model.finished == 1  # it ran to its end
        assert gateway.orphans_in_flight == 0
        assert gateway.orphaned_calls == 1

    async def test_orphans_eventual_exception_is_consumed(self, caplog):
        vt, model, gateway, _, _ = self.make(linger_s=1.0, error=RuntimeError("late failure"))
        failed(await self.decide(gateway), FailureKind.TIMEOUT)
        await vt.sleep(2.0)
        assert model.finished == 1
        assert gateway.orphans_in_flight == 0
        gc.collect()  # asyncio reports an unretrieved task exception when the task is freed
        assert not [r for r in caplog.records if "never retrieved" in r.getMessage()]

    async def test_orphan_raises_a_warning_alert_that_the_adapter_ignored_cancellation(self):
        _, _, gateway, alerts, _ = self.make()
        await self.decide(gateway, tenant_id="t_a")
        await gateway.drain()
        [alert] = alerts.alerts
        assert alert.severity is AlertSeverity.WARNING
        assert alert.kind == ALERT_CANCEL_IGNORED
        assert (alert.tenant_id, alert.guard_point) == ("t_a", "output")
        assert "stubborn" in alert.message

    async def test_cancel_ignored_warning_is_throttled_like_other_warnings(self):
        # Three orphans on one key: the per-key limit is lifted, or the third check would
        # fail admission (two orphans hold both default slots).
        _, _, gateway, alerts, _ = self.make(
            config=GatewayConfig(max_in_flight_per_key=3, **ONE_ATTEMPT)
        )
        for _ in range(3):
            await self.decide(gateway)
        assert gateway.orphaned_calls == 3
        await gateway.drain()
        assert len(alerts.warnings(ALERT_CANCEL_IGNORED)) == 1

    async def test_orphaned_attempt_is_metered_as_unanswered(self):
        _, _, gateway, _, meter = self.make()
        await self.decide(gateway)
        await gateway.drain()
        assert meter.unanswered_attempts("t_x", "output") == 1

    async def test_caller_cancellation_is_bounded_by_the_grace_too(self):
        vt, _, gateway, alerts, _ = self.make(linger_s=1.0)
        task = asyncio.ensure_future(self.decide(gateway))
        await vt.sleep(0.1)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert vt.now_s - T0 == pytest.approx(0.1 + 0.010)
        assert gateway.orphaned_calls == 1
        await gateway.drain()
        assert len(alerts.warnings(ALERT_CANCEL_IGNORED)) == 1
        await vt.sleep(2.0)
        assert gateway.orphans_in_flight == 0

    async def test_real_time_slow_to_cancel_model_does_not_hold_decide_past_the_budget(self):
        model = StubbornModel(asyncio.sleep, linger_s=0.4)
        alerts = RecordingAlertSink()
        config = GatewayConfig(default_budget_s=0.05, cancel_grace_s=0.01, **TINY_CALL)
        gateway = DecisionGateway(model, config=config, alerts=alerts)
        start = time.monotonic()
        result = await self.decide(gateway)
        elapsed = time.monotonic() - start
        failed(result, FailureKind.TIMEOUT)
        assert 0.05 <= elapsed < 0.25  # budget + grace + scheduling slack, not 0.45 s
        assert gateway.orphans_in_flight == 1
        await gateway.drain()
        assert [a.kind for a in alerts.alerts] == [ALERT_CANCEL_IGNORED]
        await asyncio.sleep(0.5)  # let the orphan finish on its own
        assert model.finished == 1
        assert gateway.orphans_in_flight == 0
        await settled()
        assert len(asyncio.all_tasks()) == 1


# ----------------------------------------------------------------------------
class ImmortalModel:
    """Ignores every cancellation, however often it is cancelled, until ``release``."""

    model_id = "immortal"

    def __init__(self) -> None:
        self.started = 0
        self.gates: list[asyncio.Event] = []
        self.tasks: list[asyncio.Task] = []

    async def decide(self, input, questions):
        self.started += 1
        gate = asyncio.Event()
        self.gates.append(gate)
        self.tasks.append(asyncio.current_task())
        while not gate.is_set():
            try:
                await gate.wait()
            except asyncio.CancelledError:
                continue
        return Failed(kind=FailureKind.UNAVAILABLE)

    async def release(self, count: int | None = None) -> None:
        """Let the ``count`` oldest calls still running (default: all) finish."""
        waiting = [gate for gate in self.gates if not gate.is_set()]
        for gate in waiting[:count]:
            gate.set()
        await settled()


@pytest.fixture
async def immortal():
    model = ImmortalModel()
    yield model
    await model.release()  # or the event loop could never shut down


class TestOrphanCap:
    """The cap counts orphans across all keys. Orphans hold their key's admission slots, so
    on one key the default limit stops new calls at 2 orphans (see TestAdmissionControl).
    These tests lift the per-key limit to test the cap on its own."""

    def make(self, model, max_orphans=4, **kwargs):
        vt = VirtualTime()
        alerts = RecordingAlertSink()
        gateway = DecisionGateway(
            model,
            config=GatewayConfig(max_orphans=max_orphans, max_in_flight_per_key=64, **ONE_ATTEMPT),
            alerts=alerts,
            clock=vt.now,
            sleep=vt.sleep,
            **kwargs,
        )
        return vt, gateway, alerts

    async def decide(self, gateway):
        return await gateway.decide(
            tenant_id="t_x", guard_point="output", input=INPUT, questions=QUESTIONS
        )

    async def fill(self, gateway, count):
        for _ in range(count):
            failed(await self.decide(gateway), FailureKind.TIMEOUT)

    def test_max_orphans_defaults_to_32(self):
        assert GatewayConfig().max_orphans == 32
        with pytest.raises(ValueError):
            GatewayConfig(max_orphans=0)

    async def test_checks_below_the_cap_still_call_the_model(self, immortal):
        _, gateway, alerts = self.make(immortal)
        await self.fill(gateway, 3)
        assert immortal.started == 3
        assert gateway.orphans_in_flight == 3
        assert not gateway.orphan_capped
        await gateway.drain()
        assert alerts.pages() == []

    async def test_at_the_cap_checks_fail_fast_as_unavailable_without_calling_the_model(
        self, immortal
    ):
        vt, gateway, _ = self.make(immortal)
        await self.fill(gateway, 4)
        assert gateway.orphan_capped
        clock = vt.now_s
        for _ in range(10):
            result = failed(await self.decide(gateway), FailureKind.UNAVAILABLE)
            assert result.reason == "orphan_cap"
        assert immortal.started == 4  # zero model calls for the ten capped checks
        assert vt.now_s == clock  # and no budget spent
        assert gateway.orphans_in_flight == 4  # so the orphans stay bounded

    async def test_capped_check_is_not_retried_and_sleeps_no_jitter(self, immortal):
        # ``unavailable`` normally gets one retry; a capped check is the exception.
        vt, gateway, _ = self.make(immortal, rng=lambda: 0.5)
        await self.fill(gateway, 4)
        started, sleeps, clock = immortal.started, list(vt.sleeps), vt.now_s
        result = failed(await self.decide(gateway), FailureKind.UNAVAILABLE)
        assert result.reason == "orphan_cap"
        assert immortal.started == started  # no first attempt, no retry
        assert vt.sleeps == sleeps  # no jitter sleep, no deadline timer
        assert vt.now_s == clock

    async def test_reaching_the_cap_raises_one_page_not_one_per_check(self, immortal):
        _, gateway, alerts = self.make(immortal)
        await self.fill(gateway, 4)
        for _ in range(10):
            await self.decide(gateway)
        await gateway.drain()
        [page] = alerts.pages()
        assert page.kind == ALERT_ORPHAN_CAP
        assert page.reason == "orphan_cap"
        assert page.count == 4

    async def test_checks_resume_only_when_orphans_fall_below_half_the_cap(self, immortal):
        _, gateway, _ = self.make(immortal)
        await self.fill(gateway, 4)
        await immortal.release(1)  # 3 left
        failed(await self.decide(gateway), FailureKind.UNAVAILABLE)
        await immortal.release(1)  # 2 left: half the cap, not below it
        assert gateway.orphans_in_flight == 2
        assert failed(await self.decide(gateway), FailureKind.UNAVAILABLE).reason == "orphan_cap"
        assert immortal.started == 4
        assert gateway.orphan_capped
        await immortal.release(1)  # 1 left
        assert not gateway.orphan_capped  # cleared when the orphan ended, not at a check
        failed(await self.decide(gateway), FailureKind.TIMEOUT)  # the model is called again
        assert immortal.started == 5
        assert not gateway.orphan_capped

    async def test_checks_in_flight_when_the_cap_is_reached_do_not_page_again(self, immortal):
        # Six checks already calling the model when the fourth orphan reaches the cap.
        _, gateway, alerts = self.make(immortal)
        results = await asyncio.gather(*(self.decide(gateway) for _ in range(6)))
        assert [r.kind for r in results] == [FailureKind.TIMEOUT] * 6
        assert gateway.orphans_in_flight == 6
        await gateway.drain()
        assert [a.kind for a in alerts.pages()] == [ALERT_ORPHAN_CAP]

    async def test_each_crossing_of_the_cap_pages_once(self, immortal):
        _, gateway, alerts = self.make(immortal)
        await self.fill(gateway, 4)
        await immortal.release(3)  # 1 left
        await self.fill(gateway, 3)  # back to 4
        assert gateway.orphan_capped
        failed(await self.decide(gateway), FailureKind.UNAVAILABLE)
        await gateway.drain()
        assert [a.kind for a in alerts.pages()] == [ALERT_ORPHAN_CAP, ALERT_ORPHAN_CAP]

    async def test_aclose_returns_within_its_bound_when_orphans_never_finish(self, immortal):
        config = GatewayConfig(
            default_budget_s=0.02,
            cancel_grace_s=0.005,
            close_timeout_s=0.1,
            max_in_flight_per_key=3,  # three orphans on one key
            **TINY_CALL,
        )
        gateway = DecisionGateway(immortal, config=config)
        await self.fill(gateway, 3)
        assert gateway.orphans_in_flight == 3
        start = time.monotonic()
        await gateway.aclose()
        elapsed = time.monotonic() - start
        assert 0.1 <= elapsed < 0.6  # waited its bound, then gave up
        assert gateway.orphans_in_flight == 0  # references dropped
        assert not any(task.done() for task in immortal.tasks)  # they really never finished

    async def test_aclose_cancels_orphans_that_can_be_stopped(self):
        model = StubbornModel(asyncio.sleep, linger_s=30.0)  # ignores one cancellation
        config = GatewayConfig(default_budget_s=0.02, cancel_grace_s=0.005, **TINY_CALL)
        gateway = DecisionGateway(model, config=config)
        await self.fill(gateway, 2)
        assert gateway.orphans_in_flight == 2
        start = time.monotonic()
        await gateway.aclose()
        assert time.monotonic() - start < 0.5  # not 30 s, and not the whole 1 s bound
        assert gateway.orphans_in_flight == 0
        assert model.finished == 0
        await settled()
        assert len(asyncio.all_tasks()) == 1


# ----------------------------------------------------------------------------
class SlowAlertSink:
    def __init__(self, delay_s: float) -> None:
        self.delay_s = delay_s
        self.alerts = []
        self.threads = set()

    def emit(self, alert) -> None:
        time.sleep(self.delay_s)
        self.threads.add(threading.get_ident())
        self.alerts.append(alert)


class SlowMeter:
    def __init__(self, delay_s: float) -> None:
        self.delay_s = delay_s
        self.records = []
        self.threads = set()

    def record(self, tenant_id, guard_point, input_tokens) -> None:
        time.sleep(self.delay_s)
        self.threads.add(threading.get_ident())
        self.records.append((tenant_id, input_tokens))

    def record_unanswered(self, tenant_id, guard_point) -> None:
        time.sleep(self.delay_s)
        self.records.append((tenant_id, "unanswered"))


class GatedMeter:
    """Blocks inside ``record`` until ``gate`` is set, like a sink whose backend hangs."""

    def __init__(self) -> None:
        self.gate = threading.Event()
        self.entered = threading.Event()
        self.tenants = []

    def record(self, tenant_id, guard_point, input_tokens) -> None:
        self.entered.set()
        self.gate.wait(timeout=10)
        self.tenants.append(tenant_id)

    def record_unanswered(self, tenant_id, guard_point) -> None:
        self.record(tenant_id, guard_point, None)


class TestSinkHandoff:
    """Alerts and metering are delivered off the request path."""

    async def decide(self, gateway, tenant_id="t_x"):
        return await gateway.decide(
            tenant_id=tenant_id, guard_point="output", input=INPUT, questions=QUESTIONS
        )

    async def test_200ms_sink_and_meter_add_nothing_to_check_latency(self):
        sink, meter = SlowAlertSink(0.2), SlowMeter(0.2)
        fake = FakeDecisionModel()
        gateway = DecisionGateway(fake, alerts=sink, meter=meter)
        latencies = []
        for _ in range(3):
            without_usage(fake)  # each check: one meter record; the first also a warning
            start = time.monotonic()
            result = await self.decide(gateway)
            latencies.append(time.monotonic() - start)
            assert isinstance(result, Answered)
        assert max(latencies) < 0.05, latencies  # inline, the first would take 400 ms
        assert sink.alerts == [] and len(meter.records) < 3  # still being delivered
        await gateway.drain()
        assert [a.kind for a in sink.alerts] == [ALERT_USAGE_UNKNOWN]
        assert meter.records == [("t_x", None)] * 3
        assert gateway.dropped_events == 0

    async def test_sinks_run_in_a_worker_thread_not_on_the_event_loop(self):
        sink, meter = SlowAlertSink(0), SlowMeter(0)
        fake = FakeDecisionModel()
        without_usage(fake)
        gateway = DecisionGateway(fake, alerts=sink, meter=meter)
        await self.decide(gateway)
        await gateway.drain()
        assert sink.threads and meter.threads
        assert threading.get_ident() not in sink.threads | meter.threads

    async def test_queued_page_does_not_delay_the_breaker_opening(self):
        sink = SlowAlertSink(0.2)
        fake = FakeDecisionModel().fail_next(FailureKind.AUTH)
        gateway = DecisionGateway(fake, alerts=sink)
        start = time.monotonic()
        failed(await self.decide(gateway), FailureKind.AUTH)
        assert gateway.breaker_open()  # opened synchronously...
        failed(await self.decide(gateway), FailureKind.AUTH)
        assert len(fake.calls) == 1  # ...so the next check already fails fast
        assert time.monotonic() - start < 0.05
        assert sink.alerts == []  # while the page is still on its way
        await gateway.drain()
        [page] = sink.alerts
        assert page.severity is AlertSeverity.PAGE and page.kind == ALERT_AUTH_FAILURE

    async def test_events_are_delivered_in_the_order_they_were_raised(self):
        meter = SlowMeter(0)
        gateway = DecisionGateway(FakeDecisionModel(), meter=meter)
        for i in range(20):
            await self.decide(gateway, tenant_id=f"t_{i}")
        await gateway.drain()
        assert [tenant for tenant, _ in meter.records] == [f"t_{i}" for i in range(20)]

    async def test_full_queue_drops_the_oldest_event_and_counts_it(self):
        meter = GatedMeter()
        gateway = DecisionGateway(
            FakeDecisionModel(), meter=meter, config=GatewayConfig(sink_queue_size=3)
        )
        try:
            await self.decide(gateway, tenant_id="t_0")
            await asyncio.to_thread(meter.entered.wait, 5)  # t_0 is being delivered, stuck
            for i in range(1, 6):  # five more events into a queue of three
                start = time.monotonic()
                assert isinstance(await self.decide(gateway, tenant_id=f"t_{i}"), Answered)
                assert time.monotonic() - start < 0.05  # a full queue never blocks a check
            assert gateway.dropped_events == 2
        finally:
            meter.gate.set()
        await gateway.drain()
        assert meter.tenants == [
            "t_0",
            "t_3",
            "t_4",
            "t_5",
        ]  # t_1 and t_2, the oldest, were dropped
        assert gateway.dropped_events == 2

    async def test_drain_returns_at_once_when_nothing_is_queued(self):
        gateway = DecisionGateway(FakeDecisionModel())
        await gateway.drain()
        await self.decide(gateway)  # no sinks configured: nothing to deliver
        await gateway.drain()
        await settled()
        assert len(asyncio.all_tasks()) == 1  # no drainer was started

    async def test_aclose_flushes_queued_events(self):
        meter = SlowMeter(0.02)
        gateway = DecisionGateway(FakeDecisionModel(), meter=meter)
        for i in range(5):
            await self.decide(gateway, tenant_id=f"t_{i}")
        assert len(meter.records) < 5
        await gateway.aclose()
        assert len(meter.records) == 5
        assert gateway.dropped_events == 0
        await settled()
        assert len(asyncio.all_tasks()) == 1  # the drainer is gone

    async def test_aclose_returns_within_its_bound_with_a_stuck_sink(self):
        meter = GatedMeter()
        gateway = DecisionGateway(
            FakeDecisionModel(), meter=meter, config=GatewayConfig(close_timeout_s=0.1)
        )
        try:
            for i in range(3):
                await self.decide(gateway, tenant_id=f"t_{i}")
                await asyncio.to_thread(meter.entered.wait, 5)
            start = time.monotonic()
            await gateway.aclose()
            elapsed = time.monotonic() - start
            assert 0.1 <= elapsed < 0.6
            assert gateway.dropped_events == 2  # t_1 and t_2 were still queued behind t_0
            await settled()
            assert len(asyncio.all_tasks()) == 1  # the drainer was stopped
        finally:
            meter.gate.set()

    async def test_stuck_sink_and_immortal_orphans_share_one_close_bound(self, immortal, caplog):
        meter = GatedMeter()
        config = GatewayConfig(
            default_budget_s=0.02, cancel_grace_s=0.005, close_timeout_s=0.1, **TINY_CALL
        )
        gateway = DecisionGateway(immortal, meter=meter, config=config)
        try:
            for _ in range(2):  # each timed-out check meters one unanswered attempt
                failed(
                    await gateway.decide(
                        tenant_id="t_x", guard_point="output", input=INPUT, questions=QUESTIONS
                    ),
                    FailureKind.TIMEOUT,
                )
            assert gateway.orphans_in_flight == 2
            start = time.monotonic()
            await gateway.aclose()
            elapsed = time.monotonic() - start
            assert 0.1 <= elapsed < 0.6  # one bound in all, not one for each
            assert gateway.orphans_in_flight == 0
            messages = [r.getMessage() for r in caplog.records]
            assert any("sink still running" in m for m in messages)
            assert any("2 model calls still running" in m for m in messages)
        finally:
            meter.gate.set()

    async def test_events_after_aclose_are_dropped_and_counted_and_checks_still_answer(self):
        meter = SlowMeter(0)
        gateway = DecisionGateway(FakeDecisionModel(), meter=meter)
        await gateway.aclose()
        await gateway.aclose()  # safe to call twice
        assert isinstance(await self.decide(gateway), Answered)
        await gateway.drain()
        assert meter.records == []
        assert gateway.dropped_events == 1

    async def test_gateway_is_an_async_context_manager_that_closes_itself(self):
        meter = SlowMeter(0.02)
        async with DecisionGateway(FakeDecisionModel(), meter=meter) as gateway:
            await self.decide(gateway)
        assert len(meter.records) == 1  # flushed on exit
        await self.decide(gateway)
        assert gateway.dropped_events == 1  # closed

    @pytest.mark.parametrize("kwargs", [{"sink_queue_size": 0}, {"close_timeout_s": -1}])
    def test_config_rejects_nonsense_handoff_settings(self, kwargs):
        with pytest.raises(ValueError):
            GatewayConfig(**kwargs)

    def test_handoff_defaults(self):
        config = GatewayConfig()
        assert config.sink_queue_size == 1024
        assert config.close_timeout_s == 1.0


# ---------------------------------------------------------------------------- admission


def checks(h: Harness, n: int, **kwargs) -> list[asyncio.Task]:
    """Start ``n`` checks at once, as tasks."""
    return [asyncio.ensure_future(h.decide(**kwargs)) for _ in range(n)]


def admission_failure(result, reason: str) -> Failed:
    result = failed(result, FailureKind.UNAVAILABLE)
    assert result.reason == reason, result
    return result


class CountingRule:
    """A custom admission rule: one call in flight, and every ``started`` recorded."""

    def __init__(self) -> None:
        self.inner = InFlightLimit(1)
        self.calls: list[tuple[KeyLoad, int]] = []

    def can_start(self, load):
        return self.inner.can_start(load)

    def predicted_wait_s(self, load, *, ahead, expected_call_s):
        return self.inner.predicted_wait_s(load, ahead=ahead, expected_call_s=expected_call_s)

    def started(self, load, *, input_tokens):
        self.calls.append((load, input_tokens))


class GateRule:
    """Admits calls only while ``open``: lets a test close every slot at will."""

    def __init__(self) -> None:
        self.open = True

    def can_start(self, load):
        return self.open

    def predicted_wait_s(self, load, *, ahead, expected_call_s):
        return 0.0

    def started(self, load, *, input_tokens):
        assert self.open


# Binary-exact admission scenarios: a fixed 0.5 s budget, a fixed 0.25 s expected call, two
# slots, and a queue allowance that lets a call wait as long as the budget leaves (0.25 s).
EXACT = {
    "default_budget_s": 0.5,
    "expected_latency_s": 0.25,
    "max_in_flight_per_key": 2,
    "queue_waits_s": {"output": 0.25},
}
# For scenarios about the queue's mechanics under a roomy fixed budget: a queue allowance
# that never binds (M1-15 bounds every queue wait by the guard point's allowance).
ROOMY_QUEUE = {"output": 60.0, "input": 60.0}


class TestAdmissionControl:
    def test_defaults_are_4_in_flight_and_64_queued_per_key(self):
        # M1-04 as amended by R6.3: the in-flight default is 4 (it was 2).
        config = GatewayConfig()
        assert (config.max_in_flight_per_key, config.max_queued_per_key) == (4, 64)
        assert (DEFAULT_MAX_IN_FLIGHT_PER_KEY, DEFAULT_MAX_QUEUED_PER_KEY) == (4, 64)
        assert DecisionGateway(FakeDecisionModel())._admission.limit == 4
        assert REASON_ADMISSION_WAIT == "admission_wait"
        assert REASON_ADMISSION_QUEUE_FULL == "admission_queue_full"

    @pytest.mark.parametrize("kwargs", [{"max_in_flight_per_key": 0}, {"max_queued_per_key": 0}])
    def test_config_rejects_nonsense_limits(self, kwargs):
        with pytest.raises(ValueError):
            GatewayConfig(**kwargs)

    # ------------------------------------------------------------ limit and queue

    @pytest.mark.parametrize("limit", [1, 2, 3])
    async def test_burst_never_has_more_than_the_limit_in_flight(self, limit):
        # 30 checks at once, each call 100 ms, budgets roomy enough for all to queue.
        h = Harness(
            GatewayConfig(
                max_in_flight_per_key=limit,
                default_budget_s=10.0,
                expected_latency_s=0.1,
                queue_waits_s=ROOMY_QUEUE,
            )
        )
        h.model.latency_s = 0.1
        results = await asyncio.gather(*checks(h, 30))
        assert all(isinstance(r, Answered) for r in results)
        assert h.model.started == 30
        assert h.model.peak == limit
        assert h.elapsed == pytest.approx(0.1 * 30 / limit)
        assert (h.gateway.in_flight(), h.gateway.queued()) == (0, 0)

    async def test_queue_is_first_in_first_out(self):
        h = Harness(
            GatewayConfig(
                max_in_flight_per_key=1,
                default_budget_s=10.0,
                expected_latency_s=0.1,
                queue_waits_s=ROOMY_QUEUE,
            )
        )
        h.model.latency_s = 0.1
        tasks = []
        for name in "abcde":
            tasks.append(asyncio.ensure_future(h.decide(input=name)))
            await asyncio.sleep(0)  # arrive in this order
        await asyncio.gather(*tasks)
        assert h.model.inputs == list("abcde")

    async def test_default_burst_runs_4_and_fails_the_rest_fast(self):
        # Defaults: 4 slots, expected call 628 ms, budget 1,128 ms of which 100 ms is the
        # queue allowance. With 4 calls just started, a fifth predicts 4/4 x 628 = 628 ms of
        # wait: over the budget (628 + 628 > 1,128) and the 100 ms allowance alike. So
        # nothing queues: the burst runs 4 and the rest fail fast.
        h = Harness()
        h.model.latency_s = 0.1
        results = await asyncio.gather(*checks(h, 6))
        assert [isinstance(r, Answered) for r in results] == [True] * 4 + [False] * 2
        for r in results[4:]:
            admission_failure(r, REASON_ADMISSION_WAIT)
        assert h.model.started == 4
        assert h.model.peak == 4
        assert h.elapsed == pytest.approx(0.1)

    # ------------------------------------------------------------ predicted wait

    async def test_predicted_wait_exactly_fitting_the_budget_queues(self):
        # 2 in flight: wait 2/2 x 0.25 = 0.25, + 0.25 = 0.5 = the budget. Queued; served.
        h = Harness(GatewayConfig(**EXACT))
        h.model.latency_s = 0.25
        results = await asyncio.gather(*checks(h, 3))
        assert all(isinstance(r, Answered) for r in results)
        assert h.model.started == 3

    async def test_predicted_wait_over_the_budget_makes_zero_provider_calls(self):
        # The fourth check: wait 3/2 x 0.25 = 0.375, + 0.25 > 0.5. It fails at once.
        h = Harness(GatewayConfig(**EXACT))
        h.model.latency_s = 0.25
        tasks = checks(h, 3)
        await asyncio.sleep(0)
        timed = await h.gateway.decide_timed(
            tenant_id="t_a", guard_point="output", input=INPUT, questions=QUESTIONS
        )
        admission_failure(timed.result, REASON_ADMISSION_WAIT)
        assert "predicted queue wait 375 ms + expected call 250 ms" in timed.result.message
        assert h.elapsed == 0  # failed fast
        assert timed.timing.provider_calls == 0
        await settled()
        assert h.model.started == 2  # only the two in flight; the queued one hasn't started
        await asyncio.gather(*tasks)
        assert h.model.started == 3  # the fourth never called the model

    async def test_budget_running_out_while_queued_removes_the_call_with_zero_calls(self):
        # Two slots, a fixed 0.5 s budget, a 0.125 s expected call. Two calls hang (5 s). A
        # third queues on the prediction (0.125 + 0.125 <= 0.5) but no slot frees; at 0.375 s
        # its remaining budget no longer covers the expected call, so it leaves the queue and
        # fails, before the hung calls time out at 0.5 s.
        h = Harness(
            GatewayConfig(
                max_in_flight_per_key=2,
                default_budget_s=0.5,
                expected_latency_s=0.125,
                queue_waits_s=ROOMY_QUEUE,
            )
        )
        h.model.latency_s = 5.0
        hung = checks(h, 2)
        await asyncio.sleep(0)
        third = asyncio.ensure_future(h.decide())
        await asyncio.sleep(0)
        assert h.gateway.queued() == 1
        result = await third
        admission_failure(result, REASON_ADMISSION_WAIT)
        assert "budget ran out while queued" in result.message
        assert h.elapsed == pytest.approx(0.5 - 0.125)
        assert h.gateway.queued() == 0
        assert h.model.started == 2
        for r in await asyncio.gather(*hung):
            failed(r, FailureKind.TIMEOUT)
        assert h.model.started == 2

    async def test_queued_call_re_predicts_when_the_queue_moves(self):
        # Limit 1, fixed 0.5 s budget, expected 0.1 s. The first call takes 0.3 s. Two
        # checks queue (waits 0.1 and 0.2 predicted). When the first call ends at 0.3 s,
        # the second check starts; the third now predicts 0.1 + 0.1 > 0.2 left and fails at
        # that wake-up, not at its deadline.
        h = Harness(
            GatewayConfig(
                max_in_flight_per_key=1,
                default_budget_s=0.5,
                expected_latency_s=0.1,
                queue_waits_s=ROOMY_QUEUE,
            )
        )
        h.model.slow_next(0.3, 0.3)
        tasks = []
        for _ in range(3):
            tasks.append(asyncio.ensure_future(h.decide()))
            await asyncio.sleep(0)
        first, second, third = await asyncio.gather(*tasks)
        assert isinstance(first, Answered)
        failed(second, FailureKind.TIMEOUT)  # started at 0.3, cut at 0.5
        admission_failure(third, REASON_ADMISSION_WAIT)
        assert h.model.started == 2

    # ------------------------------------------------------------ queue bound

    async def test_full_queue_fails_fast_with_admission_queue_full(self):
        h = Harness(
            GatewayConfig(
                max_in_flight_per_key=2,
                max_queued_per_key=2,
                default_budget_s=10.0,
                queue_waits_s=ROOMY_QUEUE,
            )
        )
        h.model.latency_s = 1.0
        tasks = checks(h, 4)  # 2 in flight, 2 queued: exactly the bound
        await asyncio.sleep(0)
        assert (h.gateway.in_flight(), h.gateway.queued()) == (2, 2)
        timed = await h.gateway.decide_timed(
            tenant_id="t_a", guard_point="output", input=INPUT, questions=QUESTIONS
        )
        admission_failure(timed.result, REASON_ADMISSION_QUEUE_FULL)
        assert h.elapsed == 0
        assert timed.timing.provider_calls == 0
        assert all(isinstance(r, Answered) for r in await asyncio.gather(*tasks))
        assert h.model.started == 4

    # ------------------------------------------------------------ failure shape

    async def test_admission_failure_is_not_retried_and_sleeps_no_jitter(self):
        h = Harness(GatewayConfig(**EXACT, retry_jitter_s=0.02), rng=lambda: 0.5)
        h.model.latency_s = 0.25
        tasks = checks(h, 3)
        await asyncio.sleep(0)
        admission_failure(await h.decide(), REASON_ADMISSION_WAIT)
        assert h.elapsed == 0  # no jitter sleep, no second admission
        await asyncio.gather(*tasks)
        assert h.model.started == 3  # the three earlier checks; the refused one made none

    async def test_admission_failure_is_distinguishable_from_a_provider_timeout(self):
        h = Harness(GatewayConfig(**EXACT))
        h.model.latency_s = 5.0
        tasks = checks(h, 3)  # 2 in flight (they will time out), 1 queued
        await asyncio.sleep(0)
        refused = await h.decide()
        first, second, queued = await asyncio.gather(*tasks)
        assert (refused.kind, refused.reason) == (FailureKind.UNAVAILABLE, "admission_wait")
        assert (queued.kind, queued.reason) == (FailureKind.UNAVAILABLE, "admission_wait")
        for r in (first, second):
            assert (r.kind, r.reason) == (FailureKind.TIMEOUT, None)

    # ------------------------------------------------------------ slots

    async def test_slot_released_after_success(self):
        h = Harness()
        h.model.latency_s = 0.1
        task = asyncio.ensure_future(h.decide())
        await h.vt.sleep(0.05)
        assert h.gateway.in_flight() == 1
        assert isinstance(await task, Answered)
        assert h.gateway.in_flight() == 0

    async def test_slot_released_after_a_provider_failure(self):
        h = Harness()
        h.fake.always(Failed(kind=FailureKind.LIMIT_EXCEEDED))
        failed(await h.decide(), FailureKind.LIMIT_EXCEEDED)
        assert h.gateway.in_flight() == 0

    async def test_slot_released_after_a_timeout(self):
        h = Harness()
        h.model.latency_s = 5.0
        failed(await h.decide(), FailureKind.TIMEOUT)
        await settled()
        assert h.gateway.in_flight() == 0

    async def test_slot_released_when_the_caller_is_cancelled(self):
        h = Harness()
        h.model.latency_s = 0.2
        task = asyncio.ensure_future(h.decide())
        await h.vt.sleep(0.05)
        assert h.gateway.in_flight() == 1
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        await settled()
        assert h.gateway.in_flight() == 0

    async def test_queued_caller_cancelled_leaves_the_queue(self):
        h = Harness(
            GatewayConfig(max_in_flight_per_key=2, default_budget_s=10.0, queue_waits_s=ROOMY_QUEUE)
        )
        h.model.latency_s = 1.0
        tasks = checks(h, 3)
        await asyncio.sleep(0)
        assert h.gateway.queued() == 1
        tasks[2].cancel()
        with pytest.raises(asyncio.CancelledError):
            await tasks[2]
        assert h.gateway.queued() == 0
        await asyncio.gather(*tasks[:2])
        assert h.model.started == 2

    async def test_slot_released_when_the_model_raises_synchronously(self):
        class Raising:
            model_id = "raising"

            def decide(self, input, questions):
                raise RuntimeError("not a coroutine")

        gateway = DecisionGateway(Raising())
        failed(
            await gateway.decide(tenant_id="t_x", guard_point="output", input=INPUT, questions={}),
            FailureKind.OTHER,
        )
        assert gateway.in_flight() == 0

    async def test_orphan_holds_its_slot_until_its_call_ends(self):
        vt = VirtualTime()
        model = StubbornModel(vt.sleep, linger_s=1.0)
        gateway = DecisionGateway(model, clock=vt.now, sleep=vt.sleep)
        result = await gateway.decide(
            tenant_id="t_x", guard_point="output", input=INPUT, questions=QUESTIONS
        )
        failed(result, FailureKind.TIMEOUT)
        assert gateway.orphans_in_flight == 1
        assert gateway.in_flight() == 1  # still holds its slot
        await vt.sleep(1.0)  # the orphan finally ends
        await settled()
        assert (gateway.orphans_in_flight, gateway.in_flight()) == (0, 0)

    async def test_orphans_in_every_slot_stall_the_key_and_checks_fail_fast(self):
        vt = VirtualTime()
        model = StubbornModel(vt.sleep, linger_s=60.0)
        alerts = RecordingAlertSink()
        gateway = DecisionGateway(
            model,
            config=GatewayConfig(warning_interval_s=0, **ONE_ATTEMPT),
            alerts=alerts,
            clock=vt.now,
            sleep=vt.sleep,
        )

        async def check():
            return await gateway.decide(
                tenant_id="t_x", guard_point="output", input=INPUT, questions=QUESTIONS
            )

        limit = DEFAULT_MAX_IN_FLIGHT_PER_KEY
        for _ in range(limit):
            failed(await check(), FailureKind.TIMEOUT)
        assert (gateway.orphans_in_flight, gateway.in_flight()) == (limit, limit)
        before = vt.now_s
        result = admission_failure(await check(), REASON_ADMISSION_WAIT)
        assert "predicted queue wait inf ms" in result.message
        assert vt.now_s == before  # fast: no waiting for a slot that won't come
        assert model.started == limit
        await gateway.drain()
        assert len(alerts.warnings(ALERT_CANCEL_IGNORED)) == limit  # the orphan alert reports it

    async def test_slots_are_per_key(self):
        # Orphans hold every slot of key-v1. After the key is replaced, checks use key-v2's.
        vt = VirtualTime()
        model = StubbornModel(vt.sleep, linger_s=60.0)
        key = ["key-v1"]
        gateway = DecisionGateway(
            model,
            config=GatewayConfig(**ONE_ATTEMPT),
            key_id=lambda: key[0],
            clock=vt.now,
            sleep=vt.sleep,
        )

        async def check():
            return await gateway.decide(
                tenant_id="t_x", guard_point="output", input=INPUT, questions=QUESTIONS
            )

        limit = DEFAULT_MAX_IN_FLIGHT_PER_KEY
        for _ in range(limit):
            failed(await check(), FailureKind.TIMEOUT)
        admission_failure(await check(), REASON_ADMISSION_WAIT)
        key[0] = "key-v2"
        failed(await check(), FailureKind.TIMEOUT)  # it called the model again
        assert model.started == limit + 1
        assert (gateway.in_flight("key-v1"), gateway.in_flight("key-v2")) == (limit, 1)

    # ------------------------------------------------------------ retry

    async def test_retry_goes_to_the_back_of_the_queue(self):
        # Limit 1. Check a's first call fails (unavailable) at 0.1 s; check b queued behind
        # it at 0.05 s. b gets the slot first; a's retry waits behind it.
        h = Harness(
            GatewayConfig(
                max_in_flight_per_key=1,
                default_budget_s=2.0,
                expected_latency_s=0.25,
                queue_waits_s=ROOMY_QUEUE,
            )
        )
        h.model.slow_next(0.1, 0.3, 0.2)
        h.fake.fail_next(FailureKind.UNAVAILABLE)
        a = asyncio.ensure_future(
            h.gateway.decide_timed(
                tenant_id="t_x", guard_point="output", input="a", questions=QUESTIONS
            )
        )
        await h.vt.sleep(0.05)
        b = asyncio.ensure_future(h.decide(input="b"))
        timed_a, result_b = await asyncio.gather(a, b)
        assert isinstance(timed_a.result, Answered)
        assert isinstance(result_b, Answered)
        assert h.model.inputs == ["a", "b", "a"]
        assert timed_a.timing.provider_calls == 2
        assert timed_a.timing.queue_wait_ms == pytest.approx(300)  # b's call, 0.1 to 0.4 s
        assert timed_a.timing.provider_latency_ms == pytest.approx(100 + 200)

    async def test_retry_refused_by_admission_keeps_the_first_result(self):
        # Limit 1, fixed 0.55 s budget, expected 0.25 s. a fails at 0.1 s with 0.45 s left:
        # enough for a retry (0.25), but b took the slot, and the retry predicts 0.25 of
        # wait + 0.25 > 0.45. The retry isn't made; a returns its own failure.
        h = Harness(
            GatewayConfig(
                max_in_flight_per_key=1,
                default_budget_s=0.55,
                expected_latency_s=0.25,
                queue_waits_s=ROOMY_QUEUE,
            )
        )
        h.model.slow_next(0.1, 5.0)
        h.fake.fail_next(FailureKind.UNAVAILABLE)
        a = asyncio.ensure_future(
            h.gateway.decide_timed(
                tenant_id="t_x", guard_point="output", input="a", questions=QUESTIONS
            )
        )
        await h.vt.sleep(0.05)
        b = asyncio.ensure_future(h.decide(input="b"))
        timed_a = await a
        assert timed_a.result == Failed(kind=FailureKind.UNAVAILABLE)
        assert timed_a.timing.provider_calls == 1
        await settled()
        assert h.model.inputs == ["a", "b"]
        failed(await b, FailureKind.TIMEOUT)

    # ------------------------------------------------------------ breaker

    async def test_open_breaker_fails_before_queueing(self):
        # Two slots; a 50 ms expected call keeps c's predicted wait inside the 100 ms queue
        # allowance. a (auth at 0.05 s) and b (hangs) take both slots; c queues. a's auth
        # opens the breaker: c, woken by a's slot coming free, fails with auth and no call,
        # and d, arriving afterwards, fails before it reaches the queue.
        h = Harness(GatewayConfig(max_in_flight_per_key=2, expected_latency_s=0.05))
        h.model.slow_next(0.05, 5.0)
        h.fake.fail_next(FailureKind.AUTH)
        a, b, c = checks(h, 3)
        await asyncio.sleep(0)
        assert h.gateway.queued() == 1
        failed(await a, FailureKind.AUTH)
        failed(await c, FailureKind.AUTH)
        assert h.gateway.breaker_open()
        timed_d = await h.gateway.decide_timed(
            tenant_id="t_x", guard_point="output", input=INPUT, questions=QUESTIONS
        )
        failed(timed_d.result, FailureKind.AUTH)
        assert timed_d.timing.queue_wait_ms == 0
        assert h.gateway.queued() == 0
        assert h.model.started == 2  # a and b only
        failed(await b, FailureKind.TIMEOUT)

    async def test_breaker_probe_uses_a_slot(self):
        h = Harness()
        await h.open_breaker()
        h.vt.advance(5.0)
        h.model.latency_s = 0.1
        probe = asyncio.ensure_future(h.decide())
        await h.vt.sleep(0.05)
        assert h.gateway.in_flight() == 1
        assert isinstance(await probe, Answered)
        assert h.gateway.in_flight() == 0

    async def test_breaker_probe_never_waits_for_a_slot(self):
        rule = GateRule()
        h = Harness(admission=rule)
        await h.open_breaker()
        rule.open = False  # no slot for anyone
        h.vt.advance(5.0)
        before = h.vt.now_s
        result = admission_failure(await h.decide(), REASON_ADMISSION_WAIT)
        assert "breaker probe" in result.message
        assert h.vt.now_s == before
        assert h.model.started == 1
        assert h.gateway.breaker_open()

    # ------------------------------------------------------------ orphan cap ordering

    async def test_orphan_cap_is_checked_before_admission(self, immortal):
        # Cap = the default limit: that many orphans both reach the cap and hold every slot.
        # The check fails with orphan_cap, the earlier of the two fast failures.
        vt = VirtualTime()
        limit = DEFAULT_MAX_IN_FLIGHT_PER_KEY
        gateway = DecisionGateway(
            immortal,
            config=GatewayConfig(max_orphans=limit, **ONE_ATTEMPT),
            clock=vt.now,
            sleep=vt.sleep,
        )

        async def check():
            return await gateway.decide(
                tenant_id="t_x", guard_point="output", input=INPUT, questions=QUESTIONS
            )

        for _ in range(limit):
            failed(await check(), FailureKind.TIMEOUT)
        assert gateway.orphan_capped
        result = failed(await check(), FailureKind.UNAVAILABLE)
        assert result.reason == REASON_ORPHAN_CAP

    async def test_below_the_orphan_cap_a_stalled_key_fails_admission(self, immortal):
        vt = VirtualTime()
        limit = DEFAULT_MAX_IN_FLIGHT_PER_KEY
        gateway = DecisionGateway(
            immortal,
            config=GatewayConfig(max_orphans=limit + 1, **ONE_ATTEMPT),
            clock=vt.now,
            sleep=vt.sleep,
        )

        async def check():
            return await gateway.decide(
                tenant_id="t_x", guard_point="output", input=INPUT, questions=QUESTIONS
            )

        for _ in range(limit):
            failed(await check(), FailureKind.TIMEOUT)
        assert not gateway.orphan_capped
        admission_failure(await check(), REASON_ADMISSION_WAIT)
        assert immortal.started == limit

    # ------------------------------------------------------------ metering

    async def test_queue_wait_and_provider_latency_are_recorded_separately(self):
        # Limit 1: a's call takes 0.3 s; b waits for it, then its own call takes 0.2 s.
        h = Harness(
            GatewayConfig(
                max_in_flight_per_key=1,
                default_budget_s=2.0,
                expected_latency_s=0.25,
                queue_waits_s=ROOMY_QUEUE,
            )
        )
        h.model.slow_next(0.3, 0.2)
        a = asyncio.ensure_future(
            h.gateway.decide_timed(
                tenant_id="t_x", guard_point="output", input="a", questions=QUESTIONS
            )
        )
        await asyncio.sleep(0)
        b = asyncio.ensure_future(
            h.gateway.decide_timed(
                tenant_id="t_x", guard_point="output", input="b", questions=QUESTIONS
            )
        )
        timed_a, timed_b = await asyncio.gather(a, b)
        assert (timed_a.timing.queue_wait_ms, timed_a.timing.provider_latency_ms) == (
            pytest.approx(0),
            pytest.approx(300),
        )
        assert (timed_b.timing.queue_wait_ms, timed_b.timing.provider_latency_ms) == (
            pytest.approx(300),
            pytest.approx(200),
        )
        await h.gateway.drain()
        recorded = h.meter.timings("t_x", "output")
        assert recorded == [pytest.approx((0, 300)), pytest.approx((300, 200))]

    async def test_every_check_records_its_timing_even_a_refused_one(self):
        h = Harness(GatewayConfig(**EXACT))
        h.model.latency_s = 0.25
        tasks = checks(h, 3)
        await asyncio.sleep(0)
        admission_failure(await h.decide(), REASON_ADMISSION_WAIT)
        await asyncio.gather(*tasks)
        await h.gateway.drain()
        timings = h.meter.timings("t_a", "output")
        assert len(timings) == 4
        assert (0, 0) in timings  # the refused check: no wait, no call

    async def test_decide_returns_what_decide_timed_returns(self):
        h = Harness()
        h.fake.set_noul("p__harm", 0.97)
        plain = await h.decide()
        timed = await h.gateway.decide_timed(
            tenant_id="t_a", guard_point="output", input=INPUT, questions=QUESTIONS
        )
        assert plain == timed.result
        assert timed.timing == CheckTiming(
            queue_wait_ms=0, provider_latency_ms=0, provider_calls=1, in_flight_at_start=0
        )

    async def test_meter_without_record_timing_still_works(self):
        class OldMeter:
            def __init__(self):
                self.records = []

            def record(self, tenant_id, guard_point, input_tokens):
                self.records.append(input_tokens)

            def record_unanswered(self, tenant_id, guard_point):
                pass

        meter = OldMeter()
        assert isinstance(meter, UsageMeter) and not isinstance(meter, CheckTimingMeter)
        gateway = DecisionGateway(FakeDecisionModel(), meter=meter)
        result = await gateway.decide(
            tenant_id="t_x", guard_point="output", input=INPUT, questions=QUESTIONS
        )
        assert isinstance(result, Answered)
        await gateway.drain()
        assert len(meter.records) == 1
        assert isinstance(InMemoryUsageMeter(), CheckTimingMeter)

    # ------------------------------------------------------------ the seam

    async def test_admission_rule_is_a_strategy(self):
        rule = CountingRule()
        h = Harness(GatewayConfig(default_budget_s=10.0, queue_waits_s=ROOMY_QUEUE), admission=rule)
        h.model.latency_s = 0.1
        await asyncio.gather(*checks(h, 4))
        assert h.model.peak == 1
        assert len(rule.calls) == 4
        load, tokens = rule.calls[0]
        assert (load.key_id, load.in_flight, load.orphans) == ("key-v1", 0, 0)
        assert tokens == estimate_tokens(INPUT)

    def test_in_flight_limit_prediction(self):
        rule = InFlightLimit(2)
        load = KeyLoad(key_id="k", in_flight=2, orphans=0, now=0.0)
        assert rule.predicted_wait_s(load, ahead=0, expected_call_s=0.3) == pytest.approx(0.3)
        assert rule.predicted_wait_s(load, ahead=1, expected_call_s=0.3) == pytest.approx(0.45)
        one_orphan = KeyLoad(key_id="k", in_flight=2, orphans=1, now=0.0)
        assert rule.predicted_wait_s(one_orphan, ahead=0, expected_call_s=0.3) == 0.3
        all_orphans = KeyLoad(key_id="k", in_flight=2, orphans=2, now=0.0)
        assert rule.predicted_wait_s(all_orphans, ahead=0, expected_call_s=0.3) == float("inf")
        with pytest.raises(ValueError):
            InFlightLimit(0)


# ----------------------------------------------------------------------------
def saturation_pages(alerts: RecordingAlertSink) -> list:
    return [a for a in alerts.pages() if a.kind == ALERT_KEY_SATURATED_BY_ORPHANS]


class TestKeySaturatedByOrphans:
    """Orphans holding every slot of a key block every check on it: page once per crossing."""

    def make(self, model):
        vt = VirtualTime()
        alerts = RecordingAlertSink()
        gateway = DecisionGateway(
            model, config=GatewayConfig(**ONE_ATTEMPT), alerts=alerts, clock=vt.now, sleep=vt.sleep
        )
        return vt, gateway, alerts

    async def check(self, gateway):
        return await gateway.decide(
            tenant_id="t_x", guard_point="output", input=INPUT, questions=QUESTIONS
        )

    async def saturate(self, gateway):
        for _ in range(DEFAULT_MAX_IN_FLIGHT_PER_KEY):
            failed(await self.check(gateway), FailureKind.TIMEOUT)

    async def test_orphans_taking_every_slot_page_once(self, immortal):
        limit = DEFAULT_MAX_IN_FLIGHT_PER_KEY
        _, gateway, alerts = self.make(immortal)
        for _ in range(limit - 1):
            failed(await self.check(gateway), FailureKind.TIMEOUT)
        await gateway.drain()
        assert saturation_pages(alerts) == []  # one slot still usable
        failed(await self.check(gateway), FailureKind.TIMEOUT)
        await gateway.drain()
        [page] = saturation_pages(alerts)
        assert (page.severity, page.key_id, page.count) == (AlertSeverity.PAGE, "default", limit)
        assert page.reason == REASON_ADMISSION_WAIT
        assert ALERT_KEY_SATURATED_BY_ORPHANS == "decision_key_saturated_by_orphans"

    async def test_later_checks_on_the_saturated_key_do_not_page_again(self, immortal):
        _, gateway, alerts = self.make(immortal)
        await self.saturate(gateway)
        for _ in range(3):
            admission_failure(await self.check(gateway), REASON_ADMISSION_WAIT)
        await gateway.drain()
        assert len(saturation_pages(alerts)) == 1
        assert immortal.started == DEFAULT_MAX_IN_FLIGHT_PER_KEY

    async def test_recovery_is_logged_at_info_when_a_slot_frees(self, immortal, caplog):
        caplog.set_level(logging.INFO, logger="guardrail_engine.gateway.gateway")
        _, gateway, _ = self.make(immortal)
        await self.saturate(gateway)
        assert not [r for r in caplog.records if "no longer saturated" in r.getMessage()]
        await immortal.release(1)
        [record] = [r for r in caplog.records if "no longer saturated" in r.getMessage()]
        assert record.levelno == logging.INFO
        assert "'default'" in record.getMessage()
        assert gateway.in_flight() == DEFAULT_MAX_IN_FLIGHT_PER_KEY - 1
        failed(await self.check(gateway), FailureKind.TIMEOUT)  # the model is called again
        assert immortal.started == DEFAULT_MAX_IN_FLIGHT_PER_KEY + 1

    async def test_a_new_crossing_after_recovery_pages_again(self, immortal):
        _, gateway, alerts = self.make(immortal)
        await self.saturate(gateway)
        await immortal.release(1)
        failed(await self.check(gateway), FailureKind.TIMEOUT)  # one more orphan: saturated
        admission_failure(await self.check(gateway), REASON_ADMISSION_WAIT)
        await gateway.drain()
        assert len(saturation_pages(alerts)) == 2

    async def test_orphans_below_the_limit_never_page(self, immortal):
        vt = VirtualTime()
        alerts = RecordingAlertSink()
        gateway = DecisionGateway(
            immortal,
            config=GatewayConfig(
                max_in_flight_per_key=DEFAULT_MAX_IN_FLIGHT_PER_KEY + 1, **ONE_ATTEMPT
            ),
            alerts=alerts,
            clock=vt.now,
            sleep=vt.sleep,
        )
        await self.saturate(gateway)  # 4 orphans of 5 slots
        await gateway.drain()
        assert saturation_pages(alerts) == []


class TestRemainingTimePrediction:
    """In-flight calls are charged max(E - elapsed, 0.1 x E), not a full E."""

    def test_burst_at_time_zero_is_unchanged(self):
        rule = InFlightLimit(2)
        burst = KeyLoad(
            key_id="k", in_flight=2, orphans=0, now=5.0, in_flight_started_at=(5.0, 5.0)
        )
        for ahead in range(4):
            assert rule.predicted_wait_s(burst, ahead=ahead, expected_call_s=0.3) == (
                pytest.approx((2 + ahead) / 2 * 0.3)
            )

    def test_in_flight_calls_are_charged_their_remaining_time(self):
        rule = InFlightLimit(2)
        load = KeyLoad(key_id="k", in_flight=2, orphans=0, now=1.2, in_flight_started_at=(1.0, 1.1))
        # remaining 0.1 and 0.2, plus one queued call ahead (0.3), over 2 slots
        got = rule.predicted_wait_s(load, ahead=1, expected_call_s=0.3)
        assert got == pytest.approx((0.1 + 0.2 + 0.3) / 2)

    def test_a_call_past_its_expected_time_is_charged_the_floor(self):
        rule = InFlightLimit(1)
        load = KeyLoad(key_id="k", in_flight=1, orphans=0, now=9.0, in_flight_started_at=(1.0,))
        assert rule.predicted_wait_s(load, ahead=0, expected_call_s=0.3) == pytest.approx(0.03)

    def test_orphans_are_not_charged(self):
        rule = InFlightLimit(2)
        load = KeyLoad(key_id="k", in_flight=2, orphans=1, now=1.0, in_flight_started_at=(0.9,))
        assert rule.predicted_wait_s(load, ahead=0, expected_call_s=0.3) == pytest.approx(0.2)

    async def test_staggered_arrival_is_admitted_where_a_full_charge_refused(self):
        # Limit 1, fixed 0.45 s budget, expected 0.25 s. a takes 0.3 s from t = 0. b arrives
        # at 0.2 s: a has about 0.05 s left, so b predicts 0.05 + 0.25 <= 0.45 and queues.
        # Charging a full 0.25 for a would predict 0.5 > 0.45 and refuse b.
        h = Harness(
            GatewayConfig(max_in_flight_per_key=1, default_budget_s=0.45, expected_latency_s=0.25)
        )
        h.model.slow_next(0.3, 0.1)
        a = asyncio.ensure_future(h.decide(input="a"))
        await h.vt.sleep(0.2)
        b = await h.decide(input="b")
        assert isinstance(b, Answered)
        assert isinstance(await a, Answered)
        assert h.model.inputs == ["a", "b"]

    @pytest.mark.parametrize(
        ("budget", "message"),
        [
            (0.27, "predicted queue wait 25 ms + expected call 250 ms"),  # 0.275 > 0.27
            (0.28, "budget ran out while queued"),  # 0.275 <= 0.28: it queued
        ],
    )
    async def test_a_call_past_its_expected_time_still_counts_for_the_floor(self, budget, message):
        # a (on input, 2 s budget) hangs; b arrives at 0.4 s, when a is 0.15 s past the
        # expected 0.25 s. a is still charged 0.1 x 0.25 = 0.025 s.
        h = Harness(
            GatewayConfig(
                max_in_flight_per_key=1,
                budgets_s={"input": 2.0, "output": budget},
                expected_latency_s=0.25,
                **ONE_ATTEMPT,
            )
        )
        h.model.slow_next(1.0)
        a = asyncio.ensure_future(h.decide(guard_point="input"))
        await h.vt.sleep(0.4)
        result = admission_failure(await h.decide(guard_point="output"), REASON_ADMISSION_WAIT)
        assert message in result.message
        assert isinstance(await a, Answered)
        assert h.model.started == 1


class TestRefusedProbe:
    async def test_refused_probe_does_not_double_the_back_off(self):
        rule = GateRule()
        h = Harness(admission=rule)
        await h.open_breaker()  # next probe 5 s later
        h.vt.advance(5.0)
        rule.open = False
        admission_failure(await h.decide(), REASON_ADMISSION_WAIT)  # the probe, refused
        rule.open = True
        h.vt.advance(4.5)
        failed(await h.decide(), FailureKind.AUTH)  # still inside the initial delay
        h.vt.advance(0.5)  # 5 s after the refusal, not 10
        assert isinstance(await h.decide(), Answered)
        assert not h.gateway.breaker_open()
        assert h.model.started == 2  # the call that opened the breaker, and the probe

    async def test_after_a_refused_probe_a_failed_probe_doubles_from_the_old_step(self):
        rule = GateRule()
        h = Harness(admission=rule)
        await h.open_breaker()
        h.vt.advance(5.0)
        rule.open = False
        admission_failure(await h.decide(), REASON_ADMISSION_WAIT)
        rule.open = True
        h.vt.advance(5.0)
        h.fake.fail_next(FailureKind.AUTH)
        failed(await h.decide(), FailureKind.AUTH)  # a real probe that fails: 5 -> 10 s
        h.vt.advance(9.5)
        failed(await h.decide(), FailureKind.AUTH)
        assert h.model.started == 2
        h.vt.advance(0.5)
        assert isinstance(await h.decide(), Answered)
        assert h.model.started == 3


# Call sizes: a floor-sized check and a full input check.
FLOOR_SIZED = {"guard_point": "output", "input": tokens_of_input(4_000), "questions": questions(12)}
INPUT_SIZED = {
    "guard_point": "input",
    "input": tokens_of_input(16_000),
    "questions": questions(200),
}


class TestOwnExpectedLatency:
    """With mixed call sizes on one key, each in-flight and queued call is charged its own
    expected latency, not the newcomer's. Defaults: a floor-sized check (4K input, 12
    questions) expects 0.675 s with a 1.18 s budget; a full input check (16K, 200
    questions) expects 1.18 s with a 2.0 s budget. The scenario tests use two slots, lifted
    caps and a 1 s queue allowance, so the prediction is what decides (M1-15's default
    allowances would refuse every one of these waits)."""

    MIXED = GatewayConfig(
        max_in_flight_per_key=2,
        budget_cap_s=5.0,
        input_budget_cap_s=5.0,
        queue_waits_s={"output": 1.0, "input": 1.0},
    )

    def test_in_flight_calls_are_charged_their_own_expected_time(self):
        rule = InFlightLimit(2)
        load = KeyLoad(
            key_id="k",
            in_flight=2,
            orphans=0,
            now=0.1,
            in_flight_started_at=(0.0, 0.0),
            in_flight_expected_s=(0.8, 0.8),
        )
        # 0.7 left on each, over 2 slots; the newcomer's own E (0.295) plays no part
        assert rule.predicted_wait_s(load, ahead=0, expected_call_s=0.295) == pytest.approx(0.7)

    def test_queued_calls_ahead_are_charged_their_own_expected_time(self):
        rule = InFlightLimit(1)
        load = KeyLoad(
            key_id="k",
            in_flight=1,
            orphans=0,
            now=0.0,
            in_flight_started_at=(0.0,),
            in_flight_expected_s=(0.3,),
            queued_ahead_expected_s=(0.8,),
        )
        assert rule.predicted_wait_s(load, ahead=1, expected_call_s=0.2) == pytest.approx(1.1)

    def test_floor_burst_at_time_zero_is_unchanged(self):
        rule = InFlightLimit(2)
        load = KeyLoad(
            key_id="k",
            in_flight=2,
            orphans=0,
            now=0.0,
            in_flight_started_at=(0.0, 0.0),
            in_flight_expected_s=(0.295, 0.295),
            queued_ahead_expected_s=(0.295,),
        )
        got = rule.predicted_wait_s(load, ahead=1, expected_call_s=0.295)
        assert got == pytest.approx(3 / 2 * 0.295)

    def test_the_defaults_give_the_reviewers_expected_latencies(self):
        # M1-15: R6.3 after U7 (380 ms time-window allowance; caps 3 s, 4 s on input).
        config = GatewayConfig()
        small = {"input_tokens": 4_000, "question_count": 12}
        large = {"input_tokens": 16_000, "question_count": 200}
        assert config.expected_p50_for(**small) == pytest.approx(0.675)
        assert config.budget_for("output", **small) == pytest.approx(3.000)
        assert config.expected_p50_for(**large) == pytest.approx(1.180)
        assert config.budget_for("input", **large) == pytest.approx(4.000)

    async def test_floor_check_after_two_input_checks_is_refused_fast(self):
        # Two input checks (1.18 s each) start at 0. A floor check at 0.1 s: they have
        # 1.08 s left each, so it predicts 1.08 s of wait, over its 1 s queue allowance, and
        # fails at once. Charged its own 0.675 s each, they'd predict 0.575 s and queue it.
        h = Harness(self.MIXED)
        h.model.slow_next(1.18, 1.18)
        large = [asyncio.ensure_future(h.decide(**INPUT_SIZED)) for _ in range(2)]
        await h.vt.sleep(0.1)
        result = admission_failure(await h.decide(**FLOOR_SIZED), REASON_ADMISSION_WAIT)
        assert "predicted queue wait 1080 ms exceeds the remaining queue allowance 1000 ms" in (
            result.message
        )
        assert h.elapsed == pytest.approx(0.1)  # fast
        assert h.model.started == 2
        assert all(isinstance(r, Answered) for r in await asyncio.gather(*large))

    async def test_input_check_after_two_floor_checks_is_admitted(self):
        # Two floor checks (0.675 s each) start at 0. An input check at 0.1 s predicts
        # 0.575 s <= 1 s and queues; charging the floor calls its own 1.18 s would predict
        # 1.08 s and refuse it. It starts at 0.675 s and is answered.
        h = Harness(self.MIXED)
        h.model.slow_next(0.675, 0.675, 0.5)
        small = [asyncio.ensure_future(h.decide(**FLOOR_SIZED)) for _ in range(2)]
        await h.vt.sleep(0.1)
        timed = await h.gateway.decide_timed(tenant_id="t_a", **INPUT_SIZED)
        assert isinstance(timed.result, Answered)
        assert timed.timing.queue_wait_ms == pytest.approx(575)
        assert timed.timing.provider_latency_ms == pytest.approx(500)
        assert all(isinstance(r, Answered) for r in await asyncio.gather(*small))
        assert h.model.started == 3

    async def test_a_queued_floor_check_ahead_is_charged_its_own_time(self):
        # Two floor checks in flight and a third queued, all from 0. An input check at
        # 0.1 s predicts (0.575 + 0.575 + 0.675) / 2 = 0.9125 s <= 1 s and queues. Charging
        # the queued floor check 1.18 s would predict 1.165 s and refuse it.
        h = Harness(self.MIXED)
        h.model.slow_next(0.675, 0.675, 0.675, 0.3)
        small = [asyncio.ensure_future(h.decide(**FLOOR_SIZED)) for _ in range(3)]
        await asyncio.sleep(0)
        assert h.gateway.queued() == 1
        await h.vt.sleep(0.1)
        result = await h.decide(**INPUT_SIZED)
        assert isinstance(result, Answered)
        assert all(isinstance(r, Answered) for r in await asyncio.gather(*small))
        assert h.model.started == 4


class TimeRule:
    """Admits calls only from clock time ``at`` on: capacity that returns with time alone."""

    def __init__(self, at: float) -> None:
        self.at = at

    def can_start(self, load):
        return load.now >= self.at

    def predicted_wait_s(self, load, *, ahead, expected_call_s):
        return max(0.0, self.at - load.now) + ahead * expected_call_s

    def started(self, load, *, input_tokens):
        assert load.now >= self.at

    def next_start_at(self, load):
        return self.at if load.now < self.at else None


class TestNextStartAt:
    async def test_waiter_wakes_when_a_time_based_rule_has_capacity(self):
        h = Harness(
            GatewayConfig(default_budget_s=1.0, queue_waits_s=ROOMY_QUEUE),
            admission=TimeRule(T0 + 0.125),
        )
        result = await h.decide()
        assert isinstance(result, Answered)
        assert h.elapsed == pytest.approx(0.125)  # woken at that time, not at its deadline

    async def test_queued_behind_a_time_based_rule_all_start_in_order(self):
        h = Harness(
            GatewayConfig(default_budget_s=2.0, expected_latency_s=0.25, queue_waits_s=ROOMY_QUEUE),
            admission=TimeRule(T0 + 0.5),
        )
        h.model.latency_s = 0.1
        tasks = []
        for name in "abc":
            tasks.append(asyncio.ensure_future(h.decide(input=name)))
            await asyncio.sleep(0)
        results = await asyncio.gather(*tasks)
        assert all(isinstance(r, Answered) for r in results)
        assert h.model.inputs == list("abc")
        assert h.elapsed == pytest.approx(0.6)

    def test_in_flight_limit_names_no_time(self):
        load = KeyLoad(key_id="k", in_flight=2, orphans=0, now=0.0)
        assert InFlightLimit(2).next_start_at(load) is None

    async def test_rules_without_next_start_at_still_work(self):
        rule = GateRule()
        assert not hasattr(rule, "next_start_at")
        h = Harness(admission=rule)
        assert isinstance(await h.decide(), Answered)


# ---------------------------------------------------------------------------- real time


class TestRealTime:
    """The default clock and sleep, against the fake's own scripted latency."""

    async def decide(self, gateway):
        return await gateway.decide(
            tenant_id="t_x", guard_point="output", input=INPUT, questions=QUESTIONS
        )

    async def test_real_deadline_cancels_slow_fake_and_returns_failed_timeout(self):
        fake = FakeDecisionModel(latency_s=5.0)
        gateway = DecisionGateway(fake, config=GatewayConfig(default_budget_s=0.05, **TINY_CALL))
        start = time.monotonic()
        result = await self.decide(gateway)
        elapsed = time.monotonic() - start
        failed(result, FailureKind.TIMEOUT)
        assert 0.04 <= elapsed < 1.0
        await settled()
        assert fake.calls == []  # cancelled mid-call: the fake records only completed calls
        assert gateway.orphaned_calls == 0  # the fake honours cancellation
        assert len(asyncio.all_tasks()) == 1

    async def test_real_slow_first_call_then_fast_call_inside_budget(self):
        fake = FakeDecisionModel().slow_next(0.02)
        config = GatewayConfig(default_budget_s=0.5, expected_latency_s=0.1)
        gateway = DecisionGateway(fake, config=config)
        assert isinstance(await self.decide(gateway), Answered)
        assert len(fake.calls) == 1

    async def test_real_defaults_retry_a_fast_unavailable_once(self):
        fake = FakeDecisionModel().fail_next(FailureKind.UNAVAILABLE)
        gateway = DecisionGateway(fake)
        assert isinstance(await self.decide(gateway), Answered)
        assert len(fake.calls) == 2

    async def test_real_slow_unavailable_is_not_retried(self):
        # Budget 100 ms, expected latency 80 ms; the failure arrives after 50 ms.
        fake = FakeDecisionModel().slow_next(0.05).fail_next(FailureKind.UNAVAILABLE)
        config = GatewayConfig(default_budget_s=0.1, expected_latency_s=0.08)
        failed(await self.decide(DecisionGateway(fake, config=config)), FailureKind.UNAVAILABLE)
        assert len(fake.calls) == 1
