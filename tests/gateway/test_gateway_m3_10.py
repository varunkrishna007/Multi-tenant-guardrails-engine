"""M3-10: the per-project token-rate limiter, the daily request counter (rolling at midnight
Pacific) and the monthly spend tracker, in the Decision Gateway.

Everything runs on the virtual clock from ``test_gateway``, with a fake model: no real sleeps,
no live calls. The wall clock the Pacific day and month roll on is a second injected clock that
follows the virtual one.
"""

import asyncio
import math
from datetime import UTC, datetime, timedelta

import pytest
from test_gateway import (  # noqa: F401  (close_gateways is an autouse fixture)
    QUESTIONS,
    T0,
    VirtualTime,
    close_gateways,
)

from guardrail_engine.decision import Answered, Failed, FailureKind, FakeDecisionModel
from guardrail_engine.decision.types import Usage
from guardrail_engine.engine import EngineSettings, SettingsError
from guardrail_engine.gateway import (
    ALERT_DAILY_REQUESTS,
    ALERT_MONTHLY_SPEND,
    ALERT_TOKEN_RATE_FAIL_FAST,
    CAPACITY_REASONS,
    CAUSE_BUCKET,
    CAUSE_DAILY_REQUESTS,
    CAUSE_MONTHLY_SPEND,
    REASON_QUOTA_EXHAUSTED,
    REASON_TOKEN_RATE,
    TESTED_FLAT_OCCUPANCY,
    TIER_LIMITS,
    AlertSeverity,
    DecisionGateway,
    FailFastWindow,
    GatewayConfig,
    InMemoryUsageMeter,
    InProcessTokenRateStore,
    RecordingAlertSink,
    TimedDecision,
    TokenRateConfig,
    TokenRateMeter,
    TokenRateStore,
    pacific_day_key,
    pacific_month_key,
)
from guardrail_engine.gateway.token_rate import (
    seconds_until_pacific_midnight,
    seconds_until_pacific_month_start,
)
from guardrail_engine.sdk import FailureReason, failure_reason_of

PROJECT = "proj-a"
MINUTE = 60.0


def text(tag: int, words: int = 100) -> str:
    """An input of a fixed size, tagged so each call can be told apart."""
    return f"{tag:04d} " + "word " * words


class TokenModel:
    """A fake model on virtual time. It records when each call started and with which input,
    and answers with ``actual(estimate)`` input tokens (``None``: no usage block)."""

    model_id = "token-virtual"

    def __init__(self, vt: VirtualTime, *, latency_s: float = 0.0, actual=None) -> None:
        self.vt = vt
        self.fake = FakeDecisionModel()
        self.latency_s = latency_s
        self.actual = actual  # an int, None for no usage, or a callable of the call's tokens
        self.starts: list[tuple[float, str]] = []
        self.estimate = 0

    @property
    def started(self) -> int:
        return len(self.starts)

    async def decide(self, input, questions):
        self.starts.append((self.vt.now_s, input))
        if self.latency_s > 0:
            await self.vt.sleep(self.latency_s)
        answered = await self.fake.decide(input, questions)
        if not isinstance(answered, Answered):
            return answered
        actual = self.actual(self.estimate) if callable(self.actual) else self.actual
        usage = None if actual is None else Usage(total_input_tokens=actual)
        return answered.model_copy(update={"usage": usage})


class Wall:
    """The wall clock: an aware datetime that follows the virtual clock, plus a skew a test can
    set to jump hours or days."""

    def __init__(self, vt: VirtualTime, start: datetime) -> None:
        self.vt, self.start, self.skew = vt, start, timedelta(0)

    def __call__(self) -> datetime:
        return self.start + timedelta(seconds=self.vt.now_s - T0) + self.skew


def estimate_of(input: str, questions=QUESTIONS) -> int:
    big = TokenRateConfig(tier="tier_3", tokens_per_minute=10_000_000, burst_capacity_s=60)
    from guardrail_engine.gateway import TokenRateLimiter

    return TokenRateLimiter(big, InProcessTokenRateStore()).estimate_for_input(input, questions)


def config_for(tokens: int, seconds_per_call: float, **kwargs) -> TokenRateConfig:
    """A project config whose bucket refills one call of ``tokens`` every ``seconds_per_call``."""
    settings = {"tier": "tier_3", "project_id": PROJECT}
    settings.update(kwargs)
    burst = settings.get("burst_capacity_s", 5.0)
    tpm = math.ceil(tokens * (60 + burst) / (seconds_per_call * TESTED_FLAT_OCCUPANCY))
    return TokenRateConfig(tokens_per_minute=tpm, **settings)


class Rig:
    def __init__(
        self,
        config: TokenRateConfig,
        *,
        model_kwargs=None,
        gateway_config: GatewayConfig | None = None,
        wall_start: datetime | None = None,
        store: TokenRateStore | None = None,
        gateways: int = 1,
        input: str | None = None,
    ) -> None:
        self.vt = VirtualTime()
        self.input = text(0) if input is None else input
        self.estimate = estimate_of(self.input)
        self.wall = Wall(self.vt, wall_start or datetime(2026, 6, 15, 12, 0, tzinfo=UTC))
        self.config = config
        self.store = store or InProcessTokenRateStore()
        self.models: list[TokenModel] = []
        self.meters: list[InMemoryUsageMeter] = []
        self.sinks: list[RecordingAlertSink] = []
        self.gateways: list[DecisionGateway] = []
        gconfig = gateway_config or GatewayConfig(max_in_flight_per_key=64)
        gconfig = GatewayConfig(
            **{**gconfig.__dict__, "token_rate": config}  # same settings, limiter on
        )
        for _ in range(gateways):
            model = TokenModel(self.vt, **(model_kwargs or {}))
            model.estimate = self.estimate
            meter, sink = InMemoryUsageMeter(), RecordingAlertSink()
            self.models.append(model)
            self.meters.append(meter)
            self.sinks.append(sink)
            self.gateways.append(
                DecisionGateway(
                    model,
                    config=gconfig,
                    meter=meter,
                    alerts=sink,
                    key_id=lambda: "key-1",
                    clock=self.vt.now,
                    sleep=self.vt.sleep,
                    rng=lambda: 0.0,
                    rate_store=self.store,
                    wall_clock=self.wall,
                )
            )

    @property
    def gateway(self) -> DecisionGateway:
        return self.gateways[0]

    @property
    def model(self) -> TokenModel:
        return self.models[0]

    @property
    def meter(self) -> InMemoryUsageMeter:
        return self.meters[0]

    @property
    def alerts(self) -> RecordingAlertSink:
        return self.sinks[0]

    @property
    def limiter(self):
        limiter = self.gateway.token_rate_limiter
        assert limiter is not None
        return limiter

    def bucket(self) -> dict:
        return {
            "now": self.vt.now_s,
            "rate_per_s": self.config.rate_per_s,
            "capacity": self.config.capacity,
        }

    def level(self) -> float:
        return self.store.level(PROJECT, **self.bucket())

    def drain_bucket(self, leave: float = 0.0) -> None:
        """Empty the bucket (as if calls had just used it), leaving ``leave`` tokens."""
        level = self.level()
        assert self.store.acquire(PROJECT, level - leave, **self.bucket()) == pytest.approx(0.0)

    async def check(
        self, guard_point="output", input=None, tenant_id="t_a", gateway=0
    ) -> TimedDecision:
        return await self.gateways[gateway].decide_timed(
            tenant_id=tenant_id,
            guard_point=guard_point,
            input=self.input if input is None else input,
            questions=QUESTIONS,
        )

    def start(self, guard_point="output", input=None, tenant_id="t_a", gateway=0):
        return asyncio.ensure_future(self.check(guard_point, input, tenant_id, gateway))

    async def drain(self) -> None:
        for gateway in self.gateways:
            await gateway.drain()


def token_rate_failure(
    timed: TimedDecision, cause_text: str | None = None, reason: str = REASON_TOKEN_RATE
) -> Failed:
    result = timed.result
    assert isinstance(result, Failed), result
    assert result.kind is FailureKind.UNAVAILABLE
    assert result.reason == reason
    assert timed.capacity_limited is True
    assert timed.timing.provider_calls == 0
    if cause_text is not None:
        assert cause_text in (result.message or "")
    return result


def quota_failure(timed: TimedDecision, cause_text: str | None = None) -> Failed:
    """A refusal at the daily request cap or the monthly spend cap."""
    return token_rate_failure(timed, cause_text, reason=REASON_QUOTA_EXHAUSTED)


# ------------------------------------------------------------------------------ settings


class TestSettings:
    def test_defaults(self):
        c = TokenRateConfig()
        assert c.tokens_per_minute == 1_000_000
        assert c.target_fraction == 0.68 == TESTED_FLAT_OCCUPANCY
        assert c.requests_per_day == 50_000
        assert c.requests_per_minute == 1_500  # Tier 1's published requests a minute
        assert c.monthly_spend_cap_usd == 250
        assert c.price_per_million_input_tokens_usd == 0.10
        assert c.burst_tested_at is None
        assert c.rate_per_s == pytest.approx(1_000_000 * 0.68 / 65)  # target / (60 + burst)

    @pytest.mark.parametrize(
        ("kwargs", "fragment"),
        [
            ({"tokens_per_minute": 0}, "tokens_per_minute must be positive"),
            ({"tokens_per_minute": -5}, "tokens_per_minute must be positive"),
            ({"tokens_per_minute": 1_000_001}, "above the tier_1 limit"),
            ({"tokens_per_minute": 4_000_001, "tier": "tier_2"}, "above the tier_2 limit"),
            ({"requests_per_day": 50_001}, "requests_per_day"),
            ({"requests_per_day": 0}, "requests_per_day must be positive"),
            ({"requests_per_minute": 1_501}, "requests_per_minute"),
            ({"requests_per_minute": 0}, "requests_per_minute must be positive"),
            ({"requests_per_minute": 5_001, "tier": "tier_2"}, "above the tier_2 limit"),
            ({"monthly_spend_cap_usd": 0}, "monthly_spend_cap_usd must be positive"),
            ({"monthly_spend_cap_usd": 251}, "above the tier_1 cap"),
            ({"price_per_million_input_tokens_usd": 0}, "price_per_million"),
            ({"target_fraction": 0}, "target_fraction must be positive"),
            ({"target_fraction": 0.69}, "above the highest occupancy tested flat"),
            ({"target_fraction": 0.9}, "above the highest occupancy tested flat"),
            ({"target_fraction": 0.9, "burst_tested_at": 0.8}, "above the highest occupancy"),
            ({"target_fraction": 1.5, "burst_tested_at": 1.0}, "at most 1"),
            ({"burst_tested_at": 1.5}, "burst_tested_at must be in"),
            ({"tier": "tier_9"}, "tier must be one of"),
            ({"tokens_per_minute": 1.5}, "whole number"),
            ({"target_fraction": float("nan")}, "target_fraction"),
        ],
    )
    def test_invalid_settings_are_refused(self, kwargs, fragment):
        with pytest.raises(ValueError, match=fragment):
            TokenRateConfig(**kwargs)

    def test_a_higher_target_needs_a_burst_test_at_least_that_high(self):
        assert TokenRateConfig(target_fraction=0.9, burst_tested_at=0.9).target_fraction == 0.9
        assert TokenRateConfig(target_fraction=0.75, burst_tested_at=0.8).target_fraction == 0.75
        # a test below the default doesn't lower the ceiling: 68% was tested flat already
        assert TokenRateConfig(target_fraction=0.68, burst_tested_at=0.5).target_fraction == 0.68

    def test_published_tier_limits_match_the_capacity_model(self):
        from capacity.model import TIERS

        by_name = {t.name.lower().replace(" ", "_"): t for t in TIERS}
        assert set(TIER_LIMITS) == set(by_name)
        for name, limits in TIER_LIMITS.items():
            assert limits.tokens_per_minute == by_name[name].tpm
            assert limits.requests_per_day == by_name[name].rpd
            assert limits.requests_per_minute == by_name[name].rpm
            assert limits.monthly_cap_usd == by_name[name].monthly_cap_usd

    def test_engine_settings_carry_the_project_quota(self):
        loaded = EngineSettings.from_mapping(
            {"token_rate": {"tokens_per_minute": 500_000, "requests_per_day": 20_000}}
        )
        assert loaded.token_rate is not None
        assert loaded.token_rate.tokens_per_minute == 500_000
        assert loaded.token_rate.target_fraction == 0.68
        assert loaded.effective_token_rate() == loaded.token_rate

    def test_the_default_is_on_outside_test_and_off_in_test(self):
        assert EngineSettings().effective_token_rate() == TokenRateConfig()  # production
        assert EngineSettings(environment="staging").effective_token_rate() == TokenRateConfig()
        assert EngineSettings(environment="test").effective_token_rate() is None
        explicit = TokenRateConfig(tokens_per_minute=100_000)
        assert (
            EngineSettings(environment="test", token_rate=explicit).effective_token_rate()
            == explicit
        )

    @pytest.mark.parametrize(
        "bad",
        [
            {"tokens_per_minute": 2_000_000},
            {"target_fraction": 0.9},
            {"tokens_per_minute": 0},
            {"nonsense": 1},
        ],
    )
    def test_engine_settings_refuse_a_bad_quota_at_startup(self, bad):
        with pytest.raises(SettingsError) as error:
            EngineSettings.from_mapping({"token_rate": bad})
        assert "token_rate" in str(error.value)

    def test_the_failure_reason_is_the_sdks_token_rate(self):
        assert REASON_TOKEN_RATE in CAPACITY_REASONS
        assert (
            failure_reason_of("model_failure", "unavailable", "token_rate", capacity_limited=True)
            is FailureReason.TOKEN_RATE
        )

    def test_the_in_process_store_meets_the_port(self):
        assert isinstance(InProcessTokenRateStore(), TokenRateStore)

    async def test_a_gateway_uses_only_the_ports_operations(self):
        class Spy(InProcessTokenRateStore):
            def __init__(self) -> None:
                super().__init__()
                self.used: set[str] = set()

            def acquire(self, *a, **k):
                self.used.add("acquire")
                return super().acquire(*a, **k)

            def level(self, *a, **k):
                self.used.add("level")
                return super().level(*a, **k)

            def adjust(self, *a, **k):
                self.used.add("adjust")
                return super().adjust(*a, **k)

            def count_request(self, *a, **k):
                self.used.add("count_request")
                return super().count_request(*a, **k)

            def requests(self, *a, **k):
                self.used.add("requests")
                return super().requests(*a, **k)

            def add_spend(self, *a, **k):
                self.used.add("add_spend")
                return super().add_spend(*a, **k)

            def spend(self, *a, **k):
                self.used.add("spend")
                return super().spend(*a, **k)

        spy = Spy()
        rig = Rig(
            TokenRateConfig(project_id=PROJECT),
            store=spy,
            model_kwargs={"actual": lambda e: e - 1},
        )
        assert isinstance((await rig.check()).result, Answered)
        assert {"acquire", "count_request", "add_spend", "adjust", "requests", "spend"} <= spy.used


# ------------------------------------------------------------ the bucket under sustained load


async def offer(rig: Rig, *, every_s: float, until_s: float, guard_point="input") -> list:
    """Offer one call every ``every_s`` virtual seconds until ``until_s`` has passed (spread
    over the rig's gateways), without waiting for each to finish."""
    tasks = []
    i = 0
    while rig.vt.now_s - T0 < until_s:
        tasks.append(
            rig.start(
                guard_point, input=f"{i % 10000:04d}" + rig.input[4:], gateway=i % len(rig.gateways)
            )
        )
        i += 1
        await rig.vt.sleep(every_s)
    return [await t for t in tasks]


def admitted_between(rig: Rig, lo_s: float, hi_s: float) -> int:
    """Tokens reserved by the provider calls that started in [lo, hi) seconds."""
    calls = sum(lo_s <= t - T0 < hi_s for model in rig.models for t, _ in model.starts)
    return calls * rig.estimate


class TestSustainedLoad:
    """Offered load above the target is held at the target (+-2%). The first seconds are
    left out: a full bucket may spend its burst once."""

    TOKENS = estimate_of(text(0, 800))

    async def run(self, gateways: int):
        # one call's worth every 0.4 s: 6.25 calls' tokens a second against 2.5 offered... the
        # offer is 10 calls a second, four times the refill
        config = config_for(self.TOKENS, 0.4, burst_capacity_s=5.0)
        rig = Rig(config, gateways=gateways, input=text(0, 800))
        assert rig.estimate == self.TOKENS
        results = await offer(rig, every_s=0.1, until_s=400)
        await rig.drain()
        return rig, results

    @pytest.mark.parametrize("gateways", [1, 2])
    async def test_offered_load_is_held_at_the_target(self, gateways):
        rig, results = await self.run(gateways)
        lo, hi = 60.0, 360.0
        admitted = admitted_between(rig, lo, hi)
        target = rig.config.rate_per_s * (hi - lo)
        assert admitted == pytest.approx(target, rel=0.02)
        # the rest were refused at the gateway, with no provider call
        refused = [r for r in results if isinstance(r.result, Failed)]
        assert refused
        for r in refused:
            token_rate_failure(r)
        assert len(results) - len(refused) == sum(m.started for m in rig.models)

    async def test_two_gateways_sharing_the_store_stay_within_the_limit(self):
        rig, _ = await self.run(2)
        started = [m.started for m in rig.models]
        assert all(n > 0 for n in started)  # both really served calls
        # Over any one minute, even with the bucket full at its start, the project is held
        # to the target plus one burst: well under the quota's 100%.
        for minute in range(0, 6):
            lo = minute * MINUTE
            tokens = admitted_between(rig, lo, lo + MINUTE)
            assert tokens <= rig.config.tokens_per_minute * TESTED_FLAT_OCCUPANCY + (
                rig.config.capacity
            )
        # Two private stores would each have admitted the full target.
        total = admitted_between(rig, 60.0, 360.0)
        assert total < 1.05 * rig.config.rate_per_s * 300


# ----------------------------------------------------------------- the burst bound


class TestBurstBound:
    def test_a_full_bucket_plus_a_minute_of_refill_is_exactly_the_target(self):
        for burst in (1.0, 5.0, 30.0):
            c = TokenRateConfig(burst_capacity_s=burst)
            target = c.tokens_per_minute * c.target_fraction
            assert c.rate_per_s * 60 + c.capacity == pytest.approx(target)
            assert c.capacity == pytest.approx(c.rate_per_s * burst)

    async def test_no_minute_carries_more_than_the_target_even_from_a_full_bucket(self):
        # Ten times the refill is offered from the start, with the bucket full. In every
        # 60-second window, the tokens admitted stay at or under tokens_per_minute x target:
        # 68% of the quota, not 73.7%.
        e = estimate_of(text(0, 800))
        config = config_for(e, 0.4, burst_capacity_s=5.0)
        rig = Rig(config, input=text(0, 800))
        assert rig.estimate == e
        await offer(rig, every_s=0.04, until_s=240)
        target = config.tokens_per_minute * config.target_fraction
        starts = [t - T0 for model in rig.models for t, _ in model.starts]
        assert starts == sorted(starts)
        worst = 0
        for lo in range(len(starts)):
            hi = lo
            while hi < len(starts) and starts[hi] < starts[lo] + 60.0:
                hi += 1
            worst = max(worst, (hi - lo) * e)
        assert worst <= target + 1  # the bound holds, the first minute (full bucket) included
        first_minute = sum(t < 60.0 for t in starts) * e
        assert first_minute > 0.95 * target  # and it is used: the limiter isn't just closed


# -------------------------------------------------------------------- waiting and failing


class TestWaitThenFail:
    async def test_a_call_that_fits_in_the_allowance_waits_for_the_refill(self):
        rig = Rig(config_for(estimate_of(text(0)), 0.08))
        rig.drain_bucket()
        timed = await rig.check("output")  # 100 ms allowance, one call's tokens = 80 ms
        assert isinstance(timed.result, Answered)
        assert rig.model.starts[0][0] - T0 == pytest.approx(0.08, abs=1e-3)
        assert timed.timing.queue_wait_ms == pytest.approx(80, abs=1)
        assert timed.timing.provider_calls == 1

    async def test_a_call_that_cannot_fit_the_allowance_fails_fast_with_no_provider_call(self):
        rig = Rig(config_for(estimate_of(text(0)), 0.5))
        rig.drain_bucket()
        timed = await rig.check("output")
        token_rate_failure(timed, "token_rate")
        assert timed.timing.queue_wait_ms == 0
        assert rig.vt.now_s == T0  # failed fast
        assert rig.model.started == 0
        assert timed.retry_after_ms == 500  # the bucket's refill time for its tokens
        await rig.drain()
        assert rig.meter.token_rate_fail_fasts(PROJECT, cause=CAUSE_BUCKET) == 1
        assert rig.meter.token_rate_fail_fasts(PROJECT, tenant_id="t_a") == 1

    async def test_the_retry_hint_is_clamped_like_every_hint(self):
        rig = Rig(config_for(estimate_of(text(0)), 20.0, burst_capacity_s=60.0))  # a 20 s refill
        rig.drain_bucket()
        timed = await rig.check("input", gateway=0)
        token_rate_failure(timed)
        assert timed.retry_after_ms == 10_000  # clamped to R8's maximum
        quick = Rig(config_for(estimate_of(text(0)), 0.5))
        quick.drain_bucket(leave=quick.estimate - 0.01 * quick.config.rate_per_s)
        assert (await quick.check("output")).result.__class__ is Answered  # 10 ms wait: served
        assert quick.model.starts[0][0] - T0 == pytest.approx(0.01, abs=1e-3)

    async def test_a_call_waits_in_the_queue_and_then_fails_when_others_take_its_turn(self):
        # Empty bucket, one call's tokens per 80 ms. A tool_result call (allowance 250 ms
        # here) predicts 80 ms and waits. At 50 ms three input checks arrive and go in front
        # of it: its turn is now 300 ms away. It has waited, and it now fails with no call.
        queue_waits = {"input": 0.30, "tool_result": 0.25, "output": 0.1}
        rig = Rig(
            config_for(estimate_of(text(0)), 0.08),
            gateway_config=GatewayConfig(max_in_flight_per_key=64, queue_waits_s=queue_waits),
        )
        rig.drain_bucket()
        late = rig.start("tool_result", input=text(9))
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        assert not late.done()
        await rig.vt.sleep(0.05)
        inputs = [rig.start("input", input=text(i + 1)) for i in range(3)]
        failed = await late
        token_rate_failure(failed, "token_rate")
        assert failed.timing.queue_wait_ms == pytest.approx(50, abs=1)
        assert failed.timing.provider_calls == 0
        served = [await t for t in inputs]
        assert all(isinstance(s.result, Answered) for s in served)
        assert [inp for _, inp in rig.model.starts] == [text(1), text(2), text(3)]  # not text(9)

    async def test_the_allowance_per_guard_point_applies(self):
        # A 250 ms wait fits input (300 ms) and tool_result (400 ms), not the critical path.
        for guard_point, fits in [
            ("input", True),
            ("tool_result", True),
            ("output", False),
            ("plan", False),
            ("tool_call", False),
        ]:
            rig = Rig(config_for(estimate_of(text(0)), 0.25))
            rig.drain_bucket()
            timed = await rig.check(guard_point)
            if fits:
                assert isinstance(timed.result, Answered), guard_point
            else:
                token_rate_failure(timed)

    async def test_the_gateway_ends_as_the_sdk_expects(self):
        rig = Rig(config_for(estimate_of(text(0)), 5.0))
        rig.drain_bucket()
        timed = await rig.check("output")
        failure = token_rate_failure(timed)
        assert (
            failure_reason_of("model_failure", "unavailable", failure.reason, capacity_limited=True)
            is FailureReason.TOKEN_RATE
        )

    async def test_the_in_flight_limit_still_applies_with_the_limiter_on(self):
        rig = Rig(
            config_for(estimate_of(text(0)), 0.01),
            gateway_config=GatewayConfig(
                max_in_flight_per_key=1, expected_latency_s=0.05, queue_waits_s={"input": 0.3}
            ),
            model_kwargs={"latency_s": 0.05},
        )
        first, second = rig.start("input", text(1)), rig.start("input", text(2))
        assert isinstance((await first).result, Answered)
        assert isinstance((await second).result, Answered)
        assert [t - T0 for t, _ in rig.model.starts] == pytest.approx([0.0, 0.05], abs=1e-6)


class TestPriority:
    async def test_input_and_output_before_plan_and_tool_call_before_tool_result(self):
        queue_waits = {gp: 2.0 for gp in ("input", "plan", "tool_call", "tool_result", "output")}
        rig = Rig(
            config_for(estimate_of(text(0)), 0.08),
            gateway_config=GatewayConfig(max_in_flight_per_key=64, queue_waits_s=queue_waits),
        )
        rig.drain_bucket()
        arrivals = [
            ("tool_result", 1),
            ("plan", 2),
            ("input", 3),
            ("tool_call", 4),
            ("output", 5),
            ("tool_result", 6),
            ("input", 7),
        ]
        tasks = []
        for guard_point, tag in arrivals:
            tasks.append(rig.start(guard_point, input=text(tag)))
            await asyncio.sleep(0)
        done = [await t for t in tasks]
        assert all(isinstance(d.result, Answered) for d in done)
        order = [int(inp[:4]) for _, inp in rig.model.starts]
        # input and output (first come first served among themselves), then plan and
        # tool_call, then tool_result
        assert order == [3, 5, 7, 2, 4, 1, 6]
        starts = [t - T0 for t, _ in rig.model.starts]
        assert starts == sorted(starts)
        assert starts[0] == pytest.approx(0.08, abs=1e-3)  # one refill apart from then on
        assert starts[-1] == pytest.approx(0.56, abs=1e-3)

    async def test_a_draft_test_waits_behind_every_guard_point_in_the_same_bucket(self):
        """M2-05, decided 2026-11-17: a test call reserves from the project's bucket like a check
        but queues in a fourth class below tool_result, however early it arrived."""
        queue_waits = {gp: 5.0 for gp in ("input", "plan", "tool_call", "tool_result", "output")}
        rig = Rig(
            config_for(estimate_of(text(0)), 0.08),
            gateway_config=GatewayConfig(max_in_flight_per_key=64, queue_waits_s=queue_waits),
        )
        rig.drain_bucket()

        def go(guard_point, tag, usage_class="check"):
            return asyncio.ensure_future(
                rig.gateway.decide_timed(
                    tenant_id="t_a", guard_point=guard_point, input=text(tag),
                    questions=QUESTIONS, usage_class=usage_class,
                )
            )  # fmt: skip

        tasks = []
        for task in (go("input", 1, "test"), go("tool_result", 2), go("plan", 3), go("input", 4)):
            tasks.append(task)
            await asyncio.sleep(0)
        done = [await t for t in tasks]
        assert all(isinstance(d.result, Answered) for d in done)
        order = [int(inp[:4]) for _, inp in rig.model.starts]
        assert order == [4, 3, 2, 1]  # input, plan, tool_result, and the test call last
        from guardrail_engine.gateway.token_rate import PRIORITY_BY_GUARD_POINT, TEST_PRIORITY

        assert max(PRIORITY_BY_GUARD_POINT.values()) < TEST_PRIORITY

    async def test_without_the_limiter_the_queue_stays_first_come_first_served(self):
        vt = VirtualTime()
        model = TokenModel(vt, latency_s=0.05)
        gateway = DecisionGateway(
            model,
            config=GatewayConfig(max_in_flight_per_key=1, queue_waits_s={"input": 5, "output": 5}),
            clock=vt.now,
            sleep=vt.sleep,
        )

        async def check(guard_point, tag):
            return await gateway.decide(
                tenant_id="t", guard_point=guard_point, input=text(tag), questions=QUESTIONS
            )

        tasks = [
            asyncio.ensure_future(check(gp, tag))
            for tag, gp in enumerate(["output", "tool_result", "input", "output"], start=1)
        ]
        await asyncio.gather(*tasks)
        assert [int(i[:4]) for _, i in model.starts] == [1, 2, 3, 4]
        await gateway.aclose()


# ------------------------------------------------------------------------- reconciliation


class TestReconciliation:
    async def test_a_reservation_is_corrected_downward_from_actual_usage(self):
        rig = Rig(
            config_for(estimate_of(text(0)), 1.0, burst_capacity_s=60.0),
            model_kwargs={"actual": lambda e: e // 2},
        )
        capacity = rig.config.capacity
        assert isinstance((await rig.check()).result, Answered)
        await rig.drain()
        assert rig.level() == pytest.approx(capacity - rig.estimate // 2)
        assert rig.meter.reserved_tokens(PROJECT) == rig.estimate
        assert rig.meter.actual_tokens(PROJECT) == rig.estimate // 2

    async def test_a_reservation_is_corrected_upward_when_the_call_used_more(self):
        rig = Rig(
            config_for(estimate_of(text(0)), 1.0, burst_capacity_s=60.0),
            model_kwargs={"actual": lambda e: e * 2},
        )
        capacity = rig.config.capacity
        await rig.check()
        assert rig.level() == pytest.approx(capacity - 2 * rig.estimate)

    async def test_unknown_usage_keeps_the_reservation(self):
        rig = Rig(
            config_for(estimate_of(text(0)), 1.0, burst_capacity_s=60.0),
            model_kwargs={"actual": None},
        )
        capacity = rig.config.capacity
        assert isinstance((await rig.check()).result, Answered)
        await rig.drain()
        assert rig.level() == pytest.approx(capacity - rig.estimate)
        assert rig.meter.reservations_kept(PROJECT) == 1
        assert rig.meter.actual_tokens(PROJECT) == 0

    async def test_a_timed_out_call_keeps_the_reservation(self):
        rig = Rig(
            config_for(estimate_of(text(0)), 1.0, burst_capacity_s=60.0),
            model_kwargs={"latency_s": 60.0},
            gateway_config=GatewayConfig(max_in_flight_per_key=64, budget_margin_s=60.0),
        )
        capacity = rig.config.capacity
        timed = await rig.check()
        assert isinstance(timed.result, Failed) and timed.result.kind is FailureKind.TIMEOUT
        assert rig.level() == pytest.approx(capacity - rig.estimate, abs=rig.estimate * 4)
        assert rig.store.requests(PROJECT, pacific_day_key(rig.wall())) == 1

    async def test_a_correction_that_frees_tokens_wakes_a_waiting_call(self):
        # The first call reserves its estimate, takes 20 ms, and reports half of it: the
        # refund lets a waiter through before the refill would have.
        rig = Rig(
            config_for(estimate_of(text(0)), 0.25, burst_capacity_s=0.25),
            model_kwargs={"latency_s": 0.02, "actual": lambda e: e // 4},
        )
        first = rig.start("input", text(1))
        await rig.vt.sleep(0.01)
        second = rig.start("input", text(2))
        await first
        await second
        starts = [t - T0 for t, _ in rig.model.starts]
        assert starts[0] == 0.0
        # one call's tokens take 250 ms to refill; the second call started soon after the
        # refund at 20 ms, long before that
        assert starts[1] < 0.1

    async def test_spend_is_actual_tokens_times_price(self):
        rig = Rig(
            config_for(estimate_of(text(0)), 1.0, price_per_million_input_tokens_usd=0.10),
            model_kwargs={"actual": 100},
        )
        for _ in range(3):
            await rig.check()
        month = pacific_month_key(rig.wall())
        assert rig.store.spend(PROJECT, month) == pytest.approx(3 * 100 * 0.10 / 1e6)


# ---------------------------------------------------------------- daily requests (Pacific)


class TestPacificPeriods:
    def test_the_day_rolls_at_midnight_pacific_not_utc(self):
        # 2026-06-16 00:30 UTC is still 17:30 on June 15 in Pacific daylight time
        assert pacific_day_key(datetime(2026, 6, 16, 0, 30, tzinfo=UTC)) == "2026-06-15"
        assert pacific_day_key(datetime(2026, 6, 16, 6, 59, 59, tzinfo=UTC)) == "2026-06-15"
        assert pacific_day_key(datetime(2026, 6, 16, 7, 0, tzinfo=UTC)) == "2026-06-16"
        # in winter midnight Pacific is 08:00 UTC
        assert pacific_day_key(datetime(2026, 12, 16, 7, 59, 59, tzinfo=UTC)) == "2026-12-15"
        assert pacific_day_key(datetime(2026, 12, 16, 8, 0, tzinfo=UTC)) == "2026-12-16"

    def test_a_day_is_23_hours_when_the_clocks_go_forward(self):
        # 2026-03-08: PST until 02:00. Midnight on the 8th is 08:00 UTC; on the 9th, 07:00 UTC.
        start = datetime(2026, 3, 8, 8, 0, tzinfo=UTC)
        assert seconds_until_pacific_midnight(start) == 23 * 3600
        assert pacific_day_key(datetime(2026, 3, 8, 7, 59, tzinfo=UTC)) == "2026-03-07"
        assert pacific_day_key(start) == "2026-03-08"
        assert pacific_day_key(datetime(2026, 3, 9, 6, 59, 59, tzinfo=UTC)) == "2026-03-08"
        assert pacific_day_key(datetime(2026, 3, 9, 7, 0, tzinfo=UTC)) == "2026-03-09"

    def test_a_day_is_25_hours_when_the_clocks_go_back(self):
        # 2026-11-01: PDT until 02:00. Midnight on the 1st is 07:00 UTC; on the 2nd, 08:00 UTC.
        start = datetime(2026, 11, 1, 7, 0, tzinfo=UTC)
        assert seconds_until_pacific_midnight(start) == 25 * 3600
        assert pacific_day_key(datetime(2026, 11, 1, 6, 59, tzinfo=UTC)) == "2026-10-31"
        assert pacific_day_key(datetime(2026, 11, 2, 7, 59, 59, tzinfo=UTC)) == "2026-11-01"
        assert pacific_day_key(datetime(2026, 11, 2, 8, 0, tzinfo=UTC)) == "2026-11-02"

    def test_the_month_rolls_on_the_1st_pacific(self):
        assert pacific_month_key(datetime(2026, 12, 1, 7, 59, tzinfo=UTC)) == "2026-11"
        assert pacific_month_key(datetime(2026, 12, 1, 8, 0, tzinfo=UTC)) == "2026-12"
        # the 1st of March: midnight is 08:00 UTC (PST); the 1st of April: 07:00 UTC (PDT)
        assert pacific_month_key(datetime(2026, 4, 1, 6, 59, tzinfo=UTC)) == "2026-03"
        assert pacific_month_key(datetime(2026, 4, 1, 7, 0, tzinfo=UTC)) == "2026-04"
        assert seconds_until_pacific_month_start(datetime(2026, 12, 1, 8, 0, tzinfo=UTC)) == (
            31 * 86400
        )


class TestDailyRequests:
    def rig(self, start: datetime, **kwargs) -> Rig:
        config = TokenRateConfig(project_id=PROJECT, requests_per_day=10, **kwargs)
        return Rig(config, wall_start=start, model_kwargs={"actual": 100})

    async def test_alerts_at_80_and_100_percent_then_calls_fail_fast_until_midnight_pacific(self):
        rig = self.rig(datetime(2026, 6, 15, 12, 0, tzinfo=UTC))  # 05:00 Pacific
        for _ in range(1, 8):
            assert isinstance((await rig.check()).result, Answered)
        await rig.drain()
        assert rig.alerts.alerts == []
        await rig.check()  # the 8th: 80%
        await rig.drain()
        [warning] = rig.alerts.alerts
        assert (warning.kind, warning.severity) == (ALERT_DAILY_REQUESTS, AlertSeverity.WARNING)
        assert warning.reason == "threshold_80"
        # The counters are per process, and the alert says so
        assert "restart at zero after a restart" in warning.message
        assert "billing" in warning.message
        await rig.check()
        await rig.check()  # the 10th: 100%
        await rig.drain()
        page = rig.alerts.pages()[0]
        assert (page.kind, page.reason) == (ALERT_DAILY_REQUESTS, "threshold_100")
        assert len(rig.alerts.alerts) == 2  # once per crossing, not per call

        started = rig.model.started
        refused = await rig.check()
        quota_failure(refused, "requests a day")
        assert rig.model.started == started  # no provider call
        # not clamped to 10 s: the time until midnight Pacific, 19 hours from 05:00
        assert refused.retry_after_ms == pytest.approx(19 * 3600 * 1000, abs=1000)
        await rig.drain()
        assert rig.meter.token_rate_fail_fasts(PROJECT, cause=CAUSE_DAILY_REQUESTS) == 1

        # 07:00 UTC is midnight Pacific in June: the count starts again
        rig.wall.skew = timedelta(hours=19) - timedelta(seconds=1)
        assert isinstance((await rig.check()).result, Failed)  # 06:59:59 UTC: same day
        rig.wall.skew += timedelta(seconds=1)
        assert isinstance((await rig.check()).result, Answered)
        assert rig.store.requests(PROJECT, "2026-06-16") == 1

    async def test_it_does_not_roll_at_utc_midnight(self):
        rig = self.rig(datetime(2026, 6, 15, 23, 59, 50, tzinfo=UTC))  # 16:59 Pacific
        for _ in range(10):
            await rig.check()
        rig.wall.skew = timedelta(seconds=30)  # 00:00:20 UTC on the 16th, 17:00 Pacific
        quota_failure(await rig.check())
        assert rig.model.started == 10

    async def test_the_count_rolls_across_the_spring_forward_day(self):
        # 2026-03-08 is 23 hours long: it ends at 07:00 UTC on the 9th, not 08:00.
        rig = self.rig(datetime(2026, 3, 8, 8, 0, tzinfo=UTC))  # 00:00 PST on the 8th
        for _ in range(10):
            await rig.check()
        quota_failure(await rig.check())
        rig.wall.skew = timedelta(hours=22, minutes=59, seconds=58)  # 06:59:58 UTC on the 9th
        quota_failure(await rig.check())
        rig.wall.skew = timedelta(hours=23)  # 07:00 UTC: midnight PDT
        assert isinstance((await rig.check()).result, Answered)
        assert rig.store.requests(PROJECT, "2026-03-09") == 1

    async def test_the_count_rolls_across_the_fall_back_day(self):
        # 2026-11-01 is 25 hours long: it ends at 08:00 UTC on the 2nd.
        rig = self.rig(datetime(2026, 11, 1, 7, 0, tzinfo=UTC))  # 00:00 PDT on the 1st
        for _ in range(10):
            await rig.check()
        rig.wall.skew = timedelta(hours=24, minutes=59, seconds=58)  # 07:59:58 UTC on the 2nd
        quota_failure(await rig.check())
        rig.wall.skew = timedelta(hours=25)  # 08:00 UTC: midnight PST
        assert isinstance((await rig.check()).result, Answered)
        assert rig.store.requests(PROJECT, "2026-11-02") == 1

    async def test_a_retry_counts_as_a_request(self):
        rig = self.rig(datetime(2026, 6, 15, 12, 0, tzinfo=UTC))
        rig.model.fake.fail_next(FailureKind.UNAVAILABLE)
        assert isinstance((await rig.check()).result, Answered)  # the retry answered
        assert rig.store.requests(PROJECT, "2026-06-15") == 2


class TestMonthlySpend:
    def rig(self, start: datetime, **model_kwargs) -> Rig:
        # $10 per million tokens and a $0.01 cap: a call of ~1,000 tokens costs $0.01/10 ...
        # so size the calls to 300 tokens: four calls pass 100%, the third passes 80%.
        config = TokenRateConfig(
            project_id=PROJECT,
            monthly_spend_cap_usd=0.01,
            price_per_million_input_tokens_usd=10.0,
            tokens_per_minute=1_000_000,
        )
        return Rig(config, wall_start=start, model_kwargs={"actual": 300, **model_kwargs})

    async def test_alerts_at_80_and_100_percent_then_calls_fail_fast_until_the_1st(self):
        rig = self.rig(datetime(2026, 11, 20, 12, 0, tzinfo=UTC))
        spent = lambda: rig.store.spend(PROJECT, "2026-11")  # noqa: E731
        for _ in range(2):
            await rig.check()
        await rig.drain()
        assert rig.alerts.alerts == []
        await rig.check()  # 3 x 300 tokens x $10/M = $0.009: 90% of $0.01
        await rig.drain()
        [warning] = rig.alerts.alerts
        assert (warning.kind, warning.severity) == (ALERT_MONTHLY_SPEND, AlertSeverity.WARNING)
        assert spent() == pytest.approx(0.009)
        await rig.check()  # $0.012: over the cap
        await rig.drain()
        assert [a.severity for a in rig.alerts.alerts] == [
            AlertSeverity.WARNING,
            AlertSeverity.PAGE,
        ]
        assert rig.alerts.alerts[1].reason == "threshold_100"
        started = rig.model.started
        refused = await rig.check()
        quota_failure(refused, "monthly spend cap")
        # the time until 08:00 UTC on December 1st from 12:00 UTC on November 20th, unclamped
        assert refused.retry_after_ms == pytest.approx((10 * 24 + 20) * 3600 * 1000, abs=1000)
        assert rig.model.started == started
        await rig.drain()
        assert rig.meter.token_rate_fail_fasts(PROJECT, cause=CAUSE_MONTHLY_SPEND) == 1

        # 08:00 UTC on December 1st is midnight Pacific (winter): the month rolls
        rig.wall.skew = datetime(2026, 12, 1, 7, 59, 59, tzinfo=UTC) - rig.wall.start
        quota_failure(await rig.check())
        rig.wall.skew = datetime(2026, 12, 1, 8, 0, tzinfo=UTC) - rig.wall.start
        assert isinstance((await rig.check()).result, Answered)
        assert rig.store.spend(PROJECT, "2026-12") == pytest.approx(0.003)

    async def test_the_estimate_is_replaced_by_actual_usage_in_the_total(self):
        rig = self.rig(datetime(2026, 11, 20, 12, 0, tzinfo=UTC))
        await rig.check()
        # 300 tokens actual, whatever the estimate was
        assert rig.store.spend(PROJECT, "2026-11") == pytest.approx(300 * 10 / 1e6)

    async def test_in_flight_calls_count_before_they_return(self):
        rig = self.rig(datetime(2026, 11, 20, 12, 0, tzinfo=UTC), latency_s=1.0)
        task = rig.start()
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        assert rig.store.spend(PROJECT, "2026-11") == pytest.approx(rig.estimate * 10 / 1e6)
        await task
        assert rig.store.spend(PROJECT, "2026-11") == pytest.approx(300 * 10 / 1e6)


class TestNeverSentIsNotCounted:
    """A call the gateway reserved for but never sent is not a request."""

    async def test_a_model_that_cannot_be_called_gives_the_reservation_back_and_counts_nothing(
        self,
    ):
        class Broken:
            model_id = "broken"

            def decide(self, input, questions):  # not a coroutine: raises before anything is sent
                raise RuntimeError("no call was made")

        rig = Rig(config_for(estimate_of(text(0)), 1.0, burst_capacity_s=60.0))
        gateway = rig.gateway
        gateway._model = Broken()  # the model of the rig's gateway, swapped for one that raises
        before = rig.level()
        timed = await rig.check()
        assert isinstance(timed.result, Failed)  # the gateway's own error, nothing sent
        assert timed.timing.provider_calls == 0
        assert rig.store.requests(PROJECT, pacific_day_key(rig.wall())) == 0
        assert rig.level() == pytest.approx(before)  # tokens back
        assert rig.store.spend(PROJECT, pacific_month_key(rig.wall())) == pytest.approx(0.0)

    async def test_a_sent_call_counts_once(self):
        rig = Rig(config_for(estimate_of(text(0)), 1.0, burst_capacity_s=60.0))
        await rig.check()
        assert rig.store.requests(PROJECT, pacific_day_key(rig.wall())) == 1


# ------------------------------------------------------------------------- meters, alerts


class TestFailFastAlert:
    def test_the_window_is_a_strict_one_tenth_of_one_percent_over_five_minutes(self):
        window = FailFastWindow()
        for i in range(1000):
            window.note_check(float(i) * 0.1)
        window.note_fail_fast(100.0)
        assert not window.exceeded(100.0)  # 1 in 1,000 is 0.1%, not more
        window.note_check(100.0)
        window.note_fail_fast(100.0)
        assert window.exceeded(100.0)  # 2 in 1,001
        # five minutes later the window is empty again
        assert not window.exceeded(100.0 + 301)
        assert window.totals(100.0 + 301) == (0, 0)

    async def test_one_alert_per_excursion_and_it_rearms(self):
        rig = Rig(config_for(estimate_of(text(0)), 30.0, burst_capacity_s=150.0))
        for _ in range(5):
            assert isinstance((await rig.check("input")).result, Answered)  # in the burst
        rig.drain_bucket()
        token_rate_failure(await rig.check("output"))
        token_rate_failure(await rig.check("output"))
        await rig.drain()
        alerts = [a for a in rig.alerts.alerts if a.kind == ALERT_TOKEN_RATE_FAIL_FAST]
        assert len(alerts) == 1  # not one per fail-fast
        assert alerts[0].severity is AlertSeverity.WARNING
        assert PROJECT in alerts[0].message
        # more than five minutes later, with calls that pass, the excursion is over ...
        await rig.vt.sleep(400.0)
        assert isinstance((await rig.check("input")).result, Answered)
        # ... and a new one raises a new alert
        rig.drain_bucket()
        token_rate_failure(await rig.check("output"))
        await rig.drain()
        alerts = [a for a in rig.alerts.alerts if a.kind == ALERT_TOKEN_RATE_FAIL_FAST]
        assert len(alerts) == 2

    async def test_a_rare_fail_fast_among_many_checks_raises_no_alert(self):
        rig = Rig(
            config_for(estimate_of(text(0)), 0.2, burst_capacity_s=30.0),
            model_kwargs={"actual": 1},
        )
        window = rig.limiter.window
        for _ in range(1500):
            window.note_check(rig.vt.now_s)
        rig.drain_bucket()
        token_rate_failure(await rig.check("output", input=text(1)))
        await rig.drain()
        assert [a for a in rig.alerts.alerts if a.kind == ALERT_TOKEN_RATE_FAIL_FAST] == []

    async def test_reserved_and_actual_tokens_are_metered_per_project(self):
        rig = Rig(config_for(estimate_of(text(0)), 1.0), model_kwargs={"actual": 100})
        assert isinstance(rig.meter, TokenRateMeter)
        for _ in range(3):
            await rig.check("input")
        await rig.drain()
        assert rig.meter.reserved_tokens(PROJECT) == 3 * rig.estimate
        assert rig.meter.actual_tokens(PROJECT) == 300
        assert rig.meter.reserved_tokens("other-project") == 0


class TestBareGateway:
    async def test_without_a_token_rate_config_nothing_changes(self):
        vt = VirtualTime()
        model = TokenModel(vt)
        gateway = DecisionGateway(model, clock=vt.now, sleep=vt.sleep)
        assert gateway.token_rate_limiter is None
        result = await gateway.decide(
            tenant_id="t", guard_point="output", input=text(1), questions=QUESTIONS
        )
        assert isinstance(result, Answered)
        await gateway.aclose()
