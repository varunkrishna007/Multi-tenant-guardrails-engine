"""M3-07 per-tenant quotas and fair scheduling, and M3-08 per-consumer non-production
allowances (M0-03 (c)), in the Decision Gateway.

Everything runs on the virtual clock from ``test_gateway`` with a fake model: no real sleeps,
no live calls. The wall clock the Pacific day rolls on is a second injected clock that follows
the virtual one.
"""

import asyncio
import dataclasses
import math
from datetime import UTC, datetime, timedelta

import pytest
from test_gateway import (  # noqa: F401  (close_gateways is an autouse fixture)
    QUESTIONS,
    T0,
    VirtualTime,
    close_gateways,
)
from test_gateway_m3_10 import (
    PROJECT,
    TokenModel,
    Wall,
    config_for,
    estimate_of,
    quota_failure,
    text,
    token_rate_failure,
)

from guardrail_engine.decision import Answered, Failed, FailureKind
from guardrail_engine.engine import EngineSettings, SettingsError
from guardrail_engine.gateway import (
    ALERT_CONSUMER_ALLOWANCE,
    ALERT_TENANT_DAILY_QUOTA,
    ALERT_TENANT_QUOTA,
    ALERT_TOKEN_RATE_FAIL_FAST,
    CAUSE_CONSUMER,
    CAUSE_TENANT_CHECKS,
    CAUSE_TENANT_DAILY,
    CAUSE_TENANT_TOKENS,
    DEFAULT_NON_PRODUCTION,
    DEFAULT_TIER_QUOTAS,
    NON_PRODUCTION_CONSUMERS,
    REASON_ADMISSION_QUEUE_FULL,
    REASON_ADMISSION_WAIT,
    TEST_PRIORITY,
    USAGE_CHECK,
    USAGE_PRODUCTION,
    AlertSeverity,
    ConsumerAllowances,
    DecisionGateway,
    FairClock,
    GatewayConfig,
    InMemoryUsageMeter,
    InProcessTokenRateStore,
    QuotaConfig,
    QuotaMeter,
    RecordingAlertSink,
    TierQuota,
    TimedDecision,
    TokenRateConfig,
    TokenRateStore,
    consumer_of,
    pacific_month_key,
    resolve_usage_class,
    usage_class,
)
from guardrail_engine.gateway.token_rate import seconds_until_pacific_month_start
from guardrail_engine.sdk import FailureReason, failure_reason_of

BIG = TokenRateConfig(tier="tier_3", tokens_per_minute=10_000_000, project_id=PROJECT)
"""A project quota nothing here comes near, so only the tenant shares bind."""
GENEROUS = TierQuota(
    weight=1, tokens_per_minute=10**9, checks_per_minute=10**7, requests_per_day=10**9
)
"""A share nothing here comes near, so only the fair order binds."""
LONG_QUEUE = {
    "queue_waits_s": {gp: 60.0 for gp in ("input", "plan", "tool_call", "tool_result", "output")},
    "budget_cap_s": 120.0,
    "input_budget_cap_s": 120.0,
}
SERIAL = {"max_in_flight_per_key": 1, **LONG_QUEUE}


def tiers(**by_name: TierQuota) -> dict[str, TierQuota]:
    return {"standard": GENEROUS, **by_name}


class QRig:
    """A gateway (or several, sharing a store) with M3-07's quotas on a virtual clock."""

    def __init__(
        self,
        quotas: QuotaConfig | None,
        *,
        project: TokenRateConfig | None = None,
        gateway_kwargs=None,
        model_kwargs=None,
        wall_start: datetime | None = None,
        store: TokenRateStore | None = None,
        gateways: int = 1,
        input: str | None = None,
    ) -> None:
        self.vt = VirtualTime()
        self.input = text(0) if input is None else input
        self.estimate = estimate_of(self.input)
        self.wall = Wall(self.vt, wall_start or datetime(2026, 6, 15, 12, 0, tzinfo=UTC))
        self.project = project
        self.store = store or InProcessTokenRateStore()
        self.models: list[TokenModel] = []
        self.meters: list[InMemoryUsageMeter] = []
        self.sinks: list[RecordingAlertSink] = []
        self.gateways: list[DecisionGateway] = []
        gconfig = GatewayConfig(
            **{"max_in_flight_per_key": 64, "sink_queue_size": 10**6, **(gateway_kwargs or {})},
            token_rate=project,
            quotas=quotas,
        )
        for _ in range(gateways):
            model = TokenModel(self.vt, **{"actual": lambda e: e, **(model_kwargs or {})})
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
        limiter = self.gateway.quota_limiter
        assert limiter is not None
        return limiter

    def project_level(self) -> float:
        assert self.project is not None
        return self.store.level(
            PROJECT,
            now=self.vt.now_s,
            rate_per_s=self.project.rate_per_s,
            capacity=self.project.capacity,
        )

    def drain_project(self) -> None:
        assert self.project is not None
        level = self.project_level()
        wait = self.store.acquire(
            PROJECT,
            level,
            now=self.vt.now_s,
            rate_per_s=self.project.rate_per_s,
            capacity=self.project.capacity,
        )
        assert wait == pytest.approx(0.0)

    def status(self, tenant_id="t_a", tier=None):
        return self.limiter.status(tenant_id, tier, now=self.vt.now_s)

    async def check(
        self,
        guard_point="output",
        input=None,
        tenant_id="t_a",
        tier=None,
        usage_class=None,
        gateway=0,
    ) -> TimedDecision:
        return await self.gateways[gateway].decide_timed(
            tenant_id=tenant_id,
            guard_point=guard_point,
            input=self.input if input is None else input,
            questions=QUESTIONS,
            tier=tier,
            usage_class=usage_class or USAGE_CHECK,
        )

    def start(self, guard_point="output", input=None, tenant_id="t_a", tier=None, usage_class=None):
        return asyncio.ensure_future(
            self.check(guard_point, input, tenant_id, tier, usage_class, 0)
        )

    async def drain(self) -> None:
        for gateway in self.gateways:
            await gateway.drain()

    def starts_of(self, lo_s: float, hi_s: float) -> int:
        return sum(lo_s <= t - T0 < hi_s for t, _ in self.model.starts)


async def drive(rig: QRig, plans: list[dict], until_s: float) -> dict[str, list[TimedDecision]]:
    """Offer each plan's load at once: ``{"tenant_id", "every_s", "guard_point"?, "tier"?,
    "usage_class"?}`` starts a check every ``every_s`` virtual seconds until ``until_s``.
    Returns the results by tenant (or consumer, for a non-production plan)."""
    tasks: dict[str, list[asyncio.Future]] = {}

    async def offer(plan: dict) -> None:
        name = plan.get("usage_class") or plan["tenant_id"]
        i = 0
        while rig.vt.now_s - T0 < until_s:
            tasks.setdefault(name, []).append(
                rig.start(
                    plan.get("guard_point", "input"),
                    input=f"{i % 10000:04d}" + rig.input[4:],
                    tenant_id=plan["tenant_id"],
                    tier=plan.get("tier"),
                    usage_class=plan.get("usage_class"),
                )
            )
            i += 1
            await rig.vt.sleep(plan["every_s"])

    await asyncio.gather(*(offer(plan) for plan in plans))
    return {name: [await t for t in ts] for name, ts in tasks.items()}


def percentile(values: list[float], q: float) -> float:
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(q * len(ordered)))] if ordered else 0.0


def answered(results: list[TimedDecision]) -> list[TimedDecision]:
    return [r for r in results if isinstance(r.result, Answered)]


def refused(results: list[TimedDecision]) -> list[TimedDecision]:
    return [r for r in results if isinstance(r.result, Failed)]


# ------------------------------------------------------------------------------ settings


class TestSettings:
    def test_defaults_are_valid_and_tiered(self):
        c = QuotaConfig()
        assert set(c.tiers) == {"standard", "regulated", "dedicated"}
        weights = [c.tiers[t].weight for t in ("standard", "regulated", "dedicated")]
        assert weights == sorted(weights) and len(set(weights)) == 3
        assert c.tiers == DEFAULT_TIER_QUOTAS
        assert set(c.non_production) == set(NON_PRODUCTION_CONSUMERS)
        assert sum(DEFAULT_NON_PRODUCTION.values()) < 1  # room left for production
        assert c.limits_for("t_x", "regulated") == DEFAULT_TIER_QUOTAS["regulated"]
        assert c.limits_for("t_x", None) == DEFAULT_TIER_QUOTAS["standard"]
        assert c.limits_for("t_x", "no_such_tier") == DEFAULT_TIER_QUOTAS["standard"]

    def test_a_tenant_override_replaces_its_tiers_share(self):
        vip = TierQuota(weight=8, tokens_per_minute=5, checks_per_minute=60, requests_per_day=7)
        c = QuotaConfig(overrides={"t_vip": vip})
        assert c.limits_for("t_vip", "standard") is vip
        assert c.limits_for("t_other", "standard") == DEFAULT_TIER_QUOTAS["standard"]

    def test_an_override_weight_is_at_most_eight_times_the_largest_tier_weight(self):
        """The default tiers' largest weight is 4, so an override may reach 32."""
        assert QuotaConfig(overrides={"t_vip": TierQuota(weight=32)}).limits_for("t_vip", None)
        with pytest.raises(ValueError, match=r"overrides\['t_vip'\] weight 33 is above 32"):
            QuotaConfig(overrides={"t_vip": TierQuota(weight=33)})
        with pytest.raises(ValueError, match="weight 1000 is above 32"):
            QuotaConfig(overrides={"t_vip": TierQuota(weight=1000)})
        # the cap follows the configured tiers
        small = {"standard": GENEROUS, "gold": TierQuota(**{**GENEROUS.__dict__, "weight": 2})}
        assert QuotaConfig(tiers=small, overrides={"t": TierQuota(weight=16)})
        with pytest.raises(ValueError, match="is above 16"):
            QuotaConfig(tiers=small, overrides={"t": TierQuota(weight=17)})

    def test_engine_settings_refuse_an_override_weight_above_the_cap(self):
        with pytest.raises(SettingsError) as error:
            EngineSettings.from_mapping({"quotas": {"overrides": {"t_vip": {"weight": 33}}}})
        assert any("quotas" in p and "t_vip" in p and "32" in p for p in error.value.problems)
        ok = EngineSettings.from_mapping({"quotas": {"overrides": {"t_vip": {"weight": 32}}}})
        assert ok.quotas is not None and ok.quotas.overrides["t_vip"].weight == 32

    @pytest.mark.parametrize(
        ("kwargs", "fragment"),
        [
            ({"default_tier": "gold"}, "default_tier"),
            ({"tiers": {}}, "at least one tier"),
            ({"burst_capacity_s": 0}, "burst_capacity_s"),
            ({"burst_capacity_s": float("inf")}, "burst_capacity_s"),
            ({"max_queued_fraction_per_tenant": 0}, "max_queued_fraction_per_tenant"),
            ({"max_queued_fraction_per_tenant": 1.5}, "max_queued_fraction_per_tenant"),
            ({"non_production": {"test": 0.1}}, "non_production must give a fraction"),
            (
                {"non_production": {**DEFAULT_NON_PRODUCTION, "shadow": 0.0}},
                "non_production\\['shadow'\\] must be in",
            ),
            (
                {"non_production": {c: 0.25 for c in NON_PRODUCTION_CONSUMERS}},
                "leave room for production",
            ),
            (
                {"tiers": {"standard": TierQuota(checks_per_minute=2)}, "burst_capacity_s": 5.0},
                "never hold one check",
            ),
        ],
    )
    def test_invalid_settings_are_refused(self, kwargs, fragment):
        with pytest.raises(ValueError, match=fragment):
            QuotaConfig(**kwargs)

    @pytest.mark.parametrize(
        "kwargs",
        [
            {"weight": 0},
            {"weight": 1001},
            {"tokens_per_minute": 0},
            {"checks_per_minute": -1},
            {"requests_per_day": 1.5},
            {"requests_per_day": True},
        ],
    )
    def test_a_bad_tier_share_is_refused(self, kwargs):
        with pytest.raises(ValueError):
            TierQuota(**kwargs)

    def test_engine_settings_carry_the_quotas(self):
        loaded = EngineSettings.from_mapping(
            {
                "quotas": {
                    "tiers": {
                        "standard": {
                            "weight": 3,
                            "tokens_per_minute": 90_000,
                            "checks_per_minute": 30,
                            "requests_per_day": 1000,
                        }
                    },
                    "overrides": {"t_vip": {"weight": 9}},
                }
            }
        )
        assert loaded.quotas is not None
        assert loaded.quotas.tiers["standard"].weight == 3
        assert loaded.quotas.overrides["t_vip"].weight == 9
        # the engine fills in the largest single check (M3-09), nothing else
        assert loaded.effective_quotas() == dataclasses.replace(
            loaded.quotas,
            largest_check_tokens=loaded.largest_check_tokens(),
            largest_check_calls=4,
        )
        assert loaded.largest_check_tokens() == 94_000  # 4 chunks x (16,000 + 50 x 150)
        gateway = loaded.effective_gateway()
        assert gateway.quotas == loaded.effective_quotas()
        assert gateway.token_rate == loaded.effective_token_rate()

    def test_the_default_is_on_outside_test_and_off_in_test(self):
        largest = EngineSettings().largest_check_tokens()
        expected = QuotaConfig(largest_check_tokens=largest, largest_check_calls=4)
        assert EngineSettings().effective_quotas() == expected  # production
        assert EngineSettings(environment="staging").effective_quotas() == expected
        assert EngineSettings(environment="test").effective_quotas() is None
        assert EngineSettings(environment="test").effective_gateway().quotas is None
        explicit = QuotaConfig(default_tier="regulated")
        test_on = EngineSettings(environment="test", quotas=explicit)
        filled = dataclasses.replace(explicit, largest_check_tokens=largest, largest_check_calls=4)
        assert test_on.effective_quotas() == filled
        assert test_on.effective_gateway().quotas == filled
        own = QuotaConfig(largest_check_tokens=5, largest_check_calls=2)  # the operator's: kept
        assert EngineSettings(quotas=own).effective_quotas() == own

    def test_a_gateway_section_that_sets_its_own_quotas_wins(self):
        own = QuotaConfig(default_tier="dedicated")
        s = EngineSettings(gateway=GatewayConfig(quotas=own), quotas=QuotaConfig())
        assert s.effective_gateway().quotas is own

    @pytest.mark.parametrize(
        "bad",
        [
            {"default_tier": "gold"},
            {"non_production": {c: 0.3 for c in NON_PRODUCTION_CONSUMERS}},
            {"tiers": {"standard": {"weight": 0}}},
            {"nonsense": 1},
        ],
    )
    def test_engine_settings_refuse_bad_quotas_at_startup(self, bad):
        with pytest.raises(SettingsError) as error:
            EngineSettings.from_mapping({"quotas": bad})
        assert any("quotas" in p for p in error.value.problems)


class TestUsageClass:
    def test_untagged_is_production_and_the_tag_is_scoped(self):
        assert consumer_of() == USAGE_PRODUCTION
        with usage_class("calibration"):
            assert consumer_of() == "calibration"
            with usage_class("red_team"):
                assert consumer_of() == "red_team"
            assert consumer_of() == "calibration"
        assert consumer_of() == USAGE_PRODUCTION

    def test_an_explicit_class_beats_the_context_and_an_unknown_label_is_throttled(self):
        with usage_class("calibration"):
            assert consumer_of("shadow") == "shadow"
            assert consumer_of("production") == USAGE_PRODUCTION
        assert consumer_of("calibraton") == "test"  # a typo is never mistaken for production
        assert consumer_of("") == "test"

    def test_one_usage_class_concept_with_the_gateways_production_default(self):
        assert USAGE_CHECK == USAGE_PRODUCTION == "check"
        assert consumer_of("check") == consumer_of("production") == USAGE_PRODUCTION
        with usage_class("calibration"):
            assert resolve_usage_class(USAGE_CHECK) == "calibration"  # feeds the argument
            assert resolve_usage_class("test") == "test"  # an explicit class stands
        assert resolve_usage_class(USAGE_CHECK) == USAGE_CHECK

    async def test_the_tag_follows_the_check_into_tasks(self):
        seen = []

        async def inner():
            await asyncio.sleep(0)
            seen.append(consumer_of())

        with usage_class("shadow"):
            await asyncio.ensure_future(inner())
        assert seen == ["shadow"]
        assert TEST_PRIORITY == 3  # behind tool_result (2)


# ------------------------------------------------------------------------------ tenant shares


def share_of(est: int, calls_per_minute: float, **kwargs) -> TierQuota:
    return TierQuota(
        **{
            "tokens_per_minute": round(est * calls_per_minute),
            "checks_per_minute": 10**7,
            "requests_per_day": 10**9,
            **kwargs,
        }
    )


class TestTenantShare:
    async def test_offered_load_above_the_share_is_held_at_the_share(self):
        est = estimate_of(text(0))
        quotas = QuotaConfig(tiers=tiers(standard=share_of(est, 60)), burst_capacity_s=5.0)
        rig = QRig(quotas, project=BIG)
        results = (await drive(rig, [{"tenant_id": "t_a", "every_s": 0.1}], 150))["t_a"]
        await rig.drain()
        lo, hi = 30.0, 150.0
        rate = est * 60 / 60  # tokens a second: the share's own rate (M3-09)
        assert rig.starts_of(lo, hi) * est == pytest.approx(rate * (hi - lo), rel=0.03)
        over = refused(results)
        assert over
        for r in over:
            token_rate_failure(r, "tenant's share")
            assert 100 <= r.retry_after_ms <= 10_000  # R8's clamp
        assert len(answered(results)) == rig.model.started
        # Metered per tenant, as the tenant's own, never as the project's fail-fast.
        assert rig.meter.tenant_refusals(PROJECT, "t_a") == len(over)
        assert rig.meter.tenant_refusals(PROJECT, "t_a", cause=CAUSE_TENANT_TOKENS) == len(over)
        assert rig.meter.token_rate_fail_fasts(PROJECT) == 0
        assert not [a for a in rig.alerts.alerts if a.kind == ALERT_TOKEN_RATE_FAIL_FAST]

    async def test_the_check_share_binds_for_small_checks(self):
        quotas = QuotaConfig(
            tiers=tiers(standard=TierQuota(tokens_per_minute=10**9, checks_per_minute=30)),
            burst_capacity_s=5.0,
        )
        rig = QRig(quotas)
        results = (await drive(rig, [{"tenant_id": "t_a", "every_s": 0.2}], 150))["t_a"]
        await rig.drain()
        lo, hi = 30.0, 150.0
        assert rig.starts_of(lo, hi) == pytest.approx(30 / 60 * (hi - lo), rel=0.03)
        for r in refused(results):
            token_rate_failure(r, "30 checks a minute")
        # (no project limiter here, so the meter's project is the default one)
        assert rig.meter.tenant_refusals("default", "t_a", cause=CAUSE_TENANT_CHECKS) == len(
            refused(results)
        )

    async def test_a_refusal_has_no_provider_call_and_retry_after_is_honest(self):
        est = estimate_of(text(0))
        quotas = QuotaConfig(tiers=tiers(standard=share_of(est, 30)), burst_capacity_s=5.0)
        rig = QRig(quotas)
        first = [await rig.check() for _ in range(40)]  # drains the bucket, then refuses
        over = refused(first)
        assert over and rig.model.started == len(first) - len(over)
        refusal = over[-1]
        token_rate_failure(refusal)
        # After the hint, the next check is admitted.
        await rig.vt.sleep(refusal.retry_after_ms / 1000)
        again = await rig.check()
        assert isinstance(again.result, Answered)
        # and a check the same instant is refused again, with a hint that is at least 100 ms
        follow = await rig.check()
        assert isinstance(follow.result, Failed)
        assert follow.retry_after_ms is not None and follow.retry_after_ms >= 100

    async def test_the_public_reason_is_the_existing_token_rate(self):
        """No new failure reason: the SDK's enum already has the gateway's token-rate limit."""
        quotas = QuotaConfig(tiers=tiers(standard=TierQuota(checks_per_minute=10)))
        rig = QRig(quotas)
        results = [await rig.check() for _ in range(12)]  # a 60 s burst holds 10
        over = refused(results)[-1]
        failed = token_rate_failure(over)
        assert (
            failure_reason_of(
                "model_failure",
                failed.kind.value,
                failed.reason,
                capacity_limited=over.capacity_limited,
            )
            is FailureReason.TOKEN_RATE
        )

    async def test_tiers_and_overrides_give_each_tenant_its_own_share(self):
        est = estimate_of(text(0))
        quotas = QuotaConfig(
            tiers={
                "standard": share_of(est, 20),
                "regulated": share_of(est, 40, weight=2),
                "dedicated": share_of(est, 80, weight=4),
            },
            overrides={"t_vip": share_of(est, 160)},
            burst_capacity_s=5.0,
        )
        rig = QRig(quotas)
        plans = [
            {"tenant_id": "t_std", "tier": "standard", "every_s": 0.2},
            {"tenant_id": "t_reg", "tier": "regulated", "every_s": 0.2},
            {"tenant_id": "t_ded", "tier": "dedicated", "every_s": 0.2},
            {"tenant_id": "t_vip", "tier": "standard", "every_s": 0.2},  # override beats the tier
            {"tenant_id": "t_new", "tier": None, "every_s": 0.2},  # no tier: the default one
        ]
        results = await drive(rig, plans, 150)
        await rig.drain()
        sent = {t: len(answered(r)) for t, r in results.items()}
        # sent in 150 s is about (share per minute x 2.5 minutes), the first burst included
        assert sent["t_std"] == pytest.approx(20 * 2.5, rel=0.15)
        assert sent["t_reg"] == pytest.approx(40 * 2.5, rel=0.15)
        assert sent["t_ded"] == pytest.approx(80 * 2.5, rel=0.15)
        assert sent["t_vip"] == pytest.approx(160 * 2.5, rel=0.15)
        assert sent["t_new"] == pytest.approx(20 * 2.5, rel=0.15)

    async def test_one_tenant_over_its_share_does_not_refuse_another(self):
        est = estimate_of(text(0))
        quotas = QuotaConfig(tiers=tiers(standard=share_of(est, 30)), burst_capacity_s=5.0)
        rig = QRig(quotas, project=BIG)
        plans = [
            {"tenant_id": "noisy", "every_s": 0.05},  # 20 a second against 0.5
            {"tenant_id": "quiet", "every_s": 4.0},  # 0.25 a second
        ]
        results = await drive(rig, plans, 120)
        assert all(isinstance(r.result, Answered) for r in results["quiet"])
        assert len(refused(results["noisy"])) > 0.9 * len(results["noisy"])
        await rig.drain()
        assert rig.meter.tenant_refusals(PROJECT, "quiet") == 0

    async def test_only_the_first_call_is_charged_a_retry_is_free(self):
        quotas = QuotaConfig(tiers=tiers(standard=share_of(estimate_of(text(0)), 600)))
        rig = QRig(quotas, project=BIG)
        rig.model.fake.fail_next(FailureKind.UNAVAILABLE)
        before = rig.status()
        done = await rig.check()
        await rig.drain()
        assert isinstance(done.result, Answered)
        assert done.timing.provider_calls == 2  # the retry was sent
        after = rig.status()
        assert before.checks_available - after.checks_available == pytest.approx(1.0, abs=0.05)
        assert after.requests_today == 1
        assert rig.meter.tenant_calls(PROJECT, "t_a") == 1

    async def test_a_call_the_project_refuses_gives_the_tenants_share_back(self):
        est = estimate_of(text(0))
        project = config_for(est, 1.0)  # one call a second
        quotas = QuotaConfig(tiers=tiers(standard=share_of(est, 600)), burst_capacity_s=5.0)
        rig = QRig(quotas, project=project)
        rig.drain_project()
        before = rig.status()
        timed = await rig.check("output")  # waits 100 ms at most, the bucket needs a second
        token_rate_failure(timed, "token_rate: ")
        assert timed.result.message and "tenant" not in timed.result.message
        after = rig.status()
        assert after.tokens_available == pytest.approx(before.tokens_available, rel=1e-6)
        assert after.checks_available == pytest.approx(before.checks_available, abs=1e-6)
        assert after.requests_today == 0  # never sent, never counted
        await rig.drain()
        assert rig.meter.tenant_refusals(PROJECT) == 0  # the project's refusal, not the tenant's
        assert rig.meter.tenant_calls(PROJECT, "t_a") == 0

    async def test_actual_usage_corrects_the_tenants_share(self):
        est = estimate_of(text(0))
        quotas = QuotaConfig(tiers=tiers(standard=share_of(est, 600)), burst_capacity_s=5.0)
        rig = QRig(quotas, model_kwargs={"actual": lambda e: e // 2})
        before = rig.status().tokens_available
        await rig.check()
        spent = before - rig.status().tokens_available
        assert spent == pytest.approx(est // 2, rel=0.01)  # half what was reserved

    async def test_two_gateways_sharing_a_store_share_the_tenants_share(self):
        est = estimate_of(text(0))
        quotas = QuotaConfig(tiers=tiers(standard=share_of(est, 6)), burst_capacity_s=5.0)
        quotas = QuotaConfig(tiers=tiers(standard=share_of(est, 60)), burst_capacity_s=12.0)
        rig = QRig(quotas, gateways=2)
        sent = 0
        for i in range(40):
            timed = await rig.check(gateway=i % 2)
            sent += isinstance(timed.result, Answered)
        # 60 a minute with a 12 s burst holds 12 calls; two private stores would pass 24
        assert sent == 12

    async def test_a_tenant_cannot_hold_more_than_its_share_of_the_queue(self):
        quotas = QuotaConfig(tiers={"standard": GENEROUS}, max_queued_fraction_per_tenant=0.5)
        rig = QRig(
            quotas,
            gateway_kwargs={**SERIAL, "max_queued_per_key": 4},
            model_kwargs={"latency_s": 1.0},
        )
        tasks = []
        for i, tenant in enumerate(["noisy"] * 5 + ["quiet"]):
            tasks.append(rig.start("input", input=text(i), tenant_id=tenant))
            await asyncio.sleep(0)
        done = [await t for t in tasks]
        # noisy: one in flight, two queued (half of 4), the rest refused as queue-full
        full = [d for d in done[:5] if isinstance(d.result, Failed)]
        assert len(full) == 2
        for d in full:
            assert d.result.reason == REASON_ADMISSION_QUEUE_FULL
            assert d.capacity_limited and d.timing.provider_calls == 0
        assert isinstance(done[5].result, Answered)  # the quiet tenant still queues


class TestDailyShare:
    def quotas(self, per_day: int = 5) -> QuotaConfig:
        return QuotaConfig(tiers=tiers(standard=TierQuota(
            tokens_per_minute=10**9, checks_per_minute=10**6, requests_per_day=per_day
        )))  # fmt: skip

    async def test_a_tenant_over_its_daily_share_is_refused_until_midnight_pacific(self):
        rig = QRig(self.quotas(5), project=BIG)
        for _ in range(5):
            assert isinstance((await rig.check()).result, Answered)
        refusal = await rig.check()
        quota_failure(refusal, "requests a day")
        assert refusal.timing.provider_calls == 0
        # 12:00 UTC is 05:00 Pacific in June: 19 hours to midnight, unclamped
        assert refusal.retry_after_ms == pytest.approx(19 * 3_600_000, abs=60_000)
        assert refusal.retry_after_ms > 10_000
        # Other tenants are not affected.
        assert isinstance((await rig.check(tenant_id="t_b")).result, Answered)
        await rig.drain()
        assert rig.meter.tenant_refusals(PROJECT, "t_a", cause=CAUSE_TENANT_DAILY) == 1
        # The counter rolls at midnight Pacific.
        rig.wall.skew = timedelta(hours=20)
        assert isinstance((await rig.check()).result, Answered)

    async def test_the_tenants_admins_are_warned_at_80_and_100_percent(self):
        rig = QRig(self.quotas(5), project=BIG)
        for _ in range(6):
            await rig.check()
        await rig.drain()
        daily = [a for a in rig.alerts.alerts if a.kind == ALERT_TENANT_DAILY_QUOTA]
        assert [(a.reason, a.severity) for a in daily] == [
            ("threshold_80", AlertSeverity.WARNING),
            ("threshold_100", AlertSeverity.WARNING),
        ]
        assert all(a.tenant_id == "t_a" for a in daily)
        assert not [a for a in rig.alerts.alerts if a.kind == "decision_daily_requests"]

    async def test_a_queue_cannot_carry_a_tenant_past_its_daily_share(self):
        rig = QRig(
            self.quotas(3),
            gateway_kwargs={**SERIAL},
            model_kwargs={"latency_s": 1.0},
        )
        tasks = [rig.start("input", input=text(i)) for i in range(6)]
        done = [await t for t in tasks]
        assert sum(isinstance(d.result, Answered) for d in done) == 3
        assert rig.model.started == 3
        assert all(
            isinstance(d.result, Failed) and d.result.reason == "quota_exhausted"
            for d in done
            if not isinstance(d.result, Answered)
        )


# ------------------------------------------------------------------------- fair scheduling


class TestFairClock:
    def test_a_waiter_with_nothing_queued_starts_at_the_classes_virtual_time(self):
        clock = FairClock()
        assert clock.tag(0, tail=0.0, cost=100, weight=1) == (0.0, 100.0)
        clock.served(0, 40.0)
        assert clock.tag(0, tail=0.0, cost=100, weight=1) == (40.0, 140.0)
        assert clock.tag(0, tail=500.0, cost=100, weight=2) == (500.0, 550.0)  # behind its line
        assert clock.tag(1, tail=0.0, cost=100, weight=1) == (0.0, 100.0)  # classes are apart
        clock.served(0, 10.0)  # never goes back
        assert clock.tag(0, tail=0.0, cost=1, weight=1)[0] == 40.0


class TestFairOrder:
    def served_order(self, rig: QRig) -> list[int]:
        return [int(inp[:4]) for _, inp in rig.model.starts]

    async def run(self, arrivals, quotas=None, **kwargs):
        rig = QRig(
            quotas if quotas is not None else QuotaConfig(tiers=tiers()),
            gateway_kwargs={**SERIAL, "max_queued_per_key": 256},  # the tenant cap isn't tested
            model_kwargs={"latency_s": 0.5},
            **kwargs,
        )
        tasks = []
        for tag, (tenant, guard_point, tier, uclass) in enumerate(arrivals):
            tasks.append(rig.start(guard_point, input=text(tag), tenant_id=tenant, tier=tier,
                                   usage_class=uclass))  # fmt: skip
            await asyncio.sleep(0)
        done = [await t for t in tasks]
        assert all(isinstance(d.result, Answered) for d in done)
        return rig

    async def test_a_quiet_tenant_is_served_next_not_after_a_noisy_backlog(self):
        arrivals = [("noisy", "input", None, None)] * 10 + [("quiet", "input", None, None)]
        rig = await self.run(arrivals)
        order = self.served_order(rig)
        assert order[0] == 0  # the noisy tenant's first call had the free slot
        assert order.index(10) == 2  # the quiet tenant's call is next in line but one

    async def test_without_quotas_the_queue_is_first_come_first_served(self):
        rig = QRig(None, gateway_kwargs=SERIAL, model_kwargs={"latency_s": 0.5})
        arrivals = ["noisy"] * 10 + ["quiet"]
        tasks = []
        for tag, tenant in enumerate(arrivals):
            tasks.append(rig.start("input", input=text(tag), tenant_id=tenant))
            await asyncio.sleep(0)
        await asyncio.gather(*tasks)
        assert self.served_order(rig) == list(range(11))  # the quiet tenant is last

    async def test_tenants_are_served_in_proportion_to_their_tiers_weight(self):
        arrivals = []
        for _ in range(24):
            arrivals.append(("light", "input", "standard", None))
            arrivals.append(("heavy", "input", "dedicated", None))  # weight 4 against 1
        quotas = QuotaConfig(
            tiers={
                "standard": GENEROUS,
                "dedicated": TierQuota(**{**GENEROUS.__dict__, "weight": 4}),
            }
        )
        rig = await self.run(arrivals, quotas)
        order = self.served_order(rig)
        first = order[1:21]  # the next 20 after the call that had the free slot
        heavy = sum(tag % 2 == 1 for tag in first)
        assert heavy == pytest.approx(16, abs=1)  # 4 to 1

    async def test_priority_classes_come_first_and_tenants_are_fair_within_each(self):
        arrivals = [
            ("a", "tool_result", None, None),  # 0: takes the free slot
            ("a", "tool_result", None, None),  # 1
            ("a", "tool_result", None, None),  # 2
            ("b", "tool_result", None, None),  # 3
            ("a", "input", None, None),  # 4
            ("a", "input", None, None),  # 5
            ("b", "input", None, None),  # 6
        ]
        rig = await self.run(arrivals)
        order = self.served_order(rig)
        # input before tool_result, whoever's; within input, a's second call is behind b's
        assert order == [0, 4, 6, 5, 1, 3, 2]

    async def test_non_production_waits_behind_every_production_class(self):
        arrivals = [
            ("a", "output", None, None),  # 0: the free slot
            ("a", "output", None, "calibration"),  # 1: behind everything below
            ("b", "tool_result", None, None),  # 2
            ("c", "input", None, None),  # 3
            ("d", "output", None, "red_team"),  # 4
            ("b", "plan", None, None),  # 5
        ]
        rig = await self.run(arrivals)
        assert self.served_order(rig) == [0, 3, 5, 2, 1, 4]

    async def test_noisy_neighbour_at_ten_times_the_load_keeps_the_quiet_waits_in_allowance(
        self,
    ):
        """One key of four slots (6.7 calls a second at 0.6 s a call). The quiet tenant offers
        one call a second, the noisy one ten: more than the key can serve. With weighted fair
        scheduling the quiet tenant is next in line whenever it arrives; first in, first out
        would leave it behind the noisy tenant's whole queue."""
        allowance = 1.0
        kwargs = {
            "max_in_flight_per_key": 4,
            "queue_waits_s": {"input": allowance},
        }
        plans = [
            {"tenant_id": "noisy", "every_s": 0.1},
            {"tenant_id": "quiet", "every_s": 1.0},
        ]
        results = {}
        for label, quotas in (("fair", QuotaConfig(tiers=tiers())), ("fifo", None)):
            rig = QRig(quotas, gateway_kwargs=kwargs, model_kwargs={"latency_s": 0.6})
            results[label] = await drive(rig, plans, 60)
        alone = QRig(
            QuotaConfig(tiers=tiers()), gateway_kwargs=kwargs, model_kwargs={"latency_s": 0.6}
        )
        baseline = (await drive(alone, plans[1:], 60))["quiet"]

        fair_quiet = results["fair"]["quiet"]
        assert all(isinstance(r.result, Answered) for r in fair_quiet)
        waits = [r.timing.queue_wait_ms for r in fair_quiet]
        assert percentile(waits, 0.95) <= allowance * 1000
        assert max(waits) <= allowance * 1000
        # the noisy tenant is the one that is turned away, and it is turned away without a call
        noisy = results["fair"]["noisy"]
        assert len(refused(noisy)) > len(noisy) / 4
        for r in refused(noisy):
            assert r.result.reason == REASON_ADMISSION_WAIT
            assert r.timing.provider_calls == 0
        # first in, first out: the quiet tenant is held up with the noisy one, and some of
        # its checks are refused or wait far longer than alone
        fifo_quiet = results["fifo"]["quiet"]
        fifo_waits = [r.timing.queue_wait_ms for r in answered(fifo_quiet)]
        assert refused(fifo_quiet) or percentile(fifo_waits, 0.95) > 2 * max(
            percentile(waits, 0.95), 100
        )
        assert all(isinstance(r.result, Answered) for r in baseline)  # alone: no queue at all

    async def test_a_noisy_neighbour_at_ten_times_its_share_leaves_the_quiet_waits_unchanged(self):
        """Both tenants are standard (a share of 30 calls a minute). The noisy one offers ten
        times that. Its excess is refused before it queues, so the quiet tenant's p95 queue
        wait rises by no more than 10% over its wait alone (M3-07)."""
        est = estimate_of(text(0))
        kwargs = {"max_in_flight_per_key": 4, "queue_waits_s": {"input": 0.3}}
        quotas = QuotaConfig(tiers=tiers(standard=share_of(est, 30)), burst_capacity_s=15.0)
        plans = [
            {"tenant_id": "noisy", "every_s": 0.2},  # 300 a minute: ten times the share
            {"tenant_id": "quiet", "every_s": 2.5},  # 24 a minute: inside its share
        ]
        rig = QRig(quotas, gateway_kwargs=kwargs, model_kwargs={"latency_s": 0.6})
        together = await drive(rig, plans, 120)
        alone = QRig(quotas, gateway_kwargs=kwargs, model_kwargs={"latency_s": 0.6})
        solo = (await drive(alone, plans[1:], 120))["quiet"]

        assert len(refused(together["noisy"])) > 0.8 * len(together["noisy"])
        assert all(isinstance(r.result, Answered) for r in together["quiet"])
        with_noisy = percentile([r.timing.queue_wait_ms for r in together["quiet"]], 0.95)
        by_itself = percentile([r.timing.queue_wait_ms for r in solo], 0.95)
        assert with_noisy <= by_itself * 1.10 + 1.0  # +1 ms: both are near zero


# -------------------------------------------------------------- non-production allowances


class TestNonProduction:
    def project(self) -> TokenRateConfig:
        return config_for(estimate_of(text(0)), 0.08)  # 12.5 calls a second at the target

    async def test_a_consumer_is_held_to_its_fraction_of_the_projects_target(self):
        project = self.project()
        rig = QRig(QuotaConfig(tiers=tiers()), project=project)
        results = (
            await drive(
                rig,
                [{"tenant_id": "t_a", "every_s": 0.04, "usage_class": "calibration"}],
                100,
            )
        )["calibration"]
        await rig.drain()
        lo, hi = 20.0, 100.0
        target = project.rate_per_s * (hi - lo) * DEFAULT_NON_PRODUCTION["calibration"]
        assert rig.starts_of(lo, hi) * rig.estimate == pytest.approx(target, rel=0.04)
        over = refused(results)
        assert over
        for r in over:
            token_rate_failure(r, "calibration allowance")
        assert rig.meter.consumer_refusals(PROJECT, "calibration") == len(over)
        assert rig.meter.consumer_calls(PROJECT, "calibration") == rig.model.started
        assert rig.meter.consumer_tokens(PROJECT, "calibration") == rig.model.started * rig.estimate
        assert rig.meter.consumer_calls(PROJECT, "test") == 0  # per consumer
        # not the project's fail-fast, and not a tenant's share
        assert rig.meter.token_rate_fail_fasts(PROJECT) == 0
        assert rig.meter.tenant_refusals(PROJECT) == 0
        assert rig.meter.tenant_calls(PROJECT, "t_a") == 0

    async def test_production_is_never_refused_because_of_non_production_use(self):
        """Every consumer offers four times its allowance while production offers 55% of the
        target. The allowances add up to 40%, so production always has its 60%."""
        project = self.project()
        rig = QRig(QuotaConfig(tiers=tiers()), project=project)
        plans = [{"tenant_id": "t_prod", "every_s": 0.08 / 0.55}]
        plans += [
            {"tenant_id": f"t_{c}", "every_s": 0.2, "usage_class": c}
            for c in NON_PRODUCTION_CONSUMERS
        ]
        results = await drive(rig, plans, 120)
        await rig.drain()
        prod = results["t_prod"]
        assert len(prod) > 800
        assert all(isinstance(r.result, Answered) for r in prod)  # not one refusal
        total_per_consumer = {}
        for consumer in NON_PRODUCTION_CONSUMERS:
            assert refused(results[consumer])  # each is turned away at its allowance
            for r in refused(results[consumer]):
                assert r.timing.provider_calls == 0
            total_per_consumer[consumer] = rig.meter.consumer_tokens(PROJECT, consumer)
            share = total_per_consumer[consumer] / (project.rate_per_s * 120)
            assert 0.07 <= share <= 0.13  # about its 10%, burst included
        assert sum(total_per_consumer.values()) < 0.45 * project.rate_per_s * 120
        assert rig.meter.token_rate_fail_fasts(PROJECT) == 0

    async def exhaust(self, rig: QRig, consumer: str) -> TimedDecision:
        """Call as ``consumer`` until its allowance (a few calls of burst) refuses one."""
        for _ in range(40):
            timed = await rig.check(usage_class=consumer)
            if isinstance(timed.result, Failed):
                return timed
        raise AssertionError("the allowance never ran out")

    async def exhaust_tagged(self, rig: QRig) -> TimedDecision:
        """As :meth:`exhaust`, for calls tagged by an enclosing ``usage_class`` block."""
        for _ in range(40):
            timed = await rig.check()
            if isinstance(timed.result, Failed):
                return timed
        raise AssertionError("the allowance never ran out")

    async def test_a_refused_consumer_call_leaves_the_projects_bucket_alone(self):
        project = self.project()
        rig = QRig(QuotaConfig(tiers=tiers()), project=project)
        refusal = await self.exhaust(rig, "red_team")
        token_rate_failure(refusal, "red_team allowance")
        level = rig.project_level()
        token_rate_failure(await rig.check(usage_class="red_team"), "red_team allowance")
        assert rig.project_level() == pytest.approx(level)
        # another consumer has its own allowance
        assert isinstance((await rig.check(usage_class="shadow")).result, Answered)

    async def test_non_production_is_not_charged_to_the_tenants_share(self):
        est = estimate_of(text(0))
        quotas = QuotaConfig(tiers=tiers(standard=share_of(est, 6)), burst_capacity_s=15.0)
        rig = QRig(quotas, project=self.project())
        before = rig.status()
        assert isinstance((await rig.check(usage_class="test")).result, Answered)
        assert rig.status().tokens_available == pytest.approx(before.tokens_available)
        assert rig.status().requests_today == 0
        # so a tenant that has used up its production share can still run its tests, and the
        # reverse: tests that spent the allowance don't touch production
        for _ in range(10):
            await rig.check()  # production: share_of(6 a minute) holds about one call
        assert isinstance((await rig.check(usage_class="calibration")).result, Answered)

    async def test_the_gateway_argument_and_the_context_tag_are_the_same_class(self):
        """M2-05's draft test calls pass ``usage_class="test"``; a calibration run tags a
        block. Both are metered apart from production, queue last, and spend an allowance."""
        rig = QRig(QuotaConfig(tiers=tiers()), project=self.project())
        assert isinstance((await rig.check(usage_class="test")).result, Answered)
        with usage_class("calibration"):
            assert isinstance((await rig.check()).result, Answered)
        assert isinstance((await rig.check()).result, Answered)  # production
        await rig.drain()
        assert rig.meter.consumer_calls(PROJECT, "test") == 1
        assert rig.meter.consumer_calls(PROJECT, "calibration") == 1
        assert rig.meter.consumer_calls(PROJECT, USAGE_PRODUCTION) == 0
        # metered under "<class>:<guard point>", as M2-05 has it, never the production figure
        assert rig.meter.metered_calls("t_a", "test:output") == 1
        assert rig.meter.metered_calls("t_a", "calibration:output") == 1
        assert rig.meter.metered_calls("t_a", "output") == 1

    async def test_the_tag_comes_from_the_context_when_none_is_given(self):
        rig = QRig(QuotaConfig(tiers=tiers()), project=self.project())
        with usage_class("shadow"):
            assert isinstance((await rig.check()).result, Answered)
            refusal = await self.exhaust_tagged(rig)
        token_rate_failure(refusal, "shadow allowance")
        assert isinstance((await rig.check()).result, Answered)  # untagged: production
        await rig.drain()
        assert rig.meter.consumer_refusals(PROJECT, "shadow") == 1
        assert rig.meter.consumer_calls(PROJECT, "shadow") >= 2
        assert rig.meter.tenant_calls(PROJECT, "t_a") == 1

    async def test_a_mistyped_label_is_throttled_as_a_test_call(self):
        rig = QRig(QuotaConfig(tiers=tiers()), project=self.project())
        token_rate_failure(await self.exhaust(rig, "calibraton"), "test allowance")

    async def test_without_a_project_limiter_non_production_is_only_queued_last(self):
        rig = QRig(QuotaConfig(tiers=tiers()))  # no token_rate: nothing to take a fraction of
        for _ in range(5):
            assert isinstance((await rig.check(usage_class="calibration")).result, Answered)

    async def test_refusals_warn_once_per_consumer_and_never_for_production(self):
        rig = QRig(QuotaConfig(tiers=tiers()), project=self.project())
        refusals = 0
        for _ in range(40):
            refusals += isinstance((await rig.check(usage_class="calibration")).result, Failed)
        assert refusals > 3
        await rig.drain()
        warned = [a for a in rig.alerts.alerts if a.kind == ALERT_CONSUMER_ALLOWANCE]
        assert len(warned) == 1  # throttled
        assert warned[0].severity is AlertSeverity.WARNING
        assert warned[0].reason == CAUSE_CONSUMER
        assert (
            "calibration" in warned[0].message and "Production is not affected" in warned[0].message
        )
        assert not [a for a in rig.alerts.alerts if a.kind == ALERT_TENANT_QUOTA]


# -------------------------------- consumer request and spend allowances

BOTH = pytest.mark.parametrize(
    "quotas",
    [None, QuotaConfig(tiers=tiers())],
    ids=["without_quotas", "with_quotas"],
)
"""The allowances hold with or without ``quotas``: they need only the project's limiter."""


def project_with(**kwargs) -> TokenRateConfig:
    return TokenRateConfig(
        tier="tier_3", tokens_per_minute=10_000_000, project_id=PROJECT, **kwargs
    )


async def offer(rig: QRig, consumer: str, calls: int, every_s: float) -> list[TimedDecision]:
    """``calls`` checks of ``consumer``, one every ``every_s`` virtual seconds."""
    done = []
    for _ in range(calls):
        done.append(await rig.check(usage_class=consumer))
        await rig.vt.sleep(every_s)
    return done


class TestConsumerAllowances:
    """Tiny non-production calls are held to a fraction of the day's requests, the
    month's spend and the minute's requests, so production is answered afterwards."""

    def test_the_figures_are_ten_percent_of_the_projects(self):
        project = project_with(requests_per_day=200, monthly_spend_cap_usd=100.0)
        assert project.requests_per_minute == 1_500  # Tier 1's published figure
        rig = QRig(None, project=project)
        allowances = rig.gateway.consumer_allowances
        assert allowances is not None
        for consumer in NON_PRODUCTION_CONSUMERS:
            assert allowances.daily_limit(consumer) == 20
            assert allowances.monthly_limit_usd(consumer) == pytest.approx(10.0)
        assert allowances.fractions == DEFAULT_NON_PRODUCTION
        assert sum(allowances.fractions.values()) == pytest.approx(0.4)

    def test_there_are_no_allowances_without_the_projects_limiter(self):
        assert QRig(None).gateway.consumer_allowances is None
        assert QRig(QuotaConfig(tiers=tiers())).gateway.consumer_allowances is None

    @BOTH
    async def test_tiny_calls_stop_at_their_daily_fraction_and_production_is_answered(self, quotas):
        """The scaled probe: requests_per_day = 200, ``test`` calls every 0.5 s
        (within the minute allowances). Before the fix the 200 were gone in 10 minutes."""
        rig = QRig(quotas, project=project_with(requests_per_day=200))
        results = await offer(rig, "test", 1200, 0.5)  # ten virtual minutes
        sent = [r for r in results if isinstance(r.result, Answered)]
        assert len(sent) == 20 == rig.model.started  # 10% of 200, not one more
        over = [r for r in results if isinstance(r.result, Failed)]
        assert len(over) == 1180
        for r in over:
            quota_failure(r, "requests a day")
            assert r.retry_after_ms is not None and r.retry_after_ms > 10_000  # unclamped
        # 12:00 UTC is 05:00 Pacific in June: 19 hours to midnight
        assert over[0].retry_after_ms == pytest.approx(19 * 3_600_000, abs=700_000)
        # production is answered afterwards, and keeps the other 90%
        for _ in range(100):
            assert isinstance((await rig.check()).result, Answered)
        await rig.drain()
        assert rig.meter.consumer_refusals(PROJECT, "test") == 1180
        warned = [a for a in rig.alerts.alerts if a.kind == ALERT_CONSUMER_ALLOWANCE]
        assert 1 <= len(warned) <= 11  # throttled to one a minute, not one a refusal
        for alert in warned:
            assert alert.reason == CAUSE_CONSUMER
            assert "requests a day" in alert.message
            assert "Production is not affected" in alert.message

    @BOTH
    async def test_all_four_consumers_together_leave_production_sixty_percent(self, quotas):
        rig = QRig(quotas, project=project_with(requests_per_day=200))
        for consumer in NON_PRODUCTION_CONSUMERS:
            results = await offer(rig, consumer, 40, 0.5)
            assert sum(isinstance(r.result, Answered) for r in results) == 20
        assert rig.model.started == 80  # 40% of the day, no more
        answered = 0
        for _ in range(130):
            if isinstance((await rig.check()).result, Answered):
                answered += 1
        assert answered == 120  # production alone reaches the project's count (exception 2)
        refused = await rig.check()
        quota_failure(refused, "the project's 200 requests a day")

    @BOTH
    async def test_tiny_calls_stop_at_their_monthly_spend_fraction(self, quotas):
        project = project_with(monthly_spend_cap_usd=100.0, price_per_million_input_tokens_usd=1000)
        rig = QRig(quotas, project=project)
        cost = rig.estimate * 1000 / 1_000_000  # dollars a call
        expected = math.ceil(10.0 / cost)  # admitted while spend < 10% of $100
        results = await offer(rig, "calibration", expected + 20, 1.0)
        assert rig.model.started == expected
        over = [r for r in results if isinstance(r.result, Failed)]
        assert len(over) == 20
        for r in over:
            quota_failure(r, "monthly spend")
            # 15 days 19 hours to the 1st (Pacific), unclamped
            assert r.retry_after_ms is not None and r.retry_after_ms > 10_000
        assert over[0].retry_after_ms == pytest.approx(
            seconds_until_pacific_month_start(rig.wall()) * 1000, abs=60_000
        )
        for _ in range(20):
            assert isinstance((await rig.check()).result, Answered)  # production
        # another consumer has its own tenth
        assert isinstance((await rig.check(usage_class="shadow")).result, Answered)
        await rig.drain()
        warned = [a for a in rig.alerts.alerts if a.kind == ALERT_CONSUMER_ALLOWANCE]
        assert len(warned) == 1 and "monthly spend" in warned[0].message

    @BOTH
    async def test_a_refund_and_a_correction_move_the_consumers_spend(self, quotas):
        project = project_with(monthly_spend_cap_usd=100.0, price_per_million_input_tokens_usd=1000)
        rig = QRig(quotas, project=project, model_kwargs={"actual": lambda e: e * 2})
        allowances = rig.gateway.consumer_allowances
        assert allowances is not None
        key = f"tq:nm:{PROJECT}:test"
        month = pacific_month_key(rig.wall())
        assert isinstance((await rig.check(usage_class="test")).result, Answered)
        # reserved estimate x price, corrected to the provider's usage (twice the estimate)
        spent = rig.store.spend(key, month)
        assert spent == pytest.approx(rig.estimate * 2 * 1000 / 1_000_000)

    @BOTH
    async def test_tiny_calls_stop_at_their_per_minute_allowance(self, quotas):
        rig = QRig(quotas, project=project_with())
        results = await offer(rig, "test", 900, 0.2)  # five per second, three minutes
        await rig.drain()
        # 10% of 1,500 a minute is 150: a bucket of 150 x 5 / 65 and a refill of 150 / 65 a second
        assert rig.starts_of(0, 60) <= 150
        rate = 150 / 65
        assert rig.starts_of(60, 120) == pytest.approx(rate * 60, rel=0.03)
        assert rig.starts_of(120, 180) == pytest.approx(rate * 60, rel=0.03)
        over = [r for r in results if isinstance(r.result, Failed)]
        assert over
        for r in over:
            token_rate_failure(r, "requests a minute")  # token_rate, not quota_exhausted
            assert r.retry_after_ms is not None and 100 <= r.retry_after_ms <= 10_000
        # production is answered at once, and the other consumers have their own bucket
        assert isinstance((await rig.check()).result, Answered)
        assert isinstance((await rig.check(usage_class="red_team")).result, Answered)
        await rig.drain()
        assert rig.meter.consumer_refusals(PROJECT, "test") == len(over)
        warned = [a for a in rig.alerts.alerts if a.kind == ALERT_CONSUMER_ALLOWANCE]
        assert 1 <= len(warned) <= 4  # throttled to one a minute over three minutes
        assert all("requests a minute" in a.message for a in warned)

    @BOTH
    async def test_a_refusal_by_one_allowance_takes_nothing_from_another(self, quotas):
        rig = QRig(quotas, project=project_with(requests_per_day=200))
        await offer(rig, "test", 40, 0.5)  # at the daily fraction after 20
        key_requests = f"tq:nr:{PROJECT}:test"
        bucket = {"rate_per_s": 150 / 65, "capacity": 150 * 5 / 65}
        level = rig.store.level(key_requests, now=rig.vt.now_s, **bucket)
        quota_failure(await rig.check(usage_class="test"), "requests a day")
        assert rig.store.level(key_requests, now=rig.vt.now_s, **bucket) == pytest.approx(level)

    @BOTH
    async def test_the_daily_allowance_rolls_at_midnight_pacific(self, quotas):
        rig = QRig(quotas, project=project_with(requests_per_day=200))
        await offer(rig, "test", 40, 0.5)
        assert rig.model.started == 20
        quota_failure(await rig.check(usage_class="test"), "requests a day")
        rig.wall.skew = timedelta(hours=18)  # 23:00 Pacific: still the same day
        quota_failure(await rig.check(usage_class="test"), "requests a day")
        rig.wall.skew = timedelta(hours=20)  # 01:00 Pacific the next day
        results = await offer(rig, "test", 40, 0.5)
        assert sum(isinstance(r.result, Answered) for r in results) == 20  # a new day's tenth
        assert rig.model.started == 40
        quota_failure(await rig.check(usage_class="test"), "requests a day")

    @BOTH
    async def test_the_monthly_allowance_rolls_on_the_first_pacific(self, quotas):
        project = project_with(monthly_spend_cap_usd=100.0, price_per_million_input_tokens_usd=1000)
        rig = QRig(quotas, project=project)
        expected = math.ceil(10.0 / (rig.estimate * 1000 / 1_000_000))
        await offer(rig, "test", expected + 5, 1.0)
        assert rig.model.started == expected
        quota_failure(await rig.check(usage_class="test"), "monthly spend")
        # 12:00 UTC on June 15 plus 15 days 18 h is 23:00 Pacific on June 30: still June
        rig.wall.skew = timedelta(days=15, hours=18)
        assert pacific_month_key(rig.wall()) == "2026-06"
        quota_failure(await rig.check(usage_class="test"), "monthly spend")
        rig.wall.skew = timedelta(days=15, hours=20)  # 01:00 Pacific on July 1
        assert pacific_month_key(rig.wall()) == "2026-07"
        results = await offer(rig, "test", expected + 5, 1.0)
        assert sum(isinstance(r.result, Answered) for r in results) == expected

    @BOTH
    async def test_two_gateways_sharing_a_store_share_the_consumers_day(self, quotas):
        rig = QRig(quotas, project=project_with(requests_per_day=200), gateways=2)
        for i in range(30):
            await rig.check(usage_class="test", gateway=i % 2)
            await rig.vt.sleep(0.5)
        assert sum(m.started for m in rig.models) == 20

    async def test_a_call_that_is_never_sent_gives_its_allowances_back(self):
        rig = QRig(None, project=project_with(requests_per_day=200))
        allowances = rig.gateway.consumer_allowances
        assert allowances is not None
        now = rig.vt.now_s
        charge = allowances.charge(tenant_id="t_a", tier=None, consumer="test", tokens=500, now=now)
        assert not hasattr(charge, "retry_after_s")
        assert charge.requests == 1 and charge.tokens == 500 and charge.month == "2026-06"
        key = f"tq:np:{PROJECT}:test"
        bucket = allowances._token_bucket("test")
        assert rig.store.level(key, now=now, **bucket) == pytest.approx(bucket["capacity"] - 500)
        allowances.refund(charge, now=now)
        assert rig.store.level(key, now=now, **bucket) == pytest.approx(bucket["capacity"])
        assert rig.store.spend(f"tq:nm:{PROJECT}:test", "2026-06") == pytest.approx(0.0, abs=1e-12)
        assert rig.store.requests(f"tq:nd:{PROJECT}:test", "2026-06-15") == 0

    def test_a_requests_per_minute_too_small_for_one_request_is_refused(self):
        tiny = TokenRateConfig(
            tier="free", tokens_per_minute=50_000, requests_per_day=10_000, requests_per_minute=100
        )
        with pytest.raises(ValueError, match="never hold one request"):
            ConsumerAllowances(None, InProcessTokenRateStore, project=tiny, wall_clock=lambda: None)
        with pytest.raises(SettingsError, match="never hold one request"):
            EngineSettings.from_mapping({"token_rate": {"requests_per_minute": 100}})


# ------------------------------------------------- the admission queue and slots


def queue_full(timed: TimedDecision) -> bool:
    """Refused ``admission_queue_full``, with no call and the capacity signal (R8)."""
    return (
        isinstance(timed.result, Failed)
        and timed.result.reason == REASON_ADMISSION_QUEUE_FULL
        and timed.capacity_limited
        and timed.timing.provider_calls == 0
    )


class TestQueueShare:
    """A tenant with fewer queued places than the largest holder is never refused for
    want of a place; the largest holder's latest waiter is pushed out instead."""

    async def arrive(self, rig: QRig, arrivals: list[str], **kwargs) -> list[TimedDecision]:
        tasks = []
        for i, tenant in enumerate(arrivals):
            tasks.append(rig.start("input", input=text(i), tenant_id=tenant, **kwargs))
            await asyncio.sleep(0)
        return [await t for t in tasks]

    def rig(self, max_queued: int = 4, **kwargs) -> QRig:
        return QRig(
            QuotaConfig(tiers=tiers()),
            gateway_kwargs={**SERIAL, "max_queued_per_key": max_queued},
            model_kwargs={"latency_s": 1.0},
            **kwargs,
        )

    def test_the_per_tenant_cap_shrinks_as_more_tenants_queue(self):
        c = QuotaConfig(tiers=tiers())  # at most half the queue, whoever else is waiting
        assert [c.queue_limit(64, n) for n in (0, 1, 2, 3, 7, 63, 200)] == [32, 32, 21, 16, 8, 1, 1]
        assert c.queue_limit(4, 0) == 2 and c.queue_limit(4, 2) == 1
        assert QuotaConfig(
            tiers=tiers(), max_queued_fraction_per_tenant=1.0
        ).queue_limit(64, 0) == 64  # fmt: skip

    async def test_two_noisy_tenants_cannot_starve_a_third(self):
        """The probe: queue 4, one slot, noisy1 x3, noisy2 x2, then quiet x1."""
        rig = self.rig()
        done = await self.arrive(rig, ["noisy1"] * 3 + ["noisy2"] * 2 + ["quiet"])
        quiet = done[-1]
        assert isinstance(quiet.result, Answered)
        assert quiet.timing.provider_calls == 1
        # noisy1: the slot and its two places; noisy2: one place (the cap among three is 4 // 3)
        # and the second refused for it; the quiet tenant had its place all along
        assert [isinstance(d.result, Answered) for d in done] == [True] * 4 + [False, True]
        assert queue_full(done[4])

    async def test_a_tenant_with_fewer_places_pushes_the_largest_holders_last_waiter_out(self):
        rig = self.rig()
        # x holds the slot; a, b, c, d one place each: the queue (4) is full
        tasks = []
        for i, tenant in enumerate(["x", "a", "b", "c", "d"]):
            tasks.append(rig.start("input", input=text(i), tenant_id=tenant))
            await asyncio.sleep(0)
        assert rig.gateway.queued() == 4
        late = rig.start("input", input=text(9), tenant_id="e")
        await asyncio.sleep(0)
        assert rig.gateway.queued() == 4  # the place was made, not added
        done_first = [await t for t in tasks]
        assert isinstance(done_first[0].result, Answered)
        assert [isinstance(d.result, Answered) for d in done_first[1:4]] == [True] * 3
        assert queue_full(done_first[4])  # d was the last in line: pushed out
        assert done_first[4].retry_after_ms is not None  # with the R8 hint
        assert isinstance((await late).result, Answered)
        # nothing was sent for the call that was pushed out, and its charge came back
        assert rig.model.started == 5
        assert rig.status("d").requests_today == 0

    async def test_the_largest_holder_is_refused_not_pushed_over_a_smaller_one(self):
        rig = self.rig()
        # a holds two places (its cap), b one, c one: full. Another call of a's is refused.
        tasks = []
        for i, tenant in enumerate(["x", "a", "a", "b", "c", "a"]):
            tasks.append(rig.start("input", input=text(i), tenant_id=tenant))
            await asyncio.sleep(0)
        done = [await t for t in tasks]
        assert queue_full(done[5])
        assert all(isinstance(d.result, Answered) for d in done[:5])  # nobody else was pushed

    async def test_a_new_tenant_pushes_out_of_a_queue_others_filled(self):
        rig = self.rig(max_queued=8)
        # x holds the slot; a takes four places (half), b and c two each: the queue is full
        tasks = []
        for i, tenant in enumerate(["x"] + ["a"] * 4 + ["b"] * 2 + ["c"] * 2):
            tasks.append(rig.start("input", input=text(i), tenant_id=tenant))
            await asyncio.sleep(0)
        assert rig.gateway.queued() == 8
        late = rig.start("input", input=text(20), tenant_id="d")  # holds none
        await asyncio.sleep(0)
        assert rig.gateway.queued() == 8
        done = [await t for t in tasks]
        assert isinstance((await late).result, Answered)
        failed = [i for i, d in enumerate(done) if isinstance(d.result, Failed)]
        assert failed == [4] and queue_full(done[4])  # a's last call, the largest holder's

    async def test_a_pushed_out_call_never_reaches_a_provider_or_keeps_its_share(self):
        est = estimate_of(text(0))
        quotas = QuotaConfig(tiers=tiers(standard=share_of(est, 60)), burst_capacity_s=15.0)
        rig = QRig(
            quotas,
            gateway_kwargs={**SERIAL, "max_queued_per_key": 4},
            model_kwargs={"latency_s": 1.0},
        )
        tasks = []
        for i, tenant in enumerate(["x", "a", "b", "c", "d"]):
            tasks.append(rig.start("input", input=text(i), tenant_id=tenant))
            await asyncio.sleep(0)
        before = rig.status("d").tokens_available
        late = rig.start("input", input=text(9), tenant_id="e")
        await asyncio.sleep(0)
        done = [await t for t in tasks]
        await late
        assert queue_full(done[4])
        # d was charged on entry and given the share back when it was pushed out
        assert rig.status("d").tokens_available >= before
        assert rig.status("d").requests_today == 0


class TestNonProductionQueueAndSlots:
    """Non-production calls hold at most a quarter of the queue and half the slots,
    so production is never refused for a place or a slot because of them."""

    PROD = "t_prod"

    def test_the_shares(self):
        from guardrail_engine.gateway.tenant_quota import (
            non_production_queue_limit,
            non_production_slot_limit,
        )

        assert [non_production_queue_limit(n) for n in (1, 3, 4, 8, 20, 64)] == [1, 1, 1, 2, 5, 16]
        assert [non_production_slot_limit(n) for n in (1, 2, 3, 4, 5, 8, 64)] == [
            1,
            1,
            1,
            2,
            2,
            4,
            32,
        ]

    def rig(self, max_queued: int, **kwargs) -> QRig:
        return QRig(
            QuotaConfig(tiers=tiers()),
            gateway_kwargs={**SERIAL, "max_queued_per_key": max_queued},
            model_kwargs={"latency_s": 1.0},
            **kwargs,
        )

    async def test_non_production_waiters_hold_a_quarter_of_the_queue(self):
        rig = self.rig(20)
        tasks = [rig.start("input", input=text(0), tenant_id=self.PROD)]  # holds the slot
        await asyncio.sleep(0)
        for i in range(6):  # a quarter of 20 is 5 places, whoever's they are
            klass = "test" if i < 3 else "calibration"
            tasks.append(
                rig.start("input", input=text(i + 1), tenant_id=f"t_{i}", usage_class=klass)
            )
            await asyncio.sleep(0)
        done = [await t for t in tasks]
        assert queue_full(done[6])  # the sixth non-production call
        assert all(isinstance(d.result, Answered) for d in done[:6])

    async def test_a_production_check_pushes_out_the_latest_non_production_waiter(self):
        """The probe, at a queue of 20 (a quarter is 5): three test and two
        calibration calls queued, the rest of the queue production from other tenants."""
        rig = self.rig(20)
        tasks = [rig.start("input", input=text(0), tenant_id="t_slot")]
        await asyncio.sleep(0)
        for i in range(3):
            tasks.append(rig.start("input", input=text(1 + i), tenant_id="t_a",
                                   usage_class="test"))  # fmt: skip
            await asyncio.sleep(0)
        for i in range(2):
            tasks.append(rig.start("input", input=text(4 + i), tenant_id="t_b",
                                   usage_class="calibration"))  # fmt: skip
            await asyncio.sleep(0)
        for i in range(15):
            tasks.append(rig.start("input", input=text(10 + i), tenant_id=f"t_p{i}"))
            await asyncio.sleep(0)
        assert rig.gateway.queued() == 20  # full
        late = rig.start("input", input=text(99), tenant_id=self.PROD)
        await asyncio.sleep(0)
        assert rig.gateway.queued() == 20
        done = [await t for t in tasks]
        assert isinstance((await late).result, Answered)
        pushed = [i for i, d in enumerate(done) if isinstance(d.result, Failed)]
        # the last non-production waiter in line: fair order puts t_a's third call (start 2)
        # behind t_b's second (start 1)
        assert pushed == [3]
        assert queue_full(done[3])
        assert all(isinstance(d.result, Answered) for i, d in enumerate(done) if i != 3)

    async def test_production_is_admitted_when_non_production_fills_a_small_queue(self):
        rig = self.rig(4)
        tasks = [rig.start("input", input=text(0), tenant_id="t_slot")]
        await asyncio.sleep(0)
        for i in range(3):  # a quarter of 4 is one place: the others are refused at once
            tasks.append(rig.start("input", input=text(1 + i), tenant_id=f"t_{i}",
                                   usage_class="test"))  # fmt: skip
            await asyncio.sleep(0)
        for i in range(3):  # three production waiters fill the queue with the test call
            tasks.append(rig.start("input", input=text(5 + i), tenant_id=f"t_p{i}"))
            await asyncio.sleep(0)
        late = rig.start("input", input=text(9), tenant_id=self.PROD)
        await asyncio.sleep(0)
        done = [await t for t in tasks]
        assert isinstance((await late).result, Answered)
        assert queue_full(done[2]) and queue_full(done[3])  # the second and third test calls
        assert queue_full(done[1])  # the one test waiter, pushed out for the newcomer
        assert all(isinstance(d.result, Answered) for d in done[4:])

    async def test_non_production_never_pushes_anyone_out(self):
        rig = self.rig(4)
        tasks = [rig.start("input", input=text(0), tenant_id="t_slot")]
        await asyncio.sleep(0)
        for i in range(4):
            tasks.append(rig.start("input", input=text(1 + i), tenant_id=f"t_p{i}"))
            await asyncio.sleep(0)
        late = rig.start("input", input=text(9), tenant_id="t_x", usage_class="red_team")
        await asyncio.sleep(0)
        assert queue_full(await late)
        assert all(isinstance(d.result, Answered) for d in [await t for t in tasks])

    async def test_calibration_cannot_take_every_slot_from_a_production_check(self):
        """The probe: four slots, four 2.5 s calibration calls offered, then a
        production input check. It starts at once instead of being refused ``admission_wait``."""
        rig = QRig(
            QuotaConfig(tiers=tiers()),
            gateway_kwargs={"max_in_flight_per_key": 4, "expected_latency_s": 2.5},
            model_kwargs={"latency_s": 2.5},
        )
        calibration = []
        for i in range(4):
            calibration.append(rig.start("input", input=text(i), tenant_id=f"t_c{i}",
                                         usage_class="calibration"))  # fmt: skip
            await asyncio.sleep(0)
        assert rig.gateway.in_flight() == 2  # half the slots at most
        produced = await rig.check("input", input=text(50), tenant_id=self.PROD)
        assert isinstance(produced.result, Answered)
        assert produced.timing.queue_wait_ms == 0
        await asyncio.gather(*calibration)

    async def test_non_production_calls_run_in_turn_within_their_share_of_the_slots(self):
        rig = QRig(
            QuotaConfig(tiers=tiers()),
            gateway_kwargs={"max_in_flight_per_key": 4, "expected_latency_s": 1.0, **LONG_QUEUE},
            model_kwargs={"latency_s": 1.0},
        )
        done = await asyncio.gather(
            *(rig.check("input", input=text(i), tenant_id="t_c", usage_class="calibration")
              for i in range(6))
        )  # fmt: skip
        assert all(isinstance(d.result, Answered) for d in done)  # none is starved or refused
        starts = sorted(t for t, _ in rig.model.starts)
        assert [round(t - T0) for t in starts] == [0, 0, 1, 1, 2, 2]  # two at a time

    async def test_a_single_slot_is_the_only_exception_and_production_waits_one_call(self):
        rig = QRig(
            QuotaConfig(tiers=tiers()),
            gateway_kwargs={**SERIAL, "expected_latency_s": 1.0},
            model_kwargs={"latency_s": 1.0},
        )
        calibration = rig.start("input", input=text(0), tenant_id="t_c", usage_class="calibration")
        await asyncio.sleep(0)
        produced = await rig.check("input", input=text(1), tenant_id=self.PROD)
        assert isinstance(produced.result, Answered)  # it waited for the one call, in budget
        assert 900 <= produced.timing.queue_wait_ms <= 1100
        await calibration

    async def test_the_queue_limits_hold_without_quotas_too(self):
        rig = QRig(
            None,
            gateway_kwargs={**SERIAL, "max_queued_per_key": 4},
            model_kwargs={"latency_s": 1.0},
        )
        tasks = [rig.start("input", input=text(0), tenant_id="t_slot")]
        await asyncio.sleep(0)
        for i in range(3):
            tasks.append(rig.start("input", input=text(1 + i), tenant_id="t_a",
                                   usage_class="test"))  # fmt: skip
            await asyncio.sleep(0)
        done = [await t for t in tasks]
        assert [isinstance(d.result, Answered) for d in done] == [True, True, False, False]
        assert queue_full(done[2]) and queue_full(done[3])


# ------------------------------------------------------------------------------- the meters


class TestMeters:
    def test_the_in_memory_meter_is_a_quota_meter(self):
        assert isinstance(InMemoryUsageMeter(), QuotaMeter)

    async def test_usage_against_share_and_refusals_by_tenant(self):
        est = estimate_of(text(0))
        quotas = QuotaConfig(
            tiers=tiers(standard=share_of(est, 120), regulated=share_of(est, 240, weight=2)),
            burst_capacity_s=12.0,
        )
        rig = QRig(quotas, project=BIG)
        for _ in range(30):
            await rig.check(tenant_id="t_std", tier="standard")  # holds 24 calls of burst
        for _ in range(5):
            await rig.check(tenant_id="t_reg", tier="regulated")
        await rig.drain()
        m = rig.meter
        assert m.tenant_calls(PROJECT, "t_std") == 24
        assert m.tenant_tokens(PROJECT, "t_std") == 24 * est
        assert m.tenant_share(PROJECT, "t_std") == round(est * 120)
        assert m.tenant_share(PROJECT, "t_reg") == round(est * 240)
        assert m.tenant_refusals(PROJECT, "t_std") == 6
        assert m.tenant_refusals(PROJECT, "t_reg") == 0
        assert m.tenant_refusals(PROJECT) == 6  # every tenant
        # a minute's burst against a minute's share: at most the share, here exactly 24 of 120
        assert m.tenant_usage_vs_share(PROJECT, "t_std", minutes=1.0) == pytest.approx(24 / 120)
        assert m.tenant_usage_vs_share(PROJECT, "t_reg", minutes=1.0) == pytest.approx(5 / 240)
        assert m.tenant_usage_vs_share(PROJECT, "nobody", minutes=1.0) == 0.0
        # and the live gauge
        status = rig.status("t_std", "standard")
        assert status.tokens_per_minute == round(est * 120) and status.weight == 1
        assert status.requests_today == 24
        assert 0.9 < status.tokens_used_fraction <= 1.0  # nearly all the burst is spent

    async def test_tenant_refusals_warn_once_per_interval_and_name_only_that_tenant(self):
        quotas = QuotaConfig(
            tiers=tiers(standard=TierQuota(checks_per_minute=10)), burst_capacity_s=30.0
        )  # holds 5
        rig = QRig(quotas)
        for _ in range(6):
            await rig.check(tenant_id="t_noisy")
        await rig.drain()
        warned = [a for a in rig.alerts.alerts if a.kind == ALERT_TENANT_QUOTA]
        assert len(warned) == 1
        assert warned[0].tenant_id == "t_noisy" and warned[0].reason == CAUSE_TENANT_CHECKS
        assert warned[0].severity is AlertSeverity.WARNING
        assert "Other tenants are not affected" in warned[0].message


class TestBareGateway:
    async def test_the_new_arguments_are_ignored_without_quotas(self):
        rig = QRig(None)
        timed = await rig.check(tier="dedicated", usage_class="calibration")
        assert isinstance(timed.result, Answered)
        assert rig.gateway.quota_limiter is None
        assert rig.model.started == 1
