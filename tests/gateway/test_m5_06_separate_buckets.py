"""M5-06: each Gemini project has its own token bucket, daily request count and monthly spend.

Two gateways (one per project) share one rate store, as engines of one process do. Using up the
dedicated project's bucket or daily count refuses its checks and never touches the other
project's, and the other way round. Virtual clock, fake model: no live call.
"""

from datetime import UTC, datetime

import pytest
from test_gateway import QUESTIONS, VirtualTime, close_gateways  # noqa: F401
from test_gateway_m3_10 import TokenModel, Wall, config_for, estimate_of, quota_failure, text
from test_gateway_m3_10 import token_rate_failure as bucket_failure

from guardrail_engine.decision import Answered
from guardrail_engine.gateway import (
    DecisionGateway,
    GatewayConfig,
    InMemoryUsageMeter,
    InProcessTokenRateStore,
    QuotaConfig,
    RecordingAlertSink,
    pacific_day_key,
    pacific_month_key,
)

DEDICATED = "reg-acme"
SHARED = "default"


class TwoProjects:
    def __init__(self, **dedicated_kwargs) -> None:
        self.vt = VirtualTime()
        self.input = text(0)
        self.estimate = estimate_of(self.input)
        self.wall = Wall(self.vt, datetime(2026, 6, 15, 12, 0, tzinfo=UTC))
        self.store = InProcessTokenRateStore()
        self.meter = InMemoryUsageMeter()
        self.configs = {
            DEDICATED: config_for(self.estimate, 1.0, project_id=DEDICATED, **dedicated_kwargs),
            SHARED: config_for(self.estimate, 1.0, project_id=SHARED),
        }
        self.models, self.gateways = {}, {}
        for project, config in self.configs.items():
            model = TokenModel(self.vt)
            model.estimate = self.estimate
            self.models[project] = model
            self.gateways[project] = DecisionGateway(
                model,
                config=GatewayConfig(
                    max_in_flight_per_key=64, token_rate=config, quotas=QuotaConfig()
                ),
                meter=self.meter,
                alerts=RecordingAlertSink(),
                key_id=lambda project=project: f"key-{project}",
                clock=self.vt.now,
                sleep=self.vt.sleep,
                rng=lambda: 0.0,
                rate_store=self.store,
                wall_clock=self.wall,
            )

    def bucket(self, project):
        c = self.configs[project]
        return {"now": self.vt.now_s, "rate_per_s": c.rate_per_s, "capacity": c.capacity}

    def level(self, project) -> float:
        return self.store.level(project, **self.bucket(project))

    def drain_bucket(self, project) -> None:
        self.store.acquire(project, self.level(project), **self.bucket(project))

    async def check(self, project, tenant_id="t_a"):
        return await self.gateways[project].decide_timed(
            tenant_id=tenant_id, guard_point="output", input=self.input, questions=QUESTIONS
        )

    async def drain(self):
        for g in self.gateways.values():
            await g.drain()


async def test_using_up_one_projects_bucket_leaves_the_other_untouched():
    rig = TwoProjects()
    rig.drain_bucket(DEDICATED)
    shared_level = rig.level(SHARED)
    assert rig.level(DEDICATED) == pytest.approx(0.0) and shared_level > 0

    refused = await rig.check(DEDICATED)
    # the dedicated project's bucket is empty: its check fails fast, with no provider call
    bucket_failure(refused)
    assert rig.models[DEDICATED].started == 0

    served = await rig.check(SHARED)
    assert isinstance(served.result, Answered)
    assert rig.models[SHARED].started == 1
    assert rig.level(SHARED) < shared_level  # only the shared project's bucket paid for it
    await rig.drain()


async def test_and_the_other_way_round():
    rig = TwoProjects()
    rig.drain_bucket(SHARED)
    bucket_failure(await rig.check(SHARED))
    served = await rig.check(DEDICATED, tenant_id="t_regulated")
    assert isinstance(served.result, Answered) and rig.models[DEDICATED].started == 1
    await rig.drain()


async def test_the_daily_request_count_and_the_monthly_spend_are_per_project():
    rig = TwoProjects(requests_per_day=2)
    for _ in range(2):
        assert isinstance((await rig.check(DEDICATED)).result, Answered)
        rig.vt.advance(5.0)  # the bucket refills
    quota_failure(await rig.check(DEDICATED))  # the dedicated project's 2 calls a day are spent
    assert rig.models[DEDICATED].started == 2

    for _ in range(3):  # the shared project's day is its own: 50,000 a day by default
        assert isinstance((await rig.check(SHARED)).result, Answered)
        rig.vt.advance(5.0)

    wall = rig.wall()
    day, month = pacific_day_key(wall), pacific_month_key(wall)
    assert rig.store.requests(DEDICATED, day) == 2 and rig.store.requests(SHARED, day) == 3
    spent = {p: rig.store.spend(p, month) for p in (DEDICATED, SHARED)}
    assert 0 < spent[DEDICATED] < spent[SHARED]  # each project's own bill
    await rig.drain()


async def test_a_tenants_usage_is_counted_under_its_own_project():
    rig = TwoProjects()
    await rig.check(DEDICATED, tenant_id="t_regulated")
    rig.vt.advance(5.0)
    await rig.check(SHARED, tenant_id="t_standard")
    await rig.drain()
    assert rig.meter.tenant_calls(DEDICATED, "t_regulated") == 1
    assert rig.meter.tenant_calls(DEDICATED, "t_standard") == 0
    assert rig.meter.tenant_calls(SHARED, "t_standard") == 1
    assert rig.meter.tenant_calls(SHARED, "t_regulated") == 0
