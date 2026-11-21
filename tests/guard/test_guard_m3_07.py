"""M3-07 through the Guard Service: the tenant's directory tier reaches the gateway, which
picks the tenant's share and its weight in fair scheduling from it.

Real time with the fake model; nothing here depends on timing.
"""

from guard_fixtures import ALPHA, BETA, TOOLS, Env, bundle, rule

from guardrail_engine.gateway import GatewayConfig, InMemoryUsageMeter, QuotaConfig, TierQuota
from guardrail_engine.guard import GuardConfig, TenantProfile
from guardrail_engine.policy import TenantAttributes

QUOTAS = QuotaConfig(
    tiers={
        "standard": TierQuota(weight=1, tokens_per_minute=111_000),
        "regulated": TierQuota(weight=2, tokens_per_minute=222_000),
        "dedicated": TierQuota(weight=4, tokens_per_minute=444_000),
    }
)


def tenant(tenant_id: str, tier: str) -> TenantProfile:
    attributes = TenantAttributes(tenant_id=tenant_id, tier=tier)
    return TenantProfile.build(attributes, "insurance", TOOLS, slug=tenant_id.removeprefix("t_"))


async def test_each_tenants_share_follows_its_directory_tier():
    meter = InMemoryUsageMeter()
    config = GuardConfig(pointer_ttl_s=60.0, gateway=GatewayConfig(quotas=QUOTAS))
    tenants = [tenant(ALPHA, "regulated"), tenant(BETA, "standard")]
    async with Env(tenants=tenants, config=config, meter=meter) as env:
        await env.publish(bundle(ALPHA, rules=[rule("adv")]))
        await env.publish(bundle(BETA, rules=[rule("adv")]))
        await env.check(ALPHA)
        await env.check(BETA)
        await env.service.gateway.drain()
    assert meter.tenant_share("default", ALPHA) == 222_000
    assert meter.tenant_share("default", BETA) == 111_000
    assert meter.tenant_calls("default", ALPHA) == meter.tenant_calls("default", BETA) == 1
