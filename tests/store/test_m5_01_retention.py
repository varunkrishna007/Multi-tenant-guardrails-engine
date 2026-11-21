"""M5-01 and R3: the retention floors follow the tenant's real tier through the existing
resolver, from the moment the operator sets it (a deletion can't be undone, so the floor does not
wait for the tenant's next publish), while the active version keeps running as published."""

from test_m4_09_retention import bundle_with, catalog, resolver

from guardrail_engine.authz import Principal
from guardrail_engine.directory import InMemoryDirectoryStore, InMemoryEventBus, TenantProvisioner
from guardrail_engine.retention import TenantRetention

OPS = Principal("ops-1", None, frozenset(), True)


class Live:
    """The resolver's directory, read straight from the store the provisioner writes."""

    def __init__(self, store):
        self.store = store

    async def get(self, tenant_id):
        return await self.store.get(tenant_id)


async def test_a_tier_change_moves_the_retention_floor_at_once_for_the_running_version():
    store = InMemoryDirectoryStore()
    prov = TenantProvisioner(store, InMemoryEventBus())
    record = await prov.create(OPS, slug="acme", domain="finance")
    tenant_id = record.tenant_id
    bundle = bundle_with([])  # the active version extends no pack, and says nothing of retention
    r = resolver(Live(store), bundle, cat=catalog())

    assert await r.resolve(tenant_id) == TenantRetention(395, "default")  # standard

    await prov.set_tier(OPS, tenant_id, 1, "regulated", "contract")
    # the regulated tier requires the finance pack here: 7 years, though the bundle never
    # extended it, and the bundle's own (absent) term does not matter
    assert await r.resolve(tenant_id) == TenantRetention(7 * 365, "default")

    await prov.set_tier(OPS, tenant_id, 2, "standard", "downgrade")
    assert await r.resolve(tenant_id) == TenantRetention(395, "default")


async def test_a_regulated_tenants_own_shorter_term_is_lifted_to_the_tiers_minimum():
    store = InMemoryDirectoryStore()
    prov = TenantProvisioner(store, InMemoryEventBus())
    record = await prov.create(OPS, slug="acme", domain="finance", tier="regulated")
    # a published term of 90 days is below finance's minimum of 395 days
    r = resolver(Live(store), bundle_with([], records_days=90), cat=catalog())
    assert await r.resolve(record.tenant_id) == TenantRetention(395, "clamped")
