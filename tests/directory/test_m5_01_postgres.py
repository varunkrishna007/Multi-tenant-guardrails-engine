"""M5-01 on Postgres: ``set_tier`` is stored with its class A event (action ``set_tier``: actor,
reason, before and after), and the audit table still refuses edits. Needs GUARDRAIL_TEST_PG_DSN."""

import pytest

from guardrail_engine.authz import Principal
from guardrail_engine.directory import InMemoryEventBus, TenantProvisioner

asyncpg = pytest.importorskip("asyncpg")

OPS = Principal("ops-1", None, frozenset(), True, issuer="https://idp.example.com/")


async def test_a_tier_change_is_stored_with_its_set_tier_event(pg):
    from guardrail_engine.store.adapters.postgres import PostgresDirectoryStore

    store = PostgresDirectoryStore(pg.pool)
    prov = TenantProvisioner(store, InMemoryEventBus(), clock=lambda: 1_700_000_000.0)
    record = await prov.create(OPS, slug="acme", domain="finance")
    change = await prov.set_tier(OPS, record.tenant_id, 1, "regulated", "contract 2026-11")
    assert (await store.get(record.tenant_id)).tier == "regulated" and change.record.version == 2

    created, event = await store.audit_events(record.tenant_id)
    assert (created.action, event.action) == ("create", "set_tier")
    assert event.actor == "https://idp.example.com/#ops-1"
    assert (event.before["tier"], event.after["tier"]) == ("standard", "regulated")
    assert event.after["reason"] == "contract 2026-11"

    with pytest.raises(asyncpg.RestrictViolationError):
        await pg.pool.execute("UPDATE tenant_directory_audit SET actor = 'x'")
