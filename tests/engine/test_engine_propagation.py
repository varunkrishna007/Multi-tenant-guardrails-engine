"""M2-07 on the engine: the factory subscribes the engine's own policy cache to
``guardrail.published`` and gives the deployment ``on_tenant_changed`` for the directory's
``tenant.changed``: a publish, rollback, suspension or reinstatement is served at the next check
when the event arrives, and within the pointer TTL when it is dropped."""

import asyncio
import json

import pytest
from engine_fixtures import TENANT, bundle, directory, settings, verifier

from guardrail_engine.admin.lifecycle import InMemoryPublishBus
from guardrail_engine.authz import InMemoryAuthzAudit, Principal, Role
from guardrail_engine.decision import FakeDecisionModel
from guardrail_engine.directory import (
    CachedTenantDirectory,
    InMemoryDirectoryStore,
    InMemoryEventBus,
    TenantProvisioner,
)
from guardrail_engine.engine import build_engine
from guardrail_engine.guard import CheckContext, Reason

BASE = "/v1/tenants/{tid}/guardrails"
OPS = Principal("ops-1", None, frozenset(), True)


async def build(pointer_ttl_s=60.0, tenants=None, **kw):
    return await build_engine(
        settings("test", guard={"pointer_ttl_s": pointer_ttl_s}),
        verifier=verifier(),
        tenants=tenants if tenants is not None else directory(),
        model=FakeDecisionModel(),
        authz_audit=InMemoryAuthzAudit(),
        **kw,
    )


async def check(engine, tenant=TENANT):
    return await engine.check(CheckContext(signed_context=verifier().issue(tenant)), "output", "hi")


def admin_of(tenant):
    return Principal("alice", tenant, frozenset({Role.GUARDRAIL_ADMIN}), issuer="https://i/")


async def decide(engine, method, route, tenant=TENANT):
    return await engine.authorizer.authorize(
        admin_of(tenant), method, BASE + route, tenant_id=tenant
    )


async def draft_and_publish(engine, doc, mode="enforce", percent=100, tenant=TENANT):
    """Save ``doc`` as the tenant's draft (replacing one) and publish it."""
    d = await decide(engine, "PUT", "/draft", tenant)
    existing = await engine.draft_service._drafts.scoped(d.scope).get(tenant)
    saved = await engine.draft_service.put_draft(
        d, admin_of(tenant), json.dumps(doc).encode(), None if existing is None else "*"
    )
    d = await decide(engine, "POST", "/draft/publish", tenant)
    body = json.dumps({"mode": mode, "rollout_percent": percent}).encode()
    return await engine.publish_service.publish(d, admin_of(tenant), body, saved.etag)


async def promote(engine, tenant=TENANT):
    d = await decide(engine, "POST", "/candidate/promote", tenant)
    return await engine.publish_service.promote(d, admin_of(tenant))


async def test_a_publish_and_a_rollback_are_served_at_the_next_check_by_event():
    engine = await build(pointer_ttl_s=60.0)  # the TTL alone would take an hour
    try:
        await draft_and_publish(engine, bundle())  # version 1, active
        assert (await check(engine)).bundle_version == 1
        await draft_and_publish(engine, bundle(), "shadow", 10)  # version 2, candidate
        await promote(engine)
        assert (await check(engine)).bundle_version == 2  # the engine's bus invalidated its cache
        await engine.publish_service.rollback(
            await decide(engine, "POST", "/versions/{v}/rollback"), admin_of(TENANT), 1
        )
        assert (await check(engine)).bundle_version == 1
    finally:
        await engine.shutdown()


async def test_a_dropped_publish_event_is_covered_by_the_pointer_ttl():
    bus = InMemoryPublishBus()
    bus.drop = True
    engine = await build(pointer_ttl_s=0.2, publish_bus=bus)
    try:
        await draft_and_publish(engine, bundle())
        assert (await check(engine)).bundle_version == 1
        await draft_and_publish(engine, bundle(), "shadow", 10)
        await promote(engine)
        assert (await check(engine)).bundle_version == 1  # inside the TTL, event lost
        await asyncio.sleep(0.3)
        await check(engine)  # revalidates in the background
        await engine.guard.policy_cache.drain()
        assert (await check(engine)).bundle_version == 2
    finally:
        await engine.shutdown()


async def tenant_with_directory(ttl_s):
    """A real directory (store, provisioner, cache) whose tenant.changed events reach the
    engine through the bus the deployment owns."""
    store, bus = InMemoryDirectoryStore(), InMemoryEventBus()
    prov = TenantProvisioner(store, bus, clock=lambda: 1_700_000_000.0)
    record = await prov.create(OPS, slug="acme", domain="insurance")
    cached = CachedTenantDirectory(store, ttl_s=ttl_s)
    bus.subscribe(cached.on_changed)  # the directory's own cache
    return prov, bus, record, cached


async def test_suspend_and_reinstate_take_effect_at_the_next_check_by_event():
    prov, bus, record, cached = await tenant_with_directory(ttl_s=3600.0)
    engine = await build(pointer_ttl_s=60.0, tenants=cached)
    bus.subscribe(engine.on_tenant_changed)  # what the deployment wires
    tid = record.tenant_id
    try:
        await draft_and_publish(engine, bundle(tid), tenant=tid)
        assert (await check(engine, tid)).bundle_version == 1
        record = await prov.set_status(OPS, tid, record.version, "suspended")
        verdict = await check(engine, tid)
        assert verdict.reason == Reason.POLICY_UNAVAILABLE  # refused at once
        record = await prov.set_status(OPS, tid, record.version, "active")
        assert (await check(engine, tid)).bundle_version == 1  # reinstated at once
    finally:
        await engine.shutdown()


async def test_a_dropped_tenant_changed_event_is_covered_by_the_ttls():
    prov, _, record, cached = await tenant_with_directory(ttl_s=0.1)
    engine = await build(pointer_ttl_s=0.2, tenants=cached)  # engine NOT subscribed: dropped
    tid = record.tenant_id
    try:
        await draft_and_publish(engine, bundle(tid), tenant=tid)
        assert (await check(engine, tid)).bundle_version == 1
        await prov.set_status(OPS, tid, record.version, "suspended")
        assert (await check(engine, tid)).bundle_version == 1  # served from the policy cache
        await asyncio.sleep(0.3)
        await check(engine, tid)  # the refresh runs in the background
        await engine.guard.policy_cache.drain()
        verdict = await check(engine, tid)
        assert verdict.reason == Reason.POLICY_UNAVAILABLE  # the suspension has reached it
    finally:
        await engine.shutdown()


async def test_the_engine_exposes_the_publish_service_and_bus_to_the_admin_app():
    engine = await build()
    try:
        assert engine.publish_service is not None and engine.publish_bus is not None
        assert engine.draft_tools is not None and engine.golden_service is not None
    finally:
        await engine.shutdown()


@pytest.mark.parametrize("missing", ["lifecycle"])
async def test_an_engine_without_a_lifecycle_store_cannot_serve_the_admin_api(missing):
    from guardrail_engine.engine import AdminApiUnavailableError
    from guardrail_engine.store import InMemoryPolicyStore

    engine = await build_engine(
        settings("production", signed_context={"allow_v1_hmac": True}),
        verifier=verifier(), tenants=directory(), model=FakeDecisionModel(),
        store=InMemoryPolicyStore(catalog=None), authz_audit=type(
            "D", (InMemoryAuthzAudit,), {"durable": True})(),
    )  # fmt: skip
    try:
        assert engine.publish_service is None  # production with an injected store: nothing built
        with pytest.raises(AdminApiUnavailableError, match="publish_service"):
            engine.admin_app()
    finally:
        await engine.shutdown()
