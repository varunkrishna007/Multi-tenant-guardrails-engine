"""M2-03 on the engine: the tool registry feeds the directory's profile (accepted entries only),
a registry change reloads the profile at once by event, and the screening goes through the
engine's own pipeline."""

import json

from test_engine_propagation import admin_of, build, tenant_with_directory

from guardrail_engine.admin.lifecycle import GuardrailPublished
from guardrail_engine.authz import Principal, Role
from guardrail_engine.store.adapters.postgres import event_payload, parse_event

BASE = "/v1/tenants/{tid}/guardrails"


def reviewer_of(tenant, subject="carol"):
    return Principal(subject, tenant, frozenset({Role.GUARDRAIL_REVIEWER}), issuer="https://i/")


async def put_tool(engine, tenant, name, description):
    d = await engine.authorizer.authorize(
        admin_of(tenant), "PUT", BASE + "/tools/{name}", tenant_id=tenant
    )
    body = json.dumps({"description": description}).encode()
    return await engine.tool_service.put(d, admin_of(tenant), name, body)


async def test_only_accepted_tools_reach_the_cached_directory_profile_at_once():
    _, bus, record, cached = await tenant_with_directory(ttl_s=3600.0)
    engine = await build(tenants=cached)
    tid = record.tenant_id
    try:
        bus.subscribe(engine.on_tenant_changed)
        assert (await cached.get(tid)).tools == {}  # cached for an hour
        entry, _ = await put_tool(engine, tid, "claims.lookup", "Looks up a claim by number.")
        assert entry.status == "accepted"
        # the registry change reached the directory cache through the engine's bus subscription
        assert sorted((await cached.get(tid)).tools) == ["claims.lookup"]
        engine.model.set_noul("p__inj_indirect", 0.7)  # escalate: held
        held, _ = await put_tool(engine, tid, "page.fetch", "Fetches a page.")
        assert held.status == "held"
        assert sorted((await cached.get(tid)).tools) == ["claims.lookup"]
    finally:
        await engine.shutdown()


async def test_the_screening_runs_through_the_engines_pipeline_and_is_metered_apart():
    _, _, record, cached = await tenant_with_directory(ttl_s=3600.0)
    engine = await build(tenants=cached)
    try:
        await put_tool(engine, record.tenant_id, "claims.lookup", "Looks up a claim by number.")
        assert len(engine.model.calls) == 1
        assert sorted(engine.model.calls[0].questions) == [
            "p__ai_addressed", "p__inj_direct", "p__inj_indirect",
        ]  # fmt: skip
        await engine.guard.gateway.drain()
    finally:
        await engine.shutdown()


def test_the_tools_event_round_trips_through_the_notify_payload():
    event = GuardrailPublished("t_alpha", 0, "tools")
    assert parse_event(event_payload(event)) == event
    assert parse_event(event_payload(GuardrailPublished("t_alpha", 3, "bogus"))) is None


async def test_an_engine_exposes_the_tool_service_to_the_admin_app():
    engine = await build()
    try:
        assert engine.tool_service is not None and engine.catalog_service is not None
        assert engine.catalog_admin is not None
    finally:
        await engine.shutdown()
