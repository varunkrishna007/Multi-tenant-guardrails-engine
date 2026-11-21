"""M2-02 factory wiring: the engine builds the draft service from its store and serves the
Admin API as an ASGI app once it has an authenticator and an authorizer."""

from __future__ import annotations

import httpx
import pytest
from engine_fixtures import TENANT, bundle, directory, settings, verifier

from guardrail_engine.admin import InMemoryDraftStore
from guardrail_engine.authz import AuthenticationError, InMemoryAuthzAudit, Principal, Role
from guardrail_engine.decision import FakeDecisionModel
from guardrail_engine.engine import AdminApiUnavailableError, build_engine
from guardrail_engine.store import InMemoryPolicyStore


class Tokens:
    """Maps a token string to a principal; anything else is refused."""

    def __init__(self, **principals):
        self.principals = principals

    async def authenticate(self, token):
        try:
            return self.principals[token]
        except KeyError:
            raise AuthenticationError("bad_signature") from None


async def build(**kwargs):
    return await build_engine(
        settings("test"), verifier=verifier(), tenants=directory(), model=FakeDecisionModel(),
        **kwargs,
    )  # fmt: skip


async def test_an_engine_without_an_authenticator_or_authorizer_cannot_serve_the_admin_api():
    engine = await build()
    try:
        assert engine.draft_service is not None  # the memory store brings its draft store
        with pytest.raises(AdminApiUnavailableError, match=r"authenticator.*authorizer"):
            engine.admin_app()
    finally:
        await engine.shutdown()


async def test_an_injected_store_in_production_has_no_draft_service_unless_one_is_passed():
    store = InMemoryPolicyStore(catalog=None)
    engine = await build_engine(
        settings("production"), verifier=verifier(), tenants=directory(),
        model=FakeDecisionModel(), store=store, authz_audit=_Durable(),
    )  # fmt: skip
    try:
        assert engine.draft_service is None
    finally:
        await engine.shutdown()


class _Durable(InMemoryAuthzAudit):
    durable = True


async def test_the_admin_app_serves_a_draft_through_the_engines_own_parts():
    principals = {"t-admin": Principal("alice", TENANT, frozenset({Role.GUARDRAIL_ADMIN}))}
    engine = await build(
        authenticator=Tokens(**principals), authz_audit=InMemoryAuthzAudit(),
        draft_store=InMemoryDraftStore(),
    )  # fmt: skip
    try:
        app = engine.admin_app()
        transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
        async with httpx.AsyncClient(transport=transport, base_url="http://admin.test") as c:
            url = f"/v1/tenants/{TENANT}/guardrails"
            assert (await c.get(url)).status_code == 401
            headers = {"Authorization": "Bearer t-admin", "Content-Type": "application/json"}
            import json

            r = await c.put(url + "/draft", content=json.dumps(bundle()), headers=headers)
            assert r.status_code == 201, r.text
            assert r.json()["document"]["tenant_id"] == TENANT
            other = await c.get("/v1/tenants/t_other/guardrails", headers=headers)
            assert other.status_code == 403
    finally:
        await engine.shutdown()


async def test_the_engines_admin_app_tests_a_draft_on_its_own_guard_service_and_stops_at_shutdown():
    import json

    principals = {"t-rev": Principal("rita", TENANT, frozenset({Role.GUARDRAIL_REVIEWER}))}
    principals["t-admin"] = Principal("alice", TENANT, frozenset({Role.GUARDRAIL_ADMIN}))
    engine = await build(
        authenticator=Tokens(**principals), authz_audit=InMemoryAuthzAudit(),
        draft_store=InMemoryDraftStore(),
    )  # fmt: skip
    app = engine.admin_app()
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://admin.test") as c:
        url = f"/v1/tenants/{TENANT}/guardrails/draft"
        json_h = {"Content-Type": "application/json"}
        admin_h = {"Authorization": "Bearer t-admin", **json_h}
        assert (await c.put(url, content=json.dumps(bundle()), headers=admin_h)).status_code == 201
        valid = await c.post(url + "/validate", headers=admin_h)
        assert valid.status_code == 200 and valid.json()["valid"] is True
        body = json.dumps({"guard_point": "output", "samples": [{"id": "a", "content": "hello"}]})
        rev_h = {"Authorization": "Bearer t-rev", **json_h}
        ran = await c.post(url + "/test", content=body, headers=rev_h)
        assert ran.status_code == 200, ran.text
        assert ran.json()["results"][0]["decision"] in {"allow", "escalate", "block"}
        await engine.shutdown()
        after = await c.post(url + "/test", content=body, headers=rev_h)
        assert after.status_code == 503 and after.json()["error"]["code"] == "unavailable"


async def test_a_running_draft_test_is_in_flight_work_and_shutdown_waits_for_it():
    """The Guard Service must not be closed under a test that is still running."""
    import asyncio
    import json

    principals = {
        "t-admin": Principal("alice", TENANT, frozenset({Role.GUARDRAIL_ADMIN})),
        "t-rev": Principal("rita", TENANT, frozenset({Role.GUARDRAIL_REVIEWER})),
    }
    engine = await build(
        authenticator=Tokens(**principals), authz_audit=InMemoryAuthzAudit(),
        draft_store=InMemoryDraftStore(),
    )  # fmt: skip
    gate, started, real = asyncio.Event(), asyncio.Event(), engine.model.decide

    async def slow(*args, **kwargs):
        started.set()
        await gate.wait()
        return await real(*args, **kwargs)

    engine.model.decide = slow
    transport = httpx.ASGITransport(app=engine.admin_app(), raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://admin.test") as c:
        url = f"/v1/tenants/{TENANT}/guardrails/draft"
        json_h = {"Content-Type": "application/json"}
        await c.put(
            url, content=json.dumps(bundle()), headers={"Authorization": "Bearer t-admin", **json_h}
        )
        body = json.dumps({"guard_point": "output", "samples": [{"id": "a", "content": "hello"}]})
        running = asyncio.ensure_future(
            c.post(url + "/test", content=body, headers={"Authorization": "Bearer t-rev", **json_h})
        )
        await started.wait()
        assert engine.in_flight == 1
        closing = asyncio.ensure_future(engine.shutdown())
        await asyncio.sleep(0.05)
        assert not closing.done() and not engine.accepting  # waiting for the test to end
        gate.set()
        assert (await running).status_code == 200
        await closing
        assert engine.in_flight == 0


async def test_the_engines_admin_app_stores_a_golden_set_and_runs_it_through_the_test_route():
    import json

    principals = {
        "t-admin": Principal("alice", TENANT, frozenset({Role.GUARDRAIL_ADMIN})),
        "t-rev": Principal("rita", TENANT, frozenset({Role.GUARDRAIL_REVIEWER})),
    }
    engine = await build(authenticator=Tokens(**principals), authz_audit=InMemoryAuthzAudit())
    try:
        assert engine.golden_service is not None  # the memory store brings its golden store
        transport = httpx.ASGITransport(app=engine.admin_app(), raise_app_exceptions=False)
        async with httpx.AsyncClient(transport=transport, base_url="http://admin.test") as c:
            base = f"/v1/tenants/{TENANT}/guardrails"
            json_h = {"Content-Type": "application/json"}
            admin_h = {"Authorization": "Bearer t-admin", **json_h}
            rev_h = {"Authorization": "Bearer t-rev", **json_h}
            assert (
                await c.put(base + "/draft", content=json.dumps(bundle()), headers=admin_h)
            ).status_code == 201
            row = {"id": "e1", "guard_point": "output", "label": "allow", "content": "hello"}
            up = await c.post(
                base + "/golden-sets",
                content=json.dumps({"name": "cases", "examples": [row]}),
                headers=rev_h,
            )
            assert up.status_code == 201, up.text
            ran = await c.post(
                base + "/draft/test",
                content=json.dumps({"guard_point": "output", "golden_set": up.json()["set_id"]}),
                headers=rev_h,
            )
            assert ran.status_code == 200, ran.text
            assert ran.json()["results"][0]["expected"] == "allow"
    finally:
        await engine.shutdown()


async def test_outside_test_an_issuerless_principal_is_refused_by_the_authorizer():
    """The audit actor needs an issuer, so a principal without one (not
    from the OIDC adapter) is refused everywhere but ``test``."""
    bare = Principal("alice", TENANT, frozenset({Role.VIEWER}))
    engine = await build_engine(
        settings("production"),
        verifier=verifier(), tenants=directory(), model=FakeDecisionModel(),
        authz_audit=type("D", (InMemoryAuthzAudit,), {"durable": True})(),
    )  # fmt: skip
    try:
        decision = await engine.authorizer.authorize(
            bare, "GET", "/v1/tenants/{tid}/guardrails", tenant_id=TENANT
        )
        assert not decision.allowed and decision.reason == "missing_issuer"
        with_issuer = Principal("alice", TENANT, frozenset({Role.VIEWER}), False, "https://i/")
        ok = await engine.authorizer.authorize(
            with_issuer, "GET", "/v1/tenants/{tid}/guardrails", tenant_id=TENANT
        )
        assert ok.allowed
    finally:
        await engine.shutdown()
