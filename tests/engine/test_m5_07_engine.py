"""M5-07 factory wiring: an engine built over a cached tenant directory refuses a terminated
tenant's checks (``forbidden`` / ``tenant_terminated``) and its Admin API calls (403,
``tenant_terminated``) from the moment the provisioner marks it ``terminating``."""

from __future__ import annotations

import sys
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "guard"))  # guard_fixtures

from engine_fixtures import TENANT, settings, verifier

from guardrail_engine.authz import InMemoryAuthzAudit, Principal, Role
from guardrail_engine.decision import FakeDecisionModel
from guardrail_engine.directory import (
    CachedTenantDirectory,
    InMemoryDirectoryStore,
    InMemoryEventBus,
    TenantProvisioner,
)
from guardrail_engine.engine import build_engine
from guardrail_engine.guard import CheckContext, Decision, Reason

BASE = f"/v1/tenants/{TENANT}/guardrails"
OPS = Principal("ops-1", None, frozenset(), True)


class Tokens:
    async def authenticate(self, token):
        return Principal(token, TENANT, frozenset({Role.GUARDRAIL_ADMIN}), issuer="https://i/")


async def test_the_engine_refuses_checks_and_admin_calls_once_the_tenant_is_terminating():
    store, bus = InMemoryDirectoryStore(), InMemoryEventBus()
    cached = CachedTenantDirectory(store)
    bus.subscribe(cached.on_changed)

    async def no_sleep(_):
        return None

    prov = TenantProvisioner(store, bus, id_factory=lambda: TENANT, sleep=no_sleep)
    await prov.create(OPS, slug="dogfood", domain="insurance")
    engine = await build_engine(
        settings("test"), verifier=verifier(), tenants=cached, model=FakeDecisionModel(),
        authz_audit=InMemoryAuthzAudit(), authenticator=Tokens(),
    )  # fmt: skip
    try:
        app = engine.admin_app()
        transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
        async with httpx.AsyncClient(transport=transport, base_url="http://admin.test") as c:
            headers = {"Authorization": "Bearer alice"}
            assert (await c.get(BASE, headers=headers)).status_code != 403

            seen = []

            async def during_the_drain():  # the status is `terminating` here, not yet terminated
                seen.append(await c.get(BASE, headers=headers))

            prov._sleep = lambda s: during_the_drain()
            await prov.terminate(OPS, TENANT, "contract ended")

            after = await c.get(BASE + "/versions", headers=headers)
            put = await c.put(
                BASE + "/draft",
                content=b"{}",
                headers={**headers, "Content-Type": "application/json"},
            )
        for r in (*seen, after, put):
            assert r.status_code == 403
            assert r.json()["error"]["code"] == "tenant_terminated"
        ctx = CheckContext(signed_context=verifier().issue(TENANT))
        verdict = await engine.check(ctx, "output", "hello")
        assert (verdict.decision, verdict.reason) == (Decision.FORBIDDEN, Reason.TENANT_TERMINATED)
        assert verdict.tenant_id is None
    finally:
        await engine.shutdown()
