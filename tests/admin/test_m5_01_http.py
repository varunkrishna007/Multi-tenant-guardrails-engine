"""M5-01 over HTTP: ``PUT /v1/tenants/{tid}/guardrails/tier`` is the platform operator's alone.
A tenant's admin (any role, own tenant or another) gets 403 and nothing changes; an operator
sets the tier, and the answer says what takes effect when and what the running version lacks."""

from __future__ import annotations

import json

import httpx
import pytest
from admin_fixtures import ALPHA, BETA, Admin, bundle
from cryptography.hazmat.primitives.asymmetric import rsa
from guard_fixtures import CLAIMS_V1, FLOOR_V1
from test_m5_02_http import ISS, JSON, headers, jwk

from guardrail_engine.admin.adapters.fastapi_app import create_admin_app
from guardrail_engine.admin.tiers import TierService
from guardrail_engine.authz import Principal
from guardrail_engine.directory import (
    DirectoryAuditEvent,
    InMemoryDirectoryStore,
    InMemoryEventBus,
    TenantProvisioner,
    TenantRecord,
)
from guardrail_engine.directory.model import audit_fields
from guardrail_engine.gateway.sinks import ALERT_TIER_RAISE_UNMET
from guardrail_engine.policy import InMemoryCatalog
from guardrail_engine.signing.adapters.oidc import OidcConfig, PyJwtAuthenticator, StaticJwksSource

AUD = "guardrail-admin-api"


@pytest.fixture(scope="module")
def key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


URL = "/v1/tenants/{}/guardrails/tier"
ROLES = ("viewer", "guardrail_admin", "guardrail_reviewer", "auditor")


@pytest.fixture
async def admin():
    a = Admin()
    yield a
    await a.aclose()


@pytest.fixture
async def world(admin):
    """The directory's write side, seeded with ALPHA and BETA (standard), and a tier service
    whose catalog requires the claims pack of the regulated tiers."""
    store, bus = InMemoryDirectoryStore(), InMemoryEventBus()
    for tenant in (ALPHA, BETA):
        record = TenantRecord(tenant, tenant.removeprefix("t_"), "insurance")
        await store.insert(
            record,
            DirectoryAuditEvent(tenant, 1, "create", "seed", 0.0, None, audit_fields(record)),
        )
    provisioner = TenantProvisioner(store, bus, alerts=admin.alerts)
    catalog = InMemoryCatalog(
        floors=[FLOOR_V1], packs=[CLAIMS_V1], tier_required_packs={"regulated": ["claims"]}
    )
    return store, TierService(provisioner, store, catalog, admin.lifecycle)


@pytest.fixture
def app(admin, world, key):
    auth = PyJwtAuthenticator(
        OidcConfig(frozenset({ISS}), AUD), StaticJwksSource({"keys": [jwk(key)]})
    )
    return create_admin_app(
        authenticator=auth, authorizer=admin.authorizer, service=admin.service,
        tools=admin.tools, golden=admin.golden, catalog=admin.catalog_service,
        publisher=admin.publisher, tool_registry=admin.tool_service, floors=admin.floors,
        repin=admin.repin, tiers=world[1],
    )  # fmt: skip


@pytest.fixture
async def client(app):
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://admin.test") as c:
        yield c


def put(client, key, path_tenant, body, *roles, operator=True):
    """The request of a platform operator (no home tenant), unless ``operator`` is False."""
    who = (
        {"tenant": None, "sub": "ops-1", "platform_operator": True}
        if operator
        else {"tenant": ALPHA}
    )
    return client.put(
        URL.format(path_tenant), content=json.dumps(body),
        headers={**headers(key, *(roles or ("viewer",)), **who), **JSON},
    )  # fmt: skip


async def tier_of(world, tenant=ALPHA):
    return (await world[0].get(tenant)).tier


@pytest.mark.parametrize("role", ROLES)
@pytest.mark.parametrize("tenant", [ALPHA, BETA])
async def test_a_tenant_admin_gets_403_whatever_the_role_or_the_tenant(
    client,
    key,
    world,
    role,
    tenant,
):
    r = await put(
        client, key, tenant, {"tier": "regulated", "reason": "self-service"},
        role, "guardrail_admin", operator=False,
    )  # fmt: skip
    assert (r.status_code, r.json()["error"]["code"]) == (403, "forbidden")
    # on its own tenant the platform route is refused for want of the operator flag; on another
    # tenant the crossing is refused first (the same 403)
    assert r.json()["error"]["message"] == (
        "not_platform_operator" if tenant == ALPHA else "tenant_mismatch"
    )
    assert await tier_of(world, ALPHA) == await tier_of(world, BETA) == "standard"
    assert len(await world[0].audit_events(ALPHA)) == 1  # only the seed


async def test_an_unauthenticated_caller_gets_401_and_a_bundle_cannot_carry_a_tier(
    client,
    key,
    world,
    admin,
):
    r = await client.put(URL.format(ALPHA), content=b"{}", headers=JSON)
    assert r.status_code == 401
    # the draft route: a tier (or project) inside a bundle is not a field, and is refused
    doc = {**bundle(ALPHA), "tier": "standard", "project": "reg-1"}
    drafted = await client.put(
        f"/v1/tenants/{ALPHA}/guardrails/draft", content=json.dumps(doc),
        headers={**headers(key, "guardrail_admin"), **JSON},
    )  # fmt: skip
    assert drafted.status_code == 422
    assert await tier_of(world) == "standard"


async def test_an_operator_sets_the_tier_and_is_told_what_takes_effect_when(
    client,
    key,
    world,
    admin,
):
    await admin.env.publish(bundle(ALPHA))  # ALPHA runs a version that lacks the claims pack
    r = await put(client, key, ALPHA, {"tier": "regulated", "reason": "contract 2026-11"})
    assert r.status_code in (200,), r.text
    body = r.json()
    assert (body["tier"], body["previous_tier"], body["version"]) == ("regulated", "standard", 2)
    assert body["approval_required"] is True
    assert body["unmet_requirements"] == ["pack:claims"]
    assert "keeps running" in body["takes_effect"]["required_packs_and_rules"]
    assert await tier_of(world) == "regulated" and await tier_of(world, BETA) == "standard"
    [event] = (await world[0].audit_events(ALPHA))[-1:]
    assert (event.action, event.actor, event.before["tier"], event.after["tier"]) == (
        "set_tier", f"{ISS}#ops-1", "standard", "regulated",
    )  # fmt: skip
    assert event.after["reason"] == "contract 2026-11"
    [alert] = admin.alerts.warnings(ALERT_TIER_RAISE_UNMET)
    assert alert.tenant_id == ALPHA and alert.reason == "pack:claims"


async def test_the_operators_cross_tenant_access_is_audited(client, key, admin):
    await put(client, key, BETA, {"tier": "regulated", "reason": "contract"})
    [event] = [e for e in admin.audit.events if e.target_tenant_id == BETA]
    assert (event.route, event.allowed, event.actor) == (
        "/v1/tenants/{tid}/guardrails/tier", True, f"{ISS}#ops-1",
    )  # fmt: skip


@pytest.mark.parametrize(
    ("body", "status", "code"),
    [
        ({"tier": "gold", "reason": "x"}, 422, "invalid_body"),
        ({"tier": "regulated"}, 422, "invalid_body"),
        ({"tier": "regulated", "reason": "x", "project": "reg-1"}, 422, "invalid_body"),
        ({"tier": "regulated", "reason": "x", "expected_version": 9}, 409, "version_conflict"),
    ],
)
async def test_a_bad_request_is_refused_and_changes_nothing(
    client,
    key,
    world,
    body,
    status,
    code,
):
    r = await put(client, key, ALPHA, body)
    assert (r.status_code, r.json()["error"]["code"]) == (status, code)
    assert await tier_of(world) == "standard"


def test_the_principal_that_asks_is_not_trusted_for_the_flag_alone():
    # the provisioner re-checks the operator flag: a principal built without it is refused there
    from guardrail_engine.directory import NotAPlatformOperator

    prov = TenantProvisioner(InMemoryDirectoryStore(), InMemoryEventBus())
    with pytest.raises(NotAPlatformOperator):
        prov._operator(Principal("ops-1", ALPHA))
