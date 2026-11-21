"""M5-06 over HTTP: the operator's tier route answers with the tenant's dedicated project, and a
raise with none free is a clear 409 operator error that changes nothing."""

from __future__ import annotations

import httpx
import pytest
from admin_fixtures import ALPHA, BETA, Admin
from cryptography.hazmat.primitives.asymmetric import rsa
from guard_fixtures import CLAIMS_V1, FLOOR_V1
from test_m5_01_http import URL, put, tier_of  # noqa: F401
from test_m5_02_http import ISS, jwk

from guardrail_engine.admin.adapters.fastapi_app import create_admin_app
from guardrail_engine.admin.tiers import TierService
from guardrail_engine.directory import (
    DirectoryAuditEvent,
    InMemoryDirectoryStore,
    InMemoryEventBus,
    TenantProvisioner,
    TenantRecord,
)
from guardrail_engine.directory.model import audit_fields
from guardrail_engine.policy import InMemoryCatalog
from guardrail_engine.projects import DedicatedProjects
from guardrail_engine.signing.adapters.oidc import OidcConfig, PyJwtAuthenticator, StaticJwksSource

AUD = "guardrail-admin-api"


@pytest.fixture(scope="module")
def key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
async def admin():
    a = Admin()
    yield a
    await a.aclose()


@pytest.fixture
async def world(admin):
    store, bus = InMemoryDirectoryStore(), InMemoryEventBus()
    for tenant in (ALPHA, BETA):
        record = TenantRecord(tenant, tenant.removeprefix("t_"), "insurance")
        await store.insert(
            record,
            DirectoryAuditEvent(tenant, 1, "create", "seed", 0.0, None, audit_fields(record)),
        )
    provisioner = TenantProvisioner(
        store, bus, projects=DedicatedProjects.of(["reg-1"], environment="production")
    )
    catalog = InMemoryCatalog(floors=[FLOOR_V1], packs=[CLAIMS_V1])
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


async def test_the_answer_names_the_dedicated_project_the_raise_assigned(client, key, world):
    r = await put(client, key, ALPHA, {"tier": "regulated", "reason": "contract"})
    assert r.status_code == 200 and r.json()["project"] == "reg-1"
    assert (await world[0].get(ALPHA)).project == "reg-1"
    event = (await world[0].audit_events(ALPHA))[-1]
    assert (event.before["project"], event.after["project"]) == (None, "reg-1")


async def test_a_raise_with_no_dedicated_project_free_is_a_clear_operator_error(
    client,
    key,
    world,
):
    first = await put(client, key, ALPHA, {"tier": "regulated", "reason": "a"})
    assert first.status_code == 200
    r = await put(client, key, BETA, {"tier": "regulated", "reason": "b"})
    assert (r.status_code, r.json()["error"]["code"]) == (409, "no_dedicated_project")
    assert "dedicated Gemini project" in r.json()["error"]["message"]
    assert await tier_of(world, BETA) == "standard"
