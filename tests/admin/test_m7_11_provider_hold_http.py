"""M7-11 over HTTP: ``GET`` and ``PUT /v1/platform/provider/degraded`` are the platform
operator's alone. A tenant's credential is refused whatever its roles, and nothing changes; an
operator's hold or lift is recorded as a class A event before the gateways change, and not made
if it can't be recorded."""

from __future__ import annotations

import json

import httpx
import pytest
from admin_fixtures import Admin
from cryptography.hazmat.primitives.asymmetric import rsa
from test_m5_02_http import ISS, JSON, headers, jwk

from guardrail_engine.admin.adapters.fastapi_app import create_admin_app
from guardrail_engine.admin.provider_health import ProviderHealthService
from guardrail_engine.signing.adapters.oidc import OidcConfig, PyJwtAuthenticator, StaticJwksSource

AUD = "guardrail-admin-api"
URL = "/v1/platform/provider/degraded"
ROLES = ("viewer", "guardrail_admin", "guardrail_reviewer", "auditor")


class Gateway:
    """What the service uses of a gateway: the hold and the status."""

    def __init__(self) -> None:
        self.held = False

    def force_degraded(self, degraded: bool) -> bool:
        changed = degraded != self.held
        self.held = degraded
        return changed

    def degraded_status(self) -> dict:
        return {"degraded": self.held, "forced": self.held, "cause": None, "next_probe_in_s": None}


@pytest.fixture(scope="module")
def key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
async def admin():
    a = Admin()
    yield a
    await a.aclose()


@pytest.fixture
def gateways():
    return {None: Gateway(), "dedicated-a": Gateway()}


@pytest.fixture
def app(admin, key, gateways):
    auth = PyJwtAuthenticator(
        OidcConfig(frozenset({ISS}), AUD), StaticJwksSource({"keys": [jwk(key)]})
    )
    return create_admin_app(
        authenticator=auth, authorizer=admin.authorizer, service=admin.service,
        tools=admin.tools, golden=admin.golden, catalog=admin.catalog_service,
        publisher=admin.publisher, tool_registry=admin.tool_service, floors=admin.floors,
        repin=admin.repin,
        provider_health=ProviderHealthService(admin.platform, lambda: gateways),
    )  # fmt: skip


@pytest.fixture
async def client(app):
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://admin.test") as c:
        yield c


def operator(key, *roles):
    return {
        **headers(key, *(roles or ("viewer",)), tenant=None, sub="ops-1", platform_operator=True),
        **JSON,
    }


def hold(client, key, degraded=True, reason="the provider's status page says it is down"):
    return client.put(
        URL, content=json.dumps({"degraded": degraded, "reason": reason}), headers=operator(key)
    )


async def test_an_operators_hold_is_recorded_first_then_applied_to_every_gateway(
    client, key, admin, gateways
):
    r = await hold(client, key)
    assert (r.status_code, r.json()) == (200, {"degraded": True, "changed": True})
    assert all(g.held for g in gateways.values())
    events = [e for e in await admin.platform.events() if e.action.startswith("provider_")]
    assert [e.action for e in events] == ["provider_degraded_hold"]
    assert events[0].actor.endswith("ops-1")
    assert events[0].detail["reason"] == "the provider's status page says it is down"


async def test_lifting_it_is_recorded_too_and_a_repeat_changes_nothing(
    client, key, admin, gateways
):
    await hold(client, key)
    lifted = await hold(client, key, degraded=False, reason="the provider is back")
    assert lifted.json() == {"degraded": False, "changed": True}
    assert not any(g.held for g in gateways.values())
    again = await hold(client, key, degraded=False, reason="checking")
    assert again.json() == {"degraded": False, "changed": False}
    actions = [e.action for e in await admin.platform.events() if e.action.startswith("provider_")]
    assert actions == ["provider_degraded_hold", "provider_degraded_lift", "provider_degraded_lift"]


async def test_the_status_lists_each_gateway(client, key, gateways):
    gateways[None].held = True
    r = await client.get(URL, headers=operator(key))
    assert r.status_code == 200
    assert r.json()["gateways"]["shared"]["degraded"] is True
    assert r.json()["gateways"]["dedicated-a"]["degraded"] is False


@pytest.mark.parametrize("role", ROLES)
@pytest.mark.parametrize("method", ["GET", "PUT"])
async def test_a_tenant_credential_is_refused_whatever_its_role(
    client, key, admin, gateways, role, method
):
    tenant = headers(key, role, "guardrail_admin", tenant="t_alpha")
    r = await client.request(
        method,
        URL,
        content=json.dumps({"degraded": True, "reason": "self-service"}),
        headers={**tenant, **JSON},
    )
    assert (r.status_code, r.json()["error"]["code"]) == (403, "forbidden")
    assert r.json()["error"]["message"] == "not_platform_operator"
    assert not any(g.held for g in gateways.values())
    assert [e for e in await admin.platform.events() if e.action.startswith("provider_")] == []


async def test_an_unauthenticated_caller_gets_401(client, gateways):
    r = await client.put(URL, content=b"{}", headers=JSON)
    assert r.status_code == 401 and not any(g.held for g in gateways.values())


async def test_if_the_event_cannot_be_recorded_the_hold_is_not_made(client, key, admin, gateways):
    admin.platform.fail_audit = True
    r = await hold(client, key)
    assert (r.status_code, r.json()["error"]["code"]) == (503, "unavailable")
    assert not any(g.held for g in gateways.values())


@pytest.mark.parametrize(
    "body",
    [
        {"reason": "no flag"},
        {"degraded": "yes", "reason": "not a boolean"},
        {"degraded": True},
        {"degraded": True, "reason": "  "},
        {"degraded": True, "reason": "x" * 201},
    ],
)
async def test_a_body_that_is_not_a_flag_and_a_reason_is_refused(client, key, gateways, body):
    r = await client.put(URL, content=json.dumps(body), headers=operator(key))
    assert (r.status_code, r.json()["error"]["code"]) == (422, "invalid_body")
    assert not any(g.held for g in gateways.values())
