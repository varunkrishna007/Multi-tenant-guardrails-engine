"""M5-02 over HTTP: the two approval routes and ``approval_id`` on publish and promote, behind
the real authenticator and authorizer, with the error codes a client sees."""

from __future__ import annotations

import json
import time
from datetime import timedelta

import httpx
import jwt
import pytest
from admin_fixtures import ALPHA, BETA, Admin, bundle, rule
from cryptography.hazmat.primitives.asymmetric import rsa

from guardrail_engine.admin.adapters.fastapi_app import create_admin_app
from guardrail_engine.admin.approvals import APPROVAL_TTL
from guardrail_engine.guard.tenants import TenantProfile
from guardrail_engine.policy.catalog import TenantAttributes
from guardrail_engine.signing.adapters.oidc import OidcConfig, PyJwtAuthenticator, StaticJwksSource

ISS, AUD = "https://idp.example.com/", "guardrail-admin-api"
BASE = "/v1/tenants/{}/guardrails"
JSON = {"Content-Type": "application/json"}


@pytest.fixture(scope="module")
def key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def jwk(key):
    entry = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    return {**entry, "kid": "k1", "use": "sig"}


@pytest.fixture
async def admin():
    a = Admin()
    a.tenants._profiles[ALPHA] = TenantProfile.build(
        TenantAttributes(tenant_id=ALPHA, tier="regulated"), "insurance", slug="alpha"
    )
    yield a
    await a.aclose()


@pytest.fixture
def app(admin, key):
    auth = PyJwtAuthenticator(
        OidcConfig(frozenset({ISS}), AUD), StaticJwksSource({"keys": [jwk(key)]})
    )
    return create_admin_app(
        authenticator=auth, authorizer=admin.authorizer, service=admin.service,
        tools=admin.tools, golden=admin.golden, catalog=admin.catalog_service,
        publisher=admin.publisher, tool_registry=admin.tool_service, floors=admin.floors,
        repin=admin.repin, calibration=admin.calibration, rollout=admin.rollout,
        approvals=admin.approvals,
    )  # fmt: skip


@pytest.fixture
async def client(app):
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://admin.test") as c:
        yield c


def headers(key, *roles, tenant=ALPHA, sub="alice", **claims):
    base = {
        "iss": ISS, "aud": AUD, "sub": sub, "iat": int(time.time()),
        "exp": int(time.time()) + 300, "roles": list(roles),
    }  # fmt: skip
    if tenant:
        base["tenant_id"] = tenant
    token = jwt.encode({**base, **claims}, key, algorithm="RS256", headers={"kid": "k1"})
    return {"Authorization": f"Bearer {token}"}


async def put_draft(client, key, name="r", if_match=None, sub="alice"):
    doc = bundle(ALPHA, rules=[rule(name, gps=("output",), mode="shadow")])
    extra = {"If-Match": if_match} if if_match else {}
    r = await client.put(
        BASE.format(ALPHA) + "/draft", content=json.dumps(doc),
        headers={**headers(key, "guardrail_admin", sub=sub), **JSON, **extra},
    )  # fmt: skip
    assert r.status_code in (200, 201), r.text
    return r.headers["etag"]


async def request(client, key, etag, body=None, **kw):
    return await client.post(
        BASE.format(ALPHA) + "/draft/approvals",
        content=json.dumps(body) if body is not None else b"",
        headers={**headers(key, "guardrail_admin", **kw), **JSON, "If-Match": etag},
    )


async def approve(client, key, approval_id, *roles, **kw):
    return await client.post(
        BASE.format(ALPHA) + f"/draft/approvals/{approval_id}/approve",
        headers=headers(key, *(roles or ("guardrail_admin",)), **kw),
    )


async def publish(client, key, etag, approval_id=None, mode="enforce", **kw):
    body = {"mode": mode, **({} if approval_id is None else {"approval_id": approval_id})}
    return await client.post(
        BASE.format(ALPHA) + "/draft/publish", content=json.dumps(body),
        headers={**headers(key, "guardrail_admin", **kw), **JSON, "If-Match": etag},
    )  # fmt: skip


async def test_request_approve_publish_over_http(client, key, admin):
    etag = await put_draft(client, key)
    asked = await request(client, key, etag)
    assert asked.status_code == 201
    body = asked.json()
    assert body["status"] == "pending" and body["action"] == "publish" and body["version"] is None
    assert body["draft_hash"] == etag.strip('"') and body["requested_by"] == f"{ISS}#alice"
    approval_id = body["id"]
    assert (await publish(client, key, etag, approval_id)).json()["error"]["code"] == (
        "approval_pending"
    )

    granted = await approve(client, key, approval_id, sub="bob")
    assert granted.status_code == 200
    assert (granted.json()["status"], granted.json()["approved_by"]) == (
        "approved", f"{ISS}#bob"
    )  # fmt: skip

    done = await publish(client, key, etag, approval_id)  # alice asked, bob approved
    assert done.status_code == 201 and done.json()["state"] == "active"
    again = await publish(client, key, etag, approval_id)
    assert (again.status_code, again.json()["error"]["code"]) == (409, "approval_used")


async def test_enforcing_without_an_approval_names_the_missing_one(client, key):
    etag = await put_draft(client, key)
    missing = await publish(client, key, etag)
    assert (missing.status_code, missing.json()["error"]["code"]) == (409, "approval_required")
    unknown = await publish(client, key, etag, "apr_" + "0" * 24)
    assert (unknown.status_code, unknown.json()["error"]["code"]) == (404, "approval_not_found")
    bad = await publish(client, key, etag, "not-an-id")
    assert (bad.status_code, bad.json()["error"]["code"]) == (422, "invalid_draft")
    shadow = await publish(client, key, etag, mode="shadow")  # a first publish can't be shadow
    assert shadow.json()["error"]["code"] == "no_active_version"


async def test_the_three_who_may_not_approve_get_their_own_403(client, key):
    etag = await put_draft(client, key)
    approval_id = (await request(client, key, etag)).json()["id"]
    mine = await approve(client, key, approval_id)  # alice asked
    assert (mine.status_code, mine.json()["error"]["code"]) == (403, "self_approval")
    robot = await approve(client, key, approval_id, sub="ci", service_account=True)
    assert (robot.status_code, robot.json()["error"]["code"]) == (403, "service_account_approval")
    grant = await approve(client, key, approval_id, sub="ci2", gty="client-credentials")
    assert grant.json()["error"]["code"] == "service_account_approval"
    operator = await approve(
        client, key, approval_id, sub="ops", tenant=None, platform_operator=True
    )  # across tenants, with the admin role
    assert (operator.status_code, operator.json()["error"]["code"]) == (403, "operator_approval")
    at_home = await approve(client, key, approval_id, sub="ops2", platform_operator=True)
    assert at_home.json()["error"]["code"] == "operator_approval"
    assert (await approve(client, key, approval_id, sub="bob")).status_code == 200  # a person


@pytest.mark.parametrize("role", ["viewer", "guardrail_reviewer", "auditor"])
async def test_only_an_admin_requests_or_approves(client, key, role):
    etag = await put_draft(client, key)
    denied = await client.post(
        BASE.format(ALPHA) + "/draft/approvals",
        headers={**headers(key, role), **JSON, "If-Match": etag},
    )
    assert (denied.status_code, denied.json()["error"]["message"]) == (403, "missing_role")
    approval_id = (await request(client, key, etag)).json()["id"]
    assert (await approve(client, key, approval_id, role, sub="bob")).status_code == 403


async def test_another_tenants_admin_cannot_reach_the_approval(client, key):
    etag = await put_draft(client, key)
    approval_id = (await request(client, key, etag)).json()["id"]
    r = await client.post(
        BASE.format(ALPHA) + f"/draft/approvals/{approval_id}/approve",
        headers=headers(key, "guardrail_admin", tenant=BETA, sub="mallory"),
    )
    assert (r.status_code, r.json()["error"]["message"]) == (403, "tenant_mismatch")


async def test_an_edit_cancels_and_time_expires(client, key, admin):
    etag = await put_draft(client, key)
    approval_id = (await request(client, key, etag)).json()["id"]
    await approve(client, key, approval_id, sub="bob")
    new_etag = await put_draft(client, key, "other", if_match=etag)
    cancelled = await publish(client, key, new_etag, approval_id)
    assert cancelled.json()["error"]["code"] == "approval_cancelled"

    fresh = (await request(client, key, new_etag)).json()["id"]
    await approve(client, key, fresh, sub="bob")
    admin.now += APPROVAL_TTL + timedelta(seconds=1)
    late = await publish(client, key, new_etag, fresh)
    assert (late.status_code, late.json()["error"]["code"]) == (409, "approval_expired")


async def test_a_request_needs_the_draft_it_saw_and_a_tenant_that_needs_approval(
    client, key, admin
):
    etag = await put_draft(client, key)
    r = await client.post(
        BASE.format(ALPHA) + "/draft/approvals", headers={**headers(key, "guardrail_admin")}
    )
    assert r.status_code == 428
    stale = await request(client, key, '"sha256:' + "0" * 64 + '"')
    assert stale.status_code == 412
    bad = await request(client, key, etag, {"action": "rollback"})
    assert bad.status_code == 422
    admin.tenants._profiles[ALPHA] = TenantProfile.build(
        TenantAttributes(tenant_id=ALPHA), "insurance", slug="alpha"
    )
    not_needed = await request(client, key, etag)
    assert (not_needed.status_code, not_needed.json()["error"]["code"]) == (
        409, "approval_not_required"
    )  # fmt: skip


async def test_promoting_a_shadow_candidate_over_http(client, key, admin):
    admin.tenants._profiles[ALPHA] = TenantProfile.build(
        TenantAttributes(tenant_id=ALPHA), "insurance", slug="alpha"
    )
    etag = await put_draft(client, key)
    assert (await publish(client, key, etag)).status_code == 201  # v1, standard tier
    admin.tenants._profiles[ALPHA] = TenantProfile.build(
        TenantAttributes(tenant_id=ALPHA, tier="regulated"), "insurance", slug="alpha"
    )
    etag = await put_draft(client, key, "r2", if_match=etag)
    assert (await publish(client, key, etag, mode="shadow")).json()["state"] == "candidate"

    promote_url = BASE.format(ALPHA) + "/candidate/promote"
    refused = await client.post(promote_url, headers=headers(key, "guardrail_admin"))
    assert (refused.status_code, refused.json()["error"]["code"]) == (409, "approval_required")
    asked = await request(client, key, etag, {"action": "promote"})
    assert (asked.status_code, asked.json()["version"]) == (201, 2)
    approval_id = asked.json()["id"]
    await approve(client, key, approval_id, sub="bob")
    done = await client.post(
        promote_url, content=json.dumps({"approval_id": approval_id}),
        headers={**headers(key, "guardrail_admin"), **JSON},
    )  # fmt: skip
    assert (done.status_code, done.json()["state"]) == (200, "active")


async def test_a_malformed_approval_id_in_the_path_is_a_404(client, key):
    r = await approve(client, key, "not-an-approval", sub="bob")
    assert (r.status_code, r.json()["error"]["code"]) == (404, "approval_not_found")


# ---------------------------------------------------------------------------- two humans


async def test_a_service_account_cannot_request_so_one_human_cannot_go_on_alone(client, key):
    """The probe over HTTP: ci-bot (a service account with the admin role) requests,
    alice approves, alice publishes. It stops at the request, with its own 403."""
    etag = await put_draft(client, key)
    for claims in ({"service_account": True}, {"gty": "client-credentials"}):
        asked = await request(client, key, etag, sub="ci-bot", **claims)
        assert (asked.status_code, asked.json()["error"]["code"]) == (
            403, "service_account_request"
        )  # fmt: skip
    listed = await client.get(
        BASE.format(ALPHA) + "/draft/approvals", headers=headers(key, "viewer")
    )
    assert listed.json() == {"items": [], "next_cursor": None}  # nothing was recorded
    assert (await publish(client, key, etag)).json()["error"]["code"] == "approval_required"


async def test_the_approver_and_a_service_account_cannot_publish_with_an_approval(client, key):
    etag = await put_draft(client, key)
    approval_id = (await request(client, key, etag)).json()["id"]  # alice asks
    await approve(client, key, approval_id, sub="bob")
    by_bob = await publish(client, key, etag, approval_id, sub="bob")
    assert (by_bob.status_code, by_bob.json()["error"]["code"]) == (403, "approver_publish")
    by_bot = await publish(client, key, etag, approval_id, sub="ci-bot", service_account=True)
    assert (by_bot.status_code, by_bot.json()["error"]["code"]) == (403, "service_account_publish")
    done = await publish(client, key, etag, approval_id)  # alice asked and publishes
    assert (done.status_code, done.json()["state"]) == (201, "active")


# ---------------------------------------------------------------------------- the list


async def listing(client, key, query="", *roles, **kw):
    return await client.get(
        BASE.format(ALPHA) + "/draft/approvals" + query,
        headers=headers(key, *(roles or ("viewer",)), **kw),
    )


async def test_the_list_is_open_to_a_viewer_and_pages_with_a_cursor(client, key, admin):
    etag = await put_draft(client, key)
    ids = []
    for _ in range(3):
        admin.now += timedelta(minutes=1)
        ids.append((await request(client, key, etag)).json()["id"])
    await approve(client, key, ids[0], sub="bob")
    first = await listing(client, key, "?limit=2")
    assert first.status_code == 200
    page = first.json()
    assert [x["id"] for x in page["items"]] == [ids[2], ids[1]] and page["next_cursor"]
    assert page["items"][0].keys() >= {
        "id", "action", "status", "draft_hash", "version", "requested_by", "approved_by",
        "expires_at",
    }  # fmt: skip
    last = (await listing(client, key, f"?limit=2&cursor={page['next_cursor']}")).json()
    assert [x["id"] for x in last["items"]] == [ids[0]] and last["next_cursor"] is None
    only = (await listing(client, key, "?status=approved")).json()["items"]
    assert [(x["id"], x["approved_by"]) for x in only] == [(ids[0], f"{ISS}#bob")]


@pytest.mark.parametrize("role", ["viewer", "guardrail_reviewer", "auditor", "guardrail_admin"])
async def test_any_role_reads_the_list_and_no_role_does_not(client, key, role):
    assert (await listing(client, key, "", role)).status_code == 200
    none = await listing(client, key, "", "nonsense")
    assert (none.status_code, none.json()["error"]["message"]) == (403, "missing_role")


async def test_the_list_is_the_tenants_own(client, key):
    other = await client.get(
        BASE.format(ALPHA) + "/draft/approvals",
        headers=headers(key, "viewer", tenant=BETA, sub="mallory"),
    )
    assert (other.status_code, other.json()["error"]["message"]) == (403, "tenant_mismatch")


@pytest.mark.parametrize(
    ("query", "code"),
    [
        ("?limit=0", "invalid_query"), ("?limit=101", "invalid_query"),
        ("?limit=x", "invalid_query"), ("?status=open", "invalid_query"),
        ("?cursor=garbage", "invalid_cursor"),
    ],
)  # fmt: skip
async def test_a_bad_list_query_is_a_400(client, key, query, code):
    r = await listing(client, key, query)
    assert (r.status_code, r.json()["error"]["code"]) == (400, code)
