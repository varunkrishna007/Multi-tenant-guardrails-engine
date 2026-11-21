"""M4-05 over HTTP: the escalation routes behind the real authenticator and authorizer, with the
roles the endpoint table gives them (viewer lists and reads, guardrail_reviewer resolves)."""

import json
import time
from datetime import UTC, datetime

import httpx
import jwt
import pytest
from admin_fixtures import ALPHA, BETA, Admin
from cryptography.hazmat.primitives.asymmetric import rsa

from guardrail_engine.admin.adapters.fastapi_app import create_admin_app
from guardrail_engine.escalation import EscalationItem, EscalationService, InMemoryEscalationStore
from guardrail_engine.escalation.model import content_sha256, item_id_for
from guardrail_engine.signing.adapters.oidc import OidcConfig, PyJwtAuthenticator, StaticJwksSource
from guardrail_engine.tenant_scope import issue_scope

ISS, AUD = "https://idp.example.com/", "guardrail-admin-api"
BASE = "/v1/tenants/{}/guardrails/escalations"
HELD = "held for the reviewer"


@pytest.fixture(scope="module")
def key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def jwk(key):
    entry = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    return {**entry, "kid": "k1", "use": "sig"}


@pytest.fixture
def items():
    return InMemoryEscalationStore()


@pytest.fixture
def client_app(key, items):
    admin = Admin()
    service = EscalationService(
        items, admin.golden, clock=lambda: datetime(2026, 11, 20, tzinfo=UTC), require_issuer=True
    )
    auth = PyJwtAuthenticator(
        OidcConfig(frozenset({ISS}), AUD), StaticJwksSource({"keys": [jwk(key)]})
    )
    app = create_admin_app(
        authenticator=auth,
        authorizer=admin.authorizer,
        service=admin.service,
        tools=admin.tools,
        golden=admin.golden,
        catalog=admin.catalog_service,
        publisher=admin.publisher,
        tool_registry=admin.tool_service,
        floors=admin.floors,
        repin=admin.repin,
        escalations=service,
    )
    return app, admin


@pytest.fixture
async def client(client_app):
    app, admin = client_app
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://admin.test") as c:
        yield c
    await admin.aclose()


def auth(key, *roles, tenant=ALPHA, sub="rita", operator=False):
    claims = {
        "iss": ISS, "aud": AUD, "sub": sub, "iat": int(time.time()),
        "exp": int(time.time()) + 300, "roles": list(roles),
    }  # fmt: skip
    if tenant:
        claims["tenant_id"] = tenant
    if operator:
        claims["platform_operator"] = True
    token = jwt.encode(claims, key, algorithm="RS256", headers={"kid": "k1"})
    return {"Authorization": f"Bearer {token}"}


async def seed(items, n=1, tenant=ALPHA, **kw) -> list[EscalationItem]:
    store = items.scoped(issue_scope(tenant))
    out = []
    for i in range(n):
        request_id = f"http-{tenant}-{i}"
        item = EscalationItem(
            id=item_id_for(tenant, request_id, "output"),
            tenant_id=tenant,
            request_id=request_id,
            guard_point="output",
            created_at=datetime(2026, 11, 20, tzinfo=UTC),
            target="queue",
            reason="policy",
            bundle_version=1,
            rules=(),
            content_sha256=content_sha256(HELD),
            store_content="hash_only",
            content=HELD,
            **kw,
        )
        await store.insert(item)
        out.append(item)
    return out


def post(client, key, item_id, body, *roles, **kw):
    return client.post(
        BASE.format(kw.pop("path_tenant", ALPHA)) + f"/{item_id}/resolve",
        content=json.dumps(body),
        headers={**auth(key, *roles, **kw), "Content-Type": "application/json"},
    )


GOOD = {"decision": "allow", "reason": "checked it"}

# ----------------------------------------------------------------------------- roles


async def test_a_viewer_lists_and_reads_but_sees_no_content(client, key, items):
    [item] = await seed(items)
    listed = await client.get(BASE.format(ALPHA), headers=auth(key, "viewer"))
    assert listed.status_code == 200
    [row] = listed.json()["items"]
    assert row["id"] == item.id and "content" not in row and row["content_held"] is True
    one = await client.get(BASE.format(ALPHA) + f"/{item.id}", headers=auth(key, "viewer"))
    assert one.status_code == 200 and "content" not in one.json()
    assert HELD not in one.text and "resolution_reason" not in one.json()


async def test_a_reviewer_reads_the_held_content_and_every_other_role_reads_the_list(
    client, key, items
):
    [item] = await seed(items)
    r = await client.get(
        BASE.format(ALPHA) + f"/{item.id}", headers=auth(key, "guardrail_reviewer")
    )
    assert r.json()["content"] == HELD
    for role in ("guardrail_admin", "auditor", "guardrail_reviewer"):
        assert (await client.get(BASE.format(ALPHA), headers=auth(key, role))).status_code == 200
    no_role = await client.get(BASE.format(ALPHA), headers=auth(key))
    assert no_role.status_code == 403 and no_role.json()["error"]["message"] == "missing_role"
    assert (await client.get(BASE.format(ALPHA))).status_code == 401


async def test_only_a_reviewer_resolves(client, key, items):
    [item] = await seed(items)
    for role in ("viewer", "guardrail_admin", "auditor"):
        r = await post(client, key, item.id, GOOD, role)
        assert (r.status_code, r.json()["error"]["message"]) == (403, "missing_role"), role
    r = await post(client, key, item.id, GOOD, "guardrail_reviewer")
    assert r.status_code == 200
    body = r.json()
    assert body["item"]["status"] == "resolved"
    assert body["item"]["resolved_by"] == f"{ISS}#rita"  # issuer#subject
    assert body["label"]["mode"] == "hash_only" and body["label"]["set_id"].startswith("gs_")


# ----------------------------------------------------------------------------- tenants


async def test_a_token_for_another_tenant_is_refused_before_anything_is_read(client, key, items):
    [item] = await seed(items)
    for role in ("viewer", "guardrail_reviewer"):
        r = await client.get(BASE.format(ALPHA), headers=auth(key, role, tenant=BETA))
        assert (r.status_code, r.json()["error"]["message"]) == (403, "tenant_mismatch")
    r = await post(client, key, item.id, GOOD, "guardrail_reviewer", tenant=BETA)
    assert r.status_code == 403
    # the other tenant's own queue is empty, and its reviewer can't reach this item by id
    own = await client.get(BASE.format(BETA), headers=auth(key, "viewer", tenant=BETA))
    assert own.json()["items"] == []
    missing = await client.get(
        BASE.format(BETA) + f"/{item.id}", headers=auth(key, "viewer", tenant=BETA)
    )
    assert missing.status_code == 404
    gone = await post(
        client, key, item.id, GOOD, "guardrail_reviewer", tenant=BETA, path_tenant=BETA
    )
    assert gone.status_code == 404
    assert (await client.get(
        BASE.format(ALPHA) + f"/{item.id}", headers=auth(key, "viewer")
    )).json()["status"] == "open"  # fmt: skip


# ----------------------------------------------------------------------------- behaviour


async def test_pagination_and_filters_over_http(client, key, items):
    await seed(items, 5)
    h = auth(key, "viewer")
    first = (await client.get(BASE.format(ALPHA) + "?limit=2", headers=h)).json()
    assert len(first["items"]) == 2 and first["next_cursor"]
    second = (
        await client.get(BASE.format(ALPHA) + f"?limit=2&cursor={first['next_cursor']}", headers=h)
    ).json()
    assert {i["id"] for i in first["items"]}.isdisjoint(i["id"] for i in second["items"])
    open_ = await client.get(BASE.format(ALPHA) + "?status=open&guard_point=output", headers=h)
    assert len(open_.json()["items"]) == 5
    for query, code in (
        ("?status=bogus", "invalid_query"),
        ("?limit=0", "invalid_query"),
        ("?cursor=garbage", "invalid_cursor"),
    ):
        r = await client.get(BASE.format(ALPHA) + query, headers=h)
        assert (r.status_code, r.json()["error"]["code"]) == (400, code)


async def test_errors_have_fixed_codes(client, key, items):
    [item, other] = await seed(items, 2)
    gone = await post(client, key, "esc_" + "0" * 24, GOOD, "guardrail_reviewer")
    assert (gone.status_code, gone.json()["error"]["code"]) == (404, "escalation_not_found")
    bad = await post(client, key, item.id, {"decision": "maybe"}, "guardrail_reviewer")
    assert bad.status_code == 422 and bad.json()["error"]["code"] == "invalid_draft"
    assert bad.json()["error"]["errors"][0]["code"].startswith("escalation.")
    assert (await post(client, key, item.id, GOOD, "guardrail_reviewer")).status_code == 200
    again = await post(client, key, item.id, GOOD, "guardrail_reviewer", sub="rob")
    assert (again.status_code, again.json()["error"]["code"]) == (409, "already_resolved")
    html = await client.post(
        BASE.format(ALPHA) + f"/{other.id}/resolve",
        content="x",
        headers={**auth(key, "guardrail_reviewer"), "Content-Type": "text/plain"},
    )
    assert html.status_code == 415


async def test_self_resolution_is_403(client, key, items):
    [item] = await seed(items, 1, triggered_by=f"{ISS}#rita")
    r = await post(client, key, item.id, GOOD, "guardrail_reviewer", sub="rita")
    assert (r.status_code, r.json()["error"]["code"]) == (403, "self_resolution")
    assert (
        await post(client, key, item.id, GOOD, "guardrail_reviewer", sub="rob")
    ).status_code == 200


# -----------------------------------------------------------------------------
async def test_a_platform_operator_may_read_but_not_resolve_a_tenants_item(client, key, items):
    """Decision: an operator crossing tenants is refused 403 and nothing changes."""
    [item] = await seed(items)
    op = dict(tenant=None, operator=True, sub="ops")
    read = await client.get(
        BASE.format(ALPHA) + f"/{item.id}", headers=auth(key, "guardrail_reviewer", **op)
    )
    assert read.status_code == 200  # reading across tenants stays allowed (and audited)
    r = await post(client, key, item.id, GOOD, "guardrail_reviewer", path_tenant=ALPHA, **op)
    assert (r.status_code, r.json()["error"]["code"]) == (403, "operator_resolution")
    again = await client.get(
        BASE.format(ALPHA) + f"/{item.id}", headers=auth(key, "guardrail_reviewer")
    )
    assert again.json()["status"] == "open"
    sets = await client.get(
        "/v1/tenants/" + ALPHA + "/guardrails/golden-sets?include=escalation",
        headers=auth(key, "viewer"),
    )
    assert sets.json()["sets"] == []  # and no label was written
    # the tenant's own reviewer still can
    assert (await post(client, key, item.id, GOOD, "guardrail_reviewer")).status_code == 200


async def test_golden_sets_can_be_filtered_to_the_escalation_labels(client, key, items):
    [item] = await seed(items)
    assert (await post(client, key, item.id, GOOD, "guardrail_reviewer")).status_code == 200
    url = "/v1/tenants/" + ALPHA + "/guardrails/golden-sets"
    h = auth(key, "viewer")
    assert (await client.get(url, headers=h)).json()["sets"] == []  # hidden by default
    shown = await client.get(url + "?include=escalation", headers=h)
    [row] = shown.json()["sets"]
    assert row["name"] == f"escalation-{item.id}" and row["examples"] == 1
    assert HELD not in shown.text  # metadata only
    bad = await client.get(url + "?include=everything", headers=h)
    assert (bad.status_code, bad.json()["error"]["code"]) == (400, "invalid_query")
