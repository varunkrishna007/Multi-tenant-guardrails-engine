"""M4-07 ``GET /v1/tenants/{tid}/guardrails/decisions`` over HTTP: the real authenticator and
authorizer, the lifecycle store (for what is floor-derived), and an in-memory decision store.
Auditor only; filters, a cursor, and no floor, nothing derived from it."""

from __future__ import annotations

import json
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from admin_fixtures import ALPHA, BETA, Admin, bundle, rule
from cryptography.hazmat.primitives.asymmetric import rsa
from test_admin_http import AUD, ISS, auth, jwk, make_client

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "audit"))
from audit_records import evaluation, fired, make_record

from guardrail_engine.admin.adapters.fastapi_app import create_admin_app
from guardrail_engine.guard.verdict import Decision
from guardrail_engine.signing.adapters.oidc import OidcConfig, PyJwtAuthenticator, StaticJwksSource

NOW = datetime.now(UTC).replace(microsecond=0)
URL = "/v1/tenants/{}/guardrails/decisions"


@pytest.fixture(scope="module")
def key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
async def admin():
    a = Admin()
    yield a
    await a.aclose()


@pytest.fixture
async def client(admin, key):
    authn = PyJwtAuthenticator(
        OidcConfig(frozenset({ISS}), AUD), StaticJwksSource({"keys": [jwk(key)]})
    )
    app = create_admin_app(
        authenticator=authn, authorizer=admin.authorizer, service=admin.service,
        tools=admin.tools, golden=admin.golden, catalog=admin.catalog_service,
        publisher=admin.publisher, tool_registry=admin.tool_service, floors=admin.floors,
        repin=admin.repin, calibration=admin.calibration, rollout=admin.rollout,
        decisions=admin.decisions,
    )  # fmt: skip
    async with make_client(app) as c:
        yield c


async def publish_v1(admin, doc):
    """Publish ``doc`` as the tenant's first (active) version."""
    import json as _json

    from guardrail_engine.authz import Role
    from guardrail_engine.tenant_scope import issue_scope

    principal = __import__("admin_fixtures").who(Role.GUARDRAIL_ADMIN, issuer="https://i/")
    base = "/v1/tenants/{tid}/guardrails"
    d = await admin.decide(principal, "PUT", base + "/draft", ALPHA)
    saved = await admin.service.put_draft(d, principal, _json.dumps(doc).encode(), None)
    d = await admin.decide(principal, "POST", base + "/draft/publish", ALPHA)
    body = _json.dumps({"mode": "enforce", "rollout_percent": 100}).encode()
    await admin.publisher.publish(d, principal, body, saved.etag)
    assert issue_scope(ALPHA)


async def seed(admin, n=5):
    for i in range(n):
        await admin.decision_records.append_many(
            [
                make_record(
                    ALPHA, NOW - timedelta(minutes=i), request_id=f"a-{i}",
                    guard_point="output" if i % 2 == 0 else "input",
                    decision=Decision.BLOCK if i % 2 == 0 else Decision.ALLOW,
                    fired_entries=[fired("t__refunds", "tenant", 0.9)] if i % 2 == 0 else [],
                )
            ]
        )  # fmt: skip
    await admin.decision_records.append_many([make_record(BETA, NOW, request_id="b-0")])


async def get(client, key, params="", *roles, tenant=ALPHA, path_tenant=ALPHA, **kw):
    return await client.get(
        URL.format(path_tenant) + (("?" + params) if params else ""),
        headers=auth(key, *(roles or ("auditor",)), tenant=tenant, **kw),
    )


async def test_only_the_auditor_role_may_read_the_decisions(client, key, admin):
    await seed(admin)
    for roles in (("viewer",), ("guardrail_admin",), ("guardrail_reviewer",)):
        r = await get(client, key, "", *roles)
        assert r.status_code == 403 and r.json()["error"]["message"] == "missing_role", roles
    assert (await client.get(URL.format(ALPHA))).status_code == 401
    assert (await get(client, key, "", "auditor")).status_code == 200


async def test_a_tenant_reads_its_own_decisions_only(client, key, admin):
    await seed(admin)
    ids = [i["request_id"] for i in (await get(client, key)).json()["items"]]
    assert ids == [f"a-{i}" for i in range(5)]  # newest first, none of BETA's
    other = await get(client, key, "", tenant=ALPHA, path_tenant=BETA)
    assert other.status_code == 403 and other.json()["error"]["message"] == "tenant_mismatch"
    mine = await get(client, key, "", tenant=BETA, path_tenant=BETA)
    assert [i["request_id"] for i in mine.json()["items"]] == ["b-0"]


async def test_filters_by_time_rule_decision_and_guard_point(client, key, admin):
    await seed(admin)

    async def ids(params):
        r = await get(client, key, params)
        assert r.status_code == 200, r.text
        return [i["request_id"] for i in r.json()["items"]]

    assert await ids("decision=block") == ["a-0", "a-2", "a-4"]
    assert await ids("guard_point=input") == ["a-1", "a-3"]
    assert await ids("rule=t__refunds") == ["a-0", "a-2", "a-4"]
    assert await ids("rule=t__refunds&guard_point=input") == []
    start = (NOW - timedelta(minutes=2, seconds=30)).isoformat().replace("+00:00", "Z")
    end = (NOW - timedelta(seconds=30)).isoformat().replace("+00:00", "Z")
    assert await ids(f"from={start}&to={end}") == ["a-1", "a-2"]


async def test_a_cursor_pages_through_everything_once(client, key, admin):
    await seed(admin, n=7)
    seen, cursor = [], None
    while True:
        params = "limit=3" + (f"&cursor={cursor}" if cursor else "")
        body = (await get(client, key, params)).json()
        seen += [i["request_id"] for i in body["items"]]
        cursor = body["next_cursor"]
        if cursor is None:
            break
    assert seen == [f"a-{i}" for i in range(7)]
    # the last full page has no cursor only when it was not full: 7 = 3 + 3 + 1
    assert (await get(client, key, "limit=7")).json()["next_cursor"] is not None  # may be more


@pytest.mark.parametrize(
    ("params", "field"),
    [
        ("limit=0", "limit"), ("limit=201", "limit"), ("limit=x", "limit"),
        ("decision=maybe", "decision"), ("from=yesterday", "from"),
        ("from=2026-01-01T00:00:00", "from"),  # no time zone
        ("from=2026-01-01T00:00:00Z&to=2026-03-01T00:00:00Z", "from"),  # over 31 days
        ("from=2026-02-01T00:00:00Z&to=2026-01-01T00:00:00Z", "from"),
        ("cursor=garbage", "cursor"), ("nope=1", "nope"), ("rule=" + "x" * 129, "rule"),
        ("limit=1&limit=2", "query"),
    ],
)  # fmt: skip
async def test_a_bad_parameter_is_refused_naming_the_field(client, key, params, field):
    r = await get(client, key, params)
    assert r.status_code == 400 and r.json()["error"]["code"] == "invalid_query"
    assert r.json()["error"]["errors"][0]["path"] == field


async def test_the_floor_and_what_is_derived_from_it_never_appear(client, key, admin):
    """A floor rule shows key, action and mode when it fired; a tenant rule that copies a floor
    question shows no probability or thresholds; the tenant's own rule shows both."""
    floor_text = next(iter(admin.catalog.floor(min(admin.catalog.floor_versions())).rules))
    copy_rule = rule("sneaky", mode="shadow")
    # the floor's own question, under another key
    copy_rule["question"] = floor_text.question.instructions
    doc = bundle(ALPHA, rules=[rule("refunds", mode="shadow"), copy_rule])
    await publish_v1(admin, doc)
    await admin.decision_records.append_many(
        [
            make_record(
                ALPHA, NOW, request_id="mixed", decision=Decision.BLOCK,
                fired_entries=[
                    fired("p__inj_direct", "floor", 0.97, block_at=0.55, escalate_at=0.3),
                    fired("t__refunds", "tenant", 0.9),
                    fired("t__sneaky", "tenant", 0.93),
                ],
                rules=[
                    evaluation("p__inj_direct", "floor", 0.97, action="block", block_at=0.55),
                    evaluation("p__other", "floor", 0.12),
                    evaluation("t__refunds", "tenant", 0.9, action="block"),
                    evaluation("t__sneaky", "tenant", 0.93, action="block"),
                ],
            )
        ]
    )  # fmt: skip
    (item,) = (await get(client, key)).json()["items"]
    text = json.dumps(item)
    for secret in ("0.97", "0.55", "0.93", "0.12", "p__other", "answers", "floor_fail_mode"):
        assert secret not in text, secret
    fired_by_rule = {f["rule"]: f for f in item["fired"]}
    assert fired_by_rule["p__inj_direct"] == {
        "rule": "p__inj_direct", "action": "block", "mode": "enforce"
    }  # fmt: skip
    assert fired_by_rule["t__sneaky"] == {"rule": "t__sneaky", "action": "block", "mode": "enforce"}
    assert fired_by_rule["t__refunds"]["p"] == 0.9
    rules = {r["rule"]: r for r in item["rules"]}
    assert set(rules) == {"t__refunds", "t__sneaky"}  # no floor rule is listed
    assert rules["t__refunds"]["p"] == 0.9 and "p" not in rules["t__sneaky"]
    assert "block_at" in rules["t__refunds"] and "block_at" not in rules["t__sneaky"]


async def test_a_record_whose_bundle_cannot_be_read_hides_every_rules_numbers(client, key, admin):
    await admin.decision_records.append_many(
        [
            make_record(
                ALPHA, NOW, request_id="orphan", bundle_version=99,
                fired_entries=[fired("t__refunds", "tenant", 0.9)],
                rules=[evaluation("t__refunds", "tenant", 0.9)],
            )
        ]
    )  # fmt: skip
    (item,) = (await get(client, key)).json()["items"]
    assert "p" not in item["fired"][0] and "p" not in item["rules"][0]
    assert "0.9" not in json.dumps(item)
