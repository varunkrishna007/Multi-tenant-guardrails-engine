"""M4-06 ``GET /v1/tenants/{tid}/guardrails/metrics`` over HTTP: the real authenticator and
authorizer. Viewer role (the authz table's), a window, per-rule rates for the tenant's own rules,
counts by key and action only for the floor and what is derived from it, tokens and cost from the
metered usage."""

from __future__ import annotations

import json
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from admin_fixtures import ALPHA, BETA, Admin, bundle, rule
from cryptography.hazmat.primitives.asymmetric import rsa
from test_admin_http import AUD, ISS, auth, jwk, make_client
from test_m4_07_decisions_http import publish_v1

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "audit"))
from audit_records import evaluation, fired, make_record

from guardrail_engine.admin.adapters.fastapi_app import create_admin_app
from guardrail_engine.delivery.events import USAGE_ANSWERED, UsageEvent, new_key
from guardrail_engine.guard.verdict import Decision
from guardrail_engine.signing.adapters.oidc import OidcConfig, PyJwtAuthenticator, StaticJwksSource

NOW = datetime.now(UTC).replace(microsecond=0)
URL = "/v1/tenants/{}/guardrails/metrics"


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
        decisions=admin.decisions, metrics=admin.metrics,
    )  # fmt: skip
    async with make_client(app) as c:
        yield c


async def get(client, key, params="", *roles, tenant=ALPHA, path_tenant=ALPHA):
    return await client.get(
        URL.format(path_tenant) + (("?" + params) if params else ""),
        headers=auth(key, *(roles or ("viewer",)), tenant=tenant),
    )


def usage(admin, tenant, gp, tokens, kind=USAGE_ANSWERED, ago=timedelta(minutes=5)):
    admin.usage_store.write(
        UsageEvent(kind, tenant, gp, tokens, (NOW - ago).timestamp()), new_key()
    )


async def test_the_viewer_role_reads_the_metrics_and_nothing_below_it(client, key, admin):
    assert (await client.get(URL.format(ALPHA))).status_code == 401
    assert (await get(client, key, "", "viewer")).status_code == 200
    assert (await get(client, key, "", "auditor")).status_code == 200  # an auditor is a viewer
    other = await get(client, key, "", tenant=ALPHA, path_tenant=BETA)
    assert other.status_code == 403 and other.json()["error"]["message"] == "tenant_mismatch"


@pytest.mark.parametrize(
    ("params", "field"),
    [
        ("from=yesterday", "from"), ("from=2026-01-01T00:00:00", "from"),
        ("from=2026-01-01T00:00:00Z&to=2026-03-01T00:00:00Z", "from"),
        ("from=2026-02-01T00:00:00Z&to=2026-01-01T00:00:00Z", "from"),
        ("nope=1", "nope"), ("guard_point=" + "x" * 65, "guard_point"), ("from=a&from=b", "query"),
    ],
)  # fmt: skip
async def test_a_bad_parameter_is_refused_naming_the_field(client, key, params, field):
    r = await get(client, key, params)
    assert r.status_code == 400 and r.json()["error"]["errors"][0]["path"] == field


async def seed_mixed(admin):
    doc = bundle(ALPHA, rules=[rule("refunds", mode="shadow"), rule("other", mode="shadow")])
    await publish_v1(admin, doc)
    records = []
    for i in range(10):
        entries, dec = [], Decision.ALLOW
        if i < 4:  # four blocked by the tenant's rule, two of them also by a floor rule
            entries.append(fired("t__refunds", "tenant", 0.91))
            dec = Decision.BLOCK
        if i in (0, 1):
            entries.append(fired("p__inj_direct", "floor", 0.97, block_at=0.55))
        if i == 5:
            entries.append(fired("t__other", "tenant", 0.61, action="escalate"))
            dec = Decision.ESCALATE
        records.append(
            make_record(
                ALPHA, NOW - timedelta(minutes=i), request_id=f"r{i}", decision=dec,
                guard_point="output" if i % 2 == 0 else "input", fired_entries=entries,
                rules=[evaluation("t__refunds", "tenant", 0.91)],
            )
        )  # fmt: skip
    await admin.decision_records.append_many(records)
    usage(admin, ALPHA, "output", 5000)
    usage(admin, ALPHA, "output", 2500)
    usage(admin, ALPHA, "input", 4000)
    usage(admin, BETA, "output", 999_999)  # another tenant's


async def test_rates_per_tenant_rule_and_counts_for_the_floor(client, key, admin):
    await seed_mixed(admin)
    body = (await get(client, key)).json()
    assert body["checks"] == {"total": 10, "by_decision": {"allow": 5, "block": 4, "escalate": 1}}
    rules = {r["rule"]: r for r in body["rules"]}
    assert rules["t__refunds"]["blocked"] == 4 and rules["t__refunds"]["block_rate"] == 0.4
    assert rules["t__other"]["escalated"] == 1 and rules["t__other"]["escalate_rate"] == 0.1
    assert [(r["rule"], r["counts"]) for r in body["platform_rules"]] == [
        ("p__inj_direct", {"block": 2})
    ]  # the floor: key and action, with no rate
    text = json.dumps(body)
    for secret in ("0.97", "0.91", "0.61", "0.55", "block_at", "escalate_at", '"p"'):
        assert secret not in text, secret


async def test_a_floor_derived_tenant_rule_is_counts_only(client, key, admin):
    floor_rule = next(iter(admin.catalog.floor(min(admin.catalog.floor_versions())).rules))
    sneaky = rule("sneaky", mode="shadow")
    sneaky["question"] = floor_rule.question.instructions  # the floor's own question
    await publish_v1(admin, bundle(ALPHA, rules=[rule("refunds", mode="shadow"), sneaky]))
    await admin.decision_records.append_many(
        [
            make_record(ALPHA, NOW, fired_entries=[fired("t__sneaky", "tenant", 0.9)]),
            make_record(ALPHA, NOW, fired_entries=[fired("t__refunds", "tenant", 0.9)]),
        ]
    )
    body = (await get(client, key)).json()
    assert [r["rule"] for r in body["rules"]] == ["t__refunds"]
    assert [(r["rule"], r["counts"]) for r in body["platform_rules"]] == [
        ("t__sneaky", {"block": 1})
    ]


async def test_a_record_with_no_readable_bundle_makes_every_rule_counts_only(client, key, admin):
    await admin.decision_records.append_many(
        [
            make_record(
                ALPHA, NOW, bundle_version=99, fired_entries=[fired("t__refunds", "tenant", 0.9)]
            )
        ]
    )
    body = (await get(client, key)).json()
    assert body["rules"] == [] and body["platform_rules"][0]["rule"] == "t__refunds"


async def test_tokens_and_cost_are_the_metered_totals_per_guard_point(client, key, admin):
    await seed_mixed(admin)
    body = (await get(client, key)).json()
    by_gp = {g["guard_point"]: g for g in body["guard_points"]}
    assert by_gp["output"]["input_tokens"] == 7500 and by_gp["input"]["input_tokens"] == 4000
    assert by_gp["output"]["cost_usd"] == round(7500 * 0.10 / 1_000_000, 8)  # 0.00075
    assert body["cost"]["input_tokens"] == 11_500  # not BETA's 999,999
    assert body["cost"]["total_usd"] == 0.00115
    assert body["cost"]["price_per_million_input_tokens_usd"] == 0.10
    assert body["cost"]["price_source"] == "test"
    assert by_gp["output"]["checks"] == 5 and by_gp["input"]["checks"] == 5
    only = (await get(client, key, "guard_point=input")).json()
    assert only["checks"]["total"] == 5 and [g["guard_point"] for g in only["guard_points"]] == [
        "input"
    ]


async def test_the_window_bounds_the_figures_and_percentiles_are_ordered(client, key, admin):
    await seed_mixed(admin)
    old = (NOW - timedelta(days=10)).isoformat().replace("+00:00", "Z")
    older = (NOW - timedelta(days=11)).isoformat().replace("+00:00", "Z")
    empty = (await get(client, key, f"from={older}&to={old}")).json()
    assert empty["checks"]["total"] == 0 and empty["latency_ms"] is None
    assert empty["reconciliation"]["difference_pct"] is None and empty["rules"] == []
    full = (await get(client, key)).json()
    lat = full["latency_ms"]
    assert lat["p50"] <= lat["p95"] <= lat["p99"] and lat["p50"] == pytest.approx(
        2.0, rel=0.011
    )  # make_record's 2.0 ms, in a 2% bucket


async def test_a_check_that_fired_nothing_and_has_no_version_does_not_hide_the_rates(
    client, key, admin
):
    """A forbidden or policy_unavailable check has no bundle version and no rules. It must
    not make every rule counts-only."""
    await publish_v1(admin, bundle(ALPHA, rules=[rule("refunds", mode="shadow")]))
    await admin.decision_records.append_many(
        [
            make_record(ALPHA, NOW, fired_entries=[fired("t__refunds", "tenant", 0.9)]),
            make_record(ALPHA, NOW - timedelta(minutes=1), decision=Decision.FORBIDDEN).model_copy(
                update={"bundle_version": None}
            ),
        ]
    )
    body = (await get(client, key)).json()
    assert body["checks"]["total"] == 2
    assert [r["rule"] for r in body["rules"]] == ["t__refunds"] and body["rules"][0]["blocked"] == 1
    assert body["rules"][0]["block_rate"] == 0.5
