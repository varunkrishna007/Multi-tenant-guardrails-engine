"""M5-06: GET metrics shows usage and cost per Gemini project (a label, ``default`` for the shared
pool), the projects add up to the totals, a tenant sees only its own rows, and no key material or
project secret is anywhere in the report."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest
from admin_fixtures import ALPHA, BETA, Admin
from cryptography.hazmat.primitives.asymmetric import rsa
from test_admin_http import AUD, ISS, auth, jwk, make_client
from test_m4_06_metrics_http import URL

from guardrail_engine.admin.adapters.fastapi_app import create_admin_app
from guardrail_engine.delivery.durable import DurableUsageMeter
from guardrail_engine.delivery.events import (
    USAGE_ANSWERED,
    UsageEvent,
    decode_usage,
    encode_usage,
    new_key,
)
from guardrail_engine.delivery.outbox import InMemoryOutbox
from guardrail_engine.delivery.usage import UsageRecorder
from guardrail_engine.signing.adapters.oidc import OidcConfig, PyJwtAuthenticator, StaticJwksSource

NOW = datetime.now(UTC).replace(microsecond=0)


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
        repin=admin.repin, metrics=admin.metrics,
    )  # fmt: skip
    async with make_client(app) as c:
        yield c


def event(admin, tenant, gp, tokens, project="", kind=USAGE_ANSWERED):
    admin.usage_store.write(
        UsageEvent(kind, tenant, gp, tokens, (NOW - timedelta(minutes=5)).timestamp(), project),
        new_key(),
    )


async def report(client, key, tenant=ALPHA):
    r = await client.get(URL.format(tenant), headers=auth(key, "viewer", tenant=tenant))
    assert r.status_code == 200, r.text
    return r.json()


async def test_usage_and_cost_are_split_by_project_and_add_up(client, key, admin):
    event(admin, ALPHA, "output", 6_000_000, project="reg-acme")
    event(admin, ALPHA, "input", 4_000_000, project="reg-acme")
    event(admin, ALPHA, "output", 1_000_000)  # the shared pool (a row with no project)
    event(admin, ALPHA, "test:output", 500_000, project="reg-acme")  # non-production
    body = await report(client, key)
    shared, dedicated = body["projects"]
    assert shared["project"] == "default" and shared["dedicated"] is False
    assert dedicated["project"] == "reg-acme" and dedicated["dedicated"] is True
    assert (shared["input_tokens"], dedicated["input_tokens"]) == (1_000_000, 10_000_000)
    assert (shared["cost_usd"], dedicated["cost_usd"]) == (0.1, 1.0)  # $0.10 per million
    assert dedicated["non_production_input_tokens"] == 500_000
    assert dedicated["non_production_cost_usd"] == 0.05
    assert dedicated["metered_events"] == {"answered": 2}
    # production tokens and cost add up to the report's totals
    assert sum(p["input_tokens"] for p in body["projects"]) == body["cost"]["input_tokens"]
    assert sum(p["cost_usd"] for p in body["projects"]) == pytest.approx(body["cost"]["total_usd"])
    assert body["cost"]["non_production_usd"] == 0.05


async def test_a_tenant_with_no_dedicated_project_sees_only_the_shared_row(client, key, admin):
    event(admin, ALPHA, "output", 1_000)
    event(admin, BETA, "output", 9_000, project="reg-beta")
    body = await report(client, key)
    assert [p["project"] for p in body["projects"]] == ["default"]
    assert "reg-beta" not in json.dumps(body)  # another tenant's project label is not here


async def test_the_report_holds_a_label_and_counts_and_no_key_material(client, key, admin):
    event(admin, ALPHA, "output", 1_000, project="reg-acme")
    text = json.dumps(await report(client, key)).lower()
    for forbidden in ("api_key", "api-key", "secret", "key_env", "aiza", "gemini_key", 'token":'):
        assert forbidden not in text.replace("input_tokens", "")


async def test_an_empty_window_has_no_project_rows(client, key):
    assert (await report(client, key))["projects"] == []


# ------------------------------------------------------------ the meter that labels the rows


class Collected(UsageRecorder):
    def __init__(self):
        super().__init__(clock=lambda: 1_700_000_000.0)
        self.events: list[UsageEvent] = []

    def _submit(self, event):
        self.events.append(event)


def test_a_project_meter_labels_every_record_and_leaves_the_shared_one_alone():
    shared = Collected()
    dedicated = shared.with_project("reg-acme")
    dedicated.record("t_a", "output", 100)
    dedicated.record("t_a", "output", None)
    dedicated.record_unanswered("t_a", "output")
    dedicated.record_provider_safety("t_a", "output")
    dedicated.record_model_skipped("t_a", "tool_call")
    shared.record("t_b", "output", 5)
    assert {e.project for e in shared.events} == {"reg-acme", ""}
    assert [e.project for e in shared.events if e.tenant_id == "t_b"] == [""]  # sink is shared
    assert len(shared.events) == 6
    with pytest.raises(ValueError):
        shared.with_project("Not A Label")


def test_the_label_survives_the_outbox_and_an_older_payload_reads_as_the_shared_pool():
    outbox = InMemoryOutbox()
    meter = DurableUsageMeter(outbox, clock=lambda: 1_700_000_000.0).with_project("reg-acme")
    meter.record("t_a", "output", 42)
    [row] = outbox._rows
    assert decode_usage(row.payload).project == "reg-acme"
    old = json.loads(encode_usage(UsageEvent(USAGE_ANSWERED, "t_a", "output", 1, 1.0)))
    del old["project"]  # written before M5-06
    assert decode_usage(json.dumps(old)).project == ""
    with pytest.raises(ValueError):
        UsageEvent(USAGE_ANSWERED, "t_a", "output", 1, 1.0, "AIzaSy-a-key")
