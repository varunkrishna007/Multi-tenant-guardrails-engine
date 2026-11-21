"""M5-02 factory wiring: the engine builds the approval service from its stores and hands it to
the draft service (an edit cancels), the publish service (an approval is consumed), the alert sink
(a rollback is told) and the Admin API (the two routes), and a regulated tenant publishes through
it end to end."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "guard"))  # guard_fixtures

from engine_fixtures import TENANT, bundle, directory, profile, settings, verifier
from guard_fixtures import rule

from guardrail_engine.authz import InMemoryAuthzAudit, Principal, Role
from guardrail_engine.decision import FakeDecisionModel
from guardrail_engine.engine import SettingsError, build_engine
from guardrail_engine.gateway.sinks import ALERT_APPROVED_VERSION_CHANGE, RecordingAlertSink
from guardrail_engine.guard import CheckContext
from guardrail_engine.signing.adapters.oidc import (
    MachineMarker,
    OidcConfig,
    PyJwtAuthenticator,
    StaticJwksSource,
)

BASE = "/v1/tenants/{tid}/guardrails"


def admin(sub):
    return Principal(sub, TENANT, frozenset({Role.GUARDRAIL_ADMIN}), issuer="https://i/")


class Tokens:
    async def authenticate(self, token):
        return admin(token)


async def build(alerts=None):
    return await build_engine(
        settings("test"), verifier=verifier(), tenants=directory(profile(tier="regulated")),
        model=FakeDecisionModel(), authz_audit=InMemoryAuthzAudit(), authenticator=Tokens(),
        alerts=alerts,
    )  # fmt: skip


def with_rule(name):
    return {**bundle(), "rules": [rule(name, gps=("output",), mode="shadow")]}


async def test_a_regulated_tenant_publishes_with_a_second_admins_approval_through_the_engine():
    engine = await build()
    try:
        assert engine.approval_service is not None
        app = engine.admin_app()
        transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
        async with httpx.AsyncClient(transport=transport, base_url="http://admin.test") as c:
            url = BASE.format(tid=TENANT)
            hdr = {"Content-Type": "application/json"}
            alice, bob = {"Authorization": "Bearer alice", **hdr}, {"Authorization": "Bearer bob"}
            put = await c.put(url + "/draft", content=json.dumps(with_rule("r")), headers=alice)
            etag = put.headers["etag"]
            refused = await c.post(
                url + "/draft/publish", content=json.dumps({"mode": "enforce"}),
                headers={**alice, "If-Match": etag},
            )  # fmt: skip
            assert refused.json()["error"]["code"] == "approval_required"
            asked = await c.post(url + "/draft/approvals", headers={**alice, "If-Match": etag})
            assert asked.status_code == 201
            approval_id = asked.json()["id"]
            own = await c.post(url + f"/draft/approvals/{approval_id}/approve", headers=alice)
            assert own.json()["error"]["code"] == "self_approval"
            granted = await c.post(url + f"/draft/approvals/{approval_id}/approve", headers=bob)
            assert granted.status_code == 200
            body = json.dumps({"mode": "enforce", "approval_id": approval_id})
            done = await c.post(
                url + "/draft/publish", content=body, headers={**alice, "If-Match": etag}
            )
            assert (done.status_code, done.json()["state"]) == (201, "active")
        ctx = CheckContext(signed_context=verifier().issue(TENANT))
        assert (await engine.check(ctx, "output", "hi")).bundle_version == 1
    finally:
        await engine.shutdown()


async def test_a_rollback_on_a_regulated_tenant_reaches_the_alert_sink():
    alerts = RecordingAlertSink()
    engine = await build(alerts)
    try:
        pub, ap = engine.publish_service, engine.approval_service

        async def decide(method, route, who):
            return await engine.authorizer.authorize(who, method, BASE + route, tenant_id=TENANT)

        alice, bob = admin("alice"), admin("bob")

        async def saved(doc, if_match):
            d = await decide("PUT", "/draft", alice)
            return await engine.draft_service.put_draft(
                d, alice, json.dumps(doc).encode(), if_match
            )

        async def approved(action, draft=None):
            d = await decide("POST", "/draft/approvals", alice)
            body = json.dumps({"action": action}).encode()
            made = await ap.request(d, alice, body, None if draft is None else draft.etag)
            d = await decide("POST", "/draft/approvals/{id}/approve", bob)
            return await ap.approve(d, bob, made.id)

        draft = await saved(with_rule("r"), None)
        first = await approved("publish", draft)
        body = json.dumps({"mode": "enforce", "approval_id": first.id}).encode()
        d = await decide("POST", "/draft/publish", alice)
        assert (await pub.publish(d, alice, body, draft.etag)).state == "active"

        draft = await saved(with_rule("r2"), "*")
        d = await decide("POST", "/draft/publish", alice)
        body = json.dumps({"mode": "shadow", "rollout_percent": 10}).encode()
        assert (await pub.publish(d, alice, body, draft.etag)).state == "candidate"
        promotion = await approved("promote")
        d = await decide("POST", "/candidate/promote", alice)
        body = json.dumps({"approval_id": promotion.id}).encode()
        assert (await pub.promote(d, alice, body)).version == 2
        assert alerts.alerts == []  # a shadow candidate's promotion is the approved one

        d = await decide("POST", "/versions/{v}/rollback", bob)
        await pub.rollback(d, bob, 1)
        (alert,) = alerts.alerts
        assert (alert.kind, alert.tenant_id, alert.reason) == (
            ALERT_APPROVED_VERSION_CHANGE, TENANT, "rollback"
        )  # fmt: skip
    finally:
        await engine.shutdown()


async def test_a_draft_edit_through_the_engine_cancels_the_open_approvals():
    engine = await build()
    try:
        d = await engine.authorizer.authorize(
            admin("alice"), "PUT", BASE + "/draft", tenant_id=TENANT
        )
        saved = await engine.draft_service.put_draft(
            d, admin("alice"), json.dumps(with_rule("r")).encode(), None
        )
        d = await engine.authorizer.authorize(
            admin("alice"), "POST", BASE + "/draft/approvals", tenant_id=TENANT
        )
        approval = await engine.approval_service.request(d, admin("alice"), b"", saved.etag)
        d = await engine.authorizer.authorize(
            admin("alice"), "PUT", BASE + "/draft", tenant_id=TENANT
        )
        await engine.draft_service.put_draft(
            d, admin("alice"), json.dumps(with_rule("r2")).encode(), "*"
        )
        store = engine.approval_service._approvals.scoped(d.scope)
        assert (await store.get(TENANT, approval.id)).status == "cancelled"
    finally:
        await engine.shutdown()


# ---------------------------------------------------------------------------- startup


def oidc(markers=None, *, tenant_issuer=False):
    sso = {"https://sso/": frozenset({TENANT})} if tenant_issuer else {}
    config = OidcConfig(
        frozenset({"https://idp/"}), "aud", tenant_issuers=sso, machine_markers=markers or {}
    )
    return PyJwtAuthenticator(
        config, {i: StaticJwksSource({"keys": []}) for i in sorted(config.issuers)}
    )


async def build_with(environment, authenticator):
    return await build_engine(
        settings(environment), verifier=verifier(), tenants=directory(),
        model=FakeDecisionModel(), authenticator=authenticator,
        authz_audit=type("D", (InMemoryAuthzAudit,), {"durable": True})(),
    )  # fmt: skip


@pytest.mark.parametrize("environment", ["production", "staging"])
async def test_an_issuer_with_no_machine_marker_is_refused_at_startup(environment):
    with pytest.raises(SettingsError, match="machine-token marker") as info:
        await build_with(environment, oidc())
    assert "https://idp/" in str(info.value) and environment in str(info.value)


@pytest.mark.parametrize("environment", ["production", "staging"])
async def test_only_the_unmarked_issuer_is_named(environment):
    markers = {"https://idp/": MachineMarker(claim="machine")}
    with pytest.raises(SettingsError, match="1 issuer") as info:
        await build_with(environment, oidc(markers, tenant_issuer=True))
    assert "https://sso/" in str(info.value) and "https://idp/" not in str(info.value)


@pytest.mark.parametrize("environment", ["production", "staging"])
@pytest.mark.parametrize(
    "marker",
    [
        MachineMarker(claim="machine"),
        MachineMarker(claim="azp_type", value="m2m"),
        MachineMarker(gty=frozenset({"client-credentials"})),
        MachineMarker(humans_only=True),
    ],
)
async def test_an_issuer_that_says_how_it_marks_machines_starts(environment, marker):
    engine = await build_with(environment, oidc({"https://idp/": marker}))
    await engine.shutdown()


async def test_the_test_environment_keeps_the_default_marker():
    engine = await build_with("test", oidc())  # no markers: the default claim and gty
    await engine.shutdown()


@pytest.mark.parametrize("environment", ["production", "staging"])
async def test_an_authenticator_that_cannot_say_is_refused_outside_test(environment):
    with pytest.raises(SettingsError, match="can't say how machine tokens are marked"):
        await build_with(environment, Tokens())
