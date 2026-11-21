"""The tier of today holds a promotion (strict, whatever approvals
it has) and, on a regulated tenant, a rollback target (R4.1 over R2's rollback exemption).
Rollback stays approval-free and the running version keeps running."""

import json

import pytest
from admin_fixtures import ALPHA, Admin, bundle, rule
from test_m5_02_approvals import (
    ALICE,
    BOB,
    approve,
    decide,
    events,
    needs_approval,
    promote,
    publish,
    request,
    rollback,
    row,
)

from guardrail_engine.admin.publish import RollbackTierError
from guardrail_engine.admin.service import DraftInvalidError
from guardrail_engine.policy.errors import ErrorCode
from guardrail_engine.tenant_scope import issue_scope

PACK = "domain/claims@1"
REQUIRED = {ErrorCode.PACK_REQUIRED_MISSING.value}


@pytest.fixture
async def a():
    admin = Admin()
    # the platform requires the claims pack of the regulated tier (R4.1's shape)
    admin.catalog._tier_packs = {"regulated": frozenset({"claims"})}
    yield admin
    await admin.aclose()


async def put(a, *, packs=(), name="r", mode="shadow"):
    doc = bundle(ALPHA, packs=packs, rules=[rule(name, gps=("output",), mode=mode)])
    d = await decide(a, "PUT", "/draft")
    current = await a.drafts.scoped(issue_scope(ALPHA)).get(ALPHA)
    return await a.service.put_draft(
        d, ALICE, json.dumps(doc).encode(), None if current is None else "*"
    )


async def state(a):
    return await a.lifecycle.scoped(issue_scope(ALPHA)).state(ALPHA)


async def activate(a, *, packs=()):
    """Publish (and activate) the first version as a standard tenant would, enforce at 100%."""
    await put(a, packs=packs, name="r1")
    return await publish(a)


# ---------------------------------------------------------------- promote


async def test_a_pre_raise_candidate_without_the_pack_cannot_be_promoted_after_a_raise(a):
    """The probe: v1 active and v2 a shadow candidate, neither extending the pack;
    raise to regulated; alice asks, bob approves; the promotion is refused."""
    await activate(a)  # v1
    await put(a, name="r2")
    assert (await publish(a, "shadow", 10)).state == "candidate"  # v2
    needs_approval(a)  # the operator raises the tier
    promotion = await approve(a, await request(a, action="promote"))
    with pytest.raises(DraftInvalidError) as refused:
        await promote(a, promotion)
    assert {e.code for e in refused.value.errors} == REQUIRED  # the codes a publish gets
    assert refused.value.errors[0].path == "$.extends"
    after = await state(a)
    assert (after.active, after.candidate.version) == (1, 2)  # nothing moved
    assert (await row(a, promotion)).status == "approved"  # and the approval was not consumed
    assert not [e for e in await events(a) if e.action == "consumed"]


async def test_the_refusal_is_the_one_a_publish_of_it_would_get(a):
    await activate(a)
    await put(a, name="r2")
    await publish(a, "shadow", 10)
    await put(a, name="r3")  # a draft saved before the raise (a draft is checked at once too)
    needs_approval(a)
    promotion = await approve(a, await request(a, action="promote"))
    with pytest.raises(DraftInvalidError) as promoted:
        await promote(a, promotion)
    await a.publisher.abandon(await decide(a, "POST", "/candidate/abandon"), ALICE)
    # its publish is refused ...
    with pytest.raises(DraftInvalidError) as published:
        await publish(a, "shadow", 10)
    # ... with the codes the promotion of the old candidate got
    assert [(e.code, e.path) for e in published.value.errors] == [
        (e.code, e.path) for e in promoted.value.errors
    ]


async def test_an_enforce_candidate_that_was_approved_is_held_to_the_tier_too(a):
    await activate(a)
    await put(a, name="r2")
    await publish(a, "enforce", 10)  # standard: no approval needed, v2 candidate
    needs_approval(a)
    with pytest.raises(DraftInvalidError) as refused:
        await promote(a, await approve(a, await request(a, action="promote")))
    assert {e.code for e in refused.value.errors} == REQUIRED


async def test_a_candidate_that_extends_the_pack_promotes_after_the_raise(a):
    await activate(a, packs=[PACK])
    await put(a, packs=[PACK], name="r2")
    await publish(a, "shadow", 10)
    needs_approval(a)
    promotion = await approve(a, await request(a, action="promote"))
    assert (await promote(a, promotion)).state == "active"


async def test_a_standard_tenant_promotes_a_candidate_without_the_pack(a):
    await activate(a)
    await put(a, name="r2")
    await publish(a, "shadow", 10)
    assert (await promote(a)).state == "active"  # no tier requirement, no approval


# ---------------------------------------------------------------- set_percent


async def set_percent(a, percent):
    d = await decide(a, "PATCH", "/candidate")
    body = json.dumps({"rollout_percent": percent}).encode()
    return await a.publisher.set_percent(d, ALICE, body)


async def test_raising_a_pre_raise_enforce_candidate_without_the_pack_is_refused(a):
    """The probe: v2 an enforce candidate at 1% without the pack; raise to
    regulated; raising its share to 100% is refused with the codes a publish gets."""
    await activate(a)
    await put(a, name="r2")
    await publish(a, "enforce", 1)
    needs_approval(a)
    with pytest.raises(DraftInvalidError) as refused:
        await set_percent(a, 100)
    assert {e.code for e in refused.value.errors} == REQUIRED
    assert (await state(a)).candidate.rollout_percent == 1  # nothing moved


async def test_lowering_or_abandoning_a_noncompliant_candidate_stays_allowed(a):
    await activate(a)
    await put(a, name="r2")
    await publish(a, "enforce", 20)
    needs_approval(a)
    assert (await set_percent(a, 5)).rollout_percent == 5  # backing out is always allowed
    await a.publisher.abandon(await decide(a, "POST", "/candidate/abandon"), ALICE)
    assert (await state(a)).candidate is None


async def test_raising_a_compliant_enforce_candidate_after_the_raise_is_allowed(a):
    await activate(a, packs=[PACK])
    await put(a, packs=[PACK], name="r2")
    await publish(a, "enforce", 10)
    needs_approval(a)
    assert (await set_percent(a, 50)).rollout_percent == 50


async def test_raising_a_shadow_candidates_share_is_not_held_to_the_tier(a):
    await activate(a)
    await put(a, name="r2")
    await publish(a, "shadow", 10)
    needs_approval(a)
    assert (await set_percent(a, 50)).rollout_percent == 50  # a shadow candidate never acts


# ---------------------------------------------------------------- rollback


async def three_versions(a):
    """v1 without the pack, v2 with it, v3 without it (v3 active); all published as standard."""
    await activate(a)  # v1 (no pack)
    await put(a, packs=[PACK], name="r2")
    await publish(a, "enforce", 100)  # v2 candidate
    await promote(a)
    await put(a, name="r3")
    await publish(a, "enforce", 100)  # v3 candidate
    await promote(a)
    assert (await state(a)).active == 3


async def test_a_rollback_on_a_regulated_tenant_must_meet_the_tier_and_names_those_that_do(a):
    await three_versions(a)
    # v3 is running and lacks the pack; of the earlier ones only v2 meets the tier
    needs_approval(a)
    with pytest.raises(RollbackTierError) as refused:
        await rollback(a, 1)
    assert {e.code for e in refused.value.errors} == REQUIRED
    assert refused.value.compliant_versions == [2]
    assert (await state(a)).active == 3  # the running version keeps running, untouched
    result = await rollback(a, 2, principal=BOB)  # one person, no approval (R2)
    assert (result.version, result.state) == (2, "active")


async def test_a_rollback_to_a_noncompliant_version_lists_none_when_none_comply(a):
    await activate(a)  # v1
    await put(a, name="r2")
    await publish(a, "enforce", 100)
    await promote(a)  # v2 active
    needs_approval(a)
    with pytest.raises(RollbackTierError) as refused:
        await rollback(a, 1)
    assert refused.value.compliant_versions == []


async def test_a_rollback_on_a_standard_tenant_is_not_held_to_the_pack(a):
    await three_versions(a)
    assert (await rollback(a, 1)).version == 1


async def test_a_rollback_stays_approval_free_on_a_regulated_tenant(a):
    await three_versions(a)
    needs_approval(a)
    result = await rollback(a, 2)  # no approval id, no approval service call
    assert result.state == "active"
    assert not [e for e in await events(a) if e.action in ("requested", "approved")]


async def test_the_http_answer_for_a_refused_rollback_lists_the_compliant_versions():
    import httpx
    from cryptography.hazmat.primitives.asymmetric import rsa
    from test_m5_02_http import ISS, headers, jwk

    from guardrail_engine.admin.adapters.fastapi_app import create_admin_app
    from guardrail_engine.signing.adapters.oidc import (
        OidcConfig,
        PyJwtAuthenticator,
        StaticJwksSource,
    )

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    admin = Admin()
    admin.catalog._tier_packs = {"regulated": frozenset({"claims"})}
    try:
        await three_versions(admin)
        needs_approval(admin)
        auth = PyJwtAuthenticator(
            OidcConfig(frozenset({ISS}), "guardrail-admin-api"),
            StaticJwksSource({"keys": [jwk(key)]}),
        )
        app = create_admin_app(
            authenticator=auth, authorizer=admin.authorizer, service=admin.service,
            tools=admin.tools, golden=admin.golden, catalog=admin.catalog_service,
            publisher=admin.publisher, tool_registry=admin.tool_service, floors=admin.floors,
            repin=admin.repin,
        )  # fmt: skip
        transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
        async with httpx.AsyncClient(transport=transport, base_url="http://admin.test") as c:
            r = await c.post(
                f"/v1/tenants/{ALPHA}/guardrails/versions/1/rollback",
                headers=headers(key, "guardrail_admin"),
            )
        assert r.status_code == 422, r.text
        error = r.json()["error"]
        assert error["compliant_versions"] == [2]
        assert {e["code"] for e in error["errors"]} == REQUIRED
    finally:
        await admin.aclose()
