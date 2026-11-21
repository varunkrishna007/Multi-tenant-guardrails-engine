"""M2-09 R5.2 to R5.6: re-pin as a platform publish, override carry-over in the service, staged
promotion with its proof, the minimum raise, and the rollback guard."""

import asyncio
import json
from datetime import timedelta

import pytest
from admin_fixtures import ALPHA, BETA, bundle, rule, who
from floor_fixtures import (
    FLOOR_V2,
    TENANT_BASE,
    active_tenant,
    docs,
    lifecycle,
    new_admin,
    operator,
    pdecide,
    release,
)

from guardrail_engine.admin.floors import (
    FloorNotReleasedError,
    PlatformEvent,
    ReleaseNotFoundError,
)
from guardrail_engine.admin.lifecycle import PublishEvent
from guardrail_engine.admin.publish import FloorBelowMinimumError
from guardrail_engine.admin.repin_service import (
    MinimumError,
    NoRepinCandidateError,
    PromotionHaltedError,
    RepinStaleError,
    TenantsBehindError,
    WindowOpenError,
    repin_proof,
)
from guardrail_engine.authz import Role
from guardrail_engine.policy.catalog import PlatformSettings
from guardrail_engine.policy.compiler import PolicyCompiler
from guardrail_engine.policy.errors import ErrorCode
from guardrail_engine.policy.repin import repin_document
from guardrail_engine.tenant_scope import issue_scope

OPS = operator("ops-1")
REASON = "calibrated thresholds"


@pytest.fixture
async def a():
    admin = new_admin()
    yield admin
    await admin.aclose()


def alpha_doc():
    """Alpha's bundle: a pack, a shadow rule, a stricter-than-floor override that survives
    floor@2 and one that doesn't, and settings of its own."""
    doc = bundle(
        ALPHA, packs=["domain/claims@1"],
        rules=[rule("r1", gps=("output",), mode="shadow")],
        defaults={"block_at": 0.8, "escalate_at": 0.45},
    )  # fmt: skip
    doc["overrides"] = [
        {"rule": "p__inj_direct", "block_at": 0.70},  # floor@2 says 0.75: still stricter
        {"rule": "p__ai_addressed", "escalate_at": 0.50},  # floor@2 says 0.40: not any more
    ]
    doc["deterministic"] = {"deny_patterns": [{"id": "x", "regex": "x+", "action": "block"}]}
    return doc


async def setup_alpha(a):
    await active_tenant(a, ALPHA, alpha_doc())
    await release(a)


async def repin_all(a, version=2, only=None):
    d = await pdecide(a, OPS, "POST", "/v1/platform/floors/{version}/repin")
    return await a.repin.repin_all(d, OPS, version, REASON, only)


async def promote(a, tid=ALPHA, version=2):
    return await a.repin.promote_tenant(OPS, tid, version)


# ---------------------------------------------------------------------------- re-pin


async def test_repin_stages_a_shadow_candidate_at_100_by_the_platform(a):
    await setup_alpha(a)
    [result] = [r for r in await repin_all(a) if r.tenant_id == ALPHA]
    assert (result.outcome, result.version) == ("staged", 2)
    st = await lifecycle(a).state(ALPHA)
    assert st.active == 1 and st.candidate.version == 2
    assert (st.candidate.mode, st.candidate.rollout_percent, st.candidate.actor) == (
        "shadow", 100, "platform"
    )  # fmt: skip
    event = (await lifecycle(a).events(ALPHA))[-1]
    assert (event.action, event.actor, event.repin_floor) == ("publish", "platform", 2)
    assert event.operator and event.cross_tenant and not event.becomes_active
    assert "ops-1" in event.note and REASON in event.note and "1 override" in event.note
    assert [(d["rule"], d["field"], d["old"], d["floor"]) for d in event.repin_drops] == [
        ("p__ai_addressed", "escalate_at", 0.50, 0.40)
    ]  # fmt: skip
    audit = [e for e in await a.platform.events() if e.action == "repin"]
    assert audit[-1].tenant_id == ALPHA and audit[-1].detail["outcome"] == "staged"
    cross = [e for e in a.audit.events if e.target_tenant_id == ALPHA and e.allowed]
    assert cross and all(e.actor == "https://i/#ops-1" for e in cross)  # the operator, audited


async def test_the_repinned_bundle_keeps_every_tenant_member_byte_identical(a):
    await setup_alpha(a)
    await repin_all(a)
    old, new = await docs(a, ALPHA, 1), await docs(a, ALPHA, 2)
    for member in old:
        if member in ("extends", "overrides", "version"):
            continue
        assert json.dumps(new[member], sort_keys=True) == json.dumps(old[member], sort_keys=True)
    assert new["extends"] == ["platform/floor@2", "domain/claims@1"]
    assert new["overrides"] == [{"rule": "p__inj_direct", "block_at": 0.70}]
    assert new["version"] == 2 and old["extends"][0] == "platform/floor@1"
    profile = await a.tenants.get(ALPHA)
    compiled = PolicyCompiler(a.catalog, profile, PlatformSettings()).compile(
        __import__("guardrail_engine.policy.document", fromlist=["parse_bundle"]).parse_bundle(new),
        profile.attributes,
    )
    thresholds = {
        r.key: (r.block_at, r.escalate_at)
        for r in compiled.guard_points["input"].rules.values()
        if r.key.startswith("p__")
    }
    assert thresholds["p__inj_direct"] == (0.70, 0.50)  # kept: 0.70 over the floor's 0.50
    assert thresholds["p__ai_addressed"] == (0.80, 0.40)  # the floor's: the override is gone


async def test_admins_are_notified_with_the_dropped_overrides(a):
    await setup_alpha(a)
    await repin_all(a)
    [notice] = [n for n in a.notifier.notices if n.tenant_id == ALPHA]
    assert notice.kind == "floor_repin_staged"
    assert notice.detail["floor_version"] == 2 and notice.detail["candidate_version"] == 2
    assert notice.detail["drops"][0]["rule"] == "p__ai_addressed"
    assert notice.detail["window_hours"] == 72 and notice.detail["reason"] == REASON


async def test_a_tenant_with_its_own_candidate_is_skipped_and_its_candidate_is_untouched(a):
    await setup_alpha(a)
    await active_tenant(a, BETA, bundle(BETA, rules=[rule("b", gps=("output",), mode="shadow")]))
    principal = who(Role.GUARDRAIL_ADMIN, tenant=BETA, issuer="https://i/")
    d = await a.decide(principal, "PUT", TENANT_BASE + "/draft", BETA)
    doc = bundle(BETA, rules=[rule("b2", gps=("output",), mode="shadow")])
    saved = await a.service.put_draft(d, principal, json.dumps(doc).encode(), "*")
    d = await a.decide(principal, "POST", TENANT_BASE + "/draft/publish", BETA)
    await a.publisher.publish(
        d, principal, b'{"mode": "shadow", "rollout_percent": 10}', saved.etag
    )
    before = await lifecycle(a, BETA).state(BETA)
    results = {r.tenant_id: r for r in await repin_all(a)}
    assert (results[BETA].outcome, results[BETA].detail) == ("skipped", "candidate_exists")
    assert results[ALPHA].outcome == "staged"
    assert await lifecycle(a, BETA).state(BETA) == before  # not abandoned, not replaced
    assert not [n for n in a.notifier.notices if n.tenant_id == BETA]


async def test_repeating_a_repin_is_idempotent_and_a_stale_one_is_replaced(a):
    await setup_alpha(a)
    await repin_all(a)
    again = {r.tenant_id: r for r in await repin_all(a)}
    assert again[ALPHA].outcome == "already_staged" and again[ALPHA].version == 2
    assert len(await lifecycle(a).versions(ALPHA)) == 2  # nothing new stored
    # the tenant drifted: the staged candidate no longer matches the active version
    store = a.policies.scoped(issue_scope(ALPHA))
    drift = dict(alpha_doc(), version=3)
    drift["rules"] = [rule("changed", gps=("output",), mode="shadow")]
    from guardrail_engine.policy.document import parse_bundle

    parsed = parse_bundle(drift)
    profile = await a.tenants.get(ALPHA)
    h = (
        PolicyCompiler(a.catalog, profile, PlatformSettings())
        .compile(parsed, profile.attributes)
        .bundle_hash
    )
    await store.put_version(ALPHA, parsed, bundle_hash=h)
    await store.set_active_version(ALPHA, 3, expected_current=1)
    replaced = {r.tenant_id: r for r in await repin_all(a)}
    assert (replaced[ALPHA].outcome, replaced[ALPHA].version) == ("replaced", 4)
    st = await lifecycle(a).state(ALPHA)
    assert st.candidate.version == 4
    assert [e.action for e in (await lifecycle(a).events(ALPHA))[-2:]] == ["abandon", "publish"]


async def test_a_tenant_already_on_the_floor_or_without_an_active_version_is_listed(a):
    await setup_alpha(a)
    r = {x.tenant_id: x for x in await repin_all(a)}
    assert (r[BETA].outcome, r[BETA].detail) == ("skipped", "no_active_version")
    await promote_after_window(a)
    again = {x.tenant_id: x for x in await repin_all(a)}
    assert again[ALPHA].outcome == "already_on_floor"


async def test_an_unreleased_or_unknown_floor_is_refused(a):
    await active_tenant(a, ALPHA, alpha_doc())
    d = await pdecide(a, OPS, "POST", "/v1/platform/floors/{version}/repin")
    with pytest.raises(ReleaseNotFoundError):
        await a.repin.repin_all(d, OPS, 2, REASON)
    from floor_fixtures import report

    p = operator("op1")
    pd = await pdecide(a, p, "POST", "/v1/platform/floors/{version}/release")
    await a.floors.propose(pd, p, 2, json.dumps({"report": report()}).encode())
    with pytest.raises(FloorNotReleasedError):  # proposed, one approval
        await a.repin.repin_all(d, OPS, 2, REASON)


async def test_a_tenant_that_does_not_compile_on_the_new_floor_stays_and_is_listed(a):
    await setup_alpha(a)
    from guardrail_engine.policy.catalog import QuestionBudgets

    a.repin._settings = PlatformSettings(question_budgets=QuestionBudgets(output=3))
    results = {r.tenant_id: r for r in await repin_all(a, only=[ALPHA])}
    assert results[ALPHA].outcome == "failed" and "does not compile" in results[ALPHA].detail
    st = await lifecycle(a).state(ALPHA)
    assert st.active == 1 and st.candidate is None  # nothing was stored


async def test_a_suspended_tenant_is_not_repinned(a):
    await setup_alpha(a)
    a.tenants.remove(ALPHA)
    assert ALPHA not in {r.tenant_id for r in await repin_all(a)}


# ---------------------------------------------------------------------------- promotion


async def promote_after_window(a, hours=72):
    await repin_all(a)
    a.now += timedelta(hours=hours, minutes=1)
    return await promote(a)


async def test_promotion_waits_for_the_window_and_then_makes_the_floor_active(a):
    await setup_alpha(a)
    await repin_all(a)
    a.now += timedelta(hours=71)
    with pytest.raises(WindowOpenError) as early:
        await promote(a)
    assert early.value.until > a.now
    a.now += timedelta(hours=1, minutes=1)
    result = await promote(a)
    assert result.outcome == "promoted"
    st = await lifecycle(a).state(ALPHA)
    assert st.active == 2 and st.candidate is None
    event = (await lifecycle(a).events(ALPHA))[-1]
    assert (event.action, event.actor, event.repin_floor) == ("promote", "platform", 2)
    assert event.becomes_active and event.mode == "enforce"
    assert [n.kind for n in a.notifier.notices if n.tenant_id == ALPHA][
        -1
    ] == "floor_repin_promoted"
    assert a.bus.published[-1].action == "promote"


async def test_a_security_urgent_release_stages_for_6_hours(a):
    await active_tenant(a, ALPHA, alpha_doc())
    await release(a, urgent=(True, True))
    await repin_all(a)
    a.now += timedelta(hours=5)
    with pytest.raises(WindowOpenError):
        await promote(a)
    a.now += timedelta(hours=1, minutes=1)
    assert (await promote(a)).outcome == "promoted"


async def test_a_halted_release_refuses_promotion_until_resumed(a):
    await setup_alpha(a)
    await repin_all(a)
    a.now += timedelta(hours=73)
    d = await pdecide(a, OPS, "POST", "/v1/platform/floors/{version}/halt")
    await a.floors.halt(d, OPS, 2, halted=True)
    with pytest.raises(PromotionHaltedError):
        await promote(a)
    d = await pdecide(a, OPS, "DELETE", "/v1/platform/floors/{version}/halt")
    await a.floors.halt(d, OPS, 2, halted=False)
    assert (await promote(a)).outcome == "promoted"


async def test_there_must_be_a_repin_candidate_for_that_release(a):
    await setup_alpha(a)
    with pytest.raises(NoRepinCandidateError):
        await promote(a)  # no candidate at all
    # a tenant's own candidate is never promoted by the platform
    principal = who(Role.GUARDRAIL_ADMIN, issuer="https://i/")
    d = await a.decide(principal, "PUT", TENANT_BASE + "/draft", ALPHA)
    doc = alpha_doc()
    doc["rules"] = [rule("own", gps=("output",), mode="shadow")]
    saved = await a.service.put_draft(d, principal, json.dumps(doc).encode(), "*")
    d = await a.decide(principal, "POST", TENANT_BASE + "/draft/publish", ALPHA)
    await a.publisher.publish(d, principal, b'{"mode": "shadow", "rollout_percent": 5}', saved.etag)
    with pytest.raises(NoRepinCandidateError):
        await promote(a)


async def test_the_proof_is_checked_against_the_current_active_version(a):
    await setup_alpha(a)
    await repin_all(a)
    a.now += timedelta(hours=73)
    store = a.policies.scoped(issue_scope(ALPHA))
    drift = dict(alpha_doc(), version=3)
    drift["defaults"] = {"block_at": 0.9, "escalate_at": 0.45}  # the tenant moved on
    from guardrail_engine.policy.document import parse_bundle

    parsed = parse_bundle(drift)
    profile = await a.tenants.get(ALPHA)
    h = (
        PolicyCompiler(a.catalog, profile, PlatformSettings())
        .compile(parsed, profile.attributes)
        .bundle_hash
    )
    await store.put_version(ALPHA, parsed, bundle_hash=h)
    await store.set_active_version(ALPHA, 3, expected_current=1)
    with pytest.raises(RepinStaleError):
        await promote(a)
    assert (await lifecycle(a).state(ALPHA)).active == 3  # nothing was promoted


def test_the_proof_function_accepts_only_the_exact_repin():
    active = alpha_doc()
    candidate = repin_document(active, FLOOR_V2).document
    candidate["version"] = 5
    assert repin_proof(active, candidate, FLOOR_V2) is None
    for edit in (
        lambda d: d["rules"].append(rule("sneaky", gps=("output",))),
        lambda d: d.update(defaults={"block_at": 0.99}),
        lambda d: d["extends"].append("domain/finance@2"),
        lambda d: d["overrides"].append({"rule": "p__secret", "block_at": 0.01}),
        lambda d: d.update(audit={"records_days": 90}),
    ):
        tampered = json.loads(json.dumps(candidate))
        edit(tampered)
        assert repin_proof(active, tampered, FLOOR_V2) == "differs"


async def test_the_platform_promotion_skips_the_tenant_gates_the_normal_one_would_apply(a):
    """A tenant whose active version enforces a rule with no evidence (it predates the gate):
    the tenant's own promote of the re-pin candidate is refused by the evidence gate; the
    platform's is not, because it changes nothing of the tenant's."""
    doc = alpha_doc()
    doc["rules"] = [rule("old", gps=("output",))]  # an enforcing tenant rule
    store = lifecycle(a)
    from guardrail_engine.policy.document import parse_bundle

    profile = await a.tenants.get(ALPHA)
    parsed = parse_bundle({**doc, "version": 1})
    h = (
        PolicyCompiler(a.catalog, profile, PlatformSettings())
        .compile(parsed, profile.attributes)
        .bundle_hash
    )
    await store.publish(
        ALPHA, parsed, h, candidate=None, expected=await store.state(ALPHA),
        event=PublishEvent(a.now, "legacy", ALPHA, "publish", 1, mode="enforce",
                           rollout_percent=100, becomes_active=True),
    )  # fmt: skip
    await release(a)
    await repin_all(a)
    a.now += timedelta(hours=73)
    principal = who(Role.GUARDRAIL_ADMIN, issuer="https://i/")
    d = await a.decide(principal, "POST", TENANT_BASE + "/candidate/promote", ALPHA)
    from guardrail_engine.admin import DraftInvalidError

    with pytest.raises(DraftInvalidError):
        await a.publisher.promote(d, principal)
    assert (await promote(a)).outcome == "promoted"


# ---------------------------------------------------------------------------- the minimum


async def test_the_minimum_is_refused_while_a_tenant_is_behind_and_names_it(a):
    await setup_alpha(a)
    await active_tenant(a, BETA, bundle(BETA))
    await repin_all(a)
    d = await pdecide(a, OPS, "PUT", "/v1/platform/minimum-floor")
    with pytest.raises(TenantsBehindError) as behind:
        await a.repin.raise_minimum(d, OPS, 2)
    assert behind.value.tenants == [ALPHA, BETA]  # alpha only has a candidate
    assert a.catalog.minimum_floor_version() == 1 and await a.platform.minimum() is None


async def test_the_minimum_is_raised_when_every_tenant_is_on_the_floor_and_applies_at_once(a):
    await setup_alpha(a)
    await active_tenant(a, BETA, bundle(BETA))
    await repin_all(a)
    a.now += timedelta(hours=73)
    await promote(a, ALPHA)
    await promote(a, BETA)
    d = await pdecide(a, OPS, "PUT", "/v1/platform/minimum-floor")
    assert await a.repin.raise_minimum(d, OPS, 2) == 2
    assert a.catalog.minimum_floor_version() == 2 and await a.platform.minimum() == 2
    assert [e.action for e in await a.platform.events()][-1] == "raise_minimum"
    assert any(p.action == "floor" for p in a.bus.published)
    # the old floor is still in the catalog, and no new bundle may extend it
    assert a.catalog.floor(1) is not None
    profile = await a.tenants.get(ALPHA)
    errors = PolicyCompiler(a.catalog, profile, PlatformSettings()).validate(
        bundle(ALPHA), profile.attributes
    )
    assert [str(e.code) for e in errors] == [ErrorCode.FLOOR_BELOW_MINIMUM]
    with pytest.raises(MinimumError):  # it only goes up
        await a.repin.raise_minimum(d, OPS, 2)
    with pytest.raises(MinimumError):
        await a.repin.raise_minimum(d, OPS, 1)


async def test_a_minimum_needs_a_released_floor_and_a_tenant_with_no_active_version_does_not_block(
    a,
):
    await active_tenant(a, ALPHA, alpha_doc())
    d = await pdecide(a, OPS, "PUT", "/v1/platform/minimum-floor")
    with pytest.raises(FloorNotReleasedError):
        await a.repin.raise_minimum(d, OPS, 2)
    await release(a)
    with pytest.raises(TenantsBehindError):
        await a.repin.raise_minimum(d, OPS, 2)


async def test_a_suspended_tenant_still_counts_for_the_minimum(a):
    await setup_alpha(a)
    await repin_all(a)
    a.now += timedelta(hours=73)
    await promote(a)
    a.tenants.remove(BETA)  # not listed by this directory any more: nothing to be behind
    d = await pdecide(a, OPS, "PUT", "/v1/platform/minimum-floor")
    assert await a.repin.raise_minimum(d, OPS, 2) == 2


# ---------------------------------------------------------------------------- rollback guard


async def raised(a):
    """Alpha promoted to floor@2 (its v1 is on floor@1), the minimum raised to 2."""
    await setup_alpha(a)
    await repin_all(a)
    a.now += timedelta(hours=73)
    await promote(a)
    d = await pdecide(a, OPS, "PUT", "/v1/platform/minimum-floor")
    await a.repin.raise_minimum(d, OPS, 2)


async def test_a_rollback_to_a_version_below_the_minimum_comes_back_on_the_current_floor(a):
    await raised(a)
    principal = who(Role.GUARDRAIL_ADMIN, issuer="https://i/")
    d = await a.decide(principal, "POST", TENANT_BASE + "/versions/{v}/rollback", ALPHA)
    result = await a.publisher.rollback(d, principal, 1)
    assert (result.version, result.state, result.mode) == (3, "active", "enforce")
    st = await lifecycle(a).state(ALPHA)
    assert st.active == 3 and st.candidate is None
    new, old = await docs(a, ALPHA, 3), await docs(a, ALPHA, 1)
    assert new["extends"][0] == "platform/floor@2" and old["extends"][0] == "platform/floor@1"
    for member in old:  # the tenant's own content is what came back
        if member not in ("extends", "overrides", "version"):
            assert new[member] == old[member], member
    assert new["overrides"] == [{"rule": "p__inj_direct", "block_at": 0.70}]
    event = (await lifecycle(a).events(ALPHA))[-1]
    assert (event.action, event.version, event.repin_floor) == ("rollback", 3, 2)
    assert event.actor == "https://i/#alice" and event.becomes_active
    assert [d["rule"] for d in event.repin_drops] == ["p__ai_addressed"]
    assert "rollback to v1" in event.note and "floor@1 to floor@2" in event.note
    assert a.bus.published[-1].action == "rollback"
    # and the new version can itself be rolled back to later: it was active
    d = await a.decide(principal, "POST", TENANT_BASE + "/versions/{v}/rollback", ALPHA)
    again = await a.publisher.rollback(d, principal, 2)
    assert again.version == 2


async def test_no_path_brings_back_an_old_floor(a):
    await raised(a)
    principal = who(Role.GUARDRAIL_ADMIN, issuer="https://i/")
    # publish on floor@1: refused by the compiler
    from guardrail_engine.admin import DraftInvalidError

    d = await a.decide(principal, "PUT", TENANT_BASE + "/draft", ALPHA)
    current = bundle(ALPHA)
    current["extends"] = ["platform/floor@2"]
    saved = await a.service.put_draft(d, principal, json.dumps(current).encode(), "*")
    stale = json.loads(saved.document)
    stale["extends"] = ["platform/floor@1"]
    with pytest.raises(DraftInvalidError) as refused:
        await a.service.put_draft(d, principal, json.dumps(stale).encode(), saved.etag)
    assert refused.value.errors[0].code == "floor.below_minimum"
    # every version that is active from here on extends floor@2 or above
    d = await a.decide(principal, "POST", TENANT_BASE + "/versions/{v}/rollback", ALPHA)
    await a.publisher.rollback(d, principal, 1)
    for event in await lifecycle(a).events(ALPHA):
        if event.becomes_active and event.version >= 2:
            doc = await docs(a, ALPHA, event.version)
            assert doc["extends"][0] == "platform/floor@2", event.version


async def test_a_candidate_staged_before_the_raise_cannot_be_promoted_after_it(a):
    await setup_alpha(a)
    principal = who(Role.GUARDRAIL_ADMIN, issuer="https://i/")
    d = await a.decide(principal, "PUT", TENANT_BASE + "/draft", ALPHA)
    doc = alpha_doc()
    doc["rules"] = [rule("later", gps=("output",), mode="shadow")]
    saved = await a.service.put_draft(d, principal, json.dumps(doc).encode(), "*")
    d = await a.decide(principal, "POST", TENANT_BASE + "/draft/publish", ALPHA)
    await a.publisher.publish(d, principal, b'{"mode": "shadow", "rollout_percent": 5}', saved.etag)
    # the platform raises the minimum with the tenant's active still on floor@1: refused...
    d2 = await pdecide(a, OPS, "PUT", "/v1/platform/minimum-floor")
    with pytest.raises(TenantsBehindError):
        await a.repin.raise_minimum(d2, OPS, 2)
    # ...so force the state a race could leave: the minimum applied, the candidate on floor@1
    a.catalog.raise_minimum(2)
    d = await a.decide(principal, "POST", TENANT_BASE + "/candidate/promote", ALPHA)
    with pytest.raises(FloorBelowMinimumError):
        await a.publisher.promote(d, principal)
    assert (await lifecycle(a).state(ALPHA)).active == 1


async def test_a_rollback_that_cannot_be_repinned_is_refused_and_changes_nothing(a):
    await raised(a)
    principal = who(Role.GUARDRAIL_ADMIN, issuer="https://i/")
    from guardrail_engine.admin.publish import RollbackRepinError
    from guardrail_engine.policy.catalog import QuestionBudgets

    a.publisher._settings = PlatformSettings(question_budgets=QuestionBudgets(output=3))
    d = await a.decide(principal, "POST", TENANT_BASE + "/versions/{v}/rollback", ALPHA)
    with pytest.raises(RollbackRepinError):
        await a.publisher.rollback(d, principal, 1)
    assert (await lifecycle(a).state(ALPHA)).active == 2


async def test_the_platform_audit_trail_has_every_step(a):
    await raised(a)
    actions = [e.action for e in await a.platform.events()]
    assert actions == [
        "release_proposed", "release_approved", "released", "repin", "promote", "raise_minimum",
    ]  # fmt: skip
    assert all(e.actor.startswith("https://i/#") for e in await a.platform.events())


# ----------------------------------------------------------------------------
async def test_the_minimum_applies_first_so_nobody_can_slip_under_it_while_it_checks(a):
    await setup_alpha(a)
    await repin_all(a)
    a.now += timedelta(hours=73)
    await promote(a)
    seen = {}
    real = a.repin._behind

    async def watched(principal, value):
        if "during" not in seen:
            profile = await a.tenants.get(ALPHA)
            seen["during"] = [
                str(e.code)
                for e in PolicyCompiler(a.catalog, profile, PlatformSettings()).validate(
                    bundle(ALPHA),
                    profile.attributes,  # a bundle on floor@1, mid-check
                )
            ]
        return await real(principal, value)

    a.repin._behind = watched
    d = await pdecide(a, OPS, "PUT", "/v1/platform/minimum-floor")
    assert await a.repin.raise_minimum(d, OPS, 2) == 2
    assert seen["during"] == [ErrorCode.FLOOR_BELOW_MINIMUM]  # refused while it was checking


async def test_a_refused_raise_gives_the_minimum_back(a):
    await setup_alpha(a)  # alpha is still on floor@1
    d = await pdecide(a, OPS, "PUT", "/v1/platform/minimum-floor")
    with pytest.raises(TenantsBehindError):
        await a.repin.raise_minimum(d, OPS, 2)
    assert a.catalog.minimum_floor_version() == 1 and await a.platform.minimum() is None
    profile = await a.tenants.get(ALPHA)
    assert (
        PolicyCompiler(a.catalog, profile, PlatformSettings()).validate(
            bundle(ALPHA), profile.attributes
        )
        == []
    )  # floor@1 is still extendable


async def test_a_failed_raise_never_lowers_the_minimum_below_one_that_landed_meanwhile(a):
    """Another replica's raise reaches this one (the stored minimum, and the local
    catalog on its reload) while this raise is checking; this one then fails and restores."""
    await setup_alpha(a)  # alpha is still on floor@1, so the raise to 2 is refused
    assert a.catalog.minimum_floor_version() == 1

    async def another_raise_lands(principal, value):
        await a.platform.set_minimum(
            2, expected=None, by="other", at=a.now,
            event=PlatformEvent(a.now, "other", "raise_minimum", 2),
        )  # fmt: skip
        a.catalog.raise_minimum(2)  # what this replica's reload does
        return [ALPHA]

    a.repin._behind = another_raise_lands
    d = await pdecide(a, OPS, "PUT", "/v1/platform/minimum-floor")
    with pytest.raises(TenantsBehindError):
        await a.repin.raise_minimum(d, OPS, 2)
    assert await a.platform.minimum() == 2
    assert a.catalog.minimum_floor_version() == 2  # not 1


async def test_two_raises_on_one_replica_run_one_after_the_other(a):
    await setup_alpha(a)
    await repin_all(a)
    a.now += timedelta(hours=73)
    await promote(a)
    running = []
    real = a.repin._behind

    async def slow(principal, value):
        running.append(1)
        assert len(running) == 1  # never two in the check at once
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        running.pop()
        return await real(principal, value)

    a.repin._behind = slow
    d = await pdecide(a, OPS, "PUT", "/v1/platform/minimum-floor")
    results = await asyncio.gather(
        a.repin.raise_minimum(d, OPS, 2), a.repin.raise_minimum(d, OPS, 2), return_exceptions=True
    )
    assert results[0] == 2 and isinstance(results[1], MinimumError)  # the second finds it raised


async def test_a_failing_write_gives_the_minimum_back_too(a):
    await setup_alpha(a)
    await repin_all(a)
    a.now += timedelta(hours=73)
    await promote(a)
    a.platform.fail_audit = True
    d = await pdecide(a, OPS, "PUT", "/v1/platform/minimum-floor")
    with pytest.raises(RuntimeError):
        await a.repin.raise_minimum(d, OPS, 2)
    assert a.catalog.minimum_floor_version() == 1


async def test_a_tenant_that_moved_below_meanwhile_is_found_and_recorded(a):
    await setup_alpha(a)
    await repin_all(a)
    a.now += timedelta(hours=73)
    await promote(a)
    real = a.repin._behind
    calls = {"n": 0}

    async def second_scan_finds_one(principal, value):
        calls["n"] += 1
        return [] if calls["n"] == 1 else [ALPHA]  # moved on another replica after the check

    a.repin._behind = second_scan_finds_one
    d = await pdecide(a, OPS, "PUT", "/v1/platform/minimum-floor")
    assert await a.repin.raise_minimum(d, OPS, 2) == 2
    last = [e for e in await a.platform.events() if e.action == "raise_minimum"][-1]
    assert last.detail == {"stragglers": [ALPHA]}
    assert real is not None
