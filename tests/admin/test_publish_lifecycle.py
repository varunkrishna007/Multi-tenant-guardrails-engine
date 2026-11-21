"""M2-07 the version lifecycle: the PF-7 state machine, publish, candidate changes, rollback and
the versions list, through the real authorizer, compiler and policy store (in memory)."""

import json

import pytest
from admin_fixtures import ALPHA, BETA, Admin, bundle, rule, who

from guardrail_engine.admin import (
    DecisionError,
    DraftConflictError,
    DraftInvalidError,
    NoDraftError,
    PreconditionRequiredError,
    TenantUnavailableError,
)
from guardrail_engine.admin.lifecycle import (
    AlreadyActiveError,
    ApprovalRequiredError,
    CandidateExistsError,
    LifecycleState,
    NoActiveVersionError,
    NoCandidateError,
    NotPreviouslyActiveError,
    PublishEvent,
    StateConflictError,
)
from guardrail_engine.authz import Role
from guardrail_engine.guard.tenants import TenantProfile
from guardrail_engine.policy.catalog import TenantAttributes
from guardrail_engine.store.port import ScopeMismatchError, VersionNotFoundError
from guardrail_engine.tenant_scope import issue_scope

BASE = "/v1/tenants/{tid}/guardrails"
ADMIN = who(Role.GUARDRAIL_ADMIN, issuer="https://i/")


@pytest.fixture
async def a():
    admin = Admin()
    yield admin
    await admin.aclose()


async def decide(a, method, route, principal=ADMIN, tid=ALPHA):
    return await a.decide(principal, method, BASE + route, tid)


async def save(a, doc=None, *, if_match=None):
    d = await decide(a, "PUT", "/draft")
    return await a.service.put_draft(d, ADMIN, json.dumps(doc or bundle(ALPHA)).encode(), if_match)


async def publish(a, mode="enforce", percent=100, note="", *, draft=None, principal=ADMIN):
    draft = draft or await a.drafts.scoped(issue_scope(ALPHA)).get(ALPHA)
    body = json.dumps({"mode": mode, "rollout_percent": percent, "note": note}).encode()
    d = await decide(a, "POST", "/draft/publish", principal)
    return await a.publisher.publish(d, principal, body, draft.etag)


async def state(a):
    return await a.lifecycle.scoped(issue_scope(ALPHA)).state(ALPHA)


async def first_active(a):
    """Tenant ALPHA with version 1 active and a draft at the same content."""
    await save(a)
    result = await publish(a)
    assert result.state == "active" and result.version == 1
    return result


# ---------------------------------------------------------------------------- first publish


async def test_a_first_publish_in_enforce_at_100_becomes_active_directly(a):
    await save(a, bundle(ALPHA, rules=[rule("r", gps=("output",), mode="shadow")]))
    result = await publish(a, note="first")
    assert (result.version, result.mode, result.rollout_percent, result.state) == (
        1, "enforce", 100, "active"
    )  # fmt: skip
    assert await state(a) == LifecycleState(active=1, candidate=None)
    assert await a.policies.scoped(issue_scope(ALPHA)).get_active_version(ALPHA) == 1
    (event,) = a.lifecycle._events
    assert event.action == "publish" and event.becomes_active and event.version == 1
    assert event.actor == "https://i/#alice" and event.note == "first"
    assert event.bundle_hash == result.bundle_hash and event.draft_hash.startswith("sha256:")
    assert [r.id for r in event.rules] == ["r"] and event.diff  # the diff against nothing
    assert [(e.tenant_id, e.version, e.action) for e in a.bus.published] == [(ALPHA, 1, "publish")]


@pytest.mark.parametrize(("mode", "percent"), [("shadow", 100), ("shadow", 10), ("enforce", 50)])
async def test_a_first_publish_must_be_enforce_at_100(a, mode, percent):
    await save(a)
    with pytest.raises(NoActiveVersionError):
        await publish(a, mode, percent)
    assert await state(a) == LifecycleState() and a.lifecycle._events == []


async def test_the_published_document_carries_the_assigned_version_number(a):
    await save(a, bundle(ALPHA, version=7))  # whatever the draft says
    await publish(a)
    stored = await a.policies.scoped(issue_scope(ALPHA)).get_version(ALPHA, 1)
    assert stored.document["version"] == 1 and stored.bundle.version == 1


# ---------------------------------------------------------------------------- preconditions


async def test_publish_needs_a_draft_and_its_current_etag(a):
    d = await decide(a, "POST", "/draft/publish")
    body = json.dumps({"mode": "enforce"}).encode()
    with pytest.raises(NoDraftError):
        await a.publisher.publish(d, ADMIN, body, "*")
    saved = await save(a)
    with pytest.raises(PreconditionRequiredError):
        await a.publisher.publish(d, ADMIN, body, None)
    with pytest.raises(DraftConflictError) as stale:
        await a.publisher.publish(d, ADMIN, body, '"sha256:stale"')
    assert stale.value.current == saved.etag
    assert (await a.publisher.publish(d, ADMIN, body, "*")).version == 1


@pytest.mark.parametrize(
    "body",
    [b"not json", b"[]", b"{}", b'{"mode": "maybe"}', b'{"mode": "shadow", "rollout_percent": 0}',
     b'{"mode": "shadow", "rollout_percent": 101}', b'{"mode": "shadow", "rollout_percent": true}',
     b'{"mode": "shadow", "tenant_id": "t_beta"}', b'{"mode": "shadow", "note": 5}',
     json.dumps({"mode": "shadow", "note": "x" * 501}).encode()],
)  # fmt: skip
async def test_a_bad_publish_request_is_refused_with_codes(a, body):
    saved = await save(a)
    d = await decide(a, "POST", "/draft/publish")
    with pytest.raises(DraftInvalidError):
        await a.publisher.publish(d, ADMIN, body, saved.etag)
    assert a.lifecycle._events == []


async def test_a_draft_the_compiler_now_refuses_is_not_published(a):
    saved = await save(a)
    stored = a.drafts._drafts[ALPHA]
    doc = json.loads(stored.document)
    doc["extends"] = ["platform/floor@1", "domain/insurance@99"]  # a pack that doesn't exist
    a.drafts._drafts[ALPHA] = type(stored)(
        ALPHA, json.dumps(doc).encode(), stored.etag, stored.updated_at, stored.updated_by
    )
    d = await decide(a, "POST", "/draft/publish")
    with pytest.raises(DraftInvalidError):
        await a.publisher.publish(d, ADMIN, b'{"mode": "enforce"}', saved.etag)
    assert await state(a) == LifecycleState() and a.bus.published == []


async def test_a_suspended_tenant_cannot_publish(a):
    saved = await save(a)
    a.tenants._profiles.pop(ALPHA)
    d = await decide(a, "POST", "/draft/publish")
    with pytest.raises(TenantUnavailableError):
        await a.publisher.publish(d, ADMIN, b'{"mode": "enforce"}', saved.etag)


# ---------------------------------------------------------------------------- the candidate


async def candidate_at(a, mode="shadow", percent=25):
    """Version 1 active and version 2 a candidate."""
    await first_active(a)
    await save(a, bundle(ALPHA, rules=[rule("v2", gps=("output",), mode="shadow")]),
               if_match="*")  # fmt: skip
    result = await publish(a, mode, percent)
    assert result.state == "candidate" and result.version == 2
    return result


async def test_a_later_publish_becomes_the_candidate_and_the_active_version_stays(a):
    result = await candidate_at(a, "shadow", 25)
    st = await state(a)
    assert st.active == 1
    assert (st.candidate.version, st.candidate.mode, st.candidate.rollout_percent) == (
        2, "shadow", 25
    )  # fmt: skip
    assert await a.policies.scoped(issue_scope(ALPHA)).get_active_version(ALPHA) == 1
    event = a.lifecycle._events[-1]
    assert not event.becomes_active and event.bundle_hash == result.bundle_hash
    assert any(d.path.startswith("/rules") for d in event.diff)  # against the active version
    assert [(e.version, e.action) for e in a.bus.published] == [(1, "publish"), (2, "publish")]


async def test_a_second_candidate_is_refused_until_the_first_is_dealt_with(a):
    await candidate_at(a)
    await save(a, bundle(ALPHA, rules=[rule("v3", gps=("output",))]), if_match="*")
    with pytest.raises(CandidateExistsError):
        await publish(a, "shadow", 10)
    assert (await state(a)).candidate.version == 2 and len(a.lifecycle._events) == 2


async def test_set_percent_changes_the_candidates_share_and_is_audited(a):
    await candidate_at(a, "shadow", 25)
    d = await decide(a, "PATCH", "/candidate")
    moved = await a.publisher.set_percent(d, ADMIN, b'{"rollout_percent": 60}')
    assert moved.rollout_percent == 60 and (await state(a)).candidate.rollout_percent == 60
    event = a.lifecycle._events[-1]
    assert (event.action, event.version, event.rollout_percent) == ("set_percent", 2, 60)
    for bad in (b"{}", b'{"rollout_percent": 0}', b'{"rollout_percent": 1, "x": 1}', b"[]"):
        with pytest.raises(DraftInvalidError):
            await a.publisher.set_percent(d, ADMIN, bad)


async def test_candidate_actions_need_a_candidate(a):
    await first_active(a)
    for call in (
        a.publisher.set_percent(
            await decide(a, "PATCH", "/candidate"), ADMIN, b'{"rollout_percent": 5}'
        ),
        a.publisher.promote(await decide(a, "POST", "/candidate/promote"), ADMIN),
        a.publisher.abandon(await decide(a, "POST", "/candidate/abandon"), ADMIN),
    ):  # fmt: skip
        with pytest.raises(NoCandidateError):
            await call


async def test_promote_makes_the_candidate_the_active_version_at_100(a):
    await candidate_at(a, "shadow", 25)
    result = await a.publisher.promote(await decide(a, "POST", "/candidate/promote"), ADMIN)
    assert (result.version, result.mode, result.rollout_percent, result.state) == (
        2, "enforce", 100, "active"
    )  # fmt: skip
    assert await state(a) == LifecycleState(active=2, candidate=None)
    assert await a.policies.scoped(issue_scope(ALPHA)).get_active_version(ALPHA) == 2
    event = a.lifecycle._events[-1]
    assert (event.action, event.from_version, event.becomes_active) == ("promote", 1, True)
    assert a.bus.published[-1].action == "promote"


async def test_abandon_drops_the_candidate_and_keeps_the_version_stored(a):
    await candidate_at(a)
    version = await a.publisher.abandon(await decide(a, "POST", "/candidate/abandon"), ADMIN)
    assert version == 2 and await state(a) == LifecycleState(active=1, candidate=None)
    stored = await a.lifecycle.scoped(issue_scope(ALPHA)).versions(ALPHA)
    assert [v.version for v in stored] == [1, 2]  # immutable: still there
    await save(a, bundle(ALPHA, rules=[rule("v3", gps=("output",))]), if_match="*")
    assert (await publish(a, "shadow", 5)).version == 3  # numbers are never reused


# ---------------------------------------------------------------------------- rollback


async def test_rollback_makes_an_earlier_version_active_and_abandons_the_candidate(a):
    await candidate_at(a)
    await a.publisher.promote(await decide(a, "POST", "/candidate/promote"), ADMIN)  # v2 active
    await save(a, bundle(ALPHA, rules=[rule("v3", gps=("output",))]), if_match="*")
    await publish(a, "shadow", 10)  # v3 candidate
    d = await decide(a, "POST", "/versions/{v}/rollback")
    result = await a.publisher.rollback(d, ADMIN, 1)
    assert (result.version, result.state) == (1, "active")
    assert await state(a) == LifecycleState(active=1, candidate=None)
    event = a.lifecycle._events[-1]
    assert (event.action, event.version, event.from_version, event.abandoned_candidate) == (
        "rollback", 1, 2, 3
    )  # fmt: skip
    assert a.bus.published[-1].action == "rollback"
    assert await a.policies.scoped(issue_scope(ALPHA)).get_active_version(ALPHA) == 1


async def test_rollback_refuses_the_active_the_unknown_and_the_candidate(a):
    await candidate_at(a)
    d = await decide(a, "POST", "/versions/{v}/rollback")
    with pytest.raises(AlreadyActiveError):
        await a.publisher.rollback(d, ADMIN, 1)
    with pytest.raises(VersionNotFoundError):
        await a.publisher.rollback(d, ADMIN, 99)
    with pytest.raises(DraftInvalidError):
        await a.publisher.rollback(d, ADMIN, 2)  # the candidate: promote it instead
    assert (await state(a)).candidate.version == 2  # nothing moved


async def test_rollback_only_goes_to_a_version_that_has_been_active(a):
    """The probe: shadow-publish an ungated rule, abandon, roll back to it.
    It never passed the enforce gates, so the rollback is refused and nothing moves."""
    await first_active(a)
    await save(a, bundle(ALPHA, rules=[rule("ungated", gps=("output",))]), if_match="*")
    await publish(a, "shadow", 1)  # v2, a candidate: no gate for shadow
    await a.publisher.abandon(await decide(a, "POST", "/candidate/abandon"), ADMIN)
    d = await decide(a, "POST", "/versions/{v}/rollback")
    with pytest.raises(NotPreviouslyActiveError):
        await a.publisher.rollback(d, ADMIN, 2)
    assert await state(a) == LifecycleState(active=1, candidate=None)
    assert a.lifecycle._events[-1].action == "abandon"  # no rollback event
    # a version that was active (promoted, then replaced) can be rolled back to
    await save(a, bundle(ALPHA, rules=[rule("shadowed", gps=("output",), mode="shadow")]),
               if_match="*")  # fmt: skip
    await publish(a)  # v3
    await a.publisher.promote(await decide(a, "POST", "/candidate/promote"), ADMIN)
    assert (await a.publisher.rollback(d, ADMIN, 1)).state == "active"
    assert (await a.publisher.rollback(d, ADMIN, 3)).version == 3  # was active once
    with pytest.raises(NotPreviouslyActiveError):
        await a.publisher.rollback(d, ADMIN, 2)


# ---------------------------------------------------------------------------- versions


async def test_the_versions_list_shows_status_mode_actor_note_and_diff(a):
    await save(a)
    await publish(a, note="the first")
    await save(a, bundle(ALPHA, rules=[rule("v2", gps=("output",))]), if_match="*")
    other = who(Role.GUARDRAIL_ADMIN, subject="bob", issuer="https://i/")
    await publish(a, "shadow", 20, "trying v2", principal=other)
    views = await a.publisher.versions(
        await decide(a, "GET", "/versions", who(Role.VIEWER, issuer="https://i/"))
    )
    assert [(v.version, v.status) for v in views] == [(1, "active"), (2, "candidate")]
    assert (views[0].published_mode, views[0].published_rollout_percent, views[0].note) == (
        "enforce",
        100,
        "the first",
    )
    assert (views[1].published_mode, views[1].published_rollout_percent) == ("shadow", 20)
    assert (views[0].current_mode, views[0].current_rollout_percent) == ("enforce", 100)
    assert (views[1].current_mode, views[1].current_rollout_percent) == ("shadow", 20)
    assert views[1].actor == "https://i/#bob" and views[1].note == "trying v2" and views[1].diff
    assert all(v.bundle_hash.startswith("sha256:") for v in views)


async def test_versions_show_the_current_status_apart_from_the_publish_time_mode(a):
    """A promoted version was published in shadow at 20% and is now enforcing at 100."""
    await first_active(a)
    await save(a, bundle(ALPHA, rules=[rule("v2", gps=("output",), mode="shadow")]), if_match="*")
    await publish(a, "shadow", 20)
    await a.publisher.promote(await decide(a, "POST", "/candidate/promote"), ADMIN)
    views = await a.publisher.versions(
        await decide(a, "GET", "/versions", who(Role.VIEWER, issuer="https://i/"))
    )
    by = {v.version: v for v in views}
    assert (by[2].status, by[2].current_mode, by[2].current_rollout_percent) == (
        "active",
        "enforce",
        100,
    )
    assert (by[2].published_mode, by[2].published_rollout_percent) == ("shadow", 20)
    assert (by[1].status, by[1].current_mode, by[1].current_rollout_percent) == (
        "inactive",
        None,
        None,
    )


# ---------------------------------------------------------------------------- approval (M5-02)


@pytest.mark.parametrize("tier", ["regulated", "dedicated"])
async def test_enforce_is_refused_for_a_tenant_that_needs_approval_but_shadow_is_not(a, tier):
    await first_active(a)  # standard tier at first
    a.tenants._profiles[ALPHA] = TenantProfile.build(
        TenantAttributes(tenant_id=ALPHA, tier=tier), "insurance", slug="alpha"
    )
    await save(a, bundle(ALPHA, rules=[rule("v2", gps=("output",))]), if_match="*")
    with pytest.raises(ApprovalRequiredError):
        await publish(a, "enforce", 100)
    assert (await publish(a, "shadow", 10)).state == "candidate"  # one person, R2
    with pytest.raises(ApprovalRequiredError):  # promotion enforces too
        await a.publisher.promote(await decide(a, "POST", "/candidate/promote"), ADMIN)


async def test_a_standard_tenant_that_opted_in_to_two_person_cannot_enforce_yet(a):
    a.tenants._profiles[ALPHA] = TenantProfile.build(
        TenantAttributes(tenant_id=ALPHA), "insurance", slug="alpha", require_two_person=True
    )
    await save(a)
    with pytest.raises(ApprovalRequiredError):
        await publish(a)


async def test_rollback_and_raising_the_percent_need_no_approval(a):
    await candidate_at(a, "shadow", 10)
    a.tenants._profiles[ALPHA] = TenantProfile.build(
        TenantAttributes(tenant_id=ALPHA, tier="regulated"), "insurance", slug="alpha"
    )
    await a.publisher.set_percent(
        await decide(a, "PATCH", "/candidate"), ADMIN, b'{"rollout_percent": 90}'
    )
    await a.publisher.abandon(await decide(a, "POST", "/candidate/abandon"), ADMIN)
    assert await state(a) == LifecycleState(active=1, candidate=None)


# ------------------------------------------------------------------ store and service guards


async def test_a_write_against_a_state_that_moved_is_refused_whole(a):
    await first_active(a)
    store = a.lifecycle.scoped(issue_scope(ALPHA))
    stale = LifecycleState(active=None, candidate=None)  # what a slow caller read earlier
    event = PublishEvent(a.now, "x", ALPHA, "abandon", 1)
    with pytest.raises(StateConflictError):
        await store.abandon(ALPHA, expected=stale, event=event)
    with pytest.raises(StateConflictError):
        await store.rollback(ALPHA, 1, expected=stale, event=event)
    assert len(a.lifecycle._events) == 1  # only the first publish was recorded


async def test_the_lifecycle_store_is_scoped_to_one_tenant(a):
    await first_active(a)
    beta = a.lifecycle.scoped(issue_scope(BETA))
    assert await beta.state(BETA) == LifecycleState()
    assert await beta.events(BETA) == [] and await beta.versions(BETA) == []
    with pytest.raises(ScopeMismatchError):
        await beta.state(ALPHA)
    with pytest.raises(ScopeMismatchError):
        await beta.events(ALPHA)
    mine = a.lifecycle.scoped(issue_scope(ALPHA))
    foreign = PublishEvent(a.now, "x", BETA, "abandon", 1)
    with pytest.raises(ScopeMismatchError):
        await mine.abandon(ALPHA, expected=await mine.state(ALPHA), event=foreign)


async def test_a_service_call_needs_the_decision_for_its_own_route(a):
    saved = await save(a)
    wrong = await decide(a, "PUT", "/draft")
    with pytest.raises(DecisionError):
        await a.publisher.publish(wrong, ADMIN, b'{"mode": "enforce"}', saved.etag)
    viewer = who(Role.VIEWER, issuer="https://i/")
    denied = await decide(a, "POST", "/draft/publish", viewer)
    with pytest.raises(DecisionError):
        await a.publisher.publish(denied, viewer, b'{"mode": "enforce"}', saved.etag)
    with pytest.raises(DecisionError):
        await a.publisher.promote(wrong, ADMIN)


async def test_an_operators_cross_tenant_publish_is_marked_in_the_event(a):
    operator = who(
        Role.GUARDRAIL_ADMIN, tenant=None, operator=True, subject="ops-1", issuer="https://p/"
    )
    d = await a.decide(operator, "PUT", BASE + "/draft", BETA)
    await a.service.put_draft(d, operator, json.dumps(bundle(BETA)).encode(), None)
    draft = await a.drafts.scoped(issue_scope(BETA)).get(BETA)
    d = await a.decide(operator, "POST", BASE + "/draft/publish", BETA)
    await a.publisher.publish(d, operator, b'{"mode": "enforce"}', draft.etag)
    event = a.lifecycle._events[-1]
    assert (event.tenant_id, event.cross_tenant, event.operator) == (BETA, True, True)
    assert event.actor == "https://p/#ops-1"


async def test_a_failing_bus_never_fails_or_undoes_the_change(a):
    class Broken:
        async def publish(self, event):
            raise ConnectionError("bus down")

    a.publisher._bus = Broken()
    await save(a)
    assert (await publish(a)).state == "active"
    assert (await state(a)).active == 1


async def test_outside_test_a_principal_without_an_issuer_cannot_publish(a):
    a.publisher._require_issuer = True
    saved = await save(a)
    bare = who(Role.GUARDRAIL_ADMIN)
    d = await decide(a, "POST", "/draft/publish", bare)
    with pytest.raises(DecisionError):
        await a.publisher.publish(d, bare, b'{"mode": "enforce"}', saved.etag)
