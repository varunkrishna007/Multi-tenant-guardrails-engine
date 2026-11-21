"""M5-02 two-person approval (R2), through the real authorizer, compiler and the in-memory stores:
the approval's tie to the draft hash, its 72 hours, who may not approve, the action matrix, the
notifications and the class A trail. Offline."""

import asyncio
import json
from datetime import timedelta

import pytest
from admin_fixtures import ALPHA, BETA, Admin, bundle, rule, who

from guardrail_engine.admin import DecisionError
from guardrail_engine.admin.approvals import (
    APPROVAL_TTL,
    ApprovalCancelledError,
    ApprovalExpiredError,
    ApprovalNotFoundError,
    ApprovalNotPendingError,
    ApprovalNotRequiredError,
    ApprovalPendingError,
    ApprovalStaleError,
    ApprovalUsedError,
    ApproverPublishError,
    InvalidApprovalCursorError,
    InvalidApprovalQueryError,
    OperatorApprovalError,
    SelfApprovalError,
    ServiceAccountApprovalError,
    ServiceAccountPublishError,
    ServiceAccountRequestError,
    approval_required,
)
from guardrail_engine.admin.lifecycle import (
    ApprovalRequiredError,
    CandidateExistsError,
    NoCandidateError,
)
from guardrail_engine.admin.service import DraftInvalidError, PreconditionRequiredError
from guardrail_engine.authz import Principal, Role
from guardrail_engine.gateway.sinks import ALERT_APPROVED_VERSION_CHANGE, AlertSeverity
from guardrail_engine.guard.tenants import TenantProfile
from guardrail_engine.policy.catalog import TenantAttributes
from guardrail_engine.store.port import ScopeMismatchError
from guardrail_engine.tenant_scope import issue_scope

BASE = "/v1/tenants/{tid}/guardrails"
ISS = "https://i/"
ALICE = who(Role.GUARDRAIL_ADMIN, issuer=ISS, subject="alice")
BOB = who(Role.GUARDRAIL_ADMIN, issuer=ISS, subject="bob")


@pytest.fixture
async def a():
    admin = Admin()
    yield admin
    await admin.aclose()


def needs_approval(a, tenant=ALPHA, *, tier="regulated", two_person=False):
    a.tenants._profiles[tenant] = TenantProfile.build(
        TenantAttributes(tenant_id=tenant, tier=tier), "insurance", slug="alpha",
        require_two_person=two_person,
    )  # fmt: skip


async def decide(a, method, route, principal=ALICE, tid=ALPHA):
    return await a.decide(principal, method, BASE + route, tid)


async def save(a, name="r", *, if_match=None, principal=ALICE):
    doc = bundle(ALPHA, rules=[rule(name, gps=("output",), mode="shadow")])
    d = await decide(a, "PUT", "/draft", principal)
    return await a.service.put_draft(d, principal, json.dumps(doc).encode(), if_match)


async def etag(a):
    return (await a.drafts.scoped(issue_scope(ALPHA)).get(ALPHA)).etag


async def request(a, principal=ALICE, action=None, if_match="current", tid=ALPHA):
    if if_match == "current":
        if_match = await etag(a)
    body = b"" if action is None else json.dumps({"action": action}).encode()
    d = await decide(a, "POST", "/draft/approvals", principal, tid)
    return await a.approvals.request(d, principal, body, if_match)


async def approve(a, approval, principal=BOB, tid=ALPHA):
    d = await decide(a, "POST", "/draft/approvals/{id}/approve", principal, tid)
    return await a.approvals.approve(d, principal, approval.id)


async def publish(a, mode="enforce", percent=100, approval=None, principal=ALICE, approval_id=None):
    draft = await a.drafts.scoped(issue_scope(ALPHA)).get(ALPHA)
    doc = {"mode": mode, "rollout_percent": percent}
    if approval is not None or approval_id is not None:
        doc["approval_id"] = approval_id or approval.id
    d = await decide(a, "POST", "/draft/publish", principal)
    return await a.publisher.publish(d, principal, json.dumps(doc).encode(), draft.etag)


async def promote(a, approval=None, principal=ALICE):
    body = b"" if approval is None else json.dumps({"approval_id": approval.id}).encode()
    d = await decide(a, "POST", "/candidate/promote", principal)
    return await a.publisher.promote(d, principal, body)


async def rollback(a, version, principal=ALICE):
    d = await decide(a, "POST", "/versions/{v}/rollback", principal)
    return await a.publisher.rollback(d, principal, version)


async def set_percent(a, percent, principal=ALICE):
    d = await decide(a, "PATCH", "/candidate", principal)
    return await a.publisher.set_percent(
        d, principal, json.dumps({"rollout_percent": percent}).encode()
    )


async def events(a):
    return await a.approval_store.scoped(issue_scope(ALPHA)).events(ALPHA)


async def row(a, approval):
    return await a.approval_store.scoped(issue_scope(ALPHA)).get(ALPHA, approval.id)


async def approved_for_publish(a):
    approval = await request(a)
    return await approve(a, approval)


async def regulated_with_active(a):
    """ALPHA, standard until version 1 is active, then regulated, with a fresh draft."""
    await save(a)
    await publish(a)
    needs_approval(a)
    await save(a, "r2", if_match="*")


# ---------------------------------------------------------------------------- the happy path


async def test_an_approved_draft_publishes_once_and_the_trail_names_each_step(a):
    needs_approval(a)
    await save(a)
    requested = await request(a)
    assert (requested.status, requested.action, requested.requested_by) == (
        "pending", "publish", "https://i/#alice"
    )  # fmt: skip
    assert requested.draft_hash == (await etag(a)).strip('"') and requested.version is None
    approved = await approve(a, requested)
    assert (approved.status, approved.approved_by) == ("approved", "https://i/#bob")

    result = await publish(a, approval=approved)  # the first publish: enforce at 100%
    assert (result.version, result.state) == (1, "active")

    assert (await row(a, approved)).status == "consumed"
    trail = await events(a)
    assert [(e.action, e.actor) for e in trail] == [
        ("requested", "https://i/#alice"),
        ("approved", "https://i/#bob"),
        ("consumed", "https://i/#alice"),
    ]  # fmt: skip
    assert {e.approval_id for e in trail} == {requested.id}
    (published,) = a.lifecycle._events
    assert f"two-person approval {requested.id}" in published.note


async def test_an_approval_is_single_use(a):
    needs_approval(a)
    await save(a)
    approval = await approved_for_publish(a)
    await publish(a, approval=approval)
    with pytest.raises(ApprovalUsedError):  # the same draft, the same approval
        await publish(a, approval=approval)
    assert [e.action for e in await events(a)].count("consumed") == 1


async def test_a_publish_that_fails_does_not_spend_the_approval(a, monkeypatch):
    from guardrail_engine.admin.lifecycle import StateConflictError, _ScopedMemoryLifecycle

    needs_approval(a)
    await save(a)
    approval = await approved_for_publish(a)

    async def lost_the_race(self, *args, **kwargs):
        raise StateConflictError()

    with monkeypatch.context() as m:
        m.setattr(_ScopedMemoryLifecycle, "_publish", lost_the_race)
        with pytest.raises(StateConflictError):
            await publish(a, approval=approval)
    assert (await row(a, approval)).status == "approved"
    assert "consumed" not in [e.action for e in await events(a)]
    assert (await publish(a, approval=approval)).version == 1  # still good


async def test_exactly_one_of_two_concurrent_enforce_publishes_uses_the_approval(a):
    await regulated_with_active(a)
    approval = await approved_for_publish(a)
    results = await asyncio.gather(
        publish(a, approval=approval), publish(a, approval=approval), return_exceptions=True
    )
    assert sum(not isinstance(r, Exception) for r in results) == 1
    (error,) = (r for r in results if isinstance(r, Exception))
    assert isinstance(error, ApprovalUsedError | CandidateExistsError)  # whichever it met first
    assert [e.action for e in await events(a)].count("consumed") == 1


# ---------------------------------------------------------------------------- refusals


async def test_enforcing_without_an_approval_is_refused_with_its_own_code(a):
    needs_approval(a)
    await save(a)
    with pytest.raises(ApprovalRequiredError):
        await publish(a)
    with pytest.raises(ApprovalNotFoundError):
        await publish(a, approval_id="apr_" + "0" * 24)


async def test_a_request_nobody_approved_is_pending_and_cannot_be_used(a):
    needs_approval(a)
    await save(a)
    approval = await request(a)
    with pytest.raises(ApprovalPendingError):
        await publish(a, approval=approval)
    assert (await row(a, approval)).status == "pending"


async def test_a_draft_edit_cancels_the_approval_and_audits_it_with_the_editor(a):
    needs_approval(a)
    await save(a)
    approval = await approved_for_publish(a)
    await save(a, "other", if_match="*", principal=BOB)  # any edit, by anyone
    cancelled = await row(a, approval)
    assert (cancelled.status, cancelled.close_reason) == ("cancelled", "draft edited")
    last = (await events(a))[-1]
    assert (last.action, last.actor, last.approval_id) == (
        "cancelled",
        "https://i/#bob",
        approval.id,
    )
    with pytest.raises(ApprovalCancelledError):
        await publish(a, approval=approval)


async def test_an_edit_that_only_touches_other_content_cancels_every_open_publish_approval(a):
    needs_approval(a)
    await save(a)
    pending = await request(a)
    approved = await approved_for_publish(a)
    await save(a, "other", if_match="*")
    assert {(await row(a, x)).status for x in (pending, approved)} == {"cancelled"}


async def test_an_approval_is_stale_against_the_draft_hash_even_if_its_cancellation_never_ran(a):
    needs_approval(a)
    await save(a)
    approval = await approved_for_publish(a)
    a.service._on_change = None  # the hook is housekeeping: the check at use is what protects
    await save(a, "other", if_match="*")
    assert (await row(a, approval)).status == "approved"
    with pytest.raises(ApprovalStaleError):
        await publish(a, approval=approval)
    assert await a.lifecycle.scoped(issue_scope(ALPHA)).versions(ALPHA) == []


async def test_editing_the_draft_back_does_not_revive_a_cancelled_approval(a):
    needs_approval(a)
    await save(a)
    approval = await approved_for_publish(a)
    await save(a, "other", if_match="*")
    await save(a, "r", if_match="*")  # the same content as when it was approved
    with pytest.raises(ApprovalCancelledError):
        await publish(a, approval=approval)


async def test_an_approval_for_a_promotion_is_not_one_for_a_publish(a):
    await regulated_with_active(a)
    await publish(a, "shadow", 10)
    promotion = await approve(a, await request(a, action="promote"))
    await a.publisher.abandon(await decide(a, "POST", "/candidate/abandon"), ALICE)
    with pytest.raises(ApprovalStaleError):
        await publish(a, approval=promotion)


# ---------------------------------------------------------------------------- 72 hours


async def test_an_approval_expires_72_hours_after_it_was_approved(a):
    needs_approval(a)
    await save(a)
    approval = await request(a)
    a.now += timedelta(hours=50)
    approved = await approve(a, approval)
    assert approved.expires_at == a.now + APPROVAL_TTL
    a.now += APPROVAL_TTL - timedelta(seconds=1)
    await publish(a, approval=approved)  # still in time


async def test_an_expired_approval_is_refused_and_the_expiry_is_audited_at_use(a):
    needs_approval(a)
    await save(a)
    approval = await approved_for_publish(a)
    a.now += APPROVAL_TTL
    with pytest.raises(ApprovalExpiredError):
        await publish(a, approval=approval, principal=BOB)
    assert (await row(a, approval)).status == "expired"
    last = (await events(a))[-1]
    assert (last.action, last.actor) == ("expired", "https://i/#bob")
    assert "when used" in last.detail
    assert await a.lifecycle.scoped(issue_scope(ALPHA)).versions(ALPHA) == []
    with pytest.raises(ApprovalExpiredError):  # and it stays expired
        await publish(a, approval=approval)
    assert [e.action for e in await events(a)].count("expired") == 1


async def test_a_request_nobody_approves_lapses_72_hours_after_it_was_made(a):
    needs_approval(a)
    await save(a)
    approval = await request(a)
    a.now += APPROVAL_TTL
    with pytest.raises(ApprovalExpiredError):
        await approve(a, approval)
    assert (await row(a, approval)).status == "expired"
    assert (await events(a))[-1].action == "expired"


# ---------------------------------------------------------------------------- who may approve


async def test_self_approval_is_rejected(a):
    needs_approval(a)
    await save(a)
    approval = await request(a)
    with pytest.raises(SelfApprovalError):
        await approve(a, approval, principal=ALICE)
    assert (await row(a, approval)).status == "pending"
    assert [e.action for e in await events(a)] == ["requested"]


async def test_the_same_subject_from_another_issuer_is_another_actor(a):
    needs_approval(a)
    await save(a)
    approval = await request(a)
    other = who(Role.GUARDRAIL_ADMIN, issuer="https://other-idp/", subject="alice")
    assert (await approve(a, approval, principal=other)).approved_by == "https://other-idp/#alice"


async def test_a_service_account_cannot_approve(a):
    needs_approval(a)
    await save(a)
    approval = await request(a)
    robot = who(Role.GUARDRAIL_ADMIN, issuer=ISS, subject="ci-bot")
    robot = type(robot)(
        robot.subject, robot.tenant_id, robot.roles, False, robot.issuer, service_account=True
    )
    with pytest.raises(ServiceAccountApprovalError):
        await approve(a, approval, principal=robot)
    assert (await row(a, approval)).status == "pending"


@pytest.mark.parametrize("home", [ALPHA, BETA, None])
async def test_a_platform_operator_cannot_approve_even_across_tenants(a, home):
    needs_approval(a)
    await save(a)
    approval = await request(a)
    operator = who(Role.GUARDRAIL_ADMIN, tenant=home, operator=True, issuer=ISS, subject="ops")
    with pytest.raises(OperatorApprovalError):
        await approve(a, approval, principal=operator)
    assert (await row(a, approval)).status == "pending"


async def test_only_a_pending_approval_can_be_approved(a):
    needs_approval(a)
    await save(a)
    approval = await approved_for_publish(a)
    with pytest.raises(ApprovalNotPendingError):
        await approve(a, approval, principal=who(Role.GUARDRAIL_ADMIN, issuer=ISS, subject="carol"))


async def test_a_tenant_cannot_use_or_approve_another_tenants_approval(a):
    needs_approval(a)
    needs_approval(a, BETA, tier="regulated")
    await save(a)
    approval = await request(a)
    carol = who(Role.GUARDRAIL_ADMIN, tenant=BETA, issuer=ISS, subject="carol")
    d = await a.decide(carol, "POST", BASE + "/draft/approvals/{id}/approve", BETA)
    with pytest.raises(ApprovalNotFoundError):
        await a.approvals.approve(d, carol, approval.id)
    with pytest.raises(ScopeMismatchError):
        await a.approval_store.scoped(issue_scope(BETA)).get(ALPHA, approval.id)


async def test_an_approval_decision_for_another_endpoint_is_refused(a):
    needs_approval(a)
    await save(a)
    d = await decide(a, "POST", "/draft/publish")
    with pytest.raises(DecisionError):
        await a.approvals.request(d, ALICE, b"", await etag(a))


# ---------------------------------------------------------------------------- the R2 matrix


@pytest.mark.parametrize(
    ("tier", "two_person", "expected"),
    [
        ("standard", False, False),
        ("standard", True, True),  # the opt-in behaves as the regulated tier does
        ("regulated", False, True),
        ("regulated", True, True),
        ("dedicated", False, True),
    ],
)
async def test_which_tenants_need_a_second_person_to_enforce(a, tier, two_person, expected):
    needs_approval(a, tier=tier, two_person=two_person)
    assert approval_required(await a.tenants.get(ALPHA)) is expected
    await save(a)
    if expected:
        with pytest.raises(ApprovalRequiredError):
            await publish(a)
    else:
        assert (await publish(a)).state == "active"  # one person
        with pytest.raises(ApprovalNotRequiredError):
            await request(a)


@pytest.mark.parametrize("tier", ["regulated", "standard"])
async def test_a_shadow_publish_needs_one_person_in_every_tier(a, tier):
    await save(a)
    await publish(a)
    needs_approval(a, tier=tier, two_person=tier == "standard")
    await save(a, "r2", if_match="*")
    assert (await publish(a, "shadow", 10)).state == "candidate"
    assert [e.action for e in await events(a)] == []  # nothing asked, nothing used


async def test_promoting_a_shadow_candidate_to_enforce_needs_an_approval_for_the_candidate(a):
    await regulated_with_active(a)
    await publish(a, "shadow", 10)
    with pytest.raises(ApprovalRequiredError):
        await promote(a)
    promotion = await request(a, action="promote")
    assert (promotion.action, promotion.version) == ("promote", 2)
    with pytest.raises(ApprovalPendingError):
        await promote(a, promotion)
    await approve(a, promotion)
    result = await promote(a, promotion)
    assert (result.version, result.state) == (2, "active")
    assert (await row(a, promotion)).status == "consumed"
    with pytest.raises(NoCandidateError):
        await promote(a, promotion)


async def test_a_promotion_approval_follows_its_candidate_not_the_draft(a):
    await regulated_with_active(a)
    await publish(a, "shadow", 10)
    promotion = await approve(a, await request(a, action="promote"))
    await save(a, "edited", if_match="*")  # the draft moves on: the candidate's approval stays
    assert (await row(a, promotion)).status == "approved"
    assert (await promote(a, promotion)).state == "active"


async def test_a_promotion_approval_for_a_replaced_candidate_is_stale(a):
    await regulated_with_active(a)
    await publish(a, "shadow", 10)
    promotion = await approve(a, await request(a, action="promote"))
    await a.publisher.abandon(await decide(a, "POST", "/candidate/abandon"), ALICE)
    await publish(a, "shadow", 10)  # candidate v3 now
    with pytest.raises(ApprovalStaleError):
        await promote(a, promotion)


async def test_asking_to_promote_needs_a_candidate(a):
    await regulated_with_active(a)
    with pytest.raises(NoCandidateError):
        await request(a, action="promote")


async def test_rollback_needs_no_approval_and_tells_the_other_admins(a):
    await regulated_with_active(a)
    approval = await approved_for_publish(a)
    await publish(a, approval=approval)  # v2 candidate (enforce at 100%)
    await promote(a)  # an approved enforce candidate: no second approver
    a.alerts.alerts.clear()
    result = await rollback(a, 1, principal=BOB)
    assert result.version == 1 and result.state == "active"
    (alert,) = a.alerts.alerts
    assert (alert.kind, alert.severity, alert.tenant_id, alert.reason) == (
        ALERT_APPROVED_VERSION_CHANGE, AlertSeverity.WARNING, ALPHA, "rollback"
    )  # fmt: skip
    assert "https://i/#bob" in alert.message and "v1" in alert.message
    notified = [e for e in await events(a) if e.action == "notified"]
    assert [(e.actor, e.version) for e in notified][-1] == ("https://i/#bob", 1)
    assert "alert sent" in notified[-1].detail
    assert a.lifecycle._events[-1].action == "rollback"  # and the lifecycle event, class A


async def test_a_rollback_on_a_standard_tenant_tells_nobody(a):
    await save(a)
    await publish(a)
    await save(a, "r2", if_match="*")
    await publish(a, "shadow", 10)
    await promote(a)
    await rollback(a, 1)
    assert a.alerts.alerts == [] and await events(a) == []


async def test_raising_the_share_of_an_approved_candidate_needs_no_approver_but_is_told(a):
    await regulated_with_active(a)
    approval = await approved_for_publish(a)
    await publish(a, "enforce", 10, approval=approval)
    a.alerts.alerts.clear()
    await set_percent(a, 50, principal=BOB)
    (alert,) = a.alerts.alerts
    assert (alert.kind, alert.reason, alert.tenant_id) == (
        ALERT_APPROVED_VERSION_CHANGE, "set_percent", ALPHA
    )  # fmt: skip
    assert "10% to 50%" in alert.message
    assert [e.action for e in await events(a)][-1] == "notified"
    await set_percent(a, 20)  # lowering is not told
    assert len(a.alerts.alerts) == 1


async def test_raising_a_shadow_candidates_share_is_not_an_enforce_change(a):
    await regulated_with_active(a)
    await publish(a, "shadow", 10)
    await set_percent(a, 90)
    assert a.alerts.alerts == []


async def test_a_notification_that_fails_never_undoes_the_change(a):
    await regulated_with_active(a)
    approval = await approved_for_publish(a)
    await publish(a, "enforce", 10, approval=approval)

    class Down:
        def emit(self, alert):
            raise ConnectionError("sink down")

    a.approvals._alerts = Down()
    assert (await set_percent(a, 60)).rollout_percent == 60
    last = (await events(a))[-1]
    assert (last.action, "alert not sent" in last.detail) == ("notified", True)


# ---------------------------------------------------------------------------- the request


async def test_a_request_for_a_publish_names_the_draft_it_saw(a):
    needs_approval(a)
    await save(a)
    with pytest.raises(PreconditionRequiredError):
        await request(a, if_match=None)
    current = await etag(a)
    await save(a, "other", if_match="*")
    from guardrail_engine.admin import DraftConflictError

    with pytest.raises(DraftConflictError):
        await request(a, if_match=current)


@pytest.mark.parametrize(
    "body",
    [b"[]", b'{"action": "rollback"}', b'{"action": 5}', b'{"extra": 1}', b"{"],
)
async def test_a_malformed_request_is_a_422(a, body):
    needs_approval(a)
    await save(a)
    d = await decide(a, "POST", "/draft/approvals")
    with pytest.raises(DraftInvalidError):
        await a.approvals.request(d, ALICE, body, await etag(a))


@pytest.mark.parametrize("bad", ["", "apr_xyz", "x" * 40, 5, ["apr_" + "0" * 24]])
async def test_a_malformed_approval_id_on_publish_is_a_422(a, bad):
    needs_approval(a)
    await save(a)
    draft = await a.drafts.scoped(issue_scope(ALPHA)).get(ALPHA)
    body = json.dumps({"mode": "enforce", "approval_id": bad}).encode()
    d = await decide(a, "POST", "/draft/publish")
    with pytest.raises(DraftInvalidError):
        await a.publisher.publish(d, ALICE, body, draft.etag)


async def test_a_promotion_with_an_unknown_field_is_a_422(a):
    await regulated_with_active(a)
    await publish(a, "shadow", 10)
    d = await decide(a, "POST", "/candidate/promote")
    with pytest.raises(DraftInvalidError):
        await a.publisher.promote(d, ALICE, b'{"nope": 1}')


async def test_without_an_approval_service_enforcing_stays_refused(a):
    needs_approval(a)
    await save(a)
    a.publisher._approvals = None
    approval = await approved_for_publish(a)
    with pytest.raises(ApprovalRequiredError):
        await publish(a, approval=approval)


async def test_an_audit_write_that_fails_leaves_no_request(a):
    needs_approval(a)
    await save(a)
    a.approval_store.fail_events = True
    with pytest.raises(ConnectionError):
        await request(a)
    a.approval_store.fail_events = False
    assert await events(a) == [] and a.approval_store._rows == {}


async def test_approving_a_request_for_a_draft_that_has_changed_is_refused_and_cancels_it(a):
    needs_approval(a)
    await save(a)
    approval = await request(a)
    a.service._on_change = None  # as if the cancellation on edit had not run
    await save(a, "other", if_match="*")
    with pytest.raises(ApprovalStaleError):
        await approve(a, approval)
    assert (await row(a, approval)).status == "cancelled"
    assert [e.action for e in await events(a)] == ["requested", "cancelled"]


async def test_approving_a_promotion_whose_candidate_is_gone_is_refused(a):
    await regulated_with_active(a)
    await publish(a, "shadow", 10)
    promotion = await request(a, action="promote")
    await a.publisher.abandon(await decide(a, "POST", "/candidate/abandon"), ALICE)
    with pytest.raises(ApprovalStaleError):
        await approve(a, promotion)
    assert (await row(a, promotion)).status == "cancelled"


# ---------------------------------------------------------------------------- two humans

ROBOT = Principal("ci-bot", ALPHA, frozenset({Role.GUARDRAIL_ADMIN}), False, ISS, True)


async def test_a_service_account_cannot_request_an_approval(a):
    needs_approval(a)
    await save(a)
    with pytest.raises(ServiceAccountRequestError):
        await request(a, principal=ROBOT)
    with pytest.raises(ServiceAccountRequestError):
        await request(a, principal=ROBOT, action="promote")
    assert await events(a) == [] and a.approval_store._rows == {}  # nothing was recorded


async def test_the_probe_fails_a_service_account_requests_and_one_human_cannot_go_on(a):
    """The probe: ci-bot requests, alice approves, alice publishes. It now stops at the
    request, so one human plus a machine can't make "two people"."""
    needs_approval(a)
    await save(a)
    with pytest.raises(ServiceAccountRequestError):
        await request(a, principal=ROBOT)
    assert a.lifecycle._events == []  # and nothing was published


async def test_the_approver_cannot_publish_with_their_own_approval(a):
    needs_approval(a)
    await save(a)
    approval = await approved_for_publish(a)  # alice asked, bob approved
    with pytest.raises(ApproverPublishError):
        await publish(a, approval=approval, principal=BOB)
    assert (await row(a, approval)).status == "approved"  # not spent
    assert a.lifecycle._events == [] and "consumed" not in [e.action for e in await events(a)]


async def test_a_service_account_cannot_publish_with_an_approval(a):
    needs_approval(a)
    await save(a)
    approval = await approved_for_publish(a)
    with pytest.raises(ServiceAccountPublishError):
        await publish(a, approval=approval, principal=ROBOT)
    assert (await row(a, approval)).status == "approved"
    assert (await publish(a, approval=approval)).version == 1  # the requester still can


async def test_the_requester_publishes_what_a_different_human_approved(a):
    """The allowed path: alice requests, bob approves, alice publishes."""
    needs_approval(a)
    await save(a)
    approval = await request(a, principal=ALICE)
    await approve(a, approval, principal=BOB)
    assert (await publish(a, approval=approval, principal=ALICE)).version == 1
    consumed = [e for e in await events(a) if e.action == "consumed"]
    assert [e.actor for e in consumed] == ["https://i/#alice"]


async def test_a_third_admin_may_publish_with_the_approval_too(a):
    needs_approval(a)
    await save(a)
    approval = await approved_for_publish(a)
    carol = who(Role.GUARDRAIL_ADMIN, issuer=ISS, subject="carol")
    assert (await publish(a, approval=approval, principal=carol)).version == 1


async def test_the_approver_and_a_service_account_cannot_promote_with_an_approval(a):
    await regulated_with_active(a)
    await publish(a, "shadow", 10)
    promotion = await approve(a, await request(a, action="promote"))
    with pytest.raises(ApproverPublishError):
        await promote(a, promotion, principal=BOB)
    with pytest.raises(ServiceAccountPublishError):
        await promote(a, promotion, principal=ROBOT)
    assert (await row(a, promotion)).status == "approved"
    assert (await promote(a, promotion, principal=ALICE)).state == "active"


# ----------------------------------------------------------------------------
async def standard_then_regulated_with_enforce_candidate(a, **needs):
    """v1 active and an enforce candidate v2 at 10%, both published while the tenant needed no
    approval; then the tenant becomes regulated (or opts in)."""
    await save(a)
    await publish(a)
    await save(a, "r2", if_match="*")
    await publish(a, "enforce", 10)
    needs_approval(a, **needs)


@pytest.mark.parametrize("needs", [{}, {"tier": "standard", "two_person": True}])
async def test_an_enforce_candidate_published_before_the_tenant_needed_approval_needs_one_now(
    a, needs
):
    await standard_then_regulated_with_enforce_candidate(a, **needs)
    with pytest.raises(ApprovalRequiredError):
        await promote(a)
    promotion = await approve(a, await request(a, action="promote"))
    assert (promotion.action, promotion.version) == ("promote", 2)
    result = await promote(a, promotion)
    assert (result.version, result.state) == (2, "active")
    assert (await row(a, promotion)).status == "consumed"
    note = a.lifecycle._events[-1].note
    assert f"two-person approval {promotion.id}" in note
    assert "published without an approval; promotion approved" in note


async def test_an_enforce_candidate_published_under_an_approval_promotes_with_that_evidence(a):
    await regulated_with_active(a)
    approval = await approved_for_publish(a)
    await publish(a, "enforce", 10, approval=approval)
    await promote(a)  # no approver: its publish consumed an approval
    promoted = a.lifecycle._events[-1]
    assert promoted.action == "promote"
    assert f"published under approval {approval.id}" in promoted.note


async def test_a_note_that_claims_an_approval_is_not_evidence(a):
    """The evidence is the approval trail, never the publisher's own words."""
    await save(a)
    await publish(a)
    await save(a, "r2", if_match="*")
    draft = await a.drafts.scoped(issue_scope(ALPHA)).get(ALPHA)
    doc = {"mode": "enforce", "rollout_percent": 10, "note": "two-person approval apr_" + "0" * 24}
    d = await decide(a, "POST", "/draft/publish")
    await a.publisher.publish(d, ALICE, json.dumps(doc).encode(), draft.etag)
    needs_approval(a)
    with pytest.raises(ApprovalRequiredError):
        await promote(a)


async def test_an_enforce_candidate_on_a_tenant_that_needs_no_approval_promotes_on_one_person(a):
    await save(a)
    await publish(a)
    await save(a, "r2", if_match="*")
    await publish(a, "enforce", 10)
    await promote(a)
    promoted = a.lifecycle._events[-1]
    assert "published without an approval; the tenant needs none" in promoted.note
    assert await events(a) == []  # nothing asked, nothing used


async def test_a_promotion_approval_for_an_enforce_candidate_is_single_use(a):
    await standard_then_regulated_with_enforce_candidate(a)
    promotion = await approve(a, await request(a, action="promote"))
    await promote(a, promotion)
    with pytest.raises(NoCandidateError):
        await promote(a, promotion)


# ---------------------------------------------------------------------------- the list


async def make_requests(a, n):
    out = []
    for _ in range(n):
        a.now += timedelta(minutes=1)
        out.append(await request(a))
    return out


async def listing(a, principal=None, **query):
    principal = principal or who(Role.VIEWER, issuer=ISS, subject="vera")
    d = await decide(a, "GET", "/draft/approvals", principal)
    return await a.approvals.list_approvals(d, **query)


async def test_the_list_pages_newest_first_with_a_cursor(a):
    needs_approval(a)
    await save(a)
    made = await make_requests(a, 5)
    first = await listing(a, limit="2")
    assert [x.id for x in first.items] == [made[4].id, made[3].id]
    assert first.next_cursor is not None
    second = await listing(a, limit="2", cursor=first.next_cursor)
    assert [x.id for x in second.items] == [made[2].id, made[1].id]
    last = await listing(a, limit="2", cursor=second.next_cursor)
    assert [x.id for x in last.items] == [made[0].id] and last.next_cursor is None
    whole = await listing(a)  # the default page holds all five
    assert [x.id for x in whole.items] == [m.id for m in reversed(made)]
    assert whole.next_cursor is None


async def test_the_list_pages_requests_made_in_the_same_instant_without_gaps(a):
    needs_approval(a)
    await save(a)
    made = [await request(a) for _ in range(4)]  # one clock reading for all
    seen, cursor = [], None
    while True:
        page = await listing(a, limit="1", cursor=cursor)
        seen += [x.id for x in page.items]
        cursor = page.next_cursor
        if cursor is None:
            break
    assert sorted(seen) == sorted(m.id for m in made) and len(set(seen)) == 4


async def test_the_list_shows_status_hash_requester_approver_and_expiry(a):
    needs_approval(a)
    await save(a)
    pending, granted = await make_requests(a, 2)
    await approve(a, granted)
    by_id = {x.id: x for x in (await listing(a)).items}
    assert by_id[pending.id].status == "pending" and by_id[pending.id].approved_by is None
    seen = by_id[granted.id]
    assert (seen.status, seen.requested_by, seen.approved_by) == (
        "approved", "https://i/#alice", "https://i/#bob"
    )  # fmt: skip
    assert seen.draft_hash == (await etag(a)).strip('"') and seen.expires_at > a.now


async def test_the_list_filters_by_status_and_shows_the_recent_past(a):
    needs_approval(a)
    await save(a)
    first, second = await make_requests(a, 2)
    await approve(a, first)
    await publish(a, approval=first)  # consumed
    await save(a, "other", if_match="*")  # cancels the second
    assert [x.status for x in (await listing(a, status="consumed")).items] == ["consumed"]
    assert [x.id for x in (await listing(a, status="cancelled")).items] == [second.id]
    assert (await listing(a, status="pending")).items == ()


async def test_the_list_is_the_tenants_own(a):
    needs_approval(a)
    await save(a)
    await make_requests(a, 2)
    beta_viewer = who(Role.VIEWER, tenant=BETA, issuer=ISS, subject="vera")
    d = await a.decide(beta_viewer, "GET", BASE + "/draft/approvals", BETA)
    assert (await a.approvals.list_approvals(d)).items == ()
    assert len((await listing(a)).items) == 2


@pytest.mark.parametrize(
    ("query", "field"),
    [
        ({"limit": "0"}, "limit"), ({"limit": "101"}, "limit"), ({"limit": "x"}, "limit"),
        ({"limit": "-1"}, "limit"), ({"status": "open"}, "status"),
    ],
)  # fmt: skip
async def test_a_bad_limit_or_status_is_refused(a, query, field):
    with pytest.raises(InvalidApprovalQueryError) as info:
        await listing(a, **query)
    assert info.value.field == field


@pytest.mark.parametrize("cursor", ["", "!!", "bm90LWE", "djE6Zm9v", "x" * 300])
async def test_a_cursor_this_api_did_not_issue_is_refused(a, cursor):
    with pytest.raises(InvalidApprovalCursorError):
        await listing(a, cursor=cursor)


async def test_the_list_decision_is_for_the_list_endpoint_only(a):
    d = await decide(a, "POST", "/draft/approvals")
    with pytest.raises(DecisionError):
        await a.approvals.list_approvals(d)
