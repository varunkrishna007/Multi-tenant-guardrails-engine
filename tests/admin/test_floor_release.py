"""M2-09 R5.1: a floor needs a passing M2-08 run and two different operators' approvals. Tenants
can't approve or block it; an unreleased floor can't be extended; the minimum only goes up."""

import json

import pytest
from admin_fixtures import ALPHA, CORPUS_HASH
from floor_fixtures import (
    FLOOR_V2,
    active_tenant,
    new_admin,
    operator,
    pdecide,
    release,
    report,
)

from guardrail_engine.admin import DraftInvalidError
from guardrail_engine.admin.floors import (
    URGENT_WINDOW,
    AlreadyReleasedError,
    Approval,
    InMemoryPlatformStore,
    ReleaseExistsError,
    ReleaseNotFoundError,
    SecondOperatorRequiredError,
    settle,
)
from guardrail_engine.admin.service import DecisionError
from guardrail_engine.policy.catalog import InMemoryCatalog
from guardrail_engine.policy.errors import ErrorCode


@pytest.fixture
async def a():
    admin = new_admin()
    yield admin
    await admin.aclose()


async def propose(a, rep=None, principal=None, urgent=False, version=2):
    p = principal or operator("op1")
    d = await pdecide(a, p, "POST", "/v1/platform/floors/{version}/release")
    body = json.dumps({"report": rep or report(), "security_urgent": urgent}).encode()
    return await a.floors.propose(d, p, version, body)


async def approve(a, principal, urgent=False, version=2):
    d = await pdecide(a, principal, "POST", "/v1/platform/floors/{version}/approve")
    digest = (await a.platform.release(version)).evidence["report_sha256"]
    body = {"security_urgent": urgent, "report_sha256": digest}
    return await a.floors.approve(d, principal, version, json.dumps(body).encode())


# ---------------------------------------------------------------------------- evidence


async def test_a_passing_live_report_is_proposed_and_the_proposer_is_the_first_approval(a):
    r = await propose(a)
    assert not r.released and [x.operator for x in r.approvals] == ["https://i/#op1"]
    assert r.floor_hash == FLOOR_V2.content_hash()
    assert r.evidence["gate"] == {"exit_code": 0, "passed": True}
    assert r.evidence["mode"] == "live" and r.evidence["corpus_sha256"] == CORPUS_HASH
    assert a.catalog.is_released(2) is False  # one approval is not a release
    events = await a.platform.events()
    assert [e.action for e in events] == ["release_proposed"]


@pytest.mark.parametrize(
    ("override", "word"),
    [
        ({"gate": {"exit_code": 1, "passed": False}}, "gate did not pass"),
        ({"gate": None}, "gate did not pass"),
        ({"mode": "fake"}, "not a live run"),
        ({"floor_version": 3}, "measured floor@3"),
        ({"floor_content_hash": "sha256:" + "0" * 64}, "content differs"),
        ({"corpus_sha256": "sha256:" + "1" * 64}, "different corpus"),
        ({"incomplete": [{"id": "x"}]}, "incomplete"),
        ({"excluded_cells": 2}, "incomplete"),
        ({"structure": {"violations": {"r1": ["a delimiter broke"]}}}, "defence broke"),
        ({"structure": None}, "defence broke"),
    ],
)  # fmt: skip
async def test_a_report_that_does_not_support_the_release_is_refused(a, override, word):
    with pytest.raises(DraftInvalidError) as refused:
        await propose(a, report(**override))
    assert all(e.code == "release.evidence" for e in refused.value.errors)
    assert word in " ".join(e.message for e in refused.value.errors)
    assert await a.platform.releases() == []


async def test_an_offline_report_is_accepted_only_when_the_engine_allows_it(a):
    with pytest.raises(DraftInvalidError):
        await propose(a, report(mode="fake"))
    a.floors._allow_offline = True  # an engine in environment test
    assert (await propose(a, report(mode="fake"))).evidence["mode"] == "fake"


async def test_a_missing_corpus_refuses_the_release_and_a_bad_body_is_refused(a):
    a.floors._corpus_sha256 = lambda: None
    with pytest.raises(DraftInvalidError):
        await propose(a)
    d = await pdecide(a, operator(), "POST", "/v1/platform/floors/{version}/release")
    for raw in (b"[]", b"{", b"{}", b'{"report": {}, "security_urgent": "yes"}',
                b'{"report": {}, "x": 1}'):  # fmt: skip
        with pytest.raises(DraftInvalidError):
            await a.floors.propose(d, operator(), 2, raw)
    with pytest.raises(ReleaseNotFoundError):  # a floor the catalog doesn't hold
        await a.floors.propose(d, operator(), 9, json.dumps({"report": report(9)}).encode())


async def test_a_floor_can_be_proposed_once(a):
    await propose(a)
    with pytest.raises(ReleaseExistsError):
        await propose(a, principal=operator("op3"))


# ---------------------------------------------------------------------------- two operators


async def test_two_different_operators_release_it_and_it_becomes_extendable(a):
    await active_tenant(a)
    assert a.catalog.is_released(2) is False
    await propose(a)
    with pytest.raises(SecondOperatorRequiredError):  # the proposer can't approve again
        await approve(a, operator("op1"))
    released = await approve(a, operator("op2"))
    assert released.released and released.released_at == a.now
    assert a.catalog.is_released(2) and a.catalog.is_released(1)
    assert [e.action for e in await a.platform.events()] == [
        "release_proposed", "release_approved", "released",
    ]  # fmt: skip
    with pytest.raises(AlreadyReleasedError):
        await approve(a, operator("op3"))
    assert any(p.action == "floor" for p in a.bus.published)  # replicas reload


async def test_an_unreleased_floor_cannot_be_extended_by_a_tenant_until_released(a):
    from admin_fixtures import bundle

    doc = bundle(ALPHA)
    doc["extends"] = ["platform/floor@2"]
    from guardrail_engine.policy.catalog import PlatformSettings
    from guardrail_engine.policy.compiler import PolicyCompiler

    profile = await a.tenants.get(ALPHA)
    compiler = PolicyCompiler(a.catalog, profile, PlatformSettings())
    errors = compiler.validate(doc, profile.attributes)
    assert [str(e.code) for e in errors] == [ErrorCode.FLOOR_NOT_RELEASED]
    assert "has not been released" in errors[0].message
    await release(a)
    assert compiler.validate(doc, profile.attributes) == []


async def test_tenant_principals_have_no_way_to_approve_or_block_a_release(a):
    """R5.1: the platform rows are the operators' alone (the authorizer); a decision a tenant
    could get is refused by the service as well."""
    from admin_fixtures import who

    from guardrail_engine.authz import Role

    tenant_admin = who(Role.GUARDRAIL_ADMIN, issuer="https://i/")
    for method, route in (
        ("POST", "/v1/platform/floors/{version}/release"),
        ("POST", "/v1/platform/floors/{version}/approve"),
        ("POST", "/v1/platform/floors/{version}/halt"),
        ("DELETE", "/v1/platform/floors/{version}/halt"),
        ("POST", "/v1/platform/floors/{version}/repin"),
        ("PUT", "/v1/platform/minimum-floor"),
    ):
        decision = await a.authorizer.authorize(tenant_admin, method, route)
        assert (decision.allowed, decision.reason) == (False, "not_platform_operator")
    denied = await a.authorizer.authorize(
        tenant_admin, "POST", "/v1/platform/floors/{version}/approve"
    )
    with pytest.raises(DecisionError):
        await a.floors.approve(denied, tenant_admin, 2, b"{}")
    with pytest.raises(DecisionError):  # a decision for another route is no decision for this
        other = await pdecide(a, operator(), "GET", "/v1/platform/floors")
        await a.floors.approve(other, operator(), 2, b"{}")
    assert await a.platform.releases() == []


# ---------------------------------------------------------------------------- urgent and halt


@pytest.mark.parametrize(
    ("urgent", "hours"),
    [((True, True), 6), ((True, False), 72), ((False, True), 72), ((False, False), 72)],
)
async def test_the_window_is_6_hours_only_when_both_approvers_said_urgent(a, urgent, hours):
    released = await release(a, urgent=urgent)
    assert released.security_urgent is (urgent == (True, True))
    assert released.window.total_seconds() == hours * 3600
    assert URGENT_WINDOW.total_seconds() == 6 * 3600


def test_settle_needs_two_different_operators():
    t = None
    one = (Approval("a", True, t),)
    assert settle(one) == (False, False)
    assert settle((*one, Approval("a", True, t))) == (False, False)  # the same operator twice
    assert settle((*one, Approval("b", True, t))) == (True, True)
    assert settle((*one, Approval("b", False, t))) == (True, False)


async def test_halt_and_resume_are_recorded(a):
    await release(a)
    op = operator("op3")
    d = await pdecide(a, op, "POST", "/v1/platform/floors/{version}/halt")
    await a.floors.halt(d, op, 2, halted=True)
    assert (await a.platform.release(2)).halted
    d = await pdecide(a, op, "DELETE", "/v1/platform/floors/{version}/halt")
    await a.floors.halt(d, op, 2, halted=False)
    assert not (await a.platform.release(2)).halted
    assert [e.action for e in (await a.platform.events())[-2:]] == ["halt", "resume"]
    d = await pdecide(a, op, "POST", "/v1/platform/floors/{version}/halt")
    with pytest.raises(ReleaseNotFoundError):
        await a.floors.halt(d, op, 7, halted=True)


# ---------------------------------------------------------------------------- the store and load


async def test_the_stored_state_is_applied_to_a_fresh_catalog_at_start(a):
    from guard_fixtures import make_catalog

    from guardrail_engine.admin.floors import FloorService

    await release(a)
    await a.platform.set_minimum(
        2, expected=None, by="x", at=a.now,
        event=__import__("guardrail_engine.admin.floors", fromlist=["PlatformEvent"]).PlatformEvent(
            a.now, "x", "raise_minimum", 2
        ),
    )  # fmt: skip
    fresh = make_catalog(extra_floors=(FLOOR_V2,))
    assert not fresh.is_released(2) or fresh.is_released(2)  # no release store yet
    fresh.set_released({1})  # what a start-up with a release store begins from
    service = FloorService(a.platform, fresh, corpus_sha256=lambda: CORPUS_HASH)
    await service.load()
    assert fresh.is_released(2) and fresh.minimum_floor_version() == 2
    assert isinstance(fresh, InMemoryCatalog)


async def test_the_baseline_is_released_without_a_record_and_a_floor_above_it_is_not(a):
    empty = InMemoryPlatformStore()
    from guardrail_engine.admin.floors import FloorService

    service = FloorService(empty, a.catalog)
    await service.load()
    assert a.catalog.is_released(1) and not a.catalog.is_released(2)


async def test_the_listing_shows_releases_the_minimum_and_unreleased_floors(a):
    await propose(a)
    op = operator()
    d = await pdecide(a, op, "GET", "/v1/platform/floors")
    listing = await a.floors.listing(d)
    assert listing["minimum_floor_version"] == 1 and listing["baseline"] == 1
    assert listing["unreleased_in_catalog"] == [2]
    assert listing["floors"][0]["released"] is False
    assert listing["floors"][0]["approvals"][0]["operator"] == "https://i/#op1"


# ---------------------------------------------------------------------------- named approvals


async def test_an_approval_names_the_report_it_approves(a):
    proposed = await propose(a)
    digest = proposed.evidence["report_sha256"]
    assert digest.startswith("sha256:") and len(digest) == 71
    q = operator("op2")
    d = await pdecide(a, q, "POST", "/v1/platform/floors/{version}/approve")
    for body in (b"{}", b'{"security_urgent": false}',
                 json.dumps({"report_sha256": "sha256:" + "0" * 64}).encode(),
                 json.dumps({"report_sha256": "nope"}).encode(),
                 json.dumps({"report_sha256": digest, "x": 1}).encode()):  # fmt: skip
        with pytest.raises(DraftInvalidError):
            await a.floors.approve(d, q, 2, body)
    assert (
        not (await a.platform.release(2)).released
        and len((await a.platform.release(2)).approvals) == 1
    )  # nothing was recorded for the refused ones
    released = await a.floors.approve(d, q, 2, json.dumps({"report_sha256": digest}).encode())
    assert released.released
    with pytest.raises(ReleaseNotFoundError):
        await a.floors.approve(d, q, 9, json.dumps({"report_sha256": digest}).encode())


async def test_a_different_report_for_the_same_floor_has_a_different_hash(a):
    first = await propose(a)
    other = new_admin()
    try:
        second = await propose(other, report(rows=173))
        assert first.evidence["report_sha256"] != second.evidence["report_sha256"]
    finally:
        await other.aclose()
