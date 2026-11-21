"""M5-02 on Postgres (040, 041, 042): the approval tables under forced RLS, the narrow status
updates, consumption in the publish's own transaction under the lifecycle lock, and the
append-only class A trail. Needs GUARDRAIL_TEST_PG_DSN; skipped without it."""

import asyncio
import json
import sys
from datetime import timedelta
from pathlib import Path

import asyncpg
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "admin"))  # admin_fixtures
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "guard"))  # guard_fixtures
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "policy"))  # policy_fixtures

from admin_fixtures import ALPHA, BETA, Admin, bundle, rule, who

from guardrail_engine.admin.approval_service import ApprovalService
from guardrail_engine.admin.approvals import (
    APPROVAL_TTL,
    ApprovalExpiredError,
    ApprovalPosition,
    ApprovalStaleError,
    ApprovalUse,
    ApprovalUsedError,
    ApproverPublishError,
    SelfApprovalError,
    ServiceAccountPublishError,
)
from guardrail_engine.admin.evidence import (
    NO_PRECISION_GATE,
    NO_REGRESSION_GATE,
    EvidenceGate,
)
from guardrail_engine.admin.lifecycle import (
    ApprovalRequiredError,
    Candidate,
    LifecycleState,
    PublishEvent,
    StateConflictError,
)
from guardrail_engine.admin.publish import PublishService
from guardrail_engine.authz import Role
from guardrail_engine.guard.tenants import TenantProfile
from guardrail_engine.policy.catalog import PlatformSettings, TenantAttributes
from guardrail_engine.policy.compiler import PolicyCompiler
from guardrail_engine.policy.document import parse_bundle
from guardrail_engine.store.adapters.approval_sql import LIFECYCLE_LOCK_SQL, consume
from guardrail_engine.store.adapters.postgres import (
    PostgresLifecycleStore,
    tenant_connection,
)
from guardrail_engine.store.adapters.postgres_approvals import PostgresApprovalStore
from guardrail_engine.tenant_scope import issue_scope

BASE = "/v1/tenants/{tid}/guardrails"
ISS = "https://i/"
ALICE = who(Role.GUARDRAIL_ADMIN, issuer=ISS, subject="alice")
BOB = who(Role.GUARDRAIL_ADMIN, issuer=ISS, subject="bob")
DENIED = (asyncpg.InsufficientPrivilegeError, asyncpg.exceptions.RestrictViolationError)


@pytest.fixture
async def a(app_pool):
    """The in-memory Admin fixture with the lifecycle and the approvals on Postgres."""
    admin = Admin()
    admin.pg = PostgresLifecycleStore(app_pool, catalog=admin.catalog)
    admin.pg_approvals = PostgresApprovalStore(app_pool)
    admin.approvals = ApprovalService(
        admin.pg_approvals, admin.drafts, admin.pg, admin.tenants,
        alerts=admin.alerts, clock=lambda: admin.now,
    )  # fmt: skip
    admin.service._on_change = admin.approvals
    admin.publisher = PublishService(
        admin.drafts, admin.pg, admin.tenants, admin.catalog, PlatformSettings(),
        gate=EvidenceGate(admin.golden_store, NO_PRECISION_GATE, NO_REGRESSION_GATE), bus=admin.bus,
        clock=lambda: admin.now, approvals=admin.approvals,
    )  # fmt: skip
    admin.tenants._profiles[ALPHA] = TenantProfile.build(
        TenantAttributes(tenant_id=ALPHA, tier="regulated"), "insurance", slug="alpha"
    )
    yield admin
    await admin.aclose()


def lifecycle(a, tenant=ALPHA):
    return a.pg.scoped(issue_scope(tenant))


def approvals(a, tenant=ALPHA):
    return a.pg_approvals.scoped(issue_scope(tenant))


async def decide(a, method, route, principal=ALICE, tid=ALPHA):
    return await a.decide(principal, method, BASE + route, tid)


async def save(a, name="r", *, if_match=None):
    doc = bundle(ALPHA, rules=[rule(name, gps=("output",), mode="shadow")])
    d = await decide(a, "PUT", "/draft")
    return await a.service.put_draft(d, ALICE, json.dumps(doc).encode(), if_match)


async def request(a, principal=ALICE, action=None):
    draft = await a.drafts.scoped(issue_scope(ALPHA)).get(ALPHA)
    body = b"" if action is None else json.dumps({"action": action}).encode()
    d = await decide(a, "POST", "/draft/approvals", principal)
    return await a.approvals.request(d, principal, body, draft.etag)


async def approve(a, approval, principal=BOB):
    d = await decide(a, "POST", "/draft/approvals/{id}/approve", principal)
    return await a.approvals.approve(d, principal, approval.id)


async def publish(a, mode="enforce", percent=100, approval=None, principal=ALICE):
    draft = await a.drafts.scoped(issue_scope(ALPHA)).get(ALPHA)
    doc = {"mode": mode, "rollout_percent": percent}
    if approval is not None:
        doc["approval_id"] = approval.id
    d = await decide(a, "POST", "/draft/publish", principal)
    return await a.publisher.publish(d, principal, json.dumps(doc).encode(), draft.etag)


async def first_active_then_regulated_draft(a):
    await save(a)
    a.tenants._profiles[ALPHA] = TenantProfile.build(
        TenantAttributes(tenant_id=ALPHA), "insurance", slug="alpha"
    )
    await publish(a)
    a.tenants._profiles[ALPHA] = TenantProfile.build(
        TenantAttributes(tenant_id=ALPHA, tier="regulated"), "insurance", slug="alpha"
    )
    await save(a, "r2", if_match="*")


# ---------------------------------------------------------------------------- the flow


async def test_the_whole_flow_runs_on_postgres_and_the_trail_is_append_only(a, app_pool):
    await save(a)
    requested = await request(a)
    approved = await approve(a, requested)
    assert (approved.status, approved.approved_by) == ("approved", "https://i/#bob")
    assert approved.expires_at == a.now + APPROVAL_TTL
    result = await publish(a, approval=approved)
    assert (result.version, result.state) == (1, "active")

    row = await approvals(a).get(ALPHA, requested.id)
    assert (row.status, row.consumed_by) == ("consumed", "https://i/#alice")
    trail = await approvals(a).events(ALPHA)
    assert [(e.action, e.actor) for e in trail] == [
        ("requested", "https://i/#alice"),
        ("approved", "https://i/#bob"),
        ("consumed", "https://i/#alice"),
    ]  # fmt: skip
    (published,) = await lifecycle(a).events(ALPHA)
    assert f"two-person approval {requested.id}" in published.note

    for statement in (
        "UPDATE tenant_approval_audit SET actor = 'x'",
        "DELETE FROM tenant_approval_audit",
        "TRUNCATE tenant_approval_audit",
        "DELETE FROM tenant_approvals",
        "TRUNCATE tenant_approvals",
    ):
        with pytest.raises(DENIED):
            await app_pool.execute(statement)


async def test_an_edit_cancels_and_the_cancellation_is_audited_on_postgres(a):
    await save(a)
    approval = await approve(a, await request(a))
    await save(a, "other", if_match="*")
    row = await approvals(a).get(ALPHA, approval.id)
    assert (row.status, row.close_reason) == ("cancelled", "draft edited")
    assert [e.action for e in await approvals(a).events(ALPHA)] == [
        "requested", "approved", "cancelled"
    ]  # fmt: skip
    from guardrail_engine.admin.approvals import ApprovalCancelledError

    with pytest.raises(ApprovalCancelledError):
        await publish(a, approval=approval)


async def test_the_72_hours_and_expiry_at_use_on_postgres(a):
    await save(a)
    approval = await approve(a, await request(a))
    a.now += APPROVAL_TTL
    with pytest.raises(ApprovalExpiredError):
        await publish(a, approval=approval)
    assert (await approvals(a).get(ALPHA, approval.id)).status == "expired"
    assert [e.action for e in await approvals(a).events(ALPHA)][-1] == "expired"
    assert await lifecycle(a).versions(ALPHA) == []


async def test_self_approval_is_refused_in_the_service_and_by_the_database(a, app_pool):
    await save(a)
    approval = await request(a)
    with pytest.raises(SelfApprovalError):
        await approve(a, approval, principal=ALICE)
    with pytest.raises(SelfApprovalError):  # the store checks too
        await approvals(a).approve(
            ALPHA, approval.id, approver=approval.requested_by, at=a.now,
            expires_at=a.now + APPROVAL_TTL, event=_event(a, approval),
        )  # fmt: skip
    async with tenant_connection(app_pool, issue_scope(ALPHA)) as conn:
        with pytest.raises(asyncpg.CheckViolationError):  # and the CHECK, past both
            await conn.execute(
                "UPDATE tenant_approvals SET status = 'approved', approved_by = requested_by, "
                "approved_at = now() WHERE id = $1",
                approval.id,
            )


def _event(a, approval):
    from guardrail_engine.admin.approvals import ApprovalEvent

    return ApprovalEvent(a.now, "https://i/#x", ALPHA, "approved", approval.id)


# ---------------------------------------------------------------------------- consumption


async def test_a_publish_that_fails_after_the_approval_is_spent_rolls_the_spending_back(a):
    await first_active_then_regulated_draft(a)
    approval = await approve(a, await request(a))
    draft = await a.drafts.scoped(issue_scope(ALPHA)).get(ALPHA)
    doc = json.loads(draft.document)
    doc["version"] = 2
    parsed = parse_bundle(doc)
    profile = await a.tenants.get(ALPHA)
    real_hash = (
        PolicyCompiler(a.catalog, profile, PlatformSettings())
        .compile(parsed, profile.attributes)
        .bundle_hash
    )
    bad = PublishEvent(
        a.now, "x", ALPHA, "publish", 2, mode="enforce", rollout_percent=100,
        bundle_hash=real_hash, draft_hash="not-a-hash",
    )  # fmt: skip
    use = ApprovalUse(approval.id, "publish", approval.draft_hash, None, "https://i/#alice", a.now)
    state = await lifecycle(a).state(ALPHA)
    with pytest.raises(asyncpg.CheckViolationError):  # the audit row's CHECK, after the consume
        await lifecycle(a).publish(
            ALPHA, parsed, real_hash, candidate=Candidate(2, "enforce", 100, a.now, "x"),
            expected=state, event=bad, approval=use,
        )  # fmt: skip
    assert (await approvals(a).get(ALPHA, approval.id)).status == "approved"
    assert "consumed" not in [e.action for e in await approvals(a).events(ALPHA)]
    assert (await publish(a, approval=approval)).state == "candidate"  # and it is still good


async def test_two_transactions_consuming_one_approval_let_exactly_one_through(a, app_pool):
    await save(a)
    approval = await approve(a, await request(a))
    use = ApprovalUse(approval.id, "publish", approval.draft_hash, None, "https://i/#alice", a.now)

    async def spend():
        async with tenant_connection(app_pool, issue_scope(ALPHA)) as conn:
            await conn.execute(LIFECYCLE_LOCK_SQL, "lifecycle:" + ALPHA)  # as every write does
            await consume(conn, ALPHA, use)

    results = await asyncio.gather(*(spend() for _ in range(6)), return_exceptions=True)
    assert sum(r is None for r in results) == 1
    assert all(isinstance(r, ApprovalUsedError) for r in results if r is not None)
    assert [e.action for e in await approvals(a).events(ALPHA)].count("consumed") == 1


async def test_two_publishes_at_once_use_the_approval_once_and_store_one_version(a):
    await first_active_then_regulated_draft(a)
    approval = await approve(a, await request(a))
    results = await asyncio.gather(
        publish(a, approval=approval), publish(a, approval=approval), return_exceptions=True
    )
    assert sum(not isinstance(r, Exception) for r in results) == 1
    (error,) = (r for r in results if isinstance(r, Exception))
    assert isinstance(error, ApprovalUsedError | StateConflictError) or type(error).__name__ == (
        "CandidateExistsError"
    )
    assert [v.version for v in await lifecycle(a).versions(ALPHA)] == [1, 2]
    assert [e.action for e in await approvals(a).events(ALPHA)].count("consumed") == 1


async def test_consuming_checks_what_the_approval_is_for(a, app_pool):
    await save(a)
    approval = await approve(a, await request(a))
    wrong = ApprovalUse(approval.id, "promote", approval.draft_hash, 2, "x", a.now)
    other_hash = ApprovalUse(approval.id, "publish", "sha256:" + "0" * 64, None, "x", a.now)
    late = ApprovalUse(approval.id, "publish", approval.draft_hash, None, "x", a.now + APPROVAL_TTL)
    for use, error in ((wrong, ApprovalStaleError), (other_hash, ApprovalStaleError),
                       (late, ApprovalExpiredError)):  # fmt: skip
        async with tenant_connection(app_pool, issue_scope(ALPHA)) as conn:
            with pytest.raises(error):
                await consume(conn, ALPHA, use)
    assert (await approvals(a).get(ALPHA, approval.id)).status == "approved"


async def test_the_approver_and_a_service_account_cannot_consume_it_in_the_store_or_the_database(
    a, app_pool
):
    """At the bottom: the lifecycle transaction's own check, then the table's CHECK."""
    await save(a)
    approval = await approve(a, await request(a))  # alice asked, bob approved
    by_approver = ApprovalUse(
        approval.id, "publish", approval.draft_hash, None, "https://i/#bob", a.now
    )
    by_robot = ApprovalUse(
        approval.id, "publish", approval.draft_hash, None, "https://i/#ci", a.now,
        service_account=True,
    )  # fmt: skip
    for use, error in ((by_approver, ApproverPublishError), (by_robot, ServiceAccountPublishError)):
        async with tenant_connection(app_pool, issue_scope(ALPHA)) as conn:
            with pytest.raises(error):
                await consume(conn, ALPHA, use)
    assert (await approvals(a).get(ALPHA, approval.id)).status == "approved"
    async with tenant_connection(app_pool, issue_scope(ALPHA)) as conn:
        with pytest.raises(asyncpg.CheckViolationError):  # past both: the CHECK
            await conn.execute(
                "UPDATE tenant_approvals SET status = 'consumed', consumed_by = approved_by, "
                "consumed_at = now() WHERE id = $1",
                approval.id,
            )
    with pytest.raises(ApproverPublishError):  # and through the publish service
        await publish(a, approval=approval, principal=BOB)
    assert await lifecycle(a).events(ALPHA) == []
    assert (await publish(a, approval=approval)).version == 1  # the requester publishes


async def test_a_publish_consumption_records_the_version_it_created(a):
    await save(a)
    approval = await approve(a, await request(a))
    await publish(a, approval=approval)
    consumed = [e for e in await approvals(a).events(ALPHA) if e.action == "consumed"]
    assert [(e.version, e.detail) for e in consumed] == [(1, "used by publish")]
    assert await a.approvals.published_under_approval(issue_scope(ALPHA), 1) == approval.id
    assert await a.approvals.published_under_approval(issue_scope(ALPHA), 2) is None


async def test_promoting_an_enforce_candidate_needs_evidence_on_postgres(a):
    """Published while the tenant needed none, promoted once it needs one."""
    await first_active_then_regulated_draft(a)  # v1 active; regulated now; draft r2
    a.tenants._profiles[ALPHA] = TenantProfile.build(
        TenantAttributes(tenant_id=ALPHA), "insurance", slug="alpha"
    )
    await publish(a, "enforce", 10)  # v2: a candidate, no approval used
    a.tenants._profiles[ALPHA] = TenantProfile.build(
        TenantAttributes(tenant_id=ALPHA, tier="regulated"), "insurance", slug="alpha"
    )
    d = await decide(a, "POST", "/candidate/promote")
    with pytest.raises(ApprovalRequiredError):
        await a.publisher.promote(d, ALICE, b"")
    promotion = await approve(a, await request(a, action="promote"))
    body = json.dumps({"approval_id": promotion.id}).encode()
    assert (await a.publisher.promote(d, ALICE, body)).state == "active"
    note = (await lifecycle(a).events(ALPHA))[-1].note
    assert f"two-person approval {promotion.id}" in note and "promotion approved" in note


async def test_the_list_on_postgres_pages_newest_first_and_filters(a, app_pool):
    await save(a)
    made = []
    for _ in range(5):
        a.now += timedelta(minutes=1)
        made.append(await request(a))
    made.append(await request(a))  # the same instant as the last one
    store = approvals(a)
    newest_first = sorted(made, key=lambda x: (x.requested_at, x.id), reverse=True)
    seen, after = [], None
    while True:
        page = await store.list_approvals(ALPHA, after=after, limit=4)
        seen += [x.id for x in page]
        if len(page) < 4:
            break
        after = ApprovalPosition(page[-1].requested_at, page[-1].id)
    assert seen == [x.id for x in newest_first]
    await approve(a, made[0])
    assert [x.id for x in await store.list_approvals(ALPHA, status="approved")] == [made[0].id]
    assert await store.list_approvals(ALPHA, status="consumed") == []
    d = await decide(a, "GET", "/draft/approvals", who(Role.VIEWER, issuer=ISS))
    listed = await a.approvals.list_approvals(d, limit="3")
    assert [x.id for x in listed.items] == [x.id for x in newest_first[:3]] and listed.next_cursor
    # another tenant's scope lists none of these (forced RLS)
    assert await approvals(a, BETA).list_approvals(BETA) == []


async def test_a_promotion_approval_on_postgres(a):
    await first_active_then_regulated_draft(a)
    await publish(a, "shadow", 10)
    promotion = await approve(a, await request(a, action="promote"))
    assert promotion.version == 2
    d = await decide(a, "POST", "/candidate/promote")
    body = json.dumps({"approval_id": promotion.id}).encode()
    result = await a.publisher.promote(d, ALICE, body)
    assert (result.version, result.state) == (2, "active")
    assert await lifecycle(a).state(ALPHA) == LifecycleState(active=2, candidate=None)
    assert (await approvals(a).get(ALPHA, promotion.id)).status == "consumed"


# ---------------------------------------------------------------------------- the table's rules


async def test_the_trigger_allows_only_the_status_moves(a, app_pool):
    await save(a)
    approval = await approve(a, await request(a))
    async with tenant_connection(app_pool, issue_scope(ALPHA)) as conn:
        for statement in (
            "UPDATE tenant_approvals SET draft_hash = 'sha256:" + "1" * 64 + "'",
            "UPDATE tenant_approvals SET requested_by = 'someone-else'",
            "UPDATE tenant_approvals SET action = 'promote', version = 2",
            "UPDATE tenant_approvals SET status = 'pending'",
            "UPDATE tenant_approvals SET status = 'approved'",
        ):
            with pytest.raises((*DENIED, asyncpg.CheckViolationError)):
                async with conn.transaction():
                    await conn.execute(statement)
    # a terminal row never moves again
    await publish(a, approval=approval)
    async with tenant_connection(app_pool, issue_scope(ALPHA)) as conn:
        for statement in (
            "UPDATE tenant_approvals SET status = 'cancelled', closed_at = now()",
            "UPDATE tenant_approvals SET consumed_by = 'y', consumed_at = now()",
            "UPDATE tenant_approvals SET status = 'approved', consumed_by = NULL, "
            "consumed_at = NULL",
        ):
            with pytest.raises((*DENIED, asyncpg.CheckViolationError)):
                async with conn.transaction():
                    await conn.execute(statement)
    with pytest.raises(DENIED):  # the app role can't loosen the columns it may update either
        await app_pool.execute("UPDATE tenant_approvals SET draft_hash = draft_hash")


async def test_the_app_role_holds_the_narrow_grants_only(app_pool):
    table = {
        (r["table_name"], r["privilege_type"])
        for r in await app_pool.fetch(
            "SELECT table_name, privilege_type FROM information_schema.role_table_grants "
            "WHERE grantee = current_user AND table_name IN "
            "('tenant_approvals', 'tenant_approval_audit')"
        )
    }
    assert table == {
        ("tenant_approvals", "SELECT"), ("tenant_approvals", "INSERT"),
        ("tenant_approval_audit", "SELECT"), ("tenant_approval_audit", "INSERT"),
    }  # fmt: skip
    columns = {
        r["column_name"]
        for r in await app_pool.fetch(
            "SELECT column_name FROM information_schema.column_privileges "
            "WHERE grantee = current_user AND table_name = 'tenant_approvals' "
            "AND privilege_type = 'UPDATE'"
        )
    }
    assert columns == {
        "status", "expires_at", "approved_by", "approved_at", "consumed_by", "consumed_at",
        "closed_at", "close_reason",
    }  # fmt: skip


async def test_a_tenant_sees_only_its_own_approvals_under_forced_rls(a, app_pool, pg_pool):
    await save(a)
    approval = await request(a)
    assert await approvals(a, BETA).get(BETA, approval.id) is None
    assert await approvals(a, BETA).events(BETA) == []
    async with tenant_connection(app_pool, issue_scope(BETA)) as conn:
        assert await conn.fetchval("SELECT count(*) FROM tenant_approvals") == 0
        assert await conn.fetchval("SELECT count(*) FROM tenant_approval_audit") == 0
        with pytest.raises(asyncpg.exceptions.InsufficientPrivilegeError):  # WITH CHECK
            await conn.execute(
                "INSERT INTO tenant_approval_audit (tenant_id, at, action, actor, cross_tenant, "
                "operator) VALUES ($1, now(), 'requested', 'x', false, false)",
                ALPHA,
            )
    forced = await pg_pool.fetchval(
        "SELECT bool_and(relforcerowsecurity) FROM pg_class "
        "WHERE relname IN ('tenant_approvals', 'tenant_approval_audit')"
    )
    assert forced is True


async def test_an_operator_pool_reaches_a_tenants_approvals_only_through_its_scope(
    a, app_pool, operator_pool
):
    await save(a)
    approval = await request(a)
    op_scope = issue_scope(ALPHA, operator=True)
    no_pool = PostgresApprovalStore(app_pool)
    from guardrail_engine.store.port import OperatorPoolUnavailableError

    with pytest.raises(OperatorPoolUnavailableError):
        await no_pool.scoped(op_scope).get(ALPHA, approval.id)
    with_pool = PostgresApprovalStore(app_pool, operator_pool)
    assert (await with_pool.scoped(op_scope).get(ALPHA, approval.id)).id == approval.id


async def test_the_grants_and_the_schema_can_be_applied_again(pg_pool, app_pool):
    from guardrail_engine.store.adapters.postgres import apply_app_role_grants, apply_schema

    role = await app_pool.fetchval("SELECT current_user")
    await apply_schema(pg_pool)
    await apply_app_role_grants(pg_pool, role)
    assert await app_pool.fetchval("SELECT count(*) FROM tenant_approvals") == 0
    assert timedelta(hours=72) == APPROVAL_TTL
