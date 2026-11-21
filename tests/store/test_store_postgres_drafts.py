"""M2-02 draft store on Postgres (008, 009): the same contract as the in-memory store, plus
forced row-level security, the append-only class A table and atomic write-with-audit. Needs
GUARDRAIL_TEST_PG_DSN; skipped without it."""

import asyncio
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

import asyncpg
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "admin"))  # admin_fixtures
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "guard"))  # guard_fixtures
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "policy"))  # policy_fixtures

from admin_fixtures import ALPHA, BETA, DRAFT, Admin, bundle, rule, who
from store_harness import OTHER

from guardrail_engine.admin import (
    DraftAuditEvent,
    DraftConflictError,
    DraftService,
    InMemoryDraftStore,
)
from guardrail_engine.authz import Role
from guardrail_engine.store.adapters.postgres import PostgresDraftStore
from guardrail_engine.store.port import ScopeMismatchError
from guardrail_engine.tenant_scope import issue_scope

H0 = "sha256:" + "0" * 64
H1 = "sha256:" + "1" * 64
H2 = "sha256:" + "2" * 64
DENIED = (asyncpg.InsufficientPrivilegeError, asyncpg.exceptions.RestrictViolationError)


def event(tenant=ALPHA, before=None, resulting=H1, action="draft.put", **flags):
    return DraftAuditEvent(
        datetime.now(UTC), "alice", tenant, action, before, resulting, (), **flags
    )


@pytest.fixture
def drafts(app_pool):
    return PostgresDraftStore(app_pool)


def view(store, tenant=ALPHA):
    return store.scoped(issue_scope(tenant))


async def test_a_first_draft_is_stored_read_back_and_audited(drafts):
    v = view(drafts)
    assert await v.get(ALPHA) is None
    stored = await v.replace(ALPHA, b'{"a":1}', expected_etag=None, event=event())
    assert stored.etag == f'"{H1}"' and stored.updated_by == "alice"
    assert await v.get(ALPHA) == stored
    (logged,) = await v.audit_events(ALPHA)
    assert (logged.actor, logged.action, logged.resulting_hash) == ("alice", "draft.put", H1)
    assert logged.before_hash is None


async def test_a_threshold_decision_rides_in_the_drafts_own_audit_event(drafts):
    """The decision and the draft write are one transaction (one event)."""
    v = view(drafts)
    first = await v.replace(ALPHA, b'{"a":1}', expected_etag=None, event=event())
    decided = DraftAuditEvent(
        datetime.now(UTC), "alice", ALPHA, "draft.thresholds", H1, H2, (),
        detail={"decisions": [{"rule": "r", "action": "accept"}], "digest": "sha256:" + "0" * 64},
    )  # fmt: skip
    await v.replace(ALPHA, b'{"a":2}', expected_etag=first.etag, event=decided)
    first_event, second = await v.audit_events(ALPHA)
    assert first_event.detail is None  # an ordinary write carries none
    assert second.action == "draft.thresholds"
    assert second.detail == {
        "decisions": [{"rule": "r", "action": "accept"}], "digest": "sha256:" + "0" * 64,
    }  # fmt: skip
    # a write that fails (a stale ETag) leaves no event behind
    with pytest.raises(DraftConflictError):
        await v.replace(ALPHA, b'{"a":3}', expected_etag=first.etag, event=decided)
    assert len(await v.audit_events(ALPHA)) == 2


async def test_replace_is_a_compare_and_set_on_the_etag(drafts):
    v = view(drafts)
    first = await v.replace(ALPHA, b'{"a":1}', expected_etag=None, event=event())
    with pytest.raises(DraftConflictError) as stale:
        await v.replace(
            ALPHA, b'{"a":2}', expected_etag='"sha256:stale"', event=event(resulting=H2)
        )
    assert stale.value.current == first.etag
    with pytest.raises(DraftConflictError) as exists:
        await v.replace(ALPHA, b'{"a":2}', expected_etag=None, event=event(resulting=H2))
    assert exists.value.current == first.etag
    second = await v.replace(
        ALPHA, b'{"a":2}', expected_etag=first.etag, event=event(before=H1, resulting=H2)
    )
    assert second.etag == f'"{H2}"'
    # a refused write left neither a draft change nor an audit row behind
    assert [e.resulting_hash for e in await v.audit_events(ALPHA)] == [H1, H2]


async def test_two_requests_creating_the_first_draft_at_once_only_one_wins(drafts):
    v = view(drafts)
    results = await asyncio.gather(
        *(v.replace(ALPHA, b"{}", expected_etag=None, event=event(resulting=h)) for h in (H1, H2)),
        return_exceptions=True,
    )
    assert sorted(type(r).__name__ for r in results) == ["DraftConflictError", "StoredDraft"]
    assert len(await v.audit_events(ALPHA)) == 1


async def test_a_failed_audit_insert_rolls_the_draft_back(drafts):
    v = view(drafts)
    bad = event(resulting="not-a-hash")  # the table's CHECK refuses it
    with pytest.raises(asyncpg.CheckViolationError):
        await v.replace(ALPHA, b"{}", expected_etag=None, event=bad)
    assert await v.get(ALPHA) is None


async def test_a_scope_cannot_read_or_write_another_tenants_draft(drafts):
    mine, theirs = view(drafts, ALPHA), view(drafts, OTHER)
    await theirs.replace(OTHER, b'{"secret":1}', expected_etag=None, event=event(OTHER))
    for call in (mine.get(OTHER), mine.audit_events(OTHER)):
        with pytest.raises(ScopeMismatchError):
            await call
    with pytest.raises(ScopeMismatchError):
        await mine.replace(OTHER, b"{}", expected_etag=None, event=event(OTHER))
    with pytest.raises(ScopeMismatchError):
        await mine.replace(ALPHA, b"{}", expected_etag=None, event=event(OTHER))
    assert await mine.get(ALPHA) is None


async def scoped_sql(pool, tenant, sql, *args):
    async with pool.acquire() as conn, conn.transaction():
        if tenant is not None:
            await conn.execute("SELECT set_config('app.tenant_id', $1, true)", tenant)
        return await conn.fetch(sql, *args)


@pytest.mark.parametrize("table", ["tenant_drafts", "tenant_draft_audit"])
async def test_row_level_security_hides_other_tenants_rows_even_with_a_forged_filter(
    drafts, app_pool, table
):
    for tenant, h in ((ALPHA, H1), (OTHER, H2)):
        await view(drafts, tenant).replace(
            tenant, b"{}", expected_etag=None, event=event(tenant, resulting=h)
        )
    rows = await scoped_sql(
        app_pool, ALPHA, f"SELECT tenant_id FROM {table} WHERE true OR $1 = $1", OTHER
    )
    assert {r["tenant_id"] for r in rows} == {ALPHA}
    assert await scoped_sql(app_pool, None, f"SELECT * FROM {table}") == []  # no setting
    assert await scoped_sql(app_pool, "", f"SELECT * FROM {table}") == []


async def test_a_write_for_another_tenant_is_refused_by_the_policy(drafts, app_pool):
    async with app_pool.acquire() as conn, conn.transaction():
        await conn.execute("SELECT set_config('app.tenant_id', $1, true)", ALPHA)
        with pytest.raises(asyncpg.InsufficientPrivilegeError):
            await conn.execute(
                "INSERT INTO tenant_drafts (tenant_id, document, etag, updated_by) "
                "VALUES ($1, '{}', $2, 'x')",
                OTHER, f'"{H1}"',
            )  # fmt: skip


async def test_the_audit_table_is_append_only_for_the_application_role(drafts, app_pool):
    await view(drafts).replace(ALPHA, b"{}", expected_etag=None, event=event())
    for statement in (
        "UPDATE tenant_draft_audit SET actor = 'mallory'",
        "DELETE FROM tenant_draft_audit",
        "TRUNCATE tenant_draft_audit",
    ):
        async with app_pool.acquire() as conn, conn.transaction():
            await conn.execute("SELECT set_config('app.tenant_id', $1, true)", ALPHA)
            with pytest.raises(DENIED):
                await conn.execute(statement)


async def test_the_application_role_can_never_delete_a_draft(drafts, app_pool):
    await view(drafts).replace(ALPHA, b"{}", expected_etag=None, event=event())
    async with app_pool.acquire() as conn, conn.transaction():
        await conn.execute("SELECT set_config('app.tenant_id', $1, true)", ALPHA)
        with pytest.raises(asyncpg.InsufficientPrivilegeError):
            await conn.execute("DELETE FROM tenant_drafts")


async def test_even_the_table_owner_cannot_edit_the_audit_rows(pg_pool):
    """The triggers hold for the owner too (RLS is forced; the trigger refuses the rest)."""
    async with pg_pool.acquire() as conn, conn.transaction():
        await conn.execute("SELECT set_config('app.tenant_id', $1, true)", ALPHA)
        await conn.execute(
            "INSERT INTO tenant_draft_audit (tenant_id, at, actor, cross_tenant, operator, action, "
            "resulting_hash, diff) "
            "VALUES ($1, now(), 'a', false, false, 'draft.put', $2, '[]'::jsonb)",
            ALPHA, H1,
        )  # fmt: skip
    for statement in ("UPDATE tenant_draft_audit SET actor = 'b'", "TRUNCATE tenant_draft_audit"):
        with pytest.raises(asyncpg.RestrictViolationError):
            async with pg_pool.acquire() as conn, conn.transaction():
                await conn.execute("SELECT set_config('app.tenant_id', $1, true)", ALPHA)
                await conn.execute(statement)


async def test_the_service_runs_on_postgres_with_the_same_results(app_pool):
    """The draft service end to end over the Postgres store, through the real authorizer."""
    a = Admin(drafts=InMemoryDraftStore())
    a.service = DraftService(
        PostgresDraftStore(app_pool), a.policies, a.tenants, a.catalog, a.service._settings
    )
    admin = who(Role.GUARDRAIL_ADMIN)
    decision = await a.decide(admin, "PUT", DRAFT)
    first = await a.service.put_draft(decision, admin, json.dumps(bundle(ALPHA)).encode(), None)
    second = await a.service.put_draft(
        decision, admin, json.dumps(bundle(ALPHA, rules=[rule("r")])).encode(), first.etag
    )
    assert second.etag != first.etag
    events = await PostgresDraftStore(app_pool).scoped(issue_scope(ALPHA)).audit_events(ALPHA)
    assert [e.action for e in events] == ["draft.put", "draft.put"]
    assert events[1].before_hash == events[0].resulting_hash
    assert any(d.path.startswith("/rules") for d in events[1].diff)
    # beta's admin sees none of it
    beta = who(Role.GUARDRAIL_ADMIN, tenant=BETA)
    view_ = await a.service.get_guardrails(
        await a.decide(beta, "GET", "/v1/tenants/{tid}/guardrails", BETA)
    )
    assert view_.draft is None


async def test_the_draft_grants_are_exactly_what_the_store_uses(app_pool):
    privileges = {
        (r["table_name"], r["privilege_type"])
        for r in await app_pool.fetch(
            "SELECT table_name, privilege_type FROM information_schema.role_table_grants "
            "WHERE grantee = current_user AND table_name IN ('tenant_drafts', 'tenant_draft_audit')"
        )
    }
    assert privileges == {
        ("tenant_drafts", "SELECT"), ("tenant_drafts", "INSERT"), ("tenant_drafts", "UPDATE"),
        ("tenant_draft_audit", "SELECT"), ("tenant_draft_audit", "INSERT"),
    }  # fmt: skip


async def test_the_actor_issuer_and_the_cross_tenant_and_operator_flags_are_stored(drafts):
    v = view(drafts)
    first = await v.replace(
        ALPHA, b"{}", expected_etag=None, event=event(cross_tenant=True, operator=True)
    )
    assert first.created is True  # the store says it created the draft
    (logged,) = await v.audit_events(ALPHA)
    assert logged.cross_tenant is True and logged.operator is True
    second = await v.replace(
        ALPHA, b'{"a":1}', expected_etag=first.etag, event=event(before=H1, resulting=H2)
    )
    assert second.created is False
    assert (await v.get(ALPHA)).created is False
    flags = [(e.cross_tenant, e.operator) for e in await v.audit_events(ALPHA)]
    assert flags == [(True, True), (False, False)]
