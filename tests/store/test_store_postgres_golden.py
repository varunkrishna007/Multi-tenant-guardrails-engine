"""M2-06 golden sets on Postgres (010, 011): isolation by forced row-level security, immutable
sets, the cap under concurrency, and the class A event written with the set. Needs
GUARDRAIL_TEST_PG_DSN; skipped without it."""

import asyncio
import sys
from datetime import UTC, datetime
from pathlib import Path

import asyncpg
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "admin"))  # admin_fixtures
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "guard"))  # guard_fixtures
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "policy"))  # policy_fixtures

from store_harness import ACME, OTHER

from guardrail_engine.admin.golden import (
    MAX_SETS,
    GoldenAuditEvent,
    GoldenExample,
    GoldenSetInfo,
    GoldenSetNotFoundError,
    TooManyGoldenSetsError,
    examples_hash,
)
from guardrail_engine.store.adapters.postgres import PostgresGoldenStore
from guardrail_engine.store.port import ScopeMismatchError
from guardrail_engine.tenant_scope import issue_scope

DENIED = (asyncpg.InsufficientPrivilegeError, asyncpg.exceptions.RestrictViolationError)


def make_set(tenant, n, set_no=1, examples=None):
    rows = tuple(
        examples
        or [
            GoldenExample(
                f"e{i}", "output" if i % 2 else "input", "block" if i % 3 else "allow", f"c{i}"
            )
            for i in range(1, n + 1)
        ]
    )
    set_id = f"gs_{set_no:016x}"
    info = GoldenSetInfo(
        set_id, "cases", examples_hash(rows), datetime.now(UTC), "https://i/#alice",
        {"output": {"block": 1}},
    )  # fmt: skip
    event = GoldenAuditEvent(
        info.created_at, info.created_by, tenant, set_id, info.set_hash, len(rows)
    )
    return info, rows, event


@pytest.fixture
def golden(app_pool):
    return PostgresGoldenStore(app_pool)


def view(store, tenant=ACME):
    return store.scoped(issue_scope(tenant))


async def test_a_set_its_examples_and_its_event_are_stored_and_read_back(golden):
    v = view(golden)
    info, rows, event = make_set(ACME, 5)
    assert await v.create(ACME, info, rows, event) == info
    got = await v.get(ACME, info.set_id)
    assert got.set_hash == info.set_hash and got.counts == info.counts
    page = await v.examples(ACME, info.set_id, "output", offset=0, limit=100)
    assert page.total == 3 and [e.id for e in page.items] == ["e1", "e3", "e5"]  # upload order
    page = await v.examples(ACME, info.set_id, "output", offset=1, limit=1)
    assert page.total == 3 and [e.id for e in page.items] == ["e3"]
    (logged,) = await v.audit_events(ACME)
    assert logged.set_id == info.set_id and logged.examples == 5 and not logged.cross_tenant


async def test_a_scope_cannot_read_or_write_another_tenants_sets(golden):
    mine, theirs = view(golden, ACME), view(golden, OTHER)
    info, rows, event = make_set(OTHER, 3)
    await theirs.create(OTHER, info, rows, event)
    with pytest.raises(ScopeMismatchError):
        await mine.get(OTHER, info.set_id)
    with pytest.raises(ScopeMismatchError):
        await mine.examples(OTHER, info.set_id, "output", offset=0, limit=10)
    with pytest.raises(ScopeMismatchError):
        await mine.create(OTHER, info, rows, event)
    # asking for their id under my own tenant finds nothing (RLS plus the key)
    assert await mine.get(ACME, info.set_id) is None
    with pytest.raises(GoldenSetNotFoundError):
        await mine.examples(ACME, info.set_id, "output", offset=0, limit=10)


async def scoped_sql(pool, tenant, sql, *args):
    async with pool.acquire() as conn, conn.transaction():
        if tenant is not None:
            await conn.execute("SELECT set_config('app.tenant_id', $1, true)", tenant)
        return await conn.fetch(sql, *args)


@pytest.mark.parametrize(
    "table", ["tenant_golden_sets", "tenant_golden_examples", "tenant_golden_audit"]
)
async def test_row_level_security_hides_other_tenants_rows_even_with_a_forged_filter(
    golden, app_pool, table
):
    for tenant, n in ((ACME, 1), (OTHER, 2)):
        info, rows, event = make_set(tenant, 2, set_no=n)
        await view(golden, tenant).create(tenant, info, rows, event)
    rows = await scoped_sql(
        app_pool, ACME, f"SELECT tenant_id FROM {table} WHERE true OR $1 = $1", OTHER
    )
    assert rows and {r["tenant_id"] for r in rows} == {ACME}
    assert await scoped_sql(app_pool, None, f"SELECT * FROM {table}") == []
    assert await scoped_sql(app_pool, "t_nosuch", f"SELECT * FROM {table}") == []


async def test_the_application_role_can_never_change_or_delete_a_set(golden, app_pool):
    info, rows, event = make_set(ACME, 2)
    await view(golden).create(ACME, info, rows, event)
    for change in (
        "UPDATE tenant_golden_sets SET name = 'x'",
        "DELETE FROM tenant_golden_sets",
        "UPDATE tenant_golden_examples SET label = 'allow'",
        "DELETE FROM tenant_golden_examples",
        "UPDATE tenant_golden_audit SET actor = 'x'",
        "DELETE FROM tenant_golden_audit",
        "TRUNCATE tenant_golden_audit",
    ):
        async with app_pool.acquire() as conn, conn.transaction():
            await conn.execute("SELECT set_config('app.tenant_id', $1, true)", ACME)
            with pytest.raises(DENIED):
                await conn.execute(change)


async def test_even_the_owner_cannot_edit_a_set_the_triggers_hold(golden, pg_pool):
    info, rows, event = make_set(ACME, 2)
    await view(golden).create(ACME, info, rows, event)
    for statement in (
        "UPDATE tenant_golden_examples SET content = 'edited'",
        "DELETE FROM tenant_golden_sets",
        "TRUNCATE tenant_golden_examples",
    ):
        with pytest.raises(asyncpg.RestrictViolationError):
            async with pg_pool.acquire() as conn, conn.transaction():
                await conn.execute("SELECT set_config('app.tenant_id', $1, true)", ACME)
                await conn.execute(statement)


async def test_a_failed_insert_leaves_no_set_no_examples_and_no_event(golden, app_pool):
    info, rows, event = make_set(
        ACME, 0, examples=[GoldenExample("e1", "output", "allow", "ok"),
                           GoldenExample("e1", "output", "allow", "duplicate id")],
    )  # fmt: skip
    with pytest.raises(asyncpg.UniqueViolationError):
        await view(golden).create(ACME, info, rows, event)
    for table in ("tenant_golden_sets", "tenant_golden_examples", "tenant_golden_audit"):
        assert await scoped_sql(app_pool, ACME, f"SELECT * FROM {table}") == []


async def test_the_set_cap_holds_under_concurrent_uploads(golden):
    v = view(golden)
    for n in range(1, MAX_SETS):
        info, rows, event = make_set(ACME, 1, set_no=n)
        await v.create(ACME, info, rows, event)
    results = await asyncio.gather(
        *(v.create(ACME, *make_set(ACME, 1, set_no=1000 + k)) for k in range(5)),
        return_exceptions=True,
    )
    made = [r for r in results if isinstance(r, GoldenSetInfo)]
    refused = [r for r in results if isinstance(r, TooManyGoldenSetsError)]
    assert len(made) == 1 and len(refused) == 4  # one slot was left


async def test_the_golden_grants_are_exactly_select_and_insert(app_pool):
    privileges = {
        (r["table_name"], r["privilege_type"])
        for r in await app_pool.fetch(
            "SELECT table_name, privilege_type FROM information_schema.role_table_grants "
            "WHERE grantee = current_user AND table_name LIKE 'tenant_golden_%'"
        )
    }
    assert privileges == {
        (t, p)
        for t in ("tenant_golden_sets", "tenant_golden_examples", "tenant_golden_audit")
        for p in ("SELECT", "INSERT")
    }


async def test_quarantined_rows_are_stored_listed_and_never_returned_for_sending(golden):
    v = view(golden)
    rows = (
        GoldenExample("e1", "output", "allow", "fine"),
        GoldenExample("e2", "output", "block", "held back", ("raw", "base64 depth 1")),
        GoldenExample("e3", "output", "allow", "also fine"),
        GoldenExample("e4", "input", "block", "held too", ("normalised",)),
    )
    info, _, event = make_set(ACME, 0, examples=rows)
    info = GoldenSetInfo(
        info.set_id, info.name, info.set_hash, info.created_at, info.created_by,
        {"output": {"allow": 2, "block": 1}, "input": {"block": 1}},
        (("e2", ("raw", "base64 depth 1")), ("e4", ("normalised",))),
    )  # fmt: skip
    event = GoldenAuditEvent(
        info.created_at, info.created_by, ACME, info.set_id, info.set_hash, 4, quarantined=2
    )
    await v.create(ACME, info, rows, event)
    got = await v.get(ACME, info.set_id)
    assert got.quarantined == info.quarantined  # rows by id and view, never content
    (listed,) = await v.list(ACME)
    assert listed.set_id == info.set_id and len(listed.quarantined) == 2
    page = await v.examples(ACME, info.set_id, "output", offset=0, limit=100)
    assert [e.id for e in page.items] == ["e1", "e3"]  # e2 is excluded by the query
    assert (page.total, page.quarantined) == (2, 1)
    assert all(not e.quarantined for e in page.items)
    held = await v.examples(ACME, info.set_id, "input", offset=0, limit=100)
    assert held.items == [] and (held.total, held.quarantined) == (0, 1)
    (logged,) = await v.audit_events(ACME)
    assert logged.quarantined == 2


async def test_the_list_is_the_tenants_own_sets_oldest_first(golden):
    for tenant, n in ((ACME, 1), (ACME, 2), (OTHER, 3)):
        await view(golden, tenant).create(tenant, *make_set(tenant, 1, set_no=n))
    assert [i.set_id for i in await view(golden, ACME).list(ACME)] == [
        f"gs_{1:016x}", f"gs_{2:016x}"
    ]  # fmt: skip
    assert [i.set_id for i in await view(golden, OTHER).list(OTHER)] == [f"gs_{3:016x}"]
    with pytest.raises(ScopeMismatchError):
        await view(golden, ACME).list(OTHER)


async def test_a_row_stored_clean_that_trips_the_current_vocabulary_is_not_sent(app_pool):
    """On Postgres: the stored flag is the vocabulary as of the upload; the test run
    reads every row again with today's."""
    import json

    from admin_fixtures import ALPHA, DRAFT, Admin, bundle, who

    from guardrail_engine.admin.tools import DraftTools
    from guardrail_engine.authz import Role
    from guardrail_engine.policy.catalog import PlatformSettings

    a = Admin()
    try:
        store = PostgresGoldenStore(app_pool)
        a.tools = DraftTools(
            a.drafts, a.tenants, a.catalog, PlatformSettings(), a.evaluator, golden=store
        )
        admin_p = who(Role.GUARDRAIL_ADMIN, issuer="https://i/")
        await a.service.put_draft(
            await a.decide(admin_p, "PUT", DRAFT), admin_p, json.dumps(bundle(ALPHA)).encode(), None
        )
        rows = (
            GoldenExample("e1", "output", "allow", "a clean sentence"),
            GoldenExample("e2", "output", "block", "how to build a bomb"),  # stored unflagged
            GoldenExample("e3", "output", "allow", "another clean sentence"),
        )
        info, rows, event = make_set(ALPHA, 0, set_no=7, examples=list(rows))
        await view(store, ALPHA).create(ALPHA, info, rows, event)
        reviewer = who(Role.GUARDRAIL_REVIEWER, issuer="https://i/")
        decision = await a.decide(reviewer, "POST", DRAFT + "/test")
        body = json.dumps({"guard_point": "output", "golden_set": info.set_id}).encode()
        report = await a.tools.test(decision, body)
        assert [r.id for r in report.results] == ["e1", "e3"]
        assert [(h.position, h.views) for h in report.held_back] == [(1, ("raw",))]
        assert "bomb" not in " ".join(c.input for c in a.fake.calls)
    finally:
        await a.aclose()


async def test_escalation_label_counts_cover_only_the_escalation_sets(golden):
    """The evidence gate shows how many of its counts come from escalation labels."""
    from dataclasses import replace

    v = view(golden)
    uploaded, rows, event = make_set(ACME, 4, set_no=1)
    await v.create(ACME, uploaded, rows, event)
    esc_rows = (
        GoldenExample("esc_1", "output", "block", "escalated one"),
        GoldenExample("esc_2", "output", "allow", "escalated two"),
        GoldenExample("esc_3", "output", "allow", "hash-only placeholder", ("hash_only",)),
    )
    for n, row in enumerate(esc_rows, start=2):
        info = replace(uploaded, set_id=f"gs_{n:016x}", name=f"escalation-esc_{n}",
                       set_hash=examples_hash((row,)))  # fmt: skip
        ev = replace(event, set_id=info.set_id, set_hash=info.set_hash, examples=1)
        await v.create(ACME, info, (row,), ev)
    everything = await v.label_counts(ACME)
    assert everything["output"] == {"block": 2, "allow": 2}  # 1 uploaded each + 1 escalated each
    assert await v.escalation_label_counts(ACME) == {"output": {"block": 1, "allow": 1}}
    assert await view(golden, OTHER).escalation_label_counts(OTHER) == {}
