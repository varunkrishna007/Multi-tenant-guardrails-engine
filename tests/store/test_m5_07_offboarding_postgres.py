"""M5-07 on Postgres: what the database itself refuses (the deletion functions called directly as
the retention role, the immutability triggers, the grants, the one-way status) and the schema's
class map. Needs GUARDRAIL_TEST_PG_DSN; skipped without it. The schema's owner is not a
superuser, so forced row-level security applies to the functions."""

import asyncio

import asyncpg
import pytest
from offboarding_env import ALL_TABLES, OPS, expected, make_pg_env

from guardrail_engine.offboarding import OffboardingJob
from guardrail_engine.offboarding.model import (
    CLASS_A_TABLES,
    DELETED_TABLES,
    RECEIPT_TABLES,
)

NOT_PREREQ = asyncpg.exceptions.ObjectNotInPrerequisiteStateError  # 55000
BAD_PARAM = asyncpg.exceptions.InvalidParameterValueError  # 22023
DENIED = asyncpg.InsufficientPrivilegeError
RESTRICT = asyncpg.exceptions.RestrictViolationError

DELETE_BATCH = "SELECT offboarding_delete_batch($1, $2, $3, $4, $5)"


@pytest.fixture
async def pg():
    env, cleanup = await make_pg_env()
    try:
        yield env
    finally:
        await cleanup()


async def tenant(pg, slug="acme-co", *, terminate=False, records=3) -> str:
    tid = await pg.new_tenant(slug)
    await pg.seed(tid, records)
    if terminate:
        await pg.terminate(tid)
    return tid


async def test_the_owner_here_is_not_a_superuser(pg):
    assert pg.owner_superuser is False  # else row-level security would prove nothing


# ----------------------------------------------------------------------------- the function itself


@pytest.mark.parametrize("status", ["active", "suspended", "offboarded", "terminating"])
async def test_the_function_refuses_a_tenant_that_is_not_terminated_even_when_called_directly(
    pg, status
):
    """The retention role calls the SECURITY DEFINER function itself, with a valid table and
    batch. The database reads the tenant's status and refuses; nothing is deleted."""
    tid = await tenant(pg)
    if status == "suspended":
        await pg.prov.set_status(OPS, tid, 1, "suspended")
    elif status == "offboarded":
        await pg.prov.set_status(OPS, tid, 1, "offboarded")
    elif status == "terminating":

        async def crash(_):
            raise RuntimeError("stopped between the two statuses")

        pg.prov._sleep = crash
        with pytest.raises(RuntimeError):
            await pg.prov.terminate(OPS, tid, "contract ended")
    for table in ALL_TABLES:
        with pytest.raises(NOT_PREREQ):
            await pg.retention_pool.fetchval(DELETE_BATCH, "r", tid, table, 100, 1)
    with pytest.raises(NOT_PREREQ):
        await pg.retention_pool.fetchval("SELECT offboarding_complete($1, $2, now())", "r", tid)
    assert await pg.counts(tid) == expected()
    assert await pg.owner.fetchval("SELECT count(*) FROM offboarding_receipts") == 0
    assert await pg.owner.fetchval("SELECT count(*) FROM offboarding_completions") == 0


async def test_the_function_refuses_an_unknown_tenant(pg):
    with pytest.raises(NOT_PREREQ):
        await pg.retention_pool.fetchval(DELETE_BATCH, "r", "t_nosuch", "tenant_drafts", 10, 1)


async def test_the_function_deletes_for_a_terminated_tenant_called_directly(pg):
    tid = await tenant(pg, terminate=True)
    n = await pg.retention_pool.fetchval(DELETE_BATCH, "r", tid, "tenant_drafts", 10, 1)
    assert n == 1 and (await pg.counts(tid))["tenant_drafts"] == 0
    receipt = await pg.owner.fetchrow(
        "SELECT table_name, data_class, deleted_count, batch FROM offboarding_receipts"
    )
    assert tuple(receipt.values()) == ("tenant_drafts", "W", 1, 1)


@pytest.mark.parametrize(
    "args",
    [
        ("r", "t_acmeco", "tenant_drafts", 0, 1),
        ("r", "t_acmeco", "tenant_drafts", 100_001, 1),
        ("r", "t_acmeco", "tenant_drafts", 10, 0),
        ("r", "t_acmeco", "tenants", 10, 1),
        ("r", "t_acmeco", "tenant_golden_audit", 10, 1),
        ("r", "t_acmeco", "escalation_items.content", 10, 1),
        ("r", "t_acmeco", "tenant_drafts; DROP TABLE tenants", 10, 1),
        ("r", "acme", "tenant_drafts", 10, 1),
        ("r", "t_AB", "tenant_drafts", 10, 1),
        ("", "t_acmeco", "tenant_drafts", 10, 1),
        ("x" * 65, "t_acmeco", "tenant_drafts", 10, 1),
    ],
)
async def test_the_function_checks_its_own_bounds(pg, args):
    with pytest.raises(BAD_PARAM):
        await pg.retention_pool.fetchval(DELETE_BATCH, *args)


async def test_complete_refuses_a_clock_ahead_of_the_database(pg):
    tid = await tenant(pg, terminate=True)
    with pytest.raises(BAD_PARAM):
        await pg.retention_pool.fetchval(
            "SELECT offboarding_complete($1, $2, now() + interval '1 hour')", "r", tid
        )


async def test_temp_tables_made_by_the_retention_role_capture_nothing(pg):
    """The role has TEMP like everyone. A temporary `tenants` that says terminated, and a
    temporary receipts table, change nothing: the function pins its search_path with pg_temp
    last and qualifies its tables."""
    active = await tenant(pg, "active-co")
    done = await tenant(pg, "done-co", terminate=True)
    async with pg.retention_pool.acquire() as conn:
        await conn.execute(
            "CREATE TEMP TABLE tenants (tenant_id text, status text, updated_at timestamptz)"
        )
        await conn.execute(f"INSERT INTO pg_temp.tenants VALUES ('{active}', 'terminated', now())")
        await conn.execute(
            "CREATE TEMP TABLE offboarding_receipts (run_id text, at timestamptz, tenant_id text,"
            " table_name text, data_class text, deleted_count int, batch int)"
        )
        await conn.execute("CREATE TEMP TABLE tenant_drafts (tenant_id text)")
        await conn.execute("CREATE TEMP TABLE offboarding_completions (tenant_id text)")
        with pytest.raises(NOT_PREREQ):
            await conn.fetchval(DELETE_BATCH, "r", active, "tenant_drafts", 10, 1)
        assert await conn.fetchval(DELETE_BATCH, "r", done, "tenant_drafts", 10, 1) == 1
        assert await conn.fetchval("SELECT count(*) FROM pg_temp.offboarding_receipts") == 0
        assert await conn.fetchval("SELECT count(*) FROM pg_temp.offboarding_completions") == 0
    assert (await pg.counts(active))["tenant_drafts"] == 1
    assert await pg.owner.fetchval("SELECT count(*) FROM offboarding_receipts") == 1


async def test_the_functions_pin_search_path_and_are_security_definer(pg):
    rows = await pg.owner.fetch(
        "SELECT proname, prosecdef, proconfig FROM pg_proc p JOIN pg_namespace n "
        "ON n.oid = p.pronamespace WHERE n.nspname = $1 AND proname = ANY($2)",
        pg.schema,
        [
            "offboarding_delete_batch",
            "offboarding_complete",
            "offboarding_pending",
            "offboarding_resweep_pending",
            "offboarding_sweep_log",
            "offboarding_delete_allowed",
            "offboarding_deletable_guard",
        ],
    )
    assert len(rows) == 7
    for r in rows:
        assert [c.replace('"', "") for c in r["proconfig"]] == [
            f"search_path=pg_catalog, {pg.schema}, pg_temp"
        ], r["proname"]
        wants_definer = r["proname"] in {
            "offboarding_delete_batch",
            "offboarding_complete",
            "offboarding_pending",
            "offboarding_resweep_pending",
            "offboarding_sweep_log",
        }
        assert r["prosecdef"] is wants_definer, r["proname"]


# ----------------------------------------------------------------------------- privileges


async def test_the_retention_role_can_only_call_the_functions_and_read_the_receipts(pg):
    tid = await tenant(pg, terminate=True)
    pool = pg.retention_pool
    for table in ("tenant_drafts", "decision_records", "tenant_golden_sets", "usage_events"):
        with pytest.raises(DENIED):
            await pool.execute(f"DELETE FROM {table}")
        with pytest.raises(DENIED):
            await pool.fetch(f"SELECT * FROM {table}")
    for statement in (
        "INSERT INTO offboarding_receipts (run_id, at, tenant_id, table_name, data_class,"
        f" deleted_count, batch) VALUES ('r', now(), '{tid}', 'tenant_drafts', 'W', 1, 1)",
        "DELETE FROM offboarding_receipts",
        "UPDATE tenants SET status = 'active'",
        f"UPDATE tenants SET status = 'active' WHERE tenant_id = '{tid}'",
    ):
        with pytest.raises(DENIED):
            await pool.execute(statement)
    await pool.fetch("SELECT * FROM offboarding_receipts")
    await pool.fetch("SELECT * FROM offboarding_completions")
    await pool.fetch("SELECT * FROM offboarding_usage_summaries")
    await pool.fetch("SELECT * FROM offboarding_sweeps")
    await pool.fetch("SELECT * FROM offboarding_resweep_pending(now(), 10)")
    with pytest.raises(DENIED):
        await pool.fetchval("SELECT offboarding_delete_allowed($1)", tid)


async def test_the_service_role_can_not_call_or_read_any_of_it(pg):
    tid = await tenant(pg, terminate=True)
    with pytest.raises(DENIED):
        await pg.app.fetchval(DELETE_BATCH, "r", tid, "tenant_drafts", 10, 1)
    with pytest.raises(DENIED):
        await pg.app.fetch("SELECT * FROM offboarding_pending(10)")
    with pytest.raises(DENIED):
        await pg.app.fetchval("SELECT offboarding_complete('r', $1, now())", tid)
    with pytest.raises(DENIED):
        await pg.app.fetch("SELECT * FROM offboarding_receipts")
    with pytest.raises(DENIED):
        await pg.app.fetch("SELECT * FROM offboarding_completions")
    with pytest.raises(DENIED):
        await pg.app.fetch("SELECT * FROM offboarding_resweep_pending(now(), 10)")
    with pytest.raises(DENIED):
        await pg.app.fetchval("SELECT offboarding_sweep_log('r', $1, 1, 0, now())", tid)


# ----------------------------------------------------------------------------- the triggers


async def owner_delete(pg, sql, tenant_id, *, flag_for=None):
    async with pg.owner.acquire() as conn, conn.transaction():
        await conn.execute("SELECT set_config('app.tenant_id', $1, true)", tenant_id)
        if flag_for is not None:
            await conn.execute("SELECT set_config('app.offboarding_tenant', $1, true)", flag_for)
        return await conn.execute(sql)


@pytest.mark.parametrize(
    "table",
    [
        "tenant_golden_examples",
        "tenant_golden_sets",
        "tenant_calibration_scores",
        "tenant_calibration_outcomes",
    ],
)
async def test_the_content_tables_still_refuse_a_delete_unless_the_tenant_is_terminated_and_named(
    pg, table
):
    active = await tenant(pg, "active-co")
    done = await tenant(pg, "done-co", terminate=True)
    sql = f"DELETE FROM {table} WHERE tenant_id = '%s'"
    # No setting: refused, whatever the tenant's status.
    for t in (active, done):
        with pytest.raises(RESTRICT):
            await owner_delete(pg, sql % t, t)
    # The setting names an active tenant: the database checks the status itself and refuses.
    with pytest.raises(RESTRICT):
        await owner_delete(pg, sql % active, active, flag_for=active)
    # The setting names another tenant: refused for this one.
    with pytest.raises(RESTRICT):
        await owner_delete(pg, sql % done, done, flag_for=active)
    # A terminated tenant that is named: the one carve-out (examples before their sets).
    if table == "tenant_golden_sets":
        await owner_delete(pg, "DELETE FROM tenant_golden_examples", done, flag_for=done)
    await owner_delete(pg, sql % done, done, flag_for=done)
    assert (await pg.counts(done))[table] == 0
    assert (await pg.counts(active))[table] == expected()[table]


@pytest.mark.parametrize(
    "table",
    [
        "tenant_golden_audit",
        "tenant_calibration_audit",
        "tenant_draft_audit",
        "tenant_publish_audit",
        "tenant_tool_audit",
        "escalation_audit",
        "tenant_approval_audit",
        "tenant_approvals",
        "policy_bundle_versions",
        "tenant_directory_audit",
        "offboarding_receipts",
        "offboarding_completions",
        "offboarding_usage_summaries",
    ],
)
async def test_class_a_tables_can_not_be_deleted_even_for_a_terminated_named_tenant(pg, table):
    done = await tenant(pg, terminate=True)
    await OffboardingJob(pg.off, clock=lambda: pg.at(1)).run_once()  # a completion exists now
    with pytest.raises((RESTRICT, DENIED)):
        await owner_delete(pg, f"DELETE FROM {table}", done, flag_for=done)
    with pytest.raises((RESTRICT, DENIED)):
        await owner_delete(pg, f"UPDATE {table} SET tenant_id = tenant_id", done, flag_for=done)


async def test_receipts_and_completions_are_append_only_for_everyone(pg):
    done = await tenant(pg, terminate=True)
    await OffboardingJob(pg.off, clock=lambda: pg.at(1)).run_once()
    for table in (
        "offboarding_receipts",
        "offboarding_completions",
        "offboarding_usage_summaries",
    ):
        for statement in (
            f"UPDATE {table} SET tenant_id = tenant_id",
            f"DELETE FROM {table}",
            f"TRUNCATE {table}",
        ):
            with pytest.raises(RESTRICT):
                await pg.owner.execute(statement)
    assert await pg.owner.fetchval("SELECT count(*) FROM offboarding_completions") == 1
    assert done


async def test_a_terminating_or_terminated_tenant_can_not_go_back(pg):
    tid = await tenant(pg, terminate=True)
    for status in ("active", "suspended", "offboarded", "terminating"):
        with pytest.raises(RESTRICT):
            await pg.admin.execute(
                f"UPDATE \"{pg.schema}\".tenants SET status = '{status}' WHERE tenant_id = $1", tid
            )
    with pytest.raises(RESTRICT):
        await pg.admin.execute(f'DELETE FROM "{pg.schema}".tenants WHERE tenant_id = $1', tid)
    stuck = await tenant(pg, "stuck-co")

    async def crash(_):
        raise RuntimeError("stopped")

    pg.prov._sleep = crash
    with pytest.raises(RuntimeError):
        await pg.prov.terminate(OPS, stuck, "contract ended")
    for status in ("active", "suspended", "offboarded"):
        with pytest.raises(RESTRICT):
            await pg.admin.execute(
                f"UPDATE \"{pg.schema}\".tenants SET status = '{status}' WHERE tenant_id = $1",
                stuck,
            )
    await pg.admin.execute(
        f"UPDATE \"{pg.schema}\".tenants SET status = 'terminated' WHERE tenant_id = $1", stuck
    )


async def test_the_status_check_names_the_two_new_words_and_no_others(pg):
    insert = (
        f'INSERT INTO "{pg.schema}".tenants (tenant_id, slug, domain, tier, status, version) '
        "VALUES ($1, $2, 'insurance', 'standard', $3, 1)"
    )
    for i, status in enumerate(("active", "terminating", "terminated")):
        await pg.admin.execute(insert, f"t_ok{i}", f"ok-{i}", status)
    with pytest.raises(asyncpg.CheckViolationError):
        await pg.admin.execute(insert, "t_gone1", "gone", "gone")


# ----------------------------------------------------------------------------- rows that remain


async def test_a_row_another_run_holds_is_skipped_and_completion_waits_for_it(pg):
    tid = await tenant(pg, terminate=True, records=6)
    holder = await pg.owner.acquire()
    tx = holder.transaction()
    await tx.start()
    try:
        await holder.execute("SELECT set_config('app.tenant_id', $1, true)", tid)
        await holder.fetch(
            "SELECT id FROM decision_records WHERE tenant_id = $1 ORDER BY id LIMIT 2 FOR UPDATE",
            tid,
        )  # two records locked by someone else
        n = await pg.retention_pool.fetchval(DELETE_BATCH, "r1", tid, "decision_records", 100, 1)
        assert n == 4  # skipped the two it could not lock, did not wait
        assert (
            await pg.retention_pool.fetchval("SELECT offboarding_complete('r1', $1, now())", tid)
            == "remaining"
        )
    finally:
        await tx.rollback()
        await pg.owner.release(holder)
    rest = await pg.retention_pool.fetchval(DELETE_BATCH, "r2", tid, "decision_records", 100, 1)
    assert rest == 2


async def test_every_table_alone_blocks_completion(pg):
    """Per table: leave only that table's rows (and a child's parent, where a foreign key says
    so) and the database says ``remaining``; then finish it and it completes."""
    for i, table in enumerate(ALL_TABLES):
        tid = await tenant(pg, f"c-{i}", terminate=True)
        for other in ALL_TABLES:
            parent_of_kept = (table, other) in {
                ("tenant_golden_examples", "tenant_golden_sets"),
                ("decision_record_rules", "decision_records"),  # records cascade to their rules
            }
            if other != table and not parent_of_kept:
                while await pg.retention_pool.fetchval(DELETE_BATCH, "r", tid, other, 1000, 2):
                    pass
        outcome = await pg.retention_pool.fetchval(
            "SELECT offboarding_complete('r', $1, now())", tid
        )
        assert outcome == "remaining", table
        for other in (table, "tenant_golden_sets", "decision_records"):
            while await pg.retention_pool.fetchval(DELETE_BATCH, "r", tid, other, 1000, 2):
                pass
        assert (
            await pg.retention_pool.fetchval("SELECT offboarding_complete('r', $1, now())", tid)
            == "completed"
        ), table


async def test_the_pending_list_is_the_unfinished_terminated_and_terminating_only(pg):
    active = await tenant(pg, "active-co")
    done = await tenant(pg, "done-co", terminate=True)
    other = await tenant(pg, "other-co", terminate=True)
    await OffboardingJob(pg.off, clock=lambda: pg.at(1)).run_once()
    assert await pg.off.pending() == []
    assert await pg.off.completion(done) is not None and await pg.off.completion(other)
    assert active not in {p.tenant_id for p in await pg.off.pending()}


async def test_two_jobs_racing_on_one_tenant_leave_one_completion(pg):
    tid = await tenant(pg, terminate=True, records=30)
    await asyncio.gather(
        *(OffboardingJob(pg.off, clock=lambda: pg.at(1), batch_size=4).run_once() for _ in range(5))
    )
    assert await pg.owner.fetchval("SELECT count(*) FROM offboarding_completions") == 1
    assert (await pg.off.completion(tid)).counts_by_class["B"] > 0


# ----------------------------------------------------------------------------- the class map


async def test_every_table_with_a_tenant_column_is_classified(pg):
    """The catalog's own list: a table that holds a tenant's rows is either deleted at
    offboarding or class A and kept. A new table fails here until it is put in one list."""
    rows = await pg.owner.fetch(
        "SELECT DISTINCT c.table_name FROM information_schema.columns c "
        "JOIN information_schema.tables t ON t.table_schema = c.table_schema "
        "AND t.table_name = c.table_name AND t.table_type = 'BASE TABLE' "
        "WHERE c.table_schema = $1 AND c.column_name = 'tenant_id'",
        pg.schema,
    )
    with_tenant = {r["table_name"] for r in rows}
    classified = set(DELETED_TABLES) | set(CLASS_A_TABLES)
    assert with_tenant - classified == set(), "unclassified tenant tables"
    all_tables = {
        r["table_name"]
        for r in await pg.owner.fetch(
            "SELECT table_name FROM information_schema.tables "
            "WHERE table_schema = $1 AND table_type = 'BASE TABLE'",
            pg.schema,
        )
    }
    assert classified - all_tables == set(), "a classified table that does not exist"
    assert not (set(DELETED_TABLES) & set(CLASS_A_TABLES))
    # The receipts table accepts exactly the names the Python lists.
    check = await pg.owner.fetchval(
        "SELECT pg_get_constraintdef(oid) FROM pg_constraint "
        "WHERE conrelid = 'offboarding_receipts'::regclass AND contype = 'c' "
        "AND pg_get_constraintdef(oid) LIKE '%table_name%'"
    )
    assert {n for n in RECEIPT_TABLES if f"'{n}'" in check} == set(RECEIPT_TABLES)
    # Every data table the functions delete has a trigger-free or carved-out DELETE path.
    assert set(DELETED_TABLES) == set(ALL_TABLES)


async def test_apply_schema_twice_keeps_the_carve_out(pg):
    """The migrations re-run (010 and 020 recreate the strict triggers, 043 replaces them): the
    last word is still the carve-out, and the job still works."""
    from guardrail_engine.store.adapters.postgres import apply_schema

    await apply_schema(pg.owner)
    tid = await tenant(pg, terminate=True)
    await OffboardingJob(pg.off, clock=lambda: pg.at(1)).run_once()
    assert await pg.counts(tid) == dict.fromkeys(ALL_TABLES, 0)
