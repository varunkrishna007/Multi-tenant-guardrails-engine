# ruff: noqa: F811  (the imported fixture is used by name)
"""M5-03 stored content on Postgres (migrations 047 to 050): forced row-level security, an
insert-only table, the 90-day CHECK, the class C deletion function (hardened) and the
roles' privileges. Needs ``GUARDRAIL_TEST_PG_DSN``."""

from datetime import UTC, datetime, timedelta

import asyncpg
import pytest
from test_m4_05_escalation_store import pg_stores  # noqa: F401  (a fixture)

from guardrail_engine.content.adapters.postgres import PostgresClassCStore, PostgresStoredContent
from guardrail_engine.content.model import StoredContent
from guardrail_engine.retention.store import RetentionError
from guardrail_engine.tenant_scope import issue_scope

ACME, OTHER = "t_acmeins", "t_otherco"
SHA = "sha256:" + "ab" * 32


def row(tenant=ACME, rid="r1", *, ts=None, days=30, content="kept text", **kw):
    ts = ts or datetime.now(UTC)
    return StoredContent(
        tenant, rid, "output", ts, ts + timedelta(days=days), content, False, SHA, 1, **kw
    )


async def as_tenant(pool, tenant, sql, *args):
    async with pool.acquire() as conn, conn.transaction():
        if tenant:
            await conn.execute("SELECT set_config('app.tenant_id', $1, true)", tenant)
        return await conn.fetch(sql, *args)


async def test_a_batch_round_trips_per_tenant_and_a_read_sees_only_its_tenant(pg_stores):
    store = PostgresStoredContent(pg_stores.app_pool)
    await store.append_many([row(ACME, "a1"), row(OTHER, "o1", content="theirs"), row(ACME, "a2")])
    got = await store.get(issue_scope(ACME), "a1", None)
    assert [(r.content, r.guard_point, r.content_sha256, r.bundle_version) for r in got] == [
        ("kept text", "output", SHA, 1)
    ]
    assert await store.get(issue_scope(ACME), "o1", None) == []  # another tenant's request id
    assert [r.content for r in await store.get(issue_scope(OTHER), "o1", "output")] == ["theirs"]
    assert await store.get(issue_scope(OTHER), "o1", "input") == []


async def test_a_row_past_its_own_time_is_not_returned_even_before_the_job_deletes_it(pg_stores):
    store = PostgresStoredContent(pg_stores.app_pool)
    now = datetime.now(UTC)
    await store.append_many(
        [row(ACME, "old", ts=now - timedelta(days=40), days=30), row(ACME, "new", ts=now)]
    )
    assert await store.get(issue_scope(ACME), "old", None) == []
    assert len(await store.get(issue_scope(ACME), "new", None)) == 1
    assert len(await as_tenant(pg_stores.app_pool, ACME, "SELECT 1 FROM stored_content")) == 2


async def test_the_database_enforces_isolation_and_the_insert_only_rule(pg_stores):
    s = pg_stores
    await PostgresStoredContent(s.app_pool).append_many([row(ACME), row(OTHER, "o1")])
    # forced row-level security: no setting, no rows; a tenant's setting, its rows only
    assert await as_tenant(s.app_pool, None, "SELECT request_id FROM stored_content") == []
    assert [
        r["request_id"]
        for r in await as_tenant(s.app_pool, ACME, "SELECT request_id FROM stored_content")
    ] == ["r1"]
    # another tenant's row can't be written, however the setting is named
    with pytest.raises(asyncpg.PostgresError):
        await as_tenant(
            s.app_pool, ACME,
            "INSERT INTO stored_content (tenant_id, request_id, guard_point, ts, retain_until, "
            "content, content_sha256) VALUES ($1, 'x', 'output', now(), now() + interval '1 day', "
            "'c', $2)",
            OTHER, SHA,
        )  # fmt: skip
    # no UPDATE, DELETE or TRUNCATE for the service's role, whatever the tenant setting
    for sql in (
        "UPDATE stored_content SET content = 'x'",
        "DELETE FROM stored_content",
        "TRUNCATE stored_content",
    ):
        with pytest.raises(asyncpg.PostgresError):
            await as_tenant(s.app_pool, ACME, sql)
    # nor may the service's role call the deletion function
    with pytest.raises(asyncpg.InsufficientPrivilegeError):
        await s.app_pool.fetchval("SELECT retention_delete_class_c('run', $1, now(), 10, 1)", ACME)
    # and a trigger refuses an UPDATE even from the owner
    with pytest.raises(asyncpg.RestrictViolationError):
        await as_tenant(s.pg_env.pool, ACME, "UPDATE stored_content SET content = 'x'")


@pytest.mark.parametrize(
    "interval",
    ["interval '91 days'", "interval '0 days'", "interval '-1 day'"],
)
async def test_no_row_can_be_written_to_live_longer_than_ninety_days_or_not_at_all(
    pg_stores, interval
):
    with pytest.raises(asyncpg.CheckViolationError):
        await as_tenant(
            pg_stores.app_pool, ACME,
            "INSERT INTO stored_content (tenant_id, request_id, guard_point, ts, retain_until, "
            f"content, content_sha256) VALUES ($1, 'x', 'output', now(), now() + {interval}, "
            "'c', $2)",
            ACME, SHA,
        )  # fmt: skip


async def test_the_retention_role_lists_tenants_and_deletes_only_through_the_function(pg_stores):
    s = pg_stores
    await PostgresStoredContent(s.app_pool).append_many([row(ACME), row(OTHER, "o1")])
    job_store = PostgresClassCStore(s.ret_pool)
    assert await job_store.class_c_tenants() == [ACME, OTHER]
    # it can read no content, and delete nothing directly
    with pytest.raises(asyncpg.InsufficientPrivilegeError):
        await s.ret_pool.fetch("SELECT content FROM stored_content")
    with pytest.raises(asyncpg.InsufficientPrivilegeError):
        await s.ret_pool.execute("DELETE FROM stored_content")


async def test_the_deletion_function_is_strict_scoped_receipted_and_bounded(pg_stores):
    s = pg_stores
    now = datetime.now(UTC)
    await PostgresStoredContent(s.app_pool).append_many(
        [
            row(ACME, "due", ts=now - timedelta(days=40), days=30),
            row(ACME, "live", ts=now),
            row(OTHER, "theirs", ts=now - timedelta(days=40), days=30),
        ]
    )
    store = PostgresClassCStore(s.ret_pool)
    # a cutoff before the row's time: nothing, and the receipt still says it looked (batch 1)
    n = await store.delete_class_c_batch(
        run_id="run-1", tenant_id=ACME, now=now - timedelta(days=11), limit=10, batch=1
    )
    assert n == 0
    n = await store.delete_class_c_batch(run_id="run-2", tenant_id=ACME, now=now, limit=10, batch=1)
    assert n == 1  # 'due' only: 'live' is in term, and the other tenant's row is untouched
    remaining = await s.pg_env.pool.fetch(
        "SELECT tenant_id, request_id FROM stored_content ORDER BY 1, 2"
    )
    assert [(r["tenant_id"], r["request_id"]) for r in remaining] == [
        (ACME, "live"),
        (OTHER, "theirs"),
    ]
    # a later batch that deletes nothing writes no receipt; batch 1 always does
    await store.delete_class_c_batch(run_id="run-2", tenant_id=ACME, now=now, limit=10, batch=2)
    receipts = await store.receipts("run-2")
    shown = [(r.tenant_id, r.retention_class, r.deleted_count, r.batch, r.source) for r in receipts]
    assert shown == [(ACME, "C", 1, 1, "row")]
    assert [r.deleted_count for r in await store.receipts("run-1")] == [0]
    # the clock: ahead of the database is refused; bounds are refused by both stores
    with pytest.raises(RetentionError):
        await store.delete_class_c_batch(
            run_id="r", tenant_id=ACME, now=now + timedelta(hours=1), limit=10, batch=1
        )
    with pytest.raises(RetentionError):
        await store.delete_class_c_batch(run_id="r", tenant_id=ACME, now=now, limit=0, batch=1)
    with pytest.raises(RetentionError):  # a bad tenant id is the database's own refusal
        await store.delete_class_c_batch(run_id="r", tenant_id="bad", now=now, limit=1, batch=1)


async def test_the_function_pins_its_search_path_and_qualifies_its_tables(pg_stores):
    """SECURITY DEFINER, ``pg_temp`` last in the pinned path, every table qualified."""
    row_ = await pg_stores.pg_env.pool.fetchrow(
        "SELECT prosecdef, proconfig, prosrc FROM pg_proc "
        "WHERE proname = 'retention_delete_class_c'"
    )
    assert row_["prosecdef"] is True
    (config,) = [c for c in row_["proconfig"] if c.startswith("search_path=")]
    assert config.endswith("pg_temp") and "pg_catalog" in config
    assert f"{pg_stores.pg_env.schema}.stored_content" in row_["prosrc"].replace('"', "")
    assert " stored_content " not in row_["prosrc"].replace(
        f"{pg_stores.pg_env.schema}.stored_content", ""
    )


async def test_the_receipts_table_accepts_class_c_and_stays_append_only(pg_stores):
    await PostgresClassCStore(pg_stores.ret_pool).delete_class_c_batch(
        run_id="rr", tenant_id=ACME, now=datetime.now(UTC), limit=1, batch=1
    )
    with pytest.raises(asyncpg.RestrictViolationError):
        await pg_stores.pg_env.pool.execute("DELETE FROM retention_receipts WHERE run_id = 'rr'")


async def test_a_read_event_is_class_a_append_only_isolated_and_holds_no_content(pg_stores):
    from guardrail_engine.content.model import ContentReadEvent

    store = PostgresStoredContent(pg_stores.app_pool)
    event = ContentReadEvent(
        ACME, datetime.now(UTC), "https://idp/#rita", "req-1", "output", 2, False, False
    )
    await store.record_read(event)
    await store.record_read(
        ContentReadEvent(OTHER, datetime.now(UTC), "https://idp/#sam", "o1", None, 0, True, True)
    )
    mine = await as_tenant(pg_stores.app_pool, ACME, "SELECT * FROM stored_content_audit")
    assert [(r["actor"], r["request_id"], r["guard_point"], r["items"]) for r in mine] == [
        ("https://idp/#rita", "req-1", "output", 2)
    ]
    assert "content" not in dict(mine[0])
    assert await as_tenant(pg_stores.app_pool, None, "SELECT 1 FROM stored_content_audit") == []
    for sql in (
        "UPDATE stored_content_audit SET actor = 'x'",
        "DELETE FROM stored_content_audit",
        "TRUNCATE stored_content_audit",
    ):
        with pytest.raises(asyncpg.PostgresError):
            await as_tenant(pg_stores.app_pool, ACME, sql)
    with pytest.raises(asyncpg.PostgresError):  # another tenant's event can't be written
        await as_tenant(
            pg_stores.app_pool, ACME,
            "INSERT INTO stored_content_audit (tenant_id, at, actor, request_id, items, "
            "cross_tenant, operator) VALUES ($1, now(), 'a', 'r', 0, false, false)",
            OTHER,
        )  # fmt: skip
    with pytest.raises(asyncpg.RestrictViolationError):  # not even the owner may change one
        await as_tenant(pg_stores.pg_env.pool, ACME, "UPDATE stored_content_audit SET actor = 'x'")
