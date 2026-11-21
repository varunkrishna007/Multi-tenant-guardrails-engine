"""M2-01 row-level security (006, 007): tenant isolation in the database itself.

``app_pool`` connects as a non-owner, non-superuser role (a superuser bypasses RLS, so the
isolation tests must not run as one). Needs GUARDRAIL_TEST_PG_DSN; skipped without it.
"""

import uuid

import asyncpg
import pytest
from policy_fixtures import make_catalog
from store_harness import ACME, OTHER, PostgresHarness, make_bundle

from guardrail_engine.store.adapters.postgres import (
    PostgresPolicyStore,
    apply_app_role_grants,
    apply_operator_policy,
)
from guardrail_engine.store.port import ScopeMismatchError, TenantSettingLeakError
from guardrail_engine.tenant_scope import issue_scope

DENIED = (asyncpg.InsufficientPrivilegeError, asyncpg.exceptions.DataError)


@pytest.fixture
async def seeded(pg_env, app_pool):
    """ACME@1 (active) and OTHER@1 (active) written through the tenant-scoped store."""
    store = PostgresHarness(app_pool).store()
    for tenant in (ACME, OTHER):
        bundle, bundle_hash = make_bundle(tenant, 1)
        await store.put_version(tenant, bundle, bundle_hash=bundle_hash)
        await store.set_active_version(tenant, 1)
    return store


async def scoped(pool, tenant, sql, *args):
    """Run ``sql`` in a transaction whose app.tenant_id is ``tenant`` (None: left unset)."""
    async with pool.acquire() as conn, conn.transaction():
        if tenant is not None:
            await conn.execute("SELECT set_config('app.tenant_id', $1, true)", tenant)
        return await conn.fetch(sql, *args)


async def test_a_query_under_one_tenants_setting_returns_none_of_the_others_rows(seeded, app_pool):
    mine = await scoped(app_pool, ACME, "SELECT tenant_id FROM policy_bundle_versions")
    assert {r["tenant_id"] for r in mine} == {ACME}
    pointers = await scoped(app_pool, ACME, "SELECT tenant_id FROM policy_active_versions")
    assert {r["tenant_id"] for r in pointers} == {ACME}


@pytest.mark.parametrize("table", ["policy_bundle_versions", "policy_active_versions"])
async def test_a_forged_tenant_filter_still_returns_nothing(seeded, app_pool, table):
    forged = await scoped(
        app_pool, ACME, f"SELECT * FROM {table} WHERE tenant_id = $1 OR true OR tenant_id = $1",
        OTHER,
    )  # fmt: skip
    assert {r["tenant_id"] for r in forged} <= {ACME}
    only = await scoped(app_pool, ACME, f"SELECT * FROM {table} WHERE tenant_id = $1", OTHER)
    assert only == []


@pytest.mark.parametrize("setting", [None, "", "t_nosuch"])
async def test_without_a_matching_setting_no_row_is_visible(seeded, app_pool, setting):
    rows = await scoped(app_pool, setting, "SELECT * FROM policy_bundle_versions")
    assert rows == []


async def test_a_write_for_another_tenant_is_refused_by_the_policy(seeded, app_pool):
    bundle, bundle_hash = make_bundle(OTHER, 2)
    document = bundle.canonical_document.decode()
    async with app_pool.acquire() as conn, conn.transaction():
        await conn.execute("SELECT set_config('app.tenant_id', $1, true)", ACME)
        with pytest.raises(asyncpg.InsufficientPrivilegeError):  # WITH CHECK violation
            await conn.execute(
                "INSERT INTO policy_bundle_versions (tenant_id, version, document, bundle_hash) "
                "VALUES ($1, 2, $2, $3)",
                OTHER, document, bundle_hash,
            )  # fmt: skip


async def test_moving_another_tenants_pointer_changes_nothing(seeded, app_pool, pg_pool):
    bundle, bundle_hash = make_bundle(OTHER, 2)
    await PostgresHarness(pg_pool).store().put_version(OTHER, bundle, bundle_hash=bundle_hash)
    async with app_pool.acquire() as conn, conn.transaction():
        await conn.execute("SELECT set_config('app.tenant_id', $1, true)", ACME)
        status = await conn.execute(
            "UPDATE policy_active_versions SET version = 2 WHERE tenant_id = $1", OTHER
        )
    assert status == "UPDATE 0"
    assert (
        await pg_pool.fetchval(
            "SELECT version FROM policy_active_versions WHERE tenant_id = $1", OTHER
        )
        == 1
    )


async def test_the_store_serves_each_tenant_only_its_own_data(seeded):
    assert (await seeded.load_active(ACME)).tenant_id == ACME
    assert (await seeded.load_active(OTHER)).tenant_id == OTHER
    assert [v.version for v in await seeded.list_versions(ACME)] == [1]
    assert await seeded.get_active_version("t_nosuch") is None


async def test_the_setting_is_per_transaction_and_does_not_leak_between_checks(seeded, app_pool):
    await scoped(app_pool, ACME, "SELECT 1")
    leaked = await app_pool.fetch("SELECT * FROM policy_bundle_versions")  # no setting now
    assert leaked == []


async def test_a_tenant_id_that_looks_like_sql_is_a_value_not_a_statement(seeded, app_pool):
    hostile = "t_x'); DROP TABLE policy_bundle_versions; --"
    rows = await scoped(app_pool, hostile, "SELECT * FROM policy_bundle_versions")
    assert rows == []
    assert len(await scoped(app_pool, ACME, "SELECT * FROM policy_bundle_versions")) == 1


async def test_rls_is_enabled_and_forced_on_both_policy_tables(pg_pool):
    rows = await pg_pool.fetch(
        "SELECT relname, relrowsecurity, relforcerowsecurity FROM pg_class "
        "WHERE relname IN ('policy_bundle_versions', 'policy_active_versions') "
        "AND relnamespace = current_schema()::regnamespace"
    )
    assert len(rows) == 2 and all(r[1] and r[2] for r in rows)
    other = await pg_pool.fetch(
        "SELECT relrowsecurity FROM pg_class WHERE relname = 'tenants' "
        "AND relnamespace = current_schema()::regnamespace"
    )
    assert other[0][0] is False  # the directory is platform data, not tenant-scoped


async def test_the_operator_role_sees_every_tenant_and_the_app_role_still_does_not(
    seeded, pg_env, app_pool
):
    role, password = f"m201_op_{uuid.uuid4().hex[:12]}", uuid.uuid4().hex
    await pg_env.pool.execute(f"CREATE ROLE \"{role}\" LOGIN PASSWORD '{password}'")
    pool = None
    try:
        await pg_env.pool.execute(f'GRANT USAGE ON SCHEMA "{pg_env.schema}" TO "{role}"')
        await apply_app_role_grants(pg_env.pool, role)
        await apply_operator_policy(pg_env.pool, role)
        pool = await asyncpg.create_pool(
            pg_env.dsn, user=role, password=password, min_size=1, max_size=2,
            server_settings={"search_path": pg_env.schema},
        )  # fmt: skip
        seen = await pool.fetch("SELECT DISTINCT tenant_id FROM policy_bundle_versions")
        assert {r[0] for r in seen} == {ACME, OTHER}
        assert await app_pool.fetch("SELECT * FROM policy_bundle_versions") == []
    finally:
        if pool is not None:
            await pool.close()
        await pg_env.pool.execute(f'DROP OWNED BY "{role}"')
        await pg_env.pool.execute(f'DROP ROLE "{role}"')


async def test_the_operator_policy_needs_a_role_name(pg_pool):
    with pytest.raises(ValueError, match="role name"):
        await apply_operator_policy(pg_pool, "")


# ---- the RLS setting comes from the verified scope, not from the call's argument


async def test_a_scope_for_one_tenant_cannot_read_another_through_the_store_api(seeded, app_pool):
    """Probed ``list_versions(OTHER)`` on the app role and got OTHER's rows."""
    store = PostgresPolicyStore(app_pool, catalog=make_catalog())
    acme = store.scoped(issue_scope(ACME))
    assert [v.version for v in await acme.list_versions(ACME)] == [1]
    for call in (
        acme.list_versions(OTHER),
        acme.get_active_version(OTHER),
        acme.load_active(OTHER),
        acme.get_version(OTHER, 1),
        acme.set_active_version(OTHER, 1),
    ):
        with pytest.raises(ScopeMismatchError):
            await call


async def test_a_scope_cannot_store_a_version_for_another_tenant(seeded, app_pool):
    store = PostgresPolicyStore(app_pool, catalog=make_catalog())
    bundle, bundle_hash = make_bundle(OTHER, 2)
    with pytest.raises(ScopeMismatchError):
        await store.scoped(issue_scope(ACME)).put_version(OTHER, bundle, bundle_hash=bundle_hash)


def test_the_postgres_store_has_no_tenant_methods_of_its_own(app_pool):
    """Only ``scoped`` is public, so no caller can pass a bare tenant id to the database."""
    store = PostgresPolicyStore(app_pool, catalog=make_catalog())
    assert {n for n in dir(store) if not n.startswith("_")} == {"scoped"}
    with pytest.raises(TypeError):
        store.scoped(ACME)  # a string is not a scope


# ---- a connection that still carries a tenant setting is refused


async def test_a_connection_that_comes_with_a_tenant_setting_is_refused(pg_env):
    async def leave_a_setting(conn):  # what a custom reset or a session pooler could do
        await conn.execute("SELECT set_config('app.tenant_id', 't_leaked', false)")

    pool = await asyncpg.create_pool(
        pg_env.dsn,
        min_size=1,
        max_size=1,
        setup=leave_a_setting,
        server_settings={"search_path": pg_env.schema},
    )
    try:
        store = PostgresPolicyStore(pool, catalog=make_catalog())
        with pytest.raises(TenantSettingLeakError):
            await store.scoped(issue_scope(ACME)).list_versions(ACME)
    finally:
        await pool.close()
