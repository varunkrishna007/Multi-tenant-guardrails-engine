"""The engine refuses to start on a Postgres role that row-level security would not
bind: a superuser, BYPASSRLS, a table owner, or a member of the operator role. Needs
GUARDRAIL_TEST_PG_DSN (and a DSN role allowed to create roles); skipped without it."""

import sys
import tempfile
import uuid
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "engine"))  # engine_fixtures
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "guard"))  # guard_fixtures

from engine_fixtures import directory, settings, verifier

from guardrail_engine.decision import FakeDecisionModel
from guardrail_engine.engine import SettingsError, build_engine
from guardrail_engine.store.adapters.postgres import app_role_problems


async def pool_as(pg_env, role, password):
    import asyncpg

    return await asyncpg.create_pool(
        pg_env.dsn,
        user=role,
        password=password,
        min_size=1,
        max_size=1,
        server_settings={"search_path": pg_env.schema},
    )


async def test_the_least_privilege_application_role_has_no_problems(app_pool):
    assert await app_role_problems(app_pool) == []


async def test_the_owner_role_is_refused(pg_pool):
    problems = await app_role_problems(pg_pool)
    assert any("owns" in p for p in problems)  # the DSN role created the schema's tables


async def test_a_bypassrls_role_is_refused(pg_env):
    role, password = f"m201_bypass_{uuid.uuid4().hex[:12]}", uuid.uuid4().hex
    await pg_env.pool.execute(f"CREATE ROLE \"{role}\" LOGIN BYPASSRLS PASSWORD '{password}'")
    try:
        await pg_env.pool.execute(f'GRANT USAGE ON SCHEMA "{pg_env.schema}" TO "{role}"')
        pool = await pool_as(pg_env, role, password)
        try:
            assert any("BYPASSRLS" in p for p in await app_role_problems(pool))
        finally:
            await pool.close()
    finally:
        await pg_env.pool.execute(f'DROP OWNED BY "{role}"')
        await pg_env.pool.execute(f'DROP ROLE "{role}"')


async def test_a_role_that_inherits_bypassrls_is_refused(pg_env, app_pool):
    me = await app_pool.fetchval("SELECT current_user")
    parent = f"m201_parent_{uuid.uuid4().hex[:12]}"
    await pg_env.pool.execute(f'CREATE ROLE "{parent}" NOLOGIN BYPASSRLS')
    try:
        await pg_env.pool.execute(f'GRANT "{parent}" TO "{me}"')
        assert any("BYPASSRLS" in p for p in await app_role_problems(app_pool))
    finally:
        await pg_env.pool.execute(f'REVOKE "{parent}" FROM "{me}"')
        await pg_env.pool.execute(f'DROP ROLE "{parent}"')


async def test_membership_in_the_operator_role_is_refused(pg_env, app_pool):
    me = await app_pool.fetchval("SELECT current_user")
    operator = f"m201_operator_{uuid.uuid4().hex[:12]}"
    await pg_env.pool.execute(f'CREATE ROLE "{operator}" NOLOGIN')
    try:
        assert await app_role_problems(app_pool, operator_role=operator) == []
        await pg_env.pool.execute(f'GRANT "{operator}" TO "{me}"')
        problems = await app_role_problems(app_pool, operator_role=operator)
        assert any("operator role" in p for p in problems)
        assert await app_role_problems(app_pool) == []  # not named: not checked
    finally:
        await pg_env.pool.execute(f'REVOKE "{operator}" FROM "{me}"')
        await pg_env.pool.execute(f'DROP ROLE "{operator}"')


async def test_a_role_that_does_not_exist_is_no_membership(app_pool):
    assert await app_role_problems(app_pool, operator_role="m201_no_such_role") == []


async def build(environment, pool, operator_pool=None):
    # A production engine with a Postgres store needs somewhere to spill regulated tenants'
    # decision records (M7-04).
    spill_dir = Path(tempfile.mkdtemp())
    spill_dir.chmod(0o700)
    return await build_engine(
        settings(
            environment,
            store={"kind": "postgres", "operator_role": "m202_operator"},
            decision_spill={"file": str(spill_dir / "spill.jsonl")},
        ),
        verifier=verifier(), tenants=directory(), model=FakeDecisionModel(), pg_pool=pool,
        pg_operator_pool=operator_pool,
    )  # fmt: skip


async def test_production_refuses_to_start_on_the_owner_role_and_names_no_credentials(pg_pool):
    with pytest.raises(SettingsError) as info:
        await build("production", pg_pool)
    assert "store:" in str(info.value) and "policy table" in str(info.value)
    assert "postgresql://" not in str(info.value)


async def test_production_starts_on_the_least_privilege_role(app_pool, operator_pool):
    """With an operator pool: the startup check of the pack versions the stored bundles name
    must be able to ask, and a production engine that can't ask does not start."""
    engine = await build("production", app_pool, operator_pool)
    try:
        assert type(engine.store).__name__ == "PostgresPolicyStore"
    finally:
        await engine.shutdown()


async def test_test_environment_only_warns(pg_pool, caplog):
    engine = await build("test", pg_pool)
    try:
        assert "not held to row-level security" in caplog.text
    finally:
        await engine.shutdown()


async def test_production_without_an_operator_pool_does_not_start_for_want_of_the_pack_check(
    app_pool,
):
    from guardrail_engine.engine.factory import EngineStartError

    with pytest.raises(EngineStartError, match="could not be checked"):
        await build("production", app_pool)
