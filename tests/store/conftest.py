"""Fixtures for the policy store tests (M1-02).

``harness`` runs each contract test against both implementations. The Postgres one needs
``GUARDRAIL_TEST_PG_DSN`` and is skipped without it, so the default run stays offline. Each
Postgres test gets its own throwaway schema, so it never touches existing tables.

The DSN's role creates the schema and so owns the tables: it plays the migrations-only owner
role. ``app_pool`` connects as a separate least-privilege role set up by the grants script,
which is how the service is meant to connect.
"""

import os
import sys
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "policy"))  # policy_fixtures

from store_harness import MemoryHarness, PostgresHarness

PG_DSN_ENV = "GUARDRAIL_TEST_PG_DSN"


@dataclass
class PgEnv:
    dsn: str
    schema: str
    pool: Any  # asyncpg.Pool connected as the owner


@pytest.fixture
async def pg_env():
    dsn = os.environ.get(PG_DSN_ENV)
    if not dsn:
        pytest.skip(f"{PG_DSN_ENV} is not set; Postgres policy store tests need a database")
    import asyncpg

    from guardrail_engine.store.adapters.postgres import apply_schema

    schema = f"m102_{uuid.uuid4().hex}"
    admin = await asyncpg.connect(dsn)
    await admin.execute(f'CREATE SCHEMA "{schema}"')
    try:
        pool = await asyncpg.create_pool(
            dsn, min_size=1, max_size=8, server_settings={"search_path": schema}
        )
        try:
            await apply_schema(pool)
            yield PgEnv(dsn, schema, pool)
        finally:
            await pool.close()
    finally:
        await admin.execute(f'DROP SCHEMA "{schema}" CASCADE')
        await admin.close()


@pytest.fixture
def pg_pool(pg_env):
    return pg_env.pool


@pytest.fixture
async def app_pool(pg_env):
    """A pool connected as a non-owner application role that has only what
    ``002_app_role_grants.sql`` grants, plus USAGE on the test schema."""
    import asyncpg

    from guardrail_engine.store.adapters.postgres import apply_app_role_grants

    role = f"m102_app_{uuid.uuid4().hex}"
    password = uuid.uuid4().hex  # throwaway, for a role that lives for one test
    await pg_env.pool.execute(f"CREATE ROLE \"{role}\" LOGIN PASSWORD '{password}'")
    try:
        await pg_env.pool.execute(f'GRANT USAGE ON SCHEMA "{pg_env.schema}" TO "{role}"')
        await apply_app_role_grants(pg_env.pool, role)
        pool = await asyncpg.create_pool(
            pg_env.dsn,
            user=role,
            password=password,
            min_size=1,
            max_size=2,
            server_settings={"search_path": pg_env.schema},
        )
        try:
            yield pool
        finally:
            await pool.close()
    finally:
        await pg_env.pool.execute(f'DROP OWNED BY "{role}"')
        await pg_env.pool.execute(f'DROP ROLE "{role}"')


@pytest.fixture(params=["memory", "postgres"])
def harness(request):
    if request.param == "memory":
        return MemoryHarness()
    return PostgresHarness(request.getfixturevalue("pg_pool"))


@pytest.fixture
async def operator_pool(pg_env):
    """A pool connected as the platform operator's database role: it has the grants and the
    ``operator_all`` policies (007 and 014), and no tenant setting is needed."""
    import asyncpg

    from guardrail_engine.store.adapters.postgres import (
        apply_app_role_grants,
        apply_operator_policy,
    )

    role = f"m207_op_{uuid.uuid4().hex[:12]}"
    password = uuid.uuid4().hex
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
        yield pool
    finally:
        if pool is not None:
            await pool.close()
        await pg_env.pool.execute(f'DROP OWNED BY "{role}"')
        await pg_env.pool.execute(f'DROP ROLE "{role}"')
