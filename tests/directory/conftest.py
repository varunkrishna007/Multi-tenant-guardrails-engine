"""Directory store fixtures: the in-memory store always, Postgres when GUARDRAIL_TEST_PG_DSN is
set (each test gets its own throwaway schema, as in tests/store/conftest.py)."""

import os
import sys
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "guard"))  # guard_fixtures
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "policy"))  # policy_fixtures

from guardrail_engine.directory import InMemoryDirectoryStore

PG_DSN_ENV = "GUARDRAIL_TEST_PG_DSN"


async def _throwaway_schema(dsn):
    import asyncpg

    from guardrail_engine.store.adapters.postgres import apply_schema

    schema = f"m201_{uuid.uuid4().hex}"
    admin = await asyncpg.connect(dsn)
    await admin.execute(f'CREATE SCHEMA "{schema}"')
    pool = await asyncpg.create_pool(
        dsn, min_size=1, max_size=4, server_settings={"search_path": schema}
    )
    await apply_schema(pool)
    return SimpleNamespace(dsn=dsn, schema=schema, pool=pool, admin=admin)


async def _drop(pg):
    await pg.pool.close()
    await pg.admin.execute(f'DROP SCHEMA "{pg.schema}" CASCADE')
    await pg.admin.close()


@pytest.fixture
async def pg():
    dsn = os.environ.get(PG_DSN_ENV)
    if not dsn:
        pytest.skip(f"{PG_DSN_ENV} is not set; Postgres directory tests need a database")
    env = await _throwaway_schema(dsn)
    try:
        yield env
    finally:
        await _drop(env)


@pytest.fixture(params=["memory", "postgres"])
async def store(request):
    if request.param == "memory":
        yield InMemoryDirectoryStore()
        return
    dsn = os.environ.get(PG_DSN_ENV)
    if not dsn:
        pytest.skip(f"{PG_DSN_ENV} is not set; Postgres directory tests need a database")
    from guardrail_engine.store.adapters.postgres import PostgresDirectoryStore

    env = await _throwaway_schema(dsn)
    try:
        yield PostgresDirectoryStore(env.pool)
    finally:
        await _drop(env)
