"""Every engine test starts with no API key and no engine DSN in the environment, so none can
pick up a real secret. A test that needs one sets a sentinel with ``monkeypatch``. (The
store tests' ``GUARDRAIL_TEST_PG_DSN`` is left alone: the one real-database test is skipped
without it.)"""

import pytest
from engine_fixtures import LocalDecisionsServer

from guardrail_engine.engine import API_KEY_ENV, PG_DSN_ENV


@pytest.fixture(autouse=True)
def _no_secrets_or_proxies(monkeypatch):
    for name in (API_KEY_ENV, PG_DSN_ENV):
        monkeypatch.delenv(name, raising=False)
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.delenv("all_proxy", raising=False)


@pytest.fixture(autouse=True)
def _pools_here_are_stand_ins(monkeypatch):
    """The engine tests that build a Postgres store use stand-in pools, which can't answer the
    role check. The check itself is tested against a real database in
    ``tests/store/test_store_app_role_check.py``."""

    async def no_problems(pool, *, operator_role=None):
        return []

    monkeypatch.setattr("guardrail_engine.store.adapters.postgres.app_role_problems", no_problems)

    async def in_memory_bus(pool):
        from guardrail_engine.admin.lifecycle import InMemoryPublishBus

        return InMemoryPublishBus()  # a stand-in pool can't LISTEN

    monkeypatch.setattr("guardrail_engine.engine.factory._start_postgres_bus", in_memory_bus)

    def in_memory_platform(pool):
        from guardrail_engine.admin.floors import InMemoryPlatformStore

        return InMemoryPlatformStore()

    monkeypatch.setattr("guardrail_engine.engine.factory._postgres_platform", in_memory_platform)


@pytest.fixture
async def server():
    """A local Decisions API stand-in on 127.0.0.1 (real sockets)."""
    srv = LocalDecisionsServer()
    await srv.start()
    yield srv
    await srv.stop()
