"""M1-11: the factory builds the whole engine from one settings object. Model override,
coupled pool size, the connection-reuse hook, and the store choices."""

from __future__ import annotations

import os
import uuid

import httpx
import pytest
from engine_fixtures import (
    TENANT,
    adapter_settings,
    answer_everything,
    bundle,
    ctx,
    directory,
    real_catalog,
    settings,
    verifier,
)

import guardrail_engine.engine.factory as factory
from guardrail_engine.decision import FakeDecisionModel
from guardrail_engine.decision.adapters.gemini import CallInfo, ConnectionUse, GeminiDecisionModel
from guardrail_engine.engine import (
    INJECTED_MODEL_KEY_ID,
    EngineStartError,
    SettingsError,
    build_engine,
    ignore_connection_info,
)
from guardrail_engine.gateway import InFlightLimit
from guardrail_engine.guard import Decision, GuardService, InMemoryAuditSink, Reason
from guardrail_engine.store import InMemoryPolicyStore

KEY = "sentinel-not-a-real-key-m1-11"


def pool_size(model: GeminiDecisionModel) -> int:
    """Idle connections the adapter's own client keeps (httpcore's pool setting)."""
    return model._client._transport._pool._max_keepalive_connections


# ---------------------------------------------------------------------- the whole engine


async def test_builds_store_catalog_directory_gateway_and_guard_service_with_the_fake():
    fake = FakeDecisionModel()
    audit = InMemoryAuditSink()
    v = verifier()
    async with await build_engine(
        settings(), verifier=v, tenants=directory(), model=fake, audit=audit
    ) as engine:
        assert isinstance(engine.guard, GuardService)
        assert isinstance(engine.store, InMemoryPolicyStore)
        assert engine.catalog.floor(1) is not None
        assert engine.gateway.model_id == "fake-decision"
        await engine.bootstrap_publish(bundle())
        verdict = await engine.check(ctx(v), "output", "What does my policy cover?")
    assert verdict.decision is Decision.ALLOW and verdict.reason is Reason.POLICY
    assert verdict.tenant_id == TENANT
    assert len(fake.calls) == 1
    assert audit.verdicts == [verdict]


async def test_model_override_needs_no_key_and_no_network(monkeypatch):
    """The fake runs the engine with GEMINI_API_KEY unset and every socket refused."""
    assert "GEMINI_API_KEY" not in os.environ

    def no_network(*args, **kwargs):
        raise AssertionError("the engine opened a network connection")

    monkeypatch.setattr("socket.socket.connect", no_network)
    fake = FakeDecisionModel().timeout_next(2)  # the first try and the retry
    v = verifier()
    async with await build_engine(
        settings(), verifier=v, tenants=directory(), model=fake
    ) as engine:
        await engine.bootstrap_publish(bundle())
        verdict = await engine.check(ctx(v), "output", "Hello.")
    # The simulated failure card: the floor still blocks, reported as a model failure.
    assert verdict.decision is Decision.BLOCK and verdict.reason is Reason.MODEL_FAILURE
    assert engine.gateway.model_id == "fake-decision"


async def test_platform_and_guard_settings_reach_the_guard_service():
    """B1's ``floor_fail_mode`` is a setting: flipped to ``open`` in the one settings object,
    a model failure allows (``allow``/``model_failure``) with no code change."""
    v = verifier()
    s = settings(platform={"floor_fail_mode": "open"}, guard={"pointer_ttl_s": 7.0})
    fake = FakeDecisionModel().timeout_next(2)
    async with await build_engine(s, verifier=v, tenants=directory(), model=fake) as engine:
        assert engine.guard.policy_cache._pointer_ttl_s == 7.0
        await engine.bootstrap_publish(bundle())
        verdict = await engine.check(ctx(v), "output", "Hello.")
    assert verdict.decision is Decision.ALLOW and verdict.reason is Reason.MODEL_FAILURE
    assert verdict.floor_fail_mode == "open"


async def test_model_override_gets_a_constant_key_id():
    engine = await build_engine(settings(), verifier=verifier(), model=FakeDecisionModel())
    assert engine.gateway._key_id() == INJECTED_MODEL_KEY_ID
    await engine.shutdown()


async def test_without_a_model_the_key_must_be_in_the_environment():
    with pytest.raises(SettingsError, match=r"GEMINI_API_KEY: not set in the environment"):
        await build_engine(adapter_settings(), verifier=verifier())


async def test_builds_the_gemini_adapter_from_the_settings(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", KEY)
    s = adapter_settings(gemini={"model": "gemini-decision-1", "keepalive_expiry_s": 42.0})
    engine = await build_engine(s, verifier=verifier())
    try:
        assert isinstance(engine.model, GeminiDecisionModel)
        assert engine.gateway.model_id == "gemini-decision-1"
        pool = engine.model._client._transport._pool
        assert pool._keepalive_expiry == 42.0
        # The gateway identifies the key by fingerprint, never by the key.
        key_id = engine.gateway._key_id()
        assert key_id.startswith("sha256:") and KEY not in key_id
    finally:
        await engine.shutdown()
    assert engine.model._client.is_closed  # the adapter's own client: closed at shutdown


async def test_injected_http_client_is_used_and_borrowed(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", KEY)
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return answer_everything(request)

    v = verifier()
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        async with await build_engine(
            adapter_settings(), verifier=v, tenants=directory(), http_client=client
        ) as engine:
            await engine.bootstrap_publish(bundle())
            verdict = await engine.check(ctx(v), "output", "Hello.")
        assert verdict.decision is Decision.ALLOW
        assert len(seen) == 1 and seen[0].headers["x-goog-api-key"] == KEY
        assert not client.is_closed  # borrowed: the caller closes it


async def test_http_client_and_model_together_are_refused():
    with pytest.raises(TypeError, match="http_client"):
        await build_engine(
            settings(), verifier=verifier(), model=FakeDecisionModel(), http_client=object()
        )


# ---------------------------------------------------------------------- coupled settings


@pytest.mark.parametrize("limit", [1, 2, 5])
async def test_the_admission_limit_sets_the_adapter_pool_size(monkeypatch, limit):
    """One setting, two effects: the gateway's in-flight limit per key and the adapter's
    idle connection pool (M1-10). The pool is never configured separately."""
    monkeypatch.setenv("GEMINI_API_KEY", KEY)
    s = adapter_settings(gateway={"max_in_flight_per_key": limit})
    engine = await build_engine(s, verifier=verifier())
    try:
        assert isinstance(engine.gateway._admission, InFlightLimit)
        assert engine.gateway._admission.limit == limit
        assert pool_size(engine.model) == limit
    finally:
        await engine.shutdown()


async def test_changing_the_limit_changes_both(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", KEY)
    sizes = []
    for limit in (2, 7):
        engine = await build_engine(
            adapter_settings(gateway={"max_in_flight_per_key": limit}), verifier=verifier()
        )
        sizes.append((engine.gateway._admission.limit, pool_size(engine.model)))
        await engine.shutdown()
    assert sizes == [(2, 2), (7, 7)]


async def test_the_default_limit_is_the_gateways_own(monkeypatch):
    """With nothing configured, the admission limit and the pool size both come from the
    gateway's single source (``DEFAULT_MAX_IN_FLIGHT_PER_KEY``), never a number of the
    engine's own: the gateway story (M1-15) changes the default in one place."""
    from guardrail_engine.gateway.gateway import DEFAULT_MAX_IN_FLIGHT_PER_KEY

    monkeypatch.setenv("GEMINI_API_KEY", KEY)
    engine = await build_engine(adapter_settings(), verifier=verifier())
    try:
        assert engine.gateway._admission.limit == DEFAULT_MAX_IN_FLIGHT_PER_KEY
        assert pool_size(engine.model) == DEFAULT_MAX_IN_FLIGHT_PER_KEY
    finally:
        await engine.shutdown()


# ---------------------------------------------------------------------- connection-reuse hook


async def test_hook_receives_each_calls_connection_use(monkeypatch, server):
    monkeypatch.setenv("GEMINI_API_KEY", KEY)
    infos: list[CallInfo] = []
    v = verifier()
    s = adapter_settings(gemini={"base_url": server.base_url})
    async with await build_engine(
        s, verifier=v, tenants=directory(), connection_hook=infos.append
    ) as engine:
        await engine.bootstrap_publish(bundle())
        for _ in range(2):
            verdict = await engine.check(ctx(v), "output", "Hello.")
            assert verdict.decision is Decision.ALLOW
    assert [i.connection for i in infos] == [ConnectionUse.NEW, ConnectionUse.REUSED]
    assert server.connections == 1


async def test_default_hook_is_the_no_op_and_is_called(monkeypatch, server):
    """The extra hook defaults to the no-op, and it is still called (the span hook, M1-06,
    runs first; see ``test_engine_telemetry.py``)."""
    monkeypatch.setenv("GEMINI_API_KEY", KEY)
    called: list[CallInfo] = []

    def spy(info: CallInfo) -> None:
        called.append(info)
        ignore_connection_info(info)

    monkeypatch.setattr(factory, "ignore_connection_info", spy)
    v = verifier()
    s = adapter_settings(gemini={"base_url": server.base_url})
    async with await build_engine(s, verifier=v, tenants=directory()) as engine:
        assert engine.connection_hook is spy
        await engine.bootstrap_publish(bundle())
        await engine.check(ctx(v), "output", "Hello.")
    assert [i.connection for i in called] == [ConnectionUse.NEW]


async def test_hook_can_be_connected_after_the_engine_is_built(monkeypatch, server):
    """An extra observer can be set on a running engine, and reset with None."""
    monkeypatch.setenv("GEMINI_API_KEY", KEY)
    v = verifier()
    s = adapter_settings(gemini={"base_url": server.base_url})
    async with await build_engine(s, verifier=v, tenants=directory()) as engine:
        assert engine.connection_hook is ignore_connection_info
        await engine.bootstrap_publish(bundle())
        await engine.check(ctx(v), "output", "Hello.")
        later: list[CallInfo] = []
        engine.connection_hook = later.append
        await engine.check(ctx(v), "output", "Hello.")
        engine.connection_hook = None  # back to the no-op
        await engine.check(ctx(v), "output", "Hello.")
    assert [i.connection for i in later] == [ConnectionUse.REUSED]
    assert engine.connection_hook is ignore_connection_info


async def test_a_hook_that_raises_does_not_change_the_verdict(monkeypatch, server, caplog):
    monkeypatch.setenv("GEMINI_API_KEY", KEY)

    def broken(info: CallInfo) -> None:
        raise RuntimeError("span exporter down")

    v = verifier()
    s = adapter_settings(gemini={"base_url": server.base_url})
    async with await build_engine(
        s, verifier=v, tenants=directory(), connection_hook=broken
    ) as engine:
        await engine.bootstrap_publish(bundle())
        verdict = await engine.check(ctx(v), "output", "Hello.")
    assert verdict.decision is Decision.ALLOW
    assert "on_call hook failed" in caplog.text


# ---------------------------------------------------------------------- the store


class FakePool:
    def __init__(self) -> None:
        self.closed = False
        self.terminated = False

    async def close(self) -> None:
        self.closed = True

    def terminate(self) -> None:
        self.terminated = True


async def test_postgres_store_needs_the_dsn_in_the_environment():
    s = settings(store={"kind": "postgres"})
    with pytest.raises(SettingsError, match=r"GUARDRAIL_PG_DSN: not set"):
        await build_engine(s, verifier=verifier(), model=FakeDecisionModel())


async def test_postgres_store_is_built_on_an_owned_pool_and_closed(monkeypatch):
    """Construction only, no database: the pool is a stand-in."""
    from guardrail_engine.store.adapters.postgres import PostgresPolicyStore

    pool = FakePool()
    dsns: list[str] = []

    async def connect(dsn: str) -> FakePool:
        dsns.append(dsn)
        return pool

    monkeypatch.setattr("guardrail_engine.store.adapters.postgres.connect_pool", connect)
    monkeypatch.setenv("GUARDRAIL_PG_DSN", "postgresql://app@db/guardrails")
    s = settings(store={"kind": "postgres"})
    engine = await build_engine(s, verifier=verifier(), model=FakeDecisionModel())
    assert isinstance(engine.store, PostgresPolicyStore)
    assert engine.store._pool is pool
    assert dsns == ["postgresql://app@db/guardrails"]
    assert "postgresql://" not in repr(engine)
    await engine.shutdown()
    assert pool.closed


async def test_a_borrowed_pool_is_not_closed():
    pool = FakePool()
    s = settings(store={"kind": "postgres"})
    engine = await build_engine(s, verifier=verifier(), model=FakeDecisionModel(), pg_pool=pool)
    assert engine.store._pool is pool
    await engine.shutdown()
    assert not pool.closed


async def test_a_pool_with_the_memory_store_is_refused():
    with pytest.raises(SettingsError, match=r"store\.kind: is 'memory'"):
        await build_engine(
            settings(), verifier=verifier(), model=FakeDecisionModel(), pg_pool=FakePool()
        )


async def test_connection_failure_does_not_repeat_the_dsn(monkeypatch):
    secret_dsn = "postgresql://app:SENTINEL-PASSWORD@db/guardrails"

    async def connect(dsn: str):
        raise OSError(f"could not connect to {dsn}")

    monkeypatch.setattr("guardrail_engine.store.adapters.postgres.connect_pool", connect)
    monkeypatch.setenv("GUARDRAIL_PG_DSN", secret_dsn)
    with pytest.raises(EngineStartError, match="could not connect to Postgres") as raised:
        await build_engine(
            settings(store={"kind": "postgres"}), verifier=verifier(), model=FakeDecisionModel()
        )
    assert "SENTINEL-PASSWORD" not in str(raised.value)
    assert raised.value.__cause__ is None and raised.value.__suppress_context__


async def test_a_failed_build_closes_what_it_opened(monkeypatch):
    pool = FakePool()

    async def connect(dsn: str) -> FakePool:
        return pool

    monkeypatch.setattr("guardrail_engine.store.adapters.postgres.connect_pool", connect)
    monkeypatch.setenv("GUARDRAIL_PG_DSN", "postgresql://app@db/guardrails")
    with pytest.raises(TypeError, match="key_id"):
        await build_engine(
            settings(store={"kind": "postgres"}),
            verifier=verifier(),
            model=FakeDecisionModel(),
            key_id="not callable",  # type: ignore[arg-type]
        )
    assert pool.closed


async def test_injected_store_is_used():
    class Store(InMemoryPolicyStore):
        pass

    store = Store(catalog=real_catalog())
    engine = await build_engine(
        settings(), verifier=verifier(), model=FakeDecisionModel(), store=store
    )
    assert engine.store is store
    await engine.shutdown()


PG_TEST_DSN = os.environ.get("GUARDRAIL_TEST_PG_DSN")


@pytest.mark.skipif(not PG_TEST_DSN, reason="GUARDRAIL_TEST_PG_DSN is not set")
async def test_postgres_store_end_to_end_against_a_real_database():
    """With a database: publish and check through the Postgres store, in a throwaway
    schema, on a borrowed pool."""
    import asyncpg

    from guardrail_engine.store.adapters.postgres import apply_schema

    schema = f"m111_{uuid.uuid4().hex}"
    admin = await asyncpg.connect(PG_TEST_DSN)
    await admin.execute(f'CREATE SCHEMA "{schema}"')
    try:
        pool = await asyncpg.create_pool(
            PG_TEST_DSN, min_size=1, max_size=4, server_settings={"search_path": schema}
        )
        try:
            await apply_schema(pool)
            v = verifier()
            async with await build_engine(
                settings(store={"kind": "postgres"}),
                verifier=v,
                tenants=directory(),
                model=FakeDecisionModel(),
                pg_pool=pool,
            ) as engine:
                await engine.bootstrap_publish(bundle())
                verdict = await engine.check(ctx(v), "output", "Hello.")
            assert verdict.decision is Decision.ALLOW
        finally:
            await pool.close()
    finally:
        await admin.execute(f'DROP SCHEMA "{schema}" CASCADE')
        await admin.close()


async def test_the_token_rate_limiter_reaches_the_gateway_by_environment(tmp_path):
    """M3-10: unset, the limiter is on in staging (Tier 1 defaults) and off in test; a
    ``token_rate`` setting turns it on anywhere, with its values."""
    v = verifier()
    async with await build_engine(
        settings(), verifier=v, tenants=directory(), model=FakeDecisionModel()
    ) as engine:
        assert engine.gateway.token_rate_limiter is None
    async with await build_engine(
        settings("staging", class_a_audit={"file": str(tmp_path / "class-a.jsonl")}),
        verifier=v,
        tenants=directory(),
        model=FakeDecisionModel(),
    ) as engine:
        limiter = engine.gateway.token_rate_limiter
        assert limiter is not None and limiter.config.target_fraction == 0.68
    configured = settings(token_rate={"tokens_per_minute": 400_000, "requests_per_day": 1_000})
    async with await build_engine(
        configured, verifier=v, tenants=directory(), model=FakeDecisionModel()
    ) as engine:
        limiter = engine.gateway.token_rate_limiter
        assert limiter is not None
        assert (limiter.config.tokens_per_minute, limiter.config.requests_per_day) == (
            400_000,
            1_000,
        )


async def test_engines_of_one_project_share_a_bucket_through_rate_store(tmp_path):
    """``rate_store`` is how two engines in one process share a project's limit; each
    engine's limiter then draws on the same bucket. Without it each has its own."""
    from guardrail_engine.gateway import InProcessTokenRateStore

    shared = InProcessTokenRateStore()
    v = verifier()
    configured = settings(token_rate={"project_id": "proj-shared"})
    async with (
        await build_engine(
            configured,
            verifier=v,
            tenants=directory(),
            model=FakeDecisionModel(),
            rate_store=shared,
        ) as first,  # fmt: skip
        await build_engine(
            configured,
            verifier=v,
            tenants=directory(),
            model=FakeDecisionModel(),
            rate_store=shared,
        ) as second,  # fmt: skip
        await build_engine(
            configured, verifier=v, tenants=directory(), model=FakeDecisionModel()
        ) as alone,
    ):
        a, b, c = (e.gateway.token_rate_limiter for e in (first, second, alone))
        assert a is not None and b is not None and c is not None
        assert a.store is shared and b.store is shared and c.store is not shared
        bucket = {"now": 0.0, "rate_per_s": a.config.rate_per_s, "capacity": a.config.capacity}
        assert shared.acquire("proj-shared", a.config.capacity, **bucket) == 0.0  # one drains it
        assert b.store.level("proj-shared", **bucket) == 0.0  # the other sees it empty
        assert c.store.level("proj-shared", **bucket) == a.config.capacity


async def test_a_rate_store_is_ignored_when_the_limiter_is_off():
    from guardrail_engine.gateway import InProcessTokenRateStore

    async with await build_engine(
        settings(), verifier=verifier(), tenants=directory(), model=FakeDecisionModel(),
        rate_store=InProcessTokenRateStore(),
    ) as engine:  # fmt: skip
        assert engine.gateway.token_rate_limiter is None
