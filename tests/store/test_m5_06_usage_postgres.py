"""M5-06 on Postgres: ``usage_events.project`` is read and written under the forced row-level
security of the table (a tenant sees its own project label and nobody else's), the metrics query
splits usage by project, and ``tenants.project`` is a label, one tenant per project."""

from datetime import timedelta

import asyncpg
import pytest
from test_m4_07_decision_records_postgres import ACME, NOW, OTHER, env  # noqa: F401  (fixture)

from guardrail_engine.metrics.adapters.postgres import PostgresUsageMetrics
from guardrail_engine.metrics.model import Window, build_report
from guardrail_engine.tenant_scope import issue_scope

INSERT = (
    "INSERT INTO usage_events (idempotency_key, kind, tenant_id, guard_point, input_tokens, "
    "occurred_at, project) VALUES ($1, 'answered', $2, $3, $4, $5, $6)"
)


async def put(e, tenant, key, gp, tokens, project=""):
    async with e.app.acquire() as conn, conn.transaction():
        await conn.execute("SELECT set_config('app.tenant_id', $1, true)", tenant)
        await conn.execute(INSERT, key, tenant, gp, tokens, NOW, project)


async def test_usage_is_split_by_project_and_a_tenant_sees_only_its_own(env):  # noqa: F811
    await put(env, ACME, "k1", "output", 6_000_000, "reg-acme")
    await put(env, ACME, "k2", "input", 4_000_000, "reg-acme")
    await put(env, ACME, "k3", "output", 1_000_000)
    await put(env, ACME, "k4", "test:output", 500_000, "reg-acme")
    await put(env, OTHER, "k5", "output", 9_999, "reg-other")
    window = Window(NOW - timedelta(hours=1), NOW + timedelta(hours=1))
    metrics = PostgresUsageMetrics(env.app, env.operator)
    totals = await metrics.totals(issue_scope(ACME), window)
    assert {(t.project, t.guard_point): t.tokens for t in totals} == {
        ("reg-acme", "output"): 6_000_000,
        ("reg-acme", "input"): 4_000_000,
        ("", "output"): 1_000_000,
        ("reg-acme", "test:output"): 500_000,
    }
    report = build_report(
        window, _no_records(), totals, floor_derived=frozenset(),
        price_per_million_usd=0.10, price_source="test",
    )  # fmt: skip
    assert [(p["project"], p["input_tokens"]) for p in report["projects"]] == [
        ("default", 1_000_000),
        ("reg-acme", 10_000_000),
    ]
    other = await metrics.totals(issue_scope(OTHER), window)
    assert {t.project for t in other} == {
        "reg-other"
    }  # no other tenant's label, whatever the filter
    assert await env.app.fetchval("SELECT count(*) FROM usage_events") == 0  # no tenant setting


def _no_records():
    from guardrail_engine.metrics.model import RecordAggregates

    return RecordAggregates(
        checks=0, by_decision={}, latency=None, guard_points=[], bundle_versions=frozenset(),
        unknown_version=False, rules=[],
    )  # fmt: skip


async def test_the_project_column_stays_under_forced_row_level_security(env):  # noqa: F811
    forced = await env.owner.fetchval(
        "SELECT relforcerowsecurity FROM pg_class WHERE relname = 'usage_events' "
        "AND relnamespace = current_schema()::regnamespace"
    )
    assert forced is True
    with pytest.raises(asyncpg.CheckViolationError):  # a label, never a key
        async with env.app.acquire() as conn, conn.transaction():
            await conn.execute("SELECT set_config('app.tenant_id', $1, true)", ACME)
            await conn.execute(INSERT, "bad", ACME, "output", 1, NOW, "AIzaSy-a-key-0123")
    with pytest.raises(asyncpg.exceptions.InsufficientPrivilegeError):
        await env.app.execute(INSERT, "k9", ACME, "output", 1, NOW, "reg-acme")  # no tenant setting


async def test_tenants_project_is_a_label_and_one_tenant_holds_it(env):  # noqa: F811
    insert = (
        "INSERT INTO tenants (tenant_id, slug, domain, tier, status, version, project) "
        "VALUES ($1, $2, 'finance', 'regulated', 'active', 1, $3)"
    )
    await env.owner.execute(insert, "t_acme1", "acme", "reg-1")
    with pytest.raises(asyncpg.UniqueViolationError):
        await env.owner.execute(insert, "t_acme2", "other", "reg-1")
    for bad in ("default", "Reg_1", "AIzaSyD-a-key-0123456789-abcdef", "x" * 41):
        with pytest.raises(asyncpg.CheckViolationError):
            await env.owner.execute(insert, "t_acme3", "third", bad)
    await env.owner.execute(insert, "t_acme3", "third", None)  # the shared pool: many tenants
    await env.owner.execute(
        "INSERT INTO tenants (tenant_id, slug, domain, tier, status, version) "
        "VALUES ('t_acme4', 'fourth', 'finance', 'standard', 'active', 1)"
    )
