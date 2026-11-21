"""M4-03 shadow agreement storage (028, 031): counters only, per tenant under forced row-level
security, added on flush, the exact grants. Needs GUARDRAIL_TEST_PG_DSN; skipped without it."""

import asyncpg
import pytest
from store_harness import ACME, OTHER

from guardrail_engine.guard.shadow import (
    InMemoryShadowStats,
    RuleCall,
    ShadowObservation,
)
from guardrail_engine.store.adapters.postgres import PostgresShadowStats
from guardrail_engine.tenant_scope import issue_scope

DENIED = (asyncpg.InsufficientPrivilegeError, asyncpg.exceptions.RestrictViolationError)


def obs(tenant, active="allow", candidate="block", *, comparable=True, a=1, c=2):
    return ShadowObservation(
        tenant, "output", a, c, comparable, active, candidate,
        (RuleCall("t__refunds", "tenant", active),),
        (RuleCall("t__refunds", "tenant", candidate),),
        issue_scope(tenant),
    )  # fmt: skip


@pytest.fixture(params=["memory", "postgres"])
def stats(request):
    if request.param == "memory":
        return InMemoryShadowStats()
    return PostgresShadowStats(request.getfixturevalue("app_pool"))


async def test_counts_are_added_per_pair_and_split_agree_stricter_looser(stats):
    for o in (
        obs(ACME, "allow", "allow"),
        obs(ACME, "allow", "block"),
        obs(ACME, "block", "allow"),
    ):
        stats.record(o)
    stats.record(obs(ACME, comparable=False))
    stats.record(obs(ACME, a=2, c=3))  # another pair
    t = await stats.tally(issue_scope(ACME), 1, 2)
    assert (t.checks, t.incomparable) == (3, 1)
    r = t.rules["t__refunds"]
    assert (r.n, r.agree, r.candidate_stricter, r.candidate_looser) == (3, 1, 1, 1)
    assert (t.decision.n, t.decision.agree) == (3, 1)
    assert (await stats.tally(issue_scope(ACME), 2, 3)).checks == 1
    assert (await stats.tally(issue_scope(ACME), 9, 9)).checks == 0


async def test_each_tally_adds_to_what_was_stored_not_replaces_it(stats):
    stats.record(obs(ACME))
    assert (await stats.tally(issue_scope(ACME), 1, 2)).checks == 1
    stats.record(obs(ACME))
    stats.record(obs(ACME))
    assert (await stats.tally(issue_scope(ACME), 1, 2)).checks == 3


async def test_a_tenant_reads_only_its_own_counts(stats):
    stats.record(obs(ACME))
    stats.record(obs(OTHER))
    stats.record(obs(OTHER))
    assert (await stats.tally(issue_scope(ACME), 1, 2)).checks == 1
    assert (await stats.tally(issue_scope(OTHER), 1, 2)).checks == 2


async def test_an_observation_without_a_scope_is_not_written(app_pool):
    stats = PostgresShadowStats(app_pool)
    o = obs(ACME)
    stats.record(_unscoped(o))
    assert (await stats.tally(issue_scope(ACME), 1, 2)).checks == 0


def _unscoped(o):
    return ShadowObservation(
        o.tenant_id, o.guard_point, o.active_version, o.candidate_version, o.comparable,
        o.active_decision, o.candidate_decision, o.active_rules, o.candidate_rules, None,
    )  # fmt: skip


class _Flaky:
    """A pool that refuses until ``up`` is set."""

    def __init__(self, pool):
        self._pool = pool
        self.up = False

    def acquire(self, *args, **kw):
        if not self.up:
            raise ConnectionError("down")
        return self._pool.acquire(*args, **kw)


async def test_a_failed_flush_keeps_the_counts_for_the_next_try(app_pool):
    flaky = _Flaky(app_pool)
    stats = PostgresShadowStats(flaky)
    stats.record(obs(ACME))
    await stats.flush()  # fails and keeps the counts
    stats.record(obs(ACME))
    flaky.up = True
    assert (await stats.tally(issue_scope(ACME), 1, 2)).checks == 2


async def test_rls_hides_other_tenants_rows_and_the_app_role_cannot_delete(app_pool):
    stats = PostgresShadowStats(app_pool)
    stats.record(obs(ACME))
    await stats.flush()
    async with app_pool.acquire() as conn:
        assert await conn.fetchval("SELECT count(*) FROM tenant_shadow_agreement") == 0  # no scope
        with pytest.raises(DENIED):
            await conn.execute("DELETE FROM tenant_shadow_agreement")
        with pytest.raises(DENIED):
            await conn.execute("TRUNCATE tenant_shadow_agreement")


async def test_the_table_holds_no_probability_column(app_pool):
    async with app_pool.acquire() as conn:
        cols = {
            r["column_name"]
            for r in await conn.fetch(
                "SELECT column_name FROM information_schema.columns "
                "WHERE table_name = 'tenant_shadow_agreement'"
            )
        }
    assert cols == {
        "tenant_id", "active_version", "candidate_version", "rule_key", "layer", "n", "agree",
        "candidate_stricter", "candidate_looser", "only_active", "only_candidate", "checks",
        "incomparable", "updated_at",
    }  # fmt: skip
