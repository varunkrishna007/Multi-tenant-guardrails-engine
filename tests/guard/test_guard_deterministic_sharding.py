"""A combined identifier set the engine can't build is sharded, not fatal.

Patterns that each compile, and compile together per tenant, can still be too much for the
engine in one set. The scan then matches over shards: a cross-tenant match still blocks, a
clean check still allows, one fixed-word alert is raised per rebuild, and the sharded set stays
the built set. The engine here is a fake: no model and no network.
"""

from __future__ import annotations

import pytest
from guard_fixtures import ALPHA, BETA, GAMMA, Env, bundle, rule

from guardrail_engine.deterministic import (
    CROSS_TENANT_RULE,
    InMemoryOtherTenantIdentifiers,
    RegexError,
    tenant_id_pattern,
)
from guardrail_engine.deterministic.adapters.google_re2 import Re2RegexEngine
from guardrail_engine.gateway import (
    ALERT_XTENANT_PATTERNS_DROPPED,
    ALERT_XTENANT_SCAN_SHARDED,
    RecordingAlertSink,
)
from guardrail_engine.guard import Decision, Reason
from guardrail_engine.guard.deterministic import CrossTenantScanner
from guardrail_engine.policy import GUARD_POINTS

BETA_INVOICE = "BET-INV-9082"


class BudgetEngine:
    """The real RE2 engine, except that ``compile_set`` raises ``RegexError`` for a set of more
    than ``budget`` patterns, as RE2 does for one over its memory bound. Records set sizes."""

    def __init__(self, budget: int) -> None:
        self._real = Re2RegexEngine()
        self.budget = budget
        self.set_sizes: list[int] = []

    def compile(self, pattern):
        return self._real.compile(pattern)

    def compile_set(self, patterns):
        self.set_sizes.append(len(patterns))
        if len(patterns) > self.budget:
            raise RegexError("pattern set too large")
        return self._real.compile_set(patterns)


class Static:
    """A source holding raw patterns (not validated)."""

    def __init__(self, by_tenant, version=1) -> None:
        self.by_tenant = by_tenant
        self.current = version

    async def version(self):
        return self.current

    async def patterns_by_tenant(self):
        return self.by_tenant


def two_tenants() -> InMemoryOtherTenantIdentifiers:
    """ALPHA and BETA each hold their id pattern and one of their own; GAMMA only its id: five
    patterns in the combined set."""
    return InMemoryOtherTenantIdentifiers(
        {ALPHA: [r"ALP-ORD-[0-9]{4}"], BETA: [r"BET-INV-[0-9]{4}"], GAMMA: []}
    )


async def test_a_combined_set_that_will_not_compile_still_blocks_a_match_and_allows_a_clean_one():
    engine = BudgetEngine(budget=3)
    alerts = RecordingAlertSink()
    async with Env(other_tenants=two_tenants(), regex=engine, alerts=alerts) as env:
        await env.publish(bundle(ALPHA, rules=[rule("adv", gps=GUARD_POINTS)]))
        leak = await env.check(ALPHA, "output", BETA_INVOICE)
        by_id = await env.check(ALPHA, "tool_result", f"see {BETA} here")
        clean = await env.check(ALPHA, "output", "Order 12345 shipped on 2024-05-06.")
        sizes_so_far = list(engine.set_sizes)
        for _ in range(3):
            await env.check(ALPHA, "output", "Hello.")
        await env.service._gateway.drain()
    assert (leak.decision, leak.reason) == (Decision.BLOCK, Reason.DETERMINISTIC)
    assert (by_id.decision, by_id.reason) == (Decision.BLOCK, Reason.DETERMINISTIC)
    assert clean.decision is Decision.ALLOW
    assert env.service._scanner.shard_count == 3  # one set per tenant
    assert env.service._scanner.dropped_tenants == ()
    [alert] = alerts.warnings(ALERT_XTENANT_SCAN_SHARDED)
    assert alert.tenant_id == "" and BETA not in alert.message and "ALP-" not in alert.message
    assert alerts.warnings(ALERT_XTENANT_PATTERNS_DROPPED) == []  # nobody was dropped
    assert engine.set_sizes == sizes_so_far  # the sharded set stays built: no retry per check
    assert sizes_so_far.count(5) == 1  # the combined set was tried exactly once


async def test_a_sharded_scan_still_leaves_out_the_callers_own_patterns():
    async with Env(other_tenants=two_tenants(), regex=BudgetEngine(budget=3)) as env:
        await env.publish(bundle(ALPHA, rules=[rule("adv", gps=GUARD_POINTS)]))
        own = await env.check(ALPHA, "output", f"my own ALP-ORD-1234 and {ALPHA}")
        other = await env.check(ALPHA, "output", "their BET-INV-1234")
    assert own.decision is Decision.ALLOW
    assert (other.decision, other.reason) == (Decision.BLOCK, Reason.DETERMINISTIC)


async def test_the_sharded_fallback_is_logged_in_fixed_words(caplog):
    async with Env(other_tenants=two_tenants(), regex=BudgetEngine(budget=3)) as env:
        await env.publish(bundle(ALPHA, rules=[rule("adv", gps=GUARD_POINTS)]))
        with caplog.at_level("ERROR"):
            await env.check(ALPHA, "output", "Hello.")
    text = "\n".join(r.getMessage() for r in caplog.records)
    assert "shards" in text and "ALP-ORD" not in text and BETA not in text


async def test_a_failing_sharded_alert_hook_does_not_fail_the_check(monkeypatch):
    async with Env(other_tenants=two_tenants(), regex=BudgetEngine(budget=3)) as env:
        await env.publish(bundle(ALPHA, rules=[rule("adv", gps=GUARD_POINTS)]))

        def boom():
            raise RuntimeError("pager down")

        monkeypatch.setattr(env.service._gateway, "identifier_scan_sharded", boom)
        verdict = await env.check(ALPHA, "output", "Hello.")
    assert verdict.decision is Decision.ALLOW


async def test_a_dropped_tenant_and_a_sharded_scan_together():
    source = Static(
        {
            BETA: ["BET-INV-(?=[0-9])"],  # doesn't compile: dropped
            GAMMA: [tenant_id_pattern(GAMMA), r"GAM-ACC-[0-9]{4}"],
            ALPHA: [tenant_id_pattern(ALPHA), r"ALP-ORD-[0-9]{4}"],
        }
    )
    async with Env(other_tenants=source, regex=BudgetEngine(budget=3)) as env:
        await env.publish(bundle(ALPHA, rules=[rule("adv", gps=GUARD_POINTS)]))
        leak = await env.check(ALPHA, "output", "see GAM-ACC-1234")
    assert (leak.decision, leak.reason) == (Decision.BLOCK, Reason.DETERMINISTIC)
    assert env.service._scanner.dropped_tenants == (BETA,)


@pytest.mark.parametrize(("chunk_size", "shards"), [(3, 6), (2, 3)])
async def test_the_scanner_matches_chunks_and_falls_back_per_tenant_for_a_chunk_too_big(
    chunk_size, shards
):
    """Six tenants with two patterns each; the engine takes at most 4 patterns in a set. In
    chunks of 3 tenants (6 patterns) every chunk is too big, so each tenant has its own set; in
    chunks of 2 (4 patterns) the chunks build, and there are three shards."""
    by_tenant = {f"t_{n}": [f"ID{n}-[0-9]{{4}}", f"REF{n}-[0-9]{{4}}"] for n in range(6)}
    sharded: list[bool] = []
    scanner = CrossTenantScanner(
        Static(by_tenant),
        BudgetEngine(budget=4),
        on_sharded=lambda: sharded.append(True),
        shard_tenants=chunk_size,
    )
    assert await scanner.scan("t_0", "ID0-1234 and REF0-1234") is None  # its own
    assert scanner.shard_count == shards and sharded == [True]
    hit = await scanner.scan("t_0", "ID5-1234")
    assert hit is not None and hit.rule == CROSS_TENANT_RULE
    assert await scanner.scan("t_0", "nothing at all") is None
    assert sharded == [True]  # once per rebuild


async def test_a_combined_set_that_builds_is_one_shard_and_raises_no_alert():
    sharded: list[bool] = []
    scanner = CrossTenantScanner(
        two_tenants(), Re2RegexEngine(), on_sharded=lambda: sharded.append(True)
    )
    assert await scanner.scan(ALPHA, "Hello.") is None
    assert scanner.shard_count == 1 and sharded == []


async def test_each_rebuild_of_a_sharded_scan_raises_the_alert_once():
    source = Static({ALPHA: [r"ALP-ORD-[0-9]{4}", r"ALP-X-[0-9]{4}"], BETA: [r"BET-INV-[0-9]{4}"]})
    sharded: list[bool] = []
    scanner = CrossTenantScanner(
        source, BudgetEngine(budget=2), on_sharded=lambda: sharded.append(True)
    )
    for _ in range(3):
        await scanner.scan(GAMMA, "Hello.")
    assert sharded == [True]
    source.current = 2
    for _ in range(3):
        await scanner.scan(GAMMA, "Hello.")
        await scanner.wait_for_rebuild()
    assert sharded == [True, True]


async def test_a_source_that_raises_still_fails_closed_when_the_scan_would_shard():
    class Down:
        async def version(self):
            return 1

        async def patterns_by_tenant(self):
            raise ConnectionError("down")

    scanner = CrossTenantScanner(Down(), BudgetEngine(budget=1))
    with pytest.raises(ConnectionError):
        await scanner.scan(ALPHA, "Hello.")
