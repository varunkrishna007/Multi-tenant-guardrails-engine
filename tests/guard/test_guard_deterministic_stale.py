"""A rebuild of the cross-tenant set never stalls a check. The scanner goes on with its
previous set while the new one is built in the background, for at most MAX_STALE_S, and after
that waits (and fails closed if it can't be built)."""

from __future__ import annotations

import asyncio

import pytest

from guardrail_engine.deterministic.adapters.google_re2 import Re2RegexEngine
from guardrail_engine.guard.deterministic import MAX_STALE_S, CrossTenantScanner

ALPHA, BETA = "t_alpha", "t_beta"
OLD, NEW = r"BET-INV-[0-9]{4}", r"BET-ACC-[0-9]{4}"


class Source:
    def __init__(self, by_tenant, version=1) -> None:
        self.by_tenant = by_tenant
        self.current = version
        self.fetches = 0
        self.fetch_hook = None

    async def version(self):
        return self.current

    async def patterns_by_tenant(self):
        self.fetches += 1
        if self.fetch_hook is not None:
            await self.fetch_hook()
        return self.by_tenant


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def make(source, clock=None, **kwargs):
    return CrossTenantScanner(source, Re2RegexEngine(), clock=clock or Clock(), **kwargs)


async def test_the_first_build_is_waited_for():
    scanner = make(Source({BETA: [OLD]}))
    assert (await scanner.scan(ALPHA, "BET-INV-1234")) is not None


async def test_a_check_during_a_rebuild_is_served_from_the_previous_set_without_waiting():
    source = Source({BETA: [OLD]})
    scanner = make(source)
    await scanner.scan(ALPHA, "Hello.")
    gate = asyncio.Event()

    async def slow():
        await gate.wait()

    source.by_tenant = {BETA: [OLD, NEW]}
    source.current = 2
    source.fetch_hook = slow
    old_hit = await asyncio.wait_for(scanner.scan(ALPHA, "BET-INV-1234"), timeout=1)
    new_not_yet = await asyncio.wait_for(scanner.scan(ALPHA, "BET-ACC-1234"), timeout=1)
    assert old_hit is not None  # the previous set still blocks what it knew
    assert new_not_yet is None  # and doesn't yet know the new identifier
    gate.set()
    await scanner.wait_for_rebuild()
    assert (await scanner.scan(ALPHA, "BET-ACC-1234")) is not None


async def test_one_rebuild_runs_at_a_time_however_many_checks_arrive():
    source = Source({BETA: [OLD]})
    scanner = make(source)
    await scanner.scan(ALPHA, "Hello.")
    source.current = 2
    await asyncio.gather(*(scanner.scan(ALPHA, "Hello.") for _ in range(8)))
    await scanner.wait_for_rebuild()
    assert source.fetches == 2  # the first build and one rebuild


async def test_a_failed_background_rebuild_keeps_the_previous_set_and_is_retried():
    source = Source({BETA: [OLD]})
    clock = Clock()
    scanner = make(source, clock)
    await scanner.scan(ALPHA, "Hello.")
    source.current = 2
    source.by_tenant = None  # iterating None fails
    assert (await scanner.scan(ALPHA, "BET-INV-1234")) is not None  # served from the previous
    await scanner.wait_for_rebuild()
    assert source.fetches == 2
    await scanner.scan(ALPHA, "Hello.")
    await scanner.wait_for_rebuild()
    assert source.fetches == 2  # not hammered: a retry waits a second
    clock.now += 2
    source.by_tenant = {BETA: [OLD, NEW]}
    await scanner.scan(ALPHA, "Hello.")
    await scanner.wait_for_rebuild()
    assert (await scanner.scan(ALPHA, "BET-ACC-1234")) is not None


async def test_after_max_stale_s_a_check_waits_for_the_rebuild_and_fails_closed():
    source = Source({BETA: [OLD]})
    clock = Clock()
    scanner = make(source, clock)
    await scanner.scan(ALPHA, "Hello.")
    source.current = 2
    source.by_tenant = None
    await scanner.scan(ALPHA, "Hello.")  # starts the failing rebuild; served from the previous
    await scanner.wait_for_rebuild()
    clock.now += MAX_STALE_S + 1
    with pytest.raises(AttributeError):  # the rebuild's own error, not a stale allow
        await scanner.scan(ALPHA, "Hello.")


async def test_after_max_stale_s_a_slow_rebuild_is_waited_for():
    source = Source({BETA: [OLD]})
    clock = Clock()
    scanner = make(source, clock)
    await scanner.scan(ALPHA, "Hello.")
    gate = asyncio.Event()

    async def slow():
        await gate.wait()

    source.fetch_hook = slow
    source.by_tenant = {BETA: [OLD, NEW]}
    source.current = 2
    assert (await scanner.scan(ALPHA, "BET-ACC-1234")) is None  # stale, within the bound
    clock.now += MAX_STALE_S + 1
    waiting = asyncio.ensure_future(scanner.scan(ALPHA, "BET-ACC-1234"))
    await asyncio.sleep(0.05)
    assert not waiting.done()  # it waits now
    gate.set()
    assert (await waiting) is not None  # and finds the identifier


async def test_max_stale_s_of_zero_waits_for_every_rebuild():
    source = Source({BETA: [OLD]})
    scanner = make(source, max_stale_s=0)
    await scanner.scan(ALPHA, "Hello.")
    source.by_tenant = {BETA: [OLD, NEW]}
    source.current = 2
    assert (await scanner.scan(ALPHA, "BET-ACC-1234")) is not None


async def test_a_negative_bound_is_refused():
    with pytest.raises(ValueError):
        make(Source({}), max_stale_s=-1)


async def test_the_stale_clock_runs_from_when_the_source_first_moved_not_from_each_rebuild():
    """A rebuild that lands for an already-superseded version doesn't restart the 30 s."""
    source = Source({BETA: [OLD]})
    clock = Clock()
    scanner = make(source, clock)
    await scanner.scan(ALPHA, "Hello.")  # built for version 1
    source.current = 2
    await scanner.scan(ALPHA, "Hello.")  # sees 2 at t0: starts a rebuild for 2
    source.current = 3  # the source moves on again before that lands
    await scanner.wait_for_rebuild()  # 2 lands; 3 is newer, so the clock isn't cleared
    clock.now += MAX_STALE_S - 1
    gate = asyncio.Event()

    async def slow():
        await gate.wait()

    source.fetch_hook = slow
    assert (await scanner.scan(ALPHA, "Hello.")) is None  # 29 s: served; the rebuild for 3 hangs
    clock.now += 2  # t0 + 31 s
    waiting = asyncio.ensure_future(scanner.scan(ALPHA, "Hello."))
    await asyncio.sleep(0.05)
    assert not waiting.done()  # over the bound counted from t0: this check waits
    gate.set()
    await waiting


async def test_the_stale_clock_is_cleared_when_the_newest_version_is_built():
    source = Source({BETA: [OLD]})
    clock = Clock()
    scanner = make(source, clock)
    await scanner.scan(ALPHA, "Hello.")
    source.current = 2
    await scanner.scan(ALPHA, "Hello.")
    await scanner.wait_for_rebuild()  # built for 2, the newest
    clock.now += MAX_STALE_S * 5  # a long quiet time
    source.current = 3
    # a fresh change gets a fresh 30 s: this check is served from the previous set, not waited
    assert (await asyncio.wait_for(scanner.scan(ALPHA, "BET-INV-1234"), timeout=1)) is not None
