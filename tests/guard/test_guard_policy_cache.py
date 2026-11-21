"""M1-05 policy loading: AC-C3 (compiled question sets cached per (tenant, version,
guard_point); a hit does no compile work), last-known-good when the store is down or the
active version fails verification, and stale-while-revalidate, the
tenant profile re-read on refresh, last-known-good after a rollback, no scans over other
tenants."""

import asyncio
import dataclasses
import time

import pytest
from guard_fixtures import (
    ALPHA,
    BETA,
    GAMMA,
    TOOLS,
    CountingCompiler,
    Env,
    bundle,
    profile,
    rule,
)

from guardrail_engine.gateway import GatewayConfig
from guardrail_engine.guard import (
    Decision,
    GuardConfig,
    InMemoryTenantDirectory,
    PolicySource,
    Reason,
    ToolCall,
    ToolInfo,
)
from guardrail_engine.store import BundleIntegrityError


@pytest.fixture(autouse=True)
def _reset_counter():
    CountingCompiler.count = 0


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def tamper(env, tenant_id, version):
    rows = env.inner_store._versions
    rows[(tenant_id, version)] = dataclasses.replace(
        rows[(tenant_id, version)], bundle_hash="sha256:" + "0" * 64
    )


# ------------------------------------------------------------------ AC-C3


async def test_ac_c3_cache_hit_does_no_compile_work():
    async with Env(compiler_factory=CountingCompiler) as env:
        await env.publish(bundle(ALPHA, rules=[rule("adv", gps=["output", "input"])]))
        cache = env.service.policy_cache
        for _ in range(5):
            await env.check(ALPHA, "output")
        assert (cache.compiles, CountingCompiler.count) == (1, 1)
        # Another guard point of the same version was cached by the same compile.
        for _ in range(3):
            await env.check(ALPHA, "input")
        assert (cache.compiles, CountingCompiler.count) == (1, 1)
    assert len(env.fake.calls) == 8


async def test_ac_c3_a_refresh_with_nothing_changed_does_no_compile_work():
    clock = Clock()
    async with Env(config=GuardConfig(pointer_ttl_s=5), cache_clock=clock) as env:
        await env.publish(bundle(ALPHA))
        await env.check(ALPHA)
        for _ in range(3):
            clock.now += 10
            await env.check(ALPHA)
            await env.service.policy_cache.drain()
        assert env.store.calls["get_active_version"] == 4
        assert env.service.policy_cache.compiles == 1


async def test_ac_c3_cache_is_keyed_by_tenant_version_and_guard_point():
    async with Env(compiler_factory=CountingCompiler) as env:
        cache = env.service.policy_cache
        await env.publish(bundle(ALPHA, rules=[rule("a1")]))
        await env.publish(bundle(BETA, rules=[rule("b1")]))
        await env.check(ALPHA)
        await env.check(BETA)
        assert CountingCompiler.count == 2
        alpha_q = set(env.fake.calls[0].questions)
        beta_q = set(env.fake.calls[1].questions)
        assert "t__a1" in alpha_q and "t__a1" not in beta_q
        assert "t__b1" in beta_q and "t__b1" not in alpha_q

        # A new active version (announced by the publish event) is a miss for that tenant only.
        await env.publish(bundle(ALPHA, version=2, rules=[rule("a2")]))
        cache.invalidate(ALPHA)
        v2 = await env.check(ALPHA)
        await env.check(BETA)
        assert CountingCompiler.count == 3
        assert v2.bundle_version == 2
        assert "t__a2" in env.fake.calls[2].questions

        # Rolling back to version 1 compiles it again (only the newest good one is kept).
        await env.inner_store.set_active_version(ALPHA, 1)
        cache.invalidate(ALPHA)
        v1 = await env.check(ALPHA)
        assert v1.bundle_version == 1 and CountingCompiler.count == 4


async def test_ac_c3_concurrent_misses_compile_once():
    async with Env(compiler_factory=CountingCompiler) as env:
        await env.publish(bundle(ALPHA, rules=[rule("adv")]))
        verdicts = await asyncio.gather(*(env.check(ALPHA) for _ in range(20)))
    assert CountingCompiler.count == 1
    assert {v.bundle_version for v in verdicts} == {1}


async def test_pointer_ttl_avoids_store_calls_and_a_stale_pointer_is_revalidated():
    clock = Clock()
    async with Env(config=GuardConfig(pointer_ttl_s=10.0), cache_clock=clock) as env:
        cache = env.service.policy_cache
        await env.publish(bundle(ALPHA))
        await env.check(ALPHA)
        await env.check(ALPHA)
        assert env.store.calls["get_active_version"] == 1

        await env.publish(bundle(ALPHA, version=2))
        assert (await env.check(ALPHA)).bundle_version == 1  # within the TTL
        clock.now += 10.0
        assert (await env.check(ALPHA)).bundle_version == 1  # stale: served, revalidating
        await cache.drain()
        assert (await env.check(ALPHA)).bundle_version == 2

        await env.inner_store.set_active_version(ALPHA, 1)
        cache.invalidate(ALPHA)  # what a publish event will call: re-read now
        assert (await env.check(ALPHA)).bundle_version == 1
        assert env.store.calls["get_active_version"] == 3


# ------------------------------------------------------------------ last-known-good


async def test_store_unavailable_serves_last_known_good_and_recovers():
    async with Env() as env:
        cache = env.service.policy_cache
        await env.publish(bundle(ALPHA, rules=[rule("adv")]))
        good = await env.check(ALPHA)
        env.store.fail = ConnectionError("database is down")
        cache.invalidate(ALPHA)
        stale = await env.check(ALPHA)
        env.store.fail = None
        cache.invalidate(ALPHA)
        fresh = await env.check(ALPHA)

    assert good.policy_source is PolicySource.ACTIVE and good.policy_error is None
    assert stale.policy_source is PolicySource.LAST_KNOWN_GOOD
    assert stale.bundle_hash == good.bundle_hash and stale.decision is Decision.ALLOW
    assert stale.model_called
    assert fresh.policy_source is PolicySource.ACTIVE and fresh.policy_error is None


async def test_active_version_failing_verification_serves_last_known_good():
    async with Env() as env:
        await env.publish(bundle(ALPHA, rules=[rule("adv")]))
        good = await env.check(ALPHA)
        await env.publish(bundle(ALPHA, version=2, rules=[rule("other")]))
        tamper(env, ALPHA, 2)
        with pytest.raises(BundleIntegrityError):
            await env.inner_store.get_version(ALPHA, 2)
        env.service.policy_cache.invalidate(ALPHA)
        env.fake.set_noul("t__adv", 0.95)
        verdict = await env.check(ALPHA)

    assert verdict.policy_source is PolicySource.LAST_KNOWN_GOOD
    assert "verification failed (hash_mismatch)" in verdict.policy_error
    assert verdict.bundle_version == 1 and verdict.bundle_hash == good.bundle_hash
    assert (verdict.decision, verdict.reason) == (Decision.BLOCK, Reason.POLICY)


async def test_r10_05c_last_known_good_after_a_rollback_is_logged_with_both_versions(caplog):
    """Known limit (documented): if the rolled-back-to version can't be loaded, the version
    that was rolled back from keeps being served; this is logged naming both versions."""
    async with Env() as env:
        await env.publish(bundle(ALPHA, rules=[rule("v1")]))
        await env.publish(bundle(ALPHA, version=2, rules=[rule("v2")]))
        assert (await env.check(ALPHA)).bundle_version == 2
        await env.inner_store.set_active_version(ALPHA, 1)  # the rollback
        tamper(env, ALPHA, 1)  # ... and v1 can't be loaded
        env.service.policy_cache.invalidate(ALPHA)
        verdict = await env.check(ALPHA)
    assert verdict.bundle_version == 2
    assert verdict.policy_source is PolicySource.LAST_KNOWN_GOOD
    assert "serving version 2 although the active pointer names version 1" in verdict.policy_error
    assert "pointer names version 1" in caplog.text


async def test_no_last_known_good_blocks_as_policy_unavailable_without_a_model_call():
    async with Env() as env:
        await env.publish(bundle(ALPHA))
        env.store.fail = ConnectionError("database is down")
        verdict = await env.check(ALPHA)
    assert (verdict.decision, verdict.reason) == (Decision.BLOCK, Reason.POLICY_UNAVAILABLE)
    assert verdict.bundle_version is None and verdict.policy_source is None
    assert "ConnectionError" in verdict.policy_error
    assert not verdict.model_called and env.fake.calls == []
    assert env.audit.verdicts == [verdict]
    assert verdict.retryable


async def test_tenant_with_no_active_version_blocks_as_policy_unavailable():
    async with Env() as env:
        await env.publish(bundle(ALPHA), activate=False)
        verdict = await env.check(ALPHA)
    assert (verdict.decision, verdict.reason) == (Decision.BLOCK, Reason.POLICY_UNAVAILABLE)
    assert "no active policy version" in verdict.policy_error
    assert env.fake.calls == []


async def test_tenant_missing_from_the_directory_blocks_as_policy_unavailable():
    async with Env(tenants=[]) as env:
        await env.publish(bundle(ALPHA))
        verdict = await env.check(ALPHA)
    assert verdict.reason is Reason.POLICY_UNAVAILABLE
    assert "tenant directory" in verdict.policy_error


async def test_last_known_good_is_per_tenant():
    async with Env() as env:
        await env.publish(bundle(ALPHA))
        await env.publish(bundle(BETA))
        await env.check(ALPHA)  # only alpha has loaded before the outage
        env.store.fail = ConnectionError("down")
        env.service.policy_cache.invalidate(ALPHA)
        alpha = await env.check(ALPHA)
        beta = await env.check(BETA)
    assert alpha.policy_source is PolicySource.LAST_KNOWN_GOOD
    assert beta.reason is Reason.POLICY_UNAVAILABLE


# ------------------------------------------------------------------ authoritative absence


def clear_pointer(env, tenant_id):
    """The store answers "no active version" (the port has no clear operation yet)."""
    env.inner_store._active.pop(tenant_id)


@pytest.mark.parametrize("absence", ["pointer cleared", "removed from the directory"])
async def test_authoritative_absence_stops_serving_and_drops_last_known_good(absence):
    async with Env() as env:
        cache = env.service.policy_cache
        await env.publish(bundle(ALPHA))
        assert (await env.check(ALPHA)).decision is Decision.ALLOW
        if absence == "pointer cleared":
            clear_pointer(env, ALPHA)
            expected = "no active policy version"
        else:
            env.directory.remove(ALPHA)
            expected = "not in the tenant directory"
        cache.invalidate(ALPHA)
        verdict = await env.check(ALPHA)
        again = await env.check(ALPHA)  # no last-known-good left to fall back on
    for v in (verdict, again):
        assert (v.decision, v.reason) == (Decision.BLOCK, Reason.POLICY_UNAVAILABLE)
        assert expected in v.policy_error
        assert v.bundle_version is None and v.policy_source is None
    assert len(env.fake.calls) == 1  # only the check before the absence


async def test_absence_found_by_a_background_refresh_also_stops_serving():
    clock = Clock()
    async with Env(config=GuardConfig(pointer_ttl_s=5.0), cache_clock=clock) as env:
        cache = env.service.policy_cache
        await env.publish(bundle(ALPHA))
        await env.check(ALPHA)
        env.directory.remove(ALPHA)  # suspended
        clock.now += 5.0
        await env.check(ALPHA)  # stale: served once while revalidating
        await cache.drain()
        verdict = await env.check(ALPHA)
        calls = env.store.calls["get_active_version"]
        await env.check(ALPHA)  # remembered for the TTL: no store call per check
        assert env.store.calls["get_active_version"] == calls
    assert verdict.reason is Reason.POLICY_UNAVAILABLE


async def test_a_tenant_that_comes_back_is_served_again():
    async with Env() as env:
        cache = env.service.policy_cache
        await env.publish(bundle(ALPHA))
        await env.check(ALPHA)
        env.directory.remove(ALPHA)
        cache.invalidate(ALPHA)
        assert (await env.check(ALPHA)).reason is Reason.POLICY_UNAVAILABLE
        env.directory.put(profile(ALPHA))
        cache.invalidate(ALPHA)
        back = await env.check(ALPHA)
    assert (back.decision, back.policy_source) == (Decision.ALLOW, PolicySource.ACTIVE)


@pytest.mark.parametrize("failure", ["store error", "store timeout", "directory error"])
async def test_a_genuine_outage_still_serves_last_known_good(failure):
    config = GuardConfig(pointer_ttl_s=60.0, store_timeout_s=0.05)

    class FailingDirectory:
        def __init__(self, inner):
            self.inner, self.fail = inner, False

        async def get(self, tenant_id):
            if self.fail:
                raise OSError("directory down")
            return await self.inner.get(tenant_id)

    directory = FailingDirectory(InMemoryTenantDirectory([profile(ALPHA)]))
    async with Env(config=config, directory=directory) as env:
        await env.publish(bundle(ALPHA))
        good = await env.check(ALPHA)
        if failure == "store error":
            env.store.fail = ConnectionError("database is down")
        elif failure == "store timeout":
            env.store.hang = True
        else:
            directory.fail = True
        env.service.policy_cache.invalidate(ALPHA)
        verdict = await env.check(ALPHA)
    assert verdict.policy_source is PolicySource.LAST_KNOWN_GOOD
    assert (verdict.decision, verdict.bundle_hash) == (Decision.ALLOW, good.bundle_hash)


# ------------------------------------------------------------------ no policy


class GatedDirectory:
    """Wraps a tenant directory; counts calls and, while ``gate`` is set, holds each call
    until the event is set."""

    def __init__(self, inner):
        self.inner, self.gate, self.calls = inner, None, 0

    async def get(self, tenant_id):
        self.calls += 1
        if self.gate is not None:
            await self.gate.wait()
        return await self.inner.get(tenant_id)


def count_arrivals(cache):
    """Counts checks that have entered ``cache.get``. There is no suspension point between
    entering it and queueing on the tenant's lock, so a check that has entered and isn't done
    is either refreshing or queued behind the refresh."""
    arrivals = []
    real = cache.get

    async def get(tenant_id, guard_point):
        arrivals.append(tenant_id)
        return await real(tenant_id, guard_point)

    cache.get = get
    return arrivals


async def until(condition, steps=1000):
    """Yield to the event loop until ``condition()`` holds (no wall-clock waiting)."""
    for _ in range(steps):
        if condition():
            return
        await asyncio.sleep(0)
    raise AssertionError("condition not reached")


async def test_queued_checks_of_an_absent_tenant_share_one_refresh_at_expiry():
    """The probe: after the TTL expires, 10 concurrent checks of a tenant missing
    from the directory made 10 directory reads, one after another."""
    clock = Clock()
    directory = GatedDirectory(InMemoryTenantDirectory([]))  # ALPHA isn't in it
    config = GuardConfig(pointer_ttl_s=5.0, store_timeout_s=30.0)
    async with Env(config=config, cache_clock=clock, directory=directory) as env:
        cache = env.service.policy_cache
        await env.publish(bundle(ALPHA))
        assert "not in the tenant directory" in (await env.check(ALPHA)).policy_error
        clock.now += 5.0
        directory.calls, directory.gate = 0, asyncio.Event()
        arrivals = count_arrivals(cache)
        tasks = [asyncio.ensure_future(env.check(ALPHA)) for _ in range(10)]
        await until(lambda: len(arrivals) == 10 and directory.calls == 1)
        assert not any(t.done() for t in tasks)  # one refreshing, nine queued behind it
        directory.gate.set()
        verdicts = await asyncio.gather(*tasks)
    assert directory.calls == 1
    for v in verdicts:
        assert (v.decision, v.reason) == (Decision.BLOCK, Reason.POLICY_UNAVAILABLE)
        assert "not in the tenant directory" in v.policy_error
    assert env.fake.calls == []


async def test_concurrent_checks_of_a_never_compiled_tenant_share_one_failed_refresh():
    """The second probe: during an outage, 5 concurrent checks of a tenant with
    nothing compiled each waited out their own store call, one after another."""
    config = GuardConfig(pointer_ttl_s=60.0, store_timeout_s=30.0)
    async with Env(config=config) as env:
        cache = env.service.policy_cache
        await env.publish(bundle(ALPHA))
        env.store.fail = ConnectionError("database is down")
        env.store.gate = asyncio.Event()
        arrivals = count_arrivals(cache)
        tasks = [asyncio.ensure_future(env.check(ALPHA)) for _ in range(5)]
        await until(lambda: len(arrivals) == 5 and env.store.calls.get("get_active_version"))
        assert not any(t.done() for t in tasks)
        env.store.gate.set()
        verdicts = await asyncio.gather(*tasks)
        assert env.store.calls["get_active_version"] == 1
        for v in verdicts:
            assert (v.decision, v.reason) == (Decision.BLOCK, Reason.POLICY_UNAVAILABLE)
            # The exception's type is recorded, never its text.
            assert v.policy_error == "ConnectionError" and not v.model_called

        # A failure isn't remembered: the next check tries again and is served once the
        # store is back, without waiting for the TTL.
        env.store.fail = None
        after = await env.check(ALPHA)
        assert env.store.calls["get_active_version"] == 2
    assert (after.decision, after.policy_source) == (Decision.ALLOW, PolicySource.ACTIVE)


@pytest.mark.parametrize("absence", ["pointer cleared", "removed from the directory"])
async def test_a_store_failure_after_an_absence_is_reported_and_retried(absence):
    """The probe: absent, then the TTL expires, then the store goes down. Every
    check for the next TTL reported the old absence without trying the store."""
    clock = Clock()
    config = GuardConfig(pointer_ttl_s=5.0, store_timeout_s=30.0)
    async with Env(config=config, cache_clock=clock) as env:
        await env.publish(bundle(ALPHA))
        if absence == "pointer cleared":
            clear_pointer(env, ALPHA)
            expected = "no active policy version"
        else:
            env.directory.remove(ALPHA)
            expected = "not in the tenant directory"
        absent = await env.check(ALPHA)
        clock.now += 5.0
        env.store.fail = ConnectionError("database is down")
        first = await env.check(ALPHA)
        second = await env.check(ALPHA)  # within the TTL of the first failure
        calls = env.store.calls["get_active_version"]
        # The store and the tenant are both back: served at the next check, with no TTL
        # wait and no invalidate.
        env.store.fail = None
        await env.inner_store.set_active_version(ALPHA, 1)
        env.directory.put(profile(ALPHA))
        back = await env.check(ALPHA)
    assert expected in absent.policy_error
    for v in (first, second):
        assert (v.decision, v.reason) == (Decision.BLOCK, Reason.POLICY_UNAVAILABLE)
        assert v.policy_error == "ConnectionError"  # type name only, no text
        assert expected not in v.policy_error
        assert v.policy_source is None and v.retryable
    assert calls == 3  # the second check tried the store too
    assert (back.decision, back.policy_source) == (Decision.ALLOW, PolicySource.ACTIVE)


# ------------------------------------------------------------------ outage latency


async def test_r10_05a_store_outage_adds_no_latency_once_a_tenant_has_a_policy():
    """Stale-while-revalidate: when the TTL expires during an outage, checks are served at
    once from the cached entry, and one background refresh per tenant waits out the store
    timeout instead of every check."""
    clock = Clock()
    # 20 checks at once, all of whose model calls must run: the gateway's per-key admission
    # limit (default 2, M1-04) is lifted to the burst, so the test still measures only the
    # policy cache. Admission control has its own tests (tests/gateway).
    config = GuardConfig(
        pointer_ttl_s=5.0,
        store_timeout_s=0.3,
        gateway=GatewayConfig(max_in_flight_per_key=20),
    )
    async with Env(config=config, cache_clock=clock) as env:
        cache = env.service.policy_cache
        await env.publish(bundle(ALPHA))
        await env.check(ALPHA)
        clock.now += 5.0
        env.store.hang = True

        start = time.perf_counter()
        verdicts = await asyncio.gather(*(env.check(ALPHA) for _ in range(20)))
        elapsed = time.perf_counter() - start
        assert elapsed < 0.15, elapsed  # not the 0.3 s store timeout
        assert all(v.decision is Decision.ALLOW for v in verdicts)
        assert env.store.calls["get_active_version"] == 2  # one background refresh

        await cache.drain()  # it times out in the background
        start = time.perf_counter()
        after = await env.check(ALPHA)
        assert time.perf_counter() - start < 0.15
        assert after.policy_source is PolicySource.LAST_KNOWN_GOOD
        assert "timed out" in after.policy_error
        assert env.store.calls["get_active_version"] == 2  # retried only after the TTL


async def test_r10_05a_background_refreshes_stop_when_the_service_closes():
    clock = Clock()
    config = GuardConfig(pointer_ttl_s=5.0, store_timeout_s=30.0)
    async with Env(config=config, cache_clock=clock) as env:
        await env.publish(bundle(ALPHA))
        await env.check(ALPHA)
        clock.now += 5.0
        env.store.hang = True
        await env.check(ALPHA)  # starts a background refresh that hangs
        start = time.perf_counter()
    assert time.perf_counter() - start < 1.0  # aclose cancelled it
    for _ in range(5):
        await asyncio.sleep(0)
    assert len(asyncio.all_tasks()) == 1


# ------------------------------------------------------------------ profile re-read


async def test_r10_05b_a_changed_tenant_profile_takes_effect_at_the_next_refresh():
    clock = Clock()
    async with Env(config=GuardConfig(pointer_ttl_s=5.0), cache_clock=clock) as env:
        cache = env.service.policy_cache
        await env.publish(bundle(ALPHA))
        context = (ToolCall("claims.status", "{}"),)
        await env.check(ALPHA, conversation=context)
        assert "TENANT DOMAIN: insurance" in env.fake.calls[-1].input

        tools = [ToolInfo("claims.status", "Now described differently."), *TOOLS[1:]]
        env.directory.put(profile(ALPHA, "general", tools))  # a platform-ops change
        clock.now += 5.0
        await env.check(ALPHA, conversation=context)  # stale, revalidating
        await cache.drain()
        await env.check(ALPHA, conversation=context)
    text = env.fake.calls[-1].input
    assert text.startswith("TENANT DOMAIN: general\n")
    assert "claims.status: Now described differently." in text
    assert cache.compiles == 2  # recompiled for the new profile; no publish needed


# ------------------------------------------------------------------ no scans


class CountingDict(dict):
    iterations = 0

    def __iter__(self):
        type(self).iterations += 1
        return super().__iter__()

    def keys(self):
        type(self).iterations += 1
        return super().keys()

    def items(self):
        type(self).iterations += 1
        return super().items()

    def values(self):
        type(self).iterations += 1
        return super().values()


async def test_r10_05d_a_refresh_touches_only_its_own_tenant():
    async with Env() as env:
        cache = env.service.policy_cache
        for tenant in (ALPHA, BETA, GAMMA):
            await env.publish(bundle(tenant))
            await env.check(tenant)
        cache._state = CountingDict(cache._state)
        CountingDict.iterations = 0
        await env.publish(bundle(ALPHA, version=2))
        cache.invalidate(ALPHA)
        assert (await env.check(ALPHA)).bundle_version == 2  # a refresh with a recompile
        await env.check(BETA)
    assert CountingDict.iterations == 0
    assert cache.compiles == 4
