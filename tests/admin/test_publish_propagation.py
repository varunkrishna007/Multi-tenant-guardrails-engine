"""M2-07 PF-13: a publish or rollback reaches the Guard Service within 30 s through the event
and within the pointer TTL (60 s) when the event is dropped. Both bounds are tested on the real
Guard Service and policy cache with an injected clock."""

import json

import pytest
from admin_fixtures import ALPHA, Admin, bundle, rule, who

from guardrail_engine.authz import Role
from guardrail_engine.guard.service import GuardConfig
from guardrail_engine.tenant_scope import issue_scope

BASE = "/v1/tenants/{tid}/guardrails"
ADMIN = who(Role.GUARDRAIL_ADMIN, issuer="https://i/")
TTL_S = 60.0  # the pointer TTL the Guard Service runs with (GuardConfig's default here)


@pytest.fixture
async def a():
    admin = Admin()
    # What the engine's factory does: the cache is invalidated on guardrail.published.
    admin.bus.subscribe(lambda event: admin.env.service.policy_cache.invalidate(event.tenant_id))
    yield admin
    await admin.aclose()


async def decide(a, method, route, principal=ADMIN):
    return await a.decide(principal, method, BASE + route, ALPHA)


async def save(a, doc, *, if_match=None):
    d = await decide(a, "PUT", "/draft")
    return await a.service.put_draft(d, ADMIN, json.dumps(doc).encode(), if_match)


async def publish(a, mode="enforce", percent=100):
    draft = await a.drafts.scoped(issue_scope(ALPHA)).get(ALPHA)
    d = await decide(a, "POST", "/draft/publish")
    body = json.dumps({"mode": mode, "rollout_percent": percent}).encode()
    return await a.publisher.publish(d, ADMIN, body, draft.etag)


async def serving(a):
    """The version the Guard Service decides with right now, and whether it hit the store."""
    verdict = await a.env.check(ALPHA)
    return verdict.bundle_version


async def two_versions(a):
    """Version 1 active and served, version 2 a published candidate (not yet promoted)."""
    await save(a, bundle(ALPHA, rules=[rule("v1", gps=("output",), mode="shadow")]))
    await publish(a)
    assert await serving(a) == 1  # the cache now holds version 1
    await save(a, bundle(ALPHA, rules=[rule("v2", gps=("output",), mode="shadow")]), if_match="*")
    await publish(a, "shadow", 10)
    assert await serving(a) == 1  # a candidate changes nothing for the Guard Service


async def test_a_promotion_is_served_at_the_next_check_when_the_event_arrives(a):
    await two_versions(a)
    await a.publisher.promote(await decide(a, "POST", "/candidate/promote"), ADMIN)
    assert a.bus.published[-1].action == "promote"
    assert await serving(a) == 2  # no clock movement at all: the event invalidated the cache


async def test_a_rollback_is_served_at_the_next_check_when_the_event_arrives(a):
    await two_versions(a)
    await a.publisher.promote(await decide(a, "POST", "/candidate/promote"), ADMIN)
    assert await serving(a) == 2
    await a.publisher.rollback(await decide(a, "POST", "/versions/{v}/rollback"), ADMIN, 1)
    assert await serving(a) == 1


@pytest.mark.parametrize("action", ["promote", "rollback"])
async def test_with_the_event_dropped_the_change_is_served_within_the_pointer_ttl(a, action):
    await two_versions(a)
    if action == "rollback":
        await a.publisher.promote(await decide(a, "POST", "/candidate/promote"), ADMIN)
        assert await serving(a) == 2
        a.bus.drop = True
        await a.publisher.rollback(await decide(a, "POST", "/versions/{v}/rollback"), ADMIN, 1)
        old, new = 2, 1
    else:
        a.bus.drop = True
        await a.publisher.promote(await decide(a, "POST", "/candidate/promote"), ADMIN)
        old, new = 1, 2
    cache = a.env.service.policy_cache
    a.cache_now += TTL_S - 1
    assert await serving(a) == old  # last-known-good, inside the TTL
    a.cache_now += 2  # past the TTL
    first_after = await serving(a)  # revalidates in the background; may still answer old
    await cache.drain()
    assert first_after in (old, new)
    assert await serving(a) == new  # and from here on, the new version
    assert GuardConfig(pointer_ttl_s=60.0).pointer_ttl_s == TTL_S


async def test_the_guard_service_never_serves_a_candidate(a):
    await two_versions(a)
    for _ in range(3):
        assert await serving(a) == 1  # shadow candidate at 10%: M4-03 decides what it does
    await a.publisher.abandon(await decide(a, "POST", "/candidate/abandon"), ADMIN)
    assert await serving(a) == 1
