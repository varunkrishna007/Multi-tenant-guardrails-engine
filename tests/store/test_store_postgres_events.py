"""M2-07: ``guardrail.published`` and ``tenant.changed`` over Postgres LISTEN/NOTIFY. Best
effort by design: what the listener misses, the TTLs cover. Needs GUARDRAIL_TEST_PG_DSN."""

import asyncio

import pytest
from store_harness import ACME, OTHER

from guardrail_engine.admin.lifecycle import GuardrailPublished
from guardrail_engine.directory.model import TenantChanged
from guardrail_engine.store.adapters.postgres import (
    EVENT_CHANNEL,
    PostgresEventBus,
    event_payload,
    parse_event,
)


async def wait_for(predicate, seconds=3.0):
    loop = asyncio.get_running_loop()
    end = loop.time() + seconds
    while loop.time() < end:
        if predicate():
            return True
        await asyncio.sleep(0.02)
    return predicate()


@pytest.fixture
async def buses(pg_pool):
    """Two buses on the same database, as two replicas. Each listener holds one connection for
    good, so the pool must have more than the buses use (the test pool for the app role has 2)."""
    first = PostgresEventBus(pg_pool, reconnect_s=0.1, check_s=0.2)
    second = PostgresEventBus(pg_pool, reconnect_s=0.1, check_s=0.2)
    yield first, second
    await first.aclose()
    await second.aclose()


async def test_a_published_event_reaches_every_listening_replica(buses):
    sender, receiver = buses
    heard_here, heard_there = [], []
    sender.subscribe(heard_here.append)
    receiver.subscribe(heard_there.append)
    await sender.start()
    await receiver.start()
    await sender.publish(GuardrailPublished(ACME, 7, "promote"))
    assert await wait_for(lambda: heard_here and heard_there)
    assert heard_here == heard_there == [GuardrailPublished(ACME, 7, "promote")]


async def test_a_tenant_changed_event_travels_too(buses):
    sender, receiver = buses
    heard = []
    receiver.subscribe(heard.append)
    await receiver.start()
    await sender.publish(TenantChanged(OTHER, 3, "set_status"))
    assert await wait_for(lambda: heard)
    assert heard == [TenantChanged(OTHER, 3, "set_status")]


async def test_nobody_hears_an_event_sent_while_they_are_not_listening(buses):
    sender, receiver = buses
    heard = []
    receiver.subscribe(heard.append)
    await sender.publish(GuardrailPublished(ACME, 1, "publish"))  # receiver not started: lost
    await receiver.start()
    await asyncio.sleep(0.3)
    assert heard == []  # best effort: the TTL is the bound, not the bus


async def test_a_payload_that_is_not_exactly_one_of_ours_is_ignored(buses, pg_pool):
    sender, receiver = buses
    heard = []
    receiver.subscribe(heard.append)
    await receiver.start()
    bad = [
        "not json",
        "[]",
        '{"v":2,"kind":"published","tenant_id":"t_acmeins","version":1,"action":"promote"}',
        '{"v":1,"kind":"published","tenant_id":"T_BAD","version":1,"action":"promote"}',
        '{"v":1,"kind":"published","tenant_id":"t_acmeins","version":1,"action":"explode"}',
        '{"v":1,"kind":"published","tenant_id":"t_acmeins","version":"1","action":"promote"}',
        '{"v":1,"kind":"published","tenant_id":"t_acmeins","version":true,"action":"promote"}',
        '{"v":1,"kind":"published","tenant_id":"t_acmeins","version":1}',  # no action
        '{"v":1,"kind":"shrug","tenant_id":"t_acmeins","version":1}',
        "x" * 2000,
    ]
    for payload in bad:
        await pg_pool.execute("SELECT pg_notify($1, $2)", EVENT_CHANNEL, payload)
    await sender.publish(GuardrailPublished(ACME, 2, "rollback"))  # one good one at the end
    assert await wait_for(lambda: heard)
    assert heard == [GuardrailPublished(ACME, 2, "rollback")]


async def test_a_listener_that_loses_its_connection_comes_back(buses, pg_pool):
    sender, receiver = buses
    heard = []
    receiver.subscribe(heard.append)
    await receiver.start()
    await sender.publish(GuardrailPublished(ACME, 1, "publish"))
    assert await wait_for(lambda: len(heard) == 1)
    # kill the application role's other sessions: the listener's connection dies
    async with pg_pool.acquire() as conn:
        # the listener's session is the one whose last statement is its keep-alive or its LISTEN
        killed = await conn.fetchval(
            "SELECT count(pg_terminate_backend(pid)) FROM pg_stat_activity "
            "WHERE pid <> pg_backend_pid() AND datname = current_database() "
            "AND (query = 'SELECT 1' OR query ILIKE 'LISTEN%')"
        )
    assert killed >= 1
    await asyncio.sleep(0.6)  # the check interval, the reconnect interval
    assert await wait_for(lambda: receiver._listening.is_set(), 5.0)
    await sender.publish(GuardrailPublished(ACME, 2, "promote"))
    assert await wait_for(lambda: len(heard) == 2, 5.0)


def test_the_payload_round_trips_and_stays_small():
    for event in (GuardrailPublished(ACME, 12, "set_percent"), TenantChanged(ACME, 1, "create")):
        payload = event_payload(event)
        assert parse_event(payload) == event and len(payload) < 200
    with pytest.raises(TypeError):
        event_payload("nope")  # type: ignore[arg-type]
