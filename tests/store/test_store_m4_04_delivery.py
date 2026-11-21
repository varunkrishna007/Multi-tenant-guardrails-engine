"""M4-04: the Postgres outbox and usage store (migrations 024 and 025).

They need ``GUARDRAIL_TEST_PG_DSN`` and are skipped without it. The sinks are synchronous and
talk to Postgres through a bridge thread, so these tests call them from a worker thread
(``asyncio.to_thread``) as the gateway's drainer does. Each test gets its own schema and a
least-privilege application role."""

import asyncio
import uuid

import asyncpg
import pytest

from guardrail_engine.delivery import (
    DeliveryError,
    DurableAlertSink,
    DurableUsageMeter,
    OutboxDispatcher,
    RetryPolicy,
)
from guardrail_engine.delivery.adapters.postgres import PgBridge, PostgresOutbox, PostgresUsageStore
from guardrail_engine.delivery.events import (
    KIND_ALERT,
    KIND_USAGE,
    UsageEvent,
    encode_alert,
    encode_usage,
)
from guardrail_engine.gateway import Alert, AlertSeverity
from guardrail_engine.store.adapters.postgres import apply_app_role_grants, apply_schema

T = 1_800_000_000.0


class Env:
    def __init__(self, pg_env, role, password) -> None:
        self.pg_env, self.role, self.password = pg_env, role, password
        self.bridges: list[PgBridge] = []

    def bridge(self) -> PgBridge:
        """A new bridge: its own loop thread and pool, as a new process would have."""

        async def connect():
            return await asyncpg.create_pool(
                self.pg_env.dsn,
                user=self.role,
                password=self.password,
                min_size=1,
                max_size=2,
                server_settings={"search_path": self.pg_env.schema},
            )

        bridge = PgBridge(connect, timeout_s=10)
        self.bridges.append(bridge)
        return bridge

    async def rows(self, sql: str, *args):
        return await self.pg_env.pool.fetch(sql, *args)


@pytest.fixture
async def env(pg_env):
    role = f"m404_app_{uuid.uuid4().hex[:12]}"
    password = uuid.uuid4().hex
    await pg_env.pool.execute(f"CREATE ROLE \"{role}\" LOGIN PASSWORD '{password}'")
    e = Env(pg_env, role, password)
    try:
        await pg_env.pool.execute(f'GRANT USAGE ON SCHEMA "{pg_env.schema}" TO "{role}"')
        await apply_app_role_grants(pg_env.pool, role)
        yield e
    finally:
        for bridge in e.bridges:
            await asyncio.to_thread(bridge.close)
        await pg_env.pool.execute(f'DROP OWNED BY "{role}"')
        await pg_env.pool.execute(f'DROP ROLE "{role}"')


def alert(**kw) -> Alert:
    fields = dict(
        severity=AlertSeverity.PAGE,
        kind="decision_auth_failure",
        message="fixed",
        key_id="k",
        tenant_id="t_a",
        guard_point="output",
    )
    fields.update(kw)
    return Alert(**fields)


class RecordingSink:
    def __init__(self) -> None:
        self.calls: list[tuple[Alert, str]] = []
        self.fail = 0

    def deliver(self, a, key):
        self.calls.append((a, key))
        if self.fail:
            self.fail -= 1
            raise DeliveryError("http_503")


async def test_the_migration_is_idempotent_and_creates_both_tables(pg_env):
    await apply_schema(pg_env.pool)  # a second time
    tables = {
        r["tablename"]
        for r in await pg_env.pool.fetch(
            "SELECT tablename FROM pg_tables WHERE schemaname = current_schema()"
        )
    }
    assert {"delivery_outbox", "usage_events"} <= tables


async def test_enqueue_claim_and_the_state_changes(env):
    outbox = PostgresOutbox(env.bridge())

    def work():
        assert outbox.enqueue(KIND_ALERT, "{}", "k1", T)
        assert not outbox.enqueue(KIND_ALERT, "{}", "k1", T)  # the same key is stored once
        assert outbox.enqueue(KIND_USAGE, "{}", "k2", T + 1)
        assert outbox.claim_due(T - 1, 10, 60, (KIND_ALERT, KIND_USAGE)) == []  # not due
        [a] = outbox.claim_due(T, 10, 60, (KIND_ALERT,))
        assert (a.key, a.kind, a.attempts) == ("k1", KIND_ALERT, 0)
        assert (a.created_at, a.lease) == (T, T + 60)
        assert outbox.claim_due(T + 30, 10, 60, (KIND_ALERT,)) == []  # leased
        [again] = outbox.claim_due(T + 61, 10, 60, (KIND_ALERT,))  # the lease ran out
        assert again.id == a.id
        assert not outbox.mark_failed(a, 1, T + 100, "stale")  # a's lease is not the event's now
        assert outbox.mark_failed(again, 1, T + 100, "http_503")
        assert outbox.claim_due(T + 99, 10, 60, (KIND_ALERT,)) == []
        [retry] = outbox.claim_due(T + 100, 10, 60, (KIND_ALERT,))
        assert retry.attempts == 1
        assert outbox.mark_dead(retry, 2, T + 101, "http_500")
        usage = outbox.claim_due(T + 1, 10, 60, (KIND_USAGE,))[0]
        assert outbox.mark_delivered(usage, T + 2)
        return outbox.stats()

    stats = await asyncio.to_thread(work)
    assert (stats.pending, stats.delivered, stats.dead) == (0, 1, 1)
    row = (await env.rows("SELECT attempts, last_error, state FROM delivery_outbox ORDER BY id"))[0]
    assert (row["attempts"], row["last_error"], row["state"]) == (2, "http_500", "dead")


async def test_claims_by_two_dispatchers_never_overlap(env):
    one, two = PostgresOutbox(env.bridge()), PostgresOutbox(env.bridge())

    def work():
        for i in range(40):
            one.enqueue(KIND_ALERT, "{}", f"k{i}", T)
        a = one.claim_due(T, 25, 60, (KIND_ALERT,))
        b = two.claim_due(T, 25, 60, (KIND_ALERT,))
        return {e.id for e in a}, {e.id for e in b}

    a, b = await asyncio.to_thread(work)
    assert len(a) == 25 and len(b) == 15 and not a & b


async def test_a_late_worker_cannot_overwrite_the_worker_that_finished(env):
    """The probe: A claims, its delivery outlives the lease, B claims, delivers and
    marks it delivered; A's late timeout must not turn it dead."""
    a_store, b_store = PostgresOutbox(env.bridge()), PostgresOutbox(env.bridge())

    def work():
        a_store.enqueue(KIND_ALERT, "{}", "k1", T)
        [a] = a_store.claim_due(T, 10, 120, (KIND_ALERT,))
        [b] = b_store.claim_due(T + 121, 10, 120, (KIND_ALERT,))  # A's lease ran out
        assert b_store.mark_delivered(b, T + 122)
        assert not a_store.mark_dead(a, 8, T + 130, "timeout")  # A's late failure: refused
        assert not a_store.mark_failed(a, 1, T + 140, "timeout")
        assert not a_store.mark_delivered(a, T + 150)
        assert a_store.renew(a, T + 150, 120) is None
        return a_store.stats()

    stats = await asyncio.to_thread(work)
    assert (stats.pending, stats.delivered, stats.dead) == (0, 1, 0)
    row = (await env.rows("SELECT state, attempts, last_error FROM delivery_outbox"))[0]
    assert (row["state"], row["attempts"], row["last_error"]) == ("delivered", 0, None)
    # An operator's requeue_dead has nothing to send again.
    assert await asyncio.to_thread(a_store.requeue_dead, T + 200) == 0


async def test_a_late_worker_cannot_undo_a_newer_workers_retry_schedule(env):
    a_store, b_store = PostgresOutbox(env.bridge()), PostgresOutbox(env.bridge())

    def work():
        a_store.enqueue(KIND_ALERT, "{}", "k1", T)
        [a] = a_store.claim_due(T, 10, 60, (KIND_ALERT,))
        [b] = b_store.claim_due(T + 61, 10, 60, (KIND_ALERT,))
        assert b_store.mark_failed(b, 1, T + 500, "http_503")
        assert not a_store.mark_failed(a, 5, T + 70, "timeout")  # would pull the retry forward
        return b_store.claim_due(T + 100, 10, 60, (KIND_ALERT,)), b_store.claim_due(
            T + 500, 10, 60, (KIND_ALERT,)
        )

    early, on_time = await asyncio.to_thread(work)
    assert early == [] and [e.attempts for e in on_time] == [1]


async def test_renew_extends_only_the_holders_lease(env):
    outbox = PostgresOutbox(env.bridge())

    def work():
        outbox.enqueue(KIND_ALERT, "{}", "k1", T)
        [a] = outbox.claim_due(T, 10, 60, (KIND_ALERT,))
        renewed = outbox.renew(a, T + 50, 60)  # now held until T + 110
        assert renewed is not None and renewed.lease == T + 110 and renewed.id == a.id
        assert outbox.claim_due(T + 100, 10, 60, (KIND_ALERT,)) == []  # still ours
        assert outbox.renew(a, T + 100, 60) is None  # the old token is spent
        assert outbox.mark_delivered(renewed, T + 101)
        return outbox.stats()

    assert (await asyncio.to_thread(work)).delivered == 1


async def test_a_slow_batch_does_not_hand_its_tail_to_the_other_replica(env):
    """The second probe on Postgres: 20 events, a sink that takes 10 s each, a
    120 s lease. The other replica takes over once the lease of the tail has run out; the
    first replica must notice at its renewal and leave those events alone."""
    clock = [T]
    outbox_a, outbox_b = PostgresOutbox(env.bridge()), PostgresOutbox(env.bridge())
    sink_a, sink_b = RecordingSink(), RecordingSink()
    dispatcher_b = OutboxDispatcher(
        outbox_b, alerts=sink_b, clock=lambda: clock[0], batch_size=20, lease_s=120.0
    )
    ran_b = []

    class SlowSink(RecordingSink):
        def deliver(self, a, key):
            super().deliver(a, key)
            clock[0] += 10.0
            if len(self.calls) == 13 and not ran_b:  # the tail's lease has now run out
                ran_b.append(dispatcher_b.run_once())

    sink_a = SlowSink()
    dispatcher_a = OutboxDispatcher(
        outbox_a, alerts=sink_a, clock=lambda: clock[0], batch_size=20, lease_s=120.0
    )

    def work():
        for i in range(20):
            outbox_a.enqueue(KIND_ALERT, encode_alert(alert(message=f"m{i}")), f"k{i:02d}", T)
        dispatcher_a.run_once()
        return outbox_a.stats()

    stats = await asyncio.to_thread(work)
    sent = [k for _, k in sink_a.calls] + [k for _, k in sink_b.calls]
    assert sorted(sent) == [f"k{i:02d}" for i in range(20)]  # each exactly once
    assert ran_b and ran_b[0] > 0
    assert (stats.pending, stats.delivered, stats.dead) == (0, 20, 0)


async def test_purge_and_requeue(env):
    outbox = PostgresOutbox(env.bridge())

    def work():
        outbox.enqueue(KIND_ALERT, "{}", "old", T)
        outbox.enqueue(KIND_ALERT, "{}", "dead", T)
        old, dead = outbox.claim_due(T, 10, 60, (KIND_ALERT,))
        assert outbox.mark_delivered(old, T)
        assert outbox.mark_dead(dead, 8, T, "http_500")
        assert outbox.purge_delivered(T - 1) == 0
        assert outbox.purge_delivered(T + 1) == 1
        assert outbox.requeue_dead(T + 5) == 1
        [back] = outbox.claim_due(T + 5, 10, 60, (KIND_ALERT,))
        return back.attempts, outbox.stats()

    attempts, stats = await asyncio.to_thread(work)
    assert attempts == 0 and (stats.pending, stats.dead, stats.delivered) == (1, 0, 0)


async def test_events_written_before_a_restart_are_delivered_after_it(env):
    """The durability test: process one writes through the gateway's sinks and goes away;
    process two (a new bridge, a new dispatcher) delivers everything, once per key."""
    first = env.bridge()

    def before_restart():
        outbox = PostgresOutbox(first)
        DurableAlertSink(outbox, clock=lambda: T).emit(alert(message="page me"))
        meter = DurableUsageMeter(outbox, clock=lambda: T)
        meter.record("t_a", "output", 120)
        meter.record("t_a", "output", None)  # usage unknown
        meter.record_unanswered("t_b", "input")
        first.close()  # the process exits; nothing was delivered

    await asyncio.to_thread(before_restart)
    assert [r["state"] for r in await env.rows("SELECT state FROM delivery_outbox")] == [
        "pending"
    ] * 4

    second = env.bridge()
    sink, usage = RecordingSink(), PostgresUsageStore(second)
    dispatcher = OutboxDispatcher(
        PostgresOutbox(second), alerts=sink, usage=usage, clock=lambda: T + 1
    )
    assert await asyncio.to_thread(dispatcher.run_once) == 4
    assert [a.message for a, _ in sink.calls] == ["page me"]
    rows = await env.rows(
        "SELECT kind, tenant_id, guard_point, input_tokens FROM usage_events ORDER BY kind"
    )
    assert [(r["kind"], r["tenant_id"], r["input_tokens"]) for r in rows] == [
        ("answered", "t_a", 120),
        ("unanswered", "t_b", None),
        ("unknown", "t_a", None),  # unknown stays NULL, never zero
    ]
    assert {r["state"] for r in await env.rows("SELECT state FROM delivery_outbox")} == {
        "delivered"
    }


async def test_an_event_claimed_by_a_process_that_died_comes_back_after_its_lease(env):
    first = env.bridge()
    event = UsageEvent("answered", "t_a", "output", 5, T)

    def before():
        outbox = PostgresOutbox(first)
        outbox.enqueue(KIND_USAGE, encode_usage(event), "k", T)
        assert len(outbox.claim_due(T, 10, 120, (KIND_USAGE,))) == 1  # then the process dies
        first.close()

    await asyncio.to_thread(before)
    second = env.bridge()
    usage = PostgresUsageStore(second)
    now = [T + 10]
    dispatcher = OutboxDispatcher(PostgresOutbox(second), usage=usage, clock=lambda: now[0])
    assert await asyncio.to_thread(dispatcher.run_once) == 0  # still leased
    now[0] = T + 121
    assert await asyncio.to_thread(dispatcher.run_once) == 1
    assert len(await env.rows("SELECT 1 FROM usage_events")) == 1


async def test_a_second_delivery_of_the_same_event_stores_one_usage_row(env):
    usage = PostgresUsageStore(env.bridge())
    event = UsageEvent("answered", "t_a", "output", 5, T)

    def work():
        usage.write(event, "same-key")
        usage.write(event, "same-key")

    await asyncio.to_thread(work)
    assert len(await env.rows("SELECT 1 FROM usage_events")) == 1


async def test_retry_then_dead_letter_in_postgres(env):
    bridge = env.bridge()
    outbox, sink = PostgresOutbox(bridge), RecordingSink()
    sink.fail = 99
    now = [T]
    dispatcher = OutboxDispatcher(
        outbox,
        alerts=sink,
        retry=RetryPolicy(base_s=10, cap_s=40, max_attempts=4, jitter=0),
        alert_retry=RetryPolicy(base_s=10, cap_s=40, max_attempts=4, jitter=0),
        clock=lambda: now[0],
    )

    def work():
        DurableAlertSink(outbox, clock=lambda: T).emit(alert())
        due = []
        for _ in range(4):
            dispatcher.run_once()
            due.append(now[0])
            now[0] += 100
        dispatcher.run_once()
        return outbox.stats()

    stats = await asyncio.to_thread(work)
    assert len(sink.calls) == 4  # not tried a fifth time
    assert (stats.dead, stats.pending) == (1, 0)
    [row] = await env.rows("SELECT attempts, last_error, state, dead_at FROM delivery_outbox")
    assert (row["attempts"], row["last_error"], row["state"]) == (4, "http_503", "dead")
    assert row["dead_at"] is not None
    assert len({k for _, k in sink.calls}) == 1  # one idempotency key through every retry


async def test_the_usage_store_is_also_a_direct_meter(env):
    store = PostgresUsageStore(env.bridge())

    def work():
        store.record("t_a", "output", 7)
        store.record_provider_safety("t_a", "output")
        store.record_model_skipped("t_a", "plan")
        store.record_identifier_patterns_dropped("t_a")

    await asyncio.to_thread(work)
    rows = await env.rows("SELECT kind, guard_point FROM usage_events ORDER BY kind")
    assert [(r["kind"], r["guard_point"]) for r in rows] == [
        ("answered", "output"),
        ("model_skipped", "plan"),
        ("patterns_dropped", ""),
        ("provider_safety", "output"),
    ]


async def test_the_application_role_cannot_rewrite_or_delete_usage(env):
    usage = PostgresUsageStore(env.bridge())
    bridge = env.bridges[0]
    await asyncio.to_thread(usage.write, UsageEvent("answered", "t_a", "g", 1, T), "k")

    async def attempt(pool, sql):
        return await pool.execute(sql)

    for sql in (
        "UPDATE usage_events SET input_tokens = 0",
        "DELETE FROM usage_events",
        "TRUNCATE usage_events",
        "DROP TABLE delivery_outbox",
    ):
        with pytest.raises(DeliveryError) as info:
            await asyncio.to_thread(bridge.run, lambda pool, sql=sql: attempt(pool, sql))
        assert info.value.code == "db_error", sql


async def test_a_database_that_is_down_fails_fast_with_a_coded_error():
    async def connect():
        raise OSError("no database here")

    bridge = PgBridge(connect, timeout_s=2)
    outbox = PostgresOutbox(bridge)
    try:
        with pytest.raises(DeliveryError) as info:
            await asyncio.to_thread(outbox.enqueue, KIND_ALERT, "{}", "k", T)
        assert info.value.code == "db_error"
    finally:
        await asyncio.to_thread(bridge.close)


async def test_a_database_that_hangs_costs_the_caller_its_timeout_and_no_more():
    never = asyncio.Event  # a coroutine that never finishes, on the bridge's own loop

    async def connect():
        await never().wait()

    bridge = PgBridge(connect, timeout_s=0.3)
    try:
        with pytest.raises(DeliveryError) as info:
            await asyncio.to_thread(PostgresOutbox(bridge).stats)
        assert info.value.code == "db_timeout"
    finally:
        await asyncio.to_thread(bridge.close, 1.0)
