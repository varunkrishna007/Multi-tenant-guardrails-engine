"""M4-04: the outbox dispatcher: retries with capped exponential backoff, dead letters,
at-least-once delivery with an idempotency key, and the durable sinks that feed it. In
memory and on injected time; the Postgres version of these is in tests/store."""

import itertools
import logging
import threading
import time

import pytest

from guardrail_engine.decision import FakeDecisionModel
from guardrail_engine.decision.types import NoulQuestion
from guardrail_engine.delivery import (
    DeliveryError,
    DurableAlertSink,
    DurableUsageMeter,
    InMemoryOutbox,
    InMemoryUsageStore,
    OutboxDispatcher,
    RetryPolicy,
)
from guardrail_engine.delivery.events import (
    KIND_ALERT,
    KIND_USAGE,
    UsageEvent,
    decode_alert,
    decode_usage,
    encode_alert,
    encode_usage,
)
from guardrail_engine.gateway import Alert, AlertSeverity, DecisionGateway

QUESTIONS = {"p__harm": NoulQuestion(instructions="Does the content help someone cause harm?")}


def alert(kind="decision_auth_failure", **kw) -> Alert:
    fields = dict(
        severity=AlertSeverity.PAGE,
        kind=kind,
        message="a fixed sentence",
        key_id="k1",
        tenant_id="t_a",
        guard_point="output",
        reason="API_KEY_INVALID",
        count=3,
        rollback="/v1/tenants/t_a/guardrails/versions/1/rollback",
    )
    fields.update(kw)
    return Alert(**fields)


class Clock:
    def __init__(self, now=1_000_000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


class KeyedSink:
    """A real sink stand-in: takes the idempotency key; can be told to fail."""

    def __init__(self) -> None:
        self.calls: list[tuple[Alert, str]] = []
        self.failures: list[Exception] = []

    def deliver(self, a: Alert, key: str) -> None:
        self.calls.append((a, key))
        if self.failures:
            raise self.failures.pop(0)


class PlainSink:
    def __init__(self) -> None:
        self.alerts: list[Alert] = []

    def emit(self, a: Alert) -> None:
        self.alerts.append(a)


def rig(*, sink=None, usage=None, retry=None, outbox=None, **kw):
    clock = Clock()
    outbox = outbox if outbox is not None else InMemoryOutbox()
    policy = retry or RetryPolicy(base_s=10, cap_s=100, max_attempts=5, jitter=0)
    dispatcher = OutboxDispatcher(
        outbox,
        alerts=sink,
        usage=usage,
        retry=policy,
        alert_retry=policy,  # a short, attempt-counted policy for both kinds
        clock=clock,
        rng=lambda: 0.0,
        **kw,
    )
    return clock, outbox, dispatcher


def put(outbox, clock, a=None, key="e1"):
    outbox.enqueue(KIND_ALERT, encode_alert(a or alert()), key, clock())


class TestRoundTrip:
    def test_an_alert_survives_encoding(self):
        a = alert()
        assert decode_alert(encode_alert(a)) == a

    def test_a_usage_event_survives_encoding_with_unknown_tokens_kept_unknown(self):
        e = UsageEvent("unknown", "t_a", "output", None, 12.5)
        assert decode_usage(encode_usage(e)) == e

    def test_an_unknown_usage_kind_is_refused(self):
        with pytest.raises(ValueError):
            UsageEvent("free", "t", "g", 1, 0.0)


class TestDelivery:
    def test_a_due_alert_is_delivered_once_with_its_key(self):
        sink = KeyedSink()
        clock, outbox, d = rig(sink=sink)
        put(outbox, clock, key="key-1")
        assert d.run_once() == 1
        assert d.run_once() == 0
        assert sink.calls == [(alert(), "key-1")]
        assert (outbox.stats().delivered, outbox.stats().pending) == (1, 0)
        assert d.stats.delivered == 1

    def test_a_plain_alert_sink_gets_emit(self):
        sink = PlainSink()
        clock, outbox, d = rig(sink=sink)
        put(outbox, clock)
        d.run_once()
        assert sink.alerts == [alert()]

    def test_usage_goes_to_the_usage_store_under_the_event_key(self):
        store = InMemoryUsageStore()
        clock, outbox, d = rig(usage=store)
        event = UsageEvent("answered", "t_a", "output", 42, clock())
        outbox.enqueue(KIND_USAGE, encode_usage(event), "u-1", clock())
        d.run_once()
        assert store.records == {"u-1": event}

    def test_a_kind_with_no_sink_stays_pending_untouched(self):
        sink = KeyedSink()
        clock, outbox, d = rig(sink=sink)
        event = UsageEvent("answered", "t_a", "output", 42, clock())
        outbox.enqueue(KIND_USAGE, encode_usage(event), "u-1", clock())
        assert d.run_once() == 0
        assert outbox.stats().pending == 1

    def test_events_are_delivered_in_the_order_they_were_written(self):
        sink = KeyedSink()
        clock, outbox, d = rig(sink=sink)
        for i in range(5):
            put(outbox, clock, alert(message=f"m{i}"), key=f"k{i}")
        d.run_once()
        assert [a.message for a, _ in sink.calls] == [f"m{i}" for i in range(5)]

    def test_a_key_is_stored_once(self):
        clock, outbox, _ = rig()
        assert outbox.enqueue(KIND_ALERT, encode_alert(alert()), "same", clock())
        assert not outbox.enqueue(KIND_ALERT, encode_alert(alert()), "same", clock())
        assert outbox.stats().pending == 1


class TestRetryAndDeadLetter:
    def test_the_schedule_is_ten_twenty_forty_eighty_then_one_hundred(self):
        policy = RetryPolicy(base_s=10, cap_s=100, max_attempts=10, jitter=0)
        assert [policy.delay_s(n) for n in range(1, 8)] == [10, 20, 40, 80, 100, 100, 100]

    def test_the_default_policy_is_two_seconds_doubling_to_five_minutes_in_eight_attempts(self):
        policy = RetryPolicy()
        assert (policy.base_s, policy.cap_s, policy.max_attempts) == (2.0, 300.0, 8)
        assert [policy.delay_s(n, lambda: 0.0) for n in range(1, 10)] == [
            2,
            4,
            8,
            16,
            32,
            64,
            128,
            256,
            300,
        ]

    def test_jitter_only_shortens_and_never_exceeds_the_cap(self):
        policy = RetryPolicy(base_s=10, cap_s=100, jitter=0.2)
        assert policy.delay_s(1, lambda: 0.0) == 10
        assert policy.delay_s(1, lambda: 0.999) == pytest.approx(10 * 0.8002, rel=1e-3)
        assert policy.delay_s(30, lambda: 0.0) == 100

    def test_a_failed_delivery_is_retried_on_the_schedule_and_then_succeeds(self):
        sink = KeyedSink()
        sink.failures = [DeliveryError("http_503"), DeliveryError("timeout")]
        clock, outbox, d = rig(sink=sink)
        put(outbox, clock, key="k")
        assert d.run_once() == 1  # fails; due again in 10 s
        clock.now += 9.9
        assert d.run_once() == 0
        clock.now += 0.1
        assert d.run_once() == 1  # fails again; due in 20 s
        clock.now += 19.9
        assert d.run_once() == 0
        clock.now += 0.1
        assert d.run_once() == 1  # succeeds
        assert [k for _, k in sink.calls] == ["k", "k", "k"]  # the same key every time
        assert outbox.stats().delivered == 1
        assert (d.stats.retried, d.stats.delivered, d.stats.dead) == (2, 1, 0)

    def test_after_max_attempts_the_event_is_dead_lettered_and_left_alone(self, caplog):
        sink = KeyedSink()
        sink.failures = [DeliveryError("http_500")] * 20
        clock, outbox, d = rig(sink=sink)  # max_attempts = 5
        put(outbox, clock)
        with caplog.at_level(logging.ERROR):
            for _ in range(5):
                assert d.run_once() == 1
                clock.now += 1000
        assert len(sink.calls) == 5
        assert outbox.stats().dead == 1 and outbox.stats().pending == 0
        assert outbox.last_error(1) == "http_500"
        assert d.run_once() == 0
        clock.now += 10**6
        assert d.run_once() == 0 and len(sink.calls) == 5
        assert any("dead-lettered" in r.getMessage() for r in caplog.records)
        assert d.stats.dead == 1

    def test_requeue_dead_gives_the_event_a_fresh_set_of_attempts(self):
        sink = KeyedSink()
        sink.failures = [DeliveryError("http_500")] * 5
        clock, outbox, d = rig(sink=sink)
        put(outbox, clock)
        for _ in range(5):
            d.run_once()
            clock.now += 1000
        assert outbox.stats().dead == 1
        assert outbox.requeue_dead(clock()) == 1
        assert d.run_once() == 1  # the sink works now
        assert outbox.stats().delivered == 1

    def test_a_failing_event_does_not_hold_back_the_ones_behind_it(self):
        sink = KeyedSink()
        sink.failures = [DeliveryError("http_500")]
        clock, outbox, d = rig(sink=sink)
        put(outbox, clock, alert(message="first"), key="a")
        put(outbox, clock, alert(message="second"), key="b")
        d.run_once()
        assert [a.message for a, _ in sink.calls] == ["first", "second"]
        assert outbox.stats().delivered == 1 and outbox.stats().pending == 1

    def test_an_event_that_cannot_be_decoded_is_dead_at_once(self):
        sink = KeyedSink()
        clock, outbox, d = rig(sink=sink)
        outbox.enqueue(KIND_ALERT, "{not json", "bad", clock())
        d.run_once()
        assert outbox.stats().dead == 1
        assert outbox.last_error(1) == "bad_payload"
        assert sink.calls == []

    def test_the_stored_error_is_a_code_never_the_exception_text(self, caplog):
        class Leaky:
            def deliver(self, a, key):
                raise RuntimeError("POST https://hooks.example/T0K3N-SECRET failed")

        clock, outbox, d = rig(sink=Leaky())
        put(outbox, clock)
        with caplog.at_level(logging.DEBUG):
            d.run_once()
        assert outbox.last_error(1) == "RuntimeError"
        assert "SECRET" not in caplog.text


class TestAtLeastOnce:
    def test_delivered_but_not_recorded_is_sent_again_with_the_same_key_and_stored_once(self):
        class FlakyOutbox(InMemoryOutbox):
            fail_mark = True

            def mark_delivered(self, entry_id, now):
                if self.fail_mark:
                    self.fail_mark = False
                    raise RuntimeError("database went away")
                super().mark_delivered(entry_id, now)

        store = InMemoryUsageStore()
        clock, outbox, d = rig(usage=store, outbox=FlakyOutbox(), lease_s=30)
        event = UsageEvent("answered", "t_a", "output", 42, clock())
        outbox.enqueue(KIND_USAGE, encode_usage(event), "u-1", clock())
        d.run_once()  # written to the store; recording it failed
        assert store.writes == 1 and outbox.stats().pending == 1
        assert d.run_once() == 0  # still leased
        clock.now += 31
        assert d.run_once() == 1  # the lease ran out: sent again
        assert store.writes == 2  # at least once...
        assert list(store.records) == ["u-1"]  # ...and the store keeps one
        assert outbox.stats().delivered == 1

    def test_a_claimed_event_is_invisible_to_another_dispatcher_until_its_lease_ends(self):
        clock, outbox, _ = rig(sink=KeyedSink(), lease_s=60)
        sink2 = KeyedSink()
        d2 = OutboxDispatcher(outbox, alerts=sink2, clock=clock)
        put(outbox, clock)
        claimed = outbox.claim_due(clock(), 10, 60, (KIND_ALERT,))  # d1 claims, then "dies"
        assert len(claimed) == 1
        assert d2.run_once() == 0
        clock.now += 61
        assert d2.run_once() == 1  # picked up after the lease: not lost
        assert len(sink2.calls) == 1

    def test_the_gateway_to_the_sinks_end_to_end_keeps_usage_exact_and_unknown_unknown(self):
        """Gateway -> durable sinks -> outbox -> dispatcher -> real sinks."""
        import asyncio

        outbox = InMemoryOutbox()
        store = InMemoryUsageStore()
        sink = KeyedSink()
        fake = FakeDecisionModel()

        async def go():
            gateway = DecisionGateway(
                fake, meter=DurableUsageMeter(outbox), alerts=DurableAlertSink(outbox)
            )
            for i in range(3):
                await gateway.decide(
                    tenant_id="t_a", guard_point="output", input=f"hello {i}", questions=QUESTIONS
                )
            await gateway.aclose()

        asyncio.run(go())
        d = OutboxDispatcher(outbox, alerts=sink, usage=store, clock=time.time)
        assert d.run_once() == 3
        assert len(store.records) == 3
        assert all(
            e.tenant_id == "t_a" and e.guard_point == "output" for e in store.records.values()
        )


class TestThread:
    def test_the_dispatcher_thread_delivers_and_closes(self):
        sink = KeyedSink()
        outbox = InMemoryOutbox()
        d = OutboxDispatcher(outbox, alerts=sink, poll_s=0.01)
        d.start()
        d.start()  # idempotent
        outbox.enqueue(KIND_ALERT, encode_alert(alert()), "k", time.time())
        deadline = time.monotonic() + 3
        while outbox.stats().delivered < 1:
            assert time.monotonic() < deadline
            time.sleep(0.005)
        assert d.close(timeout=2) is True
        assert d._thread is not None and not d._thread.is_alive()  # it has stopped

    def test_a_stuck_sink_cannot_hold_up_close_and_the_thread_is_a_daemon(self):
        gate = threading.Event()
        entered = threading.Event()

        class Stuck:
            def deliver(self, a, key):
                entered.set()
                gate.wait(30)

        outbox = InMemoryOutbox()
        d = OutboxDispatcher(outbox, alerts=Stuck(), poll_s=0.01)
        d.start()
        outbox.enqueue(KIND_ALERT, encode_alert(alert()), "k", time.time())
        assert entered.wait(3)
        thread = d._thread
        assert thread is not None and thread.daemon
        assert thread.name == "guardrail-outbox-dispatcher"
        start = time.monotonic()
        assert d.close(timeout=0.2) is False
        assert time.monotonic() - start < 1.0
        gate.set()
        thread.join(3)

    def test_a_store_that_fails_to_claim_is_counted_not_fatal(self, caplog):
        class Down(InMemoryOutbox):
            def claim_due(self, *a, **k):
                raise RuntimeError("db down")

        _, _, d = rig(sink=KeyedSink(), outbox=Down())
        assert d.run_once() == 0
        assert d.stats.store_errors == 1

    def test_policy_validation(self):
        for bad in (
            dict(base_s=0),
            dict(base_s=10, cap_s=5),
            dict(max_attempts=0),
            dict(jitter=1.0),
        ):
            with pytest.raises(ValueError):
                RetryPolicy(**bad)


class TestLeaseIsAClaimToken:
    """Marks are guarded by the claim's lease; a batch cannot outrun its lease."""

    def test_probe_one_a_late_worker_cannot_turn_a_delivered_event_dead(self):
        clock = Clock()
        outbox = InMemoryOutbox()
        put(outbox, clock)
        [a] = outbox.claim_due(clock(), 10, 120, (KIND_ALERT,))  # A claims
        clock.now += 121  # A's delivery outlives the lease
        [b] = outbox.claim_due(clock(), 10, 120, (KIND_ALERT,))  # B claims, delivers...
        assert outbox.mark_delivered(b, clock())  # ...and marks it delivered
        clock.now += 5
        assert not outbox.mark_dead(a, 8, clock(), "timeout")  # A's late timeout: refused
        assert not outbox.mark_failed(a, 1, clock() + 10, "timeout")
        assert not outbox.mark_delivered(a, clock())
        assert (outbox.stats().delivered, outbox.stats().dead) == (1, 0)
        assert outbox.requeue_dead(clock()) == 0  # nothing for an operator to send again

    def test_a_late_worker_cannot_undo_a_newer_workers_retry_schedule(self):
        clock = Clock()
        outbox = InMemoryOutbox()
        put(outbox, clock)
        [a] = outbox.claim_due(clock(), 10, 60, (KIND_ALERT,))
        clock.now += 61
        [b] = outbox.claim_due(clock(), 10, 60, (KIND_ALERT,))
        assert outbox.mark_failed(b, 1, clock() + 500, "http_503")
        assert not outbox.mark_failed(a, 7, clock() + 1, "timeout")
        assert outbox.claim_due(clock() + 100, 10, 60, (KIND_ALERT,)) == []
        [again] = outbox.claim_due(clock() + 500, 10, 60, (KIND_ALERT,))
        assert again.attempts == 1

    def test_the_dispatcher_whose_delivery_outlived_its_lease_changes_nothing(self):
        """The same probe through the dispatchers: A's sink is slow and then fails."""
        clock = Clock()
        outbox = InMemoryOutbox()
        b_sink = KeyedSink()
        b = OutboxDispatcher(outbox, alerts=b_sink, clock=clock, lease_s=120)

        class SlowThenFails:
            def deliver(self, a, key):
                clock.now += 130  # past the lease
                assert b.run_once() == 1  # B claims it, delivers it, marks it delivered
                raise DeliveryError("timeout")

        a = OutboxDispatcher(outbox, alerts=SlowThenFails(), clock=clock, lease_s=120)
        put(outbox, clock)
        a.run_once()
        assert (outbox.stats().delivered, outbox.stats().dead, outbox.stats().pending) == (1, 0, 0)
        assert len(b_sink.calls) == 1
        assert (a.stats.retried, a.stats.dead, a.stats.lease_lost) == (0, 0, 1)

    def test_probe_two_a_slow_batch_does_not_hand_its_tail_to_another_replica(self):
        """20 events, a sink that takes 10 s each, a 120 s lease: events 13 to 20 outrun the
        batch's lease. Another replica takes them; this one must renew, find them gone, and
        not send them too. Without the renewal every one of events 13 to 20 is sent twice."""
        clock = Clock()
        outbox = InMemoryOutbox()
        sink_b = KeyedSink()
        b = OutboxDispatcher(outbox, alerts=sink_b, clock=clock, batch_size=20, lease_s=120)
        b_ran = []

        class Slow(KeyedSink):
            def deliver(self, a, key):
                super().deliver(a, key)
                clock.now += 10.0
                if len(self.calls) == 13 and not b_ran:  # events 13..20's lease has run out
                    b_ran.append(b.run_once())

        sink_a = Slow()
        a = OutboxDispatcher(outbox, alerts=sink_a, clock=clock, batch_size=20, lease_s=120)
        for i in range(20):
            put(outbox, clock, alert(message=f"m{i}"), key=f"k{i:02d}")
        a.run_once()
        sent = [k for _, k in sink_a.calls] + [k for _, k in sink_b.calls]
        assert sorted(sent) == [f"k{i:02d}" for i in range(20)]  # every event exactly once
        assert b_ran == [7]  # B took events 14..20 (13 was in A's hands, renewed)
        assert outbox.stats().delivered == 20 and outbox.stats().dead == 0
        assert a.stats.lease_lost == 7

    def test_a_batch_that_fits_its_lease_costs_no_renewals(self):
        class Counting(InMemoryOutbox):
            renewals = 0

            def renew(self, entry, now, lease_s):
                self.renewals += 1
                return super().renew(entry, now, lease_s)

        clock, outbox, d = rig(sink=KeyedSink(), outbox=Counting(), lease_s=120)
        for i in range(10):
            put(outbox, clock, key=f"k{i}")
        d.run_once()
        assert outbox.renewals == 0 and d.stats.delivered == 10

    def test_a_lease_more_than_half_used_is_renewed_before_the_delivery(self):
        seen = []

        class Slow(KeyedSink):
            def deliver(self, a, key):
                seen.append((key, clock.now))
                clock.now += 70  # more than half of a 120 s lease per event

        sink = Slow()
        clock, outbox, d = rig(sink=sink, lease_s=120)
        for i in range(3):
            put(outbox, clock, key=f"k{i}")
        d.run_once()
        assert outbox.stats().delivered == 3 and d.stats.lease_lost == 0

    def test_a_renewal_that_fails_leaves_the_event_for_its_lease_to_return(self):
        class BrokenRenew(InMemoryOutbox):
            def renew(self, *a, **k):
                raise RuntimeError("db down")

        class Slow(KeyedSink):
            def deliver(self, a, key):
                super().deliver(a, key)
                clock.now += 100

        sink = Slow()
        clock, outbox, d = rig(sink=sink, outbox=BrokenRenew(), lease_s=120)
        put(outbox, clock, key="a")
        put(outbox, clock, key="b")
        d.run_once()
        assert [k for _, k in sink.calls] == ["a"]  # b's lease is more than half gone: not sent
        assert d.stats.store_errors == 1


class TestAlertsRetryForHours:
    """An alert keeps retrying for at least six hours, backoff capped at 300 s."""

    def run_until_dead(self, clock, d, outbox, step):
        start = clock.now
        for _ in range(10_000):
            d.run_once()
            if outbox.stats().dead:
                return clock.now - start
            clock.now += step
        raise AssertionError("never dead-lettered")

    def always_failing(self):
        sink = KeyedSink()

        class Down:
            def deliver(self, a, key):
                sink.calls.append((a, key))
                raise DeliveryError("http_503")

        return sink, Down()

    def test_an_alert_survives_a_five_hour_outage_and_is_delivered_when_the_sink_returns(self):
        clock = Clock()
        outbox = InMemoryOutbox()
        sink = KeyedSink()
        sink.failures = [DeliveryError("http_503")] * 1000
        d = OutboxDispatcher(outbox, alerts=sink, clock=clock, rng=lambda: 0.0)
        put(outbox, clock, key="page")
        while clock.now < 1_000_000.0 + 5 * 3600:
            d.run_once()
            clock.now += 10
        assert outbox.stats().dead == 0 and outbox.stats().pending == 1
        sink.failures.clear()  # the webhook is back
        clock.now += 300
        d.run_once()
        assert outbox.stats().delivered == 1

    def test_an_alert_is_dead_lettered_only_after_six_hours(self):
        clock = Clock()
        outbox = InMemoryOutbox()
        _, down = self.always_failing()
        d = OutboxDispatcher(outbox, alerts=down, clock=clock, rng=lambda: 0.0)
        put(outbox, clock)
        age = self.run_until_dead(clock, d, outbox, step=30)
        assert 6 * 3600 <= age < 6 * 3600 + 400  # first failure at or after six hours
        assert d.stats.dead == 1 and d.stats.dead_alerts == 1 and d.stats.dead_usage == 0

    def test_backoff_is_capped_at_300_seconds_for_the_whole_six_hours(self):
        clock = Clock()
        outbox = InMemoryOutbox()
        _, down = self.always_failing()
        d = OutboxDispatcher(outbox, alerts=down, clock=clock, rng=lambda: 0.0)
        put(outbox, clock)
        attempts_at = []
        while not outbox.stats().dead and clock.now < 1_000_000.0 + 7 * 3600:
            if d.run_once():
                attempts_at.append(clock.now)
            clock.now += 1
        gaps = [b - a for a, b in itertools.pairwise(attempts_at)]
        assert max(gaps) <= 301  # the cap, plus the one-second tick of this loop
        assert len(attempts_at) > 70  # about one attempt every five minutes for six hours

    def test_jitter_can_only_shorten_the_wait_so_six_hours_is_a_floor(self):
        clock = Clock()
        outbox = InMemoryOutbox()
        _, down = self.always_failing()
        d = OutboxDispatcher(outbox, alerts=down, clock=clock, rng=lambda: 0.999)  # max jitter
        put(outbox, clock)
        age = self.run_until_dead(clock, d, outbox, step=5)
        assert age >= 6 * 3600

    def test_usage_events_keep_the_eight_attempt_policy(self):
        clock = Clock()
        outbox = InMemoryOutbox()

        class DownStore:
            writes = 0

            def write(self, event, key):
                self.writes += 1
                raise DeliveryError("db_error")

        store = DownStore()
        d = OutboxDispatcher(outbox, usage=store, clock=clock, rng=lambda: 0.0)
        outbox.enqueue(
            KIND_USAGE, encode_usage(UsageEvent("answered", "t_a", "output", 1, 0.0)), "u", clock()
        )
        for _ in range(20):
            d.run_once()
            clock.now += 400
        assert store.writes == 8
        assert (d.stats.dead, d.stats.dead_usage, d.stats.dead_alerts) == (1, 1, 0)

    def test_a_dead_letter_is_logged_at_error_level_and_counted(self, caplog):
        clock = Clock()
        outbox = InMemoryOutbox()
        _, down = self.always_failing()
        d = OutboxDispatcher(outbox, alerts=down, clock=clock, rng=lambda: 0.0)
        put(outbox, clock)
        with caplog.at_level(logging.ERROR):
            self.run_until_dead(clock, d, outbox, step=60)
        errors = [r for r in caplog.records if r.levelno == logging.ERROR]
        assert len(errors) == 1 and "events_dead_lettered" in errors[0].getMessage()
        assert "http_503" in errors[0].getMessage()

    def test_the_default_alert_policy_is_six_hours_capped_at_five_minutes(self):
        from guardrail_engine.delivery import ALERT_RETRY

        assert (ALERT_RETRY.base_s, ALERT_RETRY.cap_s, ALERT_RETRY.max_age_s) == (2.0, 300.0, 21600)
        assert not ALERT_RETRY.exhausted(10_000, 21599.0)
        assert ALERT_RETRY.exhausted(1, 21600.0)
        with pytest.raises(ValueError):
            RetryPolicy(max_age_s=0)


class TestDeadLetterAlert:
    """A dead letter raises ``events_dead_lettered`` through a path that does not
    depend on the failing sink."""

    def test_the_watch_raises_the_alert_through_another_sink_when_the_webhook_is_down(self, caplog):
        from guardrail_engine.gateway.sinks import ALERT_EVENTS_DEAD_LETTERED, RecordingAlertSink
        from guardrail_engine.monitoring import DeadLetteredEventsWatch

        clock = Clock()
        outbox = InMemoryOutbox()

        class Down:
            def deliver(self, a, key):
                raise DeliveryError("http_503")

        d = OutboxDispatcher(
            outbox,
            alerts=Down(),
            usage=InMemoryUsageStore(),
            alert_retry=RetryPolicy(base_s=10, cap_s=100, max_attempts=2, jitter=0),
            clock=clock,
        )
        other_channel = RecordingAlertSink()
        watch = DeadLetteredEventsWatch(lambda: d.stats.dead, other_channel, clock=clock)
        put(outbox, clock)
        assert watch.tick() is None  # nothing dead yet
        for _ in range(2):
            d.run_once()
            clock.now += 1000
        with caplog.at_level(logging.ERROR):
            alert = watch.tick()
        assert alert is not None and alert.kind == ALERT_EVENTS_DEAD_LETTERED and alert.count == 1
        assert [a.kind for a in other_channel.alerts] == [ALERT_EVENTS_DEAD_LETTERED]
        assert any("dead-lettered" in r.getMessage() for r in caplog.records)

    def test_with_every_sink_down_the_loss_is_still_logged_at_error_level(self, caplog):
        from guardrail_engine.monitoring import DeadLetteredEventsWatch

        class AllDown:
            def emit(self, alert):
                raise RuntimeError("down")

        dead = [0]
        watch = DeadLetteredEventsWatch(lambda: dead[0], AllDown(), clock=Clock())
        dead[0] = 3
        with caplog.at_level(logging.ERROR):
            assert watch.tick() is None  # not reported: tried again next tick
            watch.tick()
        messages = [r.getMessage() for r in caplog.records if r.levelno == logging.ERROR]
        assert sum("3 outbox events were dead-lettered" in m for m in messages) == 1  # once
        assert any("could not hand the events_dead_lettered alert" in m for m in messages)

    def test_the_alert_counts_the_growth_and_is_throttled(self):
        from guardrail_engine.gateway.sinks import RecordingAlertSink
        from guardrail_engine.monitoring import DeadLetteredEventsWatch

        clock, sink, dead = Clock(0.0), RecordingAlertSink(), [0]
        watch = DeadLetteredEventsWatch(lambda: dead[0], sink, min_interval_s=60, clock=clock)
        dead[0] = 2
        assert watch.tick().count == 2
        dead[0] = 5
        assert watch.tick() is None  # within the minute
        clock.now = 61
        assert watch.tick().count == 3


class TestOutboxInsertFailuresAreCounted:
    """A failed outbox INSERT counts as a dropped event."""

    class DownOutbox(InMemoryOutbox):
        def enqueue(self, *a, **k):
            raise RuntimeError("db down")

    def test_a_failed_alert_insert_is_counted_and_still_raises(self):
        from guardrail_engine.delivery import DropCounter

        drops = DropCounter()
        sink = DurableAlertSink(self.DownOutbox(), drops=drops)
        with pytest.raises(RuntimeError):
            sink.emit(alert())
        assert drops.value == 1

    def test_a_failed_usage_insert_is_counted_on_the_same_counter(self):
        from guardrail_engine.delivery import DropCounter

        drops = DropCounter()
        meter = DurableUsageMeter(self.DownOutbox(), drops=drops)
        with pytest.raises(RuntimeError):
            meter.record("t_a", "output", 10)
        with pytest.raises(RuntimeError):
            meter.record_unanswered("t_a", "output")
        assert drops.value == 2

    def test_a_successful_insert_counts_nothing(self):
        sink = DurableAlertSink(InMemoryOutbox())
        sink.emit(alert())
        assert sink.drops.value == 0

    def test_the_dropped_events_watch_sees_insert_failures_added_to_the_gateways_count(self):
        import asyncio

        from guardrail_engine.delivery import DropCounter
        from guardrail_engine.gateway.sinks import ALERT_EVENTS_DROPPED, RecordingAlertSink
        from guardrail_engine.monitoring import DroppedEventsWatch

        drops = DropCounter()
        down = self.DownOutbox()
        watch_sink = RecordingAlertSink()

        async def go():
            gateway = DecisionGateway(
                FakeDecisionModel(),
                meter=DurableUsageMeter(down, drops=drops),
                alerts=DurableAlertSink(down, drops=drops),
            )
            for i in range(3):
                await gateway.decide(
                    tenant_id="t_a", guard_point="output", input=f"x {i}", questions=QUESTIONS
                )
            await gateway.aclose()
            return gateway

        gateway = asyncio.run(go())
        assert gateway.dropped_events == 0  # the gateway never saw a drop: the INSERTs failed
        assert drops.value == 3
        watch = DroppedEventsWatch(lambda: gateway.dropped_events + drops.value, watch_sink)
        alert_raised = watch.tick()
        assert alert_raised is not None and alert_raised.kind == ALERT_EVENTS_DROPPED
        assert alert_raised.count == 3
