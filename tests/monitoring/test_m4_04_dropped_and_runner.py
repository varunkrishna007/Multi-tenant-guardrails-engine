"""M4-04: the alert on the dropped-events counter, and the periodic runner."""

import asyncio
import threading
import time

import pytest

from guardrail_engine.decision import FakeDecisionModel
from guardrail_engine.decision.types import NoulQuestion
from guardrail_engine.gateway import (
    ALERT_EVENTS_DROPPED,
    AlertSeverity,
    DecisionGateway,
    GatewayConfig,
    RecordingAlertSink,
)
from guardrail_engine.monitoring import DroppedEventsWatch, PeriodicRunner

QUESTIONS = {"p__harm": NoulQuestion(instructions="Does the content help someone cause harm?")}


class Counter:
    def __init__(self) -> None:
        self.value = 0
        self.now = 0.0

    def __call__(self) -> int:
        return self.value

    def clock(self) -> float:
        return self.now


class TestDroppedEventsWatch:
    def rig(self, **kwargs):
        counter, sink = Counter(), RecordingAlertSink()
        watch = DroppedEventsWatch(counter, sink, clock=counter.clock, **kwargs)
        return counter, sink, watch

    def test_no_drops_no_alert(self):
        _, sink, watch = self.rig()
        assert watch.tick() is None
        assert sink.alerts == []

    def test_growth_raises_a_warning_with_the_count(self):
        counter, sink, watch = self.rig()
        counter.value = 7
        alert = watch.tick()
        assert alert is sink.alerts[0]
        assert alert.kind == ALERT_EVENTS_DROPPED
        assert alert.severity is AlertSeverity.WARNING
        assert alert.count == 7
        assert alert.tenant_id == ""

    def test_the_same_total_is_reported_once(self):
        counter, sink, watch = self.rig()
        counter.value = 3
        watch.tick()
        counter.now += 1000
        assert watch.tick() is None
        assert len(sink.alerts) == 1

    def test_growth_inside_the_interval_waits_and_is_added_to_the_next_alert(self):
        counter, sink, watch = self.rig(min_interval_s=60)
        counter.value = 2
        watch.tick()
        counter.value = 5
        counter.now = 30
        assert watch.tick() is None  # throttled
        counter.now = 61
        alert = watch.tick()
        assert alert.count == 3  # 5 - the 2 already reported
        assert [a.count for a in sink.alerts] == [2, 3]

    def test_a_failing_sink_is_retried_on_the_next_tick_without_losing_the_count(self):
        counter = Counter()
        fail = [True]
        seen = []

        class Flaky:
            def emit(self, alert):
                if fail[0]:
                    raise RuntimeError("down")
                seen.append(alert)

        watch = DroppedEventsWatch(counter, Flaky(), clock=counter.clock)
        counter.value = 4
        assert watch.tick() is None
        fail[0] = False
        assert watch.tick().count == 4
        assert seen[0].count == 4

    async def test_an_overflowing_gateway_is_noticed_even_though_its_own_queue_dropped(self):
        """The alert goes to a sink that is not behind the gateway's queue, so the overflow
        it reports cannot swallow it."""
        gate = threading.Event()

        class Gated:
            def record(self, tenant_id, guard_point, input_tokens):
                gate.wait(10)

            def record_unanswered(self, tenant_id, guard_point):
                gate.wait(10)

        direct = RecordingAlertSink()
        gateway = DecisionGateway(
            FakeDecisionModel(), meter=Gated(), config=GatewayConfig(sink_queue_size=2)
        )
        watch = DroppedEventsWatch(lambda: gateway.dropped_events, direct)
        try:
            for i in range(8):
                await gateway.decide(
                    tenant_id=f"t_{i}", guard_point="output", input="hi", questions=QUESTIONS
                )
                if i == 0:
                    await asyncio.sleep(0.05)  # the first event is in the stuck sink's hands
            assert gateway.dropped_events == 5
            alert = watch.tick()
            assert alert is not None and alert.count == 5
            assert direct.alerts == [alert]
        finally:
            gate.set()
            await gateway.aclose()


class TestPeriodicRunner:
    def test_it_runs_every_tick_and_survives_one_that_raises(self):
        ran = []

        def boom():
            raise RuntimeError("bad tick")

        runner = PeriodicRunner([boom, lambda: ran.append(1)], interval_s=0.01)
        runner.start()
        deadline = time.monotonic() + 3
        while len(ran) < 3:
            assert time.monotonic() < deadline
            time.sleep(0.005)
        runner.close()
        assert len(ran) >= 3

    def test_close_returns_within_its_timeout_when_a_tick_hangs(self):
        gate = threading.Event()
        entered = threading.Event()

        def stuck():
            entered.set()
            gate.wait(30)

        runner = PeriodicRunner([stuck], interval_s=0.01)
        runner.start()
        assert entered.wait(3)
        start = time.monotonic()
        runner.close(timeout=0.2)
        assert time.monotonic() - start < 1.0
        gate.set()
        assert runner.close(timeout=3) is None

    def test_the_thread_is_a_daemon(self):
        runner = PeriodicRunner([lambda: None], interval_s=60)
        runner.start()
        try:
            assert runner._thread is not None and runner._thread.daemon
            assert runner._thread.name == "guardrail-monitor-runner"
        finally:
            runner.close()

    def test_a_non_positive_interval_is_refused(self):
        with pytest.raises(ValueError):
            PeriodicRunner([], interval_s=0)
