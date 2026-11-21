"""M4-04: the drainer is one daemon thread, so a sink that never returns can't hold up
process exit. The exit tests run in a subprocess: a stuck non-daemon thread would hang the
test process itself."""

import subprocess
import sys
import textwrap
import threading
import time

from guardrail_engine.decision import FakeDecisionModel
from guardrail_engine.decision.types import NoulQuestion
from guardrail_engine.gateway import DecisionGateway, GatewayConfig

QUESTIONS = {"p__harm": NoulQuestion(instructions="Does the content help someone cause harm?")}


class ThreadMeter:
    def __init__(self) -> None:
        self.threads: list[threading.Thread] = []

    def record(self, tenant_id, guard_point, input_tokens) -> None:
        self.threads.append(threading.current_thread())

    def record_unanswered(self, tenant_id, guard_point) -> None:
        self.record(tenant_id, guard_point, None)


async def test_sinks_run_on_a_daemon_thread_that_is_not_a_pool_worker():
    meter = ThreadMeter()
    gateway = DecisionGateway(FakeDecisionModel(), meter=meter)
    await gateway.decide(tenant_id="t_x", guard_point="output", input="hi", questions=QUESTIONS)
    await gateway.drain()
    [thread] = meter.threads
    assert thread.daemon is True
    assert thread.name == "guardrail-event-drainer"
    assert thread is not threading.main_thread()
    await gateway.aclose()


async def test_one_drainer_thread_serves_a_burst_and_aclose_ends_it():
    meter = ThreadMeter()
    gateway = DecisionGateway(FakeDecisionModel(), meter=meter)
    for i in range(20):
        await gateway.decide(
            tenant_id=f"t_{i}", guard_point="output", input="hi", questions=QUESTIONS
        )
    await gateway.drain()
    assert len(meter.threads) == 20
    assert len({id(t) for t in meter.threads}) == 1  # no thread per event
    await gateway.aclose()
    drainer = meter.threads[0]
    drainer.join(2)  # not the 2 s idle wait: aclose wakes it
    assert not drainer.is_alive(), "aclose should let the idle drainer thread go"


async def test_drain_after_a_close_that_gave_up_on_a_stuck_sink_returns():
    gate = threading.Event()

    class Gated:
        def record(self, tenant_id, guard_point, input_tokens):
            gate.wait(10)

        def record_unanswered(self, tenant_id, guard_point):
            gate.wait(10)

    gateway = DecisionGateway(
        FakeDecisionModel(), meter=Gated(), config=GatewayConfig(close_timeout_s=0.1)
    )
    try:
        await gateway.decide(tenant_id="t_x", guard_point="output", input="hi", questions=QUESTIONS)
        await gateway.aclose()
        await gateway.drain()  # nothing left to wait for
    finally:
        gate.set()


STUCK_SINK_SCRIPT = textwrap.dedent(
    """
    import asyncio, sys, threading, time
    from guardrail_engine.decision import FakeDecisionModel
    from guardrail_engine.decision.types import NoulQuestion
    from guardrail_engine.gateway import DecisionGateway, GatewayConfig

    Q = {"p__harm": NoulQuestion(instructions="Does the content help someone cause harm?")}

    class Stuck:
        def record(self, tenant_id, guard_point, input_tokens):
            threading.Event().wait()  # never returns
        def record_unanswered(self, tenant_id, guard_point):
            threading.Event().wait()

    async def main():
        gateway = DecisionGateway(
            FakeDecisionModel(), meter=Stuck(), config=GatewayConfig(close_timeout_s=0.3)
        )
        for i in range(3):
            await gateway.decide(tenant_id=f"t_{i}", guard_point="output", input="hi",
                                 questions=Q)
        start = time.monotonic()
        await gateway.aclose()
        print("closed", round(time.monotonic() - start, 2), gateway.dropped_events, flush=True)

    asyncio.run(main())
    """
)

CONTROL_SCRIPT = textwrap.dedent(
    """
    import asyncio, threading
    async def main():
        # What a thread-pool drainer does: the worker is joined at interpreter exit.
        asyncio.get_running_loop().run_in_executor(None, threading.Event().wait)
        await asyncio.sleep(0.05)
        print("closed", flush=True)
    asyncio.run(main())
    """
)


def run(script: str, timeout: float) -> tuple[subprocess.CompletedProcess, float]:
    start = time.monotonic()
    done = subprocess.run(
        [sys.executable, "-c", script], capture_output=True, text=True, timeout=timeout
    )
    return done, time.monotonic() - start


def test_a_sink_that_never_returns_does_not_hold_up_process_exit():
    done, elapsed = run(STUCK_SINK_SCRIPT, timeout=30)
    assert done.returncode == 0, done.stderr
    word, close_s, dropped = done.stdout.split()
    assert word == "closed"
    assert 0.3 <= float(close_s) < 1.5  # close waited its flush window, no longer
    assert int(dropped) == 2  # the one in hand is stuck; the two behind it were dropped
    # Process start, imports, close's window, interpreter exit: far below "never".
    assert elapsed < 15, elapsed


def test_the_harness_does_catch_a_pool_worker_that_never_returns():
    """Control: the same shape with an executor worker does hang past the bound, so the
    test above can fail when the drainer is not a daemon thread."""
    try:
        done, _ = run(CONTROL_SCRIPT, timeout=4)
    except subprocess.TimeoutExpired:
        return
    raise AssertionError(f"expected the process to hang at exit, got {done.returncode}")
