"""M1-11: clean shutdown in a defined order, within a bound, even with a stuck sink.

Order: stop accepting checks -> in-flight checks finish or reach their budgets -> gateway
``aclose`` (flush, stop the drainer) -> HTTP client (the model) -> store.

Once shutdown has started a check returns ``block``/``engine_closed`` (retryable, no model
call) and never raises (M1-11, decided 2026-11-17).
"""

from __future__ import annotations

import asyncio
import logging
import threading
import time

import pytest
from engine_fixtures import bundle, ctx, directory, real_catalog, settings, verifier

from guardrail_engine.decision import FakeDecisionModel
from guardrail_engine.engine import build_engine
from guardrail_engine.guard import Decision, Reason
from guardrail_engine.store import InMemoryPolicyStore


class RecordingModel(FakeDecisionModel):
    def __init__(self, events: list[str], **kwargs) -> None:
        super().__init__(**kwargs)
        self.events = events

    async def aclose(self) -> None:
        self.events.append("model.aclose")


class RecordingStore(InMemoryPolicyStore):
    def __init__(self, events: list[str], **kwargs) -> None:
        super().__init__(**kwargs)
        self.events = events

    async def aclose(self) -> None:
        self.events.append("store.aclose")


class StuckMeter:
    """A usage meter whose every call blocks its worker thread until released."""

    def __init__(self) -> None:
        self.entered = threading.Event()
        self.release = threading.Event()

    def _stick(self, *args: object) -> None:
        self.entered.set()
        self.release.wait(10)

    record = record_unanswered = record_timing = _stick


async def build(events: list[str], *, model: FakeDecisionModel | None = None, **kwargs):
    """An engine on recording fakes, with its gateway's ``aclose`` recorded too."""
    v = verifier()
    model = model or RecordingModel(events)
    base = settings(**kwargs.pop("sections", {}))
    store = RecordingStore(events, catalog=real_catalog())
    engine = await build_engine(
        base, verifier=v, tenants=directory(), model=model, store=store, **kwargs
    )
    gateway_aclose = engine.gateway.aclose

    async def recorded_aclose() -> None:
        events.append("gateway.aclose:start")
        await gateway_aclose()
        events.append("gateway.aclose:end")

    engine.gateway.aclose = recorded_aclose  # type: ignore[method-assign]
    await engine.bootstrap_publish(bundle())
    return engine, v


async def recorded_check(engine, v, events: list[str]):
    """A check that records when it returns (in the same step, before shutdown resumes)."""
    verdict = await engine.check(ctx(v), "output", "Hello again.")
    events.append("in-flight check finished")
    return verdict


async def wait_for(condition, timeout_s: float = 2.0) -> None:
    deadline = time.monotonic() + timeout_s
    while not condition():
        assert time.monotonic() < deadline, "condition not reached"
        await asyncio.sleep(0.005)


async def test_order_and_bound_with_a_stuck_sink(caplog):
    events: list[str] = []
    meter = StuckMeter()
    model = RecordingModel(events)
    engine, v = await build(
        events, model=model, meter=meter, sections={"gateway": {"close_timeout_s": 0.2}}
    )
    try:
        # A first check leaves a metering event stuck in the sink's worker thread.
        await engine.check(ctx(v), "output", "Hello.")
        await asyncio.to_thread(meter.entered.wait, 2)
        # A second check is in flight when shutdown starts.
        model.slow_next(0.3)
        in_flight = asyncio.create_task(recorded_check(engine, v, events))
        await wait_for(lambda: engine.gateway.in_flight() == 1)

        started = time.monotonic()
        shutting_down = asyncio.create_task(engine.shutdown())
        await asyncio.sleep(0)  # shutdown has started
        refused = await engine.check(ctx(v), "output", "Too late.")
        assert (refused.decision, refused.reason) == (Decision.BLOCK, Reason.ENGINE_CLOSED)
        events.append("new check refused")
        await shutting_down
        elapsed = time.monotonic() - started
    finally:
        meter.release.set()

    assert events == [
        "new check refused",
        "in-flight check finished",
        "gateway.aclose:start",
        "gateway.aclose:end",
        "model.aclose",
        "store.aclose",
    ]
    verdict = in_flight.result()
    assert verdict.decision is Decision.ALLOW  # it finished normally, not cut off
    assert 0.2 <= elapsed < engine.shutdown_bound_s  # 0.2: the gateway's close bound
    assert "sink still running" in caplog.text  # the gateway gave up on the stuck sink


async def test_a_check_past_its_budget_ends_at_its_budget_before_the_gateway_closes():
    events: list[str] = []
    model = RecordingModel(events)
    engine, v = await build(events, model=model)
    model.slow_next(30.0, times=2)  # ignores no cancellation, but never answers in time
    in_flight = asyncio.create_task(recorded_check(engine, v, events))
    await wait_for(lambda: engine.gateway.in_flight() == 1)
    started = time.monotonic()
    await engine.shutdown()
    elapsed = time.monotonic() - started
    verdict = in_flight.result()
    assert verdict.decision is Decision.BLOCK and verdict.reason is Reason.MODEL_FAILURE
    assert verdict.failure_kind == "timeout"
    assert events[:2] == ["in-flight check finished", "gateway.aclose:start"]
    assert elapsed < engine.settings.largest_check_budget_s() + 0.5


async def test_drain_timeout_bounds_a_check_that_never_ends(caplog):
    events: list[str] = []
    engine, v = await build(
        events,
        sections={
            "gateway": {
                "budget_cap_s": 0.3,
                "input_budget_cap_s": 0.3,
                "time_window_allowance_s": 0.0,
            },
            "shutdown": {"drain_timeout_s": 0.35},
            # The drain must also cover 3 policy lookups at the store timeout
            "guard": {"store_timeout_s": 0.01},
        },
    )
    never = asyncio.Event()

    async def hangs(*args: object) -> None:
        await never.wait()

    engine.guard.check = hangs  # type: ignore[method-assign]
    stuck = asyncio.create_task(engine.check(ctx(v), "output", "Hello."))
    await wait_for(lambda: engine.in_flight == 1)
    started = time.monotonic()
    with caplog.at_level(logging.WARNING):
        await engine.shutdown()
    elapsed = time.monotonic() - started
    assert 0.35 <= elapsed < engine.shutdown_bound_s
    assert "1 checks still running after 0.35 s" in caplog.text
    assert events == ["gateway.aclose:start", "gateway.aclose:end", "model.aclose", "store.aclose"]
    stuck.cancel()
    with pytest.raises(asyncio.CancelledError):
        await stuck


async def test_shutdown_is_idempotent_and_shared():
    events: list[str] = []
    engine, v = await build(events)
    await asyncio.gather(engine.shutdown(), engine.shutdown())
    await engine.shutdown()
    assert events.count("gateway.aclose:start") == 1
    assert events.count("store.aclose") == 1
    assert not engine.accepting
    verdict = await engine.check(ctx(v), "output", "Hello.")
    assert (verdict.decision, verdict.reason) == (Decision.BLOCK, Reason.ENGINE_CLOSED)


async def test_a_cancelled_caller_does_not_stop_the_shutdown():
    events: list[str] = []
    model = RecordingModel(events)
    engine, v = await build(events, model=model)
    model.slow_next(0.1)
    checking = asyncio.create_task(engine.check(ctx(v), "output", "Hello."))
    await wait_for(lambda: engine.gateway.in_flight() == 1)
    caller = asyncio.create_task(engine.shutdown())
    await asyncio.sleep(0.01)
    caller.cancel()
    with pytest.raises(asyncio.CancelledError):
        await caller
    await engine.shutdown()  # waits for the same shutdown
    assert (await checking).decision is Decision.ALLOW
    assert events[-1] == "store.aclose"


async def test_a_failing_or_hanging_step_does_not_stop_the_next(caplog):
    events: list[str] = []

    class FailingModel(RecordingModel):
        async def aclose(self) -> None:
            raise RuntimeError("socket already gone")

    class HangingStore(RecordingStore):
        async def aclose(self) -> None:
            await asyncio.Event().wait()

    v = verifier()
    store = HangingStore(events, catalog=real_catalog())
    s = settings(shutdown={"resource_close_timeout_s": 0.1})
    engine = await build_engine(s, verifier=v, model=FailingModel(events), store=store)
    started = time.monotonic()
    await engine.shutdown()
    assert time.monotonic() - started < engine.shutdown_bound_s
    assert "closing the model and HTTP client failed (RuntimeError)" in caplog.text
    assert "closing the policy store took over 0.10 s" in caplog.text


async def test_an_owned_pool_that_will_not_close_is_terminated(monkeypatch):
    class SlowPool:
        terminated = False

        async def close(self) -> None:
            await asyncio.Event().wait()

        def terminate(self) -> None:
            self.terminated = True

    pool = SlowPool()

    async def connect(dsn: str) -> SlowPool:
        return pool

    monkeypatch.setattr("guardrail_engine.store.adapters.postgres.connect_pool", connect)
    monkeypatch.setenv("GUARDRAIL_PG_DSN", "postgresql://app@db/guardrails")
    s = settings(store={"kind": "postgres"}, shutdown={"resource_close_timeout_s": 0.1})
    engine = await build_engine(s, verifier=verifier(), model=FakeDecisionModel())
    await engine.shutdown()
    assert pool.terminated


def test_shutdown_bound_adds_up_the_steps():
    s = settings(
        gateway={"close_timeout_s": 0.5},
        # 4.8 s: at least the 4.76 s the shutdown needs (budget, grace, 3 policy lookups)
        shutdown={"drain_timeout_s": 4.8, "resource_close_timeout_s": 0.25},
    )

    async def bound() -> float:
        engine = await build_engine(s, verifier=verifier(), model=FakeDecisionModel())
        await engine.shutdown()
        return engine.shutdown_bound_s

    assert asyncio.run(bound()) == pytest.approx(4.8 + 0.5 + 3 * 0.25)
