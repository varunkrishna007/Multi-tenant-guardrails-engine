"""M3-02: the input guard in parallel with the planner, and the PF-9 invariant. Offline: the
checker is a stub whose ``input`` verdict is released by the test, or an engine with the fake
model."""

from __future__ import annotations

import asyncio
import json
import secrets
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

from guardrail_engine.decision import FakeDecisionModel
from guardrail_engine.guard.verdict import Decision, Reason, Verdict
from guardrail_engine.sdk import (
    Guard,
    GuardContext,
    InputGate,
    InputNotAllowedError,
    plan_with_input_guard,
)

SIGNED = "v1.signed-context-sentinel"
ROOT = Path(__file__).resolve().parents[2]


def verdict(decision=Decision.ALLOW, reason=Reason.POLICY, **fields) -> Verdict:
    return Verdict(
        request_id="req-1",
        tenant_id="t_1042",
        guard_point=fields.pop("guard_point", "input"),
        decision=decision,
        reason=reason,
        checked_at=datetime.now(UTC),
        latency_ms=1.0,
        **fields,
    )


class SlowChecker:
    """A checker whose answer arrives only when the test calls :meth:`answer`."""

    def __init__(self) -> None:
        self.sent: list[tuple[str, str]] = []
        self.started = asyncio.Event()
        self._answer: asyncio.Future[object] = asyncio.get_running_loop().create_future()

    def answer(self, v) -> None:
        self._answer.set_result(v)

    def fail(self, exc: Exception) -> None:
        self._answer.set_exception(exc)

    async def check(self, ctx, guard_point, content):
        self.sent.append((guard_point, content))
        self.started.set()
        return await self._answer


class World:
    """What the agent did: tools run, outputs released, planner lifecycle."""

    def __init__(self) -> None:
        self.tools: list[str] = []
        self.released: list[str] = []
        self.planner_started = asyncio.Event()
        self.planner_cancelled = False
        self.planner_finished = False

    def tool(self, name):
        async def run():
            self.tools.append(name)
            return f"{name}-result"

        return run


async def spin(n: int = 20) -> None:
    for _ in range(n):
        await asyncio.sleep(0)


def planner_for(world: World, *, tool: str = "claims.status"):
    """A planner that starts, then tries to run a tool, then returns a plan."""

    async def planner(gate: InputGate):
        world.planner_started.set()
        try:
            await gate.execute(world.tool(tool))
            await asyncio.sleep(0)
            world.planner_finished = True
            return "the-plan"
        except asyncio.CancelledError:
            world.planner_cancelled = True
            raise

    return planner


# ------------------------------------------------------------------ PF-9: slow and blocking


async def test_a_slow_blocking_input_verdict_executes_nothing_and_releases_nothing():
    """PF-9: the planner is already running (the guard doesn't delay it), but until the
    verdict arrives nothing executes and nothing is released; a block then cancels the
    planner, which stops, and nothing ever executes or is released."""
    checker, world = SlowChecker(), World()
    guard = Guard(checker)
    turn = asyncio.create_task(
        guard.plan_with_input_guard("please do X", GuardContext(SIGNED), planner_for(world))
    )
    await asyncio.wait_for(world.planner_started.wait(), 1)
    await asyncio.wait_for(checker.started.wait(), 1)
    assert checker.sent == [("input", "please do X")]  # both started, concurrently
    await spin()
    assert world.tools == [] and not turn.done()  # the verdict is slow: nothing has run

    checker.answer(verdict(Decision.BLOCK, Reason.POLICY))
    out = await asyncio.wait_for(turn, 1)

    assert not out.proceed and out.input.decision == "block"
    assert out.plan is None and out.planner_cancelled
    assert world.planner_cancelled and not world.planner_finished  # actually cancelled
    assert world.tools == []
    with pytest.raises(InputNotAllowedError) as err:
        await out.gate.release("a draft answer")
    assert err.value.result.decision == "block"
    with pytest.raises(InputNotAllowedError):
        await out.gate.execute(world.tool("claims.status"))
    assert world.tools == [] and world.released == []


async def test_output_is_not_released_while_the_input_verdict_is_pending():
    checker = SlowChecker()
    guard = Guard(checker)
    gate = guard.start_input_guard("hello", GuardContext(SIGNED))
    releasing = asyncio.create_task(gate.release("the answer"))
    await spin()
    assert not releasing.done() and not gate.done  # held until the verdict
    checker.answer(verdict(Decision.BLOCK, Reason.POLICY))
    with pytest.raises(InputNotAllowedError):
        await asyncio.wait_for(releasing, 1)


# ------------------------------------------------------------------ PF-9: slow and allowing


async def test_a_slow_allowing_input_verdict_makes_execution_wait_and_then_proceed():
    checker, world = SlowChecker(), World()
    guard = Guard(checker)
    turn = asyncio.create_task(
        guard.plan_with_input_guard("please do X", GuardContext(SIGNED), planner_for(world))
    )
    await asyncio.wait_for(world.planner_started.wait(), 1)
    await spin()
    assert world.tools == [] and not world.planner_finished and not turn.done()

    checker.answer(verdict(Decision.ALLOW, Reason.POLICY))
    out = await asyncio.wait_for(turn, 1)

    assert out.proceed and out.plan == "the-plan" and not out.planner_cancelled
    assert world.tools == ["claims.status"] and world.planner_finished  # ran, after the verdict
    assert await out.gate.release("the answer") == "the answer"
    assert await out.gate.execute(world.tool("again")) == "again-result"


@pytest.mark.parametrize(
    "decision, reason, held",
    [
        (Decision.ESCALATE, Reason.POLICY, True),
        (Decision.BLOCK, Reason.POLICY, False),
        (Decision.BLOCK, Reason.MODEL_FAILURE, False),
        (Decision.BLOCK, Reason.PROVIDER_SAFETY, False),
        (Decision.FORBIDDEN, Reason.CONTEXT_INVALID, False),
        ("quarantine", Reason.POLICY, False),  # a decision this SDK doesn't know
    ],
)
async def test_only_allow_lets_anything_proceed(decision, reason, held):
    """Escalate holds; every other decision, an unknown one included, withholds."""
    checker, world = SlowChecker(), World()
    turn = asyncio.create_task(
        Guard(checker).plan_with_input_guard("c", GuardContext(SIGNED), planner_for(world))
    )
    await asyncio.wait_for(world.planner_started.wait(), 1)
    v = (
        SimpleNamespace(decision=decision, reason=reason, request_id="r", guard_point="input",
                        fired=(), failure_kind=None, failure_reason=None, retry_after_ms=None,
                        capacity_limited=False)
        if isinstance(decision, str)
        else verdict(decision, reason)
    )  # fmt: skip
    checker.answer(v)
    out = await asyncio.wait_for(turn, 1)
    assert not out.proceed and out.plan is None and world.planner_cancelled
    assert out.input.held_for_escalation is held
    assert world.tools == []
    with pytest.raises(InputNotAllowedError) as err:
        await out.gate.release("x")
    assert err.value.result == out.input


# ------------------------------------------------------------------ the planner finishes first


async def test_a_plan_that_finishes_first_is_held_until_the_verdict():
    checker = SlowChecker()

    async def planner(gate):
        return "quick-plan"

    turn = asyncio.create_task(
        Guard(checker).plan_with_input_guard("c", GuardContext(SIGNED), planner)
    )
    await spin()
    assert not turn.done()  # the plan exists, but isn't returned before the verdict
    checker.answer(verdict(Decision.ALLOW))
    out = await asyncio.wait_for(turn, 1)
    assert out.plan == "quick-plan" and out.proceed


async def test_a_plan_that_finished_first_is_dropped_on_a_block():
    checker = SlowChecker()

    async def planner(gate):
        return "quick-plan"

    turn = asyncio.create_task(
        Guard(checker).plan_with_input_guard("c", GuardContext(SIGNED), planner)
    )
    await spin()
    checker.answer(verdict(Decision.BLOCK))
    out = await asyncio.wait_for(turn, 1)
    assert out.plan is None and not out.planner_cancelled  # nothing was left to cancel


async def test_a_block_outranks_a_planner_that_raised_and_an_allow_does_not():
    async def boom(gate):
        raise RuntimeError("planner failed")

    checker = SlowChecker()
    turn = asyncio.create_task(
        Guard(checker).plan_with_input_guard("c", GuardContext(SIGNED), boom)
    )
    await spin()
    checker.answer(verdict(Decision.BLOCK))
    assert (await asyncio.wait_for(turn, 1)).plan is None  # no "never retrieved" noise either

    checker = SlowChecker()
    turn = asyncio.create_task(
        Guard(checker).plan_with_input_guard("c", GuardContext(SIGNED), boom)
    )
    await spin()
    checker.answer(verdict(Decision.ALLOW))
    with pytest.raises(RuntimeError, match="planner failed"):
        await asyncio.wait_for(turn, 1)


# ------------------------------------------------------------------ failure and cancellation


async def test_an_input_check_that_raises_fails_closed():
    checker, world = SlowChecker(), World()
    turn = asyncio.create_task(
        Guard(checker).plan_with_input_guard("c", GuardContext(SIGNED), planner_for(world))
    )
    await asyncio.wait_for(world.planner_started.wait(), 1)
    checker.fail(ConnectionError("engine unreachable"))
    with pytest.raises(ConnectionError):
        await asyncio.wait_for(turn, 1)
    assert world.planner_cancelled and world.tools == []


async def test_cancelling_the_turn_cancels_the_planner_and_the_input_check():
    checker, world = SlowChecker(), World()
    turn = asyncio.create_task(
        Guard(checker).plan_with_input_guard("c", GuardContext(SIGNED), planner_for(world))
    )
    await asyncio.wait_for(world.planner_started.wait(), 1)
    turn.cancel()
    with pytest.raises(asyncio.CancelledError):
        await turn
    assert world.planner_cancelled and world.tools == []


async def test_waiting_on_the_verdict_and_being_cancelled_does_not_cancel_the_check():
    checker = SlowChecker()
    gate = Guard(checker).start_input_guard("c", GuardContext(SIGNED))
    waiter = asyncio.create_task(gate.verdict())
    await spin()
    waiter.cancel()
    with pytest.raises(asyncio.CancelledError):
        await waiter
    checker.answer(verdict(Decision.ALLOW))
    assert (await gate.verdict()).released


async def test_an_awaitable_planner_is_accepted():
    checker = SlowChecker()

    async def plan():
        return "p"

    turn = asyncio.create_task(
        plan_with_input_guard(Guard(checker), "c", GuardContext(SIGNED), plan())
    )
    checker.answer(verdict(Decision.ALLOW))
    assert (await asyncio.wait_for(turn, 1)).plan == "p"


async def test_the_tenant_comes_only_from_the_signed_context():
    checker = SlowChecker()
    checker.answer(verdict(Decision.ALLOW))

    async def planner(gate):
        return None

    await Guard(checker).plan_with_input_guard("c", GuardContext(SIGNED), planner)
    with pytest.raises(TypeError):
        Guard(checker).start_input_guard("c", "t_1042")  # type: ignore[arg-type]


# ------------------------------------------------------------------ through the engine


async def test_through_the_engine_a_slow_blocking_input_verdict_executes_nothing():
    """The same invariant over a real engine and the fake model, whose answer is slow."""
    from guardrail_engine.engine import EngineSettings, build_engine
    from guardrail_engine.guard import HmacContextVerifier, InMemoryTenantDirectory, TenantProfile
    from guardrail_engine.guard.audit import NullAuditSink
    from guardrail_engine.policy import TenantAttributes

    floor = ROOT / "floor" / "rules.json"
    settings = EngineSettings.from_mapping(
        {"environment": "test", "catalog": {"floor_files": [str(floor)]},
         "gemini": {"paid_tier": True}}
    )  # fmt: skip
    fake = FakeDecisionModel(
        responder=lambda t, k, q: 0.97 if k == "p__inj_direct" and "MARKER-7" in t else 0.01,
        latency_s=0.15,
    )
    verifier = HmacContextVerifier(secrets.token_bytes(32))
    tenants = InMemoryTenantDirectory(
        [TenantProfile.build(TenantAttributes(tenant_id="t_1042"), "insurance", slug="acme")]
    )
    engine = await build_engine(settings, verifier=verifier, tenants=tenants, model=fake,
                                audit=NullAuditSink())  # fmt: skip
    try:
        version = json.loads(floor.read_text()).get("version", 1)
        await engine.bootstrap_publish({"schema_version": 1, "tenant_id": "t_1042", "version": 1,
                                        "extends": [f"platform/floor@{version}"]})  # fmt: skip
        guard, ctx = Guard(engine), GuardContext(verifier.issue("t_1042"))

        async def run(content: str):
            world = World()

            async def planner(gate: InputGate):
                world.planner_started.set()
                try:
                    await gate.execute(world.tool("claims.status"))
                    return "plan"
                except asyncio.CancelledError:
                    world.planner_cancelled = True
                    raise

            return world, await guard.plan_with_input_guard(content, ctx, planner)

        world, blocked = await run("MARKER-7")
        assert not blocked.proceed and blocked.input.reason == "policy"
        assert world.planner_started.is_set() and world.planner_cancelled
        assert world.tools == [] and blocked.plan is None

        world, allowed = await run("What does my policy cover?")
        assert allowed.proceed and allowed.plan == "plan" and world.tools == ["claims.status"]
    finally:
        await engine.shutdown()


# ---------------------------------------------------------- a planner that won't stop


async def test_a_planner_that_swallows_its_cancellation_does_not_hang_the_turn(monkeypatch, caplog):
    import logging

    from guardrail_engine.sdk import parallel

    monkeypatch.setattr(parallel, "STOP_TIMEOUT_S", 0.05)
    release = asyncio.Event()
    world_tools: list[str] = []

    class Block:
        async def check(self, ctx, guard_point, content):
            return verdict(Decision.BLOCK, Reason.POLICY)

    async def stubborn(gate: InputGate):
        while not release.is_set():
            try:
                await asyncio.sleep(10)
            except asyncio.CancelledError:
                continue  # swallows it, keeps going
        return "late plan"

    guard = Guard(Block())
    with caplog.at_level(logging.WARNING, logger="guardrail_engine.sdk.parallel"):
        outcome = await asyncio.wait_for(
            guard.plan_with_input_guard("x", GuardContext("v1.signed"), stubborn), timeout=2
        )
    release.set()
    assert not outcome.proceed and outcome.plan is None and outcome.planner_cancelled
    assert world_tools == []
    assert any("did not stop" in r.message for r in caplog.records)
    # the gate still refuses everything the left-over planner might try
    with pytest.raises(InputNotAllowedError):
        await outcome.gate.execute(lambda: asyncio.sleep(0))


async def test_a_planner_that_stops_promptly_is_still_awaited_to_completion():
    stopped = asyncio.Event()

    class Block:
        async def check(self, ctx, guard_point, content):
            return verdict(Decision.BLOCK, Reason.POLICY)

    async def planner(gate: InputGate):
        try:
            await asyncio.sleep(10)
        finally:
            stopped.set()

    outcome = await Guard(Block()).plan_with_input_guard("x", GuardContext("v1.signed"), planner)
    assert stopped.is_set() and outcome.planner_cancelled
