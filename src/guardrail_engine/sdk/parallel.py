"""M3-02: the ``input`` guard in parallel with the planner, and the PF-9 invariant.

The input guard and the agent's planner run **concurrently**, so a clean request pays no
latency for the guard. The price is that the planner starts before the verdict exists, so the
SDK holds the line PF-9 draws:

    **No ``tool_call`` is executed and no ``output`` is released before the ``input``
    verdict arrives, and only an ``allow`` lets either happen.**

The line is the :class:`InputGate`. It is the one object that runs tools and releases output
for a turn: :meth:`InputGate.execute` and :meth:`InputGate.release` wait for the input
verdict, run or release only on ``allow`` (``escalate`` holds; ``block``, ``forbidden`` and
an unknown decision withhold, the M1-07 rule), and raise :class:`InputNotAllowedError`
otherwise. A planner that executes tools while it plans gets the gate as its argument and
runs them through it.

What the SDK can and can't enforce: code that bypasses the gate (calls a tool directly,
prints the model's text) isn't stopped, because the SDK doesn't own the agent's runtime. The
guarantee is that the SDK's own paths (``execute``, ``release``, the plan returned by
:func:`plan_with_input_guard` and, **given the gate**, the output windows of
:meth:`~guardrail_engine.sdk.Guard.stream_output`) honour it, and that an integrator who routes
execution through the gate can't get it wrong. ``stream_output`` requires its ``gate`` argument
(``None`` is the explicit "no input guard for this turn"), so it can't be left out by
forgetting it.

**A block cancels the plan.** The planner runs as its own task. If the verdict isn't
``allow``, that task is cancelled and awaited for at most :data:`STOP_TIMEOUT_S`, so it has
stopped when the call returns unless it ignored the cancellation (logged; the gate refuses
everything it tries), and no plan is returned. If the planner finishes first, the plan is held
until the verdict arrives, and dropped if it isn't ``allow``.

**An input check that raises** (the checker failed in a way that produced no verdict) fails
closed: the planner is cancelled, nothing is executed or released, and the exception
propagates.
"""

from __future__ import annotations

import asyncio
import inspect
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Generic, TypeVar

from guardrail_engine.sdk.result import GuardResult

if TYPE_CHECKING:
    from guardrail_engine.sdk.client import Guard, GuardContext

logger = logging.getLogger(__name__)

STOP_TIMEOUT_S = 1.0
"""How long a cancelled planner is waited for. A planner that swallows the
cancellation is left running after this, with a warning: the gate already refuses every tool
and output, so nothing it does can get past the verdict."""

T = TypeVar("T")

Planner = Callable[["InputGate"], Awaitable[T]] | Awaitable[T]
"""The caller's planner: a coroutine function taking the :class:`InputGate` (so it can run
tools through it), or an awaitable that needs no gate."""


class InputNotAllowedError(Exception):
    """The input verdict wasn't ``allow``, so the tool wasn't executed or the output wasn't
    released. :attr:`result` is the verdict (``user_message``, ``held_for_escalation``...)."""

    def __init__(self, result: GuardResult) -> None:
        self.result = result
        super().__init__(
            f"the input verdict was {result.decision}/{result.reason}; nothing is executed "
            "or released"
        )


class InputGate:
    """The PF-9 gate for one turn: holds the input check's task. Built by
    :func:`plan_with_input_guard` or :meth:`~guardrail_engine.sdk.Guard.start_input_guard`."""

    __slots__ = ("_task",)

    def __init__(self, check: asyncio.Task[GuardResult]) -> None:
        self._task = check

    @property
    def done(self) -> bool:
        """Whether the input check has finished (a verdict, or a failure)."""
        return self._task.done()

    async def verdict(self) -> GuardResult:
        """Wait for the input verdict. Cancelling a waiter doesn't cancel the check. If the
        check raised, so does this."""
        return await asyncio.shield(self._task)

    async def execute(self, run: Callable[[], Awaitable[T]]) -> T:
        """Run a tool (``run`` is called, and awaited) **only after** the input verdict
        arrives and is ``allow``. ``run`` is a callable, never an awaitable, so no part of
        the tool has started when this is refused. Raises :class:`InputNotAllowedError`
        otherwise, without calling ``run``."""
        result = await self.verdict()
        if not result.released:
            raise InputNotAllowedError(result)
        return await run()

    async def release(self, output: T) -> T:
        """Return ``output`` for release **only after** the input verdict arrives and is
        ``allow``; raises :class:`InputNotAllowedError` otherwise. (The ``output`` guard point
        is a separate check, :meth:`~guardrail_engine.sdk.Guard.check` at ``output``; both
        must allow.)"""
        result = await self.verdict()
        if not result.released:
            raise InputNotAllowedError(result)
        return output

    def cancel(self) -> None:
        """Abandon the input check (end of turn, error path)."""
        self._task.cancel()


@dataclass(frozen=True, slots=True)
class GuardedPlan(Generic[T]):
    """What :func:`plan_with_input_guard` returns."""

    input: GuardResult
    """The input verdict."""
    plan: T | None
    """The planner's result, present only when ``input.released``; None when the plan was
    cancelled or dropped."""
    planner_cancelled: bool
    """The planner task was still running when a non-allow verdict arrived and was
    cancelled (it has stopped by the time this is returned)."""
    gate: InputGate
    """Run tools and release output through this. It is already resolved."""

    @property
    def proceed(self) -> bool:
        """The input allowed the request and the plan is usable."""
        return self.input.released


async def plan_with_input_guard(
    guard: Guard, content: str, ctx: GuardContext, planner: Planner[T]
) -> GuardedPlan[T]:
    """Run the input guard on ``content`` and ``planner`` concurrently.

    * ``allow``: waits for the planner and returns its plan.
    * Any other decision (``escalate`` holds; ``block``, ``forbidden`` and an unknown value
      withhold): the planner task is **cancelled** and awaited, and ``plan`` is None.
    * The planner finished first: the plan is held until the verdict, and dropped unless
      ``allow``. A planner that raised has its exception re-raised only if the input allowed
      (a block outranks it).

    The planner, if a function, receives the :class:`InputGate`, so tools it runs while
    planning go through :meth:`InputGate.execute` (PF-9). Cancelling this call cancels both
    tasks."""
    gate = guard.start_input_guard(content, ctx)
    plan_task: asyncio.Future[T] | None = None
    try:
        plan_task = asyncio.ensure_future(_start(planner, gate))
        result = await gate.verdict()  # a failed check raises: fail closed (finally cancels)
        if not result.released:
            cancelled = not plan_task.done()
            await _stop(plan_task)
            return GuardedPlan(result, None, cancelled, gate)
        return GuardedPlan(result, await plan_task, False, gate)
    finally:
        if plan_task is not None and not plan_task.done():
            await _stop(plan_task)
        gate.cancel()  # a no-op once the check has finished


async def _stop(task: asyncio.Future[T]) -> None:
    """Cancel ``task`` and wait for it to stop, for at most :data:`STOP_TIMEOUT_S`. A failure
    it had already raised is dropped (the verdict outranks it). A planner that swallows the
    cancellation is logged and left; the call returns."""
    task.cancel()
    await asyncio.wait({task}, timeout=STOP_TIMEOUT_S)
    if not task.done():
        logger.warning(
            "the planner did not stop within %.1f s of its cancellation; it is left running, "
            "and the input gate refuses everything it tries",
            STOP_TIMEOUT_S,
        )
        return
    if not task.cancelled():
        task.exception()  # mark it retrieved


def _start(planner: Planner[T], gate: InputGate) -> Awaitable[T]:
    if inspect.isawaitable(planner):
        return planner
    return planner(gate)
