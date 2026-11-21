"""The Guard SDK client (M1-07): one call per guard point, checking only.

``Guard`` wraps anything with the engine's ``check(ctx, guard_point, content)``, in M1 the
in-process :class:`~guardrail_engine.engine.Engine`. It exposes **checking only**: no
compile, store, publish or activate operation is reachable through it, and it never hands
back the object it wraps. Publishing goes through the Admin API (M2-07) with R2's approvals.

**The tenant comes only from the signed context.** :class:`GuardContext` carries the signed
tenant context the API gateway issued, passed through unchanged. No method here takes a
tenant id, and the SDK never sends one in the payload.
"""

from __future__ import annotations

import asyncio
import random
from collections.abc import AsyncGenerator, AsyncIterable, Awaitable, Callable
from dataclasses import dataclass, replace
from enum import StrEnum
from typing import Any, Protocol, TypeVar

from guardrail_engine.guard.request import CheckContext, ContextItem, ToolResult, Turn
from guardrail_engine.sdk.parallel import GuardedPlan, InputGate, Planner, plan_with_input_guard
from guardrail_engine.sdk.result import GuardResult
from guardrail_engine.sdk.streaming import (
    DEFAULT_MAX_WINDOW_CHARS,
    DEFAULT_WINDOW_TIMEOUT_S,
    StreamEvent,
    StreamWindow,
    check_stream_options,
    stream_output,
)

MAX_REQUEST_ID_CHARS = 128
RETRY_SUFFIX = "-retry"
DEFAULT_RETRY_WAIT_MS = 1_000
"""The wait before the single retry when the result carries no ``retry_after_ms``."""
DEFAULT_JITTER_MS = 250

T = TypeVar("T")


class Checker(Protocol):
    """What :class:`Guard` wraps: the engine's check."""

    async def check(self, ctx: CheckContext, guard_point: str, content: str) -> Any: ...


@dataclass(frozen=True, slots=True)
class CheckedItem:
    """A context item tagged with the check it passed: content that didn't arrive as a user
    turn or tool result (memory, an upload, retrieved history) and was routed through a
    guard point first (R7.3(b)). Built only by :meth:`SourceCheck.context_item`."""

    item: ContextItem
    request_id: str
    """The request id of the check that allowed it."""
    guard_point: str


ConversationItem = ContextItem | CheckedItem


@dataclass(frozen=True, slots=True)
class GuardContext:
    """The request context of one check: the signed tenant context, an optional request id,
    and the conversation context, oldest first. There is no tenant id field: the tenant is
    the one the signed context names."""

    signed_context: str
    request_id: str | None = None
    conversation: tuple[ConversationItem, ...] = ()
    conversation_id: str | None = None
    """The id of the conversation this check belongs to. Pass the same one for every check of a
    conversation: with a candidate version rolling out, it picks the version that decides, so
    all guard points of the conversation use the same one (PF-7)."""
    tool: str | None = None
    """For a ``tool_call`` check: **the tool the runtime will actually execute** (the name it
    dispatches on, not a name read out of the model's text). The tool allow-list (M3-01) is
    checked against it, so a tenant with an allow-list blocks a ``tool_call`` check that
    names no tool or one outside the list. Ignored at other guard points."""

    def to_check_context(self) -> CheckContext:
        # ``tool`` is passed by name, with no feature test: if the engine's
        # ``CheckContext`` ever renames it, this fails loudly instead of dropping the tool and
        # blocking every ``tool_call`` under an allow-list.
        return CheckContext(
            signed_context=self.signed_context,
            request_id=self.request_id,
            conversation=tuple(
                i.item if isinstance(i, CheckedItem) else i for i in self.conversation
            ),
            tool=self.tool,
            conversation_id=self.conversation_id,
        )


class Source(StrEnum):
    """Content that will appear as context but didn't arrive as a user turn or tool result.
    It must pass a guard point before it is used (R7.3(b)): the floor judges the content in
    the light of its context and doesn't re-judge the context."""

    MEMORY = "memory"
    """Long-term memory. Checked at ``input``."""
    UPLOAD = "upload"
    """An uploaded document. Checked at ``input``."""
    RETRIEVAL = "retrieval"
    """History retrieved from earlier sessions. Checked at ``tool_result``."""


SOURCE_GUARD_POINT = {Source.MEMORY: "input", Source.UPLOAD: "input",
                      Source.RETRIEVAL: "tool_result"}  # fmt: skip


class ContextNotClearedError(Exception):
    """A context source that wasn't allowed was asked for as a context item."""


@dataclass(frozen=True, slots=True)
class SourceCheck:
    """The result of checking a context source. Turn it into a context item with
    :meth:`context_item`, which refuses unless the check allowed the content."""

    source: Source
    result: GuardResult
    content: str

    def context_item(self, *, role: str = "user", tool: str | None = None) -> CheckedItem:
        """The checked content as a context item, tagged with the check it passed. Memory and
        uploads become a :class:`Turn` (``role``); retrieval becomes a :class:`ToolResult`
        and needs the ``tool`` that retrieved it. Raises :class:`ContextNotClearedError` if
        the check didn't allow the content."""
        if not self.result.released:
            raise ContextNotClearedError(
                f"the {self.source.value} wasn't allowed ({self.result.decision}/"
                f"{self.result.reason}); it can't be used as context"
            )
        item: ContextItem
        if self.source is Source.RETRIEVAL:
            if not tool:
                raise ValueError("retrieved content needs the tool that retrieved it")
            item = ToolResult(tool=tool, result=self.content)
        else:
            item = Turn(role=role, text=self.content)  # type: ignore[arg-type]
        return CheckedItem(item, self.result.request_id, self.result.guard_point)


class Guard:
    """Guard checks for one agent runtime. Checking only (M1-07)."""

    __slots__ = ("_checker",)

    def __init__(self, checker: Checker) -> None:
        self._checker = checker

    def __repr__(self) -> str:
        return "Guard()"

    async def check(self, guard_point: str, content: str, ctx: GuardContext) -> GuardResult:
        """Check ``content`` at ``guard_point``. Release or execute it only if the result's
        ``released`` is true (``decision == "allow"``)."""
        if not isinstance(ctx, GuardContext):
            raise TypeError("ctx must be a GuardContext carrying the signed tenant context")
        verdict = await self._checker.check(ctx.to_check_context(), guard_point, content)
        return GuardResult.from_verdict(verdict)

    def start_input_guard(self, content: str, ctx: GuardContext) -> InputGate:
        """Start the ``input`` check now, as a task, and return the PF-9 gate (M3-02). Run
        every tool and release every output of the turn through the gate: it waits for the
        verdict and refuses unless it is ``allow``. Must be called inside a running event
        loop. Prefer :meth:`plan_with_input_guard`, which also runs the planner alongside
        and cancels it on a block."""
        if not isinstance(ctx, GuardContext):
            raise TypeError("ctx must be a GuardContext carrying the signed tenant context")
        return InputGate(asyncio.ensure_future(self.check("input", content, ctx)))

    async def plan_with_input_guard(
        self, content: str, ctx: GuardContext, planner: Planner[T]
    ) -> GuardedPlan[T]:
        """Run the ``input`` guard and the caller's ``planner`` concurrently (M3-02). A
        non-allow verdict cancels the planner; no tool runs and no output is released before
        the verdict (PF-9). See :mod:`guardrail_engine.sdk.parallel`."""
        return await plan_with_input_guard(self, content, ctx, planner)

    def stream_output(
        self,
        chunks: AsyncIterable[str],
        ctx: GuardContext,
        *,
        gate: InputGate | None,
        stream_window: StreamWindow | str = StreamWindow.SENTENCE,
        refusal_message: str | None = None,
        max_window_chars: int = DEFAULT_MAX_WINDOW_CHARS,
        window_timeout_s: float = DEFAULT_WINDOW_TIMEOUT_S,
    ) -> AsyncGenerator[StreamEvent, None]:
        """Guard a streamed answer window by window (M3-05): each window is checked at
        ``output`` and released only on ``allow``; a block stops the stream and yields the
        refusal message. **One check per window.** ``stream_window`` is the tenant's setting
        (``"sentence"`` or ``"full"``), and ``refusal_message`` the tenant's message; the
        bundle doesn't carry either yet.

        ``gate`` is required: the turn's :class:`InputGate` from
        :meth:`start_input_guard` or :meth:`plan_with_input_guard`, so that nothing is checked
        or released before the input verdict (PF-9). Pass ``gate=None`` only when no input
        guard was started for this turn. ``window_timeout_s`` must be positive.
        Every argument is checked now, not at the first iteration. See
        :mod:`guardrail_engine.sdk.streaming`."""
        if not isinstance(ctx, GuardContext):
            raise TypeError("ctx must be a GuardContext carrying the signed tenant context")
        check_stream_options(gate, max_window_chars, window_timeout_s)
        return stream_output(
            self,
            chunks,
            ctx,
            stream_window=stream_window,
            refusal_message=refusal_message,
            gate=gate,
            max_window_chars=max_window_chars,
            window_timeout_s=window_timeout_s,
        )

    async def check_source(self, source: Source, content: str, ctx: GuardContext) -> SourceCheck:
        """Route a context source through its guard point: memory and uploads at ``input``,
        retrieved history at ``tool_result``."""
        source = Source(source)
        result = await self.check(SOURCE_GUARD_POINT[source], content, ctx)
        return SourceCheck(source=source, result=result, content=content)

    async def check_with_retry(
        self,
        guard_point: str,
        content: str,
        ctx: GuardContext,
        *,
        default_wait_ms: int = DEFAULT_RETRY_WAIT_MS,
        jitter_ms: int = DEFAULT_JITTER_MS,
        sleep: Callable[[float], Awaitable[Any]] = asyncio.sleep,
        rand: Callable[[], float] = random.random,
    ) -> GuardResult:
        """:meth:`check`, retried **at most once** when the result is ``retryable``. The
        wait is at least ``retry_after_ms`` (``default_wait_ms`` when there is none) plus up
        to ``jitter_ms`` of jitter. A non-retryable result is never retried, and the content
        is withheld on every non-allow result, retried or not.

        The retry is a new check. Its request id is the first check's (the id the engine
        actually used) with ``-retry`` appended, and its result's ``retry_of`` names
        the first check's request id."""
        first = await self.check(guard_point, content, ctx)
        if not first.retryable:
            return first
        wait_ms = max(0, first.retry_after_ms or default_wait_ms) + rand() * max(0, jitter_ms)
        await sleep(wait_ms / 1000)
        second = await self.check(
            guard_point, content, replace(ctx, request_id=retry_request_id(first.request_id))
        )
        return replace(second, retry_of=first.request_id)


def retry_request_id(request_id: str | None) -> str | None:
    """The retry's request id: ``request_id`` (the first check's) with ``-retry`` appended,
    within the service's 128-character limit; None when there is none."""
    if not request_id:
        return None
    return request_id[: MAX_REQUEST_ID_CHARS - len(RETRY_SUFFIX)] + RETRY_SUFFIX
