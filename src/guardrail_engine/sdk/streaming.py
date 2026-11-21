"""M3-05: the streaming ``output`` window.

``Guard.stream_output`` takes the agent's streamed answer, cuts it into **windows**, checks
each window at the ``output`` guard point, and releases a window **only when its check is
``allow``**. A window that isn't allowed stops the stream: nothing after it is released, the
source stream is closed, and the caller gets one refusal event carrying the tenant's refusal
message.

**Where ``stream_window`` lives.** The bundle schema (``policy/schema.py``) has no
``stream_window`` setting yet (the design's sample bundle shows
``"output": {"stream_window": "sentence"}``, but the schema forbids unknown fields). Until it
does, it is an argument of :meth:`~guardrail_engine.sdk.Guard.stream_output`: the integrator
passes the tenant's value. The same goes for the tenant's refusal message: the bundle doesn't
carry one, so the integrator passes it as ``refusal_message``.

* ``StreamWindow.SENTENCE`` (``"sentence"``): one window per sentence, as defined below.
* ``StreamWindow.FULL`` (``"full"``): no streaming. The whole answer is one window, checked
  when the stream ends; nothing is released before that.

**Cost.** **One check per window**: one ``output`` check, so one decision call, per sentence.
A twenty-sentence answer is twenty checks, against the tenant's request and token budgets
(M3-07) and the provider's rate limit. Nothing is cached or batched. A tenant that can't
afford that uses ``FULL`` (one check, no streaming) or sets a larger ``max_window_chars``.

**Latency bound.** The latency a window adds is one check, and it is bounded two ways:

* no window is longer than ``max_window_chars`` (default 1,000 characters, roughly 250
  tokens), so a check never grows with the length of a run-on sentence; and
* each check has a deadline, ``window_timeout_s`` (default 5 s). A check that doesn't answer
  in time is a ``block`` with ``reason: model_failure`` and ``failure_reason: timeout``
  (retryable, so the default message says "temporarily unavailable"), and the window is
  withheld. Fail closed: no window is released unchecked. (``FULL`` mode's single window is
  not split, so it isn't bounded by ``max_window_chars``; the service's own content bound
  applies.)

Windows are checked one at a time, in order, and the source is read only as fast as they
clear. The user waits for the sentence in front of the one being checked, no more.

**Sentence splitting (conservative).** A split puts a window boundary after a sentence end.
It prefers to leave two sentences together over cutting one in two: a larger window only
costs a little hold-back, a wrong cut checks half a sentence out of context. Rules, in order:

1. A sentence ends at ``.``, ``!``, ``?`` or ``…`` (a run of them counts as one), plus any
   closing quotes or brackets, **followed by whitespace**, or at the CJK full stop,
   exclamation and question marks (U+3002, U+FF01, U+FF1F), which need no whitespace. So
   ``3.14``, ``example.com`` and ``v2.1`` never split.
2. **No split** when the next non-space character is lowercase (``"...vs. the cat"``): the
   sentence went on. A ``.`` after a known abbreviation (``Mr.``, ``Dr.``, ``e.g.``,
   ``etc.``, ``vs.`` ...), a single letter (an initial), an initialism (``U.S.``) or a number
   alone (``1.``, a list marker) is not an end either. ``etc.`` at the real end of a
   sentence is therefore not split: that is the conservative direction.
3. A blank line (a paragraph break) always ends a window, and so does any terminator
   followed by a newline.
4. A window never exceeds ``max_window_chars``: past that it is cut at the last whitespace
   within the limit (or at the limit when there is none).
5. **End of stream:** the last, partial window (text with no terminator) is checked and
   released like any other. Whitespace-only text is never checked or released.

A sentence ending is held back until the next non-space character arrives (the next word
decides whether it was an end, and the trailing whitespace is complete), the stream ends, or
the window limit is reached. Windows carry their trailing whitespace, so the released
windows concatenated are the answer, exactly, up to the point of a block.

**Context across windows.** Each window's check carries the **end of the window
released before it** (its last :data:`CONTEXT_TAIL_CHARS` characters) as an assistant turn
after ``ctx``'s conversation. Context isn't judged, but the window is judged in its light, so a
violation split across a boundary (``"the password is"`` / ``"hunter2."``) is seen without a
second check. It costs a few tokens a window. The first window has no previous one, and a
window that wasn't released ends the stream, so only released text is ever carried.

**Limits.** Only the tail of the window before it is in view, so something spread over more
than that, or over a longer span, may not be caught by the per-window check. The tenant that
needs that sets ``stream_window: full``. The PF-9 invariant (M3-02) holds here too: pass the
turn's :class:`InputGate` as ``gate`` and no window is checked or released before the input
verdict arrives, nor if it isn't ``allow``. ``gate`` is a required argument, so a
caller can't forget it; ``None`` says no input guard was started for the turn.

**The messages.** A withheld window ends the stream with one refusal event. Its text is the
tenant's ``refusal_message`` for a ``block``, ``forbidden`` or unknown decision; for an
``escalate`` (held for review, not refused) it is the SDK's hold message ("needs a review"),
and for a retryable failure "temporarily unavailable".
"""

from __future__ import annotations

import asyncio
import math
import re
from collections.abc import AsyncGenerator, AsyncIterable
from dataclasses import dataclass, replace
from enum import StrEnum
from typing import TYPE_CHECKING, Literal

from guardrail_engine.guard.request import Turn
from guardrail_engine.sdk.result import MESSAGES, FailureReason, GuardResult

if TYPE_CHECKING:
    from guardrail_engine.sdk.client import Guard, GuardContext
    from guardrail_engine.sdk.parallel import InputGate

MAX_REQUEST_ID_CHARS = 128
DEFAULT_MAX_WINDOW_CHARS = 1_000
DEFAULT_WINDOW_TIMEOUT_S = 5.0
CONTEXT_TAIL_CHARS = 400
"""How much of the previously released window the next window's check carries as context: about 100
tokens, enough for the sentence a split would have cut."""

_TERMINATORS = frozenset(".!?\u2026\u3002\uff01\uff1f")
_CJK_TERMINATORS = frozenset("\u3002\uff01\uff1f")
_CLOSERS = frozenset("\"')]}\u00bb\u201d\u2019")
_OPENERS = "\"'([{\u00ab\u201c\u2018"
_ABBREVIATIONS = frozenset(
    {
        "mr",
        "mrs",
        "ms",
        "mx",
        "dr",
        "prof",
        "sr",
        "jr",
        "st",
        "mt",
        "vs",
        "etc",
        "e.g",
        "i.e",
        "cf",
        "al",
        "approx",
        "dept",
        "est",
        "fig",
        "inc",
        "ltd",
        "co",
        "corp",
        "no",
        "nos",
        "vol",
        "vols",
        "pp",
        "ca",
        "viz",
    }
)
_INITIALISM = re.compile(r"^(?:[A-Za-z]\.)+[A-Za-z]$")


class StreamWindow(StrEnum):
    """The tenant's ``stream_window`` setting."""

    SENTENCE = "sentence"
    """One window, so one check, per sentence."""
    FULL = "full"
    """No streaming: the whole answer is one window, checked at the end of the stream."""


class SentenceSplitter:
    """Cuts streamed text into windows (see the module docstring for the rules). Feed it
    chunks; it returns the windows that are complete; :meth:`flush` returns the final partial
    window at the end of the stream."""

    __slots__ = ("_buf", "_max", "_whole")

    def __init__(self, window: StreamWindow, max_window_chars: int) -> None:
        if max_window_chars < 1:
            raise ValueError("max_window_chars must be at least 1")
        self._buf = ""
        self._max = max_window_chars
        self._whole = window is StreamWindow.FULL

    def feed(self, text: str) -> list[str]:
        self._buf += text
        return [] if self._whole else self._drain(final=False)

    def flush(self) -> list[str]:
        """The rest of the stream: the final partial window (and anything held back for
        lookahead). Whitespace-only text yields nothing."""
        out = [self._buf] if self._whole else self._drain(final=True)
        self._buf = ""
        return [w for w in out if w.strip()]

    def _drain(self, *, final: bool) -> list[str]:
        windows: list[str] = []
        while self._buf:
            end = _sentence_end(self._buf, final=final)
            if len(self._buf) > self._max and (end is None or end > self._max):
                end = _forced_cut(self._buf, self._max)
            if end is None:
                break
            window, self._buf = self._buf[:end], self._buf[end:]
            if window.strip():
                windows.append(window)  # a whitespace-only run is dropped, never checked
        if final and self._buf.strip():
            windows.append(self._buf)
        return windows


def _forced_cut(buf: str, limit: int) -> int:
    """Where to cut ``buf`` (longer than ``limit``): after the last whitespace within the
    limit, or at the limit."""
    for i in range(limit - 1, 0, -1):
        if buf[i].isspace():
            return i + 1
    return limit


def _sentence_end(buf: str, *, final: bool) -> int | None:
    """The index just after the first complete sentence in ``buf``, with the whitespace
    that follows it; None if there isn't one yet."""
    n = len(buf)
    i = 0
    while i < n:
        c = buf[i]
        if c == "\n":
            j = i + 1
            while j < n and buf[j] in " \t\r":
                j += 1
            if j < n and buf[j] == "\n" and buf[:i].strip():  # a blank line
                m = _skip_space(buf, j)
                return m if m < n or final else None
        elif c in _TERMINATORS:
            j = i
            while j < n and buf[j] in _TERMINATORS:
                j += 1
            k = j
            while k < n and buf[k] in _CLOSERS:
                k += 1
            if buf[j - 1] in _CJK_TERMINATORS:
                m = _skip_space(buf, k)
                return m if m < n or final else None
            if k >= n:
                return n if final else None  # the next character decides
            if buf[k].isspace():
                m = _skip_space(buf, k)
                if "\n" in buf[k:m] and m < n:
                    return m  # a terminator, then a line break
                if m >= n:
                    return n if final else None
                if not _continues(buf, i, j, buf[m]):
                    return m
            i = j
            continue
        i += 1
    return None


def _skip_space(buf: str, i: int) -> int:
    while i < len(buf) and buf[i].isspace():
        i += 1
    return i


def _continues(buf: str, start: int, end: int, next_char: str) -> bool:
    """Whether the terminator run ``buf[start:end]`` doesn't end the sentence: the next word
    is lowercase, or it is a ``.`` after an abbreviation, an initial, an initialism or a
    bare number."""
    if next_char.islower():
        return True
    if end - start != 1 or buf[start] != ".":
        return False
    token_start = start
    while token_start > 0 and not buf[token_start - 1].isspace():
        token_start -= 1
    token = buf[token_start:start].lstrip(_OPENERS)
    return (
        token.lower() in _ABBREVIATIONS
        or (len(token) == 1 and token.isalpha())
        or bool(_INITIALISM.match(token))
        or token.isdigit()
    )


@dataclass(frozen=True, slots=True)
class StreamEvent:
    """One event of a guarded stream: a window to release, or the refusal that ended it."""

    kind: Literal["window", "refusal"]
    text: str
    """``window``: the text to release (checked, ``allow``). ``refusal``: the message to show
    the user in place of the rest of the answer; it is not model output."""
    index: int
    """The window's position, from 0. For a refusal, the position of the window that was
    withheld (or 0 when the input verdict stopped the stream before any window)."""
    result: GuardResult
    """The check's result: the ``allow`` that released a window, or the verdict that
    withheld one (the input verdict when ``gate`` stopped it)."""

    @property
    def released(self) -> bool:
        return self.kind == "window"


def refusal_text(result: GuardResult, refusal_message: str | None) -> str:
    """The message for a withheld window: the tenant's ``refusal_message`` when it has one and
    the window was refused (``block``, ``forbidden`` or an unknown decision). Not for a
    retryable failure (an outage isn't a refusal, so it says "temporarily unavailable"), and not
    for an ``escalate`` (held for review, not refused: the hold message, "needs a review");
    otherwise the SDK's default for the result."""
    if refusal_message and not result.retryable and not result.held_for_escalation:
        return refusal_message
    return result.user_message or MESSAGES["neutral"]


def check_stream_options(gate: object, max_window_chars: int, window_timeout_s: float) -> None:
    """Refuse a stream option that would switch a bound off. ``window_timeout_s`` must be a
    positive, finite number (``None`` would disable the latency bound), and
    ``max_window_chars`` a positive integer. ``gate`` must be given (an
    :class:`InputGate`, or ``None`` for a turn with no input guard) and nothing else."""
    from guardrail_engine.sdk.parallel import InputGate

    if gate is not None and not isinstance(gate, InputGate):
        raise TypeError("gate must be the turn's InputGate, or None when there is no input guard")
    if (
        isinstance(window_timeout_s, bool)
        or not isinstance(window_timeout_s, (int, float))
        or not math.isfinite(window_timeout_s)
        or window_timeout_s <= 0
    ):
        raise ValueError("window_timeout_s must be a positive number of seconds")
    if isinstance(max_window_chars, bool) or not isinstance(max_window_chars, int):
        raise TypeError("max_window_chars must be an integer")
    if max_window_chars < 1:
        raise ValueError("max_window_chars must be at least 1")


def _with_previous(ctx: GuardContext, previous: str) -> GuardContext:
    """``ctx`` with the tail of the window released before this one as an assistant turn."""
    if not previous:
        return ctx
    tail = previous[-CONTEXT_TAIL_CHARS:]
    return replace(ctx, conversation=(*ctx.conversation, Turn(role="assistant", text=tail)))


def _window_context(ctx: GuardContext, index: int) -> GuardContext:
    """Each window is its own check with its own request id (the caller's, if any, plus
    ``-w<index>``, within the service's 128-character limit)."""
    if not ctx.request_id:
        return ctx
    suffix = f"-w{index}"
    return replace(ctx, request_id=ctx.request_id[: MAX_REQUEST_ID_CHARS - len(suffix)] + suffix)


def _timed_out(request_id: str | None) -> GuardResult:
    return GuardResult(
        decision="block",
        reason="model_failure",
        request_id=request_id or "",
        guard_point="output",
        fired=(),
        retryable=True,
        failure_reason=FailureReason.TIMEOUT,
        capacity_limited=False,
        retry_after_ms=None,
    )


async def stream_output(
    guard: Guard,
    chunks: AsyncIterable[str],
    ctx: GuardContext,
    *,
    gate: InputGate | None,
    stream_window: StreamWindow | str = StreamWindow.SENTENCE,
    refusal_message: str | None = None,
    max_window_chars: int = DEFAULT_MAX_WINDOW_CHARS,
    window_timeout_s: float = DEFAULT_WINDOW_TIMEOUT_S,
) -> AsyncGenerator[StreamEvent, None]:
    """Guard a streamed answer: see the module docstring. Yields ``window`` events to
    release, in order, and ends after one ``refusal`` event if a window isn't ``allow``.
    **One check per window** (cost: see the module docstring).

    ``gate`` is the turn's PF-9 gate and is required: nothing is checked or released
    before the input verdict arrives, and a non-allow input verdict ends the stream with a
    refusal. ``None`` says no input guard was started for this turn.
    The source stream is closed when the generator ends, whether it finished, was blocked or
    was abandoned (``aclose``). An exception from a check propagates (nothing is released)."""
    check_stream_options(gate, max_window_chars, window_timeout_s)
    window_mode = StreamWindow(stream_window)
    splitter = SentenceSplitter(window_mode, max_window_chars)
    index = 0
    previous = ""  # the last released window
    source = aiter(chunks)

    async def gated(window: str) -> StreamEvent:
        nonlocal index, previous
        n = index
        index += 1
        if gate is not None:
            first = await gate.verdict()
            if not first.released:
                return StreamEvent("refusal", refusal_text(first, refusal_message), n, first)
        wctx = _window_context(_with_previous(ctx, previous), n)
        try:
            result = await asyncio.wait_for(
                guard.check("output", window, wctx), timeout=window_timeout_s
            )
        except TimeoutError:
            result = _timed_out(wctx.request_id)
        if not result.released:
            return StreamEvent("refusal", refusal_text(result, refusal_message), n, result)
        previous = window
        return StreamEvent("window", window, n, result)

    try:
        async for chunk in source:
            if not isinstance(chunk, str):
                raise TypeError("a stream chunk must be text")
            for window in splitter.feed(chunk):
                event = await gated(window)
                yield event
                if not event.released:
                    return
        for window in splitter.flush():
            event = await gated(window)
            yield event
            if not event.released:
                return
    finally:
        close = getattr(source, "aclose", None)
        if close is not None:
            await close()
