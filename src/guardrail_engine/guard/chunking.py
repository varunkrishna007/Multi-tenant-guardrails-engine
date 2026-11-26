"""``tool_result`` chunking (M3-04, AC-G5, PF-17, PF-5).

A tool result can be larger than one decision call may carry. Content over the guard point's
``chunk_tokens`` (default :data:`~guardrail_engine.policy.catalog.DEFAULT_CHUNK_TOKENS`,
12,000 raw tokens; a bundle may set its own) is **split into chunks that overlap by 256
tokens**, so an injection that straddles a boundary is whole in at least one chunk (PF-17;
one longer than the overlap can still be cut, which the overlap can't help). Never truncated:
every token of the content is in some chunk.

**What runs once, and what runs per chunk.** The size bound (on the raw content), the
deterministic checks (deny patterns, the cross-tenant identifier scan) and PII redaction run
**once, on the whole content, before chunking**; the chunks are cut from the *redacted*
content, which is what is sent. Each chunk is then rendered and sent as its own decision
call, with the **same question set** and the same conversation context (the context is cut to
whatever room the chunk leaves, as for any content, so a full chunk carries none).

**Cost.** One decision call per chunk, each carrying all of the guard point's questions: a
result of ``n`` chunks costs ``n`` calls, ``n`` times the question tokens, and about the
content's tokens plus ``(n - 1) x 256`` for the overlaps. Every call goes through the
gateway's per-key admission control like any other (no bypass, and no assumption that calls on
one key run in parallel, M1-04); the chunk calls are *submitted* together, and the gateway
decides how many run at once and which wait or are refused. A platform cap,
``PlatformSettings.max_chunks_per_result``, bounds ``n`` so that one tool result can't turn
into an unbounded number of calls: a result needing more is a deterministic block,
``content_too_large``, with no model call.

**Merging (PF-5).** The chunk answers become one answer per question key, **maximum p per
key**, and then go through the ordinary resolution and fusion (:func:`merge_answers`). A key
whose answer was unusable in any chunk stays unusable (resolved by its fail mode, PF-6): a
chunk's problem is never outvoted by another chunk's good answer.

**Failure (B1).** If any chunk's call fails, the guard point has failed as a whole: it is a
model failure, resolved rule by rule by each rule's layer fail mode, however many other chunks
answered (:func:`combine`). A provider ``safety`` refusal of any chunk is a block (PF-12). On
the first failure the chunk calls still **queued** for a slot are cancelled,
so an outage doesn't spend the rest of the admissions on an answer that can't change; calls
already in flight are left to end.

**Chunk size.** A bundle's ``chunk_tokens`` is at least ``PlatformSettings.min_chunk_tokens``
(2,048), so the floor never sees fragments with little context. The
overlap stays a fixed 256 tokens and the cut points are deterministic (PF-17's accepted
residual: an instruction longer than the overlap can be cut, and replay stays reproducible).
"""

from __future__ import annotations

from collections.abc import Sequence

from guardrail_engine.decision.port import (
    Answered,
    AnswerProblem,
    Failed,
    FailureKind,
    SafetyBlocked,
)
from guardrail_engine.decision.types import (
    Answer,
    ChoiceAnswer,
    NoulAnswer,
    ScoreAnswer,
    Usage,
)
from guardrail_engine.gateway.gateway import CheckTiming, TimedDecision

CHUNK_OVERLAP_TOKENS = 256
"""PF-17: neighbouring chunks share this many (raw, estimated) tokens."""

_QUARTERS_PER_TOKEN = 4
"""The estimator counts an ASCII character as 1/4 token and any other as a whole token
(:func:`guardrail_engine.tokens.estimate_tokens`). Chunks are cut on that weight, in
quarter-tokens, so a chunk's estimate never exceeds the chunk size."""


def overlap_tokens(chunk_tokens: int) -> int:
    """The overlap for a chunk size: :data:`CHUNK_OVERLAP_TOKENS`, or half the chunk for a
    chunk size under 512 so the window still moves forward."""
    return min(CHUNK_OVERLAP_TOKENS, chunk_tokens // 2)


def chunk_bounds(text: str, chunk_tokens: int) -> list[tuple[int, int]]:
    """The ``(start, end)`` character range of each chunk of ``text``, in order. One range
    covering the whole text when it fits ``chunk_tokens``. Every chunk's estimated tokens are
    at most ``chunk_tokens``; consecutive chunks overlap by at least :func:`overlap_tokens`
    (estimated tokens, measured the same way; exactly that for ASCII text); the first starts
    at 0 and the last ends at ``len(text)``."""
    if chunk_tokens < 1:
        raise ValueError("chunk_tokens must be at least 1")
    size = chunk_tokens * _QUARTERS_PER_TOKEN
    overlap = overlap_tokens(chunk_tokens) * _QUARTERS_PER_TOKEN
    n = len(text)
    if text.isascii():  # one quarter-token per character: plain arithmetic
        if n <= size:
            return [(0, n)]
        step = size - overlap
        bounds, start = [], 0
        while True:
            end = min(start + size, n)
            bounds.append((start, end))
            if end == n:
                return bounds
            start += step
    weight = [0]
    for char in text:
        weight.append(weight[-1] + (1 if char < "\x80" else _QUARTERS_PER_TOKEN))
    if weight[n] <= size:
        return [(0, n)]
    bounds, start = [], 0
    while True:
        end = _last_at_most(weight, weight[start] + size)  # the furthest end that fits
        bounds.append((start, end))
        if end == n:
            return bounds
        # The next chunk starts as far back as leaves at least ``overlap`` of weight shared (a
        # whole character may overshoot by up to 3 quarter-tokens, never fall short), but not
        # so far forward that it can't take in the character the last chunk stopped before.
        # Only a chunk size of 2 tokens can't have both; progress wins there.
        keeps_overlap = _last_at_most(weight, weight[end] - overlap)
        reaches_on = _first_at_least(weight, weight[end + 1] - size)
        start = max(keeps_overlap, reaches_on)


def _last_at_most(weight: list[int], limit: int) -> int:
    """The largest index whose cumulative weight is at most ``limit`` (weights are strictly
    increasing, so this is a binary search)."""
    lo, hi = 0, len(weight) - 1
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if weight[mid] <= limit:
            lo = mid
        else:
            hi = mid - 1
    return lo


def _first_at_least(weight: list[int], limit: int) -> int:
    """The smallest index whose cumulative weight is at least ``limit``."""
    lo, hi = 0, len(weight) - 1
    while lo < hi:
        mid = (lo + hi) // 2
        if weight[mid] >= limit:
            hi = mid
        else:
            lo = mid + 1
    return lo


def split_chunks(text: str, chunk_tokens: int) -> list[str]:
    """``text`` as chunks of at most ``chunk_tokens`` estimated tokens, overlapping by
    :func:`overlap_tokens`. ``[text]`` when it fits one chunk."""
    return [text[a:b] for a, b in chunk_bounds(text, chunk_tokens)]


# --------------------------------------------------------------------------- merging


def _most_confident(answers: Sequence[Answer]) -> Answer:
    return max(answers, key=lambda a: a.confidence)


def merge_answers(chunks: Sequence[Answered]) -> Answered:
    """One :class:`Answered` from the chunks' answers (PF-5): for each question key,

    * a ``noul`` question keeps the answer with the **maximum p** (the whole answer, so its
      confidence goes with it);
    * a router (``choice``) or scorer (``score``), which never acts on its own, keeps the
      most confident chunk's answer;
    * a key with a **problem in any chunk** keeps that problem (the first, in chunk order)
      and no answer.

    The usage is the sum of the chunks' (None if any chunk has none)."""
    if not chunks:
        raise ValueError("no chunk answers to merge")
    keys: list[str] = []
    for chunk in chunks:
        for key in (*chunk.answers, *chunk.problems):
            if key not in keys:
                keys.append(key)
    answers: dict[str, Answer] = {}
    problems: dict[str, AnswerProblem] = {}
    for key in keys:
        bad = next((c.problems[key] for c in chunks if key in c.problems), None)
        if bad is not None:
            problems[key] = bad
            continue
        found = [c.answers[key] for c in chunks if key in c.answers]
        if len(found) < len(chunks):  # a chunk said nothing at all about this key
            continue  # no answer and no problem: evaluation resolves it as missing
        noul = [a for a in found if isinstance(a, NoulAnswer)]
        if len(noul) == len(found):
            answers[key] = max(noul, key=lambda a: a.noul)
        elif all(isinstance(a, ChoiceAnswer | ScoreAnswer) for a in found):
            answers[key] = _most_confident(found)
        # a mix of types for one key can't be merged: left out, so it resolves as missing
    usages = [c.usage for c in chunks]
    usage = (
        Usage(
            total_input_tokens=sum(u.total_input_tokens for u in usages if u is not None),
            total_output_tokens=sum(u.total_output_tokens for u in usages if u is not None),
        )
        if all(u is not None for u in usages)
        else None
    )
    return Answered(
        answers=answers,
        problems=problems,
        usage=usage,
        usage_problem=None if usage is not None else "a chunk reported no usage",
    )


def combine(decisions: Sequence[TimedDecision]) -> TimedDecision:
    """One gateway outcome for the chunk calls of one check.

    * any chunk **refused for safety**: that refusal (PF-12, a block);
    * else any chunk **failed**: that failure, the first in chunk order. The guard point is
      a model failure (B1) whatever the other chunks said. ``retry_after_ms`` is the longest
      the failed chunks asked for, and ``capacity_limited`` is set if any failed chunk was
      refused for capacity, and ``degraded`` if any failed chunk was failed because the provider
      is degraded (M7-11);
    * else the **merged answer** (:func:`merge_answers`).

    The timing adds up the work (queue waits, provider time and provider calls over all
    chunks); ``in_flight_at_start`` is the first chunk's, what the check met on arrival."""
    if not decisions:
        raise ValueError("no chunk decisions to combine")
    results = [d.result for d in decisions]
    timing = CheckTiming(
        queue_wait_ms=sum(d.timing.queue_wait_ms for d in decisions),
        provider_latency_ms=sum(d.timing.provider_latency_ms for d in decisions),
        provider_calls=sum(d.timing.provider_calls for d in decisions),
        in_flight_at_start=decisions[0].timing.in_flight_at_start,
    )
    safety = next((r for r in results if isinstance(r, SafetyBlocked)), None)
    if safety is not None:
        return TimedDecision(result=safety, timing=timing)
    failed = [(d, d.result) for d in decisions if not isinstance(d.result, Answered)]
    if failed:
        first = next((r for _, r in failed if isinstance(r, Failed)), None)
        if first is None:  # not a result the gateway promises
            first = Failed(kind=FailureKind.OTHER)
        waits = [d.retry_after_ms for d, _ in failed if d.retry_after_ms is not None]
        return TimedDecision(
            result=first,
            timing=timing,
            retry_after_ms=max(waits) if waits else None,
            capacity_limited=any(d.capacity_limited for d, _ in failed),
            degraded=any(d.degraded for d, _ in failed),
        )
    answered = [r for r in results if isinstance(r, Answered)]
    return TimedDecision(result=merge_answers(answered), timing=timing)
