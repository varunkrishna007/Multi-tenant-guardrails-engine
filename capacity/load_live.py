"""M3-09 live mode: the plan, the gates and the runner for the three live runs. **Not run.**

    uv run python -m capacity.load_live plan                       # call volume and cost, no calls
    uv run python -m capacity.load_live run --kind latency --out X.jsonl           # a dry run
    uv run python -m capacity.load_live run --kind latency --out X.jsonl --live \\
        --max-provider-calls 650 --max-tokens 6000000              # needs the env var too

Three runs (backlog M3-09, the [LIVE] items):

* ``capacity``: the engine (``build_engine``, the real Gemini adapter) driven by the harness's
  simulated turns on a ramp of offered load, to measure requests and tokens per turn with
  Google's tokenizer and to see the limiter hold. One project, floor-only bundles, no tenant
  shares (the pool alone is under test).
* ``latency``: the second-region latency profile: at least 500 calls on the floor-sized cell
  (4K input, 12 questions), sequential, to confirm or re-fit the R6 expected-latency model.
* ``largest``: the largest compilable calls under R6.7, at least 500 each, sequential and at the
  production in-flight limit: a full ``input`` check and a full critical-path check.

The adapter calls of ``latency`` and ``largest`` are direct (as ``bench/latency.py``): they
measure the provider, not the engine.

**The default is a dry run**: the same code, with the modelled-latency fake on a virtual clock.
A **live** run needs all of: ``--live``, ``GUARDRAILS_LIVE_LOADTEST=`` :data:`LIVE_TOKEN`, an
explicit ``--max-provider-calls`` and ``--max-tokens`` (each at most the kind's hard ceiling,
:data:`HARD_MAX_CALLS` and :data:`HARD_MAX_TOKENS`, and at least the plan's worst case), and
``GEMINI_API_KEY`` in the environment (it is read from the environment only: never from a file,
never printed, logged or written). Without all of them :func:`refuse_to_start` raises before any
model, client or key is touched.

**What may be sent (user instruction, 2026-11-17: no harmful inputs to Google).** Synthetic,
benign text only: plain words from a fixed list (:func:`capacity.load_test.benign_text`) and
templated yes/no questions about scheduling and paperwork (:func:`synthetic_questions`). No row
of any corpus, no pack, no harm-labelled or ``no_live_run`` content. Before each call the text
goes through the engine's harm-vocabulary tripwire and ``calibration.run.live_exclusion`` (the
send-time checks of ``calibration/pack_live.py``), and a run whose compiled questions carry the
harm-facilitation rule is refused. The question text is checked at plan time too.

**The first provider refusal stops the run** (and ``auth``, an unclassified failure, a 429 that
the pacing should have prevented, a failure rate over 20% of the last 50 calls, and a ceiling).
Nothing is resent. The stop is a state of the run, not an exception in one task
(:attr:`Ledger.stopped`): no call starts anywhere in the run after it, because every send checks
it immediately before going out and every pacing sleep wakes on it. A call already in
flight when it was set may finish (it is recorded, marked ``after_stop``) but is never retried.
The ceilings count what is reserved as well as what has finished: a call, and its estimated
tokens, are reserved before it is sent and settled when it completes. Records hold
sizes, timings, outcomes and token counts: never content, headers, provider text or the key.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import functools
import json
import os
import random
import sys
from collections import deque
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, NoReturn

from capacity.load_test import (
    DEFAULT_SHAPES,
    LatencyModel,
    LoadConfig,
    ModelledLatencyModel,
    RecordingModel,
    TenantSpec,
    benign_text,
    drive,
    percentile,
    render_markdown,
    run_virtual,
    sleep_unless_stopped,
    summarise,
)
from capacity.load_test import simulate as simulate_offline
from capacity.model import PRICE_PER_MILLION_INPUT_TOKENS_USD, tier
from guardrail_engine.decision.limits import estimate_question_tokens
from guardrail_engine.decision.port import Answered, Failed, FailureKind, SafetyBlocked
from guardrail_engine.decision.types import NoulCriteria, NoulQuestion
from guardrail_engine.gateway import GatewayConfig
from guardrail_engine.policy.api_tokens import estimate_api_tokens
from guardrail_engine.tokens import estimate_tokens

ROOT = Path(__file__).resolve().parents[1]

LIVE_KEY = "GUARDRAILS_LIVE_LOADTEST"
LIVE_TOKEN = "m3-09-capacity-signoff"
KINDS = ("capacity", "latency", "largest")

HARD_MAX_CALLS = {"capacity": 6_000, "latency": 800, "largest": 2_600}
"""The most provider calls a live run of each kind may be given as its ceiling. Above these the
run is refused whatever ``--max-provider-calls`` says; the plan's worst case is below them."""
HARD_MAX_TOKENS = {"capacity": 40_000_000, "latency": 8_000_000, "largest": 90_000_000}
"""The same for input tokens."""

MIN_CALLS_PER_CELL = 500
"""M3-09: at least 500 calls per cell."""
WARMUP_CALLS = 5
"""Discarded warm-up calls before each cell (connection set-up), counted against the ceilings."""
PACE_FRACTION = 0.5
"""The direct runs space their calls so the cell uses this share of Tier 1's tokens per minute
(the engine's own limiter targets 68%; these runs are not behind it)."""
MAX_TEXT_TOKENS = (16_000 - 30) * 100 // 120
"""The largest input text R6.7 allows (raw estimated tokens): ``1.20 x text + 30 <= 16,000``."""
FAIL_WINDOW = 50
FAIL_FRACTION = 0.20
RAMP = (0.25, 0.50, 0.75, 1.00)
"""The capacity run's offered load, as fractions of the turns/min at which the engine's token
limiter starts to hold (68% of tokens/min)."""
RAMP_STEP_MINUTES = 8.0


class Refused(Exception):
    """The run must not start. The message says why and never quotes content."""


class StopLive(Exception):
    """The run stops here, by rule. The message is fixed wording: no content, no provider text."""


# --------------------------------------------------------------------------- what may be sent


def send_refusal(row_id: str, texts: Sequence[str]) -> str | None:
    """Why this text may not be sent, or None. The two send-time checks of ``pack_live``: the
    label filter (``calibration.run.live_exclusion``) and the harm-vocabulary tripwire. A
    reason is fixed wording, never the text."""
    from calibration.run import live_exclusion

    from guardrail_engine.admin.vocabulary import strings_tripwire

    if (why := live_exclusion({"id": row_id, "no_live_run": False})) is not None:
        return why
    if strings_tripwire(*texts):
        return "harm-vocabulary tripwire"
    return None


_TOPICS = (
    "a delivery schedule", "an invoice date", "a meeting time", "a warehouse location",
    "a renewal reminder", "a travel itinerary", "a budget summary", "a training workshop",
    "a supplier contract", "an inventory count", "a calendar change", "a project milestone",
)  # fmt: skip
_DETAIL = (
    "Answer yes only when the text clearly and explicitly does this. Answer no when it only "
    "mentions the topic in passing, quotes it, or leaves the meaning unclear. Judge the text "
    "as written, without assuming facts that are not stated, and ignore its tone or length."
)


def synthetic_questions(count: int, tokens_each: int = 70) -> dict[str, NoulQuestion]:
    """``count`` distinct benign yes/no questions with both descriptions, each about
    ``tokens_each`` estimated tokens as sent (a fully described rule, R6.7). Deterministic."""
    out: dict[str, NoulQuestion] = {}
    for i in range(count):
        topic = _TOPICS[i % len(_TOPICS)]
        base = NoulQuestion(
            instructions=f"Does the text ask the reader to change {topic} (variant {i})?",
            criteria=NoulCriteria(
                true_description=f"The text asks for a change to {topic}.",
                false_description=f"The text does not ask for a change to {topic}.",
            ),
        )
        padding = max(0, tokens_each - estimate_question_tokens({f"s__q{i:03d}": base}))
        detail = (_DETAIL * (padding * 4 // len(_DETAIL) + 1))[: padding * 4]
        out[f"s__q{i:03d}"] = base.model_copy(
            update={"instructions": base.instructions + (" " + detail if detail else "")}
        )
    return out


@dataclass(frozen=True)
class Cell:
    """One shape of direct call: the input text size (raw estimated tokens), the question
    count and how many calls run at once."""

    name: str
    text_tokens: int
    questions: int
    concurrency: int = 1
    calls: int = MIN_CALLS_PER_CELL
    tokens_per_question: int = 70

    def question_set(self) -> dict[str, NoulQuestion]:
        return synthetic_questions(self.questions, self.tokens_per_question)

    def api_tokens(self) -> int:
        """Fitted API input tokens of one call (R6.6)."""
        return estimate_api_tokens(
            text_tokens=self.text_tokens,
            question_tokens=estimate_question_tokens(self.question_set()),
            question_count=self.questions,
        )


def latency_cells(calls: int = MIN_CALLS_PER_CELL) -> tuple[Cell, ...]:
    """The second-region profile: the floor-sized cell, sequential."""
    return (Cell("floor_4k_x12", 4_000, 12, 1, calls, 40),)


def largest_cells(calls: int = MIN_CALLS_PER_CELL, concurrency: int = 4) -> tuple[Cell, ...]:
    """The largest compilable calls (R6.7), each sequential and at the production in-flight
    limit (4 by default, R6.3: revisit if the dogfood trial settles another)."""
    cells: list[Cell] = []
    for name, questions in (("input_full_x200", 200), ("critical_full_x50", 50)):
        cells.append(Cell(f"{name}_seq", MAX_TEXT_TOKENS, questions, 1, calls))
        cells.append(Cell(f"{name}_c{concurrency}", MAX_TEXT_TOKENS, questions, concurrency, calls))
    return tuple(cells)


def cells_for(kind: str, calls: int = MIN_CALLS_PER_CELL) -> tuple[Cell, ...]:
    if kind == "latency":
        return latency_cells(calls)
    if kind == "largest":
        return largest_cells(calls)
    raise ValueError(f"{kind!r} has no direct cells")


# --------------------------------------------------------------------------- the plan


def capacity_config(minutes: float, turns_per_minute: float, seed: int = 309) -> LoadConfig:
    """The live capacity run's mix: one project (the shared pool), floor-only bundles, no pack,
    no tenant shares. Three turn shapes: chat, tool loop, and a document with a chunked
    ``tool_result``."""
    tenants = (
        TenantSpec("t_chatty", 5.0, "chat"),
        TenantSpec("t_agentic", 3.0, "tool_loop"),
        TenantSpec("t_docs", 1.0, "document"),
    )
    return LoadConfig(
        minutes=minutes, turns_per_minute=turns_per_minute, tenants=tenants,
        shapes=dict(DEFAULT_SHAPES), seed=seed, quotas=False,
    )  # fmt: skip


def cost_usd(tokens: float) -> float:
    return tokens / 1_000_000 * PRICE_PER_MILLION_INPUT_TOKENS_USD


def capacity_plan(
    *,
    requests_per_turn: float,
    tokens_per_turn: float,
    ceiling_turns_per_minute: float,
    steps: Sequence[float] = RAMP,
    minutes_per_step: float = RAMP_STEP_MINUTES,
) -> dict[str, Any]:
    """The capacity run's volume from what a turn costs: each step offers ``fraction x
    ceiling`` turns a minute for ``minutes_per_step``. Pure arithmetic."""
    rows = []
    for fraction in steps:
        rate = fraction * ceiling_turns_per_minute
        turns = rate * minutes_per_step
        rows.append(
            {
                "fraction": fraction, "turns_per_minute": rate, "minutes": minutes_per_step,
                "turns": turns, "calls": turns * requests_per_turn,
                "tokens": turns * tokens_per_turn,
                "tokens_per_minute": rate * tokens_per_turn,
            }
        )  # fmt: skip
    calls, tokens = sum(r["calls"] for r in rows), sum(r["tokens"] for r in rows)
    return {
        "steps": rows, "calls": calls, "tokens": tokens, "cost_usd": cost_usd(tokens),
        "minutes": minutes_per_step * len(rows),
        "worst_case_calls": calls * 1.25,  # about 4% of checks retry; a quarter in hand
        "worst_case_tokens": tokens * 1.25,
    }  # fmt: skip


def cell_plan(cell: Cell, pace_fraction: float = PACE_FRACTION) -> dict[str, Any]:
    """One direct cell's volume: its calls and warm-ups, tokens, cost and the time the pacing
    takes (tokens per call spread over ``pace_fraction`` of Tier 1's tokens per minute)."""
    per_call = cell.api_tokens()
    calls = cell.calls + WARMUP_CALLS
    interval_s = per_call * 60 / (pace_fraction * tier("Tier 1").tpm)
    return {
        "cell": cell.name, "text_tokens": cell.text_tokens, "questions": cell.questions,
        "concurrency": cell.concurrency, "calls": calls, "tokens_per_call": per_call,
        "tokens": calls * per_call, "cost_usd": cost_usd(calls * per_call),
        "interval_s": interval_s, "minutes": calls * interval_s / 60,
    }  # fmt: skip


def direct_plan(kind: str, calls: int = MIN_CALLS_PER_CELL) -> dict[str, Any]:
    rows = [cell_plan(c) for c in cells_for(kind, calls)]
    tokens = sum(r["tokens"] for r in rows)
    return {
        "cells": rows, "calls": sum(r["calls"] for r in rows), "tokens": tokens,
        "cost_usd": cost_usd(tokens), "minutes": sum(r["minutes"] for r in rows),
        "worst_case_calls": sum(r["calls"] for r in rows),  # direct calls are never retried
        "worst_case_tokens": tokens,
    }  # fmt: skip


@functools.cache
def _capacity_costs(seed: int = 309) -> tuple[float, float, float]:
    """(requests per turn, tokens per turn, the limiter's turns/min ceiling) of the capacity
    run's mix, from a 20-minute offline simulation of it at ``seed`` (cached: it takes
    seconds)."""
    report = summarise(
        simulate_offline(capacity_config(minutes=20, turns_per_minute=12, seed=seed))
    )
    pool = report["pools"]["shared"]
    return (
        pool["requests_per_turn"],
        pool["tokens_per_turn"],
        pool["limiter_ceiling_turns_per_minute"],
    )


def plan(
    kind: str | None = None,
    calls: int = MIN_CALLS_PER_CELL,
    step_minutes: float = RAMP_STEP_MINUTES,
    seed: int = 309,
) -> dict[str, Any]:
    """The live plan for ``kind`` (all three when None): provider calls, input tokens, cost at
    the paid-tier price and minutes of wall time. Makes no call: the capacity run's per-turn
    cost comes from an offline simulation of the same mix. Every flag that shapes a run is an
    argument here (``calls`` per direct cell, ``step_minutes`` and ``seed`` of the capacity
    ramp), and the runner takes its steps from this plan, so a live run's plan is exactly what
    it sends."""
    out: dict[str, Any] = {}
    for name in (kind,) if kind else KINDS:
        if name == "capacity":
            requests, tokens, ceiling = _capacity_costs(seed)
            out[name] = capacity_plan(
                requests_per_turn=requests,
                tokens_per_turn=tokens,
                ceiling_turns_per_minute=ceiling,
                minutes_per_step=step_minutes,
            )
            out[name]["basis"] = "an offline simulation of the same mix"
        else:
            out[name] = direct_plan(name, calls)
        out[name]["hard_max_calls"] = HARD_MAX_CALLS[name]
        out[name]["hard_max_tokens"] = HARD_MAX_TOKENS[name]
    return out


def plan_problems(kind: str, planned: Mapping[str, Any]) -> list[str]:
    """Why the plan itself is over a hard ceiling (the plan must fit under them with room)."""
    found = []
    if planned["worst_case_calls"] > HARD_MAX_CALLS[kind]:
        found.append(f"the plan needs up to {planned['worst_case_calls']:,.0f} calls")
    if planned["worst_case_tokens"] > HARD_MAX_TOKENS[kind]:
        found.append(f"the plan needs up to {planned['worst_case_tokens']:,.0f} tokens")
    return found


# --------------------------------------------------------------------------- the gates


def refuse_to_start(
    args: argparse.Namespace,
    planned: Mapping[str, Any],
    environ: Mapping[str, str] | None = None,
) -> None:
    """Raise :class:`Refused` unless the run may start. A dry run needs none of the gates (its
    ceilings, if given, still bind). A live run needs all of them, checked here before any
    model, client or key is created: the flag, the environment variable, the two explicit
    ceilings, each under its hard ceiling and over the plan's worst case, the plan itself
    inside the hard ceilings, and the key in the environment."""
    environ = os.environ if environ is None else environ
    kind = args.kind
    if kind not in KINDS:
        raise Refused(f"unknown kind {kind!r}: one of {', '.join(KINDS)}")
    if problems := plan_problems(kind, planned):
        raise Refused("; ".join(problems) + f", over the hard ceilings for {kind}")
    for flag, worst in (
        ("max_provider_calls", planned["worst_case_calls"]),
        ("max_tokens", planned["worst_case_tokens"]),
    ):
        value = getattr(args, flag, None)
        if value is not None and value < worst:
            raise Refused(
                f"--{flag.replace('_', '-')} {value:,} is under the plan's worst case "
                f"of {worst:,.0f}"
            )
    if not args.live:
        return
    if environ.get(LIVE_KEY) != LIVE_TOKEN:
        raise Refused(
            f"a live run needs the user's written approval, recorded in the environment as "
            f"{LIVE_KEY} (see docs/m3-09-load-test.md); the value is not printed here"
        )
    if args.max_provider_calls is None or args.max_tokens is None:
        raise Refused("a live run needs --max-provider-calls and --max-tokens")
    if args.max_provider_calls > HARD_MAX_CALLS[kind] or args.max_tokens > HARD_MAX_TOKENS[kind]:
        raise Refused(
            f"the ceilings are over the hard ceilings for {kind} "
            f"({HARD_MAX_CALLS[kind]:,} calls, {HARD_MAX_TOKENS[kind]:,} tokens)"
        )
    if not environ.get("GEMINI_API_KEY"):
        raise Refused("GEMINI_API_KEY is not set in the environment")
    if kind != "capacity" and args.calls < MIN_CALLS_PER_CELL:
        raise Refused(f"M3-09 asks for at least {MIN_CALLS_PER_CELL} calls per cell")
    for problem in content_problems(kind):
        raise Refused(problem)


def content_problems(kind: str) -> list[str]:
    """What stops the run's own text being sent: its questions or a sample of its content trip
    the tripwire, or the compiled floor carries the harm-facilitation rule."""
    from guardrail_engine.admin.vocabulary import strings_tripwire

    found = []
    if kind == "capacity":
        from calibration.run import StopRun, compile_floor, refuse_harm_facilitation

        doc = json.loads((ROOT / "floor" / "rules.json").read_text(encoding="utf-8"))
        questions, _ = compile_floor(doc)
        try:
            refuse_harm_facilitation(questions)
        except StopRun as e:
            found.append(str(e))
        texts = [
            json.dumps(q.model_dump(mode="json", exclude_none=True))
            for by_key in questions.values()
            for q in by_key.values()
        ]
    else:
        texts = [
            json.dumps(q.model_dump(mode="json", exclude_none=True))
            for cell in cells_for(kind)
            for q in cell.question_set().values()
        ]
    if strings_tripwire(*texts):
        found.append("the run's question text trips the harm-vocabulary tripwire")
    if strings_tripwire(benign_text(20_000, 1), benign_text(MAX_TEXT_TOKENS, 2)):
        found.append("the synthetic text trips the harm-vocabulary tripwire")
    return found


# --------------------------------------------------------------------------- the ledger


class Ledger:
    """Counts what a run has used against its ceilings, writes its records, and stops it by
    rule. One per run, shared by every cell and every concurrent task.

    **The stop is a state**: :attr:`stopped` holds the first reason, and
    :attr:`stop_event` is set with it so sleeping tasks and the load driver wake at once. Every
    send goes through :meth:`reserve`, which refuses once the run has stopped, so no call
    starts after a stop, anywhere in the run, whatever it was waiting on.

    **The ceilings count reservations**: :meth:`reserve` holds a call and its estimated
    tokens until :meth:`settle` swaps them for what the call used, so calls in flight count
    against the ceiling and it cannot be passed by the number in flight."""

    def __init__(self, out: Path | None, max_calls: int | None, max_tokens: int | None) -> None:
        self.out, self.max_calls, self.max_tokens = out, max_calls, max_tokens
        self.calls_used = 0
        self.tokens_used = 0
        self.reserved_calls = 0
        self.reserved_tokens = 0
        self.checks = 0
        self.stopped: str | None = None
        self.recent: deque[bool] = deque(maxlen=FAIL_WINDOW)
        self.records: list[dict[str, Any]] = []
        self._event: asyncio.Event | None = None
        self._event_loop: asyncio.AbstractEventLoop | None = None

    @property
    def stop_event(self) -> asyncio.Event:
        """Set when the run stops (already set if it has). Made on the running loop."""
        loop = asyncio.get_running_loop()
        if self._event is None or self._event_loop is not loop:
            self._event, self._event_loop = asyncio.Event(), loop
            if self.stopped is not None:
                self._event.set()
        return self._event

    def error(self) -> StopLive:
        return StopLive(f"stopped: {self.stopped} after {self.calls_used} calls")

    def check_running(self) -> None:
        """Raise if the run has stopped. Called immediately before anything is sent."""
        if self.stopped is not None:
            raise self.error()

    def stop_error(self) -> StopLive:
        """For ``load_test.drive``: the error to raise when ``stop_event`` wakes it."""
        return self.error()

    def reserve(self, calls: int, tokens: int) -> None:
        """Before sending: raise (nothing sent) if the run has stopped, or if what has been used
        and what is reserved by calls in flight, plus this call, would pass a ceiling. The
        reservation is held until :meth:`settle`."""
        self.check_running()
        if self.max_calls is not None and (
            self.calls_used + self.reserved_calls + calls > self.max_calls
        ):
            self.stop("provider_call_ceiling")
        if self.max_tokens is not None and (
            self.tokens_used + self.reserved_tokens + tokens > self.max_tokens
        ):
            self.stop("token_ceiling")
        self.reserved_calls += calls
        self.reserved_tokens += tokens

    def settle(self, reserved: tuple[int, int], calls: int, tokens: int) -> None:
        """A reserved send is over: release its reservation and count what it used."""
        self.reserved_calls -= reserved[0]
        self.reserved_tokens -= reserved[1]
        self.calls_used += calls
        self.tokens_used += tokens

    async def send(self, model: Any, text: str, questions: Mapping[str, Any], estimate: int) -> Any:
        """One provider call, the only way the runner sends one: reserve a call and ``estimate``
        tokens (raising if the run has stopped or a ceiling would be passed), call ``model``,
        and settle with the provider's reported tokens, else the estimate. A call that is
        cancelled in flight may have reached the provider, so it counts in full and is
        recorded."""
        self.reserve(1, estimate)  # nothing between this and the send can yield
        try:
            result = await model.decide(text, questions)
        except BaseException as e:
            self.settle((1, estimate), 1, estimate)
            if isinstance(e, asyncio.CancelledError):
                self.write({"type": "call_cancelled", "estimated_tokens": estimate})
            raise
        usage = getattr(result, "usage", None)
        reported = usage.total_input_tokens if isinstance(result, Answered) and usage else 0
        self.settle((1, estimate), 1, reported or estimate)
        return result

    def write(self, record: Mapping[str, Any]) -> None:
        row = dict(record)
        if self.stopped is not None and row.get("type") in ("check", "call", "call_cancelled"):
            row["after_stop"] = True  # it was in flight when the run stopped
        self.records.append(row)
        if self.out is not None:
            with self.out.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(row, sort_keys=True) + "\n")

    def stop(self, reason: str, **extra: Any) -> NoReturn:
        """Stop the run, now and for every task: the first reason is recorded and kept, the
        event wakes sleepers, and the error is raised in the caller. A second stop (a call that
        was in flight) records nothing more and raises the same error."""
        if self.stopped is None:
            self.stopped = reason
            self.write({"type": "run_stopped", "reason": reason, "calls": self.calls_used,
                        "tokens": self.tokens_used, **extra})  # fmt: skip
            if self._event is not None:
                self._event.set()
        raise self.error()

    def failed(self, was_failure: bool) -> None:
        self.recent.append(was_failure)
        if sum(self.recent) > FAIL_FRACTION * FAIL_WINDOW:
            self.stop("failures")


class GatedModel:
    """Every provider call of the capacity run goes through here, below the gateway: the gateway
    may retry or chunk a check into several calls, so the check-level hook can't see them. A call
    is reserved and counted by :meth:`Ledger.send`; once the run has stopped, or a ceiling would
    be passed, nothing is sent and the call comes back as a ``Failed(OTHER)``, which the gateway
    never retries. ``calls`` and ``aclose`` are the recording model's."""

    def __init__(self, recording: RecordingModel, ledger: Ledger) -> None:
        self.recording, self.ledger = recording, ledger
        self.model_id = recording.model_id

    @property
    def calls(self) -> Any:
        return self.recording.calls

    async def decide(self, input: str, questions: Mapping[str, Any]) -> Any:
        estimate = estimate_api_tokens(
            text_tokens=estimate_tokens(input),
            question_tokens=estimate_question_tokens(questions),
            question_count=len(questions),
        )
        try:
            result = await self.ledger.send(self.recording, input, questions, estimate)
        except StopLive:
            return Failed(kind=FailureKind.OTHER, message="the run has stopped: nothing was sent")
        # The stop is set here, where the refusal (or the auth failure) arrives, in the
        # same step that returns it, not later at the check level once the engine has made a
        # verdict of it: nothing the engine awaits between here and its verdict (an audit or
        # metrics write) can let another call start first. The result is still returned, so the
        # engine records the check as it would.
        reason = (
            "provider_refusal"
            if isinstance(result, SafetyBlocked)
            else "auth"
            if isinstance(result, Failed) and result.kind is FailureKind.AUTH
            else None
        )
        if reason is not None:
            # the stop is set; a second stop (a call in flight) records nothing more
            with contextlib.suppress(StopLive):
                self.ledger.stop(reason)
        return result

    async def aclose(self) -> None:
        await self.recording.aclose()


class CapacityObserver:
    """The capacity run's send-time and stop rules, for ``load_test.drive``'s observer hook:
    ``before`` re-runs the send checks (and refuses once the run has stopped); ``after`` records
    the check and stops the run at the first provider refusal. The calls themselves are reserved
    and counted by :class:`GatedModel`."""

    def __init__(self, ledger: Ledger) -> None:
        self.ledger = ledger

    @property
    def stop_event(self) -> asyncio.Event:
        return self.ledger.stop_event

    def stop_error(self) -> StopLive:
        return self.ledger.stop_error()

    def before(self, spec: Any, guard_point: str, content: str, conversation: Any) -> None:
        self.ledger.check_running()
        texts = [content] + [str(getattr(item, f, "")) for item in conversation
                             for f in ("text", "arguments", "result")]  # fmt: skip
        self.ledger.checks += 1
        if (why := send_refusal(f"loadtest-{self.ledger.checks}", texts)) is not None:
            self.ledger.stop("send_refusal", cause=why)

    def after(self, spec: Any, guard_point: str, verdict: Any, wall_s: float) -> None:
        calls = 1 if verdict.provider_calls is None else verdict.provider_calls
        usage = verdict.usage.total_input_tokens if verdict.usage else 0
        kind = verdict.failure_kind.value if verdict.failure_kind else None
        self.ledger.write({
            "type": "check", "guard_point": guard_point, "decision": verdict.decision.value,
            "reason": verdict.reason.value, "kind": kind,
            "failure_reason": verdict.failure_reason, "provider_calls": calls,
            "usage_input_tokens": usage, "wall_ms": round(wall_s * 1000, 2),
            "queue_wait_ms": verdict.queue_wait_ms, "chunks": verdict.chunks,
        })  # fmt: skip
        if verdict.reason.value == "provider_safety":
            self.ledger.stop("provider_refusal")
        if kind in ("auth", "other"):
            self.ledger.stop(kind)
        # The engine's own refusals (token_rate, admission) are the thing under test, not a
        # provider failure: they never count toward the failure rate.
        self.ledger.failed(kind is not None and not verdict.capacity_limited)


# --------------------------------------------------------------------------- direct cells


def cell_input(cell: Cell, number: int) -> str:
    """The input text of a cell's ``number``-th call: synthetic, distinct per call, sized in
    raw estimated tokens."""
    return benign_text(cell.text_tokens, number)


async def run_cell(
    model: Any,
    cell: Cell,
    ledger: Ledger,
    *,
    pace_s: float,
    warmups: int = WARMUP_CALLS,
) -> None:
    """Make ``cell.calls`` measured calls (after ``warmups`` discarded ones) on ``model``, at
    most ``cell.concurrency`` at once, one call started every ``pace_s`` seconds. Every call is
    reserved against the ceilings and sent only after the send-time checks, with nothing between
    them and the send that can yield. A stop (the first refusal, a ceiling, auth, the failure
    rate) starts no further call: the loop checks it after every wait for a slot and after the
    pacing sleep, which wakes on it, and a call that has not yet started raises instead of
    sending. Calls in flight at the stop finish, are recorded, and are not retried."""
    loop = asyncio.get_running_loop()
    questions = cell.question_set()
    per_call = cell.api_tokens()
    total = warmups + cell.calls
    slots = asyncio.Semaphore(cell.concurrency)
    stop = ledger.stop_event
    next_start = loop.time()
    started = 0

    async def one(number: int) -> None:
        text = cell_input(cell, number)
        ledger.check_running()
        if (why := send_refusal(f"{cell.name}-{number}", [text])) is not None:
            ledger.stop("send_refusal", cause=why)
        t0 = loop.time()
        result = await ledger.send(model, text, questions, per_call)
        wall = loop.time() - t0
        record: dict[str, Any] = {
            "type": "call", "cell": cell.name, "n": number, "warmup": number < warmups,
            "wall_ms": round(wall * 1000, 2), "questions": cell.questions,
            "text_tokens": cell.text_tokens, "concurrency": cell.concurrency,
        }  # fmt: skip
        if isinstance(result, Answered):
            record["outcome"] = "answered"
            record["usage_input_tokens"] = result.usage.total_input_tokens if result.usage else 0
        elif isinstance(result, SafetyBlocked):
            record["outcome"] = "provider_refusal"
        else:
            kind = result.kind.value if isinstance(result, Failed) else "other"
            record["outcome"], record["kind"] = "failed", kind
        ledger.write(record)
        if record["outcome"] == "provider_refusal":
            ledger.stop("provider_refusal")
        if record.get("kind") in ("auth", "other", FailureKind.RATE_LIMITED.value):
            ledger.stop(record["kind"])  # a 429 under the pacing is not expected: look first
        ledger.failed(record["outcome"] == "failed")

    async def guarded(number: int) -> None:
        try:
            await one(number)
        finally:
            slots.release()

    def failed_task() -> bool:
        return any(t.done() and not t.cancelled() and t.exception() for t in tasks)

    tasks: list[asyncio.Task[None]] = []
    try:
        while started < total:
            await slots.acquire()
            if ledger.stopped is not None or failed_task():
                slots.release()
                break
            await sleep_unless_stopped(next_start - loop.time(), stop)
            if ledger.stopped is not None or failed_task():  # after the pacing sleep too
                slots.release()
                break
            next_start = max(next_start, loop.time()) + pace_s
            tasks.append(asyncio.ensure_future(guarded(started)))
            started += 1
        results = await asyncio.gather(*tasks, return_exceptions=True)
    except BaseException:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        raise
    for result in results:
        if isinstance(result, BaseException):
            raise result
    ledger.check_running()


def summarise_cells(records: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Per cell: measured calls, outcomes, wall time percentiles, and the R6.3 expectation they
    are to confirm or re-fit (expected p50, attempt deadline), at the guard point's budget."""
    config = GatewayConfig()
    out = []
    names = list(dict.fromkeys(r["cell"] for r in records if r.get("type") == "call"))
    for name in names:
        calls = [r for r in records if r.get("type") == "call" and r["cell"] == name]
        measured = [r for r in calls if not r["warmup"]]
        answered = [r["wall_ms"] for r in measured if r["outcome"] == "answered"]
        first = measured[0] if measured else calls[0]
        parts = config.budget_parts(
            "output", input_tokens=first["text_tokens"], question_count=first["questions"]
        )
        deadline_ms = parts.attempt_deadline_s * 1000
        out.append({
            "cell": name, "concurrency": first["concurrency"], "measured": len(measured),
            "answered": len(answered), "failed": len(measured) - len(answered),
            "p50_ms": percentile(answered, 50), "p95_ms": percentile(answered, 95),
            "p99_ms": percentile(answered, 99), "max_ms": max(answered, default=None),
            "expected_p50_ms": parts.expected_p50_s * 1000,
            "attempt_deadline_ms": deadline_ms,
            "over_deadline": sum(w > deadline_ms for w in answered),
            "tokens_reported": sum(r.get("usage_input_tokens", 0) for r in measured),
        })  # fmt: skip
    return out


# --------------------------------------------------------------------------- running


def make_live_model(max_in_flight: int) -> Any:
    """The Gemini adapter, with the key from the environment. Only called once every gate has
    passed; the key is never shown."""
    from guardrail_engine.decision.adapters.gemini import GeminiConfig, GeminiDecisionModel

    config = GeminiConfig(api_key=os.environ["GEMINI_API_KEY"], paid_tier=True)
    return GeminiDecisionModel(config, max_in_flight=max_in_flight)


def dry_model(seed: int = 309) -> Any:
    """The offline model: the engine's fake after the modelled latency."""
    return ModelledLatencyModel(LatencyModel(), random.Random(seed))


async def run_direct(args: argparse.Namespace, ledger: Ledger) -> list[dict[str, Any]]:
    live = bool(args.live)
    for cell in cells_for(args.kind, args.calls):
        pace_s = cell_plan(cell)["interval_s"]
        model = make_live_model(max(cell.concurrency, 1)) if live else dry_model()
        try:
            await run_cell(model, cell, ledger, pace_s=0.0 if not live else pace_s)
        finally:
            closer = getattr(model, "aclose", None)
            if callable(closer):
                await closer()
    return summarise_cells(ledger.records)


async def run_capacity(
    args: argparse.Namespace, ledger: Ledger, planned: Mapping[str, Any]
) -> list[str]:
    """The ramp: each step one ``drive`` at its offered rate, with a fresh engine."""
    live = bool(args.live)
    reports: list[str] = []
    for step in planned["steps"]:
        # The plan's own steps: what is sent is what the gates were given.
        config = capacity_config(step["minutes"], step["turns_per_minute"], args.seed)
        recording = RecordingModel(make_live_model(4) if live else dry_model(args.seed), "shared")
        pool = GatedModel(recording, ledger)
        try:
            data = await drive(
                config, {"shared": pool}, observer=CapacityObserver(ledger), virtual=not live
            )
        finally:
            await pool.aclose()
        reports.append(render_markdown(summarise(data)))
    return reports


def run(args: argparse.Namespace) -> int:
    planned = plan(args.kind, args.calls, args.step_minutes, args.seed)[args.kind]
    refuse_to_start(args, planned)
    out = Path(args.out) if args.out else None
    if out is not None:
        out.parent.mkdir(parents=True, exist_ok=True)
    ledger = Ledger(out, args.max_provider_calls, args.max_tokens)
    ledger.write({
        "type": "run_started", "kind": args.kind, "mode": "live" if args.live else "dry-run",
        "estimated_calls": planned["calls"], "estimated_tokens": planned["tokens"],
        "max_provider_calls": args.max_provider_calls, "max_tokens": args.max_tokens,
    })  # fmt: skip
    main = (
        run_capacity(args, ledger, planned) if args.kind == "capacity" else run_direct(args, ledger)
    )
    runner = asyncio.run if args.live else run_virtual
    try:
        result = runner(main)
    except StopLive as e:
        print(str(e), file=sys.stderr)
        return 3
    ledger.write({"type": "run_finished", "calls": ledger.calls_used,
                  "tokens": ledger.tokens_used})  # fmt: skip
    if args.kind == "capacity":
        print("\n".join(result))
    else:
        print(json.dumps(result, indent=1))
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("plan", help="call volume and cost of each live run (makes no call)")
    p.add_argument("--kind", choices=KINDS, default=None)
    p.add_argument("--calls", type=int, default=MIN_CALLS_PER_CELL)
    p.add_argument("--seed", type=int, default=309)
    p.add_argument("--step-minutes", type=float, default=RAMP_STEP_MINUTES)
    r = sub.add_parser("run", help="a dry run by default; --live needs every gate")
    r.add_argument("--kind", required=True, choices=KINDS)
    r.add_argument("--out", default=None)
    r.add_argument("--calls", type=int, default=MIN_CALLS_PER_CELL, help="measured calls per cell")
    r.add_argument("--seed", type=int, default=309)
    r.add_argument("--step-minutes", type=float, default=RAMP_STEP_MINUTES)
    r.add_argument("--max-provider-calls", type=int, default=None)
    r.add_argument("--max-tokens", type=int, default=None)
    r.add_argument("--live", action="store_true",
                   help=f"send to the provider (also needs {LIVE_KEY} in the environment, with the "
                        "user's written approval)")  # fmt: skip
    args = parser.parse_args(argv)
    try:
        if args.command == "plan":
            print(json.dumps(plan(args.kind, args.calls, args.step_minutes, args.seed), indent=1))
            return 0
        return run(args)
    except Refused as e:
        print(str(e), file=sys.stderr)
        return 2
    except StopLive as e:
        print(str(e), file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
