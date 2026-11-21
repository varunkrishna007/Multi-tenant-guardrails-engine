"""M3-09 live mode (capacity/load_live.py), offline: the plan's arithmetic, the gates, the
send-time checks and the stop rules, with the engine's fake model. Nothing is sent to a provider
and no key is read."""

from __future__ import annotations

import argparse
import asyncio
import json
import socket
from types import SimpleNamespace

import pytest
from capacity.load_live import (
    HARD_MAX_CALLS,
    HARD_MAX_TOKENS,
    LIVE_KEY,
    LIVE_TOKEN,
    MAX_TEXT_TOKENS,
    MIN_CALLS_PER_CELL,
    Cell,
    Ledger,
    Refused,
    StopLive,
    capacity_plan,
    cell_plan,
    cost_usd,
    direct_plan,
    largest_cells,
    latency_cells,
    refuse_to_start,
    run_cell,
    send_refusal,
    summarise_cells,
    synthetic_questions,
)
from capacity.load_test import run_virtual

from capacity import load_live
from guardrail_engine.decision.limits import estimate_question_tokens
from guardrail_engine.decision.port import Answered, Failed, FailureKind, SafetyBlocked
from guardrail_engine.decision.types import Usage


@pytest.fixture(autouse=True)
def no_provider_call(monkeypatch):
    """Nothing may reach a socket, and the real adapter is never built."""

    def refuse(*args, **kwargs):
        raise AssertionError("a provider call was attempted in an offline test")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket.socket, "connect_ex", refuse)
    monkeypatch.setattr(load_live, "make_live_model", refuse)
    from guardrail_engine.decision.adapters.gemini import GeminiDecisionModel

    monkeypatch.setattr(GeminiDecisionModel, "__init__", refuse)


def args_for(kind="latency", **kwargs) -> argparse.Namespace:
    values = {
        "kind": kind, "live": False, "max_provider_calls": None, "max_tokens": None,
        "calls": MIN_CALLS_PER_CELL, "out": None, "seed": 309, "step_minutes": 8.0,
    }  # fmt: skip
    return argparse.Namespace(**{**values, **kwargs})


ENV_OK = {LIVE_KEY: LIVE_TOKEN, "GEMINI_API_KEY": "a-sentinel-not-a-key"}


def planned_for(kind, step_minutes=load_live.RAMP_STEP_MINUTES):
    if kind == "capacity":
        return capacity_plan(
            requests_per_turn=6, tokens_per_turn=20_000, ceiling_turns_per_minute=34,
            minutes_per_step=step_minutes,
        )  # fmt: skip
    return direct_plan(kind)


def live_args(kind="latency", **kwargs):
    planned = planned_for(kind)
    return args_for(
        kind, live=True,
        max_provider_calls=int(planned["worst_case_calls"]) + 10,
        max_tokens=int(planned["worst_case_tokens"]) + 1_000,
        **kwargs,
    )  # fmt: skip


# ------------------------------------------------------------------ the plan


def test_every_cell_has_at_least_500_measured_calls():
    cells = latency_cells() + largest_cells()
    assert {c.name for c in latency_cells()} == {"floor_4k_x12"}
    assert len(largest_cells()) == 4  # two shapes, sequential and concurrent
    assert all(c.calls >= MIN_CALLS_PER_CELL for c in cells)
    assert {c.concurrency for c in largest_cells()} == {1, 4}


def test_the_largest_calls_are_the_r67_bounds():
    full_input = next(c for c in largest_cells() if c.name.startswith("input_full"))
    critical = next(c for c in largest_cells() if c.name.startswith("critical_full"))
    assert (full_input.questions, critical.questions) == (200, 50)
    assert 1.2 * MAX_TEXT_TOKENS + 30 <= 16_000 < 1.2 * (MAX_TEXT_TOKENS + 1) + 30
    assert full_input.text_tokens == critical.text_tokens == MAX_TEXT_TOKENS


def test_a_cells_cost_is_calls_times_tokens_at_the_paid_price():
    cell = latency_cells()[0]
    row = cell_plan(cell)
    assert row["calls"] == cell.calls + load_live.WARMUP_CALLS
    assert row["tokens"] == row["calls"] * row["tokens_per_call"]
    assert row["cost_usd"] == pytest.approx(row["tokens"] / 1e6 * 0.10)
    assert cost_usd(1_000_000) == pytest.approx(0.10)
    # the call's size is the fitted API estimate of its text and its questions (R6.6)
    questions = cell.question_set()
    assert row["tokens_per_call"] == (
        -(-120 * cell.text_tokens // 100) + 30
        + estimate_question_tokens(questions) + 25 * len(questions)
    )  # fmt: skip


def test_the_pacing_keeps_a_cell_under_half_the_tokens_per_minute():
    for cell in latency_cells() + largest_cells():
        row = cell_plan(cell)
        per_minute = row["tokens_per_call"] * 60 / row["interval_s"]
        assert per_minute == pytest.approx(0.5 * 1_000_000)


def test_the_capacity_ramp_is_fractions_of_the_limiter_ceiling():
    plan = capacity_plan(requests_per_turn=6, tokens_per_turn=20_000, ceiling_turns_per_minute=34)
    assert [s["fraction"] for s in plan["steps"]] == [0.25, 0.5, 0.75, 1.0]
    top = plan["steps"][-1]
    assert top["turns_per_minute"] == 34
    assert top["tokens_per_minute"] == 34 * 20_000  # 680,000: the limiter's 68% of 1,000,000
    assert plan["calls"] == pytest.approx(sum(s["turns"] for s in plan["steps"]) * 6)
    assert plan["tokens"] == pytest.approx(plan["calls"] / 6 * 20_000)
    assert plan["cost_usd"] == pytest.approx(plan["tokens"] / 1e6 * 0.10)
    assert plan["minutes"] == 4 * load_live.RAMP_STEP_MINUTES


def test_the_three_plans_fit_under_their_hard_ceilings():
    for kind in ("latency", "largest"):
        planned = direct_plan(kind)
        assert planned["worst_case_calls"] < HARD_MAX_CALLS[kind]
        assert planned["worst_case_tokens"] < HARD_MAX_TOKENS[kind]
        assert load_live.plan_problems(kind, planned) == []
    assert load_live.plan_problems("capacity", planned_for("capacity")) == []


def test_the_plan_makes_no_call_and_names_all_three_runs():
    planned = load_live.plan()
    assert set(planned) == {"capacity", "latency", "largest"}
    for kind, row in planned.items():
        assert row["calls"] > 0 and row["cost_usd"] > 0
        assert row["hard_max_calls"] == HARD_MAX_CALLS[kind]


# ------------------------------------------------------------------ the gates


@pytest.mark.parametrize("kind", ["capacity", "latency", "largest"])
def test_a_dry_run_needs_no_gate(kind):
    refuse_to_start(args_for(kind), planned_for(kind), environ={})


@pytest.mark.parametrize("kind", ["capacity", "latency", "largest"])
def test_a_live_run_with_every_gate_may_start(kind):
    refuse_to_start(live_args(kind), planned_for(kind), environ=ENV_OK)


def test_a_live_run_without_the_flag_is_a_dry_run():
    args = live_args()
    args.live = False
    refuse_to_start(args, planned_for("latency"), environ={})  # nothing live is asked for


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"env": {"GEMINI_API_KEY": "x"}}, LIVE_KEY),
        ({"env": {LIVE_KEY: "yes", "GEMINI_API_KEY": "x"}}, LIVE_KEY),
        ({"env": {LIVE_KEY: LIVE_TOKEN}}, "GEMINI_API_KEY"),
        ({"max_provider_calls": None}, "--max-provider-calls and --max-tokens"),
        ({"max_tokens": None}, "--max-provider-calls and --max-tokens"),
        ({"max_provider_calls": HARD_MAX_CALLS["latency"] + 1}, "hard ceilings"),
        ({"max_tokens": HARD_MAX_TOKENS["latency"] + 1}, "hard ceilings"),
        ({"max_provider_calls": 100}, "under the plan's worst case"),
        ({"max_tokens": 1_000}, "under the plan's worst case"),
        ({"calls": 100}, "at least 500"),
    ],
)
def test_a_live_run_is_refused_without_every_gate(change, message):
    env = change.pop("env", ENV_OK)
    args = live_args()
    for name, value in change.items():
        setattr(args, name, value)
    with pytest.raises(Refused, match=message):
        refuse_to_start(args, planned_for("latency"), environ=env)


def test_a_dry_run_still_honours_ceilings_that_are_given():
    args = args_for("latency", max_provider_calls=10, max_tokens=10)
    with pytest.raises(Refused, match="worst case"):
        refuse_to_start(args, planned_for("latency"), environ={})


def test_an_unknown_kind_and_an_oversized_plan_are_refused():
    with pytest.raises(Refused, match="unknown kind"):
        refuse_to_start(args_for("everything"), planned_for("latency"), environ={})
    big = capacity_plan(requests_per_turn=60, tokens_per_turn=200_000, ceiling_turns_per_minute=34)
    with pytest.raises(Refused, match="hard ceilings"):
        refuse_to_start(args_for("capacity"), big, environ={})


def test_main_refuses_a_live_run_before_any_model_exists(capsys, tmp_path):
    """No key, no token: the command stops with exit 2 and the adapter is never built (the
    autouse guard would raise if it were)."""
    out = tmp_path / "run.jsonl"
    code = load_live.main(["run", "--kind", "latency", "--live", "--out", str(out)])
    assert code == 2
    assert not out.exists()
    assert LIVE_KEY in capsys.readouterr().err


def test_main_refuses_a_live_run_with_only_some_gates(monkeypatch, capsys):
    monkeypatch.setenv(LIVE_KEY, LIVE_TOKEN)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    argv = ["run", "--kind", "latency", "--live", "--max-provider-calls", "700"]
    assert load_live.main([*argv, "--max-tokens", "7000000"]) == 2
    assert "GEMINI_API_KEY" in capsys.readouterr().err
    assert load_live.main(argv) == 2
    assert "--max-tokens" in capsys.readouterr().err


# ------------------------------------------------------------------ what may be sent


def test_the_synthetic_content_and_questions_pass_the_send_checks():
    for cell in latency_cells() + largest_cells():
        texts = [json.dumps(q.model_dump(mode="json")) for q in cell.question_set().values()]
        assert send_refusal(cell.name, texts) is None
        assert send_refusal(cell.name, [load_live.cell_input(cell, 3)]) is None
    assert load_live.content_problems("latency") == []
    assert load_live.content_problems("largest") == []
    assert load_live.content_problems("capacity") == []


def test_a_harm_labelled_id_or_a_harm_word_is_refused_before_sending():
    assert send_refusal("row-harm-1", ["fine text"]) == "harm near-miss row"
    assert send_refusal("loadtest-1", ["a word on the list: child cover"]) == (
        "harm-vocabulary tripwire"
    )


def test_synthetic_questions_are_distinct_described_and_sized():
    questions = synthetic_questions(200, 70)
    assert len(questions) == 200 and len({q.instructions for q in questions.values()}) == 200
    assert all(q.criteria is not None for q in questions.values())
    each = estimate_question_tokens(questions) / 200
    assert 60 <= each <= 80  # a fully described rule, about 70 tokens


# ------------------------------------------------------------------ the dry run, and the stops


def small_cell(**kwargs) -> Cell:
    return Cell("cell", **{"text_tokens": 500, "questions": 3, "calls": 12, **kwargs})


def test_a_dry_run_of_a_cell_records_calls_and_summarises_them():
    ledger = Ledger(None, 100, 10_000_000)
    run_virtual(run_cell(load_live.dry_model(), small_cell(), ledger, pace_s=0.0))
    calls = [r for r in ledger.records if r["type"] == "call"]
    assert len(calls) == 12 + load_live.WARMUP_CALLS
    assert sum(r["warmup"] for r in calls) == load_live.WARMUP_CALLS
    (row,) = summarise_cells(ledger.records)
    assert row["measured"] == 12 and row["failed"] == 0
    assert row["p50_ms"] is not None and row["expected_p50_ms"] > 0
    assert all("content" not in r and "input" not in r for r in ledger.records)


def test_a_concurrent_cell_never_runs_more_than_its_concurrency():
    class Spy:
        active = peak = 0

        def __init__(self):
            self.inner = load_live.dry_model()

        async def decide(self, text, questions):
            Spy.active += 1
            Spy.peak = max(Spy.peak, Spy.active)
            try:
                return await self.inner.decide(text, questions)
            finally:
                Spy.active -= 1

    ledger = Ledger(None, None, None)
    run_virtual(run_cell(Spy(), small_cell(concurrency=3, calls=20), ledger, pace_s=0.0))
    assert Spy.peak == 3


class Scripted:
    """A model that answers like the dry one, but the n-th call (1-based) returns ``outcome``."""

    def __init__(self, at, outcome):
        self.inner = load_live.dry_model()
        self.at, self.outcome, self.sent = at, outcome, 0

    async def decide(self, text, questions):
        self.sent += 1
        if self.sent == self.at:
            return self.outcome
        return await self.inner.decide(text, questions)


@pytest.mark.parametrize(
    "outcome",
    [
        SafetyBlocked(message=None, reason="safety"),
        Failed(kind=FailureKind.AUTH),
        Failed(kind=FailureKind.OTHER),
        Failed(kind=FailureKind.RATE_LIMITED),
    ],
)
def test_the_first_refusal_stops_the_run_and_nothing_is_resent(outcome):
    ledger = Ledger(None, None, None)
    model = Scripted(at=4, outcome=outcome)
    with pytest.raises(StopLive):
        run_virtual(run_cell(model, small_cell(calls=30), ledger, pace_s=0.0))
    assert model.sent == 4  # the call that was refused is the last one sent
    assert ledger.records[-1]["type"] == "run_stopped"


def test_a_timeout_is_not_a_refusal_but_a_failure_rate_over_20_percent_stops_the_run():
    ledger = Ledger(None, None, None)
    run_virtual(
        run_cell(Scripted(3, Failed(kind=FailureKind.TIMEOUT)), small_cell(), ledger, pace_s=0.0)
    )
    assert [r["outcome"] for r in ledger.records if r["type"] == "call"].count("failed") == 1

    class Down:
        async def decide(self, text, questions):
            return Failed(kind=FailureKind.UNAVAILABLE)

    with pytest.raises(StopLive):
        run_virtual(run_cell(Down(), small_cell(calls=100), Ledger(None, None, None), pace_s=0.0))


def test_the_ceilings_stop_the_run_before_the_call_that_would_pass_them():
    model = Scripted(at=0, outcome=None)
    ledger = Ledger(None, max_calls=6, max_tokens=None)
    with pytest.raises(StopLive, match="provider_call_ceiling"):
        run_virtual(run_cell(model, small_cell(calls=50), ledger, pace_s=0.0))
    assert model.sent == 6 and ledger.calls_used == 6
    ledger = Ledger(None, max_calls=None, max_tokens=small_cell().api_tokens() * 3)
    with pytest.raises(StopLive, match="token_ceiling"):
        run_virtual(run_cell(Scripted(0, None), small_cell(calls=50), ledger, pace_s=0.0))
    assert ledger.tokens_used <= small_cell().api_tokens() * 3


def test_a_run_writes_ids_and_numbers_never_content(tmp_path):
    out = tmp_path / "r.jsonl"
    ledger = Ledger(out, None, None)
    run_virtual(run_cell(load_live.dry_model(), small_cell(calls=3), ledger, pace_s=0.0))
    text = out.read_text()
    assert "quarterly" not in text and "Does the text" not in text
    assert all(json.loads(line)["type"] == "call" for line in text.splitlines())


def test_the_capacity_dry_run_goes_through_the_engine_and_stops_on_a_refusal(tmp_path, capsys):
    """The same ``drive`` the offline report uses, with the capacity observer on it: a short
    ramp makes checks, and a scripted provider refusal stops the whole run."""
    out = tmp_path / "cap.jsonl"
    code = load_live.main(["run", "--kind", "capacity", "--step-minutes", "0.5", "--out", str(out)])
    assert code == 0
    records = [json.loads(x) for x in out.read_text().splitlines()]
    assert records[0]["type"] == "run_started" and records[0]["mode"] == "dry-run"
    assert records[-1]["type"] == "run_finished" and records[-1]["calls"] > 0
    assert any(r["type"] == "check" for r in records)
    assert "Binding PF-4 limit" in capsys.readouterr().out


def test_the_capacity_observer_stops_the_engine_run_at_a_provider_refusal(monkeypatch):
    from capacity.load_test import ModelledLatencyModel

    async def refuse(self, text, questions):
        return SafetyBlocked(message=None, reason="safety")

    monkeypatch.setattr(ModelledLatencyModel, "decide", refuse)
    ledger = Ledger(None, None, None)
    args = args_for("capacity", step_minutes=0.5)
    with pytest.raises(StopLive, match="provider_refusal"):
        run_virtual(load_live.run_capacity(args, ledger, planned_for("capacity")))
    assert ledger.records[-1]["reason"] == "provider_refusal"


# ------------------------------------------------------------------ a stop is a state


class Provider:
    """A fake provider that answers like the dry model after ``latency`` seconds, but makes
    the ``n``-th call it is sent (1-based) come back as ``outcome_at[n]``. It records, for every
    call, whether the run had already stopped when the call *started*: that must never be so.
    Calls that finish after the stop come back as a retryable failure, to show nothing retries
    them."""

    def __init__(self, ledger, *, latency=1.0, outcome_at=None, tokens=None, inner=None):
        self.inner = inner or load_live.dry_model()
        self.ledger, self.latency, self.outcome_at = ledger, latency, outcome_at or {}
        self.tokens = tokens
        self.sent = 0
        self.events: list[tuple[str, int]] = []
        self.started_after_stop: list[int] = []

    async def decide(self, text, questions):
        self.sent += 1
        n = self.sent
        if self.ledger.stopped is not None:
            self.started_after_stop.append(n)
        self.events.append(("start", n))
        await asyncio.sleep(self.latency)
        if n in self.outcome_at:
            self.events.append(("outcome", n))
            return self.outcome_at[n]
        if self.ledger.stopped is not None:
            self.events.append(("late", n))
            return Failed(kind=FailureKind.UNAVAILABLE)  # the gateway would retry this
        result = await self.inner.decide(text, questions)
        if self.tokens is not None and isinstance(result, Answered):
            result = result.model_copy(update={"usage": Usage(total_input_tokens=self.tokens)})
        self.events.append(("done", n))
        return result

    def starts_after(self, kind: str, n: int) -> list[int]:
        """Calls that started after the ``kind`` event of call ``n``, itself included."""
        at = self.events.index((kind, n))
        return [m for k, m in self.events[at:] if k == "start"]

    def late(self) -> set[int]:
        return {m for k, m in self.events if k == "late"}


REFUSAL = SafetyBlocked(message=None, reason="safety")


@pytest.mark.parametrize(("pace", "refused_call"), [(0.7, 3), (0.9, 5), (0.0, 6), (2.0, 4)])
def test_a_refusal_in_a_concurrent_paced_cell_starts_no_call_after_it(pace, refused_call):
    """The probes: a c4 cell, 1 s latency, pace 0.7 / 0.9. Before the fix one more call
    started after the refusal returned; now none does, and the calls in flight finish and are
    recorded, not resent."""
    ledger = Ledger(None, None, None)
    provider = Provider(ledger, latency=1.0, outcome_at={refused_call: REFUSAL})
    cell = small_cell(concurrency=4, calls=40)
    with pytest.raises(StopLive, match="provider_refusal"):
        run_virtual(run_cell(provider, cell, ledger, pace_s=pace))
    assert provider.started_after_stop == []
    assert provider.starts_after("outcome", refused_call) == []
    assert ledger.stopped == "provider_refusal"
    # one run_stopped record, and every call that was in flight is recorded, flagged after_stop
    assert [r["type"] for r in ledger.records].count("run_stopped") == 1
    calls = [r for r in ledger.records if r["type"] == "call"]
    assert len(calls) == provider.sent  # nothing sent went unrecorded
    flagged = {r["n"] + 1 for r in calls if r.get("after_stop")}
    # in flight at the refusal: all started by then, and those that answered after it did so as
    # failures that nothing retried
    before = provider.events[: provider.events.index(("outcome", refused_call))]
    assert provider.late() <= flagged <= {m for k, m in before if k == "start"}
    assert refused_call not in flagged
    assert all(r["outcome"] == "failed" for r in calls if r["n"] + 1 in provider.late())
    assert ledger.reserved_calls == 0


@pytest.mark.parametrize(
    ("outcome", "reason"),
    [
        (REFUSAL, "provider_refusal"),
        (Failed(kind=FailureKind.AUTH), "auth"),
        (Failed(kind=FailureKind.OTHER), "other"),
        (Failed(kind=FailureKind.RATE_LIMITED), "rate_limited"),
    ],
)
@pytest.mark.parametrize("concurrency", [1, 4])
def test_every_stop_reason_starts_no_call_after_it_in_a_cell(outcome, reason, concurrency):
    ledger = Ledger(None, None, None)
    provider = Provider(ledger, latency=1.0, outcome_at={7: outcome})
    cell = small_cell(concurrency=concurrency, calls=40)
    with pytest.raises(StopLive, match=reason):
        run_virtual(run_cell(provider, cell, ledger, pace_s=0.3))
    assert provider.started_after_stop == []
    assert provider.starts_after("outcome", 7) == []
    assert ledger.stopped == reason


def test_the_failure_rate_and_the_ceilings_start_no_call_after_them_in_a_cell():
    ledger = Ledger(None, None, None)
    down = {n: Failed(kind=FailureKind.UNAVAILABLE) for n in range(1, 200)}
    provider = Provider(ledger, latency=1.0, outcome_at=down)
    with pytest.raises(StopLive, match="failures"):
        run_virtual(run_cell(provider, small_cell(concurrency=4, calls=100), ledger, pace_s=0.3))
    assert provider.started_after_stop == [] and ledger.stopped == "failures"
    for ceiling in ({"max_calls": 9}, {"max_tokens": small_cell().api_tokens() * 9}):
        ledger = Ledger(None, ceiling.get("max_calls"), ceiling.get("max_tokens"))
        provider = Provider(ledger, latency=1.0, tokens=small_cell().api_tokens())
        with pytest.raises(StopLive, match="ceiling"):
            run_virtual(run_cell(provider, small_cell(concurrency=4, calls=40), ledger, pace_s=0.3))
        assert provider.started_after_stop == [] and provider.sent <= 9


def test_a_stop_wakes_a_cell_sleeping_on_its_pacing():
    """The pacing sleep wakes on the stop: the run ends at the refusal, not a pace later."""
    ledger = Ledger(None, None, None)
    provider = Provider(ledger, latency=0.1, outcome_at={2: REFUSAL})

    async def timed():
        loop = asyncio.get_running_loop()
        t0 = loop.time()
        with pytest.raises(StopLive):
            await run_cell(provider, small_cell(concurrency=4, calls=40), ledger, pace_s=500.0)
        return loop.time() - t0

    # call 2 is sent at 500 s and refused at 500.1 s; the next send would be at 1,000 s
    assert run_virtual(timed()) < 501
    assert provider.sent == 2


def patch_capacity_provider(monkeypatch, ledger, outcome_at=None):
    """Make the capacity run's provider a :class:`Provider` (the modelled latency and the fake's
    answers inside it); returns it."""
    from capacity.load_test import ModelledLatencyModel

    modelled, real = load_live.dry_model(), ModelledLatencyModel.decide
    inner = SimpleNamespace(decide=lambda text, questions: real(modelled, text, questions))
    provider = Provider(ledger, latency=0.0, outcome_at=outcome_at, inner=inner)

    async def decide(self, text, questions):
        return await provider.decide(text, questions)

    monkeypatch.setattr(ModelledLatencyModel, "decide", decide)
    return provider


def run_capacity_with(monkeypatch, *, outcome_at=None, max_calls=None, max_tokens=None):
    ledger = Ledger(None, max_calls, max_tokens)
    provider = patch_capacity_provider(monkeypatch, ledger, outcome_at)
    args = args_for("capacity", step_minutes=0.5)
    with pytest.raises(StopLive) as stop:
        run_virtual(load_live.run_capacity(args, ledger, planned_for("capacity", 0.5)))
    return provider, ledger, stop.value


def test_a_refusal_on_call_40_in_the_capacity_run_starts_no_further_call(monkeypatch):
    """The probe: before the fix 4 calls started after the refusal returned (turns in
    flight kept going through their steps). Now none does, and nothing is retried."""
    provider, ledger, error = run_capacity_with(monkeypatch, outcome_at={40: REFUSAL})
    assert "provider_refusal" in str(error)
    assert provider.started_after_stop == []
    assert provider.starts_after("outcome", 40) == []
    assert provider.sent >= 40
    assert [r["type"] for r in ledger.records].count("run_stopped") == 1
    assert ledger.reserved_calls == 0 and ledger.reserved_tokens == 0


@pytest.mark.parametrize(
    ("outcome", "reason"),
    [
        (Failed(kind=FailureKind.AUTH), "auth"),
        (Failed(kind=FailureKind.OTHER), "other"),
    ],
)
def test_other_stop_reasons_in_the_capacity_run_start_no_further_call(monkeypatch, outcome, reason):
    provider, _ledger, error = run_capacity_with(monkeypatch, outcome_at={25: outcome})
    assert reason in str(error)
    assert provider.started_after_stop == []
    assert provider.starts_after("outcome", 25) == []


def test_the_capacity_run_ends_at_the_stop_not_at_the_next_arrival(monkeypatch):
    """The driver wakes on the stop and cancels the turns in flight: the clock does not move on
    to the next Poisson arrival, nor to the end of any turn."""
    ledger = Ledger(None, None, None)
    patch_capacity_provider(monkeypatch, ledger, {20: REFUSAL})
    seen = {}

    async def go():
        loop = asyncio.get_running_loop()
        t0 = loop.time()
        args = args_for("capacity", step_minutes=0.5)
        try:
            await load_live.run_capacity(args, ledger, planned_for("capacity", 0.5))
        except StopLive:
            seen["end"] = loop.time() - t0
        seen["refused"] = ledger.stop_event.is_set()

    run_virtual(go())
    assert seen["refused"] and seen["end"] < 30  # the first ramp step alone is 30 s
    stopped_at = next(r for r in ledger.records if r["type"] == "run_stopped")
    assert stopped_at["reason"] == "provider_refusal"
    after = ledger.records[ledger.records.index(stopped_at) + 1 :]
    assert all(r.get("after_stop") for r in after)  # whatever was written later was in flight


# ------------------------------------------------------------------ reservations


def test_a_c4_cell_with_a_call_ceiling_of_10_sends_exactly_10():
    """The probe: ceiling 10, c4, paced: 12 were sent. Now the in-flight calls hold
    their reservation, so the 11th is refused before it starts."""
    ledger = Ledger(None, 10, None)
    provider = Provider(ledger, latency=1.0)
    with pytest.raises(StopLive, match="provider_call_ceiling"):
        run_virtual(run_cell(provider, small_cell(concurrency=4, calls=40), ledger, pace_s=0.3))
    assert provider.sent == 10 and ledger.calls_used == 10
    assert ledger.reserved_calls == 0 and ledger.reserved_tokens == 0


def test_a_c4_cell_with_a_token_ceiling_never_sends_past_it():
    cell = small_cell(concurrency=4, calls=40)
    each = cell.api_tokens()
    ledger = Ledger(None, None, each * 10 + each // 2)
    provider = Provider(ledger, latency=1.0, tokens=each)
    with pytest.raises(StopLive, match="token_ceiling"):
        run_virtual(run_cell(provider, cell, ledger, pace_s=0.3))
    assert provider.sent == 10
    assert ledger.tokens_used == each * 10 <= ledger.max_tokens


def test_the_capacity_run_with_a_call_ceiling_of_30_sends_exactly_30(monkeypatch):
    """The probe: ceiling 30, capacity: 31 were sent (a chunked tool_result is a call
    per chunk, and a check may retry). Every provider call is reserved, so none passes it."""
    provider, ledger, error = run_capacity_with(monkeypatch, max_calls=30)
    assert "provider_call_ceiling" in str(error)
    assert provider.sent == 30 and ledger.calls_used == 30
    assert provider.started_after_stop == []
    assert ledger.reserved_calls == 0 and ledger.reserved_tokens == 0


def test_the_capacity_run_with_a_token_ceiling_never_passes_it(monkeypatch):
    provider, ledger, error = run_capacity_with(monkeypatch, max_tokens=120_000)
    assert "token_ceiling" in str(error)
    assert 0 < ledger.tokens_used <= 120_000
    assert provider.started_after_stop == []
    assert ledger.reserved_tokens == 0


def test_the_reservation_is_held_until_the_call_settles():
    ledger = Ledger(None, 2, 1_000)
    ledger.reserve(1, 400)
    ledger.reserve(1, 400)
    assert (ledger.reserved_calls, ledger.reserved_tokens, ledger.calls_used) == (2, 800, 0)
    with pytest.raises(StopLive, match="provider_call_ceiling"):
        ledger.reserve(1, 1)  # two in flight already fill the ceiling
    ledger = Ledger(None, 5, 1_000)
    ledger.reserve(1, 600)
    with pytest.raises(StopLive, match="token_ceiling"):
        ledger.reserve(1, 600)
    ledger = Ledger(None, 5, 1_000)
    ledger.reserve(1, 600)
    ledger.settle((1, 600), 1, 300)  # the call used less: the difference is free again
    ledger.reserve(1, 600)
    assert (ledger.calls_used, ledger.tokens_used, ledger.reserved_tokens) == (1, 300, 600)


def test_a_cancelled_call_counts_in_full_and_is_recorded():
    ledger = Ledger(None, None, None)

    class Hang:
        async def decide(self, text, questions):
            await asyncio.sleep(1_000)

    async def go():
        task = asyncio.ensure_future(ledger.send(Hang(), "t", {}, 77))
        await asyncio.sleep(1)
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)

    run_virtual(go())
    assert (ledger.calls_used, ledger.tokens_used) == (1, 77)
    assert ledger.reserved_calls == 0 and ledger.reserved_tokens == 0
    assert ledger.records[-1]["type"] == "call_cancelled"


# ------------------------------------------------------------------ the plan is the run


def test_the_capacity_plan_honours_step_minutes():
    default = load_live.plan("capacity")["capacity"]
    long = load_live.plan("capacity", step_minutes=30)["capacity"]
    assert default["minutes"] == 4 * 8 and long["minutes"] == 4 * 30
    assert long["calls"] == pytest.approx(default["calls"] * 30 / 8)
    assert long["tokens"] == pytest.approx(default["tokens"] * 30 / 8)
    assert load_live.plan_problems("capacity", long)  # over the hard ceilings


def test_a_live_run_with_step_minutes_30_is_refused_whatever_ceilings_it_is_given(
    monkeypatch, capsys
):
    """Before the fix the plan ignored --step-minutes: a live run passed the gates against an
    8-minute plan and then ran about four times the reviewed volume."""
    monkeypatch.setenv(LIVE_KEY, LIVE_TOKEN)
    monkeypatch.setenv("GEMINI_API_KEY", "a-sentinel-not-a-key")
    default = load_live.plan("capacity")["capacity"]
    base = ["run", "--kind", "capacity", "--live", "--step-minutes", "30"]
    # ceilings sized for the reviewed 8-minute plan
    fitted = [
        "--max-provider-calls", str(int(default["worst_case_calls"]) + 1),
        "--max-tokens", str(int(default["worst_case_tokens"]) + 1),
    ]  # fmt: skip
    assert load_live.main([*base, *fitted]) == 2
    assert "plan needs up to" in capsys.readouterr().err
    # and the largest ceilings a live run may be given
    maximal = [
        "--max-provider-calls", str(HARD_MAX_CALLS["capacity"]),
        "--max-tokens", str(HARD_MAX_TOKENS["capacity"]),
    ]  # fmt: skip
    assert load_live.main([*base, *maximal]) == 2
    assert "hard ceilings" in capsys.readouterr().err


def test_a_shorter_step_gives_a_smaller_plan_and_the_dry_run_follows_it(tmp_path):
    out = tmp_path / "cap.jsonl"
    argv = ["run", "--kind", "capacity", "--step-minutes", "0.5", "--out", str(out)]
    assert load_live.main(argv) == 0
    records = [json.loads(x) for x in out.read_text().splitlines()]
    planned = load_live.plan("capacity", step_minutes=0.5)["capacity"]
    assert records[0]["estimated_calls"] == pytest.approx(planned["calls"])
    assert records[-1]["calls"] <= planned["worst_case_calls"]  # it sent no more than the plan
    assert planned["calls"] < load_live.plan("capacity")["capacity"]["calls"] / 10


def test_the_runner_takes_its_steps_from_the_plan(monkeypatch):
    seen = []
    real = load_live.capacity_config

    def spy(minutes, turns_per_minute, seed=309):
        seen.append((minutes, turns_per_minute, seed))
        return real(minutes, turns_per_minute, seed)

    monkeypatch.setattr(load_live, "capacity_config", spy)
    planned = planned_for("capacity", 0.25)
    args = args_for("capacity", step_minutes=999.0, seed=7)  # the flag is not what is sent
    run_virtual(load_live.run_capacity(args, Ledger(None, None, None), planned))
    assert seen == [(0.25, s["turns_per_minute"], 7) for s in planned["steps"]]


# ------------------------------------------------------------------ the stop at arrival


def gated(ledger, outcome):
    from capacity.load_live import GatedModel
    from capacity.load_test import RecordingModel

    async def decide(text, questions):
        return outcome

    return GatedModel(RecordingModel(SimpleNamespace(decide=decide), "shared"), ledger)


@pytest.mark.parametrize(
    ("outcome", "reason"),
    [
        (SafetyBlocked(message=None, reason="safety"), "provider_refusal"),
        (Failed(kind=FailureKind.AUTH), "auth"),
    ],
)
def test_the_stop_is_set_before_control_returns_to_the_engine(outcome, reason):
    ledger = Ledger(None, None, None)
    model = gated(ledger, outcome)
    seen = {}

    async def engine_side():
        # what the engine sees the instant `decide` returns, with nothing awaited in between
        seen["result"] = await model.decide("benign text", {})
        seen["stopped"] = ledger.stopped
        seen["event"] = ledger.stop_event.is_set()

    run_virtual(engine_side())
    assert seen["stopped"] == reason and seen["event"] is True
    assert seen["result"] is outcome  # the engine still gets the result and records the check
    stops = [r for r in ledger.records if r["type"] == "run_stopped"]
    assert [r["reason"] for r in stops] == [reason]


def test_a_later_call_through_the_gate_is_refused_not_sent():
    ledger = Ledger(None, None, None)
    model = gated(ledger, SafetyBlocked(message=None, reason="safety"))

    async def go():
        await model.decide("one", {})
        return await model.decide("two", {})

    second = run_virtual(go())
    assert isinstance(second, Failed) and second.kind is FailureKind.OTHER
    assert len(model.calls) == 1  # the second never reached the provider


def test_an_answer_or_a_timeout_does_not_stop_the_run():
    for outcome in (Failed(kind=FailureKind.TIMEOUT), Failed(kind=FailureKind.UNAVAILABLE)):
        ledger = Ledger(None, None, None)
        run_virtual(gated(ledger, outcome).decide("text", {}))
        assert ledger.stopped is None


def test_the_capacity_run_stops_at_the_refusal_without_the_check_level_observer(
    monkeypatch,
):
    """With ``CapacityObserver.after`` made a no-op, only the gate can stop the run: it does,
    and no call starts after the refusal."""
    monkeypatch.setattr(load_live.CapacityObserver, "after", lambda *a, **k: None)
    provider, ledger, error = run_capacity_with(monkeypatch, outcome_at={40: REFUSAL})
    assert ledger.stopped == "provider_refusal" and "provider_refusal" in str(error)
    assert provider.started_after_stop == [] and provider.starts_after("outcome", 40) == []
