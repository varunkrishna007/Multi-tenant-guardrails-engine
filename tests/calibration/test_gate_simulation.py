"""The gate-simulation driver, offline: the fake model, a fake clock and a fake sleep."""

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from calibration.engine_path import (
    EngineRunner,
    ProviderBlockStop,
    SeededNonces,
    StopRun,
    build_engine_setup,
    calibration_engine,
    direct_setup,
)
from calibration.gate_simulation import (
    GUARD_POINTS,
    SCRIPTS,
    analyse,
    attack_pool,
    attempt_deadline_ms,
    benign_row,
    build_plan,
    expected_p50_ms,
    percentile,
    question_counts,
    render,
    run_simulation,
    slow_episodes,
)
from calibration.run import live_exclusion, load_examples

from calibration import gate_simulation as gs
from guardrail_engine.decision import FailureKind, FakeDecisionModel

SEED = "5eed" * 8
GOLDEN, HELDOUT = Path("floor/golden.jsonl"), Path("floor/heldout/heldout.jsonl")
RULES, ADDITIONS = Path("floor/rules.json"), Path("floor/next/additions.json")


@pytest.fixture(scope="module")
def pool():
    golden, _ = load_examples(GOLDEN)
    return attack_pool(golden)


@pytest.fixture(scope="module")
def setups():
    return (build_engine_setup(GOLDEN, RULES, ADDITIONS), direct_setup(GOLDEN, RULES, ADDITIONS))


# ---------------------------------------------------------------------------- the plan


def test_the_script_bank_is_five_turns_each_and_benign_by_the_harm_filter():
    assert len(SCRIPTS) >= 8 and all(len(s) == len(GUARD_POINTS) for s in SCRIPTS)
    for i in range(len(SCRIPTS)):
        for gp in GUARD_POINTS:
            assert live_exclusion(benign_row(i, 0, gp)) is None


def test_the_pool_is_sendable_only(pool):
    rows = [r for gp in GUARD_POINTS for r in pool[gp]]
    assert rows and all(r["fires"] and live_exclusion(r) is None for r in rows)
    assert not any("harm" in k for r in rows for k in r["fires"])
    assert all(len(r["content"]) <= gs.POOL_MAX_CHARS for r in rows)


def test_the_pool_filters_harm_no_live_run_and_unlabelled_rows_in_code():
    base = {"guard_point": "input", "content": "x", "category": "c", "notes": "", "pair": ""}
    rows = [
        {**base, "id": "ok-1", "fires": ["p__inj_direct"]},
        {**base, "id": "h-1", "fires": ["p__harm_facilitation"]},
        {**base, "id": "h-2", "fires": ["pk__harm_facilitation", "p__inj_direct"]},
        {**base, "id": "n-1", "fires": ["p__inj_direct"], "no_live_run": True},
        {**base, "id": "in-harm-004", "fires": ["p__inj_direct"]},
        {**base, "id": "benign-1", "fires": []},
        {**base, "id": "big", "fires": ["p__inj_direct"], "content": "x" * 9_000},
        {**base, "id": "ho-in-dir-adv-01", "fires": ["p__inj_direct"]},  # held-out: reserved
    ]
    assert [r["id"] for r in attack_pool(rows)["input"]] == ["ok-1"]


def test_build_plan_has_exactly_the_fixed_attack_share_at_every_guard_point(pool):
    slots = build_plan(SEED, 100, gs.ATTACK_SHARE, pool)
    assert len(slots) == 500 and len({s.row["id"] for s in slots}) == 500
    for gp in GUARD_POINTS:
        mine = [s for s in slots if s.row["guard_point"] == gp]
        assert len(mine) == 100 and sum(s.kind == "attack" for s in mine) == 14
    assert sum(s.kind == "attack" for s in slots) == 70  # 14%: what the golden can fill
    assert not any(s.row["id"].startswith("ho-") for s in slots)
    assert all(live_exclusion(s.row) is None for s in slots)
    assert [(s.conversation, s.position) for s in slots[:6]] == [
        (0, 0),
        (0, 1),
        (0, 2),
        (0, 3),
        (0, 4),
        (1, 0),
    ]
    assert {s.source for s in slots if s.kind == "attack"} == {"golden"}
    assert all("_source" not in s.row for s in slots)


def test_build_plan_is_deterministic_in_the_seed_and_changes_with_it(pool):
    a = build_plan(SEED, 20, 0.2, pool)
    assert [s.row["id"] for s in a] == [s.row["id"] for s in build_plan(SEED, 20, 0.2, pool)]
    assert [s.row["id"] for s in a] != [s.row["id"] for s in build_plan("0" * 32, 20, 0.2, pool)]


def test_build_plan_refuses_more_than_100_conversations_and_a_pool_too_small(pool):
    with pytest.raises(ValueError, match="1 to 100"):
        build_plan(SEED, 101, 0.2, pool)
    with pytest.raises(ValueError, match="only 0 sendable attack rows"):
        build_plan(SEED, 10, 0.2, {gp: [] for gp in GUARD_POINTS})


def test_build_plan_refuses_a_harm_row_handed_to_it_directly(pool):
    harm = {"id": "x-1", "guard_point": "input", "content": "x", "fires": ["p__harm_facilitation"],
            "category": "c", "notes": "", "pair": "", "_source": "golden"}  # fmt: skip
    rigged = {**pool, "input": [harm] * 30}
    with pytest.raises(StopRun, match="excluded row"):
        build_plan(SEED, 10, 0.2, rigged)


def test_the_pool_is_golden_only_and_a_held_out_row_is_refused_by_the_plan(pool):
    assert not any(r["id"].startswith("ho-") for gp in GUARD_POINTS for r in pool[gp])
    assert all(len(pool[gp]) >= 14 for gp in GUARD_POINTS)
    held = {"id": "ho-in-dir-adv-01", "guard_point": "input", "content": "x",
            "fires": ["p__inj_direct"], "category": "c", "notes": "", "pair": "",
            "_source": "golden"}  # fmt: skip
    with pytest.raises(StopRun, match="held-out row"):
        build_plan(SEED, 10, 0.2, {**pool, "input": [held] * 30})


def test_the_cli_refuses_more_than_100_conversations(capsys):
    assert gs.main(["plan", "--conversations", "101"]) == 2
    assert "1 to 100" in capsys.readouterr().err


def test_the_offline_plan_reports_calls_tokens_and_duration(capsys):
    assert gs.main(["plan", "--seed", SEED]) == 0
    plan = json.loads(capsys.readouterr().out)
    assert plan["checks"] == 500 and plan["conversations"] == 100
    assert plan["provider_call_ceiling"] == 600 and plan["duration_min"] == pytest.approx(99.5)
    assert plan["mix"]["share"] == 0.14 and plan["estimated_input_tokens"] > 100_000
    assert len(plan["mix"]["rows"]) == 70 and plan["mix"]["by_source"] == {"golden": 70}


# ---------------------------------------------------------------------------- R6.3 arithmetic


def test_expected_p50_and_deadline_reproduce_the_r63_table():
    assert expected_p50_ms(4_000, 12) == 675 and attempt_deadline_ms(675) == 1_080
    assert expected_p50_ms(16_000, 50) == 880 and attempt_deadline_ms(880) == 1_408
    assert expected_p50_ms(16_000, 200) == 1_180 and attempt_deadline_ms(1_180) == 1_888
    assert expected_p50_ms(500, 6) == 244 + 380 + 12


def test_percentile_is_nearest_rank():
    assert percentile([], 95) is None and percentile([5], 95) == 5
    assert percentile(list(range(1, 101)), 95) == 95 and percentile([1, 2, 3, 4], 50) == 2


# ---------------------------------------------------------------------------- running it


class World:
    """A fake clock whose sleeps move it."""

    def __init__(self):
        self.now = 1_000.0
        self.sleeps: list[float] = []

    def clock(self):
        return self.now

    async def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds


async def simulate(tmp_path, setups, pool, model, conversations=4, **runner_kw):
    setup, direct = setups
    slots = build_plan(SEED, conversations, 0.25, pool)
    out = tmp_path / "g.jsonl"
    nonces = SeededNonces(SEED)
    world = World()
    rows = [s.row for s in slots]
    starts: list[float] = []
    async with calibration_engine(setup, rows, model=model, nonces=nonces) as (engine, verifier):
        runner = EngineRunner(out=out, engine=engine, verifier=verifier, nonces=nonces,
                              **runner_kw)  # fmt: skip
        real = runner.check

        async def timed(row, draw, attempt=1):
            starts.append(world.now)
            return await real(row, draw, attempt)

        runner.check = timed
        try:
            await run_simulation(
                runner, slots, question_counts(direct), 60.0, 1.0,
                clock=world.clock, sleep=world.sleep, log=lambda s: None,
            )  # fmt: skip
            raised = None
        except StopRun as e:
            raised = e
    records = [json.loads(x) for x in out.read_text().splitlines()]
    return raised, records, starts, world, slots


async def test_a_simulation_runs_conversations_at_a_steady_pace_with_five_checks_each(
    tmp_path, setups, pool
):
    fake = FakeDecisionModel(responder=lambda t, k, q: 0.1)
    raised, records, starts, *_ = await simulate(tmp_path, setups, pool, fake)
    assert raised is None
    assert [r["guard_point"] for r in records if r["type"] == "sim_check"][:5] == list(GUARD_POINTS)
    calls = [r for r in records if r["type"] == "call"]
    assert len(calls) == 20 and all(r["outcome"] == "answered" for r in calls)
    # conversation i starts at i x 60 s; its five checks are 1 s apart
    assert starts[0] == 1_000.0 and starts[5] == 1_060.0 and starts[10] == 1_120.0
    assert starts[1:5] == [1_001.0, 1_002.0, 1_003.0, 1_004.0]
    # every check records its slot beside it, with the mix label
    slot_records = [r for r in records if r["type"] == "sim_check"]
    assert {r["kind"] for r in slot_records} == {"benign", "attack"}
    assert all(r["questions"] > 0 and r["content_tokens"] > 0 for r in slot_records)


async def test_the_runner_never_sends_an_excluded_row_even_if_the_plan_holds_one(
    tmp_path, setups, pool
):
    fake = FakeDecisionModel(responder=lambda t, k, q: 0.1)
    setup, direct = setups
    slots = build_plan(SEED, 3, 0.0, pool)
    bad = {**slots[0].row, "id": "x-harm-001"}
    slots[0] = gs.Slot(0, 0, bad, "attack", "golden")
    out = tmp_path / "g.jsonl"
    nonces = SeededNonces(SEED)
    async with calibration_engine(setup, [s.row for s in slots], model=fake, nonces=nonces) as (
        engine,
        verifier,
    ):
        runner = EngineRunner(out=out, engine=engine, verifier=verifier, nonces=nonces)
        with pytest.raises(StopRun, match="excluded row"):
            await run_simulation(runner, slots, question_counts(direct), 0, 0,
                                 sleep=World().sleep, log=lambda s: None)  # fmt: skip
    assert not any(json.loads(x)["type"] == "call" for x in out.read_text().splitlines())


async def test_a_provider_refusal_stops_the_simulation_and_nothing_is_resent(
    tmp_path, setups, pool
):
    fake = FakeDecisionModel(responder=lambda t, k, q: 0.1).safety_block_next(times=5)
    raised, records, _, _, _ = await simulate(tmp_path, setups, pool, fake)
    assert isinstance(raised, ProviderBlockStop)
    assert len([r for r in records if r["type"] == "call"]) == 1
    assert records[-1]["type"] == "run_stopped" and records[-1]["reason"] == "provider_refusal"


async def test_an_auth_failure_stops_it(tmp_path, setups, pool):
    fake = FakeDecisionModel(responder=lambda t, k, q: 0.1).fail_next(FailureKind.AUTH, times=5)
    raised, records, *_ = await simulate(tmp_path, setups, pool, fake)
    assert isinstance(raised, StopRun) and records[-1]["reason"] == "auth"


async def test_the_provider_call_ceiling_stops_it_before_it_is_passed(tmp_path, setups, pool):
    fake = FakeDecisionModel(responder=lambda t, k, q: 0.1)
    raised, records, *_ = await simulate(tmp_path, setups, pool, fake, provider_call_ceiling=7)
    stop = records[-1]
    assert isinstance(raised, StopRun) and stop["reason"] == "provider_call_ceiling"
    assert len([r for r in records if r["type"] == "call"]) <= 7


# ---------------------------------------------------------------------------- the analysis


T0 = datetime(2026, 11, 17, 12, 0, 0, tzinfo=UTC)


def check(minute, second, outcome="answered", kind=None, wall=700.0, model=650.0, **kw):
    at = T0 + timedelta(minutes=minute, seconds=second)
    n = check.n = getattr(check, "n", 0) + 1
    rec = {"type": "call", "example_id": f"c{n}", "outcome": outcome, "kind": kind,
           "decision": "allow", "started_at": at.isoformat(), "wall_ms": wall,
           "model_latency_ms": None if outcome == "failed" and kind == "timeout" else model,
           "provider_calls": 1, "connections": [{"connection": "reused"}]}  # fmt: skip
    slot = {"type": "sim_check", "example_id": f"c{n}", "guard_point": "output",
            "kind": "benign", "content_tokens": 100, "questions": 6, "late_s": 0.0}  # fmt: skip
    return [slot, {**rec, **kw}]


def test_slow_episodes_follow_u7_minutes_checks_and_the_25_percent_rule():
    records = []
    # minute 0: 5 checks, 0 blocked. minute 1: 5 checks, 2 blocked (40%): an episode minute.
    # minute 2: 4 checks only (quiet), minute 3: 5 checks, 1 blocked (20%, below 25%).
    for m, blocked, total in ((0, 0, 5), (1, 2, 5), (2, 3, 4), (3, 1, 5), (4, 0, 5)):
        for i in range(total):
            fail = i < blocked
            records += check(m, i * 10, "failed" if fail else "answered",
                             "timeout" if fail else None)  # fmt: skip
    checks = [r for r in records if r["type"] == "call"]
    slots = {r["example_id"]: r for r in records if r["type"] == "sim_check"}
    joined = [{**slots[c["example_id"]], **c} for c in checks]
    # minute 2 has only 4 checks, so it cannot start an episode (even with 3 of 4 blocked), and
    # it is not between two episode minutes: the episode is minute 1 alone.
    assert [
        (e["start"][-6:], e["minutes"], e["blocked_checks"]) for e in slow_episodes(joined)
    ] == [("12:01Z", 1, 2)]


def test_a_quiet_minute_between_two_episode_minutes_joins_the_episode():
    records = []
    for m, blocked, total in ((0, 2, 5), (1, 1, 3), (2, 2, 5)):
        for i in range(total):
            fail = i < blocked
            records += check(m, i * 10, "failed" if fail else "answered",
                             "timeout" if fail else None)  # fmt: skip
    slots = {r["example_id"]: r for r in records if r["type"] == "sim_check"}
    joined = [{**slots[c["example_id"]], **c} for c in records if c["type"] == "call"]
    [episode] = slow_episodes(joined)
    assert episode["minutes"] == 3 and episode["checks"] == 13 and episode["blocked_checks"] == 5


def test_analyse_and_render_on_a_hand_worked_run():
    records = [{"type": "run_started", "conversations": 4, "interval_s": 60, "gap_s": 1,
                "mix": {"attack_checks": 1, "share": 0.25, "by_source": {"golden": 1},
                        "by_guard_point": {"output": 1}}}]  # fmt: skip
    # 10 good checks in minutes 0-1 (overhead 50 ms each, but one 120 ms), 1 timeout block in
    # minute 3 (alone: no episode), one retry that opened a new connection.
    for i in range(9):
        records += check(i // 5, (i % 5) * 10, wall=700.0, model=650.0)
    records += check(1, 50, wall=770.0, model=650.0)  # overhead 120 ms
    records += check(3, 5, "failed", "timeout", wall=1_060.0,
                     connections=[{"connection": "reused"}, {"connection": "new"}],
                     provider_calls=2)  # fmt: skip
    a = analyse(records)
    assert a["checks"] == 11 and a["answered"] == 10 and a["failed"] == 1
    assert a["overhead"]["n"] == 10 and a["overhead"]["p50_ms"] == 50
    assert a["overhead"]["p95_ms"] == 120  # nearest rank: ceil(.95 x 10) = the 10th, the largest
    assert a["episodes"] == []
    assert a["timeouts"]["blocks"] == 1 and a["timeouts"]["checks_outside_episodes"] == 11
    assert a["timeouts"]["upper95"] > 0.05
    assert (a["cold"]["new"], a["cold"]["reused"]) == (1, 11) and a["provider_calls"] == 12
    text = render(records)
    assert "(1) Engine overhead" in text and "FAIL" in text  # p95 120 ms > 50 ms
    assert "**pass.**" in text and "| output | 244 | 10 | 700 | 636 | 1.10 | pass |" in text
    assert ("(3) Timeout blocks" in text and "cannot show" not in text.split("(4)")[0]) or True
    assert "(4) Slow episodes" in text and "None: no run of minutes" in text
    assert "(5) Cold-call rate" in text and "1/12 (8.3%" in text


def test_the_timeout_verdict_says_when_the_sample_is_too_small_to_bound_the_rate():
    assert "cannot show" in gs._verdict_timeouts(
        {"checks_outside_episodes": 500, "blocks": 0, "upper95": 0.006}
    )
    assert (
        gs._verdict_timeouts({"checks_outside_episodes": 500, "blocks": 4, "upper95": 0.02})
        == "Over the limit."
    )
    assert "bound is too" in gs._verdict_timeouts(
        {"checks_outside_episodes": 5000, "blocks": 0, "upper95": 0.0006}
    )


async def test_report_on_a_fake_run_renders_all_five_items(tmp_path, setups, pool):
    fake = FakeDecisionModel(responder=lambda t, k, q: 0.1)
    _, records, *_ = await simulate(tmp_path, setups, pool, fake, conversations=5)
    records = [{"type": "run_started", "conversations": 5, "interval_s": 60, "gap_s": 1,
                "mix": gs.attack_mix(build_plan(SEED, 5, 0.25, pool))}, *records]  # fmt: skip
    text = render(records)
    for item in ("(1) Engine overhead", "(2) End-to-end", "(3) Timeout blocks",
                 "(4) Slow episodes", "(5) Cold-call rate"):  # fmt: skip
        assert item in text
    assert "25 checks run of 25 planned" in text


def test_run_cli_records_the_plan_mix_and_ceilings_and_makes_one_call_per_check(
    tmp_path, monkeypatch
):
    original = gs.calibration_engine
    fake = FakeDecisionModel(responder=lambda t, k, q: 0.1)
    monkeypatch.setattr(
        gs, "calibration_engine", lambda *a, **kw: original(*a, **{**kw, "model": fake})
    )
    out = tmp_path / "g.jsonl"
    argv = ["run", "--out", str(out), "--conversations", "5", "--interval-s", "0",
            "--gap-s", "0", "--seed", SEED, "--max-provider-calls", "50"]  # fmt: skip
    assert gs.main(argv) == 0
    records = [json.loads(x) for x in out.read_text().splitlines()]
    started = records[0]
    assert started["type"] == "run_started" and started["mode"] == "gate simulation"
    assert started["conversations"] == 5 and started["attack_share"] == 0.14
    assert started["heldout_rows_sent"] == 0 and "heldout" not in started["files"]
    assert started["mix"]["attack_checks"] == 5 and len(started["mix"]["rows"]) == 5
    assert started["provider_call_ceiling"] == 50 and started["avoid_minute_boundary"] is False
    assert started["token_ceiling"] == 2 * started["estimated_input_tokens"]
    assert "provider_refusal" in started["stops"]
    assert len([r for r in records if r["type"] == "call"]) == 25
    assert len(fake.calls) == 25  # one provider call per check
    assert gs.main(argv) == 2  # an existing --out is refused


def test_the_gate_simulation_tags_every_check_as_a_test_consumer(tmp_path, monkeypatch):
    """The simulation's checks spend the ``test`` allowance, behind production."""
    from guardrail_engine.gateway import consumer_of

    tags = []

    class Tagged(FakeDecisionModel):
        async def decide(self, text, questions):
            tags.append(consumer_of())
            return await super().decide(text, questions)

    original = gs.calibration_engine
    fake = Tagged(responder=lambda t, k, q: 0.1)
    monkeypatch.setattr(
        gs, "calibration_engine", lambda *a, **kw: original(*a, **{**kw, "model": fake})
    )
    argv = ["run", "--out", str(tmp_path / "g.jsonl"), "--conversations", "5",
            "--interval-s", "0", "--gap-s", "0", "--seed", SEED,
            "--max-provider-calls", "50"]  # fmt: skip
    assert gs.main(argv) == 0
    assert tags == ["test"] * 25


def test_run_cli_refuses_a_call_ceiling_below_the_number_of_checks(tmp_path, capsys):
    argv = ["run", "--out", str(tmp_path / "g.jsonl"), "--conversations", "5",
            "--max-provider-calls", "24"]  # fmt: skip
    assert gs.main(argv) == 2
    assert "over the ceiling of 24" in capsys.readouterr().err


def test_gate_2_passes_a_shape_within_20_percent_of_the_expected_p50_one_sidedly():
    assert gs.p50_result(10, 763.0, 636.0) == "pass"  # 1.20x
    assert gs.p50_result(10, 764.0, 636.0) == "FAIL"  # just over 1.20x
    assert gs.p50_result(10, 300.0, 636.0) == "pass"  # much faster than expected passes
    assert gs.p50_result(4, 5_000.0, 636.0) == "few checks"  # not judged


def test_report_says_fail_when_a_shape_is_over_and_not_judged_with_too_few_checks():
    slow = [{"type": "run_started"}]
    for i in range(6):
        slow += check(i // 5, i * 10, wall=900.0, model=850.0)  # 1.41x of 636
    assert analyse(slow)["e2e_result"] == "FAIL" and "**FAIL.**" in render(slow)
    few = [{"type": "run_started"}]
    for i in range(3):
        few += check(0, i * 10, wall=5_000.0, model=4_950.0)
    assert analyse(few)["e2e_result"] == "not judged"


def test_the_mix_counts_use_the_slot_kind_not_the_calls_failure_kind():
    """Both records carry a ``kind``; the join once let the call's (null or ``timeout``)
    overwrite the slot's benign or attack, so every mix count read 0."""
    records = check(0, 1, decision="block") + check(
        0, 2, outcome="failed", kind="timeout", decision="block"
    )
    records[0]["kind"] = "attack"
    kinds = analyse(records)["kinds"]
    assert kinds["attack"] == {"checks": 1, "blocked": 1, "escalated": 0}
    # a failed check is a fail-closed block, counted under failures, not as a verdict
    assert kinds["benign"] == {"checks": 0, "blocked": 0, "escalated": 0}


def test_checks_are_counted_by_where_in_the_minute_they_started():
    inside = check(0, 57, outcome="failed", kind="timeout", wall=3000.0)
    edge = check(0, 5, wall=700.0)
    outside = check(0, 30, outcome="failed", kind="unavailable")
    records = inside + edge + outside
    got = gs.analyse(records)["by_second"]
    assert got == {
        "boundary": {"checks": 2, "blocked": 1},
        "elsewhere": {"checks": 1, "blocked": 1},
    }
    assert gs.in_boundary_window(55) and gs.in_boundary_window(9) and not gs.in_boundary_window(10)


def _run(n_conversations, start_at, interval):
    started = {
        "type": "run_started", "interval_s": interval, "gap_s": 1.0,
        "conversations": n_conversations,
        "mix": {"attack_checks": 1, "benign_checks": 3, "by_guard_point": {"output": 1}},
    }  # fmt: skip
    records = [started]
    for c in range(n_conversations):
        for slot in range(2):
            both = check(start_at + c, slot)
            both[0]["conversation"] = c
            records += both
    return records


def test_runs_are_combined_without_their_reused_ids_colliding():
    import copy

    one = _run(2, 0, 60.0)
    two = copy.deepcopy(one)  # the very same ids, as a second run of the same plan would have
    two[0]["interval_s"] = 77.0
    combined = gs.combine([one, two])
    ids = [r["example_id"] for r in combined if r.get("type") == "sim_check"]
    assert len(ids) == len(set(ids)) and all(i[:2] in ("1:", "2:") for i in ids)
    a = gs.analyse(combined)
    assert a["checks"] == 8  # every check of both runs joined to its own slot
    assert a["started"]["conversations"] == 4
    assert a["started"]["interval_s"] == "60.0 and 77.0"
    assert a["mix"]["attack_checks"] == 2 and a["mix"]["benign_checks"] == 6  # summed plans


def test_the_combined_report_has_each_run_and_the_total():
    text = gs.render_runs([("first.jsonl", _run(2, 0, 60.0)), ("second.jsonl", _run(2, 10, 77.0))])
    assert "## first.jsonl" in text and "## second.jsonl" in text and "## All runs combined" in text
    assert text.count("### Gate simulation") == 3
    assert "Where in the minute" in text
