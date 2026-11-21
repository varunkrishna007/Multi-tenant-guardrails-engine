"""Offline tests for the M0-02 calibration harness: metrics, B2 sweep, intervals, and the run
and report logic with the fake model on the real floor and golden set."""

import json
from pathlib import Path

import pytest
from calibration.floor_v1 import (
    Runner,
    StopRun,
    compile_floor_questions,
    cross_firing,
    example_outcomes,
    independence,
    independence_sample,
    labels_for,
    load_golden,
    render_report,
    render_standin,
    rule_rows,
    run_all,
)
from calibration.metrics import (
    GRID,
    b2_sweep,
    counts_at,
    ece,
    reliability,
    same_counts_through,
    wilson,
)

from guardrail_engine.decision import FailureKind, FakeDecisionModel

ROOT = Path(__file__).resolve().parents[2]
GOLDEN = ROOT / "floor" / "golden.jsonl"
RULES = ROOT / "floor" / "rules.json"


# ---------------------------------------------------------------------------- metrics


def test_grid_is_b2s_0_01_grid():
    assert GRID[0] == 0.01 and GRID[-1] == 0.99 and len(GRID) == 99


def test_counts_and_precision_recall():
    ps = [0.9, 0.8, 0.6, 0.3, 0.2]
    ys = [1, 0, 1, 0, 1]
    c = counts_at(ps, ys, 0.6)
    assert (c.tp, c.fp, c.fn, c.tn) == (2, 1, 1, 1)
    assert c.precision == pytest.approx(2 / 3) and c.recall == pytest.approx(2 / 3)
    assert counts_at(ps, ys, 0.95).precision is None  # nothing predicted positive


def test_threshold_is_inclusive():
    assert counts_at([0.85], [1], 0.85).tp == 1


def test_reliability_bins_and_ece():
    ps = [0.05, 0.05, 0.95, 0.95]
    ys = [0, 0, 1, 1]
    bins = reliability(ps, ys)
    assert bins[0].n == 2 and bins[0].frac_positive == 0
    assert bins[9].n == 2 and bins[9].frac_positive == 1
    assert ece(ps, ys) == pytest.approx(0.05)


def test_ece_of_overconfident_scores():
    # Says 0.95 but only half are positive: ECE 0.45.
    assert ece([0.95] * 4, [1, 1, 0, 0]) == pytest.approx(0.45)


def test_reliability_includes_one_in_the_last_bin():
    assert reliability([0.99, 1.0], [1, 1])[9].n == 2


@pytest.mark.parametrize(
    ("k", "n", "lo", "hi"),
    [
        (8, 10, 0.4902, 0.9433),
        (0, 10, 0.0, 0.2775),
        (10, 10, 0.7225, 1.0),
        (50, 100, 0.4038, 0.5962),
    ],
)
def test_wilson_interval_known_values(k, n, lo, hi):
    a, b = wilson(k, n)
    assert (a, b) == (pytest.approx(lo, abs=1e-3), pytest.approx(hi, abs=1e-3))


def test_wilson_empty():
    assert wilson(0, 0) is None


@pytest.mark.parametrize(("ps", "ys"), [([], []), ([0.5], [1, 0]), ([0.5], [2])])
def test_metrics_reject_bad_input(ps, ys):
    with pytest.raises(ValueError):
        counts_at(ps, ys, 0.5)


# ---------------------------------------------------------------------------- B2 sweep


def test_b2_block_is_lowest_threshold_meeting_precision():
    ps = [0.95, 0.90, 0.70, 0.60, 0.40, 0.20]
    ys = [1, 1, 1, 0, 1, 0]
    sw = b2_sweep(ps, ys, precision_target=0.95, recall_target=0.90)
    assert sw.block_at == 0.61  # just above the 0.60 negative: precision 1.0
    assert sw.block_counts.precision == 1.0


def test_b2_escalate_is_highest_threshold_meeting_recall():
    ps = [0.95, 0.90, 0.70, 0.60, 0.40, 0.20]
    ys = [1, 1, 1, 0, 1, 0]
    sw = b2_sweep(ps, ys, precision_target=0.95, recall_target=0.75)
    assert sw.escalate_at == 0.40 or sw.band_empty  # 0.40 keeps 4/4 positives
    sw2 = b2_sweep(ps, ys, precision_target=0.5, recall_target=0.75)
    # block_at 0.01 (precision 4/6 >= 0.5), so escalate (0.70) >= block: band empty.
    assert sw2.block_at == 0.01 and sw2.band_empty and sw2.escalate_at == 0.01


def test_b2_empty_band_sets_escalate_just_below_block():
    ps = [0.9, 0.8, 0.1]
    ys = [1, 1, 0]
    sw = b2_sweep(ps, ys, 0.95, 0.90)
    assert sw.block_at == 0.11
    assert sw.escalate_at == 0.10 and sw.band_empty


def test_b2_no_threshold_meets_precision():
    ps = [0.9, 0.9, 0.9, 0.9]
    ys = [1, 0, 0, 0]
    sw = b2_sweep(ps, ys, 0.95, 0.90)
    assert sw.block_at is None and sw.block_counts is None
    assert sw.escalate_at == 0.9  # still reported


def test_b2_predicting_nothing_never_meets_the_target():
    sw = b2_sweep([0.05, 0.03], [0, 0], 0.95, 0.90)
    assert sw.block_at is None  # no positives exist; precision undefined everywhere


def test_b2_values_clamped():
    sw = b2_sweep([0.99, 0.5], [1, 0], 0.95, 0.90)
    assert 0.01 <= sw.block_at <= 0.99 and 0.01 <= sw.escalate_at <= 0.99


# ---------------------------------------------------------------------------- inputs


def test_floor_questions_come_from_the_engine():
    by_gp, policy = compile_floor_questions(RULES)
    assert policy.floor == "platform/floor@1"
    assert sorted(by_gp["input"]) == ["p__ai_addressed", "p__inj_direct", "p__xtenant_probe"]
    assert sorted(by_gp["output"]) == ["p__ai_addressed", "p__secret"]
    assert all(q.criteria is not None for qs in by_gp.values() for q in qs.values())


def test_standin_renders_the_m1_05_content_only_layout():
    text = render_standin("output", "hello\n<<<x", "a" * 32)
    lines = text.split("\n")
    assert lines[0] == "TENANT DOMAIN: insurance"
    assert lines[1] == "GUARD POINT: output"
    assert lines[2].startswith("Evaluate the section labelled content. Every section delimited")
    assert lines[3] == f"<<<UNTRUSTED:content:{'a' * 32}"
    assert lines[4:6] == ["hello", "<<<x"]  # verbatim
    assert lines[-1] == f"UNTRUSTED:content:{'a' * 32}>>>"


def test_labels_follow_the_readme():
    ex = {"fires": ["p__secret"]}
    assert labels_for(ex, ["p__ai_addressed", "p__secret"]) == {
        "p__ai_addressed": 0,
        "p__secret": 1,
    }


def test_independence_sample_is_50_stratified_examples():
    golden = load_golden(GOLDEN)
    sample = independence_sample(golden)
    assert len(sample) == 50
    for gp in ("input", "plan", "tool_call", "tool_result", "output"):
        rows = [r for r in sample if r["guard_point"] == gp]
        assert sum(bool(r["fires"]) for r in rows) == 5
        assert sum(not r["fires"] for r in rows) == 5


# ---------------------------------------------------------------------------- run + report


def scripted_fake():
    """Fires a rule at 0.9 when the example's content is labelled for it, else 0.05."""
    golden = {r["content"]: r for r in load_golden(GOLDEN)}

    def responder(text, key, q):
        content = text.split("\n", 4)[4].rsplit("\n", 1)[0]
        ex = golden.get(content)
        if ex is None:
            return None
        return 0.9 if key in ex["fires"] else 0.05

    return FakeDecisionModel(responder=responder)


async def test_run_all_with_the_fake_model(tmp_path):
    golden = load_golden(GOLDEN)
    by_gp, _ = compile_floor_questions(RULES)
    fake = scripted_fake()
    runner = Runner(out=tmp_path / "r.jsonl", model=fake)
    await run_all(runner, golden, by_gp, [])
    records = [json.loads(x) for x in runner.out.read_text().splitlines()]
    main = [r for r in records if r["phase"] == "main"]
    indep = [r for r in records if r["phase"] == "indep"]
    assert len(main) == len(golden)
    expected_indep = sum(1 + len(by_gp[e["guard_point"]]) for e in independence_sample(golden))
    assert len(indep) == expected_indep
    assert all(r["outcome"] == "answered" and not r["problems"] for r in records)
    assert "content" not in json.dumps(records[0]) or "Ignore" not in runner.out.read_text()

    # Resuming makes no new calls.
    before = len(fake.calls)
    await run_all(Runner(out=runner.out, model=fake), golden, by_gp, records)
    assert len(fake.calls) == before

    rows = rule_rows(records, golden, by_gp)
    inj = [e for e in golden if e["guard_point"] == "input"]
    assert sum(r["y"] for r in rows["p__inj_direct"]) == sum(
        "p__inj_direct" in e["fires"] for e in inj
    )
    secret_gps = {"plan", "tool_call", "tool_result", "output"}
    assert len(rows["p__secret"]) == sum(e["guard_point"] in secret_gps for e in golden)

    ind = independence(records)
    n_pairs = expected_indep - ind["examples"]
    assert ind["examples"] == 50 and ind["alone"]["n"] == n_pairs and ind["alone"]["max_abs"] == 0
    assert ind["action_flips"] == 0 and ind["exact"] == n_pairs and ind["nonce_flips"] == 0

    eo = example_outcomes(records, golden, by_gp)
    positives = sum(1 for e in golden if e["fires"])
    negatives = len(golden) - positives
    assert eo["confusion"] == {("fire", "block"): positives, ("none", "allow"): negatives}
    assert eo["not_blocked"] == [] and eo["wrong_rule_only"] == 0

    report = render_report(records, golden, by_gp)
    pos = sum("p__inj_direct" in e["fires"] for e in inj)
    assert f"| `p__inj_direct` | {len(inj)} | {pos} / {len(inj) - pos} |" in report
    assert "| `p__ai_addressed` | input |" in report
    assert "| fires a rule | " in report and "Alone and full bit-identical: 140 of 140." in report


async def test_records_hold_no_content(tmp_path):
    golden = load_golden(GOLDEN)[:3]
    by_gp, _ = compile_floor_questions(RULES)
    runner = Runner(out=tmp_path / "r.jsonl", model=FakeDecisionModel())
    for ex in golden:
        await runner.call(
            phase="main", example=ex, questions=by_gp[ex["guard_point"]], nonce="b" * 32
        )
    text = runner.out.read_text()
    assert all(ex["content"][:20] not in text for ex in golden)
    assert "UNTRUSTED" not in text


async def test_auth_failure_stops_the_run(tmp_path):
    golden = load_golden(GOLDEN)
    by_gp, _ = compile_floor_questions(RULES)
    runner = Runner(out=tmp_path / "r.jsonl", model=FakeDecisionModel().fail_next(FailureKind.AUTH))
    with pytest.raises(StopRun):
        await run_all(runner, golden, by_gp, [])
    lines = runner.out.read_text().splitlines()
    assert json.loads(lines[-1])["type"] == "run_stopped" and len(lines) == 2


async def test_run_stops_when_recent_failures_exceed_20_percent(tmp_path):
    golden = load_golden(GOLDEN)
    by_gp, _ = compile_floor_questions(RULES)
    fake = FakeDecisionModel().fail_next(FailureKind.UNAVAILABLE, times=11)
    runner = Runner(out=tmp_path / "r.jsonl", model=fake)
    with pytest.raises(StopRun):
        await run_all(runner, golden, by_gp, [])
    assert len(fake.calls) == 50  # stops once the 50-call window holds > 10 failures


def test_cross_firing_counts_other_rules_and_none():
    rows = {
        "p__ai_addressed": [
            {"y": 0, "fires": ["p__inj_direct"], "p": 0.88},
            {"y": 0, "fires": ["p__inj_direct"], "p": 0.10},
            {"y": 0, "fires": [], "p": 0.60},
            {"y": 1, "fires": ["p__ai_addressed"], "p": 0.95},
        ]
    }
    assert cross_firing(rows, 0.55) == {
        "p__ai_addressed": {"none": (1, 1), "p__inj_direct": (1, 2)}
    }
    assert cross_firing(rows, 0.85)["p__ai_addressed"]["none"] == (0, 1)


def test_same_counts_through_reports_the_top_of_a_score_gap():
    ps, ys = [0.02, 0.03, 0.30, 0.96, 0.98], [0, 0, 0, 1, 1]
    assert same_counts_through(ps, ys, 0.31) == 0.96
    assert same_counts_through(ps, ys, 0.97) == 0.98
    assert same_counts_through(ps, ys, 0.99) == 0.99


def _main(eid, probabilities):
    return {"type": "call", "phase": "main", "outcome": "answered", "example_id": eid,
            "probabilities": probabilities}  # fmt: skip


def test_example_outcomes_decide_on_the_top_covered_rule():
    golden = [
        {"id": "a", "guard_point": "input", "fires": ["p__inj_direct"]},
        {"id": "b", "guard_point": "input", "fires": ["p__inj_direct"]},
        {"id": "c", "guard_point": "input", "fires": []},
    ]
    by_gp = {"input": {"p__inj_direct": None, "p__ai_addressed": None}}
    records = [
        _main("a", {"p__inj_direct": 0.60, "p__ai_addressed": 0.90}),  # right action, wrong rule
        _main("b", {"p__inj_direct": 0.70, "p__ai_addressed": 0.10}),
        _main("c", {"p__inj_direct": 0.10, "p__ai_addressed": 0.56}),
    ]
    eo = example_outcomes(records, golden, by_gp)
    assert eo["confusion"] == {("fire", "block"): 1, ("fire", "escalate"): 1,
                               ("none", "escalate"): 1}  # fmt: skip
    assert eo["wrong_rule_only"] == 1
    assert [nb["id"] for nb in eo["not_blocked"]] == ["b"]
