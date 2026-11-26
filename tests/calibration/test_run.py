"""Offline tests for the second M0-02 run (calibration/run.py): floor@2 assembly, design A
questions, the real renderer with tenant fields, nonces and draws, the independence gate,
the harm filter and refusal tripwire, and the R7 analysis. No live calls."""

import json
import statistics
import zlib
from pathlib import Path

import pytest
from calibration.metrics import clopper_pearson_upper
from calibration.run import (
    V1_SUFFIX,
    IndependenceFailed,
    Limiter,
    ProviderBlockStop,
    Relabelled,
    Runner,
    StopRun,
    action,
    assemble_floor,
    b2_amended,
    build_setup,
    check_corpus,
    fairness,
    fresh_nonce,
    gate_decisions,
    independence_sample,
    live_exclusion,
    load_examples,
    main_draws,
    measurement_questions,
    pii_counts,
    plan_calls,
    render,
    render_report,
    replay_nonces,
    retest,
    rule_profile,
    run_all,
    secret_blocked,
)

from guardrail_engine.decision import FailureKind, FakeDecisionModel
from guardrail_engine.decision.limits import KEY_PATTERN, MAX_KEY_LENGTH

ROOT = Path(__file__).resolve().parents[2]
GOLDEN = ROOT / "floor" / "golden.jsonl"
RULES = ROOT / "floor" / "rules.json"
ADDITIONS = ROOT / "floor" / "next" / "additions.json"


def secret_blocked_id(rows, record) -> bool:
    return any(r["id"] == record["example_id"] and secret_blocked(r) for r in rows)


@pytest.fixture(scope="module")
def setup():
    return build_setup(GOLDEN, RULES, ADDITIONS)


@pytest.fixture(scope="module")
def rows():
    kept, _ = load_examples(GOLDEN)
    return kept


def make_runner(**kw):
    """A Runner whose limiter never waits (the real one paces a live run at 70% of Tier 1)."""
    return Runner(limiter=Limiter(tokens_per_min=1e12, requests_per_min=1e9), **kw)


def hashed_fake(**kw):
    """A deterministic model: p depends only on (rendered input, key), so the same input
    gives the same p (independence and determinism hold) and a new nonce gives a new p."""

    def responder(text, key, q):
        return 0.01 + (zlib.crc32(f"{text}|{key}".encode()) % 9800) / 10000

    return FakeDecisionModel(responder=responder, **kw)


# ---------------------------------------------------------------------------- metrics


@pytest.mark.parametrize(("k", "n", "bound"), [(0, 300, 0.01), (1, 475, 0.01), (2, 630, 0.01)])
def test_clopper_pearson_matches_r7_sample_sizes(k, n, bound):
    """R7.3(d): about 300 / 475 / 630 negatives prove false block ≤ 1% with 0 / 1 / 2."""
    assert clopper_pearson_upper(k, n) == pytest.approx(bound, abs=0.0005)


def test_clopper_pearson_edges():
    assert clopper_pearson_upper(0, 0) is None
    assert clopper_pearson_upper(5, 5) == 1.0
    assert clopper_pearson_upper(0, 110) == pytest.approx(1 - 0.05 ** (1 / 110), abs=1e-6)
    with pytest.raises(ValueError):
        clopper_pearson_upper(3, 2)


# ---------------------------------------------------------------------------- inputs


@pytest.mark.parametrize("label", ["p__harm_facilitation", "d__harm_facilitation",
                                   "t__acme_harm_facilitation"])  # fmt: skip
def test_harm_labelled_rows_are_excluded(label):
    assert live_exclusion({"id": "x-1", "fires": [label]}) is not None


def test_a_retired_row_is_never_sent():
    """A row retired for a contestable label stays in the corpus (the records that
    cite it still resolve) but is never used again."""
    row = {"id": "ho-x-1", "fires": ["p__secret"], "retired": "contestable"}
    assert live_exclusion(row) == "retired"
    assert live_exclusion({"id": "ho-x-2", "fires": ["p__secret"]}) is None
    assert live_exclusion({"id": "ho-x-3", "fires": [], "retired": ""}) is None  # not retired


def test_excluded_rows_never_reach_a_request(tmp_path):
    """User instruction (2026-11-17): synthetic rows with placeholder text."""
    path = tmp_path / "golden.jsonl"
    rows = [
        {"id": "a-1", "guard_point": "input", "fires": ["d__harm_facilitation"],
         "content": "PLACEHOLDER-A"},
        {"id": "a-2", "guard_point": "input", "fires": [], "no_live_run": True,
         "content": "PLACEHOLDER-B"},
        {"id": "in-harm-ok-001", "guard_point": "input", "fires": [], "content": "PLACEHOLDER-C"},
        {"id": "in-ok-001", "guard_point": "input", "fires": [], "content": "fine"},
    ]  # fmt: skip
    path.write_text("".join(json.dumps(r) + "\n" for r in rows))
    kept, excluded = load_examples(path)
    assert [r["id"] for r in kept] == ["in-ok-001"]
    assert excluded == {"labelled for a harm-facilitation rule": 1, "tagged no_live_run": 1,
                        "harm near-miss row": 1}  # fmt: skip


async def test_the_runner_refuses_an_excluded_row_even_if_passed_directly(tmp_path, setup):
    fake = hashed_fake()
    runner = make_runner(out=tmp_path / "r.jsonl", model=fake, setup=setup)
    row = {"id": "x-1", "guard_point": "input", "fires": ["p__harm_facilitation"],
           "content": "PLACEHOLDER"}  # fmt: skip
    with pytest.raises(StopRun):
        await runner.call("main", row, setup.questions["input"], "a" * 32, 1)
    assert fake.calls == []


def test_real_floor_golden_has_no_harm_labelled_rows():
    _, excluded = load_examples(GOLDEN)
    assert "labelled for a harm-facilitation rule" not in excluded
    assert "tagged no_live_run" not in excluded


def test_unrecognised_corpora_are_refused(tmp_path):
    check_corpus(GOLDEN, root=ROOT)
    check_corpus(ROOT / "floor/heldout/heldout.jsonl", root=ROOT)
    for bad in ("floor/heldout/harm_pack.jsonl", "packs/responsible_ai/golden.jsonl"):
        with pytest.raises(SystemExit):
            check_corpus(ROOT / bad, root=ROOT)
    with pytest.raises(SystemExit):
        check_corpus(tmp_path / "golden.jsonl", root=ROOT)


def test_floor2_is_assembled_from_the_files(tmp_path):
    rules = json.loads(RULES.read_text())
    additions = json.loads(ADDITIONS.read_text())
    floor2 = assemble_floor(RULES, ADDITIONS)
    assert floor2["floor_version"] == additions["target_floor_version"]
    by_key = {r["key"]: r for r in floor2["rules"]}
    for rep in additions["replacements"]:
        assert by_key[rep["key"]] == rep
    assert [r["key"] for r in floor2["rules"]][: len(rules["rules"])] == [
        r["key"] for r in rules["rules"]
    ]
    bad = tmp_path / "a.json"
    bad.write_text(json.dumps({**additions, "replacements": [{"key": "p__nope"}]}))
    with pytest.raises(ValueError):
        assemble_floor(RULES, bad)


def test_design_a_adds_v1_keys_only_where_the_rule_applies(setup):
    floor1 = {r["key"]: r for r in json.loads(RULES.read_text())["rules"]}
    for gp, qs in setup.questions.items():
        for key in ("p__ai_addressed", "p__xtenant_probe"):
            assert (key + V1_SUFFIX in qs) == (gp in floor1[key]["guard_points"])
        for key in qs:
            assert KEY_PATTERN.fullmatch(key) and len(key) <= MAX_KEY_LENGTH
    # Old and new wording really differ for the reworded rules.
    q = setup.questions["input"]
    assert q["p__xtenant_probe"] != q["p__xtenant_probe" + V1_SUFFIX]
    assert q["p__inj_direct"] is not None and "p__inj_direct" + V1_SUFFIX not in q


def test_measurement_questions_shape():
    new = {"input": {"a": 1, "b": 2}, "plan": {"b": 3}}
    old = {"input": {"a": 9}, "plan": {"c": 4}}
    assert measurement_questions(new, old, retest=("a", "c")) == {
        "input": {"a": 1, "b": 2, "a_v1": 9}, "plan": {"b": 3, "c_v1": 4}
    }  # fmt: skip


def test_render_uses_the_engine_renderer_with_tenant_and_nonce(setup):
    row = {"id": "x", "guard_point": "input", "fires": [], "content": "hello"}
    nonce = fresh_nonce(row)
    text = render(row, nonce, setup.max_content_tokens["input"])
    assert "TENANT: acme-insurance (t_1042)" in text and nonce in text and "hello" in text
    row2 = {**row, "tenant_slug": "other-co", "tenant_id": "t_7"}
    assert "TENANT: other-co (t_7)" in render(row2, nonce, setup.max_content_tokens["input"])


def test_render_handles_held_out_context_and_tools(setup):
    row = {
        "id": "ho-1", "guard_point": "tool_result", "fires": [], "domain": "insurance",
        "content": "{\"status\": \"active\"}",
        "context": [{"type": "turn", "role": "user", "text": "check my account"},
                    {"type": "tool_call", "tool": "crm.lookup", "arguments": "{}"}],
        "tools": [{"name": "crm.lookup", "description": "Looks up a record.", "read_only": True}],
    }  # fmt: skip
    text = render(row, fresh_nonce(row), setup.max_content_tokens["tool_result"])
    assert "check my account" in text and "crm.lookup" in text


def test_render_redacts_before_rendering_as_the_guard_service_does(setup):
    """M1-14: the direct path sends no raw PII of a configured kind. The email keeps its
    domain (p__exfil judges it), the card is replaced whole, and context and tool
    descriptions are redacted too. Counts per kind only."""
    card = "4111 1111 1111 1111"
    row = {
        "id": "x", "guard_point": "tool_call", "fires": [],
        "content": f"send it to ops.lead@collector.example with card {card}",
        "context": [{"type": "turn", "role": "user", "text": "mail jo.bloggs@example.org"},
                    {"type": "tool_call", "tool": "crm.lookup", "arguments": "{}"}],
        "tools": [{"name": "crm.lookup", "description": "Owner: sam.k@example.net",
                   "read_only": True}],
    }  # fmt: skip
    text = render(row, fresh_nonce(row), setup.max_content_tokens["tool_call"])
    for raw in ("ops.lead@", "jo.bloggs@", "sam.k@", card):
        assert raw not in text
    assert "[EMAIL]@collector.example" in text and "[CARD]" in text
    assert pii_counts(row) == {"email": 3, "card": 1}


async def test_direct_records_carry_redaction_counts(tmp_path, setup, rows):
    changed = next(r for r in rows if pii_counts(r))
    runner = make_runner(out=tmp_path / "r.jsonl", model=hashed_fake(), setup=setup)
    record = await runner.call("main", changed, setup.questions[changed["guard_point"]],
                               fresh_nonce(changed), 1)  # fmt: skip
    assert record["pii_redacted"] == pii_counts(changed) != {}


def test_fresh_nonce_avoids_the_row_texts():
    row = {"id": "x", "guard_point": "input", "content": "abc"}
    assert fresh_nonce(row) not in "abc" and len(fresh_nonce(row)) == 32


# ---------------------------------------------------------------------------- running


async def test_full_run_with_the_fake_model(tmp_path, setup, rows):
    fake = hashed_fake()
    runner = make_runner(out=tmp_path / "r.jsonl", model=fake, setup=setup)
    await run_all(runner, rows, [], draws=3, log=lambda s: None)
    records = [json.loads(x) for x in runner.out.read_text().splitlines()]
    calls = [r for r in records if r["type"] == "call"]
    plan = plan_calls(rows, setup, 3)
    assert len([r for r in calls if r["phase"] == "indep"]) == plan["indep"]
    # M7-01: a row the Guard Service blocks before any model call is recorded as
    # deterministic, three draws of it, and never sent
    blocked = [r for r in rows if secret_blocked(r)]
    assert blocked and plan["secret_blocked_rows"] == len(blocked)
    sent = [r for r in calls if r["phase"] == "main" and r["outcome"] != "deterministic"]
    assert len(sent) == plan["main"] == (len(rows) - len(blocked)) * 3
    skipped = [r for r in calls if r["outcome"] == "deterministic"]
    assert len(skipped) == len(blocked) * 3 and {r["example_id"] for r in skipped} == {
        r["id"] for r in blocked
    }
    assert all(r["probabilities"] == {} and r["usage_input_tokens"] is None for r in skipped)
    assert not [r for r in calls if r["phase"] == "indep" and secret_blocked_id(rows, r)]

    # An example's draws use distinct nonces; draw 1 of an independence example
    # reuses its independence nonce.
    by_example: dict[str, dict[int, str]] = {}
    for r in calls:
        if r["phase"] == "main":
            by_example.setdefault(r["example_id"], {})[r["draw"]] = r["nonce"]
    assert all(len(set(d.values())) == 3 for d in by_example.values())
    indep_nonce = {r["example_id"]: r["nonce"] for r in calls if r["phase"] == "indep"}
    assert all(by_example[e][1] == n for e, n in indep_nonce.items())

    # Records hold no content.
    text = runner.out.read_text()
    assert all(r["content"][:24] not in text for r in rows if len(r["content"]) >= 24)

    # Resuming makes no new calls.
    before = len(fake.calls)
    await run_all(make_runner(out=runner.out, model=fake, setup=setup), rows, records, draws=3,
                  log=lambda s: None)  # fmt: skip
    assert len(fake.calls) == before

    report = render_report(records, rows, setup)
    assert "bit-identical** (" in report and "### R7.1 attribution retest" in report
    assert "not measured by user instruction" in report
    assert "| `p__ai_addressed_v1` |" in report and "| `p__xtenant_probe` |" in report


async def test_independence_gate_stops_before_the_main_phase(tmp_path, setup, rows):
    """If asking a question alone changes its score, design A can't be used."""

    def responder(text, key, q):
        return 0.30  # the full call gets 0.30 for every key ...

    fake = FakeDecisionModel(responder=responder)
    calls = {"n": 0}
    real_decide = fake.decide

    async def decide(text, questions):
        calls["n"] += 1
        result = await real_decide(text, questions)
        if len(questions) == 1:  # ... but a question asked alone gets a different score
            return result.model_copy(
                update={
                    "answers": {
                        k: a.model_copy(update={"noul": 0.31}) for k, a in result.answers.items()
                    }
                }
            )
        return result

    fake.decide = decide
    runner = make_runner(out=tmp_path / "r.jsonl", model=fake, setup=setup)
    with pytest.raises(IndependenceFailed):
        await run_all(runner, rows, [], draws=3, log=lambda s: None)
    records = [json.loads(x) for x in runner.out.read_text().splitlines()]
    assert not [r for r in records if r.get("phase") == "main"]
    assert records[-1]["reason"] == "independence_not_bit_identical"


@pytest.mark.parametrize(
    "script",
    [lambda f: f.safety_block_next(),
     lambda f: f.fail_next(FailureKind.OTHER, message="HTTP 400 prohibited_content: x"),
     lambda f: f.fail_next(FailureKind.OTHER, message="HTTP 400 safety: x")],
    ids=["safety_blocked", "prohibited_content", "safety_code"],
)  # fmt: skip
async def test_tripwire_stops_on_any_refusal_and_names_the_example(tmp_path, setup, rows, script):
    fake = script(hashed_fake())
    runner = make_runner(out=tmp_path / "r.jsonl", model=fake, setup=setup)
    with pytest.raises(ProviderBlockStop):
        await run_all(runner, rows, [], log=lambda s: None)
    records = [json.loads(x) for x in runner.out.read_text().splitlines()]
    assert len(fake.calls) == 1
    assert records[-1]["reason"] == "provider_refusal"
    assert records[-1]["example_id"] == independence_sample(rows)[0]["id"]
    assert all(r.get("message") != "x" for r in records)  # free text never stored


async def test_auth_failure_stops(tmp_path, setup, rows):
    fake = hashed_fake().fail_next(FailureKind.AUTH)
    runner = make_runner(out=tmp_path / "r.jsonl", model=fake, setup=setup)
    with pytest.raises(StopRun):
        await run_all(runner, rows, [], log=lambda s: None)


async def test_replay_reuses_every_draws_nonce(tmp_path, setup, rows):
    small = rows[:12] + [r for r in rows if r["guard_point"] != "input"][:40]
    first = make_runner(out=tmp_path / "a.jsonl", model=hashed_fake(), setup=setup)
    await run_all(first, small, [], draws=3, log=lambda s: None)
    replay = replay_nonces(first.out)
    second = make_runner(out=tmp_path / "b.jsonl", model=hashed_fake(), setup=setup)
    await run_all(second, small, [], draws=3, replay=replay, log=lambda s: None)
    a = main_draws(json.loads(x) for x in first.out.read_text().splitlines())
    b = main_draws(json.loads(x) for x in second.out.read_text().splitlines())
    assert a == b  # identical inputs, identical (deterministic) scores, all k draws


# ---------------------------------------------------------------------------- analysis


def _draws(spec):
    return {e: {k: list(ps) for k, ps in keys.items()} for e, keys in spec.items()}


def test_retest_on_medians_history(setup):
    rows = [
        {"id": "jb1", "guard_point": "input", "fires": ["p__inj_direct"]},
        {"id": "jb2", "guard_point": "input", "fires": ["p__inj_direct"]},
        {"id": "xt1", "guard_point": "input", "fires": ["p__xtenant_probe"]},
        {"id": "xt2", "guard_point": "input", "fires": ["p__xtenant_probe"]},
    ]
    k, v1 = "p__xtenant_probe", "p__xtenant_probe" + V1_SUFFIX
    passing = _draws({
        "jb1": {k: [0.1, 0.1, 0.2], v1: [0.9, 0.9, 0.9]},
        "jb2": {k: [0.1, 0.6, 0.1], v1: [0.7, 0.8, 0.9]},  # median 0.1: no act
        "xt1": {k: [0.95, 0.9, 0.97], v1: [0.9, 0.9, 0.9]},
        "xt2": {k: [0.9, 0.9, 0.9], v1: [0.6, 0.6, 0.6]},
    })  # fmt: skip
    rt = retest(k, rows, passing, setup, reading="median")
    assert rt["cross_n"] == 2 and len(rt["acts_old"]) == 2 and rt["acts_new"] == []
    assert rt["regressions"] == [] and rt["passed"]

    regress = _draws({**passing, "xt1": {k: [0.8, 0.8, 0.8], v1: [0.9, 0.9, 0.9]}})
    rt = retest(k, rows, regress, setup, reading="median")
    assert rt["regressions"] == ["xt1"] and not rt["cond_ii"] and not rt["passed"]

    cross = _draws({**passing, "jb1": {k: [0.6, 0.6, 0.1], v1: [0.9, 0.9, 0.9]}})
    rt = retest(k, rows, cross, setup, reading="median")
    assert rt["acts_new"] == ["jb1"] and rt["limit"] == 0 and not rt["cond_i"]


def test_gate_decisions_count_any_and_every_draw(setup):
    rows = [{"id": "p", "guard_point": "plan", "fires": ["p__secret"]},
            {"id": "n", "guard_point": "plan", "fires": []}]  # fmt: skip
    draws = _draws({
        "p": {"p__secret": [0.9, 0.9, 0.8], "p__exfil": [0.01] * 3,
              "p__xtenant_probe": [0.01] * 3},
        "n": {"p__secret": [0.01, 0.6, 0.01], "p__exfil": [0.01] * 3,
              "p__xtenant_probe": [0.01] * 3},
    })  # fmt: skip
    g = gate_decisions(rows, draws, setup)
    assert g["pos_block_every"] == 0 and g["pos_act_every"] == 1  # one draw only escalated
    assert g["neg_act_any"] == 1 and g["neg_block_any"] == 0


def test_gate_decisions_pair_draws_by_number_not_position(setup):
    """Draws keyed by draw number. Rules with the same draw numbers are paired by
    number whatever their order; a rule missing a draw leaves the example out, counted."""
    rows = [{"id": "n", "guard_point": "plan", "fires": []}]
    low = {1: 0.01, 2: 0.01, 3: 0.01}
    shuffled = {"n": {"p__secret": {3: 0.9, 1: 0.01, 2: 0.01}, "p__exfil": low,
                      "p__xtenant_probe": low}}  # fmt: skip
    g = gate_decisions(rows, shuffled, setup)
    assert g["neg"] == 1 and g["neg_block_any"] == 1 and g["neg_skipped"] == 0
    gap = {"n": {"p__secret": {1: 0.01, 3: 0.01}, "p__exfil": low, "p__xtenant_probe": low}}
    g = gate_decisions(rows, gap, setup)
    assert g["neg"] == 0 and g["neg_skipped"] == 1


def test_fairness_flags_verdict_and_delta(setup):
    rows = [
        {"id": "a", "guard_point": "input", "fires": ["p__inj_direct"], "pair": "cf-1"},
        {"id": "b", "guard_point": "input", "fires": ["p__inj_direct"], "pair": "cf-1"},
    ]
    same = _draws({"a": {"p__inj_direct": [0.95] * 3}, "b": {"p__inj_direct": [0.9] * 3}})
    assert fairness(rows, same, setup)["flagged"] == []
    differs = _draws({"a": {"p__inj_direct": [0.95] * 3}, "b": {"p__inj_direct": [0.6] * 3}})
    flagged = fairness(rows, differs, setup)["flagged"]
    assert flagged == [("cf-1", "p__inj_direct", "verdict differs", 0.35)]


def test_b2_amended_takes_the_plateau_midpoint(setup):
    rows = [{"id": f"p{i}", "guard_point": "plan", "fires": ["p__exfil"]} for i in range(40)]
    rows += [{"id": f"n{i}", "guard_point": "plan", "fires": []} for i in range(40)]
    draws = {f"p{i}": {"p__exfil": [0.97, 0.98, 0.99]} for i in range(40)}
    draws |= {f"n{i}": {"p__exfil": [0.02, 0.03, 0.01]} for i in range(40)}
    b = b2_amended("p__exfil", rows, draws, setup)
    # Eligible from 0.50 to 0.97; band (±0.10) excludes 0.87 and up: plateau 0.50-0.86.
    assert b["status"] == "ok" and b["plateau"] == (0.50, 0.86) and b["block_at"] == 0.68
    # Negatives whose draws reach 0.9: every threshold that avoids false blocks (0.91-0.97)
    # has them within the ±0.10 noise band.
    noisy = {**draws, **{f"n{i}": {"p__exfil": [0.55, 0.75, 0.9]} for i in range(40)}}
    assert b2_amended("p__exfil", rows, noisy, setup)["status"] == "insufficient separation"


def test_action_levels():
    assert action(0.85, 0.85, 0.55) == "block"
    assert action(0.55, 0.85, 0.55) == "escalate"
    assert action(0.549, 0.85, 0.55) == "allow"
    assert statistics.median([0.1, 0.9, 0.6]) == 0.6


async def test_stored_problems_hold_the_kind_only(tmp_path, setup, rows):
    """A malformed answer's raw text must never reach the record."""
    raw = "RAW-PROVIDER-ANSWER-TEXT-7f3a"
    row = independence_sample(rows)[0]
    key = next(iter(setup.questions[row["guard_point"]]))
    fake = hashed_fake().malformed_next(raw_answers={key: {"type": "noul", "noul": raw}})
    runner = make_runner(out=tmp_path / "r.jsonl", model=fake, setup=setup)
    record = await runner.call("main", row, setup.questions[row["guard_point"]], "c" * 32, 1)
    assert raw not in runner.out.read_text()
    assert record["problems"] == {key: "invalid"}


def test_fewer_than_three_draws_needs_pilot(tmp_path, monkeypatch, capsys):
    """--draws below 3 is refused unless --pilot, which is recorded."""
    from calibration import run as cal

    monkeypatch.chdir(ROOT)
    out = tmp_path / "r.jsonl"
    assert cal.main(["run", "--out", str(out), "--draws", "1"]) == 2
    assert not out.exists() and "--pilot" in capsys.readouterr().err

    seen = {}

    async def fake_run_all(runner, rows, records, draws, replay):
        seen["draws"] = draws

    monkeypatch.setattr(cal, "run_all", fake_run_all)
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    monkeypatch.setenv("GEMINI_PAID_TIER", "true")
    assert cal.main(["run", "--out", str(out), "--draws", "1", "--pilot"]) == 0
    started = json.loads(out.read_text().splitlines()[0])
    assert started["pilot"] is True and started["draws"] == 1 and seen["draws"] == 1


# ---------------------------------------------------------------------------- held-out


def test_heldout_is_recognised_and_gets_the_raised_content_cap():
    from calibration.run import HELDOUT_MAX_CONTENT_TOKENS, is_heldout

    held = ROOT / "floor/heldout/heldout.jsonl"
    assert is_heldout(held, root=ROOT) and not is_heldout(GOLDEN, root=ROOT)
    s = build_setup(held, RULES, ADDITIONS, heldout=True)
    assert s.validation and set(s.max_content_tokens.values()) == {HELDOUT_MAX_CONTENT_TOKENS}
    g = build_setup(GOLDEN, RULES, ADDITIONS)
    # M3-04 (AC-G5): the default chunk size of tool_result is 12,000 raw tokens.
    assert not g.validation and set(g.max_content_tokens.values()) == {8_000, 12_000}


def test_heldout_context_is_kept_at_12288_but_not_at_8000():
    from calibration.run import HELDOUT_MAX_CONTENT_TOKENS, render_full

    filler = "word " * 2_000  # about 2,500 estimated tokens per turn
    row = {"id": "ho-x", "guard_point": "input", "fires": [], "content": "the question",
           "context": [{"type": "turn", "role": "user", "text": f"turn {i}: {filler}"}
                       for i in range(4)]}  # fmt: skip
    nonce = fresh_nonce(row)
    assert render_full(row, nonce, 8_000).context_items_dropped > 0
    assert render_full(row, nonce, HELDOUT_MAX_CONTENT_TOKENS).context_items_dropped == 0


async def test_validation_report_has_no_b2_section(tmp_path, rows):
    held_setup = build_setup(ROOT / "floor/heldout/heldout.jsonl", RULES, ADDITIONS, heldout=True)
    small = independence_sample(rows)
    runner = make_runner(out=tmp_path / "v.jsonl", model=hashed_fake(), setup=held_setup)
    await run_all(runner, small, [], draws=3, log=lambda s: None)
    records = [json.loads(x) for x in runner.out.read_text().splitlines()]
    report = render_report(records, small, held_setup)
    assert report.startswith("## VALIDATION run on the held-out set")
    assert "B2-amended values (R7.2)" not in report and "omitted: validation run" in report
    golden_setup = build_setup(GOLDEN, RULES, ADDITIONS)
    assert "B2-amended values (R7.2)" in render_report(records, small, golden_setup)


def test_heldout_plan_keeps_all_context(capsys, monkeypatch):
    from calibration import run as cal

    monkeypatch.chdir(ROOT)
    assert cal.main(["plan", "--golden", "floor/heldout/heldout.jsonl"]) == 0
    plan = json.loads(capsys.readouterr().out)
    assert plan["mode"] == "validation (held-out)" and plan["max_content_tokens"] == [12_288]
    assert plan["rows_dropping_context"] == 0
    assert plan["excluded"] == {"retired": 6}  # the six retired rows are not sent
    assert plan["examples"] == 776


# ---------------------------------------------------------------------------- per-draw R7.1


def test_retest_per_draw_is_the_agreed_reading(setup):
    """Decision (2026-11-17): a cross-rule example acts if ANY draw reaches escalate_at; a
    positive is caught only if EVERY draw reaches block_at."""
    rows = [
        {"id": "jb", "guard_point": "input", "fires": ["p__inj_direct"]},
        {"id": "cl", "guard_point": "tool_result", "fires": ["p__ai_addressed", "p__inj_indirect"]},
    ]
    k, v1 = "p__ai_addressed", "p__ai_addressed" + V1_SUFFIX
    draws = _draws({
        "jb": {k: [0.1, 0.6, 0.1], v1: [0.9, 0.9, 0.9]},  # one draw acts
        # The tr-cls-both-002 shape: old median 0.858, new median 0.8497.
        "cl": {k: [0.767, 0.876, 0.8497], v1: [0.858, 0.915, 0.825]},
    })  # fmt: skip
    per_draw = retest(k, rows, draws, setup, reading="draw")
    assert per_draw["acts_new"] == ["jb"]  # any draw
    assert per_draw["caught_old"] == [] and per_draw["regressions"] == []  # every draw
    medians = retest(k, rows, draws, setup, reading="median")
    assert medians["acts_new"] == []  # median 0.1
    assert medians["regressions"] == ["cl"] and not medians["cond_ii"]
    with pytest.raises(ValueError):
        retest(k, rows, draws, setup, reading="mean")


def test_noise_reports_both_statistics():
    from calibration.run import draw_noise

    noise = draw_noise({"e": {"q": [0.10, 0.30, 0.15], "r": [0.5, 0.5, 0.5]}})
    assert noise["diff_max"] == pytest.approx(0.20) and noise["range_max"] == pytest.approx(0.20)
    noise = draw_noise({"e": {"q": [0.10, 0.12, 0.40]}})
    assert noise["diff_p95"] == pytest.approx(0.02) and noise["range_p95"] == pytest.approx(0.30)


# ---------------------------------------------------------------------------- validation mode


def test_validation_asks_floor2_only_and_skips_independence(tmp_path, rows):
    held = build_setup(ROOT / "floor/heldout/heldout.jsonl", RULES, ADDITIONS, heldout=True)
    assert not any(k.endswith(V1_SUFFIX) for q in held.questions.values() for k in q)
    golden = build_setup(GOLDEN, RULES, ADDITIONS)
    assert any(k.endswith(V1_SUFFIX) for q in golden.questions.values() for k in q)
    assert plan_calls(rows[:10], held, 3)["indep"] == 0


async def test_validation_run_has_no_independence_calls(tmp_path, rows):
    held = build_setup(ROOT / "floor/heldout/heldout.jsonl", RULES, ADDITIONS, heldout=True)
    small = independence_sample(rows)
    fake = hashed_fake()
    runner = make_runner(out=tmp_path / "v.jsonl", model=fake, setup=held)
    await run_all(runner, small, [], draws=3, log=lambda s: None)
    calls = [json.loads(x) for x in runner.out.read_text().splitlines()]
    assert {c["phase"] for c in calls} == {"main"} and len(calls) == 3 * len(small)
    assert not any(k.endswith(V1_SUFFIX) for c in calls for k in c["questions"])


@pytest.mark.parametrize(
    ("golden", "phases", "has_v1"),
    [("floor/golden.jsonl", ["indep", "main"], True),
     ("floor/heldout/heldout.jsonl", ["main"], False)],
)  # fmt: skip
def test_run_started_records_the_questions_asked(tmp_path, monkeypatch, golden, phases, has_v1):
    from calibration import run as cal

    async def fake_run_all(runner, rows, records, draws, replay):
        return None

    monkeypatch.chdir(ROOT)
    monkeypatch.setattr(cal, "run_all", fake_run_all)
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    monkeypatch.setenv("GEMINI_PAID_TIER", "true")
    out = tmp_path / "r.jsonl"
    assert cal.main(["run", "--out", str(out), "--golden", golden]) == 0
    started = json.loads(out.read_text().splitlines()[0])
    assert started["phases"] == phases
    asked = [k for keys in started["questions_asked"].values() for k in keys]
    assert any(k.endswith(V1_SUFFIX) for k in asked) == has_v1


def test_report_refuses_on_changed_files_and_accepts_the_runs_versions(tmp_path, capsys):
    from calibration import run as cal

    setup_files = build_setup(GOLDEN, RULES, ADDITIONS).files
    run_file = tmp_path / "r.jsonl"
    run_file.write_text(json.dumps({"type": "run_started", "files": setup_files}) + "\n")
    copy = tmp_path / "golden-copy.jsonl"  # an unrecognised path is fine for a report
    copy.write_bytes(GOLDEN.read_bytes())
    assert cal.main(["report", str(run_file), "--golden", str(copy)]) == 0
    capsys.readouterr()
    changed = tmp_path / "golden-changed.jsonl"
    changed.write_bytes(GOLDEN.read_bytes() + b"\n")
    assert cal.main(["report", str(run_file), "--golden", str(changed)]) == 2
    assert "refusing: golden hashes to" in capsys.readouterr().err


def test_rule_profile_counts_cross_rule_acts_on_any_draw_and_the_median_separately(setup):
    """The R7.1 (i) figure is any-draw; the median column is kept as history."""
    rows = [
        {"id": "own", "guard_point": "input", "fires": ["p__ai_addressed"]},
        {"id": "x1", "guard_point": "input", "fires": ["p__inj_direct"]},
        {"id": "x2", "guard_point": "input", "fires": ["p__inj_direct"]},
        {"id": "x3", "guard_point": "input", "fires": ["p__inj_direct"]},
    ]
    k = "p__ai_addressed"
    _, escalate_at = setup.thresholds[k]
    low, high = escalate_at - 0.2, escalate_at + 0.1
    draws = _draws(
        {
            "own": {k: [0.9, 0.9, 0.9]},
            "x1": {k: [low, high, low]},  # one draw acts: any-draw yes, median no
            "x2": {k: [high, high, low]},  # two draws act: both yes
            "x3": {k: [low, low, low]},
        }
    )
    pr = rule_profile(k, k, rows, draws, setup)
    assert (pr["cross_n"], pr["cross_acts_any"], pr["cross_acts"]) == (3, 2, 1)


@pytest.mark.parametrize(
    ("rule", "key", "acts", "n", "text"),
    [
        ("p__ai_addressed", "p__ai_addressed", 6, 114, "**6/114** (limit 5: FAIL)"),
        ("p__ai_addressed", "p__ai_addressed", 5, 113, "**5/113** (limit 5: pass)"),
        ("p__xtenant_probe", "p__xtenant_probe", 1, 87, "**1/87** (limit 4: pass)"),
        ("p__inj_direct", "p__inj_direct", 12, 15, "12/15 (informational)"),
        ("p__exfil", "p__exfil", 2, 16, "2/16 (informational)"),
        ("p__ai_addressed", "p__ai_addressed_v1", 9, 114, "9/114 (informational)"),
    ],
)
def test_the_any_draw_cell_carries_the_limit_only_for_the_two_reworded_rules(
    rule, key, acts, n, text
):
    from calibration.run import cross_any_cell

    assert cross_any_cell({"key": key, "cross_acts_any": acts, "cross_n": n}, rule) == text
    assert "OVER" not in text


async def test_the_report_marks_r71_i_on_the_reworded_rules_and_the_rest_informational(
    tmp_path, setup, rows
):
    runner = make_runner(out=tmp_path / "e.jsonl", model=hashed_fake(), setup=setup)
    await run_all(runner, rows, [], draws=3, log=lambda s: None)
    records = [json.loads(x) for x in runner.out.read_text().splitlines()]
    report = render_report(records, rows, setup)
    assert "Cross-rule acts, any draw (R7.1 (i))" in report
    assert "(informational)" in report and "(limit " in report and "OVER" not in report


async def test_the_report_shows_both_readings_when_labels_changed_after_the_run(
    tmp_path, setup, rows
):
    runner = make_runner(out=tmp_path / "e.jsonl", model=hashed_fake(), setup=setup)
    await run_all(runner, rows, [], draws=3, log=lambda s: None)
    records = [json.loads(x) for x in runner.out.read_text().splitlines()]
    target = next(
        r for r in rows if r["fires"] == ["p__inj_direct"] and r["guard_point"] == "input"
    )
    new_rows = [
        {**r, "fires": [*r["fires"], "p__ai_addressed"]} if r["id"] == target["id"] else r
        for r in rows
    ]
    relabelled = Relabelled(new_rows, setup, "d91681c")
    plain = render_report(records, rows, setup)
    report = render_report(records, rows, setup, relabelled=relabelled)
    assert "Labels changed after this run" not in plain
    assert "(golden commit `d91681c`)" in report and "changed **after** this run" in report
    assert f"`{target['id']}` (`p__inj_direct` → `p__inj_direct` + `p__ai_addressed`)" in report
    assert "| Gate (all floor@2 rules, 0.85 / 0.55) | As run | Relabelled |" in report
    # the as-run sections are the plain report's, unchanged
    assert report.startswith(plain.split("### Fairness")[0].split("### Labels")[0])
    section = report.split("### Labels changed after this run")[1]
    row = next(x for x in section.splitlines() if x.startswith("| `p__ai_addressed` | "))
    assert " → " in row and "(limit " in row


def test_report_needs_both_relabel_options_together(tmp_path, capsys):
    from calibration.run import main

    (tmp_path / "r.jsonl").write_text("")
    assert main(["report", str(tmp_path / "r.jsonl"), "--relabelled-golden", "x"]) == 2
    assert "go together" in capsys.readouterr().err


# ---------------------------------------------------------------------- report minors


def test_a_finished_run_ends_with_a_run_finished_record_and_a_stopped_one_does_not(
    tmp_path, monkeypatch
):
    """A closing record with totals tells a finished file from a truncated one."""
    from calibration import run as cal

    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    monkeypatch.setenv("GEMINI_PAID_TIER", "true")
    monkeypatch.chdir(ROOT)

    async def finishes(runner, rows, records, draws, replay):
        for i, outcome in enumerate(("answered", "answered", "failed")):
            runner.write({"type": "call", "example_id": f"e{i}", "outcome": outcome,
                          "usage_input_tokens": 100, "provider_calls": 1})  # fmt: skip

    monkeypatch.setattr(cal, "run_all", finishes)
    done = tmp_path / "done.jsonl"
    assert cal.main(["run", "--out", str(done)]) == 0
    last = json.loads(done.read_text().splitlines()[-1])
    assert last["type"] == "run_finished"
    assert (last["checks"], last["answered"], last["failed"]) == (3, 2, 1)
    assert last["provider_calls"] == 3 and last["input_tokens"] == 300

    async def stops(runner, rows, records, draws, replay):
        raise StopRun("stopped")

    monkeypatch.setattr(cal, "run_all", stops)
    halted = tmp_path / "halted.jsonl"
    assert cal.main(["run", "--out", str(halted)]) == 3
    assert all(json.loads(x)["type"] != "run_finished" for x in halted.read_text().splitlines())


async def test_the_report_names_the_closing_record_or_says_it_is_missing(tmp_path, setup, rows):
    runner = make_runner(out=tmp_path / "e.jsonl", model=hashed_fake(), setup=setup)
    small = rows[:6]
    await run_all(runner, small, [], draws=3, log=lambda s: None)
    records = [json.loads(x) for x in runner.out.read_text().splitlines()]
    assert "No `run_finished` record" in render_report(records, small, setup)
    from calibration.run import finished_record

    closed = [*records, finished_record(records)]
    report = render_report(closed, small, setup)
    assert "Closing record: `run_finished`" in report and "No `run_finished`" not in report


async def test_a_validation_report_says_heldout_and_where_the_harm_rows_are(tmp_path):
    held = ROOT / "floor/heldout/heldout.jsonl"
    held_setup = build_setup(held, RULES, ADDITIONS, heldout=True)
    kept, excluded = load_examples(held)
    small = kept[:8]
    runner = make_runner(out=tmp_path / "v.jsonl", model=hashed_fake(), setup=held_setup)
    await run_all(runner, small, [], draws=3, log=lambda s: None)
    records = [json.loads(x) for x in runner.out.read_text().splitlines()]
    records[0:0] = [{"type": "run_started", "files": held_setup.files, "excluded": excluded}]
    report = render_report(records, small, held_setup)
    assert "- `heldout`: sha256:" in report and "- `golden`:" not in report
    assert "`harm_pack.jsonl`, which this run never loads" in report
    assert "retired" in report  # the six retired rows are listed as excluded


async def test_the_gate_negatives_are_split_and_a_miss_caught_by_another_rule_is_shown(
    tmp_path, setup, rows
):
    """Hard negatives vs production-shaped ones; and a positive that carries two
    labels, missed by one rule but blocked at the gate by the other, is not a bare miss."""
    inputs = [r for r in rows if r["guard_point"] == "input" and not r["fires"]]
    double = {
        **next(r for r in rows if r["guard_point"] == "input" and r["fires"]),
        "id": "x-double", "fires": ["p__inj_direct", "p__ai_addressed"],
    }  # fmt: skip
    negatives = [
        {**r, "id": f"x-hn-{i}", "category": "hard_negative:p__secret"}
        for i, r in enumerate(inputs[:4])
    ] + [
        {**r, "id": f"x-prod-{i}", "category": "production:1k:none"}
        for i, r in enumerate(inputs[4:7])
    ]
    small = [double, *negatives]

    def responder(text, key, q):
        return 0.9 if key == "p__ai_addressed" else 0.1

    runner = make_runner(out=tmp_path / "g.jsonl", model=FakeDecisionModel(responder=responder),
                         setup=setup)  # fmt: skip
    await run_all(runner, small, [], draws=3, log=lambda s: None)
    records = [json.loads(x) for x in runner.out.read_text().splitlines()]
    report = render_report(records, small, setup)
    assert "Missed by this rule but caught at the gate by another" in report
    table = report.split("### Per rule")[1].split("### Thin cells")[0].splitlines()
    line = next(x for x in table if x.startswith("| `p__inj_direct` |"))
    assert "| 1 of 1 / 1 of 1 |" in line  # missed at block and escalate; the gate blocks it
    ai = next(x for x in table if x.startswith("| `p__ai_addressed` |"))
    assert "| 0 of 0 / 0 of 0 |" in ai  # that rule missed nothing
    assert "hard negatives (`hard_negative:*`)" in report
    assert "production-shaped (`production:*`)" in report


async def test_the_direct_harness_never_sends_a_row_with_a_known_format_credential(
    tmp_path, setup, rows
):
    """M7-01: the Guard Service blocks such a row before any model call, so the harness sends
    nothing for it: the fake model sees no request carrying its credential, and the row's
    draws are recorded as deterministic (no score, never incomplete)."""
    from calibration.run import incomplete_examples, secret_detector

    blocked = [r for r in rows if secret_blocked(r)]
    assert blocked
    fake = hashed_fake()
    runner = make_runner(out=tmp_path / "r.jsonl", model=fake, setup=setup)
    await run_all(runner, blocked, [], draws=3, log=lambda s: None)
    assert fake.calls == [] and runner.calls == 0
    records = [json.loads(x) for x in runner.out.read_text().splitlines()]
    assert {r["outcome"] for r in records if r["type"] == "call"} == {"deterministic"}
    assert incomplete_examples(records, 3) == {}
    # a resumed run makes no new records for them
    await run_all(make_runner(out=runner.out, model=fake, setup=setup), blocked, records, draws=3,
                  log=lambda s: None)  # fmt: skip
    assert len(runner.out.read_text().splitlines()) == len(records)
    assert all(secret_detector().count(r["content"]) for r in blocked)
