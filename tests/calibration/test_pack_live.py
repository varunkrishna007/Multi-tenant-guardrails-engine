"""M4-08 pack calibration harness (calibration/pack_live.py), offline. The dry run goes through
the same code as a live run with the engine's fake model. No live call, no key."""

import asyncio
import json
from pathlib import Path

import pytest
from calibration.engine_path import SeededNonces
from calibration.pack_live import (
    LIVE_KEY,
    LIVE_TOKEN,
    NEVER_SENT_RULES,
    PACKS,
    PackRunner,
    Refused,
    build_report,
    check_pack_corpus,
    load_api_key,
    load_sendable,
    main,
    pace_interval_s,
    pack_engine,
    pack_problems,
    plan,
    render_markdown,
    row_strings,
    send_refusal,
)
from calibration.run import StopRun

from calibration import pack_live
from guardrail_engine.decision import FakeDecisionModel
from guardrail_engine.decision.port import SafetyBlocked

ROOT = Path(__file__).resolve().parents[2]
SENDABLE = {
    "insurance": (227, 33),
    "energy": (228, 24),
    "finance": (224, 0),
    "healthcare": (204, 20),
}
BAD_WORD = "method"  # on the engine's harm word list (the tripwire is coarse on purpose)


def records_of(path):
    return [json.loads(x) for x in path.read_text().splitlines()]


# ------------------------------------------------------------------ what may be sent


@pytest.mark.parametrize("pack", sorted(PACKS))
def test_only_the_sendable_rows_load_and_each_passes_every_send_time_check(pack):
    rows, excluded = load_sendable(pack)
    sendable, withheld = SENDABLE[pack]
    assert len(rows) == sendable
    assert excluded == ({"tagged no_live_run": withheld} if withheld else {})
    assert all(r["no_live_run"] is False and send_refusal(r) is None for r in rows)
    assert not any(NEVER_SENT_RULES & set(r["fires"]) for r in rows)
    assert {r["tenant_id"] for r in rows} == {PACKS[pack][0]}


@pytest.mark.parametrize(
    "path",
    [
        "floor/golden.jsonl",
        "floor/heldout/heldout.jsonl",
        "packs/responsible_ai/golden.jsonl",
        "redteam/corpus.jsonl",
        "packs/insurance/pack.json",
    ],
)
def test_no_corpus_but_the_two_pack_golden_sets_is_accepted(path):
    with pytest.raises(Refused):
        check_pack_corpus(ROOT / path)
    for pack in PACKS:
        check_pack_corpus(ROOT / "packs" / pack / "golden.jsonl")
    with pytest.raises(Refused):
        pack_live.corpus_path("responsible_ai")


def row(**changes):
    base = {"id": "x-001", "guard_point": "output", "category": "c", "content": "A plain sentence.",
            "fires": [], "tenant_id": "t_1042", "tenant_slug": "acme-insurance",
            "no_live_run": False}  # fmt: skip
    return {**base, **changes}


def test_a_row_is_refused_for_each_reason_and_the_reason_never_quotes_it():
    assert send_refusal(row()) is None
    cases = {
        "withheld": row(no_live_run=True),
        "missing key": {k: v for k, v in row().items() if k != "no_live_run"},
        "truthy-not-false": row(no_live_run=0),
        "fraud": row(fires=["d__ins_fraud_signal"]),
        "unsafe advice": row(fires=["d__en_unsafe_advice"]),
        "harm facilitation": row(fires=["d__harm_facilitation"]),
        "harm id": row(id="x-harm-001"),
        "retired": row(retired=True),
        "tripwire in content": row(content=f"The {BAD_WORD} is simple."),
        "tripwire in context": row(context=[{"type": "turn", "role": "user", "text": BAD_WORD}]),
        "tripwire in a tool": row(tools=[{"name": "t", "description": f"a {BAD_WORD}"}]),
    }
    for name, case in cases.items():
        why = send_refusal(case)
        assert why, name
        assert BAD_WORD not in why and "plain sentence" not in why


def test_the_pack_text_is_clean_and_the_responsible_ai_pack_is_not_sendable_here():
    assert all(pack_problems(p) == [] for p in PACKS)
    assert any("harm facilitation" in x for x in pack_problems("responsible_ai"))
    assert row_strings(row(context=[{"type": "turn", "role": "u", "text": "hi"}])) == [
        "A plain sentence.", "u", "hi"
    ]  # fmt: skip


# ------------------------------------------------------------------ the plan and the dry run


@pytest.mark.parametrize("pack", sorted(PACKS))
def test_the_plan_names_the_bundle_the_cost_and_a_pace_under_the_allowance(pack):
    p = plan(pack, 3, "ab" * 16)
    assert p["bundle_extends"] == [f"platform/floor@{p['floor_version']}", f"domain/{pack}@1"]
    assert not any("responsible" in e for e in p["bundle_extends"])
    assert p["checks"] == 3 * SENDABLE[pack][0] and p["environment"] == "test"
    assert 600_000 < p["estimated_input_tokens"] < 1_000_000
    assert p["estimated_cost_usd"] < 0.10 and p["min_interval_s"] >= 1.5
    assert p["pack_problems"] == [] and not any(p["would_exceed_a_limit"].values())


def test_the_pace_is_never_faster_than_the_floor_and_slows_for_big_checks():
    rows = [{"id": "a"}]
    assert pace_interval_s({"a": 100}, rows) == 1.5
    assert pace_interval_s({"a": 10_000}, rows) > 1.5
    assert pace_interval_s({}, []) == 1.5


@pytest.mark.parametrize("pack", sorted(PACKS))
def test_a_dry_run_sends_only_sendable_rows_through_the_engine_and_reports(tmp_path, pack):
    out = tmp_path / "run.jsonl"
    assert main(["run", "--pack", pack, "--out", str(out)]) == 0
    recs = records_of(out)
    rows, excluded = load_sendable(pack)
    started = recs[0]
    assert started["type"] == "run_started" and started["mode"] == "dry-run"
    assert started["usage_class"] == "calibration" and started["not_sent"] == excluded
    assert started["bundle_extends"][1] == f"domain/{pack}@1"
    calls = [r for r in recs if r["type"] == "call"]
    assert len(calls) == 3 * len(rows) and all(r["outcome"] == "answered" for r in calls)
    assert {r["example_id"] for r in calls} == {r["id"] for r in rows}
    assert recs[-1]["type"] == "run_finished" and recs[-1]["checks"] == len(calls)
    keys = {k for r in calls for k in r["probabilities"]}
    own = {r["key"] for r in json.loads(pack_live.pack_path(pack).read_text())["rules"]}
    assert keys and all(k.startswith("p__") or k in own for k in keys), keys
    assert not any("harm_facilitation" in k for k in keys)
    text = out.read_text()
    assert "GEMINI" not in text and "content" not in {k for r in recs for k in r}
    assert not any(r["content"] in text for r in rows)  # no row text is ever recorded
    # and the report reads the same records
    direct, _, _ = pack_live.compile_for(pack)
    from calibration.engine_path import row_token_estimates

    rep = build_report(pack, recs, rows, row_token_estimates(rows, direct))
    assert rep["spend"]["checks"] == 3 * len(rows) and rep["incomplete_examples"] == {}
    assert len(rep["rules"]) == 6 and "$" in render_markdown(rep)


# ------------------------------------------------------------------ the send-time guard


async def test_a_row_that_changes_after_loading_is_refused_before_any_model_call(tmp_path):
    rows, _ = load_sendable("insurance")
    nonces = SeededNonces("cd" * 16)
    model = FakeDecisionModel(default_noul=0.05)
    out = tmp_path / "r.jsonl"
    async with pack_engine("insurance", model, nonces) as (engine, verifier):
        runner = PackRunner(out=out, engine=engine, verifier=verifier, nonces=nonces)
        ok = await runner.check(rows[0], 1)
        assert ok["outcome"] == "answered" and len(model.calls) == 1
        for poisoned in (
            {**rows[1], "content": f"The {BAD_WORD} is simple."},
            {**rows[1], "no_live_run": True},
            {**rows[1], "fires": ["d__ins_fraud_signal"]},
        ):
            with pytest.raises(StopRun):
                await runner.check(poisoned, 1)
        assert len(model.calls) == 1  # none of the three reached the model
    stops = [r for r in records_of(out) if r["type"] == "run_stopped"]
    assert [s["reason"] for s in stops] == ["send_refusal"] * 3
    assert BAD_WORD not in out.read_text()


async def test_the_first_provider_refusal_stops_the_run_and_nothing_is_resent(tmp_path):
    rows, _ = load_sendable("energy")
    nonces = SeededNonces("ef" * 16)
    model = FakeDecisionModel(default_noul=0.05).safety_block_next(reason="prohibited_content")
    out = tmp_path / "r.jsonl"
    async with pack_engine("energy", model, nonces) as (engine, verifier):
        runner = PackRunner(out=out, engine=engine, verifier=verifier, nonces=nonces)
        with pytest.raises(StopRun) as stop:
            await pack_live.run_engine_path(runner, rows, [], draws=3, log=lambda s: None)
    assert "provider refusal" in str(stop.value)
    recs = records_of(out)
    assert [r["type"] for r in recs] == ["call", "run_stopped"]
    assert recs[0]["reason"] == "provider_safety" and recs[1]["reason"] == "provider_refusal"
    assert len(model.calls) == 1


async def test_the_engine_holds_the_floor_and_the_one_pack_and_nothing_else(tmp_path):
    rows, _ = load_sendable("insurance")
    nonces = SeededNonces("01" * 16)
    async with pack_engine("insurance", FakeDecisionModel(default_noul=0.05), nonces) as (e, v):
        runner = PackRunner(out=tmp_path / "r.jsonl", engine=e, verifier=v, nonces=nonces)
        rec = await runner.check(rows[0], 1)
    layers = {k.split("__")[0] for k in rec["probabilities"]}
    assert layers <= {"p", "d"}
    assert not any(
        k.startswith("d__") and not k.startswith("d__ins_") for k in rec["probabilities"]
    )


# ------------------------------------------------------------------ the live gates


@pytest.fixture
def no_key(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "")  # restored afterwards, whatever a test sets
    monkeypatch.delenv(LIVE_KEY, raising=False)
    monkeypatch.setattr(pack_live, "default_env_file", lambda: None)


def live(tmp_path, *extra):
    return ["run", "--pack", "insurance", "--out", str(tmp_path / "live.jsonl"), "--live", *extra]


def test_a_live_run_needs_every_gate_and_sends_nothing_before_they_all_hold(
    tmp_path, no_key, monkeypatch, capsys
):
    ceilings = ["--max-tokens", "1500000", "--max-provider-calls", "1400"]
    assert main(live(tmp_path, *ceilings)) == 2  # no approval token in the environment
    assert LIVE_KEY in capsys.readouterr().err
    monkeypatch.setenv(LIVE_KEY, LIVE_TOKEN)
    assert main(live(tmp_path)) == 2  # no ceilings
    assert "--max-tokens" in capsys.readouterr().err
    assert main(live(tmp_path, "--max-tokens", "1", "--max-provider-calls", "1")) == 2
    assert main(live(tmp_path, *ceilings, "--env-file", str(tmp_path / "none.env"))) == 2
    assert "GEMINI_API_KEY is not set" in capsys.readouterr().err
    assert not (tmp_path / "live.jsonl").exists() or not records_of(tmp_path / "live.jsonl")
    assert main(live(tmp_path, *ceilings, "--draws", "2")) == 2  # fewer than three draws


def test_the_key_is_read_from_the_env_file_and_never_printed(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("GEMINI_API_KEY", "")
    env = tmp_path / ".env"
    env.write_text("OTHER=1\nGEMINI_API_KEY='sekrit-value-123'\n")
    assert load_api_key(env) is True
    import os

    assert os.environ["GEMINI_API_KEY"] == "sekrit-value-123"
    assert "sekrit" not in capsys.readouterr().out + capsys.readouterr().err
    monkeypatch.setenv("GEMINI_API_KEY", "")
    assert load_api_key(tmp_path / "missing") is False and load_api_key(None) is False
    (tmp_path / "empty.env").write_text("GEMINI_API_KEY=\n")
    assert load_api_key(tmp_path / "empty.env") is False


def test_a_stopped_run_cannot_be_resumed_into(tmp_path, no_key):
    out = tmp_path / "run.jsonl"
    out.write_text(json.dumps({"type": "run_stopped", "reason": "provider_refusal"}) + "\n")
    assert main(["run", "--pack", "insurance", "--out", str(out)]) == 2


# ------------------------------------------------------------------ the report's arithmetic


def synthetic(pack, scores):
    """Records of three answered draws for each row, from {row id: {rule: p}}."""
    recs = []
    for rid, ps in scores.items():
        for d in (1, 2, 3):
            recs.append({"type": "call", "example_id": rid, "draw": d, "outcome": "answered",
                         "probabilities": ps, "usage_input_tokens": 1000,
                         "provider_calls": 1})  # fmt: skip
    return recs


def test_the_report_suggests_thresholds_from_the_draws_and_flags_what_it_cannot_measure():
    rule = "d__ins_payout_promise"
    rows = [
        {"id": f"p{i}", "guard_point": "output", "category": "pay", "fires": [rule]}
        for i in range(20)
    ] + [
        {"id": f"n{i}", "guard_point": "output", "category": "pay", "fires": []} for i in range(20)
    ]  # fmt: skip
    scores = {f"p{i}": {rule: 0.9 + 0.004 * i} for i in range(20)}
    scores |= {f"n{i}": {rule: 0.1 + 0.01 * i} for i in range(20)}
    rep = build_report("insurance", synthetic("insurance", scores), rows, {})
    r = next(x for x in rep["rules"] if x["key"] == rule)
    s = r["all"]["suggestion"]
    assert (r["positives"], r["negatives"], r["thin"]) == (20, 20, False)
    assert s["block_at"] == 0.29  # the lowest threshold at precision 1
    assert s["band_empty"] and s["escalate_at"] == 0.28  # recall's 0.90 is not below block_at
    assert r["all"]["at_present"]["block"]["precision"] == 1.0
    assert rep["spend"]["input_tokens"] == 120_000 and rep["spend"]["cost_usd"] == 0.012
    fraud = next(x for x in rep["rules"] if x["key"] == "d__ins_fraud_signal")
    assert fraud["max_action"] == "escalate" and "no sendable positive" in fraud["not_calibratable"]
    assert fraud["all"]["suggestion"]["block_at"] is None  # never a block_at for a capped rule


def test_an_example_short_of_its_draws_is_left_out_not_scored():
    rule = "d__ins_payout_promise"
    rows = [{"id": "a", "guard_point": "output", "category": "pay", "fires": [rule]},
            {"id": "b", "guard_point": "output", "category": "pay", "fires": []}]  # fmt: skip
    recs = synthetic("insurance", {"a": {rule: 0.9}, "b": {rule: 0.1}})
    recs = [r for r in recs if not (r["example_id"] == "b" and r["draw"] == 3)]
    rep = build_report("insurance", recs, rows, {})
    r = next(x for x in rep["rules"] if x["key"] == rule)
    assert rep["incomplete_examples"] == {"b": 2}
    assert r["positives"] == 1 and r["negatives"] == 0 and r["left_out_no_score"] == 1


def test_the_compiled_questions_of_both_packs_hold_no_harm_facilitation_rule():
    for pack in PACKS:
        direct, _, _ = pack_live.compile_for(pack)
        assert pack_live.refuse_harm_facilitation(direct.questions) is None


# ------------------------------------------------------------------ resuming after a ceiling


def test_a_run_stopped_at_a_ceiling_resumes_with_a_higher_one_and_every_check_is_made_once(
    tmp_path, no_key, monkeypatch, capsys
):
    """A token or call ceiling says only that the budget ran out before the next send, so the
    same file can go on with a higher ceiling; each (example, draw) is still sent once."""
    import calibration.engine_path as engine_path

    monkeypatch.setattr(engine_path, "tokens_of", lambda record, estimate: 2500)
    monkeypatch.setattr(pack_live, "tokens_of", lambda record, estimate: 2500)
    out = tmp_path / "run.jsonl"
    base = ["run", "--pack", "insurance", "--out", str(out), "--max-provider-calls", "2000"]
    assert main([*base, "--max-tokens", "760000"]) == 3  # stops before the 305th check
    first = records_of(out)
    assert first[-1]["reason"] == "token_ceiling" and first[-1]["before_sending"] is True
    done = sum(r["type"] == "call" for r in first)
    assert 250 < done < 681
    assert main([*base, "--max-tokens", "760000"]) == 2  # the same ceiling: refused
    assert "higher --max-tokens" in capsys.readouterr().err
    assert main([*base]) == 2  # no ceiling at all: refused too
    assert main([*base, "--max-tokens", "3000000"]) == 0
    recs = records_of(out)
    assert [r["type"] for r in recs if r["type"] in ("run_resumed", "run_finished")] == [
        "run_resumed", "run_finished"
    ]  # fmt: skip
    calls = [(r["example_id"], r["draw"]) for r in recs if r["type"] == "call"]
    assert len(calls) == len(set(calls)) == 681  # nothing sent twice, nothing missed
    assert next(r for r in recs if r["type"] == "run_resumed")["after"] == ["token_ceiling"]


def test_a_run_stopped_for_any_other_reason_is_never_resumed(tmp_path, no_key):
    for reason in ("provider_refusal", "auth", "send_refusal", "failures", "unclassified_failure"):
        out = tmp_path / f"{reason}.jsonl"
        out.write_text(json.dumps({"type": "run_stopped", "reason": reason}) + "\n")
        assert main(["run", "--pack", "insurance", "--out", str(out),
                     "--max-tokens", "9000000"]) == 2, reason  # fmt: skip


# ------------------------------------------------------------------ pack versions


@pytest.mark.parametrize("pack", ["insurance", "energy"])
def test_the_plan_for_version_2_names_the_v2_pack_and_the_same_rows(pack):
    one, two = plan(pack, 3, "ab" * 16), plan(pack, 3, "ab" * 16, version=2)
    assert one["pack"] == f"domain/{pack}@1" and two["pack"] == f"domain/{pack}@2"
    assert two["bundle_extends"][1] == f"domain/{pack}@2" and two["pack_problems"] == []
    assert (two["rows_sendable"], two["checks"]) == (one["rows_sendable"], one["checks"])
    assert not any(two["would_exceed_a_limit"].values())


def test_an_unknown_pack_version_is_refused():
    with pytest.raises(Refused):
        pack_live.pack_path("insurance", 3)
    assert pack_live.pack_path("insurance", 2).name == "pack.v2.json"


def test_a_dry_run_of_version_2_uses_the_v2_pack_and_reports_its_thresholds(tmp_path, capsys):
    out = tmp_path / "v2.jsonl"
    assert main(["run", "--pack", "insurance", "--pack-version", "2", "--out", str(out)]) == 0
    recs = records_of(out)
    started = recs[0]
    assert started["pack"] == "domain/insurance@2" and started["mode"] == "dry-run"
    assert set(started["files"]) == {"golden.jsonl", "pack.v2.json"}
    assert started["bundle_extends"][1] == "domain/insurance@2"
    rows, _ = load_sendable("insurance")
    assert sum(r["type"] == "call" for r in recs) == 3 * len(rows)
    capsys.readouterr()
    assert main(["report", "--pack", "insurance", "--pack-version", "2", str(out), "--json"]) == 0
    v2 = {r["key"]: r for r in json.loads(capsys.readouterr().out)["rules"]}
    assert (v2["d__ins_policy_advice"]["block_at"], v2["d__ins_policy_advice"]["escalate_at"]) == (
        0.5, 0.3
    )  # fmt: skip
    assert main(["report", "--pack", "insurance", str(out), "--json"]) == 0
    v1 = {r["key"]: r for r in json.loads(capsys.readouterr().out)["rules"]}
    assert v1["d__ins_policy_advice"]["block_at"] == 0.8  # the same records, read against @1


def test_a_run_started_on_one_version_is_not_continued_on_the_other(tmp_path, no_key):
    out = tmp_path / "run.jsonl"
    assert main(["run", "--pack", "energy", "--out", str(out)]) == 0
    assert main(["run", "--pack", "energy", "--pack-version", "2", "--out", str(out)]) == 2


def test_the_live_gates_apply_to_version_2_too(tmp_path, no_key):
    args = ["run", "--pack", "energy", "--pack-version", "2", "--out", str(tmp_path / "x.jsonl")]
    assert main([*args, "--live", "--max-tokens", "1000000", "--max-provider-calls", "1365"]) == 2
    assert not (tmp_path / "x.jsonl").exists() or not records_of(tmp_path / "x.jsonl")


# ------------------------------------------------------------ finance, healthcare and --rules


def test_the_withheld_set_is_asserted_at_load_and_the_healthcare_ids_are_the_agreed_twenty():
    assert pack_live.EXPECTED_WITHHELD == {
        "insurance": 33,
        "energy": 24,
        "finance": 0,
        "healthcare": 20,
    }
    assert len(pack_live.HEALTHCARE_WITHHELD) == 20
    rows = [
        json.loads(x)
        for x in (ROOT / "packs" / "healthcare" / "golden.jsonl").read_text().splitlines()
    ]
    assert {r["id"] for r in rows if r["no_live_run"]} == pack_live.HEALTHCARE_WITHHELD
    assert {r["id"] for r in load_sendable("healthcare")[0]}.isdisjoint(
        pack_live.HEALTHCARE_WITHHELD
    )


@pytest.mark.parametrize("change", ["lose_one", "gain_one", "swap_one"])
def test_a_set_whose_withheld_rows_changed_is_not_sent_until_a_person_looks(change, monkeypatch):
    base = dict(pack_live.EXPECTED_WITHHELD)
    if change == "swap_one":  # the count is right, the rows are not
        monkeypatch.setattr(
            pack_live, "HEALTHCARE_WITHHELD",
            frozenset(set(sorted(pack_live.HEALTHCARE_WITHHELD)[1:]) | {"hc-nope-001"}),
        )  # fmt: skip
    else:
        base["healthcare"] += 1 if change == "gain_one" else -1
        monkeypatch.setattr(pack_live, "EXPECTED_WITHHELD", base)
    with pytest.raises(Refused, match="withholds 20 rows"):
        load_sendable("healthcare")


@pytest.mark.parametrize("pack", ["finance", "healthcare"])
def test_the_new_packs_plan_and_pass_every_gate(pack):
    p = plan(pack, 3, "ab" * 16)
    assert p["bundle_extends"][1] == f"domain/{pack}@1" and p["pack_problems"] == []
    assert not any(p["would_exceed_a_limit"].values()) and p["rules"] is None
    assert p["checks"] == 3 * SENDABLE[pack][0] == p["ceiling_checks_with_one_retry"] // 2
    assert 550_000 < p["estimated_input_tokens"] < 800_000 and p["estimated_cost_usd"] < 0.10


def test_the_new_packs_have_a_version_2_and_the_harness_knows_no_version_3():
    """finance@2 and healthcare@2 shipped 2026-11-19; the harness still sends @1 and @2 only."""
    for pack in ("finance", "healthcare"):
        assert pack_live.pack_path(pack, 2).name == "pack.v2.json"
        with pytest.raises(Refused, match="unknown pack version"):
            pack_live.pack_path(pack, 3)


def test_the_responsible_ai_pack_and_unknown_ones_are_still_not_runnable():
    for pack in ("responsible_ai", "banking"):
        with pytest.raises(Refused):
            pack_live.corpus_path(pack)


@pytest.mark.parametrize("pack", ["finance", "healthcare"])
def test_a_dry_run_of_the_new_packs_goes_through_the_same_code(tmp_path, pack):
    out = tmp_path / "run.jsonl"
    assert main(["run", "--pack", pack, "--out", str(out)]) == 0
    recs = records_of(out)
    assert recs[0]["mode"] == "dry-run" and recs[-1]["type"] == "run_finished"
    assert sum(r["type"] == "call" for r in recs) == 3 * SENDABLE[pack][0]
    assert not any(r["id"] in pack_live.HEALTHCARE_WITHHELD for r in load_sendable(pack)[0])
    assert main(["report", "--pack", pack, str(out), "--json"]) == 0


def test_the_live_gates_apply_to_the_new_packs_too(tmp_path, no_key):
    for pack in ("finance", "healthcare"):
        args = ["run", "--pack", pack, "--out", str(tmp_path / f"{pack}.jsonl")]
        assert (
            main([*args, "--live", "--max-tokens", "1000000", "--max-provider-calls", "1400"]) == 2
        )
        assert not (tmp_path / f"{pack}.jsonl").exists() or not records_of(
            tmp_path / f"{pack}.jsonl"
        )


REMEASURE = {
    "insurance": ("d__ins_payout_promise", "d__ins_underwriting_final"),
    "energy": ("d__en_price_certainty", "d__en_outage_promise"),
}


@pytest.mark.parametrize("pack", sorted(REMEASURE))
def test_rules_selects_the_rules_own_category_and_the_cross_rule_rows_of_the_last_run(pack):
    rows, _ = load_sendable(pack)
    everything = plan(pack, 3, "ab" * 16, version=2)
    target = plan(pack, 3, "ab" * 16, version=2, rules=REMEASURE[pack])
    assert target["rules"] == list(REMEASURE[pack])
    assert target["rows_sendable"] == len(rows) and target["rows_selected"] < len(rows)
    assert target["checks"] == 3 * target["rows_selected"] < everything["checks"]
    sel = pack_live.select_rows(pack, 2, rows, REMEASURE[pack])
    own = {r["category"] for r in rows if set(r["fires"]) & set(REMEASURE[pack])}
    assert own <= {r["category"] for r in sel}  # every row of each rule's own category
    assert all(r["no_live_run"] is False for r in sel)  # never a withheld row
    assert [r["id"] for r in sel] == [r["id"] for r in rows if r in sel]  # in order


def test_the_four_rewording_numbers_are_exact():
    """What a re-measure of the four reworded @2 rules would cost: 585 checks, 306 and 279."""
    ins = plan("insurance", 3, "ab" * 16, version=2, rules=REMEASURE["insurance"])
    en = plan("energy", 3, "ab" * 16, version=2, rules=REMEASURE["energy"])
    assert (ins["rows_selected"], ins["checks"], ins["ceiling_checks_with_one_retry"]) == (
        102,
        306,
        612,
    )
    assert (en["rows_selected"], en["checks"], en["ceiling_checks_with_one_retry"]) == (
        93,
        279,
        558,
    )
    assert ins["pack"] == "domain/insurance@2" and en["pack"] == "domain/energy@2"


def test_an_unknown_rule_or_an_empty_list_is_refused_and_no_filter_means_every_row():
    with pytest.raises(Refused, match="not rules of insurance@2"):
        pack_live.parse_rules("insurance", 2, "d__ins_payout_promise,d__en_price_certainty")
    with pytest.raises(Refused):
        pack_live.parse_rules("insurance", 2, " , ")
    assert pack_live.parse_rules("insurance", 2, None) is None
    rows, _ = load_sendable("insurance")
    assert pack_live.select_rows("insurance", 2, rows, None) == rows


def test_a_dry_run_with_rules_sends_only_the_selection_and_reports_only_those_rules(
    tmp_path, capsys
):
    out = tmp_path / "re.jsonl"
    args = [
        "--pack",
        "insurance",
        "--pack-version",
        "2",
        "--rules",
        ",".join(REMEASURE["insurance"]),
    ]
    assert main(["run", *args, "--out", str(out)]) == 0
    recs = records_of(out)
    assert recs[0]["rules"] == list(REMEASURE["insurance"])
    assert sum(r["type"] == "call" for r in recs) == 306
    capsys.readouterr()
    assert main(["report", *args, str(out), "--json"]) == 0
    rep = json.loads(capsys.readouterr().out)
    assert [r["key"] for r in rep["rules"]] == list(REMEASURE["insurance"])
    assert rep["rows_sent"] == 102 and rep["incomplete_examples"] == {}


def test_a_run_started_with_other_rules_is_not_continued(tmp_path, no_key):
    out = tmp_path / "r.jsonl"
    base = ["run", "--pack", "energy", "--pack-version", "2", "--out", str(out)]
    assert main([*base, "--rules", "d__en_price_certainty"]) == 0
    assert main([*base, "--rules", "d__en_outage_promise"]) == 2
    assert main(base) == 2  # nor the whole pack after a filtered run


# ------------------------------------------------------------------ strictly one call at a time


class Counting(FakeDecisionModel):
    """Records how many calls are in flight at once, and every call's start."""

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.active = 0
        self.high = 0

    async def decide(self, input, questions):
        self.active += 1
        self.high = max(self.high, self.active)
        try:
            await asyncio.sleep(0)  # a real call yields
            return await super().decide(input, questions)
        finally:
            self.active -= 1


async def test_the_run_sends_one_call_at_a_time_retries_included(tmp_path):
    rows, _ = load_sendable("energy")
    rows = rows[:12]
    nonces = SeededNonces("ab" * 16)
    model = Counting(default_noul=0.05).timeout_next(2).fail_next(kind="unavailable", times=1)
    out = tmp_path / "r.jsonl"
    async with pack_engine("energy", model, nonces) as (engine, verifier):
        runner = PackRunner(out=out, engine=engine, verifier=verifier, nonces=nonces)
        await pack_live.run_engine_path(runner, rows, [], draws=2, log=lambda s: None)
    assert model.high == 1 and len(model.calls) >= len(rows) * 2


async def test_nothing_starts_after_a_refusal_not_a_retry_not_the_next_check(tmp_path):
    rows, _ = load_sendable("energy")
    nonces = SeededNonces("cd" * 16)
    # the third call is refused; the ones before it answer
    model = Counting(default_noul=0.05)
    real = model.decide
    n = {"calls": 0}

    async def decide(input, questions):
        n["calls"] += 1
        if n["calls"] == 3:
            return SafetyBlocked(reason="prohibited_content")
        return await real(input, questions)

    model.decide = decide  # type: ignore[method-assign]
    out = tmp_path / "r.jsonl"
    async with pack_engine("energy", model, nonces) as (engine, verifier):
        runner = PackRunner(out=out, engine=engine, verifier=verifier, nonces=nonces)
        with pytest.raises(StopRun):
            await pack_live.run_engine_path(runner, rows, [], draws=3, log=lambda s: None)
        await asyncio.sleep(0.2)  # anything still scheduled would send now
    assert n["calls"] == 3 and model.high == 1  # the refused call was the last one started


async def test_a_call_the_gateway_abandoned_stops_the_run_before_the_next_check(tmp_path):
    rows, _ = load_sendable("energy")
    nonces = SeededNonces("ef" * 16)
    model = FakeDecisionModel(default_noul=0.05)
    out = tmp_path / "r.jsonl"
    async with pack_engine("energy", model, nonces) as (engine, verifier):
        runner = PackRunner(out=out, engine=engine, verifier=verifier, nonces=nonces)
        await runner.check(rows[0], 1)
        engine.guard.gateway._orphaned_calls = 1  # an adapter that ignored cancellation
        with pytest.raises(StopRun, match="outlived its cancellation"):
            await runner.check(rows[1], 1)
        assert len(model.calls) == 2  # that check's own call, and nothing after it
    stops = [r for r in records_of(out) if r["type"] == "run_stopped"]
    assert [s["reason"] for s in stops] == ["orphaned_call"]
