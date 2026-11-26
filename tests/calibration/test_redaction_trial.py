"""Offline tests of the M7-12 redaction trial harness (calibration/redaction_trial.py): the rows,
the manifest and its verification, the arms, a whole run against a fake model, the stop rules, and
the analysis (on synthetic data and on the recorded golden pair). No live calls, no key."""

import copy
import hashlib
import json
from collections import Counter
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from calibration.engine_path import StopRun
from calibration.run import live_exclusion

from calibration import redaction_stats as stats
from calibration import redaction_trial as rt
from guardrail_engine.decision import FakeDecisionModel

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "calibration" / "results" / "m7-12-trial-manifest.json"
RESULTS = ROOT / "calibration" / "results"


@pytest.fixture(scope="module")
def manifest():
    return rt.load_manifest(MANIFEST)


@pytest.fixture(scope="module")
def rows(manifest):
    return rt.verify_manifest(manifest)


# ------------------------------------------------------------------------ the statistics


def test_clopper_pearson_matches_the_known_exact_values():
    low, high = stats.clopper_pearson(5, 10)
    assert (round(low, 4), round(high, 4)) == (0.1871, 0.8129)
    assert stats.clopper_pearson(0, 10)[0] == 0.0
    assert round(stats.clopper_pearson(0, 10)[1], 4) == 0.3085
    assert stats.clopper_pearson(10, 10)[1] == 1.0
    assert stats.clopper_pearson(0, 0) is None


def test_exact_mcnemar_on_flips():
    assert stats.mcnemar_exact(5, 0)["one_sided"] == pytest.approx(1 / 32)
    assert stats.mcnemar_exact(5, 0)["two_sided"] == pytest.approx(1 / 16)
    assert stats.mcnemar_exact(0, 0) == {"one_sided": 1.0, "two_sided": 1.0}
    assert stats.mcnemar_exact(3, 3)["two_sided"] == 1.0


def test_the_bootstrap_is_deterministic_and_brackets_the_mean():
    values = [0.0, 0.1, -0.1, 0.05, 0.2, -0.05, 0.0, 0.1]
    a = stats.bootstrap_mean(values, seed=3)
    assert a == stats.bootstrap_mean(values, seed=3)
    assert a[0] <= sum(values) / len(values) <= a[1]
    assert stats.bootstrap_mean([], seed=1) is None


# ------------------------------------------------------------------------ the rows


def test_the_committed_manifest_verifies_against_the_files(manifest, rows):
    assert len(rows) == len(manifest["rows"])
    assert manifest["checks"] == len(rows) * 2 * 3
    assert manifest["rows_sha256"] == rt.rows_sha256(manifest["rows"])


def test_the_groups_are_the_approved_shape(manifest):
    counts = manifest["counts"]
    assert counts["placebo_benign"] == counts["placebo_positive"] == 20
    assert counts["affected_positive"] == 54
    assert counts["affected_benign"] == 43  # the four retired rows are not sendable
    assert manifest["affected_but_not_sendable"] == {"retired": 4}
    assert manifest["checks"] <= rt.CEILING_CALLS


def test_every_row_may_be_sent_and_no_harm_row_is_in_it(rows):
    floor_rules = rt.load_floor_rules()
    for row in rows:
        assert live_exclusion(row) is None, row["id"]
        assert rt.send_problem(row, floor_rules) is None
        assert not any("harm" in f for f in row.get("fires", ()))
        assert not row.get("no_live_run")
        assert row["guard_point"] != "input"  # redaction changes none at input


def test_affected_rows_are_changed_by_redaction_and_placebo_rows_are_not(rows):
    for row in rows:
        kinds = rt.pii_kinds(row)
        assert bool(kinds) == row["group"].startswith("affected"), row["id"]


def test_placebo_rows_are_clean_matched_to_the_affected_guard_points_and_reach_the_model(rows):
    placebo = [r for r in rows if r["group"].startswith("placebo")]
    affected_gps = {r["guard_point"] for r in rows if r["group"].startswith("affected")}
    assert {r["guard_point"] for r in placebo} <= affected_gps
    for r in placebo:
        assert not rt.tripwire_views(r), r["id"]
        assert not rt.secret_blocked(r)
        assert r["source"] in rt.PLACEBO_SOURCES


def test_the_selection_is_deterministic(manifest):
    again = rt.build_manifest(nonce_seed=manifest["nonce_seed"])
    assert again == manifest


def test_every_matched_value_is_what_the_engine_replaces(rows):
    """The list shown to the user is the engine's own: per row, the matches of the detector over
    the request's texts add up to the spans the engine reports redacting."""
    for row in rows:
        counted = sum(rt.pii_kinds(row).values())
        assert len(rt.pii_matches(row)) == counted, row["id"]


def test_the_manifest_lists_every_value_of_every_affected_row(manifest):
    listed = Counter(m["id"] for m in manifest["matched_values"])
    for row in manifest["rows"]:
        assert listed.get(row["id"], 0) == sum(row["pii"].values())
    assert all(m["value"] for m in manifest["matched_values"])


def test_the_dropped_tripwire_manifest_is_a_subset():
    narrow = rt.build_manifest(nonce_seed="0" * 32, drop_tripwire=True)
    wide = rt.build_manifest(nonce_seed="0" * 32)
    assert {r["id"] for r in narrow["rows"] if r["group"].startswith("affected")} < {
        r["id"] for r in wide["rows"] if r["group"].startswith("affected")
    }
    assert all(not r["tripwire"] for r in narrow["rows"])
    assert narrow["drop_tripwire"] is True


def test_the_summary_page_names_every_row_value_and_hash(manifest):
    text = rt.manifest_summary(manifest)
    for row in manifest["rows"]:
        assert row["id"] in text
    for digest in manifest["files"].values():
        assert digest in text
    assert manifest["nonce_seed"] in text and str(rt.CEILING_CALLS) in text


# ------------------------------------------------------------------------ verification


def refused(manifest, rows_dir=None):
    with pytest.raises(rt.Refused) as e:
        rt.verify_manifest(manifest)
    return str(e.value)


def mutated(manifest, edit):
    changed = copy.deepcopy(manifest)
    edit(changed)
    return changed


def test_a_changed_source_file_hash_refuses(manifest):
    why = refused(mutated(manifest, lambda m: m["files"].update(heldout="sha256:" + "0" * 64)))
    assert "heldout: the file differs" in why and "nothing was sent" in why


def test_a_changed_floor_refuses(manifest):
    assert "floor@2" in refused(mutated(manifest, lambda m: m.update(floor_content_hash="x")))


def test_raised_ceilings_refuse(manifest):
    why = refused(mutated(manifest, lambda m: m["ceilings"].update(provider_calls=5000)))
    assert "ceilings are not the approved ones" in why


def test_a_changed_arm_or_draw_count_refuses(manifest):
    assert "arms or draws" in refused(mutated(manifest, lambda m: m.update(draws=5)))


def test_an_edited_row_set_refuses(manifest):
    why = refused(mutated(manifest, lambda m: m["rows"].pop()))
    assert "its own hash" in why


def test_a_row_whose_label_changed_refuses(manifest):
    def edit(m):
        m["rows"][0]["label"] = "allow" if m["rows"][0]["label"] == "block" else "block"
        m["rows_sha256"] = rt.rows_sha256(m["rows"])

    assert "no longer matches its manifest entry" in refused(mutated(manifest, edit))


def test_a_row_moved_between_groups_refuses(manifest):
    def edit(m):
        first = next(r for r in m["rows"] if r["group"] == "placebo_benign")
        first["group"] = "affected_benign"
        m["rows_sha256"] = rt.rows_sha256(m["rows"])

    assert "group and its PII disagree" in refused(mutated(manifest, edit))


def test_a_row_that_is_not_in_its_source_refuses(manifest):
    def edit(m):
        m["rows"][0]["id"] = "no-such-row"
        m["rows_sha256"] = rt.rows_sha256(m["rows"])

    assert "not in" in refused(mutated(manifest, edit))


def test_a_manifest_that_is_not_one_is_refused(tmp_path):
    path = tmp_path / "m.json"
    path.write_text("[]")
    with pytest.raises(rt.Refused):
        rt.load_manifest(path)
    path.write_text('{"schema": 99}')
    with pytest.raises(rt.Refused):
        rt.load_manifest(path)
    with pytest.raises(rt.Refused):
        rt.load_manifest(tmp_path / "missing.json")


# ------------------------------------------------------------------------ the arms


def test_the_raw_arm_finds_no_pii_and_the_redacted_arm_finds_all_of_it(rows):
    detector = rt.ArmDetector()
    text = "write to jane.doe@example.com or call"
    assert [m.kind.value for m in detector.find(text)] == ["email"]
    detector.raw = True
    assert detector.find(text) == []


def test_the_two_arms_render_the_same_row_apart_from_the_pii(rows):
    row = next(r for r in rows if r["group"] == "affected_positive")
    direct = rt.direct_setup()
    cap = direct.max_content_tokens[row["guard_point"]]
    red = rt.render_arm(row, "redacted", "a" * 32, cap)
    raw = rt.render_arm(row, "raw", "a" * 32, cap)
    values = [m["value"] for m in rt.pii_matches(row)]
    assert values and all(v in raw for v in values)
    assert not any(v in red for v in values)
    assert red != raw


def test_a_placebo_row_renders_identically_in_both_arms(rows):
    row = next(r for r in rows if r["group"] == "placebo_benign")
    cap = rt.direct_setup().max_content_tokens[row["guard_point"]]
    assert rt.render_arm(row, "redacted", "a" * 32, cap) == rt.render_arm(row, "raw", "a" * 32, cap)


def test_the_arm_order_is_deterministic_and_balanced(rows):
    firsts = Counter(rt.arm_order("s" * 32, r["id"], d)[0] for r in rows for d in (1, 2, 3))
    assert set(firsts) == {"redacted", "raw"}
    assert min(firsts.values()) > 0.35 * sum(firsts.values())
    assert rt.arm_order("s", "x", 1) == rt.arm_order("s", "x", 1)
    assert sorted(rt.arm_order("s", "x", 1)) == sorted(rt.ARMS)


def test_the_row_order_is_a_reshuffle_per_draw(rows):
    one, two = rt.row_order("s", rows, 1), rt.row_order("s", rows, 2)
    assert sorted(r["id"] for r in one) == sorted(r["id"] for r in rows)
    assert [r["id"] for r in one] != [r["id"] for r in two]
    assert len({r["group"] for r in one[:12]}) > 1  # the groups are interleaved


# ------------------------------------------------------------------------ the plan


def test_the_plan_is_inside_the_ceilings(rows):
    planned = rt.plan(rows)
    assert planned["checks"] == 822 and planned["checks"] <= rt.CEILING_CALLS
    assert 0 < planned["estimated_input_tokens"] <= rt.CEILING_INPUT_TOKENS
    assert planned["interval_s"] >= rt.LIVE_MIN_INTERVAL_S * 0.9
    assert planned["estimated_minutes"] < 120 - rt.START_MARGIN_MINUTES


# ------------------------------------------------------------------------ a whole run, offline


def fake_model():
    """A deterministic fake whose answer depends on the text it is sent (so the arms differ where
    their text does) and sometimes reaches the block level."""

    def respond(text, key, question):
        digest = hashlib.sha256(f"{key}:{text}".encode()).digest()
        return 0.05 + 0.9 * digest[0] / 255

    return FakeDecisionModel(responder=respond)


@pytest.fixture(scope="module")
def run_out(tmp_path_factory):
    import asyncio

    out = tmp_path_factory.mktemp("trial") / "records.jsonl"
    code = asyncio.run(rt.execute(rt.Args(MANIFEST, out, False), model_factory=fake_model))
    return code, out


@pytest.fixture(scope="module")
def records(run_out):
    return rt.read_records(run_out[1])


def calls(records):
    return [r for r in records if r.get("type") == "call"]


def test_a_whole_offline_run_makes_every_check_in_both_arms(run_out, records, manifest):
    assert run_out[0] == rt.EXIT_DONE
    assert len(calls(records)) == manifest["checks"] == 822
    assert records[0]["type"] == "run_started" and records[-1]["type"] == "run_finished"
    keys = Counter((r["example_id"], r["draw"], r["arm"]) for r in calls(records))
    assert set(keys.values()) == {1}
    assert Counter(r["arm"] for r in calls(records)) == {"redacted": 411, "raw": 411}


def test_both_arms_of_a_check_use_the_same_nonce(records):
    by = {}
    for r in calls(records):
        by.setdefault((r["example_id"], r["draw"]), {})[r["arm"]] = r["nonce"]
    assert all(v["redacted"] == v["raw"] for v in by.values())


def test_redaction_is_on_in_one_arm_only(records, manifest):
    meta = {r["id"]: r for r in manifest["rows"]}
    for r in calls(records):
        if r["arm"] == "raw":
            assert r["pii_redacted"] == {}, r["example_id"]
        elif meta[r["example_id"]]["group"].startswith("affected"):
            assert r["pii_redacted"] == meta[r["example_id"]]["pii"], r["example_id"]
        else:
            assert r["pii_redacted"] == {}


def test_the_arms_alternate_through_the_run(records):
    first = [r["arm"] for r in calls(records)[:40]]
    assert first.count("raw") > 8 and first.count("redacted") > 8


def test_the_records_carry_no_content(run_out, manifest, rows):
    """No row's text and none of the numbers redaction replaces is in the records (an email's
    local part is a short ordinary word, so it can't be searched for as a string)."""
    text = run_out[1].read_text()
    numbers = [m["value"] for m in manifest["matched_values"] if m["kind"] != "email"]
    assert numbers and all(v not in text for v in numbers)
    assert all(row["content"] not in text for row in rows)


def test_a_placebo_row_scores_the_same_in_both_arms_with_a_deterministic_fake(records, manifest):
    meta = {r["id"]: r for r in manifest["rows"]}
    by = {}
    for r in calls(records):
        by.setdefault((r["example_id"], r["draw"]), {})[r["arm"]] = r["probabilities"]
    for (rid, _), arms in by.items():
        if meta[rid]["group"].startswith("placebo"):
            assert arms["raw"] == arms["redacted"]


def test_the_report_of_the_run_reads_back(run_out):
    result, text = rt.report(run_out[1], MANIFEST)
    assert result["usable_rows"] == 137 and not result["incomplete_rows"]
    assert "Which line of the design's table" in text
    lines = {"keep_default_phase_2_may_go_ahead", "loss_confirmed", "false_positive_rise"}
    assert result["verdict"]["line"] in {*lines, "inconclusive"}


async def stopped_run(tmp_path, model):
    out = tmp_path / "records.jsonl"
    code = await rt.execute(rt.Args(MANIFEST, out, False), model_factory=lambda: model)
    return code, rt.read_records(out)


async def test_the_first_provider_refusal_stops_the_run_and_is_not_resent(tmp_path):
    model = fake_model().safety_block_next()
    code, records = await stopped_run(tmp_path, model)
    assert code == rt.EXIT_STOPPED
    assert records[-1]["type"] == "run_stopped" and records[-1]["reason"] == "provider_refusal"
    assert len(calls(records)) == 1


async def test_a_429_stops_the_run(tmp_path):
    model = fake_model().rate_limit_next(times=4)
    code, records = await stopped_run(tmp_path, model)
    assert code == rt.EXIT_STOPPED
    assert records[-1]["reason"] in {"unexpected_429", "failures"}
    assert len(calls(records)) < 20


async def test_a_run_that_keeps_failing_stops_on_the_failure_rate(tmp_path):
    from guardrail_engine.decision import FailureKind
    from guardrail_engine.decision.port import Failed

    model = fake_model().always(Failed(kind=FailureKind.TIMEOUT, message="slow"))
    code, records = await stopped_run(tmp_path, model)
    assert code == rt.EXIT_STOPPED
    assert records[-1]["reason"] == "failures"
    assert len(calls(records)) <= 12


async def test_a_run_refuses_an_existing_output_file(tmp_path):
    out = tmp_path / "records.jsonl"
    out.write_text('{"type": "call"}\n')
    code = await rt.execute(rt.Args(MANIFEST, out, False), model_factory=fake_model)
    assert code == rt.EXIT_REFUSED


async def test_a_live_run_takes_no_model_override_and_an_offline_one_needs_a_model(tmp_path):
    assert (
        await rt.execute(rt.Args(MANIFEST, tmp_path / "a.jsonl", True), model_factory=fake_model)
        == rt.EXIT_REFUSED
    )
    assert await rt.execute(rt.Args(MANIFEST, tmp_path / "b.jsonl", False)) == rt.EXIT_REFUSED


async def test_a_run_with_a_changed_manifest_sends_nothing(tmp_path):
    changed = json.loads(MANIFEST.read_text())
    changed["ceilings"]["provider_calls"] = 9999
    path = tmp_path / "m.json"
    path.write_text(json.dumps(changed))
    out = tmp_path / "records.jsonl"
    code = await rt.execute(rt.Args(path, out, False), model_factory=fake_model)
    assert code == rt.EXIT_REFUSED and not out.exists()


def test_the_command_line_refuses_a_run_without_live(tmp_path):
    assert rt.main(["run", "--manifest", str(MANIFEST), "--out", str(tmp_path / "x.jsonl")]) == 2


# ------------------------------------------------------------------------ the analysis


THRESHOLDS = {"p__a": (0.85, 0.55), "p__b": (0.85, 0.55)}


def meta_rows(positives=30, benign=20, placebo=10):
    rows = []
    for i in range(positives):
        rows.append({"id": f"ap{i}", "group": "affected_positive", "guard_point": "plan",
                     "fires": ["p__a"] if i % 2 else ["p__b"], "pii": {"email": 1}})  # fmt: skip
    for i in range(benign):
        rows.append({"id": f"ab{i}", "group": "affected_benign", "guard_point": "plan",
                     "fires": [], "pii": {"email": 1}})  # fmt: skip
    for i in range(placebo):
        rows.append({"id": f"pp{i}", "group": "placebo_positive", "guard_point": "plan",
                     "fires": ["p__a"], "pii": {}})  # fmt: skip
        rows.append({"id": f"pb{i}", "group": "placebo_benign", "guard_point": "plan",
                     "fires": [], "pii": {}})  # fmt: skip
    return rows


def synthetic(rows, *, lose=(), rise=(), shift=0.0, drop=()):
    """Cells where positives score 0.95 and benign 0.05 in both arms, except: rows in ``lose``
    score 0.5 in the redacted arm, rows in ``rise`` score 0.95 in the redacted arm, every
    redacted score moves by ``shift``, and cells of rows in ``drop`` are missing."""
    cells = []
    for r in rows:
        if r["id"] in drop:
            continue
        base = 0.95 if r["fires"] else 0.05
        for arm in rt.ARMS:
            p = base
            if arm == "redacted":
                moved = base + shift if r["pii"] else base
                p = 0.5 if r["id"] in lose else 0.95 if r["id"] in rise else moved
            for draw in (1, 2, 3):
                cells.append(rt.Cell(r["id"], arm, draw, {k: p for k in THRESHOLDS}))
    return cells


def test_identical_arms_keep_the_default():
    rows = meta_rows(positives=70)
    result = rt.analyse(synthetic(rows), rows, THRESHOLDS)
    assert result["verdict"]["line"] == "keep_default_phase_2_may_go_ahead"
    assert result["recall_pooled"]["diff_points"] == 0
    assert result["false_positives"]["affected"]["rise_points"] == 0


def test_a_confirmed_loss_in_one_rule_is_found():
    rows = meta_rows(positives=30)
    lose = {r["id"] for r in rows if r["group"] == "affected_positive" and r["fires"] == ["p__a"]}
    result = rt.analyse(synthetic(rows, lose=lose), rows, THRESHOLDS)
    assert result["verdict"]["line"] == "loss_confirmed"
    assert result["recall"]["p__a"]["affected"]["first_only"] == 15
    assert any("p__a" in r for r in result["verdict"]["reasons"])
    assert len(result["flips_against_redaction"]) == 15
    assert result["recall"]["p__b"]["affected"]["first_only"] == 0


def test_a_false_positive_rise_is_found():
    rows = meta_rows(positives=70, benign=40)
    rise = {r["id"] for r in rows if r["group"] == "affected_benign"}
    rise = set(sorted(rise)[:4])  # 4 of 40: 10 points
    result = rt.analyse(synthetic(rows, rise=rise), rows, THRESHOLDS)
    assert result["false_positives"]["affected"]["rise_points"] == pytest.approx(10.0)
    assert result["verdict"]["line"] == "false_positive_rise"


def test_too_few_positives_cannot_rule_out_a_large_loss():
    rows = meta_rows(positives=6)
    result = rt.analyse(synthetic(rows), rows, THRESHOLDS)
    assert result["verdict"]["line"] == "inconclusive"
    assert result["recall_pooled"]["diff_ci95_points"][1] >= rt.MARGIN_RECALL_POINTS


def test_a_rule_with_three_flips_against_redaction_is_not_clean():
    rows = meta_rows(positives=70)
    a_rows = sorted(
        r["id"] for r in rows if r["group"] == "affected_positive" and r["fires"] == ["p__a"]
    )
    result = rt.analyse(synthetic(rows, lose=set(a_rows[:3])), rows, THRESHOLDS)
    assert result["recall"]["p__a"]["affected"]["first_only"] == 3
    assert result["verdict"]["line"] == "inconclusive"
    assert any("3 flips" in r for r in result["verdict"]["reasons"])


def test_an_incomplete_row_is_left_out_and_an_incomplete_affected_row_is_named():
    rows = meta_rows(positives=70)
    result = rt.analyse(synthetic(rows, drop={"ap1"}), rows, THRESHOLDS)
    assert result["incomplete_rows"] == ["ap1"] and result["incomplete_affected_rows"] == ["ap1"]
    assert result["usable_rows"] == len(rows) - 1
    assert result["verdict"]["line"] == "inconclusive"
    placebo = rt.analyse(synthetic(rows, drop={"pb0"}), rows, THRESHOLDS)
    assert placebo["incomplete_affected_rows"] == []  # a missing placebo row doesn't block


def test_the_probability_shift_is_measured_row_by_row():
    rows = meta_rows(positives=70)
    result = rt.analyse(synthetic(rows, shift=0.02), rows, THRESHOLDS)
    shift = result["probability_shift"]
    assert shift["affected"]["all_rule_cells_by_row"]["mean_change"] == pytest.approx(0.02)
    assert shift["placebo"]["mean_abs_change_per_cell"] == 0.0  # identical text, identical score


def test_a_draw_missing_a_rule_leaves_the_cell_out_not_judged_on_fewer_draws():
    rows = meta_rows(positives=70)
    cells = synthetic(rows)
    cells = [c for c in cells if not (c.row_id == "ap0" and c.arm == "raw" and c.draw == 2)]
    cells.append(rt.Cell("ap0", "raw", 2, {}))  # answered, but without any rule's score
    result = rt.analyse(cells, rows, THRESHOLDS)
    assert result["recall_pooled"]["first"]["n"] == 69  # the ap0 cell is left out


def test_the_report_is_rendered_for_every_line():
    rows = meta_rows(positives=70, benign=40)
    text = rt.format_report(rt.analyse(synthetic(rows), rows, THRESHOLDS), {"failed": 2})
    assert "all rules together" in text and "keep_default_phase_2_may_go_ahead" in text
    assert "Checks that did not answer: failed 2" in text


# ------------------------------------------------------------------------ the recorded golden pair


def golden_pair():
    """The golden set's floor@2 calibration before redaction (M0-02) and after it (M1-14, the
    full rerun): the same rules file and the same rows, two runs hours apart. The 15 rows
    redaction changes are the affected rows; the rest are unchanged text."""

    def cells(name, arm, key):
        out = []
        for line in (RESULTS / f"{name}.jsonl").read_text().splitlines():
            r = json.loads(line)
            if r.get("type") == "call" and r.get("phase") == "main" and r["outcome"] == "answered":
                p = {k: v for k, v in (r.get(key) or {}).items() if k.startswith("p__")}
                out.append(rt.Cell(r["example_id"], arm, r["draw"], p))
        return out

    rows = []
    for line in (ROOT / "floor" / "golden.jsonl").read_text().splitlines():
        r = json.loads(line)
        kinds = rt.pii_kinds(r)
        side = "affected" if kinds else "placebo"
        rows.append({"id": r["id"], "guard_point": r["guard_point"], "pii": kinds,
                     "group": f"{side}_{'positive' if r.get('fires') else 'benign'}",
                     "fires": sorted(r.get("fires") or [])})  # fmt: skip
    both = cells("m0-02-floor2", "raw", "probabilities") + cells(
        "m0-02-r74-full", "redacted", "probabilities_raw"
    )
    return rt.analyse(both, rows, rt.load_floor_rules())


def test_the_recorded_golden_pair_gives_the_natural_experiment_the_design_reports():
    result = golden_pair()
    assert result["rows"]["affected_positive"] + result["rows"]["affected_benign"] == 15
    shift = result["probability_shift"]
    # redaction moved the affected rows' scores by about as much as the same text moves between
    # two runs (the design's table: 0.0132 on the changed rows, 0.0087 on the unchanged)
    assert shift["affected"]["mean_abs_change_per_cell"] == pytest.approx(0.0132, abs=0.0005)
    assert shift["placebo"]["mean_abs_change_per_cell"] == pytest.approx(0.0087, abs=0.0005)
    low, high = shift["affected"]["all_rule_cells_by_row"]["ci95"]
    assert low < 0.005 < high and low > -0.01 and high < 0.02
    assert result["false_positives"]["affected"]["flips_up_with_redaction"] == 0
    assert result["recall_pooled"]["first_only"] == 0  # no positive was lost by redaction


# ------------------------------------------------------------------------ the arming script

ARM = ROOT / "calibration" / "redaction_trial_arm.sh"


def arm(tmp_path, start, *, attempt="1", existing=None):
    import subprocess

    out = tmp_path / "out"
    out.mkdir(parents=True, exist_ok=True)
    for name in existing or ():
        (out / name).write_text("x")
    done = subprocess.run(
        ["bash", str(ARM), start, attempt, "0" * 40, str(ROOT), str(out), str(tmp_path / "no.env")],
        capture_output=True, text=True, timeout=60, env={"PATH": "/usr/bin:/bin"},
    )  # fmt: skip
    return done.returncode, out, done


def test_the_arming_script_sends_nothing_outside_its_window(tmp_path):
    code, out, _ = arm(tmp_path, "2020-01-01T08:00")
    assert code == 3
    assert "missed the window; nothing sent" in (out / "RESULT").read_text()
    assert not (out / "records.jsonl").exists()


def test_the_window_is_two_hours_from_the_start_it_is_given(tmp_path):
    """A start 100 minutes ago is inside its window (it goes on to the next check, which fails
    on the head sha it was given); one 130 minutes ago has closed."""
    now = datetime.now(UTC)
    inside = (now - timedelta(minutes=100)).strftime("%Y-%m-%dT%H:%M")
    code, out, _ = arm(tmp_path, inside)
    assert code == 3 and "worktree HEAD changed; nothing sent" in (out / "RESULT").read_text()
    shut = (now - timedelta(minutes=130)).strftime("%Y-%m-%dT%H:%M")
    code, out2, _ = arm(tmp_path / "late", shut)
    assert code == 3 and "missed the window; nothing sent" in (out2 / "RESULT").read_text()


def test_the_arming_script_refuses_a_start_or_an_attempt_it_does_not_understand(tmp_path):
    for bad_start, attempt in (
        ("2026-11-26", "2"),
        ("tomorrow 08:00", "2"),
        ("2026-13-45T08:00", "2"),
    ):
        code, out, _ = arm(tmp_path / bad_start.replace(" ", "_"), bad_start, attempt=attempt)
        assert code == 2 and not (out / "RESULT").exists(), bad_start
    code, out, _ = arm(tmp_path / "three", "2020-01-01T08:00", attempt="3")
    assert code == 2 and not (out / "RESULT").exists()


def test_the_arming_script_arms_one_run_into_a_directory(tmp_path):
    code, out, _ = arm(tmp_path, "2020-01-01T08:00", existing=["RESULT"])
    assert code == 3 and (out / "RESULT").read_text() == "x"  # untouched: it refused at once


def test_the_arming_script_refuses_when_records_already_exist(tmp_path):
    code, out, _ = arm(tmp_path, "2020-01-01T08:00", existing=["records.jsonl"])
    assert code == 3 and "records already exist; nothing sent" in (out / "RESULT").read_text()


def test_the_arming_script_passes_the_attempt_to_the_run():
    text = ARM.read_text()
    assert '--attempt "$ATTEMPT"' in text and "START + 7200" in text


# ------------------------------------------------------------------------ what was approved


def _rehashed(manifest, edit):
    """A manifest edited and its own row hash recomputed, as a careful editor would."""
    changed = copy.deepcopy(manifest)
    edit(changed)
    changed["rows_sha256"] = rt.rows_sha256(changed["rows"])
    return changed


def test_the_harness_holds_the_approved_manifest_itself(manifest):
    assert manifest["rows_sha256"] == rt.APPROVED_ROWS_SHA256
    assert manifest["counts"] == rt.APPROVED_COUNTS
    assert manifest["counts"] == {
        "affected_positive": 54, "affected_benign": 43, "placebo_positive": 20,
        "placebo_benign": 20,
    }  # fmt: skip
    assert manifest["nonce_seed"] == rt.APPROVED_NONCE_SEED
    assert manifest["checks"] == rt.APPROVED_CHECKS == 822
    assert rt.approval_problems(manifest, manifest["rows"]) == []


def test_fewer_rows_with_a_recomputed_hash_are_refused(manifest):
    why = refused(_rehashed(manifest, lambda m: m.update(rows=m["rows"][:-30])))
    assert "the row set is not the approved one" in why and "nothing was sent" in why


def test_a_changed_nonce_seed_is_refused(manifest):
    why = refused(mutated(manifest, lambda m: m.update(nonce_seed="a" * 32)))
    assert "the nonce seed is not the approved one" in why


def test_changed_margins_are_refused(manifest):
    why = refused(mutated(manifest, lambda m: m["margins"].update(recall_points=20.0)))
    assert "the margins are not the approved ones" in why


def test_a_different_group_count_is_refused(manifest):
    why = refused(mutated(manifest, lambda m: m["counts"].update(placebo_benign=21)))
    assert "the manifest's counts are not the approved ones" in why


def test_the_narrower_trial_is_not_the_approved_one():
    narrow = rt.build_manifest(nonce_seed=rt.APPROVED_NONCE_SEED, drop_tripwire=True)
    assert rt.approval_problems(narrow, narrow["rows"])


# ------------------------------------------------------------------------ the window


DEADLINE = datetime(2026, 11, 25, 10, 0, tzinfo=UTC)


class Ticking:
    """A fake wall clock that moves ``step`` seconds each time it is read."""

    def __init__(self, start, step=1.0):
        self.at, self.step, self.reads = start, timedelta(seconds=step), 0

    def __call__(self):
        self.reads += 1
        self.at += self.step
        return self.at


async def test_no_check_starts_after_the_deadline_and_the_run_stops_with_window_closed(tmp_path):
    clock = Ticking(DEADLINE - timedelta(seconds=300), step=2.0)
    out = tmp_path / "records.jsonl"
    code = await rt.execute(
        rt.Args(MANIFEST, out, False, DEADLINE), model_factory=fake_model, now=clock
    )
    records = rt.read_records(out)
    assert code == rt.EXIT_STOPPED
    last = records[-1]
    assert last["type"] == "run_stopped" and last["reason"] == "window_closed"
    assert last["deadline"] == "2026-11-25T10:00:00+00:00"
    stopped_at = datetime.fromisoformat(last["at"])
    assert stopped_at + timedelta(seconds=rt.WINDOW_SAFETY_S) >= DEADLINE  # it stopped at the edge
    made = len(calls(records))
    assert 0 < made < 822  # some checks went out before it, and not all of them
    # every check made was gated at a time that left the safety margin before the deadline
    assert made <= (300 - rt.WINDOW_SAFETY_S) / 2.0


async def test_a_deadline_already_passed_sends_nothing(tmp_path):
    out = tmp_path / "records.jsonl"
    clock = Ticking(DEADLINE + timedelta(minutes=1))
    code = await rt.execute(
        rt.Args(MANIFEST, out, False, DEADLINE), model_factory=fake_model, now=clock
    )
    records = rt.read_records(out)
    assert code == rt.EXIT_STOPPED and calls(records) == []
    assert records[-1]["reason"] == "window_closed"


async def test_the_deadline_is_checked_after_the_pacing_wait(tmp_path):
    """A check paced past the deadline is not sent: the clock moves while the runner sleeps."""
    from calibration.engine_path import SeededNonces, calibration_engine

    wall = {"seconds": 0.0}
    start = DEADLINE - timedelta(seconds=40)

    def now():
        return start + timedelta(seconds=wall["seconds"])

    async def sleep(seconds):
        wall["seconds"] += seconds

    row = _input_row("Summarise the policy terms.")
    nonces = SeededNonces("c" * 32)
    detector = rt.ArmDetector()
    out = tmp_path / "records.jsonl"
    async with calibration_engine(
        rt.engine_setup(), [row], model=fake_model(), nonces=nonces, pii_detector=detector
    ) as (engine, verifier):
        runner = rt.TrialRunner(
            out=out, engine=engine, verifier=verifier, nonces=nonces, detector=detector,
            deadline=DEADLINE, now=now, sleep=sleep, min_interval_s=25.0,
            clock=lambda: wall["seconds"],
        )  # fmt: skip
        await runner.check_arm(row, 1, "raw")  # at -40 s: sent, nothing to wait for
        with pytest.raises(StopRun):  # waits 25 s, then it is -15 s... still sent
            await runner.check_arm(row, 1, "redacted")
            await runner.check_arm(row, 2, "raw")  # waits 25 s more: past the margin
    records = rt.read_records(out)
    assert [r["type"] for r in records] == ["call", "call", "run_stopped"]
    assert records[-1]["reason"] == "window_closed"
    assert wall["seconds"] == 50.0  # it slept before deciding, and then did not send


async def test_a_live_run_without_a_deadline_is_refused(tmp_path):
    assert await rt.execute(rt.Args(MANIFEST, tmp_path / "a.jsonl", True), attempts=tmp_path) == 2
    assert not (tmp_path / "a.jsonl").exists() and not list(tmp_path.glob("*.started"))


async def test_a_live_run_that_would_end_after_the_window_is_refused_at_the_start(tmp_path):
    late = DEADLINE - timedelta(minutes=20)  # the plan is about 29 minutes
    code = await rt.execute(
        rt.Args(MANIFEST, tmp_path / "a.jsonl", True, DEADLINE),
        now=lambda: late,
        attempts=tmp_path / "state",
    )
    assert code == rt.EXIT_REFUSED
    assert not (tmp_path / "a.jsonl").exists() and not (tmp_path / "state").exists()


def test_the_command_line_refuses_a_live_run_without_a_deadline(tmp_path):
    assert (
        rt.main(["run", "--live", "--manifest", str(MANIFEST), "--out", str(tmp_path / "x.jsonl")])
        == 2
    )
    assert (
        rt.main(
            ["run", "--live", "--deadline", "tomorrow", "--manifest", str(MANIFEST), "--out", "x"]
        )
        == 2
    )


def test_the_arming_script_passes_the_deadline_to_the_run():
    text = ARM.read_text()
    assert '--deadline "$DEADLINE"' in text and "window_closed" in text


# ------------------------------------------------------------------------ one attempt


def test_a_second_attempt_is_refused_once_one_has_started(tmp_path):
    first = rt.Attempt(tmp_path, rt.APPROVED_ROWS_SHA256)
    first.acquire()
    first.mark({"started_at": "x"})
    first.release()
    second = rt.Attempt(tmp_path, rt.APPROVED_ROWS_SHA256)
    with pytest.raises(rt.Refused, match="has started"):
        second.acquire()
    with pytest.raises(rt.Refused):
        rt.Attempt(tmp_path, rt.APPROVED_ROWS_SHA256).mark({})  # the marker is written once


def test_a_second_attempt_is_refused_while_one_holds_the_lock(tmp_path):
    first = rt.Attempt(tmp_path, rt.APPROVED_ROWS_SHA256)
    first.acquire()
    try:
        with pytest.raises(rt.Refused, match="in progress"):
            rt.Attempt(tmp_path, rt.APPROVED_ROWS_SHA256).acquire()
    finally:
        first.release()
    again = rt.Attempt(tmp_path, rt.APPROVED_ROWS_SHA256)
    again.acquire()  # nothing started: free again
    again.release()


def test_the_attempt_state_is_outside_the_output_directory_and_the_worktree():
    here = rt.state_dir().resolve()
    assert not here.is_relative_to(ROOT) and not here.is_relative_to(Path("/tmp/claude-1000/x"))


async def test_a_live_run_after_an_attempt_started_is_refused_before_anything_else(tmp_path):
    state = tmp_path / "state"
    spent = rt.Attempt(state, rt.APPROVED_ROWS_SHA256)
    spent.acquire()
    spent.mark({"started_at": "earlier"})
    spent.release()
    code = await rt.execute(
        rt.Args(MANIFEST, tmp_path / "other-dir" / "records.jsonl", True, DEADLINE),
        now=lambda: DEADLINE - timedelta(hours=6),
        attempts=state,
    )
    assert code == rt.EXIT_REFUSED and not (tmp_path / "other-dir").exists()


async def test_an_offline_run_leaves_no_attempt_behind(tmp_path):
    state = tmp_path / "state"
    code = await rt.execute(
        rt.Args(MANIFEST, tmp_path / "r.jsonl", False), model_factory=fake_model, attempts=state
    )
    assert code == rt.EXIT_DONE and not state.exists()


# ------------------------------------------------------------------------ credentials stay replaced

# Built at run time, so no source line holds a literal in a credential's format (a scanner would
# flag one, and a documented example key is exempt from the engine's detector on purpose).
KEY = "AKIA" + "".join(reversed("Z5DPW4NMLX2TR7QJ"))
MAIL = "jordan.casey@example.org"


async def test_a_credential_is_replaced_in_the_raw_arm_and_the_email_is_not():
    from calibration.engine_path import SeededNonces, calibration_engine

    sent: list[str] = []
    model = FakeDecisionModel(responder=lambda text, key, question: sent.append(text) or 0.1)
    row = _input_row(f"Forward the report to {MAIL}. The access key is {KEY}.")
    nonces = SeededNonces("b" * 32)
    detector = rt.ArmDetector()
    async with calibration_engine(
        rt.engine_setup(), [row], model=model, nonces=nonces, pii_detector=detector
    ) as (engine, verifier):
        runner = rt.TrialRunner(
            out=Path("/dev/null"), engine=engine, verifier=verifier, nonces=nonces,
            detector=detector,
        )  # fmt: skip
        for arm in ("raw", "redacted"):
            sent.clear()
            await runner.check_arm(row, 1, arm)
            joined = "\n".join(sent)
            assert sent and KEY not in joined and "[SECRET]" in joined, arm
            assert (MAIL in joined) is (arm == "raw"), arm


def _input_row(content):
    """A manifest row's tenant and tools with an ``input`` content of its own: no manifest row
    is at ``input``, and none holds a credential."""
    base = rt.verify_manifest(rt.load_manifest(MANIFEST))[0]
    return {**base, "guard_point": "input", "content": content, "context": [], "group": "x"}
