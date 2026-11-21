"""The results note's rules (decided 2026-11-19): the B2 all-rows floor leaves out another blocking
rule's positives, and the agreed midpoint and escalate_at arithmetic. Offline; no provider."""

from pathlib import Path

import pytest

from calibration import write_results as wr

OUT, PLAN = "output", "plan"


def rule(key, *, mode="enforce", max_action=None, gps=(OUT,), block_at=0.85, escalate_at=0.55):
    r = {"key": key, "mode": mode, "guard_points": list(gps),
         "block_at": block_at, "escalate_at": escalate_at}  # fmt: skip
    if max_action:
        r["max_action"] = max_action
    return r


def row(id_, fires=(), gp=OUT):
    return {"id": id_, "fires": list(fires), "guard_point": gp, "category": "c"}


RULES = [
    rule("a"),
    rule("b"),  # enforce, can block
    rule("c", max_action="escalate"),  # escalate-only
    rule("d", mode="shadow"),  # not enforced
    rule("e", gps=(PLAN,)),  # a different guard point
]


class TestOtherBlockingPositives:
    def test_only_a_positive_of_another_enforce_blocking_rule_at_the_same_guard_point(self):
        rows = [
            row("own", ["a"]),
            row("b-pos", ["b"]),
            row("c-pos", ["c"]),  # escalate-only: counts as a negative for a
            row("d-pos", ["d"]),  # shadow: counts
            row("benign"),  # counts
            row("e-pos-at-output", ["e"], gp=OUT),  # e doesn't run at output: counts
            row("e-pos", ["e"], gp=PLAN),
            row("both", ["a", "b"]),  # a's own positive stays
        ]
        assert wr.other_blocking_positives(RULES[0], RULES, rows) == {"b-pos"}

    def test_a_rule_capped_at_escalate_is_judged_by_the_same_blockers(self):
        rows = [row("b-pos", ["b"]), row("own", ["c"]), row("benign")]
        assert wr.other_blocking_positives(RULES[2], RULES, rows) == {"b-pos"}


class TestExcludedRowsAreReported:
    """The exclusion must not hide cross-rule firing, so the rows are listed."""

    def test_each_excluded_row_names_the_rules_it_is_a_positive_of_highest_first(self):
        rows = [row("b-pos", ["b"]), row("both", ["b", "d"]), row("benign"), row("own", ["a"])]
        owners = wr.blocking_owners(RULES[0], RULES, rows)
        assert owners == {"b-pos": ["b"], "both": ["b"]}  # d is shadow: not a blocker

    def test_rule_pools_lists_the_excluded_rows_with_scores_and_leaves_them_out_of_the_all_pool(
        self,
    ):
        rows = [row("own", ["a"]), row("b-hi", ["b"]), row("b-lo", ["b"]), row("benign")]
        by_row = {
            "own": {"a": [0.9, 0.9, 0.9]},
            "b-hi": {"a": [0.8, 0.8, 0.8]},
            "b-lo": {"a": [0.1, 0.1, 0.1]},
            "benign": {"a": [0.0, 0.0, 0.0]},
        }
        all_sc, _hard, _r, draws, excluded = wr.rule_pools(RULES[0], RULES, rows, by_row)
        assert [(i, round(sc, 2), o) for i, sc, o in excluded] == [
            ("b-hi", 0.8, ["b"]),
            ("b-lo", 0.1, ["b"]),
        ]
        assert sorted(all_sc) == [(0.0, False), (0.9, True)]
        assert len(draws) == 6  # single draws of the two rows left in


def scores(positives, negatives):
    return [(p, True) for p in positives] + [(n, False) for n in negatives]


class TestAgreedThresholds:
    HARD = scores([0.97] * 16, [0.05, 0.10])

    def test_the_midpoint_rounded_clamped_and_the_escalate_arithmetic(self):
        r = wr.ruled(rule("a"), self.HARD, self.HARD)
        assert r["mid"] == pytest.approx(0.535)
        assert (r["block_at"], r["escalate_at"]) == (0.54, 0.30)  # block - 0.30 < the 0.30 floor
        assert any("floor 0.30" in n for n in r["notes"])

    def test_a_midpoint_below_the_clamp_is_raised_to_it(self):
        hard = scores([0.80] * 16, [0.10])  # midpoint 0.45
        r = wr.ruled(rule("a"), hard, hard)
        assert r["block_at"] == 0.50
        assert any("clamp floor" in n for n in r["notes"])

    def test_the_escalate_margin_over_the_highest_hard_negative(self):
        hard = scores([0.97] * 16, [0.55])  # midpoint 0.76, escalate: 0.55 + 0.05 > 0.46
        r = wr.ruled(rule("a"), hard, hard)
        assert (r["block_at"], r["escalate_at"]) == (0.76, 0.60)

    def test_another_rules_positive_raises_the_b2_floor_unless_it_is_left_out(self):
        cross = [(0.93, False)]
        with_it = wr.ruled(rule("a"), self.HARD, [*self.HARD, *cross])
        assert with_it["block_at"] == 0.94  # the sweep needs precision, so it sits above 0.93
        assert any("B2 all-rows floor bound" in n for n in with_it["notes"])
        without = wr.ruled(rule("a"), self.HARD, self.HARD)
        assert without["block_at"] == 0.54  # the midpoint

    def test_escalate_only_keeps_its_escalate_at_and_has_no_block_at(self):
        capped = rule("c", max_action="escalate", escalate_at=0.40)
        r = wr.ruled(capped, self.HARD, self.HARD)
        assert r["block_at"] is None and r["escalate_at"] == 0.40

    def test_no_positive_means_nothing_is_suggested(self):
        r = wr.ruled(rule("a"), scores([], [0.1]), scores([], [0.1]))
        assert "block_at" not in r and "no positive" in r["basis"]


@pytest.mark.parametrize("name", [run[0] for run in wr.RUNS])
def test_the_committed_note_is_what_the_records_and_the_rules_give(name, tmp_path: Path):
    committed = wr.RES / f"{name}.md"
    if not committed.is_file() or not (wr.RES / f"{name}.jsonl").is_file():
        pytest.skip("this run's record is not in the tree")
    run = next(r for r in wr.RUNS if r[0] == name)
    wr.render_run(*run, out_dir=tmp_path)
    assert (tmp_path / f"{name}.md").read_text() == committed.read_text()
