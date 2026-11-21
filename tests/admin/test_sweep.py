"""M4-01, B2: the threshold sweep, on synthetic golden sets whose correct answers are
worked out by hand."""

import pytest

from guardrail_engine.admin.sweep import (
    GRID,
    TargetError,
    Targets,
    confusion,
    meets_precision,
    precision_at,
    sweep,
)

POS, NEG = True, False


def test_the_grid_is_0_01_to_0_99():
    assert GRID[0] == 0.01 and GRID[-1] == 0.99 and len(GRID) == 99


def test_a_set_with_known_answers():
    """Positives (labelled block): 0.5 0.6 0.7 0.8 0.9 0.95. Negatives: 0.05 0.1 0.2 0.3 0.4
    0.55. Precision 0.95: at 0.55 the 0.55 negative is in (5 of 6 predicted are right, 0.83),
    at 0.56 nothing wrong is in (5 of 5): block_at 0.56. Recall 0.90 needs all six positives
    (5 of 6 is 0.83), so the highest threshold at or below the lowest positive: 0.50."""
    scores = [(p, POS) for p in (0.5, 0.6, 0.7, 0.8, 0.9, 0.95)]
    scores += [(p, NEG) for p in (0.05, 0.1, 0.2, 0.3, 0.4, 0.55)]
    s = sweep(scores, Targets(0.95, 0.90))
    assert (s.block_at, s.escalate_at, s.band_empty) == (0.56, 0.50, False)
    assert s.precision == 1.0 and s.recall == 1.0
    assert (s.examples, s.positives) == (12, 6)
    assert s.available and s.reason is None


def test_block_at_is_the_lowest_threshold_not_the_best_one():
    """Precision is not monotonic. Negatives sit low (0.05 0.06 0.07) and in the middle (0.40
    0.45 0.50); 8 positives sit at 0.30-0.34 and 0.90-0.97. At 0.07 the low negatives still
    count (8 of 12 = 0.67); at 0.08 they are out (8 of 11 = 0.727 >= 0.70). Higher
    thresholds (0.51: 3 of 3) are better, and not the answer."""
    scores = [(p, POS) for p in (0.30, 0.31, 0.32, 0.33, 0.34, 0.90, 0.95, 0.97)]
    scores += [(p, NEG) for p in (0.05, 0.06, 0.07, 0.40, 0.45, 0.50)]
    s = sweep(scores, Targets(0.70, 0.5))
    assert s.block_at == 0.08
    assert meets_precision(confusion(scores, 0.51), 0.70)  # a higher one does too
    assert not meets_precision(confusion(scores, 0.07), 0.70)


@pytest.mark.parametrize(
    ("recall", "escalate_at", "band_empty"),
    [
        (0.90, 0.50, False),  # all six positives are needed: down to the lowest, 0.50
        (1.00, 0.50, False),
        (0.80, 0.55, True),  # five of six: p >= 0.60, which is not below block_at 0.56
    ],
)
def test_escalate_at_is_the_highest_threshold_meeting_recall(recall, escalate_at, band_empty):
    scores = [(p, POS) for p in (0.5, 0.6, 0.7, 0.8, 0.9, 0.95)]
    scores += [(p, NEG) for p in (0.05, 0.1, 0.2, 0.3, 0.4, 0.55)]
    s = sweep(scores, Targets(0.95, recall))
    assert (s.block_at, s.escalate_at, s.band_empty) == (0.56, escalate_at, band_empty)


def test_a_collision_moves_escalate_at_just_below_block_at_and_reports_the_empty_band():
    """Every positive sits high and every negative low: precision is met from the bottom of
    the grid, and the highest threshold with full recall is the lowest positive (0.90)."""
    scores = [(p, POS) for p in (0.90, 0.92, 0.95)] + [(0.01, NEG)]
    s = sweep(scores, Targets(0.95, 1.0))
    assert s.block_at == 0.02 and s.escalate_at == 0.01 and s.band_empty
    # a collision higher up: recall 0.5 reaches 0.70, block_at is 0.56
    scores = [(0.6, POS), (0.7, POS), (0.8, POS), (0.5, NEG), (0.55, NEG)]
    s = sweep(scores, Targets(0.95, 0.5))
    assert (s.block_at, s.escalate_at, s.band_empty) == (0.56, 0.55, True)


def test_a_higher_recall_threshold_than_block_at_is_a_collision_and_is_pulled_down():
    scores = [(0.5, POS), (0.9, POS), (0.95, POS), (0.2, NEG)]
    s = sweep(scores, Targets(0.95, 0.5))  # block_at 0.21; recall 0.5 (2 of 3): p >= 0.90
    assert s.block_at == 0.21
    assert s.escalate_at == 0.20 and s.band_empty  # block_at - 0.01
    assert s.escalate_at < s.block_at


def test_no_threshold_meeting_precision_means_no_suggestion_at_all():
    scores = [(0.5, POS), (0.9, POS), (0.9, NEG), (0.95, NEG), (0.99, NEG)]
    s = sweep(scores, Targets(0.95, 0.9))
    assert (s.block_at, s.escalate_at) == (None, None) and not s.available
    assert s.reason == "no_threshold_meets_precision" and s.positives == 2


def test_a_threshold_with_nothing_predicted_does_not_meet_the_target():
    """The only positive scores 0.30: from 0.31 up nothing is predicted. Those thresholds
    are not 'precision 100%'; the first that predicts something decides."""
    scores = [(0.30, POS), (0.10, NEG)]
    s = sweep(scores, Targets(0.95, 0.9))
    assert s.block_at == 0.11  # the lowest where the negative at 0.10 is out and 0.30 is in
    point = confusion(scores, 0.31)
    assert point.predicted == 0 and not meets_precision(point, 0.5)


def test_a_rule_with_no_positives_or_no_examples_has_no_suggestion():
    assert sweep([(0.2, NEG), (0.9, NEG)]).reason == "no_positives"
    assert sweep([]).reason == "no_examples"


def test_no_threshold_meeting_recall_leaves_escalate_at_out_but_keeps_block_at():
    scores = [(0.00, POS), (0.9, POS), (0.95, POS)]  # a positive at 0.00: recall is never 1.0
    s = sweep(scores, Targets(0.95, 1.0))
    assert s.block_at == 0.02 and s.escalate_at is None
    assert s.reason == "no_threshold_meets_recall"


def test_block_at_is_never_0_01_so_that_escalate_at_has_room():
    scores = [(0.9, POS), (0.95, POS)]
    s = sweep(scores, Targets(0.95, 0.9))
    assert s.block_at == 0.02 and s.escalate_at is not None and s.escalate_at < s.block_at


def test_a_target_met_exactly_counts():
    """19 of 20 is exactly 0.95: it meets a target of 0.95 (no floating-point slip)."""
    scores = [(0.9, POS)] * 19 + [(0.9, NEG)]
    assert sweep(scores, Targets(0.95, 0.9)).block_at == 0.02
    assert meets_precision(confusion(scores, 0.5), 0.95)
    assert not meets_precision(confusion([(0.9, POS)] * 18 + [(0.9, NEG)] * 2, 0.5), 0.95)


def test_a_probability_equal_to_a_grid_value_is_at_or_above_it():
    assert confusion([(0.85, POS)], 0.85).tp == 1
    assert confusion([(0.85, POS)], 0.86).tp == 0
    assert confusion([(0.3 + 0.55, POS)], 0.85).tp == 1  # 0.8500000000000001-style arithmetic


def test_precision_at_the_rules_own_block_at_is_what_the_gate_checks():
    scores = [(0.9, POS)] * 18 + [(0.9, NEG)] * 2 + [(0.2, NEG)]
    point = precision_at(scores, 0.85)
    assert (point.tp, point.fp, point.precision) == (18, 2, 0.9)
    assert precision_at(scores, 0.95).precision is None  # nothing predicted


@pytest.mark.parametrize("bad", [0.49, 1.01, 0, -1, 0.955, True, "0.9", None])
def test_targets_are_0_50_to_1_00_in_hundredths(bad):
    with pytest.raises(TargetError):
        Targets(block_precision=bad)
    with pytest.raises(TargetError):
        Targets(escalate_recall=bad)


def test_the_defaults_are_the_agreed_values():
    t = Targets()
    assert (t.block_precision, t.escalate_recall) == (0.95, 0.90)
    assert Targets(0.5, 1.0).as_dict() == {
        "block_precision": 0.5,
        "escalate_recall": 1.0,
        "recall_tolerance": 2.0,
    }
