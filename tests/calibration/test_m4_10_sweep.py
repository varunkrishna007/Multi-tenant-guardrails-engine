"""M4-10: the B2 sweep never sets ``block_at`` on a rule whose ``max_action`` is ``escalate``.
Its ``escalate_at`` is the highest threshold meeting the recall target, nothing else."""

import pytest
from calibration.metrics import b2_sweep

from guardrail_engine.admin.sweep import Targets, sweep

# positives score 0.55..0.95 (10 of them), negatives 0.05..0.45
POS = [(0.55 + i * 0.04, True) for i in range(11)]
NEG = [(0.05 + i * 0.04, False) for i in range(11)]
SCORES = POS + NEG


def test_a_rule_that_may_block_gets_both_thresholds_as_before():
    s = sweep(SCORES)
    assert s.block_at is not None and s.escalate_at is not None and s.escalate_only is False


def test_an_escalate_only_rule_gets_an_escalate_at_and_never_a_block_at():
    s = sweep(SCORES, max_action="escalate")
    assert s.block_at is None and s.precision is None and s.escalate_only is True
    assert s.available is True
    # highest grid threshold at which at least 90% of the positives are at or above it
    positives = sorted(p for p, y in SCORES if y)
    expected = max(
        t / 100 for t in range(1, 100) if sum(p >= t / 100 - 1e-9 for p in positives) >= 0.9 * 11
    )
    assert s.escalate_at == pytest.approx(expected)
    assert s.recall is not None and s.recall >= 0.90 and s.band_empty is False


def test_the_precision_target_is_not_tuned_for_an_escalate_only_rule():
    noisy = (
        [(0.9, True)] * 5 + [(0.9, False)] * 5 + [(0.2, False)] * 5
    )  # precision never reaches .95
    assert sweep(noisy).available is False  # a blocking rule has no suggestion
    s = sweep(noisy, max_action="escalate")
    assert s.available is True and s.block_at is None and s.escalate_at == 0.9


def test_the_recall_target_still_decides_escalate_at():
    low = sweep(SCORES, Targets(escalate_recall=0.50), max_action="escalate")
    high = sweep(SCORES, Targets(escalate_recall=1.00), max_action="escalate")
    assert low.escalate_at > high.escalate_at
    assert high.escalate_at == pytest.approx(0.55)


def test_no_examples_or_no_positives_is_no_suggestion_and_says_why():
    assert sweep([], max_action="escalate").reason == "no_examples"
    only_neg = sweep([(0.3, False)], max_action="escalate")
    assert only_neg.reason == "no_positives" and only_neg.available is False
    unreachable = sweep([(0.005, True), (0.004, True)], max_action="escalate")
    assert unreachable.reason == "no_threshold_meets_recall" and unreachable.escalate_at is None


def test_the_calibration_harness_sweep_follows_the_same_rule():
    ps = [p for p, _ in SCORES]
    ys = [int(y) for _, y in SCORES]
    plain = b2_sweep(ps, ys, 0.95, 0.90)
    assert plain.block_at is not None
    capped = b2_sweep(ps, ys, 0.95, 0.90, max_action="escalate")
    assert capped.block_at is None and capped.band_empty is False and capped.block_counts is None
    assert capped.escalate_at is not None and capped.escalate_counts.recall >= 0.90
