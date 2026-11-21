"""The threshold sweep (M4-01, B2): pure arithmetic, no I/O.

Given the probabilities one rule gave to a tenant's labelled golden examples, find the
thresholds on the 0.01 grid that meet the tenant's targets:

* ``block_at`` is the **lowest** threshold whose **precision** (of the examples at or above it,
  the share labelled ``block``) is at least the target. A threshold at which nothing is
  predicted positive doesn't meet the target.
* ``escalate_at`` is the **highest** threshold whose **recall** (of the examples labelled
  ``block``, the share at or above it) is at least the target.
* If ``escalate_at >= block_at`` the escalation band is empty: ``escalate_at`` becomes
  ``block_at - 0.01`` and the result says so (``band_empty``).
* If no threshold meets the precision target there is **no suggestion** at all, and the rule
  fails the R1 precision gate.

The compiler requires ``0.01 <= escalate_at < block_at <= 0.99``, so ``block_at`` is searched
from 0.02 up (a ``block_at`` of 0.01 would leave no room for an ``escalate_at``), and ``block_at``
is at most 0.99.

Targets are compared exactly (as fractions of the decimal text), so a precision of exactly 0.95
meets a 0.95 target. A probability is at or above a grid value when it is within 1e-9 of it.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from fractions import Fraction

GRID = tuple(k / 100 for k in range(1, 100))
"""0.01 ... 0.99."""
DEFAULT_PRECISION = 0.95
DEFAULT_RECALL = 0.90
DEFAULT_TOLERANCE = 2.0
"""The regression gate's tolerance in recall points (AC-A3): a version may lose this many points
of golden-set recall against the active one, and no more."""
TOLERANCE_MAX = 20.0
TARGET_MIN, TARGET_MAX = 0.50, 1.00
_EPS = 1e-9


class TargetError(ValueError):
    """A target outside 0.50 to 1.00, or not a whole number of hundredths."""


@dataclass(frozen=True, slots=True)
class Targets:
    """The tenant's calibration settings: ``block_precision`` for ``block_at`` and
    ``escalate_recall`` for ``escalate_at`` (each 0.50 to 1.00 in steps of 0.01), and
    ``recall_tolerance``, the regression gate's tolerance in points (0 to 20 in steps of 0.5)."""

    block_precision: float = DEFAULT_PRECISION
    escalate_recall: float = DEFAULT_RECALL
    recall_tolerance: float = DEFAULT_TOLERANCE

    def __post_init__(self) -> None:
        for name in ("block_precision", "escalate_recall"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise TargetError(f"{name} must be a number")
            if (
                not TARGET_MIN <= value <= TARGET_MAX
                or abs(value * 100 - round(value * 100)) > _EPS
            ):
                raise TargetError(f"{name} must be 0.50 to 1.00 in steps of 0.01")
        tolerance = self.recall_tolerance
        if (
            isinstance(tolerance, bool)
            or not isinstance(tolerance, (int, float))
            or not 0 <= tolerance <= TOLERANCE_MAX
            or abs(tolerance * 2 - round(tolerance * 2)) > _EPS
        ):
            raise TargetError("recall_tolerance must be 0 to 20 points in steps of 0.5")

    def as_dict(self) -> dict[str, float]:
        return {
            "block_precision": self.block_precision,
            "escalate_recall": self.escalate_recall,
            "recall_tolerance": self.recall_tolerance,
        }


@dataclass(frozen=True, slots=True)
class Point:
    """The confusion counts at one threshold."""

    threshold: float
    tp: int
    fp: int
    positives: int

    @property
    def predicted(self) -> int:
        return self.tp + self.fp

    @property
    def precision(self) -> float | None:
        """None when nothing is predicted positive."""
        return None if self.predicted == 0 else self.tp / self.predicted

    @property
    def recall(self) -> float | None:
        return None if self.positives == 0 else self.tp / self.positives


@dataclass(frozen=True, slots=True)
class Suggestion:
    """The sweep's answer for one rule. ``block_at`` is None when no threshold meets the
    precision target (no suggestion), and then ``escalate_at`` is None too."""

    block_at: float | None
    escalate_at: float | None
    band_empty: bool
    """``escalate_at`` was moved to ``block_at - 0.01`` because recall's highest threshold
    reached ``block_at``: there is no escalation band."""
    precision: float | None
    """Precision at ``block_at``."""
    recall: float | None
    """Recall at ``escalate_at``."""
    examples: int
    positives: int
    reason: str | None = None
    """Why there is no suggestion (``no_threshold_meets_precision``, ``no_positives``,
    ``no_examples``) or no ``escalate_at`` (``no_threshold_meets_recall``)."""
    escalate_only: bool = False
    """The rule's ``max_action`` is ``escalate`` (M4-10): only ``escalate_at`` is swept, and
    ``block_at`` is never set (it stays None: nothing may block on this rule)."""

    @property
    def available(self) -> bool:
        if self.escalate_only:
            return self.escalate_at is not None
        return self.block_at is not None


def confusion(scores: Sequence[tuple[float, bool]], threshold: float) -> Point:
    """The counts at ``threshold``: ``scores`` are ``(p, labelled_block)``."""
    tp = fp = positives = 0
    for p, positive in scores:
        positives += positive
        if p >= threshold - _EPS:
            if positive:
                tp += 1
            else:
                fp += 1
    return Point(threshold, tp, fp, positives)


def meets_precision(point: Point, target: float) -> bool:
    """Precision at or above ``target`` with something predicted positive (exact)."""
    if point.predicted == 0:
        return False
    return Fraction(point.tp, point.predicted) >= Fraction(str(round(target, 2)))


def meets_recall(point: Point, target: float) -> bool:
    if point.positives == 0:
        return False
    return Fraction(point.tp, point.positives) >= Fraction(str(round(target, 2)))


def sweep_escalate_only(
    scores: Sequence[tuple[float, bool]], targets: Targets | None = None
) -> Suggestion:
    """The suggestion for a rule whose ``max_action`` is ``escalate`` (M4-10, R4.3): the rule
    may hold content for a person and never refuse it, so there is **no** ``block_at`` and no
    precision target: ``escalate_at`` is the **highest** threshold whose **recall** (of the
    examples labelled positive, the share at or above it) is at least the recall target. A
    ``p`` of 0.99 on the rule escalates, so the sweep must not tune a ``block_at`` that nothing
    can use. No threshold meeting the recall target means no suggestion."""
    targets = targets or Targets()
    n = len(scores)
    positives = sum(1 for _, positive in scores if positive)
    if n == 0:
        return Suggestion(None, None, False, None, None, 0, 0, "no_examples", True)
    if positives == 0:
        return Suggestion(None, None, False, None, None, n, 0, "no_positives", True)
    recall_ok = [
        pt
        for pt in (confusion(scores, t) for t in GRID)
        if meets_recall(pt, targets.escalate_recall)
    ]
    if not recall_ok:
        return Suggestion(
            None, None, False, None, None, n, positives, "no_threshold_meets_recall", True
        )
    best = max(recall_ok, key=lambda pt: pt.threshold)
    return Suggestion(None, best.threshold, False, None, best.recall, n, positives, None, True)


def sweep(
    scores: Sequence[tuple[float, bool]],
    targets: Targets | None = None,
    *,
    max_action: str | None = None,
) -> Suggestion:
    """The B2 suggestion for one rule from ``(p, labelled_block)`` pairs. A rule whose
    ``max_action`` is ``escalate`` gets :func:`sweep_escalate_only`: **never a ``block_at``**."""
    if max_action == "escalate":
        return sweep_escalate_only(scores, targets)
    targets = targets or Targets()
    n = len(scores)
    positives = sum(1 for _, positive in scores if positive)
    if n == 0:
        return Suggestion(None, None, False, None, None, 0, 0, "no_examples")
    if positives == 0:
        return Suggestion(None, None, False, None, None, n, 0, "no_positives")
    points = [confusion(scores, t) for t in GRID]
    block = next((pt for pt in points[1:] if meets_precision(pt, targets.block_precision)), None)
    if block is None:
        return Suggestion(
            None, None, False, None, None, n, positives, "no_threshold_meets_precision"
        )
    recall_ok = [pt for pt in points if meets_recall(pt, targets.escalate_recall)]
    if not recall_ok:
        return Suggestion(
            block.threshold, None, False, block.precision, None, n, positives,
            "no_threshold_meets_recall",
        )  # fmt: skip
    escalate = max(recall_ok, key=lambda pt: pt.threshold)
    band_empty = escalate.threshold >= block.threshold
    if band_empty:
        escalate = points[round(block.threshold * 100) - 2]  # block_at - 0.01
    return Suggestion(
        block.threshold, escalate.threshold, band_empty, block.precision, escalate.recall, n,
        positives,
    )  # fmt: skip


def precision_at(scores: Sequence[tuple[float, bool]], block_at: float) -> Point:
    """The confusion counts at the rule's own ``block_at``: what the R1 precision gate checks."""
    return confusion(scores, block_at)
