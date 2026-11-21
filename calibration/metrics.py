"""Pure calibration metrics for M0-02: reliability, ECE, precision and recall on the 0.01
grid, Wilson intervals, and the B2 threshold sweep. No I/O; tested offline."""

from __future__ import annotations

import math
from collections.abc import Sequence
from dataclasses import dataclass

GRID: tuple[float, ...] = tuple(round(i / 100, 2) for i in range(1, 100))
"""Thresholds 0.01 to 0.99 (B2's 0.01 grid). A call predicts positive when p >= threshold."""


# --------------------------------------------------------------------------- reliability


@dataclass(frozen=True)
class Bin:
    lo: float
    hi: float
    n: int
    mean_p: float | None
    frac_positive: float | None


def reliability(ps: Sequence[float], ys: Sequence[int], bins: int = 10) -> list[Bin]:
    """Equal-width bins over [0, 1]. The last bin includes 1.0."""
    _check(ps, ys)
    out = []
    for b in range(bins):
        lo, hi = b / bins, (b + 1) / bins
        idx = [i for i, p in enumerate(ps) if lo <= p < hi or (b == bins - 1 and p == hi)]
        if idx:
            out.append(
                Bin(
                    lo,
                    hi,
                    len(idx),
                    sum(ps[i] for i in idx) / len(idx),
                    sum(ys[i] for i in idx) / len(idx),
                )
            )
        else:
            out.append(Bin(lo, hi, 0, None, None))
    return out


def ece(ps: Sequence[float], ys: Sequence[int], bins: int = 10) -> float:
    """Expected calibration error: sum over bins of (n_bin / N) * |mean p - observed rate|."""
    total = len(ps)
    return sum(
        b.n / total * abs(b.mean_p - b.frac_positive)  # type: ignore[operator]
        for b in reliability(ps, ys, bins)
        if b.n
    )


# --------------------------------------------------------------------------- thresholds


@dataclass(frozen=True)
class Counts:
    threshold: float
    tp: int
    fp: int
    fn: int
    tn: int

    @property
    def predicted(self) -> int:
        return self.tp + self.fp

    @property
    def positives(self) -> int:
        return self.tp + self.fn

    @property
    def precision(self) -> float | None:
        """None when nothing is predicted positive (B2: that never meets a target)."""
        return self.tp / self.predicted if self.predicted else None

    @property
    def recall(self) -> float | None:
        return self.tp / self.positives if self.positives else None


def counts_at(ps: Sequence[float], ys: Sequence[int], threshold: float) -> Counts:
    _check(ps, ys)
    tp = fp = fn = tn = 0
    for p, y in zip(ps, ys, strict=True):
        hit = p >= threshold - 1e-12
        if hit and y:
            tp += 1
        elif hit:
            fp += 1
        elif y:
            fn += 1
        else:
            tn += 1
    return Counts(threshold, tp, fp, fn, tn)


def same_counts_through(ps: Sequence[float], ys: Sequence[int], threshold: float) -> float:
    """The highest grid threshold at or above ``threshold`` with the same counts.

    When scores are well separated, every threshold in a gap gives identical counts on the
    golden set, so a B2 ``block_at`` at the bottom of the gap is no better supported than
    one at the top. This reports the top."""
    base = counts_at(ps, ys, threshold)
    key = (base.tp, base.fp, base.fn, base.tn)
    top = threshold
    for t in GRID:
        if t < threshold - 1e-12:
            continue
        c = counts_at(ps, ys, t)
        if (c.tp, c.fp, c.fn, c.tn) != key:
            break
        top = t
    return top


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float] | None:
    """Wilson score interval for k successes in n trials (95% by default). None if n == 0."""
    if n == 0:
        return None
    phat = k / n
    denom = 1 + z * z / n
    centre = (phat + z * z / (2 * n)) / denom
    half = z * math.sqrt(phat * (1 - phat) / n + z * z / (4 * n * n)) / denom
    return max(0.0, centre - half), min(1.0, centre + half)


@dataclass(frozen=True)
class Sweep:
    precision_target: float
    recall_target: float
    block_at: float | None
    """Lowest grid threshold whose precision meets the target (B2), or None."""
    escalate_at: float | None
    """Highest grid threshold whose recall meets the target, adjusted per B2."""
    band_empty: bool
    """True if escalate_at had to be set to block_at - 0.01 (B2)."""
    block_counts: Counts | None
    escalate_counts: Counts | None


def b2_sweep(
    ps: Sequence[float],
    ys: Sequence[int],
    precision_target: float,
    recall_target: float,
    *,
    max_action: str | None = None,
) -> Sweep:
    """B2:

    * ``block_at`` is the lowest threshold on the 0.01 grid whose precision is >= the target.
      A threshold that predicts nothing positive doesn't count.
    * ``escalate_at`` is the highest threshold whose recall is >= the target.
    * If ``escalate_at >= block_at``: ``escalate_at = block_at - 0.01`` and the band is
      reported empty. Values are clamped to [0.01, 0.99].
    * If no threshold meets the precision target there is no ``block_at`` (and the rule fails
      the R1 precision gate); ``escalate_at`` is still reported.
    * **A rule whose ``max_action`` is ``escalate`` (M4-10) never gets a ``block_at``**: nothing
      may block on it, so no precision target is tuned. Its ``escalate_at`` is the highest
      threshold meeting the recall target, with no band adjustment.
    """
    table = [counts_at(ps, ys, t) for t in GRID]
    if max_action == "escalate":
        esc = next(
            (c for c in reversed(table) if c.recall is not None and c.recall >= recall_target),
            None,
        )
        return Sweep(
            precision_target, recall_target, None, esc.threshold if esc else None, False, None, esc
        )
    block = next(
        (c for c in table if c.precision is not None and c.precision >= precision_target), None
    )
    esc = next(
        (c for c in reversed(table) if c.recall is not None and c.recall >= recall_target), None
    )
    band_empty = False
    escalate_at = esc.threshold if esc else None
    if block is not None and escalate_at is not None and escalate_at >= block.threshold:
        escalate_at = _clamp(round(block.threshold - 0.01, 2))
        band_empty = True
        esc = counts_at(ps, ys, escalate_at)
    return Sweep(
        precision_target,
        recall_target,
        block.threshold if block else None,
        escalate_at,
        band_empty,
        block,
        esc,
    )


def _clamp(x: float) -> float:
    return min(0.99, max(0.01, x))


def _check(ps: Sequence[float], ys: Sequence[int]) -> None:
    if len(ps) != len(ys):
        raise ValueError("ps and ys differ in length")
    if not ps:
        raise ValueError("no data")
    if any(y not in (0, 1) for y in ys):
        raise ValueError("labels must be 0 or 1")


def _binom_cdf(k: int, n: int, p: float) -> float:
    """P(X <= k) for X ~ Binomial(n, p), summed in log space for stability."""
    if p <= 0.0:
        return 1.0
    if p >= 1.0:
        return 1.0 if k >= n else 0.0
    lp, lq = math.log(p), math.log1p(-p)
    total = 0.0
    for i in range(k + 1):
        total += math.exp(
            math.lgamma(n + 1) - math.lgamma(i + 1) - math.lgamma(n - i + 1) + i * lp + (n - i) * lq
        )
    return min(1.0, total)


def clopper_pearson_upper(k: int, n: int, confidence: float = 0.95) -> float | None:
    """One-sided Clopper-Pearson upper bound on a rate from k events in n (R7 Definitions):
    the p at which P(X <= k) = 1 - confidence. None when n is 0; 1.0 when k = n."""
    if n <= 0:
        return None
    if not 0 <= k <= n:
        raise ValueError(f"k={k} must be in [0, n={n}]")
    if k == n:
        return 1.0
    alpha = 1.0 - confidence
    lo, hi = k / n, 1.0
    for _ in range(100):  # bisection: the CDF falls as p rises
        mid = (lo + hi) / 2
        if _binom_cdf(k, n, mid) > alpha:
            lo = mid
        else:
            hi = mid
    return hi
