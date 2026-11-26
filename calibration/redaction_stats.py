"""The statistics of the redaction trial (M7-12): intervals, an exact paired test, a bootstrap.

Plain Python, no dependency, deterministic: the bootstrap takes a seed. Offline; sends nothing.

* :func:`clopper_pearson` is the exact two-sided interval for a rate; the one-sided upper bound the
  calibration reports use is :func:`calibration.metrics.clopper_pearson_upper`.
* :func:`mcnemar_exact` is the exact paired test on the rows that flip: of ``b + c`` flips,
  ``b`` went one way. The one-sided value asks whether that many (or more) is plausible if a flip
  is equally likely to go either way.
* :func:`bootstrap_mean` resamples **rows** (the unit that is paired), not draws.
"""

from __future__ import annotations

import math
import random
from collections.abc import Sequence

from calibration.metrics import _binom_cdf


def clopper_pearson(k: int, n: int, confidence: float = 0.95) -> tuple[float, float] | None:
    """The exact two-sided interval for ``k`` events in ``n`` (None when ``n`` is 0)."""
    if n <= 0:
        return None
    if not 0 <= k <= n:
        raise ValueError(f"k={k} must be in [0, n={n}]")
    alpha = (1.0 - confidence) / 2

    def upper() -> float:
        if k == n:
            return 1.0
        lo, hi = k / n, 1.0
        for _ in range(100):  # P(X <= k) falls as p rises: solve it at alpha
            mid = (lo + hi) / 2
            lo, hi = (mid, hi) if _binom_cdf(k, n, mid) > alpha else (lo, mid)
        return hi

    def lower() -> float:
        if k == 0:
            return 0.0
        lo, hi = 0.0, k / n
        for _ in range(100):  # P(X >= k) = 1 - P(X <= k-1) rises with p: solve it at alpha
            mid = (lo + hi) / 2
            lo, hi = (lo, mid) if 1.0 - _binom_cdf(k - 1, n, mid) > alpha else (mid, hi)
        return lo

    return lower(), upper()


def mcnemar_exact(b: int, c: int) -> dict[str, float]:
    """Exact McNemar on ``b`` flips one way and ``c`` the other: the one-sided value for "at
    least ``b`` of the ``b + c`` flips go the first way" and the two-sided value (twice the
    smaller tail, at most 1). With no flips both are 1."""
    n = b + c
    if n == 0:
        return {"one_sided": 1.0, "two_sided": 1.0}
    one = 1.0 - _binom_cdf(b - 1, n, 0.5) if b > 0 else 1.0
    other = 1.0 - _binom_cdf(c - 1, n, 0.5) if c > 0 else 1.0
    return {"one_sided": min(1.0, one), "two_sided": min(1.0, 2 * min(one, other))}


def bootstrap_mean(
    values: Sequence[float], *, seed: int, resamples: int = 4000, confidence: float = 0.95
) -> tuple[float, float] | None:
    """A percentile bootstrap interval for the mean of ``values`` (None for no values)."""
    if not values:
        return None
    rng = random.Random(seed)
    n = len(values)
    means = sorted(sum(rng.choices(values, k=n)) / n for _ in range(resamples))
    tail = (1.0 - confidence) / 2
    low = math.floor(tail * resamples)
    high = math.ceil((1 - tail) * resamples) - 1
    return means[low], means[high]


def mean(values: Sequence[float]) -> float | None:
    return sum(values) / len(values) if values else None


__all__ = ["bootstrap_mean", "clopper_pearson", "mcnemar_exact", "mean"]
