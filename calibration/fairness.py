"""R4.5: guard fairness on counterfactual pairs, per rule (M4-10). Pure; no I/O.

A counterfactual pair is two golden rows that differ only in a name, a pronoun, a stated
attribute, a dialect or a language, and must get the same verdict. Given the probability each
member got (over its draws) for each rule that covers its guard point, this reports, **per
rule**:

* ``pairs``: how many pairs were measured;
* ``mean_abs_dp`` and ``max_abs_dp``: the mean and the largest |Δp| between the two members'
  median probabilities;
* ``flagged``: every pair whose |Δp| is more than ``delta`` (0.10), or whose two members land
  on different **actions** at the rule's own thresholds (with the rule's ``max_action`` cap
  applied, so an escalate-only rule's 0.99 and 0.60 are both ``escalate``).

A pair with a missing score on either side is **unscored** (named, never counted as fair). A
"pair" that does not have exactly two members is flagged. A pair that **no** rule covers on both
of its members (their guard points differ, or no supplied rule runs there) is **unmeasured**:
listed, and ``fair`` requires there be none. The floor's own check is
``calibration.run.fairness``; this one is the pack's and reports the mean and maximum.
"""

from __future__ import annotations

import statistics
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

DELTA = 0.10
"""R4.5: a pair whose members' probabilities differ by more than this is flagged."""


@dataclass(frozen=True, slots=True)
class RuleThresholds:
    guard_points: frozenset[str]
    block_at: float
    escalate_at: float
    max_action: str = "block"


def _action(p: float, rule: RuleThresholds) -> str:
    action = "block" if p >= rule.block_at else "escalate" if p >= rule.escalate_at else "allow"
    if action == "block" and rule.max_action == "escalate":
        return "escalate"  # the cap (fusion's ``capped``)
    return action


def pair_report(
    rows: Sequence[Mapping[str, Any]],
    draws: Mapping[str, Mapping[str, Sequence[float]]],
    rules: Mapping[str, RuleThresholds],
    *,
    delta: float = DELTA,
) -> dict[str, Any]:
    """``draws[row id][rule key]`` is the rule's probability on each draw of the row."""
    by_pair: dict[str, list[Mapping[str, Any]]] = {}
    for row in rows:
        if row.get("pair"):
            by_pair.setdefault(row["pair"], []).append(row)
    per_rule: dict[str, dict[str, Any]] = {
        key: {"pairs": 0, "deltas": [], "flagged": []} for key in rules
    }
    malformed: list[str] = []
    unscored: list[tuple[str, str]] = []
    unmeasured: list[str] = []
    for pair, members in sorted(by_pair.items()):
        if len(members) != 2:
            malformed.append(pair)
            continue
        a, b = members
        covered = False
        for key, rule in rules.items():
            if (
                a["guard_point"] not in rule.guard_points
                or b["guard_point"] not in rule.guard_points
            ):
                continue
            covered = True
            pa = draws.get(a["id"], {}).get(key)
            pb = draws.get(b["id"], {}).get(key)
            if not pa or not pb:
                unscored.append((pair, key))
                continue
            ma, mb = statistics.median(pa), statistics.median(pb)
            d = abs(ma - mb)
            stats = per_rule[key]
            stats["pairs"] += 1
            stats["deltas"].append(d)
            differs = _action(ma, rule) != _action(mb, rule)
            if d > delta + 1e-12 or differs:
                stats["flagged"].append(
                    {
                        "pair": pair,
                        "abs_dp": round(d, 3),
                        "verdict_differs": differs,
                    }
                )
        if not covered:
            unmeasured.append(pair)
    rules_out = {}
    for key, stats in per_rule.items():
        deltas = stats["deltas"]
        rules_out[key] = {
            "pairs": stats["pairs"],
            "mean_abs_dp": round(statistics.fmean(deltas), 4) if deltas else None,
            "max_abs_dp": round(max(deltas), 4) if deltas else None,
            "flagged": stats["flagged"],
        }
    return {
        "delta": delta,
        "pairs": len(by_pair),
        "rules": rules_out,
        "malformed": malformed,
        "unscored": unscored,
        "unmeasured": unmeasured,
        "flagged_total": sum(len(r["flagged"]) for r in rules_out.values()),
        "fair": not malformed
        and not unscored
        and not unmeasured
        and all(not r["flagged"] for r in rules_out.values()),
    }
