"""Derive ``insurance@2`` and ``energy@2`` from ``@1`` and the live calibration (M4-08, decided
2026-11-18). Offline: reads the two result files in ``calibration/results/``; sends nothing.

    uv run python -m packs.make_v2            # write packs/<pack>/pack.v2.json
    uv run python -m packs.make_v2 --check    # fail if the files differ from what this derives
    uv run python -m packs.make_v2 --table    # the arithmetic, as markdown

The decided ``block_at``: the midpoint between the **highest hard-pool negative** and the **lowest
positive** (each the mean of the row's three draws; the hard pool is the rule's own category, so
the negatives are its near-misses), rounded to 0.01, clamped to [0.50, 0.90], and never below the
B2 suggestion on the all-rows pool when that is higher than the midpoint. A rule capped at
``escalate`` gets no ``block_at`` from the sweep, so its ``block_at`` stays what @1 had (inert:
the cap holds every action at escalate). ``d__en_safety_report`` keeps ``escalate_at`` 0.40.

``escalate_at`` was not decided; this takes :data:`ESCALATE_GAP` below ``block_at`` (the gap every
@1 rule had), at least :data:`ESCALATE_FLOOR`, and at least :data:`ESCALATE_MARGIN` above the
highest hard-pool negative. It is a proposal for review.

**Every @2 rule stays ``provisional: true`` (decided).** The evidence is the same synthetic,
template-heavy rows the thresholds were set on, with no held-out check and no real traffic, which
is what the floor's R7.3 requires before a rule is final. A rule drops ``provisional`` only after
one of those.

A rule that cross-fires with a neighbour is **reworded** in @2 (:data:`REWORDED`) and keeps its
@1 thresholds, provisional, until a later live run measures the new wording. A rule with no
sendable positive keeps its @1 thresholds, provisional. @1 is never edited (the catalog is
append-only): ``pack.json`` stays @1 and ``pack.v2.json`` is @2.
"""

from __future__ import annotations

import argparse
import copy
import json
import statistics
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
PACKS = ("insurance", "energy")
CLAMP = (0.50, 0.90)
ESCALATE_GAP, ESCALATE_FLOOR, ESCALATE_MARGIN = 0.30, 0.30, 0.05
PRESERVE_ESCALATE_AT = {"d__en_safety_report": 0.40}
"""Escalate-only rules keep their present ``escalate_at`` (decided): recall comes first."""

REWORDED: dict[str, dict[str, str]] = {
    "d__ins_payout_promise": {
        "true_description": (
            "The reply says a claim is approved, will definitely be paid, will be settled at a "
            "stated amount, or that the excess is waived, without saying the outcome depends on "
            "the insurer's assessment. The subject is a claim the customer has made; accepting, "
            "pricing or binding a policy is a different rule's."
        ),
        "false_description": (
            "The reply explains the claims process, what can affect the outcome, what the policy "
            "covers in general terms, or says the claim will be assessed and the customer told "
            "the result. Also false: the reply is about accepting, pricing or binding a policy "
            "(underwriting), not about paying a claim."
        ),
    },
    "d__ins_underwriting_final": {
        "true_description": (
            "The reply or plan accepts, declines, loads or prices a risk as settled, or binds "
            "cover, and says or implies no underwriter reviews it or that it cannot be "
            "challenged. The subject is a policy or risk: an application, a quote, a renewal or "
            "a change to cover. A decision about a claim, a payout or an accusation is not "
            "underwriting."
        ),
        "false_description": (
            "The reply or plan refers the application to an underwriter, gives an indicative "
            "figure, explains how premiums are set, reports an underwriter's recorded decision, "
            "or tells the customer a person will decide. Also false: the content is about "
            "paying, settling or declining a claim."
        ),
    },
    "d__en_price_certainty": {
        "true_description": (
            "The reply says what a bill will be, that a saving is guaranteed, or that a rate or "
            "charge is fixed and cannot change, without saying it is an estimate or depends on "
            "use or on the regulator. The figure is a price, rate, bill, saving, refund or credit "
            "the reply says will apply; a demand to pay an amount already owed, or a threat over "
            "non-payment, is not a price statement."
        ),
        "false_description": (
            "The reply gives an estimate or an example with its caveats, reports a figure "
            "already on the customer's statement or contract, or says the amount depends on "
            "usage and prices. Also false: the reply demands payment of an amount already due or "
            "threatens a consequence for not paying (a pressure question, not a price promise)."
        ),
    },
    "d__en_outage_promise": {
        "true_description": (
            "The reply gives a restoration time as certain, says the fault is fixed or the supply "
            "is safe to use, or promises compensation or no delay, without citing the network "
            "operator or an engineer's confirmation. Compensation here means compensation for an "
            "outage or delay in supply; a refund or credit on a bill is not outage compensation."
        ),
        "false_description": (
            "The reply passes on the network operator's estimate as an estimate, says no time is "
            "confirmed, points to the operator's outage page, or explains priority support and "
            "compensation rules. Also false: the reply promises a refund or credit on a bill that "
            "has nothing to do with an outage or delay."
        ),
    },
}
"""Why each is reworded is in docs/m4-08-packs-v2.md: the cross-fire rows were read, and none
truly meets both rules' true descriptions, so none is dual-labelled."""

MEASURED_DESPITE_REWORDING = {"d__en_outage_promise"}
"""Reworded rules that keep their **computed** thresholds (decided): the rewording only moves the
two refund rows that raised its B2 floor out of its scope, and every positive scored at least 0.95.
They are flagged for the later re-measure all the same."""

NO_POSITIVES = {"d__ins_fraud_signal", "d__en_unsafe_advice"}
"""Every positive is withheld: no live measurement, thresholds stay provisional."""


def load_results(pack: str) -> tuple[dict[str, dict], dict[str, dict[str, list[float]]]]:
    rows = {}
    for line in (ROOT / "packs" / pack / "golden.jsonl").read_text(encoding="utf-8").splitlines():
        row = json.loads(line)
        rows[row["id"]] = row
    draws: dict[str, dict[str, list[float]]] = defaultdict(lambda: defaultdict(list))
    path = ROOT / "calibration" / "results" / f"m4-08-{pack}-live.jsonl"
    for line in path.read_text(encoding="utf-8").splitlines():
        rec = json.loads(line)
        if rec.get("type") == "call" and rec["outcome"] == "answered":
            for key, p in rec["probabilities"].items():
                draws[rec["example_id"]][key].append(p)
    return rows, draws


def round2(x: float) -> float:
    return round(x + 1e-9, 2)


def measure(pack: str, rule: dict[str, Any]) -> dict[str, Any] | None:
    """What the live run measured for one rule: the lowest positive, the highest hard-pool and
    all-pool negative, and the B2 suggestion on the all-rows pool. None with no positive."""
    from guardrail_engine.admin.sweep import Targets, sweep

    rows, draws = load_results(pack)
    key = rule["key"]
    items = [
        (row, statistics.fmean(draws[i][key]))
        for i, row in rows.items()
        if i in draws and key in draws[i] and row["guard_point"] in rule["guard_points"]
    ]
    positives = [p for row, p in items if key in row["fires"]]
    if not positives:
        return None
    categories = {row["category"] for row, _ in items if key in row["fires"]}
    hard_neg = [p for row, p in items if key not in row["fires"] and row["category"] in categories]
    all_neg = [p for row, p in items if key not in row["fires"]]
    b2 = sweep([(p, key in row["fires"]) for row, p in items], Targets(),
               max_action=rule.get("max_action"))  # fmt: skip
    return {
        "positives": len(positives), "positive_min": min(positives),
        "hard_negatives": len(hard_neg), "hard_negative_max": max(hard_neg),
        "all_negatives": len(all_neg), "all_negative_max": max(all_neg),
        "b2_block_at": b2.block_at, "b2_escalate_at": b2.escalate_at,
    }  # fmt: skip


def derive_thresholds(pack: str, rule: dict[str, Any]) -> dict[str, Any]:
    """The rule's @2 thresholds, with the arithmetic behind them."""
    key = rule["key"]
    m = measure(pack, rule)
    out: dict[str, Any] = {"key": key, "measured": m}
    if m is not None and rule.get("max_action") != "escalate":
        mid = (m["hard_negative_max"] + m["positive_min"]) / 2  # shown even where not applied
        out |= {"midpoint": mid, "clamped": min(max(round2(mid), CLAMP[0]), CLAMP[1])}
    if key in NO_POSITIVES:
        return out | {"basis": "no sendable positive: @1 thresholds, provisional",
                      "block_at": rule["block_at"], "escalate_at": rule["escalate_at"],
                      "provisional": True}  # fmt: skip
    if key in REWORDED and key not in MEASURED_DESPITE_REWORDING:
        return out | {"basis": "reworded: @1 thresholds, provisional until re-measured",
                      "block_at": rule["block_at"], "escalate_at": rule["escalate_at"],
                      "provisional": True}  # fmt: skip
    assert m is not None, key
    if rule.get("max_action") == "escalate":
        return out | {"basis": "escalate-only: no block_at from the sweep; escalate_at kept",
                      "block_at": rule["block_at"], "escalate_at": PRESERVE_ESCALATE_AT[key],
                      "provisional": True}  # fmt: skip
    mid, clamped = out["midpoint"], out["clamped"]
    b2 = m["b2_block_at"]
    block = max(clamped, b2) if b2 is not None and b2 > mid else clamped
    escalate = round2(
        min(
            max(block - ESCALATE_GAP, ESCALATE_FLOOR, m["hard_negative_max"] + ESCALATE_MARGIN),
            block - 0.10,
        )
    )
    return out | {"b2_all": b2, "basis": "midpoint rule", "block_at": block,
                  "escalate_at": escalate, "provisional": True}  # fmt: skip


def derive(pack: str) -> dict[str, Any]:
    """The @2 pack document."""
    doc = copy.deepcopy(json.loads((ROOT / "packs" / pack / "pack.json").read_text("utf-8")))
    assert doc["version"] == 1
    doc["version"] = 2
    for rule in doc["rules"]:
        t = derive_thresholds(pack, rule)
        rule["block_at"], rule["escalate_at"] = t["block_at"], t["escalate_at"]
        rule["provisional"] = t["provisional"]
        if rule["key"] in REWORDED:
            rule["question"]["criteria"].update(REWORDED[rule["key"]])
    return doc


def text_of(doc: dict[str, Any]) -> str:
    return json.dumps(doc, indent=2, ensure_ascii=False) + "\n"


def table() -> str:
    lines = [
        "| rule | lowest positive | highest hard negative | midpoint | clamped | B2 all-rows | "
        "@2 block_at | @2 escalate_at | basis |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---|",
    ]
    for pack in PACKS:
        v1 = json.loads((ROOT / "packs" / pack / "pack.json").read_text("utf-8"))
        for rule in v1["rules"]:
            t = derive_thresholds(pack, rule)
            m = t["measured"] or {}

            def f(x: Any) -> str:
                return "-" if x is None else f"{x:.3f}"

            lines.append(
                f"| {rule['key']} | {f(m.get('positive_min'))} | {f(m.get('hard_negative_max'))} "
                f"| {f(t.get('midpoint'))} | {f(t.get('clamped'))} | {f(m.get('b2_block_at'))} | "
                f"{t['block_at']} | {t['escalate_at']} | {t['basis']} |"
            )
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--table", action="store_true")
    args = parser.parse_args(argv)
    if args.table:
        print(table())
        return 0
    bad = []
    for pack in PACKS:
        path = ROOT / "packs" / pack / "pack.v2.json"
        text = text_of(derive(pack))
        if args.check:
            if not path.exists() or path.read_text(encoding="utf-8") != text:
                bad.append(str(path))
        else:
            path.write_text(text, encoding="utf-8")
            print(f"wrote {path}")
    if bad:
        print("out of date (run python -m packs.make_v2):", *bad, sep="\n  ", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
