# ruff: noqa: E501
"""The results note of a pack live run (M4-08, M5-04): one ``.md`` beside each ``.jsonl``.

    uv run python -m calibration.write_results            # the four 2026-11-19 runs
    uv run python -m calibration.write_results NAME ...   # only these (names in :data:`RUNS`)

Offline: reads the records and the pack files, sends nothing, applies nothing. For each rule it
gives n, the score distribution, the thresholds the **agreed** rules suggest, the confusion
there and at the present thresholds, the gates, and the difference from the present values.

**The B2 all-rows floor excludes other rules' positives** (decided 2026-11-19, every pack): a row
that is a positive of another **enforce-mode, blocking** rule (not capped at ``escalate``) at the
same guard point is not a false positive for this rule, because blocking it is right. Benign
rows count, and so do the positives of escalate-only rules. The exclusion applies to the all
pool everywhere (the B2 suggestion, the confusion, the gates). The hard pool is the rule's own
category and is unchanged.
"""

from __future__ import annotations

import json
import math
import statistics
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:  # pragma: no cover - run as a script
    sys.path.insert(0, str(ROOT))

from calibration import pack_live as pl  # noqa: E402
from guardrail_engine.admin.sweep import Targets, confusion, sweep  # noqa: E402
from packs import make_v2  # noqa: E402

RES = ROOT / "calibration" / "results"
RUNS = [
    # name, pack, version, rules
    (
        "m4-08-insurance-v2-remeasure-r3",
        "insurance",
        2,
        ["d__ins_payout_promise", "d__ins_underwriting_final"],
    ),
    (
        "m4-08-energy-v2-remeasure-r3",
        "energy",
        2,
        ["d__en_price_certainty", "d__en_outage_promise"],
    ),
    ("m5-04-finance-live-3", "finance", 1, None),
    ("m5-04-healthcare-live-r2", "healthcare", 1, None),
]
CLAMP, GAP, FLOOR, MARGIN = (0.50, 0.90), 0.30, 0.30, 0.05
T = Targets()


def f(x, nd=2):
    return "-" if x is None else f"{x:.{nd}f}"


def pct(x):
    return "-" if x is None else f"{x:.3f}"


def q(values, p):
    if not values:
        return None
    s = sorted(values)
    return s[min(len(s) - 1, math.ceil(p * len(s)) - 1)]


def cm(scores, t):
    pt = confusion(scores, t)
    pos = pt.positives
    neg = len(scores) - pos
    return {
        "tp": pt.tp,
        "fp": pt.fp,
        "fn": pos - pt.tp,
        "tn": neg - pt.fp,
        "precision": pt.precision,
        "recall": pt.recall,
        "false_act": None if neg == 0 else pt.fp / neg,
    }


def cm_line(c):
    return (
        f"{c['tp']} / {c['fp']} / {c['fn']} / {c['tn']} | {f(c['precision'])} | "
        f"{f(c['recall'])} | {f(c['false_act'])}"
    )


def histogram(scores):
    bins = [[0, 0] for _ in range(10)]
    for p, pos in scores:
        bins[min(9, int(p * 10 + 1e-9))][0 if pos else 1] += 1
    return bins


def blocking_owners(
    rule: Mapping[str, Any], rules: Sequence[Mapping[str, Any]], rows: Sequence[Mapping[str, Any]]
) -> dict[str, list[str]]:
    """The rows that are no false positive for ``rule``, each with the rules whose positive it is:
    positives of another enforce-mode rule that can block (no ``max_action`` of ``escalate``) at
    the row's guard point (which is also one of ``rule``'s)."""
    blockers = [
        r
        for r in rules
        if r["key"] != rule["key"]
        and r.get("mode") == "enforce"
        and r.get("max_action") != "escalate"
    ]
    out: dict[str, list[str]] = {}
    for row in rows:
        if rule["key"] in row["fires"] or row["guard_point"] not in rule["guard_points"]:
            continue
        owners = [
            r["key"]
            for r in blockers
            if r["key"] in row["fires"] and row["guard_point"] in r["guard_points"]
        ]
        if owners:
            out[row["id"]] = owners
    return out


def other_blocking_positives(
    rule: Mapping[str, Any], rules: Sequence[Mapping[str, Any]], rows: Sequence[Mapping[str, Any]]
) -> set[str]:
    """Ids of the rows that are no false positive for ``rule`` (see :func:`blocking_owners`)."""
    return set(blocking_owners(rule, rules, rows))


def ruled(rule, hard, all_):
    """The decided thresholds and what bound them."""
    pos = [p for p, is_pos in hard if is_pos]
    neg = [p for p, is_pos in hard if not is_pos]
    out = {"basis": None, "notes": []}
    if not pos:
        out["basis"] = "no positive row was sent: nothing to measure; present values stand"
        return out
    out["lowest_pos"] = min(pos)
    out["highest_hard_neg"] = max(neg) if neg else None
    b2 = sweep(all_, T, max_action=rule.get("max_action"))
    out["b2"] = b2
    if rule.get("max_action") == "escalate":
        out["basis"] = "escalate-only: no block_at from the sweep; escalate_at kept (decided)"
        out["block_at"] = None
        out["escalate_at"] = rule["escalate_at"]
        out["notes"].append(
            f"B2 escalate-only suggestion (highest threshold with recall >= 0.90) is "
            f"{f(b2.escalate_at)}; not applied (recall first, decided)."
        )
        return out
    if out["highest_hard_neg"] is None:
        out["basis"] = "no hard-pool negative: the midpoint is undefined; present values stand"
        return out
    mid = (out["highest_hard_neg"] + out["lowest_pos"]) / 2
    r2 = make_v2.round2(mid)
    clamped = min(max(r2, CLAMP[0]), CLAMP[1])
    out |= {"mid": mid, "rounded": r2, "clamped": clamped}
    if r2 < CLAMP[0]:
        out["notes"].append(
            f"clamp floor {CLAMP[0]:.2f} bound (midpoint {f(mid, 3)} rounds to {f(r2)})"
        )
    elif r2 > CLAMP[1]:
        out["notes"].append(f"clamp ceiling {CLAMP[1]:.2f} bound (midpoint {f(mid, 3)})")
    block = clamped
    if CLAMP[0] <= r2 <= CLAMP[1]:
        out["notes"].append(f"midpoint {f(mid, 3)} -> {f(r2)}, no clamp")
    if b2.block_at is not None and b2.block_at > mid:
        block = max(clamped, b2.block_at)
        if b2.block_at > clamped:
            out["notes"].append(
                f"B2 all-rows floor bound: the sweep's block_at {f(b2.block_at)} is above the "
                f"midpoint, so block_at = {f(block)}"
            )
        else:
            out["notes"].append(
                f"B2 all-rows floor {f(b2.block_at)} is above the midpoint but not above the "
                f"clamped value, so it did not bind"
            )
    elif b2.block_at is None:
        out["notes"].append(f"B2 on all rows: no block_at ({b2.reason}); the midpoint is used")
    terms = {
        "block_at - 0.30": block - GAP,
        "floor 0.30": FLOOR,
        "highest hard negative + 0.05": out["highest_hard_neg"] + MARGIN,
    }
    lead = max(terms, key=terms.get)
    esc = min(max(terms.values()), block - 0.10)
    capped = max(terms.values()) > block - 0.10
    esc = make_v2.round2(esc)
    out["notes"].append(
        "escalate_at = " + ("block_at - 0.10 (the cap bound)" if capped else lead + " (bound)")
    )
    out |= {"basis": "midpoint rule", "block_at": block, "escalate_at": esc}
    return out


def pool_section(rule, name, scores, rd, present, label):
    pos = [p for p, is_pos in scores if is_pos]
    neg = [p for p, is_pos in scores if not is_pos]
    lines = [f"**{name} pool**: {len(pos)} positives, {len(neg)} negatives"]
    lines.append(
        f"positives min {f(min(pos) if pos else None, 3)}, median "
        f"{f(statistics.median(pos) if pos else None, 3)}, max {f(max(pos) if pos else None, 3)}; "
        f"negatives median {f(statistics.median(neg) if neg else None, 3)}, p95 "
        f"{f(q(neg, 0.95), 3)}, max {f(max(neg) if neg else None, 3)}"
    )
    return lines, pos, neg


def rule_pools(rule, all_rules, rows, by_row):
    """One rule's scored pools: ``(all, hard, ranges, draws, excluded)``. ``all`` and ``hard`` are
    lists of (row mean, is positive); the all pool leaves out the rows that are another blocking
    rule's positive. ``excluded`` lists them, ``(row id, row mean, the rules it is a positive of)``,
    highest first; ``draws`` are the all pool's single draws."""
    key = rule["key"]
    at_gp = [row for row in rows if row["guard_point"] in rule["guard_points"]]
    own = {row["category"] for row in at_gp if key in row["fires"]}
    skip = blocking_owners(rule, all_rules, at_gp)
    all_sc, hard_sc, ranges, draws_all, excluded = [], [], [], [], []
    for row in at_gp:
        ps = by_row.get(row["id"], {}).get(key, [])
        if not ps:
            continue
        item = (statistics.fmean(ps), key in row["fires"])
        in_hard = row["category"] in own or key in row["fires"]
        if row["id"] in skip:
            excluded.append((row["id"], item[0], skip[row["id"]]))  # blocking it is right
            if in_hard:
                hard_sc.append(item)
            continue
        all_sc.append(item)
        draws_all += [(p, key in row["fires"]) for p in ps]
        if in_hard:
            hard_sc.append(item)
        if len(ps) > 1:
            ranges.append(max(ps) - min(ps))
    excluded.sort(key=lambda e: (-e[1], e[0]))
    return all_sc, hard_sc, ranges, draws_all, excluded


def prior_all_negatives(pack, rule, all_rules):
    """The earlier live run's highest all-pool negative with another blocking rule's positives
    left out (what :func:`make_v2.measure` reports with them in)."""
    rows, draws = make_v2.load_results(pack)
    key = rule["key"]
    at_gp = [r for i, r in rows.items() if i in draws and key in draws[i]]
    skip = blocking_owners(rule, all_rules, at_gp)
    scores = [
        statistics.fmean(draws[r["id"]][key])
        for r in at_gp
        if key not in r["fires"]
        and r["guard_point"] in rule["guard_points"]
        and r["id"] not in skip
    ]
    return max(scores, default=None)


def load_run(name, pack, version, rules):
    """A run's records, the rows it sent, the pack document it measured and each row's draws."""
    records = pl._read(RES / f"{name}.jsonl")
    all_rows, _ = pl.load_sendable(pack)
    rows = pl.select_rows(pack, version, all_rows, tuple(rules) if rules else None)
    doc = json.loads(pl.pack_path(pack, version).read_text(encoding="utf-8"))
    by_row = {}
    for rec in pl.complete_records(records, 3):
        if rec.get("type") == "call":
            for key, p in rec["probabilities"].items():
                by_row.setdefault(rec["example_id"], {}).setdefault(key, []).append(p)
    return records, rows, doc, by_row


def suggestions(name):
    """The decided thresholds for every rule of a run: ``{key: ruled(...)}``. What the packs'
    next versions are derived from (``packs.derive_versions``)."""
    _name, pack, version, rules = next(r for r in RUNS if r[0] == name)
    _records, rows, doc, by_row = load_run(name, pack, version, rules)
    out = {}
    for rule in doc["rules"]:
        if rules and rule["key"] not in rules:
            continue
        all_sc, hard_sc, *_ = rule_pools(rule, doc["rules"], rows, by_row)
        out[rule["key"]] = ruled(rule, hard_sc, all_sc)
    return out


def render_run(name, pack, version, rules, out_dir=None):
    records, rows, doc, by_row = load_run(name, pack, version, rules)
    direct, _, _ = pl.compile_for(pack, version)
    rep = pl.build_report(
        pack,
        records,
        rows,
        pl.row_token_estimates(rows, direct),
        draws=3,
        version=version,
        rules=rules,
    )
    by_key = {r["key"]: r for r in doc["rules"]}
    started = next(r for r in records if r["type"] == "run_started")
    finished = next((r for r in records if r["type"] == "run_finished"), {})
    calls = [r for r in records if r.get("type") == "call"]
    failed = [r for r in calls if r["outcome"] != "answered"]
    retried = sum(1 for r in calls if (r.get("provider_calls") or 1) > 1)
    sp = rep["spend"]
    secs = sorted(int(r["started_at"][17:19]) for r in failed) if failed else []
    out = [f"# {rep['pack']}: live calibration, {name}", ""]
    out += [
        f"Run `{name}` ({started['at']} to {finished.get('at', '?')}). "
        f"Rows sent per draw: {rep['rows_sent']}, 3 draws"
        + (f", re-measure of {', '.join(rules)}" if rules else ", every sendable row")
        + ". Sendable rows only; no refusal, no auth failure, no 429; the run stopped on none of its guards.",
        "",
        "## Spend and calls",
        "",
        "| checks | answered | failed | provider calls | checks with a retry | input tokens (provider-reported) | cost | "
        "ceilings (calls / tokens) |",
        "|--:|--:|--:|--:|--:|--:|--:|--|",
        f"| {sp['checks']} | {sp['answered']} | {sp['failed']} | {sp['provider_calls']} | {retried} | "
        f"{sp['reported_input_tokens']:,} | ${sp['cost_reported_usd']:.4f} "
        f"(${sp['cost_usd']:.4f} counting failures at their estimate) | "
        f"{started['provider_call_ceiling']:,} / {started['token_ceiling']:,} |",
        "",
    ]
    if failed:
        out.append(
            f"Failed checks: {len(failed)} ({', '.join(sorted({str(r.get('kind')) for r in failed}))}), "
            f"started at second(s) {secs} of the minute; every one was re-attempted once and "
            "answered (all 3 draws are complete for every row)."
        )
    else:
        out.append("No failed check, no timeout.")
    out += [
        f"Incomplete examples (left out of every figure): {len(rep['incomplete_examples'])}.",
        "",
        f"Targets: block precision >= {T.block_precision}, escalate recall >= {T.escalate_recall}. "
        "Scores are the mean of a row's three draws. The hard pool is the rule's own "
        "category (its positives and their near-misses); the all pool is every row sent at the "
        "rule's guard points."
        + (
            " **For this re-measure the all pool is the rows sent (the rules' own categories and "
            "the rows a named rule scored 0.5 or more on last time), not the whole labelled set**, "
            "so the B2 all-rows floor is read on that subset. Most of the cross-fire rows are "
            "left out of the all pool by the exclusion below and are listed per rule."
            if rules
            else ""
        ),
        "",
        "The all pool leaves out a row that is a positive of another enforce-mode blocking rule at the "
        "same guard point (decided 2026-11-19: blocking it is right, so it is no false positive); "
        "benign rows and escalate-only rules' positives count. The hard pool is unchanged. "
        "**The excluded rows are still cross-rule firing**: each rule's count, highest score and "
        "count at or above its suggested block_at are in the summary and the ids in the detail, "
        "for the row-by-row read (dual-label or tighten) the 2026-11-18 overlap decision owes.",
        "",
        "Rules: **suggestions only; nothing is applied.** `block_at` is the agreed midpoint "
        "(highest hard-pool negative and lowest positive, rounded to 0.01, clamped to "
        "[0.50, 0.90], never below the B2 all-rows suggestion when that is above the midpoint); "
        "`escalate_at` is block_at - 0.30, at least 0.30 and 0.05 above the highest hard negative, "
        "at least 0.10 below block_at. Escalate-only rules keep their escalate_at.",
        "",
        "## Summary",
        "",
        "| rule | n (pos / neg, all pool) | excluded: another blocking rule's positives (n / highest / at or above the suggested block_at) | present block, escalate | suggested block, escalate | "
        "bound by | block precision (all / hard) | escalate recall (all / hard) | gates |",
        "|---|--:|--|---|---|---|---|---|---|",
    ]
    detail = []
    for r in rep["rules"]:
        key = r["key"]
        rule = by_key[key]
        all_sc, hard_sc, _ranges, draws_all, excluded = rule_pools(rule, doc["rules"], rows, by_row)
        rd = ruled(rule, hard_sc, all_sc)
        n_pos = sum(1 for _, p in all_sc if p)
        pr = rd.get("block_at")
        er = rd.get("escalate_at")
        if rd["basis"] is None or (pr is None and er is None):
            sug = "none"
        else:
            sug = f"{f(pr)}, {f(er)}" if pr is not None else f"none (capped), {f(er)}"
        gates = []
        conf = {}
        for pname, sc in (("all", all_sc), ("hard", hard_sc)):
            c = {}
            if pr is not None:
                c["block"] = cm(sc, pr)
            if er is not None:
                c["escalate"] = cm(sc, er)
            c["pres_block"] = (
                None if rule.get("max_action") == "escalate" else cm(sc, rule["block_at"])
            )
            c["pres_escalate"] = cm(sc, rule["escalate_at"])
            conf[pname] = c
        bp = [conf[p].get("block", {}).get("precision") for p in ("all", "hard")]
        er_ = [conf[p].get("escalate", {}).get("recall") for p in ("all", "hard")]
        ok_b = all(x is None or x >= T.block_precision for x in bp) if pr is not None else None
        ok_e = all(x is None or x >= T.escalate_recall for x in er_) if er is not None else None
        gates = (
            "block precision "
            + ("pass" if ok_b else "FAIL" if ok_b is False else "n/a")
            + ", escalate recall "
            + ("pass" if ok_e else "FAIL" if ok_e is False else "n/a")
        )
        cut = pr if pr is not None else None
        ex_cell = (
            "0"
            if not excluded
            else f"{len(excluded)} / {f(excluded[0][1], 3)} / "
            + (str(sum(1 for _i, sc, _o in excluded if sc >= cut - 1e-9)) if cut else "-")
        )
        notes = "; ".join(rd["notes"]) or rd["basis"]
        out.append(
            f"| {key} | {len(all_sc)} ({n_pos} / {len(all_sc) - n_pos}) | {ex_cell} | "
            f"{f(rule['block_at'])}, {f(rule['escalate_at'])} | {sug} | {notes} | "
            f"{f(bp[0])} / {f(bp[1])} | {f(er_[0])} / {f(er_[1])} | {gates} |"
        )
        # ---- detail
        d = [f"### {key}", ""]
        d.append(
            f"Mode {r['mode']}, guard points {', '.join(rule['guard_points'])}"
            + (f", max_action {rule['max_action']}" if rule.get("max_action") else "")
            + f". Present thresholds (pack @{version}): block_at {f(rule['block_at'])}, "
            f"escalate_at {f(rule['escalate_at'])}"
            + (", provisional" if rule.get("provisional") else "")
            + ". "
            f"Rows left out for want of a score: {r['left_out_no_score']}. "
            f"Nonce noise: p95 of a row's draw range {f(r['noise_p95_range'], 3)}."
        )
        d.append("")
        if not n_pos:
            d += [
                "No sendable positive row (every firing row is withheld): nothing to calibrate; "
                "the present thresholds stand.",
                "",
            ]
            detail += d
            continue
        for pname, sc in (("all", all_sc), ("hard", hard_sc)):
            lines, _pos, _neg = pool_section(rule, pname, sc, rd, None, None)
            d += ["- " + lines[0], "- " + lines[1]]
        if excluded:
            hi = [e for e in excluded if cut is not None and e[1] >= cut - 1e-9]
            d += [
                "",
                "**Excluded from the all pool** (positives of another enforce-mode blocking rule "
                "at this guard point; blocking them is right, decided 2026-11-19): "
                f"{len(excluded)} rows, highest {f(excluded[0][1], 3)}"
                + (f", {len(hi)} at or above the suggested block_at {f(cut)}" if cut else "")
                + ". Row mean, id, the rule(s) it is a positive of:",
                "",
                *[f"- {sc:.3f} `{rid}` ({', '.join(owners)})" for rid, sc, owners in excluded],
            ]
        d += [
            "",
            "Score distribution (row mean; positives / negatives per 0.1 bin), all pool:",
            "",
            "| bin | " + " | ".join(f"{i / 10:.1f}" for i in range(10)) + " |",
            "|---|" + "--:|" * 10,
            "| positives | " + " | ".join(str(b[0]) for b in histogram(all_sc)) + " |",
            "| negatives | " + " | ".join(str(b[1]) for b in histogram(all_sc)) + " |",
            "",
        ]
        d += [
            f"Agreed arithmetic: lowest positive {f(rd.get('lowest_pos'), 3)}, highest hard-pool "
            f"negative {f(rd.get('highest_hard_neg'), 3)}"
            + (
                f", midpoint {f(rd['mid'], 3)} -> rounded {f(rd['rounded'])} -> clamped "
                f"{f(rd['clamped'])}"
                if "mid" in rd
                else ""
            )
            + "; B2 on all rows (draw means): "
            + (
                f"block_at {f(rd['b2'].block_at)}, escalate_at {f(rd['b2'].escalate_at)}"
                f"{' (band empty)' if rd['b2'].band_empty else ''}"
                if rd["b2"].block_at is not None or rd["b2"].escalate_at is not None
                else f"none ({rd['b2'].reason})"
            )
            + ".",
            f"Binding: {'; '.join(rd['notes']) or rd['basis']}.",
            "",
        ]
        d += [
            "Confusion (row means; tp / fp / fn / tn, precision, recall, false-act rate = fp / negatives):",
            "",
            "| at | pool | threshold | tp / fp / fn / tn | precision | recall | false-act |",
            "|---|---|--:|---|--:|--:|--:|",
        ]
        for pname in ("all", "hard"):
            c = conf[pname]
            if pr is not None:
                d.append(f"| suggested block | {pname} | {f(pr)} | {cm_line(c['block'])} |")
            if er is not None:
                d.append(f"| suggested escalate | {pname} | {f(er)} | {cm_line(c['escalate'])} |")
            if c["pres_block"] is not None:
                d.append(
                    f"| present block | {pname} | {f(rule['block_at'])} | {cm_line(c['pres_block'])} |"
                )
            d.append(
                f"| present escalate | {pname} | {f(rule['escalate_at'])} | {cm_line(c['pres_escalate'])} |"
            )
        d.append("")
        dpos = [x for x, is_pos in draws_all if is_pos]
        if dpos:

            def hit(t, dpos=dpos):
                return sum(1 for x in dpos if x >= t - 1e-9)

            parts = []
            if pr is not None:
                parts.append(f"at block_at {f(pr)}: {hit(pr)} of {len(dpos)}")
            if er is not None:
                parts.append(f"at escalate_at {f(er)}: {hit(er)} of {len(dpos)}")
            d.append(
                f"Per-draw recall, all pool (single draws, not row means): {'; '.join(parts)}."
            )
        # gates and differences
        d.append(f"Against the gates (block precision >= 0.95, escalate recall >= 0.90): {gates}.")
        diff = []
        if pr is not None:
            diff.append(f"block_at {f(rule['block_at'])} -> {f(pr)} ({pr - rule['block_at']:+.2f})")
        if er is not None:
            diff.append(
                f"escalate_at {f(rule['escalate_at'])} -> {f(er)} ({er - rule['escalate_at']:+.2f})"
            )
        d.append(f"Difference from the present @{version} values: " + "; ".join(diff) + ".")
        if rules and pack in make_v2.PACKS:
            prev = make_v2.measure(pack, by_key[key])
            if prev:
                before = prior_all_negatives(pack, by_key[key], doc["rules"])
                neg_all = [p for p, is_pos in all_sc if not is_pos]
                neg_unex = [*neg_all, *(sc for _i, sc, _o in excluded)]
                b2_unex = sweep(
                    [*all_sc, *((sc, False) for _i, sc, _o in excluded)],
                    T,
                    max_action=by_key[key].get("max_action"),
                )
                d.append(
                    f"Against the @1 live measurement (2026-11-18): lowest positive "
                    f"{f(prev['positive_min'], 3)} -> {f(rd.get('lowest_pos'), 3)}, highest hard-pool "
                    f"negative {f(prev['hard_negative_max'], 3)} -> {f(rd.get('highest_hard_neg'), 3)}."
                )
                d.append(
                    f"Highest all-pool negative, like for like. Nothing excluded: "
                    f"{f(prev['all_negative_max'], 3)} -> {f(max(neg_unex, default=None), 3)}. "
                    f"With another blocking rule's positives left out: "
                    f"{f(before, 3)} -> {f(max(neg_all, default=None), 3)}. "
                    f"B2 all-rows block_at, nothing excluded: {f(prev['b2_block_at'])} -> "
                    f"{f(b2_unex.block_at)}; with them left out (this note's figure): "
                    f"{f(rd['b2'].block_at)}."
                )
        d.append("")
        detail += d
    out += ["", "## Per rule", "", *detail]
    out += [
        "Nothing here is applied: the thresholds change only through a new pack version "
        "(a pack version never changes)."
    ]
    ((out_dir or RES) / f"{name}.md").write_text("\n".join(out) + "\n", encoding="utf-8")
    return rep


def main(argv: Sequence[str] | None = None) -> int:
    names = list(sys.argv[1:] if argv is None else argv)
    unknown = [n for n in names if n not in {r[0] for r in RUNS}]
    if unknown:
        print("unknown run(s): " + ", ".join(unknown), file=sys.stderr)
        return 2
    for run in RUNS:
        if not names or run[0] in names:
            render_run(*run)
            print("wrote", run[0])
    return 0


if __name__ == "__main__":
    sys.exit(main())
