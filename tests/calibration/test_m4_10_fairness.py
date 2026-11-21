"""M4-10 / R4.5: the counterfactual-pair fairness report (per rule: mean and maximum |Δp|, flag
any pair above 0.10 or on different actions), tested offline. First as pure arithmetic, then with
the real golden set's pairs sent through a built engine whose fake model is either fair (the two
members of a pair get the same probability) or biased on chosen pairs. No live call."""

import json
import secrets
import statistics
from pathlib import Path

import pytest
from calibration.fairness import DELTA, RuleThresholds, pair_report

from guardrail_engine.decision import FakeDecisionModel
from guardrail_engine.engine import EngineSettings, build_engine
from guardrail_engine.floor_file import load_floor_file
from guardrail_engine.guard import (
    CheckContext,
    HmacContextVerifier,
    InMemoryTenantDirectory,
    TenantProfile,
)
from guardrail_engine.guard.audit import NullAuditSink
from guardrail_engine.pack_file import load_pack_file
from guardrail_engine.policy import InMemoryCatalog, TenantAttributes

ROOT = Path(__file__).resolve().parents[2]
FLOOR = load_floor_file(ROOT / "floor" / "rules.json")
RAI = load_pack_file(ROOT / "packs" / "responsible_ai" / "pack.json")
TENANT, SLUG = "t_1042", "acme-insurance"


def rows():
    text = (ROOT / "packs" / "responsible_ai" / "golden.jsonl").read_text(encoding="utf-8")
    return [json.loads(line) for line in text.splitlines()]


# ------------------------------------------------------------------ the arithmetic


RULE = RuleThresholds(frozenset({"output"}), block_at=0.85, escalate_at=0.55)
CAPPED = RuleThresholds(frozenset({"input"}), block_at=0.9, escalate_at=0.5, max_action="escalate")


def pair(pid, gp="output"):
    return [
        {"id": f"{pid}-a", "guard_point": gp, "pair": pid},
        {"id": f"{pid}-b", "guard_point": gp, "pair": pid},
    ]


def test_mean_and_max_abs_dp_are_per_rule_and_a_pair_over_0_10_is_flagged():
    prs = pair("p1") + pair("p2") + pair("p3")
    draws = {
        "p1-a": {"d__r": [0.80, 0.82, 0.78]}, "p1-b": {"d__r": [0.80, 0.80, 0.80]},  # Δ 0.0
        "p2-a": {"d__r": [0.90]}, "p2-b": {"d__r": [0.86]},  # Δ 0.04, both block: fine
        "p3-a": {"d__r": [0.90]}, "p3-b": {"d__r": [0.60]},  # Δ 0.30: flagged
    }  # fmt: skip
    report = pair_report(prs, draws, {"d__r": RULE})
    stats = report["rules"]["d__r"]
    assert stats["pairs"] == 3
    assert stats["mean_abs_dp"] == pytest.approx(statistics.fmean([0.0, 0.04, 0.30]), abs=1e-4)
    assert stats["max_abs_dp"] == pytest.approx(0.30)
    assert [(f["pair"], f["abs_dp"]) for f in stats["flagged"]] == [("p3", 0.3)]
    assert report["fair"] is False and report["flagged_total"] == 1 and report["delta"] == DELTA


def test_a_pair_on_different_actions_is_flagged_even_when_the_difference_is_small():
    prs = pair("p")
    draws = {"p-a": {"d__r": [0.86]}, "p-b": {"d__r": [0.84]}}  # block vs escalate, Δ 0.02
    (flag,) = pair_report(prs, draws, {"d__r": RULE})["rules"]["d__r"]["flagged"]
    assert flag["verdict_differs"] is True and flag["abs_dp"] == pytest.approx(0.02)


def test_an_escalate_only_rule_compares_actions_after_the_cap():
    prs = pair("p", "input")
    draws = {"p-a": {"d__c": [0.99]}, "p-b": {"d__c": [0.91]}}  # both capped to escalate, Δ 0.08
    assert pair_report(prs, draws, {"d__c": CAPPED})["rules"]["d__c"]["flagged"] == []
    far = {"p-a": {"d__c": [0.99]}, "p-b": {"d__c": [0.60]}}  # same action, but Δp 0.39
    (flag,) = pair_report(prs, far, {"d__c": CAPPED})["rules"]["d__c"]["flagged"]
    assert flag["verdict_differs"] is False and flag["abs_dp"] == pytest.approx(0.39)


def test_the_cap_makes_block_and_escalate_the_same_action():
    prs = pair("p", "input")
    draws = {"p-a": {"d__c": [0.95]}, "p-b": {"d__c": [0.88]}}  # 0.95 would block uncapped
    stats = pair_report(prs, draws, {"d__c": CAPPED})["rules"]["d__c"]
    assert stats["flagged"] == []  # Δ 0.07 and both escalate
    uncapped = RuleThresholds(CAPPED.guard_points, 0.9, 0.5)
    (flag,) = pair_report(prs, draws, {"d__c": uncapped})["rules"]["d__c"]["flagged"]
    assert flag["verdict_differs"] is True  # block vs escalate without the cap


def test_a_pair_no_rule_covers_on_both_members_is_unmeasured_and_never_fair():
    split = [
        {"id": "a", "guard_point": "input", "pair": "p"},
        {"id": "b", "guard_point": "output", "pair": "p"},
    ]  # the members sit at different guard points
    draws = {"a": {"d__r": [0.9]}, "b": {"d__r": [0.9]}}
    report = pair_report(split, draws, {"d__r": RULE})
    assert report["unmeasured"] == ["p"] and report["pairs"] == 1
    assert report["rules"]["d__r"]["pairs"] == 0 and report["fair"] is False
    assert pair_report(pair("q"), {"q-a": {"d__r": [0.9]}, "q-b": {"d__r": [0.9]}},
                       {"d__r": RULE})["unmeasured"] == []  # fmt: skip


def test_missing_scores_malformed_pairs_and_other_guard_points_are_named_not_counted_as_fair():
    prs = [
        *pair("p1"),
        {"id": "lone", "guard_point": "output", "pair": "p2"},
        *pair("p3", "input"),
    ]
    draws = {"p1-a": {"d__r": [0.9]}}  # p1-b has no scores
    report = pair_report(prs, draws, {"d__r": RULE})
    assert report["unscored"] == [("p1", "d__r")] and report["malformed"] == ["p2"]
    assert report["rules"]["d__r"]["pairs"] == 0  # p3 is at a guard point the rule doesn't cover
    assert report["unmeasured"] == ["p3"]  # named, not silently skipped
    assert report["fair"] is False
    assert pair_report([], {}, {"d__r": RULE})["rules"]["d__r"]["mean_abs_dp"] is None


# ------------------------------------------------------------------ the real pairs, a fake model


def rule_thresholds():
    return {
        r.key: RuleThresholds(frozenset(r.guard_points), r.block_at, r.escalate_at, r.max_action)
        for r in RAI._content.rules
    }


async def collect(bias):
    """Send every row of every counterfactual pair through a built engine. ``bias(row, key)`` is
    the probability the fake model gives; a fair model gives a pair's members the same one."""
    state = {"row": None}

    def responder(text, key, question):
        if key.startswith("p__"):
            return 0.01
        return None if state["row"] is None else bias(state["row"], key)

    verifier = HmacContextVerifier(secrets.token_bytes(32))
    engine = await build_engine(
        EngineSettings.from_mapping(
            {"environment": "test", "platform": {"min_floor_version": FLOOR.version}}
        ),
        verifier=verifier,
        tenants=InMemoryTenantDirectory(
            [TenantProfile.build(TenantAttributes(tenant_id=TENANT), "insurance", (), slug=SLUG)]
        ),
        model=FakeDecisionModel(responder=responder),
        catalog=InMemoryCatalog(floors=[FLOOR], packs=[RAI]),
        audit=NullAuditSink(),
    )
    await engine.bootstrap_publish(
        {
            "schema_version": 1, "tenant_id": TENANT, "version": 1,
            "extends": [f"platform/floor@{FLOOR.version}", RAI.ref],
        }
    )  # fmt: skip
    paired = [r for r in rows() if r["pair"]]
    draws: dict[str, dict[str, list[float]]] = {}
    try:
        for row in paired:
            state["row"] = row
            verdict = await engine.check(
                CheckContext(signed_context=verifier.issue(TENANT)),
                row["guard_point"],
                row["content"],
            )
            draws[row["id"]] = {e.key: [e.p] for e in verdict.rules if e.p is not None}
    finally:
        await engine.shutdown()
    return paired, draws


def fair_model(row, key):
    return 0.95 if key in row["fires"] else 0.05  # the label decides, not the attribute swapped


async def test_the_real_golden_pairs_are_fair_under_a_fair_model_with_zero_deltas():
    paired, draws = await collect(fair_model)
    report = pair_report(paired, draws, rule_thresholds())
    assert report["pairs"] >= 40  # the story's count (R4.5)
    assert report["fair"] is True and report["flagged_total"] == 0
    measured = {k: v for k, v in report["rules"].items() if v["pairs"]}
    assert measured and all(
        v["max_abs_dp"] == 0 and v["mean_abs_dp"] == 0 for v in measured.values()
    )
    assert report["malformed"] == [] and report["unscored"] == []


async def test_a_biased_model_is_caught_per_rule_with_its_mean_and_maximum():
    paired, draws0 = await collect(fair_model)
    by_pair = {}
    for r in paired:
        by_pair.setdefault(r["pair"], []).append(r["id"])
    harass_pairs = [
        pid
        for pid, ids in by_pair.items()
        if any(r["id"] == ids[0] and "d__harassment" in r["fires"] for r in paired)
    ]
    assert len(harass_pairs) >= 3
    biased_ids = {by_pair[pid][1] for pid in harass_pairs[:2]}  # the second member of two pairs

    def biased(row, key):
        p = fair_model(row, key)
        if row["id"] in biased_ids and key == "d__harassment":
            return 0.60 if p > 0.5 else p  # the swapped attribute lowers the score: 0.95 -> 0.60
        return p

    paired2, draws = await collect(biased)
    report = pair_report(paired2, draws, rule_thresholds())
    stats = report["rules"]["d__harassment"]
    assert stats["max_abs_dp"] == pytest.approx(0.35)
    assert stats["mean_abs_dp"] == pytest.approx(0.35 * 2 / stats["pairs"], abs=1e-3)
    assert {f["pair"] for f in stats["flagged"]} == set(harass_pairs[:2])
    assert all(f["verdict_differs"] is True for f in stats["flagged"])  # block vs escalate
    other = {k: v for k, v in report["rules"].items() if k != "d__harassment"}
    assert all(not v["flagged"] for v in other.values())  # the other rules stay clean
    assert report["fair"] is False and report["flagged_total"] == 2
    assert draws0 != draws
