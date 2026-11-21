"""M4-10 the responsible-AI pack (R4): its seven rules, the claims boundary, and the golden set:
the story's counts, the counterfactual pairs, the hygiene rules, and what is never sent."""

import json
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

import pytest

from guardrail_engine.admin.vocabulary import tripwire_views
from guardrail_engine.pack_file import load_pack_file

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from calibration.run import live_exclusion  # noqa: E402

PACK = load_pack_file(ROOT / "packs" / "responsible_ai" / "pack.json")
RULES = {r.key: r for r in PACK._content.rules}
WITHHELD_RULES = {
    "d__self_harm_risk",
    "d__harassment",
    "d__bias_stereotype",
    "d__bias_protected_basis",
    "d__harm_facilitation",
}
ESCALATE_ONLY = {"d__self_harm_risk", "d__vulnerability"}


def rows():
    text = (ROOT / "packs" / "responsible_ai" / "golden.jsonl").read_text(encoding="utf-8")
    return [json.loads(line) for line in text.splitlines()]


def strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for v in value.values():
            yield from strings(v)
    elif isinstance(value, list):
        for v in value:
            yield from strings(v)


# ------------------------------------------------------------------ the pack


def test_seven_rules_six_enforcing_and_harm_facilitation_in_shadow():
    assert PACK.ref == "domain/responsible_ai@1" and len(RULES) == 7
    enforcing = {k for k, r in RULES.items() if r.mode == "enforce"}
    assert len(enforcing) == 6 and RULES["d__harm_facilitation"].mode == "shadow"
    assert "d__harm_facilitation" not in enforcing


def test_each_rule_has_descriptions_guard_points_severity_and_thresholds():
    for key, r in RULES.items():
        assert r.question.criteria and r.question.criteria.true_description, key
        assert r.question.criteria.false_description and r.guard_points and r.severity, key
        assert r.block_at is not None and r.escalate_at is not None and r.provisional, key


def test_the_two_people_at_risk_rules_may_escalate_and_never_block():
    capped = {k for k, r in RULES.items() if r.max_action == "escalate"}
    assert capped == ESCALATE_ONLY
    assert all(RULES[k].guard_points == frozenset({"input"}) for k in capped)


def test_the_pack_is_per_rule_optional_and_the_only_one():
    assert PACK.per_rule_optional is True
    for name in ("insurance", "energy"):
        assert load_pack_file(ROOT / "packs" / name / "pack.json").per_rule_optional is False


def test_the_claims_boundary_is_stated_in_the_catalog_description():
    """R4.4: 'detects biased content and decisions in individual responses', and aggregate
    fairness across decisions is not measured."""
    text = PACK.description.lower()
    assert "detects biased content and decisions in individual responses" in text
    assert "aggregate fairness is not measured" in text
    assert "statistical fairness across many decisions" in text


def test_the_claims_boundary_is_stated_in_the_pack_docs():
    for path in ("packs/responsible_ai/README.md", "docs/m4-10-responsible-ai.md"):
        text = (ROOT / path).read_text(encoding="utf-8").lower()
        assert "detects biased content and decisions in individual responses" in text, path
        assert "aggregate fairness" in text and "not measured" in text, path
        assert not re.search(r"\bdetects bias\b(?! content)", text), (
            path
        )  # never just 'detects bias'


def test_the_rules_whose_question_text_names_a_harm_are_exactly_these():
    """A rule about self-harm, a protected characteristic or a harm request has to name it in
    its question, so five rules' text trips the vocabulary tripwire. That text goes to the
    provider as a **question** with every check that evaluates the pack; it is not an example.
    The set is pinned so a new rule that names a harm is noticed, and so a live run can
    leave out the ones it must not send (the shadow ``d__harm_facilitation``, through a
    per-rule opt-out) and decide about the rest."""
    document = json.loads((ROOT / "packs" / "responsible_ai" / "pack.json").read_text())
    naming = {
        r["key"]
        for r in document["rules"]
        if any(tripwire_views(s) for s in strings(r["question"]))
    }
    assert naming == {
        "d__self_harm_risk",
        "d__vulnerability",
        "d__bias_stereotype",
        "d__bias_protected_basis",
        "d__harm_facilitation",
    }
    assert not any(tripwire_views(s) for s in strings(document["description"]))


# ------------------------------------------------------------------ the golden set: counts


def test_the_golden_set_has_the_stories_counts():
    data = rows()
    assert len(data) >= 300
    per_cell = Counter()
    for r in data:
        for key in RULES:
            if r["guard_point"] in RULES[key].guard_points:
                per_cell[(key, r["guard_point"], key in r["fires"])] += 1
    for key, rule in RULES.items():
        for gp in rule.guard_points:
            assert per_cell[(key, gp, True)] >= 15, (key, gp, "firing")
            assert per_cell[(key, gp, False)] >= 15, (key, gp, "allow")


def test_there_are_at_least_40_counterfactual_pairs_each_of_two_members_with_one_label():
    pairs: dict[str, list[dict]] = {}
    for r in rows():
        if r["pair"]:
            pairs.setdefault(r["pair"], []).append(r)
    assert len(pairs) >= 40
    for pid, members in pairs.items():
        assert len(members) == 2, pid
        a, b = members
        assert a["fires"] == b["fires"] and a["guard_point"] == b["guard_point"], pid
        assert a["content"] != b["content"], pid


DIALECT_OR_LANGUAGE_PAIRS = {"rai-cf-013"}
"""Pairs whose attribute IS a dialect or language: the words differ throughout, by design."""


def test_a_counterfactual_pair_differs_only_by_swapped_words_never_an_added_or_dropped_one():
    """R4.5: a pair's members differ **only** in the protected attribute, name, pronoun,
    dialect or language. So apart from the named dialect pair, every difference between the two is
    one word or phrase replaced by another, never a word added to one side."""
    import difflib

    pairs: dict[str, list[str]] = {}
    for r in rows():
        if r["pair"]:
            pairs.setdefault(r["pair"], []).append(r["content"])
    added = []
    for pid, (a, b) in pairs.items():
        if pid in DIALECT_OR_LANGUAGE_PAIRS:
            continue
        words = [re.findall(r"\w+|\W", x) for x in (a, b)]
        ops = difflib.SequenceMatcher(None, *words, autojunk=False).get_opcodes()
        if any(tag in ("insert", "delete") for tag, *_ in ops):
            added.append(pid)
    assert added == []


def test_the_near_misses_the_story_names_are_present():
    cats = {r["category"] for r in rows()}
    assert {"benign_near_miss", "benign", "counterfactual"} <= cats
    text = " ".join(r["content"].lower() for r in rows() if not r["fires"])
    assert "maternity" in text  # a neutral mention of a protected characteristic
    assert "large print" in text or "large-print" in text  # an accommodation the person asked for


def test_the_golden_set_is_what_the_builder_produces():
    done = subprocess.run(
        [sys.executable, str(ROOT / "packs" / "responsible_ai" / "build_golden.py"), "--check"],
        capture_output=True, text=True, cwd=ROOT,
    )  # fmt: skip
    assert done.returncode == 0, done.stderr


# ------------------------------------------------------------------ what is never sent


def test_a_row_that_is_harm_labelled_sensitive_or_demeaning_is_never_sent():
    """Conservative scope (decision 2026-11-19 on U4, over U6): self-harm statements,
    insults, discriminatory text and harm-labelled rows are withheld; so is any row that trips
    the vocabulary. Their clean near-misses (rows that fire nothing) stay sendable."""
    for row in rows():
        withheld = bool(set(row["fires"]) & WITHHELD_RULES) or bool(
            tripwire_views(json.dumps(row, ensure_ascii=False))
        )
        assert row["no_live_run"] is (withheld or row["no_live_run"]), row["id"]
        if set(row["fires"]) & WITHHELD_RULES:
            assert row["no_live_run"] is True, row["id"]
            assert live_exclusion(row) is not None, row["id"]


def test_every_sendable_row_is_clean_under_the_vocabulary_and_fires_only_what_may_be_sent():
    for row in rows():
        if row["no_live_run"]:
            continue
        assert live_exclusion(row) is None, row["id"]
        assert not tripwire_views(json.dumps(row, ensure_ascii=False)), row["id"]
        assert set(row["fires"]) <= {"d__vulnerability", "d__manipulation"}, row["id"]


def test_every_harm_labelled_row_is_withheld_and_there_are_no_actionable_instructions():
    harm = [r for r in rows() if "d__harm_facilitation" in r["fires"]]
    assert harm and all(r["no_live_run"] for r in harm)
    for r in harm:
        if r["guard_point"] == "output":  # the assistant's side is refusal-style or redacted
            assert "[details removed from dataset]" in r["content"] or re.search(
                r"\b(can't|cannot|won't|unable)\b", r["content"], re.IGNORECASE
            ), r["id"]
    numbered = re.compile(r"(^|\n)\s*(1[.)]|step 1\b)", re.IGNORECASE)
    assert not [r["id"] for r in rows() if numbered.search(r["content"])]


def test_self_harm_rows_follow_safe_messaging_no_methods_no_means():
    method_words = re.compile(
        r"\b(pills?|tablets?|rope|bridge|jump(ing)?|hang(ing)?|gun|razor|knife|lethal|dose)\b", re.I
    )
    for r in rows():
        if "d__self_harm_risk" in r["fires"]:
            assert not method_words.search(r["content"]), r["id"]


def test_the_set_is_synthetic_with_no_contact_details():
    pattern = re.compile(r"@|https?://|www\.|\b\d{3}[ -]\d{3}[ -]\d{4}\b")
    assert [r["id"] for r in rows() if pattern.search(r["content"])] == []


@pytest.mark.parametrize("name", ["insurance", "energy"])
def test_the_other_packs_use_the_same_builder_check(name):
    done = subprocess.run(
        [sys.executable, str(ROOT / "packs" / name / "build_golden.py"), "--check"],
        capture_output=True, text=True, cwd=ROOT,
    )  # fmt: skip
    assert done.returncode == 0, done.stderr
