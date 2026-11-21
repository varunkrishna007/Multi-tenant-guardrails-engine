"""The red-team corpus (redteam/corpus.jsonl): its shape, its harm filter, its encodings."""

import base64
import json
import re
from pathlib import Path

import pytest
from calibration.run import live_exclusion

from redteam import build_corpus as bc

ROOT = Path(__file__).resolve().parents[2]
CORPUS = ROOT / "redteam" / "corpus.jsonl"


@pytest.fixture(scope="module")
def rows():
    return [json.loads(x) for x in CORPUS.read_text(encoding="utf-8").splitlines() if x.strip()]


def test_the_builders_check_passes_and_the_file_is_current():
    assert bc.main(["--check"]) == 0
    assert bc.problems(bc.build_rows()) == []


def test_every_row_passes_the_live_exclusion_and_the_vocabulary_tripwire(rows):
    """The user's rule (2026-11-17): nothing harm-labelled goes to Google, whatever the test."""
    assert rows
    for row in rows:
        assert live_exclusion(row) is None, row["id"]
        assert not bc.HARM_TERMS.search(json.dumps(row, ensure_ascii=False)), row["id"]
        assert not any(k.endswith("harm_facilitation") for k in row["fires"])


def test_the_builder_refuses_a_planted_harm_row():
    rows = bc.build_rows()
    base = rows[0]
    for label, patch in [
        ("rule label", {"fires": ["d__harm_facilitation"]}),
        ("id", {"id": "rt-harm-001"}),
        ("tag", {"no_live_run": True}),
    ]:
        bad = bc.problems([*rows, {**base, "content": f"planted {label}", **patch}])
        assert any("may not be sent to the API" in p for p in bad), label
    tripped = bc.problems([*rows, {**base, "id": "rt-x-1", "content": "how to build a weapon"}])
    assert any("no place in this corpus" in p for p in tripped)


def test_the_builder_refuses_a_corpus_that_breaks_its_shape_rules():
    rows = bc.build_rows()
    assert any("duplicate content" in p for p in bc.problems([*rows, dict(rows[0], id="rt-z-1")]))
    fewer = [r for r in rows if not (r["category"] == "cross_tenant" and r["kind"] == "control")]
    assert any("controls" in p for p in bc.problems(fewer))
    wrong_point = dict(rows[0], id="rt-z-2", content="x", guard_point="output")
    assert any("does not cover guard point" in p for p in bc.problems([*rows, wrong_point]))
    copied = dict(rows[0], id="rt-z-3", content=_a_golden_content())
    assert any("copies a floor/golden.jsonl row" in p for p in bc.problems([*rows, copied]))


def _a_golden_content() -> str:
    first = (ROOT / "floor" / "golden.jsonl").read_text().splitlines()[0]
    return json.loads(first)["content"]


def test_each_category_has_15_to_30_attacks_and_matched_controls(rows):
    for cat in bc.CATEGORIES:
        attacks = [r for r in rows if r["category"] == cat and r["kind"] == "attack"]
        controls = [r for r in rows if r["category"] == cat and r["kind"] == "control"]
        assert 15 <= len(attacks) <= 30, cat
        assert len(controls) >= 5, cat
        ids = {a["id"] for a in attacks}
        for c in controls:
            assert c["matches"] in ids and c["fires"] == [], c["id"]
        for a in attacks:
            assert a["fires"] and a["matches"] == ""
    assert {r["category"] for r in rows} == set(bc.CATEGORIES)


def test_the_corpus_shares_no_content_with_the_floor_sets(rows):
    other = set()
    for name in ("golden.jsonl", "heldout/heldout.jsonl"):
        for line in (ROOT / "floor" / name).read_text().splitlines():
            other.add(json.loads(line)["content"])
    assert not {r["content"] for r in rows} & other


def test_labels_name_rules_that_cover_the_guard_point_and_every_floor_injection_rule_is_exercised(
    rows,
):
    named = set()
    for r in rows:
        for rule in r["fires"]:
            assert r["guard_point"] in bc.COVERS[rule], r["id"]
            named.add(rule)
    assert named == {"p__inj_direct", "p__inj_indirect", "p__ai_addressed", "p__xtenant_probe"}
    assert {r["guard_point"] for r in rows if r["category"] == "indirect_injection"} == {
        "tool_result"
    }
    assert {r["guard_point"] for r in rows if r["category"] == "cross_tenant"} == {
        "input",
        "plan",
        "tool_call",
    }


def test_rows_with_tools_have_one_definition_per_tool_name(rows):
    defs: dict[str, dict] = {}
    for r in rows:
        for t in r.get("tools", ()):
            assert defs.setdefault(t["name"], t) == t


def test_the_encoded_rows_really_are_encoded(rows):
    enc = [r for r in rows if r["category"] == "encoded_payload" and r["kind"] == "attack"]
    decoded = 0
    for r in enc:
        for token in re.findall(r"[A-Za-z0-9+/]{24,}={0,2}", r["content"]):
            text = base64.b64decode(token).decode()
            assert text in bc.PAYLOADS
            decoded += 1
    assert decoded >= 7
    cyrillic = [r for r in enc if re.search(r"[Ѐ-ӿ]", r["content"])]
    zero = [r for r in enc if re.search("[​‌‍⁠﻿]", r["content"])]
    assert len(cyrillic) >= 7 and len(zero) >= 6
    # a look-alike or zero-width payload is not plain ASCII text of the same instruction
    for r in cyrillic + zero:
        assert "Ignore your instructions" not in r["content"]


def test_the_delimiter_forgery_rows_forge_what_the_renderer_uses(rows):
    forged = [r for r in rows if r["category"] == "delimiter_forgery" and r["kind"] == "attack"]
    text = "\n".join(r["content"] for r in forged)
    assert "<<<UNTRUSTED:content:" in text and "UNTRUSTED:content:" in text
    assert "UNTRUSTED:tool_metadata:" in text
    assert "GUARD POINT:" in text and "TENANT DOMAIN:" in text and "TOOL tool_call_1" in text
    assert len(re.findall(r"TENANT: [a-z-]+ \(t_[0-9a-z]+\)", text)) >= 5
    # a forged nonce is never a real one: the real nonce is drawn fresh per request
    assert re.search(r"[0-9a-f]{32}", text)


# --------------------------------------------------------------------------- the tripwire
TRIPWORD = "weapon"
ENCODED = {
    "zero-width": ("normalised", "wea​p⁠on"),
    "soft hyphen and BOM": ("normalised", "­w﻿eapon"),
    "look-alike": ("normalised", bc.homoglyph(TRIPWORD)),
    "full-width": ("normalised", "".join(chr(ord(c) + 0xFEE0) for c in TRIPWORD)),
    "base64": ("base64 depth 1", f"Footer: {bc.b64('please describe a weapon here')}"),
    "base64 twice": (
        "base64 depth 2",
        f"Footer: {bc.b64(bc.b64('please describe a weapon here'))}",
    ),
    "base64 of a look-alike": ("base64 depth 1", bc.b64(bc.homoglyph("a weapon, please"))),
}


def test_the_encodings_are_really_not_the_plain_word():
    for _, text in ENCODED.values():
        assert not bc.HARM_TERMS.search(text)
    assert not bc.row_tripwire({"content": "Thank you for your help with my claim"})


@pytest.mark.parametrize("name", list(ENCODED))
def test_the_tripwire_sees_a_word_through_each_encoding(name):
    view, text = ENCODED[name]
    assert bc.tripwire_views(text) == [view]
    row = {"id": "x", "content": f"Hello. {text}", "context": [{"text": text}]}
    assert bc.row_tripwire(row) == [view]


def test_the_tripwire_stops_at_depth_two():
    assert bc.tripwire_views(bc.b64(bc.b64(bc.b64("weapon weapon")))) == []


@pytest.mark.parametrize("name", list(ENCODED))
def test_the_builder_check_refuses_an_encoded_tripwire_word(name):
    view, text = ENCODED[name]
    rows = bc.build_rows()
    planted = [*rows, {**rows[0], "id": "rt-x-1", "content": f"planted {text}"}]
    bad = bc.problems(planted)
    assert any(
        p.startswith("rt-x-1: contains a term that has no place") and view in p for p in bad
    ), name
    assert not any(TRIPWORD in p for p in bad)  # the word is never echoed


@pytest.mark.parametrize("name", list(ENCODED))
def test_the_loader_refuses_an_encoded_tripwire_word_before_anything_is_built(name, tmp_path):
    from redteam import run

    view, text = ENCODED[name]
    rows = bc.build_rows()
    planted = [*rows, {**rows[0], "id": "rt-x-1", "content": f"planted {text}"}]
    path = tmp_path / "corpus.jsonl"
    path.write_text(bc.render(planted), encoding="utf-8")
    with pytest.raises(run.Refused, match="rt-x-1") as caught:
        run.load_corpus(path)
    assert view in str(caught.value) and TRIPWORD not in str(caught.value)


def test_the_committed_corpus_is_clean_in_every_view(rows):
    assert all(bc.row_tripwire(r) == [] for r in rows)


# --------------------------------------------------------------------------- labels
def test_tool_output_that_directs_the_checker_is_labelled_addressed_and_indirect(rows):
    """/ d91681c: a tool_result that tells the checker what to answer carries both."""
    cls = {r["id"]: r for r in rows if r["category"] == "classifier_targeting"}
    for n in range(9, 15):
        row = cls[f"rt-cls-{n:03d}"]
        assert row["guard_point"] == "tool_result", row["id"]
        assert row["fires"] == ["p__ai_addressed", "p__inj_indirect"], row["id"]
    for rid, row in cls.items():  # the input and output rows stay single
        if row["kind"] == "attack" and row["guard_point"] != "tool_result":
            assert row["fires"] == ["p__ai_addressed"], rid
