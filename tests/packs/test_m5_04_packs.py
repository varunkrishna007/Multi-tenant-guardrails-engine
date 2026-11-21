"""M5-04 the finance and healthcare domain packs: what they are, what their golden sets hold, and
that every golden row passes the harm-vocabulary tripwire (these rows may go to the provider for
calibration, so none may be harm-labelled or prohibited)."""

import json
import subprocess
import sys
from collections import Counter
from pathlib import Path

import pytest

from guardrail_engine.admin.vocabulary import tripwire_views
from guardrail_engine.floor_file import load_floor_file
from guardrail_engine.pack_file import PackFileError, load_pack_file
from guardrail_engine.policy import (
    ErrorCode,
    InMemoryCatalog,
    InMemoryToolRegistry,
    PlatformSettings,
    PolicyCompiler,
    TenantAttributes,
)

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from calibration.run import live_exclusion  # noqa: E402

PACKS = {
    "finance": {"tenant": ("acme-finance", "t_3310"), "rules": 6, "min_rows": 200},
    "healthcare": {"tenant": ("acme-health", "t_4410"), "rules": 6, "min_rows": 200},
}
FLOOR = load_floor_file(ROOT / "floor" / "rules.json")


def rows_of(name):
    text = (ROOT / "packs" / name / "golden.jsonl").read_text(encoding="utf-8")
    return [json.loads(line) for line in text.splitlines()]


def strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for k, v in value.items():
            yield from strings(k)
            yield from strings(v)
    elif isinstance(value, list):
        for v in value:
            yield from strings(v)


@pytest.fixture(params=sorted(PACKS))
def name(request):
    return request.param


# ------------------------------------------------------------------ the pack document


def test_the_pack_loads_through_the_catalogs_own_validation(name):
    pack = load_pack_file(ROOT / "packs" / name / "pack.json")
    assert pack.ref == f"domain/{name}@1" and len(pack._content.rules) == PACKS[name]["rules"]
    for r in pack._content.rules:
        assert r.key.startswith("d__")
        assert r.mode == "enforce", r.key
        assert (r.max_action == "escalate") == (r.key in ESCALATE_ONLY), r.key
        assert r.question.criteria is not None  # both descriptions (AC-C2.1)


def test_every_threshold_is_provisional_until_calibration(name):
    """No [LIVE] calibration has run: the numbers are first guesses (the floor's R7.3)."""
    pack = load_pack_file(ROOT / "packs" / name / "pack.json")
    assert all(r.provisional for r in pack._content.rules)
    document = json.loads((ROOT / "packs" / name / "pack.json").read_text())
    assert all(r["provisional"] is True for r in document["rules"])


def test_the_pack_declares_the_guard_points_it_covers(name):
    pack = load_pack_file(ROOT / "packs" / name / "pack.json")
    declared = {gp for r in pack._content.rules for gp in r.guard_points}
    assert pack.covers == frozenset(declared)
    expected = {
        "finance": {"input", "plan", "tool_call", "output"},
        "healthcare": {"input", "tool_call", "tool_result", "output"},
    }[name]
    assert declared == expected


R3 = {  # R3's own columns, in days: records min, max, default; content cap and default; BAA
    "finance": (395, 7 * 365, 7 * 365, 90, 30, False),
    "healthcare": (395, 7 * 365, 6 * 365, 30, 30, True),
}


def test_the_pack_carries_r3s_retention_bounds_for_its_column(name):
    """R3's table: finance records 7 years by default, 395 days at least; content opt-in 30 days
    by default and 90 at most. Healthcare records 6 years by default, 395 days at least; content
    only with a BAA flag and 30 days at most. **The figures still need legal sign-off before M5
    GA (R3).**"""
    r = load_pack_file(ROOT / "packs" / name / "pack.json").retention
    assert r is not None
    assert (
        r.records_min_days, r.records_max_days, r.records_default_days,
        r.content_max_days, r.content_default_days, r.content_requires_baa,
    ) == R3[name]  # fmt: skip


def test_the_combined_bounds_follow_the_longest_retention_and_the_shortest_cap():
    from guardrail_engine.policy.compiler import combined_retention

    settings = PlatformSettings(min_floor_version=FLOOR.version)
    fin = load_pack_file(ROOT / "packs" / "finance" / "pack.json")
    hc = load_pack_file(ROOT / "packs" / "healthcare" / "pack.json")
    both = combined_retention(settings, [fin, hc])
    assert both.records_min_days == 395 and both.records_default_days == 7 * 365  # the longest
    assert both.content_max_days == 30 and both.content_requires_baa is True  # the shortest
    alone = combined_retention(settings, [fin])
    assert alone.content_max_days == 90 and alone.content_requires_baa is False


def test_a_healthcare_tenant_needs_the_baa_flag_to_store_content_and_a_finance_one_does_not():
    for name, baa, ok in (("healthcare", False, False), ("healthcare", True, True),
                          ("finance", False, True)):  # fmt: skip
        doc = bundle_for(name) | {"audit": {"store_content": "full", "content_days": 30}}
        errors = compiler_for(name).validate(doc, TenantAttributes(tenant_id="t_dogfood", baa=baa))
        assert (errors == []) is ok, (name, baa, [e.code for e in errors])
    over = bundle_for("healthcare") | {"audit": {"store_content": "full", "content_days": 31}}
    errors = compiler_for("healthcare").validate(
        over, TenantAttributes(tenant_id="t_dogfood", baa=True)
    )
    assert [e.code for e in errors] == [ErrorCode.AUDIT_CONTENT_DAYS_OUT_OF_RANGE]


def test_the_pack_text_has_no_harm_vocabulary(name):
    document = json.loads((ROOT / "packs" / name / "pack.json").read_text())
    hits = [s[:60] for s in strings(document) if tripwire_views(s)]
    assert hits == []


def test_a_malformed_pack_file_is_refused(tmp_path):
    good = (ROOT / "packs" / "healthcare" / "pack.json").read_text()
    for text in (
        good.replace('"d__hc_diagnosis"', '"hc_diagnosis"'),  # not a d__ key
        good.replace(
            "Does the response tell the person", "Tell the person", 1
        ),  # not a closed question
        good.replace('"schema_version": 2', '"schema_version": 2, "schema_version": 2', 1),
        "[]",
        "not json",
    ):
        f = tmp_path / "pack.json"
        f.write_text(text)
        with pytest.raises(PackFileError):
            load_pack_file(f)


# --------------------------------------------- AC-C1.5: tenants can't edit the text


def compiler_for(*names):
    packs = [load_pack_file(ROOT / "packs" / n / "pack.json") for n in names]
    return PolicyCompiler(
        InMemoryCatalog(floors=[FLOOR], packs=packs),
        InMemoryToolRegistry(),
        PlatformSettings(min_floor_version=FLOOR.version),
    )


def bundle_for(name, overrides=()):
    return {
        "schema_version": 1, "tenant_id": "t_dogfood", "version": 1,
        "extends": [f"platform/floor@{FLOOR.version}", f"domain/{name}@1"],
        "overrides": list(overrides),
    }  # fmt: skip


def test_a_bundle_extending_the_pack_compiles_with_its_rules_at_the_declared_guard_points(name):
    compiled = compiler_for(name).compile(bundle_for(name), TenantAttributes(tenant_id="t_dogfood"))
    pack = load_pack_file(ROOT / "packs" / name / "pack.json")
    for gp, compiled_gp in compiled.guard_points.items():
        in_pack = {k for k, rule in compiled_gp.rules.items() if rule.layer == "pack"}
        expected = {r.key for r in pack._content.rules if gp in r.guard_points}
        assert in_pack == expected, gp


EVERY_RULE = [
    (n, r.key)
    for n in sorted(PACKS)
    for r in load_pack_file(ROOT / "packs" / n / "pack.json")._content.rules
]
"""Every rule of every pack, so a rule added later is covered without touching the tests."""
TENANT = TenantAttributes(tenant_id="t_dogfood")


def rule_of(name, key):
    return next(
        r
        for r in load_pack_file(ROOT / "packs" / name / "pack.json")._content.rules
        if r.key == key
    )


@pytest.mark.parametrize("field", ["question", "true_description", "false_description"])
@pytest.mark.parametrize(("name", "key"), EVERY_RULE)
def test_a_tenant_cannot_edit_a_pack_rules_text(name, key, field):
    errors = compiler_for(name).validate(
        bundle_for(name, [{"rule": key, field: "Is this different?"}]), TENANT
    )
    assert [(e.code, e.path) for e in errors] == [
        (ErrorCode.PACK_TEXT_EDITED, f"$.overrides[0].{field}")
    ]


@pytest.mark.parametrize(("name", "key"), EVERY_RULE)
def test_a_tenant_can_lower_a_pack_rules_thresholds_and_not_raise_them(name, key):
    rule = rule_of(name, key)
    compiler = compiler_for(name)
    lower = {"rule": key, "block_at": round(rule.block_at - 0.05, 2)}
    assert compiler.validate(bundle_for(name, [lower]), TENANT) == []
    raised = {"rule": key, "escalate_at": round(rule.escalate_at + 0.04, 2)}
    codes = {e.code for e in compiler.validate(bundle_for(name, [raised]), TENANT)}
    assert codes == {ErrorCode.PACK_OVERRIDE_RAISES}


@pytest.mark.parametrize(("name", "key"), EVERY_RULE)
def test_a_tenant_cannot_switch_a_pack_rule_off_or_change_its_mode(name, key):
    rule = rule_of(name, key)
    compiler = compiler_for(name)
    off = {"rule": key, "enabled": False}
    errors = compiler.validate(bundle_for(name, [off]), TENANT)
    assert [(e.code, e.path) for e in errors] == [
        (ErrorCode.PACK_OVERRIDE_NOT_ALLOWED, "$.overrides[0].enabled")
    ]
    other = (
        "shadow" if rule.mode == "enforce" else "enforce"
    )  # shadowing, or enforcing a shadow rule
    errors = compiler.validate(bundle_for(name, [{"rule": key, "mode": other}]), TENANT)
    assert [(e.code, e.path) for e in errors] == [
        (ErrorCode.PACK_OVERRIDE_NOT_ALLOWED, "$.overrides[0].mode")
    ]
    same = {"rule": key, "mode": rule.mode}  # restating the catalog's own mode changes nothing
    assert compiler.validate(bundle_for(name, [same]), TENANT) == []


# ------------------------------------------------------------------ the golden sets


def test_the_golden_set_is_big_balanced_and_at_the_guard_points_the_pack_covers(name):
    rows = rows_of(name)
    pack = load_pack_file(ROOT / "packs" / name / "pack.json")
    assert len(rows) >= PACKS[name]["min_rows"]
    firing = sum(1 for r in rows if r["fires"])
    assert 0.45 <= firing / len(rows) <= 0.55  # balanced allow and block
    per_gp = Counter((r["guard_point"], bool(r["fires"])) for r in rows)
    for gp in pack.covers:
        assert per_gp[(gp, True)] >= 16 and per_gp[(gp, False)] >= 16, gp
    assert {r["guard_point"] for r in rows} == set(pack.covers)  # nowhere else


def test_every_rule_has_firing_and_allow_rows_at_each_guard_point_it_covers(name):
    rows = rows_of(name)
    pack = load_pack_file(ROOT / "packs" / name / "pack.json")
    for rule in pack._content.rules:
        for gp in rule.guard_points:
            fire = [r for r in rows if r["guard_point"] == gp and rule.key in r["fires"]]
            allow = [r for r in rows if r["guard_point"] == gp and not r["fires"]]
            assert len(fire) >= 16, (rule.key, gp, len(fire))
            assert len(allow) >= 16, (rule.key, gp, len(allow))


def test_a_rows_labels_name_rules_of_the_pack_that_run_at_its_guard_point(name):
    pack = load_pack_file(ROOT / "packs" / name / "pack.json")
    runs = {(r.key, gp) for r in pack._content.rules for gp in r.guard_points}
    for row in rows_of(name):
        for key in row["fires"]:
            assert (key, row["guard_point"]) in runs, row["id"]


def test_the_rows_have_the_flat_schema_and_the_packs_tenant(name):
    slug, tenant_id = PACKS[name]["tenant"]
    ids = set()
    for row in rows_of(name):
        assert sorted(row) == sorted(
            [
                "id",
                "guard_point",
                "category",
                "content",
                "fires",
                "notes",
                "pair",
                "tenant_slug",
                "tenant_id",
                "no_live_run",
            ]
        )
        assert (row["tenant_slug"], row["tenant_id"]) == (slug, tenant_id)
        assert row["id"] not in ids
        ids.add(row["id"])
        assert row["content"].strip() and row["pair"] == ""


ESCALATE_ONLY = {"d__fin_scam_signal", "d__hc_emergency_symptoms"}
"""A person must look; refusing is the wrong outcome (M4-10): ``max_action: escalate``."""
WITHHELD_RULES = {
    "finance": set(),
    "healthcare": {"d__hc_dosage_advice"},
}
"""Rules whose firing rows state advice that could cause harm if acted on (healthcare: which
medicine to take, stop or double). Their positives are never sent (the conservative decision, U4).
Finance has none: its firing rows are misleading statements and tool calls, not dangerous
instructions, and every one is sendable."""
WITHHELD_ROWS = {
    "finance": set(),
    "healthcare": {"hc-dgn-pos-007", "hc-dgn-pos-008", "hc-out-pos-015", "hc-out-pos-016"},
}
"""Rows withheld one template at a time, the rest of their rule sendable: a
diagnosis that says there is no need to be seen (it discourages seeking care) and an outcome
promise that a diet will reverse a condition (health misinformation)."""


def test_rows_that_give_advice_which_could_cause_harm_are_withheld(name):
    rows = rows_of(name)
    assert any(r["no_live_run"] for r in rows) == bool(WITHHELD_RULES[name])
    for row in rows:
        fires_withheld = (
            bool(set(row["fires"]) & WITHHELD_RULES[name]) or row["id"] in WITHHELD_ROWS[name]
        )
        assert row["no_live_run"] is fires_withheld, row["id"]  # exactly those, and all of them
        assert (live_exclusion(row) is not None) is fires_withheld, row["id"]
    assert all(r["no_live_run"] for r in rows if len(r["fires"]) > 1)  # a dual row is withheld too


def test_exactly_twenty_healthcare_rows_are_withheld_and_none_of_finance():
    held = {r["id"] for r in rows_of("healthcare") if r["no_live_run"]}
    assert len(held) == 20 and WITHHELD_ROWS["healthcare"] <= held
    assert {i for i in held if not i.startswith("hc-dos-pos-")} == WITHHELD_ROWS["healthcare"]
    assert not [r for r in rows_of("finance") if r["no_live_run"]]


def test_every_tool_call_plan_and_tool_result_row_is_valid_json(name):
    """A plan, tool call or tool result is JSON (a doubled brace in a template once made
    a row that was not)."""
    for row in rows_of(name):
        if row["guard_point"] in ("plan", "tool_call", "tool_result"):
            json.loads(row["content"])  # raises on a bad row


def test_every_sendable_healthcare_row_is_clean():
    """What may be sent holds no dosing instruction: a sendable dosing-rule row is a near-miss
    that points to the leaflet or the pharmacist, and says what not to do rather than doing it."""
    import re

    directive = re.compile(
        r"\b(take|double|increase|reduce|skip|stop taking|give)\b"
        r".{0,30}\b(\d+|two|three|double|half)\b.{0,30}\b(tablets?|capsules?|mg|doses?|spoonfuls?)\b",
        re.IGNORECASE,
    )
    for row in rows_of("healthcare"):
        if row["no_live_run"]:
            continue
        assert directive.search(row["content"]) is None, (row["id"], row["content"])
    assert all(
        not (set(r["fires"]) & WITHHELD_RULES["healthcare"])
        for r in rows_of("healthcare")
        if not r["no_live_run"]
    )


def test_every_row_passes_the_harm_vocabulary_tripwire_in_every_view(name):
    """The engine's own tripwire (``admin/vocabulary.py``), over the whole row as JSON and over
    each of its strings, in every view (raw, normalised, percent, hex, spaced, leet, base64)."""
    bad = {}
    for row in rows_of(name):
        views = set(tripwire_views(json.dumps(row, ensure_ascii=False)))
        for text in strings(row):
            views.update(tripwire_views(text))
        if views:
            bad[row["id"]] = sorted(views)
    assert bad == {}


def test_the_rows_hold_no_real_contact_details_or_urls(name):
    import re

    pattern = re.compile(
        r"@|https?://|www\.|\b\d{3}[ -]\d{3}[ -]\d{4}\b|\b[A-Z]{2}\d{2}[A-Z0-9]{10,}\b"
    )
    hits = [r["id"] for r in rows_of(name) if pattern.search(r["content"])]
    assert hits == []


def test_the_healthcare_rows_are_synthetic_and_de_identified():
    """No medical record number, no date of birth, no full date at all: ages are numbers of
    years, a person is an invented first name, and an identifier is a marked test reference
    (``SYN-0101``). Every identifier-like token in the set is of that one marked form."""
    import re

    forbidden = re.compile(
        r"\bMRN\b|\bNHS number\b|\bDOB\b|date of birth|\bborn\b|\bSSN\b"
        r"|\b\d{1,2}[/.-]\d{1,2}[/.-]\d{2,4}\b|\b\d{4}-\d{2}-\d{2}\b|\b\d{9,}\b",
        re.IGNORECASE,
    )
    marked = re.compile(r"\bSYN-\d{4}\b")
    other_ids = re.compile(r"\b[A-Z]{2,5}-\d{3,}\b")
    for row in rows_of("healthcare"):
        text = row["content"]
        assert forbidden.search(text) is None, (row["id"], text)
        stripped = marked.sub("", text)
        assert other_ids.search(stripped) is None or "AP-" in stripped or "REF-" in stripped, row[
            "id"
        ]
    refs = [m for r in rows_of("healthcare") for m in marked.findall(r["content"])]
    assert refs  # the identifiers that exist are all marked as test references


def test_the_finance_rows_name_no_real_firm_or_instrument():
    """The firm is the fictional Acme; the symbols and funds are invented. No real company or
    index appears in a row."""
    import re

    real = re.compile(
        r"\b(Barclays|HSBC|Vanguard|BlackRock|Fidelity|Tesla|Apple|Amazon|FTSE|S&P|Nasdaq|Bitcoin)\b",
        re.IGNORECASE,
    )
    assert [r["id"] for r in rows_of("finance") if real.search(r["content"])] == []


def test_the_golden_set_is_what_the_builder_produces(name):
    done = subprocess.run(
        [sys.executable, str(ROOT / "packs" / name / "build_golden.py"), "--check"],
        capture_output=True, text=True, cwd=ROOT,
    )  # fmt: skip
    assert done.returncode == 0, done.stderr
