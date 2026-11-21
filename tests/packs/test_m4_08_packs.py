"""M4-08 the insurance and energy domain packs: what they are, what their golden sets hold, and
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
    "insurance": {"tenant": ("acme-insurance", "t_1042"), "rules": 6, "min_rows": 200},
    "energy": {"tenant": ("acme-energy", "t_2210"), "rules": 6, "min_rows": 200},
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
        # the two rules that want escalate-never-block say so (M4-10, R4.3) and enforce again
        assert r.mode == "enforce", r.key
        assert (r.max_action == "escalate") == (r.key in ESCALATE_ONLY), r.key
        assert r.question.criteria is not None  # both descriptions (AC-C2.1)


def test_every_threshold_is_provisional_until_calibration(name):
    """The [LIVE] calibration (M4-01 on the real API) hasn't run; the numbers are first guesses."""
    pack = load_pack_file(ROOT / "packs" / name / "pack.json")
    assert all(r.provisional for r in pack._content.rules)
    document = json.loads((ROOT / "packs" / name / "pack.json").read_text())
    assert all(r["provisional"] is True for r in document["rules"])


def test_the_pack_declares_the_guard_points_it_covers(name):
    pack = load_pack_file(ROOT / "packs" / name / "pack.json")
    declared = {gp for r in pack._content.rules for gp in r.guard_points}
    assert pack.covers == frozenset(declared)
    expected = {
        "insurance": {"input", "plan", "tool_result", "tool_call", "output"},
        "energy": {"input", "tool_call", "output"},
    }[name]
    assert declared == expected


def test_r3_sets_no_retention_override_so_the_standard_profile_applies(name):
    """R3's table: insurance and energy are the standard column (class B 395 days by default)."""
    assert load_pack_file(ROOT / "packs" / name / "pack.json").retention is None


def test_the_pack_text_has_no_harm_vocabulary(name):
    document = json.loads((ROOT / "packs" / name / "pack.json").read_text())
    hits = [s[:60] for s in strings(document) if tripwire_views(s)]
    assert hits == []


def test_a_malformed_pack_file_is_refused(tmp_path):
    good = (ROOT / "packs" / "energy" / "pack.json").read_text()
    for text in (
        good.replace('"d__en_price_certainty"', '"en_price_certainty"'),  # not a d__ key
        good.replace("Does the response state", "State", 1),  # not a closed question
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


ESCALATE_ONLY = {"d__ins_fraud_signal", "d__en_safety_report"}
"""M4-10: a person must look; refusing is the wrong outcome. They shipped in shadow until
``max_action`` existed, and now enforce with ``max_action: escalate``."""
WITHHELD_RULES = {
    "insurance": {"d__ins_fraud_signal"},
    "energy": {"d__en_unsafe_advice"},
}
"""Rules whose firing rows state dangerous advice (energy: do gas or electrical work yourself,
ignore a leak) or ask for help with a wrong (insurance: alter a date or a value, claim for
what did not happen). Their positives are never sent (decision 2026-11-19, on the
conservative side of the user's no-harmful-inputs rule, U4). The two rules are provisional with
no live calibration."""


def test_rows_that_state_dangerous_advice_or_ask_for_help_with_a_wrong_are_withheld(name):
    rows = rows_of(name)
    held = [r for r in rows if r["no_live_run"]]
    assert held, "the withheld rule's positives must be tagged"
    for row in rows:
        fires_withheld = bool(set(row["fires"]) & WITHHELD_RULES[name])
        assert row["no_live_run"] is fires_withheld, row["id"]  # exactly those, and all of them
        assert (live_exclusion(row) is not None) is fires_withheld, row["id"]
    # A row that meets a withheld rule as well as another rule is withheld too
    dual = [r for r in rows if len(r["fires"]) > 1]
    assert all(r["no_live_run"] for r in dual)


def test_the_energy_outage_rows_that_tell_the_customer_to_reconnect_unchecked_are_dual_labelled():
    by_id = {r["id"]: r for r in rows_of("energy")}
    for rid in ("en-out-pos-003", "en-out-pos-004", "en-out-pos-011", "en-out-pos-016"):
        assert by_id[rid]["fires"] == ["d__en_outage_promise", "d__en_unsafe_advice"], rid
        assert by_id[rid]["no_live_run"] is True, rid


def test_every_sendable_row_is_clean(name):
    """What may be sent holds no dangerous instruction and no request for help with a wrong:
    the sendable rows of the withheld rules (their near-misses) are safe-guidance answers and
    honest questions, and no sendable row says to do gas or electrical work oneself, to ignore
    a danger sign, or to alter or invent a claim detail."""
    import re

    dangerous = re.compile(
        r"(repair|fix|reconnect|bypass|move|replace)\b.{0,40}\byourself"
        r"|ignore (it|them|the alarm)|take the battery out and ignore"
        r"|(change|alter) the (invoice|date|report)|(say|put|write) it was new"
        r"|keep both payments|leave out that|make (a claim )?up|word it",
        re.IGNORECASE,
    )
    refusals = re.compile(r"\b(don't|do not|never|isn't safe|please don't)\b", re.IGNORECASE)
    for row in rows_of(name):
        if row["no_live_run"]:
            continue
        match = dangerous.search(row["content"])
        # a safe answer may mention what not to do ("please don't try to repair it yourself")
        assert match is None or refusals.search(row["content"]), (row["id"], row["content"])
    for row in rows_of(name):  # and every sendable row that fires something is a harmless one
        assert row["no_live_run"] or not (set(row["fires"]) & WITHHELD_RULES[name])


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


def test_the_golden_set_is_what_the_builder_produces(name):
    done = subprocess.run(
        [sys.executable, str(ROOT / "packs" / name / "build_golden.py"), "--check"],
        capture_output=True, text=True, cwd=ROOT,
    )  # fmt: skip
    assert done.returncode == 0, done.stderr
