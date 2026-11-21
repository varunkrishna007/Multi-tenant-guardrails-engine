"""M4-08 ``insurance@2`` and ``energy@2``: thresholds from the live calibration (decided
2026-11-18), the overlap rewordings, and @1 left exactly as it shipped. Offline."""

import hashlib
import json
import secrets
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from guardrail_engine.admin.vocabulary import tripwire_views  # noqa: E402
from guardrail_engine.decision import FakeDecisionModel  # noqa: E402
from guardrail_engine.engine import EngineSettings, build_engine  # noqa: E402
from guardrail_engine.floor_file import load_floor_file  # noqa: E402
from guardrail_engine.guard import (  # noqa: E402
    CheckContext,
    Decision,
    HmacContextVerifier,
    InMemoryTenantDirectory,
    TenantProfile,
)
from guardrail_engine.guard.audit import NullAuditSink  # noqa: E402
from guardrail_engine.pack_file import load_pack_file  # noqa: E402
from guardrail_engine.policy import (  # noqa: E402
    ErrorCode,
    InMemoryCatalog,
    InMemoryToolRegistry,
    PlatformSettings,
    PolicyCompiler,
    TenantAttributes,
)
from packs import make_v2  # noqa: E402

FLOOR = load_floor_file(ROOT / "floor" / "rules.json")
V1_SHA256 = {
    "insurance": "4dd14c3e270ea5c5f57b24d771fa85738d846775d105e788de916c8bcfc2e2de",
    "energy": "04948396fcac97c9bdd3093ec6e97dadde5716dca44f5d41da7b1eea9c2c1229",
}
EXPECTED = {  # key: (block_at, escalate_at, provisional): the arithmetic is in the doc
    "d__ins_payout_promise": (0.85, 0.55, True),  # reworded: @1's, until re-measured
    "d__ins_underwriting_final": (0.85, 0.55, True),  # reworded
    "d__ins_policy_advice": (0.50, 0.30, True),
    "d__ins_fraud_signal": (0.95, 0.50, True),  # no sendable positive
    "d__ins_fraud_accusation": (0.51, 0.30, True),
    "d__ins_binding_action": (0.50, 0.30, True),
    "d__en_price_certainty": (0.85, 0.55, True),  # reworded
    "d__en_unsafe_advice": (0.80, 0.50, True),  # no sendable positive
    "d__en_safety_report": (0.99, 0.40, True),  # escalate-only: block_at inert, 0.40 kept
    "d__en_outage_promise": (0.69, 0.39, True),  # B2 on all rows is above the midpoint; reworded
    "d__en_billing_pressure": (0.50, 0.30, True),
    "d__en_account_change": (0.50, 0.30, True),
}
TENANT = {"insurance": ("t_1042", "acme-insurance"), "energy": ("t_2210", "acme-energy")}


@pytest.fixture(params=sorted(V1_SHA256))
def name(request):
    return request.param


def doc(name, version):
    path = "pack.json" if version == 1 else "pack.v2.json"
    return json.loads((ROOT / "packs" / name / path).read_text(encoding="utf-8"))


def strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for v in value.values():
            yield from strings(v)
    elif isinstance(value, list):
        for v in value:
            yield from strings(v)


# ------------------------------------------------------------------ @1 is never edited


def test_version_1_is_byte_for_byte_what_shipped_and_still_loads(name):
    path = ROOT / "packs" / name / "pack.json"
    assert hashlib.sha256(path.read_bytes()).hexdigest() == V1_SHA256[name]
    assert load_pack_file(path).ref == f"domain/{name}@1"


def test_the_catalog_holds_both_versions_and_a_bundle_extends_either(name):
    v1 = load_pack_file(ROOT / "packs" / name / "pack.json")
    v2 = load_pack_file(ROOT / "packs" / name / "pack.v2.json")
    assert v2.ref == f"domain/{name}@2"
    tenant_id, _ = TENANT[name]
    compiler = PolicyCompiler(
        InMemoryCatalog(floors=[FLOOR], packs=[v1, v2]),
        InMemoryToolRegistry(),
        PlatformSettings(min_floor_version=FLOOR.version),
    )
    attrs = TenantAttributes(tenant_id=tenant_id)
    blocks = {}
    for pack in (v1, v2):
        bundle = {"schema_version": 1, "tenant_id": tenant_id, "version": 1,
                  "extends": [f"platform/floor@{FLOOR.version}", pack.ref]}  # fmt: skip
        compiled = compiler.compile(bundle, attrs)
        blocks[pack.ref] = {
            k: r.block_at for gp in compiled.guard_points.values() for k, r in gp.rules.items()
        }
    differing = [k for k in blocks[v1.ref] if blocks[v1.ref][k] != blocks[v2.ref][k]]
    assert differing and all(k.startswith("d__") for k in differing)  # only the pack's rules


# ------------------------------------------------------------------ what changed, and only that


def test_only_thresholds_provisional_flags_and_four_reworded_descriptions_changed(name):
    a, b = doc(name, 1), doc(name, 2)
    assert (b["version"], b["name"], b["schema_version"]) == (2, a["name"], a["schema_version"])
    assert [r["key"] for r in a["rules"]] == [r["key"] for r in b["rules"]]
    for old, new in zip(a["rules"], b["rules"], strict=True):
        key = new["key"]
        for field in ("guard_points", "mode", "severity", "max_action"):
            assert old.get(field) == new.get(field), (key, field)
        assert old["question"]["instructions"] == new["question"]["instructions"], key  # the text
        changed = old["question"]["criteria"] != new["question"]["criteria"]
        assert changed == (key in make_v2.REWORDED), key
        if changed:  # a rewording only adds scope; it keeps every word it had
            for field in ("true_description", "false_description"):
                assert (
                    old["question"]["criteria"][field].rstrip(".")
                    in new["question"]["criteria"][field]
                ), (key, field)


def test_the_v2_thresholds_are_the_agreed_ones():
    got = {}
    for name in sorted(V1_SHA256):
        for r in doc(name, 2)["rules"]:
            got[r["key"]] = (r["block_at"], r["escalate_at"], r["provisional"])
    assert got == EXPECTED


def test_every_v2_rule_is_provisional_until_a_held_out_check_or_real_traffic():
    """Decided: in-sample synthetic evidence is not enough to drop ``provisional``, the
    flag AC-O1 records on every decision."""
    for name in sorted(V1_SHA256):
        assert all(r["provisional"] is True for r in doc(name, 2)["rules"]), name
        pack = load_pack_file(ROOT / "packs" / name / "pack.v2.json")
        assert all(r.provisional for r in pack._content.rules), name


def test_the_refund_rows_are_in_price_certaintys_scope_and_out_of_outage_promises():
    """Price_certainty names a refund or credit, and outage_promise's compensation is
    for an outage or delay, so the two refund positives lean on the right rule."""
    rules = {r["key"]: r for r in doc("energy", 2)["rules"]}
    price = rules["d__en_price_certainty"]["question"]["criteria"]["true_description"]
    assert "refund or credit" in price
    outage = rules["d__en_outage_promise"]["question"]["criteria"]
    assert "compensation for an outage or delay" in outage["true_description"]
    assert "refund or credit on a bill is not outage compensation" in outage["true_description"]
    assert "refund or credit on a bill" in outage["false_description"]


def test_they_are_what_the_derivation_gives_from_the_live_results():
    """``python -m packs.make_v2 --check``: pack.v2.json is derived, never hand-edited."""
    assert make_v2.main(["--check"]) == 0


def test_the_ruling_applies_to_every_rule_it_covers():
    """block_at is the midpoint of the highest hard negative and the lowest positive, rounded and
    clamped, and never below B2 on all rows when that is higher; unmeasured, reworded and
    escalate-only rules keep @1's block_at."""
    for name in sorted(V1_SHA256):
        for old in doc(name, 1)["rules"]:
            key = old["key"]
            t = make_v2.derive_thresholds(name, old)
            new = next(r for r in doc(name, 2)["rules"] if r["key"] == key)
            m = t["measured"]
            if t["basis"] != "midpoint rule":
                assert new["block_at"] == old["block_at"], key
                continue
            mid = (m["hard_negative_max"] + m["positive_min"]) / 2
            want = min(max(round(mid, 2), 0.50), 0.90)
            if m["b2_block_at"] is not None and m["b2_block_at"] > mid:
                want = max(want, m["b2_block_at"])
            assert new["block_at"] == pytest.approx(want), key
            assert 0.01 <= new["escalate_at"] < new["block_at"] <= 0.99, key
            assert new["escalate_at"] > m["hard_negative_max"], key  # no near-miss escalates
            assert new["escalate_at"] <= m["positive_min"], key  # every positive does


def test_the_escalate_only_rules_keep_their_cap_and_get_no_block_at_from_the_sweep(name):
    for r in doc(name, 2)["rules"]:
        if r["key"] in make_v2.PRESERVE_ESCALATE_AT:
            assert r["max_action"] == "escalate" and r["escalate_at"] == 0.40
            assert r["block_at"] == 0.99  # @1's, inert: the cap holds every action at escalate
        if r["key"] == "d__ins_fraud_signal":
            assert r["max_action"] == "escalate" and r["provisional"] is True


def test_the_pack_text_still_has_no_harm_vocabulary_and_a_tenant_still_cannot_edit_it(name):
    assert [s[:60] for s in strings(doc(name, 2)) if tripwire_views(s)] == []
    v2 = load_pack_file(ROOT / "packs" / name / "pack.v2.json")
    compiler = PolicyCompiler(
        InMemoryCatalog(floors=[FLOOR], packs=[v2]),
        InMemoryToolRegistry(),
        PlatformSettings(min_floor_version=FLOOR.version),
    )
    key = v2._content.rules[0].key
    bundle = {
        "schema_version": 1, "tenant_id": TENANT[name][0], "version": 1,
        "extends": [f"platform/floor@{FLOOR.version}", v2.ref],
        "overrides": [{"rule": key, "question": "Is it fine?"}],
    }  # fmt: skip
    errors = compiler.validate(bundle, TenantAttributes(tenant_id=TENANT[name][0]))
    assert [e.code for e in errors] == [ErrorCode.PACK_TEXT_EDITED]


# ------------------------------------------------------------------ the golden set still holds


async def test_every_golden_row_still_gets_the_verdict_its_label_calls_for_under_v2(name):
    """The same oracle test as @1's release gate, on @2's thresholds: nothing about the labels
    changed (no row is dual-labelled), so the same rows must act and the same must not."""
    v2 = load_pack_file(ROOT / "packs" / name / "pack.v2.json")
    tenant_id, slug = TENANT[name]
    state = {"fires": set()}

    def oracle(text, key, question):
        if not key.startswith(("d__", "p__")):
            return None
        return 0.97 if key in state["fires"] else 0.02

    verifier = HmacContextVerifier(secrets.token_bytes(32))
    engine = await build_engine(
        EngineSettings.from_mapping(
            {"environment": "test", "platform": {"min_floor_version": FLOOR.version}}
        ),
        verifier=verifier,
        tenants=InMemoryTenantDirectory(
            [TenantProfile.build(TenantAttributes(tenant_id=tenant_id), name, (), slug=slug)]
        ),
        model=FakeDecisionModel(responder=oracle),
        catalog=InMemoryCatalog(floors=[FLOOR], packs=[v2]),
        audit=NullAuditSink(),
    )
    try:
        await engine.bootstrap_publish(
            {
                "schema_version": 1,
                "tenant_id": tenant_id,
                "version": 1,
                "extends": [f"platform/floor@{FLOOR.version}", v2.ref],
            }
        )
        wrong = []
        text = (ROOT / "packs" / name / "golden.jsonl").read_text(encoding="utf-8")
        for line in text.splitlines():
            row = json.loads(line)
            state["fires"] = set(row["fires"])
            verdict = await engine.check(
                CheckContext(signed_context=verifier.issue(tenant_id)),
                row["guard_point"], row["content"],
            )  # fmt: skip
            acted = verdict.decision in (Decision.BLOCK, Decision.ESCALATE)
            if acted != bool(row["fires"]):
                wrong.append(row["id"])
        assert wrong == []
    finally:
        await engine.shutdown()
