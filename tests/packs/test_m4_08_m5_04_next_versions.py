"""``insurance@3``, ``energy@3``, ``finance@2`` and ``healthcare@2``: thresholds from the
2026-11-19 live runs (decided 2026-11-19), every earlier version left exactly as it shipped.
Offline: the records are in ``calibration/results/``, nothing is sent."""

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
    InMemoryCatalog,
    InMemoryToolRegistry,
    PlatformSettings,
    PolicyCompiler,
    TenantAttributes,
)
from packs import derive_versions  # noqa: E402

FLOOR = load_floor_file(ROOT / "floor" / "rules.json")
NEW = {  # pack: (new version, base version)
    "insurance": (3, 2), "energy": (3, 2), "finance": (2, 1), "healthcare": (2, 1),
}  # fmt: skip
TENANT = {
    "insurance": ("t_1042", "acme-insurance"),
    "energy": ("t_2210", "acme-energy"),
    "finance": ("t_3310", "acme-finance"),
    "healthcare": ("t_4410", "acme-health"),
}
SHIPPED_SHA256 = {  # every earlier version is byte for byte what shipped
    "insurance": {
        1: "4dd14c3e270ea5c5f57b24d771fa85738d846775d105e788de916c8bcfc2e2de",
        2: "be74307cea7feef631359fa204f21b91a1043291172197905dbac03f2526660f",
    },
    "energy": {
        1: "04948396fcac97c9bdd3093ec6e97dadde5716dca44f5d41da7b1eea9c2c1229",
        2: "170fd53a4dc787bc04d98fddca5b0ea020156c342445933bad03b1f5f617720f",
    },
    "finance": {1: "5c61d63f2ec14ccd03f0642f8e2512cee807b90a19e71038c876f68961e326ab"},
    "healthcare": {1: "90b067285aacc2f25d7aad82ebc89329d055dcf4e4ca4375548dd717a53c97e2"},
}
EXPECTED = {  # key: (block_at, escalate_at): decided 2026-11-19; the arithmetic is in the notes
    "d__ins_payout_promise": (0.54, 0.30),
    "d__ins_underwriting_final": (0.50, 0.30),
    "d__ins_policy_advice": (0.50, 0.30),  # not re-measured: @2's
    "d__ins_fraud_signal": (0.95, 0.50),  # no sendable positive: @1's
    "d__ins_fraud_accusation": (0.51, 0.30),
    "d__ins_binding_action": (0.50, 0.30),
    "d__en_price_certainty": (0.63, 0.50),
    "d__en_unsafe_advice": (0.80, 0.50),
    "d__en_safety_report": (0.99, 0.40),  # escalate-only
    "d__en_outage_promise": (0.57, 0.30),
    "d__en_billing_pressure": (0.50, 0.30),
    "d__en_account_change": (0.50, 0.30),
    "d__fin_guaranteed_return": (0.54, 0.30),
    "d__fin_personal_advice": (0.50, 0.30),
    "d__fin_pressure_sale": (0.50, 0.30),
    "d__fin_payment_instruction": (0.52, 0.30),
    "d__fin_scam_signal": (0.95, 0.50),  # escalate-only: kept
    "d__fin_tax_legal_conclusion": (0.50, 0.30),
    "d__hc_diagnosis": (0.50, 0.30),
    "d__hc_dosage_advice": (0.80, 0.50),  # not calibrated live: @1's
    "d__hc_emergency_symptoms": (0.99, 0.40),  # escalate-only: kept
    "d__hc_phi_disclosure": (0.50, 0.30),
    "d__hc_record_change": (0.75, 0.59),
    "d__hc_outcome_promise": (0.50, 0.30),
}


@pytest.fixture(params=sorted(NEW))
def name(request):
    return request.param


def path(name, version):
    return ROOT / "packs" / name / ("pack.json" if version == 1 else f"pack.v{version}.json")


def doc(name, version):
    return json.loads(path(name, version).read_text(encoding="utf-8"))


def strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for v in value.values():
            yield from strings(v)
    elif isinstance(value, list):
        for v in value:
            yield from strings(v)


def test_every_earlier_version_is_byte_for_byte_what_shipped_and_still_loads(name):
    for version, sha in SHIPPED_SHA256[name].items():
        assert hashlib.sha256(path(name, version).read_bytes()).hexdigest() == sha, version
        assert load_pack_file(path(name, version)).ref == f"domain/{name}@{version}"


def test_the_new_files_are_what_the_derivation_gives_from_the_live_records():
    assert derive_versions.main(["--check"]) == 0


def test_only_thresholds_and_the_version_changed_and_every_rule_is_provisional(name):
    new_v, base_v = NEW[name]
    old, new = doc(name, base_v), doc(name, new_v)
    assert (new["version"], new["name"], new["schema_version"]) == (
        new_v, old["name"], old["schema_version"],
    )  # fmt: skip
    assert [r["key"] for r in old["rules"]] == [r["key"] for r in new["rules"]]
    for a, b in zip(old["rules"], new["rules"], strict=True):
        changed = {k for k in a.keys() | b.keys() if a.get(k) != b.get(k)}
        assert changed <= {"block_at", "escalate_at", "provisional"}, (b["key"], changed)
        assert b["provisional"] is True, b["key"]
    assert all(r.provisional for r in load_pack_file(path(name, new_v))._content.rules)


def test_the_thresholds_are_the_agreed_ones(name):
    new_v, _ = NEW[name]
    got = {r["key"]: (r["block_at"], r["escalate_at"]) for r in doc(name, new_v)["rules"]}
    assert got == {k: v for k, v in EXPECTED.items() if k in got}
    for key, (block_at, escalate_at) in got.items():
        assert 0.01 <= escalate_at < block_at <= 0.99, key


def test_escalate_only_rules_and_rules_without_a_live_positive_keep_their_values():
    for name, key in (("finance", "d__fin_scam_signal"), ("healthcare", "d__hc_emergency_symptoms"),
                      ("healthcare", "d__hc_dosage_advice"), ("energy", "d__en_safety_report"),
                      ("insurance", "d__ins_fraud_signal")):  # fmt: skip
        new_v, base_v = NEW[name]
        old = next(r for r in doc(name, base_v)["rules"] if r["key"] == key)
        new = next(r for r in doc(name, new_v)["rules"] if r["key"] == key)
        assert (new["block_at"], new["escalate_at"]) == (old["block_at"], old["escalate_at"])
    assert {"d__hc_dosage_advice"} == derive_versions.NOT_CALIBRATED_LIVE


def test_a_rule_kept_for_want_of_a_positive_must_be_named_not_calibrated_live(monkeypatch):
    """Dosage_advice is kept because nothing was measured; dropping it from the set
    makes the derivation refuse rather than keep it silently."""
    monkeypatch.setattr(derive_versions, "NOT_CALIBRATED_LIVE", frozenset())
    with pytest.raises(AssertionError, match="d__hc_dosage_advice"):
        derive_versions.derive("healthcare", 2)


def test_a_rule_listed_as_not_calibrated_live_keeps_its_base_values(monkeypatch):
    monkeypatch.setattr(derive_versions, "NOT_CALIBRATED_LIVE", frozenset({"d__hc_diagnosis"}))
    with pytest.raises(AssertionError):  # diagnosis was measured: its values moved
        derive_versions.derive("healthcare", 2)


def test_the_catalog_holds_every_version_and_a_bundle_extends_any(name):
    new_v, _ = NEW[name]
    versions = [*sorted(SHIPPED_SHA256[name]), new_v]
    packs = [load_pack_file(path(name, v)) for v in versions]
    assert [p.ref for p in packs] == [f"domain/{name}@{v}" for v in versions]
    tenant_id, _ = TENANT[name]
    compiler = PolicyCompiler(
        InMemoryCatalog(floors=[FLOOR], packs=packs),
        InMemoryToolRegistry(),
        PlatformSettings(min_floor_version=FLOOR.version),
    )
    attrs = TenantAttributes(tenant_id=tenant_id)
    blocks = {}
    for pack in packs:
        bundle = {"schema_version": 1, "tenant_id": tenant_id, "version": 1,
                  "extends": [f"platform/floor@{FLOOR.version}", pack.ref]}  # fmt: skip
        compiled = compiler.compile(bundle, attrs)
        blocks[pack.ref] = {
            k: r.block_at for gp in compiled.guard_points.values() for k, r in gp.rules.items()
        }
    differing = [
        k for k in blocks[packs[-1].ref] if blocks[packs[-1].ref][k] != blocks[packs[-2].ref][k]
    ]
    assert differing and all(k.startswith("d__") for k in differing)


def test_the_pack_text_still_has_no_harm_vocabulary(name):
    new_v, _ = NEW[name]
    assert [s[:60] for s in strings(doc(name, new_v)) if tripwire_views(s)] == []


async def test_every_golden_row_still_gets_the_verdict_its_label_calls_for(name):
    """The oracle test of the earlier versions' release gates, on the new thresholds: the same
    rows must act and the same must not (nothing about the labels changed)."""
    new_v, _ = NEW[name]
    pack = load_pack_file(path(name, new_v))
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
        catalog=InMemoryCatalog(floors=[FLOOR], packs=[pack]),
        audit=NullAuditSink(),
    )
    try:
        await engine.bootstrap_publish(
            {
                "schema_version": 1,
                "tenant_id": tenant_id,
                "version": 1,
                "extends": [f"platform/floor@{FLOOR.version}", pack.ref],
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
