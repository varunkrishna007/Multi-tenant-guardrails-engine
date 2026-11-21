"""M4-08 the offline release gate for a pack: every golden row goes through a built engine whose
catalog holds the real floor and the pack, for a tenant that extends both, with a model that
answers as the row's label says (an oracle, as the M2-08 harness's offline mode does). It proves
the plumbing, not the model: the pack's questions are sent at exactly the guard points the pack
declares, with the pack's keys, and the verdict follows the labels. The live part (what the real
model says, the thresholds) is the [LIVE] calibration and needs explicit approval."""

import json
import secrets
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

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
from guardrail_engine.policy import InMemoryCatalog, TenantAttributes  # noqa: E402

FLOOR = load_floor_file(ROOT / "floor" / "rules.json")
TENANTS = {"insurance": ("t_1042", "acme-insurance"), "energy": ("t_2210", "acme-energy")}


def rows_of(name):
    text = (ROOT / "packs" / name / "golden.jsonl").read_text(encoding="utf-8")
    return [json.loads(line) for line in text.splitlines()]


@pytest.fixture(params=sorted(TENANTS))
async def rig(request):
    name = request.param
    tenant_id, slug = TENANTS[name]
    pack = load_pack_file(ROOT / "packs" / name / "pack.json")
    state = {"fires": set()}

    def oracle(text, key, question):
        if not key.startswith(("d__", "p__")):
            return None
        if key in state["fires"]:
            return 0.99 if state.get("top") else 0.95
        return 0.02

    verifier = HmacContextVerifier(secrets.token_bytes(32))
    directory = InMemoryTenantDirectory(
        [TenantProfile.build(TenantAttributes(tenant_id=tenant_id), name, (), slug=slug)]
    )
    engine = await build_engine(
        EngineSettings.from_mapping(
            {"environment": "test", "platform": {"min_floor_version": FLOOR.version}}
        ),
        verifier=verifier, tenants=directory, model=FakeDecisionModel(responder=oracle),
        catalog=InMemoryCatalog(floors=[FLOOR], packs=[pack]), audit=NullAuditSink(),
    )  # fmt: skip
    await engine.bootstrap_publish(
        {
            "schema_version": 1, "tenant_id": tenant_id, "version": 1,
            "extends": [f"platform/floor@{FLOOR.version}", pack.ref],
        }
    )  # fmt: skip
    yield name, pack, engine, verifier, state, tenant_id
    await engine.shutdown()


async def run_row(engine, verifier, state, tenant_id, row):
    state["fires"] = set(row["fires"])
    return await engine.check(
        CheckContext(signed_context=verifier.issue(tenant_id)), row["guard_point"], row["content"]
    )


async def test_every_golden_row_gets_the_verdict_its_label_calls_for(rig):
    """A row labelled with an enforcing rule is blocked or escalated. A row labelled only with a
    shadow rule is allowed, and the verdict's evaluation shows what the rule would have done."""
    name, pack, engine, verifier, state, tenant_id = rig
    modes = {r.key: r.mode for r in pack._content.rules}
    wrong = []
    for row in rows_of(name):
        verdict = await run_row(engine, verifier, state, tenant_id, row)
        acts = any(modes[k] == "enforce" for k in row["fires"])
        acted = verdict.decision in (Decision.BLOCK, Decision.ESCALATE)
        if acted != acts:
            wrong.append((row["id"], verdict.decision.value, verdict.reason.value))
        for key in row["fires"]:
            ev = next(e for e in verdict.rules if e.key == key)
            if ev.action.value == "allow" or ev.mode != modes[key]:
                wrong.append((row["id"], key, ev.action.value, ev.mode))
    assert wrong == []


async def test_an_escalate_only_rule_escalates_even_at_the_top_of_its_range(rig):
    """M4-10: ``max_action: escalate`` caps the rule's action. A probability of 0.99 on a rule
    whose ``block_at`` is lower than that still escalates; nothing refuses a person at risk."""
    name, pack, engine, verifier, state, tenant_id = rig
    capped = {r.key for r in pack._content.rules if r.max_action == "escalate"}
    assert len(capped) == 1
    row = next(r for r in rows_of(name) if set(r["fires"]) == capped)
    state["top"] = True
    try:
        verdict = await run_row(engine, verifier, state, tenant_id, row)
    finally:
        state["top"] = False
    assert verdict.decision == Decision.ESCALATE  # never BLOCK
    (ev,) = (e for e in verdict.rules if e.key in capped)
    assert ev.action.value == "escalate" and ev.max_action == "escalate" and ev.p == 0.99


async def test_the_pack_rules_are_sent_at_exactly_the_guard_points_the_pack_declares(rig):
    name, pack, engine, verifier, state, tenant_id = rig
    seen: dict[str, set[str]] = {}
    for row in rows_of(name):
        verdict = await run_row(engine, verifier, state, tenant_id, row)
        pack_keys = {ev.key for ev in verdict.rules if ev.layer == "pack"}
        seen.setdefault(row["guard_point"], set()).update(pack_keys)
    declared = {
        gp: {r.key for r in pack._content.rules if gp in r.guard_points} for gp in pack.covers
    }
    assert seen == declared


async def test_a_firing_pack_rule_is_enforced_and_acts_with_its_own_key(rig):
    name, _pack, engine, verifier, state, tenant_id = rig
    rows = {r["id"]: r for r in rows_of(name)}
    row = next(r for r in rows.values() if r["fires"])
    verdict = await run_row(engine, verifier, state, tenant_id, row)
    assert verdict.decision in (Decision.BLOCK, Decision.ESCALATE)
    assert {f.key for f in verdict.fired if f.layer == "pack"} == set(row["fires"])


async def test_the_floor_still_answers_at_the_guard_points_the_pack_adds_rules(rig):
    """A pack adds rules; it never removes or replaces a floor rule at a guard point."""
    name, _pack, engine, verifier, state, tenant_id = rig
    row = rows_of(name)[0]
    verdict = await run_row(engine, verifier, state, tenant_id, row)
    assert {ev.key for ev in verdict.rules if ev.layer == "floor"} >= {
        k for k in ("p__inj_direct",) if row["guard_point"] == "input"
    }
    assert any(ev.layer == "floor" for ev in verdict.rules)


async def test_the_engine_reads_the_packs_from_its_catalog_settings(tmp_path):
    """The catalog entry: ``catalog.pack_files`` is how a deployment ships the packs."""
    from guardrail_engine.engine import SettingsError

    files = [str(ROOT / "packs" / n / "pack.json") for n in ("insurance", "energy")]
    settings = EngineSettings.from_mapping(
        {
            "environment": "test",
            "platform": {"min_floor_version": FLOOR.version},
            "catalog": {"floor_files": [str(ROOT / "floor" / "rules.json")], "pack_files": files},
        }
    )
    engine = await build_engine(
        settings, verifier=HmacContextVerifier(secrets.token_bytes(32)),
        model=FakeDecisionModel(), audit=NullAuditSink(),
    )  # fmt: skip
    try:
        assert {n for n, _ in engine.catalog.pack_versions()} == {"insurance", "energy"}
    finally:
        await engine.shutdown()
    broken = tmp_path / "pack.json"
    broken.write_text(
        (ROOT / "packs" / "energy" / "pack.json").read_text().replace("Does the", "Say the", 1)
    )
    bad = EngineSettings.from_mapping(
        {
            "environment": "test",
            "platform": {"min_floor_version": FLOOR.version},
            "catalog": {
                "floor_files": [str(ROOT / "floor" / "rules.json")],
                "pack_files": [str(broken)],
            },
        }
    )
    with pytest.raises(SettingsError, match=r"catalog\.pack_files\[0\].*rejected"):
        await build_engine(
            bad, verifier=HmacContextVerifier(secrets.token_bytes(32)),
            model=FakeDecisionModel(), audit=NullAuditSink(),
        )  # fmt: skip
