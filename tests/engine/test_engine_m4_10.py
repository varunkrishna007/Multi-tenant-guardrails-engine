"""M4-10 on the engine: the responsible-AI pack is loaded from the catalog settings, is on in a
new tenant's starter bundle, an opt-out of one rule keeps its justification in the class A audit
event, and an escalate-only rule escalates through a real check."""

from pathlib import Path

import pytest
from engine_fixtures import TENANT, directory, settings, verifier

from guardrail_engine.authz import Principal, Role
from guardrail_engine.decision import FakeDecisionModel
from guardrail_engine.engine import InMemoryAdminAuditSink, build_engine
from guardrail_engine.guard import CheckContext, Decision

ROOT = Path(__file__).resolve().parents[2]
RAI_FILE = str(ROOT / "packs" / "responsible_ai" / "pack.json")
JUSTIFICATION = "Age is a lawful rating factor for this product in the markets we sell to."


def rai_settings(**catalog):
    return settings(catalog={"pack_files": [RAI_FILE], **catalog})


async def build(**kwargs):
    return await build_engine(
        kwargs.pop("settings", rai_settings()),
        verifier=verifier(),
        tenants=directory(),
        model=kwargs.pop("model", FakeDecisionModel()),
        authz_audit=__import__("guardrail_engine.authz", fromlist=["x"]).InMemoryAuthzAudit(),
        **kwargs,
    )


def doc(**changes):
    base = {
        "schema_version": 1, "tenant_id": TENANT, "version": 1,
        "extends": ["platform/floor@1", "domain/responsible_ai@1"],
    }  # fmt: skip
    return base | changes


async def test_the_pack_is_in_the_catalog_with_its_claims_boundary_and_flags():
    engine = await build()
    try:
        pack = engine.catalog.pack("responsible_ai", 1)
        assert pack is not None and pack.per_rule_optional is True
        text = pack.description
        assert "detects biased content and decisions in individual responses" in text.lower()
        assert "aggregate fairness is not measured" in text.lower()
        assert len(pack._content.rules) == 7
        harm = next(r for r in pack._content.rules if r.key == "d__harm_facilitation")
        assert harm.mode == "shadow"  # observe-only (U5)
    finally:
        await engine.shutdown()


async def test_a_new_tenants_starter_bundle_has_the_pack_on_and_it_compiles():
    engine = await build()
    try:
        principal = Principal("vic", TENANT, frozenset({Role.VIEWER}), issuer="https://i/")
        d = await engine.authorizer.authorize(
            principal, "GET", "/v1/tenants/{tid}/guardrails/catalog", tenant_id=TENANT
        )
        view = await engine.catalog_service.view(d)
        starter = view["starter_bundle"]
        assert starter["extends"][1:] == ["domain/responsible_ai@1"]
        rai = next(p for p in view["packs"] if p["name"] == "responsible_ai")
        assert rai["default_on"] is True and rai["per_rule_optional"] is True
        assert "individual responses" in rai["description"]
        await engine.bootstrap_publish(starter)  # the starter is a valid first bundle
        assert await engine.store.get_active_version(TENANT) == 1
    finally:
        await engine.shutdown()


async def test_an_opt_out_with_its_justification_is_in_the_class_a_event():
    sink = InMemoryAdminAuditSink()
    engine = await build(admin_audit=sink)
    try:
        override = {
            "rule": "d__bias_protected_basis",
            "enabled": False,
            "justification": JUSTIFICATION,
        }
        await engine.bootstrap_publish(doc(overrides=[override]))
        (event,) = sink.events
        # a first publish diffs from an empty document: the whole ``overrides`` list is added
        added = [d for d in event.diff if d.path == "/overrides"]
        assert added and added[0].after[0]["justification"] == JUSTIFICATION  # in the audit event
        assert added[0].after[0]["rule"] == "d__bias_protected_basis"
        assert added[0].after[0]["enabled"] is False
    finally:
        await engine.shutdown()


async def test_an_opt_out_without_a_justification_is_refused_and_nothing_is_published():
    sink = InMemoryAdminAuditSink()
    engine = await build(admin_audit=sink)
    try:
        override = {"rule": "d__bias_protected_basis", "enabled": False}
        with pytest.raises(Exception, match="justification"):
            await engine.bootstrap_publish(doc(overrides=[override]))
        assert sink.events == [] and await engine.store.get_active_version(TENANT) is None
    finally:
        await engine.shutdown()


async def test_a_tier_required_rule_cannot_be_opted_out_of_by_a_tenant_of_that_tier():
    """The directory's fixture tenant is standard; mark the rule required for the standard tier
    to prove the setting reaches the compiler through the engine's catalog."""
    engine = await build(
        settings=rai_settings(tier_required_rules={"standard": ["d__self_harm_risk"]})
    )
    try:
        override = {"rule": "d__self_harm_risk", "enabled": False, "justification": JUSTIFICATION}
        with pytest.raises(Exception, match=r"pack\.rule_required"):
            await engine.bootstrap_publish(doc(overrides=[override]))
    finally:
        await engine.shutdown()


async def test_a_self_harm_rule_at_p_0_99_escalates_through_a_real_check():
    model = FakeDecisionModel()
    engine = await build(model=model)
    try:
        await engine.bootstrap_publish(doc())
        for key in ("p__inj_direct", "p__inj_indirect", "p__ai_addressed", "p__secret", "p__exfil"):
            model.set_noul(key, 0.01)
        model.set_noul("d__self_harm_risk", 0.99)
        verdict = await engine.check(
            CheckContext(signed_context=verifier().issue(TENANT)), "input", "a message"
        )
        assert verdict.decision == Decision.ESCALATE  # never block (R4.3)
        fired = {f.key: f.action.value for f in verdict.fired}
        assert fired["d__self_harm_risk"] == "escalate"
    finally:
        await engine.shutdown()


async def test_the_shadow_harm_rule_never_acts():
    model = FakeDecisionModel()
    engine = await build(model=model)
    try:
        await engine.bootstrap_publish(doc())
        model.set_noul("d__harm_facilitation", 0.99)
        verdict = await engine.check(
            CheckContext(signed_context=verifier().issue(TENANT)), "input", "a message"
        )
        assert verdict.decision == Decision.ALLOW
        ev = next(e for e in verdict.rules if e.key == "d__harm_facilitation")
        assert ev.mode == "shadow" and ev.action.value == "block"  # what it would have done
    finally:
        await engine.shutdown()
