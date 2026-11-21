"""M5-01 on the engine: the tier attribute drives the required packs (the whole responsible-AI
pack on the regulated tiers), the per-rule opt-out refusal and the approval gate; a raise on a
live tenant takes effect at the next publish while the active version keeps running."""

from pathlib import Path

import pytest
from engine_fixtures import TENANT, bundle, ctx, directory, profile, settings, verifier

from guardrail_engine.admin.approvals import approval_required
from guardrail_engine.authz import InMemoryAuthzAudit
from guardrail_engine.decision import FakeDecisionModel
from guardrail_engine.engine import build_engine
from guardrail_engine.guard import Decision
from guardrail_engine.policy import PolicyCompiler
from guardrail_engine.policy.catalog import REGULATED_REQUIRED_PACKS, REGULATED_TIERS
from guardrail_engine.policy.errors import ErrorCode

ROOT = Path(__file__).resolve().parents[2]
RAI_FILE = str(ROOT / "packs" / "responsible_ai" / "pack.json")
RAI_RULES = {
    "d__self_harm_risk",
    "d__vulnerability",
    "d__harassment",
    "d__manipulation",
    "d__bias_stereotype",
    "d__bias_protected_basis",
    "d__harm_facilitation",
}
RAI = "domain/responsible_ai@1"
JUSTIFICATION = "Age is a lawful rating factor for this product in the markets we sell to."


async def build(*profiles, **kwargs):
    return await build_engine(
        kwargs.pop("settings", settings(catalog={"pack_files": [RAI_FILE]})),
        verifier=verifier(),
        tenants=directory(*profiles) if profiles else directory(),
        model=kwargs.pop("model", FakeDecisionModel()),
        authz_audit=InMemoryAuthzAudit(),
        **kwargs,
    )


def errors(engine, tenant_profile, doc):
    return PolicyCompiler(engine.catalog, tenant_profile, engine.settings.platform).validate(
        doc, tenant_profile.attributes
    )


def codes(found):
    return {e.code for e in found}


def with_pack(*, overrides=(), **changes):
    return {
        **bundle(),
        "extends": ["platform/floor@1", RAI],
        "overrides": list(overrides),
        **changes,
    }


def opt_out(rule):
    return {"rule": rule, "enabled": False, "justification": JUSTIFICATION}


# ---------------------------------------------------------------- what the tier requires


async def test_the_regulated_tiers_require_the_whole_responsible_ai_pack_by_default():
    engine = await build()
    try:
        c = engine.catalog
        assert {"regulated", "dedicated"} == REGULATED_TIERS
        assert {"responsible_ai"} == REGULATED_REQUIRED_PACKS
        for tier in REGULATED_TIERS:
            assert c.packs_required_for_tier(tier) == {"responsible_ai"}
            # R4 names no rule: the whole pack, harm_facilitation (observe-only) included
            assert c.rules_required_for_tier(tier) == RAI_RULES
        assert c.packs_required_for_tier("standard") == frozenset()
        assert c.rules_required_for_tier("standard") == frozenset()
    finally:
        await engine.shutdown()


async def test_settings_add_to_the_platforms_requirements_and_never_replace_them():
    s = settings(
        catalog={
            "pack_files": [RAI_FILE],
            "tier_required_packs": {"regulated": ["claims"]},
            "tier_required_rules": {"standard": ["d__self_harm_risk"]},
        }
    )
    engine = await build(settings=s)
    try:
        assert engine.catalog.packs_required_for_tier("regulated") == {"responsible_ai", "claims"}
        assert engine.catalog.rules_required_for_tier("standard") == {"d__self_harm_risk"}
        assert engine.catalog.rules_required_for_tier("regulated") == RAI_RULES
    finally:
        await engine.shutdown()


async def test_without_the_pack_loaded_test_leaves_the_requirement_out_and_production_keeps_it(
    caplog,
):
    plain = settings()
    engine = await build(settings=plain)
    try:
        assert engine.catalog.packs_required_for_tier("regulated") == frozenset()
    finally:
        await engine.shutdown()
    assert "requires the pack(s) ['responsible_ai']" in caplog.text
    # production and staging never skip it: a regulated tenant can't publish until the pack
    # is loaded, and the engine says so at startup
    caplog.clear()
    from guardrail_engine.engine.factory import _tier_required_packs

    for environment in ("production", "staging"):
        required = _tier_required_packs(settings(environment=environment), [])
        assert required["regulated"] == required["dedicated"] == {"responsible_ai"}
    assert "can't publish until catalog.pack_files has them" in caplog.text


# ---------------------------------------------------------------- the compiler


async def test_the_compiler_refuses_a_regulated_bundle_that_drops_the_required_pack():
    engine = await build()
    try:
        for tier in REGULATED_TIERS:
            who = profile(tier=tier)
            assert ErrorCode.PACK_REQUIRED_MISSING in codes(errors(engine, who, bundle()))
            assert errors(engine, who, with_pack()) == []
        assert errors(engine, profile(), bundle()) == []  # standard: the pack is a choice
    finally:
        await engine.shutdown()


async def test_the_compiler_refuses_opting_out_of_any_tier_required_rule():
    engine = await build()
    try:
        regulated = profile(tier="regulated")
        for rule in sorted(RAI_RULES):
            found = errors(engine, regulated, with_pack(overrides=[opt_out(rule)]))
            assert codes(found) == {ErrorCode.PACK_RULE_REQUIRED}, rule
        # a standard tenant may opt out of one rule with a justification (R4.6)
        assert errors(engine, profile(), with_pack(overrides=[opt_out("d__harassment")])) == []
    finally:
        await engine.shutdown()


# ---------------------------------------------------------------- R2: the approval gate


@pytest.mark.parametrize(
    ("tier", "flag", "needed"),
    [
        ("standard", False, False),
        ("standard", True, True),  # the standard-tier opt-in stays
        ("regulated", False, True),
        ("dedicated", False, True),
        ("regulated", True, True),
    ],
)
def test_the_approval_gate_reads_the_tenants_real_tier(tier, flag, needed):
    from guardrail_engine.guard.tenants import TenantProfile
    from guardrail_engine.policy.catalog import TenantAttributes

    p = TenantProfile.build(
        TenantAttributes(tenant_id=TENANT, tier=tier), "insurance", slug="dogfood",
        require_two_person=flag,
    )  # fmt: skip
    assert approval_required(p) is needed
    assert p.attributes.regulated is (tier != "standard")


# ---------------------------------------------------------------- a raise on a live tenant


async def test_a_raise_takes_effect_at_the_next_publish_and_the_active_version_keeps_running():
    tenants = directory()
    engine = await build_engine(
        settings(catalog={"pack_files": [RAI_FILE]}),
        verifier=verifier(),
        tenants=tenants,
        model=FakeDecisionModel(),
        authz_audit=InMemoryAuthzAudit(),
    )
    try:
        await engine.bootstrap_publish(bundle())  # standard: no pack needed
        before = await engine.check(ctx(verifier()), "output", "hello there")
        assert before.decision is Decision.ALLOW

        tenants.put(profile(tier="regulated"))  # the operator raises the tier
        engine.guard.policy_cache.invalidate(TENANT)
        after = await engine.check(ctx(verifier()), "output", "hello there")
        # the version that is running is still served, compiled as it was published ...
        assert after.decision is Decision.ALLOW, after.reason
        # ... and a bundle for the next publish is held to the new tier
        regulated = profile(tier="regulated")
        assert ErrorCode.PACK_REQUIRED_MISSING in codes(
            errors(engine, regulated, bundle(version=2))
        )
        assert errors(engine, regulated, with_pack(version=2)) == []

        # a restart is the same: a cold engine on the same store compiles the stored active
        # version under the new tier, and doesn't refuse it
        restarted = await build_engine(
            settings(catalog={"pack_files": [RAI_FILE]}),
            verifier=verifier(),
            tenants=tenants,
            model=FakeDecisionModel(),
            store=engine.store,
            authz_audit=InMemoryAuthzAudit(),
        )
        try:
            again = await restarted.check(ctx(verifier()), "output", "hello there")
            assert again.decision is Decision.ALLOW, again.reason
        finally:
            await restarted.shutdown()
    finally:
        await engine.shutdown()


async def test_a_stored_version_compiles_without_the_tiers_requirements_and_a_new_one_does_not():
    engine = await build()
    try:
        regulated = profile(tier="regulated")
        replay = PolicyCompiler(
            engine.catalog, regulated, engine.settings.platform, enforce_tier_requirements=False
        )
        assert replay.validate(bundle(), regulated.attributes) == []
        strict = PolicyCompiler(engine.catalog, regulated, engine.settings.platform)
        assert ErrorCode.PACK_REQUIRED_MISSING in codes(
            strict.validate(bundle(), regulated.attributes)
        )
        # replay relaxes the tier's requirements only: an opt-out still needs its justification
        bad = with_pack(overrides=[{"rule": "d__harassment", "enabled": False}])
        assert ErrorCode.PACK_JUSTIFICATION_REQUIRED in codes(
            replay.validate(bad, regulated.attributes)
        )
    finally:
        await engine.shutdown()
