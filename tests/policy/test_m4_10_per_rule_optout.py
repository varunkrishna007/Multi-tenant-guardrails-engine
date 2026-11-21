"""M4-10 per-rule opt-out (R4.6): a deliberate exception to the merged compiler, only for a pack
whose catalog entry declares ``per_rule_optional``. In v1 that is ``domain/responsible_ai``
alone. A tenant switches one rule off with a written justification; a rule the tier requires
can't be switched off; an opted-out rule can't be shadowed instead."""

from pathlib import Path

import pytest

from guardrail_engine.floor_file import load_floor_file
from guardrail_engine.pack_file import load_pack_file
from guardrail_engine.policy import (
    ErrorCode,
    InMemoryCatalog,
    InMemoryToolRegistry,
    PlatformSettings,
    PolicyCompiler,
    TenantAttributes,
)
from guardrail_engine.policy.compiler import MAX_JUSTIFICATION_CHARS

ROOT = Path(__file__).resolve().parents[2]
FLOOR = load_floor_file(ROOT / "floor" / "rules.json")
RAI = load_pack_file(ROOT / "packs" / "responsible_ai" / "pack.json")
INSURANCE = load_pack_file(ROOT / "packs" / "insurance" / "pack.json")
STANDARD = TenantAttributes(tenant_id="t_dogfood")
REGULATED = TenantAttributes(tenant_id="t_dogfood", tier="regulated")
JUSTIFICATION = "Age is a lawful rating factor for this product in the markets we sell to."
KEY = "d__bias_protected_basis"


def compiler(required_rules=None, required_packs=None):
    return PolicyCompiler(
        InMemoryCatalog(
            floors=[FLOOR],
            packs=[RAI, INSURANCE],
            tier_required_packs=required_packs,
            tier_required_rules=required_rules,
        ),
        InMemoryToolRegistry(),
        PlatformSettings(min_floor_version=FLOOR.version),
    )


def bundle(overrides, extends=None):
    return {
        "schema_version": 1, "tenant_id": "t_dogfood", "version": 1,
        "extends": extends or [f"platform/floor@{FLOOR.version}", RAI.ref],
        "overrides": list(overrides),
    }  # fmt: skip


def opt_out(key=KEY, **more):
    return {"rule": key, "enabled": False, "justification": JUSTIFICATION, **more}


def codes(errors):
    return [(e.code, e.path) for e in errors]


def test_only_the_responsible_ai_pack_declares_per_rule_optional():
    assert RAI.per_rule_optional is True
    assert INSURANCE.per_rule_optional is False
    assert load_pack_file(ROOT / "packs" / "energy" / "pack.json").per_rule_optional is False


def test_a_rule_opted_out_with_a_justification_is_not_compiled_and_the_rest_are():
    compiled = compiler().compile(bundle([opt_out()]), STANDARD)
    all_keys = {k for gp in compiled.guard_points.values() for k in gp.rules}
    assert KEY not in all_keys
    assert {"d__bias_stereotype", "d__harassment", "d__self_harm_risk"} <= all_keys
    full = compiler().compile(bundle([]), STANDARD)
    assert KEY in {k for gp in full.guard_points.values() for k in gp.rules}
    # the questions go too: nothing about the opted-out rule is sent to the model
    for gp in compiled.guard_points.values():
        assert KEY not in gp.questions


@pytest.mark.parametrize(
    "justification", [None, "", "   ", "\n\t", "x" * (MAX_JUSTIFICATION_CHARS + 1)]
)
def test_an_opt_out_needs_a_written_justification(justification):
    override = {"rule": KEY, "enabled": False, "justification": justification}
    assert codes(compiler().validate(bundle([override]), STANDARD)) == [
        (ErrorCode.PACK_JUSTIFICATION_REQUIRED, "$.overrides[0].justification")
    ]


def test_a_justification_at_the_limit_is_accepted():
    ok = opt_out(justification="x" * MAX_JUSTIFICATION_CHARS)
    assert compiler().validate(bundle([ok]), STANDARD) == []


def test_a_rule_the_tier_requires_cannot_be_opted_out_of():
    c = compiler(required_rules={"regulated": {"d__self_harm_risk", "d__vulnerability"}})
    refused = c.validate(bundle([opt_out("d__self_harm_risk")]), REGULATED)
    assert codes(refused) == [(ErrorCode.PACK_RULE_REQUIRED, "$.overrides[0].enabled")]
    # a rule the tier does not require is still optional for that tier
    assert c.validate(bundle([opt_out()]), REGULATED) == []
    # and the required rule is optional for a tier that does not require it
    assert c.validate(bundle([opt_out("d__self_harm_risk")]), STANDARD) == []


def test_an_opted_out_rule_cannot_be_shadowed_instead():
    for override in (
        opt_out(mode="shadow"),  # off and shadow at once
        {"rule": KEY, "mode": "shadow"},  # shadow alone
    ):
        errors = compiler().validate(bundle([override]), STANDARD)
        assert {e.code for e in errors} == {ErrorCode.PACK_OVERRIDE_NOT_ALLOWED}, override
        assert all(e.path == "$.overrides[0].mode" for e in errors)


def test_for_every_other_pack_a_rule_still_cannot_be_disabled():
    errors = compiler().validate(
        bundle(
            [opt_out("d__ins_payout_promise")],
            extends=[f"platform/floor@{FLOOR.version}", INSURANCE.ref],
        ),
        STANDARD,
    )
    assert codes(errors) == [(ErrorCode.PACK_OVERRIDE_NOT_ALLOWED, "$.overrides[0].enabled")]


def test_a_floor_rule_still_cannot_be_disabled_even_with_a_justification():
    errors = compiler().validate(bundle([opt_out("p__inj_direct")]), STANDARD)
    assert [e.code for e in errors] == [ErrorCode.FLOOR_RULE_DISABLED]


def test_opting_out_of_the_whole_pack_is_leaving_it_out_and_a_required_pack_cannot_be_left_out():
    leave_out = bundle([], extends=[f"platform/floor@{FLOOR.version}"])
    assert compiler().validate(leave_out, STANDARD) == []  # standard tier: allowed
    regulated = compiler(required_packs={"regulated": {"responsible_ai"}})
    assert [e.code for e in regulated.validate(leave_out, REGULATED)] == [
        ErrorCode.PACK_REQUIRED_MISSING
    ]  # regulated: required (M5-01 sets the tier attribute)


def test_an_opted_out_rule_can_also_have_a_lowered_threshold_without_error():
    both = opt_out(block_at=0.8, escalate_at=0.5)
    assert compiler().validate(bundle([both]), STANDARD) == []
