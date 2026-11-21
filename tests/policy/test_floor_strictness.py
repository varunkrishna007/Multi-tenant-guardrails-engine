"""Outside the loader: no catalog source can
build a floor rule that is not ``enforce`` and ``high``. Compiled rules carry the
catalog's ``provisional`` marker."""

import json

import pytest
from policy_fixtures import (
    FINANCE_V2,
    FLOOR_V2,
    INSURANCE_V3,
    TOOLS,
    floor_rule,
    make_floor,
    make_pack,
    pack_rule,
)
from pydantic import ValidationError

from guardrail_engine.decision import NoulQuestion
from guardrail_engine.policy import (
    CatalogRule,
    InMemoryCatalog,
    InMemoryToolRegistry,
    PlatformSettings,
    PolicyCompiler,
)


def rule(key: str, **kw) -> CatalogRule:
    return CatalogRule(
        key=key,
        guard_points=frozenset({"output"}),
        question=NoulQuestion(instructions="Is it?"),
        block_at=0.8,
        escalate_at=0.5,
        **kw,
    )


# ---------------------------------------------------------------------------- severity


def test_floor_version_with_a_shadow_rule_cannot_be_built():
    with pytest.raises(ValidationError, match=r"p__b.*mode 'enforce'"):
        make_floor(3, floor_rule("p__a"), floor_rule("p__b", mode="shadow"))


@pytest.mark.parametrize("severity", ["medium", "low"])
def test_ruling_floor_version_with_a_rule_below_high_severity_cannot_be_built(severity):
    with pytest.raises(ValidationError, match=r"p__b.*severity 'high'"):
        make_floor(3, floor_rule("p__a"), floor_rule("p__b", severity=severity))


@pytest.mark.parametrize("key", ["p__Inj-Direct", "p__Inj_Direct", "p__inj-direct", "p__"])
def test_floor_version_with_a_key_outside_the_floor_alphabet_cannot_be_built(key):
    assert rule(key).key == key  # a valid catalog key in general; only the floor refuses it
    with pytest.raises(ValidationError, match=r"must match p__\[a-z0-9_\]\+"):
        make_floor(3, floor_rule("p__a"), floor_rule(key))


def test_loader_and_floor_version_share_one_key_pattern():
    from guardrail_engine.policy import catalog, floor_loader

    assert floor_loader.FLOOR_KEY_PATTERN is catalog.FLOOR_KEY_PATTERN


def test_pack_keys_keep_the_wider_catalog_alphabet():
    pack = make_pack("trial", 1, pack_rule("d__Ins-Claim"))
    assert pack.rules[0].key == "d__Ins-Claim"


def test_floor_version_of_enforced_high_rules_is_built():
    floor = make_floor(3, floor_rule("p__a"), floor_rule("p__b"))
    assert {(r.mode, r.severity) for r in floor.rules} == {("enforce", "high")}


def test_pack_rules_may_still_be_shadow_and_any_severity():
    pack = make_pack(
        "trial",
        1,
        pack_rule("d__a", mode="shadow", severity="low"),
        pack_rule("d__b", severity="medium"),
    )
    assert [(r.mode, r.severity) for r in pack.rules] == [("shadow", "low"), ("enforce", "medium")]


# ----------------------------------------------------------------------------
def test_compiled_rule_carries_the_catalog_provisional_marker_per_layer(compiler, tenant, bundle):
    catalog = {r.key: r.provisional for r in FLOOR_V2.rules}
    assert catalog == {"p__inj_direct": True, "p__ai_addressed": True, "p__secrets": False}
    policy = compiler.compile(bundle, tenant)
    for gp in policy.guard_points.values():
        for key, meta in gp.rules.items():
            # Floor: the catalog value. Fixture packs are calibrated. Tenant: always False.
            assert meta.provisional is catalog.get(key, False), key
    assert policy.guard_points["output"].rules["t__fin_adv_01"].provisional is False
    assert policy.guard_points["output"].rules["d__ins_claim_promise"].provisional is False


def test_provisional_pack_rule_compiles_as_provisional(tenant, bundle):
    pack = make_pack("trial", 1, pack_rule("d__trial", provisional=True))
    compiler = PolicyCompiler(
        InMemoryCatalog(floors=[FLOOR_V2], packs=[INSURANCE_V3, FINANCE_V2, pack]),
        InMemoryToolRegistry(TOOLS),
        PlatformSettings(min_floor_version=2),
    )
    bundle["extends"].append("domain/trial@1")
    rules = compiler.compile(bundle, tenant).guard_points["output"].rules
    assert rules["d__trial"].provisional is True


def test_override_lowering_a_provisional_floor_rule_leaves_it_provisional(compiler, tenant, bundle):
    bundle["overrides"] = [{"rule": "p__inj_direct", "block_at": 0.70, "escalate_at": 0.40}]
    meta = compiler.compile(bundle, tenant).guard_points["output"].rules["p__inj_direct"]
    assert (meta.block_at, meta.provisional) == (0.70, True)


def test_provisional_is_in_the_compiled_canonical_json(compiler, tenant, bundle):
    compiled = json.loads(compiler.compile(bundle, tenant).to_canonical_json())
    rules = compiled["guard_points"]["output"]["rules"]
    assert rules["p__inj_direct"]["provisional"] is True
    assert rules["p__secrets"]["provisional"] is False
    assert rules["t__fin_adv_01"]["provisional"] is False
