"""M4-10 ``max_action`` (R4.3): a rule that may escalate and never block. The catalog field, the
compiler's validation, the compiled rule, the fusion cap (table-driven), audit replay, and that a
tenant can't change it."""

import json
from pathlib import Path

import pytest

from guardrail_engine.floor_file import load_floor_file
from guardrail_engine.guard.fusion import action_ceiling, capped, fuse, resolve_rule
from guardrail_engine.guard.verdict import Action, Basis, Decision
from guardrail_engine.pack_file import load_pack_file
from guardrail_engine.policy import (
    ErrorCode,
    InMemoryCatalog,
    InMemoryToolRegistry,
    PackVersion,
    PlatformSettings,
    PolicyCompiler,
    TenantAttributes,
)
from guardrail_engine.policy.compiler import CompiledRule

ROOT = Path(__file__).resolve().parents[2]
FLOOR = load_floor_file(ROOT / "floor" / "rules.json")
RAI = load_pack_file(ROOT / "packs" / "responsible_ai" / "pack.json")
TENANT = TenantAttributes(tenant_id="t_dogfood")


def compiled_rule(max_action=None, block_at=0.9, escalate_at=0.5, fail_mode="closed"):
    return CompiledRule(
        key="d__self_harm_risk", layer="pack", source="domain/responsible_ai@1",
        question_type="noul", block_at=block_at, escalate_at=escalate_at, mode="enforce",
        severity="high", fail_mode=fail_mode, provisional=True, max_action=max_action,
    )  # fmt: skip


# ------------------------------------------------------------------ the fusion cap, table-driven


@pytest.mark.parametrize(
    ("p", "uncapped", "capped_"),
    [
        (0.00, Action.ALLOW, Action.ALLOW),
        (0.49, Action.ALLOW, Action.ALLOW),
        (0.50, Action.ESCALATE, Action.ESCALATE),
        (0.89, Action.ESCALATE, Action.ESCALATE),
        (0.90, Action.BLOCK, Action.ESCALATE),  # at block_at: capped to escalate
        (0.99, Action.BLOCK, Action.ESCALATE),  # the story's case: p 0.99 gives escalate
        (1.00, Action.BLOCK, Action.ESCALATE),
    ],
)
def test_a_probability_is_capped_at_escalate_for_an_escalate_only_rule(p, uncapped, capped_):
    plain = resolve_rule(compiled_rule(), basis=Basis.ANSWER, p=p)
    escalate_only = resolve_rule(compiled_rule("escalate"), basis=Basis.ANSWER, p=p)
    assert plain.action is uncapped  # no cap: as it always was
    assert escalate_only.action is capped_
    assert escalate_only.max_action == "escalate" and plain.max_action is None


def test_the_fused_decision_of_an_escalate_only_rule_is_escalate_never_block():
    ev = resolve_rule(compiled_rule("escalate"), basis=Basis.ANSWER, p=0.99)
    fused = fuse((ev,))
    assert fused.action is Action.ESCALATE and fused.fired[0].action is Action.ESCALATE
    assert Decision(fused.action.value) is Decision.ESCALATE


@pytest.mark.parametrize(
    ("fail_mode", "expected"), [("closed", Action.ESCALATE), ("open", Action.ALLOW)]
)
def test_a_failed_call_on_an_escalate_only_rule_escalates_rather_than_blocks(fail_mode, expected):
    """B1: a closed rule blocks when the call fails. For a rule that may only escalate, the cap
    applies to the fail-mode action as well: a person looks, nobody is refused."""
    rule = compiled_rule("escalate", fail_mode=fail_mode)
    ev = resolve_rule(rule, basis=Basis.FAIL_MODE)
    assert ev.action is expected


def test_the_ceiling_is_block_unless_the_rule_says_escalate():
    assert action_ceiling(compiled_rule()) is Action.BLOCK
    assert action_ceiling(compiled_rule("escalate")) is Action.ESCALATE
    assert action_ceiling(compiled_rule("block")) is Action.BLOCK
    for action in Action:
        assert capped(action, compiled_rule()) is action
    assert capped(Action.BLOCK, compiled_rule("escalate")) is Action.ESCALATE
    assert capped(Action.ESCALATE, compiled_rule("escalate")) is Action.ESCALATE
    assert capped(Action.ALLOW, compiled_rule("escalate")) is Action.ALLOW


def test_a_recorded_evaluation_replays_with_the_same_cap():
    """Audit replay (M1-06) re-resolves a recorded ``RuleEvaluation``: it carries the cap."""
    recorded = resolve_rule(compiled_rule("escalate"), basis=Basis.ANSWER, p=0.5)
    replayed = resolve_rule(
        recorded.model_copy(update={"block_at": 0.4}), basis=Basis.ANSWER, p=0.6
    )
    assert replayed.action is Action.ESCALATE  # above the new block_at, still capped
    older = recorded.model_dump(exclude={"max_action"})  # a record written before the field
    from guardrail_engine.guard.verdict import RuleEvaluation

    assert RuleEvaluation(**older).max_action is None


# ------------------------------------------------------------------ the catalog and the compiler


def pack_document(**rule_changes):
    document = json.loads((ROOT / "packs" / "responsible_ai" / "pack.json").read_text())
    document["rules"][0].update(rule_changes)
    return document


def test_the_catalog_refuses_a_max_action_it_does_not_know():
    for bad in ("sometimes", "BLOCK", "", None, 1):
        with pytest.raises((ValueError, TypeError)):
            PackVersion.from_document(pack_document(max_action=bad))
    assert (
        PackVersion.from_document(pack_document(max_action="block")).rules[0].max_action == "block"
    )


def test_a_router_has_no_max_action_because_only_a_noul_rule_acts():
    document = pack_document()
    document["rules"][0] = {
        "key": "d__router", "guard_points": ["input"], "max_action": "escalate",
        "question": {"type": "choice", "instructions": "Which?", "criteria": {"a": "A", "b": "B"}},
    }  # fmt: skip
    with pytest.raises(ValueError, match="max_action"):
        PackVersion.from_document(document)


def compiler(*packs):
    return PolicyCompiler(
        InMemoryCatalog(floors=[FLOOR], packs=list(packs)),
        InMemoryToolRegistry(),
        PlatformSettings(min_floor_version=FLOOR.version),
    )


def bundle(overrides=()):
    return {
        "schema_version": 1, "tenant_id": "t_dogfood", "version": 1,
        "extends": [f"platform/floor@{FLOOR.version}", RAI.ref], "overrides": list(overrides),
    }  # fmt: skip


def test_the_compiled_policy_carries_the_cap_and_only_where_there_is_one():
    compiled = compiler(RAI).compile(bundle(), TENANT)
    rules = {k: r for gp in compiled.guard_points.values() for k, r in gp.rules.items()}
    assert rules["d__self_harm_risk"].max_action == "escalate"
    assert rules["d__vulnerability"].max_action == "escalate"
    assert rules["d__harassment"].max_action is None  # no cap: the default, block
    canonical = compiled.to_canonical_json().decode()
    assert canonical.count('"max_action"') == 2  # once per capped rule at its guard point
    assert "p__inj_direct" in canonical and '"max_action":null' not in canonical


def test_a_pack_without_a_cap_compiles_to_the_bytes_it_did_before_the_field_existed():
    plain = PackVersion.from_document(
        {
            "schema_version": 1,
            "name": "plain",
            "version": 1,
            "rules": [
                {
                    "key": "d__x",
                    "guard_points": ["output"],
                    "question": {"type": "noul", "instructions": "Is it x?"},
                    "block_at": 0.8,
                    "escalate_at": 0.5,
                }
            ],
        }
    )
    b = bundle() | {"extends": [f"platform/floor@{FLOOR.version}", plain.ref]}
    assert b"max_action" not in compiler(plain).compile(b, TENANT).to_canonical_json()


@pytest.mark.parametrize("value", ["block", "escalate"])
def test_a_tenant_cannot_change_a_rules_max_action(value):
    """Naming the catalog's own value is harmless; naming any other is refused, in either
    direction: raising a capped rule to block, or capping a rule that blocks."""
    for key, catalog_value in (("d__self_harm_risk", "escalate"), ("d__harassment", "block")):
        errors = compiler(RAI).validate(bundle([{"rule": key, "max_action": value}]), TENANT)
        if value == catalog_value:
            assert errors == []
        else:
            assert [(e.code, e.path) for e in errors] == [
                (ErrorCode.OVERRIDE_MAX_ACTION_EDITED, "$.overrides[0].max_action")
            ]


def test_a_tenant_cannot_give_a_floor_rule_a_cap():
    errors = compiler(RAI).validate(
        bundle([{"rule": "p__inj_direct", "max_action": "escalate"}]), TENANT
    )
    assert [e.code for e in errors] == [ErrorCode.OVERRIDE_MAX_ACTION_EDITED]


def test_lowering_block_at_on_a_capped_rule_still_cannot_make_it_block():
    compiled = compiler(RAI).compile(
        bundle([{"rule": "d__self_harm_risk", "block_at": 0.6, "escalate_at": 0.3}]), TENANT
    )
    rule = compiled.guard_points["input"].rules["d__self_harm_risk"]
    assert rule.block_at == 0.6 and rule.max_action == "escalate"
    ev = resolve_rule(rule, basis=Basis.ANSWER, p=0.95)
    assert ev.action is Action.ESCALATE


def test_the_two_m4_08_escalate_only_rules_have_the_cap():
    for name, key in (("insurance", "d__ins_fraud_signal"), ("energy", "d__en_safety_report")):
        pack = load_pack_file(ROOT / "packs" / name / "pack.json")
        rule = next(r for r in pack._content.rules if r.key == key)
        assert rule.max_action == "escalate" and rule.mode == "enforce", key


# ------------------------------------------------------------------ copies of a capped rule


def self_harm_question():
    rule = next(r for r in RAI._content.rules if r.key == "d__self_harm_risk")
    return rule.question.instructions


def tenant_rule(**changes):
    rule = {
        "id": "mine", "guard_points": ["input"], "question": self_harm_question(),
        "true_description": "yes", "false_description": "no", "block_at": 0.8,
        "escalate_at": 0.4, "origin": "custom",
    }  # fmt: skip
    return {**rule, **changes}


def compiled_tenant_rule(**changes):
    b = bundle() | {"rules": [tenant_rule(**changes)]}
    compiled = compiler(RAI).compile(b, TENANT)
    return compiled.guard_points["input"].rules["t__mine"]


def test_a_fork_of_a_capped_rule_inherits_the_cap_and_so_can_never_block():
    rule = compiled_tenant_rule(origin="fork:d__self_harm_risk", question="Is the user at risk?")
    assert rule.max_action == "escalate"
    assert resolve_rule(rule, basis=Basis.ANSWER, p=0.99).action is Action.ESCALATE


def test_the_very_same_question_under_another_origin_inherits_it_too_ignoring_case_and_spacing():
    q = "  " + self_harm_question().upper().replace(" ", "  ")
    for origin in ("custom", "fork:d__harassment"):
        assert compiled_tenant_rule(origin=origin, question=q).max_action == "escalate"


def test_a_fork_of_an_uncapped_rule_and_an_unrelated_rule_have_no_cap():
    assert (
        compiled_tenant_rule(origin="fork:d__harassment", question="Is it rude?").max_action is None
    )
    assert compiled_tenant_rule(question="Is this a refund request?").max_action is None
    canonical = (
        compiler(RAI)
        .compile(bundle() | {"rules": [tenant_rule(question="Is this a refund request?")]}, TENANT)
        .to_canonical_json()
    )
    assert canonical.count(b'"max_action"') == 2  # only the pack's own two, not the tenant rule
