"""AC-C9 (per-key metadata), AC-C9.1 (precedence, B1 and S5) and AC-C9.2 (disabled guard
points and shadow rules)."""

import pytest
from policy_fixtures import TOOLS

from guardrail_engine.policy import (
    CompiledRule,
    InMemoryToolRegistry,
    PlatformSettings,
    PolicyCompiler,
)

# ---------------------------------------------------------------------------- AC-C9


def test_ac_c9_every_key_has_full_metadata(compiler, tenant, bundle):
    policy = compiler.compile(bundle, tenant)
    for gp in policy.guard_points.values():
        for key, meta in gp.rules.items():
            assert isinstance(meta, CompiledRule)
            assert meta.key == key
            assert meta.layer in {"floor", "pack", "tenant"}
            assert meta.mode in {"enforce", "shadow"}
            assert meta.severity in {"low", "medium", "high"}
            assert meta.fail_mode in {"closed", "open"}
            if meta.question_type == "noul":
                assert 0.01 <= meta.escalate_at < meta.block_at <= 0.99
            else:  # routers and scorers have no thresholds
                assert meta.block_at is None and meta.escalate_at is None


def test_ac_c9_metadata_values_for_each_layer(compiler, tenant, bundle):
    rules = compiler.compile(bundle, tenant).guard_points["output"].rules
    assert rules["p__inj_direct"].model_dump() == {
        "key": "p__inj_direct",
        "layer": "floor",
        "source": "platform/floor@2",
        "question_type": "noul",
        "block_at": 0.70,  # catalog 0.85, lowered by the override
        "escalate_at": 0.55,
        "mode": "enforce",
        "severity": "high",
        "fail_mode": "closed",
        "provisional": True,  # the catalog's value; the override doesn't calibrate the rule
    }
    assert rules["d__ins_claim_promise"].layer == "pack"
    assert rules["d__ins_claim_promise"].source == "domain/insurance@3"
    assert rules["t__fin_adv_01"].layer == "tenant"
    assert rules["t__fin_adv_01"].source == "tenant"
    assert rules["t__fin_adv_01"].severity == "high"


# ---------------------------------------------------------------------------- AC-C9.1


class TestAC_C9_1_Thresholds:
    def rule_meta(self, compiler, tenant, bundle, key, gp="output"):
        return compiler.compile(bundle, tenant).guard_points[gp].rules[key]

    def test_ac_c9_1_rule_value_wins(self, compiler, tenant, bundle):
        meta = self.rule_meta(compiler, tenant, bundle, "t__fin_adv_01")
        assert (meta.block_at, meta.escalate_at) == (0.80, 0.50)

    def test_ac_c9_1_bundle_defaults_when_rule_has_none(self, compiler, tenant, bundle):
        rule = bundle["rules"][0]
        del rule["block_at"], rule["escalate_at"]
        bundle["defaults"].update(block_at=0.9, escalate_at=0.6)
        meta = self.rule_meta(compiler, tenant, bundle, "t__fin_adv_01")
        assert (meta.block_at, meta.escalate_at) == (0.9, 0.6)

    def test_ac_c9_1_platform_default_when_bundle_sets_none(self, compiler, tenant, bundle):
        rule = bundle["rules"][0]
        del rule["block_at"], rule["escalate_at"]
        bundle["defaults"] = {}
        meta = self.rule_meta(compiler, tenant, bundle, "t__fin_adv_01")
        assert (meta.block_at, meta.escalate_at) == (0.85, 0.55)

    # A floor/pack rule without catalog thresholds can no longer be built, and tenant
    # defaults never reach floor or pack rules: see test_catalog_integrity.py
    # (test_ac_c9_1_noul_catalog_rule_without_both_thresholds_is_a_catalog_error and
    # test_ac_c9_1_tenant_defaults_of_099_098_leave_floor_and_pack_rules_unchanged).

    def test_ac_c9_1_override_applied_last_and_only_lowers(self, compiler, tenant, bundle):
        bundle["overrides"] = [
            {"rule": "p__inj_direct", "block_at": 0.70},
            {"rule": "d__ins_claim_promise", "escalate_at": 0.40},
        ]
        rules = compiler.compile(bundle, tenant).guard_points["output"].rules
        assert (rules["p__inj_direct"].block_at, rules["p__inj_direct"].escalate_at) == (0.70, 0.55)
        assert (
            rules["d__ins_claim_promise"].block_at,
            rules["d__ins_claim_promise"].escalate_at,
        ) == (
            0.80,
            0.40,
        )


class TestAC_C9_1_FailMode:
    def fail_modes(self, compiler, tenant, bundle, gp="output"):
        rules = compiler.compile(bundle, tenant).guard_points[gp].rules
        return {m.layer: m.fail_mode for m in rules.values()}

    def test_ac_c9_1_floor_keys_take_floor_fail_mode_even_when_tenant_is_open(
        self, compiler, tenant, bundle
    ):
        # B1: the tenant's fail_mode never applies to floor rules.
        bundle["defaults"]["fail_mode"] = "open"
        bundle["guard_points"]["output"]["fail_mode"] = "open"
        assert self.fail_modes(compiler, tenant, bundle) == {
            "floor": "closed",
            "pack": "open",
            "tenant": "open",
        }

    def test_ac_c9_1_floor_fail_mode_is_a_platform_setting(self, tenant, bundle):
        # Flipping the setting changes the output with no code change (B1 stays config).
        from policy_fixtures import make_catalog

        settings = PlatformSettings(min_floor_version=2, floor_fail_mode="open")
        compiler = PolicyCompiler(make_catalog(), InMemoryToolRegistry(TOOLS), settings)
        assert self.fail_modes(compiler, tenant, bundle)["floor"] == "open"

    def test_ac_c9_1_guard_point_fail_mode_beats_bundle_default(self, compiler, tenant, bundle):
        bundle["defaults"]["fail_mode"] = "closed"
        bundle["guard_points"]["output"]["fail_mode"] = "open"
        assert self.fail_modes(compiler, tenant, bundle)["tenant"] == "open"

    def test_ac_c9_1_bundle_default_when_guard_point_sets_none(self, compiler, tenant, bundle):
        bundle["defaults"]["fail_mode"] = "open"
        assert self.fail_modes(compiler, tenant, bundle)["pack"] == "open"

    def test_ac_c9_1_closed_when_nothing_is_set(self, compiler, tenant, bundle):
        # S5: pack and tenant rules default to closed.
        del bundle["defaults"]["fail_mode"]
        assert self.fail_modes(compiler, tenant, bundle) == {
            "floor": "closed",
            "pack": "closed",
            "tenant": "closed",
        }


# ---------------------------------------------------------------------------- AC-C9.2


@pytest.mark.parametrize("gp", ["plan", "tool_call"])
def test_ac_c9_2_disabled_guard_point_compiles_to_no_questions(compiler, tenant, bundle, gp):
    bundle["guard_points"][gp]["enabled"] = False
    bundle["rules"][0]["guard_points"] = ["output", gp]
    compiled = compiler.compile(bundle, tenant).guard_points[gp]
    assert compiled.enabled is False
    assert compiled.questions == {}
    assert compiled.rules == {}


def test_ac_c9_2_shadow_rule_is_compiled_not_dropped(compiler, tenant, bundle):
    bundle["rules"][0]["mode"] = "shadow"
    out = compiler.compile(bundle, tenant).guard_points["output"]
    assert "t__fin_adv_01" in out.questions
    assert out.rules["t__fin_adv_01"].mode == "shadow"
