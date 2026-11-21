"""Catalog integrity: AC-C9.1, AC-C1.11, AC-C2.2 and catalog rule validation."""

import subprocess
import sys
from pathlib import Path

import pytest
from policy_fixtures import (
    FIN_ADVICE_TEMPLATE,
    FINANCE_V2,
    FLOOR_V2,
    INSURANCE_V3,
    TOOLS,
    floor_document,
    floor_rule,
    make_catalog,
    make_floor,
    make_pack,
    pack_rule,
    with_rule_changed,
)
from pydantic import ValidationError

from guardrail_engine.decision import ChoiceQuestion, NoulQuestion, ScoreQuestion
from guardrail_engine.policy import (
    CatalogRule,
    ErrorCode,
    FloorVersion,
    InMemoryCatalog,
    InMemoryToolRegistry,
    PlatformSettings,
    PolicyCompiler,
)


def noul_rule(key: str = "p__x", gps=("output",), **kw) -> CatalogRule:
    thresholds = {"block_at": 0.8, "escalate_at": 0.5}
    thresholds.update(kw)
    return CatalogRule(
        key=key,
        guard_points=frozenset(gps),
        question=NoulQuestion(instructions="Is it?"),
        **thresholds,
    )


def compiler_for(*, floors=(FLOOR_V2,), packs=(INSURANCE_V3, FINANCE_V2)) -> PolicyCompiler:
    catalog = InMemoryCatalog(floors=floors, packs=packs, templates=[FIN_ADVICE_TEMPLATE])
    return PolicyCompiler(
        catalog, InMemoryToolRegistry(TOOLS), PlatformSettings(min_floor_version=2)
    )


# ----------------------------------------------------------------------------
class TestTenantDefaultsNeverReachFloorOrPack:
    @pytest.mark.parametrize(
        "thresholds", [{}, {"block_at": 0.8}, {"escalate_at": 0.5}], ids=["none", "block", "esc"]
    )
    def test_ac_c9_1_noul_catalog_rule_without_both_thresholds_is_a_catalog_error(self, thresholds):
        with pytest.raises(ValidationError, match="block_at and escalate_at"):
            CatalogRule(
                key="p__x",
                guard_points=frozenset({"output"}),
                question=NoulQuestion(instructions="Is it?"),
                **thresholds,
            )

    @pytest.mark.parametrize(
        "question",
        [
            ChoiceQuestion(instructions="Route?", criteria={"a": "", "b": ""}),
            ScoreQuestion(instructions="Grade?", criteria=["lo", "hi"]),
        ],
    )
    def test_ac_c9_1_routers_and_scorers_carry_no_thresholds(self, question):
        with pytest.raises(ValidationError, match="no thresholds"):
            CatalogRule(
                key="d__r",
                guard_points=frozenset({"input"}),
                question=question,
                block_at=0.8,
                escalate_at=0.5,
            )

    def test_ac_c9_1_tenant_defaults_of_099_098_leave_floor_and_pack_rules_unchanged(
        self, compiler, tenant, bundle
    ):
        bundle["defaults"].update(block_at=0.99, escalate_at=0.98)
        bundle["overrides"] = []
        rule = bundle["rules"][0]
        del rule["block_at"], rule["escalate_at"]
        catalog = {r.key: r for v in (FLOOR_V2, INSURANCE_V3, FINANCE_V2) for r in v.rules}

        policy = compiler.compile(bundle, tenant)
        seen = 0
        for gp in policy.guard_points.values():
            for key, meta in gp.rules.items():
                if meta.layer == "tenant":
                    assert (meta.block_at, meta.escalate_at) == (0.99, 0.98)
                else:
                    assert (meta.block_at, meta.escalate_at) == (
                        catalog[key].block_at,
                        catalog[key].escalate_at,
                    ), key
                    seen += 1
        assert seen > 0


# ----------------------------------------------------------------------------
class TestCoverageIsDerived:
    def test_ac_c1_11_floor_coverage_is_the_union_of_its_rules_guard_points(self):
        floor = make_floor(
            2, floor_rule("p__inj_direct", ("output", "input")), floor_rule("p__other", ("plan",))
        )
        assert floor.covers == frozenset({"output", "input", "plan"})

    def test_ac_c1_11_coverage_cannot_be_declared_separately(self):
        with pytest.raises(ValidationError):
            FloorVersion.from_document(floor_document(2, [floor_rule("p__x")], covers=["output"]))

    def test_ac_c1_11_pack_coverage_is_derived_too(self):
        assert INSURANCE_V3.covers == frozenset({"input", "output"})

    @pytest.mark.parametrize("gp", ["input", "plan"])
    def test_ac_c1_11_disabling_any_guard_point_a_floor_rule_runs_on(self, tenant, bundle, gp):
        # Reviewer's probe: under a declared covers={"output"} this compiled the rule away.
        floor = make_floor(
            2,
            floor_rule("p__inj_direct", ("output", "input")),
            floor_rule("p__planner", ("plan",)),
        )
        bundle["guard_points"][gp]["enabled"] = False
        errors = compiler_for(floors=(floor,)).validate(bundle, tenant)
        assert [(e.code, e.path) for e in errors] == [
            (ErrorCode.GP_FLOOR_COVERED_DISABLED, f"$.guard_points.{gp}.enabled")
        ]


# ----------------------------------------------------------------------------
class TestHashCoversExtendedCatalogContent:
    def test_ac_c2_2_changed_floor_content_under_same_version_changes_the_hash(
        self, tenant, bundle
    ):
        changed = with_rule_changed(FLOOR_V2, "p__secrets", block_at=0.79)
        a = compiler_for().compile(bundle, tenant).bundle_hash
        b = compiler_for(floors=(changed,)).compile(bundle, tenant).bundle_hash
        assert a != b

    def test_ac_c2_2_changed_pack_content_under_same_version_changes_the_hash(self, tenant, bundle):
        changed = with_rule_changed(INSURANCE_V3, "d__ins_claim_promise", escalate_at=0.45)
        a = compiler_for().compile(bundle, tenant).bundle_hash
        b = compiler_for(packs=(changed, FINANCE_V2)).compile(bundle, tenant).bundle_hash
        assert a != b

    def test_ac_c2_2_unextended_catalog_content_does_not_change_the_hash(self, tenant, bundle):
        from policy_fixtures import HEALTHCARE_V1

        changed = with_rule_changed(HEALTHCARE_V1, "d__hc_diagnosis", block_at=0.7)
        a = compiler_for(packs=(INSURANCE_V3, FINANCE_V2, HEALTHCARE_V1))
        b = compiler_for(packs=(INSURANCE_V3, FINANCE_V2, changed))
        assert a.compile(bundle, tenant).bundle_hash == b.compile(bundle, tenant).bundle_hash

    def test_ac_c2_2_catalog_refuses_a_conflicting_floor_version(self):
        changed = with_rule_changed(FLOOR_V2, "p__secrets", block_at=0.99, escalate_at=0.5)
        with pytest.raises(ValueError, match=r"floor@2 .* different content"):
            InMemoryCatalog(floors=[FLOOR_V2, changed])

    def test_ac_c2_2_catalog_refuses_a_conflicting_pack_version(self):
        changed = with_rule_changed(INSURANCE_V3, "d__ins_claim_promise", block_at=0.9)
        with pytest.raises(ValueError, match=r"insurance@3 .* different content"):
            InMemoryCatalog(packs=[INSURANCE_V3, changed])

    def test_ac_c2_2_identical_re_registration_is_accepted(self):
        catalog = InMemoryCatalog(floors=[FLOOR_V2, FLOOR_V2], packs=[INSURANCE_V3, INSURANCE_V3])
        assert catalog.floor(2) == FLOOR_V2

    def test_ac_c2_2_content_hash_is_independent_of_set_iteration_order(self):
        # guard_points are frozensets; their iteration order changes with PYTHONHASHSEED.
        here = Path(__file__).parent
        code = (
            f"import sys; sys.path.insert(0, {str(here)!r}); "
            "from policy_fixtures import FLOOR_V2; print(FLOOR_V2.content_hash())"
        )
        hashes = {
            subprocess.run(
                [sys.executable, "-c", code],
                env={"PYTHONHASHSEED": seed},
                capture_output=True,
                text=True,
                check=True,
            ).stdout.strip()
            for seed in ("1", "2", "3", "4")
        }
        assert len(hashes) == 1
        assert hashes == {FLOOR_V2.content_hash()}


# ----------------------------------------------------------------------------
class TestCatalogRulesValidatedOnConstruction:
    @pytest.mark.parametrize(
        ("kwargs", "match"),
        [
            ({"key": "x__bad"}, "p__ or d__"),
            ({"key": "t__tenant_key"}, "p__ or d__"),
            ({"key": "p__has space"}, "key"),
            ({"key": "p__" + "x" * 62}, "key"),
            ({"gps": ()}, "at least one guard point"),
            ({"gps": ("outptu",)}, "unknown guard point"),
            ({"gps": ("output", "retrieval")}, "unknown guard point"),
            ({"severity": "critical"}, "severity"),
            ({"mode": "off"}, "mode"),
            ({"block_at": 0.5, "escalate_at": 0.6}, "escalate_at < block_at"),
            ({"block_at": 0.5, "escalate_at": 0.5}, "escalate_at < block_at"),
            ({"block_at": 1.0}, "escalate_at < block_at"),
            ({"escalate_at": 0.0}, "escalate_at < block_at"),
        ],
    )
    def test_invalid_catalog_rule_raises_on_construction(self, kwargs, match):
        kwargs = dict(kwargs)
        key = kwargs.pop("key", "p__x")
        gps = kwargs.pop("gps", ("output",))
        severity = kwargs.pop("severity", "high")
        mode = kwargs.pop("mode", "enforce")
        with pytest.raises(ValidationError, match=match):
            CatalogRule(
                key=key,
                guard_points=frozenset(gps),
                question=NoulQuestion(instructions="Is it?"),
                severity=severity,
                mode=mode,
                **{"block_at": 0.8, "escalate_at": 0.5, **kwargs},
            )

    def test_floor_version_rejects_a_pack_key(self):
        with pytest.raises(ValidationError, match="p__"):
            make_floor(2, floor_rule("d__pack_rule"))

    def test_pack_version_rejects_a_floor_key(self):
        with pytest.raises(ValidationError, match="d__"):
            make_pack("p", 1, pack_rule("p__floor_rule"))

    def test_version_rejects_duplicate_keys(self):
        with pytest.raises(ValidationError, match="more than once"):
            make_floor(2, floor_rule("p__a"), floor_rule("p__a"))

    def test_valid_fixture_catalog_still_builds(self):
        assert make_catalog().floor(2) is not None
