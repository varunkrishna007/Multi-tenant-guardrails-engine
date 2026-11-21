"""AC-C1.1 to AC-C1.14: each rejection, one test per case, each with its own error code."""

import math
from fractions import Fraction

import pytest
from policy_fixtures import (
    FIN_ADVICE_TEMPLATE,
    FINANCE_V2,
    FLOOR_V1,
    FLOOR_V2,
    HEALTHCARE_V1,
    INSURANCE_V3,
    TOOLS,
    make_catalog,
    make_pack,
    pack_rule,
)
from pydantic import ValidationError

from guardrail_engine.decision import NoulCriteria, NoulQuestion
from guardrail_engine.policy import (
    API_TOKENS_PER_CALL,
    API_TOKENS_PER_QUESTION,
    API_TOKENS_TEXT_PERCENT,
    CRITICAL_PATH_QUESTION_BUDGET,
    GUARD_POINTS,
    INPUT_QUESTION_BUDGET,
    RENDER_OVERHEAD_TOKENS,
    ErrorCode,
    InMemoryCatalog,
    InMemoryToolRegistry,
    PackVersion,
    PlatformSettings,
    PolicyCompiler,
    QuestionBudgets,
    TenantAttributes,
    content_api_tokens,
    estimate_api_tokens,
    question_api_tokens,
)
from guardrail_engine.tokens import estimate_question_tokens

E = ErrorCode


def pairs(errors):
    return [(e.code, e.path) for e in errors]


def only(errors, code, path):
    assert pairs(errors) == [(code, path)], pairs(errors)


def tenant_rule(i: int | str = 1, **extra) -> dict:
    return {
        "id": f"r{i}" if isinstance(i, int) else i,
        "guard_points": ["output"],
        "question": f"Is it case {i}?",
        "true_description": "Yes.",
        "false_description": "No.",
        **extra,
    }


# ---------------------------------------------------------------------------- AC-C1.1


class TestAC_C1_1_RuleIds:
    @pytest.mark.parametrize("bad", ["Fin_Adv", "fin-adv", "has space", "", "a" * 41, "t__ü"])
    def test_ac_c1_1_rule_id_not_matching_pattern(self, compiler, tenant, bundle, bad):
        bundle["rules"][0]["id"] = bad
        only(compiler.validate(bundle, tenant), E.RULE_ID_INVALID, "$.rules[0].id")

    def test_ac_c1_1_rule_id_of_40_chars_accepted(self, compiler, tenant, bundle):
        bundle["rules"][0]["id"] = "a" * 40
        assert compiler.validate(bundle, tenant) == []

    def test_ac_c1_1_duplicate_rule_ids(self, compiler, tenant, bundle):
        bundle["rules"].append(dict(bundle["rules"][0]))
        only(compiler.validate(bundle, tenant), E.RULE_ID_DUPLICATE, "$.rules[1].id")


# ---------------------------------------------------------------------------- AC-C1.2


class TestAC_C1_2_Thresholds:
    @pytest.mark.parametrize(
        ("block", "escalate"),
        [(0.5, 0.5), (0.5, 0.6), (1.0, 0.5), (0.8, 0.0), (0.8, 0.005), (0.995, 0.5)],
    )
    def test_ac_c1_2_rule_thresholds_out_of_order_or_range(
        self, compiler, tenant, bundle, block, escalate
    ):
        bundle["rules"][0].update(block_at=block, escalate_at=escalate)
        only(compiler.validate(bundle, tenant), E.THRESHOLD_INVALID, "$.rules[0]")

    def test_ac_c1_2_rule_threshold_checked_against_defaults(self, compiler, tenant, bundle):
        # The rule sets only block_at; the default escalate_at (0.55) is above it.
        rule = bundle["rules"][0]
        del rule["escalate_at"]
        rule["block_at"] = 0.5
        only(compiler.validate(bundle, tenant), E.THRESHOLD_INVALID, "$.rules[0]")

    def test_ac_c1_2_defaults_out_of_order(self, compiler, tenant, bundle):
        bundle["defaults"].update(block_at=0.4, escalate_at=0.6)
        # Floor/pack rules have their own catalog thresholds; only the defaults are wrong.
        only(compiler.validate(bundle, tenant), E.THRESHOLD_INVALID, "$.defaults")

    def test_ac_c1_2_override_checked_after_it_is_applied(self, compiler, tenant, bundle):
        # Lowering block_at to 0.5 is allowed on its own, but the catalog escalate_at (0.55)
        # is then above it, which only shows once the override is applied.
        bundle["overrides"] = [{"rule": "p__inj_direct", "block_at": 0.50}]
        only(compiler.validate(bundle, tenant), E.THRESHOLD_INVALID, "$.overrides[0]")

    def test_ac_c1_2_override_lowering_both_is_valid(self, compiler, tenant, bundle):
        bundle["overrides"] = [{"rule": "p__inj_direct", "block_at": 0.5, "escalate_at": 0.3}]
        assert compiler.validate(bundle, tenant) == []


# ---------------------------------------------------------------------------- AC-C1.3


class TestAC_C1_3_FloorOverrides:
    @pytest.mark.parametrize(("field", "value"), [("block_at", 0.9), ("escalate_at", 0.6)])
    def test_ac_c1_3_floor_override_raises_threshold(self, compiler, tenant, bundle, field, value):
        bundle["overrides"] = [{"rule": "p__inj_direct", field: value}]
        only(compiler.validate(bundle, tenant), E.FLOOR_OVERRIDE_RAISES, f"$.overrides[0].{field}")

    @pytest.mark.parametrize("rule", ["p__does_not_exist", "d__hc_diagnosis", "t__fin_adv_01"])
    def test_ac_c1_3_override_names_unknown_rule(self, compiler, tenant, bundle, rule):
        # d__hc_diagnosis exists in the catalog, but the bundle doesn't extend healthcare.
        bundle["overrides"] = [{"rule": rule, "block_at": 0.5, "escalate_at": 0.3}]
        only(compiler.validate(bundle, tenant), E.OVERRIDE_UNKNOWN_RULE, "$.overrides[0].rule")


# ---------------------------------------------------------------------------- AC-C1.4


class TestAC_C1_4_FloorIntegrity:
    def test_ac_c1_4_disable_floor_rule(self, compiler, tenant, bundle):
        bundle["overrides"] = [{"rule": "p__secrets", "enabled": False}]
        only(compiler.validate(bundle, tenant), E.FLOOR_RULE_DISABLED, "$.overrides[0].enabled")

    def test_ac_c1_4_shadow_floor_rule(self, compiler, tenant, bundle):
        bundle["overrides"] = [{"rule": "p__secrets", "mode": "shadow"}]
        only(compiler.validate(bundle, tenant), E.FLOOR_RULE_SHADOWED, "$.overrides[0].mode")

    @pytest.mark.parametrize("field", ["question", "true_description", "false_description"])
    def test_ac_c1_4_edit_floor_question_text(self, compiler, tenant, bundle, field):
        bundle["overrides"] = [{"rule": "p__inj_direct", field: "Is it something else?"}]
        only(compiler.validate(bundle, tenant), E.FLOOR_TEXT_EDITED, f"$.overrides[0].{field}")

    def test_ac_c1_4_remove_floor_by_leaving_it_out_of_extends(self, compiler, tenant, bundle):
        bundle["extends"] = ["domain/insurance@3", "domain/finance@2"]
        bundle["overrides"] = []
        only(compiler.validate(bundle, tenant), E.FLOOR_MISSING, "$.extends")

    def test_ac_c1_4_floor_below_platform_minimum(self, compiler, tenant, bundle):
        bundle["extends"][0] = "platform/floor@1"  # minimum is 2 in these fixtures
        only(compiler.validate(bundle, tenant), E.FLOOR_BELOW_MINIMUM, "$.extends[0]")

    def test_ac_c1_4_floor_at_platform_minimum_accepted(self, tenant, bundle):
        settings = PlatformSettings(min_floor_version=1)
        compiler = PolicyCompiler(make_catalog(), InMemoryToolRegistry(TOOLS), settings)
        bundle["extends"][0] = "platform/floor@1"
        bundle["overrides"] = []
        assert compiler.validate(bundle, tenant) == []


# ---------------------------------------------------------------------------- AC-C1.5


class TestAC_C1_5_Packs:
    @pytest.mark.parametrize("field", ["question", "true_description", "false_description"])
    def test_ac_c1_5_edit_pack_question_text(self, compiler, tenant, bundle, field):
        bundle["overrides"] = [{"rule": "d__ins_claim_promise", field: "Is it different?"}]
        only(compiler.validate(bundle, tenant), E.PACK_TEXT_EDITED, f"$.overrides[0].{field}")

    @pytest.mark.parametrize(("field", "value"), [("block_at", 0.85), ("escalate_at", 0.6)])
    def test_ac_c1_5_pack_override_raises_threshold(self, compiler, tenant, bundle, field, value):
        bundle["overrides"] = [{"rule": "d__ins_claim_promise", field: value}]
        only(compiler.validate(bundle, tenant), E.PACK_OVERRIDE_RAISES, f"$.overrides[0].{field}")

    def test_ac_c1_5_pack_override_lowering_accepted(self, compiler, tenant, bundle):
        bundle["overrides"] = [{"rule": "d__ins_claim_promise", "block_at": 0.7}]
        assert compiler.validate(bundle, tenant) == []

    def test_ac_c1_5_opt_out_of_pack_required_by_tier(self, compiler, bundle):
        tenant = TenantAttributes(tenant_id="t_acmeins", tier="regulated_finance")
        bundle["extends"].remove("domain/finance@2")
        only(compiler.validate(bundle, tenant), E.PACK_REQUIRED_MISSING, "$.extends")

    def test_ac_c1_5_opt_out_of_pack_required_by_contract(self, compiler, bundle):
        tenant = TenantAttributes(tenant_id="t_acmeins", required_packs=frozenset({"insurance"}))
        bundle["extends"].remove("domain/insurance@3")
        only(compiler.validate(bundle, tenant), E.PACK_REQUIRED_MISSING, "$.extends")

    def test_ac_c1_5_opt_out_of_optional_pack_accepted(self, compiler, tenant, bundle):
        bundle["extends"].remove("domain/insurance@3")
        assert compiler.validate(bundle, tenant) == []

    @pytest.mark.parametrize(("field", "value"), [("enabled", False), ("mode", "shadow")])
    def test_ac_c1_5_pack_rule_cannot_be_disabled_or_shadowed(
        self, compiler, tenant, bundle, field, value
    ):
        bundle["overrides"] = [{"rule": "d__ins_claim_promise", field: value}]
        only(
            compiler.validate(bundle, tenant),
            E.PACK_OVERRIDE_NOT_ALLOWED,
            f"$.overrides[0].{field}",
        )


# ---------------------------------------------------------------------------- AC-C1.6


class TestAC_C1_6_TenantQuestions:
    @pytest.mark.parametrize("value", [None, "", "   "])
    def test_ac_c1_6_rule_without_question(self, compiler, tenant, bundle, value):
        if value is None:
            del bundle["rules"][0]["question"]
        else:
            bundle["rules"][0]["question"] = value
        only(compiler.validate(bundle, tenant), E.RULE_QUESTION_MISSING, "$.rules[0].question")

    @pytest.mark.parametrize("field", ["true_description", "false_description"])
    def test_ac_c1_6_rule_missing_a_description(self, compiler, tenant, bundle, field):
        del bundle["rules"][0][field]
        only(compiler.validate(bundle, tenant), E.RULE_DESCRIPTION_MISSING, f"$.rules[0].{field}")

    @pytest.mark.parametrize(
        "question",
        [
            "Recommend a specific product?",  # doesn't start with an allowed word
            "Does the response recommend a product.",  # doesn't end with '?'
            "Does the response recommend a product",
            "What does the response recommend?",
            "Doesn't the response recommend a product?",
        ],
    )
    def test_ac_c1_6_question_fails_closed_question_lint(self, compiler, tenant, bundle, question):
        bundle["rules"][0]["question"] = question
        only(compiler.validate(bundle, tenant), E.RULE_QUESTION_NOT_CLOSED, "$.rules[0].question")

    @pytest.mark.parametrize(
        "starter",
        [
            "Does",
            "Do",
            "Is",
            "Are",
            "Has",
            "Have",
            "Can",
            "Could",
            "Will",
            "Would",
            "Should",
            "Did",
            "Was",
            "Were",
            "does",
            "IS",
        ],
    )
    def test_ac_c1_6_every_allowed_starter_case_insensitive(
        self, compiler, tenant, bundle, starter
    ):
        bundle["rules"][0]["question"] = f"{starter} the response recommend a product?"
        assert compiler.validate(bundle, tenant) == []


# ---------------------------------------------------------------------------- AC-C1.7

CRITICAL_PATH = ["plan", "tool_call", "tool_result", "output"]


def bulk_pack(n: int, gp: str = "output") -> PackVersion:
    """n questions at ``gp`` of every type: noul, choice routers and score scorers."""
    rules = []
    for i in range(n):
        if i % 3 == 0:
            q = {"type": "noul", "instructions": f"Is it {i}?"}
        elif i % 3 == 1:
            q = {"type": "choice", "instructions": f"Route {i}?", "criteria": {"a": "", "b": ""}}
        else:
            q = {"type": "score", "instructions": f"Grade {i}?", "criteria": ["lo", "hi"]}
        rules.append(pack_rule(f"d__bulk_{i}", guard_points=(gp,), question=q))
    return make_pack("bulk", 1, *rules)


def roomy_compiler(*extra_packs: PackVersion, **settings) -> PolicyCompiler:
    """Token budget raised so the question budget is tested on its own."""
    catalog = InMemoryCatalog(
        floors=[FLOOR_V1, FLOOR_V2],
        packs=[INSURANCE_V3, FINANCE_V2, HEALTHCARE_V1, *extra_packs],
        templates=[FIN_ADVICE_TEMPLATE],
    )
    settings = PlatformSettings(min_floor_version=2, token_budget=10**7, **settings)
    return PolicyCompiler(catalog, InMemoryToolRegistry(TOOLS), settings)


def question_count(compiler, tenant, bundle, gp: str) -> int:
    return len(compiler.compile(bundle, tenant).guard_points[gp].questions)


def with_bulk(bundle: dict, n: int, gp: str) -> PolicyCompiler:
    """The bundle extended with a pack of ``n`` questions at ``gp``."""
    bundle["extends"].append("domain/bulk@1")
    return roomy_compiler(bulk_pack(n, gp))


class TestAC_C1_7_QuestionBudget:
    """R6.1: at most 50 compiled questions on plan, tool_call, tool_result (per chunk) and
    output, and 200 on input. R6.2: tenant rules get what the floor and packs leave."""

    def test_ac_c1_7_default_budgets_are_50_on_the_critical_path_and_200_on_input(self):
        budgets = PlatformSettings().question_budgets
        assert set(QuestionBudgets.model_fields) == set(GUARD_POINTS)
        assert {gp: budgets.for_guard_point(gp) for gp in GUARD_POINTS} == {
            "input": 200,
            "plan": 50,
            "tool_call": 50,
            "tool_result": 50,
            "output": 50,
        }
        assert (CRITICAL_PATH_QUESTION_BUDGET, INPUT_QUESTION_BUDGET) == (50, 200)

    def test_ac_c1_7_old_settings_are_gone(self):
        for withdrawn in ("max_questions_per_guard_point", "max_tenant_rules_per_guard_point"):
            with pytest.raises(ValidationError):
                PlatformSettings(**{withdrawn: 900})

    @pytest.mark.parametrize(
        ("gp", "budget"), [*((gp, 50) for gp in CRITICAL_PATH), ("input", 200)]
    )
    def test_ac_c1_7_exactly_the_budget_accepted(self, tenant, bundle, gp, budget):
        base = question_count(roomy_compiler(), tenant, bundle, gp)
        compiler = with_bulk(bundle, budget - base, gp)
        assert compiler.validate(bundle, tenant) == []
        assert question_count(compiler, tenant, bundle, gp) == budget

    @pytest.mark.parametrize(
        ("gp", "budget"), [*((gp, 50) for gp in CRITICAL_PATH), ("input", 200)]
    )
    def test_ac_c1_7_one_over_the_budget_rejected(self, tenant, bundle, gp, budget):
        base = question_count(roomy_compiler(), tenant, bundle, gp)
        compiler = with_bulk(bundle, budget + 1 - base, gp)
        only(compiler.validate(bundle, tenant), E.GP_TOO_MANY_QUESTIONS, f"$.guard_points.{gp}")

    def test_ac_c1_7_every_question_type_counts_routers_and_scorers_included(self, tenant, bundle):
        # 6 output questions in the valid bundle; the 45 added are 15 noul, 15 choice, 15 score.
        compiler = with_bulk(bundle, 45, "output")
        roomy = roomy_compiler(bulk_pack(45), question_budgets=QuestionBudgets(output=51))
        compiled = roomy.compile(bundle, tenant).guard_points["output"]
        assert len(compiled.questions) == 51
        assert {q.type for q in compiled.questions.values()} == {"noul", "choice", "score"}
        only(compiler.validate(bundle, tenant), E.GP_TOO_MANY_QUESTIONS, "$.guard_points.output")

    def test_ac_c1_7_shadow_rules_count(self, tenant, bundle):
        compiler = with_bulk(bundle, 43, "output")  # 6 + 43 = 49
        bundle["rules"].append(tenant_rule("watching", mode="shadow"))
        assert compiler.validate(bundle, tenant) == []  # 50
        bundle["rules"].append(tenant_rule("watching_too", mode="shadow"))
        only(compiler.validate(bundle, tenant), E.GP_TOO_MANY_QUESTIONS, "$.guard_points.output")

    def test_ac_c1_7_error_names_budget_count_floor_and_pack_use_and_tenant_remainder(
        self, tenant, bundle
    ):
        # Output: floor 3, packs 2 + 20 bulk = 22, so 50 - 3 - 22 = 25 are left for tenant
        # rules. The bundle has 26.
        compiler = with_bulk(bundle, 20, "output")
        bundle["rules"] += [tenant_rule(i) for i in range(25)]
        [error] = compiler.validate(bundle, tenant)
        assert (error.code, error.path) == (E.GP_TOO_MANY_QUESTIONS, "$.guard_points.output")
        assert error.message == (
            "51 compiled questions; the question budget at output is 50. The floor uses 3 and "
            "packs use 22, which leaves 25 for tenant rules; this bundle has 26"
        )

    def test_ac_c1_7_floor_and_packs_over_budget_leave_zero_for_tenant_rules(self, tenant, bundle):
        compiler = with_bulk(bundle, 46, "output")  # floor 3 + packs 48 = 51
        bundle["rules"] = []
        [error] = compiler.validate(bundle, tenant)
        assert error.code is E.GP_TOO_MANY_QUESTIONS
        assert "leaves 0 for tenant rules; this bundle has 0" in error.message

    def test_ac_c1_7_tenant_rules_get_what_the_floor_and_packs_leave(self, tenant, bundle):
        # Output: floor 3 + packs 2 leave 45 for tenant rules.
        bundle["rules"] = [tenant_rule(i) for i in range(45)]
        assert roomy_compiler().validate(bundle, tenant) == []
        bundle["rules"].append(tenant_rule(45))
        [error] = roomy_compiler().validate(bundle, tenant)
        assert (error.code, error.path) == (E.GP_TOO_MANY_QUESTIONS, "$.guard_points.output")
        assert "leaves 45 for tenant rules; this bundle has 46" in error.message

    def test_ac_c1_7_fixed_limit_of_100_tenant_rules_is_withdrawn(self, tenant, bundle):
        # Input: floor 2 + packs 1 leave 197 of the 200 for tenant rules, well past the old 100.
        bundle["rules"] = [tenant_rule(f"in_{i}", guard_points=["input"]) for i in range(197)]
        assert roomy_compiler().validate(bundle, tenant) == []
        bundle["rules"].append(tenant_rule("in_197", guard_points=["input"]))
        errors = roomy_compiler().validate(bundle, tenant)
        only(errors, E.GP_TOO_MANY_QUESTIONS, "$.guard_points.input")
        assert "leaves 197 for tenant rules; this bundle has 198" in errors[0].message

    def test_ac_c1_7_budget_is_per_guard_point(self, tenant, bundle):
        rules = [tenant_rule(i) for i in range(45)]  # output full: 50
        rules += [tenant_rule(f"in_{i}", guard_points=["input"]) for i in range(197)]  # 200
        rules += [tenant_rule(f"pl_{i}", guard_points=["plan"]) for i in range(50)]  # 50
        bundle["rules"] = rules
        assert roomy_compiler().validate(bundle, tenant) == []

    def test_ac_c1_7_budgets_are_platform_settings(self, tenant, bundle):
        compiler = roomy_compiler(question_budgets=QuestionBudgets(output=6))
        assert compiler.validate(bundle, tenant) == []  # exactly 6
        bundle["rules"].append(tenant_rule(2))
        only(compiler.validate(bundle, tenant), E.GP_TOO_MANY_QUESTIONS, "$.guard_points.output")

    @pytest.mark.parametrize("field", ["question_budget", "max_questions", "max_tenant_rules"])
    def test_ac_c1_7_a_bundle_cannot_set_its_own_budget(self, compiler, tenant, bundle, field):
        bundle["guard_points"]["output"][field] = 500
        only(
            compiler.validate(bundle, tenant),
            E.SCHEMA_INVALID,
            f"$.guard_points.output.{field}",
        )

    @pytest.mark.parametrize("bad", [{"output": 0}, {"input": -1}, {"chat": 10}])
    def test_ac_c1_7_question_budgets_reject_nonsense(self, bad):
        with pytest.raises(ValidationError):
            QuestionBudgets(**bad)


# ---------------------------------------------------------------------------- AC-C1.8


def fitted(text_tokens: int, question_tokens: int, questions: int) -> int:
    """R6.6 written out independently of the compiler, in exact arithmetic."""
    return math.ceil(Fraction(120, 100) * text_tokens) + question_tokens + 25 * questions + 30


def content_bound(max_content: int) -> int:
    """R6.7 (a), written out: 1.20 x (max content + render overhead) + 30, rounded up."""
    return math.ceil(Fraction(120, 100) * (max_content + RENDER_OVERHEAD_TOKENS)) + 30


# 1.20 x (12,796 + 512) = 15,969.6, which rounds up to 15,970; + 30 = 16,000 exactly.
LARGEST_CONTENT = 12_796
assert content_bound(LARGEST_CONTENT) == 16_000 < content_bound(LARGEST_CONTENT + 1)


def question_api(key: str, question) -> int:
    """R6.7 (b), written out: one question's wire JSON, estimated, plus 25."""
    return estimate_question_tokens({key: question}) + 25


def sized_rule(rule_id: str, api_tokens: int, guard_points=("output",)) -> dict:
    """A tenant rule whose compiled question is exactly ``api_tokens`` by R6.7 (b)."""
    question = f"Is it case {rule_id}?"
    false = "No."
    for pad in range(4 * api_tokens):
        true = "Yes" + "a" * pad + "."
        compiled = NoulQuestion(
            instructions=question,
            criteria=NoulCriteria(true_description=true, false_description=false),
        )
        size = question_api(f"t__{rule_id}", compiled)
        if size == api_tokens:
            return {
                "id": rule_id,
                "guard_points": list(guard_points),
                "question": question,
                "true_description": true,
                "false_description": false,
            }
        assert size < api_tokens, f"can't size a rule to {api_tokens}"
    raise AssertionError(f"can't size a rule to {api_tokens}")


def compiler_with(*extra_packs: PackVersion, **settings) -> PolicyCompiler:
    """The fixture catalog plus ``extra_packs``, under default token bounds."""
    catalog = InMemoryCatalog(
        floors=[FLOOR_V1, FLOOR_V2],
        packs=[INSURANCE_V3, FINANCE_V2, HEALTHCARE_V1, *extra_packs],
        templates=[FIN_ADVICE_TEMPLATE],
    )
    settings = PlatformSettings(min_floor_version=2, **settings)
    return PolicyCompiler(catalog, InMemoryToolRegistry(TOOLS), settings)


CONTENT_KEY = {
    "input": "max_input_tokens",
    "tool_result": "chunk_tokens",
    "output": "max_input_tokens",
}


class TestAC_C1_8_TokenEstimates:
    def output(self, compiler, tenant, bundle):
        return compiler.compile(bundle, tenant).guard_points["output"]

    def test_ac_c1_8_api_tokens_is_the_fitted_whole_call_estimate(self, compiler, tenant, bundle):
        out = self.output(compiler, tenant, bundle)
        assert (len(out.questions), out.max_content_tokens) == (6, 8_000)
        assert out.api_tokens == fitted(8_000 + 512, out.question_tokens, 6)
        assert out.content_api_tokens == 10_215 + 30
        assert out.question_api_tokens == out.question_tokens + 150
        assert out.api_tokens == out.content_api_tokens + out.question_api_tokens

    def test_ac_c1_8_each_question_adds_25_tokens_beyond_its_text(self, compiler, tenant, bundle):
        before = self.output(compiler, tenant, bundle)
        bundle["rules"].append(tenant_rule(2))
        after = self.output(compiler, tenant, bundle)
        added_text = after.question_tokens - before.question_tokens
        assert after.question_api_tokens - before.question_api_tokens == added_text + 25
        assert after.content_api_tokens == before.content_api_tokens  # questions don't count
        assert after.api_tokens - before.api_tokens == added_text + 25

    def test_ac_c1_8_guard_point_without_questions_has_no_estimate(self, compiler, tenant, bundle):
        plan = compiler.compile(bundle, tenant).guard_points["plan"]
        assert plan.questions == {}
        assert (
            plan.question_tokens,
            plan.api_tokens,
            plan.content_api_tokens,
            plan.question_api_tokens,
        ) == (0, 0, 0, 0)

    def test_ac_c1_8_uses_the_shared_estimator_and_documented_overhead(
        self, compiler, tenant, bundle
    ):
        from guardrail_engine.policy import api_tokens as api_tokens_module
        from guardrail_engine.policy import compiler as compiler_module

        assert compiler_module.estimate_question_tokens is estimate_question_tokens
        assert compiler_module.content_api_tokens is api_tokens_module.content_api_tokens
        assert compiler_module.question_api_tokens is api_tokens_module.question_api_tokens
        assert PlatformSettings().render_overhead_tokens == RENDER_OVERHEAD_TOKENS == 512
        out = compiler.compile(bundle, tenant).guard_points["output"]
        assert out.question_tokens == estimate_question_tokens(out.questions)

    def test_ac_c1_8_default_bounds(self):
        s = PlatformSettings()
        assert (s.token_budget, s.max_question_tokens) == (16_000, 400)
        assert s.question_text_tokens_per_budgeted_question == 150


class TestAC_C1_8a_ContentBound:
    """1.20 x (max content + render overhead) + 30 <= 16,000; question text doesn't count."""

    @pytest.mark.parametrize("gp", ["input", "tool_result", "output"])
    def test_ac_c1_8a_content_bound_exactly_16000_accepted(self, compiler, tenant, bundle, gp):
        bundle["guard_points"][gp][CONTENT_KEY[gp]] = LARGEST_CONTENT
        assert compiler.validate(bundle, tenant) == []
        assert compiler.compile(bundle, tenant).guard_points[gp].content_api_tokens == 16_000

    @pytest.mark.parametrize("gp", ["input", "tool_result", "output"])
    def test_ac_c1_8a_content_bound_16001_rejected(self, compiler, tenant, bundle, gp):
        bundle["guard_points"][gp][CONTENT_KEY[gp]] = LARGEST_CONTENT + 1
        errors = compiler.validate(bundle, tenant)
        only(errors, E.GP_TOKEN_BUDGET, f"$.guard_points.{gp}")
        assert errors[0].message == (
            f"content bound: estimated API tokens 16001 = 1.20 x (max content "
            f"{LARGEST_CONTENT + 1} + render overhead 512) + 30; limit is 16000"
        )

    def test_ac_c1_8a_question_text_does_not_count_toward_16000(self, tenant, bundle):
        # Content at its largest and a full 50-question output guard point: the combined
        # pre-R6.7 budget rejected this by thousands of tokens.
        bundle["extends"].append("domain/bulk@1")
        compiler = compiler_with(bulk_pack(44, "output"))
        bundle["guard_points"]["output"]["max_input_tokens"] = LARGEST_CONTENT
        assert compiler.validate(bundle, tenant) == []
        out = self.output(compiler, tenant, bundle)
        assert len(out.questions) == 50
        assert out.content_api_tokens == 16_000
        assert out.api_tokens > 16_000

    def output(self, compiler, tenant, bundle):
        return compiler.compile(bundle, tenant).guard_points["output"]

    def test_ac_c1_8a_uses_the_fitted_factor(self, compiler, tenant, bundle):
        """14,000 tokens of content plus the overhead is under 16,000 raw, but not x1.20."""
        bundle["guard_points"]["output"]["max_input_tokens"] = 14_000
        assert 14_000 + RENDER_OVERHEAD_TOKENS <= 16_000 < content_bound(14_000)
        only(compiler.validate(bundle, tenant), E.GP_TOKEN_BUDGET, "$.guard_points.output")

    def test_ac_c1_8a_render_overhead_counts_as_input_text(self, tenant, bundle):
        base = self.output(roomy_compiler(), tenant, bundle).content_api_tokens
        more = self.output(roomy_compiler(render_overhead_tokens=612), tenant, bundle)
        assert more.content_api_tokens - base == 120  # 100 more text tokens x 1.20

    def test_ac_c1_8a_tool_result_uses_chunk_tokens(self, compiler, tenant, bundle):
        gp = bundle["guard_points"]["tool_result"]
        gp["max_input_tokens"] = 15_900  # ignored for tool_result
        assert compiler.validate(bundle, tenant) == []
        gp["chunk_tokens"] = LARGEST_CONTENT
        assert compiler.validate(bundle, tenant) == []
        gp["chunk_tokens"] += 1
        only(compiler.validate(bundle, tenant), E.GP_TOKEN_BUDGET, "$.guard_points.tool_result")


class TestAC_C1_8b_PerQuestion:
    """Each compiled question is at most 400 estimated API tokens: its wire JSON plus 25."""

    def test_ac_c1_8b_question_of_exactly_400_accepted(self, compiler, tenant, bundle):
        bundle["rules"].append(sized_rule("big", 400))
        assert compiler.validate(bundle, tenant) == []
        out = compiler.compile(bundle, tenant).guard_points["output"]
        assert question_api("t__big", out.questions["t__big"]) == 400

    def test_ac_c1_8b_question_of_401_rejected_naming_the_rule_key(self, compiler, tenant, bundle):
        bundle["rules"].append(sized_rule("big", 401))
        errors = compiler.validate(bundle, tenant)
        only(errors, E.QUESTION_TOKENS_EXCEEDED, "$.rules[1]")
        assert errors[0].message == (
            "question 't__big': estimated API tokens 401 (its text and criteria + 25); "
            "limit is 400 per question"
        )

    def test_ac_c1_8b_the_25_per_question_counts_toward_400(self, compiler, tenant, bundle):
        rule = sized_rule("big", 401)
        compiled = NoulQuestion(
            instructions=rule["question"],
            criteria=NoulCriteria(
                true_description=rule["true_description"],
                false_description=rule["false_description"],
            ),
        )
        assert estimate_question_tokens({"t__big": compiled}) == 376  # under 400 on its own
        bundle["rules"].append(rule)
        only(compiler.validate(bundle, tenant), E.QUESTION_TOKENS_EXCEEDED, "$.rules[1]")

    def test_ac_c1_8b_reported_once_for_a_question_on_several_guard_points(
        self, compiler, tenant, bundle
    ):
        bundle["rules"].append(sized_rule("big", 401, guard_points=("input", "output", "plan")))
        only(compiler.validate(bundle, tenant), E.QUESTION_TOKENS_EXCEEDED, "$.rules[1]")

    def test_ac_c1_8b_pack_question_over_400_rejected_at_its_extends_entry(self, tenant, bundle):
        long = {"type": "noul", "instructions": "Is it " + "a" * 1_600 + "?"}
        compiler = compiler_with(make_pack("long", 1, pack_rule("d__long_q", question=long)))
        bundle["extends"].append("domain/long@1")
        errors = compiler.validate(bundle, tenant)
        only(errors, E.QUESTION_TOKENS_EXCEEDED, "$.extends[domain/long@1]")
        assert "'d__long_q'" in errors[0].message

    def test_ac_c1_8b_limit_is_a_platform_setting(self, tenant, bundle):
        bundle["rules"].append(sized_rule("mid", 200))
        assert compiler_with(max_question_tokens=200).validate(bundle, tenant) == []
        only(
            compiler_with(max_question_tokens=199).validate(bundle, tenant),
            E.QUESTION_TOKENS_EXCEEDED,
            "$.rules[1]",
        )


class TestAC_C1_8c_QuestionText:
    """A guard point's question text (estimate + 25 per question) is at most 150 x its
    question budget: 7,500 on the critical path, 30,000 on input."""

    def fill(self, bundle, gp: str, start: int, target: int) -> None:
        """Add tenant rules at ``gp`` so its question text goes from ``start`` to exactly
        ``target``, using questions of at most 375 (well inside the 400 per question)."""
        room, i = target - start, 0
        while room > 400:
            chunk = min(375, room - 100)  # leaves at least 100 for the last rule
            bundle["rules"].append(sized_rule(f"fill_{gp}_{i}", chunk, guard_points=(gp,)))
            room, i = room - chunk, i + 1
        bundle["rules"].append(sized_rule(f"fill_{gp}_{i}", room, guard_points=(gp,)))

    def text(self, compiler, tenant, bundle, gp: str) -> int:
        return compiler.compile(bundle, tenant).guard_points[gp].question_api_tokens

    @pytest.mark.parametrize(("gp", "limit"), [("output", 7_500), ("input", 30_000)])
    def test_ac_c1_8c_exactly_at_the_limit_accepted(self, compiler, tenant, bundle, gp, limit):
        self.fill(bundle, gp, self.text(compiler, tenant, bundle, gp), limit)
        assert compiler.validate(bundle, tenant) == []
        compiled = compiler.compile(bundle, tenant).guard_points[gp]
        assert compiled.question_api_tokens == limit
        assert len(compiled.questions) <= PlatformSettings().question_budgets.for_guard_point(gp)

    @pytest.mark.parametrize(("gp", "limit"), [("output", 7_500), ("input", 30_000)])
    def test_ac_c1_8c_one_over_the_limit_rejected(self, compiler, tenant, bundle, gp, limit):
        self.fill(bundle, gp, self.text(compiler, tenant, bundle, gp), limit + 1)
        errors = compiler.validate(bundle, tenant)
        only(errors, E.GP_QUESTION_TEXT_BUDGET, f"$.guard_points.{gp}")
        budget = limit // 150
        assert errors[0].message.startswith("question text: estimated API tokens ")
        assert errors[0].message.endswith(f"; limit is {limit} (150 x question budget {budget})")
        assert f"estimated API tokens {limit + 1} = " in errors[0].message

    def test_ac_c1_8c_limit_follows_the_question_budget(self, tenant, bundle):
        compiler = compiler_with(question_budgets=QuestionBudgets(output=20))  # 3,000
        self.fill(bundle, "output", self.text(compiler, tenant, bundle, "output"), 3_001)
        only(compiler.validate(bundle, tenant), E.GP_QUESTION_TEXT_BUDGET, "$.guard_points.output")

    def test_ac_c1_8c_factor_is_a_platform_setting(self, tenant, bundle):
        assert self.text(compiler_with(), tenant, bundle, "output") == 534  # the valid bundle
        compiler = compiler_with(question_text_tokens_per_budgeted_question=10)  # 500
        only(compiler.validate(bundle, tenant), E.GP_QUESTION_TEXT_BUDGET, "$.guard_points.output")


class TestFittedApiTokenEstimate:
    def test_coefficients(self):
        assert (API_TOKENS_TEXT_PERCENT, API_TOKENS_PER_QUESTION, API_TOKENS_PER_CALL) == (
            120,
            25,
            30,
        )

    @pytest.mark.parametrize(
        ("text", "questions_text", "count", "expected"),
        [
            (0, 0, 0, 30),
            (1_000, 100, 4, 1_200 + 100 + 100 + 30),
            (1, 0, 0, 2 + 30),  # 1.2 rounds up
            (5, 0, 0, 6 + 30),  # exact, no rounding
            (12_825, 505, 3, 15_390 + 505 + 75 + 30),  # 1.2 x 12,825 is exactly 15,390
            (12_826, 505, 3, 15_392 + 505 + 75 + 30),  # 15,391.2 rounds up
        ],
    )
    def test_estimate(self, text, questions_text, count, expected):
        got = estimate_api_tokens(
            text_tokens=text, question_tokens=questions_text, question_count=count
        )
        assert got == expected == fitted(text, questions_text, count)
        assert got == content_api_tokens(text) + question_api_tokens(questions_text, count)

    @pytest.mark.parametrize(
        ("text", "expected"), [(0, 30), (1, 32), (5, 36), (13_308, 16_000), (13_309, 16_001)]
    )
    def test_content_part(self, text, expected):
        assert content_api_tokens(text) == expected

    @pytest.mark.parametrize(
        ("question_tokens", "count", "expected"), [(0, 0, 0), (375, 1, 400), (505, 3, 580)]
    )
    def test_question_part(self, question_tokens, count, expected):
        assert question_api_tokens(question_tokens, count) == expected

    def test_shared_estimator_is_unchanged(self):
        from guardrail_engine.tokens import estimate_tokens

        assert estimate_tokens("a" * 400) == 100  # raw, not x1.20
        assert estimate_tokens("日本語") == 3


# ---------------------------------------------------------------------------- AC-C1.9


class TestAC_C1_9_ToolRegistry:
    def test_ac_c1_9_allowlisted_tool_not_in_registry(self, compiler, tenant, bundle):
        bundle["guard_points"]["plan"]["tool_allowlist"].append("shell.exec")
        only(
            compiler.validate(bundle, tenant),
            E.TOOL_NOT_REGISTERED,
            "$.guard_points.plan.tool_allowlist[3]",
        )


# ---------------------------------------------------------------------------- AC-C1.10


class TestAC_C1_10_Deterministic:
    @pytest.mark.parametrize(
        "regex",
        ["(a)\\1", "foo(?=bar)", "foo(?!bar)", "(?<=x)y", "(?<!x)y", "[unclosed"],
    )
    def test_ac_c1_10_deny_pattern_not_valid_re2(self, compiler, tenant, bundle, regex):
        bundle["deterministic"]["deny_patterns"][0]["regex"] = regex
        only(
            compiler.validate(bundle, tenant),
            E.DENY_PATTERN_INVALID,
            "$.deterministic.deny_patterns[0].regex",
        )

    def test_ac_c1_10_deny_action_outside_enum(self, compiler, tenant, bundle):
        bundle["deterministic"]["deny_patterns"][0]["action"] = "quarantine"
        only(
            compiler.validate(bundle, tenant),
            E.DETERMINISTIC_ACTION_INVALID,
            "$.deterministic.deny_patterns[0].action",
        )

    def test_ac_c1_10_pii_action_outside_enum(self, compiler, tenant, bundle):
        bundle["deterministic"]["pii"]["action"] = "mask"
        only(
            compiler.validate(bundle, tenant),
            E.DETERMINISTIC_ACTION_INVALID,
            "$.deterministic.pii.action",
        )

    @pytest.mark.parametrize("action", ["block", "escalate", "redact", "log"])
    def test_ac_c1_10_every_action_in_enum_accepted(self, compiler, tenant, bundle, action):
        bundle["deterministic"]["deny_patterns"][0]["action"] = action
        bundle["deterministic"]["pii"]["action"] = action
        assert compiler.validate(bundle, tenant) == []

    def test_ac_c1_10_pii_type_outside_enum(self, compiler, tenant, bundle):
        bundle["deterministic"]["pii"]["detect"].append("BLOOD_TYPE")
        only(
            compiler.validate(bundle, tenant),
            E.PII_TYPE_UNSUPPORTED,
            "$.deterministic.pii.detect[3]",
        )


# ---------------------------------------------------------------------------- AC-C1.11


class TestAC_C1_11_GuardPoints:
    @pytest.mark.parametrize("gp", ["input", "tool_result", "output"])
    def test_ac_c1_11_disable_guard_point_the_floor_covers(self, compiler, tenant, bundle, gp):
        bundle["guard_points"][gp]["enabled"] = False
        only(
            compiler.validate(bundle, tenant),
            E.GP_FLOOR_COVERED_DISABLED,
            f"$.guard_points.{gp}.enabled",
        )

    @pytest.mark.parametrize("gp", ["plan", "tool_call"])
    def test_ac_c1_11_disable_guard_point_the_floor_does_not_cover(
        self, compiler, tenant, bundle, gp
    ):
        bundle["guard_points"][gp]["enabled"] = False
        assert compiler.validate(bundle, tenant) == []

    def test_ac_c1_11_rule_lists_unknown_guard_point(self, compiler, tenant, bundle):
        bundle["rules"][0]["guard_points"] = ["output", "ouptut"]
        only(
            compiler.validate(bundle, tenant),
            E.RULE_UNKNOWN_GUARD_POINT,
            "$.rules[0].guard_points[1]",
        )

    def test_ac_c1_11_unknown_guard_point_config(self, compiler, tenant, bundle):
        bundle["guard_points"]["retrieval"] = {"enabled": True}
        only(compiler.validate(bundle, tenant), E.GP_UNKNOWN, "$.guard_points.retrieval")


# ---------------------------------------------------------------------------- AC-C1.12


class TestAC_C1_12_Escalation:
    @pytest.mark.parametrize("target", ["email", "generative_reviewer", ""])
    def test_ac_c1_12_target_not_queue_or_webhook(self, compiler, tenant, bundle, target):
        bundle["escalation"] = {"target": target}
        only(compiler.validate(bundle, tenant), E.ESCALATION_TARGET_INVALID, "$.escalation.target")

    @pytest.mark.parametrize(
        "url", ["http://hooks.acme.example/g", "ftp://hooks.acme.example", "https//x", "https://"]
    )
    def test_ac_c1_12_webhook_url_not_https(self, compiler, tenant, bundle, url):
        bundle["escalation"]["url"] = url
        only(compiler.validate(bundle, tenant), E.ESCALATION_WEBHOOK_NOT_HTTPS, "$.escalation.url")

    def test_ac_c1_12_webhook_without_url(self, compiler, tenant, bundle):
        bundle["escalation"] = {"target": "webhook"}
        only(
            compiler.validate(bundle, tenant), E.ESCALATION_WEBHOOK_URL_MISSING, "$.escalation.url"
        )

    def test_ac_c1_12_queue_needs_no_url(self, compiler, tenant, bundle):
        bundle["escalation"] = {"target": "queue"}
        assert compiler.validate(bundle, tenant) == []


# ---------------------------------------------------------------------------- AC-C1.13


class TestAC_C1_13_Audit:
    def standard(self, bundle) -> dict:
        bundle["extends"] = ["platform/floor@2", "domain/insurance@3"]
        bundle["overrides"] = []
        return bundle

    @pytest.mark.parametrize("days", [89, 7 * 365 + 1])
    def test_ac_c1_13_records_days_outside_standard_bounds(self, compiler, tenant, bundle, days):
        bundle = self.standard(bundle)
        bundle["audit"] = {"records_days": days}
        only(
            compiler.validate(bundle, tenant),
            E.AUDIT_RECORDS_DAYS_OUT_OF_RANGE,
            "$.audit.records_days",
        )

    @pytest.mark.parametrize("days", [90, 395, 7 * 365])
    def test_ac_c1_13_records_days_inside_standard_bounds(self, compiler, tenant, bundle, days):
        bundle = self.standard(bundle)
        bundle["audit"] = {"records_days": days}
        assert compiler.validate(bundle, tenant) == []

    def test_ac_c1_13_finance_pack_raises_the_records_minimum(self, compiler, tenant, bundle):
        bundle["audit"] = {"records_days": 394}
        only(
            compiler.validate(bundle, tenant),
            E.AUDIT_RECORDS_DAYS_OUT_OF_RANGE,
            "$.audit.records_days",
        )

    def test_ac_c1_13_content_days_above_standard_cap(self, compiler, tenant, bundle):
        bundle = self.standard(bundle)
        bundle["audit"] = {"store_content": "full", "content_days": 91}
        only(
            compiler.validate(bundle, tenant),
            E.AUDIT_CONTENT_DAYS_OUT_OF_RANGE,
            "$.audit.content_days",
        )

    def test_ac_c1_13_several_packs_take_the_shortest_content_cap(self, compiler, bundle):
        tenant = TenantAttributes(tenant_id="t_acmeins", baa=True)
        bundle["extends"].append("domain/healthcare@1")  # finance cap 90, healthcare cap 30
        bundle["audit"] = {"records_days": 2555, "store_content": "full", "content_days": 31}
        only(
            compiler.validate(bundle, tenant),
            E.AUDIT_CONTENT_DAYS_OUT_OF_RANGE,
            "$.audit.content_days",
        )
        bundle["audit"]["content_days"] = 30
        assert compiler.validate(bundle, tenant) == []

    def test_ac_c1_13_several_packs_take_the_longest_records_default(self, compiler, bundle):
        tenant = TenantAttributes(tenant_id="t_acmeins")
        bundle["extends"].append("domain/healthcare@1")  # finance 7 years, healthcare 6
        bundle["audit"] = {}
        assert compiler.compile(bundle, tenant).audit.records_days == 7 * 365

    def test_ac_c1_13_healthcare_content_without_baa(self, compiler, tenant, bundle):
        bundle["extends"].append("domain/healthcare@1")
        bundle["audit"] = {"records_days": 2555, "store_content": "full"}
        only(
            compiler.validate(bundle, tenant), E.AUDIT_CONTENT_REQUIRES_BAA, "$.audit.store_content"
        )

    def test_ac_c1_13_healthcare_content_with_baa_accepted(self, compiler, bundle):
        tenant = TenantAttributes(tenant_id="t_acmeins", baa=True)
        bundle["extends"].append("domain/healthcare@1")
        bundle["audit"] = {"records_days": 2555, "store_content": "full"}
        assert compiler.validate(bundle, tenant) == []
        assert compiler.compile(bundle, tenant).audit.content_days == 30

    def test_ac_c1_13_store_content_value_outside_enum(self, compiler, tenant, bundle):
        bundle["audit"]["store_content"] = "raw"
        only(
            compiler.validate(bundle, tenant),
            E.AUDIT_STORE_CONTENT_INVALID,
            "$.audit.store_content",
        )


# ---------------------------------------------------------------------------- AC-C1.14


class TestAC_C1_14_Templates:
    def template_rule(self, bundle) -> dict:
        rule = bundle["rules"][0]
        rule.update(origin="template:fin_advice@1", template_unedited=True)
        return rule

    def test_ac_c1_14_unedited_template_copy_accepted(self, compiler, tenant, bundle):
        self.template_rule(bundle)
        assert compiler.validate(bundle, tenant) == []

    @pytest.mark.parametrize(
        ("field", "value"),
        [
            ("question", "Does the response recommend any specific financial product?"),
            ("true_description", "Recommends something."),
            ("false_description", "Doesn't."),
            ("block_at", 0.9),
            ("escalate_at", 0.4),
            ("severity", "low"),  # M2-03
            ("guard_points", ["output", "input"]),
        ],
    )
    def test_ac_c1_14_template_unedited_but_differs(self, compiler, tenant, bundle, field, value):
        self.template_rule(bundle)[field] = value
        only(compiler.validate(bundle, tenant), E.TEMPLATE_MISMATCH, "$.rules[0].template_unedited")

    def test_ac_c1_14_edited_copy_with_flag_cleared_accepted(self, compiler, tenant, bundle):
        rule = self.template_rule(bundle)
        rule.update(template_unedited=False, block_at=0.9)
        assert compiler.validate(bundle, tenant) == []

    def test_ac_c1_14_unknown_template(self, compiler, tenant, bundle):
        self.template_rule(bundle)["origin"] = "template:fin_advice@9"
        only(compiler.validate(bundle, tenant), E.TEMPLATE_UNKNOWN, "$.rules[0].origin")

    def test_ac_c1_14_unedited_flag_without_template_origin(self, compiler, tenant, bundle):
        bundle["rules"][0]["template_unedited"] = True
        only(
            compiler.validate(bundle, tenant),
            E.TEMPLATE_ORIGIN_INVALID,
            "$.rules[0].template_unedited",
        )

    @pytest.mark.parametrize(
        "origin", ["custom", "fork:d__ins_claim_promise", "template:fin_advice@1"]
    )
    def test_ac_c1_14_valid_origins(self, compiler, tenant, bundle, origin):
        bundle["rules"][0]["origin"] = origin
        assert compiler.validate(bundle, tenant) == []

    @pytest.mark.parametrize("origin", ["templ:x@1", "fork:", "fork:t__mine", "template:x"])
    def test_ac_c1_14_invalid_origin(self, compiler, tenant, bundle, origin):
        bundle["rules"][0]["origin"] = origin
        only(compiler.validate(bundle, tenant), E.ORIGIN_INVALID, "$.rules[0].origin")
