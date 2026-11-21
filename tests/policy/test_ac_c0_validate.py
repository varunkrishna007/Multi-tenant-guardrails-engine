"""AC-C0: validate() returns every error, each with a JSON path and a stable code."""

import inspect

import pytest

from guardrail_engine.policy import Bundle, ErrorCode, PolicyInvalidError, parse_bundle

E = ErrorCode


def test_ac_c0_valid_bundle_returns_no_errors(compiler, tenant, bundle):
    assert compiler.validate(bundle, tenant) == []


def test_ac_c0_validate_accepts_a_parsed_bundle(compiler, tenant, bundle):
    assert compiler.validate(parse_bundle(bundle), tenant) == []


def test_ac_c0_validate_refuses_a_bare_model_because_it_has_no_submitted_document(
    compiler, tenant, bundle
):
    # The hash is over the document as submitted, and a model doesn't carry one.
    model = Bundle.model_validate(bundle)
    with pytest.raises(TypeError, match="ParsedBundle"):
        compiler.validate(model, tenant)
    with pytest.raises(TypeError, match="ParsedBundle"):
        compiler.compile(model, tenant)


def test_ac_c0_returns_every_error_not_only_the_first(compiler, tenant, bundle):
    bundle["rules"][0]["id"] = "Bad-Id"
    bundle["rules"][0]["question"] = "Recommend a product."
    bundle["overrides"] = [{"rule": "p__inj_direct", "block_at": 0.95}]
    bundle["guard_points"]["plan"]["tool_allowlist"].append("shell.exec")
    bundle["deterministic"]["deny_patterns"][0]["regex"] = "(a)\\1"
    bundle["escalation"]["url"] = "http://insecure.example"
    bundle["audit"]["records_days"] = 10

    errors = compiler.validate(bundle, tenant)
    # All seven, in the compiler's fixed pass order.
    assert [(e.code, e.path) for e in errors] == [
        (E.TOOL_NOT_REGISTERED, "$.guard_points.plan.tool_allowlist[3]"),
        (E.FLOOR_OVERRIDE_RAISES, "$.overrides[0].block_at"),
        (E.RULE_ID_INVALID, "$.rules[0].id"),
        (E.RULE_QUESTION_NOT_CLOSED, "$.rules[0].question"),
        (E.DENY_PATTERN_INVALID, "$.deterministic.deny_patterns[0].regex"),
        (E.ESCALATION_WEBHOOK_NOT_HTTPS, "$.escalation.url"),
        (E.AUDIT_RECORDS_DAYS_OUT_OF_RANGE, "$.audit.records_days"),
    ]


def test_ac_c0_error_order_is_stable(compiler, tenant, bundle):
    bundle["rules"][0]["id"] = "Bad-Id"
    bundle["escalation"]["url"] = "http://insecure.example"
    assert compiler.validate(bundle, tenant) == compiler.validate(bundle, tenant)


def test_ac_c0_every_error_has_code_path_and_message(compiler, tenant, bundle):
    bundle["rules"][0]["id"] = "Bad-Id"
    bundle["audit"]["store_content"] = "raw"
    for e in compiler.validate(bundle, tenant):
        assert isinstance(e.code, ErrorCode)
        assert e.path.startswith("$")
        assert e.message


def test_ac_c0_schema_errors_are_all_reported_with_paths(compiler, tenant, bundle):
    bundle["version"] = "fourteen"
    bundle["rules"][0]["block_at"] = "high"
    bundle["guard_points"]["input"]["max_input_tokens"] = 0
    bundle["unexpected_field"] = True
    errors = compiler.validate(bundle, tenant)
    assert {e.code for e in errors} == {E.SCHEMA_INVALID}
    assert {e.path for e in errors} == {
        "$.version",
        "$.rules[0].block_at",
        "$.guard_points.input.max_input_tokens",
        "$.unexpected_field",
    }


def test_ac_c0_compile_raises_with_the_same_errors(compiler, tenant, bundle):
    bundle["rules"][0]["id"] = "Bad-Id"
    bundle["escalation"]["target"] = "email"
    expected = compiler.validate(bundle, tenant)
    with pytest.raises(PolicyInvalidError) as exc:
        compiler.compile(bundle, tenant)
    assert exc.value.errors == expected


def test_ac_c0_bundle_for_another_tenant_rejected(compiler, bundle):
    from guardrail_engine.policy import TenantAttributes

    errors = compiler.validate(bundle, TenantAttributes(tenant_id="t_other"))
    assert [(e.code, e.path) for e in errors] == [(E.TENANT_MISMATCH, "$.tenant_id")]


# Each AC-C1 case and the code that rejects it. AC-C0: every rejection has its own code.
AC_C1_CODES = {
    "C1.1 rule id pattern": E.RULE_ID_INVALID,
    "C1.1 duplicate rule id": E.RULE_ID_DUPLICATE,
    "C1.2 thresholds": E.THRESHOLD_INVALID,
    "C1.3 floor override raises": E.FLOOR_OVERRIDE_RAISES,
    "C1.3 override of unknown rule": E.OVERRIDE_UNKNOWN_RULE,
    "C1.4 floor rule disabled": E.FLOOR_RULE_DISABLED,
    "C1.4 floor rule shadowed": E.FLOOR_RULE_SHADOWED,
    "C1.4 floor text edited": E.FLOOR_TEXT_EDITED,
    "C1.4 no floor": E.FLOOR_MISSING,
    "C1.4 floor below minimum": E.FLOOR_BELOW_MINIMUM,
    "C1.5 pack text edited": E.PACK_TEXT_EDITED,
    "C1.5 pack override raises": E.PACK_OVERRIDE_RAISES,
    "C1.5 required pack missing": E.PACK_REQUIRED_MISSING,
    "C1.6 no question": E.RULE_QUESTION_MISSING,
    "C1.6 missing description": E.RULE_DESCRIPTION_MISSING,
    "C1.6 not a closed question": E.RULE_QUESTION_NOT_CLOSED,
    "C1.7 over the question budget (tenant rules included, R6.2)": E.GP_TOO_MANY_QUESTIONS,
    "C1.8 (a) content bound": E.GP_TOKEN_BUDGET,
    "C1.8 (b) one question over 400 tokens": E.QUESTION_TOKENS_EXCEEDED,
    "C1.8 (c) question text over 150 x the question budget": E.GP_QUESTION_TEXT_BUDGET,
    "C1.9 unregistered tool": E.TOOL_NOT_REGISTERED,
    "C1.10 not RE2": E.DENY_PATTERN_INVALID,
    "C1.10 action outside enum": E.DETERMINISTIC_ACTION_INVALID,
    "C1.10 PII type outside enum": E.PII_TYPE_UNSUPPORTED,
    "C1.11 floor-covered guard point disabled": E.GP_FLOOR_COVERED_DISABLED,
    "C1.11 unknown guard point on a rule": E.RULE_UNKNOWN_GUARD_POINT,
    "C1.12 escalation target": E.ESCALATION_TARGET_INVALID,
    "C1.12 webhook not https": E.ESCALATION_WEBHOOK_NOT_HTTPS,
    "C1.13 records days": E.AUDIT_RECORDS_DAYS_OUT_OF_RANGE,
    "C1.13 content days": E.AUDIT_CONTENT_DAYS_OUT_OF_RANGE,
    "C1.13 healthcare content without BAA": E.AUDIT_CONTENT_REQUIRES_BAA,
    "C1.14 template mismatch": E.TEMPLATE_MISMATCH,
}


def test_ac_c0_every_ac_c1_rejection_has_its_own_code():
    codes = list(AC_C1_CODES.values())
    assert len(codes) == len(set(codes))


def test_ac_c0_error_codes_are_stable_strings():
    # Codes are part of the Admin API contract; these must never change.
    assert E.RULE_ID_INVALID == "rule.id_invalid"
    assert E.GP_TOKEN_BUDGET == "guard_point.token_budget_exceeded"
    assert E.FLOOR_BELOW_MINIMUM == "floor.below_minimum"
    assert E.GP_TOO_MANY_QUESTIONS == "guard_point.too_many_questions"
    assert E.QUESTION_TOKENS_EXCEEDED == "question.token_limit_exceeded"
    assert E.GP_QUESTION_TEXT_BUDGET == "guard_point.question_text_budget_exceeded"
    assert len({c.value for c in ErrorCode}) == len(ErrorCode)


def test_ac_c1_7_withdrawn_tenant_rule_limit_code_is_retired_not_reused():
    """R6.2 withdrew the fixed limit of 100 tenant rules, so nothing emits its code any
    more. The string stays reserved: codes are never renamed or reused."""
    assert E.GP_TOO_MANY_TENANT_RULES == "guard_point.too_many_tenant_rules"
    assert E.GP_TOO_MANY_TENANT_RULES not in AC_C1_CODES.values()
    from guardrail_engine.policy import compiler as compiler_module

    assert "GP_TOO_MANY_TENANT_RULES" not in inspect.getsource(compiler_module)
