"""M1-08: the compiler's floor guarantees (AC-C1.4, AC-C1.11, AC-C9.1, B1, PF-15, PF-16),
proved against the real ``floor/rules.json`` instead of fixtures. A tenant bundle can't
remove, disable, shadow, loosen or re-text any of the six rules, can't disable a guard point
they cover, and can't change how they fail."""

import json
from pathlib import Path

import pytest

from guardrail_engine.floor_file import load_floor_file
from guardrail_engine.policy import (
    GUARD_POINTS,
    ErrorCode,
    InMemoryCatalog,
    InMemoryToolRegistry,
    PlatformSettings,
    PolicyCompiler,
    TenantAttributes,
    bundle_hash,
    estimate_api_tokens,
    load_floor,
)
from guardrail_engine.tokens import estimate_question_tokens

E = ErrorCode
RULES_JSON = Path(__file__).resolve().parents[2] / "floor" / "rules.json"
RAW_RULES = json.loads(RULES_JSON.read_text(encoding="utf-8"))["rules"]
FLOOR_KEYS = [r["key"] for r in RAW_RULES]
# Read straight from the file, so these tests don't depend on the loader's own mapping.
DECLARED = {
    gp: sorted(r["key"] for r in RAW_RULES if gp in r["guard_points"]) for gp in GUARD_POINTS
}
RULE_AT_GUARD_POINT = [(r["key"], gp) for r in RAW_RULES for gp in r["guard_points"]]

FLOOR = load_floor_file(RULES_JSON)
TENANT = TenantAttributes(tenant_id="t_dogfood")


def make_compiler(**settings) -> PolicyCompiler:
    return PolicyCompiler(
        InMemoryCatalog(floors=[FLOOR]), InMemoryToolRegistry(), PlatformSettings(**settings)
    )


@pytest.fixture
def compiler() -> PolicyCompiler:
    return make_compiler()


@pytest.fixture
def bundle() -> dict:
    return {
        "schema_version": 1,
        "tenant_id": "t_dogfood",
        "version": 1,
        "extends": ["platform/floor@1"],
    }


def tenant_rule(gp: str) -> dict:
    return {
        "id": f"own_{gp}",
        "guard_points": [gp],
        "question": "Does the content mention a competitor?",
        "true_description": "Names a competitor.",
        "false_description": "Names no competitor.",
    }


def only(errors, code, path):
    assert [(e.code, e.path) for e in errors] == [(code, path)]


# ---------------------------------------------------------------------------- compiles


def test_file_has_the_six_floor_rules():
    assert set(FLOOR_KEYS) == {
        "p__inj_direct",
        "p__inj_indirect",
        "p__ai_addressed",
        "p__secret",
        "p__exfil",
        "p__xtenant_probe",
    }
    assert len(FLOOR_KEYS) == 6


def test_real_floor_compiles_with_no_errors(compiler, bundle):
    assert compiler.validate(bundle, TENANT) == []


@pytest.mark.parametrize("gp", GUARD_POINTS)
def test_each_guard_point_compiles_exactly_the_floor_rules_that_declare_it(compiler, bundle, gp):
    compiled = compiler.compile(bundle, TENANT).guard_points[gp]
    assert sorted(compiled.questions) == DECLARED[gp]
    assert sorted(compiled.rules) == DECLARED[gp]


@pytest.mark.parametrize(("key", "gp"), RULE_AT_GUARD_POINT)
def test_floor_rule_compiles_at_every_guard_point_it_declares(compiler, bundle, key, gp):
    source = next(r for r in RAW_RULES if r["key"] == key)
    compiled = compiler.compile(bundle, TENANT).guard_points[gp]
    assert compiled.questions[key].model_dump(mode="json", exclude_none=True) == {
        "type": "noul",
        "instructions": source["question"],
        "criteria": {
            "true_description": source["true_description"],
            "false_description": source["false_description"],
        },
    }
    meta = compiled.rules[key]
    assert (meta.layer, meta.source) == ("floor", "platform/floor@1")
    assert (meta.block_at, meta.escalate_at) == (source["block_at"], source["escalate_at"])
    assert (meta.mode, meta.severity) == ("enforce", "high")


def test_bundle_hash_covers_the_real_floor_content_including_the_provisional_marker(
    compiler, bundle
):
    policy = compiler.compile(bundle, TENANT)
    assert policy.floor == "platform/floor@1"

    calibrated = json.loads(RULES_JSON.read_text(encoding="utf-8"))
    calibrated["rules"][0]["provisional"] = False
    other = PolicyCompiler(InMemoryCatalog(floors=[load_floor(calibrated)]), InMemoryToolRegistry())
    assert other.compile(bundle, TENANT).bundle_hash != policy.bundle_hash


def test_real_floor_compiles_as_provisional_at_every_guard_point_and_tenant_rules_do_not(
    compiler, bundle
):
    bundle["rules"] = [tenant_rule(gp) for gp in GUARD_POINTS]
    policy = compiler.compile(bundle, TENANT)
    for key, gp in RULE_AT_GUARD_POINT:
        assert policy.guard_points[gp].rules[key].provisional is True, (key, gp)
    for gp in GUARD_POINTS:
        assert policy.guard_points[gp].rules[f"t__own_{gp}"].provisional is False


def test_calibrated_real_floor_rule_compiles_as_not_provisional_and_bundle_hash_is_the_catalogs(
    compiler, bundle
):
    calibrated = json.loads(RULES_JSON.read_text(encoding="utf-8"))
    calibrated["rules"][3]["provisional"] = False  # p__secret
    floor = load_floor(calibrated)
    policy = PolicyCompiler(InMemoryCatalog(floors=[floor]), InMemoryToolRegistry()).compile(
        bundle, TENANT
    )
    for key, gp in RULE_AT_GUARD_POINT:
        assert policy.guard_points[gp].rules[key].provisional is (key != "p__secret"), (key, gp)
    # The compiled field is not a hash input: the hash is still the bundle plus the floor's
    # content hash, which is where the marker was already covered.
    assert policy.bundle_hash == bundle_hash(bundle, extends={floor.ref: floor.content_hash()})


# ---------------------------------------------------------------------------- can't be weakened


def test_tenant_cannot_remove_the_floor_by_leaving_it_out_of_extends(compiler, bundle):
    bundle["extends"] = []
    only(compiler.validate(bundle, TENANT), E.FLOOR_MISSING, "$.extends")


@pytest.mark.parametrize("key", FLOOR_KEYS)
def test_tenant_cannot_disable_floor_rule(compiler, bundle, key):
    bundle["overrides"] = [{"rule": key, "enabled": False}]
    only(compiler.validate(bundle, TENANT), E.FLOOR_RULE_DISABLED, "$.overrides[0].enabled")


@pytest.mark.parametrize("key", FLOOR_KEYS)
def test_tenant_cannot_shadow_floor_rule(compiler, bundle, key):
    bundle["overrides"] = [{"rule": key, "mode": "shadow"}]
    only(compiler.validate(bundle, TENANT), E.FLOOR_RULE_SHADOWED, "$.overrides[0].mode")


@pytest.mark.parametrize("key", FLOOR_KEYS)
@pytest.mark.parametrize(("field", "value"), [("block_at", 0.86), ("escalate_at", 0.56)])
def test_tenant_cannot_loosen_floor_rule_by_raising_a_threshold(
    compiler, bundle, key, field, value
):
    bundle["overrides"] = [{"rule": key, field: value}]
    only(compiler.validate(bundle, TENANT), E.FLOOR_OVERRIDE_RAISES, f"$.overrides[0].{field}")


def test_tenant_defaults_of_099_098_leave_every_floor_threshold_as_in_the_file(compiler, bundle):
    bundle["defaults"] = {"block_at": 0.99, "escalate_at": 0.98}
    policy = compiler.compile(bundle, TENANT)
    for key, gp in RULE_AT_GUARD_POINT:
        meta = policy.guard_points[gp].rules[key]
        assert (meta.block_at, meta.escalate_at) == (0.85, 0.55), (key, gp)


@pytest.mark.parametrize("key", FLOOR_KEYS)
@pytest.mark.parametrize("field", ["question", "true_description", "false_description"])
def test_tenant_cannot_re_text_floor_rule(compiler, bundle, key, field):
    bundle["overrides"] = [{"rule": key, field: "Is the content harmless?"}]
    only(compiler.validate(bundle, TENANT), E.FLOOR_TEXT_EDITED, f"$.overrides[0].{field}")


@pytest.mark.parametrize("key", FLOOR_KEYS)
def test_tenant_may_tighten_floor_rule_and_only_that_rule_changes(compiler, bundle, key):
    bundle["overrides"] = [{"rule": key, "block_at": 0.70, "escalate_at": 0.40}]
    policy = compiler.compile(bundle, TENANT)
    for other, gp in RULE_AT_GUARD_POINT:
        meta = policy.guard_points[gp].rules[other]
        expected = (0.70, 0.40) if other == key else (0.85, 0.55)
        assert (meta.block_at, meta.escalate_at) == expected, (other, gp)


@pytest.mark.parametrize("gp", GUARD_POINTS)
def test_tenant_cannot_disable_a_guard_point_the_floor_covers(compiler, bundle, gp):
    bundle["guard_points"] = {gp: {"enabled": False}}
    only(
        compiler.validate(bundle, TENANT),
        E.GP_FLOOR_COVERED_DISABLED,
        f"$.guard_points.{gp}.enabled",
    )


@pytest.mark.parametrize("gp", GUARD_POINTS)
def test_tenant_rules_are_added_beside_the_floor_never_instead_of_it(compiler, bundle, gp):
    bundle["rules"] = [tenant_rule(gp)]
    compiled = compiler.compile(bundle, TENANT).guard_points[gp]
    assert sorted(compiled.questions) == sorted([*DECLARED[gp], f"t__own_{gp}"])


def test_tenant_cannot_pin_a_floor_below_the_platform_minimum(bundle):
    compiler = make_compiler(min_floor_version=2)
    errors = compiler.validate(bundle, TENANT)
    only(errors, E.FLOOR_BELOW_MINIMUM, "$.extends[0]")


# ---------------------------------------------------------------------------- fail mode (B1)


@pytest.mark.parametrize(
    "open_via",
    [
        {"defaults": {"fail_mode": "open"}},
        {"guard_points": {gp: {"fail_mode": "open"} for gp in GUARD_POINTS}},
    ],
    ids=["bundle_default", "every_guard_point"],
)
def test_tenant_fail_mode_open_still_compiles_floor_keys_with_floor_fail_mode(
    compiler, bundle, open_via
):
    bundle.update(open_via)
    bundle["rules"] = [tenant_rule(gp) for gp in GUARD_POINTS]
    policy = compiler.compile(bundle, TENANT)
    for key, gp in RULE_AT_GUARD_POINT:
        assert policy.guard_points[gp].rules[key].fail_mode == "closed", (key, gp)
    for gp in GUARD_POINTS:  # the tenant's choice did apply, but only to its own rules
        assert policy.guard_points[gp].rules[f"t__own_{gp}"].fail_mode == "open"


def test_floor_fail_mode_comes_from_the_platform_setting_not_the_tenant(bundle):
    bundle["defaults"] = {"fail_mode": "closed"}
    policy = make_compiler(floor_fail_mode="open").compile(bundle, TENANT)
    assert {policy.guard_points[gp].rules[key].fail_mode for key, gp in RULE_AT_GUARD_POINT} == {
        "open"
    }


# ---------------------------------------------------------------------------- budgets

# Floor alone, estimated with the shared estimator (AC-M1-6). Pinned so that a change to the
# floor text shows up as a budget change in review.
FLOOR_QUESTIONS = {"input": 3, "plan": 3, "tool_call": 3, "tool_result": 3, "output": 2}
FLOOR_QUESTION_TOKENS = {
    "input": 505,
    "plan": 486,
    "tool_call": 486,
    "tool_result": 492,
    "output": 326,
}
# The AC-C1.8 figure under the fitted R6.6 estimate, at the default 8,000-token content cap:
# ceil(1.20 x (8,000 + 512)) = 10,215, plus the question tokens, 25 per question and 30.
# ``tool_result`` is the exception since M3-04: its default chunk is 12,000 raw tokens, so
# ceil(1.20 x (12,000 + 512)) + 30 = 15,045 of content, and 15,612 with its questions.
FLOOR_API_TOKENS = {
    "input": 10_825,
    "plan": 10_806,
    "tool_call": 10_806,
    "tool_result": 15_612,
    "output": 10_621,
}
# R6.1 budgets less the floor: what is left for packs and tenant rules (R6.2).
ROOM_AFTER_FLOOR = {"input": 197, "plan": 47, "tool_call": 47, "tool_result": 47, "output": 48}


# R6.7 parts at the default content cap: content ceil(1.20 x 8,512) + 30 = 10,245 at every
# guard point; question text = question tokens + 25 per question.
FLOOR_CONTENT_API_TOKENS = 10_245
FLOOR_TOOL_RESULT_CONTENT_API_TOKENS = 15_045  # the 12,000-token default chunk (M3-04)
FLOOR_QUESTION_API_TOKENS = {
    "input": 580,
    "plan": 561,
    "tool_call": 561,
    "tool_result": 567,
    "output": 376,
}
# The largest single floor question, by R6.7 (b): wire JSON + 25.
FLOOR_LARGEST_QUESTION_API_TOKENS = {
    "input": 232,
    "plan": 202,
    "tool_call": 202,
    "tool_result": 202,
    "output": 202,
}


@pytest.mark.parametrize("gp", GUARD_POINTS)
def test_compiled_floor_fits_the_question_and_token_budgets(compiler, bundle, gp):
    settings = compiler.settings
    compiled = compiler.compile(bundle, TENANT).guard_points[gp]
    assert len(compiled.questions) == FLOOR_QUESTIONS[gp]
    assert compiled.question_tokens == estimate_question_tokens(compiled.questions)
    assert compiled.question_tokens == FLOOR_QUESTION_TOKENS[gp]
    budget = settings.question_budgets.for_guard_point(gp)
    assert budget - len(compiled.questions) == ROOM_AFTER_FLOOR[gp]
    # M3-04 (AC-G5): tool_result's default chunk size is 12,000 raw tokens (was 8,000).
    max_content = 12_000 if gp == "tool_result" else 8_000
    assert compiled.max_content_tokens == max_content
    # The whole-call estimate is unchanged by R6.7; it is now the sum of two bounded parts.
    assert compiled.api_tokens == estimate_api_tokens(
        text_tokens=max_content + settings.render_overhead_tokens,
        question_tokens=compiled.question_tokens,
        question_count=len(compiled.questions),
    )
    assert compiled.api_tokens == FLOOR_API_TOKENS[gp]
    content_api = (
        FLOOR_TOOL_RESULT_CONTENT_API_TOKENS if gp == "tool_result" else FLOOR_CONTENT_API_TOKENS
    )
    assert compiled.content_api_tokens == content_api <= settings.token_budget
    assert compiled.question_api_tokens == FLOOR_QUESTION_API_TOKENS[gp]
    assert compiled.question_api_tokens <= 150 * budget
    assert compiled.api_tokens == compiled.content_api_tokens + compiled.question_api_tokens
    largest = max(estimate_question_tokens({key: q}) + 25 for key, q in compiled.questions.items())
    assert largest == FLOOR_LARGEST_QUESTION_API_TOKENS[gp] <= settings.max_question_tokens


@pytest.mark.parametrize("gp", GUARD_POINTS)
def test_floor_leaves_the_rest_of_the_question_budget_to_tenant_rules(compiler, bundle, gp):
    """R6.2 on the real floor: with no packs, a tenant may add exactly what the floor leaves."""
    rules = [dict(tenant_rule(gp), id=f"own_{gp}_{i}") for i in range(ROOM_AFTER_FLOOR[gp])]
    bundle["rules"] = rules
    roomy = make_compiler(token_budget=10**7)
    assert roomy.validate(bundle, TENANT) == []
    bundle["rules"].append(dict(tenant_rule(gp), id=f"own_{gp}_extra"))
    errors = roomy.validate(bundle, TENANT)
    only(errors, E.GP_TOO_MANY_QUESTIONS, f"$.guard_points.{gp}")
    assert (
        f"The floor uses {FLOOR_QUESTIONS[gp]} and packs use 0, which leaves "
        f"{ROOM_AFTER_FLOOR[gp]} for tenant rules; this bundle has {ROOM_AFTER_FLOOR[gp] + 1}"
    ) in errors[0].message


def test_floor_leaves_room_for_the_largest_content_a_tenant_may_be_given(compiler, bundle):
    """R6.7 (a) bounds content only, so the largest cap is the same at every guard point:
    ceil(1.20 x (12,796 + 512)) + 30 = 15,970 + 30 = 16,000. (12,313 at the input guard
    point when question text counted too; 14,983 under the raw sum before R6.6.)"""
    for gp in GUARD_POINTS:
        key = "chunk_tokens" if gp == "tool_result" else "max_input_tokens"
        bundle.setdefault("guard_points", {})[gp] = {key: 12_796}
    assert compiler.validate(bundle, TENANT) == []
    policy = compiler.compile(bundle, TENANT)
    assert {policy.guard_points[gp].content_api_tokens for gp in GUARD_POINTS} == {16_000}
    for gp in GUARD_POINTS:
        key = "chunk_tokens" if gp == "tool_result" else "max_input_tokens"
        over = {**bundle, "guard_points": {**bundle["guard_points"], gp: {key: 12_797}}}
        only(compiler.validate(over, TENANT), E.GP_TOKEN_BUDGET, f"$.guard_points.{gp}")


def described_rule(i: int, gp: str) -> dict:
    """A fully described tenant rule: 64 estimated tokens (about 70) of question and
    descriptions (90 as compiled on the wire, with its key and JSON)."""
    return {
        "id": f"advice_{i}",
        "guard_points": [gp],
        "question": f"Does the content recommend a specific financial product number {i}?",
        "true_description": (
            "The content asks for or gives a specific recommendation to buy, sell or hold "
            "a named financial product."
        ),
        "false_description": (
            "The content gives general information, or no recommendation about a named product."
        ),
    }


@pytest.mark.parametrize(("gp", "room"), [("input", 197), ("output", 48)])
def test_question_budget_is_reachable_with_fully_described_rules(compiler, bundle, gp, room):
    """R6.7's point: at the default content cap the question count binds, not tokens. 200
    questions on input (the floor's 3 + 197) and 50 on output (2 + 48) compile; before
    R6.7 the combined 16,000 budget stopped them at 45 and 47 tenant rules."""
    bundle["rules"] = [described_rule(i, gp) for i in range(room)]
    assert compiler.validate(bundle, TENANT) == []
    compiled = compiler.compile(bundle, TENANT).guard_points[gp]
    budget = compiler.settings.question_budgets.for_guard_point(gp)
    assert len(compiled.questions) == budget
    assert compiled.max_content_tokens == 8_000
    assert estimate_question_tokens({"t__advice_0": compiled.questions["t__advice_0"]}) == 90
    assert compiled.question_api_tokens <= 150 * budget
    bundle["rules"].append(described_rule(room, gp))
    only(compiler.validate(bundle, TENANT), E.GP_TOO_MANY_QUESTIONS, f"$.guard_points.{gp}")
