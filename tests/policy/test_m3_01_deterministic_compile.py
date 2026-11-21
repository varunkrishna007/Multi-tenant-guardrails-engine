"""M3-01: deterministic rules in the bundle schema and compiler.

Deny patterns compile under RE2 when the bundle compiles (an invalid one is a validation
error, in the existing ``<area>.<problem>`` style), each has a valid unique id, the number and
size of patterns are bounded (PF-11), and the compiled rules are what the Guard Service runs.
Every pattern here is benign: codenames, token-looking strings, banned phrases.
"""

from __future__ import annotations

import pytest
from policy_fixtures import TOOLS, make_catalog

from guardrail_engine.deterministic import (
    DeterministicAction,
    GuardPointChecks,
    RegexError,
    default_regex_engine,
)
from guardrail_engine.deterministic.adapters.google_re2 import Re2RegexEngine
from guardrail_engine.policy import (
    ErrorCode as E,
)
from guardrail_engine.policy import (
    InMemoryToolRegistry,
    PlatformSettings,
    PolicyCompiler,
    PolicyInvalidError,
)
from guardrail_engine.policy.schema import DETERMINISTIC_ACTIONS


def codes(errors) -> list[tuple[E, str]]:
    return [(e.code, e.path) for e in errors]


def deny(bundle: dict, *patterns: dict) -> dict:
    bundle["deterministic"]["deny_patterns"] = list(patterns)
    return bundle


def test_the_schema_and_the_runtime_agree_on_the_actions():
    assert tuple(a.value for a in DeterministicAction) == DETERMINISTIC_ACTIONS


# ------------------------------------------------------------------ validation (AC-C1.10)


@pytest.mark.parametrize(
    "regex",
    [
        "(a)\\1",  # backreference
        "foo(?=bar)",  # lookahead
        "(?<!x)y",  # lookbehind
        "[unclosed",
        "x{1001}",  # RE2's repeat bound
    ],
)
def test_a_pattern_that_is_not_re2_is_a_validation_error_at_its_path(
    compiler, tenant, bundle, regex
):
    deny(bundle, {"id": "a", "regex": "fine"}, {"id": "b", "regex": regex, "action": "log"})
    errors = compiler.validate(bundle, tenant)
    assert codes(errors) == [(E.DENY_PATTERN_INVALID, "$.deterministic.deny_patterns[1].regex")]
    assert errors[0].message.startswith("not valid RE2: ")


def test_compile_raises_for_an_invalid_pattern_and_compiles_nothing(compiler, tenant, bundle):
    deny(bundle, {"id": "a", "regex": "(a)\\1"})
    with pytest.raises(PolicyInvalidError) as raised:
        compiler.compile(bundle, tenant)
    assert [e.code for e in raised.value.errors] == [E.DENY_PATTERN_INVALID]


@pytest.mark.parametrize("regex", ["a*", "(?:)", "^$", "x?", "(?i)z*"])
def test_a_pattern_that_matches_the_empty_string_is_refused(compiler, tenant, bundle, regex):
    deny(bundle, {"id": "a", "regex": regex})
    errors = compiler.validate(bundle, tenant)
    assert codes(errors) == [(E.DENY_PATTERN_INVALID, "$.deterministic.deny_patterns[0].regex")]
    assert "empty string" in errors[0].message


def test_an_action_outside_the_enum_is_still_its_own_error(compiler, tenant, bundle):
    deny(bundle, {"id": "a", "regex": "x", "action": "quarantine"})
    assert codes(compiler.validate(bundle, tenant)) == [
        (E.DETERMINISTIC_ACTION_INVALID, "$.deterministic.deny_patterns[0].action")
    ]


@pytest.mark.parametrize("rule_id", ["", "Has Space", "UPPER", "a-b", "x" * 41, "naïve"])
def test_a_deny_pattern_id_must_be_a_rule_id(compiler, tenant, bundle, rule_id):
    deny(bundle, {"id": rule_id, "regex": "x"})
    assert codes(compiler.validate(bundle, tenant)) == [
        (E.DENY_PATTERN_ID_INVALID, "$.deterministic.deny_patterns[0].id")
    ]


def test_deny_pattern_ids_are_unique(compiler, tenant, bundle):
    deny(bundle, {"id": "a", "regex": "x"}, {"id": "b", "regex": "y"}, {"id": "a", "regex": "z"})
    assert codes(compiler.validate(bundle, tenant)) == [
        (E.DENY_PATTERN_ID_DUPLICATE, "$.deterministic.deny_patterns[2].id")
    ]


def test_every_problem_of_a_pattern_is_reported_together(compiler, tenant, bundle):
    deny(bundle, {"id": "Bad Id", "regex": "(a)\\1", "action": "mask"})
    assert sorted(code for code, _ in codes(compiler.validate(bundle, tenant))) == sorted(
        [E.DENY_PATTERN_ID_INVALID, E.DETERMINISTIC_ACTION_INVALID, E.DENY_PATTERN_INVALID]
    )


# ------------------------------------------------------------------ size limits (PF-11)


def test_a_pattern_over_the_length_limit_is_refused(tenant, bundle):
    settings = PlatformSettings(min_floor_version=2, max_deny_pattern_chars=20)
    compiler = PolicyCompiler(make_catalog(), InMemoryToolRegistry(TOOLS), settings)
    deny(bundle, {"id": "ok", "regex": "x" * 20}, {"id": "long", "regex": "x" * 21})
    assert codes(compiler.validate(bundle, tenant)) == [
        (E.DENY_PATTERN_TOO_LONG, "$.deterministic.deny_patterns[1].regex")
    ]


def test_too_many_patterns_is_one_error_on_the_list(tenant, bundle):
    settings = PlatformSettings(min_floor_version=2, max_deny_patterns=2)
    compiler = PolicyCompiler(make_catalog(), InMemoryToolRegistry(TOOLS), settings)
    deny(bundle, *({"id": f"p{i}", "regex": f"word{i}"} for i in range(3)))
    assert codes(compiler.validate(bundle, tenant)) == [
        (E.DENY_PATTERNS_TOO_MANY, "$.deterministic.deny_patterns")
    ]


def test_the_default_limits_are_a_hundred_patterns_of_five_hundred_characters():
    settings = PlatformSettings()
    assert (settings.max_deny_patterns, settings.max_deny_pattern_chars) == (100, 500)


def test_a_pattern_over_the_engines_memory_bound_is_a_validation_error(tenant, bundle):
    engine = Re2RegexEngine(pattern_max_mem=64 * 1024)
    compiler = PolicyCompiler(
        make_catalog(), InMemoryToolRegistry(TOOLS), PlatformSettings(min_floor_version=2), engine
    )
    deny(bundle, {"id": "big", "regex": "(\\pL{200}){200}"})  # a small pattern, a huge program
    errors = compiler.validate(bundle, tenant)
    assert [e.code for e in errors] == [E.DENY_PATTERN_INVALID]


# ------------------------------------------------------------------ compiled at compile time


def test_patterns_are_compiled_once_by_the_compiler_not_at_check_time(tenant, bundle):
    compiled_here = []

    class Recording(Re2RegexEngine):
        def compile(self, pattern):
            compiled_here.append(pattern)
            return super().compile(pattern)

    compiler = PolicyCompiler(
        make_catalog(),
        InMemoryToolRegistry(TOOLS),
        PlatformSettings(min_floor_version=2),
        Recording(),
    )
    deny(bundle, {"id": "a", "regex": "alpha[0-9]+", "action": "escalate"})
    policy = compiler.compile(bundle, tenant)
    assert compiled_here == ["alpha[0-9]+"]
    before = list(compiled_here)
    for _ in range(3):  # using the rules compiles nothing more
        policy.checks_for("output").deny_rules[0].regex.spans("alpha12 alpha34")
    assert compiled_here == before


def test_the_compiled_rules_carry_id_action_and_a_working_regex(compiler, tenant, bundle):
    deny(
        bundle,
        {"id": "codename", "regex": "(?i)project\\s+falcon", "action": "block"},
        {"id": "token", "regex": "tok_[a-z0-9]{8}", "action": "redact"},
        {"id": "phrase", "regex": "as discussed offline", "action": "log"},
        {"id": "careful", "regex": "unreleased pricing", "action": "escalate"},
    )
    checks = compiler.compile(bundle, tenant).checks_for("output")
    assert [(r.id, r.rule_id, r.action) for r in checks.deny_rules] == [
        ("codename", "deny__codename", DeterministicAction.BLOCK),
        ("token", "deny__token", DeterministicAction.REDACT),
        ("phrase", "deny__phrase", DeterministicAction.LOG),
        ("careful", "deny__careful", DeterministicAction.ESCALATE),
    ]
    assert checks.deny_rules[0].regex.spans("a Project  Falcon b") == [(2, 17)]
    assert checks.deny_rules[1].regex.spans("tok_abcd1234 and tok_zzzz9999") == [(0, 12), (17, 29)]


def test_the_default_engine_is_the_re2_adapter():
    assert isinstance(default_regex_engine(), Re2RegexEngine)
    assert default_regex_engine() is default_regex_engine()


def test_a_bundle_without_deny_patterns_has_no_deny_rules(compiler, tenant, bundle):
    deny(bundle)
    assert compiler.compile(bundle, tenant).checks_for("output").deny_rules == ()


def test_a_compile_is_equal_to_another_and_the_rules_are_not_in_the_canonical_json(
    compiler, tenant, bundle
):
    first, second = compiler.compile(bundle, tenant), compiler.compile(bundle, tenant)
    assert first == second
    assert first.to_canonical_json() == second.to_canonical_json()
    assert b"_deny_rules" not in first.to_canonical_json()


def test_the_bundle_hash_is_unchanged_by_the_compiler_holding_rules(compiler, tenant, bundle):
    """The hash is over the document as submitted (AC-C2.2): compiling the patterns adds
    nothing to it."""
    with_rules = compiler.compile(bundle, tenant).bundle_hash
    without = compiler.compile(deny(bundle), tenant).bundle_hash
    assert with_rules != without  # the document differs
    assert compiler.compile(bundle, tenant).bundle_hash == without  # and it is stable


# ------------------------------------------------------------------ tool allow-list


def test_the_allow_list_applies_at_plan_and_tool_call_each_with_its_own_list(
    compiler, tenant, bundle
):
    bundle["guard_points"]["tool_call"] = {"enabled": True, "tool_allowlist": ["cms.search"]}
    policy = compiler.compile(bundle, tenant)
    assert policy.checks_for("tool_call").tool_allowlist == ("cms.search",)
    # M3-03: the plan guard point's own list is a plan check, and not the tool_call list.
    assert policy.checks_for("plan").tool_allowlist == policy.guard_points["plan"].tool_allowlist
    assert policy.checks_for("plan").tool_allowlist != ("cms.search",)
    for guard_point in ("input", "tool_result", "output"):
        assert policy.checks_for(guard_point).tool_allowlist is None


def test_an_allow_list_with_an_unregistered_tool_is_still_refused_at_tool_call(
    compiler, tenant, bundle
):
    bundle["guard_points"]["tool_call"] = {"tool_allowlist": ["shell.exec"]}
    assert codes(compiler.validate(bundle, tenant)) == [
        (E.TOOL_NOT_REGISTERED, "$.guard_points.tool_call.tool_allowlist[0]")
    ]


def test_an_empty_allow_list_allows_no_tool(compiler, tenant, bundle):
    bundle["guard_points"]["tool_call"] = {"tool_allowlist": []}
    assert compiler.compile(bundle, tenant).checks_for("tool_call").tool_allowlist == ()


def test_a_disabled_guard_point_has_no_tenant_checks(compiler, tenant, bundle):
    bundle["guard_points"]["plan"] = {"enabled": False, "tool_allowlist": ["cms.search"]}
    assert compiler.compile(bundle, tenant).checks_for("plan") == GuardPointChecks()


def test_regex_errors_carry_the_engines_detail():
    with pytest.raises(RegexError) as raised:
        default_regex_engine().compile("(?=x)")
    assert "(?=" in raised.value.detail
