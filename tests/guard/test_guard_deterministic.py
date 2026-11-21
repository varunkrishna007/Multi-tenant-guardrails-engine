"""M3-01 (AC-G1): deterministic checks in the Guard Service.

A deterministic ``block`` makes **zero** model calls (asserted on the fake's recorded calls);
an ``escalate`` still calls the model and the more severe result wins; ``redact`` replaces the
match before rendering; ``log`` only records. The verdict, the audit record and the span show
which rule fired by id only, never the matched text. The tool allow-list and the cross-tenant
identifier scan are checked here too. Every pattern and value is benign: invented codenames,
token-looking strings and banned phrases.
"""

from __future__ import annotations

import asyncio
import json

import pytest
from guard_fixtures import ALPHA, BETA, GAMMA, Env, bundle, profile, rule
from policy_fixtures import floor_rule, make_floor

from guardrail_engine.decision import Failed, FailureKind
from guardrail_engine.deterministic import (
    CROSS_TENANT_RULE,
    TOOL_ALLOWLIST_RULE,
    TOOL_MISMATCH_RULE,
    DeterministicAction,
    DeterministicKind,
    IdentifierPatternError,
    InMemoryOtherTenantIdentifiers,
    tenant_id_pattern,
)
from guardrail_engine.deterministic.adapters.google_re2 import Re2RegexEngine
from guardrail_engine.gateway import (
    ALERT_XTENANT_PATTERNS_DROPPED,
    InMemoryUsageMeter,
    RecordingAlertSink,
)
from guardrail_engine.guard import (
    AuditRecord,
    Decision,
    GuardConfig,
    Plan,
    Reason,
    ToolResult,
    Turn,
    replay,
)
from guardrail_engine.guard.deterministic import redact_deny_patterns
from guardrail_engine.guard.service import content_sha256
from guardrail_engine.policy import GUARD_POINTS, InMemoryCatalog
from guardrail_engine.telemetry.port import CHECK_ATTRIBUTES

CODENAME = "Project  Falcon"  # matched by (?i)project\s+falcon
TOKEN = "tok_abcd1234"
PHRASE = "as discussed offline"
PRICING = "unreleased pricing"

DENY = [
    {"id": "codename", "regex": r"(?i)project\s+falcon", "action": "block"},
    {"id": "token", "regex": r"tok_[a-z0-9]{8}", "action": "redact"},
    {"id": "phrase", "regex": PHRASE, "action": "log"},
    {"id": "careful", "regex": PRICING, "action": "escalate"},
]


def deny_bundle(tenant: str = ALPHA, patterns=DENY, **kwargs) -> dict:
    doc = bundle(tenant, rules=[rule("adv", gps=GUARD_POINTS)], **kwargs)
    doc["deterministic"] = {"deny_patterns": list(patterns)}
    return doc


def hits_of(verdict) -> dict[str, tuple[str, int]]:
    return {h.rule: (h.action.value, h.count) for h in verdict.deterministic}


def everything_recorded(verdict, record: AuditRecord, spans: list[dict]) -> str:
    """All that the verdict, the audit record and the span say, as one string."""
    return "\n".join(
        [verdict.model_dump_json(), record.model_dump_json(), json.dumps(spans, default=str)]
    )


class Spans:
    """A telemetry port that keeps each check span's attributes."""

    def __init__(self) -> None:
        self.ended: list[dict] = []

    def start_check(self):
        spans = self

        class Trace:
            def model_call_started(self) -> None:
                pass

            def model_call_ended(self, attributes) -> None:
                pass

            def end(self, attributes, *, error: bool = False) -> None:
                spans.ended.append(dict(attributes))

        return Trace()


# ------------------------------------------------------------------ AC-G1: block


@pytest.mark.parametrize("guard_point", GUARD_POINTS)
async def test_ac_g1_a_deterministic_block_makes_zero_model_calls(guard_point):
    spans = Spans()
    async with Env(telemetry=spans) as env:
        await env.publish(deny_bundle())
        verdict = await env.check(ALPHA, guard_point, f"Notes on {CODENAME} are attached.")
    assert (verdict.decision, verdict.reason) == (Decision.BLOCK, Reason.DETERMINISTIC)
    assert env.fake.calls == []  # AC-G1: zero model calls
    assert not verdict.model_called and verdict.provider_calls == 0
    assert verdict.model_id is None and verdict.rules == () and verdict.fired == ()
    assert hits_of(verdict) == {"deny__codename": ("block", 1)}
    assert not verdict.released and not verdict.retryable
    assert env.audit.verdicts == [verdict]
    assert spans.ended[0]["guardrail.deterministic_rules"] == ("deny__codename",)
    assert spans.ended[0]["guardrail.model_called"] is False


async def test_a_deterministic_block_stands_when_the_model_is_down_or_would_allow():
    """B1 rule 3: deterministic checks count whether or not the model answers."""
    async with Env() as env:
        await env.publish(deny_bundle())
        env.fake.always(Failed(kind=FailureKind.UNAVAILABLE))
        down = await env.check(ALPHA, "output", f"{CODENAME}")
    assert (down.decision, down.reason) == (Decision.BLOCK, Reason.DETERMINISTIC)
    assert down.failure_kind is None and env.fake.calls == []


async def test_the_hit_records_the_rule_by_id_kind_layer_and_count_never_the_text():
    spans = Spans()
    async with Env(telemetry=spans) as env:
        await env.publish(deny_bundle())
        content = f"first {CODENAME}, then project falcon again, and {PHRASE}."
        verdict = await env.check(ALPHA, "output", content)
    record = env.audit.records[0]
    assert hits_of(verdict) == {"deny__codename": ("block", 2), "deny__phrase": ("log", 1)}
    hit = verdict.deterministic[0]
    assert (hit.kind, hit.layer, hit.rule) == (
        DeterministicKind.DENY_PATTERN,
        "tenant",
        "deny__codename",
    )
    assert record.deterministic == verdict.deterministic
    recorded = everything_recorded(verdict, record, spans.ended)
    for text in ("falcon", "Falcon", PHRASE, "first", "then"):
        assert text not in recorded
    assert verdict.detail is None
    assert verdict.content_sha256 == content_sha256(content)  # a hash, as for any check


async def test_every_rule_that_fires_is_listed_and_a_block_wins_over_an_escalate():
    async with Env() as env:
        await env.publish(deny_bundle())
        verdict = await env.check(ALPHA, "output", f"{CODENAME} and {PRICING} and {TOKEN}")
    assert (verdict.decision, verdict.reason) == (Decision.BLOCK, Reason.DETERMINISTIC)
    assert hits_of(verdict) == {"deny__codename": ("block", 1), "deny__careful": ("escalate", 1)}
    assert env.fake.calls == []
    # A redact pattern isn't applied when the content is never sent.
    assert "deny__token" not in hits_of(verdict)


async def test_the_size_limit_is_reported_as_a_deterministic_rule():
    async with Env() as env:
        await env.publish(deny_bundle(guard_points={"output": {"max_input_tokens": 10}}))
        verdict = await env.check(ALPHA, "output", "x" * 400)
    assert verdict.reason is Reason.CONTENT_TOO_LARGE and env.fake.calls == []
    [hit] = verdict.deterministic
    assert (hit.rule, hit.kind, hit.layer) == ("size_limit", DeterministicKind.SIZE_LIMIT, "floor")


async def test_the_deny_patterns_see_the_content_as_submitted_not_the_redacted_text():
    async with Env() as env:
        patterns = [{"id": "mail", "regex": r"jo@example\.com", "action": "block"}]
        await env.publish(deny_bundle(patterns=patterns))
        verdict = await env.check(ALPHA, "output", "Write to jo@example.com today.")
    assert verdict.reason is Reason.DETERMINISTIC and env.fake.calls == []


async def test_a_deny_pattern_is_checked_against_content_not_context():
    async with Env() as env:
        await env.publish(deny_bundle())
        verdict = await env.check(
            ALPHA, "output", "Hello.", conversation=(Turn("user", f"about {CODENAME}"),)
        )
    assert verdict.decision is Decision.ALLOW and verdict.deterministic == ()
    assert len(env.fake.calls) == 1


async def test_a_tenant_without_deny_patterns_has_no_deterministic_hits():
    async with Env() as env:
        await env.publish(bundle(ALPHA, rules=[rule("adv")]))
        verdict = await env.check(ALPHA, "output", f"{CODENAME} {TOKEN}")
    assert verdict.decision is Decision.ALLOW and verdict.deterministic == ()
    assert TOKEN in env.fake.calls[0].input


async def test_one_tenants_patterns_never_apply_to_another_tenant():
    async with Env() as env:
        await env.publish(deny_bundle(ALPHA))
        await env.publish(bundle(BETA, rules=[rule("adv")]))
        beta = await env.check(BETA, "output", CODENAME)
        alpha = await env.check(ALPHA, "output", CODENAME)
    assert beta.decision is Decision.ALLOW and alpha.decision is Decision.BLOCK


# ------------------------------------------------------------------ AC-G1: escalate


async def test_ac_g1_a_deterministic_escalate_still_calls_the_model_and_escalates_on_allow():
    spans = Spans()
    async with Env(telemetry=spans) as env:
        await env.publish(deny_bundle())
        verdict = await env.check(ALPHA, "output", f"A note on {PRICING}.")
    assert len(env.fake.calls) == 1  # the model still runs
    assert verdict.model_called
    assert (verdict.decision, verdict.reason) == (Decision.ESCALATE, Reason.DETERMINISTIC)
    assert hits_of(verdict) == {"deny__careful": ("escalate", 1)}
    assert verdict.fired == () and verdict.rules  # the model's rules were evaluated and quiet
    assert not verdict.released
    assert spans.ended[0]["guardrail.deterministic_rules"] == ("deny__careful",)
    assert PRICING not in everything_recorded(verdict, env.audit.records[0], spans.ended)


async def test_ac_g1_the_more_severe_result_wins_when_the_model_blocks():
    async with Env() as env:
        env.fake.set_noul("t__adv", 0.95)
        await env.publish(deny_bundle())
        verdict = await env.check(ALPHA, "output", PRICING)
    assert (verdict.decision, verdict.reason) == (Decision.BLOCK, Reason.POLICY)
    assert [f.key for f in verdict.fired] == ["t__adv"]
    assert hits_of(verdict) == {"deny__careful": ("escalate", 1)}  # still recorded


async def test_ac_g1_a_model_escalate_and_a_deterministic_escalate_agree():
    async with Env() as env:
        env.fake.set_noul("t__adv", 0.6)
        await env.publish(deny_bundle())
        verdict = await env.check(ALPHA, "output", PRICING)
    assert (verdict.decision, verdict.reason) == (Decision.ESCALATE, Reason.POLICY)
    assert hits_of(verdict) == {"deny__careful": ("escalate", 1)}


async def test_ac_g1_a_model_failure_blocks_over_a_deterministic_escalate():
    async with Env() as env:
        env.fake.always(Failed(kind=FailureKind.UNAVAILABLE))
        await env.publish(deny_bundle())
        verdict = await env.check(ALPHA, "output", PRICING)
    assert (verdict.decision, verdict.reason) == (Decision.BLOCK, Reason.MODEL_FAILURE)
    assert hits_of(verdict) == {"deny__careful": ("escalate", 1)}


async def test_a_deterministic_escalate_is_not_loosened_by_a_less_severe_model():
    """Whatever the model says below escalate, the content is held."""
    async with Env() as env:
        env.fake.set_noul("t__adv", 0.01)
        await env.publish(deny_bundle())
        verdict = await env.check(ALPHA, "output", PRICING)
    assert verdict.decision is Decision.ESCALATE


# ------------------------------------------------------------------ AC-G1: redact


async def test_ac_g1_redact_replaces_the_match_before_rendering():
    spans = Spans()
    async with Env(telemetry=spans) as env:
        await env.publish(deny_bundle())
        content = f"The key is {TOKEN} and also {TOKEN.replace('abcd', 'zzzz')}."
        verdict = await env.check(ALPHA, "output", content)
    assert verdict.decision is Decision.ALLOW
    [call] = env.fake.calls
    assert TOKEN not in call.input and "tok_zzzz1234" not in call.input
    assert "The key is [REDACTED] and also [REDACTED]." in call.input
    assert hits_of(verdict) == {"deny__token": ("redact", 2)}
    assert verdict.content_sha256 == content_sha256(content)  # of the pre-redaction content
    assert "tok_" not in everything_recorded(verdict, env.audit.records[0], spans.ended)


async def test_redact_applies_to_the_context_too_and_counts_it():
    context = (
        Turn("user", f"my token is {TOKEN}"),
        Plan(f'{{"use": "{TOKEN}"}}'),
        ToolResult("cms.search", f"found {TOKEN}"),
    )
    async with Env() as env:
        await env.publish(deny_bundle())
        verdict = await env.check(ALPHA, "output", "Nothing here.", conversation=context)
    [call] = env.fake.calls
    assert TOKEN not in call.input and call.input.count("[REDACTED]") == 3
    assert hits_of(verdict) == {"deny__token": ("redact", 3)}


async def test_redact_runs_before_the_pii_detector_and_both_apply():
    async with Env() as env:
        await env.publish(deny_bundle())
        verdict = await env.check(ALPHA, "output", f"{TOKEN} from jo@example.com")
    [call] = env.fake.calls
    assert "[REDACTED] from [EMAIL]@example.com" in call.input
    assert hits_of(verdict) == {"deny__token": ("redact", 1)}
    assert verdict.pii_redacted and next(iter(verdict.pii_redacted.values())) == 1


async def test_a_redact_pattern_that_matches_nothing_is_not_a_hit():
    async with Env() as env:
        await env.publish(deny_bundle())
        verdict = await env.check(ALPHA, "output", "Nothing to see.")
    assert verdict.deterministic == () and "[REDACTED]" not in env.fake.calls[0].input


def test_overlapping_redactions_become_one_placeholder_and_count_per_rule():
    engine = Re2RegexEngine()
    from guardrail_engine.deterministic import DenyRule

    rules = [
        DenyRule("a", DeterministicAction.REDACT, engine.compile("abc")),
        DenyRule("b", DeterministicAction.REDACT, engine.compile("bcd")),
        DenyRule("c", DeterministicAction.BLOCK, engine.compile("xyz")),
    ]
    out, counts = redact_deny_patterns(rules, "1 abcd 2 abc 3 xyz")
    assert out == "1 [REDACTED] 2 [REDACTED] 3 xyz"
    assert counts == {"a": 2, "b": 1}
    assert redact_deny_patterns(rules, "nothing") == ("nothing", {})


# ------------------------------------------------------------------ AC-G1: log


async def test_ac_g1_log_only_records():
    async with Env() as env:
        await env.publish(deny_bundle())
        content = f"Yes, {PHRASE}."
        verdict = await env.check(ALPHA, "output", content)
    assert (verdict.decision, verdict.reason) == (Decision.ALLOW, Reason.POLICY)
    assert verdict.released
    assert hits_of(verdict) == {"deny__phrase": ("log", 1)}
    assert content in env.fake.calls[0].input  # unchanged
    assert env.audit.records[0].deterministic == verdict.deterministic


# ------------------------------------------------------------------ replay


async def test_replay_keeps_a_deterministic_escalate_under_looser_model_thresholds():
    async with Env() as env:
        env.fake.set_noul("t__adv", 0.6)
        await env.publish(deny_bundle())
        await env.check(ALPHA, "output", PRICING)
    [record] = env.audit.records
    assert record.reason is Reason.POLICY and record.decision is Decision.ESCALATE
    from guardrail_engine.guard import Thresholds

    looser = replay(record, {"t__adv": Thresholds(block_at=0.99, escalate_at=0.9)})
    assert (looser.decision, looser.reason) == (Decision.ESCALATE, Reason.DETERMINISTIC)
    stricter = replay(record, {"t__adv": Thresholds(block_at=0.55, escalate_at=0.5)})
    assert (stricter.decision, stricter.reason) == (Decision.BLOCK, Reason.POLICY)


async def test_replay_returns_a_deterministic_block_as_stored():
    async with Env() as env:
        await env.publish(deny_bundle())
        await env.check(ALPHA, "output", CODENAME)
    replayed = replay(env.audit.records[0])
    assert (replayed.decision, replayed.reason, replayed.recomputed) == (
        Decision.BLOCK,
        Reason.DETERMINISTIC,
        False,
    )


async def test_an_earlier_audit_record_without_the_field_still_loads():
    async with Env() as env:
        await env.publish(deny_bundle())
        await env.check(ALPHA, "output", "Hello.")
    data = json.loads(env.audit.records[0].model_dump_json())
    data.pop("deterministic")
    assert AuditRecord.model_validate(data).deterministic == ()


# ------------------------------------------------------------------ the tool allow-list


def allowlisted(*tools: str) -> dict:
    return deny_bundle(patterns=[], guard_points={"tool_call": {"tool_allowlist": list(tools)}})


async def test_a_tool_outside_the_allow_list_is_blocked_with_no_model_call():
    spans = Spans()
    async with Env(telemetry=spans) as env:
        await env.publish(allowlisted("cms.search"))
        verdict = await env.check(ALPHA, "tool_call", '{"id": 7}', tool="claims.status")
    assert (verdict.decision, verdict.reason) == (Decision.BLOCK, Reason.DETERMINISTIC)
    assert env.fake.calls == []
    [hit] = verdict.deterministic
    assert (hit.rule, hit.kind, hit.layer) == (
        TOOL_ALLOWLIST_RULE,
        DeterministicKind.TOOL_ALLOWLIST,
        "tenant",
    )
    assert spans.ended[0]["guardrail.deterministic_rules"] == (TOOL_ALLOWLIST_RULE,)
    assert "claims.status" not in everything_recorded(verdict, env.audit.records[0], spans.ended)


async def test_a_tool_on_the_allow_list_goes_on_to_the_model():
    async with Env() as env:
        await env.publish(allowlisted("cms.search", "claims.status"))
        verdict = await env.check(ALPHA, "tool_call", '{"q": "x"}', tool="cms.search")
    assert verdict.decision is Decision.ALLOW and verdict.deterministic == ()
    assert len(env.fake.calls) == 1


@pytest.mark.parametrize("tool", [None, "", "CMS.SEARCH", "cms.search "])
async def test_a_call_that_names_no_listed_tool_is_blocked(tool):
    async with Env() as env:
        await env.publish(allowlisted("cms.search"))
        verdict = await env.check(ALPHA, "tool_call", "{}", tool=tool)
    assert verdict.reason is Reason.DETERMINISTIC and env.fake.calls == []


async def test_an_empty_allow_list_allows_no_tool():
    async with Env() as env:
        await env.publish(allowlisted())
        verdict = await env.check(ALPHA, "tool_call", "{}", tool="cms.search")
    assert verdict.reason is Reason.DETERMINISTIC


async def test_without_an_allow_list_any_tool_may_be_called():
    async with Env() as env:
        await env.publish(deny_bundle(patterns=[]))
        verdict = await env.check(ALPHA, "tool_call", "{}", tool="anything.at.all")
    assert verdict.decision is Decision.ALLOW and verdict.deterministic == ()


async def test_the_allow_list_is_not_enforced_outside_tool_call():
    async with Env() as env:
        await env.publish(allowlisted("cms.search"))
        output = await env.check(ALPHA, "output", "Hello.", tool="claims.status")
        plan = await env.check(ALPHA, "plan", "{}", tool="claims.status")  # own list: M3-03
    assert output.decision is Decision.ALLOW and plan.decision is Decision.ALLOW


async def test_a_tool_that_is_not_text_is_an_invalid_request():
    async with Env() as env:
        await env.publish(allowlisted("cms.search"))
        verdict = await env.check(ALPHA, "tool_call", "{}", tool=["cms.search"])
    assert (verdict.decision, verdict.reason) == (Decision.BLOCK, Reason.INVALID_REQUEST)
    assert env.fake.calls == []


# -- the tool the content names must be the tool the check says


async def test_content_naming_another_tool_than_the_checked_one_is_blocked():
    """The allow-list sees ``cms.search``; the content (and so the model) sees
    ``claims.purge``. The check blocks the disagreement itself."""
    spans = Spans()
    async with Env(telemetry=spans) as env:
        await env.publish(allowlisted("cms.search"))
        verdict = await env.check(
            ALPHA, "tool_call", '{"tool": "claims.purge", "id": 7}', tool="cms.search"
        )
    assert (verdict.decision, verdict.reason) == (Decision.BLOCK, Reason.DETERMINISTIC)
    assert env.fake.calls == []
    [hit] = verdict.deterministic
    assert (hit.rule, hit.kind, hit.action, hit.layer) == (
        TOOL_MISMATCH_RULE,
        DeterministicKind.TOOL_MISMATCH,
        DeterministicAction.BLOCK,
        "floor",
    )
    assert spans.ended[0]["guardrail.deterministic_rules"] == (TOOL_MISMATCH_RULE,)
    assert "claims.purge" not in everything_recorded(verdict, env.audit.records[0], spans.ended)


@pytest.mark.parametrize(
    "content",
    [
        '{"tool": "claims.purge"}',
        '  {"id": 1, "tool": "CMS.SEARCH"}',  # exact match only
        '{"tool": "claims.purge", "tool": "cms.search"}',  # a duplicate key can't hide it
        '{"tool": "cms.search", "tool": "claims.purge"}',
        '{"tool": ["cms.search"]}',  # not text
        '{"tool": null}',
        '{"tool": 7}',
    ],
)
async def test_any_top_level_tool_that_differs_is_a_mismatch(content):
    async with Env() as env:
        await env.publish(deny_bundle(patterns=[]))  # no allow-list: the mismatch is floor
        verdict = await env.check(ALPHA, "tool_call", content, tool="cms.search")
    assert verdict.reason is Reason.DETERMINISTIC and env.fake.calls == []
    assert hits_of(verdict) == {TOOL_MISMATCH_RULE: ("block", 1)}


@pytest.mark.parametrize(
    "content",
    [
        '{"tool": "cms.search", "q": "x"}',
        '{"name": "Alice", "q": "x"}',  # "name" is an ordinary argument key
        '{"tool": "cms.search", "name": "Alice"}',
        '{"q": "x", "arguments": {"tool": "claims.purge", "name": "other"}}',  # nested: ignored
        '{"id": 7}',
        "{}",
        "[1, 2]",  # not an object
        '["tool"]',
        "not json at all",
        '{"tool": "claims.purge"',  # not valid JSON: nothing to compare
        "plain text naming claims.purge",
        '"tool"',
    ],
)
async def test_content_that_agrees_or_is_not_a_json_object_is_not_a_mismatch(content):
    async with Env() as env:
        await env.publish(allowlisted("cms.search"))
        verdict = await env.check(ALPHA, "tool_call", content, tool="cms.search")
    assert verdict.decision is Decision.ALLOW and verdict.deterministic == ()
    assert len(env.fake.calls) == 1


async def test_the_mismatch_check_runs_at_tool_call_only_and_needs_a_checked_tool():
    async with Env() as env:
        await env.publish(deny_bundle(patterns=[]))
        output = await env.check(ALPHA, "output", '{"tool": "claims.purge"}', tool="cms.search")
        result = await env.check(ALPHA, "tool_result", '{"tool": "x"}', tool="cms.search")
        untyped = await env.check(ALPHA, "tool_call", '{"tool": "claims.purge"}')  # no tool
    assert output.decision is Decision.ALLOW and result.decision is Decision.ALLOW
    assert untyped.decision is Decision.ALLOW  # nothing to compare, and no allow-list is set


async def test_the_allow_list_and_a_mismatch_both_show_when_both_fire():
    async with Env() as env:
        await env.publish(allowlisted("cms.search"))
        verdict = await env.check(ALPHA, "tool_call", '{"tool": "claims.purge"}', tool="x.y")
    assert hits_of(verdict) == {TOOL_ALLOWLIST_RULE: ("block", 1), TOOL_MISMATCH_RULE: ("block", 1)}


async def test_the_allow_list_judges_the_checked_tool_not_the_name_in_the_content():
    """``CheckContext.tool`` is the tool the runtime will execute. A listed
    ``tool`` with content that names nothing passes; an unlisted one blocks even when the
    content claims a listed name (which is also a mismatch)."""
    async with Env() as env:
        await env.publish(allowlisted("cms.search"))
        listed = await env.check(ALPHA, "tool_call", '{"q": "x"}', tool="cms.search")
        unlisted = await env.check(ALPHA, "tool_call", '{"tool": "cms.search"}', tool="claims.x")
    assert listed.decision is Decision.ALLOW
    assert unlisted.reason is Reason.DETERMINISTIC and TOOL_ALLOWLIST_RULE in hits_of(unlisted)


async def test_a_disabled_guard_point_has_no_tenant_deterministic_checks():
    floor = make_floor(
        1,
        floor_rule(
            "p__only_output",
            ("output",),
            question="Does it leak a secret?",
            true_description="Leaks one.",
            false_description="Leaks none.",
            block_at=0.85,
            escalate_at=0.55,
        ),
    )
    doc = deny_bundle(guard_points={"plan": {"enabled": False}})
    async with Env(catalog=InMemoryCatalog(floors=[floor])) as env:
        await env.publish(doc)
        verdict = await env.check(ALPHA, "plan", f"{CODENAME}")
    assert (verdict.decision, verdict.reason) == (Decision.ALLOW, Reason.NO_QUESTIONS)


# ------------------------------------------------------------------ cross-tenant identifiers

ALPHA_ORDER = "ALP-ORD-4417"
BETA_INVOICE = "BET-INV-9082"


def two_tenants() -> InMemoryOtherTenantIdentifiers:
    """Two seeded tenants, each with its own identifier pattern; the third (``t_gamma``) is
    registered with none, so only its id is scanned for."""
    return InMemoryOtherTenantIdentifiers(
        {
            ALPHA: [r"ALP-ORD-[0-9]{4}"],
            BETA: [r"BET-INV-[0-9]{4}"],
            GAMMA: [],
        }
    )


async def xtenant_env(**kwargs) -> Env:
    env = Env(other_tenants=two_tenants(), **kwargs)
    await env.publish(bundle(ALPHA, rules=[rule("adv", gps=GUARD_POINTS)]))
    await env.publish(bundle(BETA, rules=[rule("adv", gps=GUARD_POINTS)]))
    return env


@pytest.mark.parametrize("guard_point", ["tool_result", "output"])
async def test_tenant_b_identifier_in_tenant_a_content_is_a_deterministic_block(guard_point):
    spans = Spans()
    async with await xtenant_env(telemetry=spans) as env:
        verdict = await env.check(ALPHA, guard_point, f"Your invoice is {BETA_INVOICE}.")
    assert (verdict.decision, verdict.reason) == (Decision.BLOCK, Reason.DETERMINISTIC)
    assert env.fake.calls == []  # zero model calls
    [hit] = verdict.deterministic
    assert (hit.rule, hit.kind, hit.action, hit.layer) == (
        CROSS_TENANT_RULE,
        DeterministicKind.CROSS_TENANT,
        DeterministicAction.BLOCK,
        "floor",
    )
    recorded = everything_recorded(verdict, env.audit.records[0], spans.ended)
    assert BETA_INVOICE not in recorded and BETA not in recorded  # and not whose it was
    assert spans.ended[0]["guardrail.deterministic_rules"] == (CROSS_TENANT_RULE,)


@pytest.mark.parametrize("guard_point", ["tool_result", "output"])
async def test_tenant_as_own_identifiers_pass(guard_point):
    async with await xtenant_env() as env:
        verdict = await env.check(ALPHA, guard_point, f"Order {ALPHA_ORDER} for {ALPHA} shipped.")
    assert verdict.decision is Decision.ALLOW and verdict.deterministic == ()
    assert len(env.fake.calls) == 1


async def test_it_is_symmetric_tenant_a_identifier_in_tenant_b_output_blocks():
    async with await xtenant_env() as env:
        verdict = await env.check(BETA, "output", f"See {ALPHA_ORDER}.")
        own = await env.check(BETA, "output", f"See {BETA_INVOICE}.")
    assert verdict.reason is Reason.DETERMINISTIC and own.decision is Decision.ALLOW


@pytest.mark.parametrize(
    "text",
    [
        f"tenant {BETA} asked",  # another tenant's id
        "TENANT T_BETA ASKED",  # in any letter case
        f"/data/{BETA}/orders",
        f"{BETA}_orders",  # followed by a separator
        f"key={BETA}",
        BETA,
    ],
)
async def test_another_tenants_id_is_found_wherever_it_stands_alone(text):
    async with await xtenant_env() as env:
        verdict = await env.check(ALPHA, "output", text)
    assert verdict.reason is Reason.DETERMINISTIC


@pytest.mark.parametrize("text", ["t_betamax", "xt_beta", "t_bet", "beta", "t_alphabet"])
async def test_an_id_that_only_contains_another_is_not_a_match(text):
    async with await xtenant_env() as env:
        verdict = await env.check(ALPHA, "output", text)
    assert verdict.decision is Decision.ALLOW


async def test_a_tenants_id_that_extends_anothers_isnt_blocked_for_its_own_use():
    ids = InMemoryOtherTenantIdentifiers({"t_acme": [], "t_acmeinc": []})
    async with Env(other_tenants=ids, tenants=[profile("t_acme"), profile("t_acmeinc")]) as env:
        await env.publish(bundle("t_acme", rules=[rule("adv")]))
        await env.publish(bundle("t_acmeinc", rules=[rule("adv")]))
        longer_own = await env.check("t_acmeinc", "output", "I am t_acmeinc.")
        shorter_own = await env.check("t_acme", "output", "I am t_acme.")
        leak = await env.check("t_acmeinc", "output", "That is t_acme's.")
    assert longer_own.decision is Decision.ALLOW and shorter_own.decision is Decision.ALLOW
    assert leak.reason is Reason.DETERMINISTIC


@pytest.mark.parametrize("guard_point", ["input", "plan", "tool_call"])
async def test_the_scan_runs_at_tool_result_and_output_only(guard_point):
    async with await xtenant_env() as env:
        verdict = await env.check(ALPHA, guard_point, f"About {BETA_INVOICE} and {BETA}.")
    assert verdict.deterministic == () and len(env.fake.calls) == 1


async def test_the_scan_is_on_the_content_not_the_context():
    async with await xtenant_env() as env:
        verdict = await env.check(
            ALPHA, "output", "Hello.", conversation=(Turn("user", f"my {BETA_INVOICE}"),)
        )
    assert verdict.decision is Decision.ALLOW


async def test_the_scan_runs_whether_or_not_the_model_answers():
    async with await xtenant_env() as env:
        env.fake.always(Failed(kind=FailureKind.TIMEOUT))
        verdict = await env.check(ALPHA, "output", BETA_INVOICE)
    assert (verdict.decision, verdict.reason) == (Decision.BLOCK, Reason.DETERMINISTIC)
    assert verdict.failure_kind is None and env.fake.calls == []


async def test_the_scan_runs_at_a_guard_point_with_no_questions_at_all():
    """The floor here covers only ``input``, so ``output`` has no questions and no model call:
    the scan still blocks (and a clean output is allowed with ``no_questions``)."""
    floor = make_floor(
        1,
        floor_rule(
            "p__only_input",
            ("input",),
            question="Does it leak a secret?",
            true_description="Leaks one.",
            false_description="Leaks none.",
            block_at=0.85,
            escalate_at=0.55,
        ),
    )
    async with Env(other_tenants=two_tenants(), catalog=InMemoryCatalog(floors=[floor])) as env:
        await env.publish(bundle(ALPHA, guard_points={"output": {"enabled": False}}))
        leak = await env.check(ALPHA, "output", BETA_INVOICE)
        clean = await env.check(ALPHA, "output", "Hello.")
    assert (leak.decision, leak.reason) == (Decision.BLOCK, Reason.DETERMINISTIC)
    assert (clean.decision, clean.reason) == (Decision.ALLOW, Reason.NO_QUESTIONS)
    assert env.fake.calls == []


async def test_a_tenant_cannot_loosen_the_scan_with_its_own_configuration():
    """The scan reads nothing from the bundle: neither a log-only deny pattern for the same
    text, a shadow rule, nor a raised threshold changes it."""
    doc = bundle(
        ALPHA,
        rules=[rule("adv", gps=GUARD_POINTS, mode="shadow", block_at=0.99, escalate_at=0.98)],
    )
    doc["deterministic"] = {
        "deny_patterns": [{"id": "inv", "regex": r"BET-INV-[0-9]{4}", "action": "log"}]
    }
    async with Env(other_tenants=two_tenants()) as env:
        await env.publish(doc)
        verdict = await env.check(ALPHA, "output", BETA_INVOICE)
    assert verdict.reason is Reason.DETERMINISTIC and env.fake.calls == []
    assert hits_of(verdict) == {"deny__inv": ("log", 1), CROSS_TENANT_RULE: ("block", 1)}


async def test_a_newly_registered_tenant_is_scanned_for_once_the_rebuild_lands():
    source = two_tenants()
    async with Env(other_tenants=source) as env:
        await env.publish(bundle(ALPHA, rules=[rule("adv")]))
        before = await env.check(ALPHA, "output", "see t_delta and DEL-7-1234")
        source.register("t_delta", r"DEL-7-[0-9]{4}")
        stale = await env.check(ALPHA, "output", "see DEL-7-1234")  # the previous set
        await env.service._scanner.wait_for_rebuild()
        after = await env.check(ALPHA, "output", "see DEL-7-1234")
        source.remove("t_delta")
        await env.check(ALPHA, "output", "Hello.")
        await env.service._scanner.wait_for_rebuild()
        removed = await env.check(ALPHA, "output", "see t_delta and DEL-7-1234")
    assert before.decision is Decision.ALLOW
    assert stale.decision is Decision.ALLOW  # still the set built before the registration
    assert after.reason is Reason.DETERMINISTIC
    assert removed.decision is Decision.ALLOW


async def test_without_a_source_the_scan_finds_nothing():
    """The default until a real source is wired (after M2-01): documented, and pinned."""
    async with Env() as env:
        await env.publish(bundle(ALPHA, rules=[rule("adv")]))
        verdict = await env.check(ALPHA, "output", f"{BETA} {BETA_INVOICE}")
    assert verdict.decision is Decision.ALLOW and verdict.deterministic == ()


class Static:
    """A source holding raw patterns (not validated: for a source that went wrong)."""

    def __init__(self, by_tenant, version=1) -> None:
        self.by_tenant = by_tenant
        self.current = version

    async def version(self):
        return self.current

    async def patterns_by_tenant(self):
        return self.by_tenant


async def test_a_source_that_fails_blocks_closed_and_sends_nothing():
    class Down:
        async def version(self):
            return 1

        async def patterns_by_tenant(self):
            raise ConnectionError("directory unavailable: secret-host.internal")

    async with Env(other_tenants=Down()) as env:
        await env.publish(bundle(ALPHA, rules=[rule("adv")]))
        verdict = await env.check(ALPHA, "output", "Hello.")
        other = await env.check(ALPHA, "input", "Hello.")  # no scan, so no dependency
    assert (verdict.decision, verdict.reason) == (Decision.BLOCK, Reason.INTERNAL_ERROR)
    assert verdict.detail == "cross-tenant identifier scan failed: ConnectionError"
    assert "secret-host" not in verdict.model_dump_json()
    assert not verdict.model_called and other.decision is Decision.ALLOW
    assert len(env.fake.calls) == 1  # only the input check reached the model


async def test_a_source_whose_version_raises_blocks_closed_too():
    class NoVersion(Static):
        async def version(self):
            raise TimeoutError("etag lookup")

    async with Env(other_tenants=NoVersion({})) as env:
        await env.publish(bundle(ALPHA, rules=[rule("adv")]))
        verdict = await env.check(ALPHA, "tool_result", "Hello.")
    assert (verdict.decision, verdict.reason) == (Decision.BLOCK, Reason.INTERNAL_ERROR)
    assert env.fake.calls == []


async def test_a_source_that_recovers_stops_blocking_and_a_failed_rebuild_keeps_no_stale_set():
    source = Static({BETA: [r"BET-INV-[0-9]{4}"]})
    wait_for_rebuild = GuardConfig(pointer_ttl_s=60.0, identifier_max_stale_s=0)  # stale-wait off
    async with Env(other_tenants=source, config=wait_for_rebuild) as env:
        await env.publish(bundle(ALPHA, rules=[rule("adv")]))
        assert (await env.check(ALPHA, "output", BETA_INVOICE)).reason is Reason.DETERMINISTIC
        source.current = 2
        source.by_tenant = None  # the next fetch blows up: iterating None
        failed = await env.check(ALPHA, "output", "Hello.")
        source.by_tenant = {BETA: [r"BET-INV-[0-9]{4}"]}
        recovered = await env.check(ALPHA, "output", "Hello.")
    assert (failed.decision, failed.reason) == (Decision.BLOCK, Reason.INTERNAL_ERROR)
    assert recovered.decision is Decision.ALLOW


# -- a bad tenant is dropped, the others are not blocked


async def test_a_tenant_whose_patterns_do_not_compile_is_dropped_and_the_others_still_scan():
    """B's patterns hold a lookahead RE2 can't run: B is dropped from the scan, and A's check
    is neither failed closed nor blind to C's identifiers."""
    source = Static(
        {
            BETA: ["BET-INV-(?=[0-9])"],
            GAMMA: [tenant_id_pattern(GAMMA), r"GAM-ACC-[0-9]{4}"],
        }
    )
    meter, alerts = InMemoryUsageMeter(), RecordingAlertSink()
    async with Env(other_tenants=source, meter=meter, alerts=alerts) as env:
        await env.publish(bundle(ALPHA, rules=[rule("adv")]))
        clean = await env.check(ALPHA, "output", "Hello. BET-INV-9082")
        leak = await env.check(ALPHA, "tool_result", "see GAM-ACC-1234")
        await env.service._gateway.drain()
    assert clean.decision is Decision.ALLOW  # B's pattern isn't scanned for: dropped
    assert (leak.decision, leak.reason) == (Decision.BLOCK, Reason.DETERMINISTIC)
    assert env.service._scanner.dropped_tenants == (BETA,)
    [alert] = alerts.warnings(ALERT_XTENANT_PATTERNS_DROPPED)
    assert alert.tenant_id == BETA
    assert "BET-INV" not in alert.message and BETA not in alert.message  # fixed words
    assert meter.identifier_patterns_dropped(BETA) == 1


async def test_a_dropped_tenant_is_logged_in_fixed_words_without_its_patterns(caplog):
    source = Static({BETA: ["SECRET-PATTERN-(?=x)"]})
    async with Env(other_tenants=source) as env:
        await env.publish(bundle(ALPHA, rules=[rule("adv")]))
        with caplog.at_level("ERROR"):
            await env.check(ALPHA, "output", "Hello.")
    text = "\n".join(r.getMessage() for r in caplog.records)
    assert "did not compile" in text and BETA in text and "SECRET-PATTERN" not in text


async def test_the_dropped_tenant_is_alerted_once_per_rebuild_not_once_per_check():
    source = Static({BETA: ["BET-(?=x)"]})
    meter = InMemoryUsageMeter()
    async with Env(other_tenants=source, meter=meter) as env:
        await env.publish(bundle(ALPHA, rules=[rule("adv")]))
        for _ in range(4):
            await env.check(ALPHA, "output", "Hello.")
        await env.service._gateway.drain()
        assert meter.identifier_patterns_dropped(BETA) == 1
        source.current = 2  # a new version rebuilds, and the tenant is still bad
        await env.check(ALPHA, "output", "Hello.")
        await env.service._scanner.wait_for_rebuild()  # the report comes from the rebuild
        await env.service._gateway.drain()
    assert meter.identifier_patterns_dropped(BETA) == 2


async def test_a_dropped_tenant_comes_back_when_its_patterns_are_fixed():
    source = Static({BETA: ["BET-INV-(?=[0-9])"]})
    async with Env(other_tenants=source) as env:
        await env.publish(bundle(ALPHA, rules=[rule("adv")]))
        before = await env.check(ALPHA, "output", BETA_INVOICE)
        source.by_tenant = {BETA: [r"BET-INV-[0-9]{4}"]}
        source.current = 2
        await env.check(ALPHA, "output", "Hello.")  # starts the rebuild
        await env.service._scanner.wait_for_rebuild()
        after = await env.check(ALPHA, "output", BETA_INVOICE)
    assert before.decision is Decision.ALLOW and after.reason is Reason.DETERMINISTIC


async def test_a_failing_alert_hook_does_not_fail_the_check(monkeypatch):
    source = Static({BETA: ["BET-(?=x)"]})
    async with Env(other_tenants=source) as env:
        await env.publish(bundle(ALPHA, rules=[rule("adv")]))

        def boom(tenant_id):
            raise RuntimeError("pager down")

        monkeypatch.setattr(env.service._gateway, "identifier_patterns_dropped", boom)
        verdict = await env.check(ALPHA, "output", "Hello.")
    assert verdict.decision is Decision.ALLOW


async def test_a_tenants_careless_pattern_cannot_reach_the_scan_through_the_in_memory_source():
    """End to end: ``.`` is refused where it is registered, so tenant B never blocks
    tenant A's clean output."""
    source = two_tenants()
    with pytest.raises(IdentifierPatternError):
        source.register(BETA, ".")
    with pytest.raises(IdentifierPatternError):
        source.register(BETA, "[0-9]")
    async with Env(other_tenants=source) as env:
        await env.publish(bundle(ALPHA, rules=[rule("adv")]))
        verdict = await env.check(ALPHA, "output", "Order 12345 shipped on 2024-05-06.")
    assert verdict.decision is Decision.ALLOW


# -- one global set, rebuilt when the source's version changes


class Counting(Re2RegexEngine):
    def __init__(self) -> None:
        super().__init__()
        self.compiled: list[tuple[str, ...]] = []

    def compile_set(self, patterns):
        self.compiled.append(tuple(patterns))
        return super().compile_set(patterns)


async def test_one_global_set_is_compiled_and_kept_between_checks_and_callers():
    engine = Counting()
    async with Env(other_tenants=two_tenants(), regex=engine) as env:
        await env.publish(bundle(ALPHA, rules=[rule("adv")]))
        await env.publish(bundle(BETA, rules=[rule("adv")]))
        for tenant in (ALPHA, BETA, ALPHA, BETA, ALPHA):
            await env.check(tenant, "output", "Hello.")
    # three tenants checked once each for compilability, then the one global set
    assert len(engine.compiled) == 4
    assert engine.compiled[-1] == tuple(p for t in engine.compiled[:-1] for p in t)


async def test_more_than_eight_active_tenants_do_not_recompile_on_every_check():
    tenants = [f"t_load{n}" for n in range(12)]
    source = InMemoryOtherTenantIdentifiers(
        {t: [f"LD{n:02d}-[0-9]{{4}}"] for n, t in enumerate(tenants)}
    )
    engine = Counting()
    async with Env(
        other_tenants=source, regex=engine, tenants=[profile(t) for t in tenants]
    ) as env:
        for t in tenants:
            await env.publish(bundle(t, rules=[rule("adv")]))
        for _ in range(3):
            for t in tenants:
                await env.check(t, "output", "Hello.")
    assert len(engine.compiled) == len(tenants) + 1  # per-tenant probes, then one set, once


async def test_a_change_of_version_rebuilds_the_set_and_nothing_else_does():
    source = two_tenants()
    engine = Counting()
    async with Env(other_tenants=source, regex=engine) as env:
        await env.publish(bundle(ALPHA, rules=[rule("adv")]))
        await env.check(ALPHA, "output", "see DEL-7-1234")
        built = len(engine.compiled)
        await env.check(ALPHA, "output", "see DEL-7-1234")
        assert len(engine.compiled) == built
        source.register("t_delta", r"DEL-7-[0-9]{4}")
        await env.check(ALPHA, "output", "see DEL-7-1234")
        await env.service._scanner.wait_for_rebuild()
        after = await env.check(ALPHA, "output", "see DEL-7-1234")
    assert len(engine.compiled) > built and after.reason is Reason.DETERMINISTIC


async def test_the_callers_own_patterns_are_ignored_at_match_time():
    """Alpha's own order number matches the global set, and still passes for Alpha; it
    blocks for Beta."""
    async with await xtenant_env() as env:
        own = await env.check(ALPHA, "output", f"Order {ALPHA_ORDER}.")
        other = await env.check(BETA, "output", f"Order {ALPHA_ORDER}.")
        mixed = await env.check(ALPHA, "output", f"Order {ALPHA_ORDER} and {BETA_INVOICE}.")
    assert own.decision is Decision.ALLOW
    assert other.reason is Reason.DETERMINISTIC and mixed.reason is Reason.DETERMINISTIC


async def test_concurrent_first_checks_build_the_set_once():
    engine = Counting()
    async with Env(other_tenants=two_tenants(), regex=engine) as env:
        await env.publish(bundle(ALPHA, rules=[rule("adv")]))
        await asyncio.gather(*(env.check(ALPHA, "output", "Hello.") for _ in range(6)))
    assert len(engine.compiled) == 4


async def test_the_spans_attribute_name_is_in_the_ports_list():
    assert "guardrail.deterministic_rules" in CHECK_ATTRIBUTES


async def test_the_sdk_reads_a_deterministic_block_as_a_policy_block_and_an_escalate_as_held():
    from guardrail_engine.sdk.result import MESSAGES, GuardResult

    async with Env() as env:
        await env.publish(deny_bundle())
        blocked = GuardResult.from_verdict(await env.check(ALPHA, "output", CODENAME))
        held = GuardResult.from_verdict(await env.check(ALPHA, "output", PRICING))
    assert (blocked.decision, blocked.reason, blocked.retryable) == (
        "block",
        "deterministic",
        False,
    )
    assert blocked.user_message == MESSAGES["policy"] and not blocked.released
    assert (held.decision, held.reason) == ("escalate", "deterministic")
    assert held.held_for_escalation and held.user_message == MESSAGES["escalate"]
