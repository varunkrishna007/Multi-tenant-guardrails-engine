"""M7-01: credentials in a known format, in the Guard Service.

* In the **content** at ``plan``, ``tool_call``, ``tool_result`` and ``output`` (the guard
  points of the floor rule ``p__secret``) one is a floor ``block``, rule ``p__secret``, and
  the fake model records **zero** calls.
* In **any context section**, at any guard point, and in the content at ``input``, it is
  replaced by ``[SECRET]`` before rendering: the model's input holds the placeholder and
  never the value. A credential that appears only in context is redacted, not blocked.
* Templates and placeholders pass untouched; a tenant bundle cannot loosen any of it.
* The value is in no verdict, audit record, span, log line or stored record: counts only.

Every value is invented, and none holds the word EXAMPLE (a token body with it is a
placeholder).
"""

from __future__ import annotations

import asyncio
import json
import logging

import pytest
from guard_fixtures import ALPHA, Env, bundle, profile, rule
from policy_fixtures import floor_rule, make_floor

from guardrail_engine.deterministic import (
    SECRET_PLACEHOLDER,
    SECRET_RULE,
    DeterministicAction,
    DeterministicKind,
)
from guardrail_engine.guard import (
    Decision,
    Plan,
    Reason,
    RedactionStatus,
    ToolCall,
    ToolResult,
    Turn,
)
from guardrail_engine.guard.redaction import REDACT_OFF_LOOP_CHARS, redact_request
from guardrail_engine.policy import GUARD_POINTS, InMemoryCatalog, PlatformSettings

BLOCK_POINTS = ("plan", "tool_call", "tool_result", "output")
D = "-----"  # a PEM header is built from parts, so no literal here looks like a real key
AWS = "AKIA" + "Q7ZXW4K9PLM2H8T3"
URL_PASSWORD = "Pw9-fakeValue"
FORMATS = {
    "aws": AWS,
    "aws_temporary": "ASIA" + "Q7ZXW4K9PLM2H8T3",
    "github": "ghp_" + "Q7zxW4k9PlM2h8T3vB6nR1cY5dF0gJ2aS8eUxK"[:36],
    "github_pat": "github_pat_" + "11Q7zxW4k9PlM2h8T3vB6nR1cY5dF0gJ2aS8eUxK_Hp3Lm9Zq",
    "google": "AIza" + "Sy" + "Q7zxW4k9PlM2h8T3vB6nR1cY5dF0gJ2aS8eUxK"[:33],
    "slack": "xox" + "b-1234567890-1234567890123-Q7zxW4k9PlM2h8T3vB6nR1cY",
    "stripe": "sk_live_" + "Q7zxW4k9PlM2h8T3vB6nR1cY5dF0",
    "pem": (
        D + "BEGIN RSA PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSj\n"
        "Q7zxW4k9PlM2h8T3vB6nR1cY5dF0gJ2aS8eUxKhH\n-----END RSA PRIVATE KEY-----"
    ),
    "url": f"postgres://app:{URL_PASSWORD}@db.example.internal:5432/claims",
}
SECRET_OF = {"url": URL_PASSWORD}  # the part that must never be sent


def secret_part(name: str) -> str:
    return SECRET_OF.get(name, FORMATS[name])


def wrap(guard_point: str, value: str) -> str:
    """The value inside content shaped for the guard point."""
    if guard_point == "tool_call":
        return json.dumps({"tool": "http.post", "arguments": {"auth": value}})
    if guard_point == "plan":
        return json.dumps({"goal": "call the API", "steps": [{"tool": "x", "note": value}]})
    return f"Here you go: {value} (keep it safe)"


def secret_bundle(**kwargs) -> dict:
    return bundle(ALPHA, rules=[rule("adv", gps=GUARD_POINTS)], **kwargs)


async def env_with(**kwargs) -> Env:
    env = Env(**kwargs)
    await env.publish(secret_bundle())
    return env


def hit_of(verdict):
    [hit] = [h for h in verdict.deterministic if h.rule == SECRET_RULE]
    return hit


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


# ------------------------------------------------------------------ the floor block


@pytest.mark.parametrize("name", FORMATS)
@pytest.mark.parametrize("guard_point", BLOCK_POINTS)
async def test_a_known_format_credential_in_the_content_is_a_floor_block_with_no_model_call(
    name, guard_point
):
    async with await env_with() as env:
        verdict = await env.check(ALPHA, guard_point, wrap(guard_point, FORMATS[name]))
    assert (verdict.decision, verdict.reason) == (Decision.BLOCK, Reason.DETERMINISTIC)
    assert env.fake.calls == []  # zero model calls
    assert not verdict.model_called and verdict.provider_calls == 0
    assert verdict.rules == () and verdict.fired == ()
    hit = hit_of(verdict)
    assert (hit.kind, hit.action, hit.layer, hit.count) == (
        DeterministicKind.SECRET_FORMAT,
        DeterministicAction.BLOCK,
        "floor",
        1,
    )
    assert not verdict.released
    assert env.audit.records[0].deterministic == verdict.deterministic  # the audit names the rule


@pytest.mark.parametrize("guard_point", BLOCK_POINTS)
async def test_the_count_is_the_number_of_credentials_found(guard_point):
    text = f"{FORMATS['aws']} and {FORMATS['github']} and {FORMATS['stripe']}"
    async with await env_with() as env:
        verdict = await env.check(ALPHA, guard_point, text)
    assert hit_of(verdict).count == 3 and env.fake.calls == []


async def test_the_block_stands_when_the_model_would_have_failed_or_said_allow():
    from guardrail_engine.decision import Failed, FailureKind

    async with await env_with() as env:
        env.fake.always(Failed(kind=FailureKind.TIMEOUT))
        verdict = await env.check(ALPHA, "output", wrap("output", AWS))
    assert (verdict.decision, verdict.reason) == (Decision.BLOCK, Reason.DETERMINISTIC)
    assert verdict.failure_kind is None and env.fake.calls == []


async def test_other_deterministic_hits_are_recorded_beside_the_secret_block():
    doc = secret_bundle()
    doc["deterministic"] = {"deny_patterns": [{"id": "ex", "regex": "Q7ZXW4K9", "action": "log"}]}
    async with Env() as env:
        await env.publish(doc)
        verdict = await env.check(ALPHA, "output", wrap("output", AWS))
    assert {h.rule for h in verdict.deterministic} == {"deny__ex", SECRET_RULE}
    assert env.fake.calls == []


async def test_a_credential_split_across_a_chunk_boundary_is_still_blocked():
    """The scan is on the whole raw content, before it is cut into chunks (4,000-character
    chunks here), so a key that straddles a cut is found, with no model call."""
    chunk_chars = 4 * 1000
    filler = "".join(f"s{i:05d}abcd" for i in range(1_000))
    at = chunk_chars - len(AWS) // 2  # the key starts before the first cut and ends after it
    content = filler[:at] + f" {AWS} " + filler[at + len(AWS) : 9_000]
    doc = bundle(
        ALPHA,
        rules=[rule("adv", gps=("tool_result",))],
        guard_points={"tool_result": {"chunk_tokens": 1000}},
    )
    async with Env(settings=PlatformSettings(min_chunk_tokens=1)) as env:
        await env.publish(doc)
        verdict = await env.check(ALPHA, "tool_result", content)
    assert (verdict.decision, verdict.reason) == (Decision.BLOCK, Reason.DETERMINISTIC)
    assert env.fake.calls == [] and verdict.chunks == 0


async def test_a_password_in_a_urls_userinfo_is_a_block_though_the_pii_redactor_leaves_it():
    text = f"DATABASE_URL={FORMATS['url']}"
    async with await env_with() as env:
        verdict = await env.check(ALPHA, "tool_result", text)
    assert verdict.reason is Reason.DETERMINISTIC and env.fake.calls == []


@pytest.mark.parametrize("guard_point", BLOCK_POINTS)
async def test_the_scan_runs_before_redaction_so_a_tenant_redact_pattern_cannot_hide_a_key(
    guard_point,
):
    doc = secret_bundle()
    doc["deterministic"] = {
        "deny_patterns": [{"id": "all", "regex": "AKIA[A-Z0-9]+", "action": "redact"}]
    }
    async with Env() as env:
        await env.publish(doc)
        verdict = await env.check(ALPHA, guard_point, wrap(guard_point, AWS))
    assert verdict.reason is Reason.DETERMINISTIC and env.fake.calls == []


# Where a credential really turns up: after a line break in JSON text (the two characters
# backslash and n), after a tab or a CRLF, and in a percent-encoded query or form body.
SHAPES = {
    "json_newline": lambda v: json.dumps({"stdout": "tokens:\n" + v + "\n"}),
    "json_tab": lambda v: json.dumps({"stdout": "key\t" + v}),
    "json_crlf": lambda v: json.dumps({"stdout": "line one\r\n" + v + "\r\nline three"}),
    "json_two_keys": lambda v: json.dumps({"stdout": "a\n" + v + "\n" + AWS}),
    "percent_encoded": lambda v: "q=tokens%0A" + v.replace("\n", "%0A") + "%0Aend",
    "percent_equals": lambda v: "key%3D" + v + "%2Cnext",
}


def shaped_secret(name: str) -> str:
    return secret_part(name)


@pytest.mark.parametrize("shape", SHAPES)
@pytest.mark.parametrize("name", FORMATS)
@pytest.mark.parametrize("guard_point", BLOCK_POINTS)
async def test_a_credential_after_a_json_escape_or_a_percent_encoding_is_still_a_block(
    guard_point, name, shape
):
    text = SHAPES[shape](FORMATS[name])
    async with await env_with() as env:
        verdict = await env.check(ALPHA, guard_point, text)
    assert (verdict.decision, verdict.reason) == (Decision.BLOCK, Reason.DETERMINISTIC)
    assert env.fake.calls == []
    assert hit_of(verdict).action is DeterministicAction.BLOCK


async def test_the_reviewers_end_to_end_probe_blocks_at_every_point():
    github = FORMATS["github"]
    text = json.dumps({"stdout": "tokens:\n" + github + "\n" + AWS})
    async with await env_with() as env:
        verdicts = [await env.check(ALPHA, gp, text) for gp in BLOCK_POINTS]
    assert all(v.reason is Reason.DETERMINISTIC for v in verdicts) and env.fake.calls == []
    assert all(hit_of(v).count == 2 for v in verdicts)


# ------------------------------------------------------------------ templates pass


PASSING = [
    "AKIAIOSFODNN7EXAMPLE",  # AWS's documented example key id, quoted in documentation
    "ghp_" + "yourTokenGoesHere0123456789abcdefghijk",
    "postgres://USER:PASSWORD@HOST:5432/db",
    "postgresql://{USER}:{PASSWORD}@{HOST}/{DB}",
    "https://user:<your-password>@example.com/",
    "https://user:${DB_PASS}@example.com/",
    "https://user:****@example.com/",
    "https://user:xxx@example.com/",
    "AKIA" + "X" * 16,
    "ghp_" + "x" * 36,
    "xox" + "b-your-token-here",
    "sk_live_" + "x" * 24,
    D + "BEGIN PRIVATE KEY----- ... -----END PRIVATE KEY-----",
    "Set the password: in the config, or export AWS_ACCESS_KEY_ID=<your key id>.",
]


@pytest.mark.parametrize("text", PASSING)
@pytest.mark.parametrize("guard_point", ("input", *BLOCK_POINTS))
async def test_placeholders_and_templates_pass_through_untouched(text, guard_point):
    async with await env_with() as env:
        verdict = await env.check(ALPHA, guard_point, wrap(guard_point, text))
    assert verdict.decision is Decision.ALLOW
    assert verdict.deterministic == ()
    [call] = env.fake.calls
    assert SECRET_PLACEHOLDER not in call.input
    assert json.dumps(text)[1:-1] in call.input or text in call.input  # sent as written


async def test_a_credential_in_a_non_secret_format_still_goes_to_the_model_question():
    """``p__secret`` stays for what no pattern recognises: an assignment, a bearer token."""
    async with await env_with() as env:
        verdict = await env.check(ALPHA, "output", "password: hunter2-FAKE")
    assert verdict.deterministic == () and len(env.fake.calls) == 1


# ------------------------------------------------------------------ redaction before rendering


@pytest.mark.parametrize("name", FORMATS)
async def test_at_input_a_credential_is_redacted_and_the_check_goes_on(name):
    spans = Spans()
    async with await env_with(telemetry=spans) as env:
        verdict = await env.check(ALPHA, "input", wrap("input", FORMATS[name]))
    assert verdict.decision is Decision.ALLOW
    [call] = env.fake.calls
    assert secret_part(name) not in call.input
    assert f"Here you go: {SECRET_PLACEHOLDER}" in call.input or name == "url"
    assert SECRET_PLACEHOLDER in call.input
    hit = hit_of(verdict)
    assert (hit.kind, hit.action, hit.layer, hit.count) == (
        DeterministicKind.SECRET_FORMAT,
        DeterministicAction.REDACT,
        "floor",
        1,
    )
    assert verdict.redaction is RedactionStatus.APPLIED
    assert spans.ended[0]["guardrail.deterministic_rules"] == (SECRET_RULE,)


async def test_at_input_a_url_keeps_its_host_for_the_exfiltration_rule():
    async with await env_with() as env:
        await env.check(ALPHA, "input", f"connect to {FORMATS['url']} please")
    [call] = env.fake.calls
    assert "postgres://app:[SECRET]@db.example.internal:5432/claims" in call.input


CONTEXT_ITEMS = {
    "turn": lambda v: Turn("user", f"my key is {v}"),
    "plan": lambda v: Plan(json.dumps({"steps": [{"tool": "x", "key": v}]})),
    "tool_call": lambda v: ToolCall("x", json.dumps({"auth": v})),
    "tool_result": lambda v: ToolResult("x", f"loaded {v}"),
}


@pytest.mark.parametrize("item", CONTEXT_ITEMS)
@pytest.mark.parametrize("name", ["aws", "stripe", "pem", "url"])
@pytest.mark.parametrize("guard_point", GUARD_POINTS)
async def test_a_credential_in_any_context_section_is_redacted_at_every_guard_point(
    guard_point, name, item
):
    """A user pastes a key at ``input``; the next ``output`` check carries that turn as
    context. It is redacted there, not blocked: the content under check is clean."""
    async with await env_with() as env:
        verdict = await env.check(
            ALPHA,
            guard_point,
            "Done.",
            conversation=(CONTEXT_ITEMS[item](FORMATS[name]),),
        )
    assert verdict.decision is Decision.ALLOW and verdict.reason is not Reason.DETERMINISTIC
    [call] = env.fake.calls
    assert secret_part(name) not in call.input
    assert SECRET_PLACEHOLDER in call.input
    assert hit_of(verdict).action is DeterministicAction.REDACT


@pytest.mark.parametrize("shape", SHAPES)
@pytest.mark.parametrize("name", FORMATS)
@pytest.mark.parametrize("guard_point", GUARD_POINTS)
async def test_a_credential_after_an_escape_in_a_context_section_is_redacted_everywhere(
    guard_point, name, shape
):
    text = SHAPES[shape](FORMATS[name])
    async with await env_with() as env:
        verdict = await env.check(
            ALPHA, guard_point, "Done.", conversation=(ToolResult("x", text), Turn("user", text))
        )
    assert verdict.decision is Decision.ALLOW
    for call in env.fake.calls:
        assert secret_part(name) not in call.input and AWS not in call.input
        assert SECRET_PLACEHOLDER in call.input


@pytest.mark.parametrize("shape", SHAPES)
@pytest.mark.parametrize("name", FORMATS)
async def test_at_input_a_credential_after_an_escape_is_redacted_and_the_check_goes_on(name, shape):
    text = SHAPES[shape](FORMATS[name])
    async with await env_with() as env:
        verdict = await env.check(ALPHA, "input", text)
    assert verdict.decision is Decision.ALLOW
    [call] = env.fake.calls
    assert secret_part(name) not in call.input and SECRET_PLACEHOLDER in call.input


async def test_a_credential_only_in_context_never_blocks_and_chunked_calls_never_carry_it():
    doc = bundle(
        ALPHA,
        rules=[rule("adv", gps=("tool_result",))],
        guard_points={"tool_result": {"chunk_tokens": 1000}},
    )
    filler = "".join(f"s{i:05d}abcd" for i in range(1_000))[:9_000]
    async with Env(settings=PlatformSettings(min_chunk_tokens=1)) as env:
        await env.publish(doc)
        verdict = await env.check(
            ALPHA, "tool_result", filler, conversation=(Turn("user", f"key {AWS}"),)
        )
    assert verdict.decision is Decision.ALLOW and len(env.fake.calls) == 3
    assert all(AWS not in call.input for call in env.fake.calls)


async def test_the_description_of_a_referenced_registered_tool_is_redacted_too():
    from guardrail_engine.guard import ToolInfo

    tools = (ToolInfo("vault.read", f"Reads secrets; the demo key is {AWS}."),)
    async with Env(tenants=[profile(ALPHA, tools=tools)]) as env:
        await env.publish(secret_bundle())
        await env.check(ALPHA, "output", "Done.", conversation=(ToolCall("vault.read", "{}"),))
    [call] = env.fake.calls
    assert AWS not in call.input and SECRET_PLACEHOLDER in call.input


def test_redact_request_leaves_credentials_alone_unless_given_a_detector():
    """A harness that scores rows as written passes none (the Guard Service always does)."""
    out = redact_request(content=f"key {AWS}", conversation=(), tools={})
    assert out.content == f"key {AWS}" and out.secret_count == 0


async def test_the_pii_redactor_and_the_credential_redactor_work_on_the_same_text():
    async with await env_with() as env:
        await env.check(ALPHA, "input", f"mail jo.smith@example.com, key {AWS}")
    [call] = env.fake.calls
    assert "[EMAIL]@example.com" in call.input and SECRET_PLACEHOLDER in call.input
    assert AWS not in call.input


async def test_a_credential_in_the_content_at_a_guard_point_with_no_questions_sends_nothing():
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
    async with Env(catalog=InMemoryCatalog(floors=[floor])) as env:
        await env.publish(bundle(ALPHA, guard_points={"output": {"enabled": False}}))
        blocked = await env.check(ALPHA, "output", wrap("output", AWS))
        clean = await env.check(ALPHA, "output", "Hello.")
    assert (blocked.decision, blocked.reason) == (Decision.BLOCK, Reason.DETERMINISTIC)
    assert (clean.decision, clean.reason) == (Decision.ALLOW, Reason.NO_QUESTIONS)
    assert env.fake.calls == []


# ------------------------------------------------------------------ no tenant can loosen it


async def test_a_tenant_bundle_cannot_disable_or_loosen_the_check():
    doc = bundle(
        ALPHA,
        rules=[rule("adv", gps=GUARD_POINTS, mode="shadow", block_at=0.99, escalate_at=0.98)],
        defaults={"fail_mode": "open"},
    )
    doc["deterministic"] = {
        "deny_patterns": [{"id": "key", "regex": "AKIA[A-Z0-9]{16}", "action": "log"}]
    }
    async with Env() as env:
        await env.publish(doc)
        verdicts = [await env.check(ALPHA, gp, wrap(gp, AWS)) for gp in BLOCK_POINTS]
    assert all(v.reason is Reason.DETERMINISTIC and v.decision is Decision.BLOCK for v in verdicts)
    assert env.fake.calls == []
    assert all({h.rule for h in v.deterministic} == {"deny__key", SECRET_RULE} for v in verdicts)


async def test_a_bundle_cannot_raise_the_secret_thresholds_and_lowering_them_changes_nothing():
    from guardrail_engine.policy import PolicyInvalidError

    raised = secret_bundle()
    raised["overrides"] = [{"rule": "p__secret", "block_at": 0.99, "escalate_at": 0.98}]
    async with Env() as env:
        with pytest.raises(PolicyInvalidError, match=r"floor\.override_raises"):
            await env.publish(raised)
        lowered = secret_bundle()
        lowered["overrides"] = [{"rule": "p__secret", "block_at": 0.7, "escalate_at": 0.4}]
        await env.publish(lowered)
        verdict = await env.check(ALPHA, "output", wrap("output", AWS))
    assert (verdict.decision, verdict.reason) == (Decision.BLOCK, Reason.DETERMINISTIC)
    assert env.fake.calls == []


async def test_the_check_needs_no_policy_and_no_floor_rule_for_it():
    """It does not read the bundle: a check against a tenant whose policy can't be served is
    refused for that reason, never allowed because the secret scan was skipped."""
    async with Env() as env:
        verdict = await env.check("t_unknown", "output", wrap("output", AWS))
    assert verdict.decision is not Decision.ALLOW and env.fake.calls == []


# ------------------------------------------------------------------ nothing records the value


def everything_recorded(verdict, record, spans, caplog) -> str:
    logger_text = "\n".join(
        logging.Formatter("%(name)s %(levelname)s %(message)s").format(r) for r in caplog.records
    )
    return "\n".join(
        [
            verdict.model_dump_json(),
            record.model_dump_json(),
            json.dumps(spans, default=str),
            logger_text,
            repr(verdict),
        ]
    )


@pytest.mark.parametrize("name", FORMATS)
@pytest.mark.parametrize("guard_point", ("input", "output"))
async def test_the_value_is_in_no_verdict_audit_record_span_or_log(name, guard_point, caplog):
    caplog.set_level(logging.DEBUG)
    spans = Spans()
    async with await env_with(telemetry=spans) as env:
        verdict = await env.check(
            ALPHA,
            guard_point,
            wrap(guard_point, FORMATS[name]),
            conversation=(Turn("user", f"earlier: {FORMATS[name]}"),),
        )
    recorded = everything_recorded(verdict, env.audit.records[0], spans.ended, caplog)
    for part in {FORMATS[name], secret_part(name), *FORMATS[name].split("\n")}:
        if len(part) >= 8:
            assert part not in recorded
    assert SECRET_RULE in recorded


async def test_a_stored_record_of_a_redacted_check_holds_the_placeholder_not_the_value():
    from guardrail_engine.content.writer import ContentRequest

    class Sink:
        def __init__(self) -> None:
            self.submitted: list[ContentRequest] = []

        def submit(self, request: ContentRequest) -> None:
            self.submitted.append(request)

    sink = Sink()
    doc = secret_bundle()
    doc["audit"] = {"store_content": "full", "content_days": 7}
    async with Env() as env:
        env.service.attach_content(sink)
        await env.publish(doc)
        verdict = await env.check(ALPHA, "input", f"key {AWS}")
    assert verdict.decision is Decision.ALLOW
    [request] = sink.submitted
    assert AWS not in request.content and SECRET_PLACEHOLDER in request.content
    blocked_sink = Sink()
    async with Env() as env:
        env.service.attach_content(blocked_sink)
        await env.publish(doc)
        await env.check(ALPHA, "output", f"key {AWS}")
    assert blocked_sink.submitted == []  # a blocked check stores nothing


# ------------------------------------------------------------------ cost and the event loop

CRAFTED = {
    "repeated key prefix": "AKIA" * 7_500,
    "repeated pem header": (D + "BEGIN PRIVATE KEY-----\n") * 1_080,
    "repeated userinfo": "http://" + ":@" * 14_900,
    "many keys": (AWS + " ") * 1_400,
}


@pytest.mark.parametrize("name", CRAFTED)
@pytest.mark.parametrize("guard_point", ("input", "output"))
async def test_crafted_input_is_checked_in_bounded_time_and_off_the_event_loop(name, guard_point):
    """Near the default content cap (8,000 tokens, about 32,000 characters) and over
    ``REDACT_OFF_LOOP_CHARS``, the scan and the redaction run in a worker thread, as
    the other deterministic checks do; a ticker proves the loop kept turning meanwhile."""
    text = CRAFTED[name]
    assert len(text) > REDACT_OFF_LOOP_CHARS
    settings = PlatformSettings(min_chunk_tokens=1)
    doc = secret_bundle()
    ticks = 0
    stop = asyncio.Event()

    async def ticker() -> None:
        nonlocal ticks
        while not stop.is_set():
            ticks += 1
            await asyncio.sleep(0)

    async with Env(settings=settings) as env:
        await env.publish(doc)
        task = asyncio.create_task(ticker())
        verdict = await asyncio.wait_for(env.check(ALPHA, guard_point, text), timeout=30)
        stop.set()
        await task
    assert ticks > 0
    if name == "many keys":
        assert (verdict.reason is Reason.DETERMINISTIC) == (guard_point == "output")
    else:
        assert verdict.reason is not Reason.INTERNAL_ERROR
