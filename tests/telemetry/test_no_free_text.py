"""Provider and exception free text never reaches the verdict, its repr,
the audit record, its JSON, or a span.

Provider responses go through the real Gemini adapter's pure mapping
(``map_http_response``), wrapped in a tiny model, so no network is used. Every sentinel is
a neutral placeholder string.
"""

from __future__ import annotations

import json
import logging

import pytest
from guard_fixtures import ALPHA, Env, bundle, rule
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from guardrail_engine.decision import Failed, FailureKind, SafetyBlocked
from guardrail_engine.decision.adapters.gemini import map_http_response
from guardrail_engine.guard import AuditRecord, Decision, Reason
from guardrail_engine.telemetry.adapters.otel import OtelTelemetry

SENTINEL = "PLACEHOLDER-SENTINEL-4d2e"


class MappedModel:
    """Answers every call with the adapter's mapping of one canned HTTP response."""

    model_id = "mapped"

    def __init__(self, status: int, body: bytes) -> None:
        self.status, self.body = status, body
        self.results = []

    async def decide(self, input, questions):
        result = map_http_response(self.status, self.body, questions)
        self.results.append(result)
        return result


class ScriptedModel:
    model_id = "scripted"

    def __init__(self, result) -> None:
        self.result = result

    async def decide(self, input, questions):
        return self.result


def json_body(payload: dict) -> bytes:
    return json.dumps(payload).encode()


PROVIDER_CASES = {
    "provider error message (google.rpc)": (
        503,
        json_body({"error": {"code": 503, "status": "UNAVAILABLE", "message": SENTINEL}}),
        Reason.MODEL_FAILURE,
        "UNAVAILABLE",
    ),
    "provider error message (decisions dialect)": (
        400,
        json_body({"error": {"code": "invalid_request", "message": f"bad field: {SENTINEL}"}}),
        Reason.MODEL_FAILURE,
        None,
    ),
    "non-JSON provider error body": (
        502,
        f"<html><body>Bad gateway {SENTINEL}</body></html>".encode(),
        Reason.MODEL_FAILURE,
        None,
    ),
    "safety refusal message": (
        400,
        json_body({"error": {"code": "safety", "message": f"refused: {SENTINEL}"}}),
        Reason.PROVIDER_SAFETY,
        "safety",
    ),
}


def otel():
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    return OtelTelemetry(provider), exporter, provider


def everything_recorded(verdict, env, exporter) -> list[str]:
    """Every place the check's outcome is recorded, as text."""
    [record] = env.audit.records
    texts = [repr(verdict), verdict.model_dump_json(), repr(record), record.model_dump_json()]
    texts.append(AuditRecord.model_validate_json(record.model_dump_json()).model_dump_json())
    for span in exporter.get_finished_spans():
        texts += [f"{k}={v!r}" for k, v in span.attributes.items()]
        texts += [repr(e.attributes) for e in span.events]
        texts.append(str(span.status.description))
    return texts


@pytest.mark.parametrize("case", list(PROVIDER_CASES))
async def test_provider_text_reaches_no_verdict_record_or_span(case, caplog):
    status, body, reason, code = PROVIDER_CASES[case]
    telemetry, exporter, provider = otel()
    model = MappedModel(status, body)
    with caplog.at_level(logging.INFO):
        async with Env(fake=model, telemetry=telemetry) as env:
            await env.publish(bundle(ALPHA, rules=[rule("adv")]))
            verdict = await env.check(ALPHA)
    provider.shutdown()

    # The adapter did carry the text in its result...
    assert SENTINEL in (model.results[0].message or "")
    # ...but nothing recorded does.
    assert (verdict.decision, verdict.reason) == (Decision.BLOCK, reason)
    assert verdict.failure_reason == code
    for text in everything_recorded(verdict, env, exporter):
        assert SENTINEL not in text
    assert SENTINEL not in caplog.text  # not even in logs at INFO and above


async def test_provider_text_is_logged_at_debug_only_and_truncated(caplog):
    long_message = SENTINEL + " " + "x" * 1000
    with caplog.at_level(logging.DEBUG, logger="guardrail_engine.guard.service"):
        async with Env(
            fake=ScriptedModel(Failed(kind=FailureKind.OTHER, message=long_message))
        ) as env:
            await env.publish(bundle(ALPHA))
            await env.check(ALPHA)
    [entry] = [r for r in caplog.records if SENTINEL in r.getMessage()]
    assert entry.levelno == logging.DEBUG
    assert len(entry.getMessage()) < 400  # truncated to 200 characters of the message


async def test_a_structured_refusal_code_survives_while_its_message_is_dropped():
    """M1-13 maps a provider refusal to ``SafetyBlocked`` with code ``prohibited_content``:
    the code is recorded (verdict, record, span); the message isn't."""
    telemetry, exporter, provider = otel()
    refusal = SafetyBlocked(message=f"refused text {SENTINEL}", reason="prohibited_content")
    async with Env(fake=ScriptedModel(refusal), telemetry=telemetry) as env:
        await env.publish(bundle(ALPHA))
        verdict = await env.check(ALPHA)
    provider.shutdown()

    assert (verdict.decision, verdict.reason) == (Decision.BLOCK, Reason.PROVIDER_SAFETY)
    assert verdict.failure_reason == "prohibited_content"
    [record] = env.audit.records
    assert record.failure_reason == "prohibited_content"
    spans = {s.name: s for s in exporter.get_finished_spans()}
    assert spans["guard.check"].attributes["guardrail.failure_reason"] == "prohibited_content"
    assert spans["guard.model_call"].attributes["guardrail.failure_reason"] == (
        "prohibited_content"
    )
    for text in everything_recorded(verdict, env, exporter):
        assert SENTINEL not in text


@pytest.mark.parametrize(
    "result",
    [
        Failed(kind=FailureKind.UNAVAILABLE, reason=f"free text {SENTINEL}"),
        SafetyBlocked(reason=f"{SENTINEL} with spaces and more than enough words"),
    ],
    ids=["failed", "safety"],
)
async def test_free_text_where_a_code_belongs_is_recorded_as_unrecognised(result):
    telemetry, exporter, provider = otel()
    async with Env(fake=ScriptedModel(result), telemetry=telemetry) as env:
        await env.publish(bundle(ALPHA))
        verdict = await env.check(ALPHA)
    provider.shutdown()
    assert verdict.failure_reason == "unrecognised"
    for text in everything_recorded(verdict, env, exporter):
        assert SENTINEL not in text


async def test_store_exception_text_reaches_no_verdict_record_or_span(caplog):
    telemetry, exporter, provider = otel()
    async with Env(telemetry=telemetry) as env:
        await env.publish(bundle(ALPHA))
        env.store.fail = ConnectionError(f"could not connect to db host {SENTINEL}")
        verdict = await env.check(ALPHA)  # nothing compiled yet: policy unavailable
    provider.shutdown()

    assert (verdict.decision, verdict.reason) == (Decision.BLOCK, Reason.POLICY_UNAVAILABLE)
    assert verdict.policy_error == "ConnectionError"
    for text in everything_recorded(verdict, env, exporter):
        assert SENTINEL not in text
    # The operational log keeps a truncated copy for on-call.
    assert SENTINEL in caplog.text


async def test_store_exception_text_is_not_recorded_when_serving_last_known_good():
    async with Env() as env:
        await env.publish(bundle(ALPHA))
        await env.check(ALPHA)
        env.store.fail = OSError(f"driver said {SENTINEL}")
        env.service.policy_cache.invalidate(ALPHA)
        verdict = await env.check(ALPHA)
    assert verdict.policy_error.startswith("OSError")
    assert verdict.decision is Decision.ALLOW
    for text in (repr(verdict), env.audit.records[-1].model_dump_json()):
        assert SENTINEL not in text


async def test_a_provider_answer_quoted_by_the_parser_is_not_recorded():
    """The answer parser's own problem detail quotes the raw answer (its ``type``); the
    contract violation records the engine's wording instead."""
    async with Env() as env:
        await env.publish(bundle(ALPHA, rules=[rule("adv")]))
        env.fake.malformed_next(raw_answers={"t__adv": {"type": SENTINEL}})
        verdict = await env.check(ALPHA)
    [violation] = verdict.contract_violations
    assert violation.key == "t__adv"
    assert SENTINEL in repr(env.fake.calls[0].result)  # the parser did quote it
    for text in (repr(verdict), env.audit.records[0].model_dump_json()):
        assert SENTINEL not in text
