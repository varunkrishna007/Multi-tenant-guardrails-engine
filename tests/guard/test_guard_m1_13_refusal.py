"""M1-13 through the Guard Service (R10.1, R10.5): a provider refusal before scoring (HTTP 400
``prohibited_content``) is ``block`` / ``provider_safety``, not retryable, at every guard
point, with no per-rule answers and nothing fired. The code ``prohibited_content`` is
recorded as ``failure_reason`` (M1-06's shape; no ``detail``). The provider's free-text
message reaches neither the verdict, the audit record nor a span; it is logged at DEBUG only,
truncated, by the Guard Service (review decision on M1-13).

The model is the real Gemini adapter replaying the reconstructed fixture (with a sentinel
appended to its message) through ``httpx.MockTransport``: no network, no live call (U4). The
content checked is a neutral placeholder.
"""

import json
import logging
from pathlib import Path

import httpx
import pytest
from guard_fixtures import ALPHA, BETA, Env, bundle, rule
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from guardrail_engine.decision.adapters.gemini import GeminiConfig, GeminiDecisionModel
from guardrail_engine.gateway import InMemoryUsageMeter
from guardrail_engine.guard import Decision, Reason
from guardrail_engine.policy import GUARD_POINTS, PlatformSettings
from guardrail_engine.telemetry.adapters.otel import OtelTelemetry

FIXTURES = Path(__file__).parents[1] / "decision" / "fixtures" / "gemini"
RECONSTRUCTED = [
    "reconstructed_prohibited_content_400",
    "reconstructed_prohibited_content_400_top_level",
]
SENTINEL = "SENTINEL-c41e-provider-message-must-not-leak"
OBSERVED_PREFIX = "Input blocked: The prompt could not be submitted."
CONTENT = "Placeholder content for a refused check."


class Replay:
    """The Gemini adapter answering every request with ``name``, ``SENTINEL`` appended to
    the provider's message."""

    def __init__(self, name: str) -> None:
        rec = json.loads((FIXTURES / f"{name}.json").read_text())
        body = rec["body"]
        body.get("error", body)["message"] += SENTINEL
        self.status, self.content = rec["status"], json.dumps(body).encode()
        self.requests = 0
        self.model = GeminiDecisionModel(
            GeminiConfig(api_key="test-key-not-a-real-secret", paid_tier=True),
            client=httpx.AsyncClient(transport=httpx.MockTransport(self._handle)),
        )

    def _handle(self, request: httpx.Request) -> httpx.Response:
        self.requests += 1
        return httpx.Response(self.status, content=self.content)


def assert_refusal_verdict(verdict, guard_point: str) -> None:
    assert verdict.guard_point == guard_point
    assert verdict.decision is Decision.BLOCK
    assert verdict.reason is Reason.PROVIDER_SAFETY
    assert verdict.retryable is False
    assert not verdict.released
    assert verdict.detail is None  # M1-06: provider_safety carries no detail
    assert verdict.rules == ()  # no per-rule answers
    assert verdict.fired == ()
    assert verdict.probabilities == {}
    assert verdict.contract_violations == ()
    assert verdict.usage is None
    assert verdict.failure_kind is None
    assert verdict.failure_reason == "prohibited_content"  # the structured code (R10.5)
    assert verdict.model_called


def assert_refusal_audit_record(record) -> None:
    """R10.5: provider_called, provider_calls 1, no answers, fired [], the code recorded."""
    assert (record.decision, record.reason) == (Decision.BLOCK, Reason.PROVIDER_SAFETY)
    assert record.retryable is False
    assert record.provider_called is True
    assert record.provider_calls == 1
    assert record.answers == {}
    assert record.fired == ()
    assert record.failure_reason == "prohibited_content"
    assert record.detail is None


def assert_no_provider_text(*texts: str) -> None:
    for text in texts:
        assert SENTINEL not in text
        assert OBSERVED_PREFIX not in text
        assert "Prohibited Use policy" not in text


@pytest.mark.parametrize("name", RECONSTRUCTED)
async def test_refusal_blocks_with_provider_safety_at_every_guard_point(name, caplog):
    caplog.set_level(logging.DEBUG)
    replay, meter = Replay(name), InMemoryUsageMeter()
    exporter, provider = InMemorySpanExporter(), TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    async with Env(fake=replay.model, meter=meter, telemetry=OtelTelemetry(provider)) as env:
        await env.publish(bundle(ALPHA, rules=[rule("adv", gps=GUARD_POINTS)]))
        verdicts = [await env.check(ALPHA, gp, CONTENT) for gp in GUARD_POINTS]
        await env.service.gateway.drain()
    provider.shutdown()

    for gp, verdict in zip(GUARD_POINTS, verdicts, strict=True):
        assert_refusal_verdict(verdict, gp)
    for record in env.audit.records:
        assert_refusal_audit_record(record)
    assert replay.requests == len(GUARD_POINTS)  # one provider call per check, no retry
    assert env.audit.verdicts == verdicts  # each verdict audited, as returned
    assert meter.provider_safety_blocks(ALPHA) == len(GUARD_POINTS)
    assert meter.provider_safety_blocks(BETA) == 0
    for gp in GUARD_POINTS:  # metering decision: one request each, usage unknown, not answered
        assert meter.unanswered_attempts(ALPHA, gp) == 1
        assert meter.metered_calls(ALPHA, gp) == 0
        assert meter.unknown_calls(ALPHA, gp) == 0
    assert not env.service.gateway.breaker_open()

    # The provider's free text is in nothing recorded: verdicts, the audit records, spans.
    spans = exporter.get_finished_spans()
    assert spans
    assert_no_provider_text(
        *(repr(v) for v in verdicts),
        *(str(v) for v in verdicts),
        *(v.model_dump_json() for v in verdicts),
        *(repr(r) for r in env.audit.records),
        *(r.model_dump_json() for r in env.audit.records),
        *(f"{k}={v!r}" for span in spans for k, v in span.attributes.items()),
        *(repr(e.attributes) for span in spans for e in span.events),
        *(str(span.status.description) for span in spans),
    )
    # Logs: only the Guard Service's DEBUG line may carry it, truncated. The
    # sentinel sits past the truncation point, so it appears in no log line at all.
    assert SENTINEL not in caplog.text
    with_text = [r for r in caplog.records if OBSERVED_PREFIX in r.getMessage()]
    assert len(with_text) == len(GUARD_POINTS)
    for record in with_text:
        assert record.levelno == logging.DEBUG
        assert record.name == "guardrail_engine.guard.service"
    assert_no_provider_text(*(r.getMessage() for r in caplog.records if r.levelno > logging.DEBUG))


async def test_refusal_blocks_whatever_the_rule_modes_and_fail_modes():
    """PF-12 for a refusal before scoring: open floor, open tenant, a shadow rule."""
    replay = Replay("reconstructed_prohibited_content_400")
    settings = PlatformSettings(floor_fail_mode="open")
    async with Env(fake=replay.model, settings=settings) as env:
        await env.publish(
            bundle(ALPHA, rules=[rule("adv", mode="shadow")], defaults={"fail_mode": "open"})
        )
        verdict = await env.check(ALPHA, "output", CONTENT)
    assert_refusal_verdict(verdict, "output")
