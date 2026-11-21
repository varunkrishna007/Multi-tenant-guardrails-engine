"""M1-11 wires M1-06: the composed engine passes the telemetry port to the Guard Service and the
telemetry adapter's connection-reuse hook to the Gemini adapter, so a check produces the
``guard.check`` span and its ``guard.model_call`` child with ``guardrail.*`` attributes, and
the model-call span says whether the connection was reused (cold-call rate, M1-10).

Spans go to the SDK's in-memory exporter on a provider passed in; the global provider is never
set. The adapter talks to a local server on 127.0.0.1 (no network, a sentinel key).
"""

from __future__ import annotations

import pytest
from engine_fixtures import TENANT, adapter_settings, bundle, ctx, directory, settings, verifier
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from guardrail_engine.decision import FakeDecisionModel
from guardrail_engine.decision.adapters.gemini import CallInfo
from guardrail_engine.engine import build_engine
from guardrail_engine.guard import Decision
from guardrail_engine.telemetry.adapters.otel import (
    CHECK_SPAN,
    CONNECTION_REUSED,
    MODEL_CALL_SPAN,
    OtelTelemetry,
)
from guardrail_engine.telemetry.port import CHECK_ATTRIBUTES, MODEL_CALL_ATTRIBUTES

KEY = "sentinel-not-a-real-key-m1-11-telemetry"


@pytest.fixture
def otel():
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    yield provider, exporter
    provider.shutdown()


def spans(exporter, name):
    return [s for s in exporter.get_finished_spans() if s.name == name]


async def test_a_check_through_the_composed_engine_emits_both_spans(monkeypatch, server, otel):
    provider, exporter = otel
    monkeypatch.setenv("GEMINI_API_KEY", KEY)
    v = verifier()
    s = adapter_settings(gemini={"base_url": server.base_url})
    async with await build_engine(
        s, verifier=v, tenants=directory(), telemetry=OtelTelemetry(provider)
    ) as engine:
        await engine.bootstrap_publish(bundle())
        verdicts = [await engine.check(ctx(v), "output", "Hello.") for _ in range(2)]
    assert all(verdict.decision is Decision.ALLOW for verdict in verdicts)

    checks, calls = spans(exporter, CHECK_SPAN), spans(exporter, MODEL_CALL_SPAN)
    assert len(checks) == 2 and len(calls) == 2
    for check, call, verdict in zip(checks, calls, verdicts, strict=True):
        assert call.parent is not None and call.parent.span_id == check.context.span_id
        attributes = dict(check.attributes)
        assert set(attributes) <= set(CHECK_ATTRIBUTES)
        assert all(name.startswith("guardrail.") for name in attributes)
        assert attributes["guardrail.tenant_id"] == TENANT
        assert attributes["guardrail.guard_point"] == "output"
        assert attributes["guardrail.bundle_version"] == 1
        assert attributes["guardrail.decision"] == "allow"
        assert attributes["guardrail.request_id"] == verdict.request_id
        assert attributes["guardrail.input_tokens"] == 100
        assert attributes["guardrail.provider_calls"] == 1
        assert "guardrail.latency_ms" in attributes
        call_attributes = dict(call.attributes)
        assert set(call_attributes) <= set(MODEL_CALL_ATTRIBUTES)
        assert call_attributes["guardrail.model"] == "gemini-decision-1"
        assert call_attributes["guardrail.outcome"] == "answered"
    # The adapter's connection-reuse hook reached the model-call span: cold, then warm.
    assert [c.attributes[CONNECTION_REUSED] for c in calls] == [False, True]
    assert server.connections == 1
    for span in exporter.get_finished_spans():  # nothing secret on any span
        assert KEY not in str(dict(span.attributes)) and KEY not in span.name


async def test_a_callers_connection_hook_does_not_switch_off_the_span_hook(
    monkeypatch, server, otel
):
    provider, exporter = otel
    monkeypatch.setenv("GEMINI_API_KEY", KEY)
    seen: list[CallInfo] = []
    v = verifier()
    s = adapter_settings(gemini={"base_url": server.base_url})
    async with await build_engine(
        s,
        verifier=v,
        tenants=directory(),
        telemetry=OtelTelemetry(provider),
        connection_hook=seen.append,
    ) as engine:
        await engine.bootstrap_publish(bundle())
        await engine.check(ctx(v), "output", "Hello.")
    assert len(seen) == 1
    [call] = spans(exporter, MODEL_CALL_SPAN)
    assert call.attributes[CONNECTION_REUSED] is False


async def test_the_fake_model_gets_the_same_spans(otel):
    provider, exporter = otel
    v = verifier()
    async with await build_engine(
        settings(),
        verifier=v,
        tenants=directory(),
        model=FakeDecisionModel(),
        telemetry=OtelTelemetry(provider),
    ) as engine:
        await engine.bootstrap_publish(bundle())
        await engine.check(ctx(v), "output", "Hello.")
    [check], [call] = spans(exporter, CHECK_SPAN), spans(exporter, MODEL_CALL_SPAN)
    assert check.attributes["guardrail.decision"] == "allow"
    assert call.attributes["guardrail.model"] == "fake-decision"
    assert CONNECTION_REUSED not in call.attributes  # the fake reports no connection


async def test_the_default_telemetry_is_opentelemetry_on_the_global_provider():
    """With no provider configured the OpenTelemetry API is a no-op, so the default costs
    nothing until the embedding process sets up the SDK."""
    engine = await build_engine(settings(), verifier=verifier(), model=FakeDecisionModel())
    try:
        assert isinstance(engine.telemetry, OtelTelemetry)
        assert engine.guard._telemetry is engine.telemetry
    finally:
        await engine.shutdown()
