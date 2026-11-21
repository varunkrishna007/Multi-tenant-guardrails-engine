"""M1-11: once shutdown starts, ``Engine.check`` returns ``block`` with reason
``engine_closed``, ``retryable`` true, ``provider_called`` false and no ``retry_after_ms``, and
never raises (decided 2026-11-17). The verdict is audited and traced like any other, with no
model-call span. Checks racing with shutdown either run normally (started before) or get that
verdict (started after); none raises and none is lost.
"""

from __future__ import annotations

import asyncio
import logging

import pytest
from engine_fixtures import TENANT, bundle, ctx, directory, settings, verifier
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from guardrail_engine.decision import FakeDecisionModel
from guardrail_engine.engine import build_engine
from guardrail_engine.guard import CheckContext, Decision, InMemoryAuditSink, Reason
from guardrail_engine.guard.audit import AuditRecord
from guardrail_engine.telemetry.adapters.otel import CHECK_SPAN, MODEL_CALL_SPAN, OtelTelemetry


@pytest.fixture
def otel():
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    yield provider, exporter
    provider.shutdown()


async def build(**kwargs):
    v = verifier()
    fake = kwargs.pop("model", None) or FakeDecisionModel()
    audit = InMemoryAuditSink()
    engine = await build_engine(
        kwargs.pop("settings", None) or settings(),
        verifier=v,
        tenants=directory(),
        model=fake,
        audit=audit,
        **kwargs,
    )
    await engine.bootstrap_publish(bundle())
    return engine, v, fake, audit


def assert_engine_closed(verdict) -> None:
    assert (verdict.decision, verdict.reason) == (Decision.BLOCK, Reason.ENGINE_CLOSED)
    assert verdict.retryable is True
    assert verdict.released is False
    assert verdict.provider_called is False and verdict.provider_calls == 0
    assert verdict.model_called is False
    # M1-15 added the R8 fields to the verdict. Per the decision: no hint (retry on another
    # instance), and not a capacity refusal (engine_closed isn't in R8's enum of provider and
    # capacity failures). No gateway call was made, so no in-flight count either.
    assert verdict.retry_after_ms is None
    assert verdict.capacity_limited is False
    assert verdict.in_flight_at_start is None
    assert verdict.failure_reason is None and verdict.failure_kind is None
    record = AuditRecord.from_verdict(verdict).model_dump()
    assert record["in_flight_at_start"] is None
    assert record["retry_after_ms"] is None and record["capacity_limited"] is False


async def test_a_check_after_shutdown_returns_engine_closed_and_is_audited():
    engine, v, fake, audit = await build()
    await engine.shutdown()
    calls = len(fake.calls)
    verdict = await engine.check(ctx(v), "output", "Hello.")  # no exception
    assert_engine_closed(verdict)
    assert verdict.tenant_id == TENANT  # the signed context verified
    assert verdict.content_sha256 is not None and verdict.guard_point == "output"
    assert len(fake.calls) == calls  # nothing reached the model
    assert audit.verdicts[-1] is verdict
    record = AuditRecord.from_verdict(verdict)
    assert (record.decision, record.reason, record.retryable) == (
        Decision.BLOCK,
        Reason.ENGINE_CLOSED,
        True,
    )
    assert record.model_called is False and record.provider_called is False


async def test_a_check_right_after_shutdown_is_called_gets_engine_closed():
    """Shutdown stops accepting at once, before its first await."""
    engine, v, _, _ = await build()
    shutting_down = asyncio.ensure_future(engine.shutdown())
    await asyncio.sleep(0)
    assert not engine.accepting
    assert_engine_closed(await engine.check(ctx(v), "output", "Hello."))
    await shutting_down


@pytest.mark.parametrize(
    ("context", "guard_point", "content"),
    [
        (CheckContext(signed_context="not-a-signed-context"), "output", "Hello."),
        (None, "output", "Hello."),
        ("ctx", 42, None),
        (CheckContext(signed_context=None), "no-such-point", b"bytes"),
    ],
)
async def test_engine_closed_never_raises_whatever_the_request(context, guard_point, content):
    engine, _, _, audit = await build()
    await engine.shutdown()
    verdict = await engine.check(context, guard_point, content)
    assert_engine_closed(verdict)
    assert verdict.tenant_id is None  # nothing verified, so no tenant is recorded
    assert audit.verdicts[-1] is verdict


async def test_engine_closed_survives_a_failing_audit_sink(caplog):
    class BrokenAudit:
        def record(self, verdict) -> None:
            raise RuntimeError("audit queue full")

    v = verifier()
    engine = await build_engine(
        settings(), verifier=v, tenants=directory(), model=FakeDecisionModel(), audit=BrokenAudit()
    )
    await engine.shutdown()
    assert_engine_closed(await engine.check(ctx(v), "output", "Hello."))
    assert "audit sink failed" in caplog.text


async def test_engine_closed_never_raises_even_if_the_guard_service_does(monkeypatch, caplog):
    engine, v, _, _ = await build()
    await engine.shutdown()

    def broken(*args: object) -> None:
        raise RuntimeError("bug")

    monkeypatch.setattr(engine.guard, "refuse_closed", broken)
    with caplog.at_level(logging.ERROR):
        verdict = await engine.check(ctx(v), "output", "Hello.")
    assert (verdict.decision, verdict.reason) == (Decision.BLOCK, Reason.ENGINE_CLOSED)
    assert verdict.retryable
    assert "engine_closed verdict failed" in caplog.text


async def test_engine_closed_gets_a_check_span_and_no_model_call_span(otel):
    provider, exporter = otel
    engine, v, _, _ = await build(telemetry=OtelTelemetry(provider))
    await engine.check(ctx(v), "output", "Hello.")  # a normal check: both spans
    await engine.shutdown()
    exporter.clear()
    await engine.check(ctx(v), "output", "Hello.")
    spans = exporter.get_finished_spans()
    assert [s.name for s in spans] == [CHECK_SPAN]
    attributes = dict(spans[0].attributes)
    assert attributes["guardrail.decision"] == "block"
    assert attributes["guardrail.reason"] == "engine_closed"
    assert attributes["guardrail.model_called"] is False
    assert attributes["guardrail.provider_called"] is False
    assert attributes["guardrail.tenant_id"] == TENANT
    assert "guardrail.in_flight_at_start" not in attributes  # no gateway call (M1-15)
    assert attributes["guardrail.capacity_limited"] is False
    assert "guardrail.retry_after_ms" not in attributes
    assert MODEL_CALL_SPAN not in {s.name for s in spans}


async def test_checks_racing_with_shutdown_all_get_a_verdict():
    """Checks started before shutdown finish normally (the drain waits for them); checks
    started during the drain or after it get ``engine_closed``. Nothing raises, and every
    check is audited exactly once."""
    fake = FakeDecisionModel().slow_next(0.2, times=6)
    engine, v, fake, audit = await build(
        model=fake, settings=settings(gateway={"max_in_flight_per_key": 8})
    )
    audited_before = len(audit.verdicts)
    early = [asyncio.create_task(engine.check(ctx(v), "output", f"Early {i}.")) for i in range(6)]
    await asyncio.sleep(0.05)  # they are in the model call
    assert engine.in_flight == 6
    shutting_down = asyncio.create_task(engine.shutdown())
    during = [asyncio.create_task(engine.check(ctx(v), "output", f"During {i}.")) for i in range(6)]
    results = await asyncio.gather(*early, *during, return_exceptions=True)
    await shutting_down
    after = [await engine.check(ctx(v), "output", "After.") for _ in range(3)]

    assert not [r for r in results if isinstance(r, BaseException)]
    early_verdicts, during_verdicts = results[:6], results[6:]
    assert all(r.reason is not Reason.ENGINE_CLOSED for r in early_verdicts)
    assert all(r.decision is Decision.ALLOW for r in early_verdicts)  # not cut off
    for verdict in [*during_verdicts, *after]:
        assert_engine_closed(verdict)
    assert len(fake.calls) == 6  # one per early check; none for the refused ones
    new = audit.verdicts[audited_before:]
    assert sorted(id(x) for x in new) == sorted(id(x) for x in [*results, *after])
