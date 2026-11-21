"""M1-06: OpenTelemetry spans per check (AC-O2) and connection reuse on the model-call span.

Spans are collected with the SDK's in-memory exporter on a tracer provider passed to the
adapter; the global provider is never set, so other tests run with the API's no-op default.
The connection-reuse tests run the real Gemini adapter against a local HTTP/1.1 server on
127.0.0.1 (no network, no API key).
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Sequence
from contextlib import suppress

import httpx
import pytest
from guard_fixtures import ALPHA, Env, bundle, rule
from opentelemetry import trace
from opentelemetry.sdk.trace import ReadableSpan, TracerProvider
from opentelemetry.sdk.trace.export import (
    SimpleSpanProcessor,
    SpanExporter,
    SpanExportResult,
)
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.trace import StatusCode

from guardrail_engine.decision import Failed, FailureKind
from guardrail_engine.decision.adapters.gemini import (
    CallInfo,
    ConnectionUse,
    GeminiConfig,
    GeminiDecisionModel,
)
from guardrail_engine.gateway import GatewayConfig
from guardrail_engine.guard import Decision, GuardConfig, Reason
from guardrail_engine.telemetry import NullTelemetry
from guardrail_engine.telemetry.adapters.otel import (
    CHECK_SPAN,
    CONNECTION_REUSED,
    MODEL_CALL_SPAN,
    PROVIDER_CALL_EVENT,
    OtelTelemetry,
    connection_reuse_hook,
)
from guardrail_engine.telemetry.port import CHECK_ATTRIBUTES, MODEL_CALL_ATTRIBUTES

SENTINEL_CONTENT = "SPAN-CONTENT-SENTINEL-91c2"
SENTINEL_KEY = "SPAN-KEY-SENTINEL-not-a-real-key"


@pytest.fixture
def otel():
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    yield provider, exporter
    provider.shutdown()


def named(exporter: InMemorySpanExporter, name: str) -> list[ReadableSpan]:
    return [s for s in exporter.get_finished_spans() if s.name == name]


def only(exporter: InMemorySpanExporter, name: str) -> ReadableSpan:
    [span] = named(exporter, name)
    return span


# ------------------------------------------------------------------ AC-O2


async def test_ac_o2_every_check_emits_a_span_with_the_required_attributes(otel):
    provider, exporter = otel
    async with Env(telemetry=OtelTelemetry(provider)) as env:
        await env.publish(bundle(ALPHA, rules=[rule("adv")]))
        env.fake.set_noul("t__adv", 0.9)
        verdict = await env.check(ALPHA)

    span = only(exporter, CHECK_SPAN)
    attrs = dict(span.attributes)
    assert attrs["guardrail.tenant_id"] == ALPHA
    assert attrs["guardrail.bundle_version"] == 1
    assert attrs["guardrail.guard_point"] == "output"
    assert attrs["guardrail.latency_ms"] == verdict.latency_ms > 0
    assert attrs["guardrail.input_tokens"] == verdict.input_tokens > 0
    assert attrs["guardrail.decision"] == "block"
    assert attrs["guardrail.reason"] == "policy"
    assert attrs["guardrail.fired"] == ("t__adv",)
    assert (
        attrs["guardrail.model_called"],
        attrs["guardrail.provider_called"],
        attrs["guardrail.provider_calls"],
    ) == (
        True,
        True,
        1,
    )
    assert span.status.status_code is StatusCode.UNSET
    assert span.end_time >= span.start_time


async def test_ac_o2_the_model_call_gets_a_child_span_with_its_timing(otel):
    provider, exporter = otel
    async with Env(telemetry=OtelTelemetry(provider)) as env:
        await env.publish(bundle(ALPHA))
        env.fake.fail_next(FailureKind.UNAVAILABLE)  # one retry
        await env.check(ALPHA)

    check, call = only(exporter, CHECK_SPAN), only(exporter, MODEL_CALL_SPAN)
    assert call.parent is not None and call.parent.span_id == check.context.span_id
    assert call.context.trace_id == check.context.trace_id
    assert call.kind is trace.SpanKind.CLIENT
    attrs = dict(call.attributes)
    assert (
        attrs["guardrail.outcome"],
        attrs["guardrail.provider_calls"],
        attrs["guardrail.provider_called"],
    ) == (
        "answered",
        2,
        True,
    )
    assert attrs["guardrail.model"] == "fake-decision"
    assert attrs["guardrail.queue_wait_ms"] >= 0 and attrs["guardrail.provider_latency_ms"] >= 0
    assert CONNECTION_REUSED not in attrs  # the fake has no connections: absent, not guessed


async def test_ac_o2_checks_without_a_model_call_still_get_a_span(otel):
    provider, exporter = otel
    async with Env(telemetry=OtelTelemetry(provider)) as env:
        await env.publish(bundle(ALPHA))
        await env.check(ALPHA, content="x " * 200_000)  # too large: no model call
        await env.service.check(env.ctx(ALPHA, payload_tenant_id="t_x"), "output", "hi")
        await env.check(ALPHA, "not-a-guard-point")

    spans = named(exporter, CHECK_SPAN)
    assert [s.attributes["guardrail.reason"] for s in spans] == [
        "content_too_large",
        "tenant_mismatch",
        "invalid_request",
    ]
    assert [s.attributes["guardrail.decision"] for s in spans] == ["block", "forbidden", "block"]
    assert all(s.attributes["guardrail.model_called"] is False for s in spans)
    assert all(s.attributes["guardrail.provider_calls"] == 0 for s in spans)
    assert "guardrail.input_tokens" not in spans[0].attributes  # unknown: left out
    assert named(exporter, MODEL_CALL_SPAN) == []


async def test_ac_o2_admission_refusal_span_shows_the_model_path_without_a_provider_call(otel):
    provider, exporter = otel
    one_slot = GatewayConfig(max_in_flight_per_key=1, default_budget_s=0.3, expected_latency_s=0.2)
    config = GuardConfig(pointer_ttl_s=60.0, gateway=one_slot)
    async with Env(telemetry=OtelTelemetry(provider), config=config) as env:
        await env.publish(bundle(ALPHA))
        env.fake.slow_next(5.0)
        holder = asyncio.ensure_future(env.check(ALPHA))
        await asyncio.sleep(0.05)
        refused = await env.check(ALPHA)
        await holder

    [span] = [
        s
        for s in named(exporter, CHECK_SPAN)
        if s.attributes["guardrail.request_id"] == refused.request_id
    ]
    attrs = dict(span.attributes)
    assert (
        attrs["guardrail.model_called"],
        attrs["guardrail.provider_called"],
        attrs["guardrail.provider_calls"],
    ) == (
        True,
        False,
        0,
    )
    assert (attrs["guardrail.failure_kind"], attrs["guardrail.failure_reason"]) == (
        "unavailable",
        "admission_wait",
    )


async def test_m1_15_the_check_span_records_the_in_flight_count_at_check_start(otel):
    """M1-15 (R6.3): the calls in flight on the key when the check reached the gateway, so
    the dogfood can settle the in-flight limit. A check with no decision call leaves it out
    (unknown values are left out, not sent as placeholders)."""
    provider, exporter = otel
    one_slot = GatewayConfig(max_in_flight_per_key=1, default_budget_s=0.3, expected_latency_s=0.2)
    config = GuardConfig(pointer_ttl_s=60.0, gateway=one_slot)
    async with Env(telemetry=OtelTelemetry(provider), config=config) as env:
        await env.publish(bundle(ALPHA))
        env.fake.slow_next(5.0)
        holder = asyncio.ensure_future(env.check(ALPHA))
        await asyncio.sleep(0.05)
        refused = await env.check(ALPHA)
        held = await holder
        no_call = await env.check(ALPHA, content="x" * 400_000)  # deterministic size block

    by_request = {s.attributes["guardrail.request_id"]: s for s in named(exporter, CHECK_SPAN)}
    assert "guardrail.in_flight_at_start" in CHECK_ATTRIBUTES
    assert by_request[held.request_id].attributes["guardrail.in_flight_at_start"] == 0
    assert by_request[refused.request_id].attributes["guardrail.in_flight_at_start"] == 1
    assert "guardrail.in_flight_at_start" not in by_request[no_call.request_id].attributes
    # Decided on the M1-15 build: the capacity signal is on the span too, with failure_reason.
    refused_attrs = by_request[refused.request_id].attributes
    assert refused_attrs["guardrail.capacity_limited"] is True
    assert refused_attrs["guardrail.retry_after_ms"] == refused.retry_after_ms
    assert 100 <= refused.retry_after_ms <= 200
    assert refused_attrs["guardrail.failure_reason"] == "admission_wait"
    held_attrs = by_request[held.request_id].attributes
    assert held_attrs["guardrail.capacity_limited"] is False
    assert "guardrail.retry_after_ms" not in held_attrs  # unknown values are left out
    assert {"guardrail.capacity_limited", "guardrail.retry_after_ms"} <= set(CHECK_ATTRIBUTES)


async def test_ac_o2_concurrent_checks_each_parent_their_own_model_call_span(otel):
    provider, exporter = otel
    async with Env(telemetry=OtelTelemetry(provider)) as env:
        await env.publish(bundle(ALPHA))
        for _ in range(6):
            env.fake.slow_next(0.02)
        verdicts = await asyncio.gather(*(env.check(ALPHA, request_id=f"r{i}") for i in range(6)))

    checks = {s.attributes["guardrail.request_id"]: s for s in named(exporter, CHECK_SPAN)}
    assert set(checks) == {v.request_id for v in verdicts}
    parents = sorted(s.parent.span_id for s in named(exporter, MODEL_CALL_SPAN))
    assert parents == sorted(s.context.span_id for s in checks.values())
    assert len({s.context.trace_id for s in checks.values()}) == 6  # each check is its own trace


async def test_ac_o2_a_cancelled_check_ends_its_spans_with_an_error_status(otel):
    provider, exporter = otel
    async with Env(telemetry=OtelTelemetry(provider)) as env:
        await env.publish(bundle(ALPHA))
        env.fake.slow_next(5.0)
        task = asyncio.ensure_future(env.check(ALPHA))
        await asyncio.sleep(0.05)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    check = only(exporter, CHECK_SPAN)
    assert check.status.status_code is StatusCode.ERROR
    assert check.attributes["guardrail.cancelled"] is True
    assert only(exporter, MODEL_CALL_SPAN).end_time is not None
    assert trace.get_current_span() is trace.INVALID_SPAN  # nothing left attached


async def test_ac_o2_an_internal_error_marks_the_span_as_an_error(otel):
    provider, exporter = otel
    async with Env(telemetry=OtelTelemetry(provider), nonce_source=lambda: "not-hex") as env:
        await env.publish(bundle(ALPHA))
        verdict = await env.check(ALPHA)
    assert verdict.reason is Reason.INTERNAL_ERROR
    assert only(exporter, CHECK_SPAN).status.status_code is StatusCode.ERROR


async def test_ac_o2_the_engine_works_with_no_tracer_provider_configured():
    """The global provider is the API's default proxy (nothing configured): spans are
    no-ops and every check behaves exactly as without telemetry."""
    assert not isinstance(trace.get_tracer_provider(), TracerProvider)
    results = []
    for telemetry in (NullTelemetry(), OtelTelemetry(), None):
        async with Env(telemetry=telemetry) as env:
            await env.publish(bundle(ALPHA, rules=[rule("adv")]))
            env.fake.set_noul("t__adv", 0.6)
            results.append(await env.check(ALPHA))
    assert {(v.decision, v.reason) for v in results} == {(Decision.ESCALATE, Reason.POLICY)}
    # The hook is a no-op outside a recording span, too.
    connection_reuse_hook(CallInfo(connection=ConnectionUse.NEW))


# ------------------------------------------------------------------ never changes a verdict


class FailingExporter(SpanExporter):
    def export(self, spans: Sequence[ReadableSpan]) -> SpanExportResult:
        raise RuntimeError("collector down")

    def shutdown(self) -> None:
        pass


class RaisingTelemetry:
    """Raises at one stage of the port's call sequence."""

    def __init__(self, stage: str) -> None:
        self.stage = stage

    def start_check(self):
        if self.stage == "start_check":
            raise RuntimeError("telemetry down")
        return self

    def model_call_started(self):
        if self.stage == "model_call_started":
            raise RuntimeError("telemetry down")

    def model_call_ended(self, attributes):
        if self.stage == "model_call_ended":
            raise RuntimeError("telemetry down")

    def end(self, attributes, *, error=False):
        if self.stage == "end":
            raise RuntimeError("telemetry down")


def failing_exporter_telemetry():
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(FailingExporter()))
    return OtelTelemetry(provider)


TELEMETRY_FAILURES = {
    "exporter raises": failing_exporter_telemetry,
    **{
        f"port raises at {stage}": (lambda stage=stage: RaisingTelemetry(stage))
        for stage in ("start_check", "model_call_started", "model_call_ended", "end")
    },
}


@pytest.mark.parametrize("failure", sorted(TELEMETRY_FAILURES))
@pytest.mark.parametrize(
    ("p", "decision"), [(0.01, Decision.ALLOW), (0.6, Decision.ESCALATE), (0.99, Decision.BLOCK)]
)
async def test_failing_telemetry_never_changes_or_loses_the_verdict(failure, p, decision):
    results = []
    for telemetry in (None, TELEMETRY_FAILURES[failure]()):
        async with Env(telemetry=telemetry) as env:
            await env.publish(bundle(ALPHA, rules=[rule("adv")]))
            env.fake.set_noul("t__adv", p)
            results.append(await env.check(ALPHA))
            records = env.audit.records
        assert len(records) == 1  # still audited
    plain, with_failure = results
    assert with_failure.decision is plain.decision is decision
    assert with_failure.reason is plain.reason
    assert [f.key for f in with_failure.fired] == [f.key for f in plain.fired]


async def test_failing_telemetry_on_a_model_failure_still_blocks():
    async with Env(telemetry=RaisingTelemetry("model_call_ended")) as env:
        await env.publish(bundle(ALPHA, defaults={"fail_mode": "open"}))
        env.fake.always(Failed(kind=FailureKind.TIMEOUT))
        verdict = await env.check(ALPHA)
    assert (verdict.decision, verdict.reason) == (Decision.BLOCK, Reason.MODEL_FAILURE)


# ------------------------------------------------------------------ connection reuse (M1-10 hook)


class DecisionServer:
    """A keep-alive HTTP/1.1 server answering each Decisions API request with a ``noul`` of
    0.01 for every question asked. ``fail_next`` makes the next responses 503."""

    def __init__(self) -> None:
        self.connections_opened = 0
        self.requests: list[dict] = []
        self.headers: list[bytes] = []
        self.fail_next = 0
        self._writers: set[asyncio.StreamWriter] = set()
        self._tasks: set[asyncio.Task] = set()

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.base_url = f"http://127.0.0.1:{self._server.sockets[0].getsockname()[1]}/v1beta"

    async def stop(self) -> None:
        self._server.close()
        for writer in list(self._writers):
            writer.close()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        await self._server.wait_closed()

    async def close_connections(self) -> None:
        for writer in list(self._writers):
            writer.close()
        await asyncio.sleep(0.01)

    async def _handle(self, reader, writer) -> None:
        self.connections_opened += 1
        self._writers.add(writer)
        task = asyncio.current_task()
        self._tasks.add(task)
        try:
            while True:
                head = await reader.readuntil(b"\r\n\r\n")
                length = next(
                    int(v)
                    for n, _, v in (line.partition(b":") for line in head.split(b"\r\n")[1:])
                    if n.strip().lower() == b"content-length"
                )
                body = json.loads(await reader.readexactly(length))
                self.requests.append(body)
                self.headers.append(head)
                if self.fail_next:
                    self.fail_next -= 1
                    status, payload = b"503 Service Unavailable", {"error": {"code": 503}}
                else:
                    status = b"200 OK"
                    payload = {
                        "answers": {
                            key: {"type": "noul", "noul": 0.01, "confidence": 0.9}
                            for key in body["questions"]
                        },
                        "usage": {"total_input_tokens": 321, "total_output_tokens": 0},
                    }
                data = json.dumps(payload).encode()
                writer.write(
                    b"HTTP/1.1 " + status + b"\r\ncontent-type: application/json\r\n"
                    b"content-length: %d\r\n\r\n" % len(data) + data
                )
                await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            self._writers.discard(writer)
            self._tasks.discard(task)
            writer.close()
            with suppress(OSError):
                await writer.wait_closed()


@pytest.fixture(autouse=True)
def _no_proxy(monkeypatch):
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.delenv("all_proxy", raising=False)


@pytest.fixture
async def server():
    srv = DecisionServer()
    await srv.start()
    yield srv
    await srv.stop()


def gemini(base_url: str, **kwargs) -> GeminiDecisionModel:
    config = GeminiConfig(api_key=SENTINEL_KEY, paid_tier=True, base_url=base_url)
    return GeminiDecisionModel(config, on_call=connection_reuse_hook, **kwargs)


def reuse_of(span: ReadableSpan):
    return span.attributes.get(CONNECTION_REUSED)


def call_events(span: ReadableSpan) -> list[bool]:
    return [e.attributes[CONNECTION_REUSED] for e in span.events if e.name == PROVIDER_CALL_EVENT]


async def test_connection_reused_is_false_on_a_cold_call_and_true_on_a_warm_one(otel, server):
    provider, exporter = otel
    async with (
        gemini(server.base_url) as model,
        Env(fake=model, telemetry=OtelTelemetry(provider)) as env,
    ):
        await env.publish(bundle(ALPHA))
        first = await env.check(ALPHA)
        second = await env.check(ALPHA)
        await server.close_connections()  # the server drops the idle connection
        third = await env.check(ALPHA)

    assert [v.decision for v in (first, second, third)] == [Decision.ALLOW] * 3
    calls = named(exporter, MODEL_CALL_SPAN)
    assert [reuse_of(s) for s in calls] == [False, True, False]
    assert [call_events(s) for s in calls] == [[False], [True], [False]]
    assert server.connections_opened == 2
    # The check spans parent their model-call spans.
    checks = named(exporter, CHECK_SPAN)
    assert [c.parent.span_id for c in calls] == [s.context.span_id for s in checks]


async def test_connection_reused_with_a_retry_is_false_if_any_call_was_cold(otel, server):
    provider, exporter = otel
    server.fail_next = 1  # 503, retried by the gateway on the same (now warm) connection
    async with (
        gemini(server.base_url) as model,
        Env(fake=model, telemetry=OtelTelemetry(provider)) as env,
    ):
        await env.publish(bundle(ALPHA))
        verdict = await env.check(ALPHA)

    assert (verdict.decision, verdict.provider_calls) == (Decision.ALLOW, 2)
    call = only(exporter, MODEL_CALL_SPAN)
    assert call_events(call) == [False, True]
    assert reuse_of(call) is False


async def test_connection_reused_is_absent_when_the_transport_cannot_tell(otel):
    """An injected client whose transport emits no httpcore trace events (MockTransport):
    the adapter reports ``connection=None`` and the attribute is left out."""
    provider, exporter = otel

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        answers = {k: {"type": "noul", "noul": 0.01, "confidence": 0.9} for k in body["questions"]}
        return httpx.Response(200, json={"answers": answers, "usage": {"total_input_tokens": 9}})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    async with (
        client,
        gemini("http://mock.invalid/v1beta", client=client) as model,
        Env(fake=model, telemetry=OtelTelemetry(provider)) as env,
    ):
        await env.publish(bundle(ALPHA))
        verdict = await env.check(ALPHA)
    assert verdict.decision is Decision.ALLOW
    call = only(exporter, MODEL_CALL_SPAN)
    assert CONNECTION_REUSED not in call.attributes
    assert call_events(call) == []


@pytest.mark.parametrize(
    ("connection", "expected"),
    [(ConnectionUse.REUSED, True), (ConnectionUse.NEW, False), (None, None)],
)
def test_the_hook_sets_connection_reused_on_the_current_model_call_span(otel, connection, expected):
    provider, exporter = otel
    check = OtelTelemetry(provider).start_check()
    connection_reuse_hook(CallInfo(connection=connection))  # no model call yet: ignored
    check.model_call_started()
    connection_reuse_hook(CallInfo(connection=connection))
    check.model_call_ended({})
    connection_reuse_hook(CallInfo(connection=ConnectionUse.NEW))  # after it ended: ignored
    check.end({})

    assert reuse_of(only(exporter, MODEL_CALL_SPAN)) == expected
    assert CONNECTION_REUSED not in only(exporter, CHECK_SPAN).attributes


def test_the_hook_never_raises():
    connection_reuse_hook(object())  # no ``connection`` attribute
    connection_reuse_hook(None)
    connection_reuse_hook(CallInfo(connection=ConnectionUse.REUSED))  # no check at all


# ------------------------------------------------------------------ nothing sensitive on a span


ALLOWED_CHECK_ATTRIBUTES = set(CHECK_ATTRIBUTES)
ALLOWED_MODEL_CALL_ATTRIBUTES = set(MODEL_CALL_ATTRIBUTES)


def all_values(span: ReadableSpan) -> list[str]:
    values = [str(v) for v in span.attributes.values()]
    values += [str(v) for e in span.events for v in e.attributes.values()]
    values += [span.name, str(span.status.description)]
    return values


async def test_spans_never_carry_content_the_api_key_or_request_headers(otel, server):
    provider, exporter = otel
    server.fail_next = 1
    async with (
        gemini(server.base_url) as model,
        Env(fake=model, telemetry=OtelTelemetry(provider)) as env,
    ):
        await env.publish(bundle(ALPHA, rules=[rule("adv")]))
        await env.check(ALPHA, content=SENTINEL_CONTENT)
        await env.check(ALPHA, "input", content=SENTINEL_CONTENT + " again")

    assert any(SENTINEL_KEY.encode() in h for h in server.headers)  # the key was sent...
    assert any(SENTINEL_CONTENT in r["input"] for r in server.requests)  # ...and the content
    spans = exporter.get_finished_spans()
    assert {s.name for s in spans} == {CHECK_SPAN, MODEL_CALL_SPAN}
    for span in spans:
        allowed = (
            ALLOWED_CHECK_ATTRIBUTES if span.name == CHECK_SPAN else ALLOWED_MODEL_CALL_ATTRIBUTES
        )
        assert set(span.attributes) <= allowed, set(span.attributes) - allowed
        for value in all_values(span):
            assert SENTINEL_CONTENT not in value
            assert SENTINEL_KEY not in value
            assert "x-goog-api-key" not in value.lower()
            assert "content-type" not in value.lower()


# ------------------------------------------------------------------ namespaced names


async def test_every_span_attribute_and_event_is_namespaced(otel, server):
    provider, exporter = otel
    server.fail_next = 1  # a retry, so the model-call span gets two events
    async with (
        gemini(server.base_url) as model,
        Env(fake=model, telemetry=OtelTelemetry(provider)) as env,
    ):
        await env.publish(bundle(ALPHA, rules=[rule("adv")]))
        await env.check(ALPHA)
        await env.check(ALPHA, "not-a-guard-point")
    spans = exporter.get_finished_spans()
    assert spans
    for span in spans:
        assert span.attributes
        assert all(k.startswith("guardrail.") for k in span.attributes), dict(span.attributes)
        for event in span.events:
            assert event.name.startswith("guardrail.")
            assert all(k.startswith("guardrail.") for k in event.attributes)
    # The AC-O2 names are the suffixes.
    check = named(exporter, CHECK_SPAN)[0]
    for name in ("tenant_id", "bundle_version", "guard_point", "latency_ms", "decision"):
        assert f"guardrail.{name}" in check.attributes
    assert CONNECTION_REUSED == "guardrail.connection_reused"
    assert all(a.startswith("guardrail.") for a in (*CHECK_ATTRIBUTES, *MODEL_CALL_ATTRIBUTES))


def test_an_attribute_outside_the_ports_list_is_refused():
    from guardrail_engine.guard import telemetry as guard_telemetry

    with pytest.raises(ValueError, match="not in the port's list"):
        guard_telemetry._present({"content": "x"}, CHECK_ATTRIBUTES)
