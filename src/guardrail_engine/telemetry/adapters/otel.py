"""OpenTelemetry implementation of the telemetry port (M1-06, AC-O2).

Uses only the OpenTelemetry **API**. With no tracer provider configured (the API's default)
every span is a no-op and the engine runs unchanged. The process that embeds the engine
configures the SDK and exporters; tests pass their own provider.

Spans, per check:

* ``guard.check``: the whole check. Attributes from
  :func:`guardrail_engine.guard.telemetry.check_attributes`: ``guardrail.tenant_id``,
  ``guardrail.bundle_version``, ``guardrail.guard_point``, ``guardrail.latency_ms``,
  ``guardrail.input_tokens``, ``guardrail.decision`` and more (the full list is
  :data:`guardrail_engine.telemetry.port.CHECK_ATTRIBUTES`). Status ERROR for an
  ``internal_error`` verdict or a cancelled check.
* ``guard.model_call``: a child span around the decision gateway call, when the check makes
  one, with its model-path attributes (``guardrail.provider_calls``...) and
  ``guardrail.connection_reused``, set by :func:`connection_reuse_hook`.

:func:`connection_reuse_hook` is the Gemini adapter's ``on_call`` hook (M1-10): the
composition root (M1-11) passes it to ``GeminiDecisionModel(on_call=...)``. The adapter calls
it in the task running the model call, which the gateway starts from the check's task, so it
sees the context of the check's current model-call span.
"""

from __future__ import annotations

import contextlib
import logging
from contextvars import ContextVar, Token
from dataclasses import dataclass
from typing import Any

from opentelemetry import context as otel_context
from opentelemetry import trace

from guardrail_engine.telemetry.port import (
    CHECK_SPAN,
    CONNECTION_REUSED,
    MODEL_CALL_SPAN,
    PROVIDER_CALL_EVENT,
    Attributes,
    CheckTrace,
)

logger = logging.getLogger(__name__)

TRACER_NAME = "guardrail_engine"
__all__ = [
    "CHECK_SPAN",
    "CONNECTION_REUSED",
    "MODEL_CALL_SPAN",
    "PROVIDER_CALL_EVENT",
    "TRACER_NAME",
    "OtelTelemetry",
    "connection_reuse_hook",
]


@dataclass(eq=False)
class _ModelCall:
    span: trace.Span
    reused: bool | None = None
    """True only while every provider call of this model call went out on a reused
    connection; False once any opened a new one; None until a call reports which."""


_CURRENT_MODEL_CALL: ContextVar[_ModelCall | None] = ContextVar(
    "guardrail_engine_model_call", default=None
)


class OtelTelemetry:
    """The telemetry port over the OpenTelemetry API. ``tracer_provider`` defaults to the
    global one (a no-op until the embedding process configures the SDK)."""

    def __init__(self, tracer_provider: trace.TracerProvider | None = None) -> None:
        self._tracer = trace.get_tracer(TRACER_NAME, tracer_provider=tracer_provider)

    def start_check(self) -> CheckTrace:
        return _CheckTrace(self._tracer)


class _CheckTrace:
    def __init__(self, tracer: trace.Tracer) -> None:
        self._tracer = tracer
        self._span: trace.Span | None = tracer.start_span(CHECK_SPAN)
        self._token: object = otel_context.attach(trace.set_span_in_context(self._span))
        self._call: _ModelCall | None = None
        self._call_tokens: tuple[object, Token[_ModelCall | None]] | None = None

    def model_call_started(self) -> None:
        if self._span is None or self._call is not None:
            return
        span = self._tracer.start_span(MODEL_CALL_SPAN, kind=trace.SpanKind.CLIENT)
        self._call = _ModelCall(span)
        self._call_tokens = (
            otel_context.attach(trace.set_span_in_context(span)),
            _CURRENT_MODEL_CALL.set(self._call),
        )

    def model_call_ended(self, attributes: Attributes) -> None:
        call, tokens = self._call, self._call_tokens
        if call is None or tokens is None:
            return
        self._call = self._call_tokens = None
        try:
            _reset(*tokens)
        finally:
            call.span.set_attributes(dict(attributes))
            call.span.end()

    def end(self, attributes: Attributes, *, error: bool = False) -> None:
        if self._call is not None:
            self.model_call_ended({})
        span = self._span
        if span is None:
            return
        self._span = None
        try:
            otel_context.detach(self._token)
        finally:
            span.set_attributes(dict(attributes))
            if error:
                span.set_status(trace.Status(trace.StatusCode.ERROR))
            span.end()


def _reset(otel_token: object, var_token: Token[_ModelCall | None]) -> None:
    try:
        with contextlib.suppress(ValueError):  # a token from another context: nothing to undo
            _CURRENT_MODEL_CALL.reset(var_token)
    finally:
        otel_context.detach(otel_token)


def connection_reuse_hook(info: Any) -> None:
    """The adapter's ``on_call`` hook: records on the current check's model-call span
    whether the provider call's connection was reused (``connection_reused`` true) or newly
    opened (false), so the dogfood can measure the cold-call rate (M1-06, M1-10).

    ``info`` is the adapter's ``CallInfo``; only its ``connection`` (``"new"``,
    ``"reused"`` or None) is read. When the connection is unknown (None), nothing is set:
    the attribute is absent rather than guessed. With a retry, the span's attribute is false
    if **any** of its provider calls opened a new connection, and each call also adds a
    ``provider_call`` event with its own ``connection_reused``. Outside a check's model call
    (no current model-call span, or one already ended) it does nothing. Never raises.
    """
    try:
        call = _CURRENT_MODEL_CALL.get()
        connection = getattr(info, "connection", None)
        if call is None or not call.span.is_recording():
            return
        if connection == "reused":
            reused = True
        elif connection == "new":
            reused = False
        else:
            return
        call.reused = reused if call.reused is None else (call.reused and reused)
        call.span.set_attribute(CONNECTION_REUSED, call.reused)
        call.span.add_event(PROVIDER_CALL_EVENT, {CONNECTION_REUSED: reused})
    except Exception:
        logger.exception("connection reuse hook failed; ignored")
