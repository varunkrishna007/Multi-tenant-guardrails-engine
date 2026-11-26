"""Span attributes for a check (M1-06, AC-O2), built from a fixed list of fields.

These are the only attributes the Guard Service hands to the telemetry port. They are
identifiers, enums, counts and timings: never the content, the rendered input, a provider
message or operator ``detail``, the API key or request headers. An attribute whose value is
unknown is left out rather than sent as a placeholder.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from guardrail_engine.decision.port import Answered, Failed, SafetyBlocked
from guardrail_engine.gateway.gateway import CheckTiming
from guardrail_engine.guard.verdict import Reason, Verdict, recorded_code
from guardrail_engine.telemetry.port import (
    CHECK_ATTRIBUTES,
    MODEL_CALL_ATTRIBUTES,
    AttributeValue,
    attribute,
)


def _present(values: dict[str, Any], allowed: tuple[str, ...]) -> dict[str, AttributeValue]:
    """Namespaced (``guardrail.<name>``), unknown values left out. Every name must be
    in the port's list of attributes for the span."""
    out: dict[str, AttributeValue] = {}
    for name, value in values.items():
        key = attribute(name)
        if key not in allowed:
            raise ValueError(f"span attribute {key!r} is not in the port's list")
        if value is not None:
            out[key] = value.value if isinstance(value, Enum) else value
    return out


def check_attributes(verdict: Verdict) -> dict[str, AttributeValue]:
    """The ``guard.check`` span's attributes, namespaced ``guardrail.*``: AC-O2's
    ``tenant_id``, ``bundle_version``, ``guard_point``, latency (``latency_ms``), input tokens
    (``input_tokens``) and the ``decision``, plus the reason and the model-path fields,
    including ``in_flight_at_start``, ``capacity_limited`` and ``retry_after_ms`` (M1-15)."""
    return _present(
        {
            "tenant_id": verdict.tenant_id,
            "bundle_version": verdict.bundle_version,
            "bundle_hash": verdict.bundle_hash,
            "guard_point": verdict.guard_point,
            "request_id": verdict.request_id,
            "decision": verdict.decision,
            "reason": verdict.reason,
            "latency_ms": verdict.latency_ms,
            "input_tokens": verdict.input_tokens,
            "model_called": verdict.model_called,
            "model_skipped": verdict.model_skipped or None,
            "provider_called": verdict.provider_called,
            "provider_calls": verdict.provider_calls,
            "queue_wait_ms": verdict.queue_wait_ms,
            "provider_latency_ms": verdict.provider_latency_ms,
            "model_latency_ms": verdict.model_latency_ms,
            "in_flight_at_start": verdict.in_flight_at_start,
            "failure_kind": verdict.failure_kind,
            "failure_reason": verdict.failure_reason,
            "capacity_limited": verdict.capacity_limited,
            "degraded": verdict.degraded or None,
            "retry_after_ms": verdict.retry_after_ms,
            "policy_source": verdict.policy_source,
            "fired": tuple(f.key for f in verdict.fired),
            # M3-01: ids of the deterministic rules that fired, never the matched text.
            "deterministic_rules": tuple(h.rule for h in verdict.deterministic) or None,
            "redaction": verdict.redaction,
            **{f"pii_redacted.{kind.value}": n for kind, n in verdict.pii_redacted.items()},
        },
        CHECK_ATTRIBUTES,
    )


def cancelled_attributes() -> dict[str, AttributeValue]:
    """The check span's attributes when the check was cancelled (there is no verdict)."""
    return _present({"cancelled": True}, CHECK_ATTRIBUTES)


def check_failed(verdict: Verdict | None) -> bool:
    """Whether the check span gets an error status: an ``internal_error`` verdict, or no
    verdict at all (the check was cancelled)."""
    return verdict is None or verdict.reason is Reason.INTERNAL_ERROR


def model_call_attributes(
    *, model_id: str | None, result: object, timing: CheckTiming | None
) -> dict[str, AttributeValue]:
    """The ``guard.model_call`` span's attributes: the result's kind (``outcome``), how it
    failed, and where the time went. ``connection_reused`` is added by the adapter's hook."""
    values: dict[str, Any] = {"model": model_id}
    if isinstance(result, Answered | SafetyBlocked | Failed):
        values["outcome"] = result.outcome
    if isinstance(result, Failed):
        values["failure_kind"] = result.kind
    if isinstance(result, Failed | SafetyBlocked):
        values["failure_reason"] = recorded_code(result.reason)  # a code, never the message
    if isinstance(result, Answered) and result.usage is not None:
        values["input_tokens"] = result.usage.total_input_tokens
    if timing is not None:
        values.update(
            provider_calls=timing.provider_calls,
            provider_called=timing.provider_calls > 0,
            queue_wait_ms=timing.queue_wait_ms,
            provider_latency_ms=timing.provider_latency_ms,
        )
    return _present(values, MODEL_CALL_ATTRIBUTES)
