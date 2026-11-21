"""The telemetry port (M1-06, AC-O2): one span per check, with a model-call span inside it.

The engine imports no telemetry library. The Guard Service talks to this port; the
OpenTelemetry implementation is :mod:`guardrail_engine.telemetry.adapters.otel` (vendor
libraries stay in ``adapters/``, AC-M1-4). :class:`NullTelemetry`, the default, does nothing.

**Call order, per check, all from the task running the check:** ``start_check`` when the
check begins; at most one ``model_call_started`` / ``model_call_ended`` pair around the
decision gateway call; ``end`` exactly once, with the check's attributes, when the verdict is
final (or when the check is cancelled).

**Contract.** Every method must be quick, must not block, and should not raise. The Guard
Service still catches and logs anything raised: telemetry never changes a verdict and never
raises into the check path. The attributes are built by the engine from a fixed list of
verdict fields (:mod:`guardrail_engine.guard.telemetry`); they never include content, the API
key or request headers.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Protocol

AttributeValue = str | bool | int | float | Sequence[str]
Attributes = Mapping[str, AttributeValue]

# ---------------------------------------------------------------- attribute names
# Every attribute the engine puts on a span is namespaced ``guardrail.<name>``: the engine
# runs inside the integrator's process, whose own instrumentation shares the attribute space.
# This is the one list of them, for dashboards and alerts.

ATTRIBUTE_PREFIX = "guardrail."

CHECK_SPAN = "guard.check"
MODEL_CALL_SPAN = "guard.model_call"

CHECK_ATTRIBUTES: tuple[str, ...] = (
    "guardrail.tenant_id",
    "guardrail.bundle_version",
    "guardrail.bundle_hash",
    "guardrail.guard_point",
    "guardrail.request_id",
    "guardrail.decision",
    "guardrail.reason",
    "guardrail.latency_ms",
    "guardrail.input_tokens",
    "guardrail.model_called",
    # M3-03: the tool's ``skip_model`` applied (the tenant's and packs' questions were not
    # asked, the floor's were). Set only when true.
    "guardrail.model_skipped",
    "guardrail.provider_called",
    "guardrail.provider_calls",
    "guardrail.queue_wait_ms",
    "guardrail.provider_latency_ms",
    "guardrail.model_latency_ms",
    "guardrail.in_flight_at_start",
    "guardrail.failure_kind",
    "guardrail.failure_reason",
    "guardrail.capacity_limited",
    "guardrail.retry_after_ms",
    "guardrail.policy_source",
    "guardrail.fired",
    # M3-01: the ids of the deterministic rules that fired (``deny__<id>``,
    # ``tool_allowlist``, ``tool_mismatch``, ``xtenant_identifier``, ``size_limit``). Ids only:
    # never the text a
    # rule matched. Left out when none fired.
    "guardrail.deterministic_rules",
    "guardrail.cancelled",
    # M1-14: whether PII redaction ran (``applied`` / ``failed``), and spans replaced per
    # kind, set only for kinds found. Counts only, never values, positions or lengths.
    "guardrail.redaction",
    "guardrail.pii_redacted.email",
    "guardrail.pii_redacted.phone",
    "guardrail.pii_redacted.card",
    "guardrail.pii_redacted.iban",
    "guardrail.pii_redacted.uk_sort_code",
    "guardrail.pii_redacted.uk_account_number",
    "guardrail.pii_redacted.uk_nino",
    "guardrail.pii_redacted.us_ssn",
)
"""The ``guard.check`` span's attributes. AC-O2's are ``tenant_id``, ``bundle_version``,
``guard_point``, ``latency_ms``, ``input_tokens`` and ``decision``."""

CONNECTION_REUSED = "guardrail.connection_reused"

MODEL_CALL_ATTRIBUTES: tuple[str, ...] = (
    "guardrail.model",
    "guardrail.outcome",
    "guardrail.failure_kind",
    "guardrail.failure_reason",
    "guardrail.input_tokens",
    "guardrail.provider_calls",
    "guardrail.provider_called",
    "guardrail.queue_wait_ms",
    "guardrail.provider_latency_ms",
    CONNECTION_REUSED,
)
"""The ``guard.model_call`` span's attributes. ``connection_reused`` is set by the model
adapter's connection-reuse hook."""

PROVIDER_CALL_EVENT = "guardrail.provider_call"
"""An event on the model-call span per provider request, with ``connection_reused``."""


def attribute(name: str) -> str:
    """``guardrail.<name>``."""
    return ATTRIBUTE_PREFIX + name


class CheckTrace(Protocol):
    """The telemetry of one check."""

    def model_call_started(self) -> None:
        """The check is about to hand its decision call to the gateway. An implementation
        that tracks spans makes the model-call span current here, so that hooks running
        during the call (the adapter's connection-reuse hook) can find it."""
        ...

    def model_call_ended(self, attributes: Attributes) -> None: ...

    def end(self, attributes: Attributes, *, error: bool = False) -> None:
        """The check is over. ``error`` marks an ``internal_error`` verdict or a cancelled
        check."""
        ...


class Telemetry(Protocol):
    def start_check(self) -> CheckTrace: ...


class _NullTrace:
    def model_call_started(self) -> None:
        pass

    def model_call_ended(self, attributes: Attributes) -> None:
        pass

    def end(self, attributes: Attributes, *, error: bool = False) -> None:
        pass


NULL_TRACE: CheckTrace = _NullTrace()


class NullTelemetry:
    """Records nothing."""

    def start_check(self) -> CheckTrace:
        return NULL_TRACE
