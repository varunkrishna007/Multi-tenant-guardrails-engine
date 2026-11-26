"""What goes into the outbox: alerts and usage records, as JSON text (M4-04).

Both are small, flat and free of content: an alert is the :class:`Alert` the gateway or a
monitor raised (a fixed sentence, identifiers and counts, never a secret or a matched text),
a usage record is a tenant, a guard point and a token count.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import asdict, dataclass

from guardrail_engine.gateway.sinks import Alert, AlertSeverity
from guardrail_engine.projects import is_valid_project_label

KIND_ALERT = "alert"
KIND_USAGE = "usage"
KIND_ESCALATION = "escalation"
"""M4-05: a notice that an escalation item is waiting, for a tenant's webhook."""
KINDS = (KIND_ALERT, KIND_USAGE, KIND_ESCALATION)

USAGE_ANSWERED = "answered"
"""An answered model call whose input tokens are known."""
USAGE_UNKNOWN = "unknown"
"""An answered call whose usage was missing: tokens unknown, never zero."""
USAGE_UNANSWERED = "unanswered"
USAGE_PROVIDER_SAFETY = "provider_safety"
USAGE_MODEL_SKIPPED = "model_skipped"
USAGE_PATTERNS_DROPPED = "patterns_dropped"
USAGE_KINDS = (
    USAGE_ANSWERED,
    USAGE_UNKNOWN,
    USAGE_UNANSWERED,
    USAGE_PROVIDER_SAFETY,
    USAGE_MODEL_SKIPPED,
    USAGE_PATTERNS_DROPPED,
)


def new_key() -> str:
    """An idempotency key: unique per event, kept by the event through every retry."""
    return uuid.uuid4().hex


@dataclass(frozen=True)
class UsageEvent:
    kind: str
    tenant_id: str
    guard_point: str
    input_tokens: int | None
    at: float
    """Epoch seconds when the gateway raised it."""
    project: str = ""
    """M5-06: the label of the dedicated Gemini project whose key made the call, ``""`` for the
    shared pool. A label only, never a key. An event written before the field existed decodes
    with ``""``."""

    def __post_init__(self) -> None:
        if self.kind not in USAGE_KINDS:
            raise ValueError(f"unknown usage kind {self.kind!r}")
        if self.project and not is_valid_project_label(self.project):
            raise ValueError("a usage event's project must be empty or a project label")


@dataclass(frozen=True)
class EscalationNotice:
    """What the outbox holds for an escalation webhook (M4-05): identifiers, the hash of the
    content and the rules that fired (key, action, mode; never a probability). **Never the
    content**: a dead-lettered row stays in the outbox, which is platform-level, and would
    outlive the item's class D term. The receiver reads the content, if the tenant's
    ``store_content`` lets it be held, through the authenticated escalation API."""

    item_id: str
    tenant_id: str
    guard_point: str
    reason: str
    created_at: float
    """Epoch seconds when the item was created."""
    url: str
    """The tenant's webhook url, as the bundle named it when the item was routed."""
    content_sha256: str | None = None
    bundle_version: int | None = None
    rules: tuple[tuple[str, str, str], ...] = ()
    """``(key, action, mode)`` of the rules that fired."""
    content_available: bool = False
    """Whether the item holds the content for a reviewer who fetches it."""
    candidate_rules: tuple[str, ...] = ()
    """M7-08: for a provider refusal, the escalate-only rule keys the content might have been
    about (nothing fired). Keys only."""


def encode_escalation(notice: EscalationNotice) -> str:
    return json.dumps(asdict(notice), sort_keys=True, separators=(",", ":"))


def decode_escalation(payload: str) -> EscalationNotice:
    data = json.loads(payload)
    data["rules"] = tuple(tuple(r) for r in data.get("rules", ()))
    data["candidate_rules"] = tuple(data.get("candidate_rules", ()))
    return EscalationNotice(**data)


def encode_alert(alert: Alert) -> str:
    data = asdict(alert)
    data["severity"] = alert.severity.value
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


def decode_alert(payload: str) -> Alert:
    data = json.loads(payload)
    data["severity"] = AlertSeverity(data["severity"])
    return Alert(**data)


def encode_usage(event: UsageEvent) -> str:
    return json.dumps(asdict(event), sort_keys=True, separators=(",", ":"))


def decode_usage(payload: str) -> UsageEvent:
    return UsageEvent(**json.loads(payload))
