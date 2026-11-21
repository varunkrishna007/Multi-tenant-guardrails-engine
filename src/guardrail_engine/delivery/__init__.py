"""Durable delivery of alert and metering events (M4-04).

The gateway's bounded queue and drainer thread (M1-04) hand events to sinks after a check has
returned. Here the sinks are an outbox: :class:`DurableAlertSink` and :class:`DurableUsageMeter`
insert each event into it, and an :class:`OutboxDispatcher` delivers from it to the real sinks
(a signed webhook, the usage store) with retries, backoff and a dead-letter state. See
``docs/m4-04-bad-publish-detection.md``.
"""

from guardrail_engine.delivery.dispatcher import (
    ALERT_RETRY,
    ESCALATION_RETRY,
    DeliveryError,
    OutboxDispatcher,
    RetryPolicy,
)
from guardrail_engine.delivery.durable import DropCounter, DurableAlertSink, DurableUsageMeter
from guardrail_engine.delivery.outbox import InMemoryOutbox, OutboxStore
from guardrail_engine.delivery.usage import InMemoryUsageStore, UsageStore

__all__ = [
    "ALERT_RETRY",
    "ESCALATION_RETRY",
    "DeliveryError",
    "DropCounter",
    "DurableAlertSink",
    "DurableUsageMeter",
    "InMemoryOutbox",
    "InMemoryUsageStore",
    "OutboxDispatcher",
    "OutboxStore",
    "RetryPolicy",
    "UsageStore",
]
