"""Sinks that write to the outbox instead of delivering (M4-04).

Hand these to the engine as ``alerts`` and ``meter``. The gateway's drainer thread calls them
after the check has returned; each call is one insert into the outbox, after which the event
survives a restart and an :class:`~guardrail_engine.delivery.dispatcher.OutboxDispatcher`
delivers it. If the insert fails the call raises and the gateway logs it and moves on: that
one event is lost. The loss is **counted** on a :class:`DropCounter` the two sinks
share; add it to the gateway's own counter for ``DroppedEventsWatch``::

    drops = DropCounter()
    alerts, meter = DurableAlertSink(outbox, drops=drops), DurableUsageMeter(outbox, drops=drops)
    watch = DroppedEventsWatch(lambda: gateway.dropped_events + drops.value, alerts)

An alert that carries a ``dedupe_key`` is stored under it, so replicas that raise the same
alert write one outbox event.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable

from guardrail_engine.delivery.events import (
    KIND_ALERT,
    KIND_USAGE,
    UsageEvent,
    encode_alert,
    encode_usage,
    new_key,
)
from guardrail_engine.delivery.outbox import OutboxStore
from guardrail_engine.delivery.usage import UsageRecorder
from guardrail_engine.gateway.sinks import Alert


class DropCounter:
    """Events lost because their outbox INSERT failed. Thread-safe."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._value = 0

    def add(self, n: int = 1) -> None:
        with self._lock:
            self._value += n

    @property
    def value(self) -> int:
        with self._lock:
            return self._value


class DurableAlertSink:
    """An ``AlertSink`` whose ``emit`` is an outbox insert."""

    def __init__(
        self,
        outbox: OutboxStore,
        *,
        clock: Callable[[], float] = time.time,
        drops: DropCounter | None = None,
    ) -> None:
        self._outbox = outbox
        self._clock = clock
        self.drops = drops if drops is not None else DropCounter()

    def emit(self, alert: Alert) -> None:
        try:
            self._outbox.enqueue(
                KIND_ALERT, encode_alert(alert), alert.dedupe_key or new_key(), self._clock()
            )
        except Exception:
            self.drops.add()
            raise


class DurableUsageMeter(UsageRecorder):
    """A ``UsageMeter`` (with ``ProviderSafetyMeter``, ``SkippedChecksMeter`` and
    ``IdentifierScanMeter``) whose every record is an outbox insert."""

    def __init__(
        self,
        outbox: OutboxStore,
        *,
        clock: Callable[[], float] = time.time,
        drops: DropCounter | None = None,
    ) -> None:
        super().__init__(clock)
        self._outbox = outbox
        self.drops = drops if drops is not None else DropCounter()

    def _submit(self, event: UsageEvent) -> None:
        try:
            self._outbox.enqueue(KIND_USAGE, encode_usage(event), new_key(), self._usage_clock())
        except Exception:
            self.drops.add()
            raise
