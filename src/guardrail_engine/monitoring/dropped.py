"""An alert on the gateway's dropped-events counter (M4-04), so overflow is noticed.

``DecisionGateway.dropped_events`` goes up when the bounded event queue pushes out its oldest
event, when ``aclose`` gives up on a stuck sink, and for events raised after close. Nothing
looked at it. :class:`DroppedEventsWatch` compares it with the value it last reported and, when
it has grown, raises ``events_dropped`` (a warning) with the growth as ``count``.

**It must not go through the queue it reports on.** Hand it the durable alert sink (or any
sink that does not sit behind the gateway's queue), never the gateway's own ``alerts``: an
alert raised through a full queue would be dropped by the very overflow it announces.

At most one alert per ``min_interval_s``; growth in between is added to the next one. The
clock is injected (seconds, monotonic or epoch).

**Outbox INSERT failures count too.** Give it ``lambda: gateway.dropped_events +
drops.value`` where ``drops`` is the :class:`~guardrail_engine.delivery.durable.DropCounter`
the durable sinks share.

**Dead letters.** :class:`DeadLetteredEventsWatch` is the same idea for the outbox
dispatcher's ``stats.dead``: it raises ``events_dead_lettered``. The alert goes to the sink
it is given; when it is the webhook that is failing, give it a sink that does not depend on
that webhook (another channel, or the log). Independently of the sink, a growth is **always
logged at error level** by the watch, so the loss is visible with every sink down.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable

from guardrail_engine.gateway.sinks import (
    ALERT_AUDIT_RECORDS_DROPPED,
    ALERT_EVENTS_DEAD_LETTERED,
    ALERT_EVENTS_DROPPED,
    ALERT_STORED_CONTENT_DROPPED,
    Alert,
    AlertSeverity,
    AlertSink,
)

logger = logging.getLogger(__name__)


class _GrowthWatch:
    """Raises an alert when a counter has grown since it last reported, at most once per
    ``min_interval_s``."""

    kind = ""
    message = ""
    log_message = ""

    def __init__(
        self,
        counter: Callable[[], int],
        alerts: AlertSink,
        *,
        min_interval_s: float = 60.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._counter = counter
        self._alerts = alerts
        self._min_interval_s = min_interval_s
        self._clock = clock
        self._reported = 0
        self._last_alert_at: float | None = None
        self._logged = 0

    def tick(self) -> Alert | None:
        """Raise the alert if the counter has grown and the interval has passed. Returns
        the alert it raised, or None."""
        total = self._counter()
        grown = total - self._reported
        if grown <= 0:
            return None
        if total > self._logged:  # once per growth, not once per retry of the alert
            logger.error(self.log_message, total - self._logged)
            self._logged = total
        now = self._clock()
        if self._last_alert_at is not None and now - self._last_alert_at < self._min_interval_s:
            return None
        alert = Alert(
            severity=AlertSeverity.WARNING,
            kind=self.kind,
            message=self.message,
            key_id="",
            tenant_id="",
            guard_point="",
            count=grown,
        )
        try:
            self._alerts.emit(alert)
        except Exception:
            logger.exception("could not hand the %s alert to its sink", self.kind)
            return None  # not reported: the next tick tries again
        self._reported = total
        self._last_alert_at = now
        return alert


class DroppedEventsWatch(_GrowthWatch):
    kind = ALERT_EVENTS_DROPPED
    message = (
        "alert and metering events were dropped before delivery (the gateway's "
        "event queue overflowed or was closed, or an outbox insert failed); some alerts or "
        "usage records are lost"
    )
    log_message = "%d alert or metering events were dropped before delivery"

    def __init__(
        self,
        dropped: Callable[[], int],
        alerts: AlertSink,
        *,
        min_interval_s: float = 60.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        """``dropped`` returns the counter, e.g. ``lambda: gateway.dropped_events +
        drops.value``."""
        super().__init__(dropped, alerts, min_interval_s=min_interval_s, clock=clock)


class DeadLetteredEventsWatch(_GrowthWatch):
    kind = ALERT_EVENTS_DEAD_LETTERED
    message = (
        "outbox events were dead-lettered after their retries ran out (a sink is failing); "
        "they stay in the outbox until an operator requeues them"
    )
    log_message = "%d outbox events were dead-lettered"

    def __init__(
        self,
        dead: Callable[[], int],
        alerts: AlertSink,
        *,
        min_interval_s: float = 60.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        """``dead`` returns the count, e.g. ``lambda: dispatcher.stats.dead``. ``alerts``
        should not depend on the sink that is failing."""
        super().__init__(dead, alerts, min_interval_s=min_interval_s, clock=clock)


class DroppedAuditRecordsWatch(_GrowthWatch):
    kind = ALERT_AUDIT_RECORDS_DROPPED
    message = (
        "decision records were dropped before they were written (the write-behind queue was "
        "full or the database refused them); the audit trail has a gap"
    )
    log_message = "%d decision records were dropped before they were written"

    def __init__(
        self,
        dropped: Callable[[], int],
        alerts: AlertSink,
        *,
        min_interval_s: float = 60.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        """``dropped`` returns the writer's counter, e.g. ``lambda: writer.dropped``."""
        super().__init__(dropped, alerts, min_interval_s=min_interval_s, clock=clock)


class DroppedStoredContentWatch(_GrowthWatch):
    kind = ALERT_STORED_CONTENT_DROPPED
    message = (
        "stored content was dropped before it was written (the write-behind queue was full or "
        "the database refused it); a tenant that asked to keep its content has a gap"
    )
    log_message = "%d stored-content rows were dropped before they were written"

    def __init__(
        self,
        dropped: Callable[[], int],
        alerts: AlertSink,
        *,
        min_interval_s: float = 60.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        """``dropped`` returns the writer's counter, e.g. ``lambda: writer.dropped``."""
        super().__init__(dropped, alerts, min_interval_s=min_interval_s, clock=clock)
