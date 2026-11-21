"""Delivers outbox events to the real sinks, with retries and a dead-letter state (M4-04).

**Retry policy.** A failed delivery is retried after ``base_s * 2**(failures - 1)`` seconds,
capped at ``cap_s``, shortened by up to ``jitter`` (a fraction) using the injected ``rng`` so
replicas don't retry in step. After ``max_attempts`` failures the event is **dead-lettered**:
it stays in the outbox in state ``dead`` with the last error code, and is not tried again
until an operator calls ``requeue_dead``. There are two policies:

* **Alerts** (``alert_retry``, default :data:`ALERT_RETRY`): 2 s base, **300 s cap**, and no
  attempt limit; an alert is dead-lettered only once it is **6 hours old** (``max_age_s``),
  counted from when it was enqueued, at its first failure after that. A webhook outage of
  under six hours therefore loses no page.
* **Usage** (``retry``, default :class:`RetryPolicy`): 2 s base, 300 s cap, 8 attempts. The
  waits between the 8 attempts are 2, 4, 8, 16, 32, 64 and 128 s, so a sink that is down for
  about four minutes loses nothing; one that is down longer dead-letters its events.

**A dead letter is never silent.** It is logged at error level (``dead-lettered``), counted in
``stats.dead`` (also ``dead_alerts`` and ``dead_usage``), and
:class:`~guardrail_engine.monitoring.dropped.DeadLetteredEventsWatch` raises an
``events_dead_lettered`` alert from that counter, through a sink that need not be the one
that is failing.

**The lease is a claim token.** ``claim_due`` leases a batch; each event's lease is
renewed just before its delivery when less than half of it is left, so a batch cannot outrun
its lease and a slow batch does not hand its tail to another replica. Every ``mark_*`` is
guarded by the lease: a worker that lost its event (another claimed it) changes nothing and
counts ``stats.lease_lost``. ``lease_s`` must still be longer than one delivery (the webhook
sink's timeout is 5 s per connect and read).

**What counts as a failure.** The sink raises. An event whose payload cannot be decoded is
dead at once (retrying cannot fix it). The error stored with the event is a short code (the
exception's ``code`` when it has one, else its class name), never its message: messages can
carry URLs or secrets.

**At least once, idempotent.** Every event keeps its idempotency key through every retry; a
sink that gets one twice must treat the second as a no-op. Events of one kind are delivered
roughly in order, but a retrying event does not hold back the ones behind it.

**One daemon thread**, like the gateway's drainer: a sink that never returns cannot hold up
process exit. ``close(timeout)`` waits at most that long. A sink that hangs stalls this
dispatcher; give every sink its own timeout (the webhook sink does). The lease
(``lease_s``) lets another dispatcher take the events after that.

Time is injected: ``clock`` returns epoch seconds. ``run_once`` is the whole algorithm; the
thread only calls it in a loop.
"""

from __future__ import annotations

import logging
import random
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol

from guardrail_engine.delivery.events import (
    KIND_ALERT,
    KIND_ESCALATION,
    KIND_USAGE,
    EscalationNotice,
    decode_alert,
    decode_escalation,
    decode_usage,
)
from guardrail_engine.delivery.outbox import OutboxEntry, OutboxStore
from guardrail_engine.delivery.usage import UsageStore
from guardrail_engine.gateway.sinks import Alert, AlertSink

logger = logging.getLogger(__name__)


class KeyedAlertSink(Protocol):
    """An alert sink that can send an alert under the event's idempotency key."""

    def deliver(self, alert: Alert, idempotency_key: str) -> None: ...


class KeyedEscalationSink(Protocol):
    """A sink for escalation notices (M4-05): the signed webhook. Always keyed."""

    def deliver(self, notice: EscalationNotice, idempotency_key: str) -> None: ...


class DeliveryError(Exception):
    """A delivery failed. ``code`` is a short, safe label ("http_503", "timeout"); the
    message never holds a URL, a header or a secret."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class RetryPolicy:
    base_s: float = 2.0
    cap_s: float = 300.0
    max_attempts: int = 8
    jitter: float = 0.2
    max_age_s: float | None = None
    """When set, the event is dead-lettered by age (seconds since it was enqueued) and
    ``max_attempts`` is not used. It is dead at its first failure at or past this age."""

    def __post_init__(self) -> None:
        if self.base_s <= 0 or self.cap_s < self.base_s:
            raise ValueError("need 0 < base_s <= cap_s")
        if self.max_attempts < 1:
            raise ValueError("max_attempts must be at least 1")
        if not 0 <= self.jitter < 1:
            raise ValueError("jitter must be in [0, 1)")
        if self.max_age_s is not None and self.max_age_s <= 0:
            raise ValueError("max_age_s must be positive")

    def exhausted(self, failures: int, age_s: float) -> bool:
        """Is the event dead after its ``failures``-th failure, ``age_s`` after it was
        enqueued? With ``max_age_s`` set, only age counts; otherwise only attempts."""
        if self.max_age_s is not None:
            return age_s >= self.max_age_s
        return failures >= self.max_attempts

    def delay_s(self, failures: int, rng: Callable[[], float] = random.random) -> float:
        """Seconds to wait after the ``failures``-th failure (1 for the first)."""
        exponent = min(max(failures - 1, 0), 64)
        raw = min(self.cap_s, self.base_s * (2.0**exponent))
        return raw * (1.0 - self.jitter * rng())


ALERT_RETRY = RetryPolicy(base_s=2.0, cap_s=300.0, jitter=0.2, max_age_s=6 * 3600.0)
"""Alerts keep retrying, with backoff capped at 5 minutes, until they are 6 hours old."""


ESCALATION_RETRY = RetryPolicy(base_s=2.0, cap_s=300.0, jitter=0.2, max_age_s=24 * 3600.0)
"""M4-05: an escalation notice keeps retrying, with backoff capped at 5 minutes, until it is 24
hours old, then is dead-lettered (kept in the outbox, counted, and raised as
``events_dead_lettered``) until an operator requeues it."""


@dataclass
class DispatcherStats:
    delivered: int = 0
    retried: int = 0
    dead: int = 0
    """Events dead-lettered since this dispatcher started (``dead_alerts`` + ``dead_usage``)."""
    dead_alerts: int = 0
    dead_usage: int = 0
    dead_escalations: int = 0
    store_errors: int = 0
    lease_lost: int = 0
    """Events whose lease had gone to another worker by the time this one tried to renew or
    mark them: the late worker changed nothing."""


class OutboxDispatcher:
    def __init__(
        self,
        outbox: OutboxStore,
        *,
        alerts: AlertSink | KeyedAlertSink | None = None,
        usage: UsageStore | None = None,
        retry: RetryPolicy | None = None,
        alert_retry: RetryPolicy | None = None,
        escalations: KeyedEscalationSink | None = None,
        escalation_retry: RetryPolicy | None = None,
        clock: Callable[[], float] = time.time,
        rng: Callable[[], float] = random.random,
        batch_size: int = 20,
        lease_s: float = 120.0,
        poll_s: float = 1.0,
        retain_delivered_s: float = 24 * 3600.0,
    ) -> None:
        """``alerts`` and ``usage`` are the real sinks; a kind with no sink is left in the
        outbox untouched. ``retry`` is the usage policy, ``alert_retry`` the alert one.
        ``escalations`` (M4-05) is the escalation webhook, with ``escalation_retry``
        (default :data:`ESCALATION_RETRY`)."""
        self._outbox = outbox
        self._alerts = alerts
        self._usage = usage
        self._retry = retry or RetryPolicy()
        self._alert_retry = alert_retry or ALERT_RETRY
        self._escalations = escalations
        self._escalation_retry = escalation_retry or ESCALATION_RETRY
        self._clock = clock
        self._rng = rng
        self._batch_size = batch_size
        self._lease_s = lease_s
        self._poll_s = poll_s
        self._retain_delivered_s = retain_delivered_s
        self._kinds = tuple(
            kind
            for kind, sink in (
                (KIND_ALERT, alerts),
                (KIND_USAGE, usage),
                (KIND_ESCALATION, escalations),
            )
            if sink is not None
        )
        self._stats = DispatcherStats()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._last_purge = clock()

    @property
    def stats(self) -> DispatcherStats:
        return self._stats

    # ------------------------------------------------------------------ one pass

    def run_once(self) -> int:
        """Claim the events that are due and deliver each. Returns how many it handled."""
        if not self._kinds:
            return 0
        now = self._clock()
        try:
            entries = self._outbox.claim_due(now, self._batch_size, self._lease_s, self._kinds)
        except Exception:
            self._stats.store_errors += 1
            logger.exception("outbox: could not claim events")
            return 0
        for entry in entries:
            if self._stop.is_set():
                break  # leased events come back when the lease runs out
            held = self._hold(entry)
            if held is not None:
                self._handle(held)
        self._purge(now)
        return len(entries)

    def _hold(self, entry: OutboxEntry) -> OutboxEntry | None:
        """The entry under a lease that still covers its delivery, or None if the event is
        no longer ours. A lease that is more than half used up is renewed first; the renewal
        fails if another worker has claimed the event, and then it is not delivered here."""
        now = self._clock()
        if entry.lease - now >= self._lease_s / 2:
            return entry
        try:
            renewed = self._outbox.renew(entry, now, self._lease_s)
        except Exception:
            self._stats.store_errors += 1
            logger.exception("outbox: could not renew the lease of event %d", entry.id)
            return None
        if renewed is None:
            self._lost(entry, "renew")
        return renewed

    def _lost(self, entry: OutboxEntry, what: str) -> None:
        self._stats.lease_lost += 1
        logger.warning(
            "outbox: event %d (%s) is no longer held by this worker (%s); left to its holder",
            entry.id,
            entry.kind,
            what,
        )

    def _handle(self, entry: OutboxEntry) -> None:
        try:
            self._deliver(entry)
        except Exception as exc:
            self._failed(entry, exc)
            return
        try:
            applied = self._outbox.mark_delivered(entry, self._clock())
        except Exception:
            # Delivered but not recorded: the lease runs out and it is sent again (same key).
            self._stats.store_errors += 1
            logger.exception("outbox: could not mark event %d delivered", entry.id)
            return
        if not applied:
            self._lost(entry, "mark_delivered")  # sent, but another worker has it now
            return
        self._stats.delivered += 1

    def _deliver(self, entry: OutboxEntry) -> None:
        if entry.kind == KIND_ALERT and self._alerts is not None:
            try:
                alert = decode_alert(entry.payload)
            except Exception as exc:
                raise _Undeliverable("bad_payload") from exc
            deliver: Any = getattr(self._alerts, "deliver", None)
            if callable(deliver):
                deliver(alert, entry.key)
            else:
                self._alerts.emit(alert)  # type: ignore[union-attr]
        elif entry.kind == KIND_USAGE and self._usage is not None:
            try:
                event = decode_usage(entry.payload)
            except Exception as exc:
                raise _Undeliverable("bad_payload") from exc
            self._usage.write(event, entry.key)
        elif entry.kind == KIND_ESCALATION and self._escalations is not None:
            try:
                notice = decode_escalation(entry.payload)
            except Exception as exc:
                raise _Undeliverable("bad_payload") from exc
            self._escalations.deliver(notice, entry.key)
        else:
            raise _Undeliverable("no_sink")

    def _failed(self, entry: OutboxEntry, exc: Exception) -> None:
        code = _error_code(exc)
        failures = entry.attempts + 1
        now = self._clock()
        policy = {
            KIND_ALERT: self._alert_retry,
            KIND_ESCALATION: self._escalation_retry,
        }.get(entry.kind, self._retry)
        try:
            if isinstance(exc, _Undeliverable) or policy.exhausted(
                failures, now - entry.created_at
            ):
                if not self._outbox.mark_dead(entry, failures, now, code):
                    self._lost(entry, "mark_dead")
                    return
                self._stats.dead += 1
                if entry.kind == KIND_ALERT:
                    self._stats.dead_alerts += 1
                elif entry.kind == KIND_ESCALATION:
                    self._stats.dead_escalations += 1
                else:
                    self._stats.dead_usage += 1
                logger.error(
                    "outbox: events_dead_lettered: event %d (%s) dead-lettered after %d "
                    "attempts: %s",
                    entry.id,
                    entry.kind,
                    failures,
                    code,
                )
            else:
                delay = policy.delay_s(failures, self._rng)
                if not self._outbox.mark_failed(entry, failures, now + delay, code):
                    self._lost(entry, "mark_failed")
                    return
                self._stats.retried += 1
                logger.warning(
                    "outbox: event %d (%s) failed (%s), attempt %d, retrying in %.0f s",
                    entry.id,
                    entry.kind,
                    code,
                    failures,
                    delay,
                )
        except Exception:
            self._stats.store_errors += 1
            logger.exception("outbox: could not record the failure of event %d", entry.id)

    def _purge(self, now: float) -> None:
        if now - self._last_purge < 3600.0:
            return
        self._last_purge = now
        try:
            self._outbox.purge_delivered(now - self._retain_delivered_s)
        except Exception:
            self._stats.store_errors += 1
            logger.exception("outbox: could not purge delivered events")

    # ------------------------------------------------------------------ thread

    def start(self) -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(
            target=self._run, name="guardrail-outbox-dispatcher", daemon=True
        )
        self._thread.start()

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                handled = self.run_once()
            except Exception:  # run_once catches what it expects; this is the last net
                logger.exception("outbox dispatcher pass failed")
                handled = 0
            if handled < self._batch_size:
                self._stop.wait(self._poll_s)

    def close(self, timeout: float = 5.0) -> bool:
        """Stop after the delivery in hand; wait at most ``timeout`` seconds. True if the
        thread has stopped (a delivery stuck in a sink keeps it alive, and it is a daemon,
        so the process can still exit)."""
        self._stop.set()
        thread = self._thread
        if thread is None:
            return True
        thread.join(timeout)
        return not thread.is_alive()


class _Undeliverable(Exception):
    """Retrying cannot help: the event is dead-lettered at once."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _error_code(exc: BaseException) -> str:
    code = getattr(exc, "code", None)
    if isinstance(code, str) and code:
        return code[:64]
    return type(exc).__name__[:64]
