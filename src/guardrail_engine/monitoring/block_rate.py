"""Bad-publish detection and the provider-health alert (M4-04).

**Bad publish.** After a tenant's guardrails are published (``publish`` or ``promote``), the
detector watches the **15 minutes** that follow. If the tenant's policy block rate in that
window is **more than 2x** its 7-day baseline, it raises ``bad_publish_block_rate``, once per
publish, with the Admin API path that rolls the tenant back.

* **Block rate** (decided) = every **tenant-caused block** (decision ``block``, with
  reason ``policy``, ``deterministic`` or ``content_too_large``) over the checks a policy
  decided (those three reasons and ``no_questions``). A publish that adds a broad deny
  pattern, a tight tool allow-list or a lower ``max_input_tokens`` blocks traffic through the
  tenant's own configuration, and that is exactly what a bad publish looks like, so those
  blocks are in the numerator. **Only ``model_failure`` is excluded** (with the other reasons
  that say nothing about the tenant's rules: ``policy_unavailable``, ``internal_error``,
  ``engine_closed``, ``invalid_request``, ``contract_violation``, ``provider_safety`` and the
  two ``forbidden`` reasons): it is in neither the numerator nor the denominator, so a
  provider slowdown cannot look like a bad publish; it feeds the provider-health alert below.
* **Baseline** = the same rate over the seven days of whole hours before the hour of the
  publish. Hours, not minutes, so a tenant costs about 170 counters, not 10,000.
* **No baseline, no alert.** The baseline is in memory, so it needs **at least 24 hours of
  observations** of the tenant (``min_baseline_age_s``; counted from the tenant's first
  observed check, which after a restart is the restart) and at least ``min_baseline_checks``
  checks. Before that the result is ``NO_BASELINE``: logged at info level, no alert. (The
  durable baseline, read from the audit store, is M4-07: until then a restart means a day
  without bad-publish alerts for every tenant.) A window with fewer than ``min_window_checks``
  checks or ``min_window_blocks`` blocks is ``TOO_FEW_CHECKS``: a rate over a handful of
  checks is noise. A zero baseline is a baseline: any window that passes those minimums then
  alerts.
* **Shadow publishes** do not start or replace a watch and are not "the active
  version": a ``publish`` whose event says ``mode == "shadow"`` (or ``active is False``) is
  ignored. ``GuardrailPublished`` carries ``mode``, ``active`` and ``at`` (M4-03 follow-up);
  an event without them (``None``) is treated as an active publish.
* **One alert per occurrence across replicas**: the alert carries a deterministic
  ``dedupe_key`` of (kind, tenant, version, window start), which the durable sink uses as the
  outbox key and the webhook sends as its id.
* **Edges.** "More than" is strict: a window rate of exactly 2x does not alert. The window is
  the ``window_s`` of whole minutes after the publish (the first minute that starts at or
  after it); it is evaluated once the last of those minutes has ended, so alerting is about 15
  minutes after the publish at the earliest. The comparison is exact integer arithmetic.

**Provider health.** The share of checks that ended in ``model_failure``, over all tenants,
in the trailing ``provider_window_s`` (5 minutes). Above ``provider_threshold`` (5%) with at
least ``min_window_checks`` checks, it raises ``provider_health`` (platform-wide) **once**,
and does not page again until it has been healthy for ``provider_clear_s`` (5 minutes)
without a break: a rate hovering around the threshold is one incident, not one page
per tick. (``provider_repeat_s``, off by default, adds a reminder while it lasts.)

Time is injected (``clock`` returns epoch seconds). ``observe`` is called on the request path
(from the audit sink) and only counts; ``tick`` evaluates and raises alerts, off the request
path, from a :class:`~guardrail_engine.monitoring.runner.PeriodicRunner`.
"""

from __future__ import annotations

import logging
import math
import threading
import time
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Protocol

from guardrail_engine.gateway.sinks import (
    ALERT_BAD_PUBLISH,
    ALERT_PROVIDER_HEALTH,
    Alert,
    AlertSeverity,
    AlertSink,
)
from guardrail_engine.guard.audit import AuditSink
from guardrail_engine.guard.verdict import Decision, Reason, Verdict

logger = logging.getLogger(__name__)

POLICY_DECIDED = frozenset(
    {Reason.POLICY, Reason.DETERMINISTIC, Reason.NO_QUESTIONS, Reason.CONTENT_TOO_LARGE}
)
"""Reasons of a check the tenant's (or the floor's) rules decided: the denominator of the
block rate. A ``block`` with any of these is a tenant-caused block and is in the numerator."""

WATCH_ACTIONS = frozenset({"publish", "promote"})
"""``guardrail.published`` actions that start a watch. A ``rollback`` ends it."""
ROLLBACK_ACTION = "rollback"

_MINUTE = 60
_HOUR = 3600


class Outcome(StrEnum):
    ALERTED = "alerted"
    NORMAL = "normal"
    NO_BASELINE = "no_baseline"
    TOO_FEW_CHECKS = "too_few_checks"


@dataclass(frozen=True)
class Evaluation:
    """What one watch came to, for logs and tests."""

    tenant_id: str
    version: int
    outcome: Outcome
    window_checks: int
    window_blocks: int
    baseline_checks: int
    baseline_blocks: int
    baseline_observed_s: float = 0.0
    """How long before the publish the tenant was first observed (the baseline's age)."""


@dataclass(frozen=True)
class BlockRateConfig:
    window_s: float = 15 * 60
    """How long after a publish the rate is compared with the baseline."""
    multiplier: float = 2.0
    """The window's rate must be MORE than this times the baseline's."""
    baseline_days: int = 7
    min_baseline_checks: int = 100
    """Fewer checks than this in the baseline: no baseline, no alert."""
    min_baseline_age_s: float = 24 * 3600.0
    """The in-memory baseline needs this long a history of the tenant before it can fire."""
    min_window_checks: int = 20
    min_window_blocks: int = 3
    provider_window_s: float = 5 * 60
    provider_threshold: float = 0.05
    provider_clear_s: float = 300.0
    """Provider health must stay healthy this long before it can page again."""
    provider_repeat_s: float | None = None
    """Re-page this often while it stays unhealthy; None (the default): once per episode."""
    rollback_prefix: str = ""
    """Put in front of the rollback path, e.g. the Admin API's base URL, to make a link."""

    def __post_init__(self) -> None:
        if self.window_s < _MINUTE or self.provider_window_s < _MINUTE:
            raise ValueError("windows are at least one minute")
        if self.multiplier <= 0 or self.baseline_days < 1:
            raise ValueError("multiplier must be positive and the baseline at least a day")
        if not 0 < self.provider_threshold < 1:
            raise ValueError("provider_threshold must be between 0 and 1")
        if min(self.min_baseline_checks, self.min_window_checks, self.min_window_blocks) < 0:
            raise ValueError("minimums cannot be negative")
        if self.min_baseline_age_s < 0 or self.provider_clear_s < 0:
            raise ValueError("durations cannot be negative")
        if self.provider_repeat_s is not None and self.provider_repeat_s <= 0:
            raise ValueError("provider_repeat_s must be positive or None")


class PublishedEvent(Protocol):
    """The ``GuardrailPublished`` event (admin.lifecycle), by shape."""

    tenant_id: str
    version: int
    action: str


@dataclass
class _Watch:
    version: int
    started_at: float
    previous_version: int | None


_PRUNE_CHUNK = 50
"""Tenants pruned per acquisition of the detector's lock: ``observe`` waits for at
most one chunk, never for the whole sweep."""


class _Counts:
    """Policy-decided checks and policy blocks (``[checks, blocks]``) per bucket."""

    __slots__ = ("buckets", "oldest")

    def __init__(self) -> None:
        self.buckets: dict[int, list[int]] = {}
        self.oldest: int | None = None
        """The lowest bucket index, so ``prune`` is free when nothing is old enough."""

    def add(self, index: int, *, block: bool) -> None:
        cell = self.buckets.get(index)
        if cell is None:
            cell = self.buckets[index] = [0, 0]
            if self.oldest is None or index < self.oldest:
                self.oldest = index
        cell[0] += 1
        if block:
            cell[1] += 1

    def total(self, start: int, stop: int) -> tuple[int, int]:
        """Checks and blocks in buckets ``start <= i < stop``."""
        checks = blocks = 0
        for index, (c, b) in self.buckets.items():
            if start <= index < stop:
                checks += c
                blocks += b
        return checks, blocks

    def prune(self, before: int) -> None:
        if self.oldest is None or self.oldest >= before:
            return
        for index in [i for i in self.buckets if i < before]:
            del self.buckets[index]
        self.oldest = min(self.buckets) if self.buckets else None


class BadPublishDetector:
    def __init__(
        self,
        alerts: AlertSink,
        *,
        config: BlockRateConfig | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        """``alerts`` is where alerts go: in production the durable alert sink, so they
        survive a restart. ``clock`` returns epoch seconds."""
        self._alerts = alerts
        self._config = config or BlockRateConfig()
        self._clock = clock
        self._lock = threading.Lock()
        self._minutes: dict[str, _Counts] = defaultdict(_Counts)
        self._hours: dict[str, _Counts] = defaultdict(_Counts)
        self._first_seen: dict[str, float] = {}
        self._watches: dict[str, _Watch] = {}
        self._active: dict[str, int] = {}
        # Platform-wide, per minute: [checks the policy or the model decided, model_failure].
        self._provider: dict[int, list[int]] = {}
        self._provider_alerted_at: float | None = None
        self._provider_active = False
        self._provider_healthy_since: float | None = None

    # ------------------------------------------------------------------ inputs

    def observe(self, tenant_id: str | None, decision: Decision, reason: Reason) -> None:
        """Count one production check. Cheap and never raises: it runs on the request path."""
        if not tenant_id:
            return
        failure = reason is Reason.MODEL_FAILURE
        decided = reason in POLICY_DECIDED
        if not (failure or decided):
            return
        now = self._clock()
        minute, hour = int(now // _MINUTE), int(now // _HOUR)
        with self._lock:
            if failure:
                cell = self._provider.setdefault(minute, [0, 0])
                cell[0] += 1
                cell[1] += 1
            else:
                block = decision is Decision.BLOCK  # a tenant-caused block
                self._first_seen.setdefault(tenant_id, now)
                self._minutes[tenant_id].add(minute, block=block)
                self._hours[tenant_id].add(hour, block=block)
                self._provider.setdefault(minute, [0, 0])[0] += 1

    def observe_verdict(self, verdict: Verdict) -> None:
        try:
            self.observe(verdict.tenant_id, verdict.decision, verdict.reason)
        except Exception:
            logger.exception("block-rate observation failed")

    def audit_sink(self, inner: AuditSink) -> AuditSink:
        """``inner`` with this detector watching every verdict it records."""
        return _TappedAuditSink(inner, self)

    def note_publish(
        self,
        tenant_id: str,
        version: int,
        action: str,
        *,
        at: float | None = None,
        mode: str | None = None,
        active: bool | None = None,
    ) -> None:
        """A ``guardrail.published`` event: a ``publish`` or ``promote`` starts (or restarts)
        the tenant's watch; a ``rollback`` ends it and is the new active version.

        A ``publish`` that does not decide traffic (``mode == "shadow"`` or ``active is
        False``) is a candidate, not the active version: it neither starts a watch nor
        becomes the version a rollback link points at. ``at`` is the event's own
        time, so replicas that receive it a moment apart agree on the window."""
        now = self._clock() if at is None else at
        shadow = action == "publish" and (mode == "shadow" or active is False)
        with self._lock:
            if action == ROLLBACK_ACTION:
                self._watches.pop(tenant_id, None)
                self._active[tenant_id] = version
            elif action in WATCH_ACTIONS and not shadow:
                previous = self._active.get(tenant_id)
                self._watches[tenant_id] = _Watch(version, now, previous)
                self._active[tenant_id] = version

    def on_published(self, event: PublishedEvent) -> None:
        """Subscribe this to the publish bus: ``bus.subscribe(detector.on_published)``. Reads
        the event's ``mode``, ``active`` and ``at`` when it has them."""
        self.note_publish(
            event.tenant_id,
            event.version,
            event.action,
            at=getattr(event, "at", None),
            mode=getattr(event, "mode", None),
            active=getattr(event, "active", None),
        )

    # ------------------------------------------------------------------ evaluation

    def tick(self) -> list[Evaluation]:
        """Evaluate every watch whose window has ended, raise the alerts, check provider
        health, drop counters older than they are needed."""
        now = self._clock()
        results: list[Evaluation] = []
        alerts: list[Alert] = []
        with self._lock:
            for tenant_id, watch in list(self._watches.items()):
                if now < self._window_end(watch) * _MINUTE:
                    continue
                del self._watches[tenant_id]
                result, alert = self._evaluate(tenant_id, watch)
                results.append(result)
                if alert is not None:
                    alerts.append(alert)
            if (health := self._provider_health(now)) is not None:
                alerts.append(health)
        for result in results:
            if result.outcome is Outcome.NO_BASELINE:
                logger.info(
                    "no bad-publish check for %s v%s: baseline has %d checks over %.1f hours "
                    "(need %d checks over %.1f hours)",
                    result.tenant_id,
                    result.version,
                    result.baseline_checks,
                    result.baseline_observed_s / _HOUR,
                    self._config.min_baseline_checks,
                    self._config.min_baseline_age_s / _HOUR,
                )
        for alert in alerts:
            try:
                self._alerts.emit(alert)
            except Exception:
                logger.exception("could not hand the %s alert to its sink", alert.kind)
        self._prune(now)  # after the lock is released, in chunks
        return results

    def _window_end(self, watch: _Watch) -> int:
        """The first minute index after the window."""
        return math.ceil((watch.started_at + self._config.window_s) / _MINUTE)

    def _evaluate(self, tenant_id: str, watch: _Watch) -> tuple[Evaluation, Alert | None]:
        cfg = self._config
        start = math.ceil(watch.started_at / _MINUTE)
        checks, blocks = self._minutes[tenant_id].total(start, self._window_end(watch))
        hour = int(watch.started_at // _HOUR)
        base_checks, base_blocks = self._hours[tenant_id].total(hour - cfg.baseline_days * 24, hour)
        observed_s = max(0.0, watch.started_at - self._first_seen.get(tenant_id, watch.started_at))

        def result(outcome: Outcome) -> tuple[Evaluation, Alert | None]:
            return Evaluation(
                tenant_id,
                watch.version,
                outcome,
                checks,
                blocks,
                base_checks,
                base_blocks,
                observed_s,
            ), None

        if base_checks < max(1, cfg.min_baseline_checks) or observed_s < cfg.min_baseline_age_s:
            return result(Outcome.NO_BASELINE)
        if checks < max(1, cfg.min_window_checks) or blocks < max(1, cfg.min_window_blocks):
            return result(Outcome.TOO_FEW_CHECKS)
        # blocks/checks > multiplier * base_blocks/base_checks, without dividing.
        if blocks * base_checks <= cfg.multiplier * base_blocks * checks:
            return result(Outcome.NORMAL)
        minutes = int(cfg.window_s // _MINUTE)
        message = (
            f"block rate {blocks}/{checks} ({blocks / checks:.1%}) in the {minutes} "
            f"minutes after version {watch.version} was published is more than "
            f"{cfg.multiplier:g}x its 7-day baseline {base_blocks}/{base_checks} "
            f"({base_blocks / base_checks:.1%}); roll back if the publish is the cause"
        )
        alert = Alert(
            severity=AlertSeverity.PAGE,
            kind=ALERT_BAD_PUBLISH,
            message=message,
            key_id="",
            tenant_id=tenant_id,
            guard_point="",
            reason=Reason.POLICY.value,
            rollback=self._rollback_ref(tenant_id, watch.previous_version),
            dedupe_key=_dedupe_key(
                ALERT_BAD_PUBLISH, tenant_id, watch.version, int(start * _MINUTE)
            ),
        )
        evaluation = Evaluation(
            tenant_id,
            watch.version,
            Outcome.ALERTED,
            checks,
            blocks,
            base_checks,
            base_blocks,
            observed_s,
        )
        return evaluation, alert

    def _rollback_ref(self, tenant_id: str, previous: int | None) -> str:
        base = f"{self._config.rollback_prefix}/v1/tenants/{tenant_id}/guardrails/versions"
        if previous is None:
            return base  # the version to go back to is not known here: choose from the list
        return f"{base}/{previous}/rollback"

    def _provider_health(self, now: float) -> Alert | None:
        cfg = self._config
        last = int(now // _MINUTE)
        first = last - int(cfg.provider_window_s // _MINUTE) + 1
        checks = failures = 0
        for index, (c, f) in self._provider.items():
            if first <= index <= last:
                checks += c
                failures += f
        unhealthy = (
            checks >= max(1, cfg.min_window_checks) and failures > cfg.provider_threshold * checks
        )
        if not unhealthy:
            if self._provider_active:  # clear only after a full, unbroken healthy stretch
                if self._provider_healthy_since is None:
                    self._provider_healthy_since = now
                if now - self._provider_healthy_since >= cfg.provider_clear_s:
                    self._provider_active = False
                    self._provider_healthy_since = None
            return None
        self._provider_healthy_since = None
        if self._provider_active:
            repeat = cfg.provider_repeat_s
            alerted = self._provider_alerted_at
            if repeat is None or alerted is None or now - alerted < repeat:
                return None
        self._provider_active = True
        self._provider_alerted_at = now
        minutes = int(cfg.provider_window_s // _MINUTE)
        bucket = int(now // cfg.provider_window_s) * int(cfg.provider_window_s)
        return Alert(
            severity=AlertSeverity.PAGE,
            kind=ALERT_PROVIDER_HEALTH,
            message=(
                f"{failures} of {checks} checks ({failures / checks:.1%}) in the last "
                f"{minutes} minutes ended in model_failure; the decision provider or its key "
                f"is unhealthy. This is not a bad publish."
            ),
            key_id="",
            tenant_id="",
            guard_point="",
            reason=Reason.MODEL_FAILURE.value,
            dedupe_key=_dedupe_key(ALERT_PROVIDER_HEALTH, "", 0, bucket),
        )

    def _prune(self, now: float) -> None:
        """Drop counters nobody needs any more. The platform-wide counters go first, then
        the tenants in chunks of ``_PRUNE_CHUNK``, taking the lock once per chunk: the check
        path (``observe``) never waits for more than one chunk. A tenant whose
        counters are all gone is forgotten, first-seen time included."""
        cfg = self._config
        keep_minutes = int((max(cfg.window_s, cfg.provider_window_s) * 2) // _MINUTE) + 60
        minute_floor = int(now // _MINUTE) - keep_minutes
        hour_floor = int(now // _HOUR) - cfg.baseline_days * 24 - 1
        with self._lock:
            for index in [i for i in self._provider if i < minute_floor]:
                del self._provider[index]
            tenants = list(self._hours.keys() | self._minutes.keys())
        for start in range(0, len(tenants), _PRUNE_CHUNK):
            with self._lock:
                for tenant_id in tenants[start : start + _PRUNE_CHUNK]:
                    self._prune_tenant(tenant_id, minute_floor, hour_floor)

    def _prune_tenant(self, tenant_id: str, minute_floor: int, hour_floor: int) -> None:
        minutes = self._minutes.get(tenant_id)
        if minutes is not None:
            minutes.prune(minute_floor)
            if not minutes.buckets:
                del self._minutes[tenant_id]
        hours = self._hours.get(tenant_id)
        if hours is not None:
            hours.prune(hour_floor)
            if not hours.buckets:
                del self._hours[tenant_id]
                self._first_seen.pop(tenant_id, None)

    @property
    def watching(self) -> list[str]:
        """Tenants whose post-publish window is still open."""
        with self._lock:
            return sorted(self._watches)


def _dedupe_key(kind: str, tenant_id: str, version: int, window_start: int) -> str:
    """The same for every replica that raises the same alert: kind, tenant, version
    and the start of the window, in epoch seconds."""
    return f"{kind}:{tenant_id or '-'}:{version}:{window_start}"


class _TappedAuditSink:
    def __init__(self, inner: AuditSink, detector: BadPublishDetector) -> None:
        self._inner = inner
        self._detector = detector

    def record(self, verdict: Verdict) -> None:
        try:
            self._inner.record(verdict)
        finally:
            self._detector.observe_verdict(verdict)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)
