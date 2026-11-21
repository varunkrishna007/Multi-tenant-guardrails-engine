"""The gateway's two outbound ports, alerts and usage metering, with in-memory
implementations for tests and for the M1 single-process slice.

**Contract for every implementation.** ``emit``, ``record`` and ``record_unanswered`` are
plain synchronous functions, not coroutines. The gateway never calls them on the request
path: it queues each call and a drainer delivers them **off the event loop, in one daemon worker
thread** (M4-04), one at a time and in the order they were raised. So:

* An implementation may block (a pager call, a metrics write), and a slow one does not
  delay any check. It does delay the events queued behind it; when the gateway's bounded
  queue fills up, the oldest events are dropped and counted (``dropped_events``). Keep
  calls short, with their own timeouts.
* It runs in a thread other than the event loop's, so it must not touch asyncio objects.
  Calls never overlap, so it needs no locking of its own against the gateway.
* Delivery is after the check has returned. Read a sink only after
  ``await gateway.drain()``.

A sink that raises is logged and ignored, and one that is ``async`` is logged and not run;
neither changes a check's result.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, runtime_checkable


class AlertSeverity(StrEnum):
    PAGE = "page"
    """Page on-call now."""
    WARNING = "warning"
    """Needs attention, but nobody is woken up."""


ALERT_AUTH_FAILURE = "decision_auth_failure"
"""The provider rejected the key. Every check on that key now fails (B1: the floor blocks)."""
ALERT_USAGE_UNKNOWN = "decision_usage_unknown"
"""An answered call had no usable ``usage`` block, so its tokens could not be metered."""
ALERT_CANCEL_IGNORED = "decision_cancel_ignored"
"""A model call was still running after it was cancelled at the deadline and the grace
period had passed. The adapter does not honour cancellation."""
ALERT_ORPHAN_CAP = "decision_orphan_cap"
"""So many such calls are still running that checks now fail fast as unavailable."""
ALERT_KEY_SATURATED_BY_ORPHANS = "decision_key_saturated_by_orphans"
"""Calls that ignored cancellation hold every admission slot of one key, so every check on
that key fails fast with ``admission_wait`` (B1: the floor blocks) until one of them ends.
A page, once per crossing; on a single-key deployment this is a platform-wide block."""
ALERT_DAILY_REQUESTS = "decision_daily_requests"
"""M3-10: the project's requests today (Pacific day) passed 80% (a warning, reason
``threshold_80``) or reached 100% (a page, ``threshold_100``) of ``requests_per_day``. At
100% every check fails fast as ``token_rate`` until midnight Pacific."""
ALERT_MONTHLY_SPEND = "decision_monthly_spend"
"""M3-10: the project's spend this month (Pacific) passed 80% (warning) or reached 100% (page)
of ``monthly_spend_cap_usd``. At 100% every check fails fast as ``token_rate`` until the 1st."""
ALERT_TOKEN_RATE_FAIL_FAST = "decision_token_rate_fail_fast"
"""M3-10: ``token_rate`` fail-fasts exceed 0.1% of checks in the last 5 minutes. A warning,
once per excursion."""
ALERT_TENANT_QUOTA = "tenant_quota"
"""M3-07: a tenant's checks were refused for its per-minute token or check share (a warning,
raised at most once per ``warning_interval_s`` per tenant and guard point, reason = the
cause). Only that tenant is affected; the other tenants' checks go on."""
ALERT_TENANT_DAILY_QUOTA = "tenant_daily_quota"
"""M3-07: a tenant's calls today (Pacific day) passed 80% (reason ``threshold_80``) or reached
100% (``threshold_100``) of its daily share. For the tenant's admins; a warning, not a page.
At 100% the tenant's checks fail fast as ``quota_exhausted`` until midnight Pacific."""
ALERT_CONSUMER_ALLOWANCE = "consumer_allowance"
"""M3-08: a non-production consumer (test, calibration, red_team, shadow) used up one of its
allowances (tokens a minute, requests a minute, requests a day or monthly spend) and
its calls are being refused (a warning, throttled per consumer, guard point and allowance).
Production is not affected."""
ALERT_XTENANT_PATTERNS_DROPPED = "xtenant_patterns_dropped"
"""A tenant's cross-tenant identifier patterns didn't compile at scan time and were left out
of the floor's scan. The alert's ``tenant_id`` is the tenant whose patterns were
dropped; its message is a fixed sentence (never a pattern). Other tenants' checks go on."""
ALERT_XTENANT_SCAN_SHARDED = "xtenant_scan_sharded"
"""Every tenant's patterns compile, but the engine couldn't build them as one set (its memory
bound), so the floor's cross-tenant scan matches over several sets instead. Nothing
is dropped and no check fails; each check costs more. A fixed sentence, no tenant. Once per
rebuild of the scan (the gateway throttles it like its other warnings)."""
ALERT_BAD_PUBLISH = "bad_publish_block_rate"
"""M4-04: a tenant's policy block rate (reason ``policy``, never ``model_failure``) in the 15
minutes after a publish was more than 2x its 7-day baseline. A page. ``tenant_id`` is the
tenant; ``rollback`` is the reference to roll the tenant's version back."""
ALERT_PROVIDER_HEALTH = "provider_health"
"""M4-04: the share of checks that ended in ``model_failure`` is high across the platform. A
page. Kept apart from the bad-publish alert so a provider slowdown doesn't look like a bad
publish. Platform-wide: ``tenant_id`` is empty."""
ALERT_EVENTS_DROPPED = "events_dropped"
"""M4-04: the gateway's bounded event queue overflowed or was closed, so alert or metering
events were never delivered (``count`` = how many since the last such alert). A warning. It
is raised outside the queue that overflowed, straight to the durable alert sink. Failed
outbox INSERTs count here too."""
ALERT_AUDIT_RECORDS_DROPPED = "audit_records_dropped"
"""M4-07: decision records were dropped before they were written (the write-behind queue was
full, the database refused them repeatedly, or they were still queued at shutdown): the audit
trail has a gap (``count`` = how many since the last such alert). A warning. Raised outside the
check path, from the writer's own task."""
ALERT_STORED_CONTENT_DROPPED = "stored_content_dropped"
"""M5-03: stored content (R3 class C) was dropped before it was written (the write-behind queue was
full, the database refused it repeatedly, or it was still queued at shutdown). The checks were
answered as always; the tenant asked to keep their content and it is not there (``count`` = how
many since the last such alert). A warning. Raised outside the check path, from the writer's own
task. Content that was deliberately **not** stored (a tenant that may not store it) is not a
drop."""
ALERT_EVENTS_DEAD_LETTERED = "events_dead_lettered"
"""M4-04: the outbox dispatcher dead-lettered events (alerts after six hours of
failing, usage after eight attempts); they stay in the outbox until an operator requeues them
(``count`` = how many since the last such alert). A warning. Raised from the dispatcher's
counter, through a sink chosen not to be the failing one."""
ALERT_ESCALATION_DROPPED = "escalation_dropped"
"""M4-05: escalation items were not stored or not queued for their webhook (the routing queue was
full, the store or the outbox failed or timed out, or the engine was closing). The checks
that raised them were answered ``escalate`` as always, but no reviewer will see these items
(``count`` = how many since the last such alert for the tenant; ``reason`` = why). A page, per
tenant, throttled. Raised outside the routing queue it reports on."""

ALERT_REDTEAM_REGRESSION = "redteam_regression"
"""M5-05 (R5): the nightly red-team found that a configuration the platform serves (a floor version
and its packs) lost block_at recall against the previous night or the release baseline, or that a
model-independent defence failed. A page for on-call. A platform alert: ``tenant_id`` is empty on
purpose and the message names the configuration, the rules and the tenants that have it."""
ALERT_REDTEAM_QUARANTINED = "redteam_quarantined"
"""M5-05: a nightly run hit a provider refusal, so its configuration is **quarantined**:
never sent again until a platform operator clears it (an audited action). A page, at once. The
rest of that Gemini project's night waits; other projects carry on. A platform alert."""
ALERT_REDTEAM_UNASSIGNED = "redteam_unassigned"
"""M5-05: in production or staging a regulated tenant has no dedicated Gemini project,
so it is not red-teamed (it is never folded into the shared pool's run). A page, once a day."""
ALERT_REDTEAM_STALE = "redteam_stale"
"""M5-05: a configuration has gone more than seven nights without a tested result (the nightly
ceiling skipped it, or its runs keep being refused or stopped). A page, once a day."""
ALERT_REDTEAM_RUN_FAILED = "redteam_run_failed"
"""M5-05: a nightly run was stopped (a provider refusal, an auth failure, the failure rate, a
ceiling) or refused. A warning; a provider refusal also ends the night."""
ALERT_APPROVED_VERSION_CHANGE = "approved_version_change"
"""M5-02 (R2): on a tenant whose enforcing needs two-person approval, an admin rolled back to
another version (``reason`` ``rollback``) or raised an enforce candidate's ``rollout_percent``
(``set_percent``). Neither needs a second approver, so the tenant's other admins are told. A
warning for the tenant's admins; the class A event is the lifecycle event and the approval
trail's ``notified`` event. ``tenant_id`` is the tenant."""

ALERT_TIER_RAISE_UNMET = "tier_raise_unmet"
"""M5-01: a platform operator raised a tenant's tier, and the version the tenant is running no
longer meets what the new tier requires (a required pack it doesn't extend, or a required pack
rule it opted out of). The version keeps running; the requirement applies to the next publish.
A warning, for the tenant's admins and platform ops: ``tenant_id`` is the tenant, ``reason`` the
gaps (``pack:<name>``, ``rule:<key>``, comma separated; catalog names only)."""

ALERT_DEDICATED_POOL_EMPTY = "dedicated_pool_empty"
"""M5-06: a regulated tenant needed a dedicated Gemini project and none was free (none
configured, or all held). In ``production`` and ``staging`` the create or raise was refused
(409 ``no_dedicated_project``); in ``test`` the tenant fell back to the shared pool. A warning
for platform ops: a platform alert, ``tenant_id`` empty on purpose and the message naming the
tenant. Release a project of a lowered tenant (``release_project``) or add one under the
``projects`` setting."""

ALERT_OFFBOARDING_OVERDUE = "offboarding_overdue"
"""M5-07 (R3): a terminated tenant's data was not all deleted within 30 days of the termination
request (or the termination is stuck in ``terminating``). A page, raised by the offboarding job
on every run until the tenant is done. A platform alert: ``tenant_id`` is empty on purpose (the
tenant's own alert rows are among the data being deleted) and the message names the tenant."""


@dataclass(frozen=True)
class Alert:
    severity: AlertSeverity
    kind: str
    message: str
    key_id: str
    tenant_id: str
    """The tenant whose check triggered the alert. An auth failure affects every tenant."""
    guard_point: str
    reason: str | None = None
    """The provider's own reason, e.g. ``"API_KEY_INVALID"``, when it gave one."""
    count: int = 1
    """How many occurrences this alert stands for: this one plus those the gateway
    suppressed for the same kind, tenant and guard point since the previous alert."""
    rollback: str | None = None
    """M4-04: for a bad-publish alert, the Admin API path that rolls the tenant back
    (``POST /v1/tenants/{tid}/guardrails/versions/{v}/rollback``), or the versions list
    when the previous version is not known. None for every other alert."""
    dedupe_key: str | None = None
    """M4-04: a deterministic idempotency key for an alert that every replica of a
    service raises for the same occurrence (the bad-publish alert, provider health). The
    durable sink uses it as the outbox key, so replicas sharing an outbox store one event,
    and the webhook receiver gets one id. None: the sink makes a fresh key."""


@runtime_checkable
class AlertSink(Protocol):
    def emit(self, alert: Alert) -> None:
        """Deliver one alert. Synchronous; called off the event loop in a worker thread,
        after the check has returned (see the module docstring)."""
        ...


@runtime_checkable
class UsageMeter(Protocol):
    """Both methods are synchronous and are called off the event loop in a worker thread,
    after the check has returned (see the module docstring)."""

    def record(self, tenant_id: str, guard_point: str, input_tokens: int | None) -> None:
        """Record one answered model call. ``input_tokens`` is None when the provider's
        usage was missing or invalid: count that call as unknown, never as zero tokens."""
        ...

    def record_unanswered(self, tenant_id: str, guard_point: str) -> None:
        """Record one model call that was sent but got no answer: it timed out, it was
        cancelled at the deadline or with its caller, or the provider refused it
        (``SafetyBlocked``, M1-13 metering decision). The provider may still bill it, so its
        usage is unknown, and it counts as one request. Keep these apart from answered calls
        with unknown usage."""
        ...


@runtime_checkable
class CheckTimingMeter(Protocol):
    """Optional on a usage meter: the gateway calls it once per check when the meter has
    it. Synchronous and off the event loop, like ``UsageMeter``. Kept apart from
    ``UsageMeter`` so meters written before M1-04 admission control still conform."""

    def record_timing(
        self,
        tenant_id: str,
        guard_point: str,
        queue_wait_ms: float,
        provider_latency_ms: float,
    ) -> None:
        """Record one check's time waiting for admission on its key and its time in
        provider calls, each summed over the check's attempts. Recorded separately so the
        dogfood can show how much of each check was queueing."""
        ...


@runtime_checkable
class ProviderSafetyMeter(Protocol):
    """Optional on a usage meter: the gateway calls it once for every model call the
    provider refused (``SafetyBlocked``: HTTP 400 ``safety``, ``prohibited_content``,
    ``blocklist``, ``content_blocked`` or ``image_safety``) when
    the meter has it (M1-13, R10). Synchronous and off the event loop, like ``UsageMeter``.
    Kept apart from ``UsageMeter`` so meters written before M1-13 still conform.

    A refusal is the provider's own content filter, not a provider failure: it raises no
    alert. For metering it is also recorded as an attempt with usage unknown
    (``UsageMeter.record_unanswered``), never as an answered call (M1-13 decision)."""

    def record_provider_safety(self, tenant_id: str, guard_point: str) -> None:
        """Record one call the provider refused, for the per-tenant ``provider_safety``
        metric."""
        ...


@runtime_checkable
class ProviderErrorMeter(Protocol):
    """Optional on a usage meter: the gateway calls it for every 400 whose error code the
    adapter didn't recognise (``Failed.unrecognised_code``, M1-13), so a new code shows up
    in monitoring. Synchronous and off the event loop, like ``UsageMeter``."""

    def record_provider_error_unrecognised(
        self, tenant_id: str, guard_point: str, code: str
    ) -> None:
        """Record one ``provider_error_unrecognised``. Called for **every** occurrence (only
        the log line is throttled). ``code`` is a bounded label (M1-15): the provider's code
        casefolded, matching ``[a-z0-9_]{1,64}``, or one of the ``_``-prefixed placeholders
        ``_malformed`` (a code that didn't fit that pattern), ``_no_code`` (a 400 with no
        code), ``_not_json`` (a body that isn't JSON) and ``_overflow`` (the gateway has
        already passed ``MAX_UNRECOGNISED_CODE_LABELS`` distinct labels; later new ones
        share this one). So at most 64 + 4 distinct values ever arrive."""
        ...


@runtime_checkable
class TokenRateMeter(Protocol):
    """Optional on a usage meter (M3-10): reserved against actual tokens per project, and
    the ``token_rate`` fail-fasts. Synchronous and off the event loop, like ``UsageMeter``."""

    def record_token_reservation(self, project_id: str, reserved_tokens: int) -> None:
        """A provider call was sent after reserving ``reserved_tokens`` (R6.6's estimate)."""
        ...

    def record_token_actual(
        self, project_id: str, reserved_tokens: int, actual_tokens: int | None
    ) -> None:
        """A call that had reserved ``reserved_tokens`` returned. ``actual_tokens`` is the
        provider's input token count, or None when it is unknown (the reservation stands)."""
        ...

    def record_token_rate_fail_fast(
        self, project_id: str, tenant_id: str, guard_point: str, cause: str
    ) -> None:
        """A check failed fast with ``token_rate`` and no provider call. ``cause`` is
        ``bucket``, ``daily_requests`` or ``monthly_spend``."""
        ...


@runtime_checkable
class QuotaMeter(Protocol):
    """Optional on a usage meter (M3-07, M3-08): usage against share per tenant, refusals by
    tenant, and non-production usage per consumer. Synchronous and off the event loop, like
    ``UsageMeter``."""

    def record_tenant_usage(
        self, project_id: str, tenant_id: str, tier: str, tokens: int, share_tokens_per_minute: int
    ) -> None:
        """A production call of ``tenant_id`` was sent after reserving ``tokens`` of its share
        of ``share_tokens_per_minute``."""
        ...

    def record_tenant_refusal(
        self, project_id: str, tenant_id: str, tier: str, guard_point: str, cause: str
    ) -> None:
        """A check of ``tenant_id`` was refused for its share, with no provider call. ``cause``
        is ``tenant_tokens``, ``tenant_checks`` or ``tenant_daily``."""
        ...

    def record_consumer_usage(self, project_id: str, consumer: str, tokens: int) -> None:
        """A call of a non-production consumer (``test``, ``calibration``, ``red_team`` or
        ``shadow``) was sent after reserving ``tokens`` of its allowance."""
        ...

    def record_consumer_refusal(self, project_id: str, consumer: str, guard_point: str) -> None:
        """A call of a non-production consumer was refused for its allowance."""
        ...


@runtime_checkable
class IdentifierScanMeter(Protocol):
    """Optional on a usage meter: called once for every tenant dropped from the cross-tenant
    identifier scan. Synchronous and off the event loop, like ``UsageMeter``."""

    def record_identifier_patterns_dropped(self, tenant_id: str) -> None:
        """Record that ``tenant_id``'s identifier patterns were dropped from the scan."""
        ...


@runtime_checkable
class SkippedChecksMeter(Protocol):
    """Optional on a usage meter: called once for every check a tool's ``skip_model`` applied
    to (M3-03), so a tenant's floor-only coverage can be seen per tenant. Synchronous
    and off the event loop, like ``UsageMeter``."""

    def record_model_skipped(self, tenant_id: str, guard_point: str) -> None:
        """Record one check whose tenant and pack questions were skipped."""
        ...


class NullAlertSink:
    def emit(self, alert: Alert) -> None:
        return None


class RecordingAlertSink:
    """Keeps every alert in ``alerts``. In memory only, so it meets the contract."""

    def __init__(self) -> None:
        self.alerts: list[Alert] = []

    def emit(self, alert: Alert) -> None:
        self.alerts.append(alert)

    def pages(self) -> list[Alert]:
        return [a for a in self.alerts if a.severity is AlertSeverity.PAGE]

    def warnings(self, kind: str | None = None) -> list[Alert]:
        return [
            a
            for a in self.alerts
            if a.severity is AlertSeverity.WARNING and (kind is None or a.kind == kind)
        ]


class InMemoryUsageMeter:
    """Per ``(tenant_id, guard_point)``, three separate tallies: answered calls with known
    usage and their input tokens; answered calls whose usage was unknown; and unanswered
    attempts. Also each check's queue wait and provider latency (``CheckTimingMeter``) and
    the calls the provider refused (``ProviderSafetyMeter``) and 400s with an unrecognised
    code (``ProviderErrorMeter``). In memory only, so it meets the contract."""

    def __init__(self) -> None:
        self._tokens: Counter[tuple[str, str]] = Counter()
        self._calls: Counter[tuple[str, str]] = Counter()
        self._unknown: Counter[tuple[str, str]] = Counter()
        self._unanswered: Counter[tuple[str, str]] = Counter()
        self._provider_safety: Counter[tuple[str, str]] = Counter()
        self._unrecognised: Counter[tuple[str, str, str]] = Counter()
        self._patterns_dropped: Counter[str] = Counter()
        self._skipped: Counter[tuple[str, str]] = Counter()
        self._timings: dict[tuple[str, str], list[tuple[float, float]]] = {}
        self._reserved: Counter[str] = Counter()
        self._actual: Counter[str] = Counter()
        self._reserved_known: Counter[str] = Counter()
        self._actual_unknown: Counter[str] = Counter()
        self._fail_fasts: Counter[tuple[str, str, str, str]] = Counter()
        self._tenant_tokens: Counter[tuple[str, str]] = Counter()
        self._tenant_calls: Counter[tuple[str, str]] = Counter()
        self._tenant_shares: dict[tuple[str, str], int] = {}
        self._tenant_refusals: Counter[tuple[str, str, str, str]] = Counter()
        self._consumer_tokens: Counter[tuple[str, str]] = Counter()
        self._consumer_calls: Counter[tuple[str, str]] = Counter()
        self._consumer_refusals: Counter[tuple[str, str, str]] = Counter()

    def record_tenant_usage(
        self, project_id: str, tenant_id: str, tier: str, tokens: int, share_tokens_per_minute: int
    ) -> None:
        self._tenant_tokens[(project_id, tenant_id)] += tokens
        self._tenant_calls[(project_id, tenant_id)] += 1
        self._tenant_shares[(project_id, tenant_id)] = share_tokens_per_minute

    def record_tenant_refusal(
        self, project_id: str, tenant_id: str, tier: str, guard_point: str, cause: str
    ) -> None:
        self._tenant_refusals[(project_id, tenant_id, guard_point, cause)] += 1

    def record_consumer_usage(self, project_id: str, consumer: str, tokens: int) -> None:
        self._consumer_tokens[(project_id, consumer)] += tokens
        self._consumer_calls[(project_id, consumer)] += 1

    def record_consumer_refusal(self, project_id: str, consumer: str, guard_point: str) -> None:
        self._consumer_refusals[(project_id, consumer, guard_point)] += 1

    def tenant_tokens(self, project_id: str, tenant_id: str) -> int:
        """Tokens a tenant's sent production calls reserved against its share (M3-07)."""
        return self._tenant_tokens[(project_id, tenant_id)]

    def tenant_calls(self, project_id: str, tenant_id: str) -> int:
        """Production calls of a tenant that were sent."""
        return self._tenant_calls[(project_id, tenant_id)]

    def tenant_share(self, project_id: str, tenant_id: str) -> int | None:
        """The tenant's token share per minute as of its last call, or None if it made none."""
        return self._tenant_shares.get((project_id, tenant_id))

    def tenant_usage_vs_share(self, project_id: str, tenant_id: str, minutes: float) -> float:
        """Tokens used over ``minutes`` as a fraction of the tenant's share for that long
        (above 1 only through the bucket's burst). 0.0 for a tenant with no calls."""
        share = self.tenant_share(project_id, tenant_id)
        if not share or minutes <= 0:
            return 0.0
        return self.tenant_tokens(project_id, tenant_id) / (share * minutes)

    def tenant_refusals(
        self, project_id: str, tenant_id: str | None = None, *, cause: str | None = None
    ) -> int:
        """Checks refused for a tenant's share, for one tenant (None: every tenant), optionally
        for one cause."""
        return sum(
            n
            for (project, tenant, _, why), n in self._tenant_refusals.items()
            if project == project_id and tenant_id in (None, tenant) and cause in (None, why)
        )

    def consumer_tokens(self, project_id: str, consumer: str) -> int:
        """Tokens a non-production consumer's sent calls reserved."""
        return self._consumer_tokens[(project_id, consumer)]

    def consumer_calls(self, project_id: str, consumer: str) -> int:
        return self._consumer_calls[(project_id, consumer)]

    def consumer_refusals(self, project_id: str, consumer: str) -> int:
        return sum(
            n
            for (project, who, _), n in self._consumer_refusals.items()
            if project == project_id and who == consumer
        )

    def record_token_reservation(self, project_id: str, reserved_tokens: int) -> None:
        self._reserved[project_id] += reserved_tokens

    def record_token_actual(
        self, project_id: str, reserved_tokens: int, actual_tokens: int | None
    ) -> None:
        if actual_tokens is None:
            self._actual_unknown[project_id] += 1
        else:
            self._actual[project_id] += actual_tokens
            self._reserved_known[project_id] += reserved_tokens

    def record_token_rate_fail_fast(
        self, project_id: str, tenant_id: str, guard_point: str, cause: str
    ) -> None:
        self._fail_fasts[(project_id, tenant_id, guard_point, cause)] += 1

    def reserved_tokens(self, project_id: str) -> int:
        """Tokens reserved at admission, over every call sent (M3-10)."""
        return self._reserved[project_id]

    def actual_tokens(self, project_id: str) -> int:
        """Provider-reported input tokens of the calls that returned with usage."""
        return self._actual[project_id]

    def reserved_tokens_of_reconciled(self, project_id: str) -> int:
        """The reservations of those same calls, for comparing with ``actual_tokens``."""
        return self._reserved_known[project_id]

    def reservations_kept(self, project_id: str) -> int:
        """Calls that returned with unknown usage, so their reservation stood."""
        return self._actual_unknown[project_id]

    def token_rate_fail_fasts(
        self, project_id: str, *, tenant_id: str | None = None, cause: str | None = None
    ) -> int:
        """Checks that failed fast with ``token_rate``, optionally for one tenant or cause."""
        return sum(
            n
            for (project, tenant, _, why), n in self._fail_fasts.items()
            if project == project_id and tenant_id in (None, tenant) and cause in (None, why)
        )

    def record(self, tenant_id: str, guard_point: str, input_tokens: int | None) -> None:
        key = (tenant_id, guard_point)
        if input_tokens is None:
            self._unknown[key] += 1
        else:
            self._calls[key] += 1
            self._tokens[key] += input_tokens

    def record_unanswered(self, tenant_id: str, guard_point: str) -> None:
        self._unanswered[(tenant_id, guard_point)] += 1

    def record_provider_safety(self, tenant_id: str, guard_point: str) -> None:
        self._provider_safety[(tenant_id, guard_point)] += 1

    def record_provider_error_unrecognised(
        self, tenant_id: str, guard_point: str, code: str
    ) -> None:
        self._unrecognised[(tenant_id, guard_point, code)] += 1

    def record_identifier_patterns_dropped(self, tenant_id: str) -> None:
        self._patterns_dropped[tenant_id] += 1

    def record_model_skipped(self, tenant_id: str, guard_point: str) -> None:
        self._skipped[(tenant_id, guard_point)] += 1

    def model_skipped(self, tenant_id: str, guard_point: str | None = None) -> int:
        """Checks a tool's ``skip_model`` applied to, for a tenant (and a guard point)."""
        return sum(
            n
            for (tenant, point), n in self._skipped.items()
            if tenant == tenant_id and guard_point in (None, point)
        )

    def identifier_patterns_dropped(self, tenant_id: str) -> int:
        """Times ``tenant_id``'s identifier patterns were dropped from the scan."""
        return self._patterns_dropped[tenant_id]

    def record_timing(
        self,
        tenant_id: str,
        guard_point: str,
        queue_wait_ms: float,
        provider_latency_ms: float,
    ) -> None:
        self._timings.setdefault((tenant_id, guard_point), []).append(
            (queue_wait_ms, provider_latency_ms)
        )

    def timings(self, tenant_id: str, guard_point: str) -> list[tuple[float, float]]:
        """``(queue_wait_ms, provider_latency_ms)`` for each check, in order."""
        return list(self._timings.get((tenant_id, guard_point), []))

    def input_tokens(self, tenant_id: str, guard_point: str) -> int:
        """Total input tokens over the calls whose usage was known."""
        return self._tokens[(tenant_id, guard_point)]

    def metered_calls(self, tenant_id: str, guard_point: str) -> int:
        """Calls whose usage was known."""
        return self._calls[(tenant_id, guard_point)]

    def unknown_calls(self, tenant_id: str, guard_point: str) -> int:
        """Calls that were answered without usable usage. Not included in the totals above."""
        return self._unknown[(tenant_id, guard_point)]

    def unanswered_attempts(self, tenant_id: str, guard_point: str) -> int:
        """Calls that timed out or were cancelled; possibly billed. Not included above."""
        return self._unanswered[(tenant_id, guard_point)]

    def provider_safety_blocks(self, tenant_id: str, guard_point: str | None = None) -> int:
        """Calls the provider refused for ``tenant_id``, at ``guard_point`` or (None) at
        every guard point. Not included in any tally above."""
        return sum(
            n
            for (tenant, point), n in self._provider_safety.items()
            if tenant == tenant_id and guard_point in (None, point)
        )

    def provider_errors_unrecognised(
        self, tenant_id: str, guard_point: str | None = None, code: str | None = None
    ) -> int:
        """``provider_error_unrecognised`` for ``tenant_id``, optionally for one guard point
        and one code."""
        return sum(
            n
            for (tenant, point, label), n in self._unrecognised.items()
            if tenant == tenant_id and guard_point in (None, point) and code in (None, label)
        )

    def unrecognised_codes(self) -> set[str]:
        """Every code label recorded, over all tenants and guard points."""
        return {label for (_, _, label) in self._unrecognised}
