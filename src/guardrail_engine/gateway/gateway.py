"""The Decision Gateway (M1-04, minimum): the only caller of a ``DecisionModel``.

For each check it applies, in order:

1. **Auth circuit breaker, per key.** After a ``Failed(auth)`` the key's breaker is open:
   checks get ``Failed(auth)`` at once and the model is not called. The breaker closes when
   the key is replaced (``key_id()`` returns a different id) or when a probe call succeeds.
   The first probe is allowed ``probe_initial_delay_s`` (5 s) after the breaker opens. Each
   probe that does not close the breaker doubles the wait before the next one, up to
   ``probe_max_delay_s`` (60 s): 5, 10, 20, 40, 60, 60... Waits are measured from the start
   of the previous probe. Only one check is the probe; the others keep failing fast.
2. **Budget** (PF-8, R6.3 after U7, "relaxed"). Each check has a **total budget** that
   covers its admission wait, the first call and any retry: the guard point's cap,
   ``budget_cap_s`` (3,000 ms) on ``plan``, ``tool_call``, ``tool_result`` and ``output``,
   ``input_budget_cap_s`` (4,000 ms) on ``input``, unless a fixed override
   (``budgets_s``, ``default_budget_s``) replaces it. Within it the **first call** has an
   **attempt deadline**::

       expected p50     = band base + time_window_allowance_s + latency_per_question_s x questions
       attempt deadline = expected p50 + max(budget_margin_s, budget_margin_fraction x expected p50)

   with band bases of 244 / 271 / 326 / 400 ms for inputs of up to 1K / 4K / 8K / 16K
   tokens, a 380 ms time-window allowance, 2.0 ms per question and a margin of at least
   400 ms or 0.6 x expected p50. A floor-sized ``output`` check (4K input, 12 questions)
   expects 675 ms, its first call is cut at 1,080 ms, and it has 3,000 ms in all. The first
   call is cut at its attempt deadline only if what would be left could still hold a retry
   (the expected p50 plus the cancellation grace); otherwise it keeps the whole remaining
   budget, so a check never ends on a timeout before its budget is spent. When a call is
   cut, it is cancelled and the gateway waits at most ``cancel_grace_s`` (10 ms) for it to
   finish. A call still running after that is left behind as an orphan (tracked until it
   ends, its outcome discarded, its slot held, counted against the orphan cap) and a
   warning is raised: the adapter ignored cancellation. Every abandoned call is metered as
   attempted, usage unknown. When the whole budget runs out the result is
   ``Failed(timeout)``. See :class:`GatewayConfig` for how the input is measured.
3. **Retry.** At most one, only after ``timeout`` (a call cut at its attempt deadline
   included) or ``unavailable``, and only if the remaining budget is at least the call's
   expected latency: its expected p50 as above (R6.4), unless ``expected_latency_s`` fixes
   it. The retry is a new provider call: it re-enters admission at the back of the key's
   queue, with what is left of the check's queue allowance, and once admitted it gets all
   of the remaining budget. There is never more than one call of a check in flight at the
   gateway: the first has ended or been abandoned before the retry is sent (sequential, not
   hedging, R6.5). It waits a random jitter first, capped so the retry still has its
   expected latency left. A breaker probe is never retried, and so never cut early.
4. **Admission control, per key** (M1-04). Every provider call, retries included, needs
   one of the key's slots: at most ``max_in_flight_per_key`` (4, R6.3) calls are in flight
   on a key. A call that can't start at once waits in a first-in, first-out queue in front
   of the key, bounded at ``max_queued_per_key`` (64). The wait counts against the check's
   budget and is bounded by the check's **queue allowance** (R6.3, M1-15): the budget's
   ``queue_wait_s``, summed over the check's attempts. Before queueing, and again whenever
   the queue moves, the gateway predicts the wait (the in-flight calls' remaining expected
   time plus the queued calls ahead x the call's expected latency, over the usable slots;
   see :class:`InFlightLimit`) and fails fast, with no provider call, if the wait plus the
   expected latency doesn't fit in the remaining budget, or the wait is longer than the
   remaining queue allowance. A waiter is removed as soon as its remaining budget can no
   longer cover the expected call or its queue allowance runs out, whichever is first.
   Failures are ``Failed(unavailable)`` with reason ``admission_wait`` or
   ``admission_queue_full``, and are never retried. A slot is held until the provider
   call actually ends: an orphan keeps its slot. Orphans are counted out of the usable
   slots when predicting, so a key whose slots are all held by orphans fails fast; that
   raises one page per crossing (``decision_key_saturated_by_orphans``), and the recovery
   is logged when a slot frees. The rule deciding when a call may start is a strategy
   (:class:`AdmissionRule`, optionally with ``next_start_at`` for capacity that returns
   with time); the default is :class:`InFlightLimit`. A breaker probe that admission
   refuses doesn't count as a probe: the back-off is restored.
5. **Metering and alerts.** Every answered call's input tokens are recorded against the
   tenant and guard point; an answered call with unknown usage is recorded as unknown. An
   attempt that timed out or was cancelled is recorded separately as unanswered, because
   the provider may still bill it. Each check's queue wait and provider latency (summed
   over its attempts) go to a meter that implements ``record_timing``, and to the caller
   through :meth:`DecisionGateway.decide_timed`. A call the provider refused
   (``SafetyBlocked``, M1-13) is never retried, raises no alert and doesn't open the
   breaker. It is metered as one request with usage unknown, through the same
   ``record_unanswered`` path as an unfinished attempt (it may be billed; over-counting
   capacity is the safe side), never as an answered call, and also goes to a meter that
   implements ``record_provider_safety``. A 400 whose error code the adapter didn't
   recognise (``Failed.unrecognised_code``, a bounded label: the code casefolded, or
   ``_malformed``, ``_no_code``, ``_not_json``) goes, every time, to a meter that
   implements ``record_provider_error_unrecognised``; at most
   ``MAX_UNRECOGNISED_CODE_LABELS`` distinct codes are passed on, later ones as
   ``_overflow``. Its warning log line (label only) is throttled like the warnings below,
   per label, and says how many were suppressed (M1-15). Opening the breaker raises a page.
   Warnings (unknown usage, ignored cancellation) are raised at most once per
   ``warning_interval_s`` per tenant and guard point.
6. **Capacity signal** (R8, M1-15). :meth:`DecisionGateway.decide_timed` also returns
   ``retry_after_ms`` (when the gateway can time the failure: admission, the orphan cap, an
   open auth breaker) and ``capacity_limited`` (the gateway refused for lack of capacity),
   both from the gateway's own state only, and each check's ``in_flight_at_start``.

Before any of that, the **orphan cap**: once ``max_orphans`` (32) abandoned calls are still
running, checks fail fast with ``Failed(unavailable, reason="orphan_cap")``, with no model
call and no retry, until fewer than half the cap are left. Reaching the cap raises one page.
The order of the fast failures is: orphan cap, then the auth breaker, then admission.

**Alerts and metering never run on the request path.** The gateway decides synchronously
(the breaker opens, the throttle counts) and puts the resulting sink calls on a bounded
queue. One **daemon thread** (M4-04; not a thread-pool executor, whose workers are joined at
interpreter exit) delivers them, in order, so a slow sink cannot delay a check and a stuck
one cannot hold up process exit. When the queue is full the oldest event is dropped and
counted (``dropped_events``). :meth:`DecisionGateway.drain` waits for delivery;
:meth:`DecisionGateway.aclose` flushes and shuts down within ``close_timeout_s``.

Nothing raises out of :meth:`DecisionGateway.decide` except cancellation of the caller.

Time is injected: ``clock`` returns monotonic seconds and ``sleep`` waits. The deadline and
the cancellation grace are enforced by racing the model call against ``sleep``, so a test
that injects both controls time completely.

**Tenant quotas and fair scheduling (M3-07) and non-production allowances (M3-08)**, when
``config.quotas`` is set (:mod:`guardrail_engine.gateway.tenant_quota`): a check is charged to
its tenant's per-minute token and check shares (or, if tagged with :func:`usage_class`, to its
non-production consumer's allowance) before it queues, and refused at once, with no provider
call, if the share is spent; the admission queue is then ordered by priority class and, within
a class, by weighted fair order across tenants (non-production behind every production class).
``rate_limited`` is returned as it is, never retried.

**Production is never refused for tokens, queue space, slots, the day's requests or the
month's spend because of non-production use**. Non-production
calls (any ``usage_class`` but ``check``) hold at most a quarter of a key's admission queue and
half of its in-flight slots; a production check at a full queue pushes out the last
non-production waiter; and a tenant with fewer queued places than the largest holder pushes
that holder's last waiter out instead of being refused. A pushed-out waiter fails
``admission_queue_full`` with a retry hint and its share is given back. Each non-production
consumer also has **four allowances**, 10% each of the project's tokens a minute, the
tier's requests a minute, ``requests_per_day`` and ``monthly_spend_cap_usd``, enforced whenever
``config.token_rate`` is on, with or without ``config.quotas``: a call over one is refused with
no provider call, cause ``consumer_allowance``, reason ``token_rate`` (the minute allowances)
or ``quota_exhausted`` (the daily and monthly ones, retry hint to the next roll).

The exceptions to the guarantee, restated: (1) one in-flight slot per key; (2) **production's
own use** can reach the shared daily request count and monthly spend cap (non-production can
consume at most 40% of each, 4 consumers x 10%, so production keeps at least 60% of each window,
of the day and of the month; if both use their full shares, both reach the cap together);
(3) custom admission rules; (4) capacity the provider withholds; (5) a tenant's own share. See
:mod:`guardrail_engine.gateway.tenant_quota`.
"""

from __future__ import annotations

import asyncio
import inspect
import logging
import random
import threading
import time
from collections import deque
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol

from guardrail_engine.decision.port import (
    ERROR_LABEL_MALFORMED,
    ERROR_LABEL_PLACEHOLDERS,
    Answered,
    DecisionModel,
    DecisionResult,
    Failed,
    FailureKind,
    SafetyBlocked,
    bounded_error_label,
)
from guardrail_engine.decision.types import Question
from guardrail_engine.gateway.sinks import (
    ALERT_AUTH_FAILURE,
    ALERT_CANCEL_IGNORED,
    ALERT_CONSUMER_ALLOWANCE,
    ALERT_DAILY_REQUESTS,
    ALERT_KEY_SATURATED_BY_ORPHANS,
    ALERT_MONTHLY_SPEND,
    ALERT_ORPHAN_CAP,
    ALERT_TENANT_DAILY_QUOTA,
    ALERT_TENANT_QUOTA,
    ALERT_TOKEN_RATE_FAIL_FAST,
    ALERT_USAGE_UNKNOWN,
    ALERT_XTENANT_PATTERNS_DROPPED,
    ALERT_XTENANT_SCAN_SHARDED,
    Alert,
    AlertSeverity,
    AlertSink,
    CheckTimingMeter,
    IdentifierScanMeter,
    ProviderErrorMeter,
    ProviderSafetyMeter,
    QuotaMeter,
    SkippedChecksMeter,
    TokenRateMeter,
    UsageMeter,
)
from guardrail_engine.gateway.tenant_quota import (
    ALLOWANCE_MONTHLY_SPEND,
    ALLOWANCE_REQUESTS_PER_DAY,
    ALLOWANCE_REQUESTS_PER_MINUTE,
    ALLOWANCE_TOKENS,
    CAUSE_CONSUMER,
    CAUSE_TENANT_TOKENS,
    DAILY_CAUSES,
    QUOTA_CAUSES,
    USAGE_PRODUCTION,
    CheckGroup,
    ConsumerAllowances,
    FairClock,
    QuotaCharge,
    QuotaConfig,
    QuotaCrossing,
    QuotaLimiter,
    QuotaRefusal,
    consumer_of,
    non_production_queue_limit,
    non_production_slot_limit,
    resolve_usage_class,
)
from guardrail_engine.gateway.token_rate import (
    CAUSE_BUCKET,
    CAUSE_DAILY_REQUESTS,
    CAUSE_MONTHLY_SPEND,
    PRIORITY_BY_GUARD_POINT,
    REASON_QUOTA_EXHAUSTED,
    REASON_TOKEN_RATE,
    TEST_PRIORITY,
    CapRefusal,
    Crossing,
    InProcessTokenRateStore,
    Reservation,
    TokenRateConfig,
    TokenRateLimiter,
    TokenRateStore,
)
from guardrail_engine.policy.api_tokens import estimate_api_tokens
from guardrail_engine.tokens import estimate_question_tokens, estimate_tokens

logger = logging.getLogger(__name__)

DEFAULT_LATENCY_BANDS: tuple[tuple[int, float], ...] = (
    (1_000, 0.244),
    (4_000, 0.271),
    (8_000, 0.326),
    (16_000, 0.400),
)
"""R6.3: expected p50 base by input size, as (largest input in estimated tokens, seconds).
Fitted in M0-01 (``bench/results/m0-01-detail.md`` on the ``m0-01-latency-profile`` branch:
244 / 271 / 326 ms at 1K / 4K / 8K; about 400 ms at 16K from the pilot, 397 ms at 1 question).
Sequential calls from a single client in one location; to be re-fitted from production
(dogfood) data. The time-window allowance is added on top
(:data:`DEFAULT_TIME_WINDOW_ALLOWANCE_S`)."""
DEFAULT_TIME_WINDOW_ALLOWANCE_S = 0.380
"""R6.3 (it was 130 ms before): added to every band base. Three time
windows on one day gave solo 4K x 12 p50s of about 285, 443 and 663 ms; the shift is
additive, so it is a constant, fitted to the slowest window seen. A setting, re-fitted on
dogfood data."""
DEFAULT_LATENCY_PER_QUESTION_S = 0.002
"""R6.3: each question adds about 2.0 ms at any input size (M0-01 detail run: 1.96-2.07 ms).
Sequential calls from a single client in one location; to be re-fitted from production
(dogfood) data."""
DEFAULT_BUDGET_MARGIN_S = 0.400
"""R6.3: the smallest margin over the expected p50 in the first call's attempt deadline.
Sized so the M0-01 soak's slowest call (658 ms at 4K x 12) would not have timed out."""
DEFAULT_BUDGET_MARGIN_FRACTION = 0.6
"""R6.3: the attempt deadline's margin is ``max(budget_margin_s, this x expected p50)``. At
the largest calls the slowest observed call reached about 1.5x p50 (1,204 vs 811 ms at
16K x 200), which a flat 400 ms doesn't cover."""
DEFAULT_QUEUE_WAITS_S: tuple[tuple[str, float], ...] = (
    ("input", 0.300),
    ("plan", 0.100),
    ("tool_call", 0.100),
    ("tool_result", 0.400),
    ("output", 0.100),
)
"""R6.3: how long a check may wait in admission control, per guard point: 100 ms on the
critical path (``plan``, ``tool_call``, ``output``), 300 ms on ``input`` (hidden behind the
planner), 400 ms per ``tool_result`` chunk (the tool call has already taken its time). It is
inside the budget. A guard point not listed gets the smallest listed allowance."""
DEFAULT_BUDGET_CAP_S = 3.000
"""R6.3 after U7 ("give a relaxed latency"): the **total budget** of a check on ``plan``,
``tool_call``, ``tool_result`` (per chunk) and ``output``. It was 1,500 ms. The 3,000 ms
ceiling was decided by the user (U7.1: "3 s, 4 s for ``input``"); it stays a setting."""
DEFAULT_INPUT_BUDGET_CAP_S = 4.000
"""R6.3 after U7: the total budget of an ``input`` check, which runs alongside the planner.
It was 2,000 ms."""
MAX_BUDGET_OVERRIDE_S = 10.0
"""R6.3 (decided on the M1-15 build): a fixed budget override (``budgets_s``,
``default_budget_s``) above this is refused at startup."""
INPUT_GUARD_POINT = "input"
"""The guard point ``input_budget_cap_s`` applies to."""
DEFAULT_RETRY_JITTER_S = 0.025
DEFAULT_CANCEL_GRACE_S = 0.010
DEFAULT_PROBE_INITIAL_DELAY_S = 5.0
DEFAULT_PROBE_MAX_DELAY_S = 60.0
DEFAULT_WARNING_INTERVAL_S = 60.0
DEFAULT_MAX_ORPHANS = 32
DEFAULT_SINK_QUEUE_SIZE = 1024
DEFAULT_CLOSE_TIMEOUT_S = 1.0
DEFAULT_KEY_ID = "default"
DEFAULT_MAX_IN_FLIGHT_PER_KEY = 4
"""M1-04 admission control: provider calls in flight per key. 4 per R6.3 (decided 2026-11-17;
previously 2): the warm, pre-filled-window burst test met the flat test at k = 4.
It rises to 8 only if the same-window rerun passes the flat test at k = 8. A setting
(``GatewayConfig.max_in_flight_per_key``); this is its only default."""
DEFAULT_MAX_QUEUED_PER_KEY = 64
"""M1-04 admission control: calls waiting for a slot on one key."""
REASON_ORPHAN_CAP = "orphan_cap"
QUOTA_REASON_CAUSES = frozenset({CAUSE_DAILY_REQUESTS, CAUSE_MONTHLY_SPEND}) | DAILY_CAUSES
"""The causes of a refusal whose reason is ``quota_exhausted`` (the wait is until a counter
rolls); every other cause (the bucket, a tenant's minute share, a consumer's allowance) is
``token_rate``."""
_ALLOWANCE_NAMES = {
    ALLOWANCE_TOKENS: "token rate",
    ALLOWANCE_REQUESTS_PER_MINUTE: "requests a minute",
    ALLOWANCE_REQUESTS_PER_DAY: "requests a day",
    ALLOWANCE_MONTHLY_SPEND: "monthly spend cap",
}
"""How an alert names the allowance a non-production consumer used up."""
REASON_ADMISSION_WAIT = "admission_wait"
"""The check's remaining budget can't cover the predicted queue wait plus the call."""
REASON_ADMISSION_QUEUE_FULL = "admission_queue_full"
"""The key's queue has no place for the call: it holds ``max_queued_per_key`` calls (and the
call may not push another out), the tenant holds its share, non-production calls hold theirs,
or the call was itself pushed out to make room for another."""
CAPACITY_REASONS = frozenset(
    {
        REASON_ADMISSION_WAIT,
        REASON_ADMISSION_QUEUE_FULL,
        REASON_ORPHAN_CAP,
        REASON_TOKEN_RATE,
        REASON_QUOTA_EXHAUSTED,
    }
)
"""R8: the gateway's own refusals for lack of capacity (``capacity_limited``), with M3-10's
``token_rate`` (the bucket) and ``quota_exhausted`` (the daily request cap or the monthly
spend cap)."""
RETRY_AFTER_MIN_MS = 100
RETRY_AFTER_MAX_MS = 10_000
"""R8: ``retry_after_ms`` is clamped to 100-10,000 ms."""
FALLBACK_RETRY_AFTER_MS = 1_000
"""R8: the hint when the gateway refused for lack of capacity but can't predict the wait:
``orphan_cap`` (nothing says when a call that ignored cancellation will end), and admission
while orphans hold every slot (decided on the M1-15 build: every capacity refusal carries a
hint)."""

_INF = float("inf")
FINITE_SETTINGS = (
    "time_window_allowance_s",
    "latency_per_question_s",
    "budget_margin_s",
    "budget_margin_fraction",
    "budget_cap_s",
    "input_budget_cap_s",
    "default_budget_s",
    "expected_latency_s",
    "retry_jitter_s",
    "cancel_grace_s",
    "probe_initial_delay_s",
    "probe_max_delay_s",
    "warning_interval_s",
    "close_timeout_s",
)
"""The ``GatewayConfig`` number settings that must be finite (inf and NaN are refused)."""
RETRYABLE = frozenset({FailureKind.TIMEOUT, FailureKind.UNAVAILABLE})
MAX_UNRECOGNISED_CODE_LABELS = 64
"""M1-13: the most distinct unrecognised 400 codes one gateway logs and meters by name.
Provider-supplied, so capped to keep metric cardinality bounded; later codes are reported as
``UNRECOGNISED_CODE_OVERFLOW``."""
LOG_UNRECOGNISED = "provider_error_unrecognised"
"""The throttle kind of the unrecognised-code warning log line (it is a log line, not an
alert)."""
UNRECOGNISED_CODE_OVERFLOW = "_overflow"
"""The code label used once ``MAX_UNRECOGNISED_CODE_LABELS`` distinct codes have been seen.
It starts with ``_``, so no real (bounded) code can collide with it."""

Clock = Callable[[], float]
Sleep = Callable[[float], Awaitable[None]]


@dataclass(frozen=True)
class CheckBudget:
    """How one check's time is laid out (R6.3 after U7). All in seconds.

    ``total_s`` is the check's whole budget: admission wait, the first call and any retry.
    ``attempt_deadline_s`` is how long the first call may run (expected p50 plus margin); at
    run time it is also limited to what is left of ``total_s``. ``queue_wait_s`` is how long
    the check may wait for admission, summed over its attempts. ``retry_window_s`` is what is
    left for a retry if the first call used its whole attempt deadline after a full queue
    wait: ``total_s - queue_wait_s - attempt_deadline_s``."""

    expected_p50_s: float
    margin_s: float
    attempt_deadline_s: float
    queue_wait_s: float
    total_s: float
    retry_window_s: float
    override: bool
    """Whether ``total_s`` is a fixed override (``budgets_s`` or ``default_budget_s``) rather
    than the guard point's cap."""


@dataclass(frozen=True)
class GatewayConfig:
    """All durations are in seconds. Every value here is a setting (M1-11) with its one
    default in this module.

    **Budget per check** (PF-8, R6.3 after U7). A check's **total budget** covers its
    admission wait, the first call and any retry. It is, in order of precedence:

    1. ``budgets_s[guard_point]``, if the guard point is listed (a platform setting, never
       per tenant);
    2. ``default_budget_s``, if set, for every other guard point;
    3. otherwise (the default) the guard point's cap: ``budget_cap_s`` (3,000 ms) on
       ``plan``, ``tool_call``, ``tool_result`` and ``output``, ``input_budget_cap_s``
       (4,000 ms) on ``input``.

    An override (1 or 2) must be more than the smallest call's expected p50 and at most
    :data:`MAX_BUDGET_OVERRIDE_S`.

    Within the budget::

        expected p50     = band base + time_window_allowance_s
                           + latency_per_question_s x questions
        attempt deadline = expected p50
                           + max(budget_margin_s, budget_margin_fraction x expected p50)
        queue allowance  = queue_waits_s[guard_point], at most total - expected p50

    The first call is cut at its attempt deadline (or when the budget runs out, if that is
    sooner). After a ``timeout`` or ``unavailable`` one retry is made if at least the expected
    p50 is left; it gets all of the remaining budget. With the defaults
    (:meth:`budget_parts`): a floor-sized ``output`` check (4K input, 12 questions) expects
    675 ms, gets a 1,080 ms attempt deadline, 100 ms of queue allowance, a 3,000 ms budget
    and a 1,820 ms retry window.

    **Band base** is the ``latency_bands`` base for the input size. The input size is the
    shared estimator's ``estimate_tokens`` of the ``input`` text given to ``decide``
    (questions are counted by number, not tokens), because M0-01 sized its 1K / 4K / 8K /
    16K inputs with that estimator. A band covers inputs up to and including its bound; an
    input larger than the last bound uses the last band's base.

    **Queue allowance** (R6.3, M1-15): a check waits for admission at most its allowance,
    summed over its attempts, and never past the point where its remaining budget can't
    cover the expected call. The predicted-wait check uses the same two figures.

    ``expected_latency_s``, when set, replaces the expected p50 everywhere (retry threshold,
    admission, attempt deadline). It is for tests and experiments.
    """

    latency_bands: tuple[tuple[int, float], ...] = DEFAULT_LATENCY_BANDS
    """Expected p50 base by input size: ``(largest input in estimated tokens, base)``,
    ascending by size."""
    time_window_allowance_s: float = DEFAULT_TIME_WINDOW_ALLOWANCE_S
    """Added to every band base (R6.3): latency moved between time windows."""
    latency_per_question_s: float = DEFAULT_LATENCY_PER_QUESTION_S
    """Expected p50 added per question."""
    budget_margin_s: float = DEFAULT_BUDGET_MARGIN_S
    """The attempt deadline's smallest margin over the expected p50."""
    budget_margin_fraction: float = DEFAULT_BUDGET_MARGIN_FRACTION
    """The attempt deadline's margin is at least this fraction of the expected p50."""
    queue_waits_s: Mapping[str, float] = field(default_factory=lambda: dict(DEFAULT_QUEUE_WAITS_S))
    """Allowed admission queue wait per guard point. A guard point not listed gets the
    smallest listed value (0 if none is)."""
    budget_cap_s: float = DEFAULT_BUDGET_CAP_S
    """The total budget of a check on every guard point but ``input``."""
    input_budget_cap_s: float = DEFAULT_INPUT_BUDGET_CAP_S
    """The total budget of an ``input`` check."""
    default_budget_s: float | None = None
    """A fixed total budget for every guard point not in ``budgets_s``, replacing the cap.
    None (the default) uses the caps."""
    budgets_s: Mapping[str, float] = field(default_factory=dict)
    """Fixed per-guard-point total budgets, replacing the cap. Platform settings only."""
    expected_latency_s: float | None = None
    """A fixed expected call time, replacing each call's expected p50 everywhere. None (the
    default) computes it per call (R6.3)."""
    retry_jitter_s: float = DEFAULT_RETRY_JITTER_S
    """Upper bound of the random wait before a retry."""
    cancel_grace_s: float = DEFAULT_CANCEL_GRACE_S
    """How long to wait for a cancelled model call to finish before leaving it behind. A
    check can therefore take up to its budget plus this."""
    probe_initial_delay_s: float = DEFAULT_PROBE_INITIAL_DELAY_S
    """Wait between a breaker opening and its first probe."""
    probe_max_delay_s: float = DEFAULT_PROBE_MAX_DELAY_S
    """Cap on the wait between probes; the wait doubles after each probe that fails."""
    warning_interval_s: float = DEFAULT_WARNING_INTERVAL_S
    """A warning of one kind is raised at most once per this interval per tenant and guard
    point. 0 raises every one."""
    max_orphans: int = DEFAULT_MAX_ORPHANS
    """Cap on abandoned model calls still running. At the cap, checks fail fast until fewer
    than half this many are left."""
    sink_queue_size: int = DEFAULT_SINK_QUEUE_SIZE
    """How many alert and metering events can wait for delivery. Beyond it the oldest is
    dropped."""
    close_timeout_s: float = DEFAULT_CLOSE_TIMEOUT_S
    """Upper bound on ``aclose()``: flushing queued events and stopping orphans. Real time,
    not the injected clock."""
    max_in_flight_per_key: int = DEFAULT_MAX_IN_FLIGHT_PER_KEY
    """Admission control: the default rule's limit on provider calls in flight per key."""
    max_queued_per_key: int = DEFAULT_MAX_QUEUED_PER_KEY
    """Admission control: calls that may wait for a slot on one key. One more fails fast
    with ``admission_queue_full``."""
    token_rate: TokenRateConfig | None = None
    """M3-10: the project's token-rate limiter, daily request counter and monthly spend
    tracker. None (the default of a bare gateway) turns it off; the engine's settings turn it
    on with the platform defaults (``EngineSettings.token_rate``)."""
    quotas: QuotaConfig | None = None
    """M3-07, M3-08: per-tenant shares, weighted fair scheduling and non-production
    allowances. None (the default of a bare gateway) turns them off, leaving the queue first
    in, first out (or ordered by priority class with ``token_rate``); the engine's settings
    turn them on with the platform defaults (``EngineSettings.quotas``)."""

    def __post_init__(self) -> None:
        for name in (
            "max_orphans",
            "sink_queue_size",
            "max_in_flight_per_key",
            "max_queued_per_key",
        ):
            if not getattr(self, name) >= 1:
                raise ValueError(f"{name} must be >= 1, got {getattr(self, name)}")
        for name in FINITE_SETTINGS:
            value = getattr(self, name)
            if value is not None and not (isinstance(value, int | float) and -_INF < value < _INF):
                raise ValueError(f"{name} must be a finite number, got {value}")
        positive = {
            "budget_cap_s": self.budget_cap_s,
            "input_budget_cap_s": self.input_budget_cap_s,
            "probe_initial_delay_s": self.probe_initial_delay_s,
        }
        if self.default_budget_s is not None:
            positive["default_budget_s"] = self.default_budget_s
        positive.update({f"budgets_s[{gp!r}]": b for gp, b in self.budgets_s.items()})
        for name, value in positive.items():
            if not value > 0:
                raise ValueError(f"{name} must be > 0, got {value}")
        for name in (
            "time_window_allowance_s",
            "latency_per_question_s",
            "budget_margin_s",
            "budget_margin_fraction",
            "expected_latency_s",
            "retry_jitter_s",
            "cancel_grace_s",
            "warning_interval_s",
            "close_timeout_s",
        ):
            value = getattr(self, name)
            if value is not None and not value >= 0:
                raise ValueError(f"{name} must be >= 0, got {value}")
        for gp, wait in self.queue_waits_s.items():
            if not (isinstance(gp, str) and 0 <= wait < float("inf")):
                raise ValueError(f"queue_waits_s[{gp!r}] must be a finite value >= 0, got {wait}")
        if not self.latency_bands:
            raise ValueError("latency_bands must have at least one band")
        previous = 0
        for bound, base in self.latency_bands:
            if not (isinstance(bound, int) and bound > previous):
                raise ValueError(
                    "latency_bands bounds must be whole token counts in ascending order, "
                    f"got {bound} after {previous}"
                )
            if not 0 < base < _INF:
                raise ValueError(f"latency_bands base for {bound} must be > 0, got {base}")
            previous = bound
        if not self.probe_max_delay_s >= self.probe_initial_delay_s:
            raise ValueError(
                f"probe_max_delay_s ({self.probe_max_delay_s}) must be >= "
                f"probe_initial_delay_s ({self.probe_initial_delay_s})"
            )
        overrides = {f"budgets_s[{gp!r}]": b for gp, b in self.budgets_s.items()}
        if self.default_budget_s is not None:
            overrides["default_budget_s"] = self.default_budget_s
        smallest = self.smallest_expected_s()
        for name, value in overrides.items():
            if not -_INF < value < _INF:
                raise ValueError(f"{name} must be a finite number, got {value}")
            if value > MAX_BUDGET_OVERRIDE_S:
                raise ValueError(
                    f"{name} ({value} s) is above the {MAX_BUDGET_OVERRIDE_S} s limit on a "
                    "fixed budget override"
                )
            if value <= smallest:
                raise ValueError(
                    f"{name} ({value} s) is not more than the smallest call's expected p50 "
                    f"({smallest:.3f} s), so no check could finish within it"
                )

    def smallest_expected_s(self) -> float:
        """The smallest call's expected p50: the first band, one question (or
        ``expected_latency_s`` if set). A total budget must be more than this."""
        if self.expected_latency_s is not None:
            return self.expected_latency_s
        return self.expected_p50_for(input_tokens=0, question_count=1)

    def expected_p50_for(self, *, input_tokens: int, question_count: int) -> float:
        """R6.3: the band base for ``input_tokens``, plus the time-window allowance, plus the
        per-question slope."""
        base = self.latency_bands[-1][1]  # above the last bound: the last band
        for bound, band_base in self.latency_bands:
            if input_tokens <= bound:
                base = band_base
                break
        return base + self.time_window_allowance_s + self.latency_per_question_s * question_count

    def expected_latency_for(self, *, input_tokens: int, question_count: int) -> float:
        """The retry threshold for a call (R6.4), and the expected call time admission
        charges it: ``expected_latency_s`` if set, else the call's expected p50."""
        if self.expected_latency_s is not None:
            return self.expected_latency_s
        return self.expected_p50_for(input_tokens=input_tokens, question_count=question_count)

    def queue_wait_for(self, guard_point: str) -> float:
        """The guard point's configured queue allowance, before any shrinking for the cap.
        An unlisted guard point gets the smallest listed allowance."""
        if guard_point in self.queue_waits_s:
            return self.queue_waits_s[guard_point]
        return min(self.queue_waits_s.values(), default=0.0)

    def cap_for(self, guard_point: str) -> float:
        """The guard point's cap, its total budget without an override:
        ``input_budget_cap_s`` on ``input``, ``budget_cap_s`` elsewhere."""
        if guard_point == INPUT_GUARD_POINT:
            return self.input_budget_cap_s
        return self.budget_cap_s

    def budget_parts(
        self, guard_point: str, *, input_tokens: int, question_count: int
    ) -> CheckBudget:
        """How one check's time is laid out (the class docstring gives the rules)."""
        expected = self.expected_latency_for(
            input_tokens=input_tokens, question_count=question_count
        )
        margin = max(self.budget_margin_s, self.budget_margin_fraction * expected)
        override = self.budgets_s.get(guard_point, self.default_budget_s)
        total = self.cap_for(guard_point) if override is None else override
        queue = min(self.queue_wait_for(guard_point), max(0.0, total - expected))
        attempt = expected + margin
        return CheckBudget(
            expected_p50_s=expected,
            margin_s=margin,
            attempt_deadline_s=attempt,
            queue_wait_s=queue,
            total_s=total,
            retry_window_s=total - queue - attempt,
            override=override is not None,
        )

    def budget_for(self, guard_point: str, *, input_tokens: int, question_count: int) -> float:
        """The total budget for one check (:meth:`budget_parts`)."""
        return self.budget_parts(
            guard_point, input_tokens=input_tokens, question_count=question_count
        ).total_s


# ---------------------------------------------------------------------- admission seam


@dataclass(frozen=True)
class KeyLoad:
    """What an :class:`AdmissionRule` sees of one key when it decides."""

    key_id: str
    in_flight: int
    """Provider calls on the key that haven't ended, orphans included."""
    orphans: int
    """Of those, calls that ignored cancellation and are still running."""
    now: float
    """The gateway's clock."""
    in_flight_started_at: tuple[float, ...] = ()
    """When each in-flight call that isn't an orphan took its slot, oldest first. A rule
    may assume any in-flight non-orphan call not listed here has only just started."""
    in_flight_expected_s: tuple[float, ...] = ()
    """Each of those calls' own expected latency, in the same order. A rule may
    charge a call not listed here the newcomer's expected latency."""
    queued_ahead_expected_s: tuple[float, ...] = ()
    """The own expected latency of each queued call ahead of the call being predicted,
    first in line first. Empty outside a prediction. A rule may charge a call
    ahead not listed here the newcomer's expected latency."""


class AdmissionRule(Protocol):
    """Decides when a provider call may start on a key: the strategy seam of admission
    control. The gateway owns the queue (order, bound, budget checks, removal) and the slot
    count; the rule only answers these three questions.

    The default, :class:`InFlightLimit`, caps calls in flight. A **token-rate limiter**
    (tokens per interval, per key or per project), which M1-04 may add as well as or
    instead of it, fits the same interface: ``can_start`` checks its bucket,
    ``predicted_wait_s`` adds the time until the bucket refills, and ``started`` debits the
    call's tokens (``input_tokens`` is the shared estimate of the call's input text). Two
    rules would combine as "all must allow; the wait is the larger". A rule whose capacity
    comes back with time alone, not with a call ending, also implements the optional
    ``next_start_at`` (:class:`TimedAdmissionRule`), so the queue wakes its waiters then."""

    def can_start(self, load: KeyLoad) -> bool:
        """Whether one more call may start on the key now."""
        ...

    def predicted_wait_s(self, load: KeyLoad, *, ahead: int, expected_call_s: float) -> float:
        """Expected wait before a call with ``ahead`` queued calls in front of it can
        start, if each call takes ``expected_call_s``. ``float("inf")`` if it can't be
        expected to start at all."""
        ...

    def started(self, load: KeyLoad, *, input_tokens: int) -> None:
        """A call has been given a slot and is about to be sent. ``load`` is the key as it
        was just before the call took its slot."""
        ...


class TimedAdmissionRule(AdmissionRule, Protocol):
    """An :class:`AdmissionRule` with the optional ``next_start_at``.
    The gateway looks the method up on any rule and uses it when present."""

    def next_start_at(self, load: KeyLoad) -> float | None:
        """The clock time at which ``can_start`` may next become true without any call
        ending (a token bucket refilling, say), or None if only a call ending can free
        capacity. The queue wakes its waiters at that time to re-check."""
        ...


class InFlightLimit:
    """At most ``limit`` provider calls in flight per key (M1-04 default rule).

    Predicted wait = (remaining time of the calls in flight + the queued calls in front)
    / usable slots, where each in-flight call i is charged ``max(E_i - its elapsed time,
    0.1 x E_i)`` and each queued call j in front its own ``E_j``, with
    E_i and E_j those calls' own expected latencies. Usable slots are the limit
    less the orphans. With calls of one size, a burst at time zero gives the original
    "calls ahead / limit x E"; staggered arrivals aren't charged a full E for a call that
    is nearly done; and on a key carrying both large and small checks, each call is
    charged what it is expected to take. A call the load doesn't describe is charged the
    newcomer's E. Orphans are left out of both: a call that ignored cancellation has
    already outlived a budget, so it isn't expected to free its slot in time. When orphans
    hold every slot, the wait is infinite and checks fail fast."""

    REMAINING_FLOOR = 0.1
    """An in-flight call past its expected time is still charged this fraction of its
    expected time."""

    def __init__(self, limit: int) -> None:
        if not limit >= 1:
            raise ValueError(f"limit must be >= 1, got {limit}")
        self.limit = limit

    def can_start(self, load: KeyLoad) -> bool:
        return load.in_flight < self.limit

    def predicted_wait_s(self, load: KeyLoad, *, ahead: int, expected_call_s: float) -> float:
        usable = self.limit - load.orphans
        if usable <= 0:
            return float("inf")
        own = load.in_flight_expected_s
        remaining = 0.0
        for i, started_at in enumerate(load.in_flight_started_at):
            e = own[i] if i < len(own) else expected_call_s
            remaining += max(e - (load.now - started_at), self.REMAINING_FLOOR * e)
        unknown = max(0, load.in_flight - load.orphans - len(load.in_flight_started_at))
        remaining += unknown * expected_call_s  # assume just started
        listed = load.queued_ahead_expected_s[:ahead]
        queued = sum(listed) + (ahead - len(listed)) * expected_call_s
        return (remaining + queued) / usable

    def started(self, load: KeyLoad, *, input_tokens: int) -> None:
        return None

    def next_start_at(self, load: KeyLoad) -> float | None:
        return None  # only a call ending frees a slot


@dataclass(frozen=True)
class CheckTiming:
    """Where one check's time went, summed over its attempts (M1-04 metering)."""

    queue_wait_ms: float
    """Time spent waiting for admission (a slot on the key), including waits that ended in
    an admission failure."""
    provider_latency_ms: float
    """Time from sending each provider call until the gateway had its outcome (for an
    abandoned call: until the cancellation grace ended)."""
    provider_calls: int
    """Provider calls made: 0, 1, or 2 with a retry."""
    in_flight_at_start: int | None = None
    """M1-15 (R6.3): provider calls in flight on the check's key when the check arrived at
    the gateway, before any fast failure or admission wait: calls sent and not yet ended,
    orphans included (they still hold a slot and are still at the provider); calls queued
    for a slot and this check's own call are not counted. None only if the gateway failed
    before it could tell which key the check uses."""


@dataclass(frozen=True)
class TimedDecision:
    """What :meth:`DecisionGateway.decide_timed` returns: the result ``decide`` would have
    returned, the check's timing, and the R8 capacity signal."""

    result: DecisionResult
    timing: CheckTiming
    retry_after_ms: int | None = None
    """R8: when the gateway refused or failed the check for a reason it can time, how long
    to wait before trying again, clamped to 100-10,000 ms: ``admission_wait`` and
    ``admission_queue_full``, the predicted wait for a slot (the admission prediction);
    ``orphan_cap``, 1,000 ms; ``auth`` while the key's breaker is open, the time until the
    next probe. Computed by the gateway from its own state only, never from anything the
    provider sent. None for everything it can't time (``timeout``, ``unavailable``,
    ``other``...), and when the prediction is infinite (orphans hold every slot)."""
    capacity_limited: bool = False
    """R8: the gateway itself refused the check for lack of capacity (``admission_wait``,
    ``admission_queue_full``, ``orphan_cap``; ``token_rate`` with M3-10). Set from where the
    refusal was made, never from a provider's reason string."""


@dataclass(frozen=True)
class _Outcome:
    result: DecisionResult
    retry_after_s: float | None = None
    capacity_limited: bool = False


def _retry_after_ms(seconds: float | None, *, clamp_max: bool = True) -> int | None:
    """R8: a hint in whole milliseconds, clamped to 100-10,000 ms. None stays None, and so
    does a wait that can't be predicted (infinite or not a number). ``clamp_max=False`` (a
    ``quota_exhausted`` refusal) keeps the 100 ms floor but no ceiling: the time until
    midnight Pacific or the 1st is the honest answer."""
    if seconds is None or not (-_INF < seconds < _INF):  # also rejects NaN
        return None
    ms = int(-(-round(seconds * 1000, 6) // 1))  # whole ms, rounded up; no float noise
    return (
        max(ms, RETRY_AFTER_MIN_MS)
        if not clamp_max
        else min(max(ms, RETRY_AFTER_MIN_MS), RETRY_AFTER_MAX_MS)
    )


@dataclass
class _Timing:
    queue_wait_s: float = 0.0
    provider_s: float = 0.0
    calls: int = 0
    in_flight_at_start: int | None = None
    on_admitted: Callable[[], None] | None = None
    """M3-04: called each time one of the check's calls is admitted, i.e. leaves the queue for
    a slot. Lets a caller that has several checks queued tell queued from started."""
    group: CheckGroup | None = None
    group_index: int = 0
    """M3-09: the chunk group this call belongs to, and its place in it."""


@dataclass(eq=False)
class _Slot:
    """One provider call's hold on a key's slot, released when the call ends."""

    key_id: str
    started_at: float
    expected_s: float
    """The call's own expected latency."""
    orphan: bool = False
    non_production: bool = False
    """The call is not production traffic (counted against the non-production share
    of the key's slots)."""


class _Waiter:
    __slots__ = (
        "evicted",
        "expected_s",
        "finish",
        "non_production",
        "priority",
        "start",
        "tenant_id",
        "tokens",
        "wake",
    )

    def __init__(
        self,
        expected_s: float,
        tokens: int = 0,
        priority: int = 0,
        tenant_id: str = "",
        non_production: bool = False,
    ) -> None:
        self.non_production = non_production
        """Whether the call is non-production (capped to a share of the queue, and the
        first to be pushed out for production)."""
        self.evicted: str | None = None
        """Set (to the message) when the waiter was pushed out of the queue to
        make room for another call; it then fails ``admission_queue_full``."""
        self.tenant_id = tenant_id
        """M3-07: whose call it is (for weighted fair order and the per-tenant queue bound)."""
        self.start = 0.0
        self.finish = 0.0
        """M3-07: the waiter's virtual start and finish time in its priority class
        (:class:`FairClock`); the queue is ordered by ``(priority, start)``."""
        self.expected_s = expected_s
        """The queued call's own expected latency."""
        self.tokens = tokens
        """The API tokens it will reserve (M3-10); 0 without a token-rate limiter."""
        self.priority = priority
        """M3-10: 0 for ``input`` and ``output``, 1 for ``plan`` and ``tool_call``, 2 for
        ``tool_result``; the queue is ordered by it, first come first served within it."""
        self.wake: asyncio.Future[None] | None = None


@dataclass
class _KeyState:
    in_flight: int = 0
    orphans: int = 0
    waiters: deque[_Waiter] = field(default_factory=deque)
    slots: set[_Slot] = field(default_factory=set)
    saturated_by_orphans: bool = False
    """Paged: orphans hold every slot. Cleared, with an info log, when a slot frees."""
    fair: FairClock = field(default_factory=FairClock)
    """M3-07: virtual time of the queue's priority classes."""


@dataclass
class _OpenBreaker:
    next_probe_at: float
    delay: float
    """The wait that led to ``next_probe_at``; the next one is twice this, capped."""
    reason: str | None


USAGE_CHECK = USAGE_PRODUCTION
"""The usage class of production traffic (``"check"``): metered under the plain guard point
name. One concept with M3-08's production consumer."""


def metered_guard_point(guard_point: str, usage_class: str) -> str:
    """The guard point label a meter sees: the plain name for production checks, and
    ``"<class>:<name>"`` for any other class (``test:output``)."""
    return guard_point if usage_class == USAGE_CHECK else f"{usage_class}:{guard_point}"


@dataclass
class _Throttle:
    next_at: float
    suppressed: int = 0


@dataclass
class _Check:
    tenant_id: str
    guard_point: str
    key_id: str
    deadline: float
    expected_latency: float
    """A retry needs at least this much of the budget left, and so does a queued call."""
    queue_allowance: float = float("inf")
    """How long the check may wait for admission, summed over its attempts (R6.3)."""
    attempt_deadline: float | None = None
    """How long the first call may run once sent (R6.3 after U7); None: to the budget."""
    input_tokens: int = 0
    probe: bool = False
    usage_class: str = USAGE_CHECK
    timing: _Timing = field(default_factory=_Timing)
    queue_deadline: float = float("inf")
    """While the check is in ``_admit``: when its queue allowance runs out."""
    refusal_wait_s: float | None = None
    """Set with each admission refusal: the predicted wait for a slot at that moment (R8),
    or None if it couldn't be predicted."""
    priority: int = 0
    """M3-10: the queue class of the guard point (0 first)."""
    rate_tokens: int = 0
    """M3-10: the API tokens the check's call reserves (R6.6's estimate); 0 without a limiter."""
    reservation: Reservation | None = None
    """The token reservation of the call in flight, until it is reconciled."""
    refusal_cause: str | None = None
    """For a ``token_rate`` refusal: which limit (``bucket``, ``daily_requests``,
    ``monthly_spend``, or one of M3-07's ``tenant_tokens``, ``tenant_checks``,
    ``tenant_daily``, ``consumer_allowance``)."""
    refusal_limit: str = ""
    """For a ``consumer_allowance`` refusal: which allowance, as
    ``tenant_quota.ALLOWANCES`` names them."""
    tier: str | None = None
    """M3-07: the tenant's directory tier, as the caller gave it."""
    consumer: str = USAGE_PRODUCTION
    """M3-08: ``production`` or the non-production consumer the call belongs to."""
    non_production: bool = False
    """Not production traffic (any ``usage_class`` but ``check``)."""
    api_tokens: int = 1
    """M3-07: the call's estimated API tokens (R6.6) for its tenant's share, and the cost of
    its place in the fair queue."""
    charge: QuotaCharge | None = None
    """What the check took from its tenant's share (or its consumer's allowance), until the
    first call is settled; the retry takes nothing more."""
    charged: bool = False
    """Whether the first attempt has been charged (the retry is never charged again)."""
    group: CheckGroup | None = None
    """M3-09: the chunk group of a ``tool_result`` (charged together, one fair-queue place)."""
    group_index: int = 0

    @property
    def metered_guard_point(self) -> str:
        return metered_guard_point(self.guard_point, self.usage_class)


class DecisionGateway:
    """Wraps one ``DecisionModel`` with a budget, one bounded retry, an auth circuit
    breaker, usage metering and alerts. Safe for concurrent use on one event loop."""

    def __init__(
        self,
        model: DecisionModel,
        *,
        config: GatewayConfig | None = None,
        meter: UsageMeter | None = None,
        alerts: AlertSink | None = None,
        key_id: Callable[[], str] | None = None,
        clock: Clock = time.monotonic,
        sleep: Sleep = asyncio.sleep,
        rng: Callable[[], float] = random.random,
        admission: AdmissionRule | None = None,
        rate_store: TokenRateStore | None = None,
        wall_clock: Callable[[], datetime] | None = None,
    ) -> None:
        """``key_id`` returns an identifier of the API key the model is using right now,
        e.g. the secret's version in the secret store. It must change when the key is
        replaced, and it must not be the key itself: it appears in alerts and messages.

        ``rng`` returns a float in [0, 1) and scales the retry jitter.

        ``admission`` decides when a call may start on a key; the default is
        ``InFlightLimit(config.max_in_flight_per_key)``.

        ``config.token_rate`` turns on M3-10's limiter. ``rate_store`` is where its bucket and
        counters live: gateways given the same store (and project id) share one limit. The
        default is a private in-process store. ``wall_clock`` returns the current aware
        datetime, for the Pacific day and month the counters roll on; ``clock`` stays the
        monotonic clock the bucket refills by.
        """
        self._model = model
        self._config = config or GatewayConfig()
        self._meter = meter
        self._alerts = alerts
        self._key_id = key_id or (lambda: DEFAULT_KEY_ID)
        self._clock = clock
        self._sleep = sleep
        self._rng = rng
        self._admission: AdmissionRule = admission or InFlightLimit(
            self._config.max_in_flight_per_key
        )
        self._rate: TokenRateLimiter | None = None
        if self._config.token_rate is not None:
            self._rate = TokenRateLimiter(
                self._config.token_rate, rate_store or InProcessTokenRateStore(), wall_clock
            )
        self._quota: QuotaLimiter | None = None
        if self._config.quotas is not None:
            # Same store as the project's bucket (which the engine may swap for a shared
            # one), so gateways sharing it share the shares too.
            own_store = (
                self._rate.store
                if self._rate is not None
                else rate_store or InProcessTokenRateStore()
            )
            self._quota = QuotaLimiter(
                self._config.quotas,
                lambda: self._rate.store if self._rate is not None else own_store,
                project_id=self._project_id() or "default",
                project=self._config.token_rate,
                wall_clock=(self._rate.wall if self._rate is not None else wall_clock or _utc_now),
            )
        # What charges a check's first call: the tenant shares and consumer allowances with
        # quotas, else the consumer allowances alone, which need only the project's
        # limiter. None when there is neither.
        self._charger: QuotaLimiter | ConsumerAllowances | None = self._quota
        if self._charger is None and self._rate is not None:
            rate = self._rate
            self._charger = ConsumerAllowances(
                None,
                lambda: rate.store,
                project_id=rate.project_id,
                project=rate.config,
                wall_clock=rate.wall,
            )
        self._keys: dict[str, _KeyState] = {}
        self._open: dict[str, _OpenBreaker] = {}
        self._throttles: dict[tuple[str, ...], _Throttle] = {}
        # Strong references: the event loop only holds weak ones, so a task nobody
        # references can be garbage-collected while it is still running.
        self._orphans: set[asyncio.Future[Any]] = set()
        self._timers: set[asyncio.Future[Any]] = set()
        self._orphaned_calls = 0
        self._orphan_capped = False
        self._unrecognised_labels: set[str] = set()
        # Sink calls waiting for delivery off the request path: (sink name, function, args).
        # The bounded queue and its single daemon drainer thread (M4-04). ``_events_cond``
        # guards the deque, the thread flags and the idle waiters; sinks are called without it.
        self._events: deque[_Event] = deque()
        self._events_cond = threading.Condition()
        self._drainer_alive = False
        self._event_in_hand = False
        self._abandoned = False
        self._idle_waiters: list[tuple[asyncio.AbstractEventLoop, asyncio.Future[None]]] = []
        self._dropped_events = 0
        self._closed = False

    @property
    def config(self) -> GatewayConfig:
        return self._config

    @property
    def token_rate_limiter(self) -> TokenRateLimiter | None:
        """The project's M3-10 limiter (its config, store and fail-fast window), or None when
        ``config.token_rate`` is not set."""
        return self._rate

    @property
    def quota_limiter(self) -> QuotaLimiter | None:
        """The M3-07 / M3-08 limiter (tenant shares, consumer allowances), or None when
        ``config.quotas`` is not set."""
        return self._quota

    @property
    def consumer_allowances(self) -> ConsumerAllowances | None:
        """The non-production consumers' allowances (M3-08): tokens, requests a
        minute, requests a day and monthly spend. On whenever ``config.token_rate`` is, with
        or without ``config.quotas``; None without ``token_rate``."""
        if isinstance(self._charger, QuotaLimiter):
            return self._charger.allowances if self._charger.allowances.enabled else None
        return self._charger

    @property
    def dropped_events(self) -> int:
        """Alert and metering events that were never delivered: pushed out of a full queue
        by newer ones, still queued when ``aclose()`` ran out of time, or raised after it."""
        return self._dropped_events

    @property
    def orphan_capped(self) -> bool:
        """Whether checks are failing fast because too many abandoned calls are running."""
        return self._orphan_capped

    async def drain(self) -> None:
        """Wait until every alert and metering event raised so far has been delivered to
        its sink. For tests, and for callers that read a sink right after a check."""
        while (idle := self._idle_future()) is not None:
            await idle

    def _busy(self) -> bool:
        """Whether an event is queued or being delivered (and not given up on). Call with
        ``_events_cond`` held, or from a test."""
        return not self._abandoned and (bool(self._events) or self._event_in_hand)

    def _idle_future(self) -> asyncio.Future[None] | None:
        """A future the drainer thread resolves when it has emptied the queue, or None when
        it is not running (nothing is waiting for delivery)."""
        with self._events_cond:
            if not self._busy():
                return None
            loop = asyncio.get_running_loop()
            future: asyncio.Future[None] = loop.create_future()
            self._idle_waiters.append((loop, future))
            return future

    async def aclose(self) -> None:
        """Shut down: cancel the orphaned model calls, deliver the queued events, and wait
        for the orphans to stop. Returns within ``close_timeout_s`` of real time even if a
        sink is stuck or an orphan never ends: events still queued are dropped and counted,
        orphans still running are let go, and both are logged. Call it once no more checks
        will be made: events raised afterwards are dropped. Safe to call twice.

        A stuck sink's thread cannot be interrupted. It is a daemon thread, so it does not
        keep the process alive (M4-04)."""
        with self._events_cond:
            self._closed = True
            self._events_cond.notify_all()  # an idle drainer thread can go
        loop = asyncio.get_running_loop()
        deadline = loop.time() + self._config.close_timeout_s

        orphans = list(self._orphans)
        for orphan in orphans:
            orphan.cancel()  # first, so they wind down while the events are flushed

        idle = self._idle_future()
        if idle is not None:
            await asyncio.wait({idle}, timeout=max(0.0, deadline - loop.time()))
            if not idle.done():
                # A sink is stuck. Its thread cannot be interrupted; stop waiting.
                idle.cancel()
                with self._events_cond:
                    undelivered = len(self._events)
                    self._events.clear()
                    self._dropped_events += undelivered
                    self._abandoned = True
                logger.warning(
                    "gateway closed with a sink still running; %d queued events dropped",
                    undelivered,
                )

        if orphans:
            await asyncio.wait(orphans, timeout=max(0.0, deadline - loop.time()))
            abandoned = sum(not orphan.done() for orphan in orphans)
            if abandoned:
                logger.warning(
                    "gateway closed with %d model calls still running after cancellation; "
                    "abandoned",
                    abandoned,
                )
            self._orphans.clear()

    async def __aenter__(self) -> DecisionGateway:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()

    @property
    def model_id(self) -> str:
        return self._model.model_id

    @property
    def orphaned_calls(self) -> int:
        """How many model calls were left behind because they outlived their cancellation
        by more than ``cancel_grace_s``. Not zero means an adapter ignores cancellation."""
        return self._orphaned_calls

    @property
    def orphans_in_flight(self) -> int:
        """How many of those calls are still running."""
        return len(self._orphans)

    def in_flight(self, key_id: str | None = None) -> int:
        """Provider calls in flight on ``key_id`` (default: the current key), orphans
        included."""
        state = self._keys.get(self._key_id() if key_id is None else key_id)
        return 0 if state is None else state.in_flight

    def queued(self, key_id: str | None = None) -> int:
        """Calls waiting for a slot on ``key_id`` (default: the current key)."""
        state = self._keys.get(self._key_id() if key_id is None else key_id)
        return 0 if state is None else len(state.waiters)

    def breaker_open(self, key_id: str | None = None) -> bool:
        """Whether the auth breaker is open for ``key_id`` (default: the current key)."""
        return (self._key_id() if key_id is None else key_id) in self._open

    async def decide(
        self,
        *,
        tenant_id: str,
        guard_point: str,
        input: str,
        questions: Mapping[str, Question],
        tier: str | None = None,
        usage_class: str = USAGE_CHECK,
    ) -> DecisionResult:
        """One guard-point check. Returns the model's result, or ``Failed`` with the reason
        the gateway could not get one. Returns within the guard point's budget plus
        ``cancel_grace_s``. Never raises, except ``CancelledError`` when the caller itself
        is cancelled (the in-flight model call is cancelled with it). ``tier`` and
        ``usage_class`` are as for :meth:`decide_timed`."""
        timed = await self.decide_timed(
            tenant_id=tenant_id,
            guard_point=guard_point,
            input=input,
            questions=questions,
            tier=tier,
            usage_class=usage_class,
        )
        return timed.result

    async def decide_timed(
        self,
        *,
        tenant_id: str,
        guard_point: str,
        input: str,
        questions: Mapping[str, Question],
        tier: str | None = None,
        usage_class: str = USAGE_CHECK,
        on_admitted: Callable[[], None] | None = None,
        group: CheckGroup | None = None,
        group_index: int = 0,
    ) -> TimedDecision:
        """:meth:`decide`, plus where the check's time went: queue wait and provider
        latency, each summed over its attempts. The same timing goes to a meter that
        implements ``record_timing``.

        ``on_admitted`` is called (synchronously, on the event loop) each time the check's
        call gets its slot and is about to be sent. A caller with several checks submitted
        together (M3-04's chunks) uses it to tell the ones still queued, which it may cancel,
        from the ones started, which it leaves to end.

        ``group`` (from :meth:`check_group`) and ``group_index`` mark the call as one chunk of a
        check: the chunks are charged to the tenant together (all or none) and take one place in
        the fair queue (M3-09).

        ``usage_class`` keeps metering apart (M2-05): a call that is not production traffic,
        such as a draft test, is metered under the guard point ``"<class>:<guard point>"``,
        so it never adds to the production figures. Admission, budgets and the model call are
        the same as for a check, except that it queues behind production and, with
        ``config.token_rate``, spends its consumer's allowances (M3-08: ``test``, ``calibration``,
        ``red_team`` or ``shadow``; any other label counts as ``test``). ``USAGE_CHECK``, the
        default, is production, unless an enclosing
        :func:`~guardrail_engine.gateway.tenant_quota.usage_class` block tagged the call.

        ``tier`` is the tenant's directory tier (``standard``, ``regulated``, ``dedicated``),
        which picks its share and its weight in fair scheduling (M3-07); None is the
        configured default tier. It is ignored without ``config.quotas``."""
        usage_class = resolve_usage_class(usage_class)
        timing = _Timing(on_admitted=on_admitted, group=group, group_index=group_index)
        try:
            outcome = await self._decide(
                tenant_id, guard_point, input, questions, timing, tier, usage_class
            )
        except Exception as exc:
            logger.exception("decision gateway error")
            outcome = _Outcome(
                Failed(kind=FailureKind.OTHER, message=f"gateway error: {type(exc).__name__}")
            )
        check_timing = CheckTiming(
            queue_wait_ms=timing.queue_wait_s * 1000,
            provider_latency_ms=timing.provider_s * 1000,
            provider_calls=timing.calls,
            in_flight_at_start=timing.in_flight_at_start,
        )
        meter = self._meter
        if isinstance(meter, CheckTimingMeter):
            self._enqueue(
                "usage meter",
                meter.record_timing,
                tenant_id,
                metered_guard_point(guard_point, usage_class),
                check_timing.queue_wait_ms,
                check_timing.provider_latency_ms,
            )
        return TimedDecision(
            result=outcome.result,
            timing=check_timing,
            retry_after_ms=_retry_after_ms(
                outcome.retry_after_s,
                clamp_max=not (
                    isinstance(outcome.result, Failed)
                    and outcome.result.reason == REASON_QUOTA_EXHAUSTED
                ),
            ),
            capacity_limited=outcome.capacity_limited,
        )

    async def _decide(
        self,
        tenant_id: str,
        guard_point: str,
        input: str,
        questions: Mapping[str, Question],
        timing: _Timing,
        tier: str | None = None,
        usage_class: str = USAGE_CHECK,
    ) -> _Outcome:
        start = self._clock()
        input_tokens, question_count = estimate_tokens(input), len(questions)
        key_id = self._key_id()
        # What the check met on arrival, before any fast failure or wait (M1-15).
        timing.in_flight_at_start = self.in_flight(key_id)
        budget = self._config.budget_parts(
            guard_point, input_tokens=input_tokens, question_count=question_count
        )
        check = _Check(
            tenant_id=tenant_id,
            guard_point=guard_point,
            key_id=key_id,
            deadline=start + budget.total_s,
            expected_latency=self._config.expected_latency_for(
                input_tokens=input_tokens, question_count=question_count
            ),
            queue_allowance=budget.queue_wait_s,
            attempt_deadline=budget.attempt_deadline_s,
            input_tokens=input_tokens,
            timing=timing,
            usage_class=usage_class,
            non_production=usage_class != USAGE_CHECK,
            group=timing.group,
            group_index=timing.group_index,
        )
        if self._rate is not None:
            check.rate_tokens = self._rate.estimate(input_tokens, questions)
            check.priority = self._rate.priority(guard_point, production=usage_class == USAGE_CHECK)
            self._rate.window.note_check(start)
            self._check_fail_fast_window(check, start)
        if self._charger is not None:
            check.tier = tier
            check.consumer = consumer_of(usage_class)
            check.api_tokens = check.rate_tokens or max(
                1,
                estimate_api_tokens(
                    text_tokens=input_tokens,
                    question_tokens=estimate_question_tokens(questions),
                    question_count=len(questions),
                ),
            )
            check.priority = (
                PRIORITY_BY_GUARD_POINT.get(guard_point, 1)
                if check.consumer == USAGE_PRODUCTION
                else TEST_PRIORITY
            )

        if self._orphan_capped:
            # Returned from here, so it never reaches the retry below: a capped check makes
            # no model call and no retry, although ``unavailable`` is otherwise retryable.
            return _Outcome(
                Failed(
                    kind=FailureKind.UNAVAILABLE,
                    message=(
                        f"{len(self._orphans)} model calls that ignored cancellation are still "
                        "running; model not called"
                    ),
                    reason=REASON_ORPHAN_CAP,
                ),
                retry_after_s=FALLBACK_RETRY_AFTER_MS / 1000,
                capacity_limited=True,
            )

        breaker = self._open.get(check.key_id)
        if len(self._open) > (breaker is not None):
            # Breakers of keys that have been replaced: nothing is sent on those any more.
            self._open = {} if breaker is None else {check.key_id: breaker}
        if breaker is not None:
            if start < breaker.next_probe_at:
                return _Outcome(
                    Failed(
                        kind=FailureKind.AUTH,
                        message=(
                            f"auth circuit breaker is open for key {check.key_id!r}; "
                            "model not called"
                        ),
                        reason=breaker.reason,
                    ),
                    retry_after_s=breaker.next_probe_at - start,
                )
            # Claim the probe slot before awaiting, so concurrent checks keep failing fast.
            # The wait is doubled now; a probe that succeeds removes the breaker anyway.
            previous_delay = breaker.delay
            breaker.delay = min(breaker.delay * 2, self._config.probe_max_delay_s)
            breaker.next_probe_at = start + breaker.delay
            check.probe = True

        # The first call is cut at its attempt deadline (R6.3 after U7), or at the end of the
        # budget if that comes first. A breaker probe is never retried, so it isn't cut early.
        result, refused = await self._attempt(
            check, input, questions, attempt_s=None if check.probe else check.attempt_deadline
        )
        if (
            refused
            and isinstance(result, Failed)
            and result.reason in (REASON_TOKEN_RATE, REASON_QUOTA_EXHAUSTED)
        ):
            self._token_rate_fail_fast(check)
        if check.probe and refused and self._open.get(check.key_id) is breaker:
            # Admission refused the probe, so nothing was sent and the key learned nothing
            #: undo the back-off step and allow a probe again after the initial
            # delay, instead of counting this as an inconclusive probe.
            assert breaker is not None
            breaker.delay = previous_delay
            breaker.next_probe_at = self._clock() + self._config.probe_initial_delay_s
        retryable = isinstance(result, Failed) and result.kind in RETRYABLE
        if retryable and not refused and not check.probe:
            # Never after an admission refusal: admission failures are not retried.
            spare = check.deadline - self._clock() - check.expected_latency
            if spare >= 0:
                jitter = self._rng() * min(self._config.retry_jitter_s, spare)
                if jitter > 0:
                    await self._sleep(jitter)
                # The retry is a new call: it goes to the back of the key's queue and
                # passes the same predicted-wait check, with what is left of the queue
                # allowance. If it isn't admitted, the first attempt's result stands, as
                # when the budget doesn't allow a retry. Admitted, it gets all of the
                # remaining budget. The first call has ended or been abandoned by now (an
                # abandoned call that ignores cancellation is an orphan, holding its slot
                # and counted against the orphan cap): never two calls of one check at once.
                retry, retry_refused = await self._attempt(check, input, questions)
                if not retry_refused:
                    result = retry

        if not refused and isinstance(result, Failed) and result.kind is FailureKind.AUTH:
            self._on_auth_failure(result, check)
        elif check.probe and isinstance(result, Answered | SafetyBlocked):
            # The provider accepted the key. Any other failure says nothing about the key.
            self._open.pop(check.key_id, None)
        return self._outcome_of(result, refused, check)

    def _outcome_of(self, result: DecisionResult, refused: bool, check: _Check) -> _Outcome:
        """The R8 capacity signal for a check's final result, from the gateway's own state.
        ``refused``: the result is the gateway's admission refusal of the first attempt
        (a refused retry leaves the first attempt's result, which carries no hint)."""
        if not isinstance(result, Failed):
            return _Outcome(result)
        if result.kind is FailureKind.AUTH:
            # The breaker is open for the key (fast-fail, the call that opened it, a failed
            # probe, or a call refused in the queue once it opened): the next probe is when
            # the key can work again. A replaced key's late auth leaves no breaker: no hint.
            breaker = self._open.get(check.key_id)
            if breaker is None:
                return _Outcome(result)
            return _Outcome(result, retry_after_s=breaker.next_probe_at - self._clock())
        if result.kind is FailureKind.RATE_LIMITED:
            # The provider refused (429), not the gateway: its own RetryInfo delay, passed
            # through clamped, or no hint. Never capacity_limited.
            return _Outcome(result, retry_after_s=result.retry_delay_s)
        if refused and result.kind is FailureKind.UNAVAILABLE and result.reason in CAPACITY_REASONS:
            wait = check.refusal_wait_s
            if wait is None or not -_INF < wait < _INF:
                # Orphans hold every slot: the wait can't be predicted (decided: fall back).
                wait = FALLBACK_RETRY_AFTER_MS / 1000
            if check.probe:
                # A refused probe: the next one is allowed after the initial delay.
                breaker = self._open.get(check.key_id)
                if breaker is not None:
                    wait = max(wait, breaker.next_probe_at - self._clock())
            return _Outcome(result, retry_after_s=wait, capacity_limited=True)
        return _Outcome(result)

    # ------------------------------------------------------------------ one model call

    async def _attempt(
        self,
        check: _Check,
        input: str,
        questions: Mapping[str, Question],
        *,
        attempt_s: float | None = None,
    ) -> tuple[DecisionResult, bool]:
        """One model call, admitted on the check's key and cancelled at its deadline: the
        end of the check's budget, or ``attempt_s`` after it is sent if that is sooner.
        Returns the result, and whether admission refused the call (then nothing was sent
        and the result is the refusal)."""
        if check.deadline - self._clock() <= 0:
            return _budget_exhausted(), False
        admitted = await self._admit(check)
        if isinstance(admitted, Failed):
            return admitted, True
        # The slot is held from here until the provider call ends (``_call_ended``).
        slot = admitted
        if (notify := check.timing.on_admitted) is not None:
            try:
                notify()
            except Exception:
                logger.exception("the on_admitted hook failed; ignored")
        remaining = check.deadline - self._clock()
        if remaining <= 0:
            self._call_ended(slot)
            self._settle(check, 0)  # nothing was sent: the reservation goes back
            return _budget_exhausted(), False
        try:
            call: asyncio.Future[DecisionResult] = asyncio.ensure_future(
                self._model.decide(input, questions)
            )
        except BaseException:
            self._call_ended(slot)  # nothing was sent
            self._settle(check, 0)
            raise
        call.add_done_callback(lambda _call: self._call_ended(slot))
        check.timing.calls += 1
        if self._rate is not None:
            self._crossed(check, self._rate.count_sent())  # a request counts once it is sent
        self._quota_sent(check)
        sent_at = self._clock()
        # Cut the call at its attempt deadline only if a retry could still follow: at least
        # the expected call (plus the cancellation grace) would be left. Otherwise cutting
        # it would only end the check early with a timeout, before its budget is spent
        # (R6.3: "the check blocks on timeout only when the budget is spent"), so the call
        # gets the whole remaining budget instead.
        cut_by_attempt = (
            attempt_s is not None
            and remaining - attempt_s >= check.expected_latency + self._config.cancel_grace_s
        )
        timer: asyncio.Future[None] | None = None
        try:
            timer = asyncio.ensure_future(
                self._sleep(attempt_s if cut_by_attempt and attempt_s is not None else remaining)
            )
            await asyncio.wait({call, timer}, return_when=asyncio.FIRST_COMPLETED)
            finished = call.done()
            if not finished:
                await self._abandon(call, check, slot)
        except BaseException:
            # The caller was cancelled, or the injected sleep is broken. Either way the
            # model call must not be left running unbounded or unobserved.
            if not call.done():
                await self._abandon(call, check, slot)
            else:
                _consume(call)
            raise
        finally:
            if timer is not None:
                self._release(timer)
            check.timing.provider_s += self._clock() - sent_at
        result = self._outcome(call, timer, finished, check, cut_by_attempt)
        if isinstance(result, Answered) and result.usage is not None:
            self._settle(check, result.usage.total_input_tokens)
        else:
            self._settle(check, None)  # usage unknown: the reservation stands
        return result, False

    def _outcome(
        self,
        call: asyncio.Future[DecisionResult],
        timer: asyncio.Future[None] | None,
        finished: bool,
        check: _Check,
        cut_by_attempt: bool = False,
    ) -> DecisionResult:

        if not finished:
            assert timer is not None
            if not timer.cancelled() and (timer_exc := timer.exception()) is not None:
                raise timer_exc  # a broken injected sleep, not a real timeout
            if cut_by_attempt:
                return Failed(kind=FailureKind.TIMEOUT, message="attempt deadline exceeded")
            return Failed(kind=FailureKind.TIMEOUT, message="guard point budget exceeded")
        if call.cancelled():
            return Failed(kind=FailureKind.OTHER, message="model call was cancelled")
        if (exc := call.exception()) is not None:
            # A port violation: adapters return Failed, they don't raise.
            logger.error("decision model raised", exc_info=exc)
            return Failed(kind=FailureKind.OTHER, message=f"model raised {type(exc).__name__}")
        result = call.result()
        if not isinstance(result, Answered | SafetyBlocked | Failed):
            return Failed(kind=FailureKind.OTHER, message=f"model returned {type(result).__name__}")
        if isinstance(result, Answered):
            self._record_usage(result, check)
        elif isinstance(result, SafetyBlocked):
            # M1-13 metering decision: one request, usage unknown, as an unfinished attempt.
            self._record_unanswered(check)
            self._record_provider_safety(check)
        elif isinstance(result, Failed) and result.kind is FailureKind.TIMEOUT:
            self._record_unanswered(check)
        elif isinstance(result, Failed) and result.unrecognised_code is not None:
            self._record_unrecognised(result.unrecognised_code, check)
        return result

    async def _abandon(self, call: asyncio.Future[Any], check: _Check, slot: _Slot) -> None:
        """Cancel an in-flight model call and wait at most ``cancel_grace_s`` for it to
        finish. If it is still running after that, keep it as an orphan and warn."""
        self._record_unanswered(check)  # the provider may bill a call it had already received
        call.cancel()
        grace: asyncio.Future[None] | None = None
        try:
            grace = asyncio.ensure_future(self._sleep(self._config.cancel_grace_s))
            await asyncio.wait({call, grace}, return_when=asyncio.FIRST_COMPLETED)
        except Exception:
            logger.exception("could not wait for the cancelled model call")
        finally:
            if grace is not None:
                self._release(grace)
            if call.done():
                _consume(call)
            else:
                self._orphan(call, check, slot)

    def _orphan(self, call: asyncio.Future[Any], check: _Check, slot: _Slot) -> None:
        # It keeps its slot until it actually ends (``_call_ended``).
        slot.orphan = True
        state = self._keys[slot.key_id]
        state.orphans += 1
        self._check_saturated_by_orphans(slot.key_id, state, check)
        self._orphaned_calls += 1
        self._orphans.add(call)
        call.add_done_callback(self._orphan_done)
        logger.warning(
            "model call outlived its cancellation by more than %.3fs (tenant=%s guard_point=%s)",
            self._config.cancel_grace_s,
            check.tenant_id,
            check.guard_point,
        )
        self._warn(
            ALERT_CANCEL_IGNORED,
            "model call ignored cancellation at the deadline and is still running; "
            f"the adapter for {self._model.model_id!r} must honour cancellation",
            check,
        )
        if not self._orphan_capped and len(self._orphans) >= self._config.max_orphans:
            self._orphan_capped = True
            self._emit(
                Alert(
                    severity=AlertSeverity.PAGE,
                    kind=ALERT_ORPHAN_CAP,
                    message=(
                        f"{len(self._orphans)} model calls that ignored cancellation are still "
                        f"running (cap {self._config.max_orphans}); checks fail as unavailable "
                        "(floor rules block) until fewer than half the cap are left"
                    ),
                    key_id=check.key_id,
                    tenant_id=check.tenant_id,
                    guard_point=check.guard_point,
                    reason=REASON_ORPHAN_CAP,
                    count=len(self._orphans),
                )
            )

    def _orphan_done(self, call: asyncio.Future[Any]) -> None:
        self._orphans.discard(call)
        _consume(call)
        if self._orphan_capped and len(self._orphans) * 2 < self._config.max_orphans:
            self._orphan_capped = False
            logger.info(
                "%d model calls that ignored cancellation still running; checks call the "
                "model again",
                len(self._orphans),
            )

    # ------------------------------------------------------------------ admission

    def _load(self, key_id: str, state: _KeyState, ahead: tuple[_Waiter, ...] = ()) -> KeyLoad:
        """The key as a rule sees it; ``ahead`` are the waiters in front of the call being
        predicted."""
        live = sorted(
            (slot for slot in state.slots if not slot.orphan), key=lambda slot: slot.started_at
        )
        return KeyLoad(
            key_id=key_id,
            in_flight=state.in_flight,
            orphans=state.orphans,
            now=self._clock(),
            in_flight_started_at=tuple(slot.started_at for slot in live),
            in_flight_expected_s=tuple(slot.expected_s for slot in live),
            queued_ahead_expected_s=tuple(waiter.expected_s for waiter in ahead),
        )

    def _take_slot(
        self, check: _Check, state: _KeyState, reservation: Reservation | None = None
    ) -> _Slot:
        load = self._load(check.key_id, state)
        self._admission.started(load, input_tokens=check.input_tokens)
        if reservation is not None:
            check.reservation = reservation
            self._note_reservation(check, reservation)
        slot = _Slot(
            check.key_id,
            started_at=load.now,
            expected_s=check.expected_latency,
            non_production=check.non_production,
        )
        state.slots.add(slot)
        state.in_flight += 1
        return slot

    def _saturated_by_orphans(self, key_id: str, state: _KeyState) -> bool:
        """Every call on the key is an orphan and the rule expects no start at all."""
        if state.orphans == 0 or state.orphans < state.in_flight:
            return False
        wait = self._admission.predicted_wait_s(
            self._load(key_id, state), ahead=0, expected_call_s=1.0
        )
        return wait == float("inf")

    def _check_saturated_by_orphans(self, key_id: str, state: _KeyState, check: _Check) -> None:
        """Page once when orphans take the key's usable slots to zero."""
        if state.saturated_by_orphans or not self._saturated_by_orphans(key_id, state):
            return
        state.saturated_by_orphans = True
        self._emit(
            Alert(
                severity=AlertSeverity.PAGE,
                kind=ALERT_KEY_SATURATED_BY_ORPHANS,
                message=(
                    f"{state.orphans} model calls that ignored cancellation hold every slot "
                    f"of key {key_id!r}; every check on it fails as unavailable "
                    "(admission_wait; floor rules block) until one of them ends"
                ),
                key_id=key_id,
                tenant_id=check.tenant_id,
                guard_point=check.guard_point,
                reason=REASON_ADMISSION_WAIT,
                count=state.orphans,
            )
        )

    def _call_ended(self, slot: _Slot) -> None:
        """A provider call ended (answered, failed, cancelled, or an orphan finally
        stopping), or was never sent: give its slot back and let the queue move."""
        state = self._keys.get(slot.key_id)
        if state is None:
            return
        state.slots.discard(slot)
        state.in_flight -= 1
        if slot.orphan:
            state.orphans -= 1
            slot.orphan = False
        if state.saturated_by_orphans and not self._saturated_by_orphans(slot.key_id, state):
            state.saturated_by_orphans = False
            logger.info(
                "key %r no longer saturated by orphans: %d still running, a slot is free",
                slot.key_id,
                state.orphans,
            )
        self._queue_moved(slot.key_id, state)

    def _queue_moved(self, key_id: str, state: _KeyState) -> None:
        """Wake every waiter to re-check its turn and its predicted wait."""
        for waiter in state.waiters:
            if waiter.wake is not None and not waiter.wake.done():
                waiter.wake.set_result(None)
        if state.in_flight == 0 and not state.waiters:
            self._keys.pop(key_id, None)

    def _admission_failed(
        self, check: _Check, reason: str, message: str, wait_s: float | None
    ) -> Failed:
        """An admission refusal. ``wait_s`` is the predicted wait for a slot at the moment
        of refusal, kept for the R8 hint."""
        check.refusal_wait_s = wait_s
        return Failed(kind=FailureKind.UNAVAILABLE, message=message, reason=reason)

    def _breaker_refusal(self, check: _Check) -> Failed | None:
        breaker = self._open.get(check.key_id)
        if breaker is None or check.probe:
            return None
        return Failed(
            kind=FailureKind.AUTH,
            message=f"auth circuit breaker is open for key {check.key_id!r}; model not called",
            reason=breaker.reason,
        )

    async def _admit(self, check: _Check) -> _Slot | Failed:
        """Wait for a slot on the check's key, at most the rest of the check's queue
        allowance (R6.3). Returns the slot once it is held, or the reason the call can't be
        made; a refused call is never sent."""
        started = self._clock()
        check.queue_deadline = started + max(0.0, check.queue_allowance - check.timing.queue_wait_s)
        try:
            try:
                admitted = await self._wait_for_slot(check)
            except BaseException:
                self._refund_quota(check)  # cancelled while queued: nothing was sent
                raise
            if isinstance(admitted, Failed):
                self._refund_quota(check)  # refused: nothing was sent
            return admitted
        finally:
            check.timing.queue_wait_s += self._clock() - started

    async def _wait_for_slot(self, check: _Check) -> _Slot | Failed:
        key_id = check.key_id
        state = self._keys.setdefault(key_id, _KeyState())
        rule = self._admission
        rate = self._rate

        if (refusal := self._breaker_refusal(check)) is not None:
            self._queue_moved(key_id, state)  # drops the entry if it was just created
            return refusal  # a retry after the breaker opened: no slot, no queue
        if rate is not None and (capped := rate.cap_refusal()) is not None:
            # The daily request count or the monthly spend is used up (M3-10): no wait helps.
            self._queue_moved(key_id, state)
            return self._token_refusal(check, capped.message, capped.retry_after_s, capped.cause)
        if (over_share := self._charge_quota(check)) is not None:
            # M3-07, M3-08: the tenant's share or the consumer's allowance is spent. Refused
            # before queueing, so a noisy tenant's excess never takes a place in the line.
            self._queue_moved(key_id, state)
            return over_share
        if check.probe:
            # While the breaker is open nothing else is sent on the key, so the probe
            # doesn't queue. If the slots are still held (calls from before the breaker
            # opened, or orphans), it fails at once like any check that can't fit.
            load = self._load(key_id, state)
            if rule.can_start(load):
                started = self._start(check, state)
                if not isinstance(started, float):
                    return started
                self._queue_moved(key_id, state)
                return self._token_refusal(
                    check,
                    f"no tokens in the project's bucket for the breaker probe on key {key_id!r}",
                    started,
                    CAUSE_BUCKET,
                )
            self._queue_moved(key_id, state)
            return self._admission_failed(
                check,
                REASON_ADMISSION_WAIT,
                f"no free slot on key {key_id!r} for the breaker probe",
                rule.predicted_wait_s(load, ahead=0, expected_call_s=check.expected_latency),
            )
        if (full := self._group_room(check, state)) is not None:
            return full  # the whole group or none of it
        if not state.waiters and self._can_start(check, state, self._load(key_id, state)):
            started = self._start(check, state)
            if not isinstance(started, float):
                return started
            # A slot is free but the bucket lacks the tokens: queue for them.
        quota = self._quota
        if (full := self._make_room(check, state)) is not None:
            return full

        waiter = _Waiter(
            check.expected_latency,
            check.rate_tokens,
            check.priority,
            check.tenant_id,
            check.non_production,
        )
        if rate is None and quota is None:
            state.waiters.append(waiter)
        else:
            # M3-10: input and output before plan and tool_call, before tool_result; M3-08:
            # non-production behind all of them. Within a class, M3-07's weighted fair order
            # across tenants (virtual start time), first come first served at equal start.
            # Whoever is now behind the newcomer re-checks.
            if quota is not None:
                tail = max(
                    (
                        w.finish
                        for w in state.waiters
                        if w.tenant_id == waiter.tenant_id and w.priority == waiter.priority
                    ),
                    default=0.0,
                )
                group = check.group
                if group is not None and group.tag is not None:
                    # M3-09: the chunks of one check are one place in the fair queue: they share
                    # the group's start and finish, never one behind the other.
                    waiter.start, waiter.finish = group.tag
                else:
                    waiter.start, waiter.finish = state.fair.tag(
                        waiter.priority,
                        tail,
                        group.total_tokens if group is not None else check.api_tokens,
                        quota.config.limits_for(check.tenant_id, check.tier).weight,
                    )
                    if group is not None:
                        group.tag = (waiter.start, waiter.finish)
            position = len(state.waiters)
            while position > 0 and (
                (state.waiters[position - 1].priority, state.waiters[position - 1].start)
                > (waiter.priority, waiter.start)
            ):
                position -= 1
            state.waiters.insert(position, waiter)
            if position < len(state.waiters) - 1:
                self._queue_moved(key_id, state)
        timer: asyncio.Future[None] | None = None
        timer_ends = ""  # what running out at ``timer`` means: "budget" or "queue allowance"
        next_start_at = getattr(rule, "next_start_at", None)  # optional
        try:
            while True:
                if (refusal := self._breaker_refusal(check)) is not None:
                    return refusal
                if rate is not None and (capped := rate.cap_refusal()) is not None:
                    return self._token_refusal(
                        check, capped.message, capped.retry_after_s, capped.cause
                    )
                if waiter.evicted is not None:
                    return self._admission_failed(
                        check,
                        REASON_ADMISSION_QUEUE_FULL,
                        waiter.evicted,
                        rule.predicted_wait_s(
                            self._load(key_id, state, tuple(state.waiters)),
                            ahead=len(state.waiters),
                            expected_call_s=check.expected_latency,
                        ),
                    )
                ahead = state.waiters.index(waiter)
                ahead_waiters = tuple(state.waiters)[:ahead]
                load = self._load(key_id, state, ahead_waiters)
                remaining = check.deadline - load.now
                queue_left = check.queue_deadline - load.now
                token_wait = 0.0
                if rate is not None:
                    token_wait = rate.predicted_wait_s(
                        check.rate_tokens,
                        ahead_tokens=sum(w.tokens for w in ahead_waiters),
                        now=load.now,
                    )
                if ahead == 0 and self._can_start(check, state, load):
                    if check.expected_latency > remaining:
                        return self._admission_failed(
                            check,
                            REASON_ADMISSION_WAIT,
                            f"a slot on key {key_id!r} came free with "
                            f"{remaining * 1000:.0f} ms of budget left, under the expected "
                            f"call {check.expected_latency * 1000:.0f} ms; model not called",
                            0.0,
                        )
                    started = self._start(check, state)
                    if not isinstance(started, float):
                        if isinstance(started, _Slot):
                            state.waiters.remove(waiter)
                            state.fair.served(waiter.priority, waiter.start)
                        return started
                    token_wait = max(token_wait, started)  # another gateway took the tokens
                    rule_wait = 0.0
                else:
                    rule_wait = rule.predicted_wait_s(
                        load, ahead=ahead, expected_call_s=check.expected_latency
                    )
                    if check.non_production:
                        rule_wait = max(rule_wait, self._non_production_slot_wait(state, load))
                wait = max(rule_wait, token_wait)
                # The refusal names the limit that is the longer wait.
                by_tokens = token_wait > rule_wait
                what = "token-rate wait" if by_tokens else "queue wait"

                if timer is not None and timer.done():
                    # The latest moment the expected call could still fit, or the end of
                    # the queue allowance, has passed.
                    if not timer.cancelled() and (timer_exc := timer.exception()) is not None:
                        raise timer_exc  # a broken injected sleep
                    return self._refuse_wait(
                        check,
                        by_tokens,
                        wait,
                        f"{timer_ends} ran out while queued for key {key_id!r}; model not called",
                    )
                if wait + check.expected_latency > remaining:
                    return self._refuse_wait(
                        check,
                        by_tokens,
                        wait,
                        f"predicted {what} {wait * 1000:.0f} ms + expected call "
                        f"{check.expected_latency * 1000:.0f} ms exceeds the remaining budget "
                        f"{remaining * 1000:.0f} ms ({ahead} queued ahead, "
                        f"{load.in_flight} in flight on key {key_id!r}); model not called",
                    )
                if wait > queue_left:
                    return self._refuse_wait(
                        check,
                        by_tokens,
                        wait,
                        f"predicted {what} {wait * 1000:.0f} ms exceeds the remaining "
                        f"queue allowance {max(0.0, queue_left) * 1000:.0f} ms ({ahead} queued "
                        f"ahead, {load.in_flight} in flight on key {key_id!r}); "
                        "model not called",
                    )
                waiter.wake = asyncio.get_running_loop().create_future()
                if timer is None:
                    fits_until = remaining - check.expected_latency
                    # When both run out together, the budget is named: it is the binding one.
                    timer_ends = "budget" if fits_until <= queue_left else "queue allowance"
                    timer = asyncio.ensure_future(
                        self._sleep(max(0.0, min(fits_until, queue_left)))
                    )
                wakers: set[asyncio.Future[Any]] = {waiter.wake, timer}
                capacity_at = next_start_at(load) if next_start_at is not None else None
                if ahead == 0 and token_wait > 0:
                    # The bucket refills with time alone: wake when it holds the tokens.
                    refill_at = load.now + token_wait
                    capacity_at = refill_at if capacity_at is None else min(capacity_at, refill_at)
                capacity_timer = None
                if capacity_at is not None and capacity_at > load.now:
                    # The rule's capacity comes back with time alone: wake then to re-check.
                    capacity_timer = asyncio.ensure_future(self._sleep(capacity_at - load.now))
                    wakers.add(capacity_timer)
                try:
                    await asyncio.wait(wakers, return_when=asyncio.FIRST_COMPLETED)
                finally:
                    if capacity_timer is not None:
                        self._release(capacity_timer)
        finally:
            if timer is not None:
                self._release(timer)
            if waiter.wake is not None and not waiter.wake.done():
                waiter.wake.cancel()
            if waiter in state.waiters:
                state.waiters.remove(waiter)
            self._queue_moved(key_id, state)

    def _can_start(self, check: _Check, state: _KeyState, load: KeyLoad) -> bool:
        """The rule allows a start now and, for a non-production call, it would not take more
        than its share of the key's slots (production always has the rest)."""
        if not self._admission.can_start(load):
            return False
        if not check.non_production or check.probe:
            return True
        held = sum(slot.non_production for slot in state.slots)
        return held < non_production_slot_limit(self._config.max_in_flight_per_key)

    def _non_production_slot_wait(self, state: _KeyState, load: KeyLoad) -> float:
        """How long until a non-production call would be under its share of the slots: the
        soonest a non-production call in flight is expected to end, or ``inf`` if only
        orphans hold them. 0 while it is under its share."""
        held = [slot for slot in state.slots if slot.non_production]
        if len(held) < non_production_slot_limit(self._config.max_in_flight_per_key):
            return 0.0
        live = [slot for slot in held if not slot.orphan]
        if not live:
            return float("inf")
        floor = InFlightLimit.REMAINING_FLOOR
        return min(
            max(slot.expected_s - (load.now - slot.started_at), floor * slot.expected_s)
            for slot in live
        )

    def _queue_full(self, check: _Check, state: _KeyState, message: str) -> Failed:
        """Refuse a newcomer: the queue has no place for it. The hint is the predicted wait
        at the back of the queue."""
        ahead = tuple(state.waiters)
        return self._admission_failed(
            check,
            REASON_ADMISSION_QUEUE_FULL,
            message,
            self._admission.predicted_wait_s(
                self._load(check.key_id, state, ahead),
                ahead=len(ahead),
                expected_call_s=check.expected_latency,
            ),
        )

    def _make_room(self, check: _Check, state: _KeyState) -> Failed | None:
        """Decide whether the newcomer gets a place in the key's queue, pushing another
        waiter out if that is the fair thing to do. None: it may queue. Otherwise the refusal
        (``admission_queue_full``); nothing is sent.

        * **Non-production**: at most a quarter of the queue, all consumers together
          (at least one place). It never pushes anyone out.
        * **Production, queue full**: the **most recent non-production waiter** is pushed out;
          failing that, with quotas on, the **most recent waiter of the tenant
          holding the most places** when the newcomer's tenant holds fewer. Else the
          newcomer is refused: it is itself the largest holder.
        * **Production, room left** (quotas on): a tenant may hold at most
          ``max_queued_per_key / (tenants with queued work + 1)`` places, at least one, and at
          most the configured fraction. Non-production waiters aren't counted: a
          tenant's tests never take from its production places.
        """
        refusal, victim, why = self._room_plan(check, state.waiters)
        if refusal is not None:
            return self._queue_full(check, state, refusal)
        if victim is not None:
            self._push_out(
                victim,
                state,
                f"pushed out of key {check.key_id!r}'s queue {why}; model not called",
            )
        return None

    def _group_room(self, check: _Check, state: _KeyState) -> Failed | None:
        """A chunk group's places in the key's queue, decided once, at its first chunk
        to arrive, for the whole group: if a later chunk would be refused ``admission_queue_full``
        (the tenant's share of the queue, the key's limit), **no chunk is sent**; every chunk is
        refused with the same message, never some sent and the rest refused (one chunk may be
        refused only because of a different tenant's arrival in between: that is the same
        refusal an unchunked call would get). The places are worked out as the chunks will take
        them, one after another, pushing out the same waiters :meth:`_make_room` would; nothing
        is pushed out or queued here. A first chunk that can start at once takes no place."""
        group = check.group
        if group is None or check.probe:
            return None
        if not group.room_checked:
            group.room_checked = True
            waiters = list(state.waiters)
            starts_now = not waiters and self._can_start(
                check, state, self._load(check.key_id, state)
            )
            for index in range(len(group.tokens)):
                if index == 0 and starts_now:
                    continue
                refusal, victim, _ = self._room_plan(check, waiters)
                if refusal is not None:
                    group.room_refusal = refusal
                    break
                if victim is not None:
                    waiters.remove(victim)
                waiters.append(
                    _Waiter(
                        check.expected_latency,
                        0,
                        check.priority,
                        check.tenant_id,
                        check.non_production,
                    )
                )
        if group.room_refusal is None:
            return None
        return self._queue_full(
            check, state, f"{group.room_refusal}; the check's {len(group.tokens)} chunks not sent"
        )

    def _room_plan(
        self, check: _Check, waiters: Sequence[_Waiter]
    ) -> tuple[str | None, _Waiter | None, str]:
        """What :meth:`_make_room` does with a newcomer on a queue of ``waiters``, without doing
        it: (the refusal message, None), (None, the waiter to push out and why), or (None, None)
        when it simply queues."""
        limit = self._config.max_queued_per_key
        key_id = check.key_id
        if check.non_production:
            held_np = sum(w.non_production for w in waiters)
            np_limit = non_production_queue_limit(limit)
            if held_np >= np_limit:
                return (
                    f"{held_np} non-production calls already queued for key {key_id!r} "
                    f"(their share of the queue is {np_limit}); model not called",
                    None,
                    "",
                )
            if len(waiters) >= limit:
                return (
                    f"{len(waiters)} calls already queued for key {key_id!r} "
                    f"(limit {limit}); non-production calls never push another out; "
                    "model not called",
                    None,
                    "",
                )
            return None, None, ""
        counts: dict[str, int] = {}
        for w in waiters:
            if not w.non_production:  # waiters, not places: a group of n chunks counts n
                counts[w.tenant_id] = counts.get(w.tenant_id, 0) + 1
        held = counts.get(check.tenant_id, 0)
        quota = self._quota
        if len(waiters) >= limit:
            victim = next((w for w in reversed(waiters) if w.non_production), None)
            why = "to make room for a production check"
            if victim is None and quota is not None:
                victim = self._largest_holders_last(check, waiters, counts, held)
                why = "to make room for a tenant with fewer calls queued"
            if victim is None:
                return (
                    f"{len(waiters)} calls already queued for key {key_id!r} "
                    f"(limit {limit}); model not called",
                    None,
                    "",
                )
            return None, victim, why
        if quota is not None:
            cap = quota.config.queue_limit(limit, len(counts))
            if held >= cap:
                return (
                    f"{held} of the tenant's calls already queued for key {key_id!r} "
                    f"(its share of the queue is {cap}); model not called",
                    None,
                    "",
                )
        return None, None, ""

    @staticmethod
    def _largest_holders_last(
        check: _Check, waiters: Sequence[_Waiter], counts: dict[str, int], held: int
    ) -> _Waiter | None:
        """The latest waiter, in the newcomer's class or a lower one, of the tenant that holds
        the most places, if that tenant holds more than the newcomer's tenant (ties go to the
        tenant whose last waiter is latest in line)."""
        last: dict[str, tuple[int, _Waiter]] = {}
        for i, w in enumerate(waiters):
            if (
                not w.non_production
                and w.priority >= check.priority
                and w.tenant_id != check.tenant_id
            ):
                last[w.tenant_id] = (i, w)
        bigger = [t for t in last if counts[t] > held]
        if not bigger:
            return None
        tenant = max(bigger, key=lambda t: (counts[t], last[t][0]))
        return last[tenant][1]

    @staticmethod
    def _push_out(victim: _Waiter, state: _KeyState, message: str) -> None:
        """Take a waiter out of the queue now, so the newcomer takes its place; the waiter
        wakes and fails ``admission_queue_full``."""
        state.waiters.remove(victim)
        victim.evicted = message
        if victim.wake is not None and not victim.wake.done():
            victim.wake.set_result(None)

    def _start(self, check: _Check, state: _KeyState) -> _Slot | Failed | float:
        """The key's rule says a slot is free: take it, with the call's token reservation
        (M3-10) when a limiter is on. Nothing awaits between the reservation and the slot.
        Returns the slot, the refusal if a cap is reached, or (when the bucket lacks the
        tokens) the seconds until it holds them, with no slot taken."""
        if (daily := self._daily_refusal(check)) is not None:
            return daily
        rate = self._rate
        if rate is None:
            return self._take_slot(check, state)
        reserved = rate.reserve(check.rate_tokens, now=self._clock())
        if isinstance(reserved, CapRefusal):
            return self._token_refusal(
                check, reserved.message, reserved.retry_after_s, reserved.cause
            )
        if isinstance(reserved, float):
            return reserved
        return self._take_slot(check, state, reserved)

    def _refuse_wait(self, check: _Check, by_tokens: bool, wait: float, message: str) -> Failed:
        """A queued call that can't be served in time: ``token_rate`` when the bucket is the
        longer wait, else ``admission_wait``."""
        if by_tokens:
            return self._token_refusal(check, f"token_rate: {message}", wait, CAUSE_BUCKET)
        return self._admission_failed(check, REASON_ADMISSION_WAIT, message, wait)

    def _token_refusal(
        self,
        check: _Check,
        message: str,
        wait_s: float | None,
        cause: str | None,
        *,
        exhausted: bool = False,
        limit: str = "",
    ) -> Failed:
        """A ``token_rate`` refusal by the bucket, or a ``quota_exhausted`` one by the daily
        count or the monthly spend: ``wait_s`` is the time until the limit lets the call
        through, for the R8 hint. ``exhausted`` marks a consumer's daily or monthly allowance
        (its cause is ``consumer_allowance`` for all four); ``limit`` names the allowance."""
        check.refusal_cause = cause or CAUSE_BUCKET
        check.refusal_limit = limit
        reason = (
            REASON_QUOTA_EXHAUSTED
            if exhausted or check.refusal_cause in QUOTA_REASON_CAUSES
            else REASON_TOKEN_RATE
        )
        return self._admission_failed(check, reason, message, wait_s)

    def _release(self, timer: asyncio.Future[Any]) -> None:
        """Stop a sleep the gateway no longer needs, without waiting for it."""
        if timer.done():
            _consume(timer)
            return
        timer.cancel()
        self._timers.add(timer)
        timer.add_done_callback(self._timer_done)

    def _timer_done(self, timer: asyncio.Future[Any]) -> None:
        self._timers.discard(timer)
        _consume(timer)

    # ------------------------------------------------------------------ token rate (M3-10)

    def _note_reservation(self, check: _Check, reservation: Reservation) -> None:
        meter = self._meter
        if isinstance(meter, TokenRateMeter) and self._rate is not None:
            self._enqueue(
                "usage meter",
                meter.record_token_reservation,
                self._rate.project_id,
                reservation.tokens,
            )
        self._crossed(check, reservation.crossings)

    def _settle(self, check: _Check, actual_tokens: int | None) -> None:
        """Reconcile the call's token reservation with the provider's usage (M3-10). ``None``
        keeps it (usage unknown); ``0`` for a call that was never sent returns it whole."""
        self._settle_quota(check, actual_tokens)
        reservation, check.reservation = check.reservation, None
        rate = self._rate
        if rate is None or reservation is None:
            return
        meter = self._meter
        if isinstance(meter, TokenRateMeter) and actual_tokens != 0:
            self._enqueue(
                "usage meter",
                meter.record_token_actual,
                rate.project_id,
                reservation.tokens,
                actual_tokens,
            )
        self._crossed(check, rate.reconcile(reservation, actual_tokens, now=self._clock()))
        if actual_tokens is not None and actual_tokens < reservation.tokens:
            key = self._keys.get(check.key_id)
            if key is not None:
                self._queue_moved(check.key_id, key)  # tokens came back: waiters re-check

    def _crossed(self, check: _Check, crossings: tuple[Crossing, ...]) -> None:
        """80% (warning) and 100% (page) of the daily count or the monthly spend."""
        for crossing in crossings:
            daily = crossing.cause == CAUSE_DAILY_REQUESTS
            percent = round(crossing.threshold * 100)
            what = (
                f"{crossing.used:.0f} of {crossing.limit:.0f} requests today (Pacific)"
                if daily
                else f"${crossing.used:.2f} of ${crossing.limit:.2f} this month (Pacific)"
            )
            self._emit(
                Alert(
                    severity=AlertSeverity.PAGE if percent >= 100 else AlertSeverity.WARNING,
                    kind=ALERT_DAILY_REQUESTS if daily else ALERT_MONTHLY_SPEND,
                    message=(
                        f"project {self._project_id()!r} has used {percent}% of its "
                        f"{'daily request cap' if daily else 'monthly spend cap'}: {what}"
                        + ("; checks fail fast as quota_exhausted" if percent >= 100 else "")
                        + ". Counted since this process started: the counters restart at zero "
                        "after a restart, so check Google's usage and billing for the true figure"
                    ),
                    key_id=check.key_id,
                    tenant_id=check.tenant_id,
                    guard_point=check.guard_point,
                    reason=f"threshold_{percent}",
                    count=int(crossing.used),
                )
            )

    def _project_id(self) -> str:
        return "" if self._rate is None else self._rate.project_id

    def _token_rate_fail_fast(self, check: _Check) -> None:
        """A check failed fast with ``token_rate`` and no provider call."""
        if check.refusal_cause in QUOTA_CAUSES:
            self._quota_refusal(check)  # a tenant's or consumer's share, not the project's
            return
        rate = self._rate
        if rate is None:
            return
        now = self._clock()
        rate.window.note_fail_fast(now)
        meter = self._meter
        if isinstance(meter, TokenRateMeter):
            self._enqueue(
                "usage meter",
                meter.record_token_rate_fail_fast,
                rate.project_id,
                check.tenant_id,
                check.guard_point,
                check.refusal_cause or CAUSE_BUCKET,
            )
        self._check_fail_fast_window(check, now)

    def _check_fail_fast_window(self, check: _Check, now: float) -> None:
        """One alert when ``token_rate`` fail-fasts pass 0.1% of checks in the last 5
        minutes; it re-arms when they fall back under."""
        rate = self._rate
        if rate is None:
            return
        window = rate.window
        if not window.exceeded(now):
            window.alerting = False
            return
        if window.alerting:
            return
        window.alerting = True
        checks, fails = window.totals(now)
        self._emit(
            Alert(
                severity=AlertSeverity.WARNING,
                kind=ALERT_TOKEN_RATE_FAIL_FAST,
                message=(
                    f"project {rate.project_id!r}: {fails} of {checks} checks in the last "
                    f"{window.window_s / 60:g} minutes failed fast as token_rate "
                    f"(more than {window.rate:.1%}); the project is at its token-rate limit"
                ),
                key_id=check.key_id,
                tenant_id=check.tenant_id,
                guard_point=check.guard_point,
                reason=check.refusal_cause or CAUSE_BUCKET,
                count=fails,
            )
        )

    # ------------------------------------------------------- tenant quotas (M3-07, M3-08)

    def _charge_quota(self, check: _Check) -> Failed | None:
        """Charge the check's first call to its tenant's share, or its consumer's allowance;
        the refusal if that is spent. The retry and a breaker probe are never charged."""
        charger = self._charger
        if charger is None or check.charged or check.probe:
            return None
        check.charged = True
        if check.group is not None:
            charged = self._group_charge(check, charger)
        else:
            charged = charger.charge(
                tenant_id=check.tenant_id,
                tier=check.tier,
                consumer=check.consumer,
                tokens=check.api_tokens,
                now=self._clock(),
            )
        if isinstance(charged, QuotaRefusal):
            return self._token_refusal(
                check,
                charged.message,
                charged.retry_after_s,
                charged.cause,
                exhausted=charged.exhausted,
                limit=charged.limit,
            )
        check.charge = charged
        return None

    def _group_charge(
        self, check: _Check, charger: QuotaLimiter | ConsumerAllowances
    ) -> QuotaCharge | QuotaRefusal:
        """The chunk's charge, taking the whole group's on the first call (all or none): every
        chunk's tokens go to the tenant in one synchronous step, and if any can't be taken, what
        was taken is given back and every chunk gets the same refusal (M3-09)."""
        group = check.group
        assert group is not None
        if not group.attempted:
            group.attempted = True
            now = self._clock()
            taken: list[QuotaCharge] = []
            try:
                for tokens in group.tokens:
                    charged = charger.charge(
                        tenant_id=check.tenant_id,
                        tier=check.tier,
                        consumer=check.consumer,
                        tokens=tokens,
                        now=now,
                    )
                    if isinstance(charged, QuotaRefusal):
                        group.refusal = charged
                        break
                    taken.append(charged)
            except Exception:  # a store that fails mid-group: nothing is kept
                logger.exception("a chunk group's quota charge failed")
                group.refusal = QuotaRefusal(
                    CAUSE_TENANT_TOKENS,
                    FALLBACK_RETRY_AFTER_MS / 1000,
                    "token_rate: the tenant's share could not be charged; model not called",
                )
            if group.refusal is not None:
                for done in taken:  # give back what was taken, each on its own
                    try:
                        charger.refund(done, now=now)
                    except Exception:
                        logger.exception("a chunk group's quota refund failed")
            else:
                group.charges = taken
        if group.refusal is not None:
            return group.refusal
        return group.charges[check.group_index]

    def check_group(self, inputs: Sequence[str], questions: Mapping[str, Question]) -> CheckGroup:
        """The group of one check's chunk calls (``inputs``, one per chunk, all with the same
        ``questions``), to pass to :meth:`decide_timed` as ``group`` with each chunk's index.
        Its tokens are the same estimates the calls charge on their own."""
        return CheckGroup(tuple(self.estimate_call_tokens(text, questions) for text in inputs))

    def estimate_call_tokens(self, input: str, questions: Mapping[str, Question]) -> int:
        """The API tokens a call of ``input`` with ``questions`` charges (R6.6)."""
        input_tokens = estimate_tokens(input)
        rate_tokens = self._rate.estimate(input_tokens, questions) if self._rate is not None else 0
        return rate_tokens or max(
            1,
            estimate_api_tokens(
                text_tokens=input_tokens,
                question_tokens=estimate_question_tokens(questions),
                question_count=len(questions),
            ),
        )

    def _daily_refusal(self, check: _Check) -> Failed | None:
        """The tenant's daily share (or the consumer's) ran out while the call was queued
        (checked again as it takes its slot, so a queue can't carry a tenant or a consumer
        past its share)."""
        charger, charge = self._charger, check.charge
        if charger is None or charge is None or charge.counted:
            return None
        if charge.consumer != USAGE_PRODUCTION:
            allowances = charger.allowances if isinstance(charger, QuotaLimiter) else charger
            refused = allowances.daily_refusal(charge.consumer)
        elif isinstance(charger, QuotaLimiter) and charge.quota is not None:
            refused = charger.daily_refusal(check.tenant_id, check.tier)
        else:
            return None
        if refused is None:
            return None
        return self._token_refusal(
            check,
            refused.message,
            refused.retry_after_s,
            refused.cause,
            exhausted=refused.exhausted,
            limit=refused.limit,
        )

    def _refund_quota(self, check: _Check) -> None:
        """The call was never sent: give back what the check took from its share."""
        charge, check.charge = check.charge, None
        if self._charger is not None and charge is not None:
            self._charger.refund(charge, now=self._clock())

    def _settle_quota(self, check: _Check, actual_tokens: int | None) -> None:
        """The first call is over: ``0`` means it was never sent (give the share back), a
        number corrects the tokens taken, and ``None`` (usage unknown) keeps them."""
        if actual_tokens == 0:
            self._refund_quota(check)
            return
        charge, check.charge = check.charge, None
        if self._charger is not None and charge is not None and actual_tokens is not None:
            self._charger.reconcile(charge, actual_tokens, now=self._clock())

    def _quota_sent(self, check: _Check) -> None:
        """The first call was sent: count it against the tenant's daily share and meter its
        usage (the tenant's, or the non-production consumer's)."""
        quota, charge = self._charger, check.charge
        if quota is None or charge is None:
            return
        crossings = quota.count_sent(charge)
        meter = self._meter
        if isinstance(meter, QuotaMeter):
            if charge.consumer == USAGE_PRODUCTION:
                if charge.quota is not None:
                    self._enqueue(
                        "usage meter",
                        meter.record_tenant_usage,
                        quota.project_id,
                        check.tenant_id,
                        charge.tier,
                        charge.tokens,
                        charge.quota.tokens_per_minute,
                    )
            else:
                self._enqueue(
                    "usage meter",
                    meter.record_consumer_usage,
                    quota.project_id,
                    charge.consumer,
                    charge.tokens or check.api_tokens,
                )
        for crossing in crossings:
            self._tenant_crossed(check, crossing)

    def _tenant_crossed(self, check: _Check, crossing: QuotaCrossing) -> None:
        """80% and 100% of a tenant's daily share: a warning for the tenant's admins."""
        percent = round(crossing.threshold * 100)
        ends = "; its checks fail fast as quota_exhausted until midnight Pacific"
        self._emit(
            Alert(
                severity=AlertSeverity.WARNING,
                kind=ALERT_TENANT_DAILY_QUOTA,
                message=(
                    f"the tenant has used {percent}% of its daily share: {crossing.used} of "
                    f"{crossing.limit} requests today (Pacific)"
                    + (ends if percent >= 100 else "")
                    + ". Other tenants are not affected. Counted since the engine started "
                    "unless the project's store is shared"
                ),
                key_id=check.key_id,
                tenant_id=check.tenant_id,
                guard_point=check.guard_point,
                reason=f"threshold_{percent}",
                count=crossing.used,
            )
        )

    def _quota_refusal(self, check: _Check) -> None:
        """A check was refused for its tenant's share or its consumer's allowance, with no
        provider call: meter it per tenant (or per consumer) and warn, throttled."""
        charger, quota = self._charger, self._quota
        cause = check.refusal_cause or ""
        if charger is None:
            return
        meter = self._meter
        if check.consumer != USAGE_PRODUCTION:
            if isinstance(meter, QuotaMeter):
                self._enqueue(
                    "usage meter",
                    meter.record_consumer_refusal,
                    charger.project_id,
                    check.consumer,
                    check.guard_point,
                )
            limit = check.refusal_limit or ALLOWANCE_TOKENS
            if self._throttled(
                (ALERT_CONSUMER_ALLOWANCE, check.consumer, check.guard_point, limit)
            ):
                over = _ALLOWANCE_NAMES.get(limit, limit)
                refused_as = (
                    "quota_exhausted"
                    if limit in (ALLOWANCE_REQUESTS_PER_DAY, ALLOWANCE_MONTHLY_SPEND)
                    else "token_rate"
                )
                self._emit(
                    Alert(
                        severity=AlertSeverity.WARNING,
                        kind=ALERT_CONSUMER_ALLOWANCE,
                        message=(
                            f"non-production consumer {check.consumer!r} has spent its "
                            f"allowance of the project's {over}; its calls are refused "
                            f"({refused_as}) until it refills or rolls. Production is not "
                            "affected"
                        ),
                        key_id=check.key_id,
                        tenant_id=check.tenant_id,
                        guard_point=check.guard_point,
                        reason=CAUSE_CONSUMER,
                    )
                )
            return
        if quota is None:
            return
        if isinstance(meter, QuotaMeter):
            self._enqueue(
                "usage meter",
                meter.record_tenant_refusal,
                quota.project_id,
                check.tenant_id,
                check.tier or quota.config.default_tier,
                check.guard_point,
                cause,
            )
        refused_as = "quota_exhausted" if cause in DAILY_CAUSES else "token_rate"
        self._warn(
            ALERT_TENANT_QUOTA,
            f"the tenant is over its share ({cause}); its checks are refused ({refused_as}) "
            "until it refills. Other tenants are not affected",
            check,
            reason=cause,
        )

    # ------------------------------------------------------------------ metering and alerts

    def _record_usage(self, result: Answered, check: _Check) -> None:
        tokens = None if result.usage is None else result.usage.total_input_tokens
        if self._meter is not None:
            record = self._meter.record
            self._enqueue("usage meter", record, check.tenant_id, check.metered_guard_point, tokens)
        if tokens is None:
            self._warn(
                ALERT_USAGE_UNKNOWN,
                "answered call had no usable usage; counted as unknown",
                check,
                reason=result.usage_problem,
            )

    def _record_unanswered(self, check: _Check) -> None:
        meter = self._meter
        if meter is not None:
            self._enqueue(
                "usage meter",
                lambda: meter.record_unanswered(check.tenant_id, check.metered_guard_point),
            )

    def _record_provider_safety(self, check: _Check) -> None:
        """M1-13: a provider refusal counts in its own per-tenant metric only."""
        meter = self._meter
        if isinstance(meter, ProviderSafetyMeter):
            self._enqueue(
                "usage meter",
                meter.record_provider_safety,
                check.tenant_id,
                check.metered_guard_point,
            )

    def _record_unrecognised(self, code: str, check: _Check) -> None:
        """M1-13, M1-15: a 400 code the adapter didn't recognise. Counted on **every**
        occurrence by a bounded label; the warning log line is throttled per tenant, guard
        point and label, at most one per ``warning_interval_s``, and says how many were
        suppressed since the last one. Never the provider's message or the input."""
        # ``Failed`` bounds it already; the gateway doesn't rely on that. Idempotent on a
        # bounded label, so nothing moves to another bucket here.
        label = bounded_error_label(code) or ERROR_LABEL_MALFORMED
        if label not in ERROR_LABEL_PLACEHOLDERS and label not in self._unrecognised_labels:
            # Only provider codes take places under the cap; the placeholders always pass.
            if len(self._unrecognised_labels) >= MAX_UNRECOGNISED_CODE_LABELS:
                label = UNRECOGNISED_CODE_OVERFLOW
            else:
                self._unrecognised_labels.add(label)
        meter = self._meter
        if isinstance(meter, ProviderErrorMeter):
            self._enqueue(
                "usage meter",
                meter.record_provider_error_unrecognised,
                check.tenant_id,
                check.metered_guard_point,
                label,
            )
        count = self._throttled((LOG_UNRECOGNISED, check.tenant_id, check.guard_point, label))
        if count is None:
            return
        logger.warning(
            "provider_error_unrecognised code=%s tenant=%s guard_point=%s suppressed=%d",
            label,
            check.tenant_id,
            check.guard_point,
            count - 1,  # suppressed since the previous line for this label
        )

    def identifier_scan_sharded(self) -> None:
        """The cross-tenant scan couldn't build one combined set and matches over
        shards. A warning in fixed wording, throttled. Never raises."""
        if self._throttled((ALERT_XTENANT_SCAN_SHARDED,)) is None:
            return
        self._emit(
            Alert(
                severity=AlertSeverity.WARNING,
                kind=ALERT_XTENANT_SCAN_SHARDED,
                message=(
                    "the cross-tenant identifier patterns did not fit one compiled set; "
                    "the scan now matches over several, at a higher cost per check"
                ),
                key_id="",
                tenant_id="",
                guard_point="",
            )
        )

    def model_skipped(self, tenant_id: str, guard_point: str) -> None:
        """M3-03: a tool's ``skip_model`` applied to a check (its tenant and pack questions
        were skipped). Counted on a meter that implements ``SkippedChecksMeter``. Never
        raises."""
        meter = self._meter
        if isinstance(meter, SkippedChecksMeter):
            self._enqueue("usage meter", meter.record_model_skipped, tenant_id, guard_point)

    def identifier_patterns_dropped(self, tenant_id: str) -> None:
        """A tenant's cross-tenant identifier patterns were dropped from the scan.
        Counted on every occurrence on a meter that implements ``IdentifierScanMeter``, and
        raised as a warning (fixed wording, throttled per tenant). Never raises."""
        meter = self._meter
        if isinstance(meter, IdentifierScanMeter):
            self._enqueue("usage meter", meter.record_identifier_patterns_dropped, tenant_id)
        if self._throttled((ALERT_XTENANT_PATTERNS_DROPPED, tenant_id)) is None:
            return
        self._emit(
            Alert(
                severity=AlertSeverity.WARNING,
                kind=ALERT_XTENANT_PATTERNS_DROPPED,
                message=(
                    "identifier patterns of a tenant did not compile and are left out of "
                    "the cross-tenant scan; other tenants are not affected"
                ),
                key_id="",
                tenant_id=tenant_id,
                guard_point="",
            )
        )

    def _on_auth_failure(self, result: Failed, check: _Check) -> None:
        try:
            current_key_id = self._key_id()
        except Exception:
            current_key_id = check.key_id  # can't tell; treat the key as still current
        if check.key_id != current_key_id:
            # The key was replaced while this call was in flight, which is when an old key
            # gets revoked. Nothing is sent on it any more: no breaker, no page.
            logger.info(
                "auth failure on replaced key %r ignored (tenant=%s guard_point=%s reason=%s)",
                check.key_id,
                check.tenant_id,
                check.guard_point,
                result.reason,
            )
            return
        if check.key_id in self._open:
            # A failed probe, or a call that was in flight when the breaker opened. On-call
            # has been paged for this key already, and the next probe is already scheduled.
            return
        delay = self._config.probe_initial_delay_s
        self._open[check.key_id] = _OpenBreaker(
            next_probe_at=self._clock() + delay, delay=delay, reason=result.reason
        )
        self._emit(
            Alert(
                severity=AlertSeverity.PAGE,
                kind=ALERT_AUTH_FAILURE,
                message=(
                    f"decision model rejected key {check.key_id!r}; every check on it fails "
                    "(floor rules block) until the key is replaced"
                ),
                key_id=check.key_id,
                tenant_id=check.tenant_id,
                guard_point=check.guard_point,
                reason=result.reason,
            )
        )

    def _warn(self, kind: str, message: str, check: _Check, reason: str | None = None) -> None:
        """Raise a warning, at most one per kind, tenant and guard point per interval. The
        alert's ``count`` includes the occurrences suppressed since the previous one."""
        count = self._throttled((kind, check.tenant_id, check.guard_point))
        if count is None:
            return
        self._emit(
            Alert(
                severity=AlertSeverity.WARNING,
                kind=kind,
                message=message,
                key_id=check.key_id,
                tenant_id=check.tenant_id,
                guard_point=check.guard_point,
                reason=reason,
                count=count,
            )
        )

    def _throttled(self, key: tuple[str, ...]) -> int | None:
        """The gateway's one warning throttle: None while ``key`` is inside its interval
        (the occurrence is counted as suppressed); otherwise how many occurrences this one
        stands for, itself plus those suppressed since the previous one."""
        now = self._clock()
        throttle = self._throttles.get(key)
        if throttle is not None and now < throttle.next_at:
            throttle.suppressed += 1
            return None
        count = 1 + (throttle.suppressed if throttle is not None else 0)
        self._throttles[key] = _Throttle(next_at=now + self._config.warning_interval_s)
        return count

    def _emit(self, alert: Alert) -> None:
        if self._alerts is not None:
            self._enqueue(f"alert sink ({alert.kind})", self._alerts.emit, alert)

    # ------------------------------------------------------------------ sink handoff

    def _enqueue(self, name: str, fn: Callable[..., Any], *args: Any) -> None:
        """Hand one sink call to the drainer thread. Never blocks and never raises: when the
        queue is full the oldest event makes room and is counted as dropped."""
        with self._events_cond:
            if self._closed:
                self._dropped_events += 1
                return
            if len(self._events) >= self._config.sink_queue_size:
                self._events.popleft()
                self._dropped_events += 1
            self._events.append((name, fn, args))
            if self._drainer_alive:
                self._events_cond.notify()
                return
            self._drainer_alive = True
            try:
                threading.Thread(
                    target=self._drain_events, name="guardrail-event-drainer", daemon=True
                ).start()
            except RuntimeError:  # the interpreter could not start a thread
                self._drainer_alive = False
                self._dropped_events += len(self._events)
                self._events.clear()
                logger.exception("alert and metering drainer could not start")

    def _drain_events(self) -> None:
        """The drainer thread: deliver queued events one at a time, in order. It is a daemon
        thread: a sink that never returns cannot hold up interpreter exit. It waits for more
        events for ``_DRAINER_IDLE_S`` and then exits (``_enqueue`` starts a new one), so an
        idle gateway holds no thread. Taking one event at a time keeps every undelivered
        event but the one in hand in the bounded queue, where overflow and ``aclose()`` can
        see and count it."""
        while True:
            self._wake_idle_waiters()
            with self._events_cond:
                if not self._events:
                    timed_out = self._closed or not self._events_cond.wait(_DRAINER_IDLE_S)
                    if self._events:
                        pass  # an event arrived as the wait ended: deliver it
                    elif timed_out:
                        self._drainer_alive = False
                        return
                    else:
                        continue
                event = self._events.popleft()
                self._event_in_hand = True
            try:
                _deliver(event)
            finally:
                # Still "in hand" while the waiters are woken, so a caller that sees the
                # gateway idle also sees its drain future resolved.
                self._wake_idle_waiters()
                with self._events_cond:
                    self._event_in_hand = False

    def _wake_idle_waiters(self) -> None:
        """If nothing is queued, resolve the futures of the callers waiting in ``drain``."""
        with self._events_cond:
            if self._events:
                return
            waiters, self._idle_waiters = self._idle_waiters, []
        for loop, future in waiters:
            try:
                loop.call_soon_threadsafe(_resolve, future)
            except RuntimeError:  # the waiter's loop is already closed
                logger.debug("a drain waiter's event loop was closed")


def _resolve(future: asyncio.Future[None]) -> None:
    if not future.done():
        future.set_result(None)


_DRAINER_IDLE_S = 2.0
"""How long the drainer thread waits for another event before it exits."""

_Event = tuple[str, Callable[..., Any], tuple[Any, ...]]


def _deliver(event: _Event) -> None:
    """Runs in a worker thread. A sink that raises is logged and ignored. One that returns
    a coroutine broke the contract (see ``sinks.py``): it is closed, not run."""
    name, fn, args = event
    try:
        returned = fn(*args)
        if inspect.iscoroutine(returned):
            returned.close()
            logger.error("%s is async; sinks must be synchronous", name)
    except Exception:
        logger.exception("%s failed", name)


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _budget_exhausted() -> Failed:
    return Failed(kind=FailureKind.TIMEOUT, message="budget exhausted before the call")


def _consume(task: asyncio.Future[Any]) -> None:
    """Mark a finished task's outcome as seen, so asyncio does not log it as unretrieved."""
    if not task.cancelled():
        task.exception()
