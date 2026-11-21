"""M3-10: the per-project token-rate limiter, the daily request counter and the monthly
spend tracker.

A project's Gemini quota is per project, not per key (M0-03): 1,000,000 tokens a minute at
Tier 1, 50,000 requests a day, and a monthly spend cap on the billing account ($250). Hitting
the token limit gives project-wide 429s that affect every tenant at once, so the gateway
holds its own offered load below it.

* **Token bucket per project** (:class:`TokenRateStore`). It holds ``burst_capacity_s`` seconds
  of its refill rate and refills at ``tokens_per_minute x target_fraction / (60 +
  burst_capacity_s)`` tokens a second, so that a full bucket plus a full minute of refill is
  exactly ``tokens_per_minute x target_fraction``: **no minute ever carries more than the
  target**, burst included. (Refilling at target / 60 would let a minute that starts
  with a full bucket carry the target plus one burst, 73.7% of the quota at the defaults.)
  The target is the highest occupancy tested flat, 68% (R6.3), until a burst test at a higher
  level is recorded in ``burst_tested_at``. Each call **reserves** its
  estimated API tokens (R6.6, :func:`~guardrail_engine.policy.api_tokens.estimate_api_tokens`)
  when it is sent, and is **reconciled** with the provider's ``usage`` when it returns. A
  call whose usage is unknown (timeout, cancellation, provider refusal, an answer without
  usage) keeps its reservation: it may have been billed.
* **Daily request counter.** One count per provider call sent, rolling at **midnight
  America/Los_Angeles** (Google's quota resets then), not at UTC midnight. A Pacific day is 23
  or 25 hours long on the two daylight-saving changes.
* **Monthly spend.** Reserved tokens x price when a call is sent, corrected to actual tokens x
  price on return, rolling on the 1st of the month, Pacific. The cap is the billing account's.
* **Alerts** at 80% (warning) and 100% (page) of the daily count and of the monthly spend,
  once per crossing, and when ``token_rate`` fail-fasts exceed 0.1% of checks in the last 5
  minutes (:class:`FailFastWindow`).

At 100% of the daily count or the monthly spend, calls fail fast with ``Failed(unavailable)``
and reason ``quota_exhausted`` (:data:`REASON_QUOTA_EXHAUSTED`), ``capacity_limited``
true, and ``retry_after_ms`` set to the time until the count or the spend rolls (midnight
Pacific, or the 1st), **not clamped** to R8's 10 s: the outage lasts hours or days. The
bucket's own refusals stay ``token_rate``. The gateway's message, meter and alerts say which
limit it was (:data:`CAUSE_BUCKET`, :data:`CAUSE_DAILY_REQUESTS`, :data:`CAUSE_MONTHLY_SPEND`).

**The counters are per store.** With the in-process store the daily count and the month's
spend start from zero when the process restarts, so the 80% and 100% alerts can be late by
whatever was spent before; the alerts say so. A shared (Redis) store keeps them.

The store is a port: :class:`InProcessTokenRateStore` is the single-process version (M1, M2).
A Redis-compatible one implements the same seven operations, each atomic (a Lua script per
call), so every gateway replica of a project shares one bucket and one set of counters. Time
is passed in by the caller so a test controls it completely.
"""

from __future__ import annotations

import math
import threading
from collections import deque
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Literal, Protocol, runtime_checkable
from zoneinfo import ZoneInfo

from guardrail_engine.policy.api_tokens import estimate_api_tokens
from guardrail_engine.tokens import estimate_question_tokens, estimate_tokens

REASON_TOKEN_RATE = "token_rate"
"""The failure detail of a refusal by the bucket (empty, and not refilling in time)."""
REASON_QUOTA_EXHAUSTED = "quota_exhausted"
"""The failure detail when the daily request count or the monthly spend is at its limit: not
retryable before the counter rolls, and ``retry_after_ms`` says when."""
CAUSE_BUCKET = "bucket"
CAUSE_DAILY_REQUESTS = "daily_requests"
CAUSE_MONTHLY_SPEND = "monthly_spend"
CAUSES = (CAUSE_BUCKET, CAUSE_DAILY_REQUESTS, CAUSE_MONTHLY_SPEND)

PACIFIC = ZoneInfo("America/Los_Angeles")
"""Google resets the requests-per-day quota at midnight Pacific time; billing months roll on
the 1st in the same zone."""

DEFAULT_TOKENS_PER_MINUTE = 1_000_000
"""Tier 1 (M0-03, from Google's rate-limits page)."""
TESTED_FLAT_OCCUPANCY = 0.68
"""The highest occupancy of the per-minute quota tested flat (68.5%). It is the
default target and the ceiling unless ``burst_tested_at`` says a higher level was tested."""
DEFAULT_REQUESTS_PER_DAY = 50_000
DEFAULT_REQUESTS_PER_MINUTE = 1_500
"""Tier 1's published requests a minute (Gemini Decision 1). The gateway doesn't ration the
project's own minute count; it is the base of the per-minute allowance of each non-production
consumer (M3-08)."""
DEFAULT_MONTHLY_SPEND_CAP_USD = 250.0
DEFAULT_PRICE_PER_MILLION_INPUT_TOKENS_USD = 0.10
DEFAULT_BURST_CAPACITY_S = 5.0
"""How many seconds of the target rate the bucket holds: the burst a project may spend at
once. It also has to hold the largest call (R6.7: about 16K content tokens plus questions)."""
ALERT_THRESHOLDS = (0.8, 1.0)
"""Daily requests and monthly spend raise a warning at 80% and a page at 100%."""
FAIL_FAST_ALERT_RATE = 0.001
"""Alert when ``token_rate`` fail-fasts exceed 0.1% of checks ..."""
FAIL_FAST_WINDOW_S = 300.0
"""... in any 5 minutes."""
_EPSILON = 1e-3
"""Tokens of slack when comparing the bucket's level with a request, so floating-point
refill never leaves a waiter a vanishing wait short of its tokens."""

PRIORITY_BY_GUARD_POINT = {"input": 0, "output": 0, "plan": 1, "tool_call": 1, "tool_result": 2}
"""M3-07 order when tokens are scarce: ``input`` and ``output`` first, ``plan`` and
``tool_call`` next, ``tool_result`` last. Within a class, first come first served."""
DEFAULT_PRIORITY = 1
TEST_PRIORITY = 3
"""A fourth, lowest class (decided 2026-11-17): draft test calls (M2-05) and every other
non-production call (M3-08: calibration, red-team, shadow) share the project's bucket, daily
request counter and monthly spend with production, and queue below ``tool_result``. Within it,
tenants are served in weighted fair order like any class."""


@dataclass(frozen=True)
class TierLimits:
    tokens_per_minute: int
    requests_per_day: int | None
    """None is Google's "unlimited"."""
    monthly_cap_usd: float | None
    requests_per_minute: int


TIER_LIMITS: dict[str, TierLimits] = {
    "free": TierLimits(50_000, 10_000, None, 200),
    "tier_1": TierLimits(1_000_000, 50_000, 250.0, 1_500),
    "tier_2": TierLimits(4_000_000, None, 2_000.0, 5_000),
    "tier_3": TierLimits(10_000_000, None, 20_000.0, 15_000),
}
"""Gemini Decision 1's published limits per tier (``capacity/README.md`` section 1.2; a test
keeps this equal to ``capacity.model.TIERS``). Tier 3's monthly cap is the lower bound."""


@dataclass(frozen=True)
class TokenRateConfig:
    """One project's quota settings (a platform setting, set by platform ops when the project
    is added to a pool). Validated when built: a value the project's tier doesn't allow, or a
    target above what was tested, is refused at startup."""

    project_id: str = "default"
    tier: str = "tier_1"
    """One of :data:`TIER_LIMITS`. The ceiling for ``tokens_per_minute``,
    ``requests_per_day`` and ``monthly_spend_cap_usd``."""
    tokens_per_minute: int = DEFAULT_TOKENS_PER_MINUTE
    """The project's quota (positive, at most the tier's published limit)."""
    target_fraction: float = TESTED_FLAT_OCCUPANCY
    """The share of ``tokens_per_minute`` the limiter lets through: 0.68, the highest
    occupancy tested flat. Higher is refused unless ``burst_tested_at`` is at least as high."""
    burst_tested_at: float | None = None
    """The highest occupancy a burst test at the production in-flight limit has passed, once
    one has (R6.3). It raises the ceiling of ``target_fraction`` to that value."""
    requests_per_day: int = DEFAULT_REQUESTS_PER_DAY
    requests_per_minute: int = DEFAULT_REQUESTS_PER_MINUTE
    """The tier's published requests a minute (at most the tier's limit). Not rationed for the
    project as a whole; the non-production consumers' per-minute allowances are fractions of
    it (M3-08)."""
    monthly_spend_cap_usd: float = DEFAULT_MONTHLY_SPEND_CAP_USD
    price_per_million_input_tokens_usd: float = DEFAULT_PRICE_PER_MILLION_INPUT_TOKENS_USD
    burst_capacity_s: float = DEFAULT_BURST_CAPACITY_S

    def __post_init__(self) -> None:
        if problems := self.problems():
            raise ValueError("; ".join(problems))

    def problems(self) -> list[str]:
        """Every reason these settings are invalid (empty when valid). Messages never carry a
        project id's value, only setting names and limits."""
        found: list[str] = []
        if not (isinstance(self.project_id, str) and 1 <= len(self.project_id) <= 64):
            found.append("project_id must be 1 to 64 characters")
        limits = TIER_LIMITS.get(self.tier)
        if limits is None:
            found.append(f"tier must be one of {sorted(TIER_LIMITS)}")
        for name in (
            "target_fraction",
            "monthly_spend_cap_usd",
            "price_per_million_input_tokens_usd",
            "burst_capacity_s",
        ):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int | float):
                found.append(f"{name} must be a number")
            elif not 0 < value < math.inf:
                found.append(f"{name} must be positive and finite, got {value}")
        for name in ("tokens_per_minute", "requests_per_day", "requests_per_minute"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int):
                found.append(f"{name} must be a whole number")
            elif value <= 0:
                found.append(f"{name} must be positive, got {value}")
        if found:
            return found
        if limits is not None:
            if self.tokens_per_minute > limits.tokens_per_minute:
                found.append(
                    f"tokens_per_minute ({self.tokens_per_minute}) is above the "
                    f"{self.tier} limit ({limits.tokens_per_minute})"
                )
            if self.requests_per_minute > limits.requests_per_minute:
                found.append(
                    f"requests_per_minute ({self.requests_per_minute}) is above the "
                    f"{self.tier} limit ({limits.requests_per_minute})"
                )
            if limits.requests_per_day is not None and self.requests_per_day > (
                limits.requests_per_day
            ):
                found.append(
                    f"requests_per_day ({self.requests_per_day}) is above the "
                    f"{self.tier} limit ({limits.requests_per_day})"
                )
            if limits.monthly_cap_usd is not None and (
                self.monthly_spend_cap_usd > limits.monthly_cap_usd
            ):
                found.append(
                    f"monthly_spend_cap_usd ({self.monthly_spend_cap_usd}) is above the "
                    f"{self.tier} cap ({limits.monthly_cap_usd})"
                )
        if self.burst_tested_at is not None and not (
            isinstance(self.burst_tested_at, int | float)
            and not isinstance(self.burst_tested_at, bool)
            and 0 < self.burst_tested_at <= 1
        ):
            found.append("burst_tested_at must be in (0, 1]")
            return found
        if self.target_fraction > 1:
            found.append(f"target_fraction must be at most 1, got {self.target_fraction}")
        else:
            ceiling = max(TESTED_FLAT_OCCUPANCY, self.burst_tested_at or 0.0)
            if self.target_fraction > ceiling:
                found.append(
                    f"target_fraction ({self.target_fraction}) is above the highest occupancy "
                    f"tested flat ({ceiling}); a higher target needs burst_tested_at of at "
                    "least that value (R6.3: raising it needs a burst test at the new level)"
                )
        return found

    @property
    def rate_per_s(self) -> float:
        """The bucket's refill rate in tokens a second: ``tokens_per_minute x target_fraction
        / (60 + burst_capacity_s)``. With the bucket's size (``burst_capacity_s`` of this rate)
        a full bucket plus 60 s of refill is exactly the target for a minute."""
        return self.tokens_per_minute * self.target_fraction / (60.0 + self.burst_capacity_s)

    @property
    def capacity(self) -> float:
        """The bucket's size in tokens."""
        return self.rate_per_s * self.burst_capacity_s


# ----------------------------------------------------------------------------- the store


@runtime_checkable
class TokenRateStore(Protocol):
    """Where a project's bucket and counters live (M3-10). Every method is one atomic
    operation on one project's state, so gateways sharing a store share the limit. The
    in-process implementation is :class:`InProcessTokenRateStore`; a Redis-compatible one
    does each as a script, taking ``now`` from the caller (or the server) the same way.

    ``rate_per_s`` and ``capacity`` come from the caller's config on every call, so the
    store keeps only the state: a bucket's level and refill time, a counter per period."""

    def acquire(
        self, project_id: str, tokens: float, *, now: float, rate_per_s: float, capacity: float
    ) -> float:
        """Take ``tokens`` from the bucket if it holds that many and return 0.0. Otherwise
        take nothing and return the seconds until it will (> 0). A new bucket starts full."""
        ...

    def level(self, project_id: str, *, now: float, rate_per_s: float, capacity: float) -> float:
        """The bucket's level now. Negative while it is in debt (a call used more than it
        reserved)."""
        ...

    def adjust(
        self,
        project_id: str,
        delta: float,
        *,
        now: float,
        rate_per_s: float,
        capacity: float,
    ) -> None:
        """Move the level by ``-delta``: a positive ``delta`` takes more tokens (a call used
        more than it reserved; the level may go negative, down to ``-capacity``), a negative
        one gives tokens back (up to ``capacity``)."""
        ...

    def count_request(self, project_id: str, period: str) -> int:
        """Add one to the project's request count for ``period`` (a Pacific date) and
        return the new count. A new period starts at zero."""
        ...

    def requests(self, project_id: str, period: str) -> int:
        """The request count for ``period``; 0 for a period not yet seen."""
        ...

    def add_spend(self, project_id: str, period: str, usd: float) -> float:
        """Add ``usd`` (may be negative) to the project's spend for ``period`` (a Pacific
        month, ``YYYY-MM``) and return the new total. A new period starts at zero."""
        ...

    def spend(self, project_id: str, period: str) -> float:
        """The spend for ``period``; 0.0 for a period not yet seen."""
        ...


class InProcessTokenRateStore:
    """The single-process :class:`TokenRateStore`. Thread-safe. Keeps only the latest period
    of each counter."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._buckets: dict[str, tuple[float, float]] = {}  # project -> (level, as of)
        self._requests: dict[str, tuple[str, int]] = {}
        self._spend: dict[str, tuple[str, float]] = {}

    def _refilled(
        self, project_id: str, now: float, rate_per_s: float, capacity: float
    ) -> tuple[float, float]:
        level, at = self._buckets.get(project_id, (capacity, now))
        if now > at:
            level = min(capacity, level + (now - at) * rate_per_s)
            at = now
        return level, at

    def acquire(
        self, project_id: str, tokens: float, *, now: float, rate_per_s: float, capacity: float
    ) -> float:
        with self._lock:
            level, at = self._refilled(project_id, now, rate_per_s, capacity)
            if level + _EPSILON >= tokens:
                self._buckets[project_id] = (level - tokens, at)
                return 0.0
            self._buckets[project_id] = (level, at)
            return (tokens - level) / rate_per_s

    def level(self, project_id: str, *, now: float, rate_per_s: float, capacity: float) -> float:
        with self._lock:
            level, at = self._refilled(project_id, now, rate_per_s, capacity)
            self._buckets[project_id] = (level, at)
            return level

    def adjust(
        self,
        project_id: str,
        delta: float,
        *,
        now: float,
        rate_per_s: float,
        capacity: float,
    ) -> None:
        with self._lock:
            level, at = self._refilled(project_id, now, rate_per_s, capacity)
            self._buckets[project_id] = (min(capacity, max(-capacity, level - delta)), at)

    def count_request(self, project_id: str, period: str) -> int:
        with self._lock:
            current, count = self._requests.get(project_id, (period, 0))
            count = count + 1 if current == period else 1
            self._requests[project_id] = (period, count)
            return count

    def requests(self, project_id: str, period: str) -> int:
        with self._lock:
            current, count = self._requests.get(project_id, (period, 0))
            return count if current == period else 0

    def add_spend(self, project_id: str, period: str, usd: float) -> float:
        with self._lock:
            current, total = self._spend.get(project_id, (period, 0.0))
            total = total + usd if current == period else usd
            self._spend[project_id] = (period, max(total, 0.0))
            return max(total, 0.0)

    def spend(self, project_id: str, period: str) -> float:
        with self._lock:
            current, total = self._spend.get(project_id, (period, 0.0))
            return total if current == period else 0.0


# ----------------------------------------------------------------------- Pacific periods


def pacific_day_key(now: datetime) -> str:
    """The Pacific calendar date of ``now`` (an aware datetime): the daily counter's period.
    It changes at midnight Pacific, 08:00 UTC in winter and 07:00 UTC in summer."""
    return now.astimezone(PACIFIC).date().isoformat()


def pacific_month_key(now: datetime) -> str:
    """``YYYY-MM`` of ``now`` in Pacific time: the monthly spend's period."""
    local = now.astimezone(PACIFIC)
    return f"{local.year:04d}-{local.month:02d}"


def _local_midnight_utc(day) -> datetime:
    return datetime(day.year, day.month, day.day, tzinfo=PACIFIC).astimezone(UTC)


def seconds_until_pacific_midnight(now: datetime) -> float:
    """Seconds from ``now`` to the next midnight Pacific (the daily counter's roll)."""
    local = now.astimezone(PACIFIC)
    return (_local_midnight_utc(local.date() + timedelta(days=1)) - now).total_seconds()


def seconds_until_pacific_month_start(now: datetime) -> float:
    """Seconds from ``now`` to midnight Pacific on the 1st of next month."""
    local = now.astimezone(PACIFIC)
    first = local.date().replace(day=1)
    following = (first + timedelta(days=32)).replace(day=1)
    return (_local_midnight_utc(following) - now).total_seconds()


# ------------------------------------------------------------------------ the limiter


@dataclass(frozen=True)
class Crossing:
    """A counter passed 80% or 100% of its limit with one call."""

    cause: Literal["daily_requests", "monthly_spend"]
    threshold: float
    """0.8 or 1.0."""
    used: float
    limit: float


@dataclass(frozen=True)
class Reservation:
    """Tokens taken from the bucket for one provider call."""

    tokens: int
    month: str
    """The spend period it was charged to (the correction goes to the same one)."""
    crossings: tuple[Crossing, ...] = ()


@dataclass(frozen=True)
class CapRefusal:
    """The daily request count or the monthly spend is at its limit."""

    cause: str
    retry_after_s: float
    """Until the counter rolls (midnight Pacific, or the 1st); the gateway clamps it to
    R8's 100-10,000 ms like every hint."""
    message: str


class TokenRateLimiter:
    """One project's limiter over a shared :class:`TokenRateStore`. Synchronous, with no
    awaits, so a reservation and the slot it belongs to are taken together."""

    def __init__(
        self,
        config: TokenRateConfig,
        store: TokenRateStore,
        wall_clock=None,
    ) -> None:
        self.config = config
        self.store = store
        self._wall_clock = wall_clock or (lambda: datetime.now(UTC))
        self.window = FailFastWindow()

    @property
    def project_id(self) -> str:
        return self.config.project_id

    def wall(self) -> datetime:
        return self._wall_clock()

    def priority(self, guard_point: str, *, production: bool = True) -> int:
        """The queue class of a call. Production checks follow ``PRIORITY_BY_GUARD_POINT``;
        anything else (a draft test, M2-05) reserves from the same bucket and counters but
        waits below every guard point (:data:`TEST_PRIORITY`)."""
        if not production:
            return TEST_PRIORITY
        return PRIORITY_BY_GUARD_POINT.get(guard_point, DEFAULT_PRIORITY)

    def estimate(self, input_text_tokens: int, questions) -> int:
        """R6.6's fitted estimate of the call's API tokens, at most the bucket's size (a call
        can't reserve more than the bucket can ever hold)."""
        tokens = estimate_api_tokens(
            text_tokens=input_text_tokens,
            question_tokens=estimate_question_tokens(questions),
            question_count=len(questions),
        )
        return max(1, min(tokens, int(self.config.capacity)))

    def estimate_for_input(self, text: str, questions) -> int:
        return self.estimate(estimate_tokens(text), questions)

    def _bucket(self, now: float) -> dict[str, float]:
        return {
            "now": now,
            "rate_per_s": self.config.rate_per_s,
            "capacity": self.config.capacity,
        }

    def predicted_wait_s(self, tokens: int, *, ahead_tokens: int, now: float) -> float:
        """Seconds until the bucket holds ``tokens`` after the ``ahead_tokens`` of the calls
        in front have been served (0 if it already does)."""
        level = self.store.level(self.project_id, **self._bucket(now))
        return max(0.0, (tokens + ahead_tokens - level - _EPSILON) / self.config.rate_per_s)

    def cap_refusal(self) -> CapRefusal | None:
        """The daily count or the monthly spend at its limit, if either is."""
        wall = self.wall()
        used = self.store.requests(self.project_id, pacific_day_key(wall))
        if used >= self.config.requests_per_day:
            return CapRefusal(
                CAUSE_DAILY_REQUESTS,
                seconds_until_pacific_midnight(wall),
                f"quota_exhausted: the project's {self.config.requests_per_day} requests a day "
                "are used up until midnight Pacific; model not called",
            )
        spent = self.store.spend(self.project_id, pacific_month_key(wall))
        if spent >= self.config.monthly_spend_cap_usd:
            return CapRefusal(
                CAUSE_MONTHLY_SPEND,
                seconds_until_pacific_month_start(wall),
                f"quota_exhausted: the project's monthly spend cap of "
                f"${self.config.monthly_spend_cap_usd:g} is reached until the 1st (Pacific); "
                "model not called",
            )
        return None

    def reserve(self, tokens: int, *, now: float) -> Reservation | CapRefusal | float:
        """Admit one provider call: a :class:`CapRefusal` if a cap is at its limit, the
        seconds to wait (> 0) if the bucket lacks ``tokens``, otherwise a
        :class:`Reservation` (tokens taken, its cost added to the month). The request is counted
        later, by :meth:`count_sent`, when the call is sent."""
        if (refusal := self.cap_refusal()) is not None:
            return refusal
        wait = self.store.acquire(self.project_id, tokens, **self._bucket(now))
        if wait > 0:
            return wait
        month = pacific_month_key(self.wall())
        usd = tokens * self.config.price_per_million_input_tokens_usd / 1_000_000
        total = self.store.add_spend(self.project_id, month, usd)
        crossings = _crossed("monthly_spend", total - usd, total, self.config.monthly_spend_cap_usd)
        return Reservation(tokens, month, tuple(crossings))

    def count_sent(self) -> tuple[Crossing, ...]:
        """Count one provider call **actually sent** against the day's requests: the
        gateway calls this once the call exists, never for a reservation it gave back."""
        count = self.store.count_request(self.project_id, pacific_day_key(self.wall()))
        limit = self.config.requests_per_day
        return tuple(_crossed("daily_requests", count - 1, count, limit))

    def reconcile(
        self, reservation: Reservation, actual_tokens: int | None, *, now: float
    ) -> tuple[Crossing, ...]:
        """Correct a call's reservation with the provider's usage: the difference goes back
        to (or is taken from) the bucket, and the month's spend becomes actual x price.
        ``None`` (usage unknown) keeps the reservation."""
        if actual_tokens is None or actual_tokens == reservation.tokens:
            return ()
        delta = actual_tokens - reservation.tokens
        self.store.adjust(self.project_id, delta, **self._bucket(now))
        usd = delta * self.config.price_per_million_input_tokens_usd / 1_000_000
        total = self.store.add_spend(self.project_id, reservation.month, usd)
        if usd <= 0:
            return ()
        return tuple(
            _crossed("monthly_spend", total - usd, total, self.config.monthly_spend_cap_usd)
        )


def _crossed(
    cause: Literal["daily_requests", "monthly_spend"], before: float, after: float, limit: float
) -> list[Crossing]:
    """The thresholds passed going from ``before`` to ``after``."""
    return [
        Crossing(cause, threshold, after, limit)
        for threshold in ALERT_THRESHOLDS
        if before < threshold * limit <= after
    ]


# ------------------------------------------------------------------- the fail-fast window


@dataclass
class FailFastWindow:
    """Checks and ``token_rate`` fail-fasts in the last ``FAIL_FAST_WINDOW_S`` seconds, in
    one-second buckets. :meth:`exceeded` is true while fail-fasts are more than 0.1% of
    checks. ``alerting`` lets the gateway raise one alert per excursion."""

    window_s: float = FAIL_FAST_WINDOW_S
    rate: float = FAIL_FAST_ALERT_RATE
    alerting: bool = False
    _buckets: deque[list[float]] = field(default_factory=deque)  # [second, checks, fails]
    _checks: int = 0
    _fails: int = 0

    def _prune(self, now: float) -> None:
        horizon = now - self.window_s
        while self._buckets and self._buckets[0][0] <= horizon:
            _, checks, fails = self._buckets.popleft()
            self._checks -= int(checks)
            self._fails -= int(fails)

    def _bucket(self, now: float) -> list[float]:
        second = math.floor(now)
        if not self._buckets or self._buckets[-1][0] != second:
            self._buckets.append([second, 0, 0])
        return self._buckets[-1]

    def note_check(self, now: float) -> None:
        self._prune(now)
        self._bucket(now)[1] += 1
        self._checks += 1

    def note_fail_fast(self, now: float) -> None:
        self._prune(now)
        self._bucket(now)[2] += 1
        self._fails += 1

    def totals(self, now: float) -> tuple[int, int]:
        """``(checks, fail-fasts)`` in the window."""
        self._prune(now)
        return self._checks, self._fails

    def exceeded(self, now: float) -> bool:
        checks, fails = self.totals(now)
        return fails > 0 and fails > self.rate * checks
