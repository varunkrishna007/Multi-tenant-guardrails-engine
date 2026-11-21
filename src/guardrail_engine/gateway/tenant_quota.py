"""M3-07 per-tenant quotas and fair scheduling, and M3-08 per-consumer non-production
allowances (decided in M0-03 (c)): both enforced in the gateway, in front of the project's
token-rate limiter (M3-10).

A project's Gemini quota is shared by every tenant and by every non-production consumer
(tests, calibration, red-team runs, shadow candidates), because keys in a project share its
quota (M0-03). The gateway therefore divides its own offered load:

* **Per-tenant share** (:class:`TierQuota`, :class:`QuotaConfig`). Each tenant gets, by its
  tier (``standard``, ``regulated``, ``dedicated``; a per-tenant override replaces the tier's
  figures), a per-minute **token share**, a per-minute **check share** and a **daily request
  share**. Each minute share is a token bucket that refills at the share's own rate and holds
  60 s of it (a tenant's burst; see :data:`DEFAULT_BURST_CAPACITY_S` for the trade-off), and
  never less than the largest single check, so a tenant's chunked ``tool_result`` is never too
  big for its bucket. The chunks of one check are charged **together, all or none**
  (:class:`CheckGroup`): never some sent and the rest refused. A check over its tenant's share
  is refused at once with ``Failed(unavailable)``, capacity limited, no provider call, and a
  ``retry_after_ms`` that is the time until the bucket holds it. The reason is the existing
  ``token_rate`` (SDK ``FailureReason.TOKEN_RATE``: "the gateway's token-rate limit, retry
  after ``retry_after_ms``"), with the **cause** ``tenant_tokens`` or ``tenant_checks`` in the
  gateway's meters; at the daily share it is ``quota_exhausted`` (cause ``tenant_daily``),
  retry after the Pacific midnight, unclamped, with a warning to the tenant's admins at 80%
  and 100% of the share. No new public reason is added, so the SDK's enum is unchanged.
  Only the first call of a check is charged (the retry is the platform's, not the tenant's).
  Production only: a tenant's tests are not charged to its production share.
* **Fair scheduling** (:class:`FairClock`). When the admission queue is contended, waiters of
  one priority class (``input`` and ``output`` first, then ``plan`` and ``tool_call``, then
  ``tool_result``, then non-production) are served in **weighted fair order across tenants**:
  start-time fair queueing, in which each waiter gets a virtual start time (the later of the
  class's virtual time and the finish time of the tenant's last queued waiter) and a finish
  time that adds ``cost / weight``; the queue is ordered by start time. With every tenant
  backlogged, each is served in proportion to its tier's weight (what deficit round robin
  gives, without its rounds). A tenant that is not backlogged starts at the class's current
  virtual time, so a quiet tenant is served next, however long a noisy tenant's line is. The
  cost is the call's estimated API tokens (one unit without a token estimate).
* **The queue's size is shared fairly too**. A tenant may hold at most
  ``max_queued_per_key / (tenants with queued work + 1)`` places of a key's queue (at least 1,
  and never more than ``max_queued_fraction_per_tenant`` of it). When the queue is full and
  the newcomer's tenant holds fewer places than the largest holder, the largest holder's last
  waiter is **pushed out** (it fails ``admission_queue_full``, with a retry hint, and its charge
  is given back) and the newcomer is admitted: a quiet tenant is never refused for a place two
  noisy ones filled. The newcomer is refused only if it is itself the largest holder.
* **Non-production allowances** (M3-08, M0-03 (c)). A call tagged with a
  non-production consumer (:func:`usage_class`) is queued behind every production class, and
  every such consumer (``test``, ``calibration``, ``red_team``, ``shadow``) has four
  allowances, each its fraction (10% by default) of a project figure:
  **tokens a minute** (a token bucket at that fraction of M3-10's rate and size),
  **requests a minute** (of the tier's published requests-per-minute limit, 1,500 at Tier 1),
  **requests a day** (of the project's ``requests_per_day``, rolling at midnight Pacific) and
  **monthly spend** (of ``monthly_spend_cap_usd``, rolling on the 1st, Pacific). Over any of
  them the call is refused with no provider call, cause ``consumer_allowance``: reason
  ``token_rate`` for the minute allowances (retry after the bucket holds it) and
  ``quota_exhausted`` for the daily and monthly ones (retry after the next roll, unclamped).
  The counters live in the project's store and roll with the project's own. Because the
  allowances add up to less than the whole, and every non-production call also passes the
  project's bucket and caps, production always has at least ``1 - sum(allowances)`` of every
  window, of the day's requests and of the month's spend to itself. They apply whenever the
  project's token-rate limiter is on, with or without ``quotas`` (:class:`ConsumerAllowances`).
  A call nobody tagged is production.

**The guarantee (M3-08): production is never refused for tokens,
queue space, slots, the day's requests or the month's spend because of non-production use.**
It rests on four mechanisms, each tested:

* *Tokens, requests and spend*: the allowances above (need the project's token-rate limiter,
  ``token_rate``; they do not need ``quotas``). All four consumers together can use at most
  40% of the project's tokens a minute, requests a minute, requests a day and monthly spend.
* *Queue places*: non-production waiters, all consumers together, hold at most **25%** of a
  key's queue (:func:`non_production_queue_limit`, at least 1); further ones are refused
  ``admission_queue_full``. A non-production call never pushes anyone out. A production check
  that meets a full queue **pushes out the last non-production waiter** first, and only then
  (with quotas on) the fair-share push-out above. A tenant's non-production waiters don't
  count toward its production places.
* *In-flight slots*: non-production calls, all consumers together, hold at most **half** of
  ``max_in_flight_per_key`` (:func:`non_production_slot_limit`: at least 1, never all of them
  when there is more than one); a non-production call over its share waits in the queue (still
  behind every production class) while a free slot stays for production. So a production check
  finds a slot at once unless production calls hold the rest.
* *Order*: non-production waits behind every production class.

The queue and slot limits apply with or without ``quotas`` (they follow the ``usage_class``);
the allowances need ``token_rate`` and no more.

**What the guarantee does not cover (the exceptions):**

1. With ``max_in_flight_per_key == 1`` the single slot can be held by a non-production call
   already in flight; production then waits for that one call, and is refused ``admission_wait``
   only if its budget can't cover the wait plus its own call. A call in flight is never
   cancelled for another.
2. The project's **daily request count and monthly spend cap can be reached by production's
   own use**: production alone can spend the whole of the shared count or cap (they are
   shared by every tenant), and at the cap every call, production included, fails
   ``quota_exhausted`` (M3-10). Non-production can consume at most 40% of each (4 consumers x
   10%), so production keeps at least 60% of each window, of the day's requests and of the
   month's spend. That is the guarantee: if non-production uses its 40% and production the
   other 60%, both reach the cap together.
3. A custom admission rule (``admission=``) decides its own slots; the share of slots is taken
   from ``max_in_flight_per_key``, which that rule may not use.
4. Capacity the provider itself withholds (its own 429s, outages, an open breaker, orphaned
   calls holding slots) is not something the gateway can reserve.
5. A production check is still refused for its **own tenant's** share (tokens, checks, daily
   requests) and when production alone fills the queue or the slots: that is production use.

State lives in the same :class:`~guardrail_engine.gateway.token_rate.TokenRateStore` as the
project's bucket (keys per tenant and per consumer), so gateways sharing a store share the
shares. Time is passed in by the caller, so a test controls it completely.
"""

from __future__ import annotations

import math
from collections.abc import Callable, Mapping
from contextvars import ContextVar, Token
from dataclasses import dataclass, field
from datetime import datetime

from guardrail_engine.gateway.token_rate import (
    DEFAULT_BURST_CAPACITY_S as PROJECT_BURST_CAPACITY_S,
)
from guardrail_engine.gateway.token_rate import (
    TokenRateConfig,
    TokenRateStore,
    pacific_day_key,
    pacific_month_key,
    seconds_until_pacific_midnight,
    seconds_until_pacific_month_start,
)

USAGE_PRODUCTION = "check"
"""The production class, spelled as the gateway's ``USAGE_CHECK``: one concept. ``"production"``
is accepted as a synonym wherever a class is read."""
_PRODUCTION_LABELS = (USAGE_PRODUCTION, "production")
CONSUMER_TEST = "test"
CONSUMER_CALIBRATION = "calibration"
CONSUMER_RED_TEAM = "red_team"
CONSUMER_SHADOW = "shadow"
NON_PRODUCTION_CONSUMERS = (CONSUMER_TEST, CONSUMER_CALIBRATION, CONSUMER_RED_TEAM, CONSUMER_SHADOW)
"""The non-production consumers of the project's quota (M0-03 (c), M3-08): the test endpoint,
calibration runs, red-team runs and shadow candidates."""

CAUSE_TENANT_TOKENS = "tenant_tokens"
CAUSE_TENANT_CHECKS = "tenant_checks"
CAUSE_TENANT_DAILY = "tenant_daily"
CAUSE_CONSUMER = "consumer_allowance"
ALLOWANCE_TOKENS = "tokens_per_minute"
ALLOWANCE_REQUESTS_PER_MINUTE = "requests_per_minute"
ALLOWANCE_REQUESTS_PER_DAY = "requests_per_day"
ALLOWANCE_MONTHLY_SPEND = "monthly_spend"
ALLOWANCES = (
    ALLOWANCE_TOKENS,
    ALLOWANCE_REQUESTS_PER_MINUTE,
    ALLOWANCE_REQUESTS_PER_DAY,
    ALLOWANCE_MONTHLY_SPEND,
)
"""What a non-production consumer is limited by, in the order they are checked."""
QUOTA_CAUSES = (CAUSE_TENANT_TOKENS, CAUSE_TENANT_CHECKS, CAUSE_TENANT_DAILY, CAUSE_CONSUMER)
"""Why a check was refused by this module (the gateway's meter label; the public reason is
``token_rate``, or ``quota_exhausted`` for the daily share)."""
DAILY_CAUSES = frozenset({CAUSE_TENANT_DAILY})
"""The causes whose reason is ``quota_exhausted``: the wait is until the Pacific midnight."""

DEFAULT_TIER = "standard"
DEFAULT_BURST_CAPACITY_S = 60.0
"""A tenant's burst is **60 seconds of its per-minute share** (decided after the M3-09 load
harness, 2026-11-18): the bucket holds a whole minute's share and refills at the share's own
rate, a minute's share per minute. A tenant's traffic is bursty (a turn is five or more checks
within seconds, and later checks carry the conversation so far), and at the earlier 15 s burst
the bucket refilled at only 80% of the share, so a busy agentic tenant at about half its share
was refused one check in seven. **The trade-off:** a tenant that starts with a full bucket may
spend up to **twice** its share in the first minute (the bucket plus a minute of refill), and
its sustained rate is the share. The earlier rule of never more than the share in any
minute held only because the refill was cut to make room for the bucket. The project's own limiter
(68% of the project's tokens a minute) and fair scheduling still hold the total, and the shares were
already oversubscribed on purpose.

**With the floor** (:attr:`QuotaConfig.largest_check_tokens`, 94,000 tokens at the defaults) a
tenant whose share is below 94,000 a minute (a per-tenant override; the tiers are all above
it) has a bucket of 94,000, not of a minute: its first-minute burst is then well above twice
its share (a 10,000-a-minute override can spend 94,000 at once), and it takes 9.4 minutes to
refill. The floor stays, because a bucket smaller than one whole check could never take it."""
DEFAULT_MAX_QUEUED_FRACTION_PER_TENANT = 0.5
ALERT_THRESHOLDS = (0.8, 1.0)
MAX_WEIGHT = 1000
"""The largest weight a :class:`TierQuota` can hold at all."""
MAX_OVERRIDE_WEIGHT_FACTOR = 8
"""A per-tenant override's weight may be at most this multiple of the largest tier weight: with fair
queueing a tenant at 1,000 against tenants at 1 would take 99.9% of a
contended key, which is starvation in all but name."""
REQUEST_BURST_S = PROJECT_BURST_CAPACITY_S
"""How many seconds of its per-minute request allowance a consumer's bucket holds: the burst
of calls it may send at once. Fixed (the project's token burst can be set far smaller in a
test), so a request is a unit of its own."""
NON_PRODUCTION_QUEUE_FRACTION = 0.25
"""Non-production waiters, all consumers together, may hold at most this fraction of a key's
admission queue."""
NON_PRODUCTION_SLOT_FRACTION = 0.5
"""Non-production calls, all consumers together, may hold at most this fraction of a key's
in-flight slots."""


def non_production_queue_limit(max_queued_per_key: int) -> int:
    """The most queue places non-production waiters may hold together: a quarter of the
    queue, at least 1."""
    return max(1, math.floor(NON_PRODUCTION_QUEUE_FRACTION * max_queued_per_key))


def non_production_slot_limit(max_in_flight_per_key: int) -> int:
    """The most in-flight slots non-production calls may hold together: half of them, at
    least 1, and never all of them when there is more than one."""
    return max(1, math.floor(NON_PRODUCTION_SLOT_FRACTION * max_in_flight_per_key))


@dataclass(frozen=True)
class TierQuota:
    """One tier's (or one tenant's) share of the project, per tenant."""

    weight: int = 1
    """The tenant's weight in fair scheduling: a tenant with weight 2 is served twice as often
    as one with weight 1 when both are queued."""
    tokens_per_minute: int = 170_000
    """API tokens (R6.6's estimate, corrected by actual usage) per minute."""
    checks_per_minute: int = 60
    """Provider calls for first attempts, per minute."""
    requests_per_day: int = 12_500
    """Provider calls per Pacific day (the project's 50,000 a day is shared)."""

    def problems(self) -> list[str]:
        found = []
        for name, high in (
            ("weight", MAX_WEIGHT),
            ("tokens_per_minute", None),
            ("checks_per_minute", None),
            ("requests_per_day", None),
        ):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int):
                found.append(f"{name} must be a whole number")
            elif value < 1 or (high is not None and value > high):
                limit = f"between 1 and {high}" if high else "positive"
                found.append(f"{name} must be {limit}, got {value}")
        return found

    def __post_init__(self) -> None:
        if problems := self.problems():
            raise ValueError("; ".join(problems))


DEFAULT_TIER_QUOTAS: dict[str, TierQuota] = {
    "standard": TierQuota(weight=1, tokens_per_minute=170_000, checks_per_minute=60,
                          requests_per_day=12_500),
    "regulated": TierQuota(weight=2, tokens_per_minute=340_000, checks_per_minute=120,
                           requests_per_day=25_000),
    "dedicated": TierQuota(weight=4, tokens_per_minute=680_000, checks_per_minute=240,
                           requests_per_day=50_000),
}  # fmt: skip
"""Defaults for a Tier 1 project: a standard tenant may use a quarter of the 680,000 tokens a
minute the limiter lets through (68% of 1,000,000) and of the 50,000 requests a day, a
regulated tenant half, a dedicated one all of it. The shares add up to well over the project's
limit on purpose (most tenants are quiet); the project's own bucket still holds the total, and
fair scheduling decides who waits when it is contended. 60 checks a minute is 12 turns a
minute at five checks, more than 4,000 tokens a check allows by tokens, so tokens bind first
for ordinary checks and the check share binds for tiny ones. Platform ops set these per
deployment."""
DEFAULT_NON_PRODUCTION: dict[str, float] = {
    CONSUMER_TEST: 0.10,
    CONSUMER_CALIBRATION: 0.10,
    CONSUMER_RED_TEAM: 0.10,
    CONSUMER_SHADOW: 0.10,
}
"""Each non-production consumer's share of the project's token-rate target, of its requests a
minute, requests a day and monthly spend (M3-08): together 40% of each, so production
always has 60% of every window, of the day and of the month to itself. Each is at least about
5,000 tokens of burst (10% of the 52,000-token bucket), enough for a floor-sized check."""


@dataclass(frozen=True)
class QuotaConfig:
    """Platform settings for tenant quotas, fair scheduling and non-production allowances.
    Validated when built."""

    tiers: Mapping[str, TierQuota] = field(default_factory=lambda: dict(DEFAULT_TIER_QUOTAS))
    """Each directory tier's share (``standard``, ``regulated``, ``dedicated``)."""
    default_tier: str = DEFAULT_TIER
    """The tier of a tenant whose tier isn't listed, or isn't known to the gateway."""
    overrides: Mapping[str, TierQuota] = field(default_factory=dict)
    """Per-tenant figures that replace the tier's, set by platform ops (tenant id -> share)."""
    burst_capacity_s: float = DEFAULT_BURST_CAPACITY_S
    """Seconds of a tenant's share its buckets hold. The refill is the share's own rate (a
    minute's share per minute), so this is the burst on top of the sustained share."""
    largest_check_calls: int = 0
    """The most provider calls one check can make (a ``tool_result`` of the most chunks); 0
    means not set. A group charges one check per chunk, so a tenant's check bucket always holds
    at least this many, however low its checks-a-minute share. Filled in by the engine."""
    largest_check_tokens: int = 0
    """The most API tokens one check can compile to (a ``tool_result`` of the most chunks, each
    carrying the questions); 0 means not set. A tenant's token bucket always holds at least this
    much, so no tenant's bucket is too small for one whole check, however low its share. The
    engine fills it in from the platform settings (``EngineSettings.effective_quotas``)."""
    max_queued_fraction_per_tenant: float = DEFAULT_MAX_QUEUED_FRACTION_PER_TENANT
    """The most of a key's admission queue (``max_queued_per_key``) one tenant may hold."""
    non_production: Mapping[str, float] = field(
        default_factory=lambda: dict(DEFAULT_NON_PRODUCTION)
    )
    """Each non-production consumer's fraction of the project's token-rate target, requests a
    minute, requests a day and monthly spend (the same fraction for all four allowances)."""

    def __post_init__(self) -> None:
        if problems := self.problems():
            raise ValueError("; ".join(problems))

    def problems(self) -> list[str]:
        found = []
        if not isinstance(self.tiers, Mapping) or not self.tiers:
            return ["tiers must list at least one tier"]
        for name, quota in self.tiers.items():
            if not isinstance(quota, TierQuota):
                found.append(f"tiers[{name!r}] must be a TierQuota")
        if self.default_tier not in self.tiers:
            found.append(f"default_tier must be one of the listed tiers {sorted(self.tiers)}")
        tier_weights = [q.weight for q in self.tiers.values() if isinstance(q, TierQuota)]
        weight_cap = MAX_OVERRIDE_WEIGHT_FACTOR * max(tier_weights, default=1)
        for tenant, quota in self.overrides.items():
            if not isinstance(tenant, str) or not tenant:
                found.append("overrides must be keyed by tenant id")
            if not isinstance(quota, TierQuota):
                found.append("overrides must hold TierQuota values")
            elif quota.weight > weight_cap:
                found.append(
                    f"overrides[{tenant!r}] weight {quota.weight} is above {weight_cap}, "
                    f"{MAX_OVERRIDE_WEIGHT_FACTOR} times the largest tier weight "
                    f"({max(tier_weights)}): it would take nearly all of a contended queue"
                )
        if not (
            isinstance(self.burst_capacity_s, int | float)
            and not isinstance(self.burst_capacity_s, bool)
            and 0 < self.burst_capacity_s < math.inf
        ):
            found.append("burst_capacity_s must be positive and finite")
        fraction = self.max_queued_fraction_per_tenant
        if not (
            isinstance(fraction, int | float)
            and not isinstance(fraction, bool)
            and 0 < fraction <= 1
        ):
            found.append("max_queued_fraction_per_tenant must be in (0, 1]")
        for name in ("largest_check_tokens", "largest_check_calls"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                found.append(f"{name} must be a whole number, 0 or more")
        if not found:
            burst = self.burst_capacity_s
            fits = burst / 60.0  # a bucket holds this fraction of a minute's share
            for name, quota in [*self.tiers.items(), *self.overrides.items()]:
                if isinstance(quota, TierQuota) and quota.checks_per_minute * fits < 1:
                    found.append(
                        f"checks_per_minute of {name!r} ({quota.checks_per_minute}) is too "
                        f"small for a {burst:g} s burst: its bucket would never hold one check "
                        f"(at least {math.ceil(60.0 / burst)})"
                    )
        if set(self.non_production) != set(NON_PRODUCTION_CONSUMERS):
            found.append(
                f"non_production must give a fraction for each of {NON_PRODUCTION_CONSUMERS}"
            )
        else:
            total = 0.0
            for consumer, share in self.non_production.items():
                if (
                    isinstance(share, bool)
                    or not isinstance(share, int | float)
                    or not (0 < share < 1)
                ):
                    found.append(f"non_production[{consumer!r}] must be in (0, 1)")
                else:
                    total += share
            if not found and total >= 1:
                found.append(
                    f"non_production fractions add up to {total:g}; they must leave room for "
                    "production (a sum below 1)"
                )
        return found

    def limits_for(self, tenant_id: str, tier: str | None) -> TierQuota:
        """The share of ``tenant_id``: its override, else its tier's, else the default tier's."""
        if tenant_id in self.overrides:
            return self.overrides[tenant_id]
        return self.tiers.get(tier or self.default_tier, self.tiers[self.default_tier])

    def queue_limit(self, max_queued_per_key: int, tenants_queued: int = 0) -> int:
        """The most production waiters one tenant may hold in a key's queue: an equal share
        among the tenants with queued work and the newcomer (``max_queued_per_key /
        (tenants_queued + 1)``), and never more than ``max_queued_fraction_per_tenant`` of the
        queue, at least 1."""
        fixed = math.ceil(self.max_queued_fraction_per_tenant * max_queued_per_key)
        adaptive = max_queued_per_key // (tenants_queued + 1)
        return max(1, min(fixed, adaptive))


# ------------------------------------------------------------------- usage class (M3-08)

_USAGE_CLASS: ContextVar[str] = ContextVar("guardrail_usage_class", default=USAGE_PRODUCTION)


class UsageClass:
    """The context manager :func:`usage_class` returns. Reusable and nestable."""

    def __init__(self, name: str) -> None:
        self._name = name
        self._tokens: list[Token[str]] = []

    def __enter__(self) -> None:
        self._tokens.append(_USAGE_CLASS.set(self._name))

    def __exit__(self, *exc: object) -> None:
        _USAGE_CLASS.reset(self._tokens.pop())


def usage_class(name: str) -> UsageClass:
    """Tag every check made inside the block with a consumer of the project's quota::

        with usage_class("calibration"):
            await engine.check(...)

    ``"check"`` / ``"production"`` (the default, and what an untagged call is) or one of
    :data:`NON_PRODUCTION_CONSUMERS`; any other label counts as ``"test"``. It rides a context
    variable, so it follows a check through every ``await`` and into tasks it starts, and needs
    no change to the calls in between."""
    return UsageClass(name)


def consumer_of(name: str | None = None) -> str:
    """The consumer a check belongs to: ``name`` if given, else the current :func:`usage_class`.
    ``USAGE_PRODUCTION`` (``"check"``, or its synonym ``"production"``), a listed
    non-production consumer, or ``test`` for any other label (a mistyped label is throttled,
    never mistaken for production)."""
    label = _USAGE_CLASS.get() if name is None else name
    if label in _PRODUCTION_LABELS:
        return USAGE_PRODUCTION
    if label in NON_PRODUCTION_CONSUMERS:
        return label
    return CONSUMER_TEST


def resolve_usage_class(label: str | None) -> str:
    """The class the gateway uses for a call given ``label`` (its ``usage_class`` argument):
    an explicit class stands, and the production default takes the class of an enclosing
    :func:`usage_class` block, if any. This is how the context helper feeds the argument."""
    if label is None or label in _PRODUCTION_LABELS:
        return _USAGE_CLASS.get()
    return label


# ----------------------------------------------------------------------- fair scheduling


class FairClock:
    """Virtual time of one key's queue, per priority class (start-time fair queueing).

    :meth:`tag` gives a waiter its virtual start and finish; the queue is kept ordered by
    ``(priority, start)``. :meth:`served` advances the class's virtual time to the start of the
    waiter that was served. A tenant with nothing queued starts at the class's virtual time;
    one with waiters queued starts after its last one, so its line is charged for its length."""

    def __init__(self) -> None:
        self._vtime: dict[int, float] = {}

    def tag(self, priority: int, tail: float, cost: float, weight: float) -> tuple[float, float]:
        """``(start, finish)`` of a waiter whose tenant's last queued waiter finishes at
        ``tail`` (0.0 if none)."""
        start = max(self._vtime.get(priority, 0.0), tail)
        return start, start + max(cost, 1.0) / weight

    def served(self, priority: int, start: float) -> None:
        self._vtime[priority] = max(self._vtime.get(priority, 0.0), start)


# ------------------------------------------------------------------------------- limiter


@dataclass(frozen=True)
class QuotaRefusal:
    """A check refused for its tenant's share or its consumer's allowance."""

    cause: str
    retry_after_s: float
    message: str
    exhausted: bool = False
    """True when the public reason is ``quota_exhausted`` (a daily or monthly allowance: the
    wait is until the counter rolls); False for ``token_rate``."""
    limit: str = ""
    """For a consumer: which allowance it was (:data:`ALLOWANCES`)."""


@dataclass
class QuotaCharge:
    """What one check took from the shares, to give back if the call is never sent and to
    correct with the provider's usage."""

    tenant_id: str
    tier: str
    consumer: str
    tokens: int = 0
    """Tokens taken from the tenant's bucket (production) or the consumer's (non-production);
    0 when nothing was taken."""
    checks: int = 0
    """1 when the tenant's check bucket was charged."""
    quota: TierQuota | None = None
    counted: bool = False
    """Whether the tenant's (or the consumer's) daily count has been bumped for this check's
    call."""
    requests: int = 0
    """1 when the consumer's per-minute request bucket was charged."""
    month: str = ""
    """The Pacific month the consumer's spend was added to (the correction goes there too);
    empty when nothing was charged."""


@dataclass(eq=False)
class CheckGroup:
    """The chunk calls of one ``tool_result`` check (M3-04), submitted together (M3-09 decision).

    * **Charged together, all or none.** The first chunk to reach the gateway charges every
      chunk's tokens (and one check each) to the tenant in one step; if the share can't take
      them all, nothing is taken and **every** chunk is refused with the same ``token_rate``
      and retry hint. Never some chunks sent and the rest refused. (A tenant bucket never
      queues, so "wait together" is "refused together, retry after the same time".)
    * **One place in the fair queue.** The chunks share one virtual start and finish time, and
      the group's whole cost is charged to the tenant's line once, so a chunk is never put
      behind its own siblings. Each chunk still needs its own in-flight slot, and counts as a
      waiter toward the tenant's share of the queue: the per-key limits bind them as any calls."""

    tokens: tuple[int, ...]
    """Each chunk call's estimated API tokens, in submission order."""
    attempted: bool = False
    charges: list[QuotaCharge] = field(default_factory=list)
    refusal: QuotaRefusal | None = None
    tag: tuple[float, float] | None = None
    """The group's shared (start, finish) in the fair queue, set when its first chunk queues."""
    room_checked: bool = False
    room_refusal: str | None = None
    """Set by the first chunk to arrive when the queue could not take every chunk (the
    refusal message); every chunk is then refused ``admission_queue_full`` and none is sent."""

    @property
    def total_tokens(self) -> int:
        return sum(self.tokens)


@dataclass(frozen=True)
class QuotaCrossing:
    """A tenant's daily count passed 80% or 100% of its share with one call."""

    tenant_id: str
    threshold: float
    used: int
    limit: int


@dataclass(frozen=True)
class TenantQuotaStatus:
    """A tenant's usage against its share right now (for a dashboard or a test)."""

    tenant_id: str
    tier: str
    weight: int
    tokens_available: float
    tokens_capacity: float
    tokens_per_minute: int
    checks_available: float
    checks_capacity: float
    checks_per_minute: int
    requests_today: int
    requests_per_day: int

    @property
    def tokens_used_fraction(self) -> float:
        """How much of the token bucket is spent (0 empty of use, 1 spent), a gauge of the
        current burst; the sustained rate is in the meter."""
        return 1.0 - max(0.0, self.tokens_available) / self.tokens_capacity


def _bucket(per_minute: float, burst_s: float) -> tuple[float, float]:
    """``(rate per second, capacity)`` such that a full bucket plus a minute of refill is
    exactly ``per_minute``."""
    rate = per_minute / (60.0 + burst_s)
    return rate, rate * burst_s


def _tenant_bucket(per_minute: float, burst_s: float) -> tuple[float, float]:
    """``(rate per second, capacity)`` of a tenant's bucket: it refills at the share's own rate
    and holds ``burst_s`` seconds of it (60 by default: a whole minute's share)."""
    rate = per_minute / 60.0
    return rate, rate * burst_s


def allowance_problems(project: TokenRateConfig, fractions: Mapping[str, float]) -> list[str]:
    """Why the consumers' allowances can't work with ``project``: a per-minute request bucket
    too small to ever hold one request (the consumer would be refused for good)."""
    found = []
    burst = REQUEST_BURST_S
    for consumer in NON_PRODUCTION_CONSUMERS:
        fraction = fractions.get(consumer)
        if not isinstance(fraction, int | float) or isinstance(fraction, bool):
            continue
        per_minute = project.requests_per_minute * fraction
        if per_minute * burst / (60.0 + burst) < 1:
            found.append(
                f"the {consumer} allowance of {fraction:.0%} of requests_per_minute "
                f"({project.requests_per_minute}) is too small for a {burst:g} s burst: its "
                "bucket would never hold one request"
            )
    return found


def _whole(limit: float) -> int:
    """A fraction of a count as a whole number of requests, at least 1 (float noise ignored)."""
    return max(1, math.floor(limit + 1e-9))


class ConsumerAllowances:
    """The non-production consumers' allowances (M3-08): tokens a minute, requests a
    minute, requests a day and monthly spend, each a fraction of the project's figure, over the
    project's own store and Pacific day and month. Synchronous, no awaits. Needs the project's
    config (``project``); without it nothing is enforced. It has no tenant shares, so it works
    with or without :class:`QuotaConfig`; a production charge through it is empty."""

    def __init__(
        self,
        fractions: Mapping[str, float] | None,
        store: Callable[[], TokenRateStore],
        *,
        project_id: str = "default",
        project: TokenRateConfig | None = None,
        wall_clock: Callable[[], datetime],
    ) -> None:
        self.fractions: Mapping[str, float] = dict(
            DEFAULT_NON_PRODUCTION if fractions is None else fractions
        )
        self._store = store
        self.project_id = project_id
        self._project = project
        self._wall_clock = wall_clock
        if project is not None and (problems := allowance_problems(project, self.fractions)):
            raise ValueError("; ".join(problems))

    @property
    def enabled(self) -> bool:
        return self._project is not None

    def _key(self, kind: str, consumer: str) -> str:
        return f"tq:{kind}:{self.project_id}:{consumer}"

    def _applies(self, consumer: str) -> bool:
        return (
            self._project is not None
            and consumer != USAGE_PRODUCTION
            and consumer in self.fractions
        )

    def _token_bucket(self, consumer: str) -> dict:
        """Its fraction of the project's rate and size."""
        project, fraction = self._project, self.fractions[consumer]
        assert project is not None
        return {
            "rate_per_s": project.rate_per_s * fraction,
            "capacity": project.capacity * fraction,
        }

    def _request_bucket(self, consumer: str) -> dict:
        """Its fraction of the tier's requests a minute, as a bucket sized like the project's
        (a full bucket plus a minute of refill is exactly the fraction)."""
        project = self._project
        assert project is not None
        rate, capacity = _bucket(
            project.requests_per_minute * self.fractions[consumer], REQUEST_BURST_S
        )
        return {"rate_per_s": rate, "capacity": capacity}

    def daily_limit(self, consumer: str) -> int:
        """Provider calls the consumer may send per Pacific day."""
        assert self._project is not None
        return _whole(self.fractions[consumer] * self._project.requests_per_day)

    def monthly_limit_usd(self, consumer: str) -> float:
        """What the consumer may spend per Pacific month."""
        assert self._project is not None
        return self.fractions[consumer] * self._project.monthly_spend_cap_usd

    def daily_refusal(self, consumer: str) -> QuotaRefusal | None:
        """The consumer's calls sent today are at its share of the project's daily count."""
        if not self._applies(consumer):
            return None
        wall = self._wall_clock()
        limit = self.daily_limit(consumer)
        if self._store().requests(self._key("nd", consumer), pacific_day_key(wall)) < limit:
            return None
        return QuotaRefusal(
            CAUSE_CONSUMER,
            seconds_until_pacific_midnight(wall),
            f"quota_exhausted: the {consumer} allowance of {limit} requests a day "
            f"({self.fractions[consumer]:.0%} of the project's) is used up until midnight "
            "Pacific; model not called",
            exhausted=True,
            limit=ALLOWANCE_REQUESTS_PER_DAY,
        )

    def monthly_refusal(self, consumer: str) -> QuotaRefusal | None:
        """The consumer's spend this month is at its share of the project's cap."""
        if not self._applies(consumer):
            return None
        wall = self._wall_clock()
        limit = self.monthly_limit_usd(consumer)
        if self._store().spend(self._key("nm", consumer), pacific_month_key(wall)) < limit:
            return None
        return QuotaRefusal(
            CAUSE_CONSUMER,
            seconds_until_pacific_month_start(wall),
            f"quota_exhausted: the {consumer} allowance of ${limit:g} of monthly spend "
            f"({self.fractions[consumer]:.0%} of the project's cap) is used up until the 1st "
            "(Pacific); model not called",
            exhausted=True,
            limit=ALLOWANCE_MONTHLY_SPEND,
        )

    def charge(
        self, *, tenant_id: str, tier: str | None, consumer: str, tokens: int, now: float
    ) -> QuotaCharge | QuotaRefusal:
        """Take one call's allowances: the day's and the month's are checked, then one request
        and the call's tokens are taken from the minute buckets, and its cost is added to the
        month. Nothing is taken when it is refused. A production call takes nothing."""
        if not self._applies(consumer):
            return QuotaCharge(tenant_id, tier or "", consumer)  # nothing to enforce
        if (refusal := self.daily_refusal(consumer)) is not None:
            return refusal
        if (refusal := self.monthly_refusal(consumer)) is not None:
            return refusal
        store = self._store()
        fraction = self.fractions[consumer]
        requests = self._request_bucket(consumer)
        r_key = self._key("nr", consumer)
        wait = store.acquire(r_key, 1, now=now, **requests)
        if wait > 0:
            return QuotaRefusal(
                CAUSE_CONSUMER,
                wait,
                f"token_rate: the {consumer} allowance of {fraction:.0%} of the project's "
                "requests a minute is spent; model not called",
                limit=ALLOWANCE_REQUESTS_PER_MINUTE,
            )
        bucket = self._token_bucket(consumer)
        reserve = max(1, min(tokens, int(bucket["capacity"])))
        wait = store.acquire(self._key("np", consumer), reserve, now=now, **bucket)
        if wait > 0:
            store.adjust(r_key, -1, now=now, **requests)  # give the request back
            return QuotaRefusal(
                CAUSE_CONSUMER,
                wait,
                f"token_rate: the {consumer} allowance of {fraction:.0%} of the project's "
                "token rate is spent; model not called",
                limit=ALLOWANCE_TOKENS,
            )
        month = pacific_month_key(self._wall_clock())
        store.add_spend(self._key("nm", consumer), month, self._usd(reserve))
        return QuotaCharge(tenant_id, tier or "", consumer, tokens=reserve, requests=1, month=month)

    def _usd(self, tokens: float) -> float:
        assert self._project is not None
        return tokens * self._project.price_per_million_input_tokens_usd / 1_000_000

    def refund(self, charge: QuotaCharge, *, now: float) -> None:
        """The call was never sent: give back its tokens, its request and its cost."""
        if not self._applies(charge.consumer) or not charge.month:
            return
        store = self._store()
        if charge.tokens:
            store.adjust(
                self._key("np", charge.consumer),
                -charge.tokens,
                now=now,
                **self._token_bucket(charge.consumer),
            )
            store.add_spend(
                self._key("nm", charge.consumer), charge.month, -self._usd(charge.tokens)
            )
        if charge.requests:
            store.adjust(
                self._key("nr", charge.consumer),
                -charge.requests,
                now=now,
                **self._request_bucket(charge.consumer),
            )

    def reconcile(self, charge: QuotaCharge, actual_tokens: int, *, now: float) -> None:
        """Correct the tokens (and their cost) taken with the provider's usage."""
        if not self._applies(charge.consumer) or not charge.month:
            return
        delta = actual_tokens - charge.tokens
        if not delta:
            return
        store = self._store()
        store.adjust(
            self._key("np", charge.consumer), delta, now=now, **self._token_bucket(charge.consumer)
        )
        store.add_spend(self._key("nm", charge.consumer), charge.month, self._usd(delta))

    def count_sent(self, charge: QuotaCharge) -> tuple[QuotaCrossing, ...]:
        """Count the consumer's call that was actually sent against its day. Once per check."""
        if not self._applies(charge.consumer) or not charge.month or charge.counted:
            return ()
        charge.counted = True
        self._store().count_request(
            self._key("nd", charge.consumer), pacific_day_key(self._wall_clock())
        )
        return ()


class QuotaLimiter:
    """Tenant shares and consumer allowances over a shared store. Synchronous, no awaits.
    ``store`` is a callable so a store swapped into the project's limiter is followed."""

    def __init__(
        self,
        config: QuotaConfig,
        store: Callable[[], TokenRateStore],
        *,
        project_id: str = "default",
        project: TokenRateConfig | None = None,
        wall_clock: Callable[[], datetime],
    ) -> None:
        self.config = config
        self._store = store
        self.project_id = project_id
        self._project = project
        self._wall_clock = wall_clock
        self.allowances = ConsumerAllowances(
            config.non_production,
            store,
            project_id=project_id,
            project=project,
            wall_clock=wall_clock,
        )
        """The non-production consumers' allowances (needs ``project``)."""

    # keys

    def _key(self, kind: str, name: str) -> str:
        return f"tq:{kind}:{self.project_id}:{name}"

    def _tenant_buckets(self, quota: TierQuota) -> tuple[dict, dict]:
        burst = self.config.burst_capacity_s
        t_rate, t_cap = _tenant_bucket(quota.tokens_per_minute, burst)
        c_rate, c_cap = _tenant_bucket(quota.checks_per_minute, burst)
        # Never smaller than the largest single check (all its chunks), so a check is never
        # too big for the bucket whatever the share.
        t_cap = max(t_cap, float(self.config.largest_check_tokens))
        c_cap = max(c_cap, float(self.config.largest_check_calls))  # one check a chunk
        return (
            {"rate_per_s": t_rate, "capacity": t_cap},
            {"rate_per_s": c_rate, "capacity": c_cap},
        )

    # entry

    def daily_refusal(self, tenant_id: str, tier: str | None) -> QuotaRefusal | None:
        """The tenant's daily share is used up (a production tenant's calls sent today)."""
        quota = self.config.limits_for(tenant_id, tier)
        wall = self._wall_clock()
        used = self._store().requests(self._key("d", tenant_id), pacific_day_key(wall))
        if used < quota.requests_per_day:
            return None
        return QuotaRefusal(
            CAUSE_TENANT_DAILY,
            seconds_until_pacific_midnight(wall),
            f"quota_exhausted: the tenant's share of {quota.requests_per_day} requests a day "
            "is used up until midnight Pacific; model not called",
        )

    def charge(
        self, *, tenant_id: str, tier: str | None, consumer: str, tokens: int, now: float
    ) -> QuotaCharge | QuotaRefusal:
        """Take one check's share: from the tenant's token and check buckets (production), or
        the consumer's allowances (non-production, :class:`ConsumerAllowances`). Nothing is
        taken when it is refused."""
        store = self._store()
        tier_name = tier or self.config.default_tier
        if consumer != USAGE_PRODUCTION:
            return self.allowances.charge(
                tenant_id=tenant_id, tier=tier_name, consumer=consumer, tokens=tokens, now=now
            )
        quota = self.config.limits_for(tenant_id, tier)
        if (refusal := self.daily_refusal(tenant_id, tier)) is not None:
            return refusal
        tokens_bucket, checks_bucket = self._tenant_buckets(quota)
        reserve = max(1, min(tokens, int(tokens_bucket["capacity"])))
        t_key, c_key = self._key("t", tenant_id), self._key("c", tenant_id)
        wait = store.acquire(t_key, reserve, now=now, **tokens_bucket)
        if wait > 0:
            return QuotaRefusal(
                CAUSE_TENANT_TOKENS,
                wait,
                f"token_rate: the tenant's share of {quota.tokens_per_minute} tokens a minute is "
                "spent; model not called",
            )
        wait = store.acquire(c_key, 1, now=now, **checks_bucket)
        if wait > 0:
            store.adjust(t_key, -reserve, now=now, **tokens_bucket)  # give the tokens back
            return QuotaRefusal(
                CAUSE_TENANT_CHECKS,
                wait,
                f"token_rate: the tenant's share of {quota.checks_per_minute} checks a minute is "
                "spent; model not called",
            )
        return QuotaCharge(tenant_id, tier_name, USAGE_PRODUCTION, reserve, 1, quota)

    def refund(self, charge: QuotaCharge, *, now: float) -> None:
        """The call was never sent: give back what the check took."""
        if charge.consumer != USAGE_PRODUCTION:
            self.allowances.refund(charge, now=now)
            return
        self._adjust(charge, -charge.tokens, -charge.checks, now)

    def reconcile(self, charge: QuotaCharge, actual_tokens: int, *, now: float) -> None:
        """Correct the tokens taken with the provider's usage."""
        if charge.consumer != USAGE_PRODUCTION:
            self.allowances.reconcile(charge, actual_tokens, now=now)
        elif actual_tokens != charge.tokens:
            self._adjust(charge, actual_tokens - charge.tokens, 0, now)

    def _adjust(self, charge: QuotaCharge, token_delta: int, check_delta: int, now: float) -> None:
        store = self._store()
        if charge.quota is None:
            return
        tokens_bucket, checks_bucket = self._tenant_buckets(charge.quota)
        if token_delta:
            store.adjust(self._key("t", charge.tenant_id), token_delta, now=now, **tokens_bucket)
        if check_delta:
            store.adjust(self._key("c", charge.tenant_id), check_delta, now=now, **checks_bucket)

    def count_sent(self, charge: QuotaCharge) -> tuple[QuotaCrossing, ...]:
        """Count the tenant's call that was actually sent against its daily share. Once per
        check; the 80% and 100% crossings it caused."""
        if charge.consumer != USAGE_PRODUCTION:
            return self.allowances.count_sent(charge)
        if charge.quota is None or charge.counted:
            return ()
        charge.counted = True
        count = self._store().count_request(
            self._key("d", charge.tenant_id), pacific_day_key(self._wall_clock())
        )
        limit = charge.quota.requests_per_day
        return tuple(
            QuotaCrossing(charge.tenant_id, threshold, count, limit)
            for threshold in ALERT_THRESHOLDS
            if count - 1 < threshold * limit <= count
        )

    # reading

    def status(self, tenant_id: str, tier: str | None, *, now: float) -> TenantQuotaStatus:
        """The tenant's usage against its share now."""
        store = self._store()
        quota = self.config.limits_for(tenant_id, tier)
        tokens_bucket, checks_bucket = self._tenant_buckets(quota)
        return TenantQuotaStatus(
            tenant_id=tenant_id,
            tier=tier or self.config.default_tier,
            weight=quota.weight,
            tokens_available=store.level(self._key("t", tenant_id), now=now, **tokens_bucket),
            tokens_capacity=tokens_bucket["capacity"],
            tokens_per_minute=quota.tokens_per_minute,
            checks_available=store.level(self._key("c", tenant_id), now=now, **checks_bucket),
            checks_capacity=checks_bucket["capacity"],
            checks_per_minute=quota.checks_per_minute,
            requests_today=store.requests(
                self._key("d", tenant_id), pacific_day_key(self._wall_clock())
            ),
            requests_per_day=quota.requests_per_day,
        )
