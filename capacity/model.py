"""M0-03 capacity model for the Decisions API quota path. Pure arithmetic: no I/O, no calls.

    uv run python -m capacity.model                      # the tables in capacity/README.md
    uv run python -m capacity.model --tier "Tier 2" --tokens 4000 --checks-per-turn 5

Every figure of Google's comes from its own documentation (``DOCS``), read on 2026-11-17, and
is quoted in ``capacity/README.md``. Nothing here is measured against the live API. The
planning inputs (checks per turn, tokens per check, the non-production workload) are
assumptions, labelled as such in the README, and are parameters of every function.

**Five limits, not three.** The story names requests/min, tokens/min and requests/day.
Google's pages add two more that apply to the Decisions API: a spend limit per rolling 10
minutes, and a monthly spend cap on the billing account. At Google's price both are computed
here, because the monthly cap can bind first at Tier 1.

**Units.** A *check* is one Decisions API request (one guard point). A *turn* is
``checks_per_turn`` checks: five at one tool call (input, plan, tool_call, tool_result,
output), ``3 + 2 * tool_calls`` in general. Tokens are API input tokens, questions included
(``usage.total_input_tokens``): the only billed tokens, since output is always 0.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from zoneinfo import ZoneInfo

DOCS = {
    "rate_limits": "https://ai.google.dev/gemini-api/docs/rate-limits",
    "billing": "https://ai.google.dev/gemini-api/docs/billing",
    "pricing": "https://ai.google.dev/gemini-api/docs/pricing",
    "decision_model": "https://ai.google.dev/gemini-api/docs/models/gemini-decision-1",
    "decisions_api": "https://ai.google.dev/gemini-api/docs/decisions-api",
}
"""Each redirects (301) to the same path on ``aistudio.google.com/docs/``, which is where the
text was read on 2026-11-17."""

PRICE_PER_MILLION_INPUT_TOKENS_USD = 0.10
"""Gemini Decision 1, paid tier, standard. Input only: output is always 0 tokens, shared
input is billed once per request whatever the number of questions, and there is no context
caching, so repeated input is billed in full."""

MINUTES_PER_DAY = 24 * 60
SPEND_WINDOW_MINUTES = 10
DAYS_PER_MONTH = 30
PACIFIC = ZoneInfo("America/Los_Angeles")
"""Google resets the requests-per-day quota at midnight Pacific time."""


@dataclass(frozen=True)
class Tier:
    """One usage tier's limits for Gemini Decision 1 (Google's rate-limits page)."""

    name: str
    rpm: int
    tpm: int
    rpd: int | None
    """None is Google's "Unlimited"."""
    spend_per_10_min_usd: float | None
    """The spend-based rate limit, per rolling 10 minutes. None where Google gives N/A."""
    monthly_cap_usd: float | None
    """The billing tier cap per month, enforced on the billing account across every linked
    project with the Gemini API enabled. Tier 3's is "$20,000 - $100,000+": its lower bound."""


TIERS = (
    Tier("Free", 200, 50_000, 10_000, None, None),
    Tier("Tier 1", 1_500, 1_000_000, 50_000, 10.0, 250.0),
    Tier("Tier 2", 5_000, 4_000_000, None, 200.0, 2_000.0),
    Tier("Tier 3", 15_000, 10_000_000, None, 200.0, 20_000.0),
)
"""The Free tier's data may be used to improve Google's products, so production is paid tier
only (design, Multi-tenancy). It is listed for completeness."""


def tier(name: str) -> Tier:
    return next(t for t in TIERS if t.name.lower() == name.lower())


@dataclass(frozen=True)
class Workload:
    """What one turn costs the quota."""

    checks_per_turn: float = 5.0
    """Input, plan, tool_call, tool_result, output. A tool loop adds 2 per extra tool call,
    and a ``tool_result`` over ``chunk_tokens`` is one check per chunk."""
    tokens_per_check: int = 4_000
    """API input tokens per check, questions included. PF-4's planning figure."""
    retry_rate: float = 0.0
    """Extra provider requests per check from the gateway's one retry. They count against
    every limit (a timed-out call may still be billed). The alert fires above 0.05."""

    @property
    def requests_per_turn(self) -> float:
        return self.checks_per_turn * (1 + self.retry_rate)

    @property
    def tokens_per_turn(self) -> float:
        return self.requests_per_turn * self.tokens_per_check


@dataclass(frozen=True)
class Limit:
    """One limit, as the most turns it allows per minute or per day."""

    name: str
    turns: float | None
    """None when the tier has no such limit."""
    unit: str
    """What the limit counts: ``requests`` or ``tokens``."""
    amount: float | None
    """The limit itself, in ``unit`` per minute or per day."""


@dataclass(frozen=True)
class Capacity:
    tier: Tier
    workload: Workload
    per_minute: tuple[Limit, ...]
    per_day: tuple[Limit, ...]

    @property
    def binding_minute(self) -> Limit:
        return binding(self.per_minute)

    @property
    def binding_day(self) -> Limit:
        return binding(self.per_day)

    @property
    def turns_per_minute(self) -> float:
        return self.binding_minute.turns or 0.0

    @property
    def turns_per_day(self) -> float:
        return self.binding_day.turns or 0.0

    @property
    def sustained_turns_per_minute(self) -> float:
        """The daily binding limit spread over a day: what continuous traffic can average."""
        return self.turns_per_day / MINUTES_PER_DAY


def binding(limits: Sequence[Limit]) -> Limit:
    """The limit that allows the fewest turns."""
    return min((x for x in limits if x.turns is not None), key=lambda x: x.turns or 0.0)


def tokens_for_dollars(dollars: float) -> float:
    return dollars / PRICE_PER_MILLION_INPUT_TOKENS_USD * 1_000_000


def capacity(t: Tier, w: Workload, days_in_month: int = DAYS_PER_MONTH) -> Capacity:
    """Every limit that applies to ``t``, in turns per minute and per day under ``w``."""
    rpt, tpt = w.requests_per_turn, w.tokens_per_turn
    per_minute = [
        Limit("requests/min", t.rpm / rpt, "requests", t.rpm),
        Limit("tokens/min", t.tpm / tpt, "tokens", t.tpm),
    ]
    if t.spend_per_10_min_usd is not None:
        tokens_per_min = tokens_for_dollars(t.spend_per_10_min_usd) / SPEND_WINDOW_MINUTES
        per_minute.append(Limit("spend/10 min", tokens_per_min / tpt, "tokens", tokens_per_min))
    per_day = [Limit("tokens/min x 1,440", t.tpm * MINUTES_PER_DAY / tpt, "tokens",
                     t.tpm * MINUTES_PER_DAY)]  # fmt: skip
    if t.rpd is not None:
        per_day.insert(0, Limit("requests/day", t.rpd / rpt, "requests", t.rpd))
    if t.monthly_cap_usd is not None:
        tokens_per_day = tokens_for_dollars(t.monthly_cap_usd) / days_in_month
        per_day.append(Limit("monthly spend cap", tokens_per_day / tpt, "tokens", tokens_per_day))
    return Capacity(t, w, tuple(per_minute), tuple(per_day))


def crossover_tokens(t: Tier, days_in_month: int = DAYS_PER_MONTH) -> float | None:
    """The tokens per check above which the monthly spend cap allows fewer checks per day
    than the requests/day limit: below it the daily request cap binds, above it the cap on
    spend does. None without both limits."""
    if t.rpd is None or t.monthly_cap_usd is None:
        return None
    return tokens_for_dollars(t.monthly_cap_usd) / days_in_month / t.rpd


def requests_binding_minute_below(t: Tier) -> float:
    """Tokens per check below which requests/min, not tokens/min, binds per minute."""
    return t.tpm / t.rpm


# --------------------------------------------------------------------------- non-production


@dataclass(frozen=True)
class Consumer:
    """A non-production consumer of the one project's quota (tests, calibration, red-team,
    shadow candidates, tenant tests, benchmarks). All of them count against the same limits as
    production, because Google applies limits per project and there is one project."""

    name: str
    checks_per_run: int
    runs_per_month: float
    tokens_per_check: int
    basis: str
    """Where the figures come from: ``measured`` (the repo's own plan output or runs) or
    ``assumed`` (a planning figure, to be replaced by dogfood data)."""

    def checks_per_month(self) -> float:
        return self.checks_per_run * self.runs_per_month

    def tokens_per_month(self) -> float:
        return self.checks_per_month() * self.tokens_per_check

    def checks_per_day(self, days_in_month: int = DAYS_PER_MONTH) -> float:
        return self.checks_per_month() / days_in_month

    def tokens_per_day(self, days_in_month: int = DAYS_PER_MONTH) -> float:
        return self.tokens_per_month() / days_in_month


CONSUMERS = (
    Consumer(
        "Calibration, golden set (R7.4 rerun)", 1_017, 2, 822,
        "measured: plan output, 3 draws of 339",
    ),
    Consumer(
        "Calibration, held-out validation (R7.3(c))", 2_346, 2, 2_896,
        "measured: plan output, 3 draws of 782",
    ),
    Consumer("Red-team recall run (M2-08)", 1_000, 2, 850, "assumed: corpus size not yet defined"),
    Consumer("Live tests and live gates", 200, 20, 850, "assumed"),
    Consumer("Tenant test endpoint (M2-05), one partner", 500, 4, 850, "assumed"),
    Consumer(
        "Benchmarks and load tests (M0-01, M3-09)", 5_000, 1, 6_455,
        "assumed: M0-01 made about 3,100 calls",
    ),
    Consumer("Demo regeneration", 45, 2, 850, "measured: demo plan, 45 live checks"),
)  # fmt: skip
"""Shadow candidates are not here: they are a multiplier on production (``shadow_multiplier``)."""


def nonproduction_per_day(
    consumers: Sequence[Consumer] = CONSUMERS, days_in_month: int = DAYS_PER_MONTH
) -> tuple[float, float]:
    """(checks per day, tokens per day), averaged over a month."""
    return (
        sum(c.checks_per_day(days_in_month) for c in consumers),
        sum(c.tokens_per_day(days_in_month) for c in consumers),
    )


def peak_nonproduction_day(consumers: Sequence[Consumer] = CONSUMERS) -> tuple[float, float]:
    """(checks, tokens) on a day that runs the two largest single runs together: the bad day
    that matters for the daily cap, since an average hides it."""
    biggest = sorted(consumers, key=lambda c: c.checks_per_run, reverse=True)[:2]
    return (
        float(sum(c.checks_per_run for c in biggest)),
        float(sum(c.checks_per_run * c.tokens_per_check for c in biggest)),
    )


def shadow_multiplier(rollout_percent: float = 100.0) -> float:
    """A candidate in shadow is evaluated on ``rollout_percent`` of conversations on top of
    the active version (PF-7), so production's requests and tokens are multiplied by this
    while the window lasts (72 hours by default; a floor release starts every tenant's
    candidate at 100%)."""
    return 1 + rollout_percent / 100


@dataclass(frozen=True)
class Budget:
    """What production may use of the daily binding limit once non-production has its share."""

    binding: Limit
    limit_amount: float
    target: float
    nonproduction_amount: float
    production_amount: float
    production_turns_per_day: float
    production_turns_per_minute: float

    def during_shadow(self, rollout_percent: float = 100.0) -> float:
        """Production turns per day while a shadow candidate duplicates its checks."""
        return self.production_turns_per_day / shadow_multiplier(rollout_percent)


def production_budget(
    cap: Capacity,
    consumers: Sequence[Consumer] = CONSUMERS,
    utilisation: float = 0.70,
    days_in_month: int = DAYS_PER_MONTH,
    peak: bool = False,
) -> Budget:
    """The onboarding cap (S3): ``utilisation`` of the daily binding limit, less what
    non-production uses of the same limit, in that limit's own unit. ``peak`` takes the bad
    non-production day instead of the monthly average."""
    lim = cap.binding_day
    assert lim.amount is not None
    if peak:
        checks, tokens = peak_nonproduction_day(consumers)
    else:
        checks, tokens = nonproduction_per_day(consumers, days_in_month)
    used = checks if lim.unit == "requests" else tokens
    target = utilisation * lim.amount
    production = max(0.0, target - used)
    per_turn = (
        cap.workload.requests_per_turn if lim.unit == "requests" else cap.workload.tokens_per_turn
    )
    turns = production / per_turn
    return Budget(lim, lim.amount, target, used, production, turns, turns / MINUTES_PER_DAY)


# --------------------------------------------------------------------------- the daily window


def pacific_day(now: datetime) -> tuple[datetime, datetime]:
    """The Pacific-time day containing ``now`` as (start, end) in UTC. Google's requests-per-day
    quota resets at the start of it: 08:00 UTC in winter, 07:00 UTC in summer. The day is 23, 24
    or 25 hours long on the two daylight-saving changes."""
    local = now.astimezone(PACIFIC)
    start = datetime(local.year, local.month, local.day, tzinfo=PACIFIC)
    end = datetime.combine(local.date() + timedelta(days=1), datetime.min.time(), tzinfo=PACIFIC)
    return start.astimezone(UTC), end.astimezone(UTC)


# --------------------------------------------------------------------------- the tables

SHAPES = (
    ("short, golden-sized", 850),
    ("held-out mix, mean", 2_900),
    ("PF-4 planning figure", 4_000),
    ("4K x 12 benchmark shape", 6_455),
    ("held-out long contexts, p95", 14_100),
)
"""Tokens per check. 850 and 2,900 are measured with the engine's own renderer and estimator
(golden mean 822, held-out mean 2,896, p95 14,121); 4,000 is PF-4's; 6,455 is the R6.3
benchmark shape's API tokens."""


def fmt(x: float | None, digits: int = 0) -> str:
    return "unlimited" if x is None else f"{x:,.{digits}f}"


def tier_table() -> str:
    rows = ["| Tier | Requests/min | Tokens/min | Requests/day | Spend per 10 min | Monthly cap |",
            "|---|--:|--:|--:|--:|--:|"]  # fmt: skip
    for t in TIERS:
        spend = "n/a" if t.spend_per_10_min_usd is None else f"${t.spend_per_10_min_usd:,.0f}"
        cap = (
            "n/a"
            if t.monthly_cap_usd is None
            else f"${t.monthly_cap_usd:,.0f}" + ("+" if t.name == "Tier 3" else "")
        )
        rows.append(f"| {t.name} | {t.rpm:,} | {t.tpm:,} | {fmt(t.rpd)} | {spend} | {cap} |")
    return "\n".join(rows)


def shape_table(t: Tier, w: Workload) -> str:
    rows = [
        "| Check size | Tokens/check | Binds per minute | Turns/min | Binds per day | Turns/day "
        "| Sustained turns/min |",
        "|---|--:|---|--:|---|--:|--:|",
    ]
    for label, tokens in SHAPES:
        c = capacity(t, replace(w, tokens_per_check=tokens))
        rows.append(
            f"| {label} | {tokens:,} | {c.binding_minute.name} | {c.turns_per_minute:,.0f} "
            f"| {c.binding_day.name} | {c.turns_per_day:,.0f} "
            f"| {c.sustained_turns_per_minute:,.1f} |"
        )
    return "\n".join(rows)


def tier_comparison_table(w: Workload) -> str:
    """What each paid tier allows at ``w``: the move up is the quota path."""
    rows = [
        "| Tier | Binds per minute | Turns/min | Binds per day | Turns/day | Sustained turns/min |",
        "|---|---|--:|---|--:|--:|",
    ]
    for t in TIERS[1:]:
        c = capacity(t, w)
        rows.append(
            f"| {t.name} | {c.binding_minute.name} | {c.turns_per_minute:,.0f} "
            f"| {c.binding_day.name} | {c.turns_per_day:,.0f} "
            f"| {c.sustained_turns_per_minute:,.1f} |"
        )
    return "\n".join(rows)


def limit_rows(t: Tier, w: Workload) -> str:
    c = capacity(t, w)
    rows = ["| Limit | Allows (turns) | Per |", "|---|--:|---|"]
    rows += [f"| {x.name} | {fmt(x.turns, 1)} | minute |" for x in c.per_minute]
    rows += [f"| {x.name} | {fmt(x.turns)} | day |" for x in c.per_day]
    return "\n".join(rows)


def consumer_table(consumers: Sequence[Consumer] = CONSUMERS) -> str:
    rows = [
        "| Consumer | Checks/run | Runs/month | Tokens/check | Checks/day (avg) | Basis |",
        "|---|--:|--:|--:|--:|---|",
    ]
    for c in consumers:
        rows.append(
            f"| {c.name} | {c.checks_per_run:,} | {c.runs_per_month:g} "
            f"| {c.tokens_per_check:,} | {c.checks_per_day():,.0f} | {c.basis} |"
        )
    checks, tokens = nonproduction_per_day(consumers)
    total = f"**{checks:,.0f}** | {tokens / 1e6:,.1f}M tokens/day"
    rows.append(f"| **Total, monthly average** | | | | {total} |")
    return "\n".join(rows)


def budget_table(t: Tier, w: Workload) -> str:
    rows = [
        "| Check size | Binding daily limit | Non-prod, average day | Production turns/day at 70% "
        "| During a 100% shadow window | Non-prod bad day |",
        "|---|---|--:|--:|--:|--:|",
    ]
    for label, tokens in SHAPES:
        c = capacity(t, replace(w, tokens_per_check=tokens))
        avg, bad = production_budget(c), production_budget(c, peak=True)
        rows.append(
            f"| {label} ({tokens:,}) | {avg.binding.name} "
            f"| {avg.nonproduction_amount:,.0f} {avg.binding.unit} "
            f"| {avg.production_turns_per_day:,.0f} | {avg.during_shadow():,.0f} "
            f"| {bad.production_turns_per_day:,.0f} |"
        )
    return "\n".join(rows)


def tables(name: str = "Tier 1", w: Workload | None = None) -> str:
    t, w = tier(name), w or Workload()
    xo = crossover_tokens(t)
    heading = (
        f"{t.name}, {w.checks_per_turn:g} checks per turn, retry rate {w.retry_rate:.0%}, "
        f"{w.tokens_per_check:,} tokens per check:"
    )
    crossover = ""
    if xo is not None:
        crossover = (
            f"The monthly cap binds before requests/day above {xo:,.0f} tokens per check "
            f"({t.name}); requests/min binds before tokens/min only below "
            f"{requests_binding_minute_below(t):,.0f} tokens per check."
        )
    return "\n\n".join(
        [
            tier_table(),
            heading + "\n\n" + limit_rows(t, w),
            shape_table(t, w),
            "Moving up a tier, at the same check size:\n\n" + tier_comparison_table(w),
            budget_table(t, w),
            consumer_table(),
            crossover,
        ]
    )


def main(argv: Sequence[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--tier", default="Tier 1")
    ap.add_argument("--tokens", type=int, default=4_000)
    ap.add_argument("--checks-per-turn", type=float, default=5.0)
    ap.add_argument("--retry-rate", type=float, default=0.0)
    args = ap.parse_args(argv)
    print(tables(args.tier, Workload(args.checks_per_turn, args.tokens, args.retry_rate)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
