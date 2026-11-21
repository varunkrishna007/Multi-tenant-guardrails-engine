"""M0-03: the capacity model. Pure arithmetic, no calls. Google's figures are those read from
its documentation on 2026-11-17 (see capacity/README.md); the formulas are checked by hand."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from capacity.model import (
    CONSUMERS,
    TIERS,
    Consumer,
    Workload,
    capacity,
    crossover_tokens,
    pacific_day,
    production_budget,
    shadow_multiplier,
    tier,
    tokens_for_dollars,
)

from capacity import model

README = Path(__file__).resolve().parents[2] / "capacity" / "README.md"


# ------------------------------------------------------------------ Google's figures


def test_the_tiers_are_googles_decision_1_table():
    """Gemini Decision 1 (Decisions API): RPM / TPM / RPD, the spend limit per 10 minutes and
    the monthly billing cap, as published on the rate-limits and billing pages."""
    got = {t.name: (t.rpm, t.tpm, t.rpd, t.spend_per_10_min_usd, t.monthly_cap_usd) for t in TIERS}
    assert got == {
        "Free": (200, 50_000, 10_000, None, None),
        "Tier 1": (1_500, 1_000_000, 50_000, 10.0, 250.0),
        "Tier 2": (5_000, 4_000_000, None, 200.0, 2_000.0),
        "Tier 3": (15_000, 10_000_000, None, 200.0, 20_000.0),
    }
    assert model.PRICE_PER_MILLION_INPUT_TOKENS_USD == 0.10


def test_the_documentation_urls_are_google_pages():
    assert all(u.startswith("https://ai.google.dev/gemini-api/docs/") for u in model.DOCS.values())


# ------------------------------------------------------------------ the arithmetic


def test_tier_1_at_five_checks_of_4000_tokens_by_hand():
    c = capacity(tier("Tier 1"), Workload(5, 4_000))
    by_name = {x.name: x.turns for x in c.per_minute + c.per_day}
    assert by_name["requests/min"] == 1_500 / 5 == 300
    assert by_name["tokens/min"] == 1_000_000 / (5 * 4_000) == 50
    assert by_name["spend/10 min"] == 10_000_000 / 20_000 == 500  # $10 buys 100M tokens
    assert by_name["requests/day"] == 50_000 / 5 == 10_000
    assert by_name["tokens/min x 1,440"] == 1_440_000_000 / 20_000 == 72_000
    assert by_name["monthly spend cap"] == pytest.approx(2_500_000_000 / 30 / 20_000)  # 4,167
    assert c.binding_minute.name == "tokens/min" and c.turns_per_minute == 50
    assert c.binding_day.name == "monthly spend cap" and round(c.turns_per_day) == 4_167
    assert c.sustained_turns_per_minute == pytest.approx(2.894, abs=1e-3)


def test_tokens_per_minute_binds_per_minute_unless_checks_are_tiny():
    t = tier("Tier 1")
    assert model.requests_binding_minute_below(t) == pytest.approx(666.67, abs=0.01)
    assert capacity(t, Workload(5, 600)).binding_minute.name == "requests/min"
    assert capacity(t, Workload(5, 700)).binding_minute.name == "tokens/min"


def test_the_monthly_cap_overtakes_the_daily_request_cap_above_1667_tokens():
    """Below it requests/day binds; above it the $250 cap on spend does."""
    t = tier("Tier 1")
    assert crossover_tokens(t) == pytest.approx(1_666.67, abs=0.01)
    assert capacity(t, Workload(5, 850)).binding_day.name == "requests/day"
    assert capacity(t, Workload(5, 1_600)).binding_day.name == "requests/day"
    assert capacity(t, Workload(5, 1_700)).binding_day.name == "monthly spend cap"
    assert crossover_tokens(tier("Tier 2")) is None  # no daily request limit at Tier 2


def test_the_spend_per_10_minutes_limit_cannot_bind_at_google_prices():
    """At the token limit the most that can be spent in 10 minutes is $1, against $10."""
    for t in TIERS[1:]:
        spend = t.tpm * model.SPEND_WINDOW_MINUTES * model.PRICE_PER_MILLION_INPUT_TOKENS_USD / 1e6
        assert spend < t.spend_per_10_min_usd
        c = capacity(t, Workload())
        assert c.binding_minute.name != "spend/10 min"


def test_a_retry_counts_against_every_limit():
    base = capacity(tier("Tier 1"), Workload(5, 4_000, 0.0))
    retried = capacity(tier("Tier 1"), Workload(5, 4_000, 0.05))
    assert retried.turns_per_minute == pytest.approx(base.turns_per_minute / 1.05)
    assert retried.turns_per_day == pytest.approx(base.turns_per_day / 1.05)


def test_tool_loops_cost_two_checks_each():
    one = capacity(tier("Tier 1"), Workload(5, 4_000))
    three = capacity(tier("Tier 1"), Workload(3 + 2 * 3, 4_000))
    assert three.turns_per_minute == pytest.approx(one.turns_per_minute * 5 / 9)


def test_moving_up_a_tier_lifts_both_axes():
    w = Workload(5, 4_000)
    t1, t2, t3 = (capacity(tier(n), w) for n in ("Tier 1", "Tier 2", "Tier 3"))
    assert (t1.turns_per_minute, t2.turns_per_minute, t3.turns_per_minute) == (50, 200, 500)
    assert t2.turns_per_day > 7 * t1.turns_per_day  # the daily request cap goes away
    assert [x.name for x in t2.per_day].count("requests/day") == 0
    assert tokens_for_dollars(250) == 2_500_000_000


# ------------------------------------------------------------------ non-production


def test_non_production_shares_the_one_projects_quota():
    avg_checks, avg_tokens = model.nonproduction_per_day()
    assert avg_checks == pytest.approx(sum(c.checks_per_month() for c in CONSUMERS) / 30)
    assert 600 < avg_checks < 700  # about 1.3% of the daily request cap
    bad_checks, bad_tokens = model.peak_nonproduction_day()
    assert bad_checks == 5_000 + 2_346  # the two largest single runs on one day
    assert bad_tokens > 20 * avg_tokens  # the average hides the bad day


def test_the_measured_consumers_match_the_plan_output():
    by = {c.name: c for c in CONSUMERS}
    assert by["Calibration, golden set (R7.4 rerun)"].checks_per_run == 3 * 339
    assert by["Calibration, held-out validation (R7.3(c))"].checks_per_run == 3 * 782
    assert by["Demo regeneration"].checks_per_run == 45


def test_production_budget_is_the_cap_less_non_production_in_the_binding_unit():
    c = capacity(tier("Tier 1"), Workload(5, 850))  # requests/day binds
    b = production_budget(c)
    assert b.binding.name == "requests/day"
    assert b.target == 0.70 * 50_000
    assert b.production_turns_per_day == pytest.approx((35_000 - b.nonproduction_amount) / 5)
    spend_bound = production_budget(capacity(tier("Tier 1"), Workload(5, 4_000)))
    assert spend_bound.binding.unit == "tokens"
    expected = (0.7 * 2_500_000_000 / 30 - spend_bound.nonproduction_amount) / 20_000
    assert spend_bound.production_turns_per_day == pytest.approx(expected)
    assert production_budget(c, peak=True).production_turns_per_day < b.production_turns_per_day


def test_a_shadow_candidate_at_100_percent_halves_production_headroom():
    """PF-7: the candidate is evaluated on top of the active version (a floor release starts
    every tenant's at 100% for 72 hours)."""
    assert shadow_multiplier(100) == 2 and shadow_multiplier(25) == 1.25
    b = production_budget(capacity(tier("Tier 1"), Workload()))
    assert b.during_shadow() == pytest.approx(b.production_turns_per_day / 2)
    assert b.during_shadow(0) == b.production_turns_per_day


def test_production_budget_never_goes_negative():
    huge = (Consumer("flood", 10_000_000, 1, 850, "assumed"),)
    b = production_budget(capacity(tier("Tier 1"), Workload()), consumers=huge)
    assert b.production_turns_per_day == 0


# ------------------------------------------------------------------ Google's daily window


def utc(*args: int) -> datetime:
    return datetime(*args, tzinfo=UTC)


def test_the_daily_quota_resets_at_midnight_pacific_not_utc():
    """08:00 UTC in winter (PST), 07:00 UTC in summer (PDT)."""
    assert pacific_day(utc(2026, 11, 17, 14, 0)) == (utc(2026, 11, 17, 8), utc(2026, 11, 18, 8))
    # 03:00 UTC on 1 July is still 30 June in Pacific time.
    assert pacific_day(utc(2026, 7, 1, 3, 0)) == (utc(2026, 6, 30, 7), utc(2026, 7, 1, 7))
    assert pacific_day(utc(2026, 11, 17, 7, 59))[0] == utc(2026, 11, 16, 8)


def test_the_pacific_day_is_23_hours_when_the_clocks_go_forward():
    start, end = pacific_day(datetime(2026, 3, 8, 20, 0, tzinfo=UTC))
    assert (end - start).total_seconds() == 23 * 3600
    start, end = pacific_day(datetime(2026, 11, 1, 20, 0, tzinfo=UTC))
    assert (end - start).total_seconds() == 25 * 3600


def test_a_utc_day_rule_is_safe_but_a_pacific_counter_is_needed():
    """Two UTC days of 10,000 calls overlap one Pacific day by at most 20,000 < 50,000, so the
    working rule is safe. But the daily counter must roll at Pacific midnight."""
    assert tier("Tier 1").rpd > 2 * 10_000


# ------------------------------------------------------------------ the document


def test_the_readme_embeds_the_current_tables():
    """The document's tables are the model's output: change an input and this fails until
    ``python -m capacity.model`` is pasted between the markers."""
    text = README.read_text()
    start, end = "<!-- tables:start -->", "<!-- tables:end -->"
    assert start in text and end in text
    embedded = text.split(start, 1)[1].split(end, 1)[0].strip()
    assert embedded == model.tables().strip()
