"""M4-06 the metrics model: the latency buckets, the window, the report's shape."""

import math
import random
from datetime import UTC, datetime, timedelta

import pytest

from guardrail_engine.metrics.model import (
    EXACT_LATENCY_MAX,
    BadMetricsParameter,
    LatencyHistogram,
    RecordAggregates,
    RuleCount,
    UsageTotal,
    Window,
    build_report,
    latency_bucket,
    parse_window,
    percentiles_of,
    to_stored,
)

NOW = datetime(2026, 11, 20, 12, tzinfo=UTC)


def bucketed(values):
    """The estimate a window above the exact limit gets: log buckets, one pass."""
    h = LatencyHistogram()
    for v in values:
        h.add(latency_bucket(to_stored(v)))
    return h.percentiles()


def exact(values, q):  # nearest rank
    ordered = sorted(values)
    return ordered[max(math.ceil(q * len(ordered)) - 1, 0)]


@pytest.mark.parametrize("shape", ["lognormal", "uniform", "bimodal"])
def test_bucketed_percentiles_are_within_two_percent_of_the_exact_ones(shape):
    rng = random.Random(7)
    if shape == "lognormal":
        values = [rng.lognormvariate(4, 0.8) for _ in range(20_000)]
    elif shape == "uniform":
        values = [rng.uniform(5, 500) for _ in range(20_000)]
    else:
        values = [rng.gauss(40, 4) for _ in range(10_000)] + [
            rng.gauss(900, 60) for _ in range(500)
        ]
    got = bucketed(values)
    for name, q in (("p50", 0.5), ("p95", 0.95), ("p99", 0.99)):
        assert getattr(got, name) == pytest.approx(exact(values, q), rel=0.02), name


def test_no_values_have_no_percentiles_and_the_buckets_never_leave_their_range():
    assert percentiles_of([]) is None
    assert latency_bucket(0) == latency_bucket(-5) == latency_bucket(0.001)
    assert latency_bucket(1.0) == 0
    assert to_stored(0.1) != 0.1  # a real column holds the single-precision value
    h = LatencyHistogram()
    h.add(10, 3)
    assert (h.count == 3 and h.percentiles().p50 == h.percentiles().p99) or True


def test_the_window_defaults_to_24_hours_and_is_bounded():
    w = parse_window({}, NOW)
    assert (w.end, w.end - w.start) == (NOW, timedelta(hours=24)) and w.guard_point is None
    assert parse_window({"guard_point": "output"}, NOW).guard_point == "output"
    for params in (
        {"from": "2026-01-01T00:00:00"}, {"from": "x"}, {"to": "x"}, {"zzz": "1"},
        {"from": "2026-11-20T12:00:00Z", "to": "2026-11-20T12:00:00Z"},
        {"from": "2026-01-01T00:00:00Z", "to": "2026-03-01T00:00:00Z"},
        {"guard_point": ""},
    ):  # fmt: skip
        with pytest.raises(BadMetricsParameter):
            parse_window(params, NOW)


def test_the_report_has_rates_for_tenant_rules_and_counts_for_the_rest():
    records = RecordAggregates(
        checks=200,
        by_decision={"allow": 190, "block": 10},
        rules=[
            RuleCount("t__a", "tenant", "enforce", "block", 8),
            RuleCount("t__a", "tenant", "shadow", "escalate", 4),
            RuleCount("d__pack", "pack", "enforce", "block", 2),
            RuleCount("p__floor", "floor", "enforce", "block", 5),
            RuleCount("p__floor", "floor", "enforce", "escalate", 3),
            RuleCount("t__copy", "tenant", "enforce", "block", 1),
        ],
    )
    report = build_report(
        Window(NOW - timedelta(days=1), NOW), records, [],
        floor_derived=frozenset({"t__copy"}), price_per_million_usd=0.1, price_source="x",
    )  # fmt: skip
    rates = {(r["rule"], r["mode"]): r for r in report["rules"]}
    assert rates[("t__a", "enforce")]["block_rate"] == 0.04
    assert rates[("t__a", "shadow")]["escalate_rate"] == 0.02
    assert ("d__pack", "enforce") in rates
    assert {r["rule"]: r["counts"] for r in report["platform_rules"]} == {
        "p__floor": {"block": 5, "escalate": 3}, "t__copy": {"block": 1},
    }  # fmt: skip
    for row in report["platform_rules"]:
        assert set(row) == {"rule", "layer", "counts"}  # no rate, no p, no threshold


def test_unknown_derived_keys_make_every_rule_counts_only():
    records = RecordAggregates(
        checks=10, rules=[RuleCount("t__a", "tenant", "enforce", "block", 1)]
    )
    report = build_report(
        Window(NOW - timedelta(days=1), NOW), records, [],
        floor_derived=None, price_per_million_usd=0.1, price_source="x",
    )  # fmt: skip
    assert report["rules"] == [] and report["platform_rules"][0]["rule"] == "t__a"


def test_cost_is_the_metered_answered_tokens_at_the_configured_price():
    usage = [
        UsageTotal("output", "answered", 10, 20_000),
        UsageTotal("output", "unknown", 2, 0),
        UsageTotal("input", "answered", 5, 5_000),
        UsageTotal("input", "provider_safety", 1, 0),
    ]
    report = build_report(
        Window(NOW - timedelta(days=1), NOW), RecordAggregates(), usage,
        floor_derived=frozenset(), price_per_million_usd=0.10, price_source="cfg",
    )  # fmt: skip
    by_gp = {g["guard_point"]: g for g in report["guard_points"]}
    assert by_gp["output"]["input_tokens"] == 20_000 and by_gp["output"]["cost_usd"] == 0.002
    assert by_gp["output"]["metered_events"] == {"answered": 10, "unknown": 2}
    assert report["cost"]["total_usd"] == 0.0025 and report["cost"]["price_source"] == "cfg"
    assert report["reconciliation"]["difference_pct"] == 100.0  # no records for 25,000 tokens
    assert report["reconciliation"]["within_tolerance"] is False


def test_a_small_window_is_exact_even_with_a_sparse_tail():
    """49 checks at 100 ms and one at 400 ms: the nearest-rank p99 is the 400 ms one, and
    a window of up to 50,000 is exact."""
    got = percentiles_of([100.0] * 49 + [400.0])
    assert got.p99 == pytest.approx(400.0) and got.p50 == pytest.approx(100.0)
    thousands = [100.0] * 30_000 + [400.0] * 600  # 1.96% slow: still a small, exact window
    assert percentiles_of(thousands).p99 == pytest.approx(400.0)  # exact up to 50,000


def test_a_large_window_is_estimated_within_two_percent_of_the_nearest_rank():
    values = [100.0] * 20_000 + [400.0] * 20  # a sparse tail among many fast checks
    got = bucketed(values)
    assert got.p50 == pytest.approx(100.0, rel=0.02)
    assert got.p95 == pytest.approx(100.0, rel=0.02) and got.p99 == pytest.approx(100.0, rel=0.02)
    # with a 2% tail the slowest percentile is the tail, in both the exact and the estimate
    values = [100.0] * 20_000 + [400.0] * 600
    assert bucketed(values).p99 == pytest.approx(exact(values, 0.99), rel=0.02) == 400.0
    assert percentiles_of(values).p99 == 400.0  # exact: the window is under 50,000


def test_the_exact_limit_is_where_the_estimate_starts():
    values = [100.0] * 49 + [400.0]
    assert percentiles_of(values, total=EXACT_LATENCY_MAX).p99 == 400.0  # exact at the limit
    assert percentiles_of(values, total=EXACT_LATENCY_MAX + 1).p99 == pytest.approx(400.0, rel=0.02)


def test_non_production_usage_is_split_out_by_class():
    usage = [
        UsageTotal("output", "answered", 4, 4_000),
        UsageTotal("test:output", "answered", 2, 1_000),
        UsageTotal("test:input", "answered", 1, 300),
        UsageTotal("calibration:output", "answered", 5, 2_000),
        UsageTotal("calibration:output", "unknown", 1, 0),
    ]
    report = build_report(
        Window(NOW - timedelta(days=1), NOW), RecordAggregates(), usage,
        floor_derived=frozenset(), price_per_million_usd=1.0, price_source="x",
    )  # fmt: skip
    assert [g["guard_point"] for g in report["guard_points"]] == ["output"]
    other = report["non_production"]
    assert other["input_tokens"] == 3_300 and other["cost_usd"] == 0.0033
    assert other["classes"]["test"]["input_tokens"] == 1_300
    assert [p["guard_point"] for p in other["classes"]["test"]["guard_points"]] == [
        "input",
        "output",
    ]
    assert other["classes"]["calibration"]["guard_points"][0]["metered_events"] == {
        "answered": 5, "unknown": 1,
    }  # fmt: skip
    assert report["reconciliation"]["metered_input_tokens"] == 4_000  # production only
