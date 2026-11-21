"""What the metrics query takes, reads and returns (M4-06).

**Sources.** Two, both tenant-scoped (row-level security on Postgres):

* the **decision records** (M4-07): how many checks, by decision and guard point, their latency
  and the tokens each one reported, and, from the records' rule index, how often each rule
  blocked or escalated;
* the **usage events** (M4-04): what the gateway metered, per guard point, for billing. These
  are the metered totals; tokens and cost are reported from them.

The two are written by different paths (the record by the writer behind the check, the usage
event through the outbox), so a lost record or event makes them differ. The report says by how
much (``reconciliation``) and whether it is within 1%.

**Per project (M5-06).** ``projects`` splits the metered usage by the Gemini project whose key
made the calls: ``default`` is the shared pool, any other label is the tenant's dedicated
project. Billing for a regulated tenant is read from its own project's row.

**What is never in the response.** Only counts, rates, percentiles, tokens and cost. No
probability and no threshold is read at all (the aggregates are over columns that hold neither),
so the floor can't leak through it. A floor rule, and a tenant rule that is a copy of a floor
rule (``floor_derived_keys``), appear only as **counts by key and action**, without a rate,
under ``platform_rules``.

**Rates** are a rule's blocks (or escalations) divided by the checks in the window (all of them,
or those at the one guard point asked about), not by the checks that evaluated the rule.
"""

from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

DEFAULT_WINDOW = timedelta(hours=24)
MAX_WINDOW = timedelta(days=31)
MAX_TEXT = 64
PARAMETERS = frozenset({"from", "to", "guard_point"})
SHOWN_LAYERS = ("tenant", "pack")
"""Layers whose rules get rates. Everything else (the floor, a layer this code doesn't know)
gets counts by key and action only."""
RECONCILIATION_TOLERANCE_PCT = 1.0
QUANTILES = (0.5, 0.95, 0.99)


class BadMetricsParameter(ValueError):
    def __init__(self, field_name: str, message: str) -> None:
        super().__init__(f"{field_name}: {message}")
        self.field = field_name
        self.message = message


@dataclass(frozen=True, slots=True)
class Window:
    start: datetime
    """Inclusive."""
    end: datetime
    """Exclusive."""
    guard_point: str | None = None


def _time(params: Mapping[str, str], name: str) -> datetime | None:
    raw = params.get(name)
    if raw is None:
        return None
    try:
        when = datetime.fromisoformat(raw)
    except ValueError:
        raise BadMetricsParameter(name, "an ISO 8601 time with a time zone") from None
    if when.tzinfo is None:
        raise BadMetricsParameter(name, "an ISO 8601 time with a time zone")
    return when.astimezone(UTC)


def parse_window(params: Mapping[str, str], now: datetime) -> Window:
    unknown = sorted(set(params) - PARAMETERS)
    if unknown:
        raise BadMetricsParameter(unknown[0], "not a parameter of this query")
    end = _time(params, "to") or now.astimezone(UTC)
    start = _time(params, "from") or end - DEFAULT_WINDOW
    if start >= end:
        raise BadMetricsParameter("from", "must be before to")
    if end - start > MAX_WINDOW:
        raise BadMetricsParameter("from", f"at most {MAX_WINDOW.days} days before to")
    guard_point = params.get("guard_point")
    if guard_point is not None and not (
        1 <= len(guard_point) <= MAX_TEXT and guard_point.isprintable()
    ):
        raise BadMetricsParameter("guard_point", f"1 to {MAX_TEXT} printable characters")
    return Window(start, end, guard_point)


# ------------------------------------------------------------------ what the sources return


@dataclass(frozen=True, slots=True)
class Percentiles:
    p50: float
    p95: float
    p99: float

    def as_dict(self) -> dict[str, float]:
        return {"p50": round(self.p50, 3), "p95": round(self.p95, 3), "p99": round(self.p99, 3)}


@dataclass(frozen=True, slots=True)
class GuardPointRecords:
    guard_point: str
    checks: int
    record_tokens: int
    """Sum of the records' ``input_tokens`` (a record with none counts for 0)."""
    latency: Percentiles | None
    """Over the records that have a latency; None when none do."""


@dataclass(frozen=True, slots=True)
class RuleCount:
    rule: str
    layer: str
    mode: str
    action: str
    count: int


@dataclass(frozen=True, slots=True)
class RecordAggregates:
    checks: int = 0
    by_decision: Mapping[str, int] = field(default_factory=dict)
    latency: Percentiles | None = None
    guard_points: Sequence[GuardPointRecords] = ()
    bundle_versions: frozenset[int] = frozenset()
    """Versions that decided at least one check in the window (to find what is floor-derived).
    ``unknown_version`` is True when a record has none."""
    unknown_version: bool = False
    rules: Sequence[RuleCount] = ()


@dataclass(frozen=True, slots=True)
class UsageTotal:
    guard_point: str
    kind: str
    events: int
    tokens: int
    project: str = ""
    """M5-06: the dedicated Gemini project the calls went through; ``""`` is the shared pool."""


EXACT_LATENCY_MAX = 50_000
"""Up to this many records in the window the percentiles are exact, by **nearest rank**
(``percentile_disc``: the smallest latency at or above which the fraction q of the records
lies; sorting 50,000 numbers is cheap). Above it they are estimated from buckets, below."""
BUCKET_RATIO = 1.02
"""Above :data:`EXACT_LATENCY_MAX` records, latency is counted in log-scale buckets 2% wide, so
percentiles come from one pass over the rows with a group-by and no sort. **The bound:** the
estimate is within the bucket, about 2%, of the exact *nearest-rank* value, for any data: both
are the same rank, and the estimate only places the value inside its bucket. (A continuous
percentile, ``percentile_cont``, interpolates between two samples and so can differ from either
where a tail of a few slow checks sits beside thousands of fast ones; this report never
interpolates between samples.) Exact percentiles over a month of a large tenant sort every row:
1.4 s for 300,000 records, linear from there."""
MIN_LATENCY_MS = 0.001
_LOG_RATIO = math.log(BUCKET_RATIO)


def latency_bucket(value_ms: float) -> int:
    """The bucket of a latency: ``floor(ln(max(v, 0.001)) / ln(1.02))``. The SQL computes the same
    expression, on the value as stored (a ``real``), so the two agree."""
    return math.floor(math.log(max(value_ms, MIN_LATENCY_MS)) / _LOG_RATIO)


def to_stored(value_ms: float) -> float:
    """``value_ms`` as the ``real`` column holds it (single precision)."""
    import struct

    return float(struct.unpack("f", struct.pack("f", value_ms))[0])


@dataclass(slots=True)
class LatencyHistogram:
    buckets: dict[int, int] = field(default_factory=dict)

    def add(self, bucket: int, n: int = 1) -> None:
        self.buckets[bucket] = self.buckets.get(bucket, 0) + n

    def merge(self, other: LatencyHistogram) -> None:
        for bucket, n in other.buckets.items():
            self.add(bucket, n)

    @property
    def count(self) -> int:
        return sum(self.buckets.values())

    def percentiles(self) -> Percentiles | None:
        total = self.count
        if total == 0:
            return None
        ordered = sorted(self.buckets.items())
        return Percentiles(*(self._at(ordered, total, q) for q in QUANTILES))

    @staticmethod
    def _at(ordered: list[tuple[int, int]], total: int, q: float) -> float:
        index = max(math.ceil(q * total) - 1, 0)  # nearest rank, 0-based
        seen = 0
        for bucket, n in ordered:
            if index < seen + n:
                low = BUCKET_RATIO**bucket
                high = BUCKET_RATIO ** (bucket + 1)
                return low + (high - low) * ((index - seen + 0.5) / n)
            seen += n
        bucket = ordered[-1][0]
        return BUCKET_RATIO ** (bucket + 1)


def percentile_disc(values: Sequence[float], q: float) -> float:
    """Nearest rank, as PostgreSQL's ``percentile_disc``: the value at 1-based rank
    ``ceil(q * n)``."""
    ordered = sorted(values)
    return ordered[max(math.ceil(q * len(ordered)) - 1, 0)]


def percentiles_of(values: Sequence[float], *, total: int | None = None) -> Percentiles | None:
    """Percentiles of raw latencies: exact when the window has at most
    :data:`EXACT_LATENCY_MAX` records (``total``, default ``len(values)``), else through the
    same buckets the database uses."""
    if not values:
        return None
    if (len(values) if total is None else total) <= EXACT_LATENCY_MAX:
        stored = [to_stored(v) for v in values]  # as the real column holds them
        return Percentiles(*(percentile_disc(stored, q) for q in QUANTILES))
    histogram = LatencyHistogram()
    for v in values:
        histogram.add(latency_bucket(to_stored(v)))
    return histogram.percentiles()


# ------------------------------------------------------------------ the report


def build_report(
    window: Window,
    records: RecordAggregates,
    usage: Sequence[UsageTotal],
    *,
    floor_derived: frozenset[str] | None,
    price_per_million_usd: float,
    price_source: str,
) -> dict[str, Any]:
    """The response. ``floor_derived`` is the tenant rules (compiled keys) that are the floor's
    own, or None when it is not known (every rule is then counts only)."""
    metered: dict[str, dict[str, Any]] = {}
    other: dict[str, dict[str, dict[str, Any]]] = {}
    for u in usage:
        if ":" in u.guard_point:  # "<usage class>:<guard point>": not a production check
            usage_class, _, name = u.guard_point.partition(":")
            entry = other.setdefault(usage_class, {}).setdefault(name, {"events": {}, "tokens": 0})
        else:
            entry = metered.setdefault(u.guard_point, {"events": {}, "tokens": 0})
        entry["events"][u.kind] = entry["events"].get(u.kind, 0) + u.events
        if u.kind == "answered":
            entry["tokens"] += u.tokens
    by_gp = {g.guard_point: g for g in records.guard_points}
    guard_points = []
    for name in sorted(set(by_gp) | set(metered)):
        rec, met = by_gp.get(name), metered.get(name, {"events": {}, "tokens": 0})
        tokens = int(met["tokens"])
        guard_points.append(
            {
                "guard_point": name,
                "checks": rec.checks if rec else 0,
                "latency_ms": rec.latency.as_dict() if rec and rec.latency else None,
                "input_tokens": tokens,
                "cost_usd": _usd(tokens, price_per_million_usd),
                "record_input_tokens": rec.record_tokens if rec else 0,
                "metered_events": dict(sorted(met["events"].items())),
            }
        )
    metered_total = sum(int(m["tokens"]) for m in metered.values())
    record_total = sum(g.record_tokens for g in records.guard_points)
    non_production = _non_production(other, price_per_million_usd)
    tenant_rules, platform_rules = _rules(records, floor_derived)
    total = records.checks
    for item in tenant_rules:
        item["block_rate"] = _rate(item["blocked"], total)
        item["escalate_rate"] = _rate(item["escalated"], total)
    difference = abs(metered_total - record_total)
    pct = (
        None
        if max(metered_total, record_total) == 0
        else difference / max(metered_total, record_total) * 100
    )
    return {
        "window": {
            "from": window.start.isoformat(),
            "to": window.end.isoformat(),
            "guard_point": window.guard_point,
        },
        "checks": {"total": total, "by_decision": dict(sorted(records.by_decision.items()))},
        "latency_ms": records.latency.as_dict() if records.latency else None,
        "guard_points": guard_points,
        "rules": tenant_rules,
        "platform_rules": platform_rules,
        "non_production": non_production,
        "projects": _projects(usage, price_per_million_usd),
        "cost": {
            "input_tokens": metered_total,
            "total_usd": _usd(metered_total, price_per_million_usd),
            "non_production_usd": non_production["cost_usd"],
            "all_usd": round(
                _usd(metered_total, price_per_million_usd) + non_production["cost_usd"], 8
            ),
            "price_per_million_input_tokens_usd": price_per_million_usd,
            "price_source": price_source,
            "currency": "USD",
        },
        "reconciliation": {
            "metered_input_tokens": metered_total,
            "record_input_tokens": record_total,
            "difference_pct": None if pct is None else round(pct, 3),
            "within_tolerance": pct is None or pct <= RECONCILIATION_TOLERANCE_PCT,
            "tolerance_pct": RECONCILIATION_TOLERANCE_PCT,
        },
    }


SHARED_PROJECT = "default"
"""How the shared pool's usage (an empty project on the record) is named in a report."""


def _projects(usage: Sequence[UsageTotal], price_per_million: float) -> list[dict[str, Any]]:
    """M5-06: the metered usage and its cost **per Gemini project**: the dedicated project the
    tenant's calls went through, or ``default`` for the shared pool. Production checks and
    non-production calls (the usage-class guard points ``test:``, ``calibration:``...) are
    separate figures, as in ``cost``, and each project's production tokens add up to
    ``cost.input_tokens``. An id (the project's label) and counts: never a key or a project
    secret, which the engine does not hold in anything this report reads."""
    found: dict[str, dict[str, Any]] = {}
    for u in usage:
        label = u.project or SHARED_PROJECT
        entry = found.setdefault(
            label,
            {"project": label, "dedicated": bool(u.project), "input_tokens": 0, "events": {},
             "non_production_input_tokens": 0},
        )  # fmt: skip
        if ":" in u.guard_point:
            if u.kind == "answered":
                entry["non_production_input_tokens"] += u.tokens
            continue
        entry["events"][u.kind] = entry["events"].get(u.kind, 0) + u.events
        if u.kind == "answered":
            entry["input_tokens"] += u.tokens
    rows = []
    for label in sorted(found, key=lambda name: (name != SHARED_PROJECT, name)):
        e = found[label]
        rows.append(
            {
                "project": label,
                "dedicated": e["dedicated"],
                "input_tokens": e["input_tokens"],
                "cost_usd": _usd(e["input_tokens"], price_per_million),
                "metered_events": dict(sorted(e["events"].items())),
                "non_production_input_tokens": e["non_production_input_tokens"],
                "non_production_cost_usd": _usd(
                    e["non_production_input_tokens"], price_per_million
                ),
            }
        )
    return rows


def _non_production(
    other: dict[str, dict[str, dict[str, Any]]], price_per_million: float
) -> dict[str, Any]:
    """Usage that is not a production check (a draft test, a calibration run, a shadow
    candidate, a red-team run, a tool screening), by usage class. These calls have no decision
    record, so they are priced and reported here and never reconciled with the records."""
    classes: dict[str, Any] = {}
    total = 0
    for usage_class in sorted(other):
        points = []
        class_tokens = 0
        for name in sorted(other[usage_class]):
            e = other[usage_class][name]
            tokens = int(e["tokens"])
            class_tokens += tokens
            points.append(
                {
                    "guard_point": name,
                    "input_tokens": tokens,
                    "cost_usd": _usd(tokens, price_per_million),
                    "metered_events": dict(sorted(e["events"].items())),
                }
            )
        total += class_tokens
        classes[usage_class] = {
            "input_tokens": class_tokens,
            "cost_usd": _usd(class_tokens, price_per_million),
            "guard_points": points,
        }
    return {"input_tokens": total, "cost_usd": _usd(total, price_per_million), "classes": classes}


def _usd(tokens: int, price_per_million: float) -> float:
    return round(tokens * price_per_million / 1_000_000, 8)


def _rate(count: int, total: int) -> float:
    return round(count / total, 6) if total else 0.0


def _rules(
    records: RecordAggregates, floor_derived: frozenset[str] | None
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    tenant: dict[tuple[str, str, str], dict[str, Any]] = {}
    platform: dict[tuple[str, str], dict[str, Any]] = {}
    for c in records.rules:
        shown = (
            c.layer in SHOWN_LAYERS and floor_derived is not None and c.rule not in floor_derived
        )
        if shown:
            row = tenant.setdefault(
                (c.rule, c.layer, c.mode),
                {
                    "rule": c.rule, "layer": c.layer, "mode": c.mode,
                    "blocked": 0, "escalated": 0,
                },
            )  # fmt: skip
            if c.action == "block":
                row["blocked"] += c.count
            elif c.action == "escalate":
                row["escalated"] += c.count
        else:
            row = platform.setdefault(
                (c.rule, c.layer), {"rule": c.rule, "layer": c.layer, "counts": {}}
            )
            row["counts"][c.action] = row["counts"].get(c.action, 0) + c.count
    return (
        sorted(tenant.values(), key=lambda r: (r["rule"], r["mode"])),
        sorted(platform.values(), key=lambda r: r["rule"]),
    )
