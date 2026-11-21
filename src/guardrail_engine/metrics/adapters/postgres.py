"""The metrics sources on Postgres (M4-06): aggregates over ``decision_records`` and
``decision_record_rules`` (026, 032, 038) and ``usage_events`` (024, 038).

Every query runs through :func:`~guardrail_engine.store.adapters.postgres.tenant_connection`
(forced row-level security on all three tables) and also names ``tenant_id = $1``, because an
operator's policy would otherwise show every tenant. The window is a range on ``ts`` and the
filters are columns, so no JSON is read. Neither class imports the driver.
"""

from __future__ import annotations

from typing import Any

from guardrail_engine.metrics.model import (
    EXACT_LATENCY_MAX,
    GuardPointRecords,
    LatencyHistogram,
    Percentiles,
    RecordAggregates,
    RuleCount,
    UsageTotal,
    Window,
)
from guardrail_engine.store.adapters.postgres import tenant_connection
from guardrail_engine.tenant_scope import TenantScope


class PostgresRecordMetrics:
    def __init__(self, pool: Any, operator_pool: Any | None = None) -> None:
        self._pool = pool
        self._operator_pool = operator_pool

    async def aggregate(self, scope: TenantScope, window: Window) -> RecordAggregates:
        args: list[Any] = [scope.tenant_id, window.start, window.end]
        gp = ""
        if window.guard_point is not None:
            args.append(window.guard_point)
            gp = " AND guard_point = $4"
        base = f"FROM decision_records WHERE tenant_id = $1 AND ts >= $2 AND ts < $3{gp}"
        bucket = (
            "floor(ln(greatest(latency_ms::double precision, 0.001)) / ln(1.02::double precision))"
            "::integer"
        )
        async with tenant_connection(self._pool, scope, self._operator_pool) as conn:
            # One pass over the window: counts, tokens and the latency histogram, grouped.
            grouped = await conn.fetch(
                f"SELECT guard_point, decision, {bucket} AS bucket, count(*) AS n, "
                f"coalesce(sum(input_tokens), 0)::bigint AS tokens {base} "
                f"GROUP BY guard_point, decision, bucket",
                *args,
            )
            # The versions that matter are those of records with rule rows (they decide which
            # rules are floor-derived); a record that fired nothing needs no version.
            versions = await conn.fetch(
                "SELECT DISTINCT r.bundle_version FROM decision_record_rules h "
                "JOIN decision_records r ON r.id = h.record_id "
                + ("AND r.guard_point = $4 " if window.guard_point is not None else "")
                + "WHERE h.tenant_id = $1 AND h.ts >= $2 AND h.ts < $3",
                *args,
            )
            rules = await conn.fetch(
                "SELECT h.rule, coalesce(h.layer, 'unknown') AS layer, "
                "coalesce(h.mode, 'unknown') AS mode, coalesce(h.action, 'unknown') AS action, "
                "count(*) AS n "
                + (
                    "FROM decision_record_rules h "
                    if window.guard_point is None
                    else "FROM decision_record_rules h JOIN decision_records r "
                    "ON r.id = h.record_id AND r.guard_point = $4 "
                )
                + "WHERE h.tenant_id = $1 AND h.ts >= $2 AND h.ts < $3 "
                "GROUP BY 1, 2, 3, 4",
                *args,
            )
        by_decision: dict[str, int] = {}
        counts: dict[str, int] = {}
        tokens: dict[str, int] = {}
        histograms: dict[str, LatencyHistogram] = {}
        for r in grouped:
            decision = r["decision"] or "unknown"
            by_decision[decision] = by_decision.get(decision, 0) + r["n"]
            counts[r["guard_point"]] = counts.get(r["guard_point"], 0) + r["n"]
            tokens[r["guard_point"]] = tokens.get(r["guard_point"], 0) + r["tokens"]
            if r["bucket"] is not None:
                histograms.setdefault(r["guard_point"], LatencyHistogram()).add(r["bucket"], r["n"])
        overall = LatencyHistogram()
        for h in histograms.values():
            overall.merge(h)
        per_gp = {g: h.percentiles() for g, h in histograms.items()}
        overall_q = overall.percentiles()
        if sum(counts.values()) <= EXACT_LATENCY_MAX and histograms:
            # A small window: sort it, as ``percentile_disc`` does, rather than estimate.
            async with tenant_connection(self._pool, scope, self._operator_pool) as conn:
                exact = await conn.fetch(
                    "SELECT guard_point, GROUPING(guard_point) AS overall, "
                    "percentile_disc(ARRAY[0.5, 0.95, 0.99]) WITHIN GROUP (ORDER BY latency_ms) "
                    f"AS q {base} AND latency_ms IS NOT NULL "
                    "GROUP BY GROUPING SETS ((guard_point), ())",
                    *args,
                )
            for r in exact:
                found = Percentiles(float(r["q"][0]), float(r["q"][1]), float(r["q"][2]))
                if r["overall"]:
                    overall_q = found
                else:
                    per_gp[r["guard_point"]] = found
        return RecordAggregates(
            checks=sum(counts.values()),
            by_decision=by_decision,
            latency=overall_q,
            guard_points=[
                GuardPointRecords(g, counts[g], tokens[g], per_gp.get(g)) for g in sorted(counts)
            ],
            bundle_versions=frozenset(
                v["bundle_version"] for v in versions if v["bundle_version"] is not None
            ),
            unknown_version=any(v["bundle_version"] is None for v in versions),
            rules=[RuleCount(r["rule"], r["layer"], r["mode"], r["action"], r["n"]) for r in rules],
        )


class PostgresUsageMetrics:
    def __init__(self, pool: Any, operator_pool: Any | None = None) -> None:
        self._pool = pool
        self._operator_pool = operator_pool

    async def totals(self, scope: TenantScope, window: Window) -> list[UsageTotal]:
        args: list[Any] = [scope.tenant_id, window.start, window.end]
        gp = ""
        if window.guard_point is not None:
            args.append(window.guard_point)
            gp = " AND guard_point = $4"
        async with tenant_connection(self._pool, scope, self._operator_pool) as conn:
            rows = await conn.fetch(
                "SELECT guard_point, kind, project, count(*) AS n, "
                "coalesce(sum(input_tokens), 0)::bigint AS tokens FROM usage_events "
                f"WHERE tenant_id = $1 AND occurred_at >= $2 AND occurred_at < $3{gp} "
                "GROUP BY guard_point, kind, project ORDER BY guard_point, kind, project",
                *args,
            )
        return [
            UsageTotal(r["guard_point"], r["kind"], r["n"], r["tokens"], r["project"]) for r in rows
        ]
