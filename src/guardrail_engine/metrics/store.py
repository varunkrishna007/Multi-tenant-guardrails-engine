"""Ports for the metrics sources, and their in-memory implementations (M4-06)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Protocol

from guardrail_engine.audit.store import InMemoryDecisionRecords
from guardrail_engine.delivery.usage import InMemoryUsageStore
from guardrail_engine.metrics.model import (
    GuardPointRecords,
    RecordAggregates,
    RuleCount,
    UsageTotal,
    Window,
    percentiles_of,
)
from guardrail_engine.tenant_scope import TenantScope


class RecordMetrics(Protocol):
    async def aggregate(self, scope: TenantScope, window: Window) -> RecordAggregates:
        """Aggregates over the scope's tenant's decision records in the window."""
        ...


class UsageMetrics(Protocol):
    async def totals(self, scope: TenantScope, window: Window) -> list[UsageTotal]:
        """The scope's tenant's metered usage in the window, by guard point and kind."""
        ...


class InMemoryRecordMetrics:
    """Aggregates an :class:`InMemoryDecisionRecords` the way the SQL does."""

    def __init__(self, records: InMemoryDecisionRecords) -> None:
        self._records = records

    async def aggregate(self, scope: TenantScope, window: Window) -> RecordAggregates:
        rows = [
            r
            for r in self._records.all()
            if r.tenant_id == scope.tenant_id
            and window.start <= r.ts < window.end
            and (window.guard_point is None or r.guard_point == window.guard_point)
        ]
        by_decision: dict[str, int] = {}
        per_gp: dict[str, list] = {}
        versions: set[int] = set()
        unknown = False
        rules: dict[tuple[str, str, str, str], int] = {}
        for r in rows:
            by_decision[r.decision.value] = by_decision.get(r.decision.value, 0) + 1
            per_gp.setdefault(r.guard_point, []).append(r)
            if r.fired:  # only a record with rule rows needs its version (to find derived rules)
                if r.bundle_version is None:
                    unknown = True
                else:
                    versions.add(r.bundle_version)
            seen: dict[str, tuple[str, str, str]] = {}
            for f in r.fired:
                mine = (f.layer, f.mode, f.action.value)
                if f.rule not in seen or f.action.value == "block":
                    seen[f.rule] = mine
            for rule, (layer, mode, action) in seen.items():
                key = (rule, layer, mode, action)
                rules[key] = rules.get(key, 0) + 1
        guard_points = [
            GuardPointRecords(
                gp,
                len(group),
                sum(r.input_tokens or 0 for r in group),
                percentiles_of([r.latency_ms for r in group], total=len(rows)),
            )
            for gp, group in sorted(per_gp.items())
        ]
        return RecordAggregates(
            checks=len(rows),
            by_decision=by_decision,
            latency=percentiles_of([r.latency_ms for r in rows]),
            guard_points=guard_points,
            bundle_versions=frozenset(versions),
            unknown_version=unknown,
            rules=[RuleCount(k[0], k[1], k[2], k[3], n) for k, n in sorted(rules.items())],
        )


class InMemoryUsageMetrics:
    """Totals over an :class:`InMemoryUsageStore`."""

    def __init__(self, store: InMemoryUsageStore) -> None:
        self._store = store

    async def totals(self, scope: TenantScope, window: Window) -> list[UsageTotal]:
        sums: dict[tuple[str, str, str], list[int]] = {}
        for event in list(self._store.records.values()):
            when = datetime.fromtimestamp(event.at, UTC)
            if event.tenant_id != scope.tenant_id or not window.start <= when < window.end:
                continue
            if window.guard_point is not None and event.guard_point != window.guard_point:
                continue
            entry = sums.setdefault((event.guard_point, event.kind, event.project), [0, 0])
            entry[0] += 1
            entry[1] += event.input_tokens or 0
        return [
            UsageTotal(gp, kind, n, tok, project)
            for (gp, kind, project), (n, tok) in sorted(sums.items())
        ]
