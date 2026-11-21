"""What a shadow candidate did, compared with the active version (M4-03).

For each check where a shadow candidate was evaluated alongside the active version, one
:class:`ShadowObservation` is made from the two verdicts and handed to a :class:`ShadowSink`.
The sink keeps **counts, never probabilities**: per rule, how often the two versions called for
the same action, and how often the candidate called for a stricter or a looser one; the same for
the overall decision; and how many checks could not be compared (the candidate got no answer, or
the provider refused it, PF-12). So the agreement report can show **no probability**: a floor
rule's ``p`` is a gradient to tune content under its threshold, and a floor-derived tenant rule's
too, and the report holds none of them, by construction: nothing here records ``p``.

A rule is compared by its key and the **action it called for** (``allow``, ``escalate`` or
``block``; for a rule in rule-mode shadow, what it would have called for). A rule only one of
the two versions has is counted as ``only_active`` or ``only_candidate``.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any, Protocol

from guardrail_engine.guard.verdict import SEVERITY, Action, Verdict
from guardrail_engine.tenant_scope import TenantScope

DECISION_KEY = "*decision*"
"""The row that holds the overall decision's agreement, beside the rules' rows."""
MAX_RULE_KEYS = 256
"""Rules a report tracks per (tenant, version pair); a key past it is dropped (a bound, not a
limit anyone reaches: a guard point has a handful of rules)."""


@dataclass(frozen=True, slots=True)
class RuleCall:
    key: str
    layer: str
    action: str


@dataclass(frozen=True, slots=True)
class ShadowObservation:
    tenant_id: str
    guard_point: str
    active_version: int
    candidate_version: int
    comparable: bool
    """Both versions answered, so there is something to compare."""
    active_decision: str
    candidate_decision: str
    active_rules: tuple[RuleCall, ...] = ()
    candidate_rules: tuple[RuleCall, ...] = ()
    scope: TenantScope | None = None
    """The verified tenant's scope, so a sink that persists counts can write them under it."""


def _calls(verdict: Verdict) -> tuple[RuleCall, ...]:
    return tuple(RuleCall(ev.key, ev.layer, str(ev.action)) for ev in verdict.rules)


def observe(
    tenant_id: str,
    guard_point: str,
    active: Verdict,
    candidate: Verdict,
    active_version: int,
    candidate_version: int,
    scope: TenantScope | None = None,
) -> ShadowObservation:
    """The observation of one check: the active verdict and the candidate's, as actions only.
    Comparable when both evaluated rules (a deterministic block, a model failure or a
    ``provider_safety`` refusal has none), so a candidate the provider refused is counted as
    incomparable and nothing else (PF-12)."""
    return ShadowObservation(
        tenant_id=tenant_id,
        guard_point=guard_point,
        active_version=active_version,
        candidate_version=candidate_version,
        comparable=bool(active.rules) and bool(candidate.rules),
        active_decision=str(active.decision),
        candidate_decision=str(candidate.decision),
        active_rules=_calls(active),
        candidate_rules=_calls(candidate),
        scope=scope,
    )


class ShadowSink(Protocol):
    def record(self, observation: ShadowObservation) -> None:
        """Called once per compared check. Synchronous and must not block (like the audit
        sink): a real sink buffers. An exception is logged and changes nothing."""
        ...


@dataclass(slots=True)
class Counts:
    """The agreement counts of one rule (or of the decision) between two versions."""

    layer: str = ""
    n: int = 0
    """Checks where both versions had it."""
    agree: int = 0
    candidate_stricter: int = 0
    candidate_looser: int = 0
    only_active: int = 0
    only_candidate: int = 0

    def add(self, other: Counts) -> None:
        self.n += other.n
        self.agree += other.agree
        self.candidate_stricter += other.candidate_stricter
        self.candidate_looser += other.candidate_looser
        self.only_active += other.only_active
        self.only_candidate += other.only_candidate

    def as_dict(self) -> dict[str, Any]:
        return {
            "n": self.n,
            "agree": self.agree,
            "agreement_rate": None if self.n == 0 else round(self.agree / self.n, 4),
            "candidate_stricter": self.candidate_stricter,
            "candidate_looser": self.candidate_looser,
            "only_active": self.only_active,
            "only_candidate": self.only_candidate,
        }


@dataclass(slots=True)
class Tally:
    """Everything counted for one (tenant, active version, candidate version)."""

    checks: int = 0
    """Checks with a shadow candidate that were compared."""
    incomparable: int = 0
    """Checks where the candidate (or the active version) gave no rule answers."""
    rules: dict[str, Counts] = field(default_factory=dict)
    decision: Counts = field(default_factory=Counts)


def _severity(action: str) -> int:
    try:
        return SEVERITY[Action(action)]
    except (ValueError, KeyError):
        return 0


def apply(tally: Tally, obs: ShadowObservation) -> None:
    """Add one observation to a tally."""
    if not obs.comparable:
        tally.incomparable += 1
        return
    tally.checks += 1
    _compare(tally.decision, obs.active_decision, obs.candidate_decision)
    active = {c.key: c for c in obs.active_rules}
    candidate = {c.key: c for c in obs.candidate_rules}
    for key in sorted(set(active) | set(candidate)):
        counts = tally.rules.get(key)
        if counts is None:
            if len(tally.rules) >= MAX_RULE_KEYS:
                continue
            counts = tally.rules[key] = Counts(layer=(active.get(key) or candidate[key]).layer)
        a, c = active.get(key), candidate.get(key)
        if a is None:
            counts.only_candidate += 1
        elif c is None:
            counts.only_active += 1
        else:
            _compare(counts, a.action, c.action)


def _compare(counts: Counts, active_action: str, candidate_action: str) -> None:
    counts.n += 1
    a, c = _severity(active_action), _severity(candidate_action)
    if a == c:
        counts.agree += 1
    elif c > a:
        counts.candidate_stricter += 1
    else:
        counts.candidate_looser += 1


def report_of(
    tally: Tally, *, active_version: int, candidate_version: int, mode: str, rollout_percent: int
) -> dict[str, Any]:
    """The agreement report: counts and rates only. No probability, no content."""
    return {
        "active_version": active_version,
        "candidate_version": candidate_version,
        "mode": mode,
        "rollout_percent": rollout_percent,
        "checks_compared": tally.checks,
        "checks_incomparable": tally.incomparable,
        "decision": tally.decision.as_dict(),
        "rules": [
            {"rule": key, "layer": counts.layer, **counts.as_dict()}
            for key, counts in sorted(tally.rules.items())
        ],
    }


class InMemoryShadowStats:
    """Counters in this process, which is also a :class:`ShadowSink`. Used from the event loop."""

    def __init__(self) -> None:
        self._tallies: dict[tuple[str, int, int], Tally] = defaultdict(Tally)

    def record(self, observation: ShadowObservation) -> None:
        key = (observation.tenant_id, observation.active_version, observation.candidate_version)
        apply(self._tallies[key], observation)  # one event loop: no lock needed

    offboard_tables = ("tenant_shadow_agreement",)

    def offboard_tenant(
        self, tenant_id: str, table: str, limit: int, *, count_only: bool = False
    ) -> dict[str, int]:
        """M5-07: delete (or count) a terminated tenant's rows (see ``TenantDataHolder``)."""
        mine = [k for k in self._tallies if k[0] == tenant_id]
        if not count_only:
            mine = mine[:limit]
            for k in mine:
                del self._tallies[k]
        return {table: len(mine)}

    async def tally(self, scope: TenantScope, active_version: int, candidate_version: int) -> Tally:
        found = self._tallies.get((scope.tenant_id, active_version, candidate_version))
        if found is None:
            return Tally()
        copy = Tally(found.checks, found.incomparable, decision=_copy(found.decision))
        copy.rules = {k: _copy(v) for k, v in found.rules.items()}
        return copy


def _copy(c: Counts) -> Counts:
    out = Counts(layer=c.layer)
    out.add(c)
    return out


def merge(tallies: Iterable[Tally]) -> Tally:
    total = Tally()
    for t in tallies:
        total.checks += t.checks
        total.incomparable += t.incomparable
        total.decision.add(t.decision)
        for key, counts in t.rules.items():
            mine = total.rules.setdefault(key, Counts(layer=counts.layer))
            mine.add(counts)
    return total


class ShadowReader(Protocol):
    async def tally(self, scope: TenantScope, active_version: int, candidate_version: int) -> Tally:
        """What was counted for the verified tenant ``scope`` between these two versions."""
        ...


__all__ = [
    "DECISION_KEY",
    "Counts",
    "InMemoryShadowStats",
    "RuleCall",
    "ShadowObservation",
    "ShadowReader",
    "ShadowSink",
    "Tally",
    "apply",
    "merge",
    "observe",
    "report_of",
]
