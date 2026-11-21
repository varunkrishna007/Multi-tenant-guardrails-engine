"""Storage for calibration (M4-01): the tenant's targets, the stored probabilities, and the
audit trail of target changes and threshold decisions.

Three things, all tenant-scoped like the golden sets (``store.scoped(scope)``; Postgres under
forced row-level security):

* **Targets** (:class:`~guardrail_engine.admin.sweep.Targets`): the tenant's block-precision and
  escalate-recall targets, a setting beside the bundle (decided 2026-11-18). Changing them writes
  a class A audit event in the same step: actor, before, after.
* **Scores**: for a *scoring identity* (the guard point's compiled questions and the floor
  version, see :func:`~guardrail_engine.admin.calibration.scoring_hash`) and an example's
  content hash, the probability each **tenant** rule gave it. Insert-only: a score for a key that
  exists is kept. Floor, floor-derived and pack rules are never stored.
* **Audit**: append-only. ``kind`` is ``targets`` (a change of targets) or ``threshold`` (a
  tenant's accept or override of a suggestion, with the actor, the suggested and the applied
  values and the targets and draft the suggestion came from).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Protocol

from guardrail_engine.admin.sweep import Targets
from guardrail_engine.store.port import ScopeMismatchError
from guardrail_engine.tenant_scope import TenantScope

AUDIT_KINDS = ("targets",)
"""Threshold decisions are recorded in the draft's own audit event, in the draft write's
transaction: ``draft.thresholds``."""

OUTCOME_CAUSES = ("deterministic", "too_large", "refused", "failed")
TERMINAL_ATTEMPTS = {"deterministic": 1, "too_large": 1, "refused": 2}
"""Why an example has no score, and how many recorded attempts of a cause make it terminal (it
leaves the rule's pool for good under this scoring identity). ``failed`` is never terminal: it
is retried, behind examples that were tried fewer times."""
MAX_ATTEMPTS = 20


@dataclass(frozen=True, slots=True)
class CalibrationAuditEvent:
    at: datetime
    actor: str
    tenant_id: str
    kind: str
    detail: dict[str, Any]
    cross_tenant: bool = False
    operator: bool = False


class CalibrationStore(Protocol):
    """A tenant-scoped calibration store. ``tenant_id`` must be the scope's tenant (else
    :class:`ScopeMismatchError`)."""

    async def get_targets(self, tenant_id: str) -> Targets | None:
        """The tenant's own targets, or None (the platform default applies)."""
        ...

    async def set_targets(
        self, tenant_id: str, targets: Targets, event: CalibrationAuditEvent
    ) -> None:
        """Store the targets and the audit event together."""
        ...

    async def get_scores(
        self, tenant_id: str, scoring: str, guard_point: str, content_hashes: list[str]
    ) -> dict[str, dict[str, float]]:
        """The stored ``{rule key: p}`` for each of ``content_hashes`` that has one."""
        ...

    async def put_scores(
        self, tenant_id: str, scoring: str, guard_point: str, scores: dict[str, dict[str, float]]
    ) -> None:
        """Store scores; one that already exists is kept as it is."""
        ...

    async def get_outcomes(
        self, tenant_id: str, scoring: str, guard_point: str, content_hashes: list[str]
    ) -> dict[str, dict[str, int]]:
        """For each of ``content_hashes`` with any recorded failed attempt: how many attempts
        of each cause (``{"refused": 1, "failed": 2}``)."""
        ...

    async def put_outcomes(
        self, tenant_id: str, scoring: str, guard_point: str, outcomes: dict[str, str]
    ) -> None:
        """Record one more attempt, with its cause, for each content hash (at most
        :data:`MAX_ATTEMPTS` are kept per example)."""
        ...

    async def record(self, tenant_id: str, event: CalibrationAuditEvent) -> None: ...

    async def audit_events(self, tenant_id: str) -> list[CalibrationAuditEvent]: ...


class ScopedCalibrationStores(Protocol):
    def scoped(self, scope: TenantScope) -> CalibrationStore: ...


@dataclass
class InMemoryCalibrationStore:
    _targets: dict[str, Targets] = field(default_factory=dict)
    _scores: dict[tuple[str, str, str, str], dict[str, float]] = field(default_factory=dict)
    _events: list[CalibrationAuditEvent] = field(default_factory=list)
    _outcomes: dict[tuple[str, str, str, str], list[str]] = field(default_factory=dict)

    offboard_tables = (
        "tenant_calibration_scores",
        "tenant_calibration_outcomes",
        "tenant_calibration_targets",
    )

    def offboard_tenant(
        self, tenant_id: str, table: str, limit: int, *, count_only: bool = False
    ) -> dict[str, int]:
        """M5-07: delete (or count) a terminated tenant's rows (see ``TenantDataHolder``)."""
        if table == "tenant_calibration_targets":
            n = int(tenant_id in self._targets)
            if not count_only and n:
                del self._targets[tenant_id]
            return {table: n}
        rows = self._scores if table == "tenant_calibration_scores" else self._outcomes
        mine = [k for k in rows if k[0] == tenant_id]
        if not count_only:
            mine = mine[:limit]
            for k in mine:
                del rows[k]
        return {table: len(mine)}

    def scoped(self, scope: TenantScope) -> CalibrationStore:
        if not isinstance(scope, TenantScope):
            raise TypeError("scoped() takes a TenantScope")
        return _ScopedMemoryCalibration(self, scope)


class _ScopedMemoryCalibration:
    def __init__(self, store: InMemoryCalibrationStore, scope: TenantScope) -> None:
        self._store = store
        self._scope = scope

    def _check(self, tenant_id: str) -> None:
        if tenant_id != self._scope.tenant_id:
            raise ScopeMismatchError()

    async def get_targets(self, tenant_id: str) -> Targets | None:
        self._check(tenant_id)
        return self._store._targets.get(tenant_id)

    async def set_targets(
        self, tenant_id: str, targets: Targets, event: CalibrationAuditEvent
    ) -> None:
        self._check(tenant_id)
        if event.tenant_id != tenant_id:
            raise ScopeMismatchError()
        self._store._targets[tenant_id] = targets
        self._store._events.append(event)

    async def get_scores(
        self, tenant_id: str, scoring: str, guard_point: str, content_hashes: list[str]
    ) -> dict[str, dict[str, float]]:
        self._check(tenant_id)
        out: dict[str, dict[str, float]] = {}
        for h in content_hashes:
            found = self._store._scores.get((tenant_id, scoring, guard_point, h))
            if found is not None:
                out[h] = dict(found)
        return out

    async def put_scores(
        self, tenant_id: str, scoring: str, guard_point: str, scores: dict[str, dict[str, float]]
    ) -> None:
        self._check(tenant_id)
        for h, by_rule in scores.items():
            self._store._scores.setdefault((tenant_id, scoring, guard_point, h), dict(by_rule))

    async def get_outcomes(
        self, tenant_id: str, scoring: str, guard_point: str, content_hashes: list[str]
    ) -> dict[str, dict[str, int]]:
        self._check(tenant_id)
        out: dict[str, dict[str, int]] = {}
        for h in content_hashes:
            attempts = self._store._outcomes.get((tenant_id, scoring, guard_point, h))
            if attempts:
                by_cause: dict[str, int] = {}
                for cause in attempts:
                    by_cause[cause] = by_cause.get(cause, 0) + 1
                out[h] = by_cause
        return out

    async def put_outcomes(
        self, tenant_id: str, scoring: str, guard_point: str, outcomes: dict[str, str]
    ) -> None:
        self._check(tenant_id)
        for h, cause in outcomes.items():
            if cause not in OUTCOME_CAUSES:
                raise ValueError(f"unknown outcome cause {cause!r}")
            attempts = self._store._outcomes.setdefault((tenant_id, scoring, guard_point, h), [])
            if len(attempts) < MAX_ATTEMPTS:
                attempts.append(cause)

    async def record(self, tenant_id: str, event: CalibrationAuditEvent) -> None:
        self._check(tenant_id)
        if event.tenant_id != tenant_id:
            raise ScopeMismatchError()
        self._store._events.append(event)

    async def audit_events(self, tenant_id: str) -> list[CalibrationAuditEvent]:
        self._check(tenant_id)
        return [e for e in self._store._events if e.tenant_id == tenant_id]
