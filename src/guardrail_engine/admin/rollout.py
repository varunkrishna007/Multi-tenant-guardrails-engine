"""The rollout's admin side (M4-03): the Guard Service's view of the candidate, and the shadow
comparison report.

* :class:`LifecycleCandidates` is the Guard Service's :class:`~guardrail_engine.guard.rollout.
  CandidateSource`: it reads the tenant's candidate from the lifecycle store (version, mode,
  rollout percent), through the verified tenant scope.
* :class:`RolloutService` answers ``GET /candidate/comparison``: for the tenant's current
  candidate and active version, the **per-rule agreement** between them over the checks where the
  candidate was evaluated alongside (a shadow candidate). The report has counts and rates only: no
  probability and no content, so it can't show a floor rule's ``p``, or a floor-derived tenant
  rule's. A rule is compared by the action it called for; the report says how often the
  candidate called for a stricter or a looser one.
"""

from __future__ import annotations

from typing import Any

from guardrail_engine.admin.lifecycle import NoCandidateError, ScopedLifecycleStores
from guardrail_engine.admin.service import _scope_of
from guardrail_engine.authz.authorizer import AuthzDecision
from guardrail_engine.guard.rollout import CandidateRef
from guardrail_engine.guard.shadow import ShadowReader, report_of
from guardrail_engine.tenant_scope import TenantScope

COMPARISON = ("GET", "/v1/tenants/{tid}/guardrails/candidate/comparison")


class LifecycleCandidates:
    """The candidate pointer, read from the lifecycle store."""

    def __init__(self, lifecycle: ScopedLifecycleStores) -> None:
        self._lifecycle = lifecycle

    async def candidate(self, scope: TenantScope) -> CandidateRef | None:
        state = await self._lifecycle.scoped(scope).state(scope.tenant_id)
        c = state.candidate
        if c is None or state.active is None or c.mode not in ("shadow", "enforce"):
            return None
        return CandidateRef(c.version, c.mode, c.rollout_percent)


class RolloutService:
    def __init__(self, lifecycle: ScopedLifecycleStores, reader: ShadowReader) -> None:
        self._lifecycle = lifecycle
        self._reader = reader

    async def comparison(self, decision: AuthzDecision) -> dict[str, Any]:
        """The agreement report for the tenant's candidate against its active version. Raises
        :class:`~guardrail_engine.admin.lifecycle.NoCandidateError` with no candidate."""
        scope = _scope_of(decision, COMPARISON)
        state = await self._lifecycle.scoped(scope).state(scope.tenant_id)
        if state.candidate is None or state.active is None:
            raise NoCandidateError()
        candidate = state.candidate
        tally = await self._reader.tally(scope, state.active, candidate.version)
        return report_of(
            tally,
            active_version=state.active,
            candidate_version=candidate.version,
            mode=candidate.mode,
            rollout_percent=candidate.rollout_percent,
        )
