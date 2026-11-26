"""A cap on the requests a process sends to the provider, for its lifetime (M7-10).

``CallCap`` is the counter and ``CappedDecisionModel`` wraps a ``DecisionModel`` with it. The
count is taken **immediately before every send** (the check and the increment have no await
between them, so concurrent calls can't overshoot), a retry and a breaker probe included, because
every one of them is a call to ``decide``. Past the cap nothing is sent: the call returns a
``Failed`` (kind ``other``, reason ``live_call_cap``), which the engine resolves by the rules' fail
modes, so the floor blocks. The cap never rolls and never resets: it counts requests started by
this process, so "N calls approved" is exactly N, and a restart is a new run with its own approval.
"""

from __future__ import annotations

from collections.abc import Mapping

from guardrail_engine.decision.port import DecisionModel, DecisionResult, Failed, FailureKind
from guardrail_engine.decision.types import Question

REASON_LIVE_CALL_CAP = "live_call_cap"


class CallCap:
    def __init__(self, limit: int) -> None:
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
            raise ValueError("the call cap must be a whole number of at least 1")
        self.limit = limit
        self.used = 0

    def take(self) -> bool:
        """Count one send if the cap allows it. Synchronous: no other call can run between the
        check and the count."""
        if self.used >= self.limit:
            return False
        self.used += 1
        return True


class CappedDecisionModel:
    def __init__(self, model: DecisionModel, cap: CallCap) -> None:
        self._model = model
        self.cap = cap

    @property
    def model_id(self) -> str:
        return self._model.model_id

    async def decide(self, input: str, questions: Mapping[str, Question]) -> DecisionResult:
        if not self.cap.take():
            return Failed(kind=FailureKind.OTHER, reason=REASON_LIVE_CALL_CAP)
        return await self._model.decide(input, questions)
