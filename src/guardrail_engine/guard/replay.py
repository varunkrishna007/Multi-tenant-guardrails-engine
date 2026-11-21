"""Replaying a decision record under new thresholds, with no model call (M1-06).

An :class:`~guardrail_engine.guard.audit.AuditRecord` keeps every rule's evaluation: its
probability (or that it was resolved by fail mode, and why), its mode, layer, fail mode and
thresholds. :func:`replay` re-resolves each rule with the engine's own
:func:`~guardrail_engine.guard.fusion.resolve_rule`, substituting any new thresholds, and
fuses the result with the engine's own :func:`~guardrail_engine.guard.fusion.fuse`. So with
unchanged thresholds it reproduces the stored decision, reason and fired rules exactly, and
there is no second copy of the resolution logic to drift.

What thresholds can't change:

* a rule resolved by its **fail mode** (the call failed, or its answer was unusable) has no
  probability, so it resolves the same way whatever its thresholds;
* a decision that **no rule evaluation produced** (forbidden, invalid request, policy
  unavailable, content too large, no questions, provider safety, internal error) is returned
  as stored, with ``recomputed`` False.

**Replay can't loosen the floor.** Live, a compiled floor rule whose thresholds are
above the catalog's never decides: the floor integrity check fails the check closed
as ``block``/``internal_error``. So replay refuses, by raising :class:`ReplayRefused`, any
new ``block_at`` or ``escalate_at`` for a floor rule that is above the record's own value
(which is at or below the catalog's) or, when ``floor_specs`` is given, above the catalog
floor spec's. Lowering a floor threshold is allowed. Every supplied threshold must also be a
finite number (NaN, infinity, None and booleans are refused, as elsewhere in this module).

It raises rather than returning a "refused" result: a result object has a ``decision`` a
caller could read without checking a flag, and replay feeds calibration and what-if
arguments, where an outcome no live configuration can produce must not slip through. A
batch replay catches :class:`ReplayRefused` per record.
"""

from __future__ import annotations

import math
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol

from guardrail_engine.guard.audit import AuditRecord
from guardrail_engine.guard.fusion import fuse, resolve_rule
from guardrail_engine.guard.verdict import (
    Decision,
    FiredRule,
    Reason,
    RuleEvaluation,
    escalated_by_deterministic,
)

REPLAYABLE_REASONS = frozenset({Reason.POLICY, Reason.CONTRACT_VIOLATION, Reason.MODEL_FAILURE})
"""Reasons whose decision came from fusing rule evaluations. A ``deterministic`` escalate that
the model's rules also ran under is replayable too (see :func:`replay`)."""


class ThresholdPair(Protocol):
    """Anything with the two thresholds: :class:`Thresholds`, or a catalog floor spec."""

    @property
    def block_at(self) -> float | None: ...
    @property
    def escalate_at(self) -> float | None: ...


class ReplayRefused(ValueError):
    """The requested thresholds are ones the live engine could never decide with: a floor
    threshold above the record's or the catalog's, or a value that isn't a finite number.
    ``problems`` lists each, as ``"<key>: <what>"``."""

    def __init__(self, problems: list[str]) -> None:
        self.problems = problems
        super().__init__("replay refused: " + "; ".join(problems))


def _finite(value: object) -> bool:
    return isinstance(value, int | float) and not isinstance(value, bool) and math.isfinite(value)


@dataclass(frozen=True, slots=True)
class Thresholds:
    """A rule's thresholds for a replay. ``escalate_at <= block_at``, both in [0, 1]."""

    block_at: float
    escalate_at: float

    def __post_init__(self) -> None:
        values = (self.escalate_at, self.block_at)
        if not all(
            isinstance(v, int | float) and not isinstance(v, bool) and math.isfinite(v)
            for v in values
        ):
            raise ValueError(f"thresholds must be finite numbers, got {values}")
        if not 0.0 <= self.escalate_at <= self.block_at <= 1.0:
            raise ValueError(
                f"need 0 <= escalate_at <= block_at <= 1, got escalate_at={self.escalate_at} "
                f"block_at={self.block_at}"
            )


@dataclass(frozen=True, slots=True)
class Replayed:
    decision: Decision
    reason: Reason
    fired: tuple[FiredRule, ...]
    rules: tuple[RuleEvaluation, ...]
    """Every rule re-resolved, with the thresholds used."""
    recomputed: bool
    """False when the record's decision came from no rule evaluation and was returned as
    stored."""

    @property
    def fired_keys(self) -> tuple[str, ...]:
        return tuple(f.key for f in self.fired)


def replay(
    record: AuditRecord,
    thresholds: Mapping[str, ThresholdPair] | None = None,
    *,
    floor_specs: Mapping[str, ThresholdPair] | None = None,
) -> Replayed:
    """``record``'s decision recomputed with ``thresholds`` (by rule key) in place of the
    recorded ones. Rules not named keep their recorded thresholds; keys the record doesn't
    have are ignored, so one map can be replayed over records from every guard point.
    ``floor_specs`` optionally gives the catalog floor's thresholds by key, as a further
    bound on floor rules. Makes no model call: it reads only the record.

    Raises :class:`ReplayRefused` for a floor threshold above the record's (or the catalog
    spec's) or a threshold that isn't a finite number."""
    thresholds = thresholds or {}
    if problems := _refusals(record, thresholds, floor_specs or {}):
        raise ReplayRefused(problems)
    replayable = record.reason in REPLAYABLE_REASONS or (
        record.reason is Reason.DETERMINISTIC and record.decision is Decision.ESCALATE
    )
    if not replayable or not record.rules:
        return Replayed(
            decision=record.decision,
            reason=record.reason,
            fired=tuple(
                FiredRule(
                    key=f.rule,
                    p=f.p,
                    action=f.action,
                    mode=f.mode,
                    layer=f.layer,
                    provisional=f.provisional,
                    basis=f.basis,
                )
                for f in record.fired
            ),
            rules=record.rules,
            recomputed=False,
        )
    rules = tuple(
        resolve_rule(
            _with(ev, thresholds.get(ev.key)),
            basis=ev.basis,
            p=ev.p,
            answer=ev.answer,
            problem=ev.problem,
        )
        for ev in record.rules
    )
    fused = fuse(rules, call_failed=record.reason is Reason.MODEL_FAILURE)
    # A deterministic escalate stays under any thresholds: the more severe result wins.
    decision, reason = escalated_by_deterministic(
        Decision(fused.action.value), fused.reason, record.deterministic
    )
    return Replayed(
        decision=decision,
        reason=reason,
        fired=fused.fired,
        rules=rules,
        recomputed=True,
    )


def _refusals(
    record: AuditRecord,
    thresholds: Mapping[str, ThresholdPair],
    floor_specs: Mapping[str, ThresholdPair],
) -> list[str]:
    problems = []
    for ev in record.rules:
        new = thresholds.get(ev.key)
        if new is None:
            continue
        values = {"block_at": getattr(new, "block_at", None)}
        values["escalate_at"] = getattr(new, "escalate_at", None)
        bad = [name for name, value in values.items() if not _finite(value)]
        for name in bad:
            problems.append(f"{ev.key}: {name} {values[name]!r} is not a finite number")
        if bad:
            continue
        if not 0.0 <= values["escalate_at"] <= values["block_at"] <= 1.0:
            problems.append(f"{ev.key}: need 0 <= escalate_at <= block_at <= 1")
        if ev.layer != "floor":
            continue
        spec = floor_specs.get(ev.key)
        for name, value in values.items():
            bounds = [("the record's", getattr(ev, name))]
            if spec is not None and getattr(spec, name, None) is not None:
                bounds.append(("the catalog's", getattr(spec, name)))
            for whose, bound in bounds:
                # Written so that a bound that isn't a finite number also refuses.
                if not (_finite(bound) and value <= bound):
                    problems.append(
                        f"{ev.key}: floor {name} {value} is above {whose} {bound}; replay "
                        "can't loosen the floor"
                    )
    return problems


def _with(ev: RuleEvaluation, new: ThresholdPair | None) -> RuleEvaluation:
    if new is None:
        return ev
    return ev.model_copy(update={"block_at": new.block_at, "escalate_at": new.escalate_at})
