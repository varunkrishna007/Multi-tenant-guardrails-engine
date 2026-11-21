"""Resolving each rule and fusing the results into one decision (AC-G3, PF-6, B1, S4).

Per rule, an **action** (allow, escalate or block) is worked out in two steps:

1. **Base action.**
   * From the answer (``Basis.ANSWER``): for a ``noul`` rule, ``p = recalibrate(p)``; then
     ``p >= block_at`` is block, ``escalate_at <= p < block_at`` is escalate, lower is
     allow. A router (``choice``) or scorer (``score``) never acts on its own.
   * From the fail mode (``Basis.FAIL_MODE``): when the call failed (B1), or when this
     rule's answer is missing, of the wrong type or out of range (PF-6). For a ``noul``
     rule ``closed`` is block, ``open`` is allow. The fail mode is the compiled one:
     ``floor_fail_mode`` for floor rules (default ``closed``), the guard point's or
     bundle's for pack and tenant rules. Anything other than ``open`` counts as ``closed``.
     A router or scorer resolves to allow (it never acts on its own).
2. **Ceiling.** The action is capped at the rule's ceiling, :func:`action_ceiling`: block for
   every rule, except one whose ``max_action`` is ``escalate`` (M4-10: "this rule may
   escalate but never block", for people at risk).

Then :func:`fuse` takes the most severe action among **enforce** rules. Shadow rules are
evaluated and recorded with the action they would have taken, but never act.

:func:`resolve_rule` is the one place a rule's action is worked out from its basis and
probability. It takes anything shaped like a rule (:class:`RuleSpec`): a compiled rule on the
check path, or a recorded :class:`RuleEvaluation` when an audit record is replayed under new
thresholds (M1-06), so replay runs exactly this code and no copy of it.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Protocol

from guardrail_engine.decision.port import Answered, ProblemKind
from guardrail_engine.decision.types import Answer, NoulAnswer, Question, answer_matches
from guardrail_engine.guard.verdict import (
    SEVERITY,
    Action,
    Basis,
    ContractViolation,
    FiredRule,
    Reason,
    RuleEvaluation,
    most_severe,
)
from guardrail_engine.policy.compiler import CompiledRule


class RuleSpec(Protocol):
    """What resolution reads from a rule. A :class:`CompiledRule` and a recorded
    :class:`RuleEvaluation` both have it, so the check path and audit replay (M1-06) share
    :func:`resolve_rule`."""

    @property
    def key(self) -> str: ...
    @property
    def layer(self) -> str: ...
    @property
    def source(self) -> str: ...
    @property
    def question_type(self) -> str: ...
    @property
    def mode(self) -> str: ...
    @property
    def severity(self) -> str: ...
    @property
    def provisional(self) -> bool: ...
    @property
    def block_at(self) -> float | None: ...
    @property
    def escalate_at(self) -> float | None: ...
    @property
    def fail_mode(self) -> str: ...
    @property
    def max_action(self) -> str | None: ...


def recalibrate(rule: CompiledRule, p: float) -> float:
    """The identity in v1 (S4). Isotonic recalibration per rule is v1.1."""
    return p


def threshold_action(p: float, block_at: float, escalate_at: float) -> Action:
    """AC-G3: ``p >= block_at`` blocks, ``escalate_at <= p < block_at`` escalates."""
    if p >= block_at:
        return Action.BLOCK
    if p >= escalate_at:
        return Action.ESCALATE
    return Action.ALLOW


def fail_mode_action(rule: RuleSpec) -> Action:
    """B1 / PF-6, for a rule without a usable answer. A ``noul`` rule: ``open`` allows,
    anything else blocks (an unknown value fails closed). A router (``choice``) or scorer
    (``score``) never acts when answered, so it doesn't gain blocking power when its answer
    fails either: it resolves to allow, and the failure is still recorded. This
    loosens nothing: floor rules are ``noul`` and still fail closed."""
    if rule.question_type != "noul":
        return Action.ALLOW
    return Action.ALLOW if rule.fail_mode == "open" else Action.BLOCK


def action_ceiling(rule: RuleSpec) -> Action:
    """The most severe action this rule may take (M4-10, R4.3): block, or escalate for a rule
    whose ``max_action`` is ``escalate`` (it may hold content for a person, never refuse it).
    Anything but ``escalate`` is no cap. Applied to every rule's action by :func:`capped`,
    whatever the basis: a probability of 0.99, or a failed call resolved by a closed fail mode,
    on an escalate-only rule still escalates."""
    return Action.ESCALATE if rule.max_action == "escalate" else Action.BLOCK


def capped(action: Action, rule: RuleSpec) -> Action:
    ceiling = action_ceiling(rule)
    return action if SEVERITY[action] <= SEVERITY[ceiling] else ceiling


def resolve_rule(
    rule: RuleSpec,
    *,
    basis: Basis,
    p: float | None = None,
    answer: Answer | None = None,
    problem: ProblemKind | None = None,
) -> RuleEvaluation:
    """One rule's evaluation, given how it is decided and, for an answered ``noul`` rule,
    its (recalibrated) probability ``p``:

    * ``Basis.FAIL_MODE``: :func:`fail_mode_action` (the call failed, or the answer was
      unusable, PF-6 / B1);
    * ``Basis.ANSWER`` with ``p``: :func:`threshold_action` on the rule's thresholds;
    * ``Basis.ANSWER`` without ``p``: a router or scorer, which never acts on its own. An
      answered ``noul`` rule without ``p`` raises: it would otherwise resolve to
      allow, so a corrupted stored record could replay a block as an allow.

    The action is then capped at the rule's ceiling."""
    if basis is Basis.FAIL_MODE:
        action = fail_mode_action(rule)
    elif p is None and rule.question_type == "noul":
        raise ValueError(f"noul rule {rule.key!r} is answered but has no probability")
    elif p is not None:
        if rule.block_at is None or rule.escalate_at is None:  # the catalog forbids this
            raise ValueError(f"noul rule {rule.key!r} has no thresholds")
        action = threshold_action(p, rule.block_at, rule.escalate_at)
    else:
        action = Action.ALLOW
    return RuleEvaluation(
        key=rule.key,
        layer=rule.layer,
        source=rule.source,
        question_type=rule.question_type,
        mode=rule.mode,
        severity=rule.severity,
        provisional=rule.provisional,
        block_at=rule.block_at,
        escalate_at=rule.escalate_at,
        fail_mode=rule.fail_mode,
        max_action=rule.max_action,
        p=p,
        answer=answer,
        action=capped(action, rule),
        basis=basis,
        problem=problem,
    )


PROBLEM_DETAIL: dict[ProblemKind, str] = {
    ProblemKind.MISSING: "no answer for this key",
    ProblemKind.WRONG_TYPE: "the answer's type differs from the question's",
    ProblemKind.OUT_OF_RANGE: "the answer is out of range or names an undeclared option",
    ProblemKind.INVALID: "the answer is malformed",
}
"""A contract violation's recorded detail: engine wording per kind, never the parser's
text, which can quote the provider's raw answer."""


@dataclass(frozen=True, slots=True)
class Evaluated:
    rules: tuple[RuleEvaluation, ...]
    violations: tuple[ContractViolation, ...]
    probabilities_raw: dict[str, float] = field(default_factory=dict)
    """Each answered ``noul`` rule's probability as the model gave it, before
    :func:`recalibrate` (the rule's ``p`` is the recalibrated one). Recorded beside it so a
    v1.1 recalibration map can be fitted on raw values."""


def evaluate_failed(rules: Mapping[str, CompiledRule]) -> Evaluated:
    """B1: no answers at all, so every rule is resolved by its own fail mode."""
    return Evaluated(
        rules=tuple(resolve_rule(rule, basis=Basis.FAIL_MODE) for rule in rules.values()),
        violations=(),
    )


def evaluate_answered(
    rules: Mapping[str, CompiledRule],
    questions: Mapping[str, Question],
    result: Answered,
) -> Evaluated:
    """Evaluate every rule against the answers. A key whose answer is unusable is resolved
    by its fail mode and recorded as a contract violation (PF-6); the other keys are not
    affected."""
    evaluations: list[RuleEvaluation] = []
    violations: list[ContractViolation] = []
    raw: dict[str, float] = {}
    for key, rule in rules.items():
        answer = result.answers.get(key)
        problem = result.problems.get(key)
        kind: ProblemKind | None = None
        detail = ""
        if problem is not None:
            # The parser's own detail can quote the provider's raw answer: record the
            # engine's wording for the kind instead.
            kind = problem.kind
            detail = PROBLEM_DETAIL[kind]
        elif answer is None:
            kind, detail = ProblemKind.MISSING, "no answer and no recorded problem for this key"
        elif not answer_matches(questions[key], answer):
            kind, detail = ProblemKind.WRONG_TYPE, f"a {answer.type} answer does not fit"

        if kind is not None:
            ev = resolve_rule(rule, basis=Basis.FAIL_MODE, problem=kind)
            violations.append(
                ContractViolation(
                    key=key,
                    kind=kind,
                    detail=detail,
                    mode=rule.mode,
                    layer=rule.layer,
                    resolved_action=ev.action,
                )
            )
        elif isinstance(answer, NoulAnswer):
            raw[key] = answer.noul
            ev = resolve_rule(
                rule, basis=Basis.ANSWER, p=recalibrate(rule, answer.noul), answer=answer
            )
        else:  # a router or scorer: recorded, never acts on its own
            ev = resolve_rule(rule, basis=Basis.ANSWER, answer=answer)
        evaluations.append(ev)
    return Evaluated(rules=tuple(evaluations), violations=tuple(violations), probabilities_raw=raw)


@dataclass(frozen=True, slots=True)
class Fused:
    action: Action
    reason: Reason
    """``MODEL_FAILURE`` for a failed call; otherwise ``POLICY``, or ``CONTRACT_VIOLATION``
    when only rules resolved by fail mode reach the decision."""
    fired: tuple[FiredRule, ...]
    probabilities: dict[str, float]


def fuse(evaluations: tuple[RuleEvaluation, ...], *, call_failed: bool = False) -> Fused:
    """The most severe action among enforce rules wins; shadow rules never act.
    ``call_failed`` says the decision call failed (B1), so every rule was resolved by its
    fail mode and the reason is ``MODEL_FAILURE``."""
    action = most_severe(*(ev.action for ev in evaluations if ev.mode == "enforce"))
    reason = Reason.POLICY
    if call_failed:
        reason = Reason.MODEL_FAILURE
    elif action is not Action.ALLOW and not any(
        ev.mode == "enforce" and ev.action is action and ev.basis is Basis.ANSWER
        for ev in evaluations
    ):
        reason = Reason.CONTRACT_VIOLATION
    fired = tuple(
        FiredRule(
            key=ev.key,
            p=ev.p,
            action=ev.action,
            mode=ev.mode,
            layer=ev.layer,
            provisional=ev.provisional,
            basis=ev.basis,
        )
        for ev in evaluations
        if ev.action is not Action.ALLOW
    )
    probabilities = {ev.key: ev.p for ev in evaluations if ev.p is not None}
    return Fused(action=action, reason=reason, fired=fired, probabilities=probabilities)
