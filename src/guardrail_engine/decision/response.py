"""Turns a raw Decisions API response body into a :data:`DecisionResult`.

Every adapter uses this one parser: the Gemini adapter with the HTTP body, and the fake with
the body it builds, including deliberately malformed bodies (AC-M1-8). Tests of the Guard
Service therefore go through the real parsing path.

Published response shape (flaviocopes.com/gemini-decisions-api, cited by the design)::

    {"answers": {"<key>": {"type": "noul", "noul": 0.94, "confidence": 0.94}, ...},
     "usage": {"total_input_tokens": 1830, "total_output_tokens": 0, ...}}

How the body is resolved:

* If the body has no usable answers (not an object, or ``answers`` not an object), the
  result is ``Failed(OTHER)``.
* A missing or invalid ``usage`` block does not fail the call: the result is
  ``Answered`` with ``usage=None`` and ``usage_problem`` set, so the gateway can count
  and alert on it. Metering never decides whether traffic is blocked.
* Otherwise the result is :class:`Answered`. Each question key ends up in exactly one of
  two places: ``answers``, if its raw answer is valid for that question, or ``problems``,
  if it is missing, of the wrong type, out of range, or otherwise invalid. One bad key
  never fails the whole call, because the Guard Service resolves bad answers per rule
  (PF-6).
* Unknown fields are ignored and are not problems: extra top-level fields, extra fields
  inside ``usage`` or inside an answer, and answers under keys that were never asked.
  An additive provider change must not fail every floor key.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from pydantic import ValidationError

from guardrail_engine.decision.port import (
    Answered,
    AnswerProblem,
    DecisionResult,
    Failed,
    FailureKind,
    ProblemKind,
)
from guardrail_engine.decision.types import (
    ANSWER_ADAPTER,
    Answer,
    ChoiceAnswer,
    ChoiceQuestion,
    NoulQuestion,
    Question,
    ScoreAnswer,
    Usage,
)

# pydantic error types that mean "a number outside its bounds"
_RANGE_ERRORS = frozenset(
    {"greater_than", "greater_than_equal", "less_than", "less_than_equal", "finite_number"}
)


def parse_response(raw: Any, questions: Mapping[str, Question]) -> DecisionResult:
    """Parse a raw response body (plain JSON values) against the questions that were asked."""
    if not isinstance(raw, Mapping):
        return Failed(kind=FailureKind.OTHER, message="response body is not an object")
    raw_answers = raw.get("answers")
    if not isinstance(raw_answers, Mapping):
        return Failed(kind=FailureKind.OTHER, message="response has no 'answers' object")
    usage: Usage | None = None
    usage_problem: str | None = None
    if "usage" not in raw:
        usage_problem = "response has no 'usage' block"
    else:
        try:
            usage = Usage.model_validate(raw["usage"])
        except ValidationError as e:
            usage_problem = f"invalid 'usage': {_summarise(e.errors())}"

    answers: dict[str, Answer] = {}
    problems: dict[str, AnswerProblem] = {}
    for key, question in questions.items():
        if key not in raw_answers:
            problems[key] = AnswerProblem(kind=ProblemKind.MISSING, detail="no answer")
            continue
        result = parse_answer(question, raw_answers[key])
        if isinstance(result, AnswerProblem):
            problems[key] = result
        else:
            answers[key] = result
    return Answered(answers=answers, problems=problems, usage=usage, usage_problem=usage_problem)


def parse_answer(question: Question, raw: Any) -> Answer | AnswerProblem:
    """Validate one raw answer against its question. Returns the answer or the problem."""
    if not isinstance(raw, Mapping):
        return AnswerProblem(kind=ProblemKind.INVALID, detail="answer is not an object", raw=raw)
    if raw.get("type") != question.type:
        return AnswerProblem(
            kind=ProblemKind.WRONG_TYPE,
            detail=f"expected a {question.type!r} answer, got {raw.get('type')!r}",
            raw=raw,
        )
    try:
        answer = ANSWER_ADAPTER.validate_python(raw)
    except ValidationError as e:
        errors = e.errors()
        kind = (
            ProblemKind.OUT_OF_RANGE
            if all(err["type"] in _RANGE_ERRORS for err in errors)
            else ProblemKind.INVALID
        )
        return AnswerProblem(kind=kind, detail=_summarise(errors), raw=raw)

    problem = _check_against_question(question, answer)
    if problem:
        kind, detail = problem
        return AnswerProblem(kind=kind, detail=detail, raw=raw)
    return answer


def _check_against_question(question: Question, answer: Answer) -> tuple[ProblemKind, str] | None:
    """Checks that need the question (AC-M1-3): only declared options and levels, and
    ``probabilities`` covering every one of them."""
    if isinstance(question, NoulQuestion):
        return None
    if isinstance(question, ChoiceQuestion):
        assert isinstance(answer, ChoiceAnswer)
        if answer.choice not in question.criteria:
            return ProblemKind.OUT_OF_RANGE, f"choice {answer.choice!r} is not a declared option"
        declared, what = set(question.criteria), "options"
    else:
        assert isinstance(answer, ScoreAnswer)
        top = len(question.criteria) - 1
        if answer.score > top:
            return ProblemKind.OUT_OF_RANGE, f"score {answer.score} is above the top level {top}"
        declared, what = {str(i) for i in range(top + 1)}, "levels"
    stray = sorted(set(answer.probabilities) - declared)
    if stray:
        return ProblemKind.OUT_OF_RANGE, f"probabilities name undeclared {what} {stray}"
    uncovered = sorted(declared - set(answer.probabilities))
    if uncovered:
        return ProblemKind.INVALID, f"probabilities are missing {what} {uncovered}"
    return None


def _summarise(errors: list[Any]) -> str:
    return "; ".join(
        f"{'.'.join(str(p) for p in err['loc']) or '<answer>'}: {err['msg']}" for err in errors
    )
