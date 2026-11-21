"""Limits of the Gemini Decisions API, as stated in the design doc.

Request-level limits (question count, key format, context size) are checked by
:func:`validate_request`. Per-question limits (option and level counts) and answer ranges
are enforced when the pydantic models in :mod:`guardrail_engine.decision.types` are built.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import TYPE_CHECKING

from guardrail_engine.tokens import estimate_question_tokens, estimate_tokens

if TYPE_CHECKING:
    from guardrail_engine.decision.types import Question

MAX_QUESTIONS = 1000
"""Questions per request (shared input). The policy compiler reserves 100 of these."""

MAX_KEY_LENGTH = 64
KEY_PATTERN = re.compile(r"[A-Za-z0-9_-]+")
"""Question keys must fully match this pattern and be at most MAX_KEY_LENGTH chars."""

MIN_OPTIONS = 2
MAX_OPTIONS = 255
"""Option / level count bounds for ``choice`` and ``score`` questions."""

NOUL_MIN = 0.01
NOUL_MAX = 0.99
"""Range of a ``noul`` (yes/no) probability."""

CONFIDENCE_MIN = 0.0
CONFIDENCE_MAX = 1.0

CONTEXT_TOKENS = 262_144
"""Context window shared by the input and the questions. Checked by :func:`validate_request`
with the shared estimator in :mod:`guardrail_engine.tokens` (AC-M1-5). The real Gemini adapter
must verify how the API reports an overflow and map it to ``FailureKind.LIMIT_EXCEEDED``.
"""


class DecisionLimitError(ValueError):
    """A request violates a Decisions API limit. ``key`` names the offending question, if any."""

    def __init__(self, reason: str, key: str | None = None) -> None:
        self.reason = reason
        self.key = key
        super().__init__(f"{reason} (question key: {key!r})" if key is not None else reason)


def validate_key(key: str) -> None:
    """Raise :class:`DecisionLimitError` if ``key`` is not a valid question key."""
    if len(key) > MAX_KEY_LENGTH:
        raise DecisionLimitError(f"question key longer than {MAX_KEY_LENGTH} characters", key)
    if not KEY_PATTERN.fullmatch(key):
        raise DecisionLimitError("question key must match [A-Za-z0-9_-]+", key)


def validate_questions(questions: Mapping[str, Question]) -> None:
    """Check request-level limits: 1..MAX_QUESTIONS questions, every key well-formed."""
    if not questions:
        raise DecisionLimitError("a request needs at least one question")
    if len(questions) > MAX_QUESTIONS:
        raise DecisionLimitError(f"{len(questions)} questions exceeds the limit of {MAX_QUESTIONS}")
    for key in questions:
        validate_key(key)


def validate_request(input: str, questions: Mapping[str, Question]) -> None:
    """Check every request-level limit: the questions (see :func:`validate_questions`) and
    the estimated input plus question tokens against :data:`CONTEXT_TOKENS`."""
    validate_questions(questions)
    tokens = estimate_tokens(input) + estimate_question_tokens(questions)
    if tokens > CONTEXT_TOKENS:
        raise DecisionLimitError(
            f"estimated {tokens} input and question tokens exceeds the context limit of "
            f"{CONTEXT_TOKENS}"
        )
