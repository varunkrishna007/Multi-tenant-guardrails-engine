"""Question and answer types for the Decisions API contract.

Field names and shapes mirror the wire format, so
``q.model_dump(mode="json", exclude_none=True)`` produces the request shape and
``ANSWER_ADAPTER.validate_python(...)`` parses the response shape.

Sources: the design doc's call example (``noul``), and for ``choice`` and ``score`` the
request and response examples on flaviocopes.com/gemini-decisions-api, which the design
cites. That page is a secondary source, so the real Gemini adapter must verify these
shapes against Google's documentation and recorded responses.
"""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, Strict, TypeAdapter, field_validator

from guardrail_engine.decision.limits import (
    CONFIDENCE_MAX,
    CONFIDENCE_MIN,
    MAX_OPTIONS,
    MIN_OPTIONS,
    NOUL_MAX,
    NOUL_MIN,
)


class _Frozen(BaseModel):
    """Outbound and internal models: unknown fields are a bug."""

    model_config = ConfigDict(frozen=True, extra="forbid")


class _Response(BaseModel):
    """Models parsed from provider responses: unknown fields are ignored, so an
    additive provider change can't fail every call. Known fields stay strictly checked."""

    model_config = ConfigDict(frozen=True, extra="ignore")


# --------------------------------------------------------------------------- questions


class NoulCriteria(_Frozen):
    """Makes "yes" unambiguous for a ``noul`` question. Both sides are required."""

    true_description: str = Field(min_length=1)
    false_description: str = Field(min_length=1)


def _check_options(options: dict[str, str]) -> dict[str, str]:
    if not MIN_OPTIONS <= len(options) <= MAX_OPTIONS:
        raise ValueError(f"needs {MIN_OPTIONS}-{MAX_OPTIONS} options, got {len(options)}")
    if any(not k for k in options):
        raise ValueError("option keys must be non-empty")
    return options


def _check_levels(levels: list[str]) -> list[str]:
    if not MIN_OPTIONS <= len(levels) <= MAX_OPTIONS:
        raise ValueError(f"needs {MIN_OPTIONS}-{MAX_OPTIONS} levels, got {len(levels)}")
    if any(not d for d in levels):
        raise ValueError("level descriptions must be non-empty")
    return levels


class NoulQuestion(_Frozen):
    """A yes/no question. The answer is the probability of "yes"."""

    type: Literal["noul"] = "noul"
    instructions: str = Field(min_length=1)
    criteria: NoulCriteria | None = None


class ChoiceQuestion(_Frozen):
    """Pick one of 2-255 options, given as ``{option_key: description}``.

    The API sorts option keys alphabetically before the model sees them, so never
    encode meaning in option order; use :class:`ScoreQuestion` when order matters.
    """

    type: Literal["choice"] = "choice"
    instructions: str = Field(min_length=1)
    criteria: dict[str, str]

    _validate_options = field_validator("criteria")(_check_options)


class ScoreQuestion(_Frozen):
    """Grade on 2-255 ordered levels: ``criteria`` is a list of level descriptions,
    lowest first. Level ``i`` is referred to by its index (``"0"``, ``"1"``... in answers).
    """

    type: Literal["score"] = "score"
    instructions: str = Field(min_length=1)
    criteria: list[str]

    _validate_levels = field_validator("criteria")(_check_levels)


Question = Annotated[NoulQuestion | ChoiceQuestion | ScoreQuestion, Field(discriminator="type")]
QUESTION_ADAPTER: TypeAdapter[Question] = TypeAdapter(Question)


# --------------------------------------------------------------------------- answers

# Response numbers are strict: a JSON number, never a numeric string or a boolean,
# so wire-type drift surfaces as an ``invalid`` answer instead of being silently coerced.
StrictNumber = Annotated[float, Strict()]
Confidence = Annotated[float, Strict(), Field(ge=CONFIDENCE_MIN, le=CONFIDENCE_MAX)]
Probability = Annotated[float, Strict(), Field(ge=0.0, le=1.0)]


class NoulAnswer(_Response):
    type: Literal["noul"] = "noul"
    noul: StrictNumber = Field(ge=NOUL_MIN, le=NOUL_MAX)
    confidence: Confidence


class ChoiceAnswer(_Response):
    """``choice`` is the most likely option key; ``probabilities`` maps every option key to
    its probability (they sum to about 1). ``confidence`` is the chosen option's probability.
    """

    type: Literal["choice"] = "choice"
    choice: Annotated[str, Strict()] = Field(min_length=1)
    probabilities: dict[str, Probability]
    confidence: Confidence


class ScoreAnswer(_Response):
    """A distribution over the question's levels, not a single level.

    * ``score``: the expected level (probability-weighted mean of level indices), e.g. 1.12.
    * ``probabilities``: level index as a string (``"0"``, ``"1"``...) to probability.
    * ``legend``: level index as a string to that level's description.
    * ``confidence``: the probability of the most likely level.
    """

    type: Literal["score"] = "score"
    score: StrictNumber = Field(ge=0.0, allow_inf_nan=False)
    probabilities: dict[str, Probability]
    legend: dict[str, str] = Field(default_factory=dict)
    confidence: Confidence

    @property
    def expected_level(self) -> float:
        return self.score

    def argmax_level(self) -> int:
        """Index of the most likely level (ties go to the lower level).

        Falls back to ``round(score)`` when ``probabilities`` has no integer keys.
        """
        indexed = [(int(k), p) for k, p in self.probabilities.items() if k.isdigit()]
        if not indexed:
            return round(self.score)
        return min(indexed, key=lambda ip: (-ip[1], ip[0]))[0]


Answer = Annotated[NoulAnswer | ChoiceAnswer | ScoreAnswer, Field(discriminator="type")]
ANSWER_ADAPTER: TypeAdapter[Answer] = TypeAdapter(Answer)


class Usage(_Response):
    """Token usage for one call. Input is billed once per call; output is always free."""

    total_input_tokens: Annotated[int, Strict()] = Field(ge=0)
    total_output_tokens: Annotated[int, Strict()] = Field(default=0, ge=0)


def answer_matches(question: Question, answer: Answer) -> bool:
    """True if ``answer`` has the same type as ``question`` and stays within its options:
    a ``choice`` names a declared option, and a ``score`` lies within the declared levels.

    The Guard Service's per-rule contract check (PF-6, M1-05) can build on this.
    """
    if isinstance(question, NoulQuestion):
        return isinstance(answer, NoulAnswer)
    if isinstance(question, ChoiceQuestion):
        return isinstance(answer, ChoiceAnswer) and answer.choice in question.criteria
    return (
        isinstance(answer, ScoreAnswer)
        and 0 <= answer.score <= len(question.criteria) - 1
        and 0 <= answer.argmax_level() < len(question.criteria)
    )
