"""AC-M1-2 (question types) and AC-M1-3 (answer types, published shapes)."""

import pytest
from pydantic import ValidationError

from guardrail_engine.decision import (
    ANSWER_ADAPTER,
    QUESTION_ADAPTER,
    ChoiceAnswer,
    ChoiceQuestion,
    NoulAnswer,
    NoulCriteria,
    NoulQuestion,
    ScoreAnswer,
    ScoreQuestion,
    Usage,
    answer_matches,
)

# The questions from "What one call looks like" in the design doc, verbatim.
DOC_QUESTIONS = {
    "p__ai_addressed": {
        "type": "noul",
        "instructions": (
            "Does the content address an AI system or try to influence how it is evaluated?"
        ),
    },
    "t__fin_adv_01": {
        "type": "noul",
        "instructions": (
            "Does the response recommend buying, selling or holding a specific financial product?"
        ),
        "criteria": {
            "true_description": (
                "Gives a personalised recommendation on a specific product or security."
            ),
            "false_description": (
                "Explains general concepts, policy terms or factual product information."
            ),
        },
    },
    "p__route": {
        "type": "choice",
        "instructions": "Which scope does this content fall into?",
        "criteria": {
            "in_scope": "Insurance policies, claims and coverage.",
            "off_domain": "Anything unrelated to the tenant's insurance business.",
        },
    },
}

# Published examples (flaviocopes.com/gemini-decisions-api, cited by the design doc).
PUBLISHED_SCORE_QUESTION = {
    "type": "score",
    "instructions": "How severe is the reported bug?",
    "criteria": [
        "Cosmetic: appearance only, no lost functionality.",
        "Workaround available: a task fails, but another way works.",
        "Fully blocked: a task fails with no workaround.",
    ],
}
PUBLISHED_SCORE_ANSWER = {
    "confidence": 0.8264572684797179,
    "score": 1.121459528316996,
    "probabilities": {
        "0": 0.02604160160164308,
        "1": 0.8264572684797179,
        "2": 0.147501129918639,
    },
    "legend": {
        "0": "Cosmetic: appearance only, no lost functionality.",
        "1": "Workaround available: a task fails, but another way works.",
        "2": "Fully blocked: a task fails with no workaround.",
    },
    "type": "score",
}
PUBLISHED_CHOICE_ANSWER = {
    "confidence": 0.9838489287002516,
    "choice": "replacements",
    "probabilities": {
        "replacements": 0.9838489287002516,
        "billing": 0.009792702859044131,
        "general": 0.006358368440704238,
    },
    "type": "choice",
}


def opts(n: int = 2) -> dict[str, str]:
    return {f"opt{i}": f"option {i}" for i in range(n)}


def levels(n: int = 2) -> list[str]:
    return [f"level {i}" for i in range(n)]


class TestQuestionWireFormat:
    def test_doc_example_round_trips(self):
        parsed = {k: QUESTION_ADAPTER.validate_python(v) for k, v in DOC_QUESTIONS.items()}
        assert isinstance(parsed["p__ai_addressed"], NoulQuestion)
        assert isinstance(parsed["t__fin_adv_01"], NoulQuestion)
        assert isinstance(parsed["p__route"], ChoiceQuestion)
        dumped = {k: q.model_dump(mode="json", exclude_none=True) for k, q in parsed.items()}
        assert dumped == DOC_QUESTIONS

    def test_published_score_question_round_trips(self):
        q = QUESTION_ADAPTER.validate_python(PUBLISHED_SCORE_QUESTION)
        assert isinstance(q, ScoreQuestion)
        assert q.model_dump(mode="json", exclude_none=True) == PUBLISHED_SCORE_QUESTION

    def test_score_criteria_must_be_a_list(self):
        with pytest.raises(ValidationError):
            ScoreQuestion(instructions="x", criteria={"low": "a", "high": "b"})  # type: ignore[arg-type]

    def test_noul_without_criteria_omits_the_field(self):
        q = NoulQuestion(instructions="Is it spam?")
        assert q.model_dump(exclude_none=True) == {"type": "noul", "instructions": "Is it spam?"}

    def test_unknown_type_rejected(self):
        with pytest.raises(ValidationError):
            QUESTION_ADAPTER.validate_python({"type": "text", "instructions": "x"})

    def test_questions_stay_strict_on_extra_fields(self):
        with pytest.raises(ValidationError):
            NoulQuestion(instructions="x", foo=1)

    def test_questions_are_immutable(self):
        q = NoulQuestion(instructions="x")
        with pytest.raises(ValidationError):
            q.instructions = "y"

    def test_empty_instructions_rejected(self):
        with pytest.raises(ValidationError):
            NoulQuestion(instructions="")


class TestNoulCriteria:
    def test_both_descriptions_required(self):
        with pytest.raises(ValidationError):
            NoulCriteria(true_description="yes")  # type: ignore[call-arg]
        with pytest.raises(ValidationError):
            NoulCriteria(true_description="yes", false_description="")


class TestOptionAndLevelBounds:
    """AC-M1-2: building a choice or score outside 2-255 options/levels raises."""

    @pytest.mark.parametrize("n", [2, 3, 255])
    def test_choice_accepts_2_to_255(self, n):
        assert len(ChoiceQuestion(instructions="x", criteria=opts(n)).criteria) == n

    @pytest.mark.parametrize("n", [0, 1, 256])
    def test_choice_rejects_outside_range(self, n):
        with pytest.raises(ValidationError, match="2-255 options"):
            ChoiceQuestion(instructions="x", criteria=opts(n))

    def test_choice_rejects_empty_option_key(self):
        with pytest.raises(ValidationError):
            ChoiceQuestion(instructions="x", criteria={"": "a", "b": "b"})

    @pytest.mark.parametrize("n", [2, 3, 255])
    def test_score_accepts_2_to_255(self, n):
        assert len(ScoreQuestion(instructions="x", criteria=levels(n)).criteria) == n

    @pytest.mark.parametrize("n", [0, 1, 256])
    def test_score_rejects_outside_range(self, n):
        with pytest.raises(ValidationError, match="2-255 levels"):
            ScoreQuestion(instructions="x", criteria=levels(n))

    def test_score_rejects_empty_level(self):
        with pytest.raises(ValidationError):
            ScoreQuestion(instructions="x", criteria=["low", ""])


class TestPublishedAnswerShapes:
    """AC-M1-3: answer types match the published response shapes."""

    def test_doc_noul_answer_parses(self):
        a = ANSWER_ADAPTER.validate_python({"type": "noul", "noul": 0.94, "confidence": 0.94})
        assert a == NoulAnswer(noul=0.94, confidence=0.94)

    def test_published_choice_answer_parses(self):
        a = ANSWER_ADAPTER.validate_python(PUBLISHED_CHOICE_ANSWER)
        assert isinstance(a, ChoiceAnswer)
        assert a.choice == "replacements"
        assert a.probabilities["billing"] == pytest.approx(0.0098, abs=1e-4)

    def test_published_score_answer_parses(self):
        a = ANSWER_ADAPTER.validate_python(PUBLISHED_SCORE_ANSWER)
        assert isinstance(a, ScoreAnswer)
        assert a.expected_level == pytest.approx(1.1215, abs=1e-4)
        assert a.argmax_level() == 1
        assert a.legend["2"].startswith("Fully blocked")

    def test_published_answers_match_their_questions(self):
        sq = QUESTION_ADAPTER.validate_python(PUBLISHED_SCORE_QUESTION)
        assert answer_matches(sq, ANSWER_ADAPTER.validate_python(PUBLISHED_SCORE_ANSWER))
        cq = ChoiceQuestion(
            instructions="Route?", criteria={"billing": "", "replacements": "", "general": ""}
        )
        assert answer_matches(cq, ANSWER_ADAPTER.validate_python(PUBLISHED_CHOICE_ANSWER))

    def test_answers_ignore_unknown_fields(self):
        # An additive provider change must not break parsing.
        a = ANSWER_ADAPTER.validate_python({**PUBLISHED_CHOICE_ANSWER, "new_field": [1, 2]})
        assert isinstance(a, ChoiceAnswer)
        u = Usage.model_validate(
            {"total_input_tokens": 100, "total_output_tokens": 0, "total_tokens": 100}
        )
        assert u.total_input_tokens == 100


class TestAnswerBounds:
    """AC-M1-3: out-of-range values are rejected when the type is built."""

    @pytest.mark.parametrize("p", [0.01, 0.5, 0.99])
    def test_noul_range_accepted(self, p):
        assert NoulAnswer(noul=p, confidence=1.0).noul == p

    @pytest.mark.parametrize("p", [0.0, 0.009, 0.991, 1.0, 1.2])
    def test_noul_range_rejected(self, p):
        with pytest.raises(ValidationError):
            NoulAnswer(noul=p, confidence=1.0)

    @pytest.mark.parametrize("c", [-0.01, 1.01])
    def test_confidence_range_rejected(self, c):
        with pytest.raises(ValidationError):
            NoulAnswer(noul=0.5, confidence=c)

    @pytest.mark.parametrize("p", [-0.1, 1.5])
    def test_probability_range_rejected(self, p):
        with pytest.raises(ValidationError):
            ChoiceAnswer(choice="a", probabilities={"a": p}, confidence=0.5)

    @pytest.mark.parametrize("s", [-0.5, float("nan"), float("inf")])
    def test_score_must_be_finite_and_non_negative(self, s):
        with pytest.raises(ValidationError):
            ScoreAnswer(score=s, probabilities={}, confidence=0.5)


class TestAnswerMatches:
    def test_type_mismatch(self):
        q = NoulQuestion(instructions="x")
        assert not answer_matches(q, ChoiceAnswer(choice="a", probabilities={}, confidence=1))

    def test_option_must_be_declared(self):
        q = ChoiceQuestion(instructions="x", criteria={"a": "", "b": ""})
        assert answer_matches(q, ChoiceAnswer(choice="a", probabilities={}, confidence=1))
        assert not answer_matches(q, ChoiceAnswer(choice="z", probabilities={}, confidence=1))

    def test_score_must_be_within_levels(self):
        q = ScoreQuestion(instructions="x", criteria=["lo", "hi"])
        assert answer_matches(q, ScoreAnswer(score=1.0, probabilities={"1": 1.0}, confidence=1))
        assert not answer_matches(q, ScoreAnswer(score=2.0, probabilities={}, confidence=1))


class TestScoreArgmax:
    def test_ties_go_to_lower_level(self):
        a = ScoreAnswer(score=0.5, probabilities={"0": 0.5, "1": 0.5}, confidence=0.5)
        assert a.argmax_level() == 0

    def test_falls_back_to_rounded_score(self):
        assert ScoreAnswer(score=1.6, probabilities={}, confidence=0.5).argmax_level() == 2


class TestUsage:
    def test_output_tokens_default_to_zero(self):
        assert Usage(total_input_tokens=1830).total_output_tokens == 0

    def test_negative_rejected(self):
        with pytest.raises(ValidationError):
            Usage(total_input_tokens=-1)
