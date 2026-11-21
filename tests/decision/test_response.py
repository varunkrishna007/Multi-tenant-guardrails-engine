"""The shared raw-response parser (AC-M1-8 path, PF-6)."""

import json
from pathlib import Path

import pytest

from guardrail_engine.decision import (
    Answered,
    ChoiceQuestion,
    Failed,
    FailureKind,
    NoulAnswer,
    NoulQuestion,
    ProblemKind,
    ScoreQuestion,
    parse_response,
)

QUESTIONS = {
    "p__inj": NoulQuestion(instructions="Is it an injection?"),
    "t__adv": NoulQuestion(instructions="Is it advice?"),
    "p__route": ChoiceQuestion(instructions="Scope?", criteria={"in_scope": "", "off": ""}),
    "p__sev": ScoreQuestion(instructions="Severity?", criteria=["low", "mid", "high"]),
}
USAGE = {"total_input_tokens": 120, "total_output_tokens": 0}


def good_answers() -> dict:
    return {
        "p__inj": {"type": "noul", "noul": 0.02, "confidence": 0.98},
        "t__adv": {"type": "noul", "noul": 0.94, "confidence": 0.94},
        "p__route": {
            "type": "choice",
            "choice": "in_scope",
            "probabilities": {"in_scope": 0.9, "off": 0.1},
            "confidence": 0.9,
        },
        "p__sev": {
            "type": "score",
            "score": 1.1,
            "probabilities": {"0": 0.1, "1": 0.7, "2": 0.2},
            "legend": {"0": "low", "1": "mid", "2": "high"},
            "confidence": 0.7,
        },
    }


def parse(answers: dict, **top) -> Answered:
    res = parse_response({"answers": answers, "usage": USAGE, **top}, QUESTIONS)
    assert isinstance(res, Answered), res
    return res


class TestWellFormed:
    def test_all_answers_valid_and_no_problems(self):
        res = parse(good_answers())
        assert res.ok
        assert set(res.answers) == set(QUESTIONS)
        assert res.usage.total_input_tokens == 120

    def test_extra_fields_everywhere_are_ignored(self):
        # Top level, usage, and inside an answer; none are defects.
        answers = good_answers()
        answers["t__adv"]["explanation_v2"] = "new provider field"
        res = parse_response(
            {
                "answers": answers,
                "usage": {**USAGE, "total_tokens": 120, "input_tokens_by_modality": []},
                "model_version": "gemini-decision-1-001",
            },
            QUESTIONS,
        )
        assert isinstance(res, Answered)
        assert res.ok
        assert res.answers["t__adv"] == NoulAnswer(noul=0.94, confidence=0.94)

    def test_answer_for_unasked_key_is_ignored(self):
        res = parse({**good_answers(), "zz_unasked": {"type": "noul", "noul": 0.5}})
        assert res.ok
        assert "zz_unasked" not in res.answers


class TestDefects:
    def test_missing_key(self):
        answers = good_answers()
        del answers["p__inj"]
        res = parse(answers)
        assert res.problems["p__inj"].kind is ProblemKind.MISSING
        assert "p__inj" not in res.answers

    def test_wrong_type(self):
        answers = good_answers()
        answers["t__adv"] = {
            "type": "choice",
            "choice": "yes",
            "probabilities": {},
            "confidence": 1,
        }
        res = parse(answers)
        assert res.problems["t__adv"].kind is ProblemKind.WRONG_TYPE
        assert res.problems["t__adv"].raw == answers["t__adv"]

    @pytest.mark.parametrize("p", [1.0, 1.2, 0.0, -0.3])
    def test_noul_out_of_range(self, p):
        answers = good_answers()
        answers["t__adv"]["noul"] = p
        res = parse(answers)
        problem = res.problems["t__adv"]
        assert problem.kind is ProblemKind.OUT_OF_RANGE
        assert problem.raw["noul"] == p  # the raw value reaches the caller intact

    def test_probability_above_one(self):
        answers = good_answers()
        answers["p__route"]["probabilities"]["in_scope"] = 1.4
        assert parse(answers).problems["p__route"].kind is ProblemKind.OUT_OF_RANGE

    def test_confidence_out_of_range(self):
        answers = good_answers()
        answers["p__inj"]["confidence"] = 1.5
        assert parse(answers).problems["p__inj"].kind is ProblemKind.OUT_OF_RANGE

    def test_undeclared_choice(self):
        answers = good_answers()
        answers["p__route"]["choice"] = "billing"
        assert parse(answers).problems["p__route"].kind is ProblemKind.OUT_OF_RANGE

    def test_choice_probabilities_name_undeclared_option(self):
        answers = good_answers()
        answers["p__route"]["probabilities"]["billing"] = 0.0
        assert parse(answers).problems["p__route"].kind is ProblemKind.OUT_OF_RANGE

    def test_score_above_top_level(self):
        answers = good_answers()
        answers["p__sev"]["score"] = 2.5
        assert parse(answers).problems["p__sev"].kind is ProblemKind.OUT_OF_RANGE

    def test_score_probabilities_name_undeclared_level(self):
        answers = good_answers()
        answers["p__sev"]["probabilities"]["3"] = 0.0
        assert parse(answers).problems["p__sev"].kind is ProblemKind.OUT_OF_RANGE

    @pytest.mark.parametrize(
        "raw",
        [
            "0.94",
            None,
            {"type": "noul", "confidence": 0.9},  # required field missing
            {"type": "noul", "noul": "high", "confidence": 0.9},  # not a number
        ],
    )
    def test_other_malformations_are_invalid(self, raw):
        answers = good_answers()
        answers["t__adv"] = raw
        assert parse(answers).problems["t__adv"].kind is ProblemKind.INVALID

    def test_one_bad_key_leaves_the_others_intact(self):
        answers = good_answers()
        answers["t__adv"]["noul"] = 1.0
        del answers["p__sev"]
        res = parse(answers)
        assert set(res.problems) == {"t__adv", "p__sev"}
        assert set(res.answers) == {"p__inj", "p__route"}
        assert not res.ok

    def test_every_question_key_lands_in_exactly_one_place(self):
        answers = good_answers()
        del answers["p__inj"]
        answers["p__route"]["choice"] = "nope"
        res = parse(answers)
        assert set(res.answers) | set(res.problems) == set(QUESTIONS)
        assert not set(res.answers) & set(res.problems)


class TestUnusableBody:
    @pytest.mark.parametrize(
        "body",
        [
            None,
            "not json-shaped",
            [1, 2, 3],
            {"usage": USAGE},  # no answers
            {"answers": [1], "usage": USAGE},  # answers not an object
        ],
    )
    def test_gives_failed_other(self, body):
        res = parse_response(body, QUESTIONS)
        assert isinstance(res, Failed)
        assert res.kind is FailureKind.OTHER


class TestUsageUnknown:
    """Decision: metering never decides whether traffic is blocked."""

    def test_missing_usage_keeps_answers_with_usage_unknown(self):
        res = parse_response({"answers": good_answers()}, QUESTIONS)
        assert isinstance(res, Answered)
        assert res.ok
        assert res.usage is None
        assert "no 'usage'" in res.usage_problem

    @pytest.mark.parametrize(
        "usage", [{"total_input_tokens": -5}, {"total_input_tokens": "184"}, "lots", None]
    )
    def test_invalid_usage_keeps_answers_with_usage_unknown(self, usage):
        res = parse_response({"answers": good_answers(), "usage": usage}, QUESTIONS)
        assert isinstance(res, Answered)
        assert res.ok
        assert res.usage is None
        assert res.usage_problem.startswith("invalid 'usage'")

    def test_unknown_usage_is_distinguishable_from_zero(self):
        zero = parse_response(
            {"answers": good_answers(), "usage": {"total_input_tokens": 0}}, QUESTIONS
        )
        assert zero.usage is not None and zero.usage.total_input_tokens == 0
        assert zero.usage_problem is None


class TestStrictNumbers:
    """Wire-type drift is invalid, never coerced."""

    @pytest.mark.parametrize(
        ("key", "field", "value"),
        [
            ("t__adv", "noul", "0.5"),
            ("t__adv", "noul", True),
            ("t__adv", "confidence", "0.9"),
            ("p__sev", "score", "1.0"),
            ("p__route", "choice", 1),
        ],
    )
    def test_numeric_strings_and_booleans_are_invalid(self, key, field, value):
        answers = good_answers()
        answers[key][field] = value
        assert parse(answers).problems[key].kind is ProblemKind.INVALID

    def test_probability_given_as_string_is_invalid(self):
        answers = good_answers()
        answers["p__route"]["probabilities"]["in_scope"] = "0.9"
        assert parse(answers).problems["p__route"].kind is ProblemKind.INVALID

    def test_json_integers_are_accepted_as_numbers(self):
        answers = good_answers()
        answers["p__sev"].update(score=1, probabilities={"0": 0, "1": 1, "2": 0}, confidence=1)
        assert parse(answers).ok


class TestProbabilityCoverage:
    """Probabilities must cover every declared option or level."""

    @pytest.mark.parametrize("key", ["p__route", "p__sev"])
    def test_empty_probabilities_are_invalid(self, key):
        answers = good_answers()
        answers[key]["probabilities"] = {}
        problem = parse(answers).problems[key]
        assert problem.kind is ProblemKind.INVALID
        assert "missing" in problem.detail

    def test_choice_probabilities_missing_one_option(self):
        answers = good_answers()
        del answers["p__route"]["probabilities"]["off"]
        assert parse(answers).problems["p__route"].kind is ProblemKind.INVALID

    def test_score_probabilities_missing_one_level(self):
        answers = good_answers()
        del answers["p__sev"]["probabilities"]["2"]
        assert parse(answers).problems["p__sev"].kind is ProblemKind.INVALID


LIVE_FIXTURE = Path(__file__).parent / "fixtures" / "live_2026-11-16_noul_choice.json"


def test_live_response_parses_cleanly():
    """A real Decisions API body recorded on 2026-11-16 (synthetic content, no headers)."""
    body = json.loads(LIVE_FIXTURE.read_text())
    questions = {
        "t__fin_adv_01": NoulQuestion(instructions="Does it recommend a product?"),
        "p__route": ChoiceQuestion(
            instructions="Scope?", criteria={"in_scope": "", "off_domain": ""}
        ),
    }
    res = parse_response(body, questions)
    assert isinstance(res, Answered)
    assert res.ok
    assert res.noul("t__fin_adv_01") == pytest.approx(0.0147, abs=1e-4)
    assert res.answers["p__route"].choice == "in_scope"
    assert res.usage.total_input_tokens == 184
    assert res.usage.total_output_tokens == 0
