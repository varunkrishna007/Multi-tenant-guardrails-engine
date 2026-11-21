"""AC-M1-5 request limits: question count, key format, context tokens."""

from typing import ClassVar

import pytest

from guardrail_engine.decision import (
    CONTEXT_TOKENS,
    MAX_KEY_LENGTH,
    MAX_QUESTIONS,
    DecisionLimitError,
    NoulQuestion,
    validate_key,
    validate_questions,
    validate_request,
)
from guardrail_engine.tokens import estimate_question_tokens

Q = NoulQuestion(instructions="x")


@pytest.mark.parametrize("key", ["a", "t__fin_adv_01", "p__route", "A-Z_09", "x" * MAX_KEY_LENGTH])
def test_valid_keys(key):
    validate_key(key)


@pytest.mark.parametrize("key", ["", "has space", "dot.key", "slash/key", "ünï", "x" * 65])
def test_invalid_keys(key):
    with pytest.raises(DecisionLimitError) as exc:
        validate_key(key)
    assert exc.value.key == key


def test_compiled_tenant_key_fits():
    # Design doc: rule ids are [a-z0-9_]{1,40}, so "t__<id>" is at most 43 chars.
    validate_key("t__" + "a" * 40)


def test_max_questions_accepted():
    validate_questions({f"q{i}": Q for i in range(MAX_QUESTIONS)})


def test_too_many_questions_rejected():
    with pytest.raises(DecisionLimitError, match="exceeds the limit of 1000"):
        validate_questions({f"q{i}": Q for i in range(MAX_QUESTIONS + 1)})


def test_empty_request_rejected():
    with pytest.raises(DecisionLimitError, match="at least one question"):
        validate_questions({})


def test_bad_key_in_request_named():
    with pytest.raises(DecisionLimitError) as exc:
        validate_questions({"ok": Q, "bad key": Q})
    assert exc.value.key == "bad key"


class TestContextLimit:
    QS: ClassVar[dict[str, NoulQuestion]] = {"k": Q}

    def input_of(self, tokens: int) -> str:
        return "a" * (4 * tokens)  # 4 ASCII chars per estimated token

    def test_exactly_at_limit_accepted(self):
        room = CONTEXT_TOKENS - estimate_question_tokens(self.QS)
        validate_request(self.input_of(room), self.QS)

    def test_one_token_over_limit_rejected(self):
        room = CONTEXT_TOKENS - estimate_question_tokens(self.QS)
        with pytest.raises(DecisionLimitError, match="context limit of 262144"):
            validate_request(self.input_of(room) + "a", self.QS)

    def test_validate_request_also_checks_questions(self):
        with pytest.raises(DecisionLimitError) as exc:
            validate_request("hi", {"bad key": Q})
        assert exc.value.key == "bad key"
