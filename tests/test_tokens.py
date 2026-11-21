"""AC-M1-6: one deterministic, documented estimator shared by the fake, limits and compiler."""

import pytest

from guardrail_engine.decision import ChoiceQuestion, NoulQuestion
from guardrail_engine.tokens import estimate_question_tokens, estimate_tokens


@pytest.mark.parametrize(
    ("text", "tokens"),
    [("", 0), ("a", 1), ("abcd", 1), ("abcde", 2), ("abcdefgh", 2), ("abcdefghi", 3)],
)
def test_ascii_rounds_up_per_four_chars(text, tokens):
    assert estimate_tokens(text) == tokens


def test_non_ascii_counts_one_token_per_char():
    assert estimate_tokens("日本語") == 3
    assert estimate_tokens("ab日") == 2  # ceil(2/4) + 1


def test_deterministic():
    text = "Move savings into the Growth Fund. 🚀"
    assert estimate_tokens(text) == estimate_tokens(text)


def test_question_tokens_count_the_wire_json():
    q = NoulQuestion(instructions="Is it spam?")
    wire = '{"k":{"type":"noul","instructions":"Is it spam?"}}'
    assert estimate_question_tokens({"k": q}) == estimate_tokens(wire)


def test_question_tokens_sum_per_key():
    a = NoulQuestion(instructions="Is it spam?")
    b = ChoiceQuestion(instructions="Route?", criteria={"x": "X", "y": "Y"})
    assert estimate_question_tokens({"a": a, "b": b}) == (
        estimate_question_tokens({"a": a}) + estimate_question_tokens({"b": b})
    )
    assert estimate_question_tokens({}) == 0


def test_shared_by_fake_and_limits():
    # Both modules use the shared function rather than a private copy.
    from guardrail_engine.decision import fake, limits

    assert fake.estimate_tokens is estimate_tokens
    assert limits.estimate_tokens is estimate_tokens


def _reference_estimate(text: str) -> int:
    """The documented rule, one character at a time."""
    ascii_chars = sum(1 for ch in text if ord(ch) < 128)
    return -(-ascii_chars // 4) + (len(text) - ascii_chars)


@pytest.mark.parametrize(
    "text",
    [
        "",
        "abc",
        "\x00\x7f",  # the ends of ASCII
        "\x80\xff",  # just past it
        "Move savings into the Growth Fund. 🚀",
        "日本語 and English, mixed: café",
        "lone surrogate \ud800 here",
        "abcd" * 16_000 + "日",
    ],
)
def test_fast_count_matches_the_documented_rule(text):
    assert estimate_tokens(text) == _reference_estimate(text)


def test_16k_token_input_is_estimated_quickly():
    """The gateway sizes every call's input with this function (R6.3)."""
    import time

    text = "abcd" * 16_000 + "日本"
    start = time.perf_counter()
    for _ in range(10):
        estimate_tokens(text)
    assert (time.perf_counter() - start) / 10 < 0.005
