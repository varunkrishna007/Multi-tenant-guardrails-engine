"""The fitted API-token estimate used by the compiler's token bounds (AC-C1.8, R6.6, R6.7).

The shared estimator in :mod:`guardrail_engine.tokens` undercounts what the Decisions API
bills: estimate / API ranged from 0.72 to 0.88 per call shape, depending on the mix of input
text and questions, so no single factor fits (a flat x1.22 is off by -15% to +12% per call
shape). M0-01 fitted the API's ``usage`` input-token count against the shared estimator
over the detail run's 660 measured calls, warm-ups excluded
(``bench/results/m0-01-detail.md`` §5 on branch ``m0-01-latency-profile``):

    API tokens ~ 1.196 x est(text) + 0.963 x est(question text) + 23 x questions + 28

where ``est(text)`` is :func:`~guardrail_engine.tokens.estimate_tokens` of the whole input
text and ``est(question text)`` is :func:`~guardrail_engine.tokens.estimate_question_tokens`
of the ``questions`` object as sent on the wire. R6.6 rounds it to the coefficients below,
erring high on the per-question and per-call terms (25 instead of 23, 30 instead of 28)
because the bounds are ceilings:

    1.20 x est(text) + est(question text) + 25 x questions + 30

It splits into two additive parts, which R6.7 bounds separately:

* :func:`content_api_tokens`, ``ceil(1.20 x est(text)) + 30``: the input text (content at
  its cap plus the render overhead) and the per-call constant. The content bound;
* :func:`question_api_tokens`, ``est(question text) + 25 x questions``: the question text.
  One question's share is ``est({key: question}) + 25``, its wire JSON (key, type,
  instructions and criteria) plus the per-question term, so the per-question figures of a
  guard point sum exactly to its question-text figure.

The shared estimator itself is unchanged: the fake model and the API limit checks use it
raw. This module is the only place the fitted coefficients live. The arithmetic is exact
integer arithmetic (the text factor is held as a percentage), so a budget boundary never
depends on floating-point rounding.
"""

from __future__ import annotations

API_TOKENS_TEXT_PERCENT = 120
"""Input text factor, as a percentage of the shared estimate (1.20; fitted 1.196)."""
API_TOKENS_PER_QUESTION = 25
"""Tokens the API adds per question that the estimator doesn't see (fitted 23)."""
API_TOKENS_PER_CALL = 30
"""Fixed tokens per call (fitted 28)."""


def content_api_tokens(text_tokens: int) -> int:
    """The input-text part of a call: ``ceil(1.20 x text_tokens) + 30`` (R6.7 content
    bound). ``text_tokens`` is the shared estimate of the whole input text, render overhead
    included."""
    return -(-API_TOKENS_TEXT_PERCENT * text_tokens // 100) + API_TOKENS_PER_CALL


def question_api_tokens(question_tokens: int, question_count: int) -> int:
    """The question part of a call: ``question_tokens + 25 x question_count`` (R6.7
    question-text bound). For one question, pass its own wire tokens and 1."""
    return question_tokens + API_TOKENS_PER_QUESTION * question_count


def estimate_api_tokens(*, text_tokens: int, question_tokens: int, question_count: int) -> int:
    """Fitted estimate of the API input tokens for one whole call (R6.6): the content part
    plus the question part.

    ``text_tokens`` is the shared estimate of the input text, ``question_tokens`` the shared
    estimate of the ``questions`` object, and ``question_count`` the number of questions.
    The text term is rounded up: ``ceil(1.20 x text_tokens)``.
    """
    return content_api_tokens(text_tokens) + question_api_tokens(question_tokens, question_count)
