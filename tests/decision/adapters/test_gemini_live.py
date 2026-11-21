"""[LIVE] smoke tests against the real Gemini Decisions API.

Opt-in: deselected by default (``-m "not live"`` in pyproject), and skipped unless
GEMINI_API_KEY is set in the environment. Two calls per run. To run them:

    set -a; . ./.env; set +a                     # from the project root; never echo the key
    GEMINI_PAID_TIER=true uv run pytest -m live
"""

import os

import pytest

from guardrail_engine.decision import (
    Answered,
    ChoiceAnswer,
    ChoiceQuestion,
    Failed,
    FailureKind,
    NoulAnswer,
    NoulCriteria,
    NoulQuestion,
    ScoreAnswer,
    ScoreQuestion,
)
from guardrail_engine.decision.adapters.gemini import GeminiConfig, GeminiDecisionModel

pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(not os.environ.get("GEMINI_API_KEY"), reason="GEMINI_API_KEY not set"),
]

INPUT = (
    "TENANT DOMAIN: insurance\nGUARD POINT: output\n\n<<<UNTRUSTED:content:5f1c\n"
    "Your claim for water damage will definitely be approved and paid within 3 days.\n"
    "UNTRUSTED:content:5f1c>>>"
)
QUESTIONS = {
    "d__ins_claim_promise": NoulQuestion(
        instructions="Does the response promise that a claim will be approved or paid?",
        criteria=NoulCriteria(
            true_description="Commits to a claim outcome or payment.",
            false_description="Describes the process without committing to an outcome.",
        ),
    ),
    "p__route": ChoiceQuestion(
        instructions="Which scope does this content fall into?",
        criteria={"in_scope": "Insurance claims and coverage.", "off_domain": "Anything else."},
    ),
    "p__severity": ScoreQuestion(
        instructions="How risky is this statement for the insurer?",
        criteria=["Harmless", "Misleading", "Creates a binding commitment"],
    ),
}


async def test_live_smoke_noul_choice_score():
    async with GeminiDecisionModel(GeminiConfig.from_env()) as model:
        result = await model.decide(INPUT, QUESTIONS)
    assert isinstance(result, Answered), result
    assert result.ok, result.problems
    assert isinstance(result.answers["d__ins_claim_promise"], NoulAnswer)
    assert isinstance(result.answers["p__route"], ChoiceAnswer)
    assert isinstance(result.answers["p__severity"], ScoreAnswer)
    assert result.usage is not None
    assert result.usage.total_input_tokens > 0
    assert result.usage.total_output_tokens == 0


async def test_live_limit_error_maps_to_limit_exceeded():
    # Bypasses the local limit check on purpose so the provider's own 400 is exercised.
    questions = {f"q{i}": NoulQuestion(instructions="Is it?") for i in range(1001)}
    body = {
        "model": "gemini-decision-1",
        "input": "Synthetic test input.",
        "questions": {
            k: q.model_dump(mode="json", exclude_none=True) for k, q in questions.items()
        },
    }
    async with GeminiDecisionModel(GeminiConfig.from_env()) as model:
        result = await model._send(body, questions)
    assert isinstance(result, Failed), result
    assert result.kind is FailureKind.LIMIT_EXCEEDED
