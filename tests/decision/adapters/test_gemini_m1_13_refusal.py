"""M1-13: a provider refusal before scoring (HTTP 400 ``prohibited_content``) maps to
``SafetyBlocked`` with the fixed detail ``prohibited_content``; near misses keep their mapping.
So do the other refusal codes Google's Decisions API guide documents (``blocklist``,
``content_blocked``, ``image_safety``), tested on **constructed** fixtures: those three have
never been seen live.

Offline only, through ``map_http_response`` and ``httpx.MockTransport``; no live call (U4).
The two ``reconstructed_prohibited_content_400*`` fixtures were reconstructed on 2026-11-17
from a partially recorded live response (their ``source`` field says which fields are
inferred), so they are deliberately not named ``recorded_``.
"""

import json
from pathlib import Path

import httpx
import pytest

from guardrail_engine.decision import Failed, FailureKind, NoulQuestion, SafetyBlocked
from guardrail_engine.decision.adapters.gemini import (
    GeminiConfig,
    GeminiDecisionModel,
    map_http_response,
)

FIXTURES = Path(__file__).parents[1] / "fixtures" / "gemini"
RECONSTRUCTED = [
    "reconstructed_prohibited_content_400",
    "reconstructed_prohibited_content_400_top_level",
]
DOCUMENTED = ["blocklist", "content_blocked", "image_safety"]
"""Refusal codes mapped from Google's documentation alone (never seen live)."""
CONSTRUCTED = [f"constructed_{code}_400" for code in DOCUMENTED]
QUESTIONS = {"p__x": NoulQuestion(instructions="Is the content about insurance?")}
SENTINEL = "SENTINEL-7f3a-provider-message-must-not-leak"
# The observed prefix of the live message (the recorder cut it off after "Try ").
OBSERVED_PREFIX = "Input blocked: The prompt could not be submitted."


def load(name: str) -> tuple[int, dict]:
    rec = json.loads((FIXTURES / f"{name}.json").read_text())
    return rec["status"], rec["body"]


def error_of(body: dict) -> dict:
    """The dict holding the error fields: under ``"error"`` or the body itself."""
    return body.get("error", body)


def with_sentinel(name: str) -> tuple[int, bytes]:
    status, body = load(name)
    error_of(body)["message"] += SENTINEL
    return status, json.dumps(body).encode()


def replay(status: int, content: bytes) -> tuple[GeminiDecisionModel, list[httpx.Request]]:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(status, content=content)

    model = GeminiDecisionModel(
        GeminiConfig(api_key="test-key-not-a-real-secret", paid_tier=True),
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )
    return model, seen


def err(**fields) -> bytes:
    return json.dumps({"error": fields}).encode()


def top(**fields) -> bytes:
    return json.dumps(fields).encode()


class TestFixtures:
    @pytest.mark.parametrize("name", RECONSTRUCTED)
    def test_reconstructed_fixtures_say_so_and_hold_only_the_observed_fields(self, name):
        rec = json.loads((FIXTURES / f"{name}.json").read_text())
        assert not name.startswith("recorded_")
        assert rec["source"].startswith("reconstructed 2026-11-17")
        assert "Inferred:" in rec["source"]
        assert rec["status"] == 400
        error = error_of(rec["body"])
        assert set(error) == {"code", "message"}  # no status, no details: as observed
        assert error["code"] == "prohibited_content"
        assert error["message"].startswith(OBSERVED_PREFIX)


class TestMapping:
    @pytest.mark.parametrize("name", RECONSTRUCTED)
    async def test_reconstructed_refusal_is_safety_blocked_with_reason_prohibited_content(
        self, name
    ):
        status, body = load(name)
        model, seen = replay(status, json.dumps(body).encode())
        result = await model.decide("placeholder content", QUESTIONS)
        assert isinstance(result, SafetyBlocked)
        assert result.reason == "prohibited_content"
        assert result.message == error_of(body)["message"].strip()  # free text, for logs
        assert len(seen) == 1  # the adapter adds no retry of its own

    @pytest.mark.parametrize(
        "code", ["prohibited_content", "PROHIBITED_CONTENT", "Prohibited_Content"]
    )
    @pytest.mark.parametrize("shape", [err, top])
    def test_code_matches_case_insensitively_nested_or_top_level(self, code, shape):
        result = map_http_response(400, shape(code=code, message="x"), QUESTIONS)
        assert result == SafetyBlocked(reason="prohibited_content", message="x")

    @pytest.mark.parametrize("shape", [err, top])
    def test_code_alone_is_enough_without_a_message(self, shape):
        result = map_http_response(400, shape(code="prohibited_content"), QUESTIONS)
        assert result == SafetyBlocked(reason="prohibited_content", message=None)

    def test_auth_still_beats_a_refusal(self):
        body = err(code="prohibited_content", status="PERMISSION_DENIED", message="denied")
        assert map_http_response(400, body, QUESTIONS).kind is FailureKind.AUTH

    @pytest.mark.parametrize(
        ("status", "kind"), [(500, FailureKind.UNAVAILABLE), (404, FailureKind.OTHER)]
    )
    def test_only_a_400_is_a_refusal(self, status, kind):
        result = map_http_response(status, err(code="prohibited_content"), QUESTIONS)
        assert isinstance(result, Failed)
        assert result.kind is kind


class TestDocumentedRefusalCodes:
    """``blocklist``, ``content_blocked`` and ``image_safety``: refusals per Google's Decisions
    API guide, mapped like ``prohibited_content`` (never retried, always a block)."""

    @pytest.mark.parametrize("name", CONSTRUCTED)
    def test_constructed_fixtures_say_so_and_hold_only_the_documented_fields(self, name):
        rec = json.loads((FIXTURES / f"{name}.json").read_text())
        assert name.startswith("constructed_") and "recorded" not in name
        assert rec["source"].startswith("CONSTRUCTED 2026-11-17")
        assert "NOT a recording" in rec["source"] and "No live probe" in rec["source"]
        assert rec["status"] == 400
        error = error_of(rec["body"])
        assert set(error) == {"code", "message"}
        assert error["code"] == name.removeprefix("constructed_").removesuffix("_400")

    @pytest.mark.parametrize("name", CONSTRUCTED)
    async def test_each_is_safety_blocked_with_its_code_as_the_reason(self, name):
        status, body = load(name)
        model, seen = replay(status, json.dumps(body).encode())
        result = await model.decide("placeholder content", QUESTIONS)
        assert isinstance(result, SafetyBlocked)
        assert result.reason == error_of(body)["code"]
        assert len(seen) == 1  # the adapter adds no retry of its own

    @pytest.mark.parametrize("code", DOCUMENTED)
    @pytest.mark.parametrize("shape", [err, top])
    def test_matched_case_insensitively_nested_or_top_level(self, code, shape):
        for written in (code, code.upper(), code.title()):
            result = map_http_response(400, shape(code=written, message="x"), QUESTIONS)
            assert result == SafetyBlocked(reason=code, message="x")

    @pytest.mark.parametrize("code", DOCUMENTED)
    def test_the_provider_message_is_kept_apart_from_the_reason(self, code):
        status, content = with_sentinel(f"constructed_{code}_400")
        result = map_http_response(status, content, QUESTIONS)
        assert isinstance(result, SafetyBlocked)
        assert SENTINEL in (result.message or "") and SENTINEL not in (result.reason or "")

    @pytest.mark.parametrize("code", ["blocklist", "content_blocked"])
    @pytest.mark.parametrize("bad", ["{code}_v2", "my_{code}", "{code} ", " {code}"])
    def test_only_the_exact_code_counts(self, code, bad):
        result = map_http_response(400, err(code=bad.format(code=code), message="x"), QUESTIONS)
        assert isinstance(result, Failed) and result.kind is FailureKind.OTHER

    @pytest.mark.parametrize("written", ["image_safety_v2", "my_image_safety", "IMAGE_SAFETY_X"])
    def test_a_variant_of_image_safety_is_a_refusal_through_the_wider_safety_rule(self, written):
        """Reviewed and accepted: any structured field naming safety is a
        refusal, with the reason as the provider wrote it. Only the exact ``image_safety`` is
        casefolded to the constant."""
        result = map_http_response(400, err(code=written, message="x"), QUESTIONS)
        assert result == SafetyBlocked(reason=written, message="x")

    @pytest.mark.parametrize("code", DOCUMENTED)
    def test_the_message_alone_never_makes_a_refusal(self, code):
        body = err(code="invalid_request", message=f"{code}: Input blocked.")
        result = map_http_response(400, body, QUESTIONS)
        assert isinstance(result, Failed) and result.kind is FailureKind.OTHER

    @pytest.mark.parametrize("code", DOCUMENTED)
    def test_auth_still_beats_a_refusal(self, code):
        body = err(code=code, status="PERMISSION_DENIED", message="denied")
        assert map_http_response(400, body, QUESTIONS).kind is FailureKind.AUTH

    def test_the_five_documented_codes_are_all_refusals(self):
        """Google lists safety, prohibited_content, blocklist, image_safety, content_blocked."""
        import guardrail_engine.decision as public

        documented = {"prohibited_content", "blocklist", "content_blocked", "image_safety"}
        assert set(public.REFUSAL_CODES) == documented
        for code in (*public.REFUSAL_CODES, "safety"):
            result = map_http_response(400, err(code=code, message="x"), QUESTIONS)
            assert isinstance(result, SafetyBlocked), code
        assert public.REFUSAL_BLOCKLIST == "blocklist"
        assert public.REFUSAL_CONTENT_BLOCKED == "content_blocked"
        assert public.REFUSAL_IMAGE_SAFETY == "image_safety"
        assert {"REFUSAL_CODES", "REFUSAL_BLOCKLIST"} <= set(public.__all__)


class TestNearMisses:
    """A 400 that only looks like a refusal keeps its existing mapping."""

    POLICY_TEXT = "violate Google's Generative AI Prohibited Use policy. Input blocked."

    @pytest.mark.parametrize(
        "body",
        [
            err(code="invalid_request", message="Input blocked: " + POLICY_TEXT),
            top(code="invalid_request", message="Input blocked: " + POLICY_TEXT),
            err(message="Input blocked: " + POLICY_TEXT),  # message only, no code
            top(message="Input blocked: " + POLICY_TEXT),
            err(code="spii", message="Request blocked."),  # unknown code
            err(code="prohibited_content_v2", message="blocked"),  # not an exact match
            err(code="prohibited", message="blocked"),
            err(code=400, status="INVALID_ARGUMENT", message="Input blocked: " + POLICY_TEXT),
            json.dumps("Input blocked: " + POLICY_TEXT).encode(),  # a bare JSON string
            ("Input blocked: " + POLICY_TEXT).encode(),  # not JSON
        ],
        ids=[
            "invalid_request-nested",
            "invalid_request-top_level",
            "message_only-nested",
            "message_only-top_level",
            "unknown_code",
            "code_superstring",
            "code_prefix",
            "google_rpc",
            "json_string",
            "not_json",
        ],
    )
    def test_near_miss_400_is_failed_other(self, body):
        result = map_http_response(400, body, QUESTIONS)
        assert isinstance(result, Failed)
        assert result.kind is FailureKind.OTHER

    @pytest.mark.parametrize("code", ["spii", "recitation", "prohibited", "blocked"])
    def test_block_like_codes_neither_observed_nor_documented_are_not_mapped(self, code):
        result = map_http_response(400, err(code=code, message="blocked"), QUESTIONS)
        assert isinstance(result, Failed)
        assert result.kind is FailureKind.OTHER

    @pytest.mark.parametrize("shape", ["nested", "top_level"])
    def test_the_observed_prohibited_use_policy_message_without_the_code_is_not_a_refusal(
        self, shape
    ):
        """The story's Tests line: the reconstructed fixture with its ``prohibited_content``
        code removed (only the "Prohibited Use policy" message left) is not SafetyBlocked."""
        name = RECONSTRUCTED[0] if shape == "nested" else RECONSTRUCTED[1]
        status, body = load(name)
        del error_of(body)["code"]
        assert "Prohibited Use policy" in error_of(body)["message"]
        result = map_http_response(status, json.dumps(body).encode(), QUESTIONS)
        assert not isinstance(result, SafetyBlocked)
        assert isinstance(result, Failed) and result.kind is FailureKind.OTHER
        assert result.unrecognised_code == "_no_code"  # counted by shape (M1-15)

    def test_existing_limit_mapping_is_unchanged_even_with_blocked_wording(self):
        body = err(
            code="invalid_request",
            message="* CreateDecisionRequest.questions: must have between 1 and 1000 "
            "questions (request blocked)",
        )
        assert map_http_response(400, body, QUESTIONS).kind is FailureKind.LIMIT_EXCEEDED


class TestCodeAndMessageAreKeptApart:
    """Review decision on M1-13: ``reason`` is the structured code (recorded); ``message`` is
    the provider's free text, which could echo the input (DEBUG logs only, in the Guard
    Service). The sentinel must never reach ``reason``."""

    @pytest.mark.parametrize("name", RECONSTRUCTED)
    async def test_sentinel_in_the_message_stays_out_of_the_reason(self, name):
        model, _ = replay(*with_sentinel(name))
        result = await model.decide("placeholder content", QUESTIONS)
        assert isinstance(result, SafetyBlocked)
        assert result.reason == "prohibited_content"
        assert SENTINEL in result.message and result.message.startswith(OBSERVED_PREFIX)

    @pytest.mark.parametrize("name", ["safety_400", "safety_400_top_level"])
    def test_safety_refusal_carries_its_code_as_the_reason(self, name):
        status, body = load(name)
        error_of(body)["message"] += SENTINEL
        result = map_http_response(status, json.dumps(body).encode(), QUESTIONS)
        assert isinstance(result, SafetyBlocked)
        assert result.reason == "safety"
        assert SENTINEL in result.message

    @pytest.mark.parametrize(
        ("error", "reason"),
        [
            ({"code": 400, "status": "SAFETY_BLOCKED", "message": "x"}, "SAFETY_BLOCKED"),
            ({"code": 400, "status": "X", "details": [{"reason": "SAFETY"}]}, "SAFETY"),
            ({"code": "Safety", "message": "x"}, "Safety"),
        ],
    )
    def test_other_safety_fields_keep_the_value_the_provider_wrote(self, error, reason):
        """M1-06's design, unchanged: only ``prohibited_content`` is normalised."""
        result = map_http_response(400, json.dumps({"error": error}).encode(), QUESTIONS)
        assert isinstance(result, SafetyBlocked)
        assert result.reason == reason


class TestStableRefusalConstants:
    """Harness code (e.g. a bench tripwire) detects a refusal by ``isinstance(result,
    SafetyBlocked)`` and tells the kind by ``result.reason``; these values are a contract."""

    def test_values_are_pinned_and_public(self):
        import guardrail_engine.decision as public
        import guardrail_engine.decision.adapters.gemini as adapter
        import guardrail_engine.decision.port as port

        assert public.REFUSAL_PROHIBITED_CONTENT == "prohibited_content"
        assert public.REFUSAL_SAFETY == "safety"
        assert {"REFUSAL_PROHIBITED_CONTENT", "REFUSAL_SAFETY"} <= set(public.__all__)
        for module in (port, adapter):
            assert module.REFUSAL_PROHIBITED_CONTENT is public.REFUSAL_PROHIBITED_CONTENT
            assert module.REFUSAL_SAFETY is public.REFUSAL_SAFETY

    @pytest.mark.parametrize(
        ("name", "constant"),
        [
            ("reconstructed_prohibited_content_400", "REFUSAL_PROHIBITED_CONTENT"),
            ("reconstructed_prohibited_content_400_top_level", "REFUSAL_PROHIBITED_CONTENT"),
            ("safety_400", "REFUSAL_SAFETY"),
            ("safety_400_top_level", "REFUSAL_SAFETY"),
        ],
    )
    def test_each_refusal_carries_its_constant(self, name, constant):
        import guardrail_engine.decision as public

        status, body = load(name)
        result = map_http_response(status, json.dumps(body).encode(), QUESTIONS)
        assert isinstance(result, SafetyBlocked)
        assert result.reason == getattr(public, constant)


class TestUnrecognisedCode:
    @pytest.mark.parametrize(
        ("body", "label"),
        [
            (err(code="spii", message="x"), "spii"),
            (top(code="Brand_New", message="x"), "brand_new"),  # casefolded (M1-15)
            (err(code="a\nb", message="x"), "_malformed"),
            (err(code="ns:code.v2-x", message="x"), "_malformed"),  # outside [a-z0-9_]
            (err(code="a" * 65, message="x"), "_malformed"),
            (err(code="_no_code", message="x"), "_malformed"),  # can't forge a placeholder
            (err(code=400, status="FAILED_PRECONDITION", message="x"), "failed_precondition"),
            (err(code="Invalid_Request", message="x"), None),  # known, any case
            (err(code="invalid_request", message="x"), None),
            (err(code=400, status="INVALID_ARGUMENT", message="x"), None),
            (err(message="x"), "_no_code"),
            (err(code="", message="x"), "_no_code"),
            (err(code=None, message="x"), "_no_code"),
            (err(code=400, message="x"), "_no_code"),  # a google.rpc number and no status
            (b'"just a JSON string"', "_no_code"),  # JSON, but no error object
            (b"not json", "_not_json"),
            (b"<html>Bad Request</html>", "_not_json"),
        ],
        ids=[
            "unknown",
            "casefolded",
            "not_code_shaped",
            "punctuation",
            "too_long",
            "placeholder_spelled",
            "rpc_status",
            "known_any_case",
            "invalid_request",
            "invalid_argument",
            "no_code",
            "empty_code",
            "null_code",
            "rpc_number_only",
            "json_not_an_object",
            "not_json",
            "html",
        ],
    )
    def test_a_400_falling_to_other_carries_its_unrecognised_code(self, body, label):
        result = map_http_response(400, body, QUESTIONS)
        assert isinstance(result, Failed) and result.kind is FailureKind.OTHER
        assert result.unrecognised_code == label

    def test_only_400s_that_fall_to_other_carry_it(self):
        assert map_http_response(500, err(code="new_code"), QUESTIONS).unrecognised_code is None
        assert map_http_response(429, err(code="new_code"), QUESTIONS).unrecognised_code is None
        quota = err(code="new_code", message="Quota exceeded for requests per day")
        assert map_http_response(400, quota, QUESTIONS).unrecognised_code is None
