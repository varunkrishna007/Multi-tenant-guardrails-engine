"""Gemini adapter (M1-03, second half), offline: recorded and hand-written fixtures replayed
through httpx.MockTransport. No network access."""

import asyncio
import json
from pathlib import Path

import httpx
import pytest

from guardrail_engine.decision import (
    Answered,
    ChoiceAnswer,
    ChoiceQuestion,
    DecisionModel,
    Failed,
    FailureKind,
    NoulAnswer,
    NoulCriteria,
    NoulQuestion,
    SafetyBlocked,
    ScoreAnswer,
    ScoreQuestion,
)
from guardrail_engine.decision.adapters.gemini import (
    DEFAULT_BASE_URL,
    GeminiConfig,
    GeminiDecisionModel,
    PaidTierRequiredError,
    build_request,
    map_http_response,
)

FIXTURES = Path(__file__).parents[1] / "fixtures" / "gemini"
FAKE_KEY = "test-key-not-a-real-secret"

# The questions behind the recorded 200 fixture.
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
        criteria={
            "in_scope": "Insurance policies, claims and coverage.",
            "off_domain": "Anything unrelated to insurance.",
        },
    ),
    "p__severity": ScoreQuestion(
        instructions="How risky is this statement for the insurer?",
        criteria=["Harmless", "Misleading", "Creates a binding commitment"],
    ),
}


def fixture(name: str) -> tuple[int, bytes]:
    rec = json.loads((FIXTURES / f"{name}.json").read_text())
    body = rec["body"]
    return rec["status"], body.encode() if isinstance(body, str) else json.dumps(body).encode()


def config(**kw) -> GeminiConfig:
    return GeminiConfig(api_key=FAKE_KEY, paid_tier=True, **kw)


def model_with(handler) -> GeminiDecisionModel:
    return GeminiDecisionModel(
        config(), client=httpx.AsyncClient(transport=httpx.MockTransport(handler))
    )


def replay(name: str):
    status, content = fixture(name)
    return model_with(lambda request: httpx.Response(status, content=content))


# ---------------------------------------------------------------------------- startup


class TestStartup:
    def test_refuses_to_start_without_paid_tier_declaration(self):
        with pytest.raises(PaidTierRequiredError):
            GeminiDecisionModel(GeminiConfig(api_key=FAKE_KEY))

    def test_refuses_to_start_without_a_key(self):
        with pytest.raises(ValueError, match="api_key is empty"):
            GeminiDecisionModel(GeminiConfig(api_key="", paid_tier=True))

    @pytest.mark.parametrize(
        ("flag", "paid"),
        [("true", True), ("1", True), ("YES", True), ("false", False), ("", False)],
    )
    def test_from_env_reads_paid_tier_flag(self, flag, paid):
        cfg = GeminiConfig.from_env({"GEMINI_API_KEY": FAKE_KEY, "GEMINI_PAID_TIER": flag})
        assert cfg.paid_tier is paid
        assert cfg.api_key == FAKE_KEY

    def test_from_env_without_flag_refuses_to_start(self):
        with pytest.raises(PaidTierRequiredError):
            GeminiDecisionModel(GeminiConfig.from_env({"GEMINI_API_KEY": FAKE_KEY}))

    def test_key_never_in_repr(self):
        assert FAKE_KEY not in repr(config())
        assert FAKE_KEY not in repr(model_with(lambda r: httpx.Response(200)))

    def test_satisfies_the_port(self):
        model = model_with(lambda r: httpx.Response(200))
        assert isinstance(model, DecisionModel)
        assert model.model_id == "gemini-decision-1"


# ---------------------------------------------------------------------------- request


async def test_request_shape_url_and_auth_header():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["headers"] = request.headers
        seen["body"] = json.loads(request.content)
        status, content = fixture("recorded_valid_noul_choice_score")
        return httpx.Response(status, content=content)

    await model_with(handler).decide("some content", QUESTIONS)
    assert seen["url"] == f"{DEFAULT_BASE_URL}/decisions"
    assert seen["headers"]["x-goog-api-key"] == FAKE_KEY
    assert FAKE_KEY not in seen["url"]
    assert seen["body"] == build_request("gemini-decision-1", "some content", QUESTIONS)
    assert seen["body"]["questions"]["p__severity"]["criteria"] == [
        "Harmless",
        "Misleading",
        "Creates a binding commitment",
    ]
    assert "criteria" in seen["body"]["questions"]["d__ins_claim_promise"]


async def test_local_limit_violation_makes_no_http_call():
    calls = []
    model = model_with(lambda r: calls.append(r) or httpx.Response(200))
    result = await model.decide("x", {"bad key": NoulQuestion(instructions="Is it?")})
    assert isinstance(result, Failed)
    assert result.kind is FailureKind.LIMIT_EXCEEDED
    assert result.key == "bad key"
    assert calls == []


# ---------------------------------------------------------------------------- outcome mapping


async def test_recorded_200_parses_all_three_types():
    result = await replay("recorded_valid_noul_choice_score").decide("x", QUESTIONS)
    assert isinstance(result, Answered)
    assert result.ok
    assert isinstance(result.answers["d__ins_claim_promise"], NoulAnswer)
    assert isinstance(result.answers["p__route"], ChoiceAnswer)
    score = result.answers["p__severity"]
    assert isinstance(score, ScoreAnswer)
    assert score.argmax_level() == 2
    assert 1.5 < score.expected_level < 2.0
    assert result.usage.total_input_tokens == 308
    assert result.usage.total_output_tokens == 0


async def test_recorded_400_limit_error_is_limit_exceeded():
    result = await replay("recorded_invalid_too_many_questions").decide("x", QUESTIONS)
    assert isinstance(result, Failed)
    assert result.kind is FailureKind.LIMIT_EXCEEDED
    assert "between 1 and 1000 questions" in result.message


@pytest.mark.parametrize("name", ["safety_400", "safety_400_top_level"])
async def test_safety_400_is_safety_blocked(name):
    result = await replay(name).decide("x", QUESTIONS)
    assert isinstance(result, SafetyBlocked)
    assert "safety" in result.message


@pytest.mark.parametrize(
    ("name", "kind"),
    [
        ("invalid_request_not_a_limit_400", FailureKind.OTHER),
        ("rate_limited_429", FailureKind.RATE_LIMITED),
        ("unavailable_503", FailureKind.UNAVAILABLE),
        ("internal_500", FailureKind.UNAVAILABLE),
        ("unauthenticated_401", FailureKind.AUTH),
        ("recorded_invalid_key_400", FailureKind.AUTH),
    ],
)
async def test_error_fixtures_map_to_failure_kinds(name, kind):
    result = await replay(name).decide("x", QUESTIONS)
    assert isinstance(result, Failed)
    assert result.kind is kind
    assert result.message.startswith("HTTP ")


@pytest.mark.parametrize(
    ("status", "kind"),
    [
        (408, FailureKind.TIMEOUT),
        (404, FailureKind.OTHER),
        (401, FailureKind.AUTH),
        (403, FailureKind.AUTH),
        (429, FailureKind.RATE_LIMITED),
        (502, FailureKind.UNAVAILABLE),
    ],
)
def test_status_codes_without_body(status, kind):
    result = map_http_response(status, b"", QUESTIONS)
    assert isinstance(result, Failed)
    assert result.kind is kind


def test_limit_message_naming_a_key_sets_the_key():
    body = json.dumps(
        {
            "error": {
                "code": "invalid_request",
                "message": "* CreateDecisionRequest.questions[p__route]: at most 255 options",
            }
        }
    ).encode()
    result = map_http_response(400, body, QUESTIONS)
    assert result.kind is FailureKind.LIMIT_EXCEEDED
    assert result.key == "p__route"


def test_limit_message_naming_an_unknown_key_leaves_key_empty():
    body = json.dumps(
        {
            "error": {
                "code": "invalid_request",
                "message": "CreateDecisionRequest.questions.zz: too long",
            }
        }
    ).encode()
    assert map_http_response(400, body, QUESTIONS).key is None


@pytest.mark.parametrize("content", [b"<html>oops</html>", b"", b'{"no_answers": true}'])
def test_unusable_200_is_other(content):
    result = map_http_response(200, content, QUESTIONS)
    assert isinstance(result, Failed)
    assert result.kind is FailureKind.OTHER


def test_200_without_usage_is_answered_with_usage_unknown():
    _, content = fixture("recorded_valid_noul_choice_score")
    body = json.loads(content)
    del body["usage"]
    result = map_http_response(200, json.dumps(body).encode(), QUESTIONS)
    assert isinstance(result, Answered)
    assert result.ok
    assert result.usage is None


# ---------------------------------------------------------------------------- transport


async def test_transport_timeout_is_timeout():
    def handler(request):
        raise httpx.ReadTimeout("slow", request=request)

    result = await model_with(handler).decide("x", QUESTIONS)
    assert isinstance(result, Failed)
    assert result.kind is FailureKind.TIMEOUT


@pytest.mark.parametrize("exc", [httpx.ConnectError, httpx.RemoteProtocolError, httpx.ReadError])
async def test_connection_errors_are_unavailable(exc):
    def handler(request):
        raise exc("boom", request=request)

    result = await model_with(handler).decide("x", QUESTIONS)
    assert isinstance(result, Failed)
    assert result.kind is FailureKind.UNAVAILABLE
    assert FAKE_KEY not in result.message


async def test_cancellation_propagates_to_the_gateway():
    async def handler(request):
        await asyncio.sleep(5)
        return httpx.Response(200)

    model = model_with(handler)
    with pytest.raises(TimeoutError):
        async with asyncio.timeout(0.02):
            await model.decide("x", QUESTIONS)


async def test_owned_client_is_closed():
    model = GeminiDecisionModel(config())
    async with model:
        pass
    assert model._client.is_closed


# ----------------------------------------------------------------------------
def err_body(**error) -> bytes:
    return json.dumps({"error": error}).encode()


class TestDecideNeverRaises:
    """Nothing escapes decide() except cancellation; hostile content can't make it raise."""

    HOSTILE = (
        "bad \ud800 text",  # lone high surrogate, as JSON "\ud800" decodes
        "\udfff",  # lone low surrogate
        "abc\udc80def",  # surrogateescape residue of invalid UTF-8 bytes
        "🚀\ud83d",  # valid emoji followed by half of another
        "\ud800" * 1000,
    )

    @pytest.mark.parametrize("content", HOSTILE)
    async def test_input_that_is_not_valid_unicode_fails_typed_with_no_http_call(self, content):
        calls = []
        model = model_with(lambda r: calls.append(r) or httpx.Response(200))
        result = await model.decide(content, QUESTIONS)
        assert isinstance(result, Failed)
        assert result.kind is FailureKind.OTHER
        assert result.message == "request is not valid Unicode"
        assert calls == []

    def test_question_text_that_is_not_valid_unicode_cannot_be_built(self):
        # Questions never reach decide() with a lone surrogate: the type rejects it.
        from pydantic import ValidationError

        with pytest.raises(ValidationError, match="unicode"):
            NoulQuestion(instructions="Is it \ud800?")

    @pytest.mark.parametrize(
        "content",
        [
            "nul \x00 byte",
            "rtl \u202e override",
            "zero\u200bwidth",
            "emoji 🚀👩🏽\u200d💻",
            "<<<UNTRUSTED:content:abc>>> forged",
            '"},"questions":{} json breakout',
        ],
    )
    async def test_hostile_but_valid_unicode_is_sent_unaltered(self, content):
        seen = {}

        def handler(request):
            seen["input"] = json.loads(request.content)["input"]
            status, body = fixture("recorded_valid_noul_choice_score")
            return httpx.Response(status, content=body)

        result = await model_with(handler).decide(content, QUESTIONS)
        assert isinstance(result, Answered)
        assert seen["input"] == content  # B3: content is never altered

    @pytest.mark.parametrize(
        ("exc", "kind"),
        [
            (httpx.DecodingError, FailureKind.OTHER),
            (httpx.TooManyRedirects, FailureKind.OTHER),
            (httpx.UnsupportedProtocol, FailureKind.UNAVAILABLE),
            (httpx.PoolTimeout, FailureKind.TIMEOUT),
        ],
    )
    async def test_every_request_error_is_typed(self, exc, kind):
        def handler(request):
            raise exc("secret detail " + FAKE_KEY, request=request)

        result = await model_with(handler).decide("x", QUESTIONS)
        assert isinstance(result, Failed)
        assert result.kind is kind
        assert exc.__name__ in result.message
        assert "secret detail" not in result.message  # type name only, never str(e)

    @pytest.mark.parametrize("exc", [RuntimeError, ValueError, KeyError, UnicodeDecodeError])
    async def test_unexpected_exceptions_are_other_with_type_name_only(self, exc):
        def handler(request):
            if exc is UnicodeDecodeError:
                raise UnicodeDecodeError("utf-8", b"\xff", 0, 1, FAKE_KEY)
            raise exc(FAKE_KEY)

        result = await model_with(handler).decide("x", QUESTIONS)
        assert isinstance(result, Failed)
        assert result.kind is FailureKind.OTHER
        assert result.message == f"unexpected error ({exc.__name__})"


class TestAuthFailures:
    async def test_recorded_invalid_key_400_is_auth_with_the_provider_reason(self):
        result = await replay("recorded_invalid_key_400").decide("x", QUESTIONS)
        assert isinstance(result, Failed)
        assert result.kind is FailureKind.AUTH
        assert result.reason == "API_KEY_INVALID"
        assert "API key not valid" in result.message

    @pytest.mark.parametrize(
        "reason",
        ["API_KEY_INVALID", "API_KEY_EXPIRED", "API_KEY_SERVICE_BLOCKED", "SERVICE_DISABLED"],
    )
    def test_auth_reasons_in_google_rpc_dialect(self, reason):
        body = err_body(
            code=400, status="INVALID_ARGUMENT", message="no", details=[{"reason": reason}]
        )
        result = map_http_response(400, body, QUESTIONS)
        assert result.kind is FailureKind.AUTH
        assert result.reason == reason

    @pytest.mark.parametrize("status_name", ["UNAUTHENTICATED", "PERMISSION_DENIED"])
    def test_auth_statuses(self, status_name):
        result = map_http_response(400, err_body(code=400, status=status_name), QUESTIONS)
        assert result.kind is FailureKind.AUTH
        assert result.reason == status_name

    @pytest.mark.parametrize("status", [401, 403])
    def test_any_401_or_403_is_auth(self, status):
        result = map_http_response(status, b"<html>denied</html>", QUESTIONS)
        assert result.kind is FailureKind.AUTH
        assert result.reason == f"HTTP_{status}"

    def test_other_google_rpc_400_is_other_with_its_status(self):
        body = err_body(code=400, status="INVALID_ARGUMENT", message="bad field")
        result = map_http_response(400, body, QUESTIONS)
        assert result.kind is FailureKind.OTHER
        assert result.reason == "INVALID_ARGUMENT"


class TestLimitDetection:
    @pytest.mark.parametrize(
        "message",
        [
            "* CreateDecisionRequest.model: must be at most 64 characters",
            "* CreateDecisionRequest.questions[p__route].instructions: unsupported value",
            "Request rejected: the field is too long",
            "API key not valid. Please pass a valid API key.",
        ],
    )
    def test_non_limit_400s_are_not_limit_exceeded(self, message):
        result = map_http_response(
            400, err_body(code="invalid_request", message=message), QUESTIONS
        )
        assert result.kind is FailureKind.OTHER

    @pytest.mark.parametrize(
        "message",
        [
            "Request rejected: daily limit of free tier exceeded",
            "Quota exceeded for quota metric 'Requests per day'",
        ],
    )
    def test_quota_400s_are_rate_limited(self, message):
        result = map_http_response(
            400, err_body(code="invalid_request", message=message), QUESTIONS
        )
        assert result.kind is FailureKind.RATE_LIMITED

    def test_google_rpc_resource_exhausted_is_rate_limited(self):
        body = err_body(code=429, status="RESOURCE_EXHAUSTED", message="Quota exceeded")
        result = map_http_response(429, body, QUESTIONS)
        assert result.kind is FailureKind.RATE_LIMITED
        assert result.reason == "RESOURCE_EXHAUSTED"

    def test_input_limit_is_limit_exceeded(self):
        body = err_body(code="invalid_request", message="* CreateDecisionRequest.input: too long")
        assert map_http_response(400, body, QUESTIONS).kind is FailureKind.LIMIT_EXCEEDED


class TestSafetyInBothDialects:
    @pytest.mark.parametrize(
        "error",
        [
            {"code": 400, "status": "FAILED_PRECONDITION", "details": [{"reason": "SAFETY"}]},
            {"code": 400, "status": "SAFETY_BLOCKED", "message": "blocked"},
            {"code": "Safety", "message": "blocked"},
        ],
    )
    def test_safety_named_by_status_reason_or_code(self, error):
        result = map_http_response(400, json.dumps({"error": error}).encode(), QUESTIONS)
        assert isinstance(result, SafetyBlocked)


class TestKeyNeverLeaks:
    FIXTURE_NAMES = sorted(p.stem for p in FIXTURES.glob("*.json"))

    @pytest.mark.parametrize("name", FIXTURE_NAMES)
    async def test_key_absent_from_every_fixture_result(self, name):
        result = await replay(name).decide("x", QUESTIONS)
        assert FAKE_KEY not in repr(result)
        assert FAKE_KEY not in result.model_dump_json()

    async def test_key_absent_from_logs_at_debug(self, caplog):
        import logging

        caplog.set_level(logging.DEBUG)
        status, content = fixture("recorded_valid_noul_choice_score")
        model = model_with(lambda r: httpx.Response(status, content=content))
        await model.decide("x", QUESTIONS)
        await model_with(
            lambda r: (_ for _ in ()).throw(httpx.ConnectError("x", request=r))
        ).decide("x", QUESTIONS)
        assert FAKE_KEY not in caplog.text

    async def test_key_absent_from_model_client_and_config_reprs(self):
        model = model_with(lambda r: httpx.Response(200))
        for obj in (model, model._config, model._client):
            assert FAKE_KEY not in repr(obj)
            assert FAKE_KEY not in str(obj)

    async def test_key_absent_from_raised_startup_errors(self):
        with pytest.raises(PaidTierRequiredError) as exc:
            GeminiDecisionModel(GeminiConfig(api_key=FAKE_KEY))
        assert FAKE_KEY not in str(exc.value)
        assert FAKE_KEY not in repr(exc.value)


class TestStructuredSignalsBeforeMessageHeuristics:
    def test_safety_coded_400_mentioning_rate_limit_is_safety_blocked(self):
        body = err_body(
            code="safety", message="Blocked for safety; this is not a rate limit issue."
        )
        assert isinstance(map_http_response(400, body, QUESTIONS), SafetyBlocked)

    def test_safety_coded_400_mentioning_quota_is_safety_blocked(self):
        body = err_body(
            code=400, status="FAILED_PRECONDITION", message="quota", details=[{"reason": "SAFETY"}]
        )
        assert isinstance(map_http_response(400, body, QUESTIONS), SafetyBlocked)

    def test_structured_quota_reason_beats_limit_wording(self):
        body = err_body(
            code=400,
            status="INVALID_ARGUMENT",
            message="* CreateDecisionRequest.questions: must have between 1 and 1000 questions",
            details=[{"reason": "RATE_LIMIT_EXCEEDED_QUOTA"}],
        )
        assert map_http_response(400, body, QUESTIONS).kind is FailureKind.RATE_LIMITED

    def test_auth_still_beats_safety(self):
        body = err_body(code="safety", status="PERMISSION_DENIED", message="denied")
        assert map_http_response(400, body, QUESTIONS).kind is FailureKind.AUTH
