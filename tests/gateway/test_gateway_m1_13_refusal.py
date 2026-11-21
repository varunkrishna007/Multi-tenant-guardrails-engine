"""M1-13 through the Decision Gateway.

* A provider refusal (``SafetyBlocked``: HTTP 400 ``prohibited_content`` or ``safety``) is
  never retried and leaves the auth breaker, the orphan logic and the alerts alone. It is
  metered as one request with usage unknown, through the unfinished-attempt path
  (``record_unanswered``), never as an answered call, and counted in its own per-tenant,
  per-guard-point ``provider_safety`` counter (metering decision, 2026-11-17).
* A 400 whose error code the adapter doesn't recognise stays ``Failed(other)`` and is
  counted (``provider_error_unrecognised``) and logged by a bounded code label only. M1-15
  (minor fixes): every occurrence is counted, the warning is throttled per label, a 400
  with no code counts as ``_no_code`` and a non-JSON body as ``_not_json``, labels are
  casefolded, and anything that isn't 1-64 characters of ``[a-z0-9_]`` is ``_malformed``.

The model is the real Gemini adapter replaying fixtures through ``httpx.MockTransport``: no
network, no live call (U4).
"""

import json
import logging
from pathlib import Path

import httpx
import pytest

from guardrail_engine.decision import Failed, FailureKind, NoulQuestion, SafetyBlocked
from guardrail_engine.decision.adapters.gemini import GeminiConfig, GeminiDecisionModel
from guardrail_engine.gateway import (
    MAX_UNRECOGNISED_CODE_LABELS,
    UNRECOGNISED_CODE_OVERFLOW,
    DecisionGateway,
    InMemoryUsageMeter,
    ProviderErrorMeter,
    ProviderSafetyMeter,
    RecordingAlertSink,
)

FIXTURES = Path(__file__).parents[1] / "decision" / "fixtures" / "gemini"
RECONSTRUCTED = [
    "reconstructed_prohibited_content_400",
    "reconstructed_prohibited_content_400_top_level",
]
CONSTRUCTED = [  # from Google's documentation alone: never seen live
    "constructed_blocklist_400",
    "constructed_content_blocked_400",
    "constructed_image_safety_400",
]
QUESTIONS = {"p__x": NoulQuestion(instructions="Is the content about insurance?")}
INPUT = "placeholder content"
SENTINEL = "SENTINEL-9b2d-provider-message-must-not-leak"


class Replay:
    """The Gemini adapter over a mock transport answering every request with one response:
    a fixture by name, or ``status`` and ``body`` given directly."""

    def __init__(
        self, name: str = "reconstructed_prohibited_content_400", *, status=None, body=None
    ) -> None:
        if body is None:
            rec = json.loads((FIXTURES / f"{name}.json").read_text())
            status, body = rec["status"], rec["body"]
        self.status = status
        self.content = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.requests: list[httpx.Request] = []
        self.model = GeminiDecisionModel(
            GeminiConfig(api_key="test-key-not-a-real-secret", paid_tier=True),
            client=httpx.AsyncClient(transport=httpx.MockTransport(self._handle)),
        )

    def _handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return httpx.Response(self.status, content=self.content)


def code_400(code, message: str = "Request failed. " + SENTINEL) -> Replay:
    return Replay(status=400, body={"error": {"code": code, "message": message}})


async def decide(gateway: DecisionGateway, tenant_id: str = "t_a", guard_point="input"):
    result = await gateway.decide(
        tenant_id=tenant_id, guard_point=guard_point, input=INPUT, questions=QUESTIONS
    )
    await gateway.drain()
    return result


def gateway_for(replay: Replay, meter=None, alerts=None) -> DecisionGateway:
    return DecisionGateway(replay.model, meter=meter, alerts=alerts, key_id=lambda: "key-v1")


# ------------------------------------------------------------------ refusals


@pytest.mark.parametrize("name", [*RECONSTRUCTED, *CONSTRUCTED])
async def test_refusal_is_not_retried_and_is_not_a_health_signal(name):
    replay, meter, alerts = Replay(name), InMemoryUsageMeter(), RecordingAlertSink()
    async with gateway_for(replay, meter, alerts) as gateway:
        result = await decide(gateway)

        assert isinstance(result, SafetyBlocked)
        expected = "prohibited_content"
        if name in CONSTRUCTED:
            expected = name.removeprefix("constructed_").removesuffix("_400")
        assert result.reason == expected
        assert len(replay.requests) == 1  # no gateway retry
        assert not gateway.breaker_open()  # the auth breaker is untouched
        assert gateway.orphaned_calls == 0 and gateway.orphans_in_flight == 0
        assert not gateway.orphan_capped
        assert alerts.alerts == []  # no page, no warning: not provider health
        assert meter.provider_safety_blocks("t_a", "input") == 1


@pytest.mark.parametrize(
    ("name", "detail"),
    [
        ("reconstructed_prohibited_content_400", "prohibited_content"),
        ("reconstructed_prohibited_content_400_top_level", "prohibited_content"),
        ("safety_400", "safety"),
        ("safety_400_top_level", "safety"),
        ("constructed_blocklist_400", "blocklist"),
        ("constructed_content_blocked_400", "content_blocked"),
        ("constructed_image_safety_400", "image_safety"),
    ],
)
async def test_refusal_is_metered_as_one_request_with_usage_unknown(name, detail):
    """The metering decision: one request, tokens attempted with usage unknown (the same path
    as an unfinished attempt), nothing in the answered-call tallies. Both refusal codes."""
    replay, meter = Replay(name), InMemoryUsageMeter()
    async with gateway_for(replay, meter) as gateway:
        timed = await gateway.decide_timed(
            tenant_id="t_a", guard_point="input", input=INPUT, questions=QUESTIONS
        )
        await gateway.drain()
    assert isinstance(timed.result, SafetyBlocked) and timed.result.reason == detail
    assert timed.timing.provider_calls == 1
    assert meter.unanswered_attempts("t_a", "input") == 1  # attempted, usage unknown
    assert meter.metered_calls("t_a", "input") == 0  # not an answered call
    assert meter.input_tokens("t_a", "input") == 0
    assert meter.unknown_calls("t_a", "input") == 0  # not "answered, usage unknown"
    assert meter.provider_safety_blocks("t_a", "input") == 1


async def test_repeated_refusals_never_open_the_breaker_or_alert_and_calls_keep_going_out():
    replay, meter, alerts = Replay(), InMemoryUsageMeter(), RecordingAlertSink()
    async with gateway_for(replay, meter, alerts) as gateway:
        for _ in range(20):
            assert isinstance(await decide(gateway), SafetyBlocked)
        assert len(replay.requests) == 20  # every check reached the provider: no fast-fail
        assert not gateway.breaker_open()
        assert alerts.alerts == []
        assert meter.provider_safety_blocks("t_a") == 20
        assert meter.unanswered_attempts("t_a", "input") == 20


async def test_provider_safety_metric_is_per_tenant_and_guard_point():
    replay, meter = Replay(), InMemoryUsageMeter()
    async with gateway_for(replay, meter) as gateway:
        await decide(gateway, "t_a", "input")
        await decide(gateway, "t_a", "output")
        await decide(gateway, "t_b", "input")
    assert meter.provider_safety_blocks("t_a") == 2
    assert meter.provider_safety_blocks("t_a", "input") == 1
    assert meter.provider_safety_blocks("t_a", "output") == 1
    assert meter.provider_safety_blocks("t_b") == 1
    assert meter.provider_safety_blocks("t_c") == 0


async def test_only_refusals_reach_the_provider_safety_metric():
    """A near-miss 400 (``invalid_request``) stays a failure and is not counted as one."""
    replay, meter = Replay("invalid_request_not_a_limit_400"), InMemoryUsageMeter()
    async with gateway_for(replay, meter) as gateway:
        result = await decide(gateway)
    assert result.kind is FailureKind.OTHER
    assert meter.provider_safety_blocks("t_a") == 0
    assert meter.unanswered_attempts("t_a", "input") == 0


async def test_meter_without_the_optional_methods_still_conforms():
    class OldMeter:
        def __init__(self) -> None:
            self.calls = []

        def record(self, tenant_id, guard_point, input_tokens):
            self.calls.append(("record", tenant_id))

        def record_unanswered(self, tenant_id, guard_point):
            self.calls.append(("unanswered", tenant_id))

    meter = OldMeter()
    assert not isinstance(meter, ProviderSafetyMeter | ProviderErrorMeter)
    async with gateway_for(Replay(), meter) as gateway:
        assert (await decide(gateway)).reason == "prohibited_content"
        assert gateway.dropped_events == 0
    assert meter.calls == [("unanswered", "t_a")]
    async with gateway_for(code_400("brand_new_code"), meter) as gateway:
        assert (await decide(gateway)).kind is FailureKind.OTHER
        assert gateway.dropped_events == 0


def test_in_memory_meter_implements_both_optional_meters():
    assert isinstance(InMemoryUsageMeter(), ProviderSafetyMeter)
    assert isinstance(InMemoryUsageMeter(), ProviderErrorMeter)


# ------------------------------------------------------------------ unrecognised 400 codes


@pytest.mark.parametrize("code", ["spii", "recitation", "prohibited", "blocked"])
async def test_unrecognised_code_is_failed_other_counted_and_logged_by_code_only(code, caplog):
    caplog.set_level(logging.DEBUG)
    replay, meter, alerts = code_400(code), InMemoryUsageMeter(), RecordingAlertSink()
    async with gateway_for(replay, meter, alerts) as gateway:
        result = await decide(gateway, "t_a", "tool_call")
        assert not gateway.breaker_open()
    assert isinstance(result, Failed) and result.kind is FailureKind.OTHER
    assert result.unrecognised_code == code
    assert meter.provider_errors_unrecognised("t_a", "tool_call", code) == 1
    assert meter.provider_errors_unrecognised("t_a", "input") == 0
    assert meter.provider_errors_unrecognised("t_b") == 0
    assert meter.provider_safety_blocks("t_a") == 0
    assert alerts.alerts == []
    [line] = [r.getMessage() for r in caplog.records if "provider_error_unrecognised" in r.msg]
    assert line == (
        f"provider_error_unrecognised code={code} tenant=t_a guard_point=tool_call suppressed=0"
    )
    assert SENTINEL not in caplog.text  # never the provider's message
    assert INPUT not in caplog.text  # never the request content


@pytest.mark.parametrize(
    ("status", "body"),
    [
        (400, {"error": {"code": "invalid_request", "message": "bad field " + SENTINEL}}),
        (400, {"error": {"code": 400, "status": "INVALID_ARGUMENT", "message": "bad field"}}),
        (500, {"error": {"code": "brand_new_code", "message": "x"}}),
        (404, {"error": {"code": "brand_new_code", "message": "x"}}),
    ],
    ids=["invalid_request", "invalid_argument", "a_500", "a_404"],
)
async def test_known_or_non_400_codes_are_not_counted_as_unrecognised(status, body):
    meter = InMemoryUsageMeter()
    async with gateway_for(Replay(status=status, body=body), meter) as gateway:
        result = await decide(gateway)
    assert isinstance(result, Failed)
    assert result.unrecognised_code is None
    assert meter.provider_errors_unrecognised("t_a") == 0


@pytest.mark.parametrize(
    ("body", "label"),
    [
        ({"error": {"message": "violates the Prohibited Use policy " + SENTINEL}}, "_no_code"),
        ({"error": {"code": "", "message": "x " + SENTINEL}}, "_no_code"),
        ({"error": {"code": 400, "message": "x " + SENTINEL}}, "_no_code"),
        (b"<html>Bad Request " + SENTINEL.encode() + b"</html>", "_not_json"),
        (b"", "_not_json"),
    ],
    ids=["no_code", "empty_code", "rpc_number_only", "html", "empty_body"],
)
async def test_m1_15_a_400_with_no_code_or_not_json_is_counted_by_its_shape(body, label, caplog):
    """A change in the error's shape is what monitoring most needs to catch."""
    caplog.set_level(logging.DEBUG)
    meter = InMemoryUsageMeter()
    async with gateway_for(Replay(status=400, body=body), meter) as gateway:
        result = await decide(gateway)
    assert isinstance(result, Failed) and result.kind is FailureKind.OTHER
    assert result.unrecognised_code == label
    assert meter.provider_errors_unrecognised("t_a", "input", label) == 1
    assert meter.unrecognised_codes() == {label}
    lines = [r.getMessage() for r in caplog.records if "provider_error_unrecognised" in r.msg]
    assert lines == [
        f"provider_error_unrecognised code={label} tenant=t_a guard_point=input suppressed=0"
    ]
    assert SENTINEL not in caplog.text


async def test_google_rpc_status_is_the_code_when_the_code_is_a_number():
    body = {"error": {"code": 400, "status": "FAILED_PRECONDITION", "message": "x"}}
    meter = InMemoryUsageMeter()
    async with gateway_for(Replay(status=400, body=body), meter) as gateway:
        result = await decide(gateway)
    assert result.unrecognised_code == "failed_precondition"  # casefolded (M1-15)
    assert meter.provider_errors_unrecognised("t_a", code="failed_precondition") == 1


@pytest.mark.parametrize(
    ("code", "label"),
    [
        ("Brand_New_Code", "brand_new_code"),  # casefolded before counting (M1-15)
        ("BRAND_NEW_CODE", "brand_new_code"),
        ("code_9", "code_9"),
        ("9code", "9code"),  # [a-z0-9_]: a leading digit is fine
        ("ns:code.v2-x", "_malformed"),  # outside [a-z0-9_]
        ("a" * 64, "a" * 64),  # the longest kept
        ("a" * 65, "_malformed"),  # too long
        ("x" * 10_000, "_malformed"),
        ("evil\nINJECTED log line", "_malformed"),  # newline: log injection
        ("evil\r\nINJECTED", "_malformed"),
        ("code with spaces", "_malformed"),
        ("code=forged tenant=other", "_malformed"),  # forging key=value pairs
        ("ünïcode", "_malformed"),
        ("_overflow", "_malformed"),  # can't impersonate the gateway's placeholders
        ("_no_code", "_malformed"),
        ("_not_json", "_malformed"),
        ("‮RTL", "_malformed"),
    ],
)
async def test_provider_code_is_bounded_before_it_is_logged_or_used_as_a_label(code, label, caplog):
    caplog.set_level(logging.DEBUG)
    meter = InMemoryUsageMeter()
    async with gateway_for(code_400(code), meter) as gateway:
        result = await decide(gateway)
    assert result.unrecognised_code == label
    assert meter.unrecognised_codes() == {label}
    lines = [r.getMessage() for r in caplog.records if "provider_error_unrecognised" in r.msg]
    assert lines == [
        f"provider_error_unrecognised code={label} tenant=t_a guard_point=input suppressed=0"
    ]
    for record in caplog.records:
        message = record.getMessage()
        assert "\n" not in message and "\r" not in message
        assert "INJECTED" not in message and "forged" not in message


async def test_distinct_code_labels_are_capped_to_bound_metric_cardinality(caplog):
    caplog.set_level(logging.WARNING)
    meter = InMemoryUsageMeter()
    extra = 10
    codes = [f"code_{i}" for i in range(MAX_UNRECOGNISED_CODE_LABELS + extra)]
    replay = code_400("unused")
    async with gateway_for(replay, meter) as gateway:
        for code in codes:
            replay.content = json.dumps({"error": {"code": code, "message": "x"}}).encode()
            await decide(gateway)
        # A code seen before the cap was reached keeps its own label afterwards.
        replay.content = json.dumps({"error": {"code": "code_0", "message": "x"}}).encode()
        await decide(gateway)
    labels = meter.unrecognised_codes()
    assert len(labels) == MAX_UNRECOGNISED_CODE_LABELS + 1
    assert UNRECOGNISED_CODE_OVERFLOW in labels
    assert meter.provider_errors_unrecognised("t_a", code=UNRECOGNISED_CODE_OVERFLOW) == extra
    assert meter.provider_errors_unrecognised("t_a", code="code_0") == 2
    assert meter.provider_errors_unrecognised("t_a") == len(codes) + 1


async def test_gateway_bounds_the_label_even_when_a_model_hands_it_an_unbounded_one():
    """``Failed`` bounds ``unrecognised_code`` on construction, whoever builds it, with the
    metric-label rule (M1-15), which is stricter than :func:`recorded_code`. The audit
    record's ``failure_reason`` keeps using ``recorded_code``, unchanged."""
    from guardrail_engine.decision import recorded_code
    from guardrail_engine.guard import verdict

    assert verdict.recorded_code is recorded_code
    bad = Failed(kind=FailureKind.OTHER, unrecognised_code="a\nb")
    assert bad.unrecognised_code == "_malformed"
    assert Failed(kind=FailureKind.OTHER, unrecognised_code="NEW").unrecognised_code == "new"
    assert Failed(kind=FailureKind.OTHER, unrecognised_code=7).unrecognised_code == "_malformed"
    for placeholder in ("_no_code", "_not_json", "_malformed"):
        kept = Failed(kind=FailureKind.OTHER, unrecognised_code=placeholder)
        assert kept.unrecognised_code == placeholder
    # recorded_code (failure_reason in verdicts, audit records and spans) is unchanged.
    assert recorded_code("Brand_New") == "Brand_New"
    assert recorded_code("ns:code.v2-x") == "ns:code.v2-x"
    assert recorded_code("a\nb") == "unrecognised"
