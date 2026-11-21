"""M1-15 (R8 on the build): a provider 429 that carries a google.rpc ``RetryInfo``
detail passes its delay on as ``Failed.retry_delay_s``; the gateway then gives it to the
caller as ``retry_after_ms``, clamped to 100-10,000 ms. Only the structured ``retryDelay``
(a google.protobuf.Duration in JSON form, ``"2.5s"``) is read. Never the message text.
Negative, non-finite or malformed values give no delay (and so no hint).

The fixture is **constructed** from the documented google.rpc shape, not recorded: no 429 with
``RetryInfo`` has been observed on this API (its ``source`` field says so).
"""

import json
from pathlib import Path

import pytest

from guardrail_engine.decision import Failed, FailureKind, NoulQuestion
from guardrail_engine.decision.adapters.gemini import map_http_response

FIXTURES = Path(__file__).parents[1] / "fixtures" / "gemini"
QUESTIONS = {"p__x": NoulQuestion(instructions="Is the content about insurance?")}
RETRY_INFO = "type.googleapis.com/google.rpc.RetryInfo"


def load(name: str) -> tuple[int, dict, str]:
    rec = json.loads((FIXTURES / f"{name}.json").read_text())
    return rec["status"], rec["body"], rec["source"]


def rpc_429(
    *details,
    message: str = "Resource has been exhausted.",
    status: int = 429,
    rpc_status: str = "RESOURCE_EXHAUSTED",
) -> bytes:
    return json.dumps(
        {
            "error": {
                "code": status,
                "message": message,
                "status": rpc_status,
                "details": list(details),
            }
        }
    ).encode()


def retry_info(delay) -> dict:
    return {"@type": RETRY_INFO, "retryDelay": delay}


def test_the_fixture_is_labelled_as_constructed_not_recorded():
    _, body, source = load("constructed_rate_limited_retry_info_429")
    assert source.startswith("constructed 2026-11-17")
    assert "NOT a recording" in source
    assert "No 429 carrying RetryInfo has been observed" in source
    [detail] = body["error"]["details"]
    assert detail == {"@type": RETRY_INFO, "retryDelay": "2.5s"}


def test_the_constructed_429_carries_its_retry_delay():
    status, body, _ = load("constructed_rate_limited_retry_info_429")
    result = map_http_response(status, json.dumps(body).encode(), QUESTIONS)
    assert isinstance(result, Failed) and result.kind is FailureKind.RATE_LIMITED
    assert result.retry_delay_s == 2.5


@pytest.mark.parametrize(
    ("delay", "seconds"),
    [("2.5s", 2.5), ("0s", 0.0), ("3s", 3.0), ("0.000000001s", 1e-9), ("120s", 120.0)],
)
def test_well_formed_durations(delay, seconds):
    result = map_http_response(429, rpc_429(retry_info(delay)), QUESTIONS)
    assert result.kind is FailureKind.RATE_LIMITED
    assert result.retry_delay_s == pytest.approx(seconds)


@pytest.mark.parametrize(
    "delay",
    [
        "-1s",  # negative
        "-0.5s",
        "2.5",  # no unit
        "2.5ms",
        "1e3s",
        "infs",
        "NaNs",
        " 2s",
        "2s ",
        "2.1234567891s",  # more than nine fractional digits
        "1234567890123s",  # more than twelve digits of seconds
        "",
        2.5,  # not the JSON string form
        {"seconds": 2, "nanos": 0},
        None,
        True,
    ],
)
def test_malformed_or_negative_durations_give_no_delay(delay):
    result = map_http_response(429, rpc_429(retry_info(delay)), QUESTIONS)
    assert result.kind is FailureKind.RATE_LIMITED
    assert result.retry_delay_s is None


def test_only_the_structured_detail_is_read_never_the_message():
    message = "Quota exceeded. Please retry in 30s. retryDelay: 45s"
    result = map_http_response(429, rpc_429(message=message), QUESTIONS)
    assert result.kind is FailureKind.RATE_LIMITED
    assert result.retry_delay_s is None
    other_detail = {"@type": "type.googleapis.com/google.rpc.ErrorInfo", "retryDelay": "5s"}
    assert map_http_response(429, rpc_429(other_detail), QUESTIONS).retry_delay_s is None


def test_the_first_retry_info_decides():
    # A malformed first RetryInfo gives no delay, even if a later one is well formed.
    result = map_http_response(429, rpc_429(retry_info("x"), retry_info("2s")), QUESTIONS)
    assert result.retry_delay_s is None
    result = map_http_response(429, rpc_429(retry_info("1s"), retry_info("9s")), QUESTIONS)
    assert result.retry_delay_s == 1.0


def test_a_quota_400_with_retry_info_carries_it_too():
    body = json.dumps(
        {
            "error": {
                "code": "invalid_request",
                "message": "Quota exceeded for requests per minute.",
                "details": [retry_info("4s")],
            }
        }
    ).encode()
    result = map_http_response(400, body, QUESTIONS)
    assert result.kind is FailureKind.RATE_LIMITED
    assert result.retry_delay_s == 4.0


@pytest.mark.parametrize("status", [500, 503, 408, 401])
def test_retry_info_on_anything_but_a_rate_limit_is_ignored(status):
    body = rpc_429(retry_info("2s"), status=status, rpc_status="UNAVAILABLE")
    result = map_http_response(status, body, QUESTIONS)
    assert isinstance(result, Failed)
    assert result.kind is not FailureKind.RATE_LIMITED
    assert result.retry_delay_s is None


@pytest.mark.parametrize(
    "value", [-1.0, float("inf"), float("-inf"), float("nan"), True, "2.5", None]
)
def test_failed_drops_a_delay_that_isnt_a_finite_non_negative_number(value):
    assert Failed(kind=FailureKind.RATE_LIMITED, retry_delay_s=value).retry_delay_s is None
    assert Failed(kind=FailureKind.RATE_LIMITED, retry_delay_s=0).retry_delay_s == 0.0


@pytest.mark.parametrize(("delay", "positive"), [("-1s", 1.0), ("-0.5s", 0.5), ("-0s", 0.0)])
def test_the_adapter_itself_refuses_a_negative_duration(delay, positive):
    """The parser refuses the minus sign. ``Failed`` would drop a negative delay as well, but
    the adapter doesn't rely on that."""
    from guardrail_engine.decision.adapters.gemini import _retry_delay

    assert _retry_delay([retry_info(delay)]) is None
    assert _retry_delay([retry_info(delay.removeprefix("-"))]) == positive
