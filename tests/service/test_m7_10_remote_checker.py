"""M7-10 step 2: the SDK's remote checker. It returns the same results as the in-process mode,
and can only withhold when the service can't be reached."""

import asyncio
import json
import subprocess
import sys

import httpx
import pytest
from service_fixtures import INJECTION, TEXT, asgi_client, guard_ctx, make_engine, remote_guard

from guardrail_engine.decision import FailureKind
from guardrail_engine.guard.request import Plan, ToolCall, ToolResult, Turn
from guardrail_engine.sdk import FailureReason, Guard, GuardContext
from guardrail_engine.sdk.adapters.remote import RemoteChecker, connect
from guardrail_engine.service.adapters.fastapi_app import create_check_app


def same(result):
    """The two modes must agree on the whole result, the request id included (the caller's id
    travels in a header too, so even a check refused before its body is read answers it)."""
    return result


# ------------------------------------------------------------------------ the two modes agree

HISTORY = (
    Turn("user", "hello"),
    Plan('{"steps": []}'),
    ToolCall("search", "{}"),
    ToolResult("search", "three results"),
)

SCENARIOS = {
    "allow": (lambda m: m.set_noul(INJECTION, 0.01), [("input", TEXT, {})]),
    "block": (lambda m: m.set_noul(INJECTION, 0.95), [("input", TEXT, {})]),
    "escalate": (lambda m: m.set_noul(INJECTION, 0.6), [("input", TEXT, {})]),
    "provider refusal": (lambda m: m.safety_block_next(), [("input", TEXT, {})]),
    "model failure": (lambda m: m.fail_next(FailureKind.UNAVAILABLE, 2), [("input", TEXT, {})]),
    "timeout": (lambda m: m.fail_next(FailureKind.TIMEOUT, 2), [("output", TEXT, {})]),
    "bad guard point": (lambda m: None, [("lunch", TEXT, {})]),
    "no guard point": (lambda m: None, [(None, TEXT, {})]),
    "a guard point that is not text": (lambda m: None, [(5, TEXT, {})]),
    "a long guard point": (lambda m: None, [("x" * 200, TEXT, {})]),
    "an empty guard point": (lambda m: None, [("", TEXT, {})]),
    "a guard point in the wrong case": (lambda m: None, [("INPUT", TEXT, {})]),
    "bad context": (lambda m: None, [("input", TEXT, {"signed_context": "garbage"})]),
    "no context": (lambda m: None, [("input", TEXT, {"signed_context": ""})]),
    "conversation": (
        lambda m: m.set_noul(INJECTION, 0.01),
        [("input", TEXT, {"conversation": HISTORY, "conversation_id": "c-1"})],
    ),
    "tool call": (
        lambda m: m.set_noul(INJECTION, 0.01),
        [("tool_call", '{"tool": "search"}', {"tool": "search"})],
    ),
    "too large": (lambda m: None, [("input", "word " * 40_000, {})]),
    "repeat refusal": (
        lambda m: m.set_noul(INJECTION, 0.95),
        [("input", TEXT, {}), ("input", TEXT, {}), ("input", TEXT, {})],
    ),
}


@pytest.mark.parametrize("name", list(SCENARIOS))
async def test_both_modes_return_the_same_result(name):
    setup, calls = SCENARIOS[name]
    results = {}
    for mode in ("in process", "remote"):
        engine = await make_engine()
        try:
            setup(engine.model)
            guard = Guard(engine) if mode == "in process" else remote_guard(engine)
            out = []
            for i, (guard_point, content, kw) in enumerate(calls):
                ctx = guard_ctx(request_id=f"req-{i}", **kw)
                out.append(same(await guard.check(guard_point, content, ctx)))
            results[mode] = out
            await guard.aclose()
        finally:
            await engine.shutdown()
    assert results["in process"] == results["remote"]
    assert all(r.released is False for r in results["remote"] if r.decision != "allow")


async def test_a_degraded_provider_reads_the_same_over_the_wire():
    engine = await make_engine()
    try:
        guard = remote_guard(engine)
        engine.model.fail_next(FailureKind.UNAVAILABLE, 5)
        for _ in range(3):  # five failed calls in all: the breaker opens
            await guard.check("input", TEXT, guard_ctx())
        r = await guard.check("input", TEXT, guard_ctx())
        assert r.degraded and r.failure_reason is FailureReason.PROVIDER_DEGRADED
        assert r.retryable and 100 <= r.retry_after_ms <= 10_000 and not r.released
    finally:
        await engine.shutdown()


# ------------------------------------------------------------------------ over the wire


async def test_streaming_the_input_gate_and_retry_work_over_the_remote_checker():
    engine = await make_engine()
    try:
        engine.model.set_noul(INJECTION, 0.01)
        guard = remote_guard(engine)
        ctx = guard_ctx(request_id="turn-1")
        gate = guard.start_input_guard(TEXT, ctx)

        async def source():
            for piece in ("The first sentence. ", "The second one. "):
                yield piece

        events = [e async for e in guard.stream_output(source(), ctx, gate=gate)]
        assert [e.kind for e in events] == ["window", "window"]
        assert all(e.result.released for e in events)
        engine.model.fail_next(FailureKind.UNAVAILABLE, 2)  # the first try fails, the retry works
        waits = []

        async def sleep(seconds):
            waits.append(seconds)

        result = await guard.check_with_retry(
            "input", TEXT, guard_ctx(request_id="r-9"), sleep=sleep, jitter_ms=0
        )
        assert result.released and result.retry_of == "r-9" and len(waits) == 1
    finally:
        await engine.shutdown()


async def test_a_blocked_window_stops_the_stream_over_the_wire():
    engine = await make_engine()
    try:
        engine.model.set_noul(INJECTION, 0.01)
        guard = remote_guard(engine)
        ctx = guard_ctx()
        gate = guard.start_input_guard(TEXT, ctx)
        engine.model.set_noul(INJECTION, 0.95)  # from the output windows on

        async def source():
            yield "Anything at all. "

        events = [e async for e in guard.stream_output(source(), ctx, gate=gate)]
        assert events[-1].kind == "refusal" and not events[-1].result.released
    finally:
        await engine.shutdown()


async def test_a_caller_who_is_cancelled_cancels_the_check_in_the_service():
    started = asyncio.Event()
    cancelled = asyncio.Event()

    class Slow:
        async def check(self, ctx, guard_point, content):
            started.set()
            try:
                await asyncio.sleep(30)
            except asyncio.CancelledError:
                cancelled.set()
                raise

    guard = connect("http://guard.test", client=asgi_client(create_check_app(Slow())), margin_s=60)
    task = asyncio.ensure_future(guard.check("input", TEXT, guard_ctx()))
    await asyncio.wait_for(started.wait(), 5)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    # httpx's ASGI transport can't signal a disconnect, so the service-side cancel is covered
    # by the endpoint tests; here the caller's cancellation must propagate and nothing leaks.
    assert started.is_set()


# ------------------------------------------------------------------------ it can only withhold


def answer(request, status=200, **over):
    """A well-formed answer to ``request`` (its request id and guard point), with ``over``
    changed. The tests that follow bend one thing at a time."""
    asked = json.loads(request.content)
    body = {
        "decision": "allow", "reason": "policy", "request_id": asked["request_id"],
        "guard_point": asked["guard_point"], "fired": [], "retryable": False,
        "failure_reason": None, "capacity_limited": False, "retry_after_ms": None,
        "degraded": False,
    }  # fmt: skip
    return httpx.Response(status, json={**body, **over})


def mock_guard(handler, **options) -> Guard:
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler), base_url="http://guard.test")
    return connect("http://guard.test", client=client, **options)


def unreachable(result):
    assert result.decision == "block" and result.reason == "model_failure"
    assert result.failure_reason is FailureReason.GUARD_UNREACHABLE
    assert result.retryable is True and result.released is False
    assert result.capacity_limited is False and result.degraded is False


def refuse_connect(request):
    raise httpx.ConnectError("no route")


def time_out(request):
    raise httpx.ReadTimeout("slow")


FAILURES = {
    "connect error": refuse_connect,
    "timeout": time_out,
    "500": lambda r: httpx.Response(500, json={"error": {"code": "internal_error"}}),
    "502": lambda r: httpx.Response(502, text="bad gateway"),
    "503": lambda r: httpx.Response(503),
    "429": lambda r: httpx.Response(429),
    "404": lambda r: httpx.Response(404),
    "200 with html": lambda r: httpx.Response(200, text="<html>proxy</html>"),
    "200 with a list": lambda r: httpx.Response(200, json=[1, 2]),
    "200 missing members": lambda r: httpx.Response(200, json={"decision": "allow"}),
    "200 allow of the wrong type": lambda r: httpx.Response(
        200,
        json={
            "decision": "allow",
            "reason": "policy",
            "request_id": "r",
            "guard_point": "input",
            "fired": "none",
            "retryable": False,
            "failure_reason": None,
            "capacity_limited": False,
            "retry_after_ms": None,
            "degraded": False,
        },
    ),
}


@pytest.mark.parametrize("name", list(FAILURES))
async def test_a_service_that_cannot_be_reached_or_understood_is_withheld_and_retryable(name):
    guard = mock_guard(FAILURES[name])
    result = await guard.check("input", TEXT, guard_ctx(request_id="r-1"))
    unreachable(result)
    assert result.request_id == "r-1" and result.guard_point == "input"


async def test_an_unreachable_service_retries_once_and_never_releases():
    calls = []

    def handler(request):
        calls.append(json.loads(request.content)["request_id"])
        raise httpx.ConnectError("down")

    guard = mock_guard(handler)

    async def no_sleep(seconds):
        return None

    result = await guard.check_with_retry(
        "input", TEXT, guard_ctx(request_id="r-5"), sleep=no_sleep, jitter_ms=0
    )
    unreachable(result)
    assert calls == ["r-5", "r-5-retry"] and result.retry_of == "r-5"


async def test_the_size_refusals_and_a_malformed_request_are_blocks_that_are_not_retried():
    for status, reason in ((413, "content_too_large"), (400, "invalid_request"),
                           (415, "invalid_request"), (431, "invalid_request")):  # fmt: skip
        guard = mock_guard(lambda r, s=status: httpx.Response(s))
        result = await guard.check("input", TEXT, guard_ctx())
        assert (result.decision, result.reason) == ("block", reason)
        assert result.retryable is False and result.released is False


async def test_an_auth_refusal_passes_through_as_the_forbidden_it_is():
    engine = await make_engine()
    try:
        r = await remote_guard(engine).check("input", TEXT, guard_ctx(signed_context="forged"))
        assert (r.decision, r.reason) == ("forbidden", "context_invalid")
        assert r.released is False and r.retryable is False
    finally:
        await engine.shutdown()


async def test_a_failure_reason_a_newer_service_adds_reads_as_other_and_is_still_withheld():
    def handler(request):
        return answer(
            request,
            decision="block", reason="model_failure", retryable=True,
            failure_reason="a_reason_from_the_future", retry_after_ms=500,
        )  # fmt: skip

    result = await mock_guard(handler).check("input", TEXT, guard_ctx())
    assert result.failure_reason is FailureReason.OTHER and not result.released
    assert result.retry_after_ms == 500


async def test_a_decision_the_sdk_does_not_know_still_withholds():
    guard = mock_guard(lambda r: answer(r, decision="quarantine"))
    assert (await guard.check("input", TEXT, guard_ctx())).released is False


# ------------------------------------------------------------------------ what it sends


async def test_the_request_carries_the_context_in_a_header_and_no_tenant_in_the_body():
    seen = {}

    def handler(request):
        seen["headers"] = dict(request.headers)
        seen["body"] = json.loads(request.content)
        seen["timeout"] = request.extensions["timeout"]
        raise httpx.ConnectError("stop here")

    guard = mock_guard(handler)
    ctx = GuardContext(
        signed_context="v2.sentinel.context.token",
        request_id="r-1",
        conversation=(Turn("user", "hi"),),
        conversation_id="c-1",
        tool="search",
    )
    await guard.check("tool_call", "{}", ctx)
    assert seen["headers"]["guard-context"] == "v2.sentinel.context.token"
    assert set(seen["body"]) == {
        "guard_point", "content", "conversation", "conversation_id", "tool", "request_id"
    }  # fmt: skip
    assert "sentinel" not in json.dumps(seen["body"])
    assert seen["body"]["conversation"] == [{"type": "turn", "role": "user", "text": "hi"}]
    assert seen["timeout"]["read"] == 3.25  # the guard point's cap and the margin


async def test_the_client_waits_the_guard_points_cap_plus_the_margin():
    seen = []

    def handler(request):
        seen.append(request.extensions["timeout"]["read"])
        raise httpx.ConnectError("x")

    guard = mock_guard(handler, timeouts_s={"output": 5.0}, margin_s=0.5)
    for guard_point in ("input", "output", "plan"):
        await guard.check(guard_point, TEXT, guard_ctx())
    assert seen == [4.5, 5.5, 3.5]


@pytest.mark.parametrize("token", ["", "x" * 5000, "café", "line\nbreak", "tab\t"])
async def test_a_context_that_cannot_be_a_header_is_sent_as_a_missing_one(token):
    sent = []

    def handler(request):
        sent.append(request.headers["guard-context"])
        return answer(request, 401, decision="forbidden", reason="context_invalid")

    guard = mock_guard(handler)
    result = await guard.check("input", TEXT, GuardContext(signed_context=token))
    assert sent == [""] and (result.decision, result.reason) == ("forbidden", "context_invalid")


async def test_the_checker_holds_no_secret_and_says_nothing_in_its_repr():
    guard = connect("http://guard.test")
    assert repr(guard) == "Guard()" and repr(guard._checker) == "RemoteChecker()"
    await guard.aclose()


def test_the_limits_are_checked():
    with pytest.raises(ValueError):
        RemoteChecker("http://x", margin_s=-1)
    with pytest.raises(ValueError):
        RemoteChecker("http://x", max_connections=0)


# ------------------------------------------------------------------------ the client install


def test_importing_the_sdk_and_the_remote_checker_loads_no_engine_adapter_or_server():
    """The runtime needs no provider adapter, database driver, web framework or signing library
    just to check: the remote mode's imports stay that small."""
    code = (
        "import sys, guardrail_engine.sdk, guardrail_engine.sdk.adapters.remote;"
        "bad = sorted(m for m in sys.modules if m.split('.')[0] in "
        "('asyncpg', 'fastapi', 'starlette', 'uvicorn', 'cryptography', 'jwt')"
        " or m.startswith('guardrail_engine.engine')"
        " or m.endswith('.adapters.fastapi_app')"
        " or m.startswith(('guardrail_engine.decision.adapters',"
        " 'guardrail_engine.store.adapters'))"
        ");"
        "print(bad)"
    )
    out = subprocess.run(
        [sys.executable, "-I", "-c", code], capture_output=True, text=True, check=True
    ).stdout
    assert out.strip() == "[]"


# ------------------------------------------------------------------------ an answer to this request


def released(result) -> bool:
    return result.released


async def asked(handler, guard_point="input", **kw):
    return await mock_guard(handler).check(guard_point, TEXT, guard_ctx(request_id="r-7", **kw))


@pytest.mark.parametrize("status", [401, 403])
async def test_a_401_or_403_whose_body_is_an_allow_is_not_released(status):
    result = await asked(lambda r: answer(r, status))
    unreachable(result)


async def test_a_forbidden_with_a_200_is_not_accepted_either():
    forbidden = {"decision": "forbidden", "reason": "context_invalid"}
    unreachable(await asked(lambda r: answer(r, 200, **forbidden)))


@pytest.mark.parametrize("status", [401, 403])
async def test_a_forbidden_with_401_or_403_is_accepted(status):
    forbidden = {"decision": "forbidden", "reason": "context_invalid"}
    result = await asked(lambda r: answer(r, status, **forbidden))
    assert (result.decision, result.released) == ("forbidden", False) and result.request_id == "r-7"


async def test_an_allow_that_answers_another_request_is_not_released():
    unreachable(await asked(lambda r: answer(r, request_id="someone-elses")))


async def test_an_allow_that_answers_another_guard_point_is_not_released():
    unreachable(await asked(lambda r: answer(r, guard_point="output")))


async def test_members_a_newer_service_adds_are_dropped_not_refused():
    result = await asked(lambda r: answer(r, p=0.01, threshold={"block_at": 0.8}))
    assert result.released and not hasattr(result, "p") and not hasattr(result, "threshold")


@pytest.mark.parametrize("member", ["decision", "retry_after_ms", "failure_reason", "degraded"])
async def test_a_member_of_the_contract_that_is_missing_is_not_an_answer(member):
    def handler(request):
        response = answer(request)
        body = json.loads(response.content)
        del body[member]
        return httpx.Response(200, json=body)

    unreachable(await asked(handler))


@pytest.mark.parametrize(
    "over",
    [
        {"retryable": "false"}, {"capacity_limited": 0}, {"degraded": None},
        {"fired": [{"key": "k"}]}, {"retry_after_ms": "5"}, {"decision": 5},
    ],
)  # fmt: skip
async def test_a_member_of_the_wrong_type_is_not_an_answer(over):
    unreachable(await asked(lambda r: answer(r, **over)))


async def test_a_redirect_is_never_followed_and_the_context_never_leaves_for_another_host():
    hosts = []

    def handler(request):
        hosts.append((request.url.host, request.headers.get("guard-context")))
        if request.url.host == "guard.test":
            return httpx.Response(307, headers={"Location": "http://elsewhere.example/v1/check"})
        return answer(request)

    client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler), base_url="http://guard.test", follow_redirects=True
    )  # the caller's client follows redirects: the checker must not
    guard = connect("http://guard.test", client=client)
    unreachable(await guard.check("input", TEXT, guard_ctx(request_id="r-7")))
    assert [h for h, _ in hosts] == ["guard.test"]  # nothing went to elsewhere.example


async def test_the_request_id_travels_in_a_header_and_the_body_too():
    seen = {}

    def handler(request):
        seen["header"] = request.headers["guard-request-id"]
        seen["body"] = json.loads(request.content)["request_id"]
        return answer(request)

    result = await mock_guard(handler).check("input", TEXT, guard_ctx())  # no id: one is made
    assert seen["header"] == seen["body"] == result.request_id and len(seen["header"]) == 32


# ------------------------------------------------------------------------ time, and a bad body


async def test_a_body_that_never_finishes_is_guard_unreachable_at_the_deadline():
    """A response dripped one byte at a time, each gap short, would pass httpx's per-read
    timeout for ever. The whole exchange has a deadline."""
    import time

    body = json.dumps(
        {
            "decision": "allow", "reason": "policy", "request_id": "r-7", "guard_point": "input",
            "fired": [], "retryable": False, "failure_reason": None,
            "capacity_limited": False, "retry_after_ms": None, "degraded": False,
        }
    ).encode()  # fmt: skip

    async def serve(reader, writer):
        await reader.readuntil(b"\r\n\r\n")  # the request's head; the body isn't read
        writer.write(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
            + f"Content-Length: {len(body)}\r\n\r\n".encode()
        )
        for i in range(0, len(body), 8):  # eight bytes at a time, 0.2 s apart: well past 0.6 s
            try:
                writer.write(body[i : i + 8])
                await writer.drain()
                await asyncio.sleep(0.2)
            except ConnectionError:
                return
        writer.close()

    server = await asyncio.start_server(serve, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        guard = connect(
            f"http://127.0.0.1:{port}", timeouts_s={"input": 0.5}, margin_s=0.1
        )  # every read arrives inside 0.6 s; the whole answer takes about 3 s
        started = time.perf_counter()
        result = await guard.check("input", TEXT, guard_ctx(request_id="r-7"))
        took = time.perf_counter() - started
        await guard.aclose()
    finally:
        server.close()
        await server.wait_closed()
    unreachable(result)
    assert took < 1.5  # at the deadline, not when the drip ended


async def test_a_deeply_nested_body_is_guard_unreachable_and_never_an_exception():
    nested = b"[" * 200_000 + b"]" * 200_000
    unreachable(await asked(lambda r: httpx.Response(200, content=nested)))


async def test_any_exception_while_reading_the_answer_is_guard_unreachable():
    class Breaks(httpx.AsyncByteStream):
        async def __aiter__(self):
            yield b'{"decision":'
            raise RuntimeError("the stream broke")

    unreachable(await asked(lambda r: httpx.Response(200, stream=Breaks())))


# ---- the runtime holds no credentials


def test_the_credential_variables_are_the_ones_the_engine_reads():
    from guardrail_engine.engine.factory import API_KEY_ENV, PG_DSN_ENV, PG_OPERATOR_DSN_ENV
    from guardrail_engine.sdk.adapters.remote import CREDENTIAL_VARIABLES

    assert set(CREDENTIAL_VARIABLES) == {API_KEY_ENV, PG_DSN_ENV, PG_OPERATOR_DSN_ENV}


@pytest.mark.parametrize(
    "name", ["GEMINI_API_KEY", "GUARDRAIL_PG_DSN", "GUARDRAIL_PG_OPERATOR_DSN", "GEMINI_KEY_ACME"]
)
def test_remote_mode_refuses_a_runtime_that_holds_a_key_or_a_dsn(name):
    from guardrail_engine.sdk.adapters.remote import CredentialsInRuntimeError

    with pytest.raises(CredentialsInRuntimeError) as raised:
        connect("http://guard.test", environ={name: "sentinel-secret-value", "PATH": "/bin"})
    assert name in str(raised.value) and "sentinel-secret-value" not in str(raised.value)


def test_an_empty_variable_is_not_a_credential_and_the_operator_can_allow_one():
    guard = connect("http://guard.test", environ={"GEMINI_API_KEY": ""})
    assert repr(guard) == "Guard()"
    connect(
        "http://guard.test", environ={"GEMINI_API_KEY": "x"}, allow_credentials_in_environment=True
    )


def test_it_reads_the_process_environment_by_default(monkeypatch):
    from guardrail_engine.sdk.adapters.remote import CredentialsInRuntimeError, credentials_in

    monkeypatch.setenv("GUARDRAIL_PG_DSN", "postgresql://u:secret@host/db")
    assert credentials_in() == ["GUARDRAIL_PG_DSN"]
    with pytest.raises(CredentialsInRuntimeError):
        connect("http://guard.test")


async def test_an_invalid_guard_point_is_blocked_locally_without_a_call():
    calls = []

    def handler(request):
        calls.append(request)
        return answer(request)

    guard = mock_guard(handler)
    for bad in (None, 5, "", "lunch", "INPUT", "input ", ["input"]):
        result = await guard.check(bad, TEXT, guard_ctx(request_id="r-1"))
        assert (result.decision, result.reason) == ("block", "invalid_request")
        assert result.retryable is False and result.released is False
    assert calls == []  # the service was never asked


def test_a_deployments_own_key_variable_names_can_be_listed():
    from guardrail_engine.sdk.adapters.remote import CredentialsInRuntimeError, credentials_in

    env = {"ACME_GEMINI_SECRET": "sentinel", "PATH": "/bin"}
    assert credentials_in(env) == []  # a name the runtime isn't told can't be found
    assert credentials_in(env, extra=["ACME_GEMINI_SECRET"]) == ["ACME_GEMINI_SECRET"]
    connect("http://guard.test", environ=env)  # not found: allowed (the stated gap)
    with pytest.raises(CredentialsInRuntimeError) as raised:
        connect("http://guard.test", environ=env, extra_credential_variables=["ACME_GEMINI_SECRET"])
    assert "ACME_GEMINI_SECRET" in str(raised.value) and "sentinel" not in str(raised.value)
