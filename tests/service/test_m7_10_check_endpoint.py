"""M7-10 step 1: the check listener. A real engine (fake model) behind ``create_check_app``,
driven over an ASGI transport."""

import asyncio
import json

import httpx
import pytest
from service_fixtures import INJECTION, TEXT, asgi_client, make_engine, signed

from guardrail_engine.service.adapters.fastapi_app import create_check_app
from guardrail_engine.service.wire import RESULT_MEMBERS

HEADERS = {"Guard-Context": "", "Content-Type": "application/json"}


def headers(token=None, **more):
    return {**HEADERS, "Guard-Context": signed() if token is None else token, **more}


def body(**members):
    return json.dumps({"guard_point": "input", "content": TEXT, **members})


@pytest.fixture
async def engine():
    e = await make_engine()
    yield e
    await e.shutdown()


@pytest.fixture
async def client(engine):
    async with asgi_client(create_check_app(engine)) as c:
        yield c


async def test_an_allowed_check_returns_the_public_result_and_nothing_else(client, engine):
    engine.model.set_noul(INJECTION, 0.01)
    r = await client.post("/v1/check", content=body(request_id="req-1"), headers=headers())
    assert r.status_code == 200
    doc = r.json()
    assert list(doc) == list(RESULT_MEMBERS)  # exactly the contract, in order
    assert (doc["decision"], doc["reason"], doc["request_id"]) == ("allow", "policy", "req-1")
    assert doc["retryable"] is False and doc["failure_reason"] is None and doc["degraded"] is False
    assert r.headers["cache-control"] == "no-store"


async def test_a_blocked_check_names_the_rules_that_fired_but_never_their_numbers(client, engine):
    engine.model.set_noul(INJECTION, 0.95)
    r = await client.post("/v1/check", content=body(), headers=headers())
    doc = r.json()
    assert r.status_code == 200 and doc["decision"] == "block" and doc["reason"] == "policy"
    assert [f["key"] for f in doc["fired"]] == [INJECTION]
    assert set(doc["fired"][0]) == {"key", "action", "mode"}
    text = r.text
    for private in ("probabilit", "threshold", "block_at", "escalate_at", "0.95", "model_id"):
        assert private not in text


async def test_every_verdict_is_a_200_including_a_provider_refusal(client, engine):
    engine.model.safety_block_next(message="the provider's own words")
    r = await client.post("/v1/check", content=body(), headers=headers())
    assert r.status_code == 200 and r.json()["reason"] == "provider_safety"
    assert "the provider's own words" not in r.text


async def test_the_engine_judges_the_types_of_the_guard_point_and_the_content(client):
    odd = json.dumps({"guard_point": "lunch", "content": TEXT})
    r = await client.post("/v1/check", content=odd, headers=headers())
    assert (r.status_code, r.json()["reason"]) == (200, "invalid_request")
    r = await client.post(
        "/v1/check", content=json.dumps({"guard_point": "input", "content": 5}), headers=headers()
    )
    assert (r.status_code, r.json()["reason"]) == (200, "invalid_request")


async def test_a_conversation_reaches_the_engine_as_typed_items(client, engine):
    engine.model.set_noul(INJECTION, 0.01)
    items = [
        {"type": "turn", "role": "user", "text": "hello"},
        {"type": "plan", "text": "{}"},
        {"type": "tool_call", "tool": "search", "arguments": "{}"},
        {"type": "tool_result", "tool": "search", "result": "ok"},
    ]
    r = await client.post("/v1/check", content=body(conversation=items), headers=headers())
    assert r.status_code == 200 and r.json()["decision"] == "allow"
    assert "hello" in engine.model.calls[-1].input  # it was rendered into the call


# ------------------------------------------------------------------------ the context


@pytest.mark.parametrize(
    "token",
    [None, "", "v2.nonsense", "x" * 5000, "has a space \x01", "forged.token.here"],
)
async def test_a_missing_malformed_or_forged_context_is_a_401_with_the_public_forbidden(
    client, engine, token
):
    h = {"Content-Type": "application/json"}
    if token is not None:
        h["Guard-Context"] = token
    r = await client.post("/v1/check", content=body(), headers=h)
    assert r.status_code == 401
    doc = r.json()
    assert (doc["decision"], doc["reason"]) == ("forbidden", "context_invalid")
    assert list(doc) == list(RESULT_MEMBERS)  # no detail beyond the in-process codes
    assert engine.model.calls == []  # nothing was sent to the model


async def test_a_missing_context_is_decided_before_the_body_is_read(client, engine):
    r = await client.post(
        "/v1/check", content=b"{ not json at all", headers={"Content-Type": "application/json"}
    )
    assert r.status_code == 401  # not a 400: the body was never looked at


async def test_the_tenant_is_only_the_contexts_and_a_body_cannot_name_one(client):
    r = await client.post("/v1/check", content=body(tenant_id="t_other"), headers=headers())
    assert (r.status_code, r.json()["error"]["code"]) == (400, "invalid_body")


# ------------------------------------------------------------------------ limits and shape


async def test_oversized_headers_are_a_431(engine):
    async with asgi_client(create_check_app(engine, max_header_bytes=2_000)) as c:
        r = await c.post("/v1/check", content=body(), headers=headers(**{"X-Pad": "a" * 3_000}))
    assert (r.status_code, r.json()["error"]["code"]) == (431, "headers_too_large")


async def test_a_body_over_the_cap_is_a_413_by_its_length_and_while_streaming(engine):
    async with asgi_client(create_check_app(engine, max_body_bytes=1_000)) as c:
        r = await c.post("/v1/check", content=body(content="x" * 5_000), headers=headers())
        assert (r.status_code, r.json()["error"]["code"]) == (413, "body_too_large")

        async def chunks():  # no Content-Length: the cap is applied as it reads
            for _ in range(10):
                yield b"x" * 500

        r = await c.post("/v1/check", content=chunks(), headers=headers())
        assert r.status_code == 413


@pytest.mark.parametrize(
    "payload",
    [
        b"not json",
        b"[]",
        b'{"guard_point": "input"}',
        b'{"guard_point": "input", "content": "x", "conversation": "no"}',
        b'{"guard_point": "input", "content": "x", "conversation": [{"type": "memo"}]}',
        b'{"guard_point": "input", "content": "x", "conversation": [{"type": "turn", "role": "bot", "text": "t"}]}',  # noqa: E501
        b'{"guard_point": "input", "content": "x", "conversation": [{"type": "plan", "text": 4}]}',
        b'{"guard_point": "input", "content": "x", "tool": 5}',
        b'{"guard_point": "input", "content": "x", "extra": 1}',
    ],
)
async def test_a_body_that_is_not_the_contract_is_a_400(client, payload):
    r = await client.post("/v1/check", content=payload, headers=headers())
    assert (r.status_code, r.json()["error"]["code"]) == (400, "invalid_body")


async def test_only_json_is_accepted(client):
    r = await client.post(
        "/v1/check", content=body(), headers=headers(**{"Content-Type": "text/plain"})
    )
    assert r.status_code == 415


# ------------------------------------------------------------------------ the surface


async def test_health_is_liveness_only_and_shows_no_state(client, engine):
    r = await client.get("/healthz")
    assert (r.status_code, r.json()) == (200, {"status": "ok"})
    await engine.shutdown()  # still alive while it drains; no state to show either way
    assert (await client.get("/healthz")).json() == {"status": "ok"}


@pytest.mark.parametrize("path", ["/docs", "/redoc", "/openapi.json", "/v1/platform/floors", "/"])
async def test_there_is_no_other_route(client, path):
    assert (await client.get(path)).status_code == 404


async def test_a_check_after_shutdown_has_begun_is_the_engines_retryable_block(client, engine):
    await engine.shutdown()
    r = await client.post("/v1/check", content=body(), headers=headers())
    doc = r.json()
    assert (r.status_code, doc["decision"], doc["reason"]) == (200, "block", "engine_closed")
    assert doc["retryable"] is True


async def test_an_engine_that_raises_is_a_generic_500():
    class Broken:
        async def check(self, ctx, guard_point, content):
            raise RuntimeError("secret detail")

    async with asgi_client(create_check_app(Broken())) as c:
        r = await c.post("/v1/check", content=body(), headers=headers())
    assert (r.status_code, r.json()) == (500, {"error": {"code": "internal_error"}})
    assert "secret detail" not in r.text


async def test_the_limits_are_checked():
    with pytest.raises(ValueError):
        create_check_app(object(), max_body_bytes=0)  # type: ignore[arg-type]


# ------------------------------------------------------------------------ disconnect


async def test_a_client_that_goes_away_cancels_its_check():
    started, cancelled = asyncio.Event(), asyncio.Event()

    class Slow:
        async def check(self, ctx, guard_point, content):
            started.set()
            try:
                await asyncio.sleep(30)
            except asyncio.CancelledError:
                cancelled.set()
                raise

    app = create_check_app(Slow())
    payload = body().encode()
    messages = asyncio.Queue()
    await messages.put({"type": "http.request", "body": payload, "more_body": False})
    sent = []

    async def receive():
        return await messages.get()

    async def send(message):
        sent.append(message)

    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "path": "/v1/check",
        "raw_path": b"/v1/check",
        "query_string": b"",
        "headers": [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(payload)).encode()),
            (b"guard-context", signed().encode()),
        ],
        "server": ("test", 80),
        "client": ("test", 1),
        "scheme": "http",
    }
    handler = asyncio.ensure_future(app(scope, receive, send))
    await asyncio.wait_for(started.wait(), 5)
    await messages.put({"type": "http.disconnect"})  # the runtime stopped waiting
    await asyncio.wait_for(cancelled.wait(), 5)
    await asyncio.wait_for(handler, 5)


# ------------------------------------------------------------------------ headers


async def test_two_context_headers_are_malformed_whichever_order(client):
    for pair in ([signed(), "garbage"], ["garbage", signed()], [signed(), signed()]):
        r = await client.post(
            "/v1/check",
            content=body(),
            headers=httpx.Headers(
                [("Content-Type", "application/json"), *[("Guard-Context", v) for v in pair]]
            ),
        )
        assert r.status_code == 401 and r.json()["reason"] == "context_invalid"


@pytest.mark.parametrize("length", ["abc", "-5", "1.5", "", "\uff10\uff15"])
async def test_a_content_length_that_is_not_a_number_is_a_400(engine, length):
    app = create_check_app(engine)
    payload = body().encode()
    sent = []

    async def receive():
        return {"type": "http.request", "body": payload, "more_body": False}

    async def send(message):
        sent.append(message)

    scope = {
        "type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": "POST",
        "path": "/v1/check", "raw_path": b"/v1/check", "query_string": b"",
        "headers": [
            (b"content-type", b"application/json"),
            (b"content-length", length.encode("utf-8")),
            (b"guard-context", signed().encode()),
        ],
        "server": ("test", 80), "client": ("test", 1), "scheme": "http",
    }  # fmt: skip
    await app(scope, receive, send)
    assert sent[0]["status"] == 400


async def test_the_request_id_header_is_echoed_on_a_check_refused_before_its_body(client):
    r = await client.post(
        "/v1/check",
        content=b"not read",
        headers={"Content-Type": "application/json", "Guard-Request-Id": "req-42"},
    )
    assert r.status_code == 401 and r.json()["request_id"] == "req-42"


async def test_an_unusable_request_id_header_is_not_echoed(client):
    r = await client.post(
        "/v1/check",
        content=b"x",
        headers={"Content-Type": "application/json", "Guard-Request-Id": "x" * 300},
    )
    assert r.status_code == 401 and r.json()["request_id"] != "x" * 300


async def test_a_body_request_id_must_equal_the_header_when_there_is_one(client, engine):
    engine.model.set_noul(INJECTION, 0.01)
    same = await client.post(
        "/v1/check",
        content=body(request_id="req-1"),
        headers=headers(**{"Guard-Request-Id": "req-1"}),
    )
    assert same.status_code == 200 and same.json()["request_id"] == "req-1"
    for payload in (body(request_id="req-2"), body()):
        r = await client.post(
            "/v1/check", content=payload, headers=headers(**{"Guard-Request-Id": "req-1"})
        )
        assert (r.status_code, r.json()["error"]["code"]) == (400, "invalid_body")
    bad = await client.post(
        "/v1/check",
        content=body(request_id="x" * 300),
        headers=headers(**{"Guard-Request-Id": "x" * 300}),
    )
    assert bad.status_code == 400
    plain = await client.post("/v1/check", content=body(request_id="req-3"), headers=headers())
    assert plain.status_code == 200  # no header: the body's id, as before
