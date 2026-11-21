"""M1-10: warm connections in the Gemini adapter, against a local HTTP/1.1 test server on
real sockets (127.0.0.1 only). No network access to Google and no API key.

Idle gaps are scaled down: a test that stands for "30 s apart under a 60 s keepalive" sets a
short keepalive and a gap of the same proportion, and checks the expiry side too. One test
checks the real 60 s default with httpcore's clock shifted forward instead of sleeping.
"""

import asyncio
import json
import time
from contextlib import suppress
from pathlib import Path

import httpcore._async.http11 as httpcore_http11
import httpx
import pytest

from guardrail_engine.decision import (
    Answered,
    ChoiceQuestion,
    Failed,
    FailureKind,
    NoulCriteria,
    NoulQuestion,
    ScoreQuestion,
)
from guardrail_engine.decision.adapters.gemini import (
    DEFAULT_KEEPALIVE_EXPIRY_S,
    DEFAULT_MAX_IN_FLIGHT,
    CallInfo,
    ConnectionUse,
    GeminiConfig,
    GeminiDecisionModel,
)
from guardrail_engine.gateway import DecisionGateway, GatewayConfig

FIXTURES = Path(__file__).parents[1] / "fixtures" / "gemini"
FIXTURE = FIXTURES / "recorded_valid_noul_choice_score.json"
FAKE_KEY = "test-key-not-a-real-secret"
NEW, REUSED = ConnectionUse.NEW, ConnectionUse.REUSED

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


def _recorded_body() -> bytes:
    body = json.loads(FIXTURE.read_text())["body"]
    return body.encode() if isinstance(body, str) else json.dumps(body).encode()


class LocalServer:
    """A minimal keep-alive HTTP/1.1 server that answers every POST with the recorded 200.

    It counts the connections it accepts and the requests it reads, and can close its idle
    connections, drop a connection after reading a request, or hold responses until a
    number of requests are in (to make a burst really concurrent).
    """

    def __init__(self) -> None:
        self.body = _recorded_body()
        self.connections_opened = 0
        self.requests = 0
        self.drop_next_after_read = False
        self._open: set[asyncio.StreamWriter] = set()
        self._idle: set[asyncio.StreamWriter] = set()
        self._hold_for = 0
        self._held = 0
        self._release = asyncio.Event()
        self._hold_timeout_s = 2.0
        self._server: asyncio.Server | None = None
        self._handlers: set[asyncio.Task] = set()

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.port = self._server.sockets[0].getsockname()[1]

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.port}/v1beta"

    def hold_until(self, n: int, timeout_s: float = 2.0) -> None:
        """Hold each response until ``n`` requests have arrived (or ``timeout_s`` passes)."""
        self._hold_for, self._held, self._hold_timeout_s = n, 0, timeout_s
        self._release = asyncio.Event()

    async def close_idle_connections(self) -> None:
        for writer in list(self._idle):
            writer.close()
            with suppress(OSError):
                await writer.wait_closed()

    async def stop(self) -> None:
        assert self._server is not None
        self._server.close()
        self._release.set()
        for writer in list(self._open):
            writer.close()
        await asyncio.gather(*self._handlers, return_exceptions=True)
        await self._server.wait_closed()

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.connections_opened += 1
        self._open.add(writer)
        task = asyncio.current_task()
        assert task is not None
        self._handlers.add(task)
        try:
            while True:
                self._idle.add(writer)
                head = await reader.readuntil(b"\r\n\r\n")
                self._idle.discard(writer)
                length = 0
                for line in head.split(b"\r\n")[1:]:
                    name, _, value = line.partition(b":")
                    if name.strip().lower() == b"content-length":
                        length = int(value)
                await reader.readexactly(length)
                self.requests += 1
                if self.drop_next_after_read:
                    self.drop_next_after_read = False
                    return  # the whole request was read; close without a response
                if self._hold_for:
                    self._held += 1
                    if self._held >= self._hold_for:
                        self._release.set()
                    with suppress(TimeoutError):
                        await asyncio.wait_for(self._release.wait(), self._hold_timeout_s)
                writer.write(
                    b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n"
                    b"content-length: %d\r\n\r\n" % len(self.body) + self.body
                )
                await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError):
            pass  # the client (or close_idle_connections) closed the connection
        finally:
            self._idle.discard(writer)
            self._open.discard(writer)
            self._handlers.discard(task)
            writer.close()
            with suppress(OSError):
                await writer.wait_closed()


@pytest.fixture(autouse=True)
def _no_proxy(monkeypatch):
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.delenv("all_proxy", raising=False)


@pytest.fixture
async def server():
    srv = LocalServer()
    await srv.start()
    yield srv
    await srv.stop()


def model_for(server: LocalServer, infos: list[CallInfo], **config) -> GeminiDecisionModel:
    max_in_flight = config.pop("max_in_flight", DEFAULT_MAX_IN_FLIGHT)
    cfg = GeminiConfig(api_key=FAKE_KEY, paid_tier=True, base_url=server.base_url, **config)
    return GeminiDecisionModel(cfg, max_in_flight=max_in_flight, on_call=infos.append)


async def answered(model: GeminiDecisionModel) -> Answered:
    result = await model.decide("some content", QUESTIONS)
    assert isinstance(result, Answered), result
    return result


def connections(infos: list[CallInfo]) -> list[ConnectionUse | None]:
    return [info.connection for info in infos]


# ---------------------------------------------------------------------------- keepalive


class TestKeepalive:
    """Criterion: pooled connections stay open about 60 s idle (configurable)."""

    def test_defaults(self):
        assert DEFAULT_KEEPALIVE_EXPIRY_S == 60.0
        assert GeminiConfig(api_key=FAKE_KEY).keepalive_expiry_s == 60.0
        assert DEFAULT_MAX_IN_FLIGHT >= 2  # at least M1-04's default in-flight limit

    async def test_two_calls_a_half_keepalive_apart_reuse_one_connection(self, server):
        # "30 s apart under a 60 s keepalive", scaled to 0.3 s under 0.6 s.
        infos: list[CallInfo] = []
        async with model_for(server, infos, keepalive_expiry_s=0.6) as model:
            await answered(model)
            await asyncio.sleep(0.3)
            await answered(model)
        assert server.connections_opened == 1
        assert connections(infos) == [NEW, REUSED]

    async def test_a_call_after_the_keepalive_opens_a_new_connection(self, server):
        infos: list[CallInfo] = []
        async with model_for(server, infos, keepalive_expiry_s=0.6) as model:
            await answered(model)
            await asyncio.sleep(1.2)
            await answered(model)
        assert server.connections_opened == 2
        assert connections(infos) == [NEW, NEW]

    async def test_default_keepalive_reuses_after_30s_and_expires_after_60s(
        self, server, monkeypatch
    ):
        """The real default, with httpcore's keepalive clock shifted instead of sleeping.
        Tied to httpcore 1.0's module layout: if that moves, this fails at setattr."""
        shift = {"s": 0.0}

        class ShiftedTime:
            @staticmethod
            def monotonic() -> float:
                return time.monotonic() + shift["s"]

        monkeypatch.setattr(httpcore_http11, "time", ShiftedTime)
        infos: list[CallInfo] = []
        async with model_for(server, infos) as model:
            await answered(model)
            shift["s"] += 30.0  # idle 30 s: httpx's own 5 s keepalive would have closed it
            await answered(model)
            shift["s"] += 61.0  # idle 61 s: past the 60 s keepalive
            await answered(model)
        assert connections(infos) == [NEW, REUSED, NEW]
        assert server.connections_opened == 2


# ---------------------------------------------------------------------------- burst


class TestBurst:
    """Criterion: the pool keeps at least the in-flight limit's worth of connections, so a
    burst up to the limit opens no more connections than the limit, and a later burst
    opens none."""

    @pytest.mark.parametrize("limit", [DEFAULT_MAX_IN_FLIGHT, 32])
    async def test_bursts_up_to_the_limit_open_at_most_the_limit(self, server, limit):
        infos: list[CallInfo] = []
        async with model_for(server, infos, max_in_flight=limit) as model:
            server.hold_until(limit)  # every call is in flight at once
            await asyncio.gather(*(answered(model) for _ in range(limit)))
            assert server.connections_opened == limit
            assert connections(infos) == [NEW] * limit

            await asyncio.sleep(0.1)
            infos.clear()
            server.hold_until(limit)
            await asyncio.gather(*(answered(model) for _ in range(limit)))
        assert server.connections_opened == limit  # the second burst opened none
        assert connections(infos) == [REUSED] * limit
        assert server.requests == 2 * limit


# ---------------------------------------------------------------------------- no keep-warm


async def test_no_synthetic_keep_warm_requests(server):
    """Criterion: connections are kept at the transport level only. Idle time, including
    past the keepalive, sends nothing and opens nothing."""
    infos: list[CallInfo] = []
    async with model_for(server, infos, keepalive_expiry_s=0.2) as model:
        await answered(model)
        await asyncio.sleep(0.7)
        assert server.requests == 1
        assert server.connections_opened == 1
    assert server.requests == 1
    assert len(infos) == 1


# ---------------------------------------------------------------------------- stale connections


class TestStaleConnection:
    """Criterion: a pooled connection the server closed before the request is sent is
    replaced on a new connection, inside the call; once the request may have been sent,
    the normal failure mapping applies."""

    async def test_server_closed_idle_connection_is_replaced_transparently(self, server):
        infos: list[CallInfo] = []
        async with model_for(server, infos) as model:
            await answered(model)
            await server.close_idle_connections()
            await asyncio.sleep(0.1)  # let the FIN reach the client's socket
            await answered(model)
        assert server.connections_opened == 2
        assert server.requests == 2  # nothing was sent on the closed connection
        assert connections(infos) == [NEW, NEW]

    async def test_replacement_is_not_a_gateway_retry_and_fits_the_budget(self, server):
        infos: list[CallInfo] = []
        async with (
            model_for(server, infos) as model,
            DecisionGateway(model, config=GatewayConfig(default_budget_s=2.0)) as gateway,
        ):

            async def check():
                return await gateway.decide(
                    tenant_id="t_1", guard_point="output", input="x", questions=QUESTIONS
                )

            assert isinstance(await check(), Answered)
            await server.close_idle_connections()
            await asyncio.sleep(0.1)
            assert isinstance(await check(), Answered)
        assert server.requests == 2  # one request per check: the gateway didn't retry
        assert connections(infos) == [NEW, NEW]

    async def test_request_that_may_have_been_sent_is_not_resent(self, server):
        infos: list[CallInfo] = []
        async with model_for(server, infos) as model:
            await answered(model)
            server.drop_next_after_read = True  # reads the request, then closes
            result = await model.decide("some content", QUESTIONS)
        assert isinstance(result, Failed)
        assert result.kind is FailureKind.UNAVAILABLE
        assert "RemoteProtocolError" in result.message or "ReadError" in result.message
        assert server.requests == 2  # the adapter did not send it a second time
        assert connections(infos) == [NEW, REUSED]


# ---------------------------------------------------------------------------- metering


class TestMetering:
    """Criterion: each call records whether its connection was reused or new."""

    async def test_each_call_reports_new_or_reused(self, server):
        infos: list[CallInfo] = []
        async with model_for(server, infos) as model:
            for _ in range(3):
                await answered(model)
        assert infos == [CallInfo(NEW), CallInfo(REUSED), CallInfo(REUSED)]

    async def test_cancelled_call_is_reported(self, server):
        infos: list[CallInfo] = []
        async with model_for(server, infos) as model:
            server.hold_until(2, timeout_s=0.5)  # the one call is held
            with pytest.raises(TimeoutError):
                async with asyncio.timeout(0.1):
                    await model.decide("some content", QUESTIONS)
        assert connections(infos) == [NEW]

    async def test_failed_call_is_reported(self, server):
        infos: list[CallInfo] = []
        server.drop_next_after_read = True
        async with model_for(server, infos) as model:
            result = await model.decide("some content", QUESTIONS)
        assert isinstance(result, Failed)
        assert connections(infos) == [NEW]

    async def test_a_hook_that_raises_does_not_change_the_result(self, server, caplog):
        def hook(info: CallInfo) -> None:
            raise RuntimeError("metering is down")

        cfg = GeminiConfig(api_key=FAKE_KEY, paid_tier=True, base_url=server.base_url)
        async with GeminiDecisionModel(cfg, on_call=hook) as model:
            await answered(model)
        assert "on_call hook failed" in caplog.text
        assert FAKE_KEY not in caplog.text

    async def test_an_async_hook_is_closed_not_run(self, server, caplog):
        ran = []

        async def hook(info: CallInfo) -> None:
            ran.append(info)

        cfg = GeminiConfig(api_key=FAKE_KEY, paid_tier=True, base_url=server.base_url)
        async with GeminiDecisionModel(cfg, on_call=hook) as model:
            await answered(model)
        assert ran == []
        assert "must be synchronous" in caplog.text

    async def test_no_report_when_no_http_call_is_made(self, server):
        infos: list[CallInfo] = []
        async with model_for(server, infos) as model:
            await model.decide("x", {"bad key": NoulQuestion(instructions="Is it?")})
            await model.decide("bad \ud800", QUESTIONS)
        assert infos == []
        assert server.connections_opened == 0

    async def test_injected_client_without_trace_events_reports_none(self):
        infos: list[CallInfo] = []
        status, body = 200, _recorded_body()
        client = httpx.AsyncClient(
            transport=httpx.MockTransport(lambda r: httpx.Response(status, content=body))
        )
        cfg = GeminiConfig(api_key=FAKE_KEY, paid_tier=True)
        async with client, GeminiDecisionModel(cfg, client=client, on_call=infos.append) as m:
            await answered(m)
        assert infos == [CallInfo(None)]


# ---------------------------------------------------------------------------- configuration


class TestConfiguration:
    @pytest.mark.parametrize("value", [0, -1, 1.5, True, "8"])
    def test_max_in_flight_must_be_a_whole_number_of_at_least_one(self, value):
        with pytest.raises(ValueError, match="max_in_flight"):
            GeminiDecisionModel(GeminiConfig(api_key=FAKE_KEY, paid_tier=True), max_in_flight=value)

    @pytest.mark.parametrize("value", [0.0, -1.0, float("nan")])
    def test_keepalive_must_be_positive(self, value):
        with pytest.raises(ValueError, match="keepalive_expiry_s"):
            GeminiDecisionModel(
                GeminiConfig(api_key=FAKE_KEY, paid_tier=True, keepalive_expiry_s=value)
            )


# ---------------------------------------------------------------------------- diagnostics


class RawServer:
    """One request per connection, answered by ``behaviour(writer)``: to make a response
    carry ``Connection: close``, never come, or be a dropped connection (M0-02 diagnostics)."""

    def __init__(self) -> None:
        self.behaviour = self.ok
        self._server: asyncio.Server | None = None
        self._tasks: set[asyncio.Task] = set()

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.base_url = f"http://127.0.0.1:{self._server.sockets[0].getsockname()[1]}/v1beta"

    async def stop(self) -> None:
        assert self._server is not None
        self._server.close()
        for task in list(self._tasks):
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        await self._server.wait_closed()

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        task = asyncio.current_task()
        assert task is not None
        self._tasks.add(task)
        try:
            head = await reader.readuntil(b"\r\n\r\n")
            length = next(
                (int(line.split(b":")[1]) for line in head.split(b"\r\n")
                 if line.lower().startswith(b"content-length")),
                0,
            )  # fmt: skip
            await reader.readexactly(length)
            await self.behaviour(writer)
        except (asyncio.IncompleteReadError, ConnectionError, asyncio.CancelledError):
            pass
        finally:
            self._tasks.discard(task)
            writer.close()
            with suppress(OSError, asyncio.CancelledError):
                await writer.wait_closed()

    @staticmethod
    def response(body: bytes, *extra: bytes) -> bytes:
        return (b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n" + b"".join(extra)
                + b"content-length: %d\r\n\r\n" % len(body) + body)  # fmt: skip

    async def ok(self, writer: asyncio.StreamWriter) -> None:
        writer.write(self.response(_recorded_body()))
        await writer.drain()

    async def close_header(self, writer: asyncio.StreamWriter) -> None:
        writer.write(self.response(_recorded_body(), b"connection: close\r\n"))
        await writer.drain()

    async def drop(self, writer: asyncio.StreamWriter) -> None:
        return None  # read the request, then close without a response

    async def slow(self, writer: asyncio.StreamWriter) -> None:
        await asyncio.sleep(5)


@pytest.fixture
async def raw():
    srv = RawServer()
    await srv.start()
    yield srv
    await srv.stop()


def raw_model(srv: RawServer, infos: list[CallInfo], **config) -> GeminiDecisionModel:
    cfg = GeminiConfig(api_key=FAKE_KEY, paid_tier=True, base_url=srv.base_url, **config)
    return GeminiDecisionModel(cfg, on_call=infos.append)


class TestDiagnostics:
    """What a call tells about its connection (M0-02, after the R7.4 run's timeout bursts):
    new or reused, how long each step took, the HTTP version, whether the server said it was
    closing, how a failure happened, and a rough connection age."""

    async def test_a_new_then_a_reused_connection(self, server):
        infos: list[CallInfo] = []
        async with model_for(server, infos) as model:
            await answered(model)
            await asyncio.sleep(0.05)
            await answered(model)
        first, second = infos
        assert (first.seq, second.seq) == (1, 2)
        assert first.connection is NEW and first.connect_ms is not None
        assert first.tls_ms is None  # plain http on loopback
        assert first.to_send_ms >= first.connect_ms  # the connect is part of getting to send
        assert first.send_ms is not None and first.ttfb_ms is not None
        assert first.http_version == "HTTP/1.1" and first.server_closes is False
        assert first.ended == "response" and first.failure is None and first.idle_s is None
        assert first.total_ms >= first.ttfb_ms
        assert second.connection is REUSED and second.connect_ms is None
        assert second.idle_s >= 0.05  # the gap since the first call ended
        assert second.connection_age_s >= 0.05  # counted from when that connection opened
        assert second.started_at > first.started_at  # ISO 8601, so it sorts

    async def test_a_response_that_says_connection_close_is_noted_and_the_next_call_is_new(
        self, raw
    ):
        infos: list[CallInfo] = []
        raw.behaviour = raw.close_header
        async with raw_model(raw, infos) as model:
            await answered(model)
            await answered(model)
        first, second = infos
        assert first.server_closes is True
        assert (first.connection, second.connection) == (NEW, NEW)

    async def test_a_dropped_connection_names_the_failed_step_and_the_exception_class(self, raw):
        infos: list[CallInfo] = []
        raw.behaviour = raw.drop
        async with raw_model(raw, infos) as model:
            result = await model.decide("some content", QUESTIONS)
        assert isinstance(result, Failed) and result.kind is FailureKind.UNAVAILABLE
        [info] = infos
        assert info.ended == "transport_error"
        assert info.failure == "http11.receive_response_headers.failed:RemoteProtocolError"
        assert info.http_version is None and info.ttfb_ms is None  # no response head came
        assert info.connection is NEW

    async def test_a_failed_call_closes_its_connection_so_the_next_one_is_new(self, raw):
        infos: list[CallInfo] = []
        raw.behaviour = raw.drop
        async with raw_model(raw, infos) as model:
            await model.decide("some content", QUESTIONS)
            raw.behaviour = raw.ok
            await answered(model)
        failed, next_call = infos
        assert failed.failure is not None
        assert next_call.connection is NEW and next_call.failure is None
        assert next_call.connection_age_s < 1  # its own connection's age, not the old one's

    async def test_a_transport_timeout_ends_as_timeout(self, raw):
        infos: list[CallInfo] = []
        raw.behaviour = raw.slow
        async with raw_model(raw, infos, transport_timeout_s=0.2) as model:
            result = await model.decide("some content", QUESTIONS)
        assert isinstance(result, Failed) and result.kind is FailureKind.TIMEOUT
        [info] = infos
        assert info.ended == "timeout"
        assert info.failure == "http11.receive_response_headers.failed:ReadTimeout"
        assert info.ttfb_ms is None and info.total_ms >= 150

    async def test_a_call_cancelled_by_the_gateways_deadline_ends_as_cancelled(self, raw):
        infos: list[CallInfo] = []
        raw.behaviour = raw.slow
        async with raw_model(raw, infos) as model:
            with pytest.raises(TimeoutError):
                await asyncio.wait_for(model.decide("some content", QUESTIONS), 0.2)
        [info] = infos
        assert info.ended == "cancelled" and info.connection is NEW
        assert info.failure is not None and info.failure.endswith(":CancelledError")
        assert info.send_ms is not None  # the request was sent; the wait for the answer was cut

    async def test_no_diagnostic_holds_the_key_a_header_or_a_url(self, server):
        infos: list[CallInfo] = []
        async with model_for(server, infos) as model:
            await answered(model)
            await answered(model)
        text = json.dumps([info.diagnostics() for info in infos])  # JSON-safe, by construction
        for forbidden in (FAKE_KEY, "x-goog-api-key", "127.0.0.1", "/decisions", "content-type"):
            assert forbidden.lower() not in text.lower(), forbidden
        assert set(infos[0].diagnostics()) <= {
            "seq", "started_at", "ended", "connection", "total_ms", "to_send_ms", "connect_ms",
            "tls_ms", "send_ms", "ttfb_ms", "http_version", "server_closes", "failure",
            "connection_age_s", "idle_s",
        }  # fmt: skip

    async def test_the_tracer_never_keeps_anything_from_the_request(self):
        from guardrail_engine.decision.adapters.gemini import _ConnectionTracer

        class Request:
            def __repr__(self) -> str:
                return "REQUEST-WITH-SECRET-HEADER"

        tracer = _ConnectionTracer()
        request = Request()
        for event in (
            "connection.connect_tcp.started", "connection.connect_tcp.complete",
            "http11.send_request_headers.started", "http11.send_request_headers.complete",
            "http11.send_request_body.complete", "http11.receive_response_headers.started",
        ):  # fmt: skip
            await tracer(event, {"request": request, "host": "h", "return_value": None})
        head = (b"HTTP/1.1", 200, b"OK", [(b"Connection", b"keep-alive"), (b"x", b"y")])
        await tracer("http11.receive_response_headers.complete", {"return_value": head})
        await tracer("http11.response_closed.failed", {"request": request, "exception": OSError()})
        assert "SECRET" not in repr(vars(tracer))
        assert tracer.http_version == "HTTP/1.1" and tracer.server_closes is False
        assert tracer.failure == "http11.response_closed.failed:OSError"

    async def test_a_malformed_response_head_never_breaks_a_call(self):
        from guardrail_engine.decision.adapters.gemini import _ConnectionTracer

        tracer = _ConnectionTracer()
        await tracer("http11.receive_response_headers.complete", {"return_value": "garbage"})
        assert tracer.http_version is None and tracer.server_closes is None

    def test_the_diagnostics_do_not_take_part_in_equality(self):
        assert CallInfo(NEW) == CallInfo(NEW, connect_ms=3.0, ended="response", seq=9)
        assert CallInfo(NEW) != CallInfo(REUSED, connect_ms=3.0)
        assert CallInfo(NEW, connect_ms=1.5, failure=None).diagnostics() == {
            "connection": "new", "connect_ms": 1.5,
        }  # fmt: skip
