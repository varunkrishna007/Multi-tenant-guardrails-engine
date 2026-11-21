"""M4-04: the HTTP webhook alert sink, against a local server on 127.0.0.1 (no real network)."""

import hashlib
import hmac
import json
import logging
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from guardrail_engine.delivery import DeliveryError
from guardrail_engine.delivery.adapters.webhook import (
    HEADER_KEY,
    HEADER_SIGNATURE,
    HEADER_TIMESTAMP,
    WebhookAlertSink,
    sign,
)
from guardrail_engine.gateway import Alert, AlertSeverity

SECRET = "s3cr3t-signing-key-0123456789"
PATH_TOKEN = "T0K3N-IN-THE-URL"


class Receiver:
    def __init__(self) -> None:
        self.requests: list[dict] = []
        self.status = 200
        self.delay_s = 0.0
        self.location: str | None = None
        receiver = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers["Content-Length"]))
                receiver.requests.append(
                    {"path": self.path, "headers": dict(self.headers), "body": body}
                )
                if receiver.delay_s:
                    time.sleep(receiver.delay_s)
                self.send_response(receiver.status)
                if receiver.location:
                    self.send_header("Location", receiver.location)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.thread = threading.Thread(
            target=self.server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True
        )
        self.thread.start()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.server.server_address[1]}/hook/{PATH_TOKEN}"

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(3)


@pytest.fixture
def receiver():
    r = Receiver()
    yield r
    r.close()


def alert(**kw) -> Alert:
    fields = dict(
        severity=AlertSeverity.PAGE,
        kind="bad_publish_block_rate",
        message="policy block rate is high",
        key_id="",
        tenant_id="t_a",
        guard_point="",
        reason="policy",
        rollback="/v1/tenants/t_a/guardrails/versions/1/rollback",
    )
    fields.update(kw)
    return Alert(**fields)


def test_the_body_is_json_and_signed_with_hmac_sha256_over_timestamp_and_body(receiver):
    sink = WebhookAlertSink(receiver.url, SECRET, clock=lambda: 1_700_000_000.9)
    sink.deliver(alert(), "event-key-1")
    [req] = receiver.requests
    assert req["path"] == f"/hook/{PATH_TOKEN}"
    h = req["headers"]
    assert h[HEADER_KEY] == "event-key-1"
    assert h[HEADER_TIMESTAMP] == "1700000000"
    expected = hmac.new(SECRET.encode(), b"1700000000." + req["body"], hashlib.sha256).hexdigest()
    assert h[HEADER_SIGNATURE] == f"v1={expected}"
    assert h["Content-Type"] == "application/json"
    body = json.loads(req["body"])
    assert body["id"] == "event-key-1" and body["type"] == "alert"
    assert body["alert"]["kind"] == "bad_publish_block_rate"
    assert body["alert"]["severity"] == "page"
    assert body["alert"]["rollback"] == "/v1/tenants/t_a/guardrails/versions/1/rollback"
    assert SECRET not in req["body"].decode()


def test_a_receiver_can_verify_and_a_tampered_body_fails(receiver):
    WebhookAlertSink(receiver.url, SECRET).deliver(alert(), "k")
    [req] = receiver.requests
    ts = req["headers"][HEADER_TIMESTAMP]
    assert hmac.compare_digest(
        sign(SECRET.encode(), ts, req["body"]), req["headers"][HEADER_SIGNATURE]
    )
    tampered = req["body"].replace(b"t_a", b"t_b")
    assert sign(SECRET.encode(), ts, tampered) != req["headers"][HEADER_SIGNATURE]
    assert sign(b"another-secret-0123456789", ts, req["body"]) != req["headers"][HEADER_SIGNATURE]


def test_emit_is_the_plain_port_and_sends_a_fresh_key_each_time(receiver):
    sink = WebhookAlertSink(receiver.url, SECRET)
    sink.emit(alert())
    sink.emit(alert())
    keys = {r["headers"][HEADER_KEY] for r in receiver.requests}
    assert len(keys) == 2


@pytest.mark.parametrize("status", [400, 429, 500, 503])
def test_a_non_2xx_is_a_coded_failure(receiver, status):
    receiver.status = status
    with pytest.raises(DeliveryError) as info:
        WebhookAlertSink(receiver.url, SECRET).deliver(alert(), "k")
    assert info.value.code == f"http_{status}"


def test_a_slow_receiver_times_out_within_the_timeout(receiver):
    receiver.delay_s = 3.0
    sink = WebhookAlertSink(receiver.url, SECRET, timeout_s=0.3)
    start = time.monotonic()
    with pytest.raises(DeliveryError) as info:
        sink.deliver(alert(), "k")
    assert info.value.code == "timeout"
    assert time.monotonic() - start < 2.0


def test_a_refused_connection_is_a_coded_failure():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]  # closed again at the end of the block: nothing listens
    with pytest.raises(DeliveryError) as info:
        WebhookAlertSink(f"http://127.0.0.1:{port}/x", SECRET).deliver(alert(), "k")
    assert info.value.code == "connection_failed"


def test_redirects_are_not_followed(receiver):
    other = Receiver()
    try:
        receiver.status = 302
        receiver.location = other.url
        with pytest.raises(DeliveryError) as info:
            WebhookAlertSink(receiver.url, SECRET).deliver(alert(), "k")
        assert info.value.code == "http_302"
        assert other.requests == []  # the signed body never went there
    finally:
        other.close()


def test_proxy_environment_variables_are_ignored(receiver, monkeypatch):
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:9")
    monkeypatch.setenv("http_proxy", "http://127.0.0.1:9")
    WebhookAlertSink(receiver.url, SECRET).deliver(alert(), "k")
    assert len(receiver.requests) == 1


def test_no_secret_or_url_in_errors_reprs_or_logs(receiver, caplog):
    receiver.status = 500
    sink = WebhookAlertSink(receiver.url, SECRET)
    with caplog.at_level(logging.DEBUG), pytest.raises(DeliveryError) as info:
        sink.deliver(alert(), "k")
    shown = " ".join([str(info.value), repr(info.value), repr(sink), str(sink), caplog.text])
    assert SECRET not in shown and PATH_TOKEN not in shown and "127.0.0.1" not in shown
    assert info.value.__cause__ is None  # no chained exception carrying the request


def test_no_secret_in_the_log_when_the_dispatcher_retries(receiver, caplog):
    from guardrail_engine.delivery import InMemoryOutbox, OutboxDispatcher
    from guardrail_engine.delivery.events import KIND_ALERT, encode_alert

    receiver.status = 503
    outbox = InMemoryOutbox()
    outbox.enqueue(KIND_ALERT, encode_alert(alert()), "k", 0.0)
    d = OutboxDispatcher(outbox, alerts=WebhookAlertSink(receiver.url, SECRET), clock=lambda: 1.0)
    with caplog.at_level(logging.DEBUG):
        d.run_once()
    assert "http_503" in caplog.text
    assert SECRET not in caplog.text and PATH_TOKEN not in caplog.text
    assert outbox.last_error(1) == "http_503"


class TestUrlAndSecretRules:
    def test_https_is_accepted(self):
        WebhookAlertSink("https://hooks.example.com/x", SECRET)

    @pytest.mark.parametrize(
        "url",
        [
            "http://hooks.example.com/x",  # plain http off the machine
            "http://10.0.0.5/x",
            "ftp://example.com/x",
            "https://user:pw@hooks.example.com/x",  # credentials in the url
            "https:///nohost",
            "not a url",
        ],
    )
    def test_bad_urls_are_refused(self, url):
        with pytest.raises(ValueError):
            WebhookAlertSink(url, SECRET)

    @pytest.mark.parametrize(
        "url", ["http://127.0.0.1:9/x", "http://localhost/x", "http://[::1]/x"]
    )
    def test_plain_http_is_only_for_loopback(self, url):
        WebhookAlertSink(url, SECRET)

    def test_a_short_secret_is_refused_and_not_echoed(self):
        with pytest.raises(ValueError) as info:
            WebhookAlertSink("https://hooks.example.com/x", "short")
        assert "short" not in str(info.value).replace("at least", "")

    def test_a_non_positive_timeout_is_refused(self):
        with pytest.raises(ValueError):
            WebhookAlertSink("https://hooks.example.com/x", SECRET, timeout_s=0)
