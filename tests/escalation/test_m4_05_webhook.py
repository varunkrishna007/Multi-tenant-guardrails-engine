"""M4-05: the escalation webhook: signed POST, retries and the dead-letter state through the M4-04
outbox. A local server on 127.0.0.1 only; no real network."""

import json
import logging
import threading
import time
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from esc_fixtures import ALPHA, BETA, NOW, Sink, doc

from guardrail_engine.delivery import (
    DeliveryError,
    InMemoryOutbox,
    OutboxDispatcher,
    RetryPolicy,
)
from guardrail_engine.delivery.adapters.webhook import (
    HEADER_KEY,
    HEADER_SIGNATURE,
    HEADER_TIMESTAMP,
    sign,
)
from guardrail_engine.delivery.events import (
    KIND_ESCALATION,
    EscalationNotice,
    encode_escalation,
)
from guardrail_engine.escalation import (
    EscalationItem,
    EscalationRequest,
    EscalationRouter,
    InMemoryEscalationStore,
)
from guardrail_engine.escalation.adapters.webhook import (
    EscalationWebhookSink,
    StaticWebhookSecrets,
)
from guardrail_engine.monitoring.dropped import DeadLetteredEventsWatch
from guardrail_engine.tenant_scope import issue_scope

SECRET = "alpha-signing-secret-0123456789"
BETA_SECRET = "beta-signing-secret-9876543210"
PATH_TOKEN = "T0K3N-IN-THE-URL"


class Receiver:
    def __init__(self) -> None:
        self.requests: list[dict] = []
        self.status = 200
        receiver = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers["Content-Length"]))
                receiver.requests.append(
                    {"path": self.path, "headers": dict(self.headers), "body": body}
                )
                self.send_response(receiver.status)
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


class Clock:
    def __init__(self, now=1_000_000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


def notice(url: str, tenant: str = ALPHA, **kw) -> EscalationNotice:
    fields = dict(
        item_id="esc_" + "ab" * 12,
        tenant_id=tenant,
        guard_point="output",
        reason="policy",
        created_at=1_000_000.0,
        url=url,
        content_sha256="sha256:" + "c" * 64,
        bundle_version=3,
        rules=(("t__x", "escalate", "enforce"),),
        content_available=False,
    )
    fields.update(kw)
    return EscalationNotice(**fields)


def sink(clock=None, **kw) -> EscalationWebhookSink:
    """A sink that may reach the 127.0.0.1 test servers (the test-only allowance); the
    host rules themselves are tested in test_webhook_hosts.py with it off."""
    secrets = StaticWebhookSecrets({ALPHA: SECRET, BETA: BETA_SECRET})
    kw.setdefault("allow_non_global_hosts_for_tests", True)
    return EscalationWebhookSink(secrets, clock=clock or Clock(), **kw)


# --- the request


def test_the_post_is_signed_with_the_m4_04_scheme_and_carries_the_idempotency_key(receiver):
    sink().deliver(notice(receiver.url), "key-1")
    [req] = receiver.requests
    h = req["headers"]
    assert h[HEADER_KEY] == "key-1"
    assert h[HEADER_SIGNATURE] == sign(SECRET.encode(), h[HEADER_TIMESTAMP], req["body"])
    assert h[HEADER_SIGNATURE].startswith("v1=")
    body = json.loads(req["body"])
    assert (body["id"], body["type"]) == ("key-1", "escalation")
    esc = body["escalation"]
    assert esc["id"] == "esc_" + "ab" * 12 and esc["tenant_id"] == ALPHA
    assert esc["rules"] == [{"key": "t__x", "action": "escalate", "mode": "enforce"}]
    assert esc["resolve"] == {
        "method": "POST",
        "path": f"/v1/tenants/{ALPHA}/guardrails/escalations/{esc['id']}/resolve",
    }
    assert esc["content_sha256"] == "sha256:" + "c" * 64


def test_the_body_has_no_content_and_no_probability_key(receiver):
    sink().deliver(notice(receiver.url, content_available=True), "key-2")
    body = json.loads(receiver.requests[0]["body"])

    def keys(x):
        if isinstance(x, dict):
            for k, v in x.items():
                yield k
                yield from keys(v)
        elif isinstance(x, list):
            for v in x:
                yield from keys(v)

    assert not {"content", "p", "probability", "probabilities", "text"} & set(keys(body))
    assert body["escalation"]["content_available"] is True  # fetch it through the API


def test_each_tenant_is_signed_with_its_own_secret(receiver):
    sink().deliver(notice(receiver.url, tenant=ALPHA), "k-a")
    sink().deliver(notice(receiver.url, tenant=BETA), "k-b")
    a, b = receiver.requests
    assert a["headers"][HEADER_SIGNATURE] == sign(
        SECRET.encode(), a["headers"][HEADER_TIMESTAMP], a["body"]
    )
    assert b["headers"][HEADER_SIGNATURE] == sign(
        BETA_SECRET.encode(), b["headers"][HEADER_TIMESTAMP], b["body"]
    )
    assert a["headers"][HEADER_SIGNATURE] != b["headers"][HEADER_SIGNATURE]


def test_a_tenant_with_no_secret_or_a_bad_url_sends_nothing(receiver, caplog):
    caplog.set_level(logging.DEBUG)
    with pytest.raises(DeliveryError) as no_secret:
        sink().deliver(notice(receiver.url, tenant="t_nosecret"), "k")
    assert no_secret.value.code == "no_secret"
    strict = sink(allow_non_global_hosts_for_tests=False)
    with pytest.raises(DeliveryError) as bad:
        strict.deliver(notice("http://example.com/hook"), "k")  # plain http
    assert bad.value.code == "bad_url"
    with pytest.raises(DeliveryError):
        strict.deliver(notice("https://user:pw@example.com/hook"), "k")
    assert receiver.requests == []


def test_a_failure_is_a_short_code_and_never_leaks_the_url_or_the_secret(receiver, caplog):
    caplog.set_level(logging.DEBUG)
    receiver.status = 503
    s = sink()
    with pytest.raises(DeliveryError) as exc:
        s.deliver(notice(receiver.url), "k")
    assert exc.value.code == "http_503"
    for text in (str(exc.value), repr(exc.value), repr(s), caplog.text):
        assert PATH_TOKEN not in text and SECRET not in text
    with pytest.raises(DeliveryError) as down:
        sink().deliver(notice("http://127.0.0.1:1/hook"), "k")  # nothing listens there
    assert down.value.code == "connection_failed"


# --- retry and dead letter


def dispatcher(outbox, clock, receiver_sink, **kw) -> OutboxDispatcher:
    return OutboxDispatcher(
        outbox, escalations=receiver_sink, clock=clock, rng=lambda: 0.0, lease_s=60.0, **kw
    )


def test_a_failing_receiver_is_retried_with_the_same_key_then_delivered(receiver):
    clock, outbox = Clock(), InMemoryOutbox()
    outbox.enqueue(KIND_ESCALATION, encode_escalation(notice(receiver.url)), "esc_key", clock())
    d = dispatcher(outbox, clock, sink(clock))
    receiver.status = 500
    assert d.run_once() == 1
    assert (d.stats.retried, d.stats.delivered) == (1, 0)
    assert d.run_once() == 0  # backing off: not due yet
    clock.now += 2.0  # base 2 s
    assert d.run_once() == 1 and d.stats.retried == 2
    receiver.status = 200
    clock.now += 4.0
    assert d.run_once() == 1
    assert (d.stats.delivered, d.stats.dead) == (1, 0)
    assert len(receiver.requests) == 3
    assert {r["headers"][HEADER_KEY] for r in receiver.requests} == {"esc_key"}  # one key
    assert outbox.stats().delivered == 1


def test_after_the_attempts_run_out_the_notice_is_dead_lettered_and_raised(receiver, caplog):
    clock, outbox = Clock(), InMemoryOutbox()
    outbox.enqueue(KIND_ESCALATION, encode_escalation(notice(receiver.url)), "esc_key", clock())
    receiver.status = 502
    d = dispatcher(outbox, clock, sink(clock), escalation_retry=RetryPolicy(max_attempts=3))
    alerts = Sink()
    watch = DeadLetteredEventsWatch(lambda: d.stats.dead, alerts, clock=clock)
    with caplog.at_level(logging.ERROR):
        for _ in range(3):
            d.run_once()
            clock.now += 400.0
    assert (d.stats.dead, d.stats.dead_escalations, d.stats.retried) == (1, 1, 2)
    assert outbox.stats().dead == 1 and outbox.stats().pending == 0
    assert outbox.last_error(1) == "http_502"
    assert any("dead-lettered" in r.getMessage() for r in caplog.records)
    watch.tick()
    [alert] = alerts.alerts
    assert alert.kind == "events_dead_lettered"
    before = len(receiver.requests)
    clock.now += 3600.0
    assert d.run_once() == 0 and len(receiver.requests) == before  # not tried again
    # an operator can put it back
    receiver.status = 200
    assert outbox.requeue_dead(clock()) == 1
    assert d.run_once() == 1 and d.stats.delivered == 1


def test_the_default_policy_keeps_retrying_for_a_day_before_dead_lettering(receiver):
    clock, outbox = Clock(), InMemoryOutbox()
    outbox.enqueue(KIND_ESCALATION, encode_escalation(notice(receiver.url)), "esc_key", clock())
    receiver.status = 500
    d = dispatcher(outbox, clock, sink(clock))
    for _ in range(40):  # a bit over three hours of five-minute retries
        d.run_once()
        clock.now += 300.0
    assert d.stats.dead == 0 and outbox.stats().pending == 1
    clock.now += 24 * 3600.0
    d.run_once()
    assert d.stats.dead_escalations == 1


def test_a_notice_nobody_can_decode_is_dead_at_once(receiver):
    clock, outbox = Clock(), InMemoryOutbox()
    outbox.enqueue(KIND_ESCALATION, "{not json", "esc_bad", clock())
    d = dispatcher(outbox, clock, sink(clock))
    d.run_once()
    assert outbox.stats().dead == 1 and receiver.requests == []


def test_without_an_escalation_sink_the_events_are_left_in_the_outbox(receiver):
    clock, outbox = Clock(), InMemoryOutbox()
    outbox.enqueue(KIND_ESCALATION, encode_escalation(notice(receiver.url)), "esc_key", clock())
    d = OutboxDispatcher(outbox, alerts=Sink(), clock=clock)
    assert d.run_once() == 0 and outbox.stats().pending == 1


# --- end to end


async def test_a_routed_escalation_reaches_the_receiver_signed_and_only_once(receiver):
    """Router -> store + outbox -> dispatcher -> a signed POST; a duplicate submit adds none."""
    items, outbox, clock = InMemoryEscalationStore(), InMemoryOutbox(), Clock()
    router = EscalationRouter(items, outbox=outbox)
    item = EscalationItem(
        id="esc_" + "12" * 12,
        tenant_id=ALPHA,
        request_id="r1",
        guard_point="output",
        created_at=datetime(2026, 11, 20, tzinfo=UTC),
        target="webhook",
        reason="policy",
        bundle_version=2,
        rules=(),
        content_sha256="sha256:" + "d" * 64,
        store_content="hash_only",
    )
    request = EscalationRequest(scope=issue_scope(ALPHA), item=item, url=receiver.url)
    assert router.submit(request) and await router.drain(2.0)
    assert router.submit(request) and await router.drain(2.0)  # the same check again
    await router.aclose(1.0)
    assert outbox.stats().pending == 1  # one event: the item id is the idempotency key
    d = dispatcher(outbox, clock, sink(clock))
    clock.now = time.time() + 5  # the outbox stamped the real time
    assert d.run_once() == 1 and d.stats.delivered == 1
    [req] = receiver.requests
    assert req["headers"][HEADER_KEY] == item.id
    assert json.loads(req["body"])["escalation"]["id"] == item.id
    assert len(items.items(ALPHA)) == 1  # and the item waits in the queue for a reviewer


def test_the_bundle_only_accepts_an_https_webhook():
    """The compile-time rule (AC-C1.12) the loopback tests above don't weaken."""
    from guard_fixtures import make_catalog, profile

    from guardrail_engine.policy import PlatformSettings, PolicyCompiler, parse_bundle
    from guardrail_engine.policy.errors import PolicyInvalidError

    compiler = PolicyCompiler(make_catalog(), profile(ALPHA), PlatformSettings())
    bad = doc(ALPHA, target="webhook", url="http://hooks.acme.example/x")
    with pytest.raises(PolicyInvalidError):
        compiler.compile(parse_bundle(bad), profile(ALPHA).attributes)


_ = NOW
