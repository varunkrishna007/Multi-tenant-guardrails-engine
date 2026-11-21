"""A tenant-chosen escalation webhook may only reach the public internet, when the url is
configured and when the notice is sent, and the sender connects to the address it checked.
Only 127.0.0.1 servers and a stand-in for DNS: no real network."""

import ipaddress
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from esc_fixtures import ALPHA, doc
from guard_fixtures import make_catalog, profile

from guardrail_engine.delivery import DeliveryError
from guardrail_engine.delivery.adapters import resolve
from guardrail_engine.delivery.adapters.resolve import resolve_global
from guardrail_engine.delivery.adapters.webhook import (
    _PinnedHTTPSConnection,
    post_signed_pinned,
    validate_tenant_webhook_url,
)
from guardrail_engine.delivery.events import EscalationNotice
from guardrail_engine.escalation.adapters.webhook import (
    EscalationWebhookSink,
    StaticWebhookSecrets,
)
from guardrail_engine.net_safety import (
    HostNotPublicError,
    HostUnresolvedError,
    is_global_address,
    literal_host_problem,
    url_host,
)
from guardrail_engine.policy import PlatformSettings, PolicyCompiler, parse_bundle
from guardrail_engine.policy.errors import ErrorCode, PolicyInvalidError

SECRET = "alpha-signing-secret-0123456789"

NON_GLOBAL = [
    "10.0.0.1",
    "10.255.255.255",
    "172.16.0.1",
    "172.31.255.255",
    "192.168.1.1",  # private
    "127.0.0.1",
    "127.1.2.3",
    "::1",  # loopback
    "169.254.169.254",
    "169.254.0.1",
    "fe80::1",  # link-local, including the cloud metadata address
    "100.64.0.1",
    "100.127.255.254",  # CGNAT
    "224.0.0.1",
    "239.255.255.250",
    "ff02::1",  # multicast
    "0.0.0.0",
    "::",  # unspecified
    "fc00::1",
    "fd12:3456::1",  # IPv6 unique local
    "::ffff:10.0.0.1",
    "::ffff:127.0.0.1",
    "::ffff:169.254.169.254",  # IPv4-mapped
    "::10.0.0.1",  # IPv4-compatible
    "64:ff9b::a00:1",  # NAT64 around 10.0.0.1
    "2002:a00:1::",  # 6to4 around 10.0.0.1
    "240.0.0.1",
    "255.255.255.255",  # reserved, broadcast
    "192.0.2.1",
    "198.51.100.7",
    "2001:db8::1",  # documentation
]
GLOBAL = ["8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:4700:4700::1111", "::ffff:8.8.8.8"]


@pytest.mark.parametrize("address", NON_GLOBAL)
def test_non_global_addresses_are_refused(address):
    assert is_global_address(address) is False
    assert literal_host_problem(address) is not None
    if ":" in address:
        assert literal_host_problem(f"[{address}]") is not None
    with pytest.raises(HostNotPublicError):
        resolve_global(address, 443)


@pytest.mark.parametrize("address", GLOBAL)
def test_global_addresses_pass(address):
    assert is_global_address(address) is True
    assert literal_host_problem(address) is None
    assert ipaddress.ip_address(resolve_global(address, 443)) == ipaddress.ip_address(address)


@pytest.mark.parametrize(
    "name",
    [
        "localhost",
        "LOCALHOST.",
        "app.localhost",
        "db.internal",
        "printer.local",
        "router.lan",
        "intranet",
        "metadata",
        "",
    ],
)
def test_names_for_a_local_network_are_refused_without_any_lookup(name):
    assert literal_host_problem(name) is not None


@pytest.mark.parametrize(
    ("url", "host"),
    [
        ("https://hooks.acme.example/x", "hooks.acme.example"),
        ("https://hooks.acme.example:8443/x?a=b", "hooks.acme.example"),
        ("https://user:pw@hooks.acme.example/x", "hooks.acme.example"),
        ("https://[fd00::1]:443/x", "fd00::1"),
        ("https://good.example\\@10.0.0.1/x", "10.0.0.1"),  # the part after the last @ is the host
        ("https://10.0.0.1#@good.example/", "10.0.0.1"),
        ("not a url", ""),
    ],
)
def test_the_host_of_a_url_agrees_with_the_one_the_sender_connects_to(url, host):
    from urllib.parse import urlsplit

    assert url_host(url) == host
    if host:
        assert (urlsplit(url).hostname or "") == host


def test_an_ordinary_public_name_passes_the_literal_check():
    assert literal_host_problem("hooks.acme.example") is None


# --------------------------------------------------------------------------- when configured


def compile_with(url):
    compiler = PolicyCompiler(make_catalog(), profile(ALPHA), PlatformSettings())
    bundle = parse_bundle(doc(ALPHA, target="webhook", url=url))
    return compiler.compile(bundle, profile(ALPHA).attributes)


@pytest.mark.parametrize(
    "url",
    [
        "https://127.0.0.1/hook",
        "https://localhost/hook",
        "https://10.1.2.3/hook",
        "https://169.254.169.254/latest/meta-data",
        "https://[::1]/hook",
        "https://[fd00::1]/hook",
        "https://[::ffff:10.0.0.1]/hook",
        "https://100.64.0.9/hook",
        "https://vault.internal/hook",
        "https://intranet/hook",
    ],
)
def test_a_bundle_naming_a_private_webhook_host_does_not_compile(url):
    with pytest.raises(PolicyInvalidError) as exc:
        compile_with(url)
    assert [(e.code, e.path) for e in exc.value.errors] == [
        (ErrorCode.ESCALATION_WEBHOOK_HOST_NOT_PUBLIC, "$.escalation.url")
    ]


def test_a_bundle_naming_a_public_webhook_host_compiles():
    assert compile_with("https://hooks.acme.example/guardrail").escalation.url


# --------------------------------------------------------------------------- when sent


class FakeDns:
    """Stands in for the resolver inside the resolver module only: a script of answers, one per
    lookup, and a count (the HTTP stack's own lookups of the pinned literal are untouched)."""

    SOCK_STREAM = socket.SOCK_STREAM

    def __init__(self, *answers):
        self.answers = list(answers)
        self.calls = []

    def getaddrinfo(self, host, port, **kw):
        self.calls.append(host)
        answer = self.answers.pop(0) if len(self.answers) > 1 else self.answers[0]
        if isinstance(answer, Exception):
            raise answer
        if isinstance(answer, str):
            answer = [answer]
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (a, port)) for a in answer]


@pytest.fixture
def dns(monkeypatch):
    def install(*answers):
        fake = FakeDns(*answers)
        monkeypatch.setattr(resolve, "socket", fake)
        return fake

    return install


class Receiver:
    def __init__(self) -> None:
        self.requests = []
        receiver = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers["Content-Length"]))
                receiver.requests.append({"headers": dict(self.headers), "body": body})
                self.send_response(200)
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
    def port(self) -> int:
        return self.server.server_address[1]

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(3)


@pytest.fixture
def receiver():
    r = Receiver()
    yield r
    r.close()


def notice(url) -> EscalationNotice:
    return EscalationNotice(
        item_id="esc_" + "ab" * 12,
        tenant_id=ALPHA,
        guard_point="output",
        reason="policy",
        created_at=1_000_000.0,
        url=url,
        content_sha256=None,
        bundle_version=1,
        rules=(),
        content_available=False,
    )


def strict_sink() -> EscalationWebhookSink:
    return EscalationWebhookSink(StaticWebhookSecrets({ALPHA: SECRET}), clock=lambda: 1_000_000.0)


@pytest.fixture
def no_connections(monkeypatch):
    """Any attempt to open a connection fails the test: a refused host must never be dialled."""
    dialled = []

    def refuse(*args, **kw):
        dialled.append(args)
        raise AssertionError("a connection was attempted")

    monkeypatch.setattr(socket, "create_connection", refuse)
    return dialled


def test_the_sink_refuses_every_private_url_before_any_connection(receiver, no_connections):
    s = strict_sink()
    for url in (
        f"https://127.0.0.1:{receiver.port}/hook",
        "https://10.0.0.5/hook",
        "https://169.254.169.254/latest",
        "https://[::1]/hook",
        "https://localhost/hook",
        f"http://127.0.0.1:{receiver.port}/hook",  # plain http, even to loopback
    ):
        with pytest.raises(DeliveryError) as exc:
            s.deliver(notice(url), "k")
        assert exc.value.code == "bad_url"
    assert receiver.requests == [] and no_connections == []


@pytest.mark.parametrize("answer", ["10.0.0.5", "127.0.0.1", "169.254.169.254", "100.64.1.1"])
def test_a_name_that_resolves_to_a_private_address_is_refused_at_send_time(
    dns, no_connections, answer
):
    fake = dns(answer)
    with pytest.raises(DeliveryError) as exc:
        strict_sink().deliver(notice("https://hooks.acme.example/hook"), "k")
    assert exc.value.code == "host_not_public"
    assert fake.calls == ["hooks.acme.example"] and no_connections == []


def test_one_private_answer_among_public_ones_refuses_the_name(dns, no_connections):
    dns(["93.184.216.34", "10.0.0.5"])
    with pytest.raises(DeliveryError) as exc:
        strict_sink().deliver(notice("https://hooks.acme.example/hook"), "k")
    assert exc.value.code == "host_not_public" and no_connections == []


def test_a_name_that_does_not_resolve_is_a_retryable_dns_failure(dns, no_connections):
    dns(OSError("no such host"))
    with pytest.raises(DeliveryError) as exc:
        strict_sink().deliver(notice("https://hooks.acme.example/hook"), "k")
    assert exc.value.code == "dns_failed"
    with pytest.raises(HostUnresolvedError):
        resolve_global("hooks.acme.example", 443)


def test_the_connection_goes_to_the_checked_address_and_keeps_the_hostname(receiver, monkeypatch):
    """DNS rebinding: the first lookup says one thing, any later lookup would say 10.0.0.5. The
    post uses the first answer only, and the request still names the hostname."""
    fake = FakeDns("127.0.0.1", "10.0.0.5")
    monkeypatch.setattr(resolve, "socket", fake)
    post_signed_pinned(
        f"http://hooks.acme.example:{receiver.port}/hook?x=1",
        SECRET.encode(),
        "key-1",
        {"id": "key-1"},
        sent_at=1_000_000.0,
        timeout_s=2.0,
        allow_non_global=True,
    )
    [req] = receiver.requests
    assert req["headers"]["Host"] == f"hooks.acme.example:{receiver.port}"  # the name, not the IP
    assert fake.calls == ["hooks.acme.example"]  # resolved once; the connect never looked again


def test_the_tls_server_name_is_the_hostname_while_the_socket_goes_to_the_ip(receiver):
    seen = {}

    class Context:
        def wrap_socket(self, sock, server_hostname=None):
            seen["sni"] = server_hostname
            seen["peer"] = sock.getpeername()
            return sock

    conn = _PinnedHTTPSConnection(
        "hooks.acme.example", receiver.port, ip="127.0.0.1", timeout_s=2.0, context=Context()
    )
    conn.connect()
    conn.close()
    assert seen == {"sni": "hooks.acme.example", "peer": ("127.0.0.1", receiver.port)}


def test_the_test_allowance_is_off_by_default_and_only_a_constructor_argument(
    receiver, no_connections
):
    import inspect

    default = (
        inspect.signature(EscalationWebhookSink)
        .parameters["allow_non_global_hosts_for_tests"]
        .default
    )
    assert default is False
    assert inspect.signature(post_signed_pinned).parameters["allow_non_global"].default is False
    assert inspect.signature(resolve_global).parameters["allow_non_global"].default is False
    # nothing a tenant sends (the url, the bundle) reaches it: a loopback url is refused anyway
    with pytest.raises(DeliveryError):
        strict_sink().deliver(notice(f"http://127.0.0.1:{receiver.port}/x"), "k")
    with pytest.raises(ValueError):
        validate_tenant_webhook_url(f"http://127.0.0.1:{receiver.port}/x")
    validate_tenant_webhook_url(f"http://127.0.0.1:{receiver.port}/x", allow_non_global=True)
    with pytest.raises(ValueError):
        validate_tenant_webhook_url("ftp://127.0.0.1/x", allow_non_global=True)


def test_a_refused_host_never_reaches_a_log_line_or_the_message(dns, caplog, no_connections):
    dns("10.0.0.5")
    with pytest.raises(DeliveryError) as exc:
        strict_sink().deliver(notice("https://secret-token.acme.example/hook"), "k")
    for text in (str(exc.value), repr(exc.value), caplog.text):
        assert "secret-token" not in text and "10.0.0.5" not in text
