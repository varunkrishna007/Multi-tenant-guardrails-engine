"""The HTTP webhook alert sink (M4-04). No paging vendor is integrated: whatever receives
this (a paging service's inbound webhook, a chat relay) is the deployment's choice.

**Request.** ``POST`` of a JSON body::

    {"id": "<idempotency key>", "type": "alert", "sent_at": <epoch s>, "alert": {...}}

with headers ``X-Guardrail-Idempotency-Key`` (the same on every retry: drop a repeat),
``X-Guardrail-Timestamp`` (epoch seconds) and ``X-Guardrail-Signature: v1=<hex>``, where the
hex is **HMAC-SHA256** of ``"<timestamp>.<body>"`` under the shared secret. A receiver
recomputes it over the raw body and checks the timestamp is recent.

**Safety.**

* The secret and the URL are never logged, never in an exception message and not in the
  repr: a failure is a short code (``http_503``, ``timeout``, ``connection_failed``).
* The URL must be ``https``; plain ``http`` only to a loopback address (local tests, a
  sidecar), and no credentials in the URL.
* Redirects are not followed (the signed body would go somewhere the operator did not
  choose), and proxy environment variables are ignored.
* ``timeout_s`` applies to connecting and to each read; the response body is never read.

``emit`` (the plain ``AlertSink`` port) and ``deliver`` (with the event's idempotency key,
used by the dispatcher) both **raise** :class:`DeliveryError` on failure. Behind the gateway's
queue that raise is logged and the alert is gone; behind the dispatcher it is retried.
"""

from __future__ import annotations

import hashlib
import hmac
import http.client
import ipaddress
import json
import socket
import ssl
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import asdict
from typing import Any
from urllib.parse import urlsplit

from guardrail_engine.delivery.adapters.resolve import resolve_global
from guardrail_engine.delivery.dispatcher import DeliveryError
from guardrail_engine.delivery.events import new_key
from guardrail_engine.gateway.sinks import Alert
from guardrail_engine.net_safety import (
    HostNotPublicError,
    HostUnresolvedError,
    literal_host_problem,
)

HEADER_KEY = "X-Guardrail-Idempotency-Key"
HEADER_TIMESTAMP = "X-Guardrail-Timestamp"
HEADER_SIGNATURE = "X-Guardrail-Signature"
MIN_SECRET_BYTES = 16


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


def sign(secret: bytes, timestamp: str, body: bytes) -> str:
    """The ``v1=`` signature of ``body`` sent at ``timestamp``."""
    mac = hmac.new(secret, timestamp.encode("ascii") + b"." + body, hashlib.sha256)
    return "v1=" + mac.hexdigest()


def _loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def validate_webhook_url(url: str) -> None:
    """Raise ``ValueError`` unless ``url`` may be posted to: ``https`` (``http`` only to a
    loopback address), a host and no credentials."""
    parts = urlsplit(url)
    host = parts.hostname or ""
    if not host or parts.username or parts.password:
        raise ValueError("webhook url: a host and no credentials in the url")
    if parts.scheme != "https" and not (parts.scheme == "http" and _loopback(host)):
        raise ValueError("webhook url must be https (http only to a loopback address)")


def validate_tenant_webhook_url(url: str, *, allow_non_global: bool = False) -> None:
    """Raise ``ValueError`` unless ``url`` may be posted to when a **tenant** chose it:
    ``https`` with a host and no credentials, and a host that is not a private, loopback,
    link-local or other non-global address or a name for one (the literal check; the name is
    resolved and checked again when the request is sent). ``allow_non_global`` is the test-only
    allowance: it also accepts ``http`` and any host, so a test can use a ``127.0.0.1`` server."""
    parts = urlsplit(url)
    host = parts.hostname or ""
    if not host or parts.username or parts.password:
        raise ValueError("webhook url: a host and no credentials in the url")
    _ = parts.port  # a malformed port raises ValueError here
    if allow_non_global:
        if parts.scheme not in ("https", "http"):
            raise ValueError("webhook url must be http or https")
        return
    if parts.scheme != "https":
        raise ValueError("webhook url must be https")
    if literal_host_problem(host) is not None:
        raise ValueError("webhook url: the host must be on the public internet")


def check_secret(secret: str | bytes) -> bytes:
    key = secret.encode("utf-8") if isinstance(secret, str) else bytes(secret)
    if len(key) < MIN_SECRET_BYTES:
        raise ValueError(f"webhook secret must be at least {MIN_SECRET_BYTES} bytes")
    return key


def build_opener() -> urllib.request.OpenerDirector:
    """No redirects (the signed body would go somewhere the operator did not choose) and no
    proxy environment variables."""
    return urllib.request.build_opener(_NoRedirect, urllib.request.ProxyHandler({}))


def post_signed(
    opener: urllib.request.OpenerDirector,
    url: str,
    secret: bytes,
    idempotency_key: str,
    document: dict[str, Any],
    *,
    sent_at: float,
    timeout_s: float,
) -> None:
    """POST ``document`` (JSON) signed as the module docstring says. Raises
    :class:`DeliveryError` with a short code on any failure; nothing else escapes, and no
    message holds the url, a header or the secret."""
    body = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    timestamp = str(int(sent_at))
    request = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "User-Agent": "guardrail-engine-webhook",
            HEADER_KEY: idempotency_key,
            HEADER_TIMESTAMP: timestamp,
            HEADER_SIGNATURE: sign(secret, timestamp, body),
        },
    )
    try:
        with opener.open(request, timeout=timeout_s) as response:
            status = response.status
    except urllib.error.HTTPError as exc:
        exc.close()
        raise DeliveryError(f"http_{exc.code}") from None
    except TimeoutError:
        raise DeliveryError("timeout") from None
    except urllib.error.URLError as exc:
        timed_out = isinstance(exc.reason, TimeoutError | socket.timeout)
        raise DeliveryError("timeout" if timed_out else "connection_failed") from None
    except OSError:
        raise DeliveryError("connection_failed") from None
    if not 200 <= status < 300:
        raise DeliveryError(f"http_{status}")


class _PinnedHTTPConnection(http.client.HTTPConnection):
    """Connects to ``ip`` while the request still names ``host`` (the Host header)."""

    def __init__(self, host: str, port: int, *, ip: str, timeout_s: float) -> None:
        super().__init__(host, port, timeout=timeout_s)
        self._ip = ip

    def connect(self) -> None:
        self.sock = socket.create_connection((self._ip, self.port), self.timeout)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """Connects to ``ip``, and still sends ``host`` as the TLS server name and checks the
    certificate against it, and names it in the Host header."""

    def __init__(
        self, host: str, port: int, *, ip: str, timeout_s: float, context: ssl.SSLContext
    ) -> None:
        super().__init__(host, port, timeout=timeout_s, context=context)
        self._ip = ip
        self._tls = context

    def connect(self) -> None:
        sock = socket.create_connection((self._ip, self.port), self.timeout)
        try:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            self.sock = self._tls.wrap_socket(sock, server_hostname=self.host)
        except BaseException:
            sock.close()
            raise


def post_signed_pinned(
    url: str,
    secret: bytes,
    idempotency_key: str,
    document: dict[str, Any],
    *,
    sent_at: float,
    timeout_s: float,
    allow_non_global: bool = False,
) -> None:
    """Like :func:`post_signed`, for a url a **tenant** chose. The host is resolved
    here, every address must be global, and the connection goes to **the address that was
    checked**: a second lookup can't answer with a private one (DNS rebinding). The request still
    names the host (the Host header, the TLS server name and the certificate check). No
    redirects and no proxies, as before. Raises :class:`DeliveryError`: ``host_not_public`` for a
    refused address (no connection is made), ``dns_failed``, ``timeout``, ``connection_failed``
    or ``http_<status>``; never a url, host, address or secret."""
    parts = urlsplit(url)
    host = parts.hostname or ""
    try:
        port = parts.port or (443 if parts.scheme == "https" else 80)
        ip = resolve_global(host, port, allow_non_global=allow_non_global)
    except HostNotPublicError:
        raise DeliveryError("host_not_public") from None
    except HostUnresolvedError:
        raise DeliveryError("dns_failed") from None
    except ValueError:
        raise DeliveryError("bad_url") from None
    body = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    timestamp = str(int(sent_at))
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "guardrail-engine-webhook",
        HEADER_KEY: idempotency_key,
        HEADER_TIMESTAMP: timestamp,
        HEADER_SIGNATURE: sign(secret, timestamp, body),
    }
    target = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
    conn: http.client.HTTPConnection
    if parts.scheme == "https":
        conn = _PinnedHTTPSConnection(
            host, port, ip=ip, timeout_s=timeout_s, context=ssl.create_default_context()
        )
    else:
        conn = _PinnedHTTPConnection(host, port, ip=ip, timeout_s=timeout_s)
    try:
        conn.request("POST", target, body=body, headers=headers)
        status = conn.getresponse().status
    except TimeoutError:
        raise DeliveryError("timeout") from None
    except (OSError, http.client.HTTPException):
        raise DeliveryError("connection_failed") from None
    finally:
        conn.close()
    if not 200 <= status < 300:
        raise DeliveryError(f"http_{status}")


class WebhookAlertSink:
    def __init__(
        self,
        url: str,
        secret: str | bytes,
        *,
        timeout_s: float = 5.0,
        clock: Callable[[], float] = time.time,
    ) -> None:
        validate_webhook_url(url)
        key = check_secret(secret)
        if timeout_s <= 0:
            raise ValueError("timeout_s must be positive")
        self._url = url
        self._secret = key
        self._timeout_s = timeout_s
        self._clock = clock
        self._opener = build_opener()

    def __repr__(self) -> str:
        return "WebhookAlertSink(<redacted>)"

    def emit(self, alert: Alert) -> None:
        self.deliver(alert, new_key())

    def deliver(self, alert: Alert, idempotency_key: str) -> None:
        sent_at = self._clock()
        data = asdict(alert)
        data["severity"] = alert.severity.value
        data.pop("dedupe_key", None)  # it is the body's "id" and the key header
        post_signed(
            self._opener,
            self._url,
            self._secret,
            idempotency_key,
            {"id": idempotency_key, "type": "alert", "sent_at": int(sent_at), "alert": data},
            sent_at=sent_at,
            timeout_s=self._timeout_s,
        )
