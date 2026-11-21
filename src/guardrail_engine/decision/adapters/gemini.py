"""Gemini Decision 1 adapter: the ``DecisionModel`` port over the public Decisions API.

    config = GeminiConfig.from_env()          # GEMINI_API_KEY, GEMINI_PAID_TIER=true
    async with GeminiDecisionModel(config) as model:
        result = await model.decide(input, questions)

HTTP outcomes map to the result union (M1-03, and the retry decision):

=========================================  ==========================================
Outcome                                    Result
=========================================  ==========================================
request not valid Unicode (no HTTP call)   ``Failed(OTHER)``
200, a body with an ``answers`` map        ``Answered`` via the shared ``parse_response``
200, not JSON or no ``answers`` map        ``Failed(OTHER)``
401, 403, status UNAUTHENTICATED or       ``Failed(AUTH)``, ``reason`` = the provider's
PERMISSION_DENIED, or a reason such as     reason (e.g. ``API_KEY_INVALID``)
API_KEY_INVALID (observed: a 400)
429, status RESOURCE_EXHAUSTED, a QUOTA    ``Failed(RATE_LIMITED)``; a google.rpc
reason, or a 400 naming a quota or daily   ``RetryInfo`` delay is kept as
limit                                      ``retry_delay_s`` (M1-15)
400 with code ``prohibited_content``,      ``SafetyBlocked``, ``reason`` = the code,
``blocklist``, ``content_blocked`` or      casefolded (``"prohibited_content"``...)
``image_safety`` (any case; nested or
top-level; M1-13)
400 naming safety (code, status, reason)   ``SafetyBlocked``, ``reason`` = the field that
                                           named it (``"safety"`` for the documented code)
400 naming CreateDecisionRequest.questions ``Failed(LIMIT_EXCEEDED)``, with the key if named
or .input with limit wording
any other 400                              ``Failed(OTHER)``; a code other than
                                           ``invalid_request``/``INVALID_ARGUMENT``,
                                           no code, or a non-JSON body also sets
                                           ``unrecognised_code`` (M1-13, M1-15)
408, or a transport timeout                ``Failed(TIMEOUT)``
5xx, or a connection error                 ``Failed(UNAVAILABLE)``
other request errors, anything unexpected  ``Failed(OTHER)``, exception type name only
anything else (404...)                     ``Failed(OTHER)``
=========================================  ==========================================

The API speaks two error dialects (both observed on 2026-11-16):

* Decisions: ``{"error": {"code": "invalid_request", "message": "* CreateDecisionRequest.
  questions: must have between 1 and 1000 questions\\n"}}``. A limit error has the generic
  code ``invalid_request``, so it is recognised by the field path plus limit wording.
* google.rpc: ``{"error": {"code": 400, "status": "INVALID_ARGUMENT", "details":
  [{"reason": "API_KEY_INVALID", ...}]}}`` for an invalid key.

The ``safety`` code comes from the design and the published docs and isn't observed live yet.
It is accepted nested or top-level, and as a status or reason naming safety.

Provider refusals (M1-13, R10)
------------------------------

Observed live on 2026-11-17 (warm burst run): HTTP 400 with the string code
``prohibited_content``, no ``status``, no details, and a message beginning "Input blocked: The
prompt could not be submitted. The prompt contains sensitive words that violate Google's
[Generative AI Prohibited Use policy](...)". That is the provider's own content filter
refusing the input before scoring: deterministic on resend, so not a provider failure. It maps
to ``SafetyBlocked``, which the gateway never retries and the Guard Service turns into
``block`` / ``provider_safety`` (PF-12, R10).

* **Matched on the structured code only**, compared case-insensitively and exactly, wherever
  the parser finds it (under ``"error"`` or top-level; which one the live response used was
  not recorded). Never on the message alone: the message is free text, its wording is not a
  contract, and a 400 whose message merely says "blocked" or quotes the policy (an
  ``invalid_request`` echoing input, say) must keep its own mapping. The backlog's "or the
  Prohibited Use policy message" is deliberately not implemented for that reason.
* **Four exact codes map, and ``safety`` keeps its wider rule.** Google's Decisions API guide
  lists the safety error codes as ``safety``, ``prohibited_content``, ``blocklist``,
  ``image_safety`` and ``content_blocked`` (read 2026-11-17; <https://ai.google.dev/gemini-api/
  docs/decisions-api>). ``prohibited_content`` is the only one **observed live**. The others
  are mapped **from that documentation alone**: ``blocklist`` and ``content_blocked`` were
  previously left as ``Failed(OTHER)`` on the reading that they were ``blockReason`` values of
  other Gemini APIs, which Google's page now contradicts for this API. They are matched exactly
  and case-insensitively on the structured code, like ``prohibited_content``, and tested on
  **constructed** fixtures (``constructed_*_400.json``: the observed body shape with the
  documented code and invented message wording, never a recording). ``image_safety`` was
  already ``SafetyBlocked`` through the wider rule below; it is now named, so its mapping
  doesn't depend on a substring. ``safety`` keeps its broader matching: any code,
  status or reason that contains "safety" is a refusal.
* **Codes still not mapped,** because neither the documentation nor an observation lists them
  for this API: ``spii``, ``recitation``, ``prohibited`` and ``blocked``. Each stays
  ``Failed(OTHER)`` and is reported as an unrecognised code (below) until observed or documented.
* **Unrecognised codes are reported, by code only.** A 400 that falls to ``Failed(OTHER)``
  with a code other than ``invalid_request`` (or google.rpc ``INVALID_ARGUMENT``) carries
  a label for that code in ``Failed.unrecognised_code``: the code casefolded, or
  ``_malformed`` if it isn't 1-64 characters of ``[a-z0-9_]``
  (:func:`~guardrail_engine.decision.port.provider_error_label`, M1-15). A 400 with no code
  carries ``_no_code``, and one whose body isn't JSON ``_not_json``, so a change in the
  error's *shape* is counted too. The gateway counts it as
  ``provider_error_unrecognised`` per tenant and guard point and logs the label, so a new
  code shows up in monitoring and gets a mapping once observed.
* **Code and message are kept apart.** ``SafetyBlocked.reason`` carries the structured code
  (one of :data:`~guardrail_engine.decision.port.REFUSAL_CODES`, or ``safety``); the
  verdict and audit record keep it as ``failure_reason``. ``SafetyBlocked.message`` is the
  provider's free text, which could echo the input: the Guard Service logs it at DEBUG,
  truncated, and never records it. Nothing in this module logs it.

The adapter applies no deadline of its own beyond a generous transport timeout: the gateway
owns the budget and cancels the call (M1-04). Request limits are checked locally first, so a
config bug costs no quota.

The API key is sent only in the ``x-goog-api-key`` header. It never appears in a URL, a
result message or ``repr``.

Warm connections (M1-10)
------------------------

A cold call (new TCP and TLS connection) cost about 200 ms more than a warm one in M0-01,
and httpx's default 5 s keepalive closed the connection between almost every call. The
client the adapter builds for itself therefore:

* keeps an idle pooled connection open for ``GeminiConfig.keepalive_expiry_s`` (60 s by
  default) before closing it;
* keeps at least ``max_in_flight`` idle connections (default 8; pass the gateway's
  in-flight limit per key, M1-04), so a burst up to that limit finds a warm connection for
  every call instead of opening new ones;
* speaks HTTP/1.1 only, so each call in flight has a connection of its own.

**No keep-warm requests.** Connections are kept at the transport level only. The adapter
starts no background task and sends nothing but the calls it is asked to make: every
request counts against the daily cap (PF-4) and is billed.

**A connection the server has closed.** The server may close an idle connection before our
60 s are up. httpcore checks every idle connection when it hands one to a request, before a
byte of that request is written: a connection whose keepalive has expired, or whose socket
is readable while idle (the server's FIN or RST has arrived; an idle HTTP/1.1 connection
has nothing else to read), is closed and the request goes to another idle connection or a
new one. That replacement happens inside the same ``decide`` call and under the gateway's
deadline, returns the normal result, and is not a gateway retry. It is reported as a
``new`` connection.

The adapter adds **no retry of its own**, because nothing httpx 0.28 and httpcore 1.0
raise after that check proves the request was not sent:

* ``ReadError`` and ``RemoteProtocolError`` ("Server disconnected without sending a
  response") are what a reused connection closed in the instant after the check produces,
  but they are equally what a server that read the request and then dropped the
  connection produces.
* ``WriteError`` never reaches us on HTTP/1.1: httpcore swallows it and reads the response,
  which then fails as one of the two above. A write that failed may also have written part
  of the request first.
* ``WriteTimeout`` and ``ReadTimeout`` come after bytes may have been written.
* ``ConnectError``, ``ConnectTimeout`` and ``PoolTimeout`` do prove the request was not
  sent, but they come from opening a *new* connection (or waiting for one), not from a
  stale one: the provider is unreachable, which is ``unavailable`` or ``timeout`` and the
  gateway's to retry.

So all of them keep the mapping in the table above, and a request that may have reached
the provider is never sent twice by the adapter. httpx's own ``retries`` transport option
doesn't change this: it retries only ``ConnectError``/``ConnectTimeout`` while opening a
new connection (with a 0.5 s, 1 s... backoff), never a failure on an open connection, so
it is left at 0.

**Metering.** ``on_call`` (a constructor argument) receives a :class:`CallInfo` for every
call that reached the HTTP client, saying whether its connection was ``new`` or
``reused``, so the check's span can record it and the dogfood can show the cold-call rate.
It is found with httpcore's public ``trace`` request extension.

The same ``CallInfo`` carries connection diagnostics (M0-02): when the call began and how it
ended, the connect, TLS, send and first-byte times, the response's HTTP version and whether it
said ``Connection: close``, the first failed httpcore event with the exception *class* name
(a reset or early close is a ``ReadError`` or ``RemoteProtocolError``; HTTP/1.1 has no GOAWAY),
and an estimate of the connection's age and the idle gap before the call. They are numbers,
flags and event or exception names only, and take no part in ``CallInfo`` equality.

These settings apply only to the client the adapter builds. A caller that passes its own
``client`` owns its limits.
"""

from __future__ import annotations

import inspect
import json
import logging
import os
import re
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

import httpx

from guardrail_engine.decision.limits import DecisionLimitError, validate_request
from guardrail_engine.decision.port import (
    ERROR_LABEL_NO_CODE,
    ERROR_LABEL_NOT_JSON,
    DecisionResult,
    Failed,
    FailureKind,
    SafetyBlocked,
    provider_error_label,
)
from guardrail_engine.decision.port import REFUSAL_CODES as REFUSAL_CODES
from guardrail_engine.decision.port import REFUSAL_PROHIBITED_CONTENT as REFUSAL_PROHIBITED_CONTENT
from guardrail_engine.decision.port import REFUSAL_SAFETY as REFUSAL_SAFETY
from guardrail_engine.decision.response import parse_response
from guardrail_engine.decision.types import Question

DEFAULT_BASE_URL = "https://generativelanguage.googleapis.com/v1beta"
DEFAULT_MODEL = "gemini-decision-1"
DEFAULT_KEEPALIVE_EXPIRY_S = 60.0
"""M1-10: how long an idle pooled connection is kept (httpx's own default is 5 s)."""
DEFAULT_MAX_IN_FLIGHT = 8
"""M1-10: idle connections kept, at least the gateway's in-flight limit per key (M1-04)."""
_HTTPX_DEFAULT_MAX_CONNECTIONS = 100

logger = logging.getLogger(__name__)

_TRUE = frozenset({"1", "true", "yes"})
_LIMIT_WORDING = re.compile(
    r"must have between|at most|at least|exceed|too (?:many|long|large)|limit|maximum",
    re.IGNORECASE,
)
# A limit 400 must name a request field the limits cover, as the observed error does:
# "* CreateDecisionRequest.questions: must have between 1 and 1000 questions".
_LIMITED_FIELD = re.compile(r"CreateDecisionRequest\.(?:questions|input)\b")
# Google.rpc auth failures. Observed live: HTTP 400 INVALID_ARGUMENT / API_KEY_INVALID.
_AUTH_REASONS = frozenset(
    {
        "API_KEY_INVALID",
        "API_KEY_EXPIRED",
        "API_KEY_SERVICE_BLOCKED",
        "API_KEY_HTTP_REFERRER_BLOCKED",
        "API_KEY_IP_ADDRESS_BLOCKED",
        "SERVICE_DISABLED",
        "CONSUMER_SUSPENDED",
    }
)
_AUTH_STATUSES = frozenset({"UNAUTHENTICATED", "PERMISSION_DENIED"})
# A quota or daily-cap rejection belongs with rate limits, whatever the status.
_QUOTA = re.compile(r"quota|daily limit|requests per (?:day|minute)|rate limit", re.IGNORECASE)
_KEY_IN_MESSAGE = re.compile(r"questions(?:\[[\"']?|\.)([A-Za-z0-9_-]+)")
_MAX_MESSAGE = 500
# M1-13: the exact refusal codes (observed: ``prohibited_content``; the rest from Google's
# Decisions API guide). Codes deliberately not mapped are listed in the module docstring.
_REFUSAL_CODES = REFUSAL_CODES
# M1-13: 400 codes whose meaning is known even when they fall to ``Failed(OTHER)``: the
# Decisions dialect's generic ``invalid_request`` and google.rpc's ``INVALID_ARGUMENT`` (both
# observed live). Any other code on a 400 that falls to OTHER is reported as unrecognised.
_KNOWN_400_CODES = frozenset({"invalid_request", "invalid_argument"})


class PaidTierRequiredError(RuntimeError):
    """The configuration doesn't declare a paid-tier key. Free-tier data may be used by Google
    to improve its products, so the adapter refuses to start (§Multi-tenancy, data handling)."""


@dataclass(frozen=True)
class GeminiConfig:
    api_key: str = field(repr=False)
    paid_tier: bool = False
    """Set by the operator to declare that ``api_key`` is a paid-tier key."""
    model: str = DEFAULT_MODEL
    base_url: str = DEFAULT_BASE_URL
    transport_timeout_s: float = 10.0
    """A backstop only. The gateway's per-guard-point budget is the real deadline."""
    keepalive_expiry_s: float = DEFAULT_KEEPALIVE_EXPIRY_S
    """How long an idle pooled connection stays open (M1-10)."""

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> GeminiConfig:
        """Read ``GEMINI_API_KEY`` and ``GEMINI_PAID_TIER`` (``true``/``1``/``yes``)."""
        env = os.environ if env is None else env
        return cls(
            api_key=env.get("GEMINI_API_KEY", ""),
            paid_tier=env.get("GEMINI_PAID_TIER", "").strip().lower() in _TRUE,
            model=env.get("GEMINI_DECISION_MODEL", DEFAULT_MODEL),
        )


class ConnectionUse(StrEnum):
    NEW = "new"
    """The call opened a connection (a cold call: TCP and TLS set-up)."""
    REUSED = "reused"
    """The call went out on a pooled connection that an earlier call had opened."""


@dataclass(frozen=True)
class CallInfo:
    """Transport facts about one call, for its span (M1-10 metering)."""

    connection: ConnectionUse | None
    """None when the call ended before it was given a connection (e.g. cancelled or
    ``PoolTimeout`` while waiting for one), or when an injected client's transport doesn't
    emit httpcore trace events (e.g. ``httpx.MockTransport``)."""

    # Connection diagnostics (M0-02, decided 2026-11-17 after the R7.4 run's bursts of
    # timeouts). Timings, so they take no part in equality (``compare=False``): two calls
    # that differ only in how long they took are the same ``CallInfo`` to the M1-10 tests.
    # Everything here is a number, a version string, a boolean or the *name* of an httpcore
    # event and of an exception class: never the request, a header, a URL or a message.
    seq: int | None = field(default=None, compare=False)
    """The adapter's call counter: 1 for its first call."""
    started_at: str | None = field(default=None, compare=False)
    """UTC time the call began, ISO 8601 with milliseconds."""
    ended: str | None = field(default=None, compare=False)
    """How the call ended: ``response``, ``timeout``, ``transport_error``, ``request_error``,
    ``error`` or ``cancelled`` (the gateway's deadline)."""
    total_ms: float | None = field(default=None, compare=False)
    to_send_ms: float | None = field(default=None, compare=False)
    """From the call's start to the first request byte: waiting for a pooled connection plus
    opening one. A large value on a call with no ``connect_ms`` is a stall in the pool."""
    connect_ms: float | None = field(default=None, compare=False)
    """Opening the TCP connection (to its completion or failure); only for a ``new`` one."""
    tls_ms: float | None = field(default=None, compare=False)
    send_ms: float | None = field(default=None, compare=False)
    """Writing the request headers and body."""
    ttfb_ms: float | None = field(default=None, compare=False)
    """From the request fully written to the response headers read: the provider's time."""
    http_version: str | None = field(default=None, compare=False)
    server_closes: bool | None = field(default=None, compare=False)
    """The response carried ``Connection: close``: the server ends the connection after it."""
    failure: str | None = field(default=None, compare=False)
    """The first httpcore event that failed and the exception class's name, e.g.
    ``http11.receive_response_headers.failed:ReadError`` (a reset or an early close is a
    ``ReadError`` or ``RemoteProtocolError``). HTTP/1.1 has no GOAWAY: this adapter never
    speaks HTTP/2."""
    connection_age_s: float | None = field(default=None, compare=False)
    """An **estimate**: time since the most recently opened connection was opened. Exact when
    calls run one at a time and a cancelled or failed call closes its connection (httpcore
    does); None when unknown."""
    idle_s: float | None = field(default=None, compare=False)
    """Time since the adapter's previous call ended (None for its first)."""

    def diagnostics(self) -> dict[str, Any]:
        """The diagnostics as JSON-safe values, for a record. Absent values are left out."""
        keep = {
            "seq": self.seq, "started_at": self.started_at, "ended": self.ended,
            "connection": self.connection.value if self.connection else None,
            "total_ms": self.total_ms, "to_send_ms": self.to_send_ms,
            "connect_ms": self.connect_ms, "tls_ms": self.tls_ms, "send_ms": self.send_ms,
            "ttfb_ms": self.ttfb_ms, "http_version": self.http_version,
            "server_closes": self.server_closes, "failure": self.failure,
            "connection_age_s": self.connection_age_s, "idle_s": self.idle_s,
        }  # fmt: skip
        return {k: v for k, v in keep.items() if v is not None}


class _ConnectionTracer:
    """httpcore ``trace`` extension for one call: notes whether a connection was opened, and
    (M0-02) when each step happened.

    httpcore opens a connection inside the request it was created for, so a
    ``connection.connect_*`` event during this request means a new connection; reaching
    ``send_request_headers`` without one means a pooled connection was reused.

    **SECURITY:** the event's ``info`` holds the request and its headers, which hold the API
    key. This class never stores ``info`` or anything from the request: it reads only the
    response's version and ``Connection`` header from ``receive_response_headers.complete``
    and the *class name* of an exception from a ``.failed`` event.
    """

    _OPENED = frozenset(
        {"connection.connect_tcp.started", "connection.connect_unix_socket.started"}
    )
    _SENDING = frozenset(
        {"http11.send_request_headers.started", "http2.send_request_headers.started"}
    )

    def __init__(self) -> None:
        self.connection: ConnectionUse | None = None
        self.created = time.monotonic()
        self.at: dict[str, float] = {}
        """When each event first happened (``time.monotonic``), by event name."""
        self.http_version: str | None = None
        self.server_closes: bool | None = None
        self.failure: str | None = None

    async def __call__(self, event: str, info: Mapping[str, Any]) -> None:
        self.at.setdefault(event, time.monotonic())
        if event in self._OPENED:
            self.connection = ConnectionUse.NEW
        elif event in self._SENDING and self.connection is None:
            self.connection = ConnectionUse.REUSED
        if event.endswith(".failed") and self.failure is None:
            self.failure = f"{event}:{type(info.get('exception')).__name__}"
        elif event.endswith("receive_response_headers.complete"):
            self._read_response_head(info.get("return_value"))

    def _read_response_head(self, head: Any) -> None:
        """``(http_version, status, reason, headers)`` of the response. Never raises."""
        try:
            version, _status, _reason, headers = head
            self.http_version = bytes(version).decode("ascii", "replace")
            self.server_closes = any(
                bytes(name).lower() == b"connection" and b"close" in bytes(value).lower()
                for name, value in headers
            )
        except Exception:  # a diagnostic must never break a call
            return

    def _gap(self, start: str, *ends: str) -> float | None:
        """Milliseconds from event ``start`` to the first of ``ends`` that happened."""
        if start not in self.at:
            return None
        end = next((self.at[e] for e in ends if e in self.at), None)
        return None if end is None else round((end - self.at[start]) * 1000, 2)

    def timings(self) -> dict[str, float | None]:
        proto = "http2" if any(e.startswith("http2.") for e in self.at) else "http11"
        sent = next(
            (self.at[e] for e in (f"{proto}.send_request_body.complete",
                                  f"{proto}.send_request_headers.complete") if e in self.at),
            None,
        )  # fmt: skip
        got = self.at.get(f"{proto}.receive_response_headers.complete")
        first = self.at.get(f"{proto}.send_request_headers.started")
        return {
            "to_send_ms": None if first is None else round((first - self.created) * 1000, 2),
            "connect_ms": self._gap(
                "connection.connect_tcp.started",
                "connection.connect_tcp.complete", "connection.connect_tcp.failed",
            ),
            "tls_ms": self._gap(
                "connection.start_tls.started",
                "connection.start_tls.complete", "connection.start_tls.failed",
            ),
            "send_ms": self._gap(
                f"{proto}.send_request_headers.started",
                f"{proto}.send_request_body.complete", f"{proto}.send_request_headers.complete",
            ),
            "ttfb_ms": None if sent is None or got is None else round((got - sent) * 1000, 2),
        }  # fmt: skip

    @property
    def connected_at(self) -> float | None:
        """When a connection this call opened became usable, if it opened one."""
        for event in ("connection.start_tls.complete", "connection.connect_tcp.complete"):
            if event in self.at:
                return self.at[event]
        return None


class GeminiDecisionModel:
    """``DecisionModel`` over the Gemini Decisions API. Safe for concurrent tasks."""

    def __init__(
        self,
        config: GeminiConfig,
        *,
        client: httpx.AsyncClient | None = None,
        max_in_flight: int = DEFAULT_MAX_IN_FLIGHT,
        on_call: Callable[[CallInfo], None] | None = None,
    ) -> None:
        """``max_in_flight`` is the most calls the caller will have in flight at once on this
        key (the gateway's admission limit, M1-04). The pool keeps that many idle
        connections. ``max_in_flight`` and ``config.keepalive_expiry_s`` apply only when
        ``client`` is None.

        ``on_call`` is called once for every call that reached the HTTP client, however it
        ended (cancellation included), with that call's :class:`CallInfo`. It runs in the
        task that runs ``decide``, so it sees that task's context (e.g. the current span).
        It must be synchronous, quick and non-blocking; anything it raises is logged and
        ignored.
        """
        if not config.api_key:
            raise ValueError("GeminiConfig.api_key is empty")
        if not config.paid_tier:
            raise PaidTierRequiredError(
                "refusing to start: the configuration doesn't declare a paid-tier key "
                "(set GEMINI_PAID_TIER=true only for a paid-tier key)"
            )
        if isinstance(max_in_flight, bool) or not (
            isinstance(max_in_flight, int) and max_in_flight >= 1
        ):
            raise ValueError(f"max_in_flight must be a whole number >= 1, got {max_in_flight!r}")
        if not config.keepalive_expiry_s > 0:
            raise ValueError(f"keepalive_expiry_s must be > 0, got {config.keepalive_expiry_s!r}")
        self._config = config
        self._on_call = on_call
        self._owns_client = client is None
        self._client = client or httpx.AsyncClient(
            timeout=config.transport_timeout_s,
            limits=httpx.Limits(
                max_connections=max(_HTTPX_DEFAULT_MAX_CONNECTIONS, max_in_flight),
                max_keepalive_connections=max_in_flight,
                keepalive_expiry=config.keepalive_expiry_s,
            ),
        )
        self._url = f"{config.base_url.rstrip('/')}/decisions"
        self._calls = 0
        self._connection_opened_at: float | None = None
        """When the most recently opened connection became usable (for an age estimate)."""
        self._last_call_ended_at: float | None = None

    @property
    def model_id(self) -> str:
        return self._config.model

    def __repr__(self) -> str:
        return f"GeminiDecisionModel(model={self._config.model!r}, url={self._url!r})"

    async def __aenter__(self) -> GeminiDecisionModel:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    async def decide(self, input: str, questions: Mapping[str, Question]) -> DecisionResult:
        questions = dict(questions)
        try:
            validate_request(input, questions)
        except DecisionLimitError as e:
            return Failed(kind=FailureKind.LIMIT_EXCEEDED, message=e.reason, key=e.key)
        return await self._send(build_request(self._config.model, input, questions), questions)

    async def _send(
        self, body: dict[str, Any], questions: Mapping[str, Question]
    ) -> DecisionResult:
        """POST ``body`` as-is and map the outcome. Never raises for a request or response
        problem; only cancellation propagates, so the gateway owns the deadline.

        Messages carry exception type names only, never ``str(e)``, so nothing from the
        request can leak into a result.
        """
        try:
            # Encode ourselves so content that isn't valid Unicode (e.g. a lone surrogate
            # decoded from JSON "\ud800") fails here, typed, with no HTTP call. The content
            # is never altered (B3).
            content = json.dumps(body, ensure_ascii=False).encode("utf-8")
        except UnicodeEncodeError:
            return Failed(kind=FailureKind.OTHER, message="request is not valid Unicode")
        tracer = _ConnectionTracer()
        started = tracer.created
        started_at = datetime.now(UTC).isoformat(timespec="milliseconds")
        self._calls += 1
        seq = self._calls
        idle = None if self._last_call_ended_at is None else started - self._last_call_ended_at
        ended = "cancelled"  # stays so if cancellation propagates (the gateway's deadline)
        try:
            # SECURITY: httpx masks only Authorization headers in reprs. Never log request
            # headers, the request object or this call's locals: they hold the API key.
            response = await self._client.post(
                self._url,
                content=content,
                headers={
                    "content-type": "application/json",
                    "x-goog-api-key": self._config.api_key,
                },
                extensions={"trace": tracer},
            )
            ended = "response"
        except httpx.TimeoutException as e:
            ended = "timeout"
            return Failed(
                kind=FailureKind.TIMEOUT, message=f"transport timeout ({type(e).__name__})"
            )
        except httpx.TransportError as e:
            ended = "transport_error"
            return Failed(
                kind=FailureKind.UNAVAILABLE, message=f"transport error ({type(e).__name__})"
            )
        except httpx.RequestError as e:  # decoding errors, too many redirects...
            ended = "request_error"
            return Failed(kind=FailureKind.OTHER, message=f"request error ({type(e).__name__})")
        except Exception as e:  # last resort: the port promises a result, not an exception
            ended = "error"
            return Failed(kind=FailureKind.OTHER, message=f"unexpected error ({type(e).__name__})")
        finally:
            self._report(self._call_info(tracer, seq, started_at, started, idle, ended))
        return map_http_response(response.status_code, response.content, questions)

    def _call_info(
        self,
        tracer: _ConnectionTracer,
        seq: int,
        started_at: str,
        started: float,
        idle: float | None,
        ended: str,
    ) -> CallInfo:
        """The call's :class:`CallInfo`, with the connection diagnostics, and update the rough
        picture of which connection the next call will find (see ``connection_age_s``)."""
        now = time.monotonic()
        opened = tracer.connected_at
        if opened is not None:
            self._connection_opened_at = opened
        reference = self._connection_opened_at
        age = None
        if reference is not None and tracer.connection is not None:
            age = round(
                (tracer.at.get("http11.send_request_headers.started", started) - reference), 3
            )
        if ended != "response" or tracer.failure is not None:
            self._connection_opened_at = None  # a failed or cancelled call's connection is closed
        self._last_call_ended_at = now
        return CallInfo(
            connection=tracer.connection,
            seq=seq,
            started_at=started_at,
            ended=ended,
            total_ms=round((now - started) * 1000, 2),
            http_version=tracer.http_version,
            server_closes=tracer.server_closes,
            failure=tracer.failure,
            connection_age_s=age,
            idle_s=None if idle is None else round(idle, 3),
            **tracer.timings(),
        )

    def _report(self, info: CallInfo) -> None:
        if self._on_call is None:
            return
        try:
            returned = self._on_call(info)
            if inspect.iscoroutine(returned):
                returned.close()
                logger.error("on_call hook is async; it must be synchronous")
        except Exception:
            logger.exception("on_call hook failed; ignored")


def build_request(model: str, input: str, questions: Mapping[str, Question]) -> dict[str, Any]:
    """The request body, as in the design's §Runtime flow example."""
    return {
        "model": model,
        "input": input,
        "questions": {
            key: q.model_dump(mode="json", exclude_none=True) for key, q in questions.items()
        },
    }


def map_http_response(
    status: int, content: bytes, questions: Mapping[str, Question]
) -> DecisionResult:
    """Map an HTTP status and body to the result union. Pure, so it is tested on fixtures."""
    body = _json_or_none(content)
    if status == 200:
        if body is None:
            return Failed(kind=FailureKind.OTHER, message="200 response is not JSON")
        return parse_response(body, questions)

    err = _error_fields(body, content)
    labels = [x for x in (err.code, err.status, *err.reasons) if x]
    detail = f"HTTP {status}" + "".join(f" {x}" for x in dict.fromkeys(labels))
    detail += f": {err.message}" if err.message else ""

    reason = next(iter(err.reasons), None) or err.status
    auth_reasons = sorted(_AUTH_REASONS & set(err.reasons))
    if status in (401, 403) or err.status in _AUTH_STATUSES or auth_reasons:
        return Failed(
            kind=FailureKind.AUTH,
            message=detail,
            reason=auth_reasons[0] if auth_reasons else reason or f"HTTP_{status}",
        )
    # Structured signals first (auth above, then safety, then structured quota),
    # and only then the message-wording heuristics.
    if status == 400 and (code := _safety_code(err)) is not None:
        # ``reason`` is the structured code, which is recorded; ``message`` is the provider's
        # free text, for DEBUG logs only (review decision on M1-13).
        return SafetyBlocked(message=err.message or None, reason=code)
    if (
        status == 429
        or err.status == "RESOURCE_EXHAUSTED"
        or any("QUOTA" in r.upper() for r in err.reasons)
    ):
        return Failed(
            kind=FailureKind.RATE_LIMITED,
            message=detail,
            reason=reason,
            retry_delay_s=err.retry_delay_s,
        )
    if status == 400:
        if _QUOTA.search(err.message):
            return Failed(
                kind=FailureKind.RATE_LIMITED,
                message=detail,
                reason=reason,
                retry_delay_s=err.retry_delay_s,
            )
        if _LIMITED_FIELD.search(err.message) and _LIMIT_WORDING.search(err.message):
            return Failed(
                kind=FailureKind.LIMIT_EXCEEDED,
                message=detail,
                key=_key_in(err.message, questions),
            )
        return Failed(
            kind=FailureKind.OTHER,
            message=detail,
            reason=reason,
            unrecognised_code=_unrecognised_code(err, is_json=_is_json(content)),
        )
    if status == 408:
        return Failed(kind=FailureKind.TIMEOUT, message=detail, reason=reason)
    if 500 <= status <= 599:
        return Failed(kind=FailureKind.UNAVAILABLE, message=detail, reason=reason)
    return Failed(kind=FailureKind.OTHER, message=detail, reason=reason)


def _json_or_none(content: bytes) -> Any:
    try:
        return json.loads(content)
    except (ValueError, UnicodeDecodeError):
        return None


@dataclass(frozen=True)
class _ErrorFields:
    code: str | None
    """Decisions dialect: ``"invalid_request"``, ``"safety"``, ``"prohibited_content"``.
    google.rpc: the HTTP number."""
    status: str | None
    """google.rpc only, e.g. ``"INVALID_ARGUMENT"``."""
    reasons: tuple[str, ...]
    """google.rpc ``details[].reason``, e.g. ``("API_KEY_INVALID",)``."""
    message: str
    retry_delay_s: float | None = None
    """google.rpc ``RetryInfo.retryDelay``, when the first ``RetryInfo`` detail carries a
    well-formed one (M1-15). Never read from the message."""


def _error_fields(body: Any, content: bytes) -> _ErrorFields:
    """Error fields in either dialect the API speaks:

    * Decisions: ``{"error": {"code": "invalid_request", "message": ...}}``, or top-level;
    * google.rpc: ``{"error": {"code": 400, "status": "INVALID_ARGUMENT",
      "details": [{"reason": "API_KEY_INVALID", ...}], "message": ...}}``;
    * anything else: the body as text.
    """
    if isinstance(body, Mapping):
        err = body.get("error") if isinstance(body.get("error"), Mapping) else body
        code, status, message = err.get("code"), err.get("status"), err.get("message")
        details = err.get("details") if isinstance(err.get("details"), list) else []
        reasons = tuple(
            str(d["reason"]) for d in details if isinstance(d, Mapping) and d.get("reason")
        )
        return _ErrorFields(
            code=str(code) if code is not None else None,
            status=str(status) if status is not None else None,
            reasons=reasons,
            retry_delay_s=_retry_delay(details),
            message=str(message).strip()[:_MAX_MESSAGE] if message is not None else "",
        )
    text = body if isinstance(body, str) else content.decode("utf-8", "replace")
    return _ErrorFields(code=None, status=None, reasons=(), message=text.strip()[:_MAX_MESSAGE])


_RETRY_INFO_TYPE = "type.googleapis.com/google.rpc.RetryInfo"
# google.protobuf.Duration in its JSON form: seconds with up to nine fractional digits and an
# "s" suffix. A negative duration is refused (no minus sign accepted).
_DURATION = re.compile(r"([0-9]{1,12})(\.[0-9]{1,9})?s")


def _retry_delay(details: list[Any]) -> float | None:
    """The provider's requested retry delay, from the first google.rpc ``RetryInfo`` detail
    (``{"@type": "type.googleapis.com/google.rpc.RetryInfo", "retryDelay": "2.5s"}``), or
    None: no such detail, or a ``retryDelay`` that isn't a well-formed non-negative duration.
    Only this structured field is read; nothing is ever derived from message text."""
    for detail in details:
        if isinstance(detail, Mapping) and detail.get("@type") == _RETRY_INFO_TYPE:
            delay = detail.get("retryDelay")
            if isinstance(delay, str) and (match := _DURATION.fullmatch(delay)):
                return float(match.group(1) + (match.group(2) or ""))
            return None
    return None


def _unrecognised_code(err: _ErrorFields, *, is_json: bool) -> str | None:
    """The metric label of a 400 that fell to ``Failed(OTHER)`` without a code the adapter
    knows, or None when its code is a known one (M1-13; labels per M1-15):

    * the body isn't JSON: ``_not_json``;
    * no code (none, null, empty, or google.rpc's HTTP number with no ``status``):
      ``_no_code``;
    * otherwise the code (the Decisions dialect's string ``code``, or, when ``code`` is
      google.rpc's HTTP number, the ``status``) through
      :func:`~guardrail_engine.decision.port.provider_error_label`: casefolded, or
      ``_malformed`` if it isn't 1-64 characters of ``[a-z0-9_]``.

    Only called for a 400 that already fell to ``Failed(OTHER)``.
    """
    if not is_json:
        return ERROR_LABEL_NOT_JSON
    raw = err.code if err.code is not None and not err.code.strip().isdigit() else err.status
    if raw is None or not raw.strip():
        return ERROR_LABEL_NO_CODE
    if raw.strip().casefold() in _KNOWN_400_CODES:
        return None
    return provider_error_label(raw)


def _is_json(content: bytes) -> bool:
    try:
        json.loads(content)
    except (ValueError, UnicodeDecodeError):
        return False
    return True


def _safety_code(err: _ErrorFields) -> str | None:
    """The structured refusal code of a provider refusal, or None when ``err`` isn't one.
    It becomes ``SafetyBlocked.reason``, which the audit record keeps; the message itself is
    never recorded.

    1. M1-13: a ``code`` that is exactly one of :data:`REFUSAL_CODES` (``prohibited_content``,
       ``blocklist``, ``content_blocked``, ``image_safety``), compared case-insensitively,
       gives that code, casefolded (:data:`REFUSAL_PROHIBITED_CONTENT` for the first). Never
       matched on the message (see "Provider refusals" in the module docstring).
    2. As before: the first structured field naming safety (a reason, the status,
       then the code), as the provider wrote it; the documented ``"code": "safety"`` gives
       :data:`REFUSAL_SAFETY`.
    """
    if err.code is not None and (code := err.code.casefold()) in _REFUSAL_CODES:
        return code
    for name in (*err.reasons, err.status, err.code):
        if name and "SAFETY" in name.upper():
            return name
    return None


def _key_in(message: str, questions: Mapping[str, Question]) -> str | None:
    """The question key a limit message names, if it names one we asked."""
    for match in _KEY_IN_MESSAGE.finditer(message):
        if match.group(1) in questions:
            return match.group(1)
    return None
