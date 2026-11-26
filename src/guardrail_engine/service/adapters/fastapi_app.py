"""The check listener of the guard service (M7-10): ``POST /v1/check`` and ``GET /healthz``,
and no other route. The wire contract is in :mod:`guardrail_engine.service.wire`.

**What it adds to the engine, and no more.** It authenticates with the signed context the engine
already verifies, parses the body, bounds its size, runs ``Engine.check`` and returns the public
result. It reads no tenant id from anywhere but the verified context, and it holds no policy,
key or state of its own.

* **A context that is missing, malformed (not ASCII, over 4,096 characters, or with control
  characters) or rejected by the engine is a 401** with the public ``forbidden`` result: the same
  ``context_invalid`` the in-process call gives, with no detail. A missing or malformed header is
  decided **before the body is read**, by running the check with an empty context: the engine's
  forbidden verdict (and its audit record, with no tenant) is the same as in process.
* **Limits.** The headers' total size, then the body (by ``Content-Length``, and again while
  reading, for a body with none), are capped; over the header cap is a 431 and over the body cap
  a 413 (the client reads it as a blocked ``content_too_large``). A body that isn't a JSON object
  of the contract's members is a 400; a body that isn't ``application/json`` a 415.
* **Disconnect.** If the client goes away while its check runs, the check is cancelled: the
  engine releases what it holds for it (a repeat-attempt slot, queued admission), and a provider
  call already in flight is left to end, as when a caller cancels in process.
* **Health is liveness only.** ``GET /healthz`` answers ``{"status": "ok"}`` while the process
  serves. It shows no tenant, policy, breaker or key state; those are on the Admin API.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, Protocol

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

from guardrail_engine.guard.context import MAX_TOKEN_CHARS
from guardrail_engine.guard.request import CheckContext
from guardrail_engine.sdk.result import GuardResult
from guardrail_engine.service.wire import (
    CHECK_PATH,
    CONTEXT_HEADER,
    HEALTH_PATH,
    MAX_REQUEST_ID_CHARS,
    REQUEST_ID_HEADER,
    WireError,
    check_context,
    request_from_body,
    result_to_wire,
)

logger = logging.getLogger(__name__)

DEFAULT_MAX_BODY_BYTES = 4 * 1024 * 1024
"""A body over this is a 413. The runner derives the figure from the platform's largest
content (the chunk cap times the chunk size, plus the conversation); this is the default of an
app built without it."""
DEFAULT_MAX_HEADER_BYTES = 16 * 1024
DISCONNECT_POLL_S = 0.1

_HEADERS = {"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"}


class Checker(Protocol):
    """What the app runs: the engine's check."""

    async def check(self, ctx: CheckContext, guard_point: str, content: str) -> Any: ...


def _error(status: int, code: str) -> JSONResponse:
    return JSONResponse({"error": {"code": code}}, status_code=status, headers=_HEADERS)


class _Disconnected(Exception):
    pass


async def _until_disconnected(request: Request, work: Any) -> Any:
    """Run ``work`` (a coroutine); cancel it if the client goes away first."""
    task = asyncio.ensure_future(work)
    try:
        while True:
            done, _ = await asyncio.wait({task}, timeout=DISCONNECT_POLL_S)
            if done:
                return task.result()
            if await request.is_disconnected():
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
                raise _Disconnected
    except asyncio.CancelledError:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        raise


def _header_bytes(request: Request) -> int:
    return sum(len(k) + len(v) + 4 for k, v in request.scope.get("headers", ()))


def _well_formed(token: str | None) -> str:
    """The header's value if it can be a signed context at all, else the empty string, which
    the engine rejects as a missing one."""
    if (
        token is None
        or not 0 < len(token) <= MAX_TOKEN_CHARS
        or not token.isascii()
        or not token.isprintable()
    ):
        return ""
    return token


class _TooLarge(Exception):
    pass


class _BadLength(Exception):
    pass


async def _read_body(request: Request, limit: int) -> bytes:
    """The body, at most ``limit`` bytes. Raises :class:`_BadLength` for a ``Content-Length``
    that isn't a number and :class:`_TooLarge` past the limit, declared or read."""
    declared = request.headers.get("content-length")
    if declared is not None:
        if not declared.isascii() or not declared.isdigit():
            raise _BadLength
        if int(declared) > limit:
            raise _TooLarge
    body = bytearray()
    async for part in request.stream():
        body += part
        if len(body) > limit:
            raise _TooLarge
    return bytes(body)


def _request_id_of(request: Request) -> tuple[str | None, bool]:
    """The ``Guard-Request-Id`` header's value and whether it is acceptable: printable ASCII,
    1 to 128 characters. Absent is ``(None, True)``."""
    values = request.headers.getlist(REQUEST_ID_HEADER)
    if not values:
        return None, True
    value = values[0]
    ok = (
        len(values) == 1
        and 0 < len(value) <= MAX_REQUEST_ID_CHARS
        and value.isascii()
        and value.isprintable()
    )
    return (value if ok else None), ok


def _status_of(result: GuardResult) -> int:
    if result.decision != "forbidden":
        return 200
    return 401 if result.reason == "context_invalid" else 403


def create_check_app(
    engine: Checker,
    *,
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
    max_header_bytes: int = DEFAULT_MAX_HEADER_BYTES,
) -> FastAPI:
    if max_body_bytes < 1 or max_header_bytes < 1:
        raise ValueError("max_body_bytes and max_header_bytes must be at least 1")
    app = FastAPI(title="Guard check", docs_url=None, redoc_url=None, openapi_url=None)

    async def respond(verdict: Any) -> JSONResponse:
        result = GuardResult.from_verdict(verdict)
        return JSONResponse(
            result_to_wire(result), status_code=_status_of(result), headers=_HEADERS
        )

    @app.get(HEALTH_PATH)
    async def health() -> Response:
        return JSONResponse({"status": "ok"}, headers=_HEADERS)

    @app.post(CHECK_PATH)
    async def check(request: Request) -> Response:
        try:
            if _header_bytes(request) > max_header_bytes:
                return _error(431, "headers_too_large")
            contexts = request.headers.getlist(CONTEXT_HEADER)
            # Two context headers on one request are ambiguous (a proxy may append rather than
            # replace): malformed, like any other.
            signed = _well_formed(contexts[0] if len(contexts) == 1 else None)
            header_id, header_id_ok = _request_id_of(request)
            if not signed:
                # Decided before the body is read; the engine's forbidden verdict is what an
                # in-process call with no context gets, with the caller's request id echoed.
                verdict = await _until_disconnected(
                    request,
                    engine.check(
                        CheckContext(signed_context="", request_id=header_id), "input", ""
                    ),
                )
                return await respond(verdict)
            if not request.headers.get("content-type", "").lower().startswith("application/json"):
                return _error(415, "unsupported_media_type")
            try:
                raw = await _read_body(request, max_body_bytes)
            except _TooLarge:
                return _error(413, "body_too_large")
            except _BadLength:
                return _error(400, "invalid_body")
            try:
                guard_point, content, members = request_from_body(json.loads(raw))
            except (WireError, ValueError, RecursionError):
                return _error(400, "invalid_body")
            if not header_id_ok or (
                REQUEST_ID_HEADER.lower() in request.headers and members["request_id"] != header_id
            ):
                return _error(400, "invalid_body")  # the header and the body disagree
            verdict = await _until_disconnected(
                request,
                engine.check(check_context(signed, members), guard_point, content),
            )
            return await respond(verdict)
        except _Disconnected:
            return Response(status_code=499)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("the check endpoint failed")
            return _error(500, "internal_error")

    return app
