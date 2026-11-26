"""The remote checker (M7-10): the SDK's :class:`~guardrail_engine.sdk.client.Checker` that sends
each check to the guard service over HTTP, so the agent runtime holds no provider key and no
database credential.

``connect(url)`` is the one-line switch from the in-process engine. Everything above the
checker (streaming windows, the input gate, retry) is the same code in both modes, and the result
is the same :class:`~guardrail_engine.sdk.result.GuardResult`.

**It can only withhold.** Whatever goes wrong between the runtime and the service, the result is
never an allow:

* the service can't be reached (a connect error, a timeout, a 5xx, a body that isn't the
  contract's, any other status): ``decision`` block, ``reason`` ``model_failure``,
  ``failure_reason`` ``guard_unreachable``, ``retryable`` true. Its own reason says "my guard
  service is down", apart from ``unavailable`` and ``timeout``, which say the provider is;
* the service refuses the body's size (413): a blocked ``content_too_large``, not retryable;
* the service finds the request malformed (400, 415, 431): a blocked ``invalid_request``, not
  retryable.

**Time.** The client waits for the guard point's cap (3 s, 4 s at ``input``: the gateway's own
budget) plus ``margin_s`` (250 ms), because the service already bounds itself to the cap; a
service whose operator set longer budgets needs ``timeouts_s`` to match.

A caller who is cancelled closes the request, and the service cancels the check.
"""

from __future__ import annotations

import asyncio
import logging
import os
import uuid
from collections.abc import Iterable, Mapping
from dataclasses import replace

import httpx

from guardrail_engine.guard.request import CheckContext
from guardrail_engine.policy.schema import GUARD_POINTS
from guardrail_engine.sdk.client import Guard
from guardrail_engine.sdk.result import FailureReason, GuardResult
from guardrail_engine.service.wire import (
    CHECK_PATH,
    CONTEXT_HEADER,
    REQUEST_ID_HEADER,
    WireError,
    request_to_body,
    result_from_wire,
)

logger = logging.getLogger(__name__)

CREDENTIAL_VARIABLES = ("GEMINI_API_KEY", "GUARDRAIL_PG_DSN", "GUARDRAIL_PG_OPERATOR_DSN")
"""The environment variables the engine reads a provider key or a database DSN from
(``engine/factory.py``: ``API_KEY_ENV``, ``PG_DSN_ENV``, ``PG_OPERATOR_DSN_ENV``; a test keeps
the two lists equal). A runtime that checks through the guard service has none of them."""
CREDENTIAL_PREFIXES = ("GEMINI_KEY_",)
"""A dedicated Gemini project's key variable (``GEMINI_KEY_<LABEL>``, M5-06)."""
DEFAULT_TIMEOUT_S = 3.0
INPUT_TIMEOUT_S = 4.0
DEFAULT_MARGIN_S = 0.25
DEFAULT_MAX_CONNECTIONS = 64
MAX_CONTEXT_CHARS = 4096


class RemoteChecker:
    """Sends each check to the guard service at ``base_url``.

    ``client`` is an ``httpx.AsyncClient`` to use (tests pass one over an ASGI transport); by
    default one is built with a pool of ``max_connections`` (keep it at least the most checks
    the runtime has in flight) and closed by :meth:`aclose`. The checker holds no secret: the
    signed context is the caller's, per request."""

    def __init__(
        self,
        base_url: str,
        *,
        client: httpx.AsyncClient | None = None,
        margin_s: float = DEFAULT_MARGIN_S,
        timeouts_s: Mapping[str, float] | None = None,
        max_connections: int = DEFAULT_MAX_CONNECTIONS,
    ) -> None:
        if margin_s < 0 or max_connections < 1:
            raise ValueError("margin_s must be >= 0 and max_connections >= 1")
        self._margin_s = margin_s
        self._timeouts = {"input": INPUT_TIMEOUT_S, **(timeouts_s or {})}
        self._owns_client = client is None
        self._client = client or httpx.AsyncClient(
            base_url=base_url,
            limits=httpx.Limits(max_connections=max_connections),
        )
        self._base_url = base_url

    def __repr__(self) -> str:
        return "RemoteChecker()"

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    def _timeout(self, guard_point: object) -> float:
        cap = (
            self._timeouts.get(guard_point, DEFAULT_TIMEOUT_S)
            if isinstance(guard_point, str)
            else DEFAULT_TIMEOUT_S
        )
        return cap + self._margin_s

    async def check(self, ctx: CheckContext, guard_point: str, content: str) -> GuardResult:
        request_id = ctx.request_id or uuid.uuid4().hex
        point = _label(guard_point)
        if not isinstance(guard_point, str) or guard_point not in GUARD_POINTS:
            # The engine would block it as invalid_request; so does the client, without a call:
            # a guard point that isn't one of the five can't be matched against an answer.
            return _withheld(request_id, point, "invalid_request")
        signed = ctx.signed_context
        if (
            not isinstance(signed, str)
            or not 0 < len(signed) <= MAX_CONTEXT_CHARS
            or not signed.isascii()
            or not signed.isprintable()
        ):
            signed = ""  # the service answers a missing context as it does a malformed one
        try:
            body = request_to_body(
                guard_point,
                content,
                conversation=ctx.conversation,
                conversation_id=ctx.conversation_id,
                tool=ctx.tool,
                request_id=request_id,
            )
            timeout = self._timeout(guard_point)
            # httpx's timeout is per read, so a response dripped a few bytes at a time would
            # never expire; this bounds the whole exchange, the body's reading included.
            async with asyncio.timeout(timeout):
                response = await self._client.post(
                    CHECK_PATH,
                    json=body,
                    headers={CONTEXT_HEADER: signed, REQUEST_ID_HEADER: request_id},
                    timeout=timeout,
                    follow_redirects=False,  # the context is a bearer token: never to another host
                )
            return self._result_of(
                response,
                request_id,
                point,
                asked=guard_point,
            )
        except Exception as exc:  # whatever happens, the content is withheld, never an error
            logger.warning("the guard service could not be used (%s)", type(exc).__name__)
            return self._unreachable(request_id, point)

    def _result_of(
        self, response: httpx.Response, request_id: str, point: str, *, asked: str
    ) -> GuardResult:
        """The answer to this request, or ``guard_unreachable``. Accepted only if the status
        agrees with the decision (200 for everything but ``forbidden``; 401 or 403 only with it)
        and the body is the contract's answer to this request and this guard point."""
        status = response.status_code
        if status in (200, 401, 403):
            # A 401 is answered before the service reads the body, so its guard point is the
            # service's placeholder: only the request id (echoed from the header) is checked, and
            # the result is given the guard point that was asked.
            try:
                result = result_from_wire(
                    response.json(),
                    request_id=request_id,
                    guard_point=None if status == 401 else asked,
                )
            except (WireError, ValueError, RecursionError):
                return self._unreachable(request_id, point)
            if (status == 200) == (result.decision == "forbidden"):
                return self._unreachable(request_id, point)  # the status disagrees with the body
            return replace(result, guard_point=point) if status == 401 else result
        if status == 413:
            return _withheld(request_id, point, "content_too_large")
        if status in (400, 415, 431):
            return _withheld(request_id, point, "invalid_request")
        return self._unreachable(request_id, point)

    @staticmethod
    def _unreachable(request_id: str, point: str) -> GuardResult:
        return GuardResult(
            decision="block",
            reason="model_failure",
            request_id=request_id,
            guard_point=point,
            fired=(),
            retryable=True,
            failure_reason=FailureReason.GUARD_UNREACHABLE,
            capacity_limited=False,
            retry_after_ms=None,
        )


def _label(value: object, limit: int = 64) -> str:
    """How the engine names a guard point in a verdict: the text, cut to 64 characters, or the
    name of its type for anything else."""
    return value[:limit] if isinstance(value, str) else f"<{type(value).__name__}>"


def _withheld(request_id: str, point: str, reason: str) -> GuardResult:
    return GuardResult(
        decision="block",
        reason=reason,
        request_id=request_id,
        guard_point=point,
        fired=(),
        retryable=False,
        failure_reason=None,
        capacity_limited=False,
        retry_after_ms=None,
    )


class CredentialsInRuntimeError(RuntimeError):
    """The runtime's environment holds a provider key or a database DSN, which is what the guard
    service exists to keep out of it. The message names the variables, never a value."""


def credentials_in(
    environ: Mapping[str, str] | None = None, extra: Iterable[str] = ()
) -> list[str]:
    """The names of the variables in ``environ`` (default: the process environment) that hold a
    provider key or a database DSN and are not empty: the engine's own variables, the
    ``GEMINI_KEY_`` convention, and any ``extra`` names the caller gives. Names only.

    **A name the runtime isn't told can't be found.** A dedicated project's ``key_env`` may name
    any variable, so a deployment that uses other names lists them in ``extra``."""
    env = os.environ if environ is None else environ
    names = {*CREDENTIAL_VARIABLES, *extra}
    return sorted(
        name
        for name, value in env.items()
        if value and (name in names or name.startswith(CREDENTIAL_PREFIXES))
    )


def connect(
    base_url: str,
    *,
    environ: Mapping[str, str] | None = None,
    allow_credentials_in_environment: bool = False,
    extra_credential_variables: Iterable[str] = (),
    **options: object,
) -> Guard:
    """A :class:`~guardrail_engine.sdk.client.Guard` whose checks go to the guard service at
    ``base_url``: the one-line switch from the in-process engine (``Guard(engine)``, unchanged).
    ``options`` are :class:`RemoteChecker`'s. Call ``await guard.aclose()`` when done.

    **Remote mode is the one where the runtime holds no provider key and no database
    credential**, so it refuses to start if the environment holds one
    (:class:`CredentialsInRuntimeError`, naming the variables), unless
    ``allow_credentials_in_environment`` says the operator knows. It checks the environment
    variables the engine reads such secrets from, plus ``extra_credential_variables`` (the names a
    deployment configured through ``key_env``); a secret kept anywhere else, under a name the
    runtime isn't told, is not found."""
    held = (
        []
        if allow_credentials_in_environment
        else credentials_in(environ, extra_credential_variables)
    )
    if held:
        raise CredentialsInRuntimeError(
            "this runtime's environment holds " + ", ".join(held) + ": a runtime that checks "
            "through the guard service holds no provider key and no database credential"
        )
    return Guard(RemoteChecker(base_url, **options))  # type: ignore[arg-type]


__all__ = ["CredentialsInRuntimeError", "RemoteChecker", "connect", "credentials_in"]
