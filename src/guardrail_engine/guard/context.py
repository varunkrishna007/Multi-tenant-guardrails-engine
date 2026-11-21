"""The signed tenant context: the only source of a check's tenant (AC-T1, design
§Multi-tenancy, Identity).

The platform's API gateway verifies the caller's token and issues a short-lived signed
context naming the tenant. The SDK passes it through unchanged (M1-07). The Guard Service
verifies it on every check and takes the tenant from it, never from the request payload.

:class:`ContextVerifier` is the port. :class:`HmacContextVerifier` is one simple
implementation: HMAC-SHA256 over the tenant id and an expiry, with a key supplied at
construction. A deployment that uses another scheme (for example the API gateway's JWT)
implements the same port.

Token format (``HmacContextVerifier``)::

    v1.<base64url(JSON {"exp": <unix seconds>, "tid": "<tenant id>"})>.<base64url(HMAC)>

The HMAC covers ``"v1." + <payload part>`` and is checked, in constant time, before the
payload is decoded.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import re
import time
from collections.abc import Callable
from dataclasses import InitVar, dataclass, field
from typing import Final, Protocol

# The one tenant id rule (B3), shared with the bundle schema, the store and the
# tenant directory. Re-exported here for callers that import it from this module.
from guardrail_engine.tenant_ids import TENANT_ID_PATTERN as TENANT_ID_PATTERN
from guardrail_engine.tenant_ids import is_valid_tenant_id as is_valid_tenant_id
from guardrail_engine.tenant_scope import TenantScope, issue_scope

TOKEN_VERSION = "v1"
MIN_KEY_BYTES = 32
MAX_TOKEN_CHARS = 4096


_VERIFIED_MINT: Final = object()
"""Passed by the two verifiers (``HmacContextVerifier`` here and ``Ed25519ContextVerifier`` in
``signed_context.py``) when they build a :class:`VerifiedContext`, and by nothing else."""


@dataclass(frozen=True, slots=True)
class VerifiedContext:
    """A signed context that verified. ``tenant_id`` is the only tenant a check may use.

    It is built only by a verifier, after the signature checked: a call without the verifiers'
    private mint raises ``TypeError``, so ``VerifiedContext("t_other", 0).scope`` is not a way
    to make a :class:`~guardrail_engine.tenant_scope.TenantScope` from a string.
    ``tests/test_tenant_scope.py`` also fails on any ``VerifiedContext(`` call outside the two
    verifiers."""

    tenant_id: str
    expires_at: float
    _mint: InitVar[object] = None
    scope: TenantScope = field(init=False, repr=False, compare=False)
    """The tenant as a :class:`~guardrail_engine.tenant_scope.TenantScope`: the only form the
    policy store accepts."""

    def __post_init__(self, _mint: object) -> None:
        if _mint is not _VERIFIED_MINT:
            raise TypeError("a VerifiedContext is built by a signed-context verifier")
        object.__setattr__(self, "scope", issue_scope(self.tenant_id))


class ContextVerificationError(Exception):
    """The signed context did not verify. ``reason`` is one of ``missing``, ``malformed``,
    ``bad_signature``, ``expired``."""

    def __init__(self, reason: str, detail: str = "") -> None:
        self.reason = reason
        self.detail = detail
        super().__init__(f"signed context rejected: {reason}" + (f" ({detail})" if detail else ""))


class ContextVerifier(Protocol):
    def verify(self, signed_context: str) -> VerifiedContext:
        """Return the verified context, or raise :class:`ContextVerificationError`. Must be
        quick and must not block: it runs on every check.

        **Every way a token can be invalid must raise ContextVerificationError**: missing,
        malformed, badly signed, expired, wrong issuer or audience. An implementation that
        wraps a third-party library (a JWT library, say) must map that library's own
        "invalid token" exceptions to it. Any other exception is treated as a fault in the
        Guard Service: the check fails closed as ``block``/``internal_error``, not
        ``forbidden``/``context_invalid``, so it would not reach the per-tenant security
        alert on ``context_invalid`` spikes."""
        ...


def _b64encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


_B64URL = re.compile(r"[A-Za-z0-9_-]*")


def _b64decode(text: str) -> bytes:
    """Strict unpadded base64url: only the URL-safe alphabet, no padding, and the canonical
    spelling (the unused low bits of the last character are zero). So exactly one string
    encodes each value, and no two token strings carry the same signature."""
    if not _B64URL.fullmatch(text) or len(text) % 4 == 1:
        raise ValueError("not canonical unpadded base64url")
    data = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    if _b64encode(data) != text:
        raise ValueError("not canonical unpadded base64url")
    return data


class HmacContextVerifier:
    """Issues and verifies HMAC-SHA256 signed tenant contexts.

    ``key`` is a secret of at least 32 bytes from the secret store. It is never logged and
    never part of ``repr``. ``clock`` returns Unix seconds.
    """

    def __init__(self, key: bytes, *, clock: Callable[[], float] = time.time) -> None:
        if not isinstance(key, bytes) or len(key) < MIN_KEY_BYTES:
            raise ValueError(f"the signing key must be at least {MIN_KEY_BYTES} bytes")
        self.__key = key
        self._clock = clock

    def __repr__(self) -> str:
        return "HmacContextVerifier(key=<redacted>)"

    def _sign(self, signed_part: str) -> bytes:
        return hmac.new(self.__key, signed_part.encode("ascii"), hashlib.sha256).digest()

    def issue(self, tenant_id: str, *, ttl_s: float = 300.0) -> str:
        """A signed context for ``tenant_id`` that expires ``ttl_s`` seconds from now. For
        the issuing side (the API gateway) and tests."""
        _check_tenant_id(tenant_id)
        payload = json.dumps(
            {"exp": int(self._clock() + ttl_s), "tid": tenant_id},
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
        signed_part = f"{TOKEN_VERSION}.{_b64encode(payload)}"
        return f"{signed_part}.{_b64encode(self._sign(signed_part))}"

    def verify(self, signed_context: str) -> VerifiedContext:
        if not isinstance(signed_context, str) or not signed_context:
            raise ContextVerificationError("missing")
        if len(signed_context) > MAX_TOKEN_CHARS or not signed_context.isascii():
            raise ContextVerificationError("malformed", "too long or not ASCII")
        parts = signed_context.split(".")
        if len(parts) != 3 or parts[0] != TOKEN_VERSION:
            raise ContextVerificationError("malformed", "not a v1 signed context")
        signed_part = f"{parts[0]}.{parts[1]}"
        try:
            signature = _b64decode(parts[2])
        except (binascii.Error, ValueError):
            raise ContextVerificationError("malformed", "signature is not base64url") from None
        if not hmac.compare_digest(signature, self._sign(signed_part)):
            raise ContextVerificationError("bad_signature")
        # Only signed bytes are decoded from here on.
        try:
            claims = json.loads(_b64decode(parts[1]))
        except (binascii.Error, ValueError):
            raise ContextVerificationError("malformed", "payload is not JSON") from None
        if not isinstance(claims, dict):
            raise ContextVerificationError("malformed", "payload is not an object")
        tenant_id, expires_at = claims.get("tid"), claims.get("exp")
        if type(expires_at) is not int:
            raise ContextVerificationError("malformed", "exp is not an integer")
        try:
            _check_tenant_id(tenant_id)
        except ValueError as e:
            raise ContextVerificationError("malformed", str(e)) from None
        if self._clock() >= expires_at:
            raise ContextVerificationError("expired")
        return VerifiedContext(
            tenant_id=tenant_id, expires_at=float(expires_at), _mint=_VERIFIED_MINT
        )


def _check_tenant_id(tenant_id: object) -> None:
    if not is_valid_tenant_id(tenant_id):
        raise ValueError(
            f"tenant id must match {TENANT_ID_PATTERN.pattern}, got {_short(tenant_id)}"
        )


def _short(value: object, limit: int = 64) -> str:
    text = repr(value)
    return text if len(text) <= limit else text[:limit] + "..."
