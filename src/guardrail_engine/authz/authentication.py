"""The authentication port of the Admin API (M2-01): a bearer token in, a :class:`Principal`
out, or an :class:`AuthenticationError` with a fixed reason. The OIDC implementation (PyJWT,
pinned algorithms, issuer allowlist, required audience, JWKS key-id pinning) is the adapter in
``signing/adapters/oidc.py``; the REST layer (M2-02) calls this port, then the authorizer."""

from __future__ import annotations

from typing import Protocol

from guardrail_engine.authz.model import Principal

REASONS = frozenset(
    {
        "missing", "malformed", "too_long", "unsupported_algorithm", "unknown_key",
        "bad_signature", "expired", "not_yet_valid", "wrong_issuer", "wrong_audience",
        "missing_claim", "bad_claim", "jwks_unavailable", "operator_not_allowed",
        "tenant_not_allowed",
    }
)  # fmt: skip


class AuthenticationError(Exception):
    """The token did not authenticate. ``reason`` is one of :data:`REASONS`: a fixed word that
    never carries the token or a claim. The REST layer answers 401 for all of them (and 503 for
    ``jwks_unavailable``)."""

    def __init__(self, reason: str) -> None:
        if reason not in REASONS:
            raise ValueError(f"unknown authentication failure {reason!r}")
        self.reason = reason
        super().__init__(f"authentication failed: {reason}")


class Authenticator(Protocol):
    async def authenticate(self, bearer_token: str | None) -> Principal: ...
