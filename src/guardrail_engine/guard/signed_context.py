"""The v2 signed tenant context: Ed25519, key ids, a keyset with validity windows (M2-01).

The API gateway verifies the caller's token and **signs** a short-lived context naming the
tenant. The Guard Service **verifies** it with public keys only, so a compromised Guard Service
host cannot mint a context for another tenant (it could with the v1 HMAC scheme, which shares
one secret between issuer and verifier). Decided 2026-11-17 (backlog M2-01).

Token format::

    v2.<kid>.<base64url(JSON payload)>.<base64url(Ed25519 signature)>

* ``kid`` names the signing key: 1-32 characters of ``[A-Za-z0-9_-]``.
* The payload is canonical JSON (sorted keys, no spaces) with **exactly** these fields:
  ``tid`` (the tenant id, the one shared pattern), ``iat`` and ``exp`` (Unix seconds,
  integers), ``aud`` (``"guard-service"``) and ``iss`` (the issuing gateway). Any other field,
  and any missing one, is refused.
* The signature covers ``"v2." + kid + "." + <payload part>`` and is checked **before** the
  payload is decoded. There is no ``alg`` header: the algorithm is the scheme, so there is
  nothing for a caller to confuse.
* base64url is strict and canonical (as in v1), and a token is at most 4,096 characters.

**Lifetime and skew.** An issuer's default lifetime is 300 s. The verifier refuses a token whose
``exp - iat`` exceeds 600 s, and allows 30 s of clock skew either way: a token issued up to 30 s
in the future, or expired up to 30 s ago, still verifies.

**Keyset and rotation without downtime.** The verifier holds a :class:`Keyset`: public keys,
each with a validity window (``valid_from``, ``valid_until``) and a ``may_verify`` switch. A
key **verifies a token only if the token was issued inside the key's window** (give or take the
skew): ``valid_from - skew <= iat <= valid_until + skew``. Rotation is three steps:

1. add the new public key to every verifier's keyset (``valid_from`` in the near future);
2. switch the gateway to sign with the new ``kid``;
3. remove the old key once ``valid_until + max lifetime + skew`` has passed (about 11 minutes).
   The verifier also stops accepting a key by itself after that time, so a forgotten removal is
   not a standing hole.

Both keys verify during the overlap. :class:`KeysetRefresher` re-reads the keyset from a source
(the secret manager) every 60 s; a document that fails to parse **keeps the last good keyset**
and calls the alert hook. ``verify`` never does I/O.

The v1 :class:`~guardrail_engine.guard.context.HmacContextVerifier` is unchanged and still
passes the same port, for tests and for deployments that have not rotated yet.
"""

from __future__ import annotations

import json
import re
import time
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass
from typing import Any, Protocol

from guardrail_engine.guard.context import (
    _VERIFIED_MINT,
    MAX_TOKEN_CHARS,
    ContextVerificationError,
    ContextVerifier,
    VerifiedContext,
    _b64decode,
    _b64encode,
    _check_tenant_id,
)
from guardrail_engine.tenant_ids import is_valid_tenant_id

TOKEN_VERSION = "v2"
AUDIENCE = "guard-service"
DEFAULT_TTL_S = 300.0
MAX_LIFETIME_S = 600
SKEW_S = 30
KID_PATTERN = re.compile(r"[A-Za-z0-9_-]{1,32}")
ISSUER_PATTERN = re.compile(r"[A-Za-z0-9_.:/-]{1,64}")
KEYSET_REFRESH_S = 60.0
PAYLOAD_FIELDS = frozenset({"tid", "iat", "exp", "aud", "iss"})
RETIRE_AFTER_S = MAX_LIFETIME_S + SKEW_S
"""A key stops verifying this long after its ``valid_until``: no token it signed can be live."""


class SignatureVerifier(Protocol):
    """A public key. The Ed25519 implementation is in ``signing/adapters/ed25519.py``."""

    def verify(self, signature: bytes, data: bytes) -> bool: ...


class Signer(Protocol):
    """A private key: the issuing side's only secret."""

    def sign(self, data: bytes) -> bytes: ...


@dataclass(frozen=True, slots=True)
class KeyEntry:
    """One verification key and when tokens signed with it may have been issued."""

    kid: str
    verifier: SignatureVerifier
    valid_from: float
    valid_until: float | None = None
    may_verify: bool = True

    def __post_init__(self) -> None:
        if not KID_PATTERN.fullmatch(self.kid):
            raise ValueError(f"kid must match {KID_PATTERN.pattern}")
        if self.valid_until is not None and self.valid_until < self.valid_from:
            raise ValueError("valid_until is before valid_from")

    def __repr__(self) -> str:
        return f"KeyEntry(kid={self.kid!r})"


class Keyset:
    """An immutable set of verification keys, looked up by ``kid``."""

    def __init__(self, keys: Iterable[KeyEntry]) -> None:
        by_kid: dict[str, KeyEntry] = {}
        for key in keys:
            if key.kid in by_kid:
                raise ValueError(f"duplicate kid {key.kid!r}")
            by_kid[key.kid] = key
        if not by_kid:
            raise ValueError("a keyset needs at least one key")
        self._keys = by_kid

    def get(self, kid: str) -> KeyEntry | None:
        return self._keys.get(kid)

    def kids(self) -> tuple[str, ...]:
        return tuple(sorted(self._keys))

    @classmethod
    def parse(cls, text: str, load_key: Callable[[bytes], SignatureVerifier]) -> Keyset:
        """From the secret manager's JSON document::

            {"keys": [{"kid": "k1", "x": "<base64url of the 32-byte public key>",
                       "valid_from": 1700000000, "valid_until": null, "may_verify": true}]}

        ``load_key`` turns the 32 raw bytes into a verifier (the composition root passes the
        Ed25519 adapter's ``from_raw``); it raises ``ValueError`` for a bad key. Raises
        ``ValueError`` for anything else (unknown fields, a bad key, a wrong type)."""
        try:
            doc = json.loads(text)
        except ValueError:
            raise ValueError("keyset is not JSON") from None
        if not isinstance(doc, dict) or set(doc) != {"keys"} or not isinstance(doc["keys"], list):
            raise ValueError('keyset must be {"keys": [...]}')
        entries = []
        for item in doc["keys"]:
            if not isinstance(item, dict) or not {"kid", "x", "valid_from"} <= set(item):
                raise ValueError("a key needs kid, x and valid_from")
            if set(item) - {"kid", "x", "valid_from", "valid_until", "may_verify"}:
                raise ValueError("a key has an unknown field")
            valid_from, valid_until = item["valid_from"], item.get("valid_until")
            may_verify = item.get("may_verify", True)
            if (
                type(valid_from) not in (int, float)
                or (valid_until is not None and type(valid_until) not in (int, float))
                or type(may_verify) is not bool
                or not isinstance(item["kid"], str)
                or not isinstance(item["x"], str)
            ):
                raise ValueError("a key field has the wrong type")
            try:
                public = load_key(_b64decode(item["x"]))
            except ValueError:
                raise ValueError("a key is not a 32-byte Ed25519 public key") from None
            entries.append(KeyEntry(item["kid"], public, float(valid_from),
                                    None if valid_until is None else float(valid_until),
                                    may_verify))  # fmt: skip
        return cls(entries)


class Ed25519ContextSigner:
    """The issuing side (the API gateway; tests). Holds the one private key it signs with.

    ``private_key`` is never logged and not part of ``repr``."""

    def __init__(
        self,
        private_key: Signer,
        kid: str,
        issuer: str,
        *,
        audience: str = AUDIENCE,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if not KID_PATTERN.fullmatch(kid):
            raise ValueError(f"kid must match {KID_PATTERN.pattern}")
        if not ISSUER_PATTERN.fullmatch(issuer):
            raise ValueError(f"issuer must match {ISSUER_PATTERN.pattern}")
        self.__key = private_key
        self.kid = kid
        self.issuer = issuer
        self.audience = audience
        self._clock = clock

    def __repr__(self) -> str:
        return f"Ed25519ContextSigner(kid={self.kid!r}, key=<redacted>)"

    def issue(self, tenant_id: str, *, ttl_s: float = DEFAULT_TTL_S) -> str:
        _check_tenant_id(tenant_id)
        if not 0 < ttl_s <= MAX_LIFETIME_S:
            raise ValueError(f"ttl_s must be in (0, {MAX_LIFETIME_S}]")
        now = int(self._clock())
        payload = json.dumps(
            {"aud": self.audience, "exp": now + int(ttl_s), "iat": now, "iss": self.issuer,
             "tid": tenant_id},
            separators=(",", ":"), sort_keys=True,
        ).encode()  # fmt: skip
        signed_part = f"{TOKEN_VERSION}.{self.kid}.{_b64encode(payload)}"
        signature = self.__key.sign(signed_part.encode("ascii"))
        return f"{signed_part}.{_b64encode(signature)}"


class Ed25519ContextVerifier:
    """The :class:`~guardrail_engine.guard.context.ContextVerifier` for v2 tokens.

    ``issuers`` is the set of gateway names accepted. ``keyset`` can be replaced at any time with
    :meth:`set_keyset` (a refresher does this); the swap is atomic and ``verify`` does no I/O."""

    def __init__(
        self,
        keyset: Keyset,
        issuers: Iterable[str],
        *,
        audience: str = AUDIENCE,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._keyset = keyset
        self._issuers = frozenset(issuers)
        if not self._issuers:
            raise ValueError("at least one issuer must be accepted")
        self._audience = audience
        self._clock = clock

    def __repr__(self) -> str:
        return f"Ed25519ContextVerifier(kids={self._keyset.kids()})"

    @property
    def keyset(self) -> Keyset:
        return self._keyset

    def set_keyset(self, keyset: Keyset) -> None:
        self._keyset = keyset

    def verify(self, signed_context: str) -> VerifiedContext:
        if not isinstance(signed_context, str) or not signed_context:
            raise ContextVerificationError("missing")
        if len(signed_context) > MAX_TOKEN_CHARS or not signed_context.isascii():
            raise ContextVerificationError("malformed", "too long or not ASCII")
        parts = signed_context.split(".")
        if len(parts) != 4 or parts[0] != TOKEN_VERSION:
            raise ContextVerificationError("malformed", "not a v2 signed context")
        _, kid, payload_part, signature_part = parts
        if not KID_PATTERN.fullmatch(kid):
            raise ContextVerificationError("malformed", "bad key id")
        try:
            signature = _b64decode(signature_part)
        except ValueError:
            raise ContextVerificationError("malformed", "signature is not base64url") from None
        key = self._keyset.get(kid)
        if key is None or not key.may_verify:
            raise ContextVerificationError("unknown_key")
        signed = f"{TOKEN_VERSION}.{kid}.{payload_part}".encode("ascii")
        if not key.verifier.verify(signature, signed):
            raise ContextVerificationError("bad_signature")
        # Only signed bytes are decoded from here on.
        claims = self._claims(payload_part)
        now = self._clock()
        iat, exp = claims["iat"], claims["exp"]
        if exp <= iat or exp - iat > MAX_LIFETIME_S:
            raise ContextVerificationError("malformed", "lifetime out of range")
        if iat > now + SKEW_S:
            raise ContextVerificationError("not_yet_valid")
        if now >= exp + SKEW_S:
            raise ContextVerificationError("expired")
        if iat < key.valid_from - SKEW_S or (
            key.valid_until is not None and iat > key.valid_until + SKEW_S
        ):
            raise ContextVerificationError("unknown_key", "issued outside the key's window")
        if key.valid_until is not None and now > key.valid_until + RETIRE_AFTER_S:
            raise ContextVerificationError("unknown_key", "key retired")
        if claims["aud"] != self._audience:
            raise ContextVerificationError("wrong_audience")
        if claims["iss"] not in self._issuers:
            raise ContextVerificationError("wrong_issuer")
        return VerifiedContext(tenant_id=claims["tid"], expires_at=float(exp), _mint=_VERIFIED_MINT)

    @staticmethod
    def _claims(payload_part: str) -> dict[str, Any]:
        try:
            claims = json.loads(_b64decode(payload_part))
        except ValueError:
            raise ContextVerificationError("malformed", "payload is not JSON") from None
        if not isinstance(claims, dict):
            raise ContextVerificationError("malformed", "payload is not an object")
        if set(claims) != PAYLOAD_FIELDS:
            raise ContextVerificationError("malformed", "payload fields are not exactly the v2 set")
        if type(claims["iat"]) is not int or type(claims["exp"]) is not int:
            raise ContextVerificationError("malformed", "iat and exp must be integers")
        if not isinstance(claims["aud"], str) or not isinstance(claims["iss"], str):
            raise ContextVerificationError("malformed", "aud and iss must be strings")
        if not is_valid_tenant_id(claims["tid"]):
            raise ContextVerificationError("malformed", "tid is not a tenant id")
        return claims


class VersionedContextVerifier:
    """Verifies v2 tokens, and v1 HMAC tokens only while a migration allows it.

    A token starting ``v2.`` goes to the v2 verifier. A token starting ``v1.`` goes to the v1
    verifier if one was given; with none, it is refused (``unsupported_version``). The engine
    factory builds this only when ``signed_context.allow_v1_hmac`` is set, and in production
    refuses a v1 verifier otherwise (:func:`accepts_v1`)."""

    def __init__(self, v2: ContextVerifier, v1: ContextVerifier | None = None) -> None:
        self.v2 = v2
        self.v1 = v1

    def verify(self, signed_context: str) -> VerifiedContext:
        if isinstance(signed_context, str) and signed_context.startswith("v1."):
            if self.v1 is None:
                raise ContextVerificationError("unsupported_version")
            return self.v1.verify(signed_context)
        return self.v2.verify(signed_context)


def accepts_v1(verifier: object) -> bool:
    """Whether ``verifier`` would accept a v1 HMAC context: a v1 verifier itself, or a
    :class:`VersionedContextVerifier` holding one."""
    from guardrail_engine.guard.context import HmacContextVerifier

    if isinstance(verifier, HmacContextVerifier):
        return True
    return isinstance(verifier, VersionedContextVerifier) and verifier.v1 is not None


class KeysetSource(Protocol):
    async def read(self) -> str:
        """The keyset document (the secret manager's current value)."""
        ...


class KeysetRefresher:
    """Re-reads the keyset every :data:`KEYSET_REFRESH_S` seconds and swaps it into the verifier.

    A document that fails to read or parse **keeps the last good keyset** and calls ``alert``
    (with a short fixed reason, never the document). ``refresh_once`` is the unit a test calls;
    ``run`` loops until cancelled."""

    def __init__(
        self,
        verifier: Ed25519ContextVerifier,
        source: KeysetSource,
        load_key: Callable[[bytes], SignatureVerifier],
        *,
        alert: Callable[[str], None] = lambda reason: None,
        interval_s: float = KEYSET_REFRESH_S,
        sleep: Callable[[float], Awaitable[None]] | None = None,
    ) -> None:
        import asyncio

        self._verifier = verifier
        self._source = source
        self._load_key = load_key
        self._alert = alert
        self._interval_s = interval_s
        self._sleep = sleep or asyncio.sleep
        self._task: Any = None

    async def refresh_once(self) -> bool:
        """True if the verifier now holds a freshly read keyset."""
        try:
            keyset = Keyset.parse(await self._source.read(), self._load_key)
        except ValueError:
            self._alert("keyset_invalid")
            return False
        except Exception:
            self._alert("keyset_unreadable")
            return False
        self._verifier.set_keyset(keyset)
        return True

    async def run(self) -> None:
        while True:
            await self.refresh_once()
            await self._sleep(self._interval_s)

    def start(self) -> None:
        """Run :meth:`run` as a background task until :meth:`aclose`."""
        import asyncio

        if self._task is None:
            self._task = asyncio.ensure_future(self.run())

    async def aclose(self) -> None:
        """Stop the background task (the engine closes it at shutdown). Safe to call twice."""
        import asyncio

        task, self._task = self._task, None
        if task is None:
            return
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            return


__all__ = [
    "AUDIENCE",
    "Ed25519ContextSigner",
    "Ed25519ContextVerifier",
    "KeyEntry",
    "Keyset",
    "KeysetRefresher",
    "KeysetSource",
    "SignatureVerifier",
    "Signer",
    "VersionedContextVerifier",
    "accepts_v1",
]
