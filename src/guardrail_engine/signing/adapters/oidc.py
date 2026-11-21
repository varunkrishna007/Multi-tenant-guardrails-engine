"""OIDC bearer-token authentication on PyJWT (M2-01; decided 2026-11-17).

What is pinned, so a token cannot choose how it is checked:

* **Algorithms: RS256 and ES256 only.** ``none``, every HMAC algorithm and anything else is
  refused before a key is looked at (the classic algorithm-confusion attack signs with HS256
  using the public key as the secret). The header's algorithm must also fit the key's type.
* **Keys: pinned by ``kid`` to the JWKS.** No ``kid``, or a ``kid`` the JWKS does not hold, is
  refused; an unknown ``kid`` triggers one refresh of the JWKS, at most every 30 s. Only RSA and
  EC keys marked for signatures are used. A JWK that names an ``alg`` must match the header.
* **Issuer: an allowlist, and each issuer has a kind.** A ``platform`` issuer is
  platform-controlled and the only kind whose ``platform_operator`` claim counts. A ``tenant``
  issuer (for example a customer's SSO) is bound to a fixed set of tenant ids: a token that
  claims any other tenant, or claims to be an operator, is refused. An issuer listed as both
  is refused when the config is built. Each issuer has its own JWKS, so one issuer's key can't
  sign for another. **Audience: required**, and must be this API's. ``exp``, ``iat``,
  ``iss``, ``aud`` and ``sub`` are required; 30 s of clock leeway.
* A token over :data:`MAX_TOKEN_CHARS` is refused before it is parsed.

**Machine tokens (M5-02).** R2's two people are two humans, so the engine has to know
which tokens are machines. Each issuer says how its machine tokens are marked
(:class:`MachineMarker`, in ``OidcConfig.machine_markers``): a claim name and the value it has on
a machine token, or ``gty`` values (``client-credentials`` for the OAuth client-credentials
grant), or an explicit declaration that the issuer issues human tokens only. An issuer with
none of these gets the test default (the ``service_account`` claim is ``true``, or ``gty`` is
``client-credentials``), which the engine's startup refuses in production and staging
(:meth:`OidcConfig.unmarked_issuers`).

Claims become a :class:`~guardrail_engine.authz.model.Principal`: ``sub``; ``tenant_id`` (the
shared id pattern; required unless the caller is a platform operator); ``roles`` (a list; names
that are not one of the four roles grant nothing); ``platform_operator`` (only the JSON value
``true`` counts). Claim names are configurable. Failures carry a fixed reason, never the token.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Protocol

import jwt
from jwt import PyJWK

from guardrail_engine.authz.authentication import AuthenticationError
from guardrail_engine.authz.model import Principal, Role
from guardrail_engine.tenant_ids import is_valid_tenant_id

ALGORITHMS = ("RS256", "ES256")
KEY_TYPES = {"RS256": "RSA", "ES256": "EC"}
MAX_TOKEN_CHARS = 8192
LEEWAY_S = 30
JWKS_MIN_REFRESH_S = 30.0
MAX_SUBJECT_CHARS = 256
MAX_ISSUER_CHARS = 512
REQUIRED_CLAIMS = ("exp", "iat", "iss", "aud", "sub")


class JwksSource(Protocol):
    async def fetch(self) -> Mapping[str, Any]:
        """The provider's JWKS document (``{"keys": [...]}``). Raises on failure."""
        ...


class StaticJwksSource:
    def __init__(self, document: Mapping[str, Any]) -> None:
        self.document = document
        self.fetches = 0

    async def fetch(self) -> Mapping[str, Any]:
        self.fetches += 1
        return self.document


class HttpJwksSource:
    """Fetches the JWKS over HTTPS. ``url`` comes from configuration, never from a token."""

    def __init__(self, url: str, client: Any, timeout_s: float = 5.0) -> None:
        if not url.startswith("https://"):
            raise ValueError("a JWKS url must be https")
        self._url, self._client, self._timeout_s = url, client, timeout_s

    async def fetch(self) -> Mapping[str, Any]:
        response = await self._client.get(self._url, timeout=self._timeout_s)
        response.raise_for_status()
        return response.json()


DEFAULT_SERVICE_ACCOUNT_CLAIM = "service_account"
CLIENT_CREDENTIALS_GTY = "client-credentials"
MAX_MARKER_CHARS = 256


@dataclass(frozen=True, slots=True)
class MachineMarker:
    """How one issuer marks the tokens of machine identities (a service account): exactly one of

    * ``claim`` (with ``value``, ``True`` by default): the token is a machine's when the claim has
      this value (a string claim can be a list that contains it);
    * ``gty``: the token's ``gty`` claim is one of these (for example ``client-credentials``);
    * ``humans_only``: the issuer issues tokens for people only, so no token is a machine's.

    ``claim`` and ``gty`` may be set together (either one marks a machine).
    """

    claim: str | None = None
    value: bool | str = True
    gty: frozenset[str] = frozenset()
    humans_only: bool = False

    def __post_init__(self) -> None:
        if self.humans_only and (self.claim is not None or self.gty):
            raise ValueError("an issuer that issues humans only has no machine marker")
        if not self.humans_only and self.claim is None and not self.gty:
            raise ValueError("a machine marker needs a claim, gty values, or humans_only")
        if self.claim is not None and not 1 <= len(self.claim) <= MAX_MARKER_CHARS:
            raise ValueError("the machine claim name must be 1 to 256 characters")
        if isinstance(self.value, str) and not 1 <= len(self.value) <= MAX_MARKER_CHARS:
            raise ValueError("the machine claim value must be 1 to 256 characters")
        if not all(isinstance(g, str) and 1 <= len(g) <= MAX_MARKER_CHARS for g in self.gty):
            raise ValueError("gty values are non-empty strings")
        object.__setattr__(self, "gty", frozenset(self.gty))

    def is_machine(self, claims: Mapping[str, Any]) -> bool:
        if self.humans_only:
            return False
        if self.gty and claims.get("gty") in self.gty:
            return True
        if self.claim is None or self.claim not in claims:
            return False
        got = claims[self.claim]
        if isinstance(self.value, bool):
            return got is self.value
        return got == self.value or (isinstance(got, list) and self.value in got)


@dataclass(frozen=True, slots=True)
class OidcConfig:
    platform_issuers: frozenset[str]
    """Issuers the platform controls. Only these may grant ``platform_operator``."""
    audience: str
    tenant_issuers: Mapping[str, frozenset[str]] = field(default_factory=dict)
    """Issuer -> the tenant ids it may name (non-empty). A token from it must carry one of them."""
    tenant_claim: str = "tenant_id"
    roles_claim: str = "roles"
    operator_claim: str = "platform_operator"
    machine_markers: Mapping[str, MachineMarker] = field(default_factory=dict)
    """Issuer -> how it marks machine tokens. An issuer not listed gets the test default:
    a boolean ``service_account`` claim that is ``true``, or ``gty: client-credentials``."""
    leeway_s: int = LEEWAY_S

    def __post_init__(self) -> None:
        if not (self.platform_issuers or self.tenant_issuers) or not self.audience:
            raise ValueError("an OIDC config needs at least one issuer and an audience")
        for issuer in self.issuers:
            # The audit actor is ``<issuer>#<subject>``: a "#" in an issuer would make
            # it ambiguous, and an issuer plus a 256-character subject must fit the column.
            if not issuer or "#" in issuer or len(issuer) > MAX_ISSUER_CHARS:
                raise ValueError(
                    f"an issuer must be 1 to {MAX_ISSUER_CHARS} characters and contain no '#'"
                )
        both = self.platform_issuers & set(self.tenant_issuers)
        if both:
            raise ValueError(
                f"{len(both)} issuer(s) are listed as both platform and tenant; an issuer has "
                "one kind"
            )
        for tenants in self.tenant_issuers.values():
            if not tenants or not all(is_valid_tenant_id(t) for t in tenants):
                raise ValueError("a tenant issuer needs a non-empty set of valid tenant ids")
        unknown = set(self.machine_markers) - self.issuers
        if unknown:
            raise ValueError(f"{len(unknown)} machine marker(s) name an issuer that isn't listed")
        object.__setattr__(self, "tenant_issuers", MappingProxyType(dict(self.tenant_issuers)))
        object.__setattr__(self, "machine_markers", MappingProxyType(dict(self.machine_markers)))

    @property
    def issuers(self) -> frozenset[str]:
        return self.platform_issuers | frozenset(self.tenant_issuers)

    def unmarked_issuers(self) -> list[str]:
        """The issuers with no machine marker and no ``humans_only`` declaration, sorted. In
        production and staging the engine refuses to start with any."""
        return sorted(self.issuers - set(self.machine_markers))


class PyJwtAuthenticator:
    def __init__(
        self,
        config: OidcConfig,
        jwks: JwksSource | Mapping[str, JwksSource],
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        """``jwks`` is one source per issuer. A single source is accepted when the config has
        exactly one issuer: with several, one issuer's keys must not verify another's."""
        if isinstance(jwks, Mapping):
            sources = dict(jwks)
        elif len(config.issuers) == 1:
            sources = {next(iter(config.issuers)): jwks}
        else:
            raise ValueError("several issuers need one JWKS source each (a mapping)")
        if set(sources) != set(config.issuers):
            raise ValueError("there must be a JWKS source for every issuer, and only for them")
        self._config = config
        self._sources = sources
        self._clock = clock
        self._keys: dict[str, dict[str, tuple[PyJWK, str | None]]] = {i: {} for i in sources}
        self._last_fetch: dict[str, float] = dict.fromkeys(sources, float("-inf"))

    def unmarked_issuers(self) -> list[str]:
        """The issuers that say nothing about how their machine tokens are marked; the
        engine's startup asks, and refuses in production and staging when there are any."""
        return self._config.unmarked_issuers()

    async def authenticate(self, bearer_token: str | None) -> Principal:
        if not isinstance(bearer_token, str) or not bearer_token:
            raise AuthenticationError("missing")
        if len(bearer_token) > MAX_TOKEN_CHARS:
            raise AuthenticationError("too_long")
        try:
            header = jwt.get_unverified_header(bearer_token)
        except jwt.PyJWTError:
            raise AuthenticationError("malformed") from None
        algorithm = header.get("alg")
        if algorithm not in ALGORITHMS:
            raise AuthenticationError("unsupported_algorithm")
        kid = header.get("kid")
        if not isinstance(kid, str) or not kid:
            raise AuthenticationError("unknown_key")
        issuer = self._claimed_issuer(bearer_token)
        key, jwk_alg = await self._key(issuer, kid)
        if key.key_type != KEY_TYPES[algorithm] or (jwk_alg is not None and jwk_alg != algorithm):
            raise AuthenticationError("unsupported_algorithm")
        claims = self._decode(bearer_token, key, algorithm, issuer)
        return self._principal(claims, issuer)

    def _claimed_issuer(self, token: str) -> str:
        """The ``iss`` the token claims, read before the signature is checked only to choose
        which issuer's keys to check it with. The signature is then verified against that
        issuer's keys alone, and ``iss`` must equal it."""
        try:
            claims = jwt.decode(token, options={"verify_signature": False})
        except jwt.PyJWTError:
            raise AuthenticationError("malformed") from None
        issuer = claims.get("iss")
        if issuer is None:
            raise AuthenticationError("missing_claim")
        if not isinstance(issuer, str) or issuer not in self._sources:
            raise AuthenticationError("wrong_issuer")
        return issuer

    async def _key(self, issuer: str, kid: str) -> tuple[PyJWK, str | None]:
        if kid not in self._keys[issuer]:
            await self._refresh(issuer)
        key = self._keys[issuer].get(kid)
        if key is None:
            raise AuthenticationError("unknown_key")
        return key

    async def _refresh(self, issuer: str) -> None:
        """Re-read the issuer's JWKS, at most once per :data:`JWKS_MIN_REFRESH_S`."""
        now = self._clock()
        if now - self._last_fetch[issuer] < JWKS_MIN_REFRESH_S:
            return
        self._last_fetch[issuer] = now
        try:
            document = await self._sources[issuer].fetch()
            keys = document["keys"]
            parsed: dict[str, tuple[PyJWK, str | None]] = {}
            for entry in keys:
                if not isinstance(entry, dict) or entry.get("kty") not in {"RSA", "EC"}:
                    continue
                if entry.get("use", "sig") != "sig" or not isinstance(entry.get("kid"), str):
                    continue
                try:
                    alg = entry.get("alg")
                    parsed[entry["kid"]] = (PyJWK(entry), alg if isinstance(alg, str) else None)
                except jwt.PyJWTError:
                    continue
        except Exception:
            raise AuthenticationError("jwks_unavailable") from None
        self._keys[issuer] = parsed

    def _decode(self, token: str, key: PyJWK, algorithm: str, issuer: str) -> dict[str, Any]:
        try:
            return jwt.decode(
                token,
                key.key,
                algorithms=[algorithm],
                audience=self._config.audience,
                issuer=[issuer],
                leeway=self._config.leeway_s,
                options={"require": list(REQUIRED_CLAIMS)},
            )
        except jwt.ExpiredSignatureError:
            raise AuthenticationError("expired") from None
        except jwt.ImmatureSignatureError:
            raise AuthenticationError("not_yet_valid") from None
        except jwt.InvalidIssuerError:
            raise AuthenticationError("wrong_issuer") from None
        except jwt.InvalidAudienceError:
            raise AuthenticationError("wrong_audience") from None
        except jwt.MissingRequiredClaimError:
            raise AuthenticationError("missing_claim") from None
        except jwt.InvalidSignatureError:
            raise AuthenticationError("bad_signature") from None
        except jwt.InvalidAlgorithmError:
            raise AuthenticationError("unsupported_algorithm") from None
        except jwt.PyJWTError:
            raise AuthenticationError("malformed") from None

    def _principal(self, claims: Mapping[str, Any], issuer: str) -> Principal:
        cfg = self._config
        subject = claims["sub"]
        if not isinstance(subject, str) or not 0 < len(subject) <= MAX_SUBJECT_CHARS:
            raise AuthenticationError("bad_claim")
        operator = claims.get(cfg.operator_claim, False) is True
        if cfg.operator_claim in claims and not isinstance(claims[cfg.operator_claim], bool):
            raise AuthenticationError("bad_claim")
        tenant = claims.get(cfg.tenant_claim)
        allowed_tenants = cfg.tenant_issuers.get(issuer)
        if allowed_tenants is not None:  # a tenant issuer: never an operator, only its tenants
            if operator:
                raise AuthenticationError("operator_not_allowed")
            if tenant is None:
                raise AuthenticationError("missing_claim")
            if not is_valid_tenant_id(tenant):
                raise AuthenticationError("bad_claim")
            if tenant not in allowed_tenants:
                raise AuthenticationError("tenant_not_allowed")
        elif tenant is None:
            if not operator:
                raise AuthenticationError("missing_claim")
        elif not is_valid_tenant_id(tenant):
            raise AuthenticationError("bad_claim")
        roles = claims.get(cfg.roles_claim, [])
        if not isinstance(roles, list) or not all(isinstance(r, str) for r in roles):
            raise AuthenticationError("bad_claim")
        marker = cfg.machine_markers.get(issuer)
        if marker is not None:
            if (  # a boolean marker on a claim of another type: fail closed, as the default does
                marker.claim in claims
                and isinstance(marker.value, bool)
                and not isinstance(claims[marker.claim], bool)
            ):
                raise AuthenticationError("bad_claim")
            service_account = marker.is_machine(claims)
        else:  # the test default: today's behaviour
            service_account = claims.get(DEFAULT_SERVICE_ACCOUNT_CLAIM, False)
            if not isinstance(service_account, bool):
                raise AuthenticationError("bad_claim")
            service_account = service_account or claims.get("gty") == CLIENT_CREDENTIALS_GTY
        return Principal(
            subject, tenant, frozenset(_known_roles(roles)), operator, issuer, service_account
        )


def _known_roles(names: Iterable[str]) -> list[Role]:
    known = {r.value: r for r in Role}
    return [known[n] for n in names if n in known]
