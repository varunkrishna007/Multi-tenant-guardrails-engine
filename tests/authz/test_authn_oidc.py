"""M2-01: OIDC bearer-token authentication on PyJWT. Offline: keys are generated here, the JWKS
is a static document."""

import base64
import json

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from guardrail_engine.authz import AuthenticationError, Principal, Role
from guardrail_engine.signing.adapters.oidc import (
    HttpJwksSource,
    MachineMarker,
    OidcConfig,
    PyJwtAuthenticator,
    StaticJwksSource,
)

ISS, AUD = "https://idp.example.com/", "guardrail-admin-api"
NOW = 1_700_000_000
ALPHA = "t_alpha1"


@pytest.fixture(scope="module")
def rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="module")
def ec_key():
    return ec.generate_private_key(ec.SECP256R1())


def jwk(key, kid, alg=None, **extra):
    entry = (
        json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
        if isinstance(key, rsa.RSAPrivateKey)
        else json.loads(jwt.algorithms.ECAlgorithm.to_jwk(key.public_key()))
    )
    entry.update({"kid": kid, **({"alg": alg} if alg else {}), **extra})
    return entry


class Clock:
    now = 0.0

    def __call__(self):
        Clock.now += 100.0  # every call is 100 s later: refreshes are never rate-limited by it
        return Clock.now


def make(keys, **cfg):
    source = StaticJwksSource({"keys": keys})
    config = OidcConfig(frozenset({ISS}), AUD, **cfg)
    return PyJwtAuthenticator(config, source), source


def token(key, kid="k1", alg="RS256", **claims):
    base = {"iss": ISS, "aud": AUD, "sub": "alice", "iat": int(__import__("time").time()),
            "exp": int(__import__("time").time()) + 300, "tenant_id": ALPHA,
            "roles": ["guardrail_admin"]}  # fmt: skip
    payload = {**base, **claims}
    payload = {k: v for k, v in payload.items() if v is not ...}
    return jwt.encode(payload, key, algorithm=alg, headers={"kid": kid} if kid else {})


async def refused(auth, tok):
    with pytest.raises(AuthenticationError) as info:
        await auth.authenticate(tok)
    return info.value.reason


# ---------------------------------------------------------------------------- the happy path


async def test_an_rs256_token_becomes_a_principal(rsa_key):
    auth, _ = make([jwk(rsa_key, "k1")])
    principal = await auth.authenticate(token(rsa_key))
    assert principal == Principal("alice", ALPHA, frozenset({Role.GUARDRAIL_ADMIN}), False, ISS)
    assert principal.issuer == ISS and principal.actor == f"{ISS}#alice"


async def test_an_es256_token_works_and_both_key_types_can_coexist(rsa_key, ec_key):
    auth, _ = make([jwk(rsa_key, "k1"), jwk(ec_key, "k2")])
    assert (await auth.authenticate(token(ec_key, "k2", "ES256"))).subject == "alice"
    assert (await auth.authenticate(token(rsa_key, "k1", "RS256"))).subject == "alice"


async def test_roles_unknown_to_us_grant_nothing_and_an_operator_needs_no_tenant(rsa_key):
    auth, _ = make([jwk(rsa_key, "k1")])
    p = await auth.authenticate(token(rsa_key, roles=["viewer", "root", "superadmin"]))
    assert p.roles == {Role.VIEWER}
    op = await auth.authenticate(token(rsa_key, tenant_id=..., platform_operator=True, roles=[]))
    assert op.platform_operator is True and op.tenant_id is None


async def test_claim_names_are_configurable(rsa_key):
    auth, _ = make([jwk(rsa_key, "k1")], tenant_claim="org", roles_claim="grp")
    p = await auth.authenticate(token(rsa_key, tenant_id=..., org=ALPHA, grp=["auditor"]))
    assert (p.tenant_id, p.roles) == (ALPHA, {Role.AUDITOR})


@pytest.mark.parametrize(
    ("claims", "expected"),
    [
        ({}, False),
        ({"service_account": True}, True),
        ({"service_account": False}, False),
        ({"gty": "client-credentials"}, True),  # the OAuth client-credentials grant
        ({"gty": "authorization_code"}, False),
        ({"gty": "client-credentials", "service_account": False}, True),
    ],
)
async def test_a_token_marks_a_service_account_by_claim_or_by_grant_type(rsa_key, claims, expected):
    """M5-02: a machine identity can't approve a publish. A token with neither marker is a
    person: the identity provider has to emit one for its machine clients."""
    auth, _ = make([jwk(rsa_key, "k1")])
    assert (await auth.authenticate(token(rsa_key, **claims))).service_account is expected


def make_marked(keys, marker):
    source = StaticJwksSource({"keys": keys})
    config = OidcConfig(frozenset({ISS}), AUD, machine_markers={ISS: marker})
    return PyJwtAuthenticator(config, source)


async def test_the_default_marker_claim_must_be_a_boolean(rsa_key):
    auth, _ = make([jwk(rsa_key, "k1")])
    assert await refused(auth, token(rsa_key, service_account="yes")) == "bad_claim"


CC = frozenset({"client-credentials"})


@pytest.mark.parametrize(
    ("marker", "claims", "expected"),
    [
        # a claim name and the value a machine token has
        (MachineMarker(claim="machine"), {"machine": True}, True),
        (MachineMarker(claim="machine"), {"service_account": True}, False),  # not this issuer's
        (MachineMarker(claim="machine"), {"machine": False}, False),
        (MachineMarker(claim="machine"), {}, False),
        (MachineMarker(claim="azp_type", value="m2m"), {"azp_type": "m2m"}, True),
        (MachineMarker(claim="azp_type", value="m2m"), {"azp_type": "user"}, False),
        (MachineMarker(claim="kinds", value="m2m"), {"kinds": ["x", "m2m"]}, True),
        # gty values; the default's gty is not assumed once the issuer says how
        (MachineMarker(gty=CC), {"gty": "client-credentials"}, True),
        (MachineMarker(gty=CC), {"gty": "password"}, False),
        (MachineMarker(claim="machine", gty=frozenset({"x"})), {"gty": "x"}, True),
        (MachineMarker(claim="machine", gty=frozenset({"x"})), {"machine": True}, True),
        # an issuer that declares humans only has no machine tokens
        (MachineMarker(humans_only=True), {"machine": True, "gty": "client-credentials"}, False),
        (MachineMarker(humans_only=True), {"service_account": True}, False),
    ],
)
async def test_an_issuer_says_how_its_machine_tokens_are_marked(rsa_key, marker, claims, expected):
    auth = make_marked([jwk(rsa_key, "k1")], marker)
    assert (await auth.authenticate(token(rsa_key, **claims))).service_account is expected


async def test_a_boolean_marker_on_a_claim_of_another_type_is_refused(rsa_key):
    auth = make_marked([jwk(rsa_key, "k1")], MachineMarker(claim="machine"))
    assert await refused(auth, token(rsa_key, machine="yes")) == "bad_claim"


@pytest.mark.parametrize(
    "bad",
    [
        {},  # nothing declared
        {"humans_only": True, "claim": "machine"},
        {"humans_only": True, "gty": frozenset({"x"})},
        {"claim": ""},
        {"gty": frozenset({""})},
        {"claim": "m", "value": ""},
    ],
)
def test_a_marker_is_exactly_one_declaration(bad):
    with pytest.raises(ValueError):
        MachineMarker(**bad)


def test_markers_name_listed_issuers_and_the_unmarked_ones_are_reported():
    humans = MachineMarker(humans_only=True)
    with pytest.raises(ValueError, match="isn't listed"):
        OidcConfig(frozenset({ISS}), AUD, machine_markers={"https://other/": humans})
    sso = {"https://sso/": frozenset({ALPHA})}
    assert OidcConfig(frozenset({ISS}), AUD, tenant_issuers=sso).unmarked_issuers() == [
        ISS, "https://sso/"
    ]  # fmt: skip
    marked = {ISS: MachineMarker(claim="machine"), "https://sso/": humans}
    cfg = OidcConfig(frozenset({ISS}), AUD, tenant_issuers=sso, machine_markers=marked)
    assert cfg.unmarked_issuers() == []


# ---------------------------------------------------------------------------- algorithm pinning


async def test_alg_none_is_refused(rsa_key):
    auth, _ = make([jwk(rsa_key, "k1")])
    header = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT","kid":"k1"}').rstrip(b"=")
    body = base64.urlsafe_b64encode(
        json.dumps(
            {"iss": ISS, "aud": AUD, "sub": "x", "exp": 9_999_999_999, "iat": 1, "tenant_id": ALPHA}
        ).encode()
    ).rstrip(b"=")
    assert await refused(auth, f"{header.decode()}.{body.decode()}.") == "unsupported_algorithm"


@pytest.mark.parametrize("alg", ["HS256", "HS384", "HS512"])
async def test_hmac_with_the_public_key_as_the_secret_is_refused(rsa_key, alg):
    """The algorithm-confusion attack: sign with the PUBLIC key as an HMAC secret. PyJWT itself
    refuses to build such a token, so it is assembled by hand here, as an attacker would."""
    import hashlib
    import hmac

    from cryptography.hazmat.primitives import serialization

    pem = rsa_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )

    def b64(data):
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    signing_input = (
        b64(json.dumps({"alg": alg, "typ": "JWT", "kid": "k1"}).encode())
        + "."
        + b64(
            json.dumps(
                {
                    "iss": ISS,
                    "aud": AUD,
                    "sub": "x",
                    "tenant_id": ALPHA,
                    "iat": 1,
                    "exp": 9_999_999_999,
                }
            ).encode()
        )
    )
    digest = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}[alg]
    forged = signing_input + "." + b64(hmac.new(pem, signing_input.encode(), digest).digest())
    auth, _ = make([jwk(rsa_key, "k1")])
    assert await refused(auth, forged) == "unsupported_algorithm"


@pytest.mark.parametrize("alg", ["RS384", "RS512", "PS256", "ES384", "EdDSA"])
async def test_algorithms_other_than_rs256_and_es256_are_refused(rsa_key, alg):
    auth, _ = make([jwk(rsa_key, "k1")])
    header = base64.urlsafe_b64encode(json.dumps({"alg": alg, "kid": "k1"}).encode()).rstrip(b"=")
    assert await refused(auth, f"{header.decode()}.e30.AAAA") == "unsupported_algorithm"


async def test_an_algorithm_that_does_not_fit_the_keys_type_is_refused(rsa_key, ec_key):
    auth, _ = make([jwk(rsa_key, "k1"), jwk(ec_key, "k2")])
    header = base64.urlsafe_b64encode(json.dumps({"alg": "ES256", "kid": "k1"}).encode())
    body = base64.urlsafe_b64encode(json.dumps({"iss": ISS}).encode()).rstrip(b"=").decode()
    assert (
        await refused(auth, f"{header.rstrip(b'=').decode()}.{body}.AAAA")
        == "unsupported_algorithm"
    )


async def test_a_jwk_that_names_a_different_alg_is_refused(rsa_key):
    auth, _ = make([jwk(rsa_key, "k1", alg="RS512")])
    assert await refused(auth, token(rsa_key)) == "unsupported_algorithm"


# ---------------------------------------------------------------------------- key pinning


async def test_no_kid_or_an_unknown_kid_is_refused_and_an_unknown_kid_refreshes_the_jwks_once(
    rsa_key,
):
    auth, source = make([jwk(rsa_key, "k1")])
    assert await refused(auth, token(rsa_key, kid=None)) == "unknown_key"
    assert source.fetches == 0
    assert await refused(auth, token(rsa_key, kid="other")) == "unknown_key"
    assert source.fetches == 1
    assert await refused(auth, token(rsa_key, kid="other2")) == "unknown_key"
    assert source.fetches == 1  # rate-limited: not every unknown kid re-reads the JWKS


async def test_a_new_kid_is_picked_up_once_the_refresh_interval_has_passed(rsa_key, ec_key):
    document = {"keys": [jwk(rsa_key, "k1")]}
    source = StaticJwksSource(document)
    auth = PyJwtAuthenticator(OidcConfig(frozenset({ISS}), AUD), source, clock=Clock())
    await auth.authenticate(token(rsa_key))  # loads k1
    document["keys"].append(jwk(ec_key, "k2"))  # the IdP rotated in a new key
    assert (await auth.authenticate(token(ec_key, "k2", "ES256"))).subject == "alice"


async def test_a_token_signed_by_the_wrong_key_with_a_known_kid_is_bad_signature(rsa_key):
    auth, _ = make([jwk(rsa_key, "k1")])
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    assert await refused(auth, token(other, "k1")) == "bad_signature"


async def test_keys_not_for_signatures_or_of_other_types_are_ignored(rsa_key):
    auth, _ = make([jwk(rsa_key, "k1", use="enc"), {"kty": "oct", "kid": "k2", "k": "AAAA"}])
    assert await refused(auth, token(rsa_key)) == "unknown_key"


async def test_an_unreadable_jwks_is_jwks_unavailable_not_a_pass(rsa_key):
    class Down:
        async def fetch(self):
            raise ConnectionError("down")

    auth = PyJwtAuthenticator(OidcConfig(frozenset({ISS}), AUD), Down())
    assert await refused(auth, token(rsa_key)) == "jwks_unavailable"


# ---------------------------------------------------------------------------- claims


@pytest.mark.parametrize(
    ("claims", "reason"),
    [
        ({"iss": "https://evil.example/"}, "wrong_issuer"),
        ({"aud": "someone-else"}, "wrong_audience"),
        ({"aud": ...}, "missing_claim"),
        ({"iss": ...}, "missing_claim"),
        ({"sub": ...}, "missing_claim"),
        ({"exp": ...}, "missing_claim"),
        ({"iat": ...}, "missing_claim"),
        ({"exp": 1}, "expired"),
        ({"nbf": 9_999_999_999}, "not_yet_valid"),
        ({"sub": ""}, "bad_claim"),
        ({"sub": 7}, "malformed|bad_claim"),  # PyJWT 2.10+ rejects it itself; 2.9 leaves it to us
        ({"tenant_id": "t_Acme"}, "bad_claim"),
        ({"tenant_id": 5}, "bad_claim"),
        ({"tenant_id": ...}, "missing_claim"),
        ({"roles": "viewer"}, "bad_claim"),
        ({"roles": [1]}, "bad_claim"),
        ({"platform_operator": "true"}, "bad_claim"),
    ],
)
async def test_each_bad_or_missing_claim_is_refused_with_its_reason(rsa_key, claims, reason):
    auth, _ = make([jwk(rsa_key, "k1")])
    assert await refused(auth, token(rsa_key, **claims)) in reason.split("|")


async def test_only_the_json_true_makes_an_operator(rsa_key):
    auth, _ = make([jwk(rsa_key, "k1")])
    assert (
        await auth.authenticate(token(rsa_key, platform_operator=False))
    ).platform_operator is False
    assert (
        await auth.authenticate(token(rsa_key, platform_operator=True))
    ).platform_operator is True


async def test_the_30_second_leeway_applies_to_expiry(rsa_key):
    auth, _ = make([jwk(rsa_key, "k1")])
    now = int(__import__("time").time())
    assert (await auth.authenticate(token(rsa_key, iat=now - 400, exp=now - 20))).subject == "alice"
    assert await refused(auth, token(rsa_key, iat=now - 400, exp=now - 60)) == "expired"


@pytest.mark.parametrize("bad", [None, "", "not.a.jwt", "a.b.c", "x" * 9000, 5])
async def test_missing_malformed_and_oversized_tokens_are_refused(rsa_key, bad):
    auth, source = make([jwk(rsa_key, "k1")])
    reason = await refused(auth, bad)
    assert reason in {"missing", "malformed", "too_long"} and source.fetches == 0


async def test_failures_never_carry_the_token_or_a_claim(rsa_key):
    auth, _ = make([jwk(rsa_key, "k1")])
    secret = token(rsa_key, sub="super-secret-subject", aud="nope")
    with pytest.raises(AuthenticationError) as info:
        await auth.authenticate(secret)
    assert "super-secret" not in str(info.value) and secret not in str(info.value)
    assert info.value.reason == "wrong_audience"


def test_the_authentication_error_only_takes_a_fixed_reason():
    with pytest.raises(ValueError):
        AuthenticationError("because the token said so")


def test_config_needs_an_issuer_and_an_audience():
    with pytest.raises(ValueError):
        OidcConfig(frozenset(), AUD)
    with pytest.raises(ValueError):
        OidcConfig(frozenset({ISS}), "")


async def test_the_http_jwks_source_needs_https_and_fetches_the_document(rsa_key):
    import httpx

    document = {"keys": [jwk(rsa_key, "k1")]}

    def handler(request):
        assert str(request.url) == "https://idp.example.com/jwks"
        return httpx.Response(200, json=document)

    with pytest.raises(ValueError, match="https"):
        HttpJwksSource("http://idp.example.com/jwks", None)
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        auth = PyJwtAuthenticator(
            OidcConfig(frozenset({ISS}), AUD),
            HttpJwksSource("https://idp.example.com/jwks", client),
        )
        assert (await auth.authenticate(token(rsa_key))).subject == "alice"


# ---------------------------------------------------------------------------- issuer kinds

TENANT_ISS = "https://sso.customer.example/"
BETA = "t_beta2"


def make_two(platform_key, tenant_key, tenants=(ALPHA,)):
    """One platform issuer and one tenant issuer, each with its own JWKS."""
    config = OidcConfig(frozenset({ISS}), AUD, tenant_issuers={TENANT_ISS: frozenset(tenants)})
    return PyJwtAuthenticator(
        config,
        {
            ISS: StaticJwksSource({"keys": [jwk(platform_key, "p1")]}),
            TENANT_ISS: StaticJwksSource({"keys": [jwk(tenant_key, "c1")]}),
        },
    )


async def test_an_operator_claim_from_a_tenant_issuer_is_refused(rsa_key, ec_key):
    auth = make_two(rsa_key, ec_key)
    assert (
        await refused(
            auth,
            token(ec_key, "c1", "ES256", iss=TENANT_ISS, platform_operator=True, tenant_id=...),
        )
        == "operator_not_allowed"
    )
    # the same claim from the platform issuer counts
    ok = await auth.authenticate(token(rsa_key, "p1", platform_operator=True, tenant_id=...))
    assert ok.platform_operator is True


async def test_a_tenant_issuer_cannot_name_a_tenant_outside_its_set(rsa_key, ec_key):
    auth = make_two(rsa_key, ec_key)
    assert (
        await refused(auth, token(ec_key, "c1", "ES256", iss=TENANT_ISS, tenant_id=BETA))
        == "tenant_not_allowed"
    )
    own = await auth.authenticate(token(ec_key, "c1", "ES256", iss=TENANT_ISS, tenant_id=ALPHA))
    assert own.tenant_id == ALPHA and own.platform_operator is False


async def test_a_tenant_issuer_token_must_name_a_tenant(rsa_key, ec_key):
    auth = make_two(rsa_key, ec_key)
    assert (
        await refused(auth, token(ec_key, "c1", "ES256", iss=TENANT_ISS, tenant_id=...))
        == "missing_claim"
    )


async def test_one_issuers_key_cannot_sign_for_another_issuer(rsa_key, ec_key):
    """A token signed with the tenant IdP's key that claims the platform issuer verifies against
    the platform issuer's keys only, and fails."""
    auth = make_two(rsa_key, ec_key)
    forged = token(ec_key, "c1", "ES256", iss=ISS, platform_operator=True, tenant_id=...)
    assert await refused(auth, forged) == "unknown_key"  # the platform JWKS has no kid c1
    forged = token(ec_key, "p1", "ES256", iss=ISS, platform_operator=True, tenant_id=...)
    assert await refused(auth, forged) in {"unsupported_algorithm", "bad_signature"}


async def test_an_unlisted_issuer_is_refused(rsa_key, ec_key):
    auth = make_two(rsa_key, ec_key)
    assert await refused(auth, token(rsa_key, "p1", iss="https://evil.example/")) == "wrong_issuer"


def test_an_issuer_listed_as_both_kinds_is_refused_at_config_time():
    with pytest.raises(ValueError, match="both"):
        OidcConfig(frozenset({ISS}), AUD, tenant_issuers={ISS: frozenset({ALPHA})})


@pytest.mark.parametrize("tenants", [frozenset(), frozenset({"not a tenant"})])
def test_a_tenant_issuer_needs_a_set_of_valid_tenant_ids(tenants):
    with pytest.raises(ValueError):
        OidcConfig(frozenset({ISS}), AUD, tenant_issuers={TENANT_ISS: tenants})


def test_several_issuers_need_one_jwks_each(rsa_key):
    config = OidcConfig(frozenset({ISS}), AUD, tenant_issuers={TENANT_ISS: frozenset({ALPHA})})
    with pytest.raises(ValueError):
        PyJwtAuthenticator(config, StaticJwksSource({"keys": []}))
    with pytest.raises(ValueError):
        PyJwtAuthenticator(config, {ISS: StaticJwksSource({"keys": []})})


@pytest.mark.parametrize("issuer", ["https://idp.example.com/#frag", "#", "x" * 513, ""])
def test_an_issuer_that_would_make_the_audit_actor_ambiguous_or_too_long_is_refused(issuer):
    """The actor is ``<issuer>#<subject>``, in a column of at most 1024 characters."""
    with pytest.raises(ValueError, match="issuer"):
        OidcConfig(frozenset({issuer}), AUD)
    with pytest.raises(ValueError, match="issuer"):
        OidcConfig(frozenset({ISS}), AUD, tenant_issuers={issuer: frozenset({ALPHA})})


def test_the_longest_issuer_with_the_longest_subject_fits_the_actor_column():
    longest = "https://" + "a" * (512 - len("https://"))
    config = OidcConfig(frozenset({longest}), AUD)
    assert len(longest) == 512 and config.issuers == {longest}
    assert len(f"{longest}#{'s' * 256}") <= 1024
