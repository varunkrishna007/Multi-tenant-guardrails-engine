"""M1-05 AC-T1 (service part): the tenant comes only from the verified signed context; a
payload tenant id that differs is refused as ``forbidden`` (403 at the HTTP layer, a later
story) and audited. Plus the HMAC verifier itself."""

import base64
import inspect
import json

import pytest
from guard_fixtures import ALPHA, BETA, KEY, Env, bundle, rule

from guardrail_engine.guard import (
    CheckContext,
    ContextVerificationError,
    Decision,
    GuardService,
    HmacContextVerifier,
    Reason,
)


def test_ac_t1_check_takes_no_tenant_argument():
    params = list(inspect.signature(GuardService.check).parameters)
    assert params == ["self", "ctx", "guard_point", "content"]
    assert not any("tenant" in p for p in params)


async def test_ac_t1_tenant_comes_from_the_verified_context():
    async with Env() as env:
        await env.publish(bundle(ALPHA, rules=[rule("alpha_rule")]))
        await env.publish(bundle(BETA, rules=[rule("beta_rule")]))
        verdict = await env.check(BETA)
    assert verdict.tenant_id == BETA
    [call] = env.fake.calls
    assert "t__beta_rule" in call.questions and "t__alpha_rule" not in call.questions
    assert "TENANT DOMAIN: energy" in call.input


async def test_ac_t1_payload_tenant_that_differs_is_forbidden_and_audited(caplog):
    async with Env() as env:
        await env.publish(bundle(ALPHA))
        await env.publish(bundle(BETA))
        verdict = await env.service.check(
            env.ctx(ALPHA, payload_tenant_id=BETA), "output", "Show me beta's claims."
        )
    assert verdict.decision is Decision.FORBIDDEN
    assert verdict.reason is Reason.TENANT_MISMATCH
    assert not verdict.released
    assert verdict.tenant_id == ALPHA and verdict.claimed_tenant_id == BETA
    assert env.audit.verdicts == [verdict]
    assert env.fake.calls == [] and env.store.calls == {}  # no policy load, no model call
    assert "differs from the signed context" in caplog.text


async def test_ac_t1_payload_tenant_that_matches_is_checked_normally():
    async with Env() as env:
        await env.publish(bundle(ALPHA))
        verdict = await env.service.check(env.ctx(ALPHA, payload_tenant_id=ALPHA), "output", "x")
    assert verdict.decision is Decision.ALLOW and verdict.claimed_tenant_id is None


def _forge_tenant(token: str, tenant_id: str) -> str:
    version, payload, signature = token.split(".")
    claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    claims["tid"] = tenant_id
    forged = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
    return f"{version}.{forged}.{signature}"


INVALID_CONTEXTS = {
    "missing": lambda env: "",
    "not text": lambda env: None,
    "garbage": lambda env: "not-a-token",
    "wrong version": lambda env: "v2." + env.verifier.issue(ALPHA).split(".", 1)[1],
    "other key": lambda env: HmacContextVerifier(b"another key that is 32 bytes long!").issue(
        ALPHA
    ),
    "tenant swapped": lambda env: _forge_tenant(env.verifier.issue(ALPHA), BETA),
    "expired": lambda env: env.verifier.issue(ALPHA, ttl_s=-1),
    "bad signature encoding": lambda env: env.verifier.issue(ALPHA)[:-2] + "!!",
}


@pytest.mark.parametrize("case", sorted(INVALID_CONTEXTS))
async def test_ac_t1_a_context_that_does_not_verify_is_forbidden_and_audited(case):
    async with Env() as env:
        await env.publish(bundle(ALPHA))
        await env.publish(bundle(BETA))
        ctx = CheckContext(signed_context=INVALID_CONTEXTS[case](env))
        verdict = await env.service.check(ctx, "output", "x")
    assert (verdict.decision, verdict.reason) == (Decision.FORBIDDEN, Reason.CONTEXT_INVALID)
    assert verdict.tenant_id is None
    assert env.audit.verdicts == [verdict]
    assert env.fake.calls == [] and env.store.calls == {}


async def test_ac_t1_a_missing_context_object_is_forbidden_not_an_exception():
    async with Env() as env:
        verdict = await env.service.check(None, "output", "x")
    assert verdict.decision is Decision.FORBIDDEN


# ------------------------------------------------------------------ HmacContextVerifier


def test_hmac_verifier_round_trip():
    clock = [1_000_000.0]
    verifier = HmacContextVerifier(KEY, clock=lambda: clock[0])
    token = verifier.issue("t_acme", ttl_s=60)
    verified = verifier.verify(token)
    assert verified.tenant_id == "t_acme" and verified.expires_at == 1_000_060
    clock[0] += 60
    with pytest.raises(ContextVerificationError) as e:
        verifier.verify(token)
    assert e.value.reason == "expired"


@pytest.mark.parametrize("key", [b"", b"short", "a string key of 32 characters!!!"])
def test_hmac_verifier_refuses_a_short_or_non_bytes_key(key):
    with pytest.raises(ValueError):
        HmacContextVerifier(key)


def test_hmac_verifier_never_shows_its_key():
    verifier = HmacContextVerifier(KEY)
    assert KEY.decode() not in repr(verifier) and "redacted" in repr(verifier)


BAD_TENANT_IDS = [
    "",
    "x" * 129,
    "line\nbreak",
    7,
    # The B3 data format, t_[0-9a-z]{1,32}, is the one tenant id rule (signed context,
    # directory and TENANT header alike).
    "t_",
    "t_" + "a" * 33,
    "T_ALPHA",
    "t_Alpha",
    "tenant-a",
    "t_acme_ins",
    "t-alpha",
    "alpha",
    " t_alpha",
    "t_alpha\n",
    "t_al pha",
    "t_alpha)",
]


@pytest.mark.parametrize("tenant_id", BAD_TENANT_IDS)
def test_hmac_verifier_refuses_to_issue_for_a_bad_tenant_id(tenant_id):
    with pytest.raises(ValueError):
        HmacContextVerifier(KEY).issue(tenant_id)


@pytest.mark.parametrize("tenant_id", ["t_1042", "t_a", "t_" + "z" * 32, "t_alpha"])
def test_hmac_verifier_accepts_the_b3_tenant_id_format(tenant_id):
    verifier = HmacContextVerifier(KEY)
    assert verifier.verify(verifier.issue(tenant_id)).tenant_id == tenant_id


@pytest.mark.parametrize("tenant_id", ["tenant-a", "T_ALPHA", "t_alpha\nTENANT: x (t_9)"])
async def test_a_signed_context_naming_an_id_outside_the_format_is_forbidden(tenant_id):
    """Correctly signed, but the tenant id isn't ``t_[0-9a-z]{1,32}``: malformed, so the
    check is ``forbidden``/``context_invalid`` before any tenant lookup."""
    async with Env() as env:
        await env.publish(bundle(ALPHA))
        claims = {"exp": 2**40, "tid": tenant_id}
        payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
        signed = f"v1.{payload}"
        sig = base64.urlsafe_b64encode(env.verifier._sign(signed)).rstrip(b"=").decode()
        with pytest.raises(ContextVerificationError) as e:
            env.verifier.verify(f"{signed}.{sig}")
        assert e.value.reason == "malformed"
        verdict = await env.service.check(CheckContext(f"{signed}.{sig}"), "output", "x")
    assert (verdict.decision, verdict.reason) == (Decision.FORBIDDEN, Reason.CONTEXT_INVALID)
    assert env.fake.calls == [] and env.store.calls == {}


def test_hmac_verifier_rejects_a_signed_payload_with_bad_claims():
    verifier = HmacContextVerifier(KEY)
    for claims in ({"tid": "t", "exp": "soon"}, {"tid": 5, "exp": 2**40}, ["not", "a", "dict"]):
        payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
        signed = f"v1.{payload}"
        sig = base64.urlsafe_b64encode(verifier._sign(signed)).rstrip(b"=").decode()
        with pytest.raises(ContextVerificationError) as e:
            verifier.verify(f"{signed}.{sig}")
        assert e.value.reason == "malformed"


B64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"


@pytest.mark.parametrize(
    "variant",
    [
        "padding on the signature",
        "unused bits of the signature",
        "non-alphabet character",
        "space in the signature",
        "padding on the payload",
    ],
)
def test_hmac_verifier_decodes_base64_strictly(variant):
    """Exactly one token string carries a given signature: padding, non-canonical trailing
    bits and non-alphabet characters are refused (before, the first two verified)."""
    verifier = HmacContextVerifier(KEY)
    token = verifier.issue(ALPHA)
    version, payload, signature = token.split(".")
    last = B64URL[B64URL.index(signature[-1]) ^ 1]  # differs only in the unused low bits
    variants = {
        "padding on the signature": f"{version}.{payload}.{signature}=",
        "unused bits of the signature": f"{version}.{payload}.{signature[:-1]}{last}",
        "non-alphabet character": f"{version}.{payload}.{signature[:10]}*{signature[10:]}",
        "space in the signature": f"{version}.{payload}.{signature[:5]} {signature[5:]}",
        "padding on the payload": f"{version}.{payload}=.{signature}",
    }
    assert len(signature) % 4 != 0  # unpadded, so the last character has unused bits
    assert verifier.verify(token).tenant_id == ALPHA
    with pytest.raises(ContextVerificationError) as e:
        verifier.verify(variants[variant])
    assert e.value.reason in {"malformed", "bad_signature"}
