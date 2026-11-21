"""M2-01: the v2 signed context (Ed25519, key ids, keyset, rotation). Offline."""

import base64
import json

import pytest
from guard_fixtures import ALPHA, BETA, Env, bundle

from guardrail_engine.guard import CheckContext, ContextVerificationError, Decision, Reason
from guardrail_engine.guard import signed_context as sc
from guardrail_engine.guard.signed_context import (
    Ed25519ContextSigner,
    Ed25519ContextVerifier,
    KeyEntry,
    Keyset,
    KeysetRefresher,
)
from guardrail_engine.signing.adapters.ed25519 import Ed25519Key, Ed25519Verifier

NOW = 1_700_000_000.0
LOAD = Ed25519Verifier.from_raw
ISSUER = "gateway-eu"


class Clock:
    def __init__(self, now=NOW):
        self.now = now

    def __call__(self):
        return self.now


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


class Kit:
    """A signer, a verifier and a clock that agree."""

    def __init__(self, kid="k1", valid_from=NOW - 1000, valid_until=None, issuers=(ISSUER,)):
        self.clock = Clock()
        self.private = Ed25519Key.generate()
        self.signer = Ed25519ContextSigner(self.private, kid, ISSUER, clock=self.clock)
        self.keyset = Keyset([KeyEntry(kid, self.private.verifier(), valid_from, valid_until)])
        self.verifier = Ed25519ContextVerifier(self.keyset, issuers, clock=self.clock)

    def forge(self, payload, kid="k1", private=None):
        """A correctly signed token with an arbitrary payload (to test claim checking)."""
        body = b64(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode())
        signed = f"v2.{kid}.{body}"
        return f"{signed}.{b64((private or self.private).sign(signed.encode()))}"

    def claims(self, **over):
        now = int(self.clock())
        claims = {"aud": "guard-service", "exp": now + 300, "iat": now, "iss": ISSUER, "tid": ALPHA}
        return {**claims, **over}


def refused(kit_or_verifier, token):
    verifier = getattr(kit_or_verifier, "verifier", kit_or_verifier)
    with pytest.raises(ContextVerificationError) as info:
        verifier.verify(token)
    return info.value.reason


# ---------------------------------------------------------------------------- the round trip


def test_round_trip_names_the_tenant_and_the_expiry():
    kit = Kit()
    verified = kit.verifier.verify(kit.signer.issue(ALPHA))
    assert verified.tenant_id == ALPHA and verified.expires_at == NOW + 300


def test_token_format_is_v2_kid_payload_signature_with_exactly_the_five_fields():
    kit = Kit(kid="gw-2024_a")
    version, kid, payload, signature = kit.signer.issue(ALPHA).split(".")
    assert (version, kid) == ("v2", "gw-2024_a")
    body = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    assert set(body) == {"tid", "iat", "exp", "aud", "iss"} and body["aud"] == "guard-service"
    assert len(base64.urlsafe_b64decode(signature + "==")) == 64  # an Ed25519 signature


def test_the_signer_and_verifier_never_show_a_key():
    kit = Kit()
    assert "key=<redacted>" in repr(kit.signer)
    assert repr(kit.keyset.get("k1")) == "KeyEntry(kid='k1')"
    assert "private" not in repr(kit.verifier).lower()


@pytest.mark.parametrize("ttl", [0, -1, 601])
def test_the_signer_refuses_a_lifetime_outside_zero_to_600_seconds(ttl):
    with pytest.raises(ValueError, match="ttl_s"):
        Kit().signer.issue(ALPHA, ttl_s=ttl)


@pytest.mark.parametrize("tenant", ["t_Acme", "t-acme", "t_acme_ins", "t_" + "a" * 33, ""])
def test_the_signer_refuses_a_tenant_id_outside_the_format(tenant):
    with pytest.raises(ValueError):
        Kit().signer.issue(tenant)


@pytest.mark.parametrize("kid", ["", "has.dot", "a" * 33, "sp ace"])
def test_a_kid_outside_the_pattern_is_refused(kid):
    with pytest.raises(ValueError, match="kid"):
        Ed25519ContextSigner(Ed25519Key.generate(), kid, ISSUER)


# ---------------------------------------------------------------------------- forgery


def test_a_tampered_payload_signature_or_kid_is_bad_signature_or_unknown_key():
    kit = Kit()
    token = kit.signer.issue(ALPHA)
    version, kid, payload, signature = token.split(".")
    claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    swapped = b64(json.dumps({**claims, "tid": BETA}, sort_keys=True).encode())
    assert refused(kit, f"{version}.{kid}.{swapped}.{signature}") == "bad_signature"
    flipped = signature[:-3] + ("A" if signature[-3] != "A" else "B") + signature[-2:]
    assert refused(kit, f"{version}.{kid}.{payload}.{flipped}") == "bad_signature"
    assert refused(kit, f"{version}.k9.{payload}.{signature}") == "unknown_key"


def test_a_token_signed_by_another_key_with_a_known_kid_is_bad_signature():
    kit = Kit()
    other = Ed25519Key.generate()
    assert refused(kit, kit.forge(kit.claims(), private=other)) == "bad_signature"


def test_a_v1_hmac_token_is_not_accepted_by_the_v2_verifier():
    from guardrail_engine.guard import HmacContextVerifier

    kit = Kit()
    assert refused(kit, HmacContextVerifier(b"k" * 32).issue(ALPHA)) == "malformed"


@pytest.mark.parametrize(
    "token",
    [
        "", None, 5, "v2", "v2.k1.payload", "v2.k1.a.b.c", "v3.k1.AAAA.AAAA",
        "v2.k1.%%%%.AAAA", "v2.k1.AAAA.AAAA=", "v2..AAAA.AAAA", "v2.k 1.AAAA.AAAA",
        "v2.k1." + "é" * 10 + ".AAAA", "v2.k1." + "A" * 5000 + ".AAAA",
    ],
)  # fmt: skip
def test_malformed_or_missing_tokens_are_refused_not_raised_as_other_errors(token):
    # a bad signature part is refused before the payload is read, so it may say bad_signature
    assert refused(Kit(), token) in ("missing", "malformed", "bad_signature")


def test_a_non_canonical_base64_signature_is_malformed():
    kit = Kit()
    version, kid, payload, signature = kit.signer.issue(ALPHA).split(".")
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    spare_bits_set = signature[:-1] + alphabet[alphabet.index(signature[-1]) | 1]
    assert refused(kit, f"{version}.{kid}.{payload}.{spare_bits_set}") == "malformed"
    # an extra character that keeps the spelling canonical is a different (wrong) signature
    assert refused(kit, f"{version}.{kid}.{payload}.{signature}A") == "bad_signature"


# ---------------------------------------------------------------------------- the claims


@pytest.mark.parametrize(
    ("over", "reason"),
    [
        ({"extra": 1}, "malformed"),
        ({"iat": "1"}, "malformed"),
        ({"exp": 1.5}, "malformed"),
        ({"tid": "t_Acme"}, "malformed"),
        ({"tid": 7}, "malformed"),
        ({"aud": "someone-else"}, "wrong_audience"),
        ({"iss": "gateway-us"}, "wrong_issuer"),
    ],
)
def test_signed_but_wrong_claims_are_refused_with_their_reason(over, reason):
    kit = Kit()
    assert refused(kit, kit.forge(kit.claims(**over))) == reason


@pytest.mark.parametrize("missing", ["tid", "iat", "exp", "aud", "iss"])
def test_a_missing_field_is_malformed(missing):
    kit = Kit()
    claims = kit.claims()
    del claims[missing]
    assert refused(kit, kit.forge(claims)) == "malformed"


def test_lifetime_over_600_seconds_or_not_positive_is_refused():
    kit = Kit()
    now = int(NOW)
    assert refused(kit, kit.forge(kit.claims(exp=now + 601))) == "malformed"
    assert refused(kit, kit.forge(kit.claims(exp=now))) == "malformed"
    assert kit.verifier.verify(kit.forge(kit.claims(exp=now + 600))).tenant_id == ALPHA


def test_the_clock_skew_leeway_is_30_seconds_each_way():
    kit = Kit()
    token = kit.signer.issue(ALPHA)  # iat = NOW, exp = NOW + 300
    kit.clock.now = NOW + 300 + 29
    assert kit.verifier.verify(token).tenant_id == ALPHA  # expired 29 s ago: within leeway
    kit.clock.now = NOW + 300 + 30
    assert refused(kit, token) == "expired"
    kit.clock.now = NOW - 29
    assert kit.verifier.verify(token).tenant_id == ALPHA  # issued 29 s in the future
    kit.clock.now = NOW - 31
    assert refused(kit, token) == "not_yet_valid"


# ---------------------------------------------------------------------------- keys and rotation


def test_a_key_that_may_not_verify_or_is_not_in_the_keyset_is_unknown():
    kit = Kit()
    token = kit.signer.issue(ALPHA)
    kit.verifier.set_keyset(Keyset([KeyEntry("k1", kit.private.verifier(), 0, None, False)]))
    assert refused(kit, token) == "unknown_key"


def test_a_token_issued_outside_its_keys_window_is_refused():
    kit = Kit(valid_from=NOW + 100)  # the key starts 100 s from now
    assert refused(kit, kit.signer.issue(ALPHA)) == "unknown_key"
    ended = Kit(valid_until=NOW - 100)  # the key stopped signing 100 s ago
    assert refused(ended, ended.signer.issue(ALPHA)) == "unknown_key"
    edge = Kit(valid_until=NOW - 20)  # within the 30 s skew of its end
    assert edge.verifier.verify(edge.signer.issue(ALPHA)).tenant_id == ALPHA


def test_a_key_retires_itself_630_seconds_after_valid_until():
    kit = Kit(valid_until=NOW)
    token = kit.signer.issue(ALPHA, ttl_s=600)  # iat = NOW, the last token this key could sign
    kit.clock.now = NOW + 629
    assert kit.verifier.verify(token).tenant_id == ALPHA
    kit.clock.now = NOW + 631
    assert refused(kit, token) in ("expired", "unknown_key")  # expired by its own exp too
    # a token with the longest lifetime that is still live when the key retires is impossible:
    assert sc.RETIRE_AFTER_S == sc.MAX_LIFETIME_S + sc.SKEW_S


def test_rotation_keeps_both_keys_valid_during_the_overlap_then_retires_the_old():
    clock = Clock()
    old, new = Ed25519Key.generate(), Ed25519Key.generate()
    old_signer = Ed25519ContextSigner(old, "k1", ISSUER, clock=clock)
    new_signer = Ed25519ContextSigner(new, "k2", ISSUER, clock=clock)
    switch = NOW + 100  # the gateway switches its signer at this time
    # step 1: both public keys are in the verifier's keyset before the switch
    keyset = Keyset([
        KeyEntry("k1", old.verifier(), NOW - 1000, valid_until=switch),
        KeyEntry("k2", new.verifier(), switch),
    ])  # fmt: skip
    verifier = Ed25519ContextVerifier(keyset, [ISSUER], clock=clock)
    clock.now = NOW + 50
    issued_by_old = old_signer.issue(ALPHA)
    clock.now = switch + 1  # step 2: the gateway now signs with k2
    issued_by_new = new_signer.issue(ALPHA)
    assert verifier.verify(issued_by_old).tenant_id == ALPHA  # still live, old key
    assert verifier.verify(issued_by_new).tenant_id == ALPHA
    # a token the old key could not have signed after the switch is refused
    clock.now = switch + 60  # more than the 30 s skew past the old key's last signing time
    forged_late = old_signer.issue(ALPHA)
    assert refused(verifier, forged_late) == "unknown_key"
    # step 3: past valid_until + max lifetime + skew the old key verifies nothing
    clock.now = switch + sc.RETIRE_AFTER_S + 1
    assert refused(verifier, issued_by_old) in ("expired", "unknown_key")
    fresh = new_signer.issue(ALPHA)
    assert verifier.verify(fresh).tenant_id == ALPHA
    # removing the old key from the keyset: its tokens are unknown_key
    verifier.set_keyset(Keyset([KeyEntry("k2", new.verifier(), switch)]))
    assert refused(verifier, issued_by_old) in ("expired", "unknown_key")


def test_a_keyset_needs_one_key_and_refuses_duplicate_kids():
    key = Ed25519Key.generate().verifier()
    with pytest.raises(ValueError, match="at least one"):
        Keyset([])
    with pytest.raises(ValueError, match="duplicate"):
        Keyset([KeyEntry("k1", key, 0), KeyEntry("k1", key, 0)])
    with pytest.raises(ValueError):
        KeyEntry("k1", key, valid_from=10, valid_until=5)


def keyset_doc(*entries):
    return json.dumps({"keys": list(entries)})


def entry(private, kid="k1", **over):
    return {"kid": kid, "x": private.public_text(), "valid_from": 100, **over}


def test_keyset_parse_reads_the_documented_json():
    a, b = Ed25519Key.generate(), Ed25519Key.generate()
    keyset = Keyset.parse(
        keyset_doc(entry(a), entry(b, "k2", valid_until=900.5, may_verify=False)), LOAD
    )
    assert keyset.kids() == ("k1", "k2")
    assert keyset.get("k2").valid_until == 900.5 and keyset.get("k2").may_verify is False
    assert keyset.get("k1").valid_until is None and keyset.get("k1").may_verify is True


@pytest.mark.parametrize(
    "text",
    [
        "", "not json", "[]", '{"keys": []}', '{"keys": {}}', '{"keys": [], "x": 1}',
        '{"keys": [{"kid": "k1"}]}',
        '{"keys": [{"kid": "k1", "x": "AAAA", "valid_from": 1}]}',  # not 32 bytes
        '{"keys": [{"kid": 5, "x": "AAAA", "valid_from": 1}]}',
        '{"keys": [{"kid": "bad.kid", "x": "AAAA", "valid_from": 1}]}',
    ],
)  # fmt: skip
def test_keyset_parse_refuses_anything_else(text):
    with pytest.raises(ValueError):
        Keyset.parse(text, LOAD)


def test_keyset_parse_refuses_unknown_fields_and_wrong_types():
    key = Ed25519Key.generate()
    for bad in ({"admin": True}, {"may_verify": "yes"}, {"valid_from": "100"},
                {"valid_until": "soon"}):  # fmt: skip
        with pytest.raises(ValueError):
            Keyset.parse(keyset_doc(entry(key, **bad)), LOAD)


class Source:
    def __init__(self, *texts):
        self.texts = list(texts)

    async def read(self):
        text = self.texts.pop(0) if len(self.texts) > 1 else self.texts[0]
        if isinstance(text, Exception):
            raise text
        return text


async def test_the_refresher_swaps_a_good_keyset_and_keeps_the_last_good_one_on_a_bad_one():
    first, second = Ed25519Key.generate(), Ed25519Key.generate()
    kit = Kit()
    alerts: list[str] = []
    source = Source(
        keyset_doc(entry(first, "a1")), "garbage", ConnectionError("down"),
        keyset_doc(entry(second, "a2")),
    )  # fmt: skip
    refresher = KeysetRefresher(kit.verifier, source, LOAD, alert=alerts.append)
    assert await refresher.refresh_once() is True and kit.verifier.keyset.kids() == ("a1",)
    assert await refresher.refresh_once() is False and kit.verifier.keyset.kids() == ("a1",)
    assert await refresher.refresh_once() is False and kit.verifier.keyset.kids() == ("a1",)
    assert alerts == ["keyset_invalid", "keyset_unreadable"]  # fixed words, never the document
    assert await refresher.refresh_once() is True and kit.verifier.keyset.kids() == ("a2",)


async def test_the_refresher_loop_refreshes_every_interval():
    kit = Kit()
    sleeps: list[float] = []

    async def sleep(seconds):
        sleeps.append(seconds)
        if len(sleeps) == 3:
            raise KeyboardInterrupt

    refresher = KeysetRefresher(
        kit.verifier, Source(keyset_doc(entry(Ed25519Key.generate()))), LOAD, sleep=sleep
    )
    with pytest.raises(KeyboardInterrupt):
        await refresher.run()
    assert sleeps == [60.0, 60.0, 60.0] and sc.KEYSET_REFRESH_S == 60.0


# ---------------------------------------------------------------------------- the Guard Service


async def test_the_guard_service_takes_the_tenant_from_a_v2_context_and_refuses_a_forged_one():
    kit = Kit()
    kit.clock.now = __import__("time").time()  # the service's checks use real time for caches
    kit.signer = Ed25519ContextSigner(kit.private, "k1", ISSUER, clock=kit.clock)
    kit.verifier = Ed25519ContextVerifier(kit.keyset, [ISSUER], clock=kit.clock)
    async with Env() as env:
        env.service._verifier = kit.verifier
        await env.publish(bundle(ALPHA))
        await env.publish(bundle(BETA))
        good = await env.service.check(
            CheckContext(signed_context=kit.signer.issue(BETA)), "output", "Hello."
        )
        assert good.tenant_id == BETA and good.decision is Decision.ALLOW
        forged = kit.forge(kit.claims(tid=BETA), private=Ed25519Key.generate())
        bad = await env.service.check(CheckContext(signed_context=forged), "output", "Hello.")
    assert (bad.decision, bad.reason) == (Decision.FORBIDDEN, Reason.CONTEXT_INVALID)
    assert bad.tenant_id is None
