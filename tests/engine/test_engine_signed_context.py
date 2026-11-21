"""M2-01 factory wiring: the v2 verifier from a keyset source, the v1 HMAC rule in production,
the keyset refresher's lifecycle, and the Admin API's authenticator and authorizer."""

from __future__ import annotations

import asyncio
import json
import logging

import pytest
from engine_fixtures import TENANT, bundle, ctx, directory, settings, verifier

from guardrail_engine.authz import InMemoryAuthzAudit
from guardrail_engine.decision import FakeDecisionModel
from guardrail_engine.engine import EngineSettings, SettingsError, build_engine
from guardrail_engine.engine.factory import EngineStartError
from guardrail_engine.guard import CheckContext, Decision, Reason
from guardrail_engine.guard.signed_context import Ed25519ContextSigner
from guardrail_engine.signing.adapters.ed25519 import Ed25519Key, Ed25519Verifier

ISSUER = "gateway-eu"
LOAD = Ed25519Verifier.from_raw


class Source:
    def __init__(self, document):
        self.document = document
        self.reads = 0

    async def read(self):
        self.reads += 1
        if isinstance(self.document, Exception):
            raise self.document
        return self.document


def keyset_doc(key, kid="k1"):
    return json.dumps({"keys": [{"kid": kid, "x": key.public_text(), "valid_from": 0}]})


def v2_settings(environment="test", **sc):
    return settings(environment, signed_context={"issuers": [ISSUER], **sc})


async def build_v2(key, environment="test", source=None, **kw):
    source = source or Source(keyset_doc(key))
    engine = await build_engine(
        v2_settings(environment), keyset_source=source, key_loader=LOAD,
        tenants=directory(), model=FakeDecisionModel(), **kw,
    )  # fmt: skip
    return engine, source


# ---------------------------------------------------------------------------- the v1 rule


async def test_a_v1_verifier_is_refused_in_production_by_default():
    with pytest.raises(SettingsError, match="allow_v1_hmac") as info:
        await build_engine(
            settings("production", signed_context={"allow_v1_hmac": False}),
            verifier=verifier(), tenants=directory(), model=FakeDecisionModel(),
        )  # fmt: skip
    assert "refused in production" in str(info.value)


async def test_production_default_settings_refuse_v1_without_naming_any_setting():
    with pytest.raises(SettingsError, match="allow_v1_hmac"):
        await build_engine(
            EngineSettings.from_mapping({}), verifier=verifier(), tenants=directory(),
            model=FakeDecisionModel(),
        )  # fmt: skip


async def test_the_migration_setting_lets_production_run_v1_and_it_is_recorded(caplog):
    caplog.set_level(logging.INFO, logger="guardrail_engine.engine.factory")
    engine = await build_engine(
        settings("production", signed_context={"allow_v1_hmac": True}),
        verifier=verifier(), tenants=directory(), model=FakeDecisionModel(),
    )  # fmt: skip
    try:
        assert engine.signed_context_mode == "v1"
        assert engine.settings.signed_context.allow_v1_hmac is True
        assert "accepting v1 HMAC signed contexts" in caplog.text
        assert "signed_context=v1" in caplog.text
    finally:
        await engine.shutdown()


async def test_the_v1_rule_does_not_apply_in_test():
    engine = await build_engine(
        settings("test", signed_context={"allow_v1_hmac": False}),
        verifier=verifier(), tenants=directory(), model=FakeDecisionModel(),
    )  # fmt: skip
    await engine.shutdown()


async def test_the_v1_rule_applies_in_staging_too():
    """Staging takes production-shaped traffic."""
    with pytest.raises(SettingsError, match="refused in staging"):
        await build_engine(
            settings("staging", signed_context={"allow_v1_hmac": False}),
            verifier=verifier(), tenants=directory(), model=FakeDecisionModel(),
        )  # fmt: skip


def test_allow_v1_hmac_defaults_to_false():
    assert EngineSettings().signed_context.allow_v1_hmac is False


# ---------------------------------------------------------------------------- v2


async def test_the_engine_checks_with_a_v2_context_and_refuses_v1_and_forged_ones(caplog):
    key = Ed25519Key.generate()
    engine, _ = await build_v2(key)
    try:
        assert engine.signed_context_mode == "v2"
        await engine.bootstrap_publish(bundle())
        signer = Ed25519ContextSigner(key, "k1", ISSUER)
        ok = await engine.check(CheckContext(signed_context=signer.issue(TENANT)), "output", "Hi.")
        assert ok.decision is Decision.ALLOW
        for bad in (
            verifier().issue(TENANT),  # a v1 HMAC context
            Ed25519ContextSigner(Ed25519Key.generate(), "k1", ISSUER).issue(TENANT),  # forged
            Ed25519ContextSigner(key, "k1", "gateway-us").issue(TENANT),  # wrong issuer
        ):
            verdict = await engine.check(CheckContext(signed_context=bad), "output", "Hi.")
            assert (verdict.decision, verdict.reason) == (
                Decision.FORBIDDEN,
                Reason.CONTEXT_INVALID,
            )
    finally:
        await engine.shutdown()


async def test_v1_is_refused_even_in_production_without_a_legacy_verifier():
    key = Ed25519Key.generate()
    engine, _ = await build_v2(key, environment="production")
    try:
        assert engine.signed_context_mode == "v2"  # no allow_v1_hmac needed: v1 is not accepted
        verdict = await engine.check(ctx(verifier()), "output", "Hi.")
        assert verdict.reason is Reason.CONTEXT_INVALID
    finally:
        await engine.shutdown()


async def test_a_legacy_verifier_runs_beside_v2_only_when_the_migration_is_allowed():
    key = Ed25519Key.generate()
    common = dict(keyset_source=Source(keyset_doc(key)), key_loader=LOAD, tenants=directory(),
                  model=FakeDecisionModel())  # fmt: skip
    with pytest.raises(SettingsError, match="legacy"):
        await build_engine(
            v2_settings("production", allow_v1_hmac=False), legacy_verifier=verifier(), **common
        )
    engine = await build_engine(
        v2_settings("production", allow_v1_hmac=True), legacy_verifier=verifier(), **common
    )
    try:
        assert engine.signed_context_mode == "v2+v1_migration"
        await engine.bootstrap_publish(bundle()) if engine.settings.environment != "production" \
            else None  # fmt: skip
        v1 = await engine.check(ctx(verifier()), "output", "Hi.")
        signer = Ed25519ContextSigner(key, "k1", ISSUER)
        v2 = await engine.check(CheckContext(signed_context=signer.issue(TENANT)), "output", "Hi.")
        assert v1.reason is not Reason.CONTEXT_INVALID and v2.reason is not Reason.CONTEXT_INVALID
    finally:
        await engine.shutdown()


# ---------------------------------------------------------------------------- the wiring rules


async def test_pass_a_verifier_or_a_keyset_source_not_both_or_neither():
    key = Ed25519Key.generate()
    base = dict(tenants=directory(), model=FakeDecisionModel())
    with pytest.raises(SettingsError, match="not both"):
        await build_engine(
            v2_settings(), verifier=verifier(), keyset_source=Source(keyset_doc(key)),
            key_loader=LOAD, **base,
        )  # fmt: skip
    with pytest.raises(SettingsError, match="both keyset_source and key_loader"):
        await build_engine(v2_settings(), **base)
    with pytest.raises(SettingsError, match="both keyset_source and key_loader"):
        await build_engine(v2_settings(), keyset_source=Source(keyset_doc(key)), **base)


async def test_a_keyset_source_needs_issuers():
    key = Ed25519Key.generate()
    with pytest.raises(SettingsError, match=r"signed_context\.issuers"):
        await build_engine(
            settings("test"), keyset_source=Source(keyset_doc(key)), key_loader=LOAD,
            tenants=directory(), model=FakeDecisionModel(),
        )  # fmt: skip


async def test_a_bad_issuer_name_is_a_settings_error():
    with pytest.raises(SettingsError):
        settings("test", signed_context={"issuers": ["has space"]})


@pytest.mark.parametrize("document", ["not json", '{"keys": []}', ConnectionError("down")])
async def test_an_invalid_or_unreadable_first_keyset_stops_startup_and_leaves_nothing_running(
    document,
):
    before = len(asyncio.all_tasks())
    with pytest.raises(EngineStartError, match="signed context keyset"):
        await build_engine(
            v2_settings(), keyset_source=Source(document), key_loader=LOAD,
            tenants=directory(), model=FakeDecisionModel(),
        )  # fmt: skip
    assert len(asyncio.all_tasks()) == before


# ---------------------------------------------------------------------------- the refresher


async def test_the_refresher_runs_while_the_engine_does_and_stops_at_shutdown():
    key = Ed25519Key.generate()
    engine, source = await build_v2(key)
    refresher = engine._background_close.close.__self__
    await asyncio.sleep(0)  # let the task take its first turn
    assert refresher._task is not None and not refresher._task.done()
    assert source.reads >= 2  # startup read + the refresher's first read
    await engine.shutdown()
    assert refresher._task is None
    assert all(t.done() or t is asyncio.current_task() for t in asyncio.all_tasks()
               if "KeysetRefresher" in repr(t))  # fmt: skip


async def test_a_new_keyset_document_changes_who_may_sign_without_a_restart():
    old, new = Ed25519Key.generate(), Ed25519Key.generate()
    engine, source = await build_v2(old)
    try:
        await engine.bootstrap_publish(bundle())
        token_new = Ed25519ContextSigner(new, "k2", ISSUER).issue(TENANT)
        before = await engine.check(CheckContext(signed_context=token_new), "output", "Hi.")
        assert before.reason is Reason.CONTEXT_INVALID  # k2 is not in the keyset yet
        source.document = json.dumps({"keys": [
            {"kid": "k1", "x": old.public_text(), "valid_from": 0},
            {"kid": "k2", "x": new.public_text(), "valid_from": 0},
        ]})  # fmt: skip
        refresher = engine._background_close.close.__self__
        assert await refresher.refresh_once() is True  # the 60 s loop, run by hand
        after = await engine.check(CheckContext(signed_context=token_new), "output", "Hi.")
        assert after.reason is not Reason.CONTEXT_INVALID
    finally:
        await engine.shutdown()


# ---------------------------------------------------------------------------- Admin API pieces


async def test_the_authenticator_and_an_authorizer_are_kept_for_the_rest_layer():
    class Auth:
        async def authenticate(self, token):
            raise AssertionError("not called by the Guard Service")

    auth, audit = Auth(), InMemoryAuthzAudit()
    engine = await build_engine(
        settings("test"), verifier=verifier(), tenants=directory(), model=FakeDecisionModel(),
        authenticator=auth, authz_audit=audit,
    )  # fmt: skip
    try:
        assert engine.authenticator is auth and engine.authorizer is not None
    finally:
        await engine.shutdown()
    bare = await build_engine(
        settings("test"), verifier=verifier(), tenants=directory(), model=FakeDecisionModel()
    )
    assert (bare.authenticator, bare.authorizer) == (None, None)
    await bare.shutdown()
