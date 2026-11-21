"""M1-11 (decided 2026-11-17): ``Engine.bootstrap_publish()`` compiles, stores and activates a
bundle without the Admin API, for the dogfood and the demo only. It is refused when
``environment`` is ``production`` (the default) or the tenant's tier isn't ``standard``, and
it writes a class A audit event (actor ``bootstrap``, the diff and the hash) before
activating. It was called ``publish()`` earlier."""

from __future__ import annotations

import inspect
import json
import logging

import pytest
from engine_fixtures import (
    FLOOR_FILE,
    TENANT,
    bundle,
    ctx,
    directory,
    profile,
    settings,
    verifier,
)

from guardrail_engine.decision import FakeDecisionModel
from guardrail_engine.engine import (
    ADMIN_AUDIT_LOGGER,
    BootstrapRefusedError,
    Engine,
    EngineSettings,
    InMemoryAdminAuditSink,
    build_engine,
    document_diff,
)
from guardrail_engine.guard import Decision

REGULATED = "t_regulated"


class DurableRecorder(InMemoryAdminAuditSink):
    """An in-memory sink that declares itself durable, standing in for a durable one where
    the test is about something else."""

    durable = True


async def build(environment: str = "test", **kwargs):
    v = verifier()
    admin = kwargs.pop("admin_audit", InMemoryAdminAuditSink())
    engine = await build_engine(
        settings(environment=environment),
        verifier=v,
        tenants=directory(profile(), profile(REGULATED, tier="regulated")),
        model=FakeDecisionModel(),
        admin_audit=admin,
        **kwargs,
    )
    return engine, v, admin


def test_the_privileged_path_is_named_as_a_bootstrap_and_documented_as_privileged():
    assert not hasattr(Engine, "publish")
    doc = inspect.getdoc(Engine.bootstrap_publish) or ""
    assert doc.startswith("**Privileged.**")
    assert "without the Admin API" in doc and "SDK" in doc


def test_the_environment_defaults_to_production():
    assert EngineSettings().environment == "production"


async def test_refused_in_production():
    engine, _, admin = await build(environment="production")
    try:
        with pytest.raises(BootstrapRefusedError, match="environment is 'production'"):
            await engine.bootstrap_publish(bundle())
        assert await engine.store.list_versions(TENANT) == []  # nothing stored
        assert admin.events == []
    finally:
        await engine.shutdown()


async def test_refused_by_default_settings():
    """Settings that don't name an environment are production."""
    v = verifier()
    s = EngineSettings.from_mapping(
        {
            "catalog": {"floor_files": [str(FLOOR_FILE)]},
            "signed_context": {"allow_v1_hmac": True},  # v1 verifier below: allowed for this test
        }
    )
    engine = await build_engine(s, verifier=v, tenants=directory(), model=FakeDecisionModel())
    try:
        with pytest.raises(BootstrapRefusedError):
            await engine.bootstrap_publish(bundle())
    finally:
        await engine.shutdown()


@pytest.mark.parametrize("tier", ["regulated", "enterprise", "Standard", ""])
async def test_refused_for_a_tenant_whose_tier_is_not_standard(tier):
    """M5-01 hasn't fixed the regulated-tier attribute's values yet, so anything other than
    ``standard`` is refused: a new or misspelt tier never gets the unapproved path."""
    tenant = "t_other"
    v = verifier()
    admin = InMemoryAdminAuditSink()
    engine = await build_engine(
        settings(),
        verifier=v,
        tenants=directory(profile(tenant, tier=tier)),
        model=FakeDecisionModel(),
        admin_audit=admin,
    )
    try:
        with pytest.raises(BootstrapRefusedError, match="only the standard tier"):
            await engine.bootstrap_publish(bundle(tenant))
        assert await engine.store.list_versions(tenant) == []
        assert admin.events == []
    finally:
        await engine.shutdown()


@pytest.mark.parametrize("environment", ["staging", "test"])
async def test_audited_otherwise(environment):
    """Allowed in staging (the dogfood) and test (tests and the demo), the only other values
    ``environment`` may take (decided 2026-11-17). Staging needs a durable sink."""
    engine, v, admin = await build(environment=environment, admin_audit=DurableRecorder())
    try:
        first = await engine.bootstrap_publish(bundle())
        second_doc = {**bundle(version=2), "defaults": {"fail_mode": "closed"}}
        second = await engine.bootstrap_publish(second_doc)
        verdict = await engine.check(ctx(v), "output", "Hello.")
    finally:
        await engine.shutdown()
    assert verdict.decision is Decision.ALLOW and verdict.bundle_version == 2
    one, two = admin.events
    assert (one.actor, one.audit_class, one.action) == ("bootstrap", "A", "bootstrap_publish")
    assert (one.tenant_id, one.version, one.bundle_hash) == (TENANT, 1, first)
    assert one.environment == environment
    assert (one.previous_version, one.previous_bundle_hash) == (None, None)
    assert {d.path for d in one.diff} == set(f"/{k}" for k in bundle())  # all added
    assert all(d.op == "add" for d in one.diff)
    assert (two.version, two.bundle_hash, two.previous_version) == (2, second, 1)
    assert two.previous_bundle_hash == first
    assert [(d.path, d.op, d.before, d.after) for d in two.diff] == [
        ("/defaults", "add", None, {"fail_mode": "closed"}),
        ("/version", "replace", 1, 2),
    ]
    assert one.activate and two.activate


async def test_the_event_is_written_before_activation_and_a_failed_write_activates_nothing():
    class BrokenAdminAudit:
        def record_admin(self, event) -> None:
            raise RuntimeError("audit store down")

    engine, _, _ = await build(admin_audit=BrokenAdminAudit())
    try:
        with pytest.raises(RuntimeError, match="audit store down"):
            await engine.bootstrap_publish(bundle())
        assert await engine.store.get_active_version(TENANT) is None
    finally:
        await engine.shutdown()


async def test_without_activation_the_pointer_does_not_move():
    engine, _, admin = await build()
    try:
        await engine.bootstrap_publish(bundle(), activate=False)
        assert await engine.store.get_active_version(TENANT) is None
    finally:
        await engine.shutdown()
    [event] = admin.events
    assert event.activate is False


async def test_the_default_admin_sink_logs_one_json_line(caplog):
    v = verifier()
    engine = await build_engine(
        settings(), verifier=v, tenants=directory(), model=FakeDecisionModel()
    )
    try:
        with caplog.at_level(logging.INFO, logger=ADMIN_AUDIT_LOGGER):
            bundle_hash = await engine.bootstrap_publish(bundle())
    finally:
        await engine.shutdown()
    [record] = [r for r in caplog.records if r.name == ADMIN_AUDIT_LOGGER]
    event = json.loads(record.getMessage().removeprefix("class A audit event "))
    assert event["actor"] == "bootstrap" and event["bundle_hash"] == bundle_hash


def test_document_diff():
    before = {"a": 1, "b": [1, 2, 3], "c": {"d": True}, "e/f": 0}
    after = {"a": 1.0, "b": [1, 5], "c": {"d": 1}, "g": None, "e/f": 0}
    assert [(d.path, d.op, d.before, d.after) for d in document_diff(before, after)] == [
        ("/a", "replace", 1, 1.0),
        ("/b/1", "replace", 2, 5),
        ("/b/2", "remove", 3, None),
        ("/c/d", "replace", True, 1),
        ("/g", "add", None, None),
    ]
    assert document_diff(before, before) == ()
