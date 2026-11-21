"""M3-01 wiring: the engine's cross-tenant identifier scan reads the real tenant directory.

A tenant's registered identifier patterns are written by the platform operator (validated and
audited), reach the scan through the directory's ``tenant.changed`` event, and block in every
other tenant's ``tool_result`` and ``output``; the tenant's own pass."""

import pytest
from engine_fixtures import settings, verifier
from test_engine_propagation import OPS, bundle, draft_and_publish

from guardrail_engine.admin.lifecycle import InMemoryPublishBus
from guardrail_engine.authz import InMemoryAuthzAudit
from guardrail_engine.decision import FakeDecisionModel
from guardrail_engine.deterministic import CROSS_TENANT_RULE
from guardrail_engine.directory import (
    CachedTenantDirectory,
    InMemoryDirectoryStore,
    InMemoryEventBus,
    InvalidTenantRecord,
    TenantProvisioner,
)
from guardrail_engine.engine import build_engine
from guardrail_engine.guard import CheckContext, Decision, Reason

ALPHA_ORDER = "ALP-ORD-4821"
BETA_INVOICE = "BET-INV-9082"


async def world(**engine_kwargs):
    store, bus = InMemoryDirectoryStore(), InMemoryEventBus()
    prov = TenantProvisioner(store, bus, clock=lambda: 1_700_000_000.0)
    alpha = await prov.create(OPS, slug="alpha", domain="insurance")
    beta = await prov.create(OPS, slug="beta", domain="energy")
    cached = CachedTenantDirectory(store, ttl_s=3600.0)
    bus.subscribe(cached.on_changed)
    engine = await build_engine(
        settings("test"),
        verifier=verifier(),
        tenants=cached,
        model=FakeDecisionModel(),
        authz_audit=InMemoryAuthzAudit(),
        publish_bus=InMemoryPublishBus(),
        **engine_kwargs,
    )
    bus.subscribe(engine.on_tenant_changed)
    for tenant in (alpha, beta):
        await draft_and_publish(engine, bundle(tenant.tenant_id), tenant=tenant.tenant_id)
    return prov, store, engine, alpha, beta


async def check(engine, tenant_id, content, point="output"):
    ctx = CheckContext(signed_context=verifier().issue(tenant_id))
    return await engine.check(ctx, point, content)


async def test_another_tenants_id_blocks_and_the_callers_own_passes():
    _, _, engine, alpha, beta = await world()
    try:
        leak = await check(engine, alpha.tenant_id, f"see {beta.tenant_id} records")
        own = await check(engine, alpha.tenant_id, f"see {alpha.tenant_id} records")
        tool = await check(engine, alpha.tenant_id, f"row {beta.tenant_id}", "tool_result")
    finally:
        await engine.shutdown()
    assert (leak.decision, leak.reason) == (Decision.BLOCK, Reason.DETERMINISTIC)
    assert {h.rule for h in leak.deterministic} == {CROSS_TENANT_RULE}
    assert own.decision is Decision.ALLOW
    assert tool.reason is Reason.DETERMINISTIC


async def test_a_registered_pattern_blocks_in_other_tenants_content_and_passes_in_its_own():
    prov, _, engine, alpha, beta = await world()
    try:
        record = await prov.set_identifier_patterns(
            OPS, beta.tenant_id, beta.version, [r"BET-INV-[0-9]{4}"]
        )
        assert record.identifier_patterns == (r"BET-INV-[0-9]{4}",)
        await check(engine, alpha.tenant_id, "Hello.")  # starts the rebuild the event asked for
        await engine.guard._scanner.wait_for_rebuild()
        leak = await check(engine, alpha.tenant_id, f"invoice {BETA_INVOICE}")
        own = await check(engine, beta.tenant_id, f"invoice {BETA_INVOICE}")
    finally:
        await engine.shutdown()
    assert leak.reason is Reason.DETERMINISTIC and not leak.model_called
    assert own.decision is Decision.ALLOW


async def test_a_pattern_the_platform_would_not_review_is_refused_and_nothing_is_stored():
    prov, store, engine, _, beta = await world()
    try:
        for bad in ("[0-9]", ".", "account", "2025-", r"(?i)page [0-9]", "ORD-[a-z]+"):
            with pytest.raises(InvalidTenantRecord, match="identifier pattern refused"):
                await prov.set_identifier_patterns(OPS, beta.tenant_id, beta.version, [bad])
        with pytest.raises(InvalidTenantRecord):
            await prov.set_identifier_patterns(
                OPS, beta.tenant_id, beta.version, [f"BET-{i:02d}-[0-9]{{4}}" for i in range(21)]
            )
        assert (await store.get(beta.tenant_id)).identifier_patterns == ()
        assert (await store.get(beta.tenant_id)).version == beta.version
    finally:
        await engine.shutdown()


async def test_an_engine_over_an_in_memory_directory_scans_for_nothing():
    from engine_fixtures import directory

    engine = await build_engine(
        settings("test"), verifier=verifier(), tenants=directory(),
        model=FakeDecisionModel(), authz_audit=InMemoryAuthzAudit(),
    )  # fmt: skip
    try:
        assert engine.guard._scanner.shard_count == 0
        verdict = await check(engine, "t_acme", "t_other_tenant BET-INV-9082")
    finally:
        await engine.shutdown()
    assert verdict.reason is not Reason.DETERMINISTIC


# ------------------------------------------------------------------ no silent no-scan


@pytest.mark.parametrize("environment", ["production", "staging"])
async def test_a_production_or_staging_engine_with_no_identifier_source_refuses_to_start(
    environment,
):
    from engine_fixtures import profile

    from guardrail_engine.engine import SettingsError
    from guardrail_engine.guard import InMemoryTenantDirectory

    for tenants in (InMemoryTenantDirectory([profile()]), None):  # a plain directory, or omitted
        with pytest.raises(SettingsError, match="other_tenants"):
            await build_engine(
                settings(environment),
                verifier=verifier(),
                tenants=tenants,
                model=FakeDecisionModel(),
                authz_audit=_durable_audit(),
            )


@pytest.mark.parametrize("environment", ["test"])
async def test_test_keeps_scanning_for_nothing_without_a_source(environment):
    """There is no other environment: ``production``, ``staging`` and ``test``."""
    from engine_fixtures import profile

    from guardrail_engine.guard import InMemoryTenantDirectory

    engine = await build_engine(
        settings(environment),
        verifier=verifier(),
        tenants=InMemoryTenantDirectory([profile()]),
        model=FakeDecisionModel(),
        authz_audit=InMemoryAuthzAudit(),
    )
    await engine.shutdown()


@pytest.mark.parametrize("environment", ["production", "staging"])
async def test_the_opt_out_is_explicit_and_logged_as_a_warning(environment, caplog):
    import logging

    from engine_fixtures import profile

    from guardrail_engine.deterministic import NoOtherTenantIdentifiers
    from guardrail_engine.guard import InMemoryTenantDirectory

    with caplog.at_level(logging.WARNING, logger="guardrail_engine.engine.factory"):
        engine = await build_engine(
            settings(environment),
            verifier=verifier(),
            tenants=InMemoryTenantDirectory([profile()]),
            other_tenants=NoOtherTenantIdentifiers(),
            model=FakeDecisionModel(),
            authz_audit=_durable_audit(),
        )
    await engine.shutdown()
    assert any("switched off on purpose" in r.message for r in caplog.records)


@pytest.mark.parametrize("environment", ["production", "staging"])
async def test_a_directory_whose_own_source_scans_nothing_warns_too(environment, caplog):
    """The warning follows the resolved source, not only the argument."""
    import logging

    from engine_fixtures import directory

    with caplog.at_level(logging.WARNING, logger="guardrail_engine.engine.factory"):
        engine = await build_engine(
            settings(environment),
            verifier=verifier(),
            tenants=directory(),  # its other_tenant_identifiers() is NoOtherTenantIdentifiers
            model=FakeDecisionModel(),
            authz_audit=_durable_audit(),
        )
    await engine.shutdown()
    assert any("switched off on purpose" in r.message for r in caplog.records)


@pytest.mark.parametrize("environment", ["production", "staging"])
async def test_a_directory_with_a_source_or_a_passed_source_starts_without_a_warning(
    environment, caplog
):
    import logging

    from guardrail_engine.deterministic import InMemoryOtherTenantIdentifiers

    store = InMemoryDirectoryStore()
    cached = CachedTenantDirectory(store)  # provides its own source
    explicit = InMemoryOtherTenantIdentifiers()
    with caplog.at_level(logging.WARNING, logger="guardrail_engine.engine.factory"):
        for tenants, other in ((cached, None), (cached, explicit)):
            engine = await build_engine(
                settings(environment),
                verifier=verifier(),
                tenants=tenants,
                other_tenants=other,
                model=FakeDecisionModel(),
                authz_audit=_durable_audit(),
            )
            await engine.shutdown()
    assert not [r for r in caplog.records if "identifier scan" in r.message]


def _durable_audit():
    return type("Durable", (InMemoryAuthzAudit,), {"durable": True})()


async def test_a_tenants_rejected_patterns_reach_the_guard_services_alert_and_meter():
    """In the default path, the directory's source reports through the Guard Service."""
    from guardrail_engine.directory import TenantRecord
    from guardrail_engine.directory.model import DirectoryAuditEvent, audit_fields
    from guardrail_engine.gateway import InMemoryUsageMeter

    meter = InMemoryUsageMeter()
    _, store, engine, alpha, _ = await world(meter=meter)
    try:
        raw = TenantRecord(
            "t_carelesss", "careless", "energy", identifier_patterns=("[0-9]", r"CAR-INV-[0-9]{4}")
        )
        await store.insert(
            raw, DirectoryAuditEvent(raw.tenant_id, 1, "create", "x", 0.0, None, audit_fields(raw))
        )
        engine.on_tenant_changed(type("E", (), {"tenant_id": raw.tenant_id})())
        await check(engine, alpha.tenant_id, "Hello.")
        await engine.guard._scanner.wait_for_rebuild()
        await engine.guard._gateway.drain()
        leak = await check(engine, alpha.tenant_id, "see CAR-INV-1234")
    finally:
        await engine.shutdown()
    assert leak.reason is Reason.DETERMINISTIC  # its good pattern still scans
    assert meter.identifier_patterns_dropped(raw.tenant_id) == 1


# ------------------------------------------------------------------ M4-01 wiring


async def test_the_engine_builds_the_calibration_service_and_the_gate_uses_it():
    from engine_fixtures import directory

    engine = await build_engine(
        settings("test"), verifier=verifier(), tenants=directory(),
        model=FakeDecisionModel(), authz_audit=InMemoryAuthzAudit(),
    )  # fmt: skip
    try:
        assert engine.calibration_service is not None
        assert engine.publish_service._gate._precision is engine.calibration_service
        assert engine.draft_tools._calibration is engine.calibration_service
    finally:
        await engine.shutdown()


async def test_an_enforcing_tenant_rule_is_refused_by_the_engine_with_the_precision_gate_listed():
    from engine_fixtures import TENANT, directory

    from guardrail_engine.admin import DraftInvalidError

    engine = await build_engine(
        settings("test"), verifier=verifier(), tenants=directory(), model=FakeDecisionModel(),
        authz_audit=InMemoryAuthzAudit(), publish_bus=InMemoryPublishBus(),
    )  # fmt: skip
    try:
        doc = {**bundle(TENANT), "rules": [{
            "id": "refunds", "guard_points": ["output"], "question": "Is this about refunds?",
            "true_description": "Yes.", "false_description": "No.",
        }]}  # fmt: skip
        with pytest.raises(DraftInvalidError) as refused:
            await draft_and_publish(engine, doc)
        codes = {e.code for e in refused.value.errors}
        assert {"evidence_gate.label_counts", "evidence_gate.precision"} <= codes
    finally:
        await engine.shutdown()


@pytest.mark.parametrize("environment", ["production", "staging"])
async def test_a_production_engine_that_can_publish_needs_a_calibration_store(environment):
    """Without a calibration store the precision gate has nothing to read, so no tenant
    rule could ever enforce: refused at build, not discovered at the first publish."""
    from engine_fixtures import directory

    from guardrail_engine.admin import InMemoryDraftStore
    from guardrail_engine.admin.golden import InMemoryGoldenStore
    from guardrail_engine.admin.lifecycle import InMemoryLifecycleStore
    from guardrail_engine.deterministic import NoOtherTenantIdentifiers
    from guardrail_engine.engine import SettingsError
    from guardrail_engine.store import InMemoryPolicyStore

    store = InMemoryPolicyStore(catalog=None)
    with pytest.raises(SettingsError, match="calibration_store"):
        await build_engine(
            settings(environment),
            verifier=verifier(),
            tenants=directory(),
            model=FakeDecisionModel(),
            store=store,
            draft_store=InMemoryDraftStore(),
            golden_store=InMemoryGoldenStore(),
            lifecycle_store=InMemoryLifecycleStore(store),
            other_tenants=NoOtherTenantIdentifiers(),
            authz_audit=type("D", (InMemoryAuthzAudit,), {"durable": True})(),
        )
