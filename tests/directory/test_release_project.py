"""An operator releases a lowered tenant's dedicated project; an empty pool alerts besides
refusing; and a candidate that falls short of a raised tier raises an alert."""

from __future__ import annotations

import pytest
from guard_fixtures import CLAIMS_V1, FLOOR_V1

from guardrail_engine.authz import Principal, Role
from guardrail_engine.directory import (
    InMemoryDirectoryStore,
    InMemoryEventBus,
    NotAPlatformOperator,
    ProjectInUse,
    TenantNotFound,
    TenantProvisioner,
    TenantTerminated,
)
from guardrail_engine.directory.tier import CatalogTierImpact
from guardrail_engine.gateway.sinks import (
    ALERT_DEDICATED_POOL_EMPTY,
    ALERT_TIER_RAISE_UNMET,
    AlertSeverity,
    RecordingAlertSink,
)
from guardrail_engine.policy import InMemoryCatalog
from guardrail_engine.policy.document import parse_bundle
from guardrail_engine.projects import DedicatedProjects, NoDedicatedProject

OPS = Principal("ops-1", None, frozenset(), True)
ALICE = Principal("alice", "t_alpha", frozenset({Role.GUARDRAIL_ADMIN}))


def build(labels=("reg-1",), environment="production", *, impact=None):
    store, bus, alerts = InMemoryDirectoryStore(), InMemoryEventBus(), RecordingAlertSink()
    prov = TenantProvisioner(
        store, bus, clock=lambda: 1_700_000_000.0, alerts=alerts, impact=impact,
        projects=DedicatedProjects.of(list(labels), environment=environment),
    )  # fmt: skip
    return prov, store, bus, alerts


# ---------------------------------------------------------------- release_project


async def test_a_lowered_tenants_project_is_released_and_the_next_regulated_tenant_gets_it():
    prov, store, bus, _ = build()
    bank = await prov.create(OPS, slug="bank", domain="finance", tier="regulated")
    assert bank.project == "reg-1"
    lowered = await prov.set_tier(OPS, bank.tenant_id, 1, "standard", "downgrade")
    assert lowered.record.project == "reg-1"  # kept until an operator releases it
    with pytest.raises(NoDedicatedProject):  # so the pool is empty meanwhile
        await prov.create(OPS, slug="next", domain="finance", tier="regulated")

    released = await prov.release_project(OPS, bank.tenant_id)
    assert (released.project, released.tier, released.version) == (None, "standard", 3)
    assert (await store.get(bank.tenant_id)).project is None
    nxt = await prov.create(OPS, slug="next", domain="finance", tier="regulated")
    assert nxt.project == "reg-1"
    # class A: the actor, the project before and gone after, the reason; and the bus is told
    event = next(e for e in await store.audit_events(bank.tenant_id) if e.version == 3)
    assert (event.action, event.actor) == ("update", "ops-1")
    assert (event.before["project"], event.after["project"]) == ("reg-1", None)
    assert event.after["reason"] == "release_project reg-1"
    assert [e.version for e in bus.published if e.tenant_id == bank.tenant_id][-1] == 3


async def test_release_is_refused_while_the_tenant_is_regulated_and_nothing_is_written():
    prov, store, _, _ = build()
    for tier in ("regulated", "dedicated"):
        record = await prov.create(OPS, slug=f"t-{tier}", domain="finance")
        raised = await prov.set_tier(OPS, record.tenant_id, 1, tier, "contract")
        project = raised.record.project
        with pytest.raises(ProjectInUse):
            await prov.release_project(OPS, record.tenant_id)
        kept = await store.get(record.tenant_id)
        assert (kept.project, kept.version) == (project, 2)
        await prov.set_tier(OPS, record.tenant_id, 2, "standard", "downgrade")
        await prov.release_project(OPS, record.tenant_id)  # the next loop turn needs it free


async def test_only_a_platform_operator_releases_a_project():
    prov, store, _, _ = build()
    record = await prov.create(OPS, slug="bank", domain="finance", tier="regulated")
    await prov.set_tier(OPS, record.tenant_id, 1, "standard", "downgrade")
    for caller in (ALICE, Principal("ops-2", "t_alpha", frozenset({Role.GUARDRAIL_ADMIN}), False)):
        with pytest.raises(NotAPlatformOperator):
            await prov.release_project(caller, record.tenant_id)
    assert (await store.get(record.tenant_id)).project == "reg-1"


async def test_releasing_a_tenant_with_no_project_writes_nothing_and_unknown_or_ended_is_refused():
    prov, store, _, _ = build()
    plain = await prov.create(OPS, slug="shop", domain="insurance")
    assert (await prov.release_project(OPS, plain.tenant_id)).version == 1
    assert len(await store.audit_events(plain.tenant_id)) == 1
    with pytest.raises(TenantNotFound):
        await prov.release_project(OPS, "t_nobody")
    prov._drain_s = 0.0
    held = await prov.create(OPS, slug="bank", domain="finance", tier="regulated")
    await prov.terminate(OPS, held.tenant_id, "contract ended")
    with pytest.raises(TenantTerminated):
        await prov.release_project(OPS, held.tenant_id)


# ---------------------------------------------------------------- dedicated_pool_empty


@pytest.mark.parametrize("environment", ["production", "staging"])
async def test_an_empty_pool_alerts_as_well_as_refusing(environment):
    prov, store, _, alerts = build((), environment)
    with pytest.raises(NoDedicatedProject):
        await prov.create(OPS, slug="bank", domain="finance", tier="regulated")
    [alert] = alerts.warnings(ALERT_DEDICATED_POOL_EMPTY)
    assert (alert.severity, alert.tenant_id, alert.reason) == (
        AlertSeverity.WARNING,
        "",
        "pool_empty",
    )
    assert "was refused" in alert.message and "'projects' setting" in alert.message
    assert await store.list() == []  # nothing was written
    # a raise that finds none free alerts too
    standard = await prov.create(OPS, slug="shop", domain="insurance")
    with pytest.raises(NoDedicatedProject):
        await prov.set_tier(OPS, standard.tenant_id, 1, "regulated", "contract")
    assert len(alerts.warnings(ALERT_DEDICATED_POOL_EMPTY)) == 2
    assert standard.tenant_id in alerts.warnings(ALERT_DEDICATED_POOL_EMPTY)[-1].message


async def test_the_test_fallback_alerts_too_and_a_free_project_or_standard_tenant_does_not():
    prov, _, _, alerts = build((), "test")
    shared = await prov.create(OPS, slug="bank", domain="finance", tier="regulated")
    assert shared.project is None
    [alert] = alerts.warnings(ALERT_DEDICATED_POOL_EMPTY)
    assert "uses the shared pool" in alert.message

    prov, _, _, alerts = build(("reg-1",), "production")
    await prov.create(OPS, slug="shop", domain="insurance")  # standard: no project needed
    await prov.create(OPS, slug="bank", domain="finance", tier="regulated")  # one is free
    assert alerts.alerts == []


# ---------------------------------------------------------------- the candidate's gaps


def doc(tenant_id, *extends):
    return {
        "schema_version": 1, "tenant_id": tenant_id, "version": 1,
        "extends": ["platform/floor@1", *extends], "overrides": [],
    }  # fmt: skip


class Versions:
    """Each tenant's active and candidate bundle, as the tier service's loaders read them."""

    def __init__(self):
        self.active: dict[str, dict] = {}
        self.candidate: dict[str, dict] = {}

    async def load_active(self, tenant_id):
        found = self.active.get(tenant_id)
        return None if found is None else parse_bundle(found)

    async def load_candidate(self, tenant_id):
        found = self.candidate.get(tenant_id)
        return None if found is None else parse_bundle(found)


def claims_impact(versions):
    catalog = InMemoryCatalog(
        floors=[FLOOR_V1], packs=[CLAIMS_V1], tier_required_packs={"regulated": ["claims"]}
    )
    return CatalogTierImpact(catalog, versions.load_active, versions.load_candidate)


async def test_a_raise_reports_and_alerts_a_candidate_that_falls_short():
    versions = Versions()
    prov, _, _, alerts = build(("reg-1",), impact=claims_impact(versions))
    record = await prov.create(OPS, slug="acme", domain="insurance")
    versions.active[record.tenant_id] = doc(record.tenant_id, "domain/claims@1")  # meets it
    versions.candidate[record.tenant_id] = doc(record.tenant_id)  # does not
    change = await prov.set_tier(OPS, record.tenant_id, 1, "regulated", "contract")
    assert change.gaps == () and change.candidate_gaps == ("pack:claims",)
    [alert] = alerts.warnings(ALERT_TIER_RAISE_UNMET)  # one alert, though the active is fine
    assert alert.tenant_id == record.tenant_id
    assert alert.reason == "candidate:pack:claims"
    assert "candidate" in alert.message and "can't be promoted" in alert.message


async def test_the_active_and_the_candidate_gaps_are_both_in_the_one_alert():
    versions = Versions()
    prov, _, _, alerts = build(("reg-1",), impact=claims_impact(versions))
    record = await prov.create(OPS, slug="acme", domain="insurance")
    versions.active[record.tenant_id] = doc(record.tenant_id)
    versions.candidate[record.tenant_id] = doc(record.tenant_id)
    change = await prov.set_tier(OPS, record.tenant_id, 1, "regulated", "contract")
    assert (change.gaps, change.candidate_gaps) == (("pack:claims",), ("pack:claims",))
    [alert] = alerts.warnings(ALERT_TIER_RAISE_UNMET)
    assert alert.reason == "pack:claims; candidate:pack:claims"
    assert "keeps running" in alert.message and "can't be promoted" in alert.message


async def test_a_candidate_that_meets_the_tier_or_no_candidate_adds_nothing():
    versions = Versions()
    prov, _, _, alerts = build(("reg-1", "reg-2"), impact=claims_impact(versions))
    meets = await prov.create(OPS, slug="meets", domain="insurance")
    none = await prov.create(OPS, slug="none", domain="insurance")
    for record in (meets, none):
        versions.active[record.tenant_id] = doc(record.tenant_id, "domain/claims@1")
    versions.candidate[meets.tenant_id] = doc(meets.tenant_id, "domain/claims@1")
    for record in (meets, none):
        change = await prov.set_tier(OPS, record.tenant_id, 1, "regulated", "contract")
        assert change.candidate_gaps == ()
    assert alerts.alerts == []
