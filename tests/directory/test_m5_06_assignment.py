"""M5-06 on the directory's write path: a regulated tenant is assigned a dedicated Gemini project
when it is created or raised (refused, in production and staging, when none is free; the shared
pool with a warning in test), one tenant per project, a label and never a key."""

from __future__ import annotations

import pytest

from guardrail_engine.authz import Principal, Role
from guardrail_engine.directory import (
    InMemoryDirectoryStore,
    InMemoryEventBus,
    InvalidTenantRecord,
    NotAPlatformOperator,
    TenantProvisioner,
)
from guardrail_engine.projects import DedicatedProjects, NoDedicatedProject

OPS = Principal("ops-1", None, frozenset(), True)
ALICE = Principal("alice", "t_alpha", frozenset({Role.GUARDRAIL_ADMIN}))


def build(*, projects=None):
    store, bus = InMemoryDirectoryStore(), InMemoryEventBus()
    prov = TenantProvisioner(store, bus, clock=lambda: 1_700_000_000.0, projects=projects)
    return prov, store, bus, None, None


async def test_only_a_platform_operator_assigns_a_project():
    prov, store, _, _, _ = build(projects=DedicatedProjects.of(["reg-1"], environment="test"))
    record = await prov.create(OPS, slug="acme", domain="insurance")
    with pytest.raises(NotAPlatformOperator):
        await prov.assign_project(ALICE, record.tenant_id, 1, "reg-1")
    with pytest.raises(NotAPlatformOperator):
        await prov.create(
            ALICE, slug="other", domain="insurance", tier="regulated", project="reg-1"
        )
    assert (await store.get(record.tenant_id)).project is None


# ---------------------------------------------------------------- M5-06: the dedicated project


async def test_a_regulated_tenant_gets_a_dedicated_project_when_created_or_raised():
    prov, store, _, _, _ = build(
        projects=DedicatedProjects.of(["reg-1", "reg-2"], environment="production")
    )
    created = await prov.create(OPS, slug="bank", domain="finance", tier="regulated")
    plain = await prov.create(OPS, slug="shop", domain="insurance")  # standard: shared
    assert (created.project, plain.project) == ("reg-1", None)
    change = await prov.set_tier(OPS, plain.tenant_id, 1, "regulated", "contract")
    assert (change.record.project, change.project_assigned) == ("reg-2", "reg-2")
    # the assignment is in the same class A event as the tier
    event = (await store.audit_events(plain.tenant_id))[-1]
    assert (event.before["project"], event.after["project"]) == (None, "reg-2")
    # lowering the tier keeps the project (billing continuity); an operator releases it
    lowered = await prov.set_tier(OPS, plain.tenant_id, 2, "standard", "downgrade")
    assert lowered.record.project == "reg-2"


async def test_an_explicit_project_must_be_configured_and_free():
    prov, _, _, _, _ = build(
        projects=DedicatedProjects.of(["reg-1", "reg-2"], environment="production")
    )
    first = await prov.create(OPS, slug="bank", domain="finance", tier="regulated", project="reg-2")
    assert first.project == "reg-2"
    with pytest.raises(InvalidTenantRecord, match="not a configured"):
        await prov.create(OPS, slug="a", domain="finance", tier="regulated", project="nope")
    with pytest.raises(InvalidTenantRecord, match="already assigned"):
        await prov.create(OPS, slug="b", domain="finance", tier="regulated", project="reg-2")
    # the next regulated tenant takes the one that is free
    nxt = await prov.create(OPS, slug="c", domain="finance", tier="regulated")
    assert nxt.project == "reg-1"


@pytest.mark.parametrize("environment", ["production", "staging"])
@pytest.mark.parametrize("configured", [[], ["reg-1"]])
async def test_production_and_staging_refuse_a_regulated_tenant_with_no_dedicated_project(
    environment, configured
):
    prov, store, bus, _, _ = build(
        projects=DedicatedProjects.of(configured, environment=environment)
    )
    if configured:
        await prov.create(OPS, slug="first", domain="finance", tier="regulated")  # takes it
    before = len(await store.list())
    with pytest.raises(NoDedicatedProject, match="no dedicated Gemini project is free"):
        await prov.create(OPS, slug="bank", domain="finance", tier="regulated")
    standard = await prov.create(OPS, slug="shop", domain="insurance")
    with pytest.raises(NoDedicatedProject) as raised:
        await prov.set_tier(OPS, standard.tenant_id, 1, "regulated", "contract")
    assert "'projects' setting" in str(raised.value) and environment in str(raised.value)
    with pytest.raises(NoDedicatedProject):
        await prov.update(OPS, standard.tenant_id, 1, tier="dedicated")
    # nothing was written for the refusals: the tenant is still standard, on version 1
    assert (await store.get(standard.tenant_id)).tier == "standard"
    assert (await store.get(standard.tenant_id)).version == 1
    assert len(await store.list()) == before + 1  # only the standard tenant
    assert [e.kind for e in bus.published].count("set_tier") == 0


async def test_test_falls_back_to_the_shared_pool_with_a_warning(caplog):
    prov, _, _, _, _ = build(projects=DedicatedProjects.of([], environment="test"))
    record = await prov.create(OPS, slug="bank", domain="finance", tier="regulated")
    assert (record.tier, record.project) == ("regulated", None)  # the shared pool
    assert "using the shared pool" in caplog.text
    caplog.clear()
    plain = await prov.create(OPS, slug="shop", domain="insurance")
    change = await prov.set_tier(OPS, plain.tenant_id, 1, "regulated", "contract")
    assert change.record.project is None and "using the shared pool" in caplog.text


async def test_an_existing_regulated_tenant_is_brought_into_the_pools_by_assign_project():
    prov, _, _, _, _ = build()  # no pools yet: a legacy regulated tenant, no project
    legacy = await prov.create(OPS, slug="old", domain="finance", tier="regulated")
    assert legacy.project is None
    prov._projects = DedicatedProjects.of(["reg-1"], environment="production")
    assigned = await prov.assign_project(OPS, legacy.tenant_id, 1)
    assert assigned.project == "reg-1" and assigned.version == 2
    same = await prov.assign_project(OPS, legacy.tenant_id, 2)  # already there: nothing to write
    assert same.version == 2


async def test_a_terminated_tenant_gives_its_project_back():
    prov, store, _, _, _ = build(projects=DedicatedProjects.of(["reg-1"], environment="production"))
    prov._drain_s = 0.0
    first = await prov.create(OPS, slug="gone", domain="finance", tier="regulated")
    await prov.terminate(OPS, first.tenant_id, "contract ended")
    second = await prov.create(OPS, slug="next", domain="finance", tier="regulated")
    assert second.project == "reg-1"
    assert (await store.get(first.tenant_id)).project == "reg-1"  # the old record is class A


def test_a_project_is_a_label_never_a_key():
    from guardrail_engine.directory import TenantRecord

    for bad in ("AIzaSyD-fake-key-0123456789", "Reg_1", "default", "x" * 41, ""):
        with pytest.raises(InvalidTenantRecord, match="project"):
            TenantRecord("t_acme1", "acme", "finance", project=bad)
    assert TenantRecord("t_acme1", "acme", "finance", project="acme-reg").project == "acme-reg"
    with pytest.raises(ValueError):
        DedicatedProjects(("ok", "Not Ok"))


async def test_the_assignment_round_trips_and_is_audited_on_memory_and_postgres(store):
    from guardrail_engine.directory import TenantExists, TenantRecord
    from guardrail_engine.directory.model import DirectoryAuditEvent

    prov = TenantProvisioner(
        store, InMemoryEventBus(), projects=DedicatedProjects.of(["a", "b"], environment="staging")
    )
    first = await prov.create(OPS, slug="one", domain="finance", tier="regulated")
    second = await prov.create(OPS, slug="two", domain="finance", tier="dedicated")
    assert (first.project, second.project) == ("a", "b")
    assert (await store.get(first.tenant_id)).project == "a"
    assert {r.tenant_id: r.project for r in await store.list()} == {
        first.tenant_id: "a",
        second.tenant_id: "b",
    }
    [created] = await store.audit_events(first.tenant_id)
    assert created.after["project"] == "a" and created.before is None
    with pytest.raises(NoDedicatedProject):
        await prov.create(OPS, slug="three", domain="finance", tier="regulated")
    # the store itself holds one tenant per project, whoever writes
    clash = TenantRecord("t_clash1", "clash", "finance", tier="regulated", project="a")
    with pytest.raises(TenantExists):
        await store.insert(clash, DirectoryAuditEvent("t_clash1", 1, "create", "x", 0.0, None, {}))
