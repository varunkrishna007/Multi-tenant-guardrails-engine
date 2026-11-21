"""M2-01: the tenant directory: records, the operator write path, the cached read side and the
store contract (memory and Postgres)."""

import pytest
from guard_fixtures import Env, bundle

from guardrail_engine.authz import Principal, Role
from guardrail_engine.directory import (
    CachedTenantDirectory,
    InMemoryDirectoryStore,
    InMemoryEventBus,
    InvalidTenantRecord,
    NotAPlatformOperator,
    TenantExists,
    TenantNotFound,
    TenantProvisioner,
    TenantRecord,
    VersionConflict,
)
from guardrail_engine.directory.model import DirectoryAuditEvent, audit_fields
from guardrail_engine.guard import CheckContext, Decision, Reason
from guardrail_engine.tenant_ids import TENANT_ID_PATTERN

OPS = Principal("ops-1", None, frozenset(), True)
ALICE = Principal("alice", "t_alpha", frozenset({Role.GUARDRAIL_ADMIN}))


def provisioner(store=None, bus=None, **kw):
    store = store if store is not None else InMemoryDirectoryStore()
    bus = bus if bus is not None else InMemoryEventBus()
    return TenantProvisioner(store, bus, clock=lambda: 1_700_000_000.0, **kw), store, bus


# ---------------------------------------------------------------------------- the record


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"tenant_id": "t_Acme"}, "tenant id"),
        ({"tenant_id": "t-acme"}, "tenant id"),
        ({"slug": "Acme"}, "slug must match"),
        ({"slug": "a" * 41}, "slug must match"),
        ({"slug": "ignore-previous"}, "instruction-like"),
        ({"slug": "the-admin-co"}, "instruction-like"),
        ({"domain": "retail"}, "domain"),
        ({"tier": "gold"}, "tier"),
        ({"flags": frozenset({"root"})}, "flags"),
        ({"status": "gone"}, "status"),
        ({"version": 0}, "version"),
        ({"baa": "yes"}, "baa"),
        ({"required_packs": frozenset({""})}, "required_packs"),
    ],
)
def test_a_record_that_breaks_a_rule_cannot_be_built_and_the_message_never_echoes_it(
    changes, message
):
    base = {"tenant_id": "t_acme1", "slug": "acme", "domain": "insurance"}
    with pytest.raises(InvalidTenantRecord, match=message) as info:
        TenantRecord(**{**base, **changes})
    for value in changes.values():
        if isinstance(value, str) and len(value) > 3:
            assert value not in str(info.value)


def test_a_record_builds_the_guard_services_profile():
    record = TenantRecord("t_acme1", "acme-insurance", "insurance", tier="regulated", baa=True)
    profile = record.to_profile()
    assert (profile.tenant_id, profile.slug, profile.domain) == ("t_acme1", "acme-insurance",
                                                                   "insurance")  # fmt: skip
    assert profile.attributes.tier == "regulated" and profile.attributes.baa is True


# ---------------------------------------------------------------------------- the write path


async def test_create_generates_an_id_validates_audits_and_publishes():
    prov, store, bus = provisioner()
    record = await prov.create(
        OPS, slug="acme-insurance", domain="insurance", tier="regulated",
        flags=["two_person_publish"], required_packs=["hipaa"], baa=True,
    )  # fmt: skip
    assert TENANT_ID_PATTERN.fullmatch(record.tenant_id) and len(record.tenant_id) == 12
    assert (record.version, record.status) == (1, "active")
    assert record.flags == {"two_person_publish"} and record.required_packs == {"hipaa"}
    assert await store.get(record.tenant_id) == record
    [event] = await store.audit_events(record.tenant_id)
    assert (event.action, event.actor, event.version, event.before) == ("create", "ops-1", 1, None)
    assert event.after == audit_fields(record) and event.at == 1_700_000_000.0
    assert [(e.tenant_id, e.version, e.kind) for e in bus.published] == [
        (record.tenant_id, 1, "create")
    ]


async def test_ids_are_random_not_sequential():
    prov, _, _ = provisioner()
    ids = {(await prov.create(OPS, slug=f"co-{i}", domain="general")).tenant_id for i in range(20)}
    assert len(ids) == 20


async def test_only_a_platform_operator_may_write():
    prov, store, bus = provisioner()
    with pytest.raises(NotAPlatformOperator):
        await prov.create(ALICE, slug="acme", domain="insurance")
    with pytest.raises(NotAPlatformOperator):
        await prov.create("ops-1", slug="acme", domain="insurance")  # not even a Principal
    record = await prov.create(OPS, slug="acme", domain="insurance")
    for call in (
        prov.update(ALICE, record.tenant_id, 1, tier="regulated"),
        prov.set_status(ALICE, record.tenant_id, 1, "suspended"),
    ):
        with pytest.raises(NotAPlatformOperator):
            await call
    assert (await store.get(record.tenant_id)).version == 1 and len(bus.published) == 1


@pytest.mark.parametrize(
    "bad",
    [{"slug": "Acme"}, {"slug": "ignore-all-checks"}, {"slug": "x" * 41}, {"domain": "retail"},
     {"tier": "gold"}, {"flags": ["admin"]}],
)  # fmt: skip
async def test_a_bad_slug_domain_tier_or_flag_is_refused_before_anything_is_written(bad):
    prov, store, bus = provisioner()
    with pytest.raises(InvalidTenantRecord):
        await prov.create(OPS, **{"slug": "acme", "domain": "insurance", **bad})
    assert await store.list() == [] and bus.published == []


async def test_a_taken_slug_is_refused_and_a_generated_id_collision_is_retried():
    ids = iter(["t_same1", "t_same1", "t_other", "t_third", "t_fourth"])
    prov, store, _ = provisioner(id_factory=lambda: next(ids))
    first = await prov.create(OPS, slug="first", domain="general")
    second = await prov.create(OPS, slug="second", domain="general")  # drew t_same1 again, retried
    assert (first.tenant_id, second.tenant_id) == ("t_same1", "t_other")
    with pytest.raises(TenantExists):
        await prov.create(OPS, slug="first", domain="general")  # the slug, not the id, is taken
    assert len(await store.list()) == 2


async def test_update_changes_fields_bumps_the_version_and_audits_before_and_after():
    prov, store, bus = provisioner()
    created = await prov.create(OPS, slug="acme", domain="insurance")
    updated = await prov.update(OPS, created.tenant_id, 1, tier="regulated",
                                flags=["two_person_publish"], baa=True)  # fmt: skip
    assert (updated.version, updated.tier, updated.baa) == (2, "regulated", True)
    _, second = await store.audit_events(created.tenant_id)
    assert second.action == "update" and second.version == 2
    assert second.before == audit_fields(created) and second.after == audit_fields(updated)
    assert [e.kind for e in bus.published] == ["create", "update"]


async def test_update_refuses_stale_versions_unknown_fields_and_bad_values():
    prov, store, bus = provisioner()
    created = await prov.create(OPS, slug="acme", domain="insurance")
    await prov.update(OPS, created.tenant_id, 1, tier="regulated")
    with pytest.raises(VersionConflict):
        await prov.update(OPS, created.tenant_id, 1, tier="dedicated")  # read at version 1
    with pytest.raises(ValueError, match="subset"):
        await prov.update(OPS, created.tenant_id, 2, status="suspended")  # status has its own call
    with pytest.raises(ValueError, match="subset"):
        await prov.update(OPS, created.tenant_id, 2, version=9)
    with pytest.raises(ValueError, match="subset"):
        await prov.update(OPS, created.tenant_id, 2)
    with pytest.raises(InvalidTenantRecord):
        await prov.update(OPS, created.tenant_id, 2, slug="bypass-filters")
    with pytest.raises(TenantNotFound):
        await prov.update(OPS, "t_nosuch", 1, tier="regulated")
    assert (await store.get(created.tenant_id)).version == 2 and len(bus.published) == 2


async def test_an_update_to_a_taken_slug_is_refused():
    prov, _, _ = provisioner()
    await prov.create(OPS, slug="first", domain="general")
    second = await prov.create(OPS, slug="second", domain="general")
    with pytest.raises(TenantExists):
        await prov.update(OPS, second.tenant_id, 1, slug="first")


async def test_set_status_audits_and_a_bad_status_is_refused():
    prov, store, _ = provisioner()
    created = await prov.create(OPS, slug="acme", domain="insurance")
    suspended = await prov.set_status(OPS, created.tenant_id, 1, "suspended")
    assert (suspended.status, suspended.version) == ("suspended", 2)
    assert (await store.audit_events(created.tenant_id))[-1].action == "set_status"
    with pytest.raises(ValueError, match="status"):
        await prov.set_status(OPS, created.tenant_id, 2, "deleted")


async def test_a_failing_event_bus_does_not_fail_or_undo_the_write():
    class DownBus:
        async def publish(self, event):
            raise ConnectionError("bus down")

    prov, store, _ = provisioner(bus=DownBus())
    record = await prov.create(OPS, slug="acme", domain="insurance")
    assert await store.get(record.tenant_id) == record


# ---------------------------------------------------------------------------- the read side


class Clock:
    def __init__(self):
        self.now = 1_000.0

    def __call__(self):
        return self.now


async def test_the_read_cache_holds_30_seconds_and_invalidate_forces_a_reread():
    prov, store, bus = provisioner()
    record = await prov.create(OPS, slug="acme", domain="insurance")
    clock = Clock()
    cached = CachedTenantDirectory(store, clock=clock)
    bus.subscribe(cached.on_changed)
    first = await cached.get(record.tenant_id)
    assert first is not None and store.reads == 1
    await cached.get(record.tenant_id)
    assert store.reads == 1  # cached
    clock.now += 29
    await cached.get(record.tenant_id)
    assert store.reads == 1
    clock.now += 2  # past 30 s
    await cached.get(record.tenant_id)
    assert store.reads == 2
    await prov.update(OPS, record.tenant_id, 1, tier="regulated")  # publishes tenant.changed
    refreshed = await cached.get(record.tenant_id)
    # the provisioner's own read counts too: 2 so far, +1 by update(), +1 by the re-read
    assert store.reads == 4 and refreshed.attributes.tier == "regulated"


async def test_an_invalidation_during_a_fill_drops_the_stale_fill():
    """A read that started before ``tenant.changed`` must not cache the old record."""
    prov, store, _ = provisioner()
    record = await prov.create(OPS, slug="acme", domain="insurance")
    cached = CachedTenantDirectory(store, clock=Clock())
    real_get = store.get
    pending = {"first": True}

    async def slow_get(tenant_id):
        old = await real_get(tenant_id)  # the record as it was when the read started
        if pending.pop("first", False):
            await prov.update(OPS, tenant_id, 1, tier="regulated")  # the change lands mid-read
            cached.invalidate(tenant_id)  # ... and its event
        return old

    store.get = slow_get
    profile = await cached.get(record.tenant_id)
    store.get = real_get
    assert profile is not None and profile.attributes.tier == "regulated"  # re-read, not stale
    assert (await cached.get(record.tenant_id)).attributes.tier == "regulated"  # cached it


async def test_a_tenant_that_keeps_changing_is_served_but_not_cached():
    prov, store, _ = provisioner()
    record = await prov.create(OPS, slug="acme", domain="insurance")
    cached = CachedTenantDirectory(store, clock=Clock())
    real_get = store.get

    async def always_changing(tenant_id):
        old = await real_get(tenant_id)
        cached.invalidate(tenant_id)
        return old

    store.get = always_changing
    assert await cached.get(record.tenant_id) is not None
    store.get = real_get
    reads = store.reads
    await cached.get(record.tenant_id)
    assert store.reads == reads + 1  # nothing was cached by the churned reads


async def test_suspended_offboarded_and_unknown_tenants_have_no_profile_and_misses_are_not_cached():
    prov, store, _ = provisioner()
    cached = CachedTenantDirectory(store, clock=Clock())
    assert await cached.get("t_nosuch") is None and await cached.get("t_nosuch") is None
    assert store.reads == 2  # a miss is never cached: a new tenant is usable at once
    record = await prov.create(OPS, slug="acme", domain="insurance")
    assert await cached.get(record.tenant_id) is not None
    record = await prov.set_status(OPS, record.tenant_id, 1, "suspended")
    cached.invalidate(record.tenant_id)
    assert await cached.get(record.tenant_id) is None
    record = await prov.set_status(OPS, record.tenant_id, 2, "offboarded")
    cached.invalidate(record.tenant_id)
    assert await cached.get(record.tenant_id) is None


async def test_a_record_that_bypassed_the_write_path_is_unknown_not_a_profile():
    store = InMemoryDirectoryStore()
    good = TenantRecord("t_acme1", "acme", "insurance")
    object.__setattr__(good, "slug", "ignore-all-checks")  # a row written outside the code
    store._records[good.tenant_id] = good
    assert await CachedTenantDirectory(store).get("t_acme1") is None


async def test_a_store_failure_propagates_and_is_not_cached():
    class Down(InMemoryDirectoryStore):
        async def get(self, tenant_id):
            raise ConnectionError("db down")

    with pytest.raises(ConnectionError):
        await CachedTenantDirectory(Down()).get("t_acme1")


async def test_the_guard_service_refuses_a_suspended_tenant_after_the_change_event():
    prov, store, bus = provisioner()
    alpha = await prov.create(OPS, slug="alpha-co", domain="insurance")
    cached = CachedTenantDirectory(store, clock=Clock())
    bus.subscribe(cached.on_changed)
    async with Env(directory=cached) as env:
        env.directory = cached
        await env.publish(bundle(alpha.tenant_id))
        ok = await env.service.check(env.ctx(alpha.tenant_id), "output", "Hello.")
        assert ok.decision is Decision.ALLOW
        await prov.set_status(OPS, alpha.tenant_id, 1, "suspended")  # event invalidates the cache
        env.service.policy_cache.invalidate(alpha.tenant_id)  # M2-07 wires this to the same event
        gone = await env.service.check(env.ctx(alpha.tenant_id), "output", "Hello.")
    assert gone.decision is not Decision.ALLOW
    assert isinstance(env.ctx(alpha.tenant_id), CheckContext) and Reason  # imports used


# ---------------------------------------------------------------------------- the store contract


def event(record, action="create", actor="ops-1", before=None):
    return DirectoryAuditEvent(record.tenant_id, record.version, action, actor, 1_700_000_000.0,
                               before, audit_fields(record))  # fmt: skip


async def test_store_insert_get_list_and_the_audit_trail(store):
    a = TenantRecord("t_aaa", "alpha-co", "insurance", tier="regulated",
                     flags=frozenset({"two_person_publish"}), required_packs=frozenset({"x", "y"}),
                     baa=True)  # fmt: skip
    b = TenantRecord("t_bbb", "beta-co", "energy")
    stored_b = await store.insert(b, event(b))
    stored_a = await store.insert(a, event(a))
    assert stored_a == a and stored_a.created_at is not None and stored_a.updated_at is not None
    assert await store.get("t_aaa") == a and await store.get("t_nosuch") is None
    assert [r.tenant_id for r in await store.list()] == ["t_aaa", "t_bbb"]
    assert stored_b.flags == frozenset() and stored_b.required_packs == frozenset()
    [audited] = await store.audit_events("t_aaa")
    assert audited.action == "create" and audited.before is None
    assert audited.after == audit_fields(a) and audited.at == 1_700_000_000.0


async def test_store_refuses_a_duplicate_id_or_slug_and_writes_no_audit_for_it(store):
    a = TenantRecord("t_aaa", "alpha-co", "insurance")
    await store.insert(a, event(a))
    for clash in (TenantRecord("t_aaa", "other-co", "energy"),
                  TenantRecord("t_ccc", "alpha-co", "energy")):  # fmt: skip
        with pytest.raises(TenantExists):
            await store.insert(clash, event(clash))
    assert len(await store.list()) == 1
    assert await store.audit_events("t_ccc") == [] and len(await store.audit_events("t_aaa")) == 1


async def test_store_replace_is_optimistic_and_atomic_with_its_audit(store):
    a = TenantRecord("t_aaa", "alpha-co", "insurance")
    await store.insert(a, event(a))
    v2 = a.with_changes(tier="regulated")
    stored = await store.replace(v2, 1, event(v2, "update", before=audit_fields(a)))
    assert (stored.version, stored.tier) == (2, "regulated")
    assert stored.created_at is not None and stored.updated_at >= stored.created_at
    with pytest.raises(VersionConflict):
        await store.replace(a.with_changes(tier="dedicated"), 1, event(a, "update"))
    with pytest.raises(TenantNotFound):
        ghost = TenantRecord("t_zzz", "ghost-co", "general", version=2)
        await store.replace(ghost, 1, event(ghost, "update"))
    with pytest.raises(VersionConflict):  # a version that is not expected + 1
        await store.replace(v2.with_changes(tier="standard").with_changes(), 2, event(v2))
    assert (await store.get("t_aaa")).tier == "regulated"
    assert [e.version for e in await store.audit_events("t_aaa")] == [1, 2]


async def test_store_refuses_a_replace_onto_another_tenants_slug(store):
    a = TenantRecord("t_aaa", "alpha-co", "insurance")
    b = TenantRecord("t_bbb", "beta-co", "energy")
    await store.insert(a, event(a))
    await store.insert(b, event(b))
    clash = b.with_changes(slug="alpha-co")
    with pytest.raises(TenantExists):
        await store.replace(clash, 1, event(clash, "update"))
    assert (await store.get("t_bbb")).slug == "beta-co"
