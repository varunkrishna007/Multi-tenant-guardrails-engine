"""M5-07: terminating a tenant through the provisioner, and the refusal that follows. The directory
contract runs on the in-memory store and on Postgres (the ``store`` fixture); the Guard Service
and the authorizer run against the cached directory over the in-memory store."""

import asyncio

import pytest
from guard_fixtures import Env, bundle

from guardrail_engine.authz import Authorizer, InMemoryAuthzAudit, Principal, Role
from guardrail_engine.directory import (
    TERMINATION_STATUSES,
    CachedTenantDirectory,
    InMemoryDirectoryStore,
    InMemoryEventBus,
    NotAPlatformOperator,
    TenantNotFound,
    TenantProvisioner,
    TenantTerminated,
)
from guardrail_engine.guard import Decision, Reason
from guardrail_engine.guard.verdict import CANONICAL, RETRYABLE_REASONS

OPS = Principal("ops-1", None, frozenset(), True)
ALICE = Principal("alice", "t_alpha", frozenset({Role.GUARDRAIL_ADMIN}))
NOW = 1_700_000_000.0


class Sleeps:
    """Stands in for the drain: records the waits and lets a test act in the middle."""

    def __init__(self):
        self.waits: list[float] = []
        self.during = None

    async def __call__(self, seconds):
        self.waits.append(seconds)
        if self.during is not None:
            await self.during()


def provisioner(store=None, bus=None, **kw):
    store = store if store is not None else InMemoryDirectoryStore()
    bus = bus if bus is not None else InMemoryEventBus()
    kw.setdefault("sleep", Sleeps())
    return TenantProvisioner(store, bus, clock=lambda: NOW, **kw), store, bus


# ---------------------------------------------------------------------------- the provisioner


async def test_terminating_goes_to_terminating_then_terminated_audited_with_actor_and_reason(store):
    sleeps = Sleeps()
    prov, _, bus = provisioner(store, sleep=sleeps, drain_s=35.0)
    record = await prov.create(OPS, slug="acme-insurance", domain="insurance")
    seen = []

    async def during():  # in the drain, the tenant is already refused as terminating
        seen.append((await store.get(record.tenant_id)).status)

    sleeps.during = during

    done = await prov.terminate(OPS, record.tenant_id, "contract ended on 2026-11-01")

    assert done.status == "terminated" and done.version == 3
    assert seen == ["terminating"] and sleeps.waits == [35.0]
    events = await store.audit_events(record.tenant_id)
    assert [e.action for e in events] == ["create", "terminating", "terminated"]
    for e, status in zip(events[1:], ("terminating", "terminated"), strict=True):
        assert e.actor == "ops-1" and e.at == NOW
        assert e.after["status"] == status
        assert e.after["reason"] == "contract ended on 2026-11-01"
        assert e.before["status"] == ("active" if status == "terminating" else "terminating")
    assert [(e.tenant_id, e.kind) for e in bus.published][1:] == [
        (record.tenant_id, "terminating"),
        (record.tenant_id, "terminated"),
    ]
    assert {"terminating", "terminated"} == TERMINATION_STATUSES


async def test_only_a_platform_operator_may_terminate(store):
    prov, _, _ = provisioner(store)
    record = await prov.create(OPS, slug="acme-insurance", domain="insurance")
    with pytest.raises(NotAPlatformOperator):
        await prov.terminate(ALICE, record.tenant_id, "reason")
    assert (await store.get(record.tenant_id)).status == "active"


@pytest.mark.parametrize("reason", ["", "   ", "x" * 501, "line\nbreak", None, 5])
async def test_a_reason_is_required_and_bounded(store, reason):
    prov, _, _ = provisioner(store)
    record = await prov.create(OPS, slug="acme-insurance", domain="insurance")
    with pytest.raises(ValueError, match="reason"):
        await prov.terminate(OPS, record.tenant_id, reason)
    assert (await store.get(record.tenant_id)).status == "active"


async def test_an_unknown_tenant_is_not_found(store):
    prov, _, _ = provisioner(store)
    with pytest.raises(TenantNotFound):
        await prov.terminate(OPS, "t_nosuch", "reason")


async def test_terminating_again_changes_nothing(store):
    prov, _, bus = provisioner(store)
    record = await prov.create(OPS, slug="acme-insurance", domain="insurance")
    first = await prov.terminate(OPS, record.tenant_id, "reason")
    published = len(bus.published)
    again = await prov.terminate(OPS, record.tenant_id, "another reason")
    assert again.version == first.version and again.status == "terminated"
    assert len(await store.audit_events(record.tenant_id)) == 3 and len(bus.published) == published


async def test_a_terminate_that_died_half_way_is_finished_by_the_next_call(store):
    prov, _, _ = provisioner(store)
    record = await prov.create(OPS, slug="acme-insurance", domain="insurance")

    async def crash(_):
        raise RuntimeError("the process died in the drain")

    prov._sleep = crash
    with pytest.raises(RuntimeError):
        await prov.terminate(OPS, record.tenant_id, "reason")
    assert (await store.get(record.tenant_id)).status == "terminating"

    prov._sleep = Sleeps()
    done = await prov.terminate(OPS, record.tenant_id, "reason")
    assert done.status == "terminated"
    assert [e.action for e in await store.audit_events(record.tenant_id)] == [
        "create",
        "terminating",
        "terminated",
    ]


async def test_two_operators_terminating_at_once_leave_one_of_each_event(store):
    prov, _, _ = provisioner(store)
    record = await prov.create(OPS, slug="acme-insurance", domain="insurance")
    results = await asyncio.gather(
        prov.terminate(OPS, record.tenant_id, "reason"),
        prov.terminate(OPS, record.tenant_id, "reason"),
    )
    assert {r.status for r in results} == {"terminated"}
    actions = [e.action for e in await store.audit_events(record.tenant_id)]
    assert actions.count("terminating") == 1 and actions.count("terminated") == 1


async def test_a_terminating_or_terminated_tenant_can_not_be_changed_or_reinstated(store):
    prov, _, _ = provisioner(store)
    record = await prov.create(OPS, slug="acme-insurance", domain="insurance")
    stuck = await prov.create(OPS, slug="stuck-co", domain="insurance")

    async def crash(_):
        raise RuntimeError("stopped")

    prov._sleep = crash
    with pytest.raises(RuntimeError):
        await prov.terminate(OPS, stuck.tenant_id, "reason")
    prov._sleep = Sleeps()
    await prov.terminate(OPS, record.tenant_id, "reason")

    for tid in (record.tenant_id, stuck.tenant_id):
        version = (await store.get(tid)).version
        for status in ("active", "suspended", "offboarded"):
            with pytest.raises(TenantTerminated):
                await prov.set_status(OPS, tid, version, status)
        with pytest.raises(TenantTerminated):
            await prov.update(OPS, tid, version, tier="regulated")
        assert (await store.get(tid)).version == version
    assert TenantTerminated.code == "tenant_terminated"


@pytest.mark.parametrize("status", ["terminating", "terminated"])
async def test_set_status_is_not_the_way_to_terminate(store, status):
    prov, _, _ = provisioner(store)
    record = await prov.create(OPS, slug="acme-insurance", domain="insurance")
    with pytest.raises(ValueError, match=r"terminate\(\)"):
        await prov.set_status(OPS, record.tenant_id, 1, status)
    assert (await store.get(record.tenant_id)).status == "active"


async def test_suspended_and_offboarded_keep_their_old_meaning(store):
    prov, _, _ = provisioner(store)
    record = await prov.create(OPS, slug="acme-insurance", domain="insurance")
    suspended = await prov.set_status(OPS, record.tenant_id, 1, "suspended")
    back = await prov.set_status(OPS, record.tenant_id, suspended.version, "active")
    assert back.status == "active"
    done = await prov.terminate(OPS, record.tenant_id, "reason from a suspended tenant")
    assert done.status == "terminated"


# ---------------------------------------------------------------------------- the Guard Service


async def test_a_terminating_tenants_check_is_forbidden_with_its_own_code_and_leaves_no_trace():
    sleeps = Sleeps()
    prov, store, bus = provisioner(sleep=sleeps)
    alpha = await prov.create(OPS, slug="alpha-co", domain="insurance")
    beta = await prov.create(OPS, slug="beta-co", domain="insurance")
    cached = CachedTenantDirectory(store)
    bus.subscribe(cached.on_changed)
    async with Env(directory=cached) as env:
        for t in (alpha, beta):
            await env.publish(bundle(t.tenant_id))
        ok = await env.check(alpha.tenant_id)
        assert ok.decision is Decision.ALLOW  # (and the policy and profile are now cached)
        during = []

        async def check_in_the_drain():
            during.append(await env.check(alpha.tenant_id))

        sleeps.during = check_in_the_drain

        await prov.terminate(OPS, alpha.tenant_id, "contract ended")

        after = await env.check(alpha.tenant_id)
        other = await env.check(beta.tenant_id)

    for verdict in (*during, after):
        assert verdict.decision is Decision.FORBIDDEN
        assert verdict.reason is Reason.TENANT_TERMINATED == "tenant_terminated"
        assert verdict.tenant_id is None and verdict.retryable is False
    assert other.decision is Decision.ALLOW  # the other tenant's checks go on
    # Nothing of the refused checks is filed under the tenant: its audit records carry no id.
    refused = [r for r in env.audit.records if r.reason is Reason.TENANT_TERMINATED]
    assert len(refused) == 2 and all(r.tenant_id is None for r in refused)
    assert Reason.TENANT_TERMINATED in CANONICAL[Decision.FORBIDDEN]
    assert Reason.TENANT_TERMINATED not in RETRYABLE_REASONS


async def test_a_payload_naming_another_tenant_is_still_a_tenant_mismatch_not_a_terminated_leak():
    prov, store, _ = provisioner()
    alpha = await prov.create(OPS, slug="alpha-co", domain="insurance")
    beta = await prov.create(OPS, slug="beta-co", domain="insurance")
    await prov.terminate(OPS, alpha.tenant_id, "contract ended")
    cached = CachedTenantDirectory(store)
    async with Env(directory=cached) as env:
        await env.publish(bundle(beta.tenant_id))
        verdict = await env.check(beta.tenant_id, payload_tenant_id=alpha.tenant_id)
    assert verdict.reason is Reason.TENANT_MISMATCH


class _Tick:
    """The directory cache's injected clock."""

    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


async def test_an_unreadable_directory_lets_checks_go_on_for_five_minutes_then_fails_closed():
    """ "status unknown, so the check goes on" lasts only while the last successful
    directory read of the tenant is under 300 s old; then the check is a retryable
    ``policy_unavailable`` block (the policy cache's last-known-good can't carry it)."""
    prov, store, _ = provisioner()
    alpha = await prov.create(OPS, slug="alpha-co", domain="insurance")
    tick = _Tick()
    cached = CachedTenantDirectory(store, clock=tick)
    async with Env(directory=cached) as env:
        await env.publish(bundle(alpha.tenant_id))
        assert (await env.check(alpha.tenant_id)).decision is Decision.ALLOW  # read at t=1000

        async def down(_):
            raise ConnectionError("directory down")

        store.get = down
        for later in (31.0, 150.0, 299.0):  # the 30 s read cache has expired: it reads and fails
            tick.now = 1000.0 + later
            assert (await env.check(alpha.tenant_id)).decision is Decision.ALLOW
        tick.now = 1000.0 + 300.0  # exactly 300 s is no longer "under"
        verdict = await env.check(alpha.tenant_id)
        assert verdict.decision is Decision.BLOCK and verdict.reason is Reason.POLICY_UNAVAILABLE
        assert verdict.retryable is True
        assert verdict.tenant_id == alpha.tenant_id  # not known to be ended: nothing hidden
        tick.now = 1000.0 + 3600.0
        assert (await env.check(alpha.tenant_id)).reason is Reason.POLICY_UNAVAILABLE


async def test_the_unknown_status_window_is_configurable_and_a_recovered_directory_resets_it():
    prov, store, _ = provisioner()
    alpha = await prov.create(OPS, slug="alpha-co", domain="insurance")
    tick = _Tick()
    cached = CachedTenantDirectory(store, clock=tick, max_unknown_s=60.0)
    assert await cached.ended(alpha.tenant_id) is False  # a successful read at t=1000
    real_get = store.get

    async def down(_):
        raise ConnectionError("directory down")

    store.get = down
    tick.now = 1029.0  # inside the 30 s read cache: no read at all
    assert await cached.ended(alpha.tenant_id) is False
    tick.now = 1059.0  # cache expired, the read fails, the last good read is 59 s old
    assert await cached.ended(alpha.tenant_id) is False
    tick.now = 1061.0  # 61 s
    with pytest.raises(ConnectionError):
        await cached.ended(alpha.tenant_id)
    store.get = real_get  # the directory comes back: one good read resets the window
    assert await cached.ended(alpha.tenant_id) is False  # read at t=1061
    store.get = down
    tick.now = 1120.0  # cache expired again; 59 s since the good read
    assert await cached.ended(alpha.tenant_id) is False
    tick.now = 1122.0
    with pytest.raises(ConnectionError):
        await cached.ended(alpha.tenant_id)
    with pytest.raises(ValueError):
        CachedTenantDirectory(store, max_unknown_s=-1)


async def test_a_tenant_this_process_never_read_fails_closed_the_moment_the_directory_is_down():
    prov, store, _ = provisioner()
    alpha = await prov.create(OPS, slug="alpha-co", domain="insurance")
    cached = CachedTenantDirectory(store, clock=_Tick())

    async def down(_):
        raise ConnectionError("directory down")

    store.get = down
    with pytest.raises(ConnectionError):
        await cached.ended(alpha.tenant_id)
    async with Env(directory=cached) as env:
        await env.publish(bundle(alpha.tenant_id))
        verdict = await env.check(alpha.tenant_id)
    assert verdict.decision is Decision.BLOCK and verdict.reason is Reason.POLICY_UNAVAILABLE


async def test_once_seen_terminated_is_remembered_even_if_the_directory_goes_down():
    prov, store, _ = provisioner()
    alpha = await prov.create(OPS, slug="alpha-co", domain="insurance")
    cached = CachedTenantDirectory(store)
    await prov.terminate(OPS, alpha.tenant_id, "contract ended")
    assert await cached.ended(alpha.tenant_id) is True

    async def down(_):
        raise ConnectionError("directory down")

    store.get = down
    assert await cached.ended(alpha.tenant_id) is True
    assert await cached.ended_fresh(alpha.tenant_id) is True
    with pytest.raises(ConnectionError):
        await cached.ended("t_other1")


async def test_ended_fresh_reads_the_store_each_time_and_an_active_tenant_is_not_ended():
    prov, store, _ = provisioner()
    alpha = await prov.create(OPS, slug="alpha-co", domain="insurance")
    cached = CachedTenantDirectory(store)
    reads = store.reads
    assert await cached.ended_fresh(alpha.tenant_id) is False
    assert await cached.ended_fresh(alpha.tenant_id) is False
    assert store.reads == reads + 2
    assert await cached.ended_fresh("t_nosuch") is False


# ---------------------------------------------------------------------------- the Admin API gate


def gated(ended):
    audit = InMemoryAuthzAudit()

    async def fn(tenant_id):
        return await ended(tenant_id)

    return Authorizer(audit, clock=lambda: NOW, tenant_ended=fn), audit


ALPHA, BETA = "t_alpha", "t_beta"
ADMIN = Principal("alice", ALPHA, frozenset({Role.GUARDRAIL_ADMIN}))
OPERATOR = Principal("ops-1", None, frozenset({Role.GUARDRAIL_ADMIN}), True)
ROUTE = ("PUT", "/v1/tenants/{tid}/guardrails/draft")
PLATFORM_ROUTE = ("POST", "/v1/tenants/{tid}/guardrails/floor/repin")


async def test_admin_calls_on_a_terminated_tenant_are_refused_for_everyone_with_a_clear_reason():
    async def ended(tenant_id):
        return tenant_id == ALPHA

    authorizer, audit = gated(ended)
    for principal in (ADMIN, OPERATOR):
        for method, route in (ROUTE, PLATFORM_ROUTE, ("GET", "/v1/tenants/{tid}/guardrails")):
            decision = await authorizer.authorize(principal, method, route, tenant_id=ALPHA)
            assert not decision.allowed and decision.status == 403
            assert decision.reason == "tenant_terminated" and decision.scope is None
    # Another tenant's admin sees only the ordinary refusal: nothing says alpha is terminated.
    stranger = Principal("bob", BETA, frozenset({Role.GUARDRAIL_ADMIN}))
    decision = await authorizer.authorize(stranger, *ROUTE, tenant_id=ALPHA)
    assert decision.reason == "tenant_mismatch"
    # An operator's refused crossing is recorded like any denial.
    assert [e.reason for e in audit.events if e.actor == "ops-1"] == ["tenant_terminated"] * 3
    # Active tenants are as before.
    assert (await authorizer.authorize(stranger, *ROUTE, tenant_id=BETA)).allowed
    assert (await authorizer.authorize(OPERATOR, *ROUTE, tenant_id=BETA)).allowed


async def test_admin_calls_fail_closed_when_the_status_cannot_be_read():
    async def down(tenant_id):
        raise ConnectionError("directory down")

    authorizer, _ = gated(down)
    decision = await authorizer.authorize(ADMIN, *ROUTE, tenant_id=ALPHA)
    assert not decision.allowed and decision.reason == "tenant_status_unavailable"
    assert decision.status == 403


async def test_an_authorizer_without_a_gate_is_what_it_was():
    authorizer = Authorizer(InMemoryAuthzAudit(), clock=lambda: NOW)
    assert (await authorizer.authorize(ADMIN, *ROUTE, tenant_id=ALPHA)).allowed


async def test_the_cached_directorys_fresh_check_is_the_authorizers_gate_end_to_end():
    prov, store, _ = provisioner()
    alpha = await prov.create(OPS, slug="alpha-co", domain="insurance")
    cached = CachedTenantDirectory(store)
    principal = Principal("alice", alpha.tenant_id, frozenset({Role.GUARDRAIL_ADMIN}))
    authorizer = Authorizer(
        InMemoryAuthzAudit(), clock=lambda: NOW, tenant_ended=cached.ended_fresh
    )
    assert (await authorizer.authorize(principal, *ROUTE, tenant_id=alpha.tenant_id)).allowed

    async def refuse_in_the_drain():
        d = await authorizer.authorize(principal, *ROUTE, tenant_id=alpha.tenant_id)
        assert d.reason == "tenant_terminated"  # refused from the moment of `terminating`

    prov._sleep.during = refuse_in_the_drain
    await prov.terminate(OPS, alpha.tenant_id, "contract ended")
    assert (await authorizer.authorize(principal, *ROUTE, tenant_id=alpha.tenant_id)).reason == (
        "tenant_terminated"
    )
