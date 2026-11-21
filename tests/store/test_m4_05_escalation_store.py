"""M4-05: the escalation stores and the class D deletion job, in memory and (with
``GUARDRAIL_TEST_PG_DSN``) on Postgres (migrations 034 to 037), the service and the retention job
each connected as its own least-privilege role. The clock is injected and always in the past, so
the database's own bound on the job's clock (never ahead of the database) is met."""

import asyncio
import uuid
from datetime import UTC, datetime, timedelta

import pytest

from guardrail_engine.escalation import ClassDJob, ClassDTerm, InMemoryEscalationStore
from guardrail_engine.escalation.model import (
    AlreadyResolvedError,
    EscalationAuditEvent,
    EscalationItem,
    EscalationNotFoundError,
    ItemFilter,
    Resolution,
    RuleRef,
    item_id_for,
)
from guardrail_engine.escalation.retention import (
    FALLBACK_TERM,
    HEALTHCARE_TERM,
    STANDARD_TERM,
)
from guardrail_engine.retention import RetentionError
from guardrail_engine.store.port import ScopeMismatchError
from guardrail_engine.tenant_scope import issue_scope

NOW = datetime(2026, 11, 1, 12, 0, 0, tzinfo=UTC)
DAY = timedelta(days=1)
ACME, OTHER = "t_acmeins", "t_otherco"
HEX = "sha256:" + "a" * 64


def make_item(tenant=ACME, n=0, *, created=NOW - DAY, content="held text", **kw) -> EscalationItem:
    request_id = kw.pop("request_id", f"req-{tenant}-{n}")
    fields = dict(
        id=item_id_for(tenant, request_id, "output"),
        tenant_id=tenant,
        request_id=request_id,
        guard_point="output",
        created_at=created,
        target="queue",
        reason="policy",
        bundle_version=4,
        rules=(RuleRef("t__x", "escalate", "enforce", "tenant"),),
        content_sha256=HEX,
        store_content="hash_only",
        content=content,
    )
    fields.update(kw)
    return EscalationItem(**fields)


def event(item: EscalationItem, action="resolved", **kw) -> EscalationAuditEvent:
    fields = dict(
        at=NOW, tenant_id=item.tenant_id, item_id=item.id, action=action, actor="iss#rita",
        decision="allow",
    )  # fmt: skip
    if action == "resolved":
        fields["reason_sha256"] = "b" * 64
    fields.update(kw)
    return EscalationAuditEvent(**fields)


def resolution(at=NOW, decision="allow") -> Resolution:
    return Resolution(decision, "looked fine", "iss#rita", at)


# ----------------------------------------------------------------------------- the two stores


class MemoryEnv:
    kind = "memory"

    def __init__(self) -> None:
        self.store = InMemoryEscalationStore()
        self.retention = self.store.retention

    def scoped(self, tenant=ACME, *, operator=False):
        return self.store.scoped(issue_scope(tenant, operator=operator))

    async def count(self, tenant) -> int:
        return len(self.store.items(tenant))

    async def receipts(self, run_id):
        return await self.retention.receipts(run_id)


class PgEnvStores:
    kind = "postgres"

    def __init__(self, pg_env, app_pool, ret_pool, operator_pool) -> None:
        from guardrail_engine.escalation.adapters.postgres import (
            PostgresClassDStore,
            PostgresEscalationStore,
        )

        self.pg_env, self.app_pool, self.ret_pool = pg_env, app_pool, ret_pool
        self.store = PostgresEscalationStore(app_pool, operator_pool)
        self.retention = PostgresClassDStore(ret_pool)

    def scoped(self, tenant=ACME, *, operator=False):
        return self.store.scoped(issue_scope(tenant, operator=operator))

    async def count(self, tenant) -> int:
        return int(
            await self.pg_env.pool.fetchval(
                "SELECT count(*) FROM escalation_items WHERE tenant_id = $1", tenant
            )
        )

    async def receipts(self, run_id):
        return await self.retention.receipts(run_id)


async def _role_pool(pg_env, prefix, grants):
    import asyncpg

    role = f"{prefix}_{uuid.uuid4().hex[:12]}"
    password = uuid.uuid4().hex
    await pg_env.pool.execute(f"CREATE ROLE \"{role}\" LOGIN PASSWORD '{password}'")
    await pg_env.pool.execute(f'GRANT USAGE ON SCHEMA "{pg_env.schema}" TO "{role}"')
    await grants(pg_env.pool, role)
    pool = await asyncpg.create_pool(
        pg_env.dsn,
        user=role,
        password=password,
        min_size=1,
        max_size=4,
        server_settings={"search_path": pg_env.schema},
    )
    return role, pool


@pytest.fixture
async def pg_stores(pg_env):
    from guardrail_engine.store.adapters.postgres import (
        apply_app_role_grants,
        apply_operator_policy,
        apply_retention_role_grants,
    )

    async def operator_grants(pool, role):
        await apply_app_role_grants(pool, role)
        await apply_operator_policy(pool, role)

    app_role, app_pool = await _role_pool(pg_env, "m405_app", apply_app_role_grants)
    ret_role, ret_pool = await _role_pool(pg_env, "m405_ret", apply_retention_role_grants)
    op_role, op_pool = await _role_pool(pg_env, "m405_op", operator_grants)
    try:
        stores = PgEnvStores(pg_env, app_pool, ret_pool, op_pool)
        stores.app_role, stores.ret_role = app_role, ret_role
        yield stores
    finally:
        for pool in (app_pool, ret_pool, op_pool):
            await pool.close()
        for role in (app_role, ret_role, op_role):
            await pg_env.pool.execute(f'DROP OWNED BY "{role}"')
            await pg_env.pool.execute(f'DROP ROLE "{role}"')


@pytest.fixture(params=["memory", "postgres"])
def stores(request):
    if request.param == "memory":
        return MemoryEnv()
    return request.getfixturevalue("pg_stores")


# ----------------------------------------------------------------------------- the item store


async def test_an_item_round_trips_and_a_duplicate_is_ignored(stores):
    item = make_item()
    assert await stores.scoped().insert(item) is True
    assert await stores.scoped().insert(make_item(content="a different text")) is False
    got = await stores.scoped().get(ACME, item.id)
    assert got.content == "held text"  # the first one stands
    assert (got.status, got.guard_point, got.content_sha256, got.bundle_version) == (
        "open", "output", HEX, 4,
    )  # fmt: skip
    assert got.rules == item.rules and got.seq > 0
    assert await stores.scoped().get(ACME, "esc_" + "0" * 24) is None


async def test_listing_is_by_cursor_in_insertion_order_with_filters(stores):
    items = [make_item(n=i, created=NOW - DAY * (5 - i)) for i in range(5)]
    for i in items:
        await stores.scoped().insert(i)
    page = await stores.scoped().list(ACME, ItemFilter(), after=None, limit=2)
    assert [i.id for i in page] == [items[0].id, items[1].id]
    rest = await stores.scoped().list(ACME, ItemFilter(), after=page[-1].seq, limit=10)
    assert [i.id for i in rest] == [i.id for i in items[2:]]
    await stores.scoped().resolve(ACME, items[1].id, resolution(), event(items[1]))
    only = await stores.scoped().list(ACME, ItemFilter(status="resolved"), after=None, limit=9)
    assert [i.id for i in only] == [items[1].id]
    since = await stores.scoped().list(
        ACME, ItemFilter(since=NOW - DAY * 3, until=NOW - DAY), after=None, limit=9
    )
    assert [i.id for i in since] == [items[2].id, items[3].id]  # created_at in [since, until)
    by_rule = await stores.scoped().list(ACME, ItemFilter(rule="t__x"), after=None, limit=9)
    assert len(by_rule) == 5
    assert await stores.scoped().list(ACME, ItemFilter(rule="t__y"), after=None, limit=9) == []


async def test_a_resolution_is_once_and_writes_its_class_a_event(stores):
    item = make_item()
    await stores.scoped().insert(item)
    done = await stores.scoped().resolve(ACME, item.id, resolution(), event(item))
    assert (done.status, done.decision, done.resolved_by) == ("resolved", "allow", "iss#rita")
    assert done.resolved_at == NOW and done.resolution_reason == "looked fine"
    assert done.content == "held text"  # the resolution doesn't touch the content
    with pytest.raises(AlreadyResolvedError):
        await stores.scoped().resolve(ACME, item.id, resolution(decision="block"), event(item))
    with pytest.raises(EscalationNotFoundError):
        await stores.scoped().resolve(
            ACME, "esc_" + "0" * 24, resolution(), event(item, item_id="esc_" + "0" * 24)
        )
    events = await stores.scoped().audit_events(ACME)
    assert [(e.action, e.actor, e.decision) for e in events] == [("resolved", "iss#rita", "allow")]


async def test_a_label_is_attached_once_to_a_resolved_item_only(stores):
    item = make_item()
    await stores.scoped().insert(item)
    labelled = event(item, "label_created", label_set_id="gs_" + "1" * 16, label_mode="hash_only")
    with pytest.raises(AlreadyResolvedError):  # not resolved yet
        await stores.scoped().attach_label(ACME, item.id, "gs_" + "1" * 16, "hash_only", labelled)
    await stores.scoped().resolve(ACME, item.id, resolution(), event(item))
    done = await stores.scoped().attach_label(
        ACME, item.id, "gs_" + "1" * 16, "hash_only", labelled
    )
    assert (done.label_set_id, done.label_mode) == ("gs_" + "1" * 16, "hash_only")
    again = await stores.scoped().attach_label(
        ACME, item.id, "gs_" + "2" * 16, "content", event(item, "label_created")
    )
    assert again.label_set_id == "gs_" + "1" * 16  # the first one stands
    assert len(await stores.scoped().audit_events(ACME)) == 2  # and no second event


async def test_a_failed_event_leaves_no_resolution_behind(stores):
    """The resolution and its event are one step: an event the store refuses rolls it back."""
    item = make_item()
    await stores.scoped().insert(item)
    bad = event(item, tenant_id=OTHER)  # an event for another tenant
    with pytest.raises(ScopeMismatchError):
        await stores.scoped().resolve(ACME, item.id, resolution(), bad)
    assert (await stores.scoped().get(ACME, item.id)).status == "open"


async def test_one_tenant_never_reads_or_changes_anothers_items(stores):
    mine, theirs = make_item(ACME), make_item(OTHER)
    await stores.scoped(ACME).insert(mine)
    await stores.scoped(OTHER).insert(theirs)
    assert [
        i.id for i in await stores.scoped(ACME).list(ACME, ItemFilter(), after=None, limit=9)
    ] == [mine.id]
    # the other tenant's id, through this tenant's scope: nothing, whatever the tenant argument
    assert await stores.scoped(ACME).get(ACME, theirs.id) is None
    with pytest.raises(EscalationNotFoundError):
        await stores.scoped(ACME).resolve(
            ACME, theirs.id, resolution(), event(theirs, tenant_id=ACME)
        )
    with pytest.raises(ScopeMismatchError):
        await stores.scoped(ACME).get(OTHER, theirs.id)
    with pytest.raises(ScopeMismatchError):
        await stores.scoped(ACME).insert(theirs)
    assert (await stores.scoped(OTHER).get(OTHER, theirs.id)).status == "open"
    assert await stores.scoped(OTHER).audit_events(OTHER) == []


# ----------------------------------------------------------------------------- class D: the job


class FixedResolver:
    def __init__(self, term: ClassDTerm) -> None:
        self.term = term

    async def resolve(self, tenant_id):
        return self.term


def job(stores, term=STANDARD_TERM, *, now=NOW, **kw) -> ClassDJob:
    return ClassDJob(stores.retention, FixedResolver(term), clock=lambda: now, **kw)


async def put(stores, item, *, resolved_at=None, tenant=ACME):
    await stores.scoped(tenant).insert(item)
    if resolved_at is not None:
        await stores.scoped(tenant).resolve(
            tenant, item.id, resolution(at=resolved_at), event(item, at=resolved_at)
        )


async def test_standard_class_d_deletes_30_days_after_resolution_at_the_boundary(stores):
    cutoff = NOW - timedelta(days=30)
    exactly = make_item(n=1)
    older = make_item(n=2)
    newer = make_item(n=3)
    await put(stores, exactly, resolved_at=cutoff)
    await put(stores, older, resolved_at=cutoff - timedelta(seconds=1))
    await put(stores, newer, resolved_at=cutoff + timedelta(seconds=1))

    report = await job(stores).run_once()

    assert report.deleted == 1 and report.sweeps[0].cutoff == cutoff
    left = {i.id for i in await stores.scoped().list(ACME, ItemFilter(), after=None, limit=10)}
    assert left == {exactly.id, newer.id}  # exactly 30 days is kept; one second older is gone


async def test_standard_class_d_keeps_an_unresolved_item_however_old(stores):
    ancient = make_item(created=NOW - timedelta(days=900))
    await put(stores, ancient)
    report = await job(stores).run_once()
    assert report.deleted == 0 and await stores.count(ACME) == 1  # until resolved


async def test_healthcare_class_d_expires_unresolved_items_30_days_after_creation(stores):
    cutoff = NOW - timedelta(days=30)
    hc = {"retention_mode": "total"}  # routed under the healthcare profile
    exactly = make_item(n=1, created=cutoff, **hc)
    old_open = make_item(n=2, created=cutoff - timedelta(seconds=1), **hc)
    old_resolved = make_item(n=3, created=cutoff - DAY, **hc)
    fresh_resolved = make_item(n=4, created=cutoff + DAY, **hc)
    await put(stores, exactly)
    await put(stores, old_open)
    await put(stores, old_resolved, resolved_at=NOW - DAY)  # resolved yesterday, created 31 d ago
    await put(stores, fresh_resolved, resolved_at=NOW - DAY)

    report = await job(stores, HEALTHCARE_TERM).run_once()

    [sweep] = report.sweeps
    assert (sweep.deleted, sweep.expired_unresolved) == (2, 1)  # 30 days in all, resolved or not
    left = {i.id for i in await stores.scoped().list(ACME, ItemFilter(), after=None, limit=10)}
    assert left == {exactly.id, fresh_resolved.id}
    [receipt] = await stores.receipts(report.run_id)
    assert (receipt.deleted_count, receipt.expired_unresolved) == (2, 1)


async def test_the_clock_is_the_injected_one(stores):
    item = make_item()
    await put(stores, item, resolved_at=NOW - timedelta(days=40))
    assert (await job(stores, now=NOW - timedelta(days=20)).run_once()).deleted == 0
    assert (await job(stores, now=NOW).run_once()).deleted == 1


async def test_a_naive_clock_is_refused():
    j = ClassDJob(
        InMemoryEscalationStore().retention, FixedResolver(STANDARD_TERM), clock=datetime.now
    )
    with pytest.raises(ValueError):
        await j.run_once()


async def test_the_receipt_holds_tenant_class_cutoff_counts_and_run_id_and_no_content(stores):
    for n in range(3):
        await put(stores, make_item(n=n), resolved_at=NOW - timedelta(days=45))
    await put(stores, make_item(OTHER, 9), resolved_at=NOW - timedelta(days=45), tenant=OTHER)

    report = await ClassDJob(
        stores.retention,
        FixedResolver(STANDARD_TERM),
        clock=lambda: NOW,
        run_id_factory=lambda: "run-d-1",
    ).run_once()

    receipts = {r.tenant_id: r for r in await stores.receipts("run-d-1")}
    r = receipts[ACME]
    assert (r.run_id, r.retention_class, r.deleted_count, r.expired_unresolved) == (
        "run-d-1", "D", 3, 0,
    )  # fmt: skip
    assert (r.cutoff, r.retention_days, r.source, r.batch) == (
        NOW - timedelta(days=30), 30, "default", 1,
    )  # fmt: skip
    if stores.kind == "memory":
        assert r.at == NOW
    else:  # the database stamps its own clock
        assert abs(r.at - datetime.now(UTC)) < timedelta(minutes=5)
    assert receipts[OTHER].deleted_count == 1
    assert report.run_id == "run-d-1"
    assert set(r.__slots__) == {  # no item id, no content
        "run_id", "at", "tenant_id", "retention_class", "cutoff", "deleted_count", "batch",
        "retention_days", "source", "expired_unresolved",
    }  # fmt: skip


async def test_a_run_with_nothing_to_delete_still_leaves_a_zero_receipt(stores):
    await put(stores, make_item(), resolved_at=NOW - DAY)
    report = await job(stores).run_once()
    [receipt] = await stores.receipts(report.run_id)
    assert (receipt.tenant_id, receipt.retention_class, receipt.deleted_count) == (ACME, "D", 0)


async def test_each_tenant_is_swept_under_its_own_rule_and_never_touches_the_others(stores):
    old = NOW - timedelta(days=60)
    await put(stores, make_item(ACME, 1, created=old, retention_mode="total"))
    await put(stores, make_item(OTHER, 1, created=old), tenant=OTHER)

    class PerTenant:
        async def resolve(self, tenant_id):
            return {ACME: HEALTHCARE_TERM, OTHER: FALLBACK_TERM}[tenant_id]

    report = await ClassDJob(stores.retention, PerTenant(), clock=lambda: NOW).run_once()

    assert {s.tenant_id: (s.deleted, s.source) for s in report.sweeps} == {
        ACME: (1, "healthcare"),
        OTHER: (0, "fallback"),  # unresolved and routed as resolved_plus: kept
    }
    assert await stores.count(OTHER) == 1


async def test_second_run_is_idempotent_and_batches_are_bounded_and_resumable(stores):
    for n in range(25):
        await put(stores, make_item(n=n), resolved_at=NOW - timedelta(days=60, seconds=n))
    capped = await job(stores, batch_size=10, max_batches_per_tenant=2).run_once()
    assert capped.deleted == 20 and capped.sweeps[0].more_to_do is True
    rest = await job(stores, batch_size=10, max_batches_per_tenant=2).run_once()
    assert rest.deleted == 5 and rest.sweeps[0].more_to_do is False
    assert (await job(stores).run_once()).deleted == 0
    assert [r.deleted_count for r in await stores.receipts(capped.run_id)] == [10, 10]


async def test_one_tenant_failing_does_not_stop_the_others(stores):
    await put(stores, make_item(ACME, 1), resolved_at=NOW - timedelta(days=60))
    await put(stores, make_item(OTHER, 1), resolved_at=NOW - timedelta(days=60), tenant=OTHER)

    class Flaky:
        def __init__(self, inner) -> None:
            self.inner = inner

        async def class_d_tenants(self):
            return await self.inner.class_d_tenants()

        async def delete_class_d_batch(self, **kw):
            if kw["tenant_id"] == ACME:
                raise RuntimeError("database down")
            return await self.inner.delete_class_d_batch(**kw)

    report = await ClassDJob(
        Flaky(stores.retention), FixedResolver(STANDARD_TERM), clock=lambda: NOW
    ).run_once()
    assert report.failed == (ACME,) and report.deleted == 1
    assert await stores.count(ACME) == 1


@pytest.mark.parametrize(
    "kw",
    [
        {"mode": "bogus"},
        {"days": 0},
        {"days": 1},
        {"days": 29},  # R3's class D term is 30 days; nothing shorter
        {"days": 401},
        {"source": "invented"},
        {"limit": 0},
        {"limit": 100_001},
    ],
)
async def test_the_store_refuses_out_of_bounds_calls(stores, kw):
    call = dict(
        run_id="r", tenant_id=ACME, now=NOW, mode="resolved_plus", days=30, source="default",
        limit=10, batch=1,
    )  # fmt: skip
    call.update(kw)
    with pytest.raises(RetentionError):
        await stores.retention.delete_class_d_batch(**call)


async def test_a_clock_hours_ahead_deletes_nothing_in_postgres_and_is_refused(stores):
    if stores.kind != "postgres":
        pytest.skip("the database's own bound on the job's clock")
    await put(stores, make_item(), resolved_at=NOW - timedelta(days=60))
    future = datetime.now(UTC) + timedelta(hours=3)
    with pytest.raises(RetentionError, match="refused the deletion"):
        await stores.retention.delete_class_d_batch(
            run_id="r", tenant_id=ACME, now=future, mode="resolved_plus", days=30,
            source="default", limit=10, batch=1,
        )  # fmt: skip
    assert await stores.count(ACME) == 1


# --------------------------------------------------------- the item's own term decides


async def _delete(stores, *, mode, days, tenant=ACME, now=NOW, limit=100):
    return await stores.retention.delete_class_d_batch(
        run_id="probe", tenant_id=tenant, now=now, mode=mode, days=days, source="default",
        limit=limit, batch=1,
    )  # fmt: skip


async def test_a_caller_naming_total_cannot_delete_an_unresolved_standard_item(stores):
    """The probe: the retention role, a 2-day-old open item on a standard tenant,
    mode 'total' and 1 day. Nothing is deleted, and the call is refused outright."""
    item = make_item(created=NOW - 2 * DAY)
    await put(stores, item)
    with pytest.raises(RetentionError):
        await _delete(stores, mode="total", days=1)
    # at the shortest term R3 allows, 'total' still removes nothing the item wasn't routed as
    result = await _delete(stores, mode="total", days=30)
    assert (result.deleted, result.expired_unresolved) == (0, 0)
    assert await stores.count(ACME) == 1
    # nor does an ancient one, whatever the caller names
    ancient = make_item(n=2, created=NOW - timedelta(days=900))
    await put(stores, ancient)
    assert (await _delete(stores, mode="total", days=30)).deleted == 0
    assert (await _delete(stores, mode="resolved_plus", days=30)).deleted == 0
    assert await stores.count(ACME) == 2


async def test_each_item_is_deleted_by_its_own_mode_whatever_mode_the_caller_names(stores):
    old = NOW - timedelta(days=60)
    standard_open = make_item(n=1, created=old)
    healthcare_open = make_item(n=2, created=old, retention_mode="total")
    standard_resolved = make_item(n=3, created=old)
    await put(stores, standard_open)
    await put(stores, healthcare_open)
    await put(stores, standard_resolved, resolved_at=old)
    result = await _delete(stores, mode="resolved_plus", days=30)
    assert (result.deleted, result.expired_unresolved) == (2, 1)
    left = {i.id for i in await stores.scoped().list(ACME, ItemFilter(), after=None, limit=9)}
    assert left == {standard_open.id}


async def test_a_job_that_takes_a_standard_tenant_for_healthcare_deletes_nothing_unresolved(
    stores,
):
    old = NOW - timedelta(days=500)
    for n in range(3):  # routed as resolved_plus
        await put(stores, make_item(n=n, created=old))
    report = await job(stores, HEALTHCARE_TERM).run_once()  # the job's mistake
    assert report.deleted == 0 and await stores.count(ACME) == 3


async def test_the_retention_mode_is_stored_with_the_item(stores):
    plain, total = make_item(n=1), make_item(n=2, retention_mode="total")
    await put(stores, plain)
    await put(stores, total)
    assert (await stores.scoped().get(ACME, plain.id)).retention_mode == "resolved_plus"
    assert (await stores.scoped().get(ACME, total.id)).retention_mode == "total"


# ----------------------------------------------------------------------------- Postgres only


async def test_the_database_itself_enforces_isolation_and_the_narrow_update_path(pg_stores):
    s = pg_stores
    a, b = make_item(ACME, 1), make_item(OTHER, 1)
    await s.scoped(ACME).insert(a)
    await s.scoped(OTHER).insert(b)

    async def as_tenant(tenant, sql, *args):
        async with s.app_pool.acquire() as conn, conn.transaction():
            if tenant:
                await conn.execute("SELECT set_config('app.tenant_id', $1, true)", tenant)
            return await conn.fetch(sql, *args)

    # forced row-level security: no setting, no rows; a tenant's setting, its rows only
    assert await as_tenant(None, "SELECT id FROM escalation_items") == []
    assert [r["id"] for r in await as_tenant(ACME, "SELECT id FROM escalation_items")] == [a.id]
    # a write for another tenant's rows is refused outright
    import asyncpg

    with pytest.raises(asyncpg.PostgresError):
        await as_tenant(
            ACME, "INSERT INTO escalation_items (tenant_id, id, request_id, guard_point, "
            "created_at, target, reason, store_content) VALUES ($1, $2, 'r', 'output', now(), "
            "'queue', 'policy', 'hash_only')", OTHER, "esc_" + "9" * 24,
        )  # fmt: skip
    # the service role cannot delete, or change content, or resolve twice, or change a resolution
    for sql in (
        "DELETE FROM escalation_items",
        "UPDATE escalation_items SET content = 'changed'",
        "UPDATE escalation_items SET tenant_id = 't_otherco'",
        "UPDATE escalation_audit SET actor = 'x'",
        "DELETE FROM escalation_audit",
    ):
        with pytest.raises(asyncpg.PostgresError):
            await as_tenant(ACME, sql)
    await s.scoped(ACME).resolve(ACME, a.id, resolution(), event(a))
    with pytest.raises(asyncpg.PostgresError):  # the trigger: a resolution is set once
        await as_tenant(ACME, "UPDATE escalation_items SET decision = 'block'")
    with pytest.raises(asyncpg.PostgresError):  # a label can't un-resolve it
        await as_tenant(ACME, "UPDATE escalation_items SET status = 'open'")
    with pytest.raises(asyncpg.PostgresError):  # not the hash-only/full setting either
        await as_tenant(ACME, "UPDATE escalation_items SET store_content = 'full'")
    # the owner cannot truncate or rewrite the audit trail either
    with pytest.raises(asyncpg.PostgresError):
        await s.pg_env.pool.execute("TRUNCATE escalation_items")
    with pytest.raises(asyncpg.PostgresError):
        await s.pg_env.pool.execute("UPDATE escalation_audit SET actor = 'x'")


async def test_the_service_role_cannot_call_the_deletion_function_and_the_job_role_cannot_read(
    pg_stores,
):
    import asyncpg

    s = pg_stores
    await s.scoped(ACME).insert(make_item())
    with pytest.raises(asyncpg.PostgresError):
        await s.app_pool.fetchval(
            "SELECT retention_delete_class_d('r', $1, now(), 'total', 30, 'default', 10, 1)", ACME
        )
    for sql in (
        "SELECT content FROM escalation_items",
        "SELECT * FROM escalation_items",
        "DELETE FROM escalation_items",
        "UPDATE escalation_items SET content = NULL",
        "INSERT INTO retention_receipts (run_id, at, retention_class, cutoff, deleted_count, "
        "batch, retention_days, source) VALUES ('r', now(), 'D', now(), 1, 1, 30, 'default')",
    ):
        with pytest.raises(asyncpg.PostgresError):
            await s.ret_pool.fetch(sql)
    # it can list the tenants (one column) and nothing else
    assert await s.ret_pool.fetch("SELECT DISTINCT tenant_id FROM escalation_items") != []


async def test_an_operator_scope_reads_through_the_operator_pool_and_is_refused_without_one(
    pg_stores,
):
    from guardrail_engine.escalation.adapters.postgres import PostgresEscalationStore
    from guardrail_engine.store.port import OperatorPoolUnavailableError

    s = pg_stores
    item = make_item(ACME, 1)
    await s.scoped(ACME).insert(item)
    assert (await s.scoped(ACME, operator=True).get(ACME, item.id)).id == item.id
    no_pool = PostgresEscalationStore(s.app_pool, None)
    with pytest.raises(OperatorPoolUnavailableError):
        await no_pool.scoped(issue_scope(ACME, operator=True)).get(ACME, item.id)


async def test_the_outbox_accepts_the_escalation_kind(pg_env):
    from guardrail_engine.delivery.adapters.postgres import PgBridge, PostgresOutbox
    from guardrail_engine.delivery.events import KIND_ESCALATION

    async def connect():
        import asyncpg

        return await asyncpg.create_pool(
            pg_env.dsn, min_size=1, max_size=2, server_settings={"search_path": pg_env.schema}
        )

    bridge = PgBridge(connect, timeout_s=10)
    try:
        outbox = PostgresOutbox(bridge)
        assert await asyncio.to_thread(outbox.enqueue, KIND_ESCALATION, "{}", "esc_k", 1.8e9)
        assert not await asyncio.to_thread(outbox.enqueue, KIND_ESCALATION, "{}", "esc_k", 1.8e9)
        [entry] = await asyncio.to_thread(outbox.claim_due, 1.8e9 + 1, 5, 60.0, (KIND_ESCALATION,))
        assert (entry.kind, entry.key) == (KIND_ESCALATION, "esc_k")
        assert (
            await asyncio.to_thread(outbox.claim_due, 1.8e9 + 1, 5, 60.0, ("alert", "usage")) == []
        )
    finally:
        await asyncio.to_thread(bridge.close)


async def test_the_function_refuses_a_term_under_30_days_and_leaves_the_item(pg_stores):
    import asyncpg

    s = pg_stores
    await s.scoped().insert(make_item(created=NOW - 2 * DAY))
    for days in (-1, 0, 1, 29):
        with pytest.raises(asyncpg.PostgresError, match=r"30..400"):
            await s.ret_pool.fetchrow(
                "SELECT * FROM retention_delete_class_d('run1', $1, now(), 'total', $2, "
                "'default', 100, 1)",
                ACME,
                days,
            )
    assert await s.count(ACME) == 1
    assert await s.ret_pool.fetch("SELECT 1 FROM retention_receipts WHERE run_id = 'run1'") == []


async def test_the_reviewers_probe_deletes_nothing_in_the_database(pg_stores):
    """As it was run: as the retention role, a 2-day-old open item on a standard
    tenant, ``total`` and 1 day. It used to return (1, 1)."""
    import asyncpg

    s = pg_stores
    await s.scoped().insert(make_item(created=datetime.now(UTC) - 2 * DAY))
    with pytest.raises(asyncpg.PostgresError):
        await s.ret_pool.fetchrow(
            "SELECT * FROM retention_delete_class_d('run1', $1, now(), 'total', 1, 'default', 100, "
            "1)",
            ACME,
        )
    row = await s.ret_pool.fetchrow(
        "SELECT * FROM retention_delete_class_d('run1', $1, now(), 'total', 30, 'default', 100, 1)",
        ACME,
    )
    assert (row["deleted"], row["expired"]) == (0, 0)
    assert await s.count(ACME) == 1


async def test_the_function_puts_the_callers_tenant_setting_back(pg_stores):
    s = pg_stores
    await s.scoped().insert(make_item(created=NOW - timedelta(days=60)))
    call = (
        "SELECT * FROM retention_delete_class_d('r', $1, now(), 'resolved_plus', 30, 'default', "
        "10, 1)"
    )
    async with s.ret_pool.acquire() as conn, conn.transaction():
        await conn.execute("SELECT set_config('app.tenant_id', 't_before', true)")
        await conn.fetchrow(call, ACME)
        assert await conn.fetchval("SELECT current_setting('app.tenant_id', true)") == "t_before"
    async with s.ret_pool.acquire() as conn, conn.transaction():
        await conn.fetchrow(call, ACME)  # nothing was set before: the swept tenant isn't left
        assert await conn.fetchval("SELECT current_setting('app.tenant_id', true)") in ("", None)


async def test_the_retention_mode_cannot_be_changed_after_routing(pg_stores):
    import asyncpg

    s = pg_stores
    await s.scoped().insert(make_item())
    with pytest.raises(asyncpg.PostgresError):  # the owner's own update, past the grants
        await s.pg_env.pool.execute("UPDATE escalation_items SET retention_mode = 'total'")
    with pytest.raises(asyncpg.PostgresError):  # the service role has no such column grant
        async with s.app_pool.acquire() as conn, conn.transaction():
            await conn.execute("SELECT set_config('app.tenant_id', $1, true)", ACME)
            await conn.execute("UPDATE escalation_items SET retention_mode = 'total'")
    with pytest.raises(asyncpg.PostgresError):  # and only the two modes exist
        await s.scoped().insert(make_item(n=2, retention_mode="never"))
