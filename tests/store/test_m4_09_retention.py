"""M4-09: the retention engine for classes A and B.

Every behaviour test runs against the in-memory store and, when ``GUARDRAIL_TEST_PG_DSN`` is
set, the Postgres one (migrations 026 to 028, with the service and the retention job each
connected as its own least-privilege role). The clock is injected and always in the past, so the
database's own bound on the job's clock (never ahead of the database) is met.
"""

import asyncio
import copy
import json
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from policy_fixtures import (
    FINANCE_V2_DOCUMENT,
    FLOOR_DOCUMENTS,
    HEALTHCARE_V1_DOCUMENT,
    INSURANCE_V3_DOCUMENT,
    valid_bundle,
)

from guardrail_engine.directory.model import TenantRecord
from guardrail_engine.guard.audit import AuditRecord
from guardrail_engine.guard.verdict import Decision, Reason
from guardrail_engine.policy import (
    FloorVersion,
    InMemoryCatalog,
    PackVersion,
    PlatformSettings,
    parse_bundle,
)
from guardrail_engine.retention import (
    CatalogRetentionResolver,
    InMemoryDecisionStore,
    RetentionError,
    RetentionJob,
    TenantRetention,
)
from guardrail_engine.retention.adapters.postgres import (
    PostgresDecisionRecords,
    PostgresRetentionStore,
)

NOW = datetime(2026, 11, 1, 12, 0, 0, tzinfo=UTC)
DAY = timedelta(days=1)
ACME = "t_acmeins"
OTHER = "t_otherco"


def record(
    tenant_id: str | None,
    ts: datetime,
    *,
    days: int = 395,
    retain_until: datetime | None = None,
    request_id: str | None = None,
) -> AuditRecord:
    """A class B record. ``retain_until`` defaults to ``ts + days``."""
    return AuditRecord(
        ts=ts,
        retain_until=retain_until if retain_until is not None else ts + timedelta(days=days),
        request_id=request_id or uuid.uuid4().hex,
        tenant_id=tenant_id,
        claimed_tenant_id=tenant_id,
        guard_point="output",
        bundle_version=1,
        bundle_hash="sha256:" + "0" * 64,
        policy_source=None,
        policy_error=None,
        model=None,
        content_sha256="sha256:" + "1" * 64,
        content_tokens=10,
        context_items=0,
        context_items_dropped=0,
        decision=Decision.ALLOW,
        reason=Reason.POLICY,
        retryable=False,
        detail=None,
        fired=(),
        answers={"t__a": 0.1},
        provisional_rules=(),
        rules=(),
        contract_violations=(),
        model_called=True,
        provider_called=True,
        provider_calls=1,
        queue_wait_ms=0.0,
        provider_latency_ms=1.0,
        in_flight_at_start=0,
        model_latency_ms=1.0,
        failure_kind=None,
        failure_reason=None,
        capacity_limited=False,
        retry_after_ms=None,
        latency_ms=2.0,
        input_tokens=10,
        floor_fail_mode=None,
    )


class FixedResolver:
    def __init__(self, days: int, source="bundle") -> None:
        self.term = TenantRetention(days, source)

    async def resolve(self, tenant_id):
        return self.term


# ----------------------------------------------------------------------------- the two stores


class MemoryEnv:
    kind = "memory"

    def __init__(self) -> None:
        self.records = InMemoryDecisionStore()
        self.retention = self.records.retention

    async def total(self) -> int:
        return len(self.records._records)


class _OwnerCountRecords(PostgresDecisionRecords):
    """Writes as the service role; counts as the owner, who sees every tenant (and the rows
    with no tenant), which row-level security (032) hides from the service role."""

    def __init__(self, app_pool, owner_pool) -> None:
        super().__init__(app_pool)
        self._owner = owner_pool

    async def count(self, tenant_id):
        return int(
            await self._owner.fetchval(
                "SELECT count(*) FROM decision_records WHERE tenant_id IS NOT DISTINCT FROM $1",
                tenant_id,
            )
        )


class PgEnvStores:
    kind = "postgres"

    def __init__(self, pg_env, app_pool, retention_pool) -> None:
        self.pg_env = pg_env
        self.app_pool, self.retention_pool = app_pool, retention_pool
        self.records = _OwnerCountRecords(app_pool, pg_env.pool)
        self.retention = PostgresRetentionStore(retention_pool)

    async def total(self) -> int:
        return int(await self.pg_env.pool.fetchval("SELECT count(*) FROM decision_records"))


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
        apply_retention_role_grants,
    )

    app_role, app_pool = await _role_pool(pg_env, "m409_app", apply_app_role_grants)
    ret_role, ret_pool = await _role_pool(pg_env, "m409_ret", apply_retention_role_grants)
    try:
        stores = PgEnvStores(pg_env, app_pool, ret_pool)
        stores.app_role, stores.ret_role = app_role, ret_role
        yield stores
    finally:
        await app_pool.close()
        await ret_pool.close()
        for role in (app_role, ret_role):
            await pg_env.pool.execute(f'DROP OWNED BY "{role}"')
            await pg_env.pool.execute(f'DROP ROLE "{role}"')


@pytest.fixture(params=["memory", "postgres"])
def stores(request):
    if request.param == "memory":
        return MemoryEnv()
    return request.getfixturevalue("pg_stores")


def job(stores, days=395, *, now=NOW, **kw) -> RetentionJob:
    return RetentionJob(stores.retention, FixedResolver(days), clock=lambda: now, **kw)


# ----------------------------------------------------------------------------- the boundary


async def test_a_record_exactly_at_the_cutoff_is_kept_and_one_second_older_is_deleted(stores):
    cutoff = NOW - timedelta(days=395)
    exactly = record(ACME, cutoff, request_id="exactly")
    older = record(ACME, cutoff - timedelta(seconds=1), request_id="older")
    newer = record(ACME, cutoff + timedelta(seconds=1), request_id="newer")
    for r in (exactly, older, newer):
        await stores.records.append(r)

    report = await job(stores).run_once()

    assert report.deleted == 1
    assert await stores.records.count(ACME) == 2
    assert report.sweeps[0].cutoff == cutoff


async def test_a_record_is_also_kept_until_its_own_retain_until(stores):
    """A tenant that shortened its term doesn't lose records written under the longer one."""
    old = NOW - timedelta(days=200)
    kept = record(ACME, old, retain_until=NOW + DAY, request_id="longer_term")
    gone = record(ACME, old, retain_until=NOW - DAY, request_id="shorter_term")
    await stores.records.append(kept)
    await stores.records.append(gone)

    report = await job(stores, days=90).run_once()  # both are older than the 90-day cutoff

    assert report.deleted == 1
    assert await stores.records.count(ACME) == 1


async def test_retain_until_boundary_is_strict(stores):
    old = NOW - timedelta(days=200)
    await stores.records.append(record(ACME, old, retain_until=NOW))  # not yet past
    await stores.records.append(record(ACME, old, retain_until=NOW - timedelta(seconds=1)))

    assert (await job(stores, days=90).run_once()).deleted == 1


async def test_tenants_are_swept_with_their_own_terms_and_never_each_others_records(stores):
    ts = NOW - timedelta(days=120)
    await stores.records.append(record(ACME, ts, days=90))
    await stores.records.append(record(OTHER, ts, days=90))
    await stores.records.append(record(None, ts, days=90))

    class PerTenant:
        async def resolve(self, tenant_id):
            return TenantRetention({ACME: 90, OTHER: 395, None: 2555}[tenant_id], "bundle")

    report = await RetentionJob(stores.retention, PerTenant(), clock=lambda: NOW).run_once()

    assert {s.tenant_id: s.deleted for s in report.sweeps} == {ACME: 1, OTHER: 0, None: 0}
    assert await stores.records.count(OTHER) == 1
    assert await stores.records.count(None) == 1


async def test_second_run_is_idempotent(stores):
    for i in range(5):
        await stores.records.append(record(ACME, NOW - timedelta(days=400 + i)))
    await stores.records.append(record(ACME, NOW - DAY))

    first = await job(stores).run_once()
    second = await job(stores).run_once()

    assert (first.deleted, second.deleted) == (5, 0)
    assert await stores.records.count(ACME) == 1


async def test_the_clock_is_the_injected_one(stores):
    ts = NOW - timedelta(days=100)
    await stores.records.append(record(ACME, ts, days=90))
    assert (await job(stores, days=90, now=NOW - timedelta(days=20)).run_once()).deleted == 0
    assert (await job(stores, days=90, now=NOW).run_once()).deleted == 1


async def test_bounded_batches_and_a_resumable_cap(stores):
    for i in range(25):
        await stores.records.append(record(ACME, NOW - timedelta(days=500, seconds=i)))

    capped = await job(stores, batch_size=10, max_batches_per_tenant=2).run_once()
    assert capped.deleted == 20
    assert capped.sweeps[0].more_to_do is True
    assert capped.sweeps[0].batches == 2

    rest = await job(stores, batch_size=10, max_batches_per_tenant=2).run_once()
    assert rest.deleted == 5
    assert rest.sweeps[0].more_to_do is False
    assert await stores.total() == 0

    receipts = await stores.retention.receipts(capped.run_id)
    assert [r.deleted_count for r in receipts] == [10, 10]
    assert [r.batch for r in receipts] == [1, 2]


async def test_a_run_with_nothing_to_delete_still_leaves_a_zero_receipt(stores):
    await stores.records.append(record(ACME, NOW - DAY))
    report = await job(stores).run_once()
    [receipt] = await stores.retention.receipts(report.run_id)
    assert (receipt.tenant_id, receipt.retention_class, receipt.deleted_count) == (ACME, "B", 0)


async def test_one_tenant_failing_does_not_stop_the_others(stores):
    await stores.records.append(record(ACME, NOW - timedelta(days=500)))
    await stores.records.append(record(OTHER, NOW - timedelta(days=500)))

    class Flaky:
        def __init__(self, inner) -> None:
            self.inner = inner

        async def class_b_tenants(self):
            return await self.inner.class_b_tenants()

        async def delete_class_b_batch(self, **kw):
            if kw["tenant_id"] == ACME:
                raise RuntimeError("database down")
            return await self.inner.delete_class_b_batch(**kw)

    report = await RetentionJob(
        Flaky(stores.retention), FixedResolver(395), clock=lambda: NOW
    ).run_once()

    assert report.failed == (ACME,)
    assert report.deleted == 1
    assert await stores.records.count(ACME) == 1


# ----------------------------------------------------------------------------- the receipt


async def test_the_receipt_holds_tenant_class_cutoff_count_and_run_id_only(stores):
    for i in range(3):
        await stores.records.append(record(ACME, NOW - timedelta(days=500, seconds=i)))
    await stores.records.append(record(OTHER, NOW - timedelta(days=500)))

    report = await RetentionJob(
        stores.retention,
        FixedResolver(395, "clamped"),
        clock=lambda: NOW,
        run_id_factory=lambda: "run-0001",
    ).run_once()

    receipts = {r.tenant_id: r for r in await stores.retention.receipts("run-0001")}
    r = receipts[ACME]
    assert report.run_id == "run-0001"
    assert (r.run_id, r.tenant_id, r.retention_class) == ("run-0001", ACME, "B")
    assert (r.cutoff, r.deleted_count) == (NOW - timedelta(days=395), 3)
    if stores.kind == "memory":
        assert r.at == NOW
    else:  # the database stamps the receipt with its own clock, not the job's
        assert abs(r.at - datetime.now(UTC)) < timedelta(minutes=5)
    assert (r.retention_days, r.source, r.batch) == (395, "clamped", 1)
    assert receipts[OTHER].deleted_count == 1
    # Nothing but those fields: no content and no record data.
    assert set(r.__slots__) == {
        "run_id", "at", "tenant_id", "retention_class", "cutoff", "deleted_count",
        "batch", "retention_days", "source",
    }  # fmt: skip


async def test_the_deleted_records_content_never_reaches_the_receipt(stores):
    marker = "SECRET-CONTENT-MARKER"
    rec = record(ACME, NOW - timedelta(days=500), request_id=marker)
    await stores.records.append(rec)
    report = await job(stores).run_once()
    receipts = await stores.retention.receipts(report.run_id)
    assert marker not in repr(receipts) and marker not in repr(report)


# ----------------------------------------------------------------------------- concurrency


async def test_two_concurrent_runs_never_delete_or_count_a_record_twice(stores):
    n = 240
    for i in range(n):
        await stores.records.append(record(ACME, NOW - timedelta(days=500, seconds=i)))
    survivors = 7
    for i in range(survivors):
        await stores.records.append(record(ACME, NOW - timedelta(days=i)))

    a = job(stores, batch_size=10, run_id_factory=lambda: "run-a")
    b = job(stores, batch_size=10, run_id_factory=lambda: "run-b")
    ra, rb = await asyncio.gather(a.run_once(), b.run_once())

    assert ra.deleted + rb.deleted == n
    receipts = await stores.retention.receipts()
    assert sum(r.deleted_count for r in receipts) == n
    assert {r.run_id for r in receipts} <= {"run-a", "run-b"}
    for report in (ra, rb):  # each run's receipts add up to what it reports
        mine = [r for r in receipts if r.run_id == report.run_id]
        assert sum(r.deleted_count for r in mine) == report.deleted
    assert await stores.records.count(ACME) == survivors


# ----------------------------------------------------------------------------- the resolver


def catalog(*, tier_required=None) -> InMemoryCatalog:
    return InMemoryCatalog(
        floors=[FloorVersion.from_document(d) for d in FLOOR_DOCUMENTS],
        packs=[
            PackVersion.from_document(d)
            for d in (INSURANCE_V3_DOCUMENT, FINANCE_V2_DOCUMENT, HEALTHCARE_V1_DOCUMENT)
        ],
        tier_required_packs=tier_required
        if tier_required is not None
        else {"regulated": ["finance"]},
    )


class Directory:
    def __init__(self, *records: TenantRecord) -> None:
        self.by_id = {r.tenant_id: r for r in records}

    async def get(self, tenant_id):
        return self.by_id.get(tenant_id)


def tenant(tier="standard", **kw) -> TenantRecord:
    return TenantRecord(tenant_id=ACME, slug="acme", domain="insurance", tier=tier, **kw)


def bundle_with(extends, records_days=None):
    raw = copy.deepcopy(valid_bundle())
    raw["extends"] = ["platform/floor@2", *extends]
    raw["overrides"] = []
    raw["audit"] = {} if records_days is None else {"records_days": records_days}
    return parse_bundle(raw)


def resolver(directory, bundle, *, cat=None) -> CatalogRetentionResolver:
    async def load(tenant_id):
        if isinstance(bundle, Exception):
            raise bundle
        return bundle

    return CatalogRetentionResolver(
        catalog=cat or catalog(),
        settings=PlatformSettings(min_floor_version=2),
        directory=directory,
        load_active_bundle=load,
    )


@pytest.mark.parametrize(
    ("extends", "expected"),
    [
        ([], 395),  # no pack: the standard default
        (["domain/insurance@3"], 395),
        (["domain/healthcare@1"], 6 * 365),
        (["domain/finance@2"], 7 * 365),
        (["domain/healthcare@1", "domain/insurance@3"], 6 * 365),
        (["domain/healthcare@1", "domain/finance@2"], 7 * 365),  # several packs: the longest
        (["domain/finance@2", "domain/healthcare@1", "domain/insurance@3"], 7 * 365),
    ],
)
async def test_default_term_is_the_longest_among_the_packs(extends, expected):
    term = await resolver(Directory(tenant()), bundle_with(extends)).resolve(ACME)
    assert term == TenantRetention(expected, "default")


async def test_a_tenants_own_term_is_used_inside_its_bounds():
    r = resolver(Directory(tenant()), bundle_with([], records_days=90))
    assert await r.resolve(ACME) == TenantRetention(90, "bundle")
    r = resolver(Directory(tenant()), bundle_with([], records_days=7 * 365))
    assert await r.resolve(ACME) == TenantRetention(7 * 365, "bundle")


@pytest.mark.parametrize(
    ("extends", "asked", "expected"),
    [
        (["domain/finance@2"], 90, 395),  # a pack raised the minimum
        (["domain/healthcare@1"], 200, 395),
        ([], 89, 90),  # below the standard minimum
        ([], 7 * 365 + 1, 7 * 365),  # above the maximum
    ],
)
async def test_a_term_outside_the_bounds_is_moved_into_them(extends, asked, expected):
    r = resolver(Directory(tenant()), bundle_with(extends, records_days=asked))
    assert await r.resolve(ACME) == TenantRetention(expected, "clamped")


async def test_tier_bounds_apply_even_if_the_active_bundle_lacks_the_required_pack():
    """The regulated tier requires finance; a bundle published before that still gets 395 as
    its minimum and 7 years as its default."""
    d = Directory(tenant("regulated"))
    assert await resolver(d, bundle_with([], records_days=100)).resolve(ACME) == TenantRetention(
        395, "clamped"
    )
    assert await resolver(d, bundle_with([])).resolve(ACME) == TenantRetention(7 * 365, "default")


async def test_a_contract_required_pack_counts_too():
    d = Directory(tenant(required_packs=frozenset({"healthcare"})))
    assert await resolver(d, bundle_with([])).resolve(ACME) == TenantRetention(6 * 365, "default")


async def test_no_active_bundle_gets_the_packs_default():
    d = Directory(tenant("regulated"))
    assert await resolver(d, None).resolve(ACME) == TenantRetention(7 * 365, "default")


@pytest.mark.parametrize(
    "case", ["no_tenant_id", "not_in_directory", "load_fails", "pack_not_in_catalog"]
)
async def test_an_unresolvable_tenant_keeps_the_longest_term(case):
    directory = Directory(tenant())
    bundle = bundle_with([], records_days=90)
    if case == "no_tenant_id":
        assert await resolver(directory, bundle).resolve(None) == TenantRetention(
            7 * 365, "fallback"
        )
        return
    if case == "not_in_directory":
        directory = Directory()
    elif case == "load_fails":
        bundle = RuntimeError("integrity")
    else:
        bundle = bundle_with(["domain/finance@9"], records_days=90)
    assert await resolver(directory, bundle).resolve(ACME) == TenantRetention(7 * 365, "fallback")


async def test_the_resolver_uses_the_compilers_bounds_code():
    from guardrail_engine.policy import compiler as c
    from guardrail_engine.retention import resolver as r

    assert r.combined_retention is c.combined_retention
    assert r.records_days_in_bounds is c.records_days_in_bounds


async def test_end_to_end_multi_pack_term_deletes_at_the_longest_pack_term(stores):
    """Finance and healthcare packs together: 7 years, not healthcare's 6."""
    r = resolver(
        Directory(tenant()),
        bundle_with(["domain/finance@2", "domain/healthcare@1"]),
    )
    cutoff = NOW - timedelta(days=7 * 365)
    await stores.records.append(record(ACME, cutoff - timedelta(seconds=1), days=7 * 365))
    await stores.records.append(record(ACME, cutoff, days=7 * 365))
    await stores.records.append(record(ACME, NOW - timedelta(days=6 * 365 + 30), days=7 * 365))

    report = await RetentionJob(stores.retention, r, clock=lambda: NOW).run_once()

    assert report.deleted == 1
    assert await stores.records.count(ACME) == 2
    assert report.sweeps[0].retention_days == 7 * 365


# ----------------------------------------------------------------------------- the stores' bounds


async def test_the_store_refuses_a_cutoff_inside_the_ninety_day_minimum(stores):
    await stores.records.append(record(ACME, NOW - timedelta(days=100), days=1))
    for days, cutoff in ((89, NOW - timedelta(days=89)), (0, NOW), (90, NOW - timedelta(days=89))):
        with pytest.raises(RetentionError):
            await stores.retention.delete_class_b_batch(
                run_id="r", tenant_id=ACME, cutoff=cutoff, now=NOW, limit=10,
                retention_days=days, source="bundle", batch=1,
            )  # fmt: skip
    assert await stores.records.count(ACME) == 1


@pytest.mark.parametrize("limit", [0, -1, 100_001])
async def test_the_store_refuses_an_unbounded_batch(stores, limit):
    with pytest.raises(RetentionError):
        await stores.retention.delete_class_b_batch(
            run_id="r", tenant_id=ACME, cutoff=NOW - timedelta(days=395), now=NOW, limit=limit,
            retention_days=395, source="bundle", batch=1,
        )  # fmt: skip


@pytest.mark.parametrize(
    ("days", "cutoff_days", "source"),
    [
        (395, 394, "bundle"),  # the receipt's figure disagrees with the cutoff
        (395, 396, "bundle"),
        (90, 395, "default"),
        (36_501, 36_501, "bundle"),  # a term over 100 years
        (395, 395, ""),
        (395, 395, "Bundle"),  # uppercase
        (395, 395, "bundle;"),  # outside the letters
        (395, 395, "a" * 17),  # too long
    ],
)
async def test_the_store_refuses_a_receipt_that_disagrees_with_the_cutoff_or_a_bad_source(
    stores, days, cutoff_days, source
):
    await stores.records.append(record(ACME, NOW - timedelta(days=40_000)))
    with pytest.raises(RetentionError):
        await stores.retention.delete_class_b_batch(
            run_id="r", tenant_id=ACME, cutoff=NOW - timedelta(days=cutoff_days), now=NOW,
            limit=10, retention_days=days, source=source, batch=1,
        )  # fmt: skip
    assert await stores.records.count(ACME) == 1
    assert await stores.retention.receipts() == []


async def test_the_record_store_offers_no_delete():
    store = InMemoryDecisionStore()
    assert not [n for n in dir(store) if "delete" in n or "remove" in n or "purge" in n]
    assert not [
        n for n in dir(PostgresDecisionRecords) if "delete" in n or "remove" in n or "purge" in n
    ]


# ----------------------------------------------------------------------------- Postgres roles


async def test_the_database_refuses_ordinary_roles_any_delete_or_change(pg_stores):
    import asyncpg

    await pg_stores.records.append(record(ACME, NOW - timedelta(days=500)))
    app = pg_stores.app_pool
    denied = (asyncpg.InsufficientPrivilegeError,)

    with pytest.raises(denied):
        await app.execute("DELETE FROM decision_records")
    with pytest.raises(denied):
        await app.execute("UPDATE decision_records SET tenant_id = 't_x'")
    with pytest.raises(denied):
        await app.execute("TRUNCATE decision_records")
    with pytest.raises(denied):  # the service role may not call the deletion path
        await app.fetchval(
            "SELECT retention_delete_class_b('r', $1, $2, $3, 10, 395, 'bundle', 1)",
            ACME, NOW - timedelta(days=400), NOW,
        )  # fmt: skip
    with pytest.raises(denied):  # nor touch the receipts
        await app.fetch("SELECT * FROM retention_receipts")
    with pytest.raises(denied):
        await app.execute(
            "INSERT INTO retention_receipts (run_id, at, retention_class, cutoff, deleted_count,"
            " batch, retention_days, source) VALUES ('x', now(), 'B', now(), 0, 1, 90, 'bundle')"
        )
    assert await pg_stores.total() == 1


async def test_the_retention_role_can_only_delete_through_the_function(pg_stores):
    import asyncpg

    await pg_stores.records.append(record(ACME, NOW - timedelta(days=500)))
    ret = pg_stores.retention_pool
    denied = (asyncpg.InsufficientPrivilegeError,)

    with pytest.raises(denied):
        await ret.execute("DELETE FROM decision_records")
    with pytest.raises(denied):
        await ret.execute("UPDATE decision_records SET tenant_id = 't_x'")
    with pytest.raises(denied):
        await ret.fetch("SELECT record FROM decision_records")  # only tenant_id is readable
    with pytest.raises(denied):
        await ret.execute(
            "INSERT INTO retention_receipts (run_id, at, retention_class, cutoff, deleted_count,"
            " batch, retention_days, source) VALUES ('x', now(), 'B', now(), 0, 1, 90, 'bundle')"
        )
    with pytest.raises(denied):
        await ret.execute("DELETE FROM retention_receipts")
    assert await pg_stores.total() == 1

    report = await job(pg_stores).run_once()  # the function works
    assert report.deleted == 1
    assert await pg_stores.total() == 0


async def test_the_function_is_not_executable_by_public(pg_stores, pg_env):
    privileged = await pg_env.pool.fetchval(
        "SELECT has_function_privilege($1, 'retention_delete_class_b(text,text,timestamptz,"
        "timestamptz,integer,integer,text,integer)', 'EXECUTE')",
        pg_stores.app_role,
    )
    assert privileged is False
    assert (
        await pg_env.pool.fetchval(
            "SELECT has_function_privilege($1, 'retention_delete_class_b(text,text,timestamptz,"
            "timestamptz,integer,integer,text,integer)', 'EXECUTE')",
            pg_stores.ret_role,
        )
        is True
    )


async def test_receipts_and_records_are_protected_from_the_owner_too(pg_stores, pg_env):
    import asyncpg

    await pg_stores.records.append(record(ACME, NOW - timedelta(days=500)))
    await pg_stores.records.append(record(ACME, NOW - DAY))  # survives, so an UPDATE has a row
    await job(pg_stores).run_once()
    owner = pg_env.pool
    for sql in (
        "UPDATE retention_receipts SET deleted_count = 0",
        "DELETE FROM retention_receipts",
        "TRUNCATE retention_receipts",
        "UPDATE decision_records SET tenant_id = 't_x'",
        "TRUNCATE decision_records",
    ):
        with pytest.raises(asyncpg.PostgresError) as e:
            await owner.execute(sql)
        # (M4-07: TRUNCATE of the parent is refused first by the index table's foreign key)
        assert e.value.sqlstate in ("23001", "0A000"), sql


async def test_the_function_refuses_a_clock_ahead_of_the_database(pg_stores):
    future = datetime.now(UTC) + timedelta(days=30)
    with pytest.raises(RetentionError):
        await pg_stores.retention.delete_class_b_batch(
            run_id="r", tenant_id=ACME, cutoff=future - timedelta(days=395), now=future,
            limit=10, retention_days=395, source="bundle", batch=1,
        )  # fmt: skip


async def test_rows_another_run_holds_are_skipped_not_waited_for(pg_stores, pg_env):
    for i in range(4):
        await pg_stores.records.append(record(ACME, NOW - timedelta(days=500, seconds=i)))
    async with pg_env.pool.acquire() as conn:
        tx = conn.transaction()
        await tx.start()
        try:
            held = await conn.fetchval(
                "SELECT id FROM decision_records ORDER BY id LIMIT 1 FOR UPDATE"
            )
            n = await asyncio.wait_for(
                pg_stores.retention.delete_class_b_batch(
                    run_id="r", tenant_id=ACME, cutoff=NOW - timedelta(days=395), now=NOW,
                    limit=10, retention_days=395, source="bundle", batch=1,
                ),
                timeout=10,
            )  # fmt: skip
        finally:
            await tx.rollback()
    assert n == 3
    assert held is not None
    assert await pg_stores.total() == 1


async def test_a_decision_record_round_trips_without_content(pg_stores, pg_env):
    rec = record(ACME, NOW - timedelta(days=3))
    await pg_stores.records.append(rec)
    text = await pg_env.pool.fetchval("SELECT record FROM decision_records")
    assert AuditRecord.model_validate_json(text) == rec
    assert "content" not in json.loads(text).keys() - {"content_sha256", "content_tokens"}


# ------------------------------------------------------- the function itself

_FN_SQL = "SELECT retention_delete_class_b($1, $2, $3, $4, $5, $6, $7, $8)"
_TEMP_RECEIPTS = (
    "CREATE TEMP TABLE retention_receipts ("
    " id bigint GENERATED ALWAYS AS IDENTITY, run_id text, at timestamptz, tenant_id text,"
    " retention_class text, cutoff timestamptz, deleted_count integer, batch integer,"
    " retention_days integer, source text)"
)
_TEMP_RECORDS = (
    "CREATE TEMP TABLE decision_records ("
    " id bigint GENERATED ALWAYS AS IDENTITY, tenant_id text, request_id text,"
    " guard_point text, ts timestamptz, retain_until timestamptz, record text)"
)


async def _call(conn, *, now=NOW, days=395, source="bundle", tenant=ACME, cutoff=None):
    cutoff = cutoff if cutoff is not None else now - timedelta(days=days)
    return await conn.fetchval(_FN_SQL, "run1", tenant, cutoff, now, 1000, days, source, 1)


async def test_the_function_pins_search_path_with_pg_temp_last(pg_stores, pg_env):
    config = await pg_env.pool.fetchval(
        "SELECT proconfig FROM pg_proc WHERE proname = 'retention_delete_class_b'"
        " AND pronamespace = $1::regnamespace",
        pg_env.schema,
    )
    paths = [c for c in config if c.startswith("search_path=")]
    assert len(paths) == 1
    items = [i.strip().strip('"') for i in paths[0].removeprefix("search_path=").split(",")]
    assert items == ["pg_catalog", pg_env.schema, "pg_temp"]
    # The tables' schema is the migration's, and the body names it on every table.
    body = await pg_env.pool.fetchval(
        "SELECT prosrc FROM pg_proc WHERE proname = 'retention_delete_class_b'"
        " AND pronamespace = $1::regnamespace",
        pg_env.schema,
    )
    assert body.count(f"{pg_env.schema}.decision_records") == 2
    assert body.count(f"{pg_env.schema}.retention_receipts") == 1
    assert " FROM decision_records" not in body
    assert "INTO retention_receipts" not in body


async def test_a_temp_table_cannot_swallow_the_receipt_or_stand_in_for_the_records(
    pg_stores, pg_env
):
    """The probe. TEMP is not revoked (PUBLIC holds it; see 030), so the
    retention role can create the shadowing tables; the function must ignore them."""
    for i in range(3):
        await pg_stores.records.append(record(ACME, NOW - timedelta(days=500, seconds=i)))
    await pg_stores.records.append(record(ACME, NOW - DAY))  # survives

    async with pg_stores.retention_pool.acquire() as conn:
        await conn.execute(_TEMP_RECEIPTS)  # the role can: the shadow exists
        await conn.execute(_TEMP_RECORDS)
        await conn.execute(
            "INSERT INTO decision_records (tenant_id, request_id, guard_point, ts, retain_until,"
            " record) VALUES ($1, 'x', 'output', $2, $2, '{}')",
            ACME,
            NOW - timedelta(days=900),
        )
        try:
            n = await _call(conn)
            temp_receipts = await conn.fetchval("SELECT count(*) FROM pg_temp.retention_receipts")
            temp_records = await conn.fetchval("SELECT count(*) FROM pg_temp.decision_records")
        finally:
            await conn.execute("DROP TABLE pg_temp.retention_receipts, pg_temp.decision_records")

    assert n == 3  # the real expired rows went; the temp table's row was never considered
    assert temp_receipts == 0
    assert temp_records == 1
    assert await pg_stores.total() == 1
    durable = await pg_env.pool.fetch("SELECT deleted_count, run_id FROM retention_receipts")
    assert [(r["deleted_count"], r["run_id"]) for r in durable] == [(3, "run1")]


async def test_the_receipt_time_is_the_database_clock_not_the_callers(pg_stores, pg_env):
    async with pg_stores.retention_pool.acquire() as conn:
        await _call(conn)  # p_now is a fortnight-old fixed date
    at = await pg_env.pool.fetchval("SELECT at FROM retention_receipts")
    assert abs(at - datetime.now(UTC)) < timedelta(minutes=5)
    assert at != NOW


async def test_a_record_is_not_deleted_before_its_retain_until_by_the_databases_clock(
    pg_stores, pg_env
):
    """p_now may be five minutes ahead of the database; retain_until is compared with the
    earlier of the two, so a record 2 minutes from expiry is kept."""
    real = datetime.now(UTC)
    ahead = real + timedelta(minutes=4)
    old = real - timedelta(days=500)
    await pg_stores.records.append(
        record(ACME, old, retain_until=real + timedelta(minutes=2), request_id="soon")
    )
    await pg_stores.records.append(
        record(ACME, old, retain_until=real - timedelta(minutes=2), request_id="past")
    )
    async with pg_stores.retention_pool.acquire() as conn:
        n = await _call(conn, now=ahead)
    assert n == 1
    left = await pg_env.pool.fetchval("SELECT request_id FROM decision_records")
    assert left == "soon"


@pytest.mark.parametrize(
    ("days", "cutoff_days", "source"),
    [
        (395, 394, "bundle"),
        (395, 396, "bundle"),
        (89, 89, "bundle"),
        (36_501, 36_501, "bundle"),
        (None, 395, "bundle"),
        (395, 395, None),
        (395, 395, ""),
        (395, 395, "Bundle"),
        (395, 395, "bundle; drop"),
        (395, 395, "a" * 17),
    ],
)
async def test_the_function_itself_refuses_a_figure_or_source_that_disagrees(
    pg_stores, pg_env, days, cutoff_days, source
):
    """Straight at the SQL, bypassing the Python pre-check."""
    import asyncpg

    await pg_stores.records.append(record(ACME, NOW - timedelta(days=40_000)))
    async with pg_stores.retention_pool.acquire() as conn:
        with pytest.raises(asyncpg.InvalidParameterValueError):
            await conn.fetchval(
                _FN_SQL, "run1", ACME, NOW - timedelta(days=cutoff_days), NOW, 10, days, source, 1
            )
    assert await pg_stores.total() == 1
    assert await pg_env.pool.fetchval("SELECT count(*) FROM retention_receipts") == 0


def test_the_migration_numbers_are_the_lowest_free_after_025():
    from guardrail_engine.store.adapters.postgres import migration_sql

    for name in ("026_retention.sql", "029_retention_app_grants.sql"):
        assert migration_sql(name)
    assert ':"retention_role"' in migration_sql("030_retention_role_grants.sql")
    assert ':"app_role"' in migration_sql("029_retention_app_grants.sql")
