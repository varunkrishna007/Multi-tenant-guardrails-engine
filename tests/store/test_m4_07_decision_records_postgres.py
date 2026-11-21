"""M4-07 on Postgres: the decision-record writer's insert and the audit query's read, under
forced row-level security (032, 033), with a **non-superuser owner** so the policies really
apply (a superuser bypasses row-level security, and the other store tests connect as one).
Needs GUARDRAIL_TEST_PG_DSN; skipped without it."""

import os
import sys
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import asyncpg
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "audit"))
from audit_records import ACME, NOW, OTHER, evaluation, fired, make_record

from guardrail_engine.audit.adapters.postgres import PostgresDecisionStore
from guardrail_engine.audit.store import DecisionFilter, Position
from guardrail_engine.guard.verdict import Decision
from guardrail_engine.retention.adapters.postgres import PostgresRetentionStore
from guardrail_engine.store.adapters.postgres import (
    apply_app_role_grants,
    apply_operator_policy,
    apply_retention_role_grants,
    apply_schema,
)
from guardrail_engine.tenant_scope import issue_scope

DENIED = (asyncpg.InsufficientPrivilegeError, asyncpg.exceptions.RestrictViolationError)
WIDE = DecisionFilter(NOW - timedelta(days=40), NOW + timedelta(days=1))


class Env:
    pass


async def _login_role(admin, schema, prefix):
    role = f"{prefix}_{uuid.uuid4().hex[:10]}"
    password = uuid.uuid4().hex
    await admin.execute(f"CREATE ROLE \"{role}\" LOGIN PASSWORD '{password}'")
    return role, password


@pytest.fixture
async def env():
    dsn = os.environ.get("GUARDRAIL_TEST_PG_DSN")
    if not dsn:
        pytest.skip("GUARDRAIL_TEST_PG_DSN is not set; Postgres tests need a database")
    e = Env()
    schema = e.schema = f"m407_{uuid.uuid4().hex[:16]}"
    admin = await asyncpg.connect(dsn)
    roles: list[str] = []
    pools: list = []
    try:
        owner, owner_pw = await _login_role(admin, schema, "m407_owner")
        roles.append(owner)
        await admin.execute(f'CREATE SCHEMA "{schema}" AUTHORIZATION "{owner}"')

        async def pool_for(role, password):
            p = await asyncpg.create_pool(
                dsn, user=role, password=password, min_size=1, max_size=4,
                server_settings={"search_path": schema},
            )  # fmt: skip
            pools.append(p)
            return p

        e.owner = await pool_for(owner, owner_pw)
        await apply_schema(e.owner)  # as a role that is NOT a superuser
        app, app_pw = await _login_role(admin, schema, "m407_app")
        ret, ret_pw = await _login_role(admin, schema, "m407_ret")
        op, op_pw = await _login_role(admin, schema, "m407_op")
        roles += [app, ret, op]
        for role in (app, ret, op):
            await e.owner.execute(f'GRANT USAGE ON SCHEMA "{schema}" TO "{role}"')
        await apply_app_role_grants(e.owner, app)
        await apply_retention_role_grants(e.owner, ret)
        await apply_app_role_grants(e.owner, op)
        await apply_operator_policy(e.owner, op)
        e.app = await pool_for(app, app_pw)
        e.retention_pool = await pool_for(ret, ret_pw)
        e.operator = await pool_for(op, op_pw)
        e.store = PostgresDecisionStore(e.app, e.operator)
        e.retention = PostgresRetentionStore(e.retention_pool)
        e.admin = admin  # a superuser: it sees what row-level security hides from everyone
        e.owner_superuser = await e.owner.fetchval(
            "SELECT rolsuper FROM pg_roles WHERE rolname = current_user"
        )
        yield e
    finally:
        for p in pools:
            await p.close()
        await admin.execute(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
        for role in roles:
            await admin.execute(f'DROP OWNED BY "{role}"')
            await admin.execute(f'DROP ROLE "{role}"')
        await admin.close()


async def test_the_owner_in_these_tests_is_not_a_superuser(env):
    assert env.owner_superuser is False  # else row-level security would prove nothing


async def test_a_batch_is_written_per_tenant_and_a_tenant_reads_only_its_own(env):
    await env.store.append_many(
        [make_record(ACME, NOW - timedelta(minutes=i)) for i in range(3)]
        + [make_record(OTHER, NOW), make_record(None, NOW)]
    )
    acme = await env.store.page(issue_scope(ACME), WIDE, 50, None)
    other = await env.store.page(issue_scope(OTHER), WIDE, 50, None)
    assert [d.record["tenant_id"] for d in acme] == [ACME] * 3
    assert [d.record["tenant_id"] for d in other] == [OTHER]
    assert (
        await env.owner.fetchval("SELECT count(*) FROM decision_records") == 5
    )  # the null one too


async def test_the_service_role_sees_nothing_without_a_tenant_setting_and_cannot_change_rows(env):
    await env.store.append_many([make_record(ACME), make_record(None)])
    assert await env.app.fetchval("SELECT count(*) FROM decision_records") == 0  # no setting
    async with env.app.acquire() as conn, conn.transaction():
        await conn.execute("SELECT set_config('app.tenant_id', $1, true)", ACME)
        assert await conn.fetchval("SELECT count(*) FROM decision_records") == 1  # not the null
    for statement in (
        "DELETE FROM decision_records",
        "UPDATE decision_records SET guard_point = 'x'",
        "TRUNCATE decision_records",
    ):
        with pytest.raises(DENIED):
            await env.app.execute(statement)


async def test_a_write_under_another_tenants_setting_is_refused(env):
    record = make_record(OTHER)
    async with env.app.acquire() as conn, conn.transaction():
        await conn.execute("SELECT set_config('app.tenant_id', $1, true)", ACME)
        with pytest.raises(asyncpg.exceptions.InsufficientPrivilegeError):
            await conn.execute(
                "INSERT INTO decision_records (tenant_id, request_id, guard_point, ts, "
                "retain_until, record) VALUES ($1, 'r', 'output', $2, $3, '{}')",
                OTHER, record.ts, record.retain_until,
            )  # fmt: skip


async def test_the_page_filters_by_time_guard_point_decision_and_fired_rule(env):
    block = fired("t__refunds", "tenant", 0.9)
    shadow = fired("t__refunds", "tenant", 0.6, action="escalate", mode="shadow")
    other = fired("t__other", "tenant", 0.9)
    await env.store.append_many(
        [
            make_record(ACME, NOW - timedelta(hours=1), decision=Decision.BLOCK,
                        fired_entries=[block]),
            make_record(ACME, NOW - timedelta(hours=2), guard_point="input",
                        decision=Decision.ESCALATE, fired_entries=[shadow]),
            make_record(ACME, NOW - timedelta(hours=3), fired_entries=[other]),
            make_record(ACME, NOW - timedelta(days=10)),
        ]
    )  # fmt: skip
    scope = issue_scope(ACME)

    async def ids(**kw):
        flt = DecisionFilter(**{"start": NOW - timedelta(days=1), "end": NOW, **kw})
        return [d.record["guard_point"] + ":" + d.record["decision"]
                for d in await env.store.page(scope, flt, 50, None)]  # fmt: skip

    assert len(await ids()) == 3  # the 10-day-old one is outside the window
    assert await ids(rule="t__refunds") == ["output:block", "input:escalate"]  # a shadow too
    assert await ids(guard_point="input") == ["input:escalate"]
    assert await ids(decision="block") == ["output:block"]
    assert await ids(rule="t__refunds", decision="escalate") == ["input:escalate"]
    assert await ids(rule="nope") == []
    # the start is inclusive and the end exclusive
    flt = DecisionFilter(NOW - timedelta(hours=1), NOW - timedelta(hours=1) + timedelta(seconds=1))
    assert len(await env.store.page(scope, flt, 50, None)) == 1
    flt = DecisionFilter(NOW - timedelta(hours=2), NOW - timedelta(hours=1))
    assert [d.record["decision"] for d in await env.store.page(scope, flt, 50, None)] == [
        "escalate"
    ]


async def test_pages_follow_a_keyset_without_gaps_or_repeats_even_for_equal_times(env):
    same = NOW - timedelta(minutes=5)
    await env.store.append_many(
        [make_record(ACME, same, request_id=f"same-{i}") for i in range(7)]
        + [make_record(ACME, NOW - timedelta(minutes=i), request_id=f"r-{i}") for i in range(8, 14)]
    )
    scope = issue_scope(ACME)
    seen, after = [], None
    while True:
        rows = await env.store.page(scope, WIDE, 4, after)
        seen += [d.record["request_id"] for d in rows]
        if len(rows) < 4:
            break
        after = Position(rows[-1].ts, rows[-1].id)
    assert len(seen) == 13 and len(set(seen)) == 13
    ts = [d.ts for d in await env.store.page(scope, WIDE, 50, None)]
    assert ts == sorted(ts, reverse=True)


async def test_an_operator_scope_reads_the_tenant_it_names_and_no_other(env):
    await env.store.append_many([make_record(ACME), make_record(OTHER), make_record(OTHER)])
    scope = issue_scope(OTHER, operator=True)
    assert len(await env.store.page(scope, WIDE, 50, None)) == 2
    with pytest.raises(DENIED):  # the operator role has no write
        await env.operator.execute(
            "INSERT INTO decision_records (tenant_id, request_id, guard_point, ts, retain_until,"
            " record) VALUES ('t_otherco', 'r', 'output', now(), now(), '{}')"
        )


async def test_the_retention_role_lists_tenants_and_deletes_only_through_the_function(env):
    now = datetime(2026, 11, 1, 12, tzinfo=UTC)  # before the database's clock, as it must be
    old = now - timedelta(days=500)
    await env.store.append_many(
        [make_record(ACME, old, days=90), make_record(None, old, days=90), make_record(ACME, now)]
    )
    assert set(await env.retention.class_b_tenants()) == {ACME, None}  # policy 033
    with pytest.raises(DENIED):
        await env.retention_pool.fetch("SELECT record FROM decision_records")  # columns
    n = await env.retention.delete_class_b_batch(
        run_id="r1", tenant_id=ACME, cutoff=now - timedelta(days=395), now=now, limit=100,
        retention_days=395, source="bundle", batch=1,
    )  # fmt: skip
    # the SECURITY DEFINER function runs as the owner: forced RLS still lets it select and
    # delete (the owner's policies in 032), for the one tenant it was asked about
    assert n == 1
    assert await env.owner.fetchval("SELECT count(*) FROM decision_records") == 2
    n = await env.retention.delete_class_b_batch(
        run_id="r1", tenant_id=None, cutoff=now - timedelta(days=395), now=now, limit=100,
        retention_days=395, source="fallback", batch=1,
    )  # fmt: skip
    assert n == 1


async def test_the_columns_are_copies_of_the_record_and_old_rows_without_them_still_load(env):
    entry = fired("t__refunds", "tenant", 0.9)
    await env.store.append_many(
        [make_record(ACME, decision=Decision.BLOCK, fired_entries=[entry, entry])]
    )
    row = await env.owner.fetchrow("SELECT decision, fired_rules FROM decision_records")
    assert row["decision"] == "block" and row["fired_rules"] == ["t__refunds"]  # once each
    async with env.app.acquire() as conn, conn.transaction():  # a row from before 032
        await conn.execute("SELECT set_config('app.tenant_id', $1, true)", ACME)
        await conn.execute(
            "INSERT INTO decision_records (tenant_id, request_id, guard_point, ts, retain_until,"
            " record) VALUES ($1, 'old', 'output', $2, $3, $4)",
            ACME, NOW - timedelta(hours=9), NOW, make_record(ACME).model_dump_json(),
        )  # fmt: skip
    rows = await env.store.page(issue_scope(ACME), WIDE, 50, None)
    assert len(rows) == 2
    assert {evaluation("t__a", "tenant", 0.1).key} == {"t__a"}  # the helper builds one


async def test_the_rule_index_rows_follow_their_record_and_go_with_it(env):
    now = datetime(2026, 11, 1, 12, tzinfo=UTC)
    old = now - timedelta(days=500)
    a, b = fired("t__refunds", "tenant", 0.9), fired("t__other", "tenant", 0.9, action="escalate")
    await env.store.append_many(
        [
            make_record(ACME, old, days=90, fired_entries=[a, b, a]),
            make_record(ACME, now, fired_entries=[a]),
            make_record(OTHER, now, fired_entries=[a]),
            make_record(None, now, fired_entries=[a]),  # no tenant: nothing to index
        ]
    )
    rows = await env.admin.fetch(
        f'SELECT tenant_id, rule FROM "{env.schema}".decision_record_rules ORDER BY 1, 2'
    )
    assert [tuple(r) for r in rows] == [
        (ACME, "t__other"),
        (ACME, "t__refunds"),
        (ACME, "t__refunds"),
        (OTHER, "t__refunds"),
    ]  # fmt: skip  (once per rule and record, never for a record with no tenant)
    n = await env.retention.delete_class_b_batch(
        run_id="r1", tenant_id=ACME, cutoff=now - timedelta(days=395), now=now, limit=100,
        retention_days=395, source="bundle", batch=1,
    )  # fmt: skip
    assert n == 1  # the old record
    left = await env.admin.fetchval(f'SELECT count(*) FROM "{env.schema}".decision_record_rules')
    assert left == 2  # its two index rows went with it
    scope = issue_scope(ACME)
    flt = DecisionFilter(now - timedelta(days=1), now + timedelta(days=1), rule="t__refunds")
    assert len(await env.store.page(scope, flt, 50, None)) == 1


async def test_the_index_table_is_tenant_scoped_and_insert_only(env):
    await env.store.append_many([make_record(ACME, fired_entries=[fired("t__a", "tenant", 0.9)])])
    assert await env.app.fetchval("SELECT count(*) FROM decision_record_rules") == 0  # no setting
    for statement in (
        "DELETE FROM decision_record_rules",
        "UPDATE decision_record_rules SET rule = 'x'",
        "TRUNCATE decision_record_rules",
    ):
        with pytest.raises(DENIED):
            await env.app.execute(statement)


async def test_a_rule_and_the_other_filters_together_walk_the_rules_index(env):
    hit = fired("t__a", "tenant", 0.9)
    await env.store.append_many(
        [
            make_record(ACME, NOW - timedelta(minutes=i), guard_point=gp, decision=dec,
                        fired_entries=[hit], request_id=f"r{i}")
            for i, (gp, dec) in enumerate(
                [("input", Decision.BLOCK), ("output", Decision.ALLOW), ("input", Decision.ALLOW),
                 ("input", Decision.BLOCK), ("output", Decision.BLOCK)]
            )
        ]
    )  # fmt: skip
    scope = issue_scope(ACME)

    async def ids(after=None, limit=50, **kw):
        flt = DecisionFilter(NOW - timedelta(days=1), NOW + timedelta(days=1), rule="t__a", **kw)
        rows = await env.store.page(scope, flt, limit, after)
        return [d.record["request_id"] for d in rows], rows

    assert (await ids())[0] == ["r0", "r1", "r2", "r3", "r4"]
    assert (await ids(guard_point="input"))[0] == ["r0", "r2", "r3"]
    assert (await ids(guard_point="input", decision="block"))[0] == ["r0", "r3"]
    first, rows = await ids(limit=2)
    second, _ = await ids(after=Position(rows[-1].ts, rows[-1].id), limit=2)
    assert first + second == ["r0", "r1", "r2", "r3"]


# ------------------------------------------------------------------ the p95 benchmark (slow)

BENCH_ROWS = int(os.environ.get("M407_BENCH_ROWS", "300000"))
"""Records of the large tenant over the 30 days. The default is what the local test database
(about 900 MB of tmpfs) holds; set ``M407_BENCH_ROWS`` for more on a bigger one."""
BENCH_NOISE = BENCH_ROWS // 4
"""Records of ten other tenants, in the same table and the same indexes."""

_SEED = """
INSERT INTO decision_records
    (tenant_id, request_id, guard_point, ts, retain_until, record, decision, fired_rules,
     latency_ms, input_tokens, bundle_version)
SELECT
    $1,
    md5($1 || g::text),
    gp,
    ts,
    ts + interval '395 days',
    jsonb_build_object(
        'request_id', md5($1 || g::text), 'tenant_id', $1, 'ts', ts, 'guard_point', gp,
        'decision', dec, 'reason', 'policy', 'retryable', false, 'detail', null,
        'bundle_version', 1 + g % 3, 'candidate_version', null, 'candidate_decision', null,
        'model_called', true, 'failure_kind', null, 'latency_ms', 40 + g % 50,
        'content_sha256', 'sha256:' || md5(g::text) || md5(g::text),
        'retain_until', ts + interval '395 days', 'deterministic', '[]'::jsonb,
        'fired', CASE WHEN dec = 'allow' THEN '[]'::jsonb ELSE jsonb_build_array(jsonb_build_object(
            'rule', fr, 'p', 0.9, 'block_at', 0.8, 'escalate_at', 0.5, 'mode', 'enforce',
            'action', dec, 'provisional', false, 'layer', 'tenant', 'basis', 'answer')) END,
        'rules', jsonb_build_array(
            jsonb_build_object('key', 't__refunds', 'layer', 'tenant', 'mode', 'enforce',
                'action', dec, 'basis', 'answer', 'provisional', false, 'p', 0.4,
                'block_at', 0.8, 'escalate_at', 0.5),
            jsonb_build_object('key', 't__pii', 'layer', 'tenant', 'mode', 'shadow',
                'action', 'allow', 'basis', 'answer', 'provisional', false, 'p', 0.1,
                'block_at', 0.8, 'escalate_at', 0.5),
            jsonb_build_object('key', 'p__inj_direct', 'layer', 'floor', 'mode', 'enforce',
                'action', 'allow', 'basis', 'answer', 'provisional', false, 'p', 0.02,
                'block_at', 0.55, 'escalate_at', 0.3))
    )::text,
    dec,
    CASE WHEN dec = 'allow' THEN '{}'::text[] ELSE ARRAY[fr] END,
    40 + (g % 50) + (g % 7) * 0.5, 600 + g % 400, 1 + g % 3
FROM (
    SELECT g,
           $2::timestamptz - (g::double precision / $3) * interval '30 days' AS ts,
           (ARRAY['input', 'plan', 'tool_call', 'tool_result', 'output'])[1 + g % 5] AS gp,
           CASE WHEN g % 100 < 90 THEN 'allow' WHEN g % 100 < 98 THEN 'block' ELSE 'escalate' END
               AS dec,
           CASE WHEN g % 1000 = 8 THEN 't__rare' WHEN g % 2 = 0 THEN 't__refunds'
                ELSE 't__other' END AS fr
    FROM generate_series(1, $3) g
) s
"""


async def _seed(env, tenant, rows, now):
    async with env.app.acquire() as conn, conn.transaction():
        await conn.execute("SELECT set_config('app.tenant_id', $1, true)", tenant)
        await conn.execute(_SEED, tenant, now, rows)
        await conn.execute(
            "INSERT INTO decision_record_rules "
            "(record_id, tenant_id, rule, ts, action, layer, mode) "
            "SELECT id, tenant_id, unnest(fired_rules), ts, decision, 'tenant', 'enforce' "
            "FROM decision_records "
            "WHERE tenant_id = $1 AND cardinality(fired_rules) > 0",
            tenant,
        )


@pytest.mark.slow
async def test_the_audit_query_p95_is_within_two_seconds_on_30_days_of_a_large_tenant(env):
    """AC (M4-07): p95 <= 2 s over a seeded 30-day data set. Volume: ``BENCH_ROWS`` records for
    one tenant spread evenly over 30 days (10,000 a day by default, 90% allow, 8% block, 2%
    escalate, five guard points, three rules a record) and a quarter as many for ten other
    tenants in the same table. Each query goes through the audit service as the auditor would
    call it: the page's records read back and presented. 200 queries of seven kinds, with
    varying windows, deep cursors included."""
    import random
    import statistics
    import time

    from guardrail_engine.admin.decisions import DECISIONS_ENDPOINT, DecisionsService
    from guardrail_engine.authz import ENDPOINTS
    from guardrail_engine.authz.authorizer import AuthzDecision

    now = datetime.now(UTC).replace(microsecond=0)
    await _seed(env, ACME, BENCH_ROWS, now)
    for i in range(10):
        await _seed(env, f"t_noise{i}", BENCH_NOISE // 10, now)
    await env.owner.execute("ANALYZE decision_records")
    total = await env.owner.fetchval("SELECT count(*) FROM decision_records")

    class NoDerived:
        async def keys(self, scope, version):
            return frozenset()

    service = DecisionsService(env.store, NoDerived())
    endpoint = next(e for e in ENDPOINTS if (e.method, e.route) == DECISIONS_ENDPOINT)
    decision = AuthzDecision(True, 200, "ok", endpoint=endpoint, scope=issue_scope(ACME))

    def iso(t):
        return t.isoformat().replace("+00:00", "Z")

    rng = random.Random(407)
    kinds = {
        "latest": lambda: {"limit": "50"},
        "decision=block": lambda: {"decision": "block", "limit": "100"},
        "guard_point": lambda: {"guard_point": "tool_call", "limit": "100"},
        "rule (common)": lambda: {"rule": "t__refunds", "limit": "50"},
        "rule (rare)": lambda: {"rule": "t__rare", "limit": "50"},
        "rule (none)": lambda: {"rule": "t__typo", "limit": "50"},
        "rule + decision": lambda: {"rule": "t__other", "decision": "block", "limit": "50"},
        "week window": lambda: {
            "from": iso(now - timedelta(days=rng.randint(8, 30))),
            "to": iso(now - timedelta(days=rng.randint(1, 7))),
            "decision": "escalate",
            "guard_point": "output",
            "limit": "200",
        },
        "deep cursor": None,
    }
    timings: dict[str, list[float]] = {k: [] for k in kinds}

    async def timed(kind, params):
        started = time.perf_counter()
        body = await service.query(decision, {"from": iso(now - timedelta(days=30)), **params})
        timings[kind].append(time.perf_counter() - started)
        return body

    for _ in range(200 // len(kinds) + 1):
        for kind, make in kinds.items():
            if make is not None:
                await timed(kind, make())
                continue
            # walk to a deep page: ten pages down, then time the eleventh
            cursor = None
            for _ in range(10):
                body = await service.query(
                    decision,
                    {"from": iso(now - timedelta(days=30)), "limit": "200"}
                    | ({"cursor": cursor} if cursor else {}),
                )
                cursor = body["next_cursor"]
            await timed(kind, {"limit": "200", "cursor": cursor})

    every = sorted(t for ts in timings.values() for t in ts)
    p95 = every[int(len(every) * 0.95) - 1]
    for kind, ts in timings.items():
        ts.sort()
        print(
            f"{kind:16s} n={len(ts):3d} median={statistics.median(ts) * 1000:7.1f} ms "
            f"p95={ts[max(0, int(len(ts) * 0.95) - 1)] * 1000:7.1f} ms max={ts[-1] * 1000:7.1f} ms"
        )
    print(f"records in table={total}  tenant records={BENCH_ROWS}  queries={len(every)}  "
          f"overall p95={p95 * 1000:.1f} ms")  # fmt: skip
    assert p95 <= 2.0


# ------------------------------------------------------------------ M4-06 metrics sources


async def test_the_metrics_aggregates_on_postgres_equal_the_in_memory_ones(env):
    from guardrail_engine.audit.store import InMemoryDecisionRecords
    from guardrail_engine.metrics.adapters.postgres import PostgresRecordMetrics
    from guardrail_engine.metrics.model import Window
    from guardrail_engine.metrics.store import InMemoryRecordMetrics

    def one(i):
        entries = []
        if i % 3 == 0:
            entries.append(fired("t__refunds", "tenant", 0.9))
        if i % 4 == 0:
            entries.append(fired("p__inj_direct", "floor", 0.97, action="escalate"))
        if i % 5 == 0:  # a rule listed twice: the most severe action counts, once
            entries += [
                fired("t__dup", "tenant", 0.7, action="escalate"),
                fired("t__dup", "tenant", 0.9),
            ]
        record = make_record(
            ACME, NOW - timedelta(minutes=i * 7), guard_point=("input", "output", "plan")[i % 3],
            decision=(Decision.BLOCK, Decision.ALLOW, Decision.ESCALATE)[i % 3],
            fired_entries=entries, bundle_version=1 + i % 2,
        )  # fmt: skip
        return record.model_copy(update={"latency_ms": 5.0 + i * 1.7, "input_tokens": 100 + i})

    records = [one(i) for i in range(60)] + [make_record(OTHER, NOW)]
    await env.store.append_many(records)
    mem = InMemoryDecisionRecords()
    await mem.append_many(records)
    window = Window(NOW - timedelta(days=2), NOW + timedelta(hours=1))
    for guard_point in (None, "output"):
        w = Window(window.start, window.end, guard_point)
        scope = issue_scope(ACME)
        pg = await PostgresRecordMetrics(env.app, env.operator).aggregate(scope, w)
        want = await InMemoryRecordMetrics(mem).aggregate(scope, w)
        assert pg.checks == want.checks and dict(pg.by_decision) == dict(want.by_decision)
        assert pg.bundle_versions == want.bundle_versions and not pg.unknown_version
        assert sorted(pg.rules, key=lambda r: (r.rule, r.action)) == sorted(
            want.rules, key=lambda r: (r.rule, r.action)
        )
        for a, b in zip(pg.guard_points, want.guard_points, strict=True):
            assert (a.guard_point, a.checks, a.record_tokens) == (
                b.guard_point,
                b.checks,
                b.record_tokens,
            )
            assert a.latency.p95 == pytest.approx(b.latency.p95, rel=1e-4)  # real vs float
        assert pg.latency.p50 == pytest.approx(want.latency.p50, rel=1e-4)
        assert pg.latency.p99 == pytest.approx(want.latency.p99, rel=1e-4)


async def test_the_usage_events_are_tenant_scoped(env):
    from guardrail_engine.metrics.adapters.postgres import PostgresUsageMetrics
    from guardrail_engine.metrics.model import Window

    async def put(tenant, key, tokens):
        async with env.app.acquire() as conn, conn.transaction():
            await conn.execute("SELECT set_config('app.tenant_id', $1, true)", tenant)
            await conn.execute(
                "INSERT INTO usage_events (idempotency_key, kind, tenant_id, guard_point, "
                "input_tokens, occurred_at) VALUES ($1, 'answered', $2, 'output', $3, $4)",
                key, tenant, tokens, NOW,
            )  # fmt: skip

    await put(ACME, "k1", 100)
    await put(ACME, "k2", 250)
    await put(OTHER, "k3", 9999)
    window = Window(NOW - timedelta(hours=1), NOW + timedelta(hours=1))
    metrics = PostgresUsageMetrics(env.app, env.operator)
    (acme,) = await metrics.totals(issue_scope(ACME), window)
    assert (acme.guard_point, acme.kind, acme.events, acme.tokens) == ("output", "answered", 2, 350)
    (other,) = await metrics.totals(issue_scope(OTHER), window)
    assert other.tokens == 9999
    assert await env.app.fetchval("SELECT count(*) FROM usage_events") == 0  # no setting
    (op,) = await metrics.totals(issue_scope(OTHER, operator=True), window)
    assert op.tokens == 9999  # an operator names a tenant and still gets only that one
    with pytest.raises(asyncpg.exceptions.InsufficientPrivilegeError):
        await env.app.execute(
            "INSERT INTO usage_events (idempotency_key, kind, tenant_id, guard_point, "
            "input_tokens, occurred_at) VALUES ('k5', 'answered', 't_acmeins', 'output', 1, now())"
        )  # no tenant setting: refused


@pytest.mark.slow
async def test_the_metrics_query_over_30_days_of_a_large_tenant_is_within_two_seconds(env):
    """AC (M4-06): the metrics report over the same seeded 30 days (see the audit benchmark for
    the volume): a 30-day window and a 24-hour one, with and without a guard point, each run
    20 times through the metrics service; the slowest run and the p95 must be within 2 s."""
    import time

    from guardrail_engine.admin.decisions import DerivedKeys  # noqa: F401
    from guardrail_engine.admin.metrics import METRICS_ENDPOINT, MetricsService
    from guardrail_engine.authz import ENDPOINTS
    from guardrail_engine.authz.authorizer import AuthzDecision
    from guardrail_engine.metrics.adapters.postgres import (
        PostgresRecordMetrics,
        PostgresUsageMetrics,
    )

    now = datetime.now(UTC).replace(microsecond=0)
    await _seed(env, ACME, BENCH_ROWS, now)
    await _seed(env, "t_noise0", BENCH_NOISE, now)
    async with env.app.acquire() as conn, conn.transaction():
        await conn.execute("SELECT set_config('app.tenant_id', $1, true)", ACME)
        await conn.execute(
            "INSERT INTO usage_events (idempotency_key, kind, tenant_id, guard_point, "
            "input_tokens, occurred_at) SELECT 'u' || g, 'answered', $1, "
            "(ARRAY['input','plan','tool_call','tool_result','output'])[1 + g % 5], 600 + g % 400, "
            "$2::timestamptz - (g::double precision / $3) * interval '30 days' "
            "FROM generate_series(1, $3) g",
            ACME, now, BENCH_ROWS,
        )  # fmt: skip
    await env.owner.execute("ANALYZE decision_records")

    class AllVersions:
        async def keys(self, scope, version):
            return frozenset()

    service = MetricsService(
        PostgresRecordMetrics(env.app, env.operator),
        PostgresUsageMetrics(env.app, env.operator),
        AllVersions(),
        price_per_million_usd=0.10,
        price_source="bench",
    )
    endpoint = next(e for e in ENDPOINTS if (e.method, e.route) == METRICS_ENDPOINT)
    decision = AuthzDecision(True, 200, "ok", endpoint=endpoint, scope=issue_scope(ACME))

    def iso(t):
        return t.isoformat().replace("+00:00", "Z")

    kinds = {
        "30 days": {"from": iso(now - timedelta(days=30)), "to": iso(now + timedelta(hours=1))},
        "30 days, one guard point": {
            "from": iso(now - timedelta(days=30)), "to": iso(now + timedelta(hours=1)),
            "guard_point": "tool_call",
        },
        "24 hours": {"from": iso(now - timedelta(days=1)), "to": iso(now + timedelta(hours=1))},
    }  # fmt: skip
    times = []
    for kind, params in kinds.items():
        runs = []
        for _ in range(20):
            started = time.perf_counter()
            body = await service.report(decision, params)
            runs.append(time.perf_counter() - started)
        times += runs
        runs.sort()
        print(f"{kind:26s} median={runs[10] * 1000:7.1f} ms max={runs[-1] * 1000:7.1f} ms "
              f"checks={body['checks']['total']}")  # fmt: skip
    times.sort()
    assert times[int(len(times) * 0.95) - 1] <= 2.0 and times[-1] <= 4.0


async def test_a_connection_that_comes_with_a_tenant_setting_is_refused_for_a_write(env):
    """The writer's own connection helper keeps the leak check of ``tenant_connection``: a pooled
    connection that still carries another tenant's setting is not written under."""
    from guardrail_engine.audit.adapters.postgres import record_connection
    from guardrail_engine.store.port import TenantSettingLeakError

    async def leave_a_setting(conn):  # what a custom reset or a session pooler could do
        await conn.execute("SELECT set_config('app.tenant_id', 't_leaked', false)")

    dsn = os.environ["GUARDRAIL_TEST_PG_DSN"]
    pool = await asyncpg.create_pool(
        dsn, min_size=1, max_size=1, setup=leave_a_setting,
        server_settings={"search_path": env.schema},
    )  # fmt: skip
    try:
        with pytest.raises(TenantSettingLeakError):
            async with record_connection(pool, ACME):
                pytest.fail("a write was allowed under a leaked setting")
        with pytest.raises(TenantSettingLeakError):
            await PostgresDecisionStore(pool).append_many([make_record(ACME)])
    finally:
        await pool.close()
