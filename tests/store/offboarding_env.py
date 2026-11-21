"""Two environments for the M5-07 offboarding tests: the in-memory one (the in-memory directory
and a counting data holder) and the Postgres one (the real schema under a **non-superuser
owner**, so forced row-level security really applies, with the offboarding job connected as the
retention role). Both offer the same calls, so the behaviour tests run against each.

The clock: the provisioner's clock is ``env.now`` (a float read at each directory write) and the
job's clock is whatever the test passes. ``T0`` is in the past, so the database's bound on the job's
clock (never ahead of the database) is met even 31 days later.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta

import asyncpg
import pytest

from guardrail_engine.authz import Principal
from guardrail_engine.delivery.events import UsageEvent
from guardrail_engine.directory import InMemoryDirectoryStore, InMemoryEventBus, TenantProvisioner
from guardrail_engine.offboarding import InMemoryOffboardingStore
from guardrail_engine.offboarding.adapters.postgres import PostgresOffboardingStore
from guardrail_engine.offboarding.model import OFFBOARD_TABLES

T0 = datetime(2026, 1, 5, 12, 0, 0, tzinfo=UTC)
DAY = timedelta(days=1)
OPS = Principal("ops-1", None, frozenset(), True)
ALL_TABLES = tuple(t.name for t in OFFBOARD_TABLES)

SEEDED_USAGE = (
    ("answered", 5, datetime(2026, 1, 31, 23, 30, tzinfo=UTC)),
    ("answered", 7, datetime(2026, 2, 1, 0, 30, tzinfo=UTC)),
)
"""The two usage rows ``seed`` leaves: (kind, input tokens, occurred_at), an hour apart, across a
UTC month boundary."""


def expected(records: int = 3) -> dict[str, int]:
    """The rows ``seed`` leaves per table (the escalation items' content count is separate)."""
    return {
        "decision_record_rules": records,
        "decision_records": records,
        "usage_events": 2,
        "tenant_shadow_agreement": 2,
        "delivery_outbox": 2,
        "escalation_items": 3,
        "stored_content": 2,
        "nightly_redteam_results": 2,
        "tenant_golden_examples": 4,
        "tenant_golden_sets": 2,
        "tenant_calibration_scores": 2,
        "tenant_calibration_outcomes": 2,
        "tenant_calibration_targets": 1,
        "tenant_drafts": 1,
        "tenant_candidates": 1,
        "tenant_tools": 2,
    }


HELD_CONTENT = 2
"""Of the three escalation items, two hold stored content (class C)."""


def by_class(records: int = 3) -> dict[str, int]:
    e = expected(records)
    out = {c: sum(e[t.name] for t in OFFBOARD_TABLES if t.data_class == c) for c in "BDEGW"}
    # class C: the stored-content rows (M5-03) and the escalation items that hold content
    out["C"] = HELD_CONTENT + e["stored_content"]
    return out


class _Clock:
    def __init__(self) -> None:
        self.now = T0


async def _no_sleep(_: float) -> None:
    return None


class BaseEnv:
    kind: str
    clock: _Clock
    prov: TenantProvisioner
    off: object

    async def new_tenant(self, slug: str) -> str:
        record = await self.prov.create(OPS, slug=slug, domain="insurance")
        return record.tenant_id

    async def terminate(self, tenant_id: str, reason: str = "contract ended") -> None:
        await self.prov.terminate(OPS, tenant_id, reason)

    def at(self, days: float = 0, seconds: float = 0) -> datetime:
        return T0 + timedelta(days=days, seconds=seconds)


# ------------------------------------------------------------------------------------ in memory


class CountingHolder:
    """A stand-in for every deletable table: ``rows[table][tenant]`` is a row count."""

    offboard_tables = ALL_TABLES

    def __init__(self) -> None:
        self.rows: dict[str, dict[str, int]] = {t: {} for t in ALL_TABLES}
        self.held: dict[str, int] = {}
        self.usage: dict[str, list[UsageEvent]] = {}

    def offboard_usage_rows(self, tenant_id: str, limit: int) -> list[UsageEvent]:
        rows = self.usage.get(tenant_id, [])
        gone, self.usage[tenant_id] = rows[:limit], rows[limit:]
        return gone

    def offboard_tenant(
        self, tenant_id: str, table: str, limit: int, *, count_only: bool = False
    ) -> Mapping[str, int]:
        if table == "usage_events":
            rows = self.usage.get(tenant_id, [])
            return {
                table: len(rows) if count_only else len(self.offboard_usage_rows(tenant_id, limit))
            }
        have = self.rows[table].get(tenant_id, 0)
        n = have if count_only else min(have, limit)
        out = {table: n}
        if not count_only:
            self.rows[table][tenant_id] = have - n
        if table == "escalation_items":
            held = self.held.get(tenant_id, 0)
            # the items that go first hold the content (the order is the seed's)
            gone_held = min(held, n)
            if not count_only:
                self.held[tenant_id] = held - gone_held
            out["escalation_items.content"] = gone_held
        return out


class MemoryEnv(BaseEnv):
    kind = "memory"

    def __init__(self) -> None:
        self.clock = _Clock()
        self.directory = InMemoryDirectoryStore()
        self.bus = InMemoryEventBus()
        self.prov = TenantProvisioner(
            self.directory,
            self.bus,
            clock=lambda: self.clock.now.timestamp(),
            drain_s=0,
            sleep=_no_sleep,
        )
        self.holder = CountingHolder()
        self.off = InMemoryOffboardingStore(self.directory, [self.holder])

    async def seed(self, tenant_id: str, records: int = 3) -> None:
        for table, n in expected(records).items():
            self.holder.rows[table][tenant_id] = n
        self.holder.held[tenant_id] = HELD_CONTENT
        await self.add_usage(tenant_id, list(SEEDED_USAGE))

    async def add_usage(self, tenant_id: str, rows) -> None:
        events = self.holder.usage.setdefault(tenant_id, [])
        for kind, tokens, at in rows:
            events.append(UsageEvent(kind, tenant_id, "output", tokens, at.timestamp()))

    async def counts(self, tenant_id: str) -> dict[str, int]:
        out = {t: self.holder.rows[t].get(tenant_id, 0) for t in ALL_TABLES}
        out["usage_events"] = len(self.holder.usage.get(tenant_id, []))
        return out

    async def class_a(self, tenant_id: str) -> dict[str, int]:
        events = await self.directory.audit_events(tenant_id)
        return {"tenant_directory_audit": len(events)}


# ------------------------------------------------------------------------------------ postgres

HASH = "sha256:" + "a" * 64


class PgEnv(BaseEnv):
    kind = "postgres"

    async def seed(self, tenant_id: str, records: int = 3) -> None:
        t = tenant_id
        async with self.owner.acquire() as conn, conn.transaction():
            await conn.execute("SELECT set_config('app.tenant_id', $1, true)", t)
            for kind, tokens, at in SEEDED_USAGE:
                await conn.execute(
                    "INSERT INTO usage_events (idempotency_key, kind, tenant_id, guard_point, "
                    "input_tokens, occurred_at) VALUES ($1, $2, $3, 'output', $4, $5)",
                    uuid.uuid4().hex,
                    kind,
                    t,
                    tokens,
                    at,
                )
            for i in range(records):
                rid = await conn.fetchval(
                    "INSERT INTO decision_records (tenant_id, request_id, guard_point, ts, "
                    "retain_until, record) VALUES ($1, $2, 'output', now(), now(), '{}') "
                    "RETURNING id",
                    t,
                    f"r{i}",
                )
                await conn.execute(
                    "INSERT INTO decision_record_rules (record_id, tenant_id, rule, ts) "
                    "VALUES ($1, $2, 'rule_a', now())",
                    rid,
                    t,
                )
            for i in range(2):
                await conn.execute(
                    "INSERT INTO tenant_shadow_agreement (tenant_id, active_version, "
                    "candidate_version, rule_key) VALUES ($1, 1, $2, 'rule_a')",
                    t,
                    i + 2,
                )
                await conn.execute(
                    "INSERT INTO delivery_outbox (idempotency_key, kind, payload, created_at, "
                    "next_attempt_at) VALUES ($1, 'usage', $2, now(), now())",
                    f"{t}-o{i}",
                    f'{{"at":1.0,"guard_point":"output","kind":"answered","tenant_id":"{t}"}}',
                )
            for i in range(3):
                held = i < HELD_CONTENT
                await conn.execute(
                    "INSERT INTO escalation_items (tenant_id, id, request_id, guard_point, "
                    "created_at, target, reason, store_content, content) "
                    "VALUES ($1, $2, $3, 'output', now(), 'queue', 'rule', $4, $5)",
                    t,
                    f"esc_{i:024x}",
                    f"req{i}",
                    "full" if held else "hash_only",
                    "held text" if held else None,
                )
            for i in range(2):  # class C (M5-03): stored content
                await conn.execute(
                    "INSERT INTO stored_content (tenant_id, request_id, guard_point, ts, "
                    "retain_until, content, content_sha256) "
                    "VALUES ($1, $2, 'output', now(), now() + interval '30 days', 'kept', $3)",
                    t,
                    f"sc{i}",
                    HASH,
                )
            for i in range(2):  # class B (M5-05): the nightly red-team's results
                await conn.execute(
                    "INSERT INTO nightly_redteam_results (tenant_id, bundle_version, config_key, "
                    "run_id, run_at, mode, floor_version, corpus_sha256, draws, rows, status) "
                    "VALUES ($1, 1, 'platform/floor@2', $2, now(), 'fake', 2, $3, 3, 172, 'pass')",
                    t,
                    f"run{i}",
                    HASH,
                )
            for s in range(2):
                sid = f"gs_{s:016x}"
                await conn.execute(
                    "INSERT INTO tenant_golden_sets (tenant_id, set_id, name, set_hash, "
                    "created_at, created_by, counts) VALUES ($1, $2, $3, $4, now(), 'a#b', '{}')",
                    t,
                    sid,
                    f"set {s}",
                    HASH,
                )
                for p in range(2):
                    await conn.execute(
                        "INSERT INTO tenant_golden_examples (tenant_id, set_id, position, "
                        "example_id, guard_point, label, content) "
                        "VALUES ($1, $2, $3, $4, 'output', 'allow', 'labelled text')",
                        t,
                        sid,
                        p,
                        f"e{p}",
                    )
            for i in range(2):
                await conn.execute(
                    "INSERT INTO tenant_calibration_scores (tenant_id, scoring, guard_point, "
                    "content_hash, scores) VALUES ($1, $2, 'output', $3, '{}')",
                    t,
                    HASH,
                    "sha256:" + f"{i:064x}",
                )
                await conn.execute(
                    "INSERT INTO tenant_calibration_outcomes (tenant_id, scoring, guard_point, "
                    "content_hash, attempt, cause) VALUES ($1, $2, 'output', $3, 1, 'failed')",
                    t,
                    HASH,
                    "sha256:" + f"{i:064x}",
                )
                await conn.execute(
                    "INSERT INTO tenant_tools (tenant_id, name, description, read_only, status, "
                    "description_hash, submitted_by, submitted_at, version) "
                    "VALUES ($1, $2, 'a tool', true, 'accepted', $3, 'a#b', now(), 1)",
                    t,
                    f"tool_{i}",
                    HASH,
                )
            await conn.execute(
                "INSERT INTO tenant_calibration_targets (tenant_id, block_precision, "
                "escalate_recall, updated_at, updated_by) VALUES ($1, 0.9, 0.9, now(), 'a#b')",
                t,
            )
            await conn.execute(
                "INSERT INTO tenant_drafts (tenant_id, document, etag, updated_by) "
                "VALUES ($1, '{}', $2, 'a#b')",
                t,
                f'"{HASH}"',
            )
            await conn.execute(
                "INSERT INTO policy_bundle_versions (tenant_id, version, document, bundle_hash) "
                "VALUES ($1, 1, $2, $3) ON CONFLICT DO NOTHING",
                t,
                f'{{"tenant_id":"{t}","version":1}}',
                HASH,
            )
            await conn.execute(
                "INSERT INTO tenant_candidates (tenant_id, version, mode, rollout_percent, at, "
                "actor) VALUES ($1, 1, 'shadow', 10, now(), 'a#b')",
                t,
            )
            # Class A, which stays.
            await conn.execute(
                "INSERT INTO tenant_draft_audit (tenant_id, at, actor, cross_tenant, operator, "
                "action, resulting_hash, diff) VALUES ($1, now(), 'a#b', false, false, "
                "'draft.put', $2, '[]')",
                t,
                HASH,
            )
            await conn.execute(
                "INSERT INTO tenant_publish_audit (tenant_id, at, actor, cross_tenant, operator, "
                "action, version) VALUES ($1, now(), 'a#b', false, false, 'publish', 1)",
                t,
            )
            await conn.execute(
                "INSERT INTO tenant_tool_audit (tenant_id, at, actor, cross_tenant, operator, "
                "action, name) VALUES ($1, now(), 'a#b', false, false, 'put', 'tool_0')",
                t,
            )
            await conn.execute(
                "INSERT INTO tenant_golden_audit (tenant_id, at, actor, cross_tenant, operator, "
                "set_id, set_hash, examples) VALUES ($1, now(), 'a#b', false, false, $2, $3, 2)",
                t,
                "gs_" + "0" * 16,
                HASH,
            )
            await conn.execute(
                "INSERT INTO tenant_calibration_audit (tenant_id, at, actor, kind, cross_tenant, "
                "operator, detail) VALUES ($1, now(), 'a#b', 'targets', false, false, '{}')",
                t,
            )
            await conn.execute(
                "INSERT INTO escalation_audit (tenant_id, at, item_id, action, actor, "
                "cross_tenant, operator) VALUES ($1, now(), $2, 'resolved', 'a#b', false, false)",
                t,
                "esc_" + "0" * 24,
            )
            await conn.execute(
                "INSERT INTO tenant_approvals (tenant_id, id, action, draft_hash, requested_by, "
                "requested_at, expires_at) VALUES ($1, $2, 'publish', $3, 'a#b', now(), "
                "now() + interval '1 day') ON CONFLICT DO NOTHING",
                t,
                "apr_" + "0" * 24,
                HASH,
            )
            await conn.execute(
                "INSERT INTO tenant_approval_audit (tenant_id, at, action, actor, cross_tenant, "
                "operator) VALUES ($1, now(), 'requested', 'a#b', false, false)",
                t,
            )

    async def add_usage(self, tenant_id: str, rows) -> None:
        async with self.owner.acquire() as conn, conn.transaction():
            await conn.execute("SELECT set_config('app.tenant_id', $1, true)", tenant_id)
            for kind, tokens, at in rows:
                await conn.execute(
                    "INSERT INTO usage_events (idempotency_key, kind, tenant_id, guard_point, "
                    "input_tokens, occurred_at) VALUES ($1, $2, $3, 'output', $4, $5)",
                    uuid.uuid4().hex,
                    kind,
                    tenant_id,
                    tokens,
                    at,
                )

    async def _count(self, conn, table: str, tenant_id: str) -> int:
        if table == "delivery_outbox":
            return int(
                await conn.fetchval(
                    "SELECT count(*) FROM delivery_outbox "
                    "WHERE kind IN ('usage', 'escalation') "
                    "AND position('\"tenant_id\":\"' || $1 || '\"' IN payload) > 0",
                    tenant_id,
                )
            )
        return int(
            await conn.fetchval(f"SELECT count(*) FROM {table} WHERE tenant_id = $1", tenant_id)
        )

    async def counts(self, tenant_id: str) -> dict[str, int]:
        async with self.owner.acquire() as conn, conn.transaction():
            await conn.execute("SELECT set_config('app.tenant_id', $1, true)", tenant_id)
            return {t: await self._count(conn, t, tenant_id) for t in ALL_TABLES}

    CLASS_A = (
        "tenant_directory_audit",
        "policy_bundle_versions",
        "tenant_draft_audit",
        "tenant_publish_audit",
        "tenant_tool_audit",
        "tenant_golden_audit",
        "tenant_calibration_audit",
        "escalation_audit",
        "tenant_approvals",
        "tenant_approval_audit",
        "tenants",
    )

    async def class_a(self, tenant_id: str) -> dict[str, int]:
        async with self.owner.acquire() as conn, conn.transaction():
            await conn.execute("SELECT set_config('app.tenant_id', $1, true)", tenant_id)
            return {t: await self._count(conn, t, tenant_id) for t in self.CLASS_A}


async def _login_role(admin, prefix):
    role = f"{prefix}_{uuid.uuid4().hex[:10]}"
    password = uuid.uuid4().hex
    await admin.execute(f"CREATE ROLE \"{role}\" LOGIN PASSWORD '{password}'")
    return role, password


async def make_pg_env():
    """Yields ``(env, cleanup)`` for the Postgres environment, or skips without a database."""
    from guardrail_engine.store.adapters.postgres import (
        PostgresDirectoryStore,
        apply_app_role_grants,
        apply_retention_role_grants,
        apply_schema,
    )

    dsn = os.environ.get("GUARDRAIL_TEST_PG_DSN")
    if not dsn:
        pytest.skip("GUARDRAIL_TEST_PG_DSN is not set; Postgres tests need a database")
    env = PgEnv()
    env.kind = "postgres"
    env.schema = schema = f"m507_{uuid.uuid4().hex[:16]}"
    env.dsn = dsn
    admin = await asyncpg.connect(dsn)
    env.admin = admin  # a superuser
    roles: list[str] = []
    pools: list = []
    owner, owner_pw = await _login_role(admin, "m507_owner")
    roles.append(owner)
    await admin.execute(f'CREATE SCHEMA "{schema}" AUTHORIZATION "{owner}"')

    async def pool_for(role, password, size=6):
        p = await asyncpg.create_pool(
            dsn, user=role, password=password, min_size=1, max_size=size,
            server_settings={"search_path": schema},
        )  # fmt: skip
        pools.append(p)
        return p

    async def cleanup():
        for p in pools:
            await p.close()
        await admin.execute(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
        for role in roles:
            await admin.execute(f'DROP OWNED BY "{role}"')
            await admin.execute(f'DROP ROLE "{role}"')
        await admin.close()

    try:
        env.owner = await pool_for(owner, owner_pw)
        await apply_schema(env.owner)  # as a role that is NOT a superuser
        app, app_pw = await _login_role(admin, "m507_app")
        ret, ret_pw = await _login_role(admin, "m507_ret")
        roles += [app, ret]
        for role in (app, ret):
            await env.owner.execute(f'GRANT USAGE ON SCHEMA "{schema}" TO "{role}"')
        await apply_app_role_grants(env.owner, app)
        await apply_retention_role_grants(env.owner, ret)
        env.app_role, env.ret_role = app, ret
        env.app = await pool_for(app, app_pw)
        env.retention_pool = await pool_for(ret, ret_pw, size=12)
        env.owner_superuser = await env.owner.fetchval(
            "SELECT rolsuper FROM pg_roles WHERE rolname = current_user"
        )
        env.clock = _Clock()
        env.bus = InMemoryEventBus()
        env.directory = PostgresDirectoryStore(env.owner)
        env.prov = TenantProvisioner(
            env.directory,
            env.bus,
            clock=lambda: env.clock.now.timestamp(),
            drain_s=0,
            sleep=_no_sleep,
        )
        env.off = PostgresOffboardingStore(env.retention_pool)
    except BaseException:
        await cleanup()
        raise
    return env, cleanup
