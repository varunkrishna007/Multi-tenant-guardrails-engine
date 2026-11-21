"""M4-01 calibration storage (020, 021): the contract on both stores (memory and Postgres), and
on Postgres: isolation by forced row-level security, insert-only scores and audit, the exact
grants. Postgres needs GUARDRAIL_TEST_PG_DSN; skipped without it."""

import json
import sys
from datetime import UTC, datetime
from pathlib import Path

import asyncpg
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "admin"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "guard"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "policy"))

from store_harness import ACME, OTHER

from guardrail_engine.admin.calibration_store import (
    CalibrationAuditEvent,
    InMemoryCalibrationStore,
)
from guardrail_engine.admin.sweep import Targets
from guardrail_engine.store.adapters.postgres import PostgresCalibrationStore
from guardrail_engine.store.port import ScopeMismatchError
from guardrail_engine.tenant_scope import issue_scope

DENIED = (asyncpg.InsufficientPrivilegeError, asyncpg.exceptions.RestrictViolationError)
H1, H2, H3 = (f"sha256:{c * 64}" for c in "123")
SCORING = "sha256:" + "a" * 64


def event(tenant, kind="targets", **detail):
    return CalibrationAuditEvent(
        datetime.now(UTC), "https://i/#alice", tenant, kind, detail or {"x": 1}
    )


@pytest.fixture(params=["memory", "postgres"])
def calibration(request):
    if request.param == "memory":
        return InMemoryCalibrationStore()
    app_pool = request.getfixturevalue("app_pool")
    return PostgresCalibrationStore(app_pool)


def view(store, tenant=ACME):
    return store.scoped(issue_scope(tenant))


async def test_targets_are_none_until_set_then_replaced_and_audited_together(calibration):
    v = view(calibration)
    assert await v.get_targets(ACME) is None
    await v.set_targets(ACME, Targets(0.9, 0.8), event(ACME, before=None, after="a"))
    assert await v.get_targets(ACME) == Targets(0.9, 0.8)
    await v.set_targets(ACME, Targets(0.99, 0.5, 7.5), event(ACME, before="a", after="b"))
    assert await v.get_targets(ACME) == Targets(0.99, 0.5, 7.5)  # the regression tolerance too
    events = await v.audit_events(ACME)
    assert [e.detail["after"] for e in events] == ["a", "b"]
    assert all(e.kind == "targets" and e.actor == "https://i/#alice" for e in events)
    assert await view(calibration, OTHER).get_targets(OTHER) is None


async def test_scores_are_kept_per_key_and_the_first_one_stays(calibration):
    v = view(calibration)
    await v.put_scores(ACME, SCORING, "output", {H1: {"t__a": 0.7}, H2: {"t__a": 0.2}})
    await v.put_scores(ACME, SCORING, "output", {H1: {"t__a": 0.99}, H3: {"t__a": 0.5}})
    got = await v.get_scores(ACME, SCORING, "output", [H1, H2, H3, "sha256:" + "f" * 64])
    assert got == {H1: {"t__a": 0.7}, H2: {"t__a": 0.2}, H3: {"t__a": 0.5}}  # H1 unchanged
    assert await v.get_scores(ACME, SCORING, "input", [H1]) == {}  # another guard point
    assert await v.get_scores(ACME, "sha256:" + "b" * 64, "output", [H1]) == {}  # another identity
    assert await v.get_scores(ACME, SCORING, "output", []) == {}
    await v.put_scores(ACME, SCORING, "output", {})


async def test_outcomes_count_attempts_by_cause_and_are_capped(calibration):
    v = view(calibration)
    assert await v.get_outcomes(ACME, SCORING, "output", [H1]) == {}
    await v.put_outcomes(ACME, SCORING, "output", {H1: "failed", H2: "deterministic"})
    await v.put_outcomes(ACME, SCORING, "output", {H1: "refused"})
    await v.put_outcomes(ACME, SCORING, "output", {H1: "failed"})
    got = await v.get_outcomes(ACME, SCORING, "output", [H1, H2, H3])
    assert got == {H1: {"failed": 2, "refused": 1}, H2: {"deterministic": 1}}
    assert await v.get_outcomes(ACME, SCORING, "input", [H1]) == {}  # another guard point
    assert await v.get_outcomes(ACME, "sha256:" + "b" * 64, "output", [H1]) == {}  # identity
    for _ in range(30):
        await v.put_outcomes(ACME, SCORING, "output", {H3: "failed"})
    assert (await v.get_outcomes(ACME, SCORING, "output", [H3]))[H3] == {"failed": 20}
    assert await v.get_outcomes(ACME, SCORING, "output", []) == {}
    await v.put_outcomes(ACME, SCORING, "output", {})
    with pytest.raises((ValueError, asyncpg.PostgresError)):
        await v.put_outcomes(ACME, SCORING, "output", {H1: "nonsense"})
    with pytest.raises(ScopeMismatchError):
        await v.get_outcomes(OTHER, SCORING, "output", [H1])
    with pytest.raises(ScopeMismatchError):
        await v.put_outcomes(OTHER, SCORING, "output", {H1: "failed"})
    assert await view(calibration, OTHER).get_outcomes(OTHER, SCORING, "output", [H1]) == {}


async def test_the_audit_trail_records_events_in_order_with_their_actor(calibration):
    v = view(calibration)
    await v.record(ACME, event(ACME, "targets", rule="a", action="accept"))
    await v.record(ACME, event(ACME, "targets", rule="b", action="override"))
    got = await v.audit_events(ACME)
    assert [(e.kind, e.detail["rule"]) for e in got] == [("targets", "a"), ("targets", "b")]
    assert got[0].actor == "https://i/#alice" and got[0].cross_tenant is False


async def test_a_scope_cannot_read_or_write_another_tenants_calibration(calibration):
    v = view(calibration)
    with pytest.raises(ScopeMismatchError):
        await v.get_targets(OTHER)
    with pytest.raises(ScopeMismatchError):
        await v.set_targets(OTHER, Targets(), event(OTHER))
    with pytest.raises(ScopeMismatchError):
        await v.get_scores(OTHER, SCORING, "output", [H1])
    with pytest.raises(ScopeMismatchError):
        await v.put_scores(OTHER, SCORING, "output", {H1: {"t__a": 0.1}})
    with pytest.raises(ScopeMismatchError):
        await v.record(OTHER, event(OTHER))
    with pytest.raises(ScopeMismatchError):
        await v.audit_events(OTHER)
    with pytest.raises(ScopeMismatchError):
        await v.record(ACME, event(OTHER))  # an event for another tenant


async def test_one_tenants_scores_and_targets_are_invisible_to_another(calibration):
    await view(calibration).put_scores(ACME, SCORING, "output", {H1: {"t__a": 0.7}})
    await view(calibration).set_targets(ACME, Targets(0.9, 0.9), event(ACME))
    other = view(calibration, OTHER)
    assert await other.get_scores(OTHER, SCORING, "output", [H1]) == {}
    assert await other.get_targets(OTHER) is None and await other.audit_events(OTHER) == []


def test_a_scope_is_required():
    with pytest.raises(TypeError):
        InMemoryCalibrationStore().scoped(ACME)  # type: ignore[arg-type]


# ------------------------------------------------------------------ Postgres only


async def scoped_sql(pool, tenant, sql, *args):
    async with pool.acquire() as conn, conn.transaction():
        if tenant is not None:
            await conn.execute("SELECT set_config('app.tenant_id', $1, true)", tenant)
        return await conn.fetch(sql, *args)


@pytest.mark.parametrize(
    "table",
    [
        "tenant_calibration_targets",
        "tenant_calibration_scores",
        "tenant_calibration_outcomes",
        "tenant_calibration_audit",
    ],
)
async def test_row_level_security_hides_other_tenants_rows_even_with_a_forged_filter(
    app_pool, table
):
    store = PostgresCalibrationStore(app_pool)
    for tenant in (ACME, OTHER):
        v = view(store, tenant)
        await v.set_targets(tenant, Targets(0.9, 0.9), event(tenant))
        await v.put_scores(tenant, SCORING, "output", {H1: {"t__a": 0.7}})
        await v.put_outcomes(tenant, SCORING, "output", {H1: "failed"})
    rows = await scoped_sql(
        app_pool, ACME, f"SELECT tenant_id FROM {table} WHERE true OR $1 = $1", OTHER
    )
    assert rows and {r["tenant_id"] for r in rows} == {ACME}
    assert await scoped_sql(app_pool, None, f"SELECT * FROM {table}") == []
    assert await scoped_sql(app_pool, "t_nosuch", f"SELECT * FROM {table}") == []


async def test_scores_and_audit_are_insert_only_even_for_the_owner(app_pool, pg_pool):
    store = view(PostgresCalibrationStore(app_pool))
    await store.put_scores(ACME, SCORING, "output", {H1: {"t__a": 0.7}})
    await store.record(ACME, event(ACME, "targets", rule="a"))
    for change in (
        "UPDATE tenant_calibration_scores SET scores = '{}'",
        "DELETE FROM tenant_calibration_scores",
        "UPDATE tenant_calibration_outcomes SET cause = 'failed'",
        "DELETE FROM tenant_calibration_outcomes",
        "TRUNCATE tenant_calibration_outcomes",
        "UPDATE tenant_calibration_audit SET actor = 'x'",
        "DELETE FROM tenant_calibration_audit",
        "TRUNCATE tenant_calibration_audit",
        "TRUNCATE tenant_calibration_scores",
        "TRUNCATE tenant_calibration_targets",
        "DELETE FROM tenant_calibration_targets",
    ):
        async with app_pool.acquire() as conn, conn.transaction():
            await conn.execute("SELECT set_config('app.tenant_id', $1, true)", ACME)
            with pytest.raises(DENIED):
                await conn.execute(change)
    for change in (
        "UPDATE tenant_calibration_scores SET scores = '{}'",
        "DELETE FROM tenant_calibration_audit",
        "TRUNCATE tenant_calibration_scores",
    ):
        with pytest.raises(asyncpg.exceptions.RestrictViolationError):
            await pg_pool.execute(change)  # the owner is held by the triggers too


async def test_the_calibration_grants_are_exact(app_pool):
    privileges = {
        (r["table_name"], r["privilege_type"])
        for r in await app_pool.fetch(
            "SELECT table_name, privilege_type FROM information_schema.role_table_grants "
            "WHERE grantee = current_user AND table_name LIKE 'tenant_calibration_%'"
        )
    }
    assert privileges == {
        ("tenant_calibration_targets", "SELECT"),
        ("tenant_calibration_targets", "INSERT"),
        ("tenant_calibration_targets", "UPDATE"),
        ("tenant_calibration_scores", "SELECT"),
        ("tenant_calibration_scores", "INSERT"),
        ("tenant_calibration_outcomes", "SELECT"),
        ("tenant_calibration_outcomes", "INSERT"),
        ("tenant_calibration_audit", "SELECT"),
        ("tenant_calibration_audit", "INSERT"),
    }


async def test_the_database_holds_the_target_range_and_the_event_shape(app_pool):
    async with app_pool.acquire() as conn:
        for bad in (
            "INSERT INTO tenant_calibration_targets (tenant_id, block_precision, escalate_recall, "
            "recall_tolerance, updated_at, updated_by) VALUES ('t_acme', 0.4, 0.9, 2, now(), 'x')",
            "INSERT INTO tenant_calibration_targets (tenant_id, block_precision, escalate_recall, "
            "recall_tolerance, updated_at, updated_by) VALUES ('t_acme', 0.9, 1.1, 2, now(), 'x')",
            "INSERT INTO tenant_calibration_targets (tenant_id, block_precision, escalate_recall, "
            "recall_tolerance, updated_at, updated_by) VALUES ('t_acme', 0.9, 0.9, 21, now(), 'x')",
            "INSERT INTO tenant_calibration_targets (tenant_id, block_precision, escalate_recall, "
            "recall_tolerance, updated_at, updated_by) VALUES ('t_acme', 0.9, 0.9, -1, now(), 'x')",
            "INSERT INTO tenant_calibration_audit (tenant_id, at, actor, kind, cross_tenant, "
            "operator, detail) VALUES ('t_acme', now(), 'x', 'other', false, false, '{}')",
        ):
            async with conn.transaction():
                await conn.execute("SELECT set_config('app.tenant_id', 't_acme', true)")
                with pytest.raises(asyncpg.CheckViolationError):
                    await conn.execute(bad)


async def test_an_audit_event_round_trips_its_detail_exactly(app_pool):
    store = view(PostgresCalibrationStore(app_pool))
    detail = {"rule": "r", "applied": {"block_at": 0.56, "escalate_at": 0.5}, "n": [1, 2]}
    await store.record(ACME, event(ACME, "targets", **detail))
    (got,) = await store.audit_events(ACME)
    assert got.detail == detail and json.dumps(got.detail, sort_keys=True)
