"""M5-05 the nightly red-team's results and the active-version source on Postgres (migrations 051
to 053), through the **operator** pool, which is the role the job connects as. Needs
``GUARDRAIL_TEST_PG_DSN``."""

from datetime import UTC, datetime, timedelta

import asyncpg
import pytest

from guardrail_engine.nightly.adapters.postgres import (
    PostgresActiveBundles,
    PostgresNightlyResults,
    PostgresQuarantine,
)
from guardrail_engine.nightly.model import NightlyResult, QuarantineEvent
from guardrail_engine.store.port import OperatorPoolUnavailableError

SHA = "sha256:" + "ab" * 32
D0 = datetime(2026, 11, 20, 3, 0, tzinfo=UTC)


def result(tenant="t_acmeins", version=1, *, day=0, status="pass", config="platform/floor@2",
           mode="fake", regressions=(), project="", seed="a1" * 16):  # fmt: skip
    return NightlyResult(
        tenant_id=tenant, bundle_version=version, project=project, config_key=config,
        run_id=f"run{day}",
        run_at=D0 + timedelta(days=day), mode=mode, floor_version=2, packs=(), corpus_sha256=SHA,
        draws=3, rows=172, status=status, regressions=tuple(regressions),
        block_recall={"p__inj_direct": {"hits": 30, "cells": 30}},
        false_act={"overall": {"hits": 0, "cells": 60}}, structure_violations=0,
        provider_calls=516, input_tokens=600_000, note="", nonce_seed=seed,
    )  # fmt: skip


async def test_results_round_trip_and_the_latest_per_tenant_is_the_newest(operator_pool):
    store = PostgresNightlyResults(operator_pool)
    await store.append_many(
        [
            result("t_acmeins", 1, day=0), result("t_acmeins", 2, day=1, status="regression",
                regressions=[{"rule": "p__inj_direct", "vs": "previous"}]),
            result("t_otherco", 1, day=0),
        ]
    )  # fmt: skip
    latest = await store.latest_per_tenant(status=None, after=None, limit=10)
    assert [(r.tenant_id, r.bundle_version, r.status) for r in latest] == [
        ("t_acmeins", 2, "regression"), ("t_otherco", 1, "pass"),
    ]  # fmt: skip
    assert latest[0].regressions == ({"rule": "p__inj_direct", "vs": "previous"},)
    assert latest[0].block_recall == {"p__inj_direct": {"hits": 30, "cells": 30}}
    only = await store.latest_per_tenant(status="regression", after=None, limit=10)
    assert [r.tenant_id for r in only] == ["t_acmeins"]
    rest = await store.latest_per_tenant(status=None, after="t_acmeins", limit=10)
    assert [r.tenant_id for r in rest] == ["t_otherco"]
    week = await store.latest_for_tenant("t_acmeins")
    assert [r.bundle_version for r in week] == [2, 1] and await store.latest_for_tenant("t_x") == []


async def test_the_previous_result_is_the_latest_tested_one_of_the_configuration_and_mode(
    operator_pool,
):
    store = PostgresNightlyResults(operator_pool)
    await store.append_many(
        [
            result(day=0), result(day=1, status="pass"), result(day=2, status="refused"),
            result(day=3, status="stopped"), result(version=2, day=1, mode="live"),
            result(version=3, day=1, config="platform/floor@2+domain/a@1"),
        ]
    )  # fmt: skip
    prev = await store.previous_for_config("platform/floor@2", "fake", D0 + timedelta(days=9))
    assert prev is not None and prev.run_id == "run1"  # refused and stopped aren't comparable
    assert (
        await store.previous_for_config("platform/floor@2", "fake", D0) is None
    )  # strictly before
    dates = await store.config_dates("platform/floor@2", "fake")
    assert (dates.last_tested, dates.first_seen) == (D0 + timedelta(days=1), D0)
    none = await store.config_dates("platform/floor@9", "fake")
    assert (none.last_tested, none.first_seen) == (None, None)


async def test_the_table_is_insert_only_and_a_result_cannot_name_a_bad_status(operator_pool):
    store = PostgresNightlyResults(operator_pool)
    await store.append_many([result()])
    for sql in (
        "UPDATE nightly_redteam_results SET status = 'pass'",
        "DELETE FROM nightly_redteam_results",
        "TRUNCATE nightly_redteam_results",
    ):
        with pytest.raises(asyncpg.PostgresError):
            await operator_pool.execute(sql)
    with pytest.raises(asyncpg.CheckViolationError):
        await store.append_many([result(status="maybe")])
    with pytest.raises(asyncpg.UniqueViolationError):  # one row per (tenant, version, run)
        await store.append_many([result()])


async def test_the_tenants_own_pool_sees_only_its_rows_and_cannot_write(
    pg_env, app_pool, operator_pool
):
    await PostgresNightlyResults(operator_pool).append_many(
        [result("t_acmeins"), result("t_otherco")]
    )

    async def as_tenant(tenant, sql):
        async with app_pool.acquire() as conn, conn.transaction():
            if tenant:
                await conn.execute("SELECT set_config('app.tenant_id', $1, true)", tenant)
            return await conn.fetch(sql)

    assert await as_tenant(None, "SELECT 1 FROM nightly_redteam_results") == []
    mine = await as_tenant("t_acmeins", "SELECT tenant_id FROM nightly_redteam_results")
    assert [r["tenant_id"] for r in mine] == ["t_acmeins"]
    with pytest.raises(asyncpg.PostgresError):
        await as_tenant("t_acmeins", "DELETE FROM nightly_redteam_results")


async def test_without_an_operator_pool_nothing_works():
    for call in (
        PostgresNightlyResults(None).latest_per_tenant(status=None, after=None, limit=1),
        PostgresNightlyResults(None).append_many([result()]),
        PostgresActiveBundles(None).active_bundles(),
    ):
        with pytest.raises(OperatorPoolUnavailableError):
            await call


async def test_the_active_versions_name_their_floor_and_packs(pg_env, operator_pool):
    import json

    async with pg_env.pool.acquire() as conn:
        for tenant, extends, active in (
            ("t_acmeins", ["platform/floor@2", "domain/insurance@2", "domain/finance@1"], True),
            ("t_otherco", ["platform/floor@1"], True),
            ("t_inactive", ["platform/floor@2", "domain/energy@1"], False),
        ):
            doc = json.dumps({"tenant_id": tenant, "version": 1, "extends": extends})
            await conn.execute("SELECT set_config('app.tenant_id', $1, false)", tenant)
            await conn.execute(
                "INSERT INTO policy_bundle_versions (tenant_id, version, document, bundle_hash) "
                "VALUES ($1, 1, $2, $3)", tenant, doc, SHA,
            )  # fmt: skip
            if active:
                await conn.execute(
                    "INSERT INTO policy_active_versions (tenant_id, version) VALUES ($1, 1)",
                    tenant,
                )
            await conn.execute("SELECT set_config('app.tenant_id', '', false)")
    found = await PostgresActiveBundles(operator_pool).active_bundles()
    assert [(b.tenant_id, b.floor_ref, b.pack_refs) for b in found] == [
        ("t_acmeins", "platform/floor@2", ("domain/finance@1", "domain/insurance@2")),
        ("t_otherco", "platform/floor@1", ()),
    ]  # fmt: skip


async def test_the_project_is_stored_filtered_and_checked(operator_pool):
    store = PostgresNightlyResults(operator_pool)
    await store.append_many(
        [
            result("t_acmeins"),
            result("t_otherco", project="reg-acme", config="reg-acme|platform/floor@2"),
        ]
    )
    allr = await store.latest_per_tenant(status=None, after=None, limit=10)
    assert {r.tenant_id: r.project for r in allr} == {"t_acmeins": "", "t_otherco": "reg-acme"}
    only = await store.latest_per_tenant(status=None, after=None, limit=10, project="reg-acme")
    assert [r.tenant_id for r in only] == ["t_otherco"]
    shared = await store.latest_per_tenant(status=None, after=None, limit=10, project="")
    assert [r.tenant_id for r in shared] == ["t_acmeins"]
    with pytest.raises(asyncpg.CheckViolationError):  # a label's shape, never a key
        await store.append_many([result("t_acmeins", 5, project="AIzaSyNOTAKEY")])


async def test_the_nonce_seed_is_stored_and_checked(operator_pool):
    store = PostgresNightlyResults(operator_pool)
    await store.append_many([result(), result(version=2, seed="")])
    got = {r.bundle_version: r.nonce_seed for r in await store.latest_for_tenant("t_acmeins")}
    assert got == {1: "a1" * 16, 2: ""}
    with pytest.raises(asyncpg.CheckViolationError):
        await store.append_many([result(version=3, seed="not a seed")])


def event(action="quarantine", *, day=0, config="acme|platform/floor@2", mode="live", **kw):
    return QuarantineEvent(
        config_key=config, mode=mode, project=kw.get("project", "acme"), action=action,
        row_id=kw.get("row_id", ""),
        at=D0 + timedelta(days=day), actor=kw.get("actor", "nightly"),
        operator=kw.get("operator", False), reason=kw.get("reason", "provider_refusal"),
        run_id=kw.get("run_id", "run0"),
    )  # fmt: skip


async def test_the_quarantine_is_the_latest_event_per_configuration_and_mode(operator_pool):
    q = PostgresQuarantine(operator_pool)
    await q.append(event())
    await q.append(event(config="platform/floor@1", project=""))
    await q.append(event(config="acme|platform/floor@2", mode="fake"))
    held = await q.quarantined("live")
    assert sorted(held) == ["acme|platform/floor@2", "platform/floor@1"]
    await q.append(
        event("clear", day=1, actor="idp#ops-1", operator=True, reason="provider confirmed")
    )
    assert sorted(await q.quarantined("live")) == ["platform/floor@1"]
    assert sorted(await q.quarantined("fake")) == ["acme|platform/floor@2"]  # another mode
    history = await q.history("acme|platform/floor@2", "live")
    assert [(e.action, e.actor, e.operator) for e in history] == [
        ("quarantine", "nightly", False), ("clear", "idp#ops-1", True),
    ]  # fmt: skip
    await q.append(event(day=2))  # refused again after a clear: back in quarantine
    assert "acme|platform/floor@2" in await q.quarantined("live")


async def test_a_refused_row_is_held_by_its_own_key_and_its_id_is_checked(operator_pool):
    q = PostgresQuarantine(operator_pool)
    await q.append(event(config="row:rt-dir-001", project="", row_id="rt-dir-001"))
    await q.append(event(row_id="rt-dir-001"))
    held = await q.quarantined("live")
    assert held["row:rt-dir-001"].row_id == "rt-dir-001"
    assert held["acme|platform/floor@2"].row_id == "rt-dir-001"
    with pytest.raises(asyncpg.CheckViolationError):  # an id, never content
        await q.append(event(config="row:x", row_id="a b; drop"))


async def test_the_quarantine_table_is_append_only_and_checked(operator_pool, app_pool):
    q = PostgresQuarantine(operator_pool)
    await q.append(event())
    for sql in (
        "UPDATE nightly_redteam_quarantine SET reason = 'x'",
        "DELETE FROM nightly_redteam_quarantine",
        "TRUNCATE nightly_redteam_quarantine",
    ):
        with pytest.raises(asyncpg.PostgresError):
            await operator_pool.execute(sql)
    for bad in (event("hold"), event(reason=""), event(reason="x" * 201), event(mode="dry"),
                event(project="Not A Label"), event(actor="")):  # fmt: skip
        with pytest.raises(asyncpg.CheckViolationError):
            await q.append(bad)
    with pytest.raises(asyncpg.PostgresError):
        await app_pool.execute("DELETE FROM nightly_redteam_quarantine")


async def test_the_quarantine_needs_the_operator_pool():
    for call in (
        PostgresQuarantine(None).append(event()),
        PostgresQuarantine(None).quarantined("live"),
        PostgresQuarantine(None).history("k", "live"),
    ):
        with pytest.raises(OperatorPoolUnavailableError):
            await call
