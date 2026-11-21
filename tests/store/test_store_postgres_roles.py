"""Postgres policy store: role separation and concurrent pointer moves.

The table owner can disable the immutability trigger, so the service must not connect as the
owner. ``app_pool`` connects as a role set up only by ``002_app_role_grants.sql``. These
tests show that role can run the whole store and cannot defeat immutability.

They need ``GUARDRAIL_TEST_PG_DSN`` and are skipped without it.
"""

import asyncio

import asyncpg
import pytest
from store_harness import ACME, PostgresHarness, make_bundle

from guardrail_engine.store import ActivePointerConflictError
from guardrail_engine.store.adapters.postgres import apply_app_role_grants

DENIED = asyncpg.InsufficientPrivilegeError


@pytest.fixture
async def app_store(app_pool):
    """A store running as the application role, holding ACME@1 (active) and ACME@2."""
    store = PostgresHarness(app_pool).store()
    for version in (1, 2):
        bundle, bundle_hash = make_bundle(ACME, version)
        await store.put_version(ACME, bundle, bundle_hash=bundle_hash)
    await store.set_active_version(ACME, 1)
    return store


async def test_app_role_is_not_a_superuser_and_owns_neither_table(app_pool, app_store):
    assert await app_pool.fetchval("SELECT current_user") != await app_pool.fetchval(
        "SELECT tableowner FROM pg_tables WHERE tablename = 'policy_bundle_versions' "
        "AND schemaname = current_schema()"
    )
    assert await app_pool.fetchval("SELECT NOT rolsuper FROM pg_roles WHERE rolname = current_user")
    owners = await app_pool.fetch(
        "SELECT tableowner FROM pg_tables WHERE schemaname = current_schema()"
    )
    assert (
        len(owners) == 39
    )  # policy 2, directory 2, drafts 2, golden 3, lifecycle 2, tools 2, platform 4,
    # calibration 4, delivery 2, retention 2, shadow agreement 1, decision records 1, escalation 2,
    # approvals 2, offboarding 4 (receipts, completions, usage summaries, sweeps), stored content 2
    # (the rows and the read audit), nightly red-team results 1 and quarantine events 1
    assert await app_pool.fetchval("SELECT current_user") not in {r[0] for r in owners}


async def test_app_role_can_run_every_store_operation(app_store):
    assert [v.version for v in await app_store.list_versions(ACME)] == [1, 2]
    assert (await app_store.get_version(ACME, 2)).version == 2
    assert await app_store.get_active_version(ACME) == 1
    await app_store.set_active_version(ACME, 2)
    await app_store.set_active_version(ACME, 1, expected_current=2)
    assert (await app_store.load_active(ACME)).version == 1
    again, again_hash = make_bundle(ACME, 2)
    assert (await app_store.put_version(ACME, again, bundle_hash=again_hash)).version == 2


@pytest.mark.parametrize(
    "statement",
    [
        "ALTER TABLE policy_bundle_versions DISABLE TRIGGER USER",
        "ALTER TABLE policy_bundle_versions DISABLE TRIGGER ALL",
        "ALTER TABLE policy_bundle_versions "
        "DISABLE TRIGGER policy_bundle_versions_no_update_or_delete",
        "DROP TRIGGER policy_bundle_versions_no_update_or_delete ON policy_bundle_versions",
        "DROP TRIGGER policy_bundle_versions_no_truncate ON policy_bundle_versions",
        "ALTER TABLE policy_bundle_versions DROP CONSTRAINT "
        "policy_bundle_versions_row_matches_document",
        "ALTER TABLE policy_bundle_versions OWNER TO CURRENT_USER",
        "DROP TABLE policy_bundle_versions CASCADE",
        "CREATE OR REPLACE FUNCTION policy_bundle_versions_immutable() RETURNS trigger "
        "LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END; $$",
        "UPDATE policy_bundle_versions SET bundle_hash = bundle_hash",
        "UPDATE policy_bundle_versions SET document = '{}'",
        "DELETE FROM policy_bundle_versions",
        "TRUNCATE policy_bundle_versions CASCADE",
        "DELETE FROM policy_active_versions",
        "TRUNCATE policy_active_versions",
    ],
)
async def test_app_role_cannot_change_stored_versions_or_remove_the_guards(
    app_pool, app_store, pg_pool, statement
):
    before = await pg_pool.fetch("SELECT * FROM policy_bundle_versions ORDER BY version")

    with pytest.raises(DENIED):
        await app_pool.execute(statement)

    assert await pg_pool.fetch("SELECT * FROM policy_bundle_versions ORDER BY version") == before
    assert await app_store.get_active_version(ACME) == 1
    # The trigger is still in force, even for the owner.
    with pytest.raises(asyncpg.PostgresError, match="is immutable"):
        await pg_pool.execute("DELETE FROM policy_bundle_versions")


async def test_grants_script_can_be_applied_again_and_removes_extra_privileges(
    app_pool, app_store, pg_pool
):
    role = await app_pool.fetchval("SELECT current_user")
    await pg_pool.execute(f'GRANT ALL ON policy_bundle_versions TO "{role}"')  # a past mistake

    await apply_app_role_grants(pg_pool, role)

    granted = await pg_pool.fetch(
        "SELECT table_name, privilege_type FROM information_schema.role_table_grants "
        "WHERE grantee = $1 AND table_schema = current_schema() ORDER BY 1, 2",
        role,
    )
    assert [tuple(r) for r in granted] == [
        ("decision_record_rules", "INSERT"),
        ("decision_record_rules", "SELECT"),
        ("decision_records", "INSERT"),
        ("decision_records", "SELECT"),
        ("delivery_outbox", "DELETE"),
        ("delivery_outbox", "INSERT"),
        ("delivery_outbox", "SELECT"),
        ("delivery_outbox", "UPDATE"),
        ("escalation_audit", "INSERT"),
        ("escalation_audit", "SELECT"),
        ("escalation_items", "INSERT"),
        ("escalation_items", "SELECT"),
        ("nightly_redteam_quarantine", "INSERT"),
        ("nightly_redteam_quarantine", "SELECT"),
        ("nightly_redteam_results", "INSERT"),
        ("nightly_redteam_results", "SELECT"),
        ("platform_audit", "INSERT"),
        ("platform_audit", "SELECT"),
        ("platform_floor_approvals", "INSERT"),
        ("platform_floor_approvals", "SELECT"),
        ("platform_floor_releases", "INSERT"),
        ("platform_floor_releases", "SELECT"),
        ("platform_floor_state", "INSERT"),
        ("platform_floor_state", "SELECT"),
        ("platform_floor_state", "UPDATE"),
        ("policy_active_versions", "INSERT"),
        ("policy_active_versions", "SELECT"),
        ("policy_active_versions", "UPDATE"),
        ("policy_bundle_versions", "INSERT"),
        ("policy_bundle_versions", "SELECT"),
        ("stored_content", "INSERT"),
        ("stored_content", "SELECT"),
        ("stored_content_audit", "INSERT"),
        ("stored_content_audit", "SELECT"),
        ("tenant_approval_audit", "INSERT"),
        ("tenant_approval_audit", "SELECT"),
        ("tenant_approvals", "INSERT"),
        ("tenant_approvals", "SELECT"),
        ("tenant_calibration_audit", "INSERT"),
        ("tenant_calibration_audit", "SELECT"),
        ("tenant_calibration_outcomes", "INSERT"),
        ("tenant_calibration_outcomes", "SELECT"),
        ("tenant_calibration_scores", "INSERT"),
        ("tenant_calibration_scores", "SELECT"),
        ("tenant_calibration_targets", "INSERT"),
        ("tenant_calibration_targets", "SELECT"),
        ("tenant_calibration_targets", "UPDATE"),
        ("tenant_candidates", "DELETE"),
        ("tenant_candidates", "INSERT"),
        ("tenant_candidates", "SELECT"),
        ("tenant_candidates", "UPDATE"),
        ("tenant_draft_audit", "INSERT"),
        ("tenant_draft_audit", "SELECT"),
        ("tenant_drafts", "INSERT"),
        ("tenant_drafts", "SELECT"),
        ("tenant_drafts", "UPDATE"),
        ("tenant_golden_audit", "INSERT"),
        ("tenant_golden_audit", "SELECT"),
        ("tenant_golden_examples", "INSERT"),
        ("tenant_golden_examples", "SELECT"),
        ("tenant_golden_sets", "INSERT"),
        ("tenant_golden_sets", "SELECT"),
        ("tenant_publish_audit", "INSERT"),
        ("tenant_publish_audit", "SELECT"),
        ("tenant_shadow_agreement", "INSERT"),
        ("tenant_shadow_agreement", "SELECT"),
        ("tenant_shadow_agreement", "UPDATE"),
        ("tenant_tool_audit", "INSERT"),
        ("tenant_tool_audit", "SELECT"),
        ("tenant_tools", "DELETE"),
        ("tenant_tools", "INSERT"),
        ("tenant_tools", "SELECT"),
        ("tenant_tools", "UPDATE"),
        ("usage_events", "INSERT"),
        ("usage_events", "SELECT"),
    ]  # the policy store's (002), the drafts' (009) and the golden sets' (011)


async def test_grants_refuse_an_empty_role_name_and_quote_an_odd_one(pg_pool):
    with pytest.raises(ValueError):
        await apply_app_role_grants(pg_pool, "")
    # Quoted as an identifier, so this is a role that doesn't exist, not injected SQL.
    with pytest.raises(asyncpg.UndefinedObjectError):
        await apply_app_role_grants(pg_pool, 'nobody"; DROP TABLE policy_active_versions; --')
    assert await pg_pool.fetchval("SELECT count(*) FROM policy_active_versions") == 0


# --------------------------------------------------------------------------- concurrent


async def test_concurrent_compare_and_set_lets_exactly_one_mover_win(pg_pool):
    store = PostgresHarness(pg_pool).store()
    targets = list(range(2, 10))
    for version in (1, *targets):
        bundle, bundle_hash = make_bundle(ACME, version)
        await store.put_version(ACME, bundle, bundle_hash=bundle_hash)
    await store.set_active_version(ACME, 1)

    results = await asyncio.gather(
        *(store.set_active_version(ACME, v, expected_current=1) for v in targets),
        return_exceptions=True,
    )

    winners = [v for v, r in zip(targets, results, strict=True) if r is None]
    losers = [r for r in results if r is not None]
    assert len(winners) == 1
    assert len(losers) == len(targets) - 1
    assert all(isinstance(r, ActivePointerConflictError) for r in losers), losers
    assert all(r.expected == 1 and r.actual == winners[0] for r in losers)
    assert await store.get_active_version(ACME) == winners[0]


async def test_concurrent_first_publish_lets_exactly_one_mover_win(pg_pool):
    store = PostgresHarness(pg_pool).store()
    targets = list(range(1, 7))
    for version in targets:
        bundle, bundle_hash = make_bundle(ACME, version)
        await store.put_version(ACME, bundle, bundle_hash=bundle_hash)

    results = await asyncio.gather(
        *(store.set_active_version(ACME, v, expected_current=None) for v in targets),
        return_exceptions=True,
    )

    winners = [v for v, r in zip(targets, results, strict=True) if r is None]
    assert len(winners) == 1
    assert all(isinstance(r, ActivePointerConflictError) for r in results if r is not None)
    assert await store.get_active_version(ACME) == winners[0]
