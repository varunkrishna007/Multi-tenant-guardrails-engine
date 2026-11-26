"""Postgres policy store: what the database itself enforces (M1-02).

These tests bypass ``PostgresPolicyStore`` and send raw SQL, to show the guarantees hold for
any client. They need ``GUARDRAIL_TEST_PG_DSN`` and are skipped without it.
"""

import asyncpg
import pytest
from store_harness import ACME, OTHER, PostgresHarness, make_bundle

from guardrail_engine.store import VersionConflictError
from guardrail_engine.store.adapters.postgres import (
    APP_ROLE_GRANTS,
    MIGRATIONS,
    apply_schema,
    migration_sql,
)

IMMUTABLE = "policy_bundle_versions is immutable"


@pytest.fixture
async def stored(pg_pool):
    """A pool whose database holds ACME@1 (active) and OTHER@1."""
    store = PostgresHarness(pg_pool).store()
    for tenant_id in (ACME, OTHER):
        bundle, bundle_hash = make_bundle(tenant_id, 1)
        await store.put_version(tenant_id, bundle, bundle_hash=bundle_hash)
    await store.set_active_version(ACME, 1)
    return pg_pool


async def _rows(pool):
    return await pool.fetch(
        "SELECT tenant_id, version, document, bundle_hash, created_at "
        "FROM policy_bundle_versions ORDER BY tenant_id, version"
    )


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE policy_bundle_versions SET document = '{}'",
        "UPDATE policy_bundle_versions SET bundle_hash = 'sha256:" + "0" * 64 + "'",
        "UPDATE policy_bundle_versions SET created_at = now()",
        "UPDATE policy_bundle_versions SET version = version",
    ],
    ids=["document", "bundle_hash", "created_at", "no-op"],
)
async def test_raw_update_of_a_stored_version_is_refused_by_the_database(stored, statement):
    before = await _rows(stored)

    with pytest.raises(asyncpg.PostgresError, match=IMMUTABLE) as e:
        await stored.execute(statement + " WHERE tenant_id = $1 AND version = 1", ACME)

    assert e.value.sqlstate == "23001"  # restrict_violation, raised by the trigger
    assert await _rows(stored) == before


async def test_raw_delete_of_a_stored_version_is_refused_by_the_database(stored):
    before = await _rows(stored)

    for tenant_id in (ACME, OTHER):  # with and without an active pointer on the row
        with pytest.raises(asyncpg.PostgresError, match=IMMUTABLE) as e:
            await stored.execute(
                "DELETE FROM policy_bundle_versions WHERE tenant_id = $1", tenant_id
            )
        assert e.value.sqlstate == "23001"

    assert await _rows(stored) == before


async def test_raw_truncate_of_stored_versions_is_refused_by_the_database(stored):
    before = await _rows(stored)

    with pytest.raises(asyncpg.PostgresError, match=IMMUTABLE):
        await stored.execute("TRUNCATE policy_bundle_versions CASCADE")

    assert await _rows(stored) == before


async def test_raw_upsert_over_a_stored_version_is_refused_by_the_database(stored):
    before = await _rows(stored)

    with pytest.raises(asyncpg.PostgresError, match=IMMUTABLE):
        await stored.execute(
            "INSERT INTO policy_bundle_versions (tenant_id, version, document, bundle_hash) "
            "SELECT tenant_id, version, document, bundle_hash FROM policy_bundle_versions "
            "ON CONFLICT (tenant_id, version) DO UPDATE SET bundle_hash = EXCLUDED.bundle_hash"
        )
    with pytest.raises(asyncpg.UniqueViolationError):
        await stored.execute(
            "INSERT INTO policy_bundle_versions (tenant_id, version, document, bundle_hash) "
            "SELECT tenant_id, version, document, bundle_hash FROM policy_bundle_versions"
        )

    assert await _rows(stored) == before


async def test_raw_pointer_at_another_tenants_version_is_refused_by_the_database(stored):
    store = PostgresHarness(stored).store()
    bundle, bundle_hash = make_bundle(ACME, 2)
    await store.put_version(ACME, bundle, bundle_hash=bundle_hash)

    # OTHER has no version 2; only ACME does.
    with pytest.raises(asyncpg.ForeignKeyViolationError):
        await stored.execute(
            "INSERT INTO policy_active_versions (tenant_id, version) VALUES ($1, 2)", OTHER
        )
    with pytest.raises(asyncpg.ForeignKeyViolationError):
        await stored.execute(
            "UPDATE policy_active_versions SET version = 9 WHERE tenant_id = $1", ACME
        )

    assert await store.get_active_version(OTHER) is None
    assert await store.get_active_version(ACME) == 1


async def test_raw_insert_of_a_bundle_under_another_tenant_or_version_is_refused(stored):
    bundle, bundle_hash = make_bundle(ACME, 3)
    document = bundle.canonical_document.decode()
    insert = (
        "INSERT INTO policy_bundle_versions (tenant_id, version, document, bundle_hash) "
        "VALUES ($1, $2, $3, $4)"
    )

    for tenant_id, version in ((OTHER, 3), (ACME, 4)):
        with pytest.raises(asyncpg.CheckViolationError, match="row_matches_document"):
            await stored.execute(insert, tenant_id, version, document, bundle_hash)
    with pytest.raises(asyncpg.CheckViolationError):
        await stored.execute(insert, ACME, 3, document, "md5:abc")

    await stored.execute(insert, ACME, 3, document, bundle_hash)  # the matching row is fine


@pytest.mark.parametrize("tenant_id", ["t_acme_ins", "t_Acme", "t-acme", "t_" + "a" * 33])
async def test_raw_insert_under_a_tenant_id_outside_the_rule_is_refused(stored, tenant_id):
    """B3: the database holds the tenant id rule for any client. The document
    names the same tenant, so only the id rule can refuse the row."""
    import json

    bundle, bundle_hash = make_bundle(ACME, 3)
    document = json.loads(bundle.canonical_document)
    document["tenant_id"] = tenant_id
    with pytest.raises(asyncpg.CheckViolationError, match="tenant_id_format"):
        await stored.execute(
            "INSERT INTO policy_bundle_versions (tenant_id, version, document, bundle_hash) "
            "VALUES ($1, $2, $3, $4)",
            tenant_id,
            3,
            json.dumps(document),
            bundle_hash,
        )


async def test_applying_the_schema_again_keeps_data_and_immutability(stored):
    before = await _rows(stored)

    await apply_schema(stored)
    await apply_schema(stored)

    assert await _rows(stored) == before
    with pytest.raises(asyncpg.PostgresError, match=IMMUTABLE):
        await stored.execute("DELETE FROM policy_bundle_versions")


async def test_concurrent_puts_of_one_version_store_exactly_one_and_refuse_the_other(pg_pool):
    import asyncio

    store = PostgresHarness(pg_pool).store()
    first, first_hash = make_bundle(ACME, 1)
    second, second_hash = make_bundle(ACME, 1, rules=[])

    results = await asyncio.gather(
        store.put_version(ACME, first, bundle_hash=first_hash),
        store.put_version(ACME, second, bundle_hash=second_hash),
        return_exceptions=True,
    )

    errors = [r for r in results if isinstance(r, Exception)]
    assert len(errors) == 1 and isinstance(errors[0], VersionConflictError)
    (kept,) = await store.list_versions(ACME)
    assert kept.bundle_hash in (first_hash, second_hash)
    assert (await store.get_version(ACME, 1)).bundle_hash == kept.bundle_hash


def test_schema_is_a_plain_sql_file_shipped_inside_the_package():
    """Runs without a database: the migration is package data, not generated."""
    assert MIGRATIONS == (
        "001_policy_store.sql",
        "003_tenant_id_format.sql",
        "004_tenant_directory.sql",
        "006_row_level_security.sql",
        "008_drafts.sql",
        "010_golden_sets.sql",
        "012_publish_lifecycle.sql",
        "015_tenant_tools.sql",
        "017_platform_floors.sql",
        "019_directory_identifier_patterns.sql",
        "020_calibration.sql",
        "022_draft_audit_decisions.sql",
        "023_calibration_tolerance.sql",
        "024_delivery_outbox.sql",
        "026_retention.sql",
        "027_tool_pending_edit.sql",
        "028_shadow_agreement.sql",
        "032_decision_records_query.sql",
        "034_escalation_queue.sql",
        "038_metrics.sql",
        "040_approvals.sql",
        "043_offboarding.sql",
        "045_regulated_tier.sql",
        "046_gemini_projects.sql",
        "047_stored_content.sql",
        "051_nightly_redteam.sql",
        "054_decision_record_keys.sql",
        "055_escalation_candidate_rules.sql",
        "056_provider_degraded_actions.sql",
    )
    tenant_rule = migration_sql(MIGRATIONS[1])
    assert "CHECK (tenant_id ~ '^t_[0-9a-z]{1,32}$') NOT VALID" in tenant_rule
    assert "IF NOT EXISTS" in tenant_rule  # safe to run more than once
    assert "GRANT SELECT, INSERT ON policy_bundle_versions" in migration_sql(APP_ROLE_GRANTS)
    sql = migration_sql(MIGRATIONS[0])
    for needle in (
        "CREATE TABLE IF NOT EXISTS policy_bundle_versions",
        "CREATE TABLE IF NOT EXISTS policy_active_versions",
        "BEFORE UPDATE OR DELETE ON policy_bundle_versions",
        "BEFORE TRUNCATE ON policy_bundle_versions",
    ):
        assert needle in sql
