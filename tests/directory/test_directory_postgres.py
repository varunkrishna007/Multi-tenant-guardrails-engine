"""M2-01: the Postgres tenant directory: constraints, append-only audit, atomic writes and the
reader and writer roles. Needs GUARDRAIL_TEST_PG_DSN (skipped without it); each test gets a
throwaway schema."""

import uuid

import pytest

from guardrail_engine.directory import TenantExists, TenantRecord
from guardrail_engine.directory.model import DirectoryAuditEvent, audit_fields

asyncpg = pytest.importorskip("asyncpg")

INSERT = (
    "INSERT INTO tenants (tenant_id, slug, domain, tier, status, version) "
    "VALUES ($1, $2, $3, $4, $5, $6)"
)
GOOD = ("t_acme1", "acme", "insurance", "standard", "active", 1)


def event(record, actor="ops-1"):
    return DirectoryAuditEvent(record.tenant_id, record.version, "create", actor, 1_700_000_000.0,
                               None, audit_fields(record))  # fmt: skip


@pytest.mark.parametrize(
    "bad",
    [
        ("t_Acme", "acme", "insurance", "standard", "active", 1),  # id format
        ("t_acme1", "Acme", "insurance", "standard", "active", 1),  # slug pattern
        ("t_acme1", "a" * 41, "insurance", "standard", "active", 1),  # slug length
        ("t_acme1", "acme", "retail", "standard", "active", 1),  # domain
        ("t_acme1", "acme", "insurance", "gold", "active", 1),  # tier
        ("t_acme1", "acme", "insurance", "standard", "gone", 1),  # status
        ("t_acme1", "acme", "insurance", "standard", "active", 0),  # version
    ],
)
async def test_the_database_enforces_the_directory_rules_itself(pg, bad):
    with pytest.raises(asyncpg.CheckViolationError):
        await pg.pool.execute(INSERT, *bad)
    assert await pg.pool.fetchval("SELECT count(*) FROM tenants") == 0


async def test_the_database_refuses_an_unknown_flag_and_a_duplicate_slug(pg):
    with pytest.raises(asyncpg.CheckViolationError):
        await pg.pool.execute(
            "INSERT INTO tenants (tenant_id, slug, domain, tier, status, version, flags) "
            "VALUES ('t_acme1', 'acme', 'insurance', 'standard', 'active', 1, '{root}')"
        )
    await pg.pool.execute(INSERT, *GOOD)
    with pytest.raises(asyncpg.UniqueViolationError):
        await pg.pool.execute(INSERT, "t_acme2", "acme", "energy", "standard", "active", 1)


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE tenant_directory_audit SET actor = 'x'",
        "DELETE FROM tenant_directory_audit",
        "TRUNCATE tenant_directory_audit",
    ],
)
async def test_the_audit_table_is_append_only(pg, statement):
    from guardrail_engine.store.adapters.postgres import PostgresDirectoryStore

    store = PostgresDirectoryStore(pg.pool)
    record = TenantRecord(*GOOD[:3])
    await store.insert(record, event(record))
    with pytest.raises(asyncpg.RestrictViolationError):
        await pg.pool.execute(statement)
    assert len(await store.audit_events("t_acme1")) == 1


async def test_a_write_and_its_audit_event_commit_together_or_not_at_all(pg):
    from guardrail_engine.store.adapters.postgres import PostgresDirectoryStore

    store = PostgresDirectoryStore(pg.pool)
    record = TenantRecord(*GOOD[:3])
    with pytest.raises(asyncpg.CheckViolationError):
        await store.insert(record, event(record, actor=""))  # the audit row is refused
    assert await store.get("t_acme1") is None  # so the tenant row rolled back too
    await store.insert(record, event(record))
    v2 = record.with_changes(tier="regulated")
    with pytest.raises(asyncpg.CheckViolationError):
        await store.replace(v2, 1, event(v2, actor=""))
    assert (await store.get("t_acme1")).tier == "standard"
    assert len(await store.audit_events("t_acme1")) == 1


async def test_the_directory_round_trips_every_field_through_postgres(pg):
    from guardrail_engine.store.adapters.postgres import PostgresDirectoryStore

    store = PostgresDirectoryStore(pg.pool)
    record = TenantRecord(
        "t_acme1", "acme-insurance", "healthcare", tier="dedicated",
        flags=frozenset({"two_person_publish"}), required_packs=frozenset({"hipaa", "pii"}),
        baa=True, status="suspended", version=1,
    )  # fmt: skip
    await store.insert(record, event(record))
    back = await store.get("t_acme1")
    assert back == record and back.created_at is not None
    assert (await store.audit_events("t_acme1"))[0].after == audit_fields(record)


@pytest.fixture
async def roles(pg):
    """A reader and a writer role with the directory grants, as pools on the throwaway schema."""
    from guardrail_engine.store.adapters.postgres import apply_directory_grants

    made, pools = {}, {}
    for kind in ("reader", "writer"):
        name, password = f"m201_{kind}_{uuid.uuid4().hex[:12]}", uuid.uuid4().hex
        await pg.pool.execute(f"CREATE ROLE \"{name}\" LOGIN PASSWORD '{password}'")
        await pg.pool.execute(f'GRANT USAGE ON SCHEMA "{pg.schema}" TO "{name}"')
        made[kind] = (name, password)
    await apply_directory_grants(pg.pool, made["reader"][0], made["writer"][0])
    try:
        for kind, (name, password) in made.items():
            pools[kind] = await asyncpg.create_pool(
                pg.dsn, user=name, password=password, min_size=1, max_size=2,
                server_settings={"search_path": pg.schema},
            )  # fmt: skip
        yield pools
    finally:
        for pool in pools.values():
            await pool.close()
        for name, _ in made.values():
            await pg.pool.execute(f'DROP OWNED BY "{name}"')
            await pg.pool.execute(f'DROP ROLE "{name}"')


async def test_the_writer_role_can_provision_but_not_delete_or_rewrite_the_audit(pg, roles):
    from guardrail_engine.store.adapters.postgres import PostgresDirectoryStore

    store = PostgresDirectoryStore(roles["writer"])
    record = TenantRecord(*GOOD[:3])
    await store.insert(record, event(record))
    v2 = record.with_changes(tier="regulated")
    await store.replace(v2, 1, event(v2))
    with pytest.raises(TenantExists):
        await store.insert(record.with_changes(), event(record))
    for statement in ("DELETE FROM tenants", "TRUNCATE tenants",
                      "UPDATE tenant_directory_audit SET actor = 'x'",
                      "DELETE FROM tenant_directory_audit"):  # fmt: skip
        with pytest.raises(asyncpg.InsufficientPrivilegeError):
            await roles["writer"].execute(statement)


async def test_the_reader_role_can_read_tenants_and_nothing_else(pg, roles):
    from guardrail_engine.store.adapters.postgres import PostgresDirectoryStore

    writer, reader = (
        PostgresDirectoryStore(roles["writer"]),
        PostgresDirectoryStore(roles["reader"]),
    )
    record = TenantRecord(*GOOD[:3])
    await writer.insert(record, event(record))
    assert await reader.get("t_acme1") == await writer.get("t_acme1")
    assert [r.tenant_id for r in await reader.list()] == ["t_acme1"]
    for statement in (
        "UPDATE tenants SET tier = 'dedicated'", "DELETE FROM tenants",
        "SELECT * FROM tenant_directory_audit",
    ):  # fmt: skip
        with pytest.raises(asyncpg.InsufficientPrivilegeError):
            await roles["reader"].execute(statement)
    with pytest.raises(asyncpg.InsufficientPrivilegeError):
        await reader.insert(TenantRecord("t_acme2", "other", "energy"), event(record))


async def test_the_grants_need_two_different_roles(pg):
    from guardrail_engine.store.adapters.postgres import apply_directory_grants

    with pytest.raises(ValueError, match="differ"):
        await apply_directory_grants(pg.pool, "same", "same")
    with pytest.raises(ValueError, match="role name"):
        await apply_directory_grants(pg.pool, "", "other")
