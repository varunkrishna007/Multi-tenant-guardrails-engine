"""The Postgres ``PolicyStore`` (M1-02). The only module that imports the database driver.

Schema: ``store/migrations/001_policy_store.sql``, applied with :func:`apply_schema` by an
owner role. The service connects as a separate, least-privilege role set up by
``002_app_role_grants.sql`` (:func:`apply_app_role_grants`), which can't alter the tables.

The database itself refuses UPDATE, DELETE and TRUNCATE on stored versions (a trigger) and
refuses a pointer to another tenant's version (a composite foreign key). This class adds the
hash check on store, on every load and before every pointer move.

A version's document is stored as the canonical JSON text of what was submitted, in a
``text`` column, so no database type can rewrite it.

Every statement filters on ``tenant_id`` and passes values as bind parameters.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
from collections.abc import AsyncIterator, Awaitable, Callable
from datetime import UTC, datetime
from importlib import resources
from typing import Any

import asyncpg

from guardrail_engine.admin.approvals import ApprovalUse
from guardrail_engine.admin.calibration_store import CalibrationAuditEvent, CalibrationStore
from guardrail_engine.admin.drafts import (
    DraftAuditEvent,
    DraftConflictError,
    DraftStore,
    StoredDraft,
)
from guardrail_engine.admin.floors import (
    AlreadyReleasedError,
    Approval,
    FloorRelease,
    PlatformConflictError,
    PlatformEvent,
    ReleaseExistsError,
    ReleaseNotFoundError,
    SecondOperatorRequiredError,
    settle,
)
from guardrail_engine.admin.golden import (
    MAX_ESCALATION_SETS as GOLDEN_MAX_ESCALATION_SETS,
)
from guardrail_engine.admin.golden import (
    MAX_SETS as GOLDEN_MAX_SETS,
)
from guardrail_engine.admin.golden import (
    GoldenAuditEvent,
    GoldenExample,
    GoldenPage,
    GoldenSetExistsError,
    GoldenSetInfo,
    GoldenSetNotFoundError,
    GoldenStore,
    TooManyGoldenSetsError,
    content_key,
)
from guardrail_engine.admin.lifecycle import (
    EVENT_ACTIONS,
    Candidate,
    GuardrailPublished,
    LifecycleState,
    LifecycleStore,
    PublishEvent,
    RuleSnapshot,
    StateConflictError,
    VersionEntry,
)
from guardrail_engine.admin.sweep import Targets
from guardrail_engine.admin.tool_registry import (
    PendingEdit,
    ToolConflictError,
    ToolEntry,
    ToolEvent,
    ToolStore,
)
from guardrail_engine.directory.model import (
    DirectoryAuditEvent,
    TenantChanged,
    TenantExists,
    TenantNotFound,
    TenantRecord,
    VersionConflict,
)
from guardrail_engine.guard.shadow import (
    DECISION_KEY,
    Counts,
    ShadowObservation,
    Tally,
    apply,
    merge,
)
from guardrail_engine.policy.catalog import Catalog
from guardrail_engine.policy.diff import DiffEntry
from guardrail_engine.policy.document import ParsedBundle
from guardrail_engine.store.adapters.approval_sql import consume as consume_approval
from guardrail_engine.store.port import (
    UNCHECKED,
    ActivePointerConflictError,
    AlertHook,
    OperatorPoolUnavailableError,
    PolicyStore,
    ScopeMismatchError,
    StoredVersion,
    TenantSettingLeakError,
    VersionConflictError,
    VersionInfo,
    VersionNotFoundError,
    _Unchecked,
)
from guardrail_engine.store.verification import MAX_VERSION, BundleVerifier
from guardrail_engine.tenant_ids import is_valid_tenant_id
from guardrail_engine.tenant_scope import TenantScope

_SET_TENANT_SQL = (
    "WITH prior AS MATERIALIZED (SELECT current_setting('app.tenant_id', true) AS v) "
    "SELECT v FROM prior, set_config('app.tenant_id', $1, true)"
)
"""Reads the setting as it was, then sets it for this transaction: one round trip. A non-empty
prior value means a connection came back with another tenant's setting."""

logger = logging.getLogger(__name__)

MIGRATIONS = (
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
"""Run in order by :func:`apply_schema`, as the role that will own the tables."""
APP_ROLE_GRANTS = "002_app_role_grants.sql"
DRAFT_GRANTS = "009_draft_grants.sql"
GOLDEN_GRANTS = "011_golden_grants.sql"
PUBLISH_GRANTS = "013_publish_grants.sql"
TOOL_GRANTS = "016_tool_grants.sql"
PLATFORM_GRANTS = "018_platform_grants.sql"
CALIBRATION_GRANTS = "021_calibration_grants.sql"
DELIVERY_GRANTS = "025_delivery_grants.sql"
RETENTION_APP_GRANTS = "029_retention_app_grants.sql"
RETENTION_ROLE_GRANTS = "030_retention_role_grants.sql"
SHADOW_GRANTS = "031_shadow_grants.sql"
RETENTION_ROLE_POLICY = "033_decision_records_retention_policy.sql"
ESCALATION_GRANTS = "035_escalation_grants.sql"
ESCALATION_RETENTION_GRANTS = "037_escalation_retention_grants.sql"
ESCALATION_OPERATOR_POLICIES = "036_escalation_operator_policies.sql"
APPROVAL_GRANTS = "041_approval_grants.sql"
APPROVAL_OPERATOR_POLICIES = "042_approval_operator_policies.sql"
OFFBOARDING_ROLE_GRANTS = "044_offboarding_role_grants.sql"
NIGHTLY_GRANTS = "052_nightly_redteam_grants.sql"
NIGHTLY_OPERATOR_POLICIES = "053_nightly_redteam_operator_policies.sql"
CONTENT_GRANTS = "048_stored_content_grants.sql"
CONTENT_RETENTION_GRANTS = "049_stored_content_retention_grants.sql"
CONTENT_OPERATOR_POLICIES = "050_stored_content_operator_policies.sql"
"""Run by :func:`apply_app_role_grants`, as the owner, once per service role."""
_APP_ROLE_VARIABLE = ':"app_role"'  # psql's quoted-identifier variable syntax
_MIGRATION_LOCK = 0x4D31_3032  # "M102": one migration run at a time


def migration_sql(name: str) -> str:
    return (resources.files("guardrail_engine.store") / "migrations" / name).read_text("utf-8")


async def apply_schema(pool: asyncpg.Pool) -> None:
    """Create the policy store tables and triggers. Safe to run more than once. Objects are
    created in the first schema of the connection's ``search_path`` and owned by the
    connecting role, which should be a migrations-only owner role, not the service's."""
    async with pool.acquire() as conn, conn.transaction():
        await conn.execute("SELECT pg_advisory_xact_lock($1)", _MIGRATION_LOCK)
        for name in MIGRATIONS:
            await conn.execute(migration_sql(name))


async def connect_pool(dsn: str) -> asyncpg.Pool:
    """Open a connection pool for :class:`PostgresPolicyStore`, for a caller that will own
    and close it (the engine factory, M1-11). ``dsn`` should name the least-privilege
    application role. Kept here so the driver is imported by this module only."""
    return await asyncpg.create_pool(dsn)


async def apply_app_role_grants(pool: asyncpg.Pool, app_role: str) -> None:
    """Give ``app_role`` (an existing role) exactly the privileges the store needs, and no
    others. Run as the owner. The same file works with ``psql -v app_role=<name>``."""
    if not app_role or "\x00" in app_role:
        raise ValueError("app_role must be a non-empty role name")
    quoted = '"' + app_role.replace('"', '""') + '"'
    async with pool.acquire() as conn, conn.transaction():
        for name in (
            APP_ROLE_GRANTS,
            DRAFT_GRANTS,
            GOLDEN_GRANTS,
            PUBLISH_GRANTS,
            TOOL_GRANTS,
            PLATFORM_GRANTS,
            CALIBRATION_GRANTS,
            DELIVERY_GRANTS,
            RETENTION_APP_GRANTS,
            SHADOW_GRANTS,
            ESCALATION_GRANTS,
            APPROVAL_GRANTS,
            CONTENT_GRANTS,
            NIGHTLY_GRANTS,
        ):
            sql = migration_sql(name)
            if _APP_ROLE_VARIABLE not in sql:
                raise RuntimeError(f"{name} does not use {_APP_ROLE_VARIABLE}")
            await conn.execute(sql.replace(_APP_ROLE_VARIABLE, quoted))


_RETENTION_VARIABLE = ':"retention_role"'


async def apply_retention_role_grants(pool: asyncpg.Pool, retention_role: str) -> None:
    """Give ``retention_role`` (an existing role, not the service's application role) the
    privileges of the M4-09 deletion job: EXECUTE on ``retention_delete_class_b`` and read
    access to the receipts, and nothing that deletes or inserts directly. It also gets the M4-05
    class D, M5-03 class C and M5-07 offboarding functions (EXECUTE) and the offboarding
    receipts (SELECT).
    Run as the owner."""
    if not retention_role or "\x00" in retention_role:
        raise ValueError("retention_role must be a non-empty role name")
    quoted = '"' + retention_role.replace('"', '""') + '"'
    policy = migration_sql(RETENTION_ROLE_POLICY)
    if _RETENTION_VARIABLE not in policy:
        raise RuntimeError(f"{RETENTION_ROLE_POLICY} does not use {_RETENTION_VARIABLE}")
    async with pool.acquire() as conn, conn.transaction():
        for name in (
            RETENTION_ROLE_GRANTS,
            ESCALATION_RETENTION_GRANTS,
            OFFBOARDING_ROLE_GRANTS,
            CONTENT_RETENTION_GRANTS,
        ):
            sql = migration_sql(name)
            if _RETENTION_VARIABLE not in sql:
                raise RuntimeError(f"{name} does not use {_RETENTION_VARIABLE}")
            await conn.execute(sql.replace(_RETENTION_VARIABLE, quoted))
        await conn.execute(policy.replace(_RETENTION_VARIABLE, quoted))


OPERATOR_POLICY = "007_rls_operator_policy.sql"
OPERATOR_POLICIES_LATER = "014_operator_policies.sql"
_OPERATOR_VARIABLE = ':"operator_role"'


async def apply_operator_policy(pool: asyncpg.Pool, operator_role: str) -> None:
    """Let ``operator_role`` (an existing, non-superuser role that also has the 002 grants) see
    and write every tenant's rows through row-level security. Run as the owner."""
    if not operator_role or "\x00" in operator_role:
        raise ValueError("operator_role must be a non-empty role name")
    sql = migration_sql(OPERATOR_POLICY)
    if _OPERATOR_VARIABLE not in sql:
        raise RuntimeError(f"{OPERATOR_POLICY} does not use {_OPERATOR_VARIABLE}")
    quoted = '"' + operator_role.replace('"', '""') + '"'
    later = []
    for name in (
        OPERATOR_POLICIES_LATER,
        ESCALATION_OPERATOR_POLICIES,
        APPROVAL_OPERATOR_POLICIES,
        CONTENT_OPERATOR_POLICIES,
        NIGHTLY_OPERATOR_POLICIES,
    ):
        more = migration_sql(name)
        if _OPERATOR_VARIABLE not in more:
            raise RuntimeError(f"{name} does not use {_OPERATOR_VARIABLE}")
        later.append(more)
    async with pool.acquire() as conn, conn.transaction():
        await conn.execute(sql.replace(_OPERATOR_VARIABLE, quoted))
        for more in later:
            await conn.execute(more.replace(_OPERATOR_VARIABLE, quoted))


@contextlib.asynccontextmanager
async def tenant_connection(
    pool: asyncpg.Pool, scope: TenantScope, operator_pool: asyncpg.Pool | None = None
) -> AsyncIterator[asyncpg.Connection]:
    """A connection in a transaction with ``app.tenant_id`` set to the scope's tenant for the
    transaction only (row-level security, 006 and 008). The setting comes from the scope alone
    and is parameterised, not interpolated.

    Isolation between checks relies on one of two things, and this asserts it: the setting is
    empty when a connection is acquired. asyncpg resets a connection's session state on
    release, and ``set_config(..., true)`` is transaction-local, so a custom ``reset`` or a
    transaction-mode pooler that keeps session state must keep using transaction-local
    settings only; a non-empty setting at acquire is refused."""
    if scope.operator:
        # Only the authorizer issues an operator scope, for an allowed cross-tenant access by a
        # platform operator. Without an operator pool it is refused, never served from the
        # tenant-scoped pool.
        if operator_pool is None:
            raise OperatorPoolUnavailableError()
        pool = operator_pool
    async with pool.acquire() as conn, conn.transaction():
        prior = await conn.fetchval(_SET_TENANT_SQL, scope.tenant_id)
        if prior:
            raise TenantSettingLeakError()
        yield conn


class PostgresPolicyStore:
    """The Postgres policy store. It has no tenant methods of its own: ``scoped(scope)`` returns
    a view for one verified tenant. Row-level security (006) is set from that scope
    only, and a view refuses any call whose ``tenant_id`` differs from it, so a tenant id that
    came from a request can't choose which rows the database shows."""

    def __init__(
        self,
        pool: asyncpg.Pool,
        *,
        catalog: Catalog | None,
        on_integrity_failure: AlertHook | None = None,
        operator_pool: asyncpg.Pool | None = None,
    ) -> None:
        """``catalog`` is required but may be None: a store with no catalog refuses every
        store, load and pointer move, because it can't verify a hash. The caller owns
        ``pool``, which should connect as the least-privilege application role, and
        ``operator_pool`` (the operator role, used only for an operator scope)."""
        self._pool = pool
        self._operator_pool = operator_pool
        self._verifier = BundleVerifier(catalog, on_integrity_failure)

    def scoped(self, scope: TenantScope) -> PolicyStore:
        if not isinstance(scope, TenantScope):
            raise TypeError("scoped() takes a TenantScope")
        return _ScopedPostgresStore(self._pool, self._verifier, scope, self._operator_pool)


class PostgresCatalogReferences:
    """How many stored bundles, across all tenants, use a catalog item (M2-03). A platform-wide
    question, so it needs the operator role (007 and 014 give it every tenant's rows) and never
    the tenant-scoped pool: with no ``operator_pool`` it raises, which refuses the catalog
    removal it guards. It returns a count, not rows."""

    def __init__(self, operator_pool: asyncpg.Pool | None) -> None:
        self._operator_pool = operator_pool

    async def count(self, ref: str) -> int:
        if self._operator_pool is None:
            raise OperatorPoolUnavailableError()
        if ref.startswith("template:"):
            sql = (
                "SELECT count(*) FROM policy_bundle_versions WHERE EXISTS ("
                "SELECT 1 FROM jsonb_array_elements("
                "CASE WHEN jsonb_typeof(document::jsonb -> 'rules') = 'array' "
                "THEN document::jsonb -> 'rules' ELSE '[]'::jsonb END) r "
                "WHERE r ->> 'origin' = $1)"
            )
        else:
            sql = (
                "SELECT count(*) FROM policy_bundle_versions WHERE "
                "jsonb_typeof(document::jsonb -> 'extends') = 'array' "
                "AND (document::jsonb -> 'extends') @> to_jsonb($1::text)"
            )
        async with self._operator_pool.acquire() as conn:
            return int(await conn.fetchval(sql, ref))

    async def active_pack_refs(self) -> frozenset[str]:
        """The ``domain/<pack>@<n>`` references named by every tenant's **active** version and
        its **candidate**: what a deployment's ``catalog.pack_files`` must still hold.
        Needs the operator role, like :meth:`count`; returns references, never a document."""
        if self._operator_pool is None:
            raise OperatorPoolUnavailableError()
        sql = (
            "SELECT DISTINCT e FROM ("
            " SELECT v.document FROM policy_bundle_versions v"
            "  JOIN policy_active_versions a ON a.tenant_id = v.tenant_id AND a.version = v.version"
            " UNION"
            " SELECT v.document FROM policy_bundle_versions v"
            "  JOIN tenant_candidates c ON c.tenant_id = v.tenant_id AND c.version = v.version"
            ") d, jsonb_array_elements_text(CASE WHEN jsonb_typeof(d.document::jsonb -> 'extends')"
            " = 'array' THEN d.document::jsonb -> 'extends' ELSE '[]'::jsonb END) AS e "
            "WHERE e LIKE 'domain/%'"
        )
        async with self._operator_pool.acquire() as conn:
            return frozenset(r["e"] for r in await conn.fetch(sql))


class _ScopedPostgresStore:
    """The policy store for one tenant scope. Every operation runs in a transaction with
    ``app.tenant_id`` set from the scope for that transaction only."""

    def __init__(
        self,
        pool: asyncpg.Pool,
        verifier: BundleVerifier,
        scope: TenantScope,
        operator_pool: asyncpg.Pool | None = None,
    ) -> None:
        self._pool = pool
        self._operator_pool = operator_pool
        self._verifier = verifier
        self._scope = scope

    def _check(self, tenant_id: str) -> None:
        if tenant_id != self._scope.tenant_id:
            raise ScopeMismatchError()

    @contextlib.asynccontextmanager
    async def _scoped(self, tenant_id: str) -> AsyncIterator[asyncpg.Connection]:
        """A connection in a transaction scoped to the scope's tenant (:func:`tenant_connection`);
        ``tenant_id``, the argument the caller filters on, must be that same tenant."""
        self._check(tenant_id)
        async with tenant_connection(self._pool, self._scope, self._operator_pool) as conn:
            yield conn

    async def put_version(
        self, tenant_id: str, bundle: ParsedBundle, *, bundle_hash: str
    ) -> VersionInfo:
        self._check(tenant_id)
        self._verifier.check_new(tenant_id, bundle, bundle_hash)
        version = bundle.bundle.version
        async with self._scoped(tenant_id) as conn:
            created_at = await conn.fetchval(
                "INSERT INTO policy_bundle_versions (tenant_id, version, document, bundle_hash) "
                "VALUES ($1, $2, $3, $4) "
                "ON CONFLICT (tenant_id, version) DO NOTHING "
                "RETURNING created_at",
                tenant_id,
                version,
                bundle.canonical_document.decode("utf-8"),
                bundle_hash,
            )
            if created_at is not None:
                return VersionInfo(tenant_id, version, bundle_hash, created_at)
            # The version exists and can't change or disappear. The hash covers the whole
            # document, and check_new tied this hash to this document, so equal hashes mean
            # equal content.
            row = await conn.fetchrow(
                "SELECT bundle_hash, created_at FROM policy_bundle_versions "
                "WHERE tenant_id = $1 AND version = $2",
                tenant_id,
                version,
            )
        if row is None or row["bundle_hash"] != bundle_hash:
            raise VersionConflictError(tenant_id, version)
        return VersionInfo(tenant_id, version, row["bundle_hash"], row["created_at"])

    async def get_version(self, tenant_id: str, version: int) -> StoredVersion:
        self._check(tenant_id)
        row = None
        if 1 <= version <= MAX_VERSION:
            async with self._scoped(tenant_id) as conn:
                row = await conn.fetchrow(
                    "SELECT document, bundle_hash, created_at "
                    "FROM policy_bundle_versions WHERE tenant_id = $1 AND version = $2",
                    tenant_id,
                    version,
                )
        if row is None:
            raise VersionNotFoundError(tenant_id, version)
        return self._verified(tenant_id, version, row)

    async def list_versions(self, tenant_id: str) -> list[VersionInfo]:
        async with self._scoped(tenant_id) as conn:
            rows = await conn.fetch(
                "SELECT version, bundle_hash, created_at FROM policy_bundle_versions "
                "WHERE tenant_id = $1 ORDER BY version",
                tenant_id,
            )
        return [
            VersionInfo(tenant_id, r["version"], r["bundle_hash"], r["created_at"]) for r in rows
        ]

    async def get_active_version(self, tenant_id: str) -> int | None:
        async with self._scoped(tenant_id) as conn:
            return await conn.fetchval(
                "SELECT version FROM policy_active_versions WHERE tenant_id = $1", tenant_id
            )

    async def set_active_version(
        self,
        tenant_id: str,
        version: int,
        *,
        expected_current: int | _Unchecked | None = UNCHECKED,
    ) -> None:
        self._check(tenant_id)
        # Verify first. A version can't change or disappear once stored, so there is
        # nothing to race between this check and the write below.
        await self.get_version(tenant_id, version)
        if expected_current is UNCHECKED:
            async with self._scoped(tenant_id) as conn:
                await conn.execute(
                    "INSERT INTO policy_active_versions (tenant_id, version) VALUES ($1, $2) "
                    "ON CONFLICT (tenant_id) DO UPDATE "
                    "SET version = EXCLUDED.version, updated_at = now()",
                    tenant_id,
                    version,
                )
            return
        # Compare-and-set. Each is one statement, so the comparison and the write are
        # atomic: a concurrent mover waits on the row and then sees the new value.
        if expected_current is None:
            async with self._scoped(tenant_id) as conn:
                status = await conn.execute(
                    "INSERT INTO policy_active_versions (tenant_id, version) VALUES ($1, $2) "
                    "ON CONFLICT (tenant_id) DO NOTHING",
                    tenant_id,
                    version,
                )
            moved = status == "INSERT 0 1"
        else:
            moved = False
            if 1 <= expected_current <= MAX_VERSION:
                async with self._scoped(tenant_id) as conn:
                    status = await conn.execute(
                        "UPDATE policy_active_versions SET version = $2, updated_at = now() "
                        "WHERE tenant_id = $1 AND version = $3",
                        tenant_id,
                        version,
                        expected_current,
                    )
                moved = status == "UPDATE 1"
        if not moved:
            actual = await self.get_active_version(tenant_id)
            raise ActivePointerConflictError(tenant_id, expected_current, actual)

    async def load_active(self, tenant_id: str) -> StoredVersion | None:
        # One statement, so the pointer and the version it names are read together.
        async with self._scoped(tenant_id) as conn:
            row = await conn.fetchrow(
                "SELECT v.version, v.document, v.bundle_hash, v.created_at "
                "FROM policy_active_versions a "
                "JOIN policy_bundle_versions v "
                "ON v.tenant_id = a.tenant_id AND v.version = a.version "
                "WHERE a.tenant_id = $1",
                tenant_id,
            )
        return None if row is None else self._verified(tenant_id, row["version"], row)

    def _verified(self, tenant_id: str, version: int, row: asyncpg.Record) -> StoredVersion:
        parsed = self._verifier.verify_stored(
            tenant_id, version, row["document"], row["bundle_hash"]
        )
        return StoredVersion(tenant_id, version, parsed, row["bundle_hash"], row["created_at"])


_APP_ROLE_CHECK_SQL = """
SELECT
  EXISTS (SELECT 1 FROM pg_roles r WHERE r.rolsuper AND pg_has_role(current_user, r.oid, 'USAGE'))
    AS superuser,
  EXISTS (SELECT 1 FROM pg_roles r
          WHERE r.rolbypassrls AND pg_has_role(current_user, r.oid, 'USAGE')) AS bypassrls,
  EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
          WHERE c.relname IN ('policy_bundle_versions', 'policy_active_versions')
            AND n.nspname = current_schema()
            AND pg_has_role(current_user, c.relowner, 'USAGE')) AS owns_tables,
  COALESCE((SELECT pg_has_role(current_user, r.oid, 'MEMBER') FROM pg_roles r
            WHERE r.rolname = $1), false) AS operator_member
"""


async def app_role_problems(pool: asyncpg.Pool, *, operator_role: str | None = None) -> list[str]:
    """Why the connected role would not be held to row-level security, as fixed
    sentences without names: it is (or inherits) a superuser or a BYPASSRLS role, it owns (or
    inherits ownership of) a policy table (the table owner is exempt from a non-forced policy,
    and can ``ALTER`` it), or it is a member of ``operator_role``. Empty means the role is
    subject to the policies. The check inspects membership with inheritance, as Postgres
    applies it."""
    async with pool.acquire() as conn:
        row = await conn.fetchrow(_APP_ROLE_CHECK_SQL, operator_role or "")
    problems = []
    if row["superuser"]:
        problems.append("the application role is (or inherits) a superuser; RLS does not apply")
    if row["bypassrls"]:
        problems.append("the application role has (or inherits) BYPASSRLS; RLS does not apply")
    if row["owns_tables"]:
        problems.append("the application role owns (or inherits ownership of) a policy table")
    if row["operator_member"]:
        problems.append(
            "the application role is a member of the operator role; it sees all tenants"
        )
    return problems


DIRECTORY_GRANTS = "005_directory_grants.sql"
_DIRECTORY_VARIABLES = (':"reader_role"', ':"writer_role"')


def _quote(role: str) -> str:
    if not role or "\x00" in role:
        raise ValueError("a role must be a non-empty role name")
    return '"' + role.replace('"', '""') + '"'


async def apply_directory_grants(pool: asyncpg.Pool, reader_role: str, writer_role: str) -> None:
    """Give the tenant directory's two service roles exactly their privileges (see
    ``005_directory_grants.sql``). Run as the owner. The roles must exist and must differ."""
    if reader_role == writer_role:
        raise ValueError("the reader and writer roles must differ")
    sql = migration_sql(DIRECTORY_GRANTS)
    for variable in _DIRECTORY_VARIABLES:
        if variable not in sql:
            raise RuntimeError(f"{DIRECTORY_GRANTS} does not use {variable}")
    sql = sql.replace(_DIRECTORY_VARIABLES[0], _quote(reader_role))
    sql = sql.replace(_DIRECTORY_VARIABLES[1], _quote(writer_role))
    async with pool.acquire() as conn, conn.transaction():
        await conn.execute(sql)


_TENANT_COLUMNS = (
    "tenant_id, slug, domain, tier, flags, required_packs, baa, status, version, "
    "identifier_patterns, project, created_at, updated_at"
)


def _tenant_from(row: asyncpg.Record) -> TenantRecord:
    return TenantRecord(
        tenant_id=row["tenant_id"], slug=row["slug"], domain=row["domain"], tier=row["tier"],
        flags=frozenset(row["flags"]), required_packs=frozenset(row["required_packs"]),
        baa=row["baa"], status=row["status"], version=row["version"],
        identifier_patterns=tuple(row["identifier_patterns"]), project=row["project"],
        created_at=row["created_at"], updated_at=row["updated_at"],
    )  # fmt: skip


class PostgresDirectoryStore:
    """The tenant directory over Postgres (M2-01). A write and its audit event share one
    transaction. Connect the Guard Service as the reader role (``get`` and ``list`` only) and the
    platform API as the writer role; neither can delete."""

    def __init__(self, pool: asyncpg.Pool) -> None:
        self._pool = pool

    async def insert(self, record: TenantRecord, event: DirectoryAuditEvent) -> TenantRecord:
        try:
            async with self._pool.acquire() as conn, conn.transaction():
                row = await conn.fetchrow(
                    f"INSERT INTO tenants (tenant_id, slug, domain, tier, flags, required_packs, "
                    f"baa, status, version, identifier_patterns, project) "
                    f"VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) "
                    f"RETURNING {_TENANT_COLUMNS}",
                    record.tenant_id, record.slug, record.domain, record.tier,
                    sorted(record.flags), sorted(record.required_packs), record.baa,
                    record.status, record.version, list(record.identifier_patterns),
                    record.project,
                )  # fmt: skip
                await self._audit(conn, event)
        except asyncpg.UniqueViolationError:
            raise TenantExists from None
        return _tenant_from(row)

    async def replace(
        self, record: TenantRecord, expected_version: int, event: DirectoryAuditEvent
    ) -> TenantRecord:
        if record.version != expected_version + 1:
            raise VersionConflict
        try:
            async with self._pool.acquire() as conn, conn.transaction():
                row = await conn.fetchrow(
                    "UPDATE tenants SET slug = $2, domain = $3, tier = $4, flags = $5, "
                    "required_packs = $6, baa = $7, status = $8, version = $9, "
                    "identifier_patterns = $11, project = $12, updated_at = now() "
                    f"WHERE tenant_id = $1 AND version = $10 RETURNING {_TENANT_COLUMNS}",
                    record.tenant_id, record.slug, record.domain, record.tier,
                    sorted(record.flags), sorted(record.required_packs), record.baa,
                    record.status, record.version, expected_version,
                    list(record.identifier_patterns), record.project,
                )  # fmt: skip
                if row is None:
                    exists = await conn.fetchval(
                        "SELECT 1 FROM tenants WHERE tenant_id = $1", record.tenant_id
                    )
                    raise VersionConflict if exists else TenantNotFound
                await self._audit(conn, event)
        except asyncpg.UniqueViolationError:
            raise TenantExists from None
        return _tenant_from(row)

    async def get(self, tenant_id: str) -> TenantRecord | None:
        row = await self._pool.fetchrow(
            f"SELECT {_TENANT_COLUMNS} FROM tenants WHERE tenant_id = $1", tenant_id
        )
        return None if row is None else _tenant_from(row)

    async def list(self) -> list[TenantRecord]:
        rows = await self._pool.fetch(f"SELECT {_TENANT_COLUMNS} FROM tenants ORDER BY tenant_id")
        return [_tenant_from(r) for r in rows]

    async def audit_events(self, tenant_id: str) -> list[DirectoryAuditEvent]:
        rows = await self._pool.fetch(
            "SELECT tenant_id, version, action, actor, at, before, after "
            "FROM tenant_directory_audit WHERE tenant_id = $1 ORDER BY id",
            tenant_id,
        )
        return [
            DirectoryAuditEvent(
                tenant_id=r["tenant_id"], version=r["version"], action=r["action"],
                actor=r["actor"], at=r["at"].timestamp(),
                before=None if r["before"] is None else json.loads(r["before"]),
                after=json.loads(r["after"]),
            )
            for r in rows
        ]  # fmt: skip

    @staticmethod
    async def _audit(conn: asyncpg.Connection, event: DirectoryAuditEvent) -> None:
        await conn.execute(
            "INSERT INTO tenant_directory_audit (tenant_id, version, action, actor, at, before, "
            "after) VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7::jsonb)",
            event.tenant_id, event.version, event.action, event.actor,
            datetime.fromtimestamp(event.at, UTC),
            None if event.before is None else json.dumps(event.before, sort_keys=True),
            json.dumps(event.after, sort_keys=True),
        )  # fmt: skip


class PostgresDraftStore:
    """The draft store on Postgres (M2-02). Like the policy store it has no tenant methods of
    its own: ``scoped(scope)`` returns a view whose every operation runs in a transaction with
    ``app.tenant_id`` set from the scope (row-level security, 008). A write and its class A
    audit row are one transaction, and the audit table refuses UPDATE, DELETE and TRUNCATE."""

    def __init__(self, pool: asyncpg.Pool, operator_pool: asyncpg.Pool | None = None) -> None:
        self._pool = pool
        self._operator_pool = operator_pool

    def scoped(self, scope: TenantScope) -> DraftStore:
        if not isinstance(scope, TenantScope):
            raise TypeError("scoped() takes a TenantScope")
        return _ScopedPostgresDrafts(self._pool, scope, self._operator_pool)


def _draft_from(row: asyncpg.Record, *, created: bool = False) -> StoredDraft:
    return StoredDraft(
        row["tenant_id"], row["document"].encode("utf-8"), row["etag"], row["updated_at"],
        row["updated_by"], created=created,
    )  # fmt: skip


class _ScopedPostgresDrafts:
    def __init__(
        self, pool: asyncpg.Pool, scope: TenantScope, operator_pool: asyncpg.Pool | None = None
    ) -> None:
        self._pool = pool
        self._operator_pool = operator_pool
        self._scope = scope

    def _check(self, tenant_id: str) -> None:
        if tenant_id != self._scope.tenant_id:
            raise ScopeMismatchError()

    async def get(self, tenant_id: str) -> StoredDraft | None:
        self._check(tenant_id)
        async with tenant_connection(self._pool, self._scope, self._operator_pool) as conn:
            row = await conn.fetchrow(
                "SELECT tenant_id, document, etag, updated_at, updated_by "
                "FROM tenant_drafts WHERE tenant_id = $1",
                tenant_id,
            )
        return None if row is None else _draft_from(row)

    async def replace(
        self,
        tenant_id: str,
        document: bytes,
        *,
        expected_etag: str | None,
        event: DraftAuditEvent,
    ) -> StoredDraft:
        self._check(tenant_id)
        if event.tenant_id != tenant_id:
            raise ScopeMismatchError()
        etag = '"' + event.resulting_hash + '"'
        async with tenant_connection(self._pool, self._scope, self._operator_pool) as conn:
            current = await conn.fetchval(
                "SELECT etag FROM tenant_drafts WHERE tenant_id = $1 FOR UPDATE", tenant_id
            )
            if current != expected_etag:
                raise DraftConflictError(current)
            if current is None:
                row = await conn.fetchrow(
                    "INSERT INTO tenant_drafts (tenant_id, document, etag, updated_by) "
                    "VALUES ($1, $2, $3, $4) ON CONFLICT (tenant_id) DO NOTHING "
                    "RETURNING tenant_id, document, etag, updated_at, updated_by",
                    tenant_id, document.decode("utf-8"), etag, event.actor,
                )  # fmt: skip
                if (
                    row is None
                ):  # another request created the first draft between our read and write
                    raise DraftConflictError(
                        await conn.fetchval(
                            "SELECT etag FROM tenant_drafts WHERE tenant_id = $1", tenant_id
                        )
                    )
            else:
                row = await conn.fetchrow(
                    "UPDATE tenant_drafts SET document = $2, etag = $3, updated_at = now(), "
                    "updated_by = $4 WHERE tenant_id = $1 "
                    "RETURNING tenant_id, document, etag, updated_at, updated_by",
                    tenant_id, document.decode("utf-8"), etag, event.actor,
                )  # fmt: skip
            await conn.execute(
                "INSERT INTO tenant_draft_audit (tenant_id, at, actor, cross_tenant, operator, "
                "action, before_hash, resulting_hash, diff, detail) "
                "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb, $10::jsonb)",
                tenant_id, event.at, event.actor, event.cross_tenant, event.operator,
                event.action, event.before_hash, event.resulting_hash,
                json.dumps([d.model_dump() for d in event.diff]),
                None if event.detail is None else json.dumps(event.detail, sort_keys=True),
            )  # fmt: skip
        return _draft_from(row, created=current is None)

    async def audit_events(self, tenant_id: str) -> list[DraftAuditEvent]:
        self._check(tenant_id)
        async with tenant_connection(self._pool, self._scope, self._operator_pool) as conn:
            rows = await conn.fetch(
                "SELECT tenant_id, at, actor, cross_tenant, operator, action, before_hash, "
                "resulting_hash, diff, detail "
                "FROM tenant_draft_audit WHERE tenant_id = $1 ORDER BY id",
                tenant_id,
            )
        return [
            DraftAuditEvent(
                r["at"], r["actor"], r["tenant_id"], r["action"], r["before_hash"],
                r["resulting_hash"], tuple(DiffEntry(**d) for d in json.loads(r["diff"])),
                r["cross_tenant"], r["operator"],
                None if r["detail"] is None else json.loads(r["detail"]),
            )
            for r in rows
        ]  # fmt: skip


class PostgresPlatformStore:
    """The platform's floor releases, approvals, minimum floor and class A trail (M2-09, 017).
    No tenant column and no row-level security: only the platform routes reach it. Every write
    is one transaction with its audit rows."""

    def __init__(self, pool: asyncpg.Pool) -> None:
        self._pool = pool

    @staticmethod
    async def _audit(conn: Any, e: PlatformEvent) -> None:
        await conn.execute(
            "INSERT INTO platform_audit (at, actor, action, floor_version, tenant_id, detail) "
            "VALUES ($1, $2, $3, $4, $5, $6::jsonb)",
            e.at, e.actor, e.action, e.floor_version, e.tenant_id, json.dumps(e.detail),
        )  # fmt: skip

    @staticmethod
    def _release(row: Any, approvals: list[Any]) -> FloorRelease:
        return FloorRelease(
            floor_version=row["floor_version"], floor_hash=row["floor_hash"],
            evidence=json.loads(row["evidence"]), proposed_by=row["proposed_by"],
            proposed_at=row["proposed_at"],
            approvals=tuple(Approval(a["operator"], a["urgent"], a["at"]) for a in approvals),
            released_at=row["released_at"], security_urgent=row["security_urgent"],
            halted=row["halted"],
        )  # fmt: skip

    async def release(self, version: int) -> FloorRelease | None:
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM platform_floor_releases WHERE floor_version = $1", version
            )
            if row is None:
                return None
            approvals = await conn.fetch(
                "SELECT operator, urgent, at FROM platform_floor_approvals "
                "WHERE floor_version = $1 ORDER BY at, operator",
                version,
            )
        return self._release(row, approvals)

    async def releases(self) -> list[FloorRelease]:
        async with self._pool.acquire() as conn:
            rows = await conn.fetch("SELECT * FROM platform_floor_releases ORDER BY floor_version")
            approvals = await conn.fetch(
                "SELECT floor_version, operator, urgent, at FROM platform_floor_approvals "
                "ORDER BY at, operator"
            )
        return [
            self._release(r, [a for a in approvals if a["floor_version"] == r["floor_version"]])
            for r in rows
        ]

    async def propose(self, release: FloorRelease, event: PlatformEvent) -> None:
        async with self._pool.acquire() as conn, conn.transaction():
            status = await conn.execute(
                "INSERT INTO platform_floor_releases (floor_version, floor_hash, evidence, "
                "proposed_by, proposed_at) VALUES ($1, $2, $3::jsonb, $4, $5) "
                "ON CONFLICT DO NOTHING",
                release.floor_version, release.floor_hash, json.dumps(release.evidence),
                release.proposed_by, release.proposed_at,
            )  # fmt: skip
            if status != "INSERT 0 1":
                raise ReleaseExistsError()
            for a in release.approvals:
                await conn.execute(
                    "INSERT INTO platform_floor_approvals (floor_version, operator, urgent, at) "
                    "VALUES ($1, $2, $3, $4)",
                    release.floor_version, a.operator, a.urgent, a.at,
                )  # fmt: skip
            await self._audit(conn, event)

    async def approve(
        self, version: int, approval: Approval, event: PlatformEvent, released: PlatformEvent
    ) -> FloorRelease:
        async with self._pool.acquire() as conn, conn.transaction():
            row = await conn.fetchrow(
                "SELECT * FROM platform_floor_releases WHERE floor_version = $1 FOR UPDATE",
                version,
            )
            if row is None:
                raise ReleaseNotFoundError()
            if row["released_at"] is not None:
                raise AlreadyReleasedError()
            status = await conn.execute(
                "INSERT INTO platform_floor_approvals (floor_version, operator, urgent, at) "
                "VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
                version, approval.operator, approval.urgent, approval.at,
            )  # fmt: skip
            if status != "INSERT 0 1":
                raise SecondOperatorRequiredError()
            rows = await conn.fetch(
                "SELECT operator, urgent, at FROM platform_floor_approvals "
                "WHERE floor_version = $1 ORDER BY at, operator",
                version,
            )
            approvals = tuple(Approval(r["operator"], r["urgent"], r["at"]) for r in rows)
            done, urgent = settle(approvals)
            if done:
                await conn.execute(
                    "UPDATE platform_floor_releases SET released_at = $2, security_urgent = $3 "
                    "WHERE floor_version = $1",
                    version, approval.at, urgent,
                )  # fmt: skip
            await self._audit(conn, event)
            if done:
                await self._audit(conn, released)
            fresh = await conn.fetchrow(
                "SELECT * FROM platform_floor_releases WHERE floor_version = $1", version
            )
        return self._release(fresh, rows)

    async def set_halted(self, version: int, halted: bool, event: PlatformEvent) -> None:
        async with self._pool.acquire() as conn, conn.transaction():
            status = await conn.execute(
                "UPDATE platform_floor_releases SET halted = $2 WHERE floor_version = $1",
                version, halted,
            )  # fmt: skip
            if status != "UPDATE 1":
                raise ReleaseNotFoundError()
            await self._audit(conn, event)

    async def minimum(self) -> int | None:
        async with self._pool.acquire() as conn:
            return await conn.fetchval("SELECT minimum_floor_version FROM platform_floor_state")  # type: ignore[no-any-return]

    async def set_minimum(
        self, value: int, *, expected: int | None, by: str, at: datetime, event: PlatformEvent
    ) -> None:
        async with self._pool.acquire() as conn, conn.transaction():
            if expected is None:
                status = await conn.execute(
                    "INSERT INTO platform_floor_state (minimum_floor_version, set_by, at) "
                    "VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
                    value, by, at,
                )  # fmt: skip
                moved = status == "INSERT 0 1"
            else:
                status = await conn.execute(
                    "UPDATE platform_floor_state SET minimum_floor_version = $1, set_by = $2, "
                    "at = $3 WHERE minimum_floor_version = $4 AND $1 > $4",
                    value, by, at, expected,
                )  # fmt: skip
                moved = status == "UPDATE 1"
            if not moved:
                raise PlatformConflictError()
            await self._audit(conn, event)

    async def record(self, event: PlatformEvent) -> None:
        async with self._pool.acquire() as conn:
            await self._audit(conn, event)

    async def events(self) -> list[PlatformEvent]:
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT at, actor, action, floor_version, tenant_id, detail "
                "FROM platform_audit ORDER BY id"
            )
        return [
            PlatformEvent(
                r["at"], r["actor"], r["action"], r["floor_version"], r["tenant_id"],
                json.loads(r["detail"]),
            )
            for r in rows
        ]  # fmt: skip


class PostgresToolStore:
    """The tool registry on Postgres (M2-03, 015): ``scoped(scope)`` returns a view whose every
    operation runs in a transaction with ``app.tenant_id`` set from the scope. An entry and its
    class A row are one transaction, and the class A table refuses UPDATE and DELETE."""

    def __init__(self, pool: asyncpg.Pool, operator_pool: asyncpg.Pool | None = None) -> None:
        self._pool = pool
        self._operator_pool = operator_pool

    def scoped(self, scope: TenantScope) -> ToolStore:
        if not isinstance(scope, TenantScope):
            raise TypeError("scoped() takes a TenantScope")
        return _ScopedPostgresTools(self._pool, scope, self._operator_pool)


_TOOL_COLUMNS = (
    "name, description, read_only, status, hold_reason, description_hash, submitted_by, "
    "submitted_at, reviewed_by, reviewed_at, version, pending_description, pending_read_only, "
    "pending_hash, pending_reason, pending_by, pending_at"
)


def _tool_entry(r: Any) -> ToolEntry:
    return ToolEntry(
        name=r["name"], description=r["description"], read_only=r["read_only"],
        status=r["status"], hold_reason=r["hold_reason"], description_hash=r["description_hash"],
        submitted_by=r["submitted_by"], submitted_at=r["submitted_at"],
        reviewed_by=r["reviewed_by"], reviewed_at=r["reviewed_at"], version=r["version"],
        pending=None
        if r["pending_description"] is None
        else PendingEdit(
            r["pending_description"], r["pending_read_only"], r["pending_hash"],
            r["pending_reason"], r["pending_by"], r["pending_at"],
        ),
    )  # fmt: skip


class _ScopedPostgresTools:
    def __init__(
        self, pool: asyncpg.Pool, scope: TenantScope, operator_pool: asyncpg.Pool | None = None
    ) -> None:
        self._pool = pool
        self._scope = scope
        self._operator_pool = operator_pool

    def _check(self, tenant_id: str) -> None:
        if tenant_id != self._scope.tenant_id:
            raise ScopeMismatchError()

    def _conn(self) -> Any:
        return tenant_connection(self._pool, self._scope, self._operator_pool)

    async def get(self, tenant_id: str, name: str) -> ToolEntry | None:
        self._check(tenant_id)
        async with self._conn() as conn:
            row = await conn.fetchrow(
                f"SELECT {_TOOL_COLUMNS} FROM tenant_tools WHERE tenant_id = $1 AND name = $2",
                tenant_id, name,
            )  # fmt: skip
        return None if row is None else _tool_entry(row)

    async def list(self, tenant_id: str) -> list[ToolEntry]:
        self._check(tenant_id)
        async with self._conn() as conn:
            rows = await conn.fetch(
                f"SELECT {_TOOL_COLUMNS} FROM tenant_tools WHERE tenant_id = $1 ORDER BY name",
                tenant_id,
            )
        return [_tool_entry(r) for r in rows]

    @staticmethod
    async def _audit(conn: Any, tenant_id: str, e: ToolEvent) -> None:
        if e.tenant_id != tenant_id:
            raise ScopeMismatchError()
        await conn.execute(
            "INSERT INTO tenant_tool_audit (tenant_id, at, actor, cross_tenant, operator, action, "
            "name, description_hash, status, reason, fired) "
            "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::jsonb)",
            tenant_id, e.at, e.actor, e.cross_tenant, e.operator, e.action, e.name,
            e.description_hash, e.status, e.reason,
            json.dumps([{"rule": k, "action": a} for k, a in e.fired]),
        )  # fmt: skip

    async def save(
        self, tenant_id: str, entry: ToolEntry, event: ToolEvent, *, expected_version: int | None
    ) -> None:
        self._check(tenant_id)
        values = (
            tenant_id, entry.name, entry.description, entry.read_only, entry.status,
            entry.hold_reason, entry.description_hash, entry.submitted_by, entry.submitted_at,
            entry.reviewed_by, entry.reviewed_at, entry.version,
            *(
                (None,) * 6
                if entry.pending is None
                else (
                    entry.pending.description, entry.pending.read_only,
                    entry.pending.description_hash, entry.pending.hold_reason,
                    entry.pending.submitted_by, entry.pending.submitted_at,
                )
            ),
        )  # fmt: skip
        async with self._conn() as conn:
            if expected_version is None:
                inserted = await conn.execute(
                    "INSERT INTO tenant_tools (tenant_id, name, description, read_only, status, "
                    "hold_reason, description_hash, submitted_by, submitted_at, reviewed_by, "
                    "reviewed_at, version, pending_description, pending_read_only, pending_hash, "
                    "pending_reason, pending_by, pending_at) "
                    "VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18) "
                    "ON CONFLICT DO NOTHING",
                    *values,
                )
                done = inserted.endswith(" 1")
            else:
                updated = await conn.execute(
                    "UPDATE tenant_tools SET description=$3, read_only=$4, status=$5, "
                    "hold_reason=$6, description_hash=$7, submitted_by=$8, submitted_at=$9, "
                    "reviewed_by=$10, reviewed_at=$11, version=$12, pending_description=$13, "
                    "pending_read_only=$14, pending_hash=$15, pending_reason=$16, "
                    "pending_by=$17, pending_at=$18 "
                    "WHERE tenant_id=$1 AND name=$2 AND version=$19",
                    *values, expected_version,
                )  # fmt: skip
                done = updated.endswith(" 1")
            if not done:
                raise ToolConflictError("the tool changed")
            await self._audit(conn, tenant_id, event)

    async def delete(
        self, tenant_id: str, name: str, event: ToolEvent, *, expected_version: int
    ) -> None:
        self._check(tenant_id)
        async with self._conn() as conn:
            deleted = await conn.execute(
                "DELETE FROM tenant_tools WHERE tenant_id=$1 AND name=$2 AND version=$3",
                tenant_id, name, expected_version,
            )  # fmt: skip
            if not deleted.endswith(" 1"):
                raise ToolConflictError("the tool changed")
            await self._audit(conn, tenant_id, event)

    async def record(self, tenant_id: str, event: ToolEvent) -> None:
        self._check(tenant_id)
        async with self._conn() as conn:
            await self._audit(conn, tenant_id, event)

    async def events(self, tenant_id: str) -> list[ToolEvent]:
        self._check(tenant_id)
        async with self._conn() as conn:
            rows = await conn.fetch(
                "SELECT at, actor, tenant_id, action, name, description_hash, status, reason, "
                "fired, cross_tenant, operator FROM tenant_tool_audit WHERE tenant_id = $1 "
                "ORDER BY id",
                tenant_id,
            )
        return [
            ToolEvent(
                at=r["at"], actor=r["actor"], tenant_id=r["tenant_id"], action=r["action"],
                name=r["name"], description_hash=r["description_hash"], status=r["status"],
                reason=r["reason"],
                fired=tuple((f["rule"], f["action"]) for f in json.loads(r["fired"])),
                cross_tenant=r["cross_tenant"], operator=r["operator"],
            )
            for r in rows
        ]  # fmt: skip


class PostgresShadowStats:
    """The shadow agreement counters on Postgres (M4-03, 028): a :class:`ShadowSink` that
    buffers in memory (``record`` is called on the check path and never touches the database)
    and a :class:`ShadowReader` that flushes first. :meth:`flush` adds the buffered counts to
    the tenant's rows under its scope (row-level security). Counts only, never probabilities."""

    def __init__(self, pool: asyncpg.Pool, operator_pool: asyncpg.Pool | None = None) -> None:
        self._pool = pool
        self._operator_pool = operator_pool
        self._buffer: dict[tuple[str, int, int], tuple[TenantScope, Tally]] = {}
        self._flushing = asyncio.Lock()

    def record(self, observation: ShadowObservation) -> None:
        if observation.scope is None:
            return  # nothing to write it under
        key = (observation.tenant_id, observation.active_version, observation.candidate_version)
        _, tally = self._buffer.setdefault(key, (observation.scope, Tally()))
        apply(tally, observation)

    async def flush(self) -> None:
        """Write what has been counted since the last flush. A failure puts it back."""
        async with self._flushing:
            taken, self._buffer = self._buffer, {}
            failed: dict[tuple[str, int, int], tuple[TenantScope, Tally]] = {}
            for (tenant_id, active, candidate), (scope, tally) in taken.items():
                try:
                    async with tenant_connection(self._pool, scope, self._operator_pool) as conn:
                        await conn.executemany(
                            _SHADOW_UPSERT,
                            [(tenant_id, active, candidate, *row) for row in _shadow_rows(tally)],
                        )
                except Exception:
                    logger.exception("shadow counts could not be written; kept for the next try")
                    failed[(tenant_id, active, candidate)] = (scope, tally)
            for key, (scope, tally) in failed.items():  # merge back with anything newer
                mine = self._buffer.get(key)
                self._buffer[key] = (scope, merge([tally, mine[1]]) if mine else tally)

    async def tally(self, scope: TenantScope, active_version: int, candidate_version: int) -> Tally:
        await self.flush()
        async with tenant_connection(self._pool, scope, self._operator_pool) as conn:
            rows = await conn.fetch(
                "SELECT rule_key, layer, n, agree, candidate_stricter, candidate_looser, "
                "only_active, only_candidate, checks, incomparable FROM tenant_shadow_agreement "
                "WHERE tenant_id = $1 AND active_version = $2 AND candidate_version = $3",
                scope.tenant_id, active_version, candidate_version,
            )  # fmt: skip
        tally = Tally()
        for r in rows:
            if r["rule_key"] == _SUMMARY_KEY:
                tally.checks, tally.incomparable = r["checks"], r["incomparable"]
                continue
            counts = Counts(
                layer=r["layer"], n=r["n"], agree=r["agree"],
                candidate_stricter=r["candidate_stricter"], candidate_looser=r["candidate_looser"],
                only_active=r["only_active"], only_candidate=r["only_candidate"],
            )  # fmt: skip
            if r["rule_key"] == DECISION_KEY:
                tally.decision = counts
            else:
                tally.rules[r["rule_key"]] = counts
        return tally


_SUMMARY_KEY = "*summary*"
_SHADOW_UPSERT = (
    "INSERT INTO tenant_shadow_agreement (tenant_id, active_version, candidate_version, "
    "rule_key, layer, n, agree, candidate_stricter, candidate_looser, only_active, "
    "only_candidate, checks, incomparable) "
    "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) "
    "ON CONFLICT (tenant_id, active_version, candidate_version, rule_key) DO UPDATE SET "
    "n = tenant_shadow_agreement.n + EXCLUDED.n, "
    "agree = tenant_shadow_agreement.agree + EXCLUDED.agree, "
    "candidate_stricter = tenant_shadow_agreement.candidate_stricter "
    "+ EXCLUDED.candidate_stricter, "
    "candidate_looser = tenant_shadow_agreement.candidate_looser + EXCLUDED.candidate_looser, "
    "only_active = tenant_shadow_agreement.only_active + EXCLUDED.only_active, "
    "only_candidate = tenant_shadow_agreement.only_candidate + EXCLUDED.only_candidate, "
    "checks = tenant_shadow_agreement.checks + EXCLUDED.checks, "
    "incomparable = tenant_shadow_agreement.incomparable + EXCLUDED.incomparable, "
    "updated_at = now()"
)


def _shadow_rows(tally: Tally) -> list[tuple[Any, ...]]:
    """The counter rows of a tally: the summary, the decision and each rule (rule key, layer,
    the six counts, the checks and the incomparable)."""
    rows: list[tuple[Any, ...]] = [
        (_SUMMARY_KEY, "", 0, 0, 0, 0, 0, 0, tally.checks, tally.incomparable),
        (DECISION_KEY, "", *_count_tuple(tally.decision), 0, 0),
    ]
    rows += [(key, c.layer, *_count_tuple(c), 0, 0) for key, c in sorted(tally.rules.items())]
    return rows


def _count_tuple(c: Counts) -> tuple[int, ...]:
    return (c.n, c.agree, c.candidate_stricter, c.candidate_looser, c.only_active, c.only_candidate)


class PostgresCalibrationStore:
    """The calibration store on Postgres (M4-01): ``scoped(scope)`` returns a view whose every
    operation runs in a transaction with ``app.tenant_id`` set from the scope (row-level
    security, 020). New targets and their audit event are one transaction; the scores and the
    audit tables refuse UPDATE and DELETE."""

    def __init__(self, pool: asyncpg.Pool, operator_pool: asyncpg.Pool | None = None) -> None:
        self._pool = pool
        self._operator_pool = operator_pool

    def scoped(self, scope: TenantScope) -> CalibrationStore:
        if not isinstance(scope, TenantScope):
            raise TypeError("scoped() takes a TenantScope")
        return _ScopedPostgresCalibration(self._pool, scope, self._operator_pool)


class _ScopedPostgresCalibration:
    def __init__(
        self, pool: asyncpg.Pool, scope: TenantScope, operator_pool: asyncpg.Pool | None = None
    ) -> None:
        self._pool = pool
        self._operator_pool = operator_pool
        self._scope = scope

    def _check(self, tenant_id: str) -> None:
        if tenant_id != self._scope.tenant_id:
            raise ScopeMismatchError()

    def _conn(self) -> Any:
        return tenant_connection(self._pool, self._scope, self._operator_pool)

    async def get_targets(self, tenant_id: str) -> Targets | None:
        self._check(tenant_id)
        async with self._conn() as conn:
            row = await conn.fetchrow(
                "SELECT block_precision, escalate_recall, recall_tolerance "
                "FROM tenant_calibration_targets WHERE tenant_id = $1",
                tenant_id,
            )
        return None if row is None else Targets(
            float(row["block_precision"]), float(row["escalate_recall"]),
            float(row["recall_tolerance"]),
        )  # fmt: skip

    async def set_targets(
        self, tenant_id: str, targets: Targets, event: CalibrationAuditEvent
    ) -> None:
        self._check(tenant_id)
        if event.tenant_id != tenant_id:
            raise ScopeMismatchError()
        async with self._conn() as conn:
            await conn.execute(
                "INSERT INTO tenant_calibration_targets (tenant_id, block_precision, "
                "escalate_recall, recall_tolerance, updated_at, updated_by) "
                "VALUES ($1, $2, $3, $4, $5, $6) "
                "ON CONFLICT (tenant_id) DO UPDATE SET block_precision = EXCLUDED.block_precision, "
                "escalate_recall = EXCLUDED.escalate_recall, "
                "recall_tolerance = EXCLUDED.recall_tolerance, updated_at = EXCLUDED.updated_at, "
                "updated_by = EXCLUDED.updated_by",
                tenant_id, targets.block_precision, targets.escalate_recall,
                targets.recall_tolerance, event.at, event.actor,
            )  # fmt: skip
            await self._audit(conn, event)

    async def get_scores(
        self, tenant_id: str, scoring: str, guard_point: str, content_hashes: list[str]
    ) -> dict[str, dict[str, float]]:
        self._check(tenant_id)
        if not content_hashes:
            return {}
        async with self._conn() as conn:
            rows = await conn.fetch(
                "SELECT content_hash, scores FROM tenant_calibration_scores WHERE tenant_id = $1 "
                "AND scoring = $2 AND guard_point = $3 AND content_hash = ANY($4::text[])",
                tenant_id, scoring, guard_point, content_hashes,
            )  # fmt: skip
        return {r["content_hash"]: json.loads(r["scores"]) for r in rows}

    async def put_scores(
        self, tenant_id: str, scoring: str, guard_point: str, scores: dict[str, dict[str, float]]
    ) -> None:
        self._check(tenant_id)
        if not scores:
            return
        async with self._conn() as conn:
            await conn.executemany(
                "INSERT INTO tenant_calibration_scores (tenant_id, scoring, guard_point, "
                "content_hash, scores) VALUES ($1, $2, $3, $4, $5::jsonb) "
                "ON CONFLICT DO NOTHING",
                [
                    (tenant_id, scoring, guard_point, h, json.dumps(by_rule, sort_keys=True))
                    for h, by_rule in scores.items()
                ],
            )

    async def get_outcomes(
        self, tenant_id: str, scoring: str, guard_point: str, content_hashes: list[str]
    ) -> dict[str, dict[str, int]]:
        self._check(tenant_id)
        if not content_hashes:
            return {}
        async with self._conn() as conn:
            rows = await conn.fetch(
                "SELECT content_hash, cause, count(*) AS n FROM tenant_calibration_outcomes "
                "WHERE tenant_id = $1 AND scoring = $2 AND guard_point = $3 "
                "AND content_hash = ANY($4::text[]) GROUP BY content_hash, cause",
                tenant_id, scoring, guard_point, content_hashes,
            )  # fmt: skip
        out: dict[str, dict[str, int]] = {}
        for r in rows:
            out.setdefault(r["content_hash"], {})[r["cause"]] = r["n"]
        return out

    async def put_outcomes(
        self, tenant_id: str, scoring: str, guard_point: str, outcomes: dict[str, str]
    ) -> None:
        self._check(tenant_id)
        if not outcomes:
            return
        async with self._conn() as conn:
            for h, cause in outcomes.items():
                await conn.execute(
                    "INSERT INTO tenant_calibration_outcomes (tenant_id, scoring, guard_point, "
                    "content_hash, attempt, cause) "
                    "SELECT $1, $2, $3, $4, m + 1, $5 FROM (SELECT coalesce(max(attempt), 0) AS m "
                    "FROM tenant_calibration_outcomes WHERE tenant_id = $1 AND scoring = $2 "
                    "AND guard_point = $3 AND content_hash = $4) t WHERE m < 20 "
                    "ON CONFLICT DO NOTHING",
                    tenant_id, scoring, guard_point, h, cause,
                )  # fmt: skip

    async def record(self, tenant_id: str, event: CalibrationAuditEvent) -> None:
        self._check(tenant_id)
        if event.tenant_id != tenant_id:
            raise ScopeMismatchError()
        async with self._conn() as conn:
            await self._audit(conn, event)

    async def audit_events(self, tenant_id: str) -> list[CalibrationAuditEvent]:
        self._check(tenant_id)
        async with self._conn() as conn:
            rows = await conn.fetch(
                "SELECT at, actor, tenant_id, kind, cross_tenant, operator, detail "
                "FROM tenant_calibration_audit WHERE tenant_id = $1 ORDER BY id",
                tenant_id,
            )
        return [
            CalibrationAuditEvent(
                r["at"], r["actor"], r["tenant_id"], r["kind"], json.loads(r["detail"]),
                r["cross_tenant"], r["operator"],
            )
            for r in rows
        ]  # fmt: skip

    @staticmethod
    async def _audit(conn: asyncpg.Connection, event: CalibrationAuditEvent) -> None:
        await conn.execute(
            "INSERT INTO tenant_calibration_audit (tenant_id, at, actor, kind, cross_tenant, "
            "operator, detail) VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb)",
            event.tenant_id, event.at, event.actor, event.kind, event.cross_tenant,
            event.operator, json.dumps(event.detail, sort_keys=True),
        )  # fmt: skip


class PostgresGoldenStore:
    """The golden-set store on Postgres (M2-06): ``scoped(scope)`` returns a view whose every
    operation runs in a transaction with ``app.tenant_id`` set from the scope (row-level
    security, 010). A set, its examples and its class A event are one transaction; the tables
    refuse UPDATE and DELETE, so a set never changes."""

    def __init__(self, pool: asyncpg.Pool, operator_pool: asyncpg.Pool | None = None) -> None:
        self._pool = pool
        self._operator_pool = operator_pool

    def scoped(self, scope: TenantScope) -> GoldenStore:
        if not isinstance(scope, TenantScope):
            raise TypeError("scoped() takes a TenantScope")
        return _ScopedPostgresGolden(self._pool, scope, self._operator_pool)


_GOLDEN_COLUMNS = "set_id, name, set_hash, created_at, created_by, counts, quarantine"


def _golden_info(row: asyncpg.Record) -> GoldenSetInfo:
    return GoldenSetInfo(
        row["set_id"], row["name"], row["set_hash"], row["created_at"], row["created_by"],
        json.loads(row["counts"]),
        tuple((q["id"], tuple(q["views"])) for q in json.loads(row["quarantine"])),
    )  # fmt: skip


class _ScopedPostgresGolden:
    def __init__(
        self, pool: asyncpg.Pool, scope: TenantScope, operator_pool: asyncpg.Pool | None = None
    ) -> None:
        self._pool = pool
        self._operator_pool = operator_pool
        self._scope = scope

    def _check(self, tenant_id: str) -> None:
        if tenant_id != self._scope.tenant_id:
            raise ScopeMismatchError()

    async def create(
        self,
        tenant_id: str,
        info: GoldenSetInfo,
        examples: tuple[GoldenExample, ...],
        event: GoldenAuditEvent,
    ) -> GoldenSetInfo:
        self._check(tenant_id)
        if event.tenant_id != tenant_id:
            raise ScopeMismatchError()
        async with tenant_connection(self._pool, self._scope, self._operator_pool) as conn:
            # One lock per tenant for the cap check, so two uploads can't both pass it.
            await conn.execute("SELECT pg_advisory_xact_lock(hashtext($1))", "golden:" + tenant_id)
            # Escalation label sets (M4-05) have their own cap, apart from uploaded sets.
            count = await conn.fetchval(
                "SELECT count(*) FROM tenant_golden_sets WHERE tenant_id = $1 "
                "AND (left(name, 11) = 'escalation-') = $2",
                tenant_id,
                info.is_escalation_label,
            )
            if count >= (
                GOLDEN_MAX_ESCALATION_SETS if info.is_escalation_label else GOLDEN_MAX_SETS
            ):
                raise TooManyGoldenSetsError()
            if await conn.fetchval(
                "SELECT 1 FROM tenant_golden_sets WHERE tenant_id = $1 AND set_id = $2",
                tenant_id,
                info.set_id,
            ):
                raise GoldenSetExistsError()
            await conn.execute(
                "INSERT INTO tenant_golden_sets (tenant_id, set_id, name, set_hash, created_at, "
                "created_by, counts, quarantine) "
                "VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8::jsonb)",
                tenant_id, info.set_id, info.name, info.set_hash, info.created_at,
                info.created_by, json.dumps(info.counts),
                json.dumps([{"id": i, "views": list(v)} for i, v in info.quarantined]),
            )  # fmt: skip
            await conn.executemany(
                "INSERT INTO tenant_golden_examples (tenant_id, set_id, position, example_id, "
                "guard_point, label, content, quarantine) "
                "VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
                [
                    (
                        tenant_id,
                        info.set_id,
                        i,
                        e.id,
                        e.guard_point,
                        e.label,
                        e.content,
                        list(e.quarantine),
                    )
                    for i, e in enumerate(examples)
                ],
            )
            await conn.execute(
                "INSERT INTO tenant_golden_audit (tenant_id, at, actor, cross_tenant, operator, "
                "set_id, set_hash, examples, quarantined) "
                "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
                tenant_id, event.at, event.actor, event.cross_tenant, event.operator,
                event.set_id, event.set_hash, event.examples, event.quarantined,
            )  # fmt: skip
        return info

    async def get(self, tenant_id: str, set_id: str) -> GoldenSetInfo | None:
        self._check(tenant_id)
        async with tenant_connection(self._pool, self._scope, self._operator_pool) as conn:
            row = await conn.fetchrow(
                f"SELECT {_GOLDEN_COLUMNS} FROM tenant_golden_sets "
                "WHERE tenant_id = $1 AND set_id = $2",
                tenant_id, set_id,
            )  # fmt: skip
        return None if row is None else _golden_info(row)

    async def label_counts(self, tenant_id: str) -> dict[str, dict[str, int]]:
        return await self._counts(tenant_id, escalation_only=False)

    async def escalation_label_counts(self, tenant_id: str) -> dict[str, dict[str, int]]:
        return await self._counts(tenant_id, escalation_only=True)

    async def _counts(self, tenant_id: str, *, escalation_only: bool) -> dict[str, dict[str, int]]:
        self._check(tenant_id)
        async with tenant_connection(self._pool, self._scope, self._operator_pool) as conn:
            rows = await conn.fetch(
                "SELECT DISTINCT e.guard_point, e.label, e.content FROM tenant_golden_examples e "
                "WHERE e.tenant_id = $1 AND cardinality(e.quarantine) = 0 "
                "AND (NOT $2::boolean OR EXISTS (SELECT 1 FROM tenant_golden_sets s "
                "WHERE s.tenant_id = e.tenant_id AND s.set_id = e.set_id "
                "AND left(s.name, 11) = 'escalation-'))",
                tenant_id,
                escalation_only,
            )
        labels: dict[tuple[str, str], set[str]] = {}
        for r in rows:  # keyed on the normalised content, as the memory store does
            labels.setdefault((r["guard_point"], content_key(r["content"])), set()).add(r["label"])
        counts: dict[str, dict[str, int]] = {}
        for (guard_point, _), seen in labels.items():
            if len(seen) == 1:  # a content labelled both ways proves nothing
                (label,) = seen
                by = counts.setdefault(guard_point, {})
                by[label] = by.get(label, 0) + 1
        return counts

    async def list(self, tenant_id: str) -> list[GoldenSetInfo]:
        self._check(tenant_id)
        async with tenant_connection(self._pool, self._scope, self._operator_pool) as conn:
            rows = await conn.fetch(
                f"SELECT {_GOLDEN_COLUMNS} FROM tenant_golden_sets WHERE tenant_id = $1 "
                "ORDER BY created_at, set_id",
                tenant_id,
            )
        return [_golden_info(r) for r in rows]

    async def examples(
        self, tenant_id: str, set_id: str, guard_point: str, *, offset: int, limit: int
    ) -> GoldenPage:
        self._check(tenant_id)
        async with tenant_connection(self._pool, self._scope, self._operator_pool) as conn:
            if not await conn.fetchval(
                "SELECT 1 FROM tenant_golden_sets WHERE tenant_id = $1 AND set_id = $2",
                tenant_id, set_id,
            ):  # fmt: skip
                raise GoldenSetNotFoundError()
            counts = await conn.fetchrow(
                "SELECT count(*) FILTER (WHERE cardinality(quarantine) = 0) AS sendable, "
                "count(*) FILTER (WHERE cardinality(quarantine) > 0) AS held "
                "FROM tenant_golden_examples "
                "WHERE tenant_id = $1 AND set_id = $2 AND guard_point = $3",
                tenant_id, set_id, guard_point,
            )  # fmt: skip
            # A quarantined row is never returned: it is excluded here, in the query.
            rows = await conn.fetch(
                "SELECT example_id, guard_point, label, content FROM tenant_golden_examples "
                "WHERE tenant_id = $1 AND set_id = $2 AND guard_point = $3 "
                "AND cardinality(quarantine) = 0 ORDER BY position OFFSET $4 LIMIT $5",
                tenant_id, set_id, guard_point, offset, limit,
            )  # fmt: skip
        return GoldenPage(
            counts["sendable"],
            counts["held"],
            [
                GoldenExample(r["example_id"], r["guard_point"], r["label"], r["content"])
                for r in rows
            ],
        )

    async def audit_events(self, tenant_id: str) -> list[GoldenAuditEvent]:
        self._check(tenant_id)
        async with tenant_connection(self._pool, self._scope, self._operator_pool) as conn:
            rows = await conn.fetch(
                "SELECT at, actor, tenant_id, set_id, set_hash, examples, quarantined, "
                "cross_tenant, operator FROM tenant_golden_audit WHERE tenant_id = $1 ORDER BY id",
                tenant_id,
            )
        return [
            GoldenAuditEvent(
                r["at"], r["actor"], r["tenant_id"], r["set_id"], r["set_hash"], r["examples"],
                r["quarantined"], r["cross_tenant"], r["operator"],
            )
            for r in rows
        ]  # fmt: skip


_EVENT_COLUMNS = (
    "at, actor, tenant_id, action, version, from_version, mode, rollout_percent, bundle_hash, "
    "draft_hash, diff, note, rules, cross_tenant, operator, becomes_active, "
    "abandoned_candidate, repin_floor, repin_drops"
)


class PostgresLifecycleStore:
    """The version lifecycle on Postgres (M2-07). ``scoped(scope)`` returns a view whose every
    operation runs in one transaction with ``app.tenant_id`` set from the scope (row-level
    security, 012), holding a per-tenant advisory lock for a write so two lifecycle changes of
    one tenant never interleave. A write checks the state it expected (compare-and-set), changes
    the version, the pointer or the candidate and appends its class A row in that same
    transaction. A version that is about to become active is loaded and verified first, as
    ``set_active_version`` does."""

    def __init__(
        self,
        pool: asyncpg.Pool,
        *,
        catalog: Catalog | None,
        on_integrity_failure: AlertHook | None = None,
        operator_pool: asyncpg.Pool | None = None,
    ) -> None:
        self._pool = pool
        self._operator_pool = operator_pool
        self._verifier = BundleVerifier(catalog, on_integrity_failure)

    def scoped(self, scope: TenantScope) -> LifecycleStore:
        if not isinstance(scope, TenantScope):
            raise TypeError("scoped() takes a TenantScope")
        return _ScopedPostgresLifecycle(self._pool, self._verifier, scope, self._operator_pool)


class _ScopedPostgresLifecycle:
    def __init__(
        self,
        pool: asyncpg.Pool,
        verifier: BundleVerifier,
        scope: TenantScope,
        operator_pool: asyncpg.Pool | None,
    ) -> None:
        self._pool = pool
        self._operator_pool = operator_pool
        self._verifier = verifier
        self._scope = scope

    def _check(self, tenant_id: str) -> None:
        if tenant_id != self._scope.tenant_id:
            raise ScopeMismatchError()

    def _conn(self) -> contextlib.AbstractAsyncContextManager[asyncpg.Connection]:
        return tenant_connection(self._pool, self._scope, self._operator_pool)

    @staticmethod
    async def _read_state(conn: asyncpg.Connection, tenant_id: str) -> LifecycleState:
        active = await conn.fetchval(
            "SELECT version FROM policy_active_versions WHERE tenant_id = $1", tenant_id
        )
        row = await conn.fetchrow(
            "SELECT version, mode, rollout_percent, at, actor FROM tenant_candidates "
            "WHERE tenant_id = $1",
            tenant_id,
        )
        candidate = (
            None
            if row is None
            else Candidate(
                row["version"], row["mode"], row["rollout_percent"], row["at"], row["actor"]
            )
        )
        return LifecycleState(active, candidate)

    @contextlib.asynccontextmanager
    async def exclusive(self, tenant_id: str) -> AsyncIterator[None]:
        """The tenant's lifecycle advisory lock, held for the block (a transaction): every
        lifecycle write waits for it."""
        self._check(tenant_id)
        async with self._conn() as conn:
            await conn.execute(
                "SELECT pg_advisory_xact_lock(hashtext($1))", "lifecycle:" + tenant_id
            )
            yield

    async def _locked(
        self, conn: asyncpg.Connection, tenant_id: str, expected: LifecycleState
    ) -> None:
        await conn.execute("SELECT pg_advisory_xact_lock(hashtext($1))", "lifecycle:" + tenant_id)
        if await self._read_state(conn, tenant_id) != expected:
            raise StateConflictError()

    async def _verify(self, conn: asyncpg.Connection, tenant_id: str, version: int) -> None:
        row = await conn.fetchrow(
            "SELECT document, bundle_hash FROM policy_bundle_versions "
            "WHERE tenant_id = $1 AND version = $2",
            tenant_id, version,
        )  # fmt: skip
        if row is None:
            raise VersionNotFoundError(tenant_id, version)
        self._verifier.verify_stored(tenant_id, version, row["document"], row["bundle_hash"])

    @staticmethod
    async def _point_active(
        conn: asyncpg.Connection, tenant_id: str, version: int, current: int | None
    ) -> None:
        """Move the pointer from ``current`` (None: unset) to ``version``, or raise."""
        if current is None:
            status = await conn.execute(
                "INSERT INTO policy_active_versions (tenant_id, version) VALUES ($1, $2) "
                "ON CONFLICT (tenant_id) DO NOTHING",
                tenant_id, version,
            )  # fmt: skip
            moved = status == "INSERT 0 1"
        else:
            status = await conn.execute(
                "UPDATE policy_active_versions SET version = $2, updated_at = now() "
                "WHERE tenant_id = $1 AND version = $3",
                tenant_id, version, current,
            )  # fmt: skip
            moved = status == "UPDATE 1"
        if not moved:
            raise StateConflictError()

    @staticmethod
    async def _append(conn: asyncpg.Connection, event: PublishEvent) -> None:
        await conn.execute(
            f"INSERT INTO tenant_publish_audit ({_EVENT_COLUMNS}) VALUES "
            "($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::jsonb, $12, $13::jsonb, $14, $15, "
            "$16, $17, $18, $19::jsonb)",
            event.at, event.actor, event.tenant_id, event.action, event.version,
            event.from_version, event.mode, event.rollout_percent, event.bundle_hash,
            event.draft_hash, json.dumps([d.model_dump() for d in event.diff]), event.note,
            json.dumps(
                [{"id": r.id, "mode": r.mode, "fingerprint": r.fingerprint} for r in event.rules]
            ),
            event.cross_tenant, event.operator, event.becomes_active, event.abandoned_candidate,
            event.repin_floor, json.dumps(list(event.repin_drops)),
        )  # fmt: skip

    # ------------------------------------------------------------------ reads

    async def state(self, tenant_id: str) -> LifecycleState:
        self._check(tenant_id)
        async with self._conn() as conn:
            return await self._read_state(conn, tenant_id)

    async def versions(self, tenant_id: str) -> list[VersionEntry]:
        self._check(tenant_id)
        async with self._conn() as conn:
            rows = await conn.fetch(
                "SELECT version, bundle_hash, created_at FROM policy_bundle_versions "
                "WHERE tenant_id = $1 ORDER BY version",
                tenant_id,
            )
        return [VersionEntry(r["version"], r["bundle_hash"], r["created_at"]) for r in rows]

    async def document(self, tenant_id: str, version: int) -> dict[str, Any] | None:
        self._check(tenant_id)
        async with self._conn() as conn:
            text = await conn.fetchval(
                "SELECT document FROM policy_bundle_versions WHERE tenant_id = $1 AND version = $2",
                tenant_id, version,
            )  # fmt: skip
        return None if text is None else json.loads(text)

    async def events(self, tenant_id: str) -> list[PublishEvent]:
        self._check(tenant_id)
        async with self._conn() as conn:
            rows = await conn.fetch(
                f"SELECT {_EVENT_COLUMNS} FROM tenant_publish_audit WHERE tenant_id = $1 "
                "ORDER BY id",
                tenant_id,
            )
        return [
            PublishEvent(
                at=r["at"], actor=r["actor"], tenant_id=r["tenant_id"], action=r["action"],
                version=r["version"], from_version=r["from_version"], mode=r["mode"],
                rollout_percent=r["rollout_percent"], bundle_hash=r["bundle_hash"],
                draft_hash=r["draft_hash"],
                diff=tuple(DiffEntry(**d) for d in json.loads(r["diff"])), note=r["note"],
                rules=tuple(
                    RuleSnapshot(x["id"], x["mode"], x["fingerprint"])
                    for x in json.loads(r["rules"])
                ),
                cross_tenant=r["cross_tenant"], operator=r["operator"],
                becomes_active=r["becomes_active"], abandoned_candidate=r["abandoned_candidate"],
                repin_floor=r["repin_floor"], repin_drops=tuple(json.loads(r["repin_drops"])),
            )
            for r in rows
        ]  # fmt: skip

    # ------------------------------------------------------------------ writes

    async def publish(
        self,
        tenant_id: str,
        parsed: ParsedBundle,
        bundle_hash: str,
        *,
        candidate: Candidate | None,
        expected: LifecycleState,
        event: PublishEvent,
        approval: ApprovalUse | None = None,
    ) -> None:
        self._check(tenant_id)
        if event.tenant_id != tenant_id:
            raise ScopeMismatchError()
        self._verifier.check_new(tenant_id, parsed, bundle_hash)
        version = parsed.bundle.version
        async with self._conn() as conn:
            await self._locked(conn, tenant_id, expected)
            if approval is not None:  # M5-02: spent in this transaction, or nothing is
                await consume_approval(conn, tenant_id, approval)
            created = await conn.fetchval(
                "INSERT INTO policy_bundle_versions (tenant_id, version, document, bundle_hash) "
                "VALUES ($1, $2, $3, $4) ON CONFLICT (tenant_id, version) DO NOTHING "
                "RETURNING created_at",
                tenant_id, version, parsed.canonical_document.decode("utf-8"), bundle_hash,
            )  # fmt: skip
            if created is None:
                raise StateConflictError()  # another publish took the number
            if candidate is not None:
                await conn.execute(
                    "INSERT INTO tenant_candidates (tenant_id, version, mode, rollout_percent, "
                    "at, actor) VALUES ($1, $2, $3, $4, $5, $6)",
                    tenant_id, candidate.version, candidate.mode, candidate.rollout_percent,
                    candidate.at, candidate.actor,
                )  # fmt: skip
            else:
                await self._point_active(conn, tenant_id, version, expected.active)
            await self._append(conn, event)

    async def set_percent(
        self, tenant_id: str, percent: int, *, expected: LifecycleState, event: PublishEvent
    ) -> None:
        self._check(tenant_id)
        if event.tenant_id != tenant_id:
            raise ScopeMismatchError()
        async with self._conn() as conn:
            await self._locked(conn, tenant_id, expected)
            await conn.execute(
                "UPDATE tenant_candidates SET rollout_percent = $2 WHERE tenant_id = $1",
                tenant_id, percent,
            )  # fmt: skip
            await self._append(conn, event)

    async def promote(
        self,
        tenant_id: str,
        *,
        expected: LifecycleState,
        event: PublishEvent,
        approval: ApprovalUse | None = None,
    ) -> None:
        self._check(tenant_id)
        if event.tenant_id != tenant_id or expected.candidate is None:
            raise ScopeMismatchError()
        async with self._conn() as conn:
            await self._locked(conn, tenant_id, expected)
            if approval is not None:  # M5-02: spent in this transaction, or nothing is
                await consume_approval(conn, tenant_id, approval)
            await self._verify(conn, tenant_id, expected.candidate.version)
            await self._point_active(conn, tenant_id, expected.candidate.version, expected.active)
            await conn.execute("DELETE FROM tenant_candidates WHERE tenant_id = $1", tenant_id)
            await self._append(conn, event)

    async def abandon(
        self, tenant_id: str, *, expected: LifecycleState, event: PublishEvent
    ) -> None:
        self._check(tenant_id)
        if event.tenant_id != tenant_id:
            raise ScopeMismatchError()
        async with self._conn() as conn:
            await self._locked(conn, tenant_id, expected)
            await conn.execute("DELETE FROM tenant_candidates WHERE tenant_id = $1", tenant_id)
            await self._append(conn, event)

    async def rollback(
        self, tenant_id: str, target: int, *, expected: LifecycleState, event: PublishEvent
    ) -> None:
        self._check(tenant_id)
        if event.tenant_id != tenant_id:
            raise ScopeMismatchError()
        async with self._conn() as conn:
            await self._locked(conn, tenant_id, expected)
            await self._verify(conn, tenant_id, target)  # it loads and verifies before the move
            await self._point_active(conn, tenant_id, target, expected.active)
            await conn.execute("DELETE FROM tenant_candidates WHERE tenant_id = $1", tenant_id)
            await self._append(conn, event)

    async def activate_new(
        self,
        tenant_id: str,
        parsed: ParsedBundle,
        bundle_hash: str,
        *,
        expected: LifecycleState,
        event: PublishEvent,
    ) -> None:
        self._check(tenant_id)
        if event.tenant_id != tenant_id:
            raise ScopeMismatchError()
        self._verifier.check_new(tenant_id, parsed, bundle_hash)
        version = parsed.bundle.version
        async with self._conn() as conn:
            await self._locked(conn, tenant_id, expected)
            created = await conn.fetchval(
                "INSERT INTO policy_bundle_versions (tenant_id, version, document, bundle_hash) "
                "VALUES ($1, $2, $3, $4) ON CONFLICT (tenant_id, version) DO NOTHING "
                "RETURNING created_at",
                tenant_id, version, parsed.canonical_document.decode("utf-8"), bundle_hash,
            )  # fmt: skip
            if created is None:
                raise StateConflictError()
            await self._point_active(conn, tenant_id, version, expected.active)
            await conn.execute("DELETE FROM tenant_candidates WHERE tenant_id = $1", tenant_id)
            await self._append(conn, event)


# --------------------------------------------------------------------------- event bus

EVENT_CHANNEL = "guardrail_events"
MAX_EVENT_PAYLOAD_BYTES = 1024
"""A NOTIFY payload may be 8,000 bytes; ours are far smaller, and a bigger one is not ours."""
_EVENT_VERSION = 1


def event_payload(event: GuardrailPublished | TenantChanged) -> str:
    if isinstance(event, GuardrailPublished):
        body: dict[str, Any] = {
            "v": _EVENT_VERSION, "kind": "published", "tenant_id": event.tenant_id,
            "version": event.version, "action": event.action,
        }  # fmt: skip
        for key in ("mode", "active", "at"):  # only what is known
            if getattr(event, key) is not None:
                body[key] = getattr(event, key)
    elif isinstance(event, TenantChanged):
        body = {
            "v": _EVENT_VERSION, "kind": "tenant_changed", "tenant_id": event.tenant_id,
            "version": event.version, "change": event.kind,
        }  # fmt: skip
    else:
        raise TypeError(f"not an event this bus carries: {type(event).__name__}")
    return json.dumps(body, separators=(",", ":"))


def parse_event(payload: str) -> GuardrailPublished | TenantChanged | None:
    """The event a NOTIFY payload carries, or None for anything that isn't exactly one of ours:
    wrong size, shape, tenant id, action or numbers. A listener ignores what it can't parse."""
    if (
        not isinstance(payload, str)
        or len(payload.encode("utf-8", "replace")) > MAX_EVENT_PAYLOAD_BYTES
    ):
        return None
    try:
        body = json.loads(payload)
    except ValueError:
        return None
    if not isinstance(body, dict) or body.get("v") != _EVENT_VERSION:
        return None
    tenant, version = body.get("tenant_id"), body.get("version")
    if not is_valid_tenant_id(tenant) or not isinstance(version, int) or isinstance(version, bool):
        return None
    if version < 0:
        return None
    if body.get("kind") == "published" and {
        "v",
        "kind",
        "tenant_id",
        "version",
        "action",
    } <= set(body):  # unknown keys are ignored: a newer writer may add fields
        action = body["action"]
        mode, active, at = body.get("mode"), body.get("active"), body.get("at")
        if (
            (mode is not None and mode not in ("shadow", "enforce"))
            or (active is not None and not isinstance(active, bool))
            or (
                at is not None
                and (isinstance(at, bool) or not isinstance(at, (int, float)) or at < 0)
            )
        ):
            return None
        at = None if at is None else float(at)
        if action not in EVENT_ACTIONS:
            return None
        return GuardrailPublished(tenant, version, action, mode, active, at)
    if body.get("kind") == "tenant_changed" and set(body) == {
        "v",
        "kind",
        "tenant_id",
        "version",
        "change",
    }:
        change = body["change"]
        return TenantChanged(tenant, version, change) if change in _TENANT_CHANGES else None
    return None


_TENANT_CHANGES = ("create", "update", "set_status")


class PostgresEventBus:
    """``guardrail.published`` and ``tenant.changed`` over Postgres ``LISTEN``/``NOTIFY``, so
    every replica hears of a publish, rollback or directory change with no new infrastructure.

    **Best effort by design.** A NOTIFY goes to the sessions listening at that moment; one sent
    while a replica's listener is down or reconnecting is lost. The pointer TTL (60 s) and the
    directory's cache TTL (30 s) are what bound staleness then, and the docs say "within the
    TTL". A listener that fails reconnects every ``reconnect_s``.

    ``publish`` only sends: local subscribers hear the event through the listener like everyone
    else, so call :meth:`start` on every process that should react. A payload that isn't exactly
    one of our events (:func:`parse_event`) is ignored."""

    def __init__(
        self, pool: asyncpg.Pool, *, reconnect_s: float = 1.0, check_s: float = 5.0
    ) -> None:
        self._pool = pool
        self._reconnect_s = reconnect_s
        self._check_s = check_s
        self._subscribers: list[Callable[[Any], Awaitable[None] | None]] = []
        self._task: asyncio.Task[None] | None = None
        self._listening = asyncio.Event()
        self._closed = False

    def subscribe(self, fn: Callable[[Any], Awaitable[None] | None]) -> None:
        self._subscribers.append(fn)

    async def publish(self, event: GuardrailPublished | TenantChanged) -> None:
        await self._pool.execute("SELECT pg_notify($1, $2)", EVENT_CHANNEL, event_payload(event))

    async def start(self, *, wait_s: float = 5.0) -> None:
        """Start listening and wait until the listener is in place (or ``wait_s`` passes)."""
        if self._task is None:
            self._task = asyncio.ensure_future(self._run())
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(self._listening.wait(), wait_s)

    async def aclose(self) -> None:
        self._closed = True
        if self._task is not None:
            self._task.cancel()
            await asyncio.gather(self._task, return_exceptions=True)
            self._task = None

    def _on_notify(self, connection: Any, pid: int, channel: str, payload: str) -> None:
        event = parse_event(payload)
        if event is None:
            return
        for fn in list(self._subscribers):
            try:
                result = fn(event)
                if result is not None:
                    asyncio.ensure_future(result)  # noqa: RUF006 (fire and forget by design)
            except Exception:
                logger.exception("an event subscriber failed")

    async def _run(self) -> None:
        while not self._closed:
            try:
                async with self._pool.acquire() as conn:
                    await conn.add_listener(EVENT_CHANNEL, self._on_notify)
                    try:
                        self._listening.set()
                        while not self._closed:
                            await asyncio.sleep(self._check_s)
                            await conn.execute("SELECT 1")  # a dead connection raises here
                    finally:
                        # Leave the listener off the connection before it goes back to the pool.
                        with contextlib.suppress(Exception):
                            await conn.remove_listener(EVENT_CHANNEL, self._on_notify)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.warning("event listener lost (%s); retrying", type(exc).__name__)
            finally:
                self._listening.clear()
            if not self._closed:
                await asyncio.sleep(self._reconnect_s)
