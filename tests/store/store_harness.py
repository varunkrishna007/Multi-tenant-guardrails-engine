"""Test helpers for the policy store: bundles with real compiler hashes, and one harness per
implementation so the contract tests can build stores and corrupt stored rows the same way."""

import copy
import json
from collections.abc import Callable

from policy_fixtures import TOOLS, make_catalog, valid_bundle

from guardrail_engine.policy import (
    InMemoryToolRegistry,
    ParsedBundle,
    PlatformSettings,
    PolicyCompiler,
    TenantAttributes,
    canonical_json,
    parse_bundle,
)
from guardrail_engine.store import InMemoryPolicyStore, PolicyStore
from guardrail_engine.store.memory import _Row
from guardrail_engine.store.port import InvalidTenantIdError, VersionNotFoundError
from guardrail_engine.tenant_ids import is_valid_tenant_id
from guardrail_engine.tenant_scope import issue_scope

ACME = "t_acmeins"
OTHER = "t_otherco"
DEFAULT = object()


def make_bundle(tenant_id: str = ACME, version: int = 1, **changes) -> tuple[ParsedBundle, str]:
    """A valid submitted bundle and the hash the real compiler gives it against
    ``make_catalog()``."""
    raw = copy.deepcopy(valid_bundle())
    raw.update(tenant_id=tenant_id, version=version, **changes)
    compiler = PolicyCompiler(
        make_catalog(), InMemoryToolRegistry(TOOLS), PlatformSettings(min_floor_version=2)
    )
    parsed = parse_bundle(raw)
    compiled = compiler.compile(parsed, TenantAttributes(tenant_id=tenant_id))
    return parsed, compiled.bundle_hash


def catalog_hashes() -> dict[str, str]:
    """``extends`` content hashes for the versions ``valid_bundle()`` extends."""
    catalog = make_catalog()
    versions = (catalog.floor(2), catalog.pack("insurance", 3), catalog.pack("finance", 2))
    return {v.ref: v.content_hash() for v in versions}


class MemoryHarness:
    name = "memory"

    def __init__(self) -> None:
        self._first: InMemoryPolicyStore | None = None

    def store(self, catalog=DEFAULT, hook=None) -> PolicyStore:
        """A store over this harness's data. Later stores share the first one's data, the way
        two Postgres stores share a database."""
        catalog = make_catalog() if catalog is DEFAULT else catalog
        store = InMemoryPolicyStore(catalog=catalog, on_integrity_failure=hook)
        if self._first is None:
            self._first = store
        else:
            store._versions = self._first._versions
            store._active = self._first._active
        return store

    async def tamper_document(self, tenant_id: str, version: int, change: Callable[[dict], None]):
        row = self._first._versions[(tenant_id, version)]
        document = json.loads(row.document)
        change(document)
        self._first._versions[(tenant_id, version)] = _Row(
            canonical_json(document), row.bundle_hash, row.created_at
        )

    async def tamper_hash(self, tenant_id: str, version: int, new_hash: str):
        row = self._first._versions[(tenant_id, version)]
        self._first._versions[(tenant_id, version)] = _Row(row.document, new_hash, row.created_at)


class RoutedStore:
    """Test-only: the contract tests name the tenant on each call, so this issues a scope for
    that tenant per call and uses the real scoped store. Production code gets its scope from a
    verifier or the authorizer; only tests (and this adapter) make one from a string."""

    def __init__(self, store) -> None:
        self._store = store

    def _for(self, tenant_id: str):
        return self._store.scoped(issue_scope(tenant_id))

    # A key outside the tenant id rule can't be scoped. The unscoped stores answered it as an
    # unknown tenant (and refused to store under it); these keep that contract.

    async def put_version(self, tenant_id, bundle, *, bundle_hash):
        if not is_valid_tenant_id(tenant_id):
            raise InvalidTenantIdError
        return await self._for(tenant_id).put_version(tenant_id, bundle, bundle_hash=bundle_hash)

    async def get_version(self, tenant_id, version):
        if not is_valid_tenant_id(tenant_id):
            raise VersionNotFoundError(tenant_id, version)
        return await self._for(tenant_id).get_version(tenant_id, version)

    async def list_versions(self, tenant_id):
        if not is_valid_tenant_id(tenant_id):
            return []
        return await self._for(tenant_id).list_versions(tenant_id)

    async def get_active_version(self, tenant_id):
        if not is_valid_tenant_id(tenant_id):
            return None
        return await self._for(tenant_id).get_active_version(tenant_id)

    async def set_active_version(self, tenant_id, version, **kwargs):
        if not is_valid_tenant_id(tenant_id):
            raise VersionNotFoundError(tenant_id, version)
        return await self._for(tenant_id).set_active_version(tenant_id, version, **kwargs)

    async def load_active(self, tenant_id):
        if not is_valid_tenant_id(tenant_id):
            return None
        return await self._for(tenant_id).load_active(tenant_id)


class PostgresHarness:
    name = "postgres"

    def __init__(self, pool) -> None:
        self.pool = pool

    def store(self, catalog=DEFAULT, hook=None) -> PolicyStore:
        from guardrail_engine.store.adapters.postgres import PostgresPolicyStore

        catalog = make_catalog() if catalog is DEFAULT else catalog
        return RoutedStore(
            PostgresPolicyStore(self.pool, catalog=catalog, on_integrity_failure=hook)
        )

    async def _with_triggers_off(self, sql: str, *args):
        """What someone with table-owner rights could do. The hash check must still catch it."""
        async with self.pool.acquire() as conn, conn.transaction():
            await conn.execute("ALTER TABLE policy_bundle_versions DISABLE TRIGGER USER")
            assert await conn.execute(sql, *args) == "UPDATE 1"
            await conn.execute("ALTER TABLE policy_bundle_versions ENABLE TRIGGER USER")

    async def tamper_document(self, tenant_id: str, version: int, change: Callable[[dict], None]):
        text = await self.pool.fetchval(
            "SELECT document FROM policy_bundle_versions WHERE tenant_id = $1 AND version = $2",
            tenant_id,
            version,
        )
        document = json.loads(text)
        change(document)
        await self._with_triggers_off(
            "UPDATE policy_bundle_versions SET document = $3 WHERE tenant_id = $1 AND version = $2",
            tenant_id,
            version,
            json.dumps(document),
        )

    async def tamper_hash(self, tenant_id: str, version: int, new_hash: str):
        await self._with_triggers_off(
            "UPDATE policy_bundle_versions SET bundle_hash = $3 "
            "WHERE tenant_id = $1 AND version = $2",
            tenant_id,
            version,
            new_hash,
        )
