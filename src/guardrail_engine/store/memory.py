"""An in-memory ``PolicyStore`` for tests and local runs (M1-02).

It keeps the same contract as the Postgres store. Each version is held as the canonical JSON
bytes of the document as submitted, not as a live object, so nothing a caller does to a
bundle it stored or loaded can change what the store holds, and every load reads and
re-verifies the stored bytes.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime

from guardrail_engine.policy.catalog import Catalog
from guardrail_engine.policy.document import ParsedBundle
from guardrail_engine.store.port import (
    UNCHECKED,
    ActivePointerConflictError,
    AlertHook,
    PolicyStore,
    ScopeMismatchError,
    StoredVersion,
    VersionConflictError,
    VersionInfo,
    VersionNotFoundError,
    _Unchecked,
)
from guardrail_engine.store.verification import BundleVerifier
from guardrail_engine.tenant_scope import TenantScope


class MemoryCatalogReferences:
    """The platform-wide reference count for the append-only catalog (M2-03), over an
    :class:`InMemoryPolicyStore`. A separate object so the store itself offers no platform-wide
    read (the contract test lists its methods)."""

    def __init__(self, store: InMemoryPolicyStore) -> None:
        self._store = store

    async def count(self, ref: str) -> int:
        n = 0
        for row in list(self._store._versions.values()):
            document = json.loads(row.document)
            if ref.startswith("template:"):
                origins = (
                    r.get("origin") for r in document.get("rules", []) if isinstance(r, dict)
                )
                n += any(o == ref for o in origins)
            else:
                n += ref in document.get("extends", [])
        return n

    async def active_pack_refs(self) -> frozenset[str]:
        """The ``domain/<pack>@<n>`` references named by every tenant's **active** version.
        A candidate lives in the lifecycle store, which the memory store has no view of."""
        refs: set[str] = set()
        for (tenant_id, version), row in list(self._store._versions.items()):
            if self._store._active.get(tenant_id) == version:
                refs.update(_pack_refs(json.loads(row.document)))
        return frozenset(refs)


class MemoryActiveBundles:
    """Every tenant's active version, with the floor and packs it extends (M5-05), over an
    :class:`InMemoryPolicyStore`. A separate object, like :class:`MemoryCatalogReferences`."""

    def __init__(self, store: InMemoryPolicyStore) -> None:
        self._store = store

    async def active_bundles(self) -> list:
        from guardrail_engine.nightly.store import bundle_of

        out = []
        for (tenant_id, version), row in sorted(self._store._versions.items()):
            if self._store._active.get(tenant_id) == version:
                found = bundle_of(tenant_id, version, json.loads(row.document).get("extends"))
                if found is not None:
                    out.append(found)
        return out


def _pack_refs(document: dict) -> list[str]:
    extends = document.get("extends")
    if not isinstance(extends, list):
        return []
    return [e for e in extends if isinstance(e, str) and e.startswith("domain/")]


@dataclass(frozen=True, slots=True)
class _Row:
    document: bytes
    bundle_hash: str
    created_at: datetime


class InMemoryPolicyStore:
    def __init__(
        self,
        *,
        catalog: Catalog | None,
        on_integrity_failure: AlertHook | None = None,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        """``catalog`` is required but may be None: a store with no catalog refuses every
        store, load and pointer move, because it can't verify a hash."""
        self._verifier = BundleVerifier(catalog, on_integrity_failure)
        self._clock = clock
        self._versions: dict[tuple[str, int], _Row] = {}
        self._active: dict[str, int] = {}

    def scoped(self, scope: TenantScope) -> PolicyStore:
        if not isinstance(scope, TenantScope):
            raise TypeError("scoped() takes a TenantScope")
        return _ScopedMemoryStore(self, scope)

    async def put_version(
        self, tenant_id: str, bundle: ParsedBundle, *, bundle_hash: str
    ) -> VersionInfo:
        self._verifier.check_new(tenant_id, bundle, bundle_hash)
        version = bundle.bundle.version
        key = (tenant_id, version)
        existing = self._versions.get(key)
        if existing is None:
            existing = self._versions[key] = _Row(
                bundle.canonical_document, bundle_hash, self._clock()
            )
        elif existing.bundle_hash != bundle_hash:
            raise VersionConflictError(tenant_id, version)
        return VersionInfo(tenant_id, version, existing.bundle_hash, existing.created_at)

    async def get_version(self, tenant_id: str, version: int) -> StoredVersion:
        row = self._versions.get((tenant_id, version))
        if row is None:
            raise VersionNotFoundError(tenant_id, version)
        parsed = self._verifier.verify_stored(tenant_id, version, row.document, row.bundle_hash)
        return StoredVersion(tenant_id, version, parsed, row.bundle_hash, row.created_at)

    async def list_versions(self, tenant_id: str) -> list[VersionInfo]:
        return [
            VersionInfo(tenant_id, version, row.bundle_hash, row.created_at)
            for (tid, version), row in sorted(self._versions.items())
            if tid == tenant_id
        ]

    async def get_active_version(self, tenant_id: str) -> int | None:
        return self._active.get(tenant_id)

    async def set_active_version(
        self,
        tenant_id: str,
        version: int,
        *,
        expected_current: int | _Unchecked | None = UNCHECKED,
    ) -> None:
        await self.get_version(tenant_id, version)  # verified before the pointer moves
        # No await between the comparison and the write, so they are atomic on one loop.
        actual = self._active.get(tenant_id)
        if expected_current is not UNCHECKED and actual != expected_current:
            raise ActivePointerConflictError(tenant_id, expected_current, actual)
        self._active[tenant_id] = version

    async def load_active(self, tenant_id: str) -> StoredVersion | None:
        version = self._active.get(tenant_id)
        return None if version is None else await self.get_version(tenant_id, version)


class _ScopedMemoryStore:
    """An in-memory store bound to one :class:`TenantScope`, with the Postgres view's contract:
    a call that names another tenant is refused."""

    def __init__(self, inner: InMemoryPolicyStore, scope: TenantScope) -> None:
        self._inner = inner
        self._scope = scope

    def _check(self, tenant_id: str) -> None:
        if tenant_id != self._scope.tenant_id:
            raise ScopeMismatchError()

    async def put_version(
        self, tenant_id: str, bundle: ParsedBundle, *, bundle_hash: str
    ) -> VersionInfo:
        self._check(tenant_id)
        return await self._inner.put_version(tenant_id, bundle, bundle_hash=bundle_hash)

    async def get_version(self, tenant_id: str, version: int) -> StoredVersion:
        self._check(tenant_id)
        return await self._inner.get_version(tenant_id, version)

    async def list_versions(self, tenant_id: str) -> list[VersionInfo]:
        self._check(tenant_id)
        return await self._inner.list_versions(tenant_id)

    async def get_active_version(self, tenant_id: str) -> int | None:
        self._check(tenant_id)
        return await self._inner.get_active_version(tenant_id)

    async def set_active_version(
        self,
        tenant_id: str,
        version: int,
        *,
        expected_current: int | _Unchecked | None = UNCHECKED,
    ) -> None:
        self._check(tenant_id)
        await self._inner.set_active_version(tenant_id, version, expected_current=expected_current)

    async def load_active(self, tenant_id: str) -> StoredVersion | None:
        self._check(tenant_id)
        return await self._inner.load_active(tenant_id)
