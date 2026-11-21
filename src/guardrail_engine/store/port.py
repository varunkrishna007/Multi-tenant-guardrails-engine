"""The ``PolicyStore`` port (M1-02): immutable bundle versions and one active-version pointer
per tenant (design §Architecture).

The contract every implementation keeps:

* **Tenant scope.** Every operation takes a ``tenant_id`` and sees only that tenant's rows.
  Another tenant's version is indistinguishable from one that doesn't exist.
* **Immutability.** A stored version never changes and is never deleted. The port has no
  update or delete operation, and storing different content under an existing version number
  is refused.
* **The document as submitted.** A store persists the bundle document exactly as it was
  submitted (its canonical JSON text), never a re-serialised model, and the hash is always
  computed over that document.
* **Verified loads.** A version is stored with its ``bundle_hash``. Every load recomputes the
  hash from the stored document and the catalog content of the versions it extends
  (AC-C2.2). Anything short of a match raises :class:`BundleIntegrityError` and calls the
  alert hook: a different hash, no catalog, an extended version missing from the catalog, or
  a stored document that no longer parses. A load never returns an unverified bundle.
* **A pointer never names an unloadable version.** Moving the active pointer runs the same
  verification first and leaves the pointer alone if it fails.

This module and the in-memory store import no database driver. The driver lives only in
``store/adapters/postgres.py``.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from enum import Enum, StrEnum
from typing import Any, Final, Protocol

from guardrail_engine.policy.document import ParsedBundle
from guardrail_engine.policy.schema import Bundle
from guardrail_engine.tenant_scope import TenantScope

# --------------------------------------------------------------------------- values


@dataclass(frozen=True, slots=True)
class VersionInfo:
    """What the store knows about a version without loading or verifying its bundle."""

    tenant_id: str
    version: int
    bundle_hash: str
    created_at: datetime


@dataclass(frozen=True, slots=True)
class StoredVersion:
    """A loaded version. Its ``bundle_hash`` has been re-verified against ``bundle``."""

    tenant_id: str
    version: int
    parsed: ParsedBundle
    """The stored document and the model read from it. Pass this to ``PolicyCompiler.compile``."""
    bundle_hash: str
    created_at: datetime

    @property
    def bundle(self) -> Bundle:
        return self.parsed.bundle

    @property
    def document(self) -> dict[str, Any]:
        """A copy of the bundle document exactly as it was submitted."""
        return self.parsed.document

    @property
    def info(self) -> VersionInfo:
        return VersionInfo(self.tenant_id, self.version, self.bundle_hash, self.created_at)


# --------------------------------------------------------------------------- errors


class PolicyStoreError(Exception):
    """Base class for every error the policy store raises."""


class VersionNotFoundError(PolicyStoreError):
    """The tenant has no such version. Also raised for a version another tenant owns."""

    def __init__(self, tenant_id: str, version: int) -> None:
        self.tenant_id = tenant_id
        self.version = version
        super().__init__(f"tenant {tenant_id!r} has no bundle version {version}")


class VersionConflictError(PolicyStoreError):
    """The version number is taken by different content. Stored versions are immutable."""

    def __init__(self, tenant_id: str, version: int) -> None:
        self.tenant_id = tenant_id
        self.version = version
        super().__init__(
            f"tenant {tenant_id!r} already has a bundle version {version} with different "
            "content; stored versions are immutable"
        )


class InvalidTenantIdError(PolicyStoreError):
    """The tenant id isn't a valid store key: it doesn't match
    :data:`~guardrail_engine.tenant_ids.TENANT_ID_PATTERN` (B3). The id is not
    repeated in the message."""

    def __init__(self) -> None:
        from guardrail_engine.tenant_ids import TENANT_ID_PATTERN

        super().__init__(f"tenant id must match {TENANT_ID_PATTERN.pattern}")


class ScopeMismatchError(PolicyStoreError):
    """A call named a tenant other than the one its :class:`TenantScope` is verified for. Refused
    before anything is sent to the database. No ids in the message."""

    def __init__(self) -> None:
        super().__init__("the tenant in the call is not the tenant of the store's scope")


class OperatorPoolUnavailableError(PolicyStoreError):
    """A cross-tenant operator access reached a store with no operator pool configured, so it
    is refused (HTTP 503) rather than served from the tenant-scoped pool."""

    def __init__(self) -> None:
        super().__init__("no operator database pool is configured")


class TenantSettingLeakError(PolicyStoreError):
    """A connection came out of the pool with ``app.tenant_id`` already set. The
    operation is refused; the pool's reset on release is not doing its job."""

    def __init__(self) -> None:
        super().__init__("a pooled connection still carried a tenant setting")


class TenantMismatchError(PolicyStoreError):
    """The bundle's own ``tenant_id`` is not the tenant the caller is acting for."""

    def __init__(self, tenant_id: str, bundle_tenant_id: str) -> None:
        self.tenant_id = tenant_id
        self.bundle_tenant_id = bundle_tenant_id
        super().__init__(
            f"bundle belongs to tenant {bundle_tenant_id!r}, not to tenant {tenant_id!r}"
        )


class ActivePointerConflictError(PolicyStoreError):
    """The active pointer was not where the caller expected, so it was not moved."""

    def __init__(self, tenant_id: str, expected: int | None, actual: int | None) -> None:
        self.tenant_id = tenant_id
        self.expected = expected
        self.actual = actual
        """The pointer when the move was refused. None means no pointer was set."""
        super().__init__(
            f"tenant {tenant_id!r}: expected the active version to be {expected}, "
            f"but it is {actual}"
        )


class UnstorableDocumentError(PolicyStoreError):
    """The document holds something no store accepts: a NUL character in a string or key.
    (Postgres can't hold one in a JSON value, so every implementation refuses it.)"""

    def __init__(self, tenant_id: str, version: int, detail: str) -> None:
        self.tenant_id = tenant_id
        self.version = version
        super().__init__(f"bundle {tenant_id}@{version} can't be stored: {detail}")


class _Unchecked(Enum):
    UNCHECKED = "unchecked"


UNCHECKED: Final = _Unchecked.UNCHECKED
"""``set_active_version(..., expected_current=UNCHECKED)``: move the pointer wherever it is."""


class IntegrityFailure(StrEnum):
    HASH_MISMATCH = "hash_mismatch"
    """The recomputed hash differs from the stored (or supplied) one."""
    NO_CATALOG = "no_catalog"
    """The store has no catalog, so the hash can't be recomputed."""
    CATALOG_VERSION_MISSING = "catalog_version_missing"
    """The bundle extends a floor or pack version the catalog doesn't have."""
    BUNDLE_UNREADABLE = "bundle_unreadable"
    """The stored document doesn't parse as a bundle, has a malformed or repeated ``extends``
    entry, or names a different tenant or version than the row it is stored under."""


class BundleIntegrityError(PolicyStoreError):
    """Hash verification failed. The bundle is refused, never returned."""

    def __init__(
        self,
        *,
        tenant_id: str,
        version: int,
        reason: IntegrityFailure,
        expected_hash: str,
        recomputed_hash: str | None = None,
        detail: str = "",
    ) -> None:
        self.tenant_id = tenant_id
        self.version = version
        self.reason = reason
        self.expected_hash = expected_hash
        """The hash stored with the version (on load) or supplied by the caller (on store)."""
        self.recomputed_hash = recomputed_hash
        """None when the hash could not be recomputed at all."""
        self.detail = detail
        super().__init__(
            f"bundle {tenant_id}@{version} failed hash verification ({reason.value})"
            + (f": {detail}" if detail else "")
        )


@dataclass(frozen=True, slots=True)
class IntegrityAlert:
    """Passed to the alert hook when a **load** fails verification."""

    tenant_id: str
    version: int
    reason: IntegrityFailure
    stored_hash: str
    recomputed_hash: str | None
    detail: str


AlertHook = Callable[[IntegrityAlert], None]
"""Called synchronously before the load raises. It must be quick and must not block: hand
the alert to a queue or a metrics counter. An exception from the hook is logged and does not
replace the :class:`BundleIntegrityError`."""


# --------------------------------------------------------------------------- port


class CatalogReferences(Protocol):
    """A platform-wide question the append-only catalog needs answered (M2-03): how many
    **stored bundles**, across all tenants, use a catalog item. ``ref`` is ``platform/floor@N``
    or ``domain/<pack>@V`` (a bundle's ``extends``), or ``template:<id>@V`` (a rule's
    ``origin``). It is a count, never a tenant list, so it exposes nothing of a tenant's."""

    async def count(self, ref: str) -> int: ...


class PolicyStore(Protocol):
    async def put_version(
        self, tenant_id: str, bundle: ParsedBundle, *, bundle_hash: str
    ) -> VersionInfo:
        """Store the submitted document as the immutable version ``bundle.bundle.version`` of
        ``tenant_id``. What is persisted is ``bundle.canonical_document``, nothing derived.

        ``bundle_hash`` is the compiler's hash (``CompiledPolicy.bundle_hash``). It is checked
        against a recomputation before anything is written, so an unverifiable version is
        never stored.

        Storing the same content under the same version again is a no-op that returns the
        existing record, so a loader can be re-run safely.

        Raises:
            TenantMismatchError: ``bundle.tenant_id`` is not ``tenant_id``.
            BundleIntegrityError: the hash doesn't match, or can't be recomputed.
            VersionConflictError: the version number already holds different content.
            UnstorableDocumentError: the document contains a NUL character.
        """
        ...

    async def get_version(self, tenant_id: str, version: int) -> StoredVersion:
        """Load one version and re-verify its hash.

        Raises:
            VersionNotFoundError: ``tenant_id`` has no such version.
            BundleIntegrityError: verification failed. The alert hook has been called.
        """
        ...

    async def list_versions(self, tenant_id: str) -> list[VersionInfo]:
        """The tenant's versions, oldest first. Bundles are not loaded, so nothing is verified."""
        ...

    async def get_active_version(self, tenant_id: str) -> int | None:
        """The version the tenant's pointer names, or None if it has never been set."""
        ...

    async def set_active_version(
        self,
        tenant_id: str,
        version: int,
        *,
        expected_current: int | _Unchecked | None = UNCHECKED,
    ) -> None:
        """Point the tenant at one of its own stored versions (publish or rollback).

        The target is loaded and verified exactly as ``get_version`` would before the pointer
        moves. If that fails the pointer is left unchanged, so a tenant is never left
        pointing at a version that can't be loaded.

        ``expected_current`` makes the move a compare-and-set: an ``int`` means "only if the
        pointer names this version now", ``None`` means "only if no pointer is set yet". The
        default, ``UNCHECKED``, moves it unconditionally.

        Raises:
            VersionNotFoundError: ``tenant_id`` has no such version.
            BundleIntegrityError: the target failed verification. The alert hook was called.
            ActivePointerConflictError: the pointer is not at ``expected_current``.
        """
        ...

    async def load_active(self, tenant_id: str) -> StoredVersion | None:
        """``get_version`` for the active version, or None if the pointer has never been set.

        Raises:
            BundleIntegrityError: verification failed. The alert hook has been called.
        """
        ...


class ScopedPolicyStores(Protocol):
    """What the guard path and the Admin API are given: a store that hands out a
    :class:`PolicyStore` for one verified tenant. The returned store refuses a call whose
    ``tenant_id`` is not the scope's (:class:`ScopeMismatchError`). The Postgres store offers
    only this, so row-level security is set from the scope and never from a caller's string."""

    def scoped(self, scope: TenantScope) -> PolicyStore: ...
