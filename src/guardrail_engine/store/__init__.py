"""The policy store (M1-02): immutable bundle versions and the active-version pointer.

This package exports the port and the in-memory store only. The Postgres store is imported
from ``guardrail_engine.store.adapters.postgres``, so importing this package never loads a
database driver.
"""

from guardrail_engine.store.memory import InMemoryPolicyStore
from guardrail_engine.store.port import (
    UNCHECKED,
    ActivePointerConflictError,
    AlertHook,
    BundleIntegrityError,
    IntegrityAlert,
    IntegrityFailure,
    InvalidTenantIdError,
    PolicyStore,
    PolicyStoreError,
    StoredVersion,
    TenantMismatchError,
    UnstorableDocumentError,
    VersionConflictError,
    VersionInfo,
    VersionNotFoundError,
)

__all__ = [
    "UNCHECKED",
    "ActivePointerConflictError",
    "AlertHook",
    "BundleIntegrityError",
    "InMemoryPolicyStore",
    "IntegrityAlert",
    "IntegrityFailure",
    "InvalidTenantIdError",
    "PolicyStore",
    "PolicyStoreError",
    "StoredVersion",
    "TenantMismatchError",
    "UnstorableDocumentError",
    "VersionConflictError",
    "VersionInfo",
    "VersionNotFoundError",
]
