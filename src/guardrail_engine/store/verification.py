"""Hash verification shared by every ``PolicyStore`` implementation (M1-02).

Both stores keep a version as the canonical JSON text of the document as submitted, plus the
hash it was stored with, and both call :meth:`BundleVerifier.verify_stored` on every load and
before every pointer move. Keeping the check here means the in-memory store used by other
stories' tests refuses exactly what Postgres refuses.

The hash is always computed over the stored document itself (``ParsedBundle.bundle_hash``),
never over a model, so a change to the schema's defaults can't fail a stored version.
"""

from __future__ import annotations

import logging
from typing import Any, NoReturn

from guardrail_engine.policy import EXTENDS_REF_PATTERN
from guardrail_engine.policy.catalog import Catalog
from guardrail_engine.policy.document import ParsedBundle, read_bundle
from guardrail_engine.store.port import (
    AlertHook,
    BundleIntegrityError,
    IntegrityAlert,
    IntegrityFailure,
    InvalidTenantIdError,
    TenantMismatchError,
    UnstorableDocumentError,
)
from guardrail_engine.tenant_ids import is_valid_tenant_id

_log = logging.getLogger(__name__)

MAX_VERSION = 2**63 - 1
"""Version numbers fit a Postgres ``bigint``."""


class _Unverifiable(Exception):
    def __init__(self, reason: IntegrityFailure, detail: str) -> None:
        self.reason = reason
        self.detail = detail
        super().__init__(detail)


def recompute_bundle_hash(parsed: ParsedBundle, catalog: Catalog | None) -> str:
    """The compiler's ``bundle_hash`` for the submitted document, from the catalog's current
    content.

    Raises ``_Unverifiable`` when there is no catalog, an ``extends`` entry is malformed or
    repeated, or the catalog doesn't have an extended version. A missing version is never
    skipped: leaving it out of the hash input would let a bundle pass with part of its
    content unchecked.
    """
    if catalog is None:
        raise _Unverifiable(IntegrityFailure.NO_CATALOG, "the store has no catalog")
    extends: dict[str, str] = {}
    for ref in parsed.bundle.extends:
        # The compiler's own grammar, so the two can't disagree about a reference.
        m = EXTENDS_REF_PATTERN.fullmatch(ref)
        if not m:
            raise _Unverifiable(
                IntegrityFailure.BUNDLE_UNREADABLE, f"malformed extends entry {ref!r}"
            )
        is_floor, pack_name, number = m.group(1), m.group(2), int(m.group(3))
        found = catalog.floor(number) if is_floor else catalog.pack(pack_name, number)
        if found is None:
            raise _Unverifiable(
                IntegrityFailure.CATALOG_VERSION_MISSING, f"the catalog has no {ref}"
            )
        if found.ref in extends:
            raise _Unverifiable(
                IntegrityFailure.BUNDLE_UNREADABLE, f"extends entry {ref!r} is repeated"
            )
        extends[found.ref] = found.content_hash()
    return parsed.bundle_hash(extends=extends)


def _has_nul(value: Any) -> bool:
    if isinstance(value, str):
        return "\x00" in value
    if isinstance(value, dict):
        return any(_has_nul(k) or _has_nul(v) for k, v in value.items())
    if isinstance(value, list):
        return any(_has_nul(v) for v in value)
    return False


class BundleVerifier:
    """Recomputes hashes against one catalog and reports failed loads to one alert hook."""

    def __init__(self, catalog: Catalog | None, on_integrity_failure: AlertHook | None) -> None:
        self._catalog = catalog
        self._hook = on_integrity_failure

    def check_new(self, tenant_id: str, parsed: ParsedBundle, supplied_hash: str) -> None:
        """Gate for ``put_version``. Raises, but doesn't alert: nothing at rest is wrong, the
        caller handed over something that can't be verified."""
        if not isinstance(parsed, ParsedBundle):
            # A model has no submitted document, and a model dump must never be stored.
            raise TypeError(
                f"put_version takes a ParsedBundle (see parse_bundle), not {type(parsed).__name__}"
            )
        if not is_valid_tenant_id(tenant_id):
            # One id rule for every store key (B3); the database checks it too.
            raise InvalidTenantIdError()
        bundle = parsed.bundle
        if bundle.tenant_id != tenant_id:
            raise TenantMismatchError(tenant_id, bundle.tenant_id)
        document = parsed.document
        if _has_nul(document):
            raise UnstorableDocumentError(
                tenant_id, bundle.version, "a string or key contains a NUL character"
            )
        # The database ties each row to the tenant and version its document states, so the
        # document must state the version as a plain integer (not 14.0, "14" or true).
        if type(document.get("version")) is not int or not 1 <= bundle.version <= MAX_VERSION:
            raise UnstorableDocumentError(
                tenant_id,
                bundle.version,
                f"version must be written as an integer between 1 and {MAX_VERSION}",
            )
        try:
            recomputed = recompute_bundle_hash(parsed, self._catalog)
        except _Unverifiable as e:
            raise BundleIntegrityError(
                tenant_id=tenant_id,
                version=bundle.version,
                reason=e.reason,
                expected_hash=supplied_hash,
                detail=e.detail,
            ) from None
        if recomputed != supplied_hash:
            raise BundleIntegrityError(
                tenant_id=tenant_id,
                version=bundle.version,
                reason=IntegrityFailure.HASH_MISMATCH,
                expected_hash=supplied_hash,
                recomputed_hash=recomputed,
                detail="the supplied hash is not the hash of this document and catalog",
            )

    def verify_stored(
        self, tenant_id: str, version: int, document: str | bytes, stored_hash: str
    ) -> ParsedBundle:
        """Read a stored document (its JSON text) and re-verify its hash. Returns the parsed
        bundle only on a match; every other outcome alerts and raises
        :class:`BundleIntegrityError`."""
        parsed, errors = read_bundle(document)
        if parsed is None:
            first = f"{errors[0].path}: {errors[0].code.value}" if errors else "unknown"
            self._refuse(
                tenant_id,
                version,
                IntegrityFailure.BUNDLE_UNREADABLE,
                stored_hash,
                None,
                f"the stored document is not a readable bundle ({len(errors)} error(s), "
                f"first: {first})",
            )
        bundle = parsed.bundle
        if bundle.tenant_id != tenant_id or bundle.version != version:
            self._refuse(
                tenant_id,
                version,
                IntegrityFailure.BUNDLE_UNREADABLE,
                stored_hash,
                None,
                f"the stored document says it is {bundle.tenant_id}@{bundle.version}",
            )
        try:
            recomputed = recompute_bundle_hash(parsed, self._catalog)
        except _Unverifiable as e:
            self._refuse(tenant_id, version, e.reason, stored_hash, None, e.detail)
        if recomputed != stored_hash:
            self._refuse(
                tenant_id,
                version,
                IntegrityFailure.HASH_MISMATCH,
                stored_hash,
                recomputed,
                "the stored document or an extended catalog version changed after it was stored",
            )
        return parsed

    def _refuse(
        self,
        tenant_id: str,
        version: int,
        reason: IntegrityFailure,
        stored_hash: str,
        recomputed_hash: str | None,
        detail: str,
    ) -> NoReturn:
        _log.error("policy bundle %s@%s refused: %s (%s)", tenant_id, version, reason.value, detail)
        if self._hook is not None:
            alert = IntegrityAlert(tenant_id, version, reason, stored_hash, recomputed_hash, detail)
            try:
                self._hook(alert)
            except Exception:
                # A broken alert hook must not turn a refusal into some other error.
                _log.exception("policy store alert hook failed for %s@%s", tenant_id, version)
        raise BundleIntegrityError(
            tenant_id=tenant_id,
            version=version,
            reason=reason,
            expected_hash=stored_hash,
            recomputed_hash=recomputed_hash,
            detail=detail,
        ) from None
