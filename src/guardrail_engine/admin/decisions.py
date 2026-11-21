"""The audit query's service (M4-07): ``GET /v1/tenants/{tid}/guardrails/decisions``, auditor only.

It reads one tenant's decision records (:mod:`guardrail_engine.audit`) under the scope the
authorizer issued, and presents them without the floor or anything derived from it. Whether a
tenant rule is floor-derived depends on the bundle version that made the decision, so the
service loads that version's document (verified, through the lifecycle store) and caches the
answer per (tenant, version); a version it can't load hides every rule's numbers for the page.
"""

from __future__ import annotations

import logging
from collections import OrderedDict
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any, Protocol

from guardrail_engine.admin.lifecycle import ScopedLifecycleStores
from guardrail_engine.admin.service import DraftServiceError, _scope_of
from guardrail_engine.admin.tools import floor_derived_keys
from guardrail_engine.audit.query import (
    BadParameterError,
    DecisionQuery,
    next_cursor,
    parse_query,
    present,
)
from guardrail_engine.audit.store import DecisionRecordReader
from guardrail_engine.authz.authorizer import AuthzDecision
from guardrail_engine.policy.catalog import Catalog
from guardrail_engine.policy.document import parse_bundle
from guardrail_engine.tenant_scope import TenantScope

logger = logging.getLogger(__name__)

DECISIONS_ENDPOINT = ("GET", "/v1/tenants/{tid}/guardrails/decisions")
_CACHE = 512


class DerivedKeys(Protocol):
    async def keys(self, scope: TenantScope, version: int) -> frozenset[str]:
        """The compiled keys of the version's tenant rules that are the floor's own. Raises
        if the version can't be read."""
        ...


class DecisionsService:
    def __init__(
        self,
        reader: DecisionRecordReader,
        derived: DerivedKeys,
        *,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._reader = reader
        self._derived = derived
        self._clock = clock
        self._cache: OrderedDict[tuple[str, int], frozenset[str] | None] = OrderedDict()

    async def query(self, decision: AuthzDecision, params: dict[str, str]) -> dict[str, Any]:
        """Raises :class:`DecisionQueryError` for a bad parameter."""
        scope = _scope_of(decision, DECISIONS_ENDPOINT)
        try:
            parsed: DecisionQuery = parse_query(params, self._clock())
        except BadParameterError as e:
            raise DecisionQueryError(e.field, e.message) from None
        rows = await self._reader.page(scope, parsed.flt, parsed.limit, parsed.after)
        hidden: dict[int | None, frozenset[str] | None] = {}
        items = []
        for row in rows:
            version = row.record.get("bundle_version")
            if version not in hidden:
                hidden[version] = await self._hidden(scope, version)
            items.append(present(row.record, hidden[version]))
        return {"items": items, "next_cursor": next_cursor(rows, parsed.limit)}

    async def _hidden(self, scope: TenantScope, version: int | None) -> frozenset[str] | None:
        if not isinstance(version, int) or isinstance(version, bool):
            return None
        key = (scope.tenant_id, version)
        if key in self._cache:
            self._cache.move_to_end(key)
            return self._cache[key]
        try:
            value: frozenset[str] | None = await self._derived.keys(scope, version)
        except Exception:
            logger.warning("the bundle of a decision record could not be read; numbers hidden")
            return None  # not cached: the next page tries again
        self._cache[key] = value
        if len(self._cache) > _CACHE:
            self._cache.popitem(last=False)
        return value


class DecisionQueryError(DraftServiceError):
    """A query parameter is not acceptable (HTTP 400); ``field`` names it."""

    def __init__(self, field: str, message: str) -> None:
        super().__init__(f"{field}: {message}")
        self.field = field
        self.message = message


class LifecycleDerivedKeys:
    """:class:`DerivedKeys` over the lifecycle store: the version's stored document (verified
    on the way out), parsed, and checked against the catalog's floors."""

    def __init__(self, lifecycle: ScopedLifecycleStores, catalog: Catalog) -> None:
        self._lifecycle = lifecycle
        self._catalog = catalog

    async def keys(self, scope: TenantScope, version: int) -> frozenset[str]:
        document = await self._lifecycle.scoped(scope).document(scope.tenant_id, version)
        if document is None:
            raise LookupError("the version is not stored")
        return floor_derived_keys(self._catalog, parse_bundle(document))
