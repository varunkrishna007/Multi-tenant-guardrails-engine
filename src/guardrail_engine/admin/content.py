"""The stored-content read (M5-03): ``GET /v1/tenants/{tid}/guardrails/decisions/{request_id}/
content``, auditor only.

R3 class C: a tenant that turned content storage on can read back the post-redaction text of a
check it asked to keep, by the check's request id (the id the decision record carries), for as
long as its own deletion time has not passed. An expired row is not returned even before the
deletion job has removed it. Nothing is returned for a tenant that never stored content, for
another tenant's request id, or for content that was never stored: all are the same 404, so the
route can't be used to ask whether another request exists.

**Every read leaves a class A event** (:class:`~guardrail_engine.content.model.ContentReadEvent`:
the actor as ``issuer#subject``, the tenant, the request id, the guard point asked for, how many
rows came back, whether it crossed tenants and whether the actor is a platform operator; **never
the content**), written **before** the content is returned, and a read that finds nothing leaves
one too (with 0 rows: someone asked). If the event can't be written the read is refused (503): a
read of personal content that leaves no trail does not happen.

The content is returned and never logged. The tenant comes from the scope the authorizer issued,
and the reader filters on it again (row-level security and a ``tenant_id`` predicate).
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from guardrail_engine.admin.service import DraftServiceError, _scope_of
from guardrail_engine.authz import Principal
from guardrail_engine.authz.authorizer import AuthzDecision
from guardrail_engine.content.model import ContentReadEvent
from guardrail_engine.content.store import ContentReadAudit, ContentReader
from guardrail_engine.policy.schema import GUARD_POINTS

logger = logging.getLogger(__name__)

CONTENT_ENDPOINT = ("GET", "/v1/tenants/{tid}/guardrails/decisions/{request_id}/content")
MAX_REQUEST_ID_CHARS = 256


class ContentQueryError(DraftServiceError):
    """A parameter is not acceptable (HTTP 400); ``field`` names it."""

    def __init__(self, field: str, message: str) -> None:
        super().__init__(f"{field}: {message}")
        self.field = field
        self.message = message


class StoredContentNotFoundError(DraftServiceError):
    """No unexpired stored content for that request id (HTTP 404)."""


class ContentAuditUnavailableError(DraftServiceError):
    """The class A event of a read could not be written, so nothing is returned (HTTP 503)."""


class StoredContentService:
    def __init__(
        self,
        reader: ContentReader,
        audit: ContentReadAudit | None = None,
        *,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        """``audit`` defaults to the reader itself when it can record reads (both stores do);
        with neither, every read is refused."""
        self._reader = reader
        self._audit: ContentReadAudit | None = audit or (
            reader if hasattr(reader, "record_read") else None  # type: ignore[assignment]
        )
        self._clock = clock

    async def get(
        self,
        decision: AuthzDecision,
        principal: Principal,
        request_id: str,
        params: dict[str, str],
    ) -> dict[str, Any]:
        scope = _scope_of(decision, CONTENT_ENDPOINT)
        if not 1 <= len(request_id) <= MAX_REQUEST_ID_CHARS or not request_id.isprintable():
            raise ContentQueryError("request_id", "not a request id")
        unknown = set(params) - {"guard_point"}
        if unknown:
            raise ContentQueryError(sorted(unknown)[0], "not a parameter of this route")
        guard_point = params.get("guard_point")
        if guard_point is not None and guard_point not in GUARD_POINTS:
            raise ContentQueryError("guard_point", f"one of {', '.join(GUARD_POINTS)}")
        rows = await self._reader.get(scope, request_id, guard_point)
        await self._record(scope.tenant_id, decision, principal, request_id, guard_point, len(rows))
        if not rows:
            raise StoredContentNotFoundError("no stored content for that request")
        return {
            "request_id": request_id,
            "items": [
                {
                    "guard_point": r.guard_point,
                    "ts": r.ts.isoformat(),
                    "retain_until": r.retain_until.isoformat(),
                    "content": r.content,
                    "truncated": r.truncated,
                    "content_sha256": r.content_sha256,
                    "bundle_version": r.bundle_version,
                }
                for r in rows
            ],
        }

    async def _record(
        self,
        tenant_id: str,
        decision: AuthzDecision,
        principal: Principal,
        request_id: str,
        guard_point: str | None,
        items: int,
    ) -> None:
        event = ContentReadEvent(
            tenant_id=tenant_id,
            at=self._clock(),
            actor=principal.actor,
            request_id=request_id,
            guard_point=guard_point,
            items=items,
            cross_tenant=decision.cross_tenant,
            operator=principal.platform_operator,
        )
        try:
            if self._audit is None:
                raise RuntimeError("no class A sink for content reads")
            await self._audit.record_read(event)
        except Exception as exc:
            logger.error("a stored-content read event could not be written: %s", type(exc).__name__)
            raise ContentAuditUnavailableError("the read could not be recorded") from None
