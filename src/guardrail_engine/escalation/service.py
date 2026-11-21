"""The escalation queue's Admin API core (M4-05): list, read and resolve, framework-independent.
The REST adapter is ``admin/adapters/fastapi_app.py``.

**Roles.** ``GET escalations`` and ``GET escalations/{id}`` need ``viewer`` (every role includes
it): a viewer sees an item's metadata (rules by key and action, hashes, status, who resolved it
and the decision). The **content** the item holds for a reviewer, and the reviewer's free-text
reason, are shown only to a principal holding ``guardrail_reviewer`` (``GET {id}`` only; a list
never carries content). ``POST escalations/{id}/resolve`` needs ``guardrail_reviewer``.

**Resolving.** The body is ``{"decision": "allow"|"block", "reason": "...",
"promote_content": false, "deidentified_content": "..."}`` (the last two optional). In order:

1. The actor is ``issuer#subject`` from the principal, never from the body. If the item records
   who triggered it (``triggered_by``) and it is the actor, the resolution is refused (403
   ``self_resolution``). The check context carries no end-user identity today, so that field is
   None and the rule can't fire yet: see ``docs/m4-05-escalation-queue.md``.
2. The item moves ``open`` to ``resolved`` once, with a class A event (actor, decision, a hash of
   the reason), in one step. A second resolution is 409 ``already_resolved``.
3. **The golden label** (R3): the label (``allow`` or ``block`` by the decision) always goes to
   the golden set. The content goes with it only if the tenant's ``store_content`` was ``full``
   when the item was routed (class C on), or the reviewer promoted the item
   (``promote_content``). For a tenant whose packs need a BAA (healthcare) a promoted item must
   be de-identified first: the reviewer sends ``deidentified_content``, and that text, not the
   held one, is what is labelled; without it the resolution is refused (422) before anything is
   changed. Otherwise the label is a **hash-only placeholder** (the content's hash, stored
   quarantined so it is never sent to the model and never counted as evidence). A label with
   content goes through the harm-vocabulary tripwire like any upload (a hit is stored
   quarantined and never sent). The label creation is its own class A event.

Step 3 follows step 2 and is **idempotent**: the golden set's id comes from the item, so if the
engine fails between the two (a 5xx), the same ``POST`` again, by the same actor with the same
decision, finishes the label and returns 200. Anyone else gets 409.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from guardrail_engine.admin.golden import GoldenService, GoldenSetInfo
from guardrail_engine.admin.service import DecisionError, DraftError, DraftInvalidError, _scope_of
from guardrail_engine.authz.authorizer import AuthzDecision
from guardrail_engine.authz.model import Principal, Role, role_satisfies
from guardrail_engine.escalation.model import (
    DECISIONS,
    DEFAULT_LIST_LIMIT,
    LABEL_CONTENT,
    LABEL_HASH_ONLY,
    MAX_CONTENT_CHARS,
    MAX_LIST_LIMIT,
    MAX_REASON_CHARS,
    STATUSES,
    STORE_FULL,
    AlreadyResolvedError,
    DeidentifiedContentRequiredError,
    EscalationAuditEvent,
    EscalationItem,
    EscalationNotFoundError,
    InvalidQueryError,
    ItemFilter,
    ItemPage,
    OperatorResolutionError,
    Resolution,
    SelfResolutionError,
    decode_cursor,
    encode_cursor,
)
from guardrail_engine.escalation.store import ScopedEscalationStores
from guardrail_engine.policy.json_document import parse_json_text
from guardrail_engine.policy.schema import GUARD_POINTS
from guardrail_engine.tenant_scope import TenantScope

LIST_ESCALATIONS = ("GET", "/v1/tenants/{tid}/guardrails/escalations")
GET_ESCALATION = ("GET", "/v1/tenants/{tid}/guardrails/escalations/{id}")
RESOLVE_ESCALATION = ("POST", "/v1/tenants/{tid}/guardrails/escalations/{id}/resolve")
MAX_BODY_BYTES = 256 * 1024
_ITEM_ID = re.compile(r"esc_[0-9a-f]{24}")
_REQUEST_FIELDS = {"decision", "reason", "promote_content", "deidentified_content"}
MAX_RULE_FILTER_CHARS = 128

NeedsDeidentification = Callable[[TenantScope], Awaitable[bool]]
"""Whether a tenant's promoted content must be de-identified first (healthcare, R3)."""


async def _never(scope: TenantScope) -> bool:
    return False


@dataclass(frozen=True, slots=True)
class LabelInfo:
    set_id: str
    mode: str
    quarantined: bool


@dataclass(frozen=True, slots=True)
class ResolveResult:
    item: EscalationItem
    label: LabelInfo | None


def item_view(
    item: EscalationItem, *, reviewer: bool, with_content: bool = False
) -> dict[str, Any]:
    """An item as the API shows it. Never a probability (the item holds none)."""
    body: dict[str, Any] = {
        "id": item.id,
        "request_id": item.request_id,
        "guard_point": item.guard_point,
        "created_at": item.created_at.isoformat(),
        "target": item.target,
        "status": item.status,
        "reason": item.reason,
        "bundle_version": item.bundle_version,
        "rules": [
            {"key": r.key, "action": r.action, "mode": r.mode, "layer": r.layer} for r in item.rules
        ],
        "content_sha256": item.content_sha256,
        "content_held": item.content_held,
        "content_truncated": item.content_truncated,
        "decision": item.decision,
        "resolved_by": item.resolved_by,
        "resolved_at": None if item.resolved_at is None else item.resolved_at.isoformat(),
        "label_set_id": item.label_set_id,
        "label_mode": item.label_mode,
    }
    if reviewer:
        body["resolution_reason"] = item.resolution_reason
        if with_content:
            body["content"] = item.content
    return body


def _parse_time(value: str | None, name: str) -> datetime | None:
    if value is None:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        raise InvalidQueryError(name) from None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


class EscalationService:
    def __init__(
        self,
        store: ScopedEscalationStores,
        golden: GoldenService,
        *,
        needs_deidentification: NeedsDeidentification = _never,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        require_issuer: bool = False,
    ) -> None:
        self._store = store
        self._golden = golden
        self._needs_deid = needs_deidentification
        self._clock = clock
        self._require_issuer = require_issuer

    # ------------------------------------------------------------------ reads

    async def list_items(
        self,
        decision: AuthzDecision,
        *,
        status: str | None = None,
        guard_point: str | None = None,
        rule: str | None = None,
        since: str | None = None,
        until: str | None = None,
        cursor: str | None = None,
        limit: str | None = None,
    ) -> ItemPage:
        """One page, oldest first. Filters that are out of range raise
        :class:`InvalidQueryError`; a cursor this API didn't issue,
        :class:`InvalidCursorError`."""
        scope = _scope_of(decision, LIST_ESCALATIONS)
        if status is not None and status not in STATUSES:
            raise InvalidQueryError("status")
        if guard_point is not None and guard_point not in GUARD_POINTS:
            raise InvalidQueryError("guard_point")
        if rule is not None and not 1 <= len(rule) <= MAX_RULE_FILTER_CHARS:
            raise InvalidQueryError("rule")
        n = DEFAULT_LIST_LIMIT
        if limit is not None:
            if not limit.isascii() or not limit.isdigit() or not 1 <= int(limit) <= MAX_LIST_LIMIT:
                raise InvalidQueryError("limit")
            n = int(limit)
        filt = ItemFilter(
            status, guard_point, rule, _parse_time(since, "since"), _parse_time(until, "until")
        )
        after = None if cursor is None else decode_cursor(cursor)
        rows = await self._store.scoped(scope).list(scope.tenant_id, filt, after=after, limit=n + 1)
        more = len(rows) > n
        page = rows[:n]
        return ItemPage(tuple(page), encode_cursor(page[-1].seq) if more and page else None)

    async def get_item(self, decision: AuthzDecision, item_id: str) -> EscalationItem:
        scope = _scope_of(decision, GET_ESCALATION)
        if not _ITEM_ID.fullmatch(item_id):
            raise EscalationNotFoundError()
        item = await self._store.scoped(scope).get(scope.tenant_id, item_id)
        if item is None:
            raise EscalationNotFoundError()
        return item

    # ------------------------------------------------------------------ resolve

    async def resolve(
        self, decision: AuthzDecision, principal: Principal, item_id: str, body: bytes
    ) -> ResolveResult:
        scope = _scope_of(decision, RESOLVE_ESCALATION)
        if principal.platform_operator:
            # Decision: an operator crossing tenants may read (audited) but never decides
            # a tenant's item or writes its labels, as R2 refuses operators as approvers.
            raise OperatorResolutionError()
        if not role_satisfies(principal.roles, Role.GUARDRAIL_REVIEWER):
            raise DecisionError("resolving needs the reviewer role")
        if self._require_issuer and principal.issuer is None:
            raise DecisionError("the principal has no issuer; the audit actor needs one")
        if len(body) > MAX_BODY_BYTES:
            raise DraftInvalidError(
                [DraftError("escalation.too_large", "$", f"at most {MAX_BODY_BYTES} bytes")]
            )
        verdict, reason, promote, deidentified = _parse_resolution(body)
        if not _ITEM_ID.fullmatch(item_id):
            raise EscalationNotFoundError()
        store = self._store.scoped(scope)
        item = await store.get(scope.tenant_id, item_id)
        if item is None:
            raise EscalationNotFoundError()
        actor = principal.actor
        if item.triggered_by is not None and item.triggered_by == actor:
            raise SelfResolutionError()
        label_text = await self._label_text(scope, item, promote, deidentified)
        now = self._clock()
        if item.resolved:
            retry = (
                item.resolved_by == actor and item.decision == verdict and item.label_set_id is None
            )
            if not retry:
                raise AlreadyResolvedError()
        else:
            item = await store.resolve(
                scope.tenant_id,
                item_id,
                Resolution(verdict, reason, actor, now),
                self._event(scope, decision, principal, item, "resolved", now, verdict, reason),
            )
        info, mode = await self._golden.add_escalation_label(
            decision,
            principal,
            RESOLVE_ESCALATION,
            item_id=item.id,
            guard_point=item.guard_point,
            label=verdict,
            content=label_text,
            content_sha256=item.content_sha256,
        )
        item = await store.attach_label(
            scope.tenant_id,
            item.id,
            info.set_id,
            LABEL_CONTENT if mode == LABEL_CONTENT else LABEL_HASH_ONLY,
            self._event(
                scope, decision, principal, item, "label_created", now, verdict, None, info, mode
            ),
        )
        return ResolveResult(item, _label_info(info, mode))

    async def _label_text(
        self, scope: TenantScope, item: EscalationItem, promote: bool, deidentified: str | None
    ) -> str | None:
        """The text the label may carry under R3, or None for a hash-only placeholder. Raises
        before anything is changed when the request can't be honoured."""
        if deidentified is not None and not promote:
            raise DraftInvalidError(
                [
                    DraftError(
                        "escalation.deidentified_without_promote",
                        "$.deidentified_content",
                        "send deidentified_content only with promote_content",
                    )
                ]
            )
        if promote:
            if deidentified is not None:
                return deidentified
            if await self._needs_deid(scope):
                raise DeidentifiedContentRequiredError()
            return item.content if _usable(item) else None
        if item.store_content == STORE_FULL:  # class C was on: the content goes with the label
            return item.content if _usable(item) else None
        return None

    def _event(
        self,
        scope: TenantScope,
        decision: AuthzDecision,
        principal: Principal,
        item: EscalationItem,
        action: str,
        now: datetime,
        verdict: str,
        reason: str | None,
        info: GoldenSetInfo | None = None,
        mode: str | None = None,
    ) -> EscalationAuditEvent:
        return EscalationAuditEvent(
            at=now,
            tenant_id=scope.tenant_id,
            item_id=item.id,
            action=action,
            actor=principal.actor,
            decision=verdict,
            reason_sha256=None
            if reason is None
            else hashlib.sha256(reason.encode("utf-8", "surrogatepass")).hexdigest(),
            label_set_id=None if info is None else info.set_id,
            label_mode=mode,
            cross_tenant=decision.cross_tenant,
            operator=principal.platform_operator,
        )


def _usable(item: EscalationItem) -> bool:
    return item.content is not None and not item.content_truncated


def _label_info(info: GoldenSetInfo, mode: str) -> LabelInfo:
    return LabelInfo(info.set_id, mode, bool(info.quarantined))


def _parse_resolution(body: bytes) -> tuple[str, str, bool, str | None]:
    doc, problems = parse_json_text(body)
    if problems:
        raise DraftInvalidError([DraftError(str(p.code), p.path, p.message) for p in problems])
    errors: list[DraftError] = []

    def bad(code: str, path: str, message: str) -> None:
        errors.append(DraftError(f"escalation.{code}", path, message))

    if not isinstance(doc, dict):
        raise DraftInvalidError([DraftError("escalation.not_object", "$", "an object")])
    for extra in sorted(set(doc) - _REQUEST_FIELDS):
        bad("unknown_field", f"$.{extra}", "not a field of a resolution")
    verdict = doc.get("decision")
    if verdict not in DECISIONS:
        bad("decision", "$.decision", f"one of {', '.join(DECISIONS)}")
    reason = doc.get("reason")
    if (
        not isinstance(reason, str)
        or not reason.strip()
        or len(reason) > MAX_REASON_CHARS
        or not reason.isprintable()
    ):
        bad("reason", "$.reason", f"printable text of 1 to {MAX_REASON_CHARS} characters")
    promote = doc.get("promote_content", False)
    if not isinstance(promote, bool):
        bad("promote_content", "$.promote_content", "true or false")
    deidentified = doc.get("deidentified_content")
    if deidentified is not None and (
        not isinstance(deidentified, str) or not 1 <= len(deidentified) <= MAX_CONTENT_CHARS
    ):
        bad("deidentified_content", "$.deidentified_content", "text, 1 to 100000 characters")
    if errors:
        raise DraftInvalidError(errors)
    return verdict, reason, bool(promote), deidentified  # type: ignore[return-value]


__all__ = [
    "GET_ESCALATION",
    "LIST_ESCALATIONS",
    "RESOLVE_ESCALATION",
    "EscalationService",
    "LabelInfo",
    "ResolveResult",
    "item_view",
]
