"""Requesting and granting two-person approval, using it, and telling the admins (M5-02, R2).

Like every service here, each method takes the :class:`AuthzDecision` the authorizer returned and
uses only ``decision.scope`` as the tenant.

**Who may approve** (R2). The approver must be a *different human* admin of the same tenant:

* not the requester (same ``issuer#subject``), ``self_approval``;
* not a service account (``Principal.service_account``), ``service_account_approval``;
* not a platform operator, even one who crosses into the tenant (``Principal.platform_operator``),
  ``operator_approval`` (the same rule as for tool review and escalation resolution);
* and the authorizer has already required the ``guardrail_admin`` role on the tenant's own path.

**Two humans, end to end** (R2). A service account may not *request* an approval
(``service_account_request``), and whoever publishes or promotes with an approval must be a human
(``service_account_publish``) who is not the approver (``approver_publish``). The requester may
be the publisher. So the requester, the approver and the publisher are never one human plus
a machine: at least two people are involved.

**Using an approval** is the publish service's step (:meth:`ApprovalService.use_for`): it
finds the approval, persists an expiry it finds, and refuses a missing, pending, cancelled,
expired, stale or used approval with its own code. The approval is then consumed by the
lifecycle store in the publish's own transaction, which checks it again against the locked row.

**A draft edit cancels the approvals for the old draft** (:meth:`ApprovalService.draft_changed`,
called by the draft service after every draft write). The cancellation is housekeeping and an
audit line; safety never depends on it, because an approval is checked against the draft hash at
use, so a cancellation that didn't happen can't let a changed draft through.

**Notification** (:meth:`ApprovalService.notify_change`): a rollback, or raising an enforce
candidate's share, needs no second approver but is told to the tenant's other admins: an alert on
the existing alert sink plus a class A ``notified`` event.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from datetime import UTC, datetime

from guardrail_engine.admin.approvals import (
    APPROVAL_ID_PATTERN,
    APPROVAL_TTL,
    STATUSES,
    Approval,
    ApprovalEvent,
    ApprovalNotFoundError,
    ApprovalNotRequiredError,
    ApprovalPage,
    ApprovalPosition,
    ApprovalStaleError,
    ApprovalUse,
    InvalidApprovalQueryError,
    OperatorApprovalError,
    ScopedApprovalStores,
    SelfApprovalError,
    ServiceAccountApprovalError,
    ServiceAccountRequestError,
    approval_required,
    check_approvable,
    check_usable,
    decode_approval_cursor,
    encode_approval_cursor,
    new_approval_id,
    parse_list_limit,
)
from guardrail_engine.admin.drafts import ScopedDraftStores
from guardrail_engine.admin.lifecycle import NoCandidateError, ScopedLifecycleStores
from guardrail_engine.admin.service import (
    DecisionError,
    DraftConflictError,
    DraftError,
    DraftInvalidError,
    NoDraftError,
    PreconditionRequiredError,
    TenantUnavailableError,
    _convert,
    _if_match_ok,
    _scope_of,
)
from guardrail_engine.authz.authorizer import AuthzDecision
from guardrail_engine.authz.model import Principal
from guardrail_engine.gateway.sinks import (
    ALERT_APPROVED_VERSION_CHANGE,
    Alert,
    AlertSeverity,
    AlertSink,
)
from guardrail_engine.guard.tenants import TenantDirectory, TenantProfile
from guardrail_engine.policy.json_document import parse_json_text
from guardrail_engine.tenant_scope import TenantScope

logger = logging.getLogger(__name__)

REQUEST = ("POST", "/v1/tenants/{tid}/guardrails/draft/approvals")
APPROVE = ("POST", "/v1/tenants/{tid}/guardrails/draft/approvals/{id}/approve")
LIST = ("GET", "/v1/tenants/{tid}/guardrails/draft/approvals")

_REQUEST_FIELDS = {"action"}


def _bad(code: str, path: str, message: str) -> DraftInvalidError:
    return DraftInvalidError([DraftError(code, path, message)])


def parse_request(body: bytes) -> str:
    """``{"action"?: "publish" | "promote"}`` (default ``publish``), strictly."""
    if not body.strip():
        return "publish"
    doc, problems = parse_json_text(body)
    if problems:
        raise DraftInvalidError(_convert(problems))
    if not isinstance(doc, dict):
        raise _bad("approval.not_object", "$", "the request is an object")
    errors = [
        DraftError("approval.unknown_field", f"$.{extra}", "not a field")
        for extra in sorted(set(doc) - _REQUEST_FIELDS)
    ]
    action = doc.get("action", "publish")
    if action not in ("publish", "promote"):
        errors.append(DraftError("approval.action", "$.action", "publish or promote"))
    if errors:
        raise DraftInvalidError(errors)
    return str(action)


class ApprovalService:
    def __init__(
        self,
        approvals: ScopedApprovalStores,
        drafts: ScopedDraftStores,
        lifecycle: ScopedLifecycleStores,
        tenants: TenantDirectory,
        *,
        alerts: AlertSink | None = None,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        require_issuer: bool = False,
    ) -> None:
        self._approvals = approvals
        self._drafts = drafts
        self._lifecycle = lifecycle
        self._tenants = tenants
        self._alerts = alerts
        self._clock = clock
        self._require_issuer = require_issuer

    # ------------------------------------------------------------------ helpers

    def _check_actor(self, principal: Principal) -> None:
        if self._require_issuer and principal.issuer is None:
            raise DecisionError("the principal has no issuer; the audit actor needs one")

    async def _profile(self, scope: TenantScope) -> TenantProfile:
        profile = await self._tenants.get(scope.tenant_id)
        if profile is None:
            raise TenantUnavailableError()
        return profile

    @staticmethod
    def _event(
        approval: Approval,
        decision: AuthzDecision,
        principal: Principal,
        action: str,
        at: datetime,
        detail: str = "",
    ) -> ApprovalEvent:
        return ApprovalEvent(
            at, principal.actor, approval.tenant_id, action, approval.id, approval.draft_hash,
            approval.version, detail, decision.cross_tenant, principal.platform_operator,
        )  # fmt: skip

    async def _expire(
        self,
        scope: TenantScope,
        decision: AuthzDecision,
        principal: Principal,
        approval: Approval,
        now: datetime,
        when: str,
    ) -> None:
        """Persist that an open approval found past its expiry is expired (expiry-at-use), with
        its class A event. The caller then raises."""
        if approval.status in ("pending", "approved") and now >= approval.expires_at:
            event = self._event(approval, decision, principal, "expired", now, f"found {when}")
            await self._approvals.scoped(scope).expire(
                scope.tenant_id, approval.id, at=now, event=event
            )

    async def _candidate_binding(self, scope: TenantScope) -> tuple[int, str]:
        """The candidate's version and the draft hash it was published from, for a promotion's
        approval. Raises :class:`NoCandidateError`, or a 422 when the candidate has no draft
        hash (a platform re-pin candidate, which has no draft to approve)."""
        store = self._lifecycle.scoped(scope)
        state = await store.state(scope.tenant_id)
        if state.candidate is None:
            raise NoCandidateError()
        version = state.candidate.version
        events = await store.events(scope.tenant_id)
        hashes = [
            e.draft_hash
            for e in events
            if e.action == "publish" and e.version == version and e.draft_hash
        ]
        if not hashes:
            raise _bad(
                "approval.no_draft_hash", "$.action",
                "the candidate was not published from a draft, so it has nothing to approve",
            )  # fmt: skip
        return version, hashes[-1]

    # ------------------------------------------------------------------ request

    async def request(
        self,
        decision: AuthzDecision,
        principal: Principal,
        body: bytes,
        if_match: str | None,
    ) -> Approval:
        """Ask for an approval of the draft (``publish``, tied to the draft's hash: send the
        draft's ETag in ``If-Match``) or of the candidate's promotion to enforce (``promote``)."""
        scope = _scope_of(decision, REQUEST)
        self._check_actor(principal)
        if principal.service_account:  # a machine can't be one of the two people
            raise ServiceAccountRequestError()
        action = parse_request(body)
        profile = await self._profile(scope)
        if not approval_required(profile):
            raise ApprovalNotRequiredError()
        version: int | None = None
        if action == "publish":
            draft = await self._drafts.scoped(scope).get(scope.tenant_id)
            if draft is None:
                raise NoDraftError()
            if if_match is None:
                raise PreconditionRequiredError()
            if not _if_match_ok(if_match, draft.etag):
                raise DraftConflictError(draft.etag)
            draft_hash = draft.etag.strip('"')
        else:
            version, draft_hash = await self._candidate_binding(scope)
        now = self._clock()
        approval = Approval(
            id=new_approval_id(), tenant_id=scope.tenant_id, action=action, draft_hash=draft_hash,
            version=version, requested_by=principal.actor, requested_at=now,
            expires_at=now + APPROVAL_TTL,
        )  # fmt: skip
        event = self._event(approval, decision, principal, "requested", now, action)
        await self._approvals.scoped(scope).request(scope.tenant_id, approval, event)
        return approval

    # ------------------------------------------------------------------ approve

    async def approve(
        self, decision: AuthzDecision, principal: Principal, approval_id: str
    ) -> Approval:
        scope = _scope_of(decision, APPROVE)
        self._check_actor(principal)
        # R2: who may not approve, whatever the approval is.
        if principal.platform_operator:
            raise OperatorApprovalError()
        if principal.service_account:
            raise ServiceAccountApprovalError()
        store = self._approvals.scoped(scope)
        approval = await store.get(scope.tenant_id, approval_id)
        if approval is None:
            raise ApprovalNotFoundError()
        if principal.actor == approval.requested_by:
            raise SelfApprovalError()
        now = self._clock()
        await self._expire(scope, decision, principal, approval, now, "when approved")
        check_approvable(approval, now)
        await self._refuse_if_stale(scope, decision, principal, approval, now)
        expires_at = now + APPROVAL_TTL
        event = self._event(approval, decision, principal, "approved", now)
        return await store.approve(
            scope.tenant_id, approval.id,
            approver=principal.actor, at=now, expires_at=expires_at, event=event,
        )  # fmt: skip

    async def _refuse_if_stale(
        self,
        scope: TenantScope,
        decision: AuthzDecision,
        principal: Principal,
        approval: Approval,
        now: datetime,
    ) -> None:
        """An approval for a draft that has changed (or a candidate that is gone) isn't granted:
        it is cancelled, and the request is refused as stale."""
        if approval.action == "publish":
            draft = await self._drafts.scoped(scope).get(scope.tenant_id)
            current = None if draft is None else draft.etag.strip('"')
            stale = current != approval.draft_hash
        else:
            try:
                binding = await self._candidate_binding(scope)
            except (NoCandidateError, DraftInvalidError):
                binding = None
            stale = binding != (approval.version, approval.draft_hash)
        if stale:
            await self._cancel_one(scope, decision, principal, approval, now, "stale when approved")
            raise ApprovalStaleError()

    async def _cancel_one(
        self,
        scope: TenantScope,
        decision: AuthzDecision,
        principal: Principal,
        approval: Approval,
        now: datetime,
        reason: str,
    ) -> None:
        await self._approvals.scoped(scope).cancel(
            scope.tenant_id, approval.id, at=now, reason=reason,
            event=self._event(approval, decision, principal, "cancelled", now, reason),
        )  # fmt: skip

    # ------------------------------------------------------------------ a draft edit

    async def draft_changed(
        self, scope: TenantScope, decision: AuthzDecision, principal: Principal, new_etag: str
    ) -> list[Approval]:
        """After a draft write: cancel every open ``publish`` approval of the tenant that was
        for another draft (the approvals for the new content, if any, stay). Never raises: the
        draft is already stored, and an approval that isn't cancelled still can't be used for a
        draft it doesn't match."""
        now = self._clock()
        try:
            return await self._approvals.scoped(scope).cancel_publish_approvals(
                scope.tenant_id,
                keep_draft_hash=new_etag.strip('"'),
                at=now,
                reason="draft edited",
                event_for=lambda a: self._event(
                    a, decision, principal, "cancelled", now, "draft edited"
                ),
            )
        except Exception:
            logger.exception("approvals could not be cancelled after a draft edit")
            return []

    # ------------------------------------------------------------------ use

    async def use_for(
        self,
        scope: TenantScope,
        decision: AuthzDecision,
        principal: Principal,
        *,
        approval_id: str,
        action: str,
        draft_hash: str,
        version: int | None,
        for_version: int | None = None,
    ) -> ApprovalUse:
        """The approval for a publish or promotion, ready for the lifecycle store to consume, or
        an error naming why not: not found, pending, cancelled, expired (persisted here, with its
        event), stale (another draft, candidate or action), used, or the user is a
        service account or the approver. ``for_version`` is the version the publish creates or
        the promotion activates, which the ``consumed`` event records."""
        now = self._clock()
        approval = await self._approvals.scoped(scope).get(scope.tenant_id, approval_id)
        if approval is None:
            raise ApprovalNotFoundError()
        use = ApprovalUse(
            approval_id, action, draft_hash, version, principal.actor, now,
            decision.cross_tenant, principal.platform_operator, principal.service_account,
            for_version,
        )  # fmt: skip
        await self._expire(scope, decision, principal, approval, now, "when used")
        check_usable(approval, use)
        return use

    async def published_under_approval(self, scope: TenantScope, version: int) -> str | None:
        """The id of the approval that the publish of ``version`` consumed, from the class A
        trail, or None when that publish used none. Not read from the publish's note,
        which carries the publisher's own words."""
        trail = await self._approvals.scoped(scope).events(scope.tenant_id)
        for event in reversed(trail):
            if (
                event.action == "consumed"
                and event.version == version
                and event.detail == "used by publish"
                and event.approval_id is not None
            ):
                return event.approval_id
        return None

    # ------------------------------------------------------------------ list

    async def list_approvals(
        self,
        decision: AuthzDecision,
        *,
        status: str | None = None,
        cursor: str | None = None,
        limit: str | None = None,
    ) -> ApprovalPage:
        """One page of the tenant's approvals, newest request first: open ones and the recent
        past (consumed, cancelled, expired). A bad status or limit raises
        :class:`InvalidApprovalQueryError`, a cursor this API didn't issue
        :class:`InvalidApprovalCursorError`."""
        scope = _scope_of(decision, LIST)
        if status is not None and status not in STATUSES:
            raise InvalidApprovalQueryError("status")
        n = parse_list_limit(limit)
        after = None if cursor is None else decode_approval_cursor(cursor)
        rows = await self._approvals.scoped(scope).list_approvals(
            scope.tenant_id, status=status, after=after, limit=n + 1
        )
        page = rows[:n]
        more = len(rows) > n
        next_cursor = (
            encode_approval_cursor(ApprovalPosition(page[-1].requested_at, page[-1].id))
            if more and page
            else None
        )
        return ApprovalPage(tuple(page), next_cursor)

    # ------------------------------------------------------------------ notification

    async def notify_change(
        self,
        scope: TenantScope,
        decision: AuthzDecision,
        principal: Principal,
        *,
        change: str,
        version: int,
        detail: str,
    ) -> None:
        """Tell the tenant's admins of a change that needs no second approver (a rollback, or
        a larger share for an enforce candidate): an alert on the existing sink and a class A
        ``notified`` event. After the change committed, so it never fails or undoes it."""
        now = self._clock()
        sent = False
        if self._alerts is not None:
            alert = Alert(
                severity=AlertSeverity.WARNING,
                kind=ALERT_APPROVED_VERSION_CHANGE,
                message=f"{principal.actor} {detail} on tenant {scope.tenant_id}; this needed no "
                "second approver, so the tenant's other admins are told",
                key_id="",
                tenant_id=scope.tenant_id,
                guard_point="",
                reason=change,
                dedupe_key=f"{ALERT_APPROVED_VERSION_CHANGE}:{scope.tenant_id}:{change}:"
                f"{version}:{int(now.timestamp())}",
            )
            try:
                await asyncio.to_thread(self._alerts.emit, alert)
                sent = True
            except Exception:
                logger.exception("the admin notification could not be sent")
        event = ApprovalEvent(
            now, principal.actor, scope.tenant_id, "notified", None, None, version,
            f"{change}: {detail}; alert {'sent' if sent else 'not sent'}"[:500],
            decision.cross_tenant, principal.platform_operator,
        )  # fmt: skip
        try:
            await self._approvals.scoped(scope).record(scope.tenant_id, event)
        except Exception:
            logger.exception("the admin notification could not be recorded")


__all__ = [
    "APPROVAL_ID_PATTERN", "APPROVE", "LIST", "REQUEST", "ApprovalService", "parse_request",
]  # fmt: skip
