"""Two-person approval: the records, the errors, the storage port and the in-memory store (M5-02,
R2). The service that requests and approves is :mod:`guardrail_engine.admin.approval_service`; the
lifecycle store consumes an approval in the same step as the publish or promotion that uses it.

An **approval** is a request that one admin (the requester) makes and a *different* human admin
of the same tenant approves. It is tied to a hash and used once:

* a ``publish`` approval to the **draft hash** (the draft's ETag without its quotes). Any edit to
  the draft changes the hash, so the approval no longer matches and is cancelled;
* a ``promote`` approval to the **candidate** (its version and the draft hash the candidate was
  published from), for promoting a shadow candidate to enforce (R2).

It expires **72 hours** after it was approved (a request nobody approves lapses 72 hours after it
was made), by the service's injected clock. It is single use: consuming it is a narrow update
that happens in the lifecycle transaction of the publish that uses it, under the tenant's
lifecycle advisory lock, so two publishes can't both use it and a publish that fails doesn't burn
it.

Every request, approval, cancellation, expiry-at-use, consumption and admin notification is a
class A event (:class:`ApprovalEvent`) with the actor, written in the step it describes.
"""

from __future__ import annotations

import base64
import binascii
import re
import secrets
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from typing import Protocol

from guardrail_engine.admin.service import DraftServiceError
from guardrail_engine.guard.tenants import TenantProfile
from guardrail_engine.store.port import ScopeMismatchError
from guardrail_engine.tenant_scope import TenantScope

APPROVAL_TTL = timedelta(hours=72)
ACTIONS = ("publish", "promote")
STATUSES = ("pending", "approved", "consumed", "cancelled", "expired")
EVENT_ACTIONS = ("requested", "approved", "cancelled", "expired", "consumed", "notified")
MAX_DETAIL_CHARS = 500
DEFAULT_LIST_LIMIT = 50
MAX_LIST_LIMIT = 100
APPROVAL_ID_PREFIX = "apr_"
APPROVAL_ID_PATTERN = r"apr_[0-9a-f]{24}"


def new_approval_id() -> str:
    return APPROVAL_ID_PREFIX + secrets.token_hex(12)


def approval_required(profile: TenantProfile) -> bool:
    """R2: enforcing (publish in enforce, or promoting a candidate to enforce) needs a second
    person for every tenant on a regulated tier, and for a standard tenant that opted in
    (``require_two_person``, the standard-tier opt-in). Reads the tenant's real tier attribute
    (M5-01: ``TenantAttributes.regulated``, set only by a platform operator), at the time of the
    call: a tier raise needs approval from the next publish on."""
    return profile.attributes.regulated or profile.require_two_person


# --------------------------------------------------------------------------- records


@dataclass(frozen=True, slots=True)
class Approval:
    id: str
    tenant_id: str
    action: str
    """``publish`` or ``promote``."""
    draft_hash: str
    """``sha256:<hex>``: the draft's hash for ``publish``; for ``promote`` the hash of the draft
    the candidate was published from."""
    version: int | None
    """The candidate's version, for ``promote``; None for ``publish``."""
    requested_by: str
    requested_at: datetime
    expires_at: datetime
    status: str = "pending"
    approved_by: str | None = None
    approved_at: datetime | None = None
    consumed_by: str | None = None
    consumed_at: datetime | None = None
    closed_at: datetime | None = None
    """When it was cancelled or found expired."""
    close_reason: str | None = None

    def __post_init__(self) -> None:
        if self.action not in ACTIONS:
            raise ValueError(f"unknown approval action {self.action!r}")
        if self.status not in STATUSES:
            raise ValueError(f"unknown approval status {self.status!r}")


@dataclass(frozen=True, slots=True)
class ApprovalEvent:
    """A class A event: who did what to which approval (or, for ``notified``, which change of an
    approved version the tenant's admins were told about)."""

    at: datetime
    actor: str
    tenant_id: str
    action: str
    approval_id: str | None = None
    draft_hash: str | None = None
    version: int | None = None
    detail: str = ""
    cross_tenant: bool = False
    operator: bool = False

    def __post_init__(self) -> None:
        if self.action not in EVENT_ACTIONS:
            raise ValueError(f"unknown approval event {self.action!r}")
        if len(self.detail) > MAX_DETAIL_CHARS:
            raise ValueError("an approval event's detail is bounded")


@dataclass(frozen=True, slots=True)
class ApprovalUse:
    """What a publish or promotion hands the lifecycle store to consume an approval in its own
    transaction: which approval, what it must match, and the class A facts of the consumer."""

    approval_id: str
    action: str
    draft_hash: str
    version: int | None
    actor: str
    at: datetime
    cross_tenant: bool = False
    operator: bool = False
    service_account: bool = False
    """The consumer is a machine identity: it may not publish or promote."""
    for_version: int | None = None
    """The version the publish creates or the promotion activates. The ``consumed`` event records
    it, so a later promotion can tell which candidate was published under an approval."""


# --------------------------------------------------------------------------- errors


class ApprovalNotRequiredError(DraftServiceError):
    """The tenant's enforce publishes don't need a second person (HTTP 409)."""


class ApprovalNotFoundError(DraftServiceError):
    """No such approval for this tenant (HTTP 404)."""


class ApprovalPendingError(DraftServiceError):
    """The approval hasn't been approved yet (HTTP 409 ``approval_pending``)."""


class ApprovalNotPendingError(DraftServiceError):
    """Only a pending approval can be approved (HTTP 409 ``approval_not_pending``)."""


class ApprovalExpiredError(DraftServiceError):
    """The approval's 72 hours are over (HTTP 409 ``approval_expired``)."""


class ApprovalCancelledError(DraftServiceError):
    """A draft edit (or a change of candidate) cancelled the approval (HTTP 409
    ``approval_cancelled``)."""


class ApprovalStaleError(DraftServiceError):
    """The approval is for another draft, candidate or action than the one being published or
    promoted (HTTP 409 ``approval_stale``)."""


class ApprovalUsedError(DraftServiceError):
    """The approval was used already: it is single use (HTTP 409 ``approval_used``)."""


class SelfApprovalError(DraftServiceError):
    """The approver is the requester (HTTP 403 ``self_approval``)."""


class ServiceAccountApprovalError(DraftServiceError):
    """The approver is a service account (HTTP 403 ``service_account_approval``)."""


class OperatorApprovalError(DraftServiceError):
    """The approver is a platform operator (HTTP 403 ``operator_approval``)."""


class ServiceAccountRequestError(DraftServiceError):
    """A service account asked for an approval (HTTP 403 ``service_account_request``): R2's two
    people are two humans, so a machine can't be one of them."""


class ServiceAccountPublishError(DraftServiceError):
    """A service account tried to publish or promote with an approval (HTTP 403
    ``service_account_publish``)."""


class ApproverPublishError(DraftServiceError):
    """The approver tried to publish or promote with their own approval (HTTP 403
    ``approver_publish``): the publisher may be the requester, never the approver."""


class InvalidApprovalCursorError(DraftServiceError):
    """The cursor isn't one this API issued (HTTP 400 ``invalid_cursor``)."""


class InvalidApprovalQueryError(DraftServiceError):
    """A filter or limit is out of range (HTTP 400 ``invalid_query``). ``field`` names it."""

    def __init__(self, field_name: str) -> None:
        self.field = field_name
        super().__init__(field_name)


# --------------------------------------------------------------------------- rules


def check_approvable(approval: Approval, now: datetime) -> None:
    """Raise unless ``approval`` is pending and in time. Used by the services and, against the
    locked row, by the stores."""
    if approval.status == "consumed":
        raise ApprovalUsedError()
    if approval.status == "cancelled":
        raise ApprovalCancelledError()
    if approval.status == "expired" or now >= approval.expires_at:
        raise ApprovalExpiredError()
    if approval.status != "pending":
        raise ApprovalNotPendingError()


def check_usable(approval: Approval, use: ApprovalUse) -> None:
    """Raise unless ``approval`` is approved, unexpired at ``use.at``, single use not yet spent,
    and for exactly what ``use`` describes (the action, the draft hash and, for a promotion, the
    candidate's version)."""
    if approval.status == "consumed":
        raise ApprovalUsedError()
    if approval.status == "cancelled":
        raise ApprovalCancelledError()
    if approval.status == "expired" or use.at >= approval.expires_at:
        raise ApprovalExpiredError()
    if approval.status == "pending":
        raise ApprovalPendingError()
    if (approval.action, approval.draft_hash, approval.version) != (
        use.action, use.draft_hash, use.version,
    ):  # fmt: skip
        raise ApprovalStaleError()
    # R2: whoever publishes or promotes with it is a human and not the approver. The
    # requester may be the publisher; an approver publishing their own approval would leave one
    # person's say (and a machine's request) behind a "two-person" publish.
    if use.service_account:
        raise ServiceAccountPublishError()
    if use.actor == approval.approved_by:
        raise ApproverPublishError()


# --------------------------------------------------------------------------- listing


@dataclass(frozen=True, slots=True)
class ApprovalPosition:
    """Where a page ended: the request time and id of its last approval (the list's order)."""

    requested_at: datetime
    id: str


@dataclass(frozen=True, slots=True)
class ApprovalPage:
    items: tuple[Approval, ...]
    next_cursor: str | None


_CURSOR_ID = re.compile(APPROVAL_ID_PATTERN)


def encode_approval_cursor(position: ApprovalPosition) -> str:
    raw = f"v1:{position.requested_at.isoformat()}|{position.id}"
    return base64.urlsafe_b64encode(raw.encode()).decode().rstrip("=")


def decode_approval_cursor(cursor: str) -> ApprovalPosition:
    """Strictly: anything this API didn't issue raises :class:`InvalidApprovalCursorError`."""
    try:
        if not 1 <= len(cursor) <= 200:
            raise ValueError
        raw = base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)).decode("ascii")
        head, _, rest = raw.partition(":")
        stamp, _, approval_id = rest.partition("|")
        at = datetime.fromisoformat(stamp)
        if head != "v1" or at.tzinfo is None or not _CURSOR_ID.fullmatch(approval_id):
            raise ValueError
        return ApprovalPosition(at, approval_id)
    except (ValueError, binascii.Error):
        raise InvalidApprovalCursorError() from None


def parse_list_limit(limit: str | None) -> int:
    if limit is None:
        return DEFAULT_LIST_LIMIT
    if not limit.isascii() or not limit.isdigit() or not 1 <= int(limit) <= MAX_LIST_LIMIT:
        raise InvalidApprovalQueryError("limit")
    return int(limit)


# --------------------------------------------------------------------------- the port


class ApprovalStore(Protocol):
    """A tenant-scoped approval store. ``tenant_id`` must be the scope's tenant (else
    :class:`ScopeMismatchError`). The writes that change a status run under the tenant's
    lifecycle advisory lock, with their class A event in the same step."""

    async def get(self, tenant_id: str, approval_id: str) -> Approval | None: ...

    async def request(self, tenant_id: str, approval: Approval, event: ApprovalEvent) -> None:
        """Store a new pending approval and its ``requested`` event."""
        ...

    async def approve(
        self,
        tenant_id: str,
        approval_id: str,
        *,
        approver: str,
        at: datetime,
        expires_at: datetime,
        event: ApprovalEvent,
    ) -> Approval:
        """pending -> approved (the approver, the time and the new expiry) with its event, or
        raise (:func:`check_approvable`, :class:`SelfApprovalError`)."""
        ...

    async def expire(
        self, tenant_id: str, approval_id: str, *, at: datetime, event: ApprovalEvent
    ) -> bool:
        """pending or approved -> expired when ``at`` is past its expiry, with its event.
        False when it was not open or not past expiry (nothing written)."""
        ...

    async def cancel(
        self, tenant_id: str, approval_id: str, *, at: datetime, reason: str, event: ApprovalEvent
    ) -> bool:
        """pending or approved -> cancelled, with its event. False when it was not open."""
        ...

    async def cancel_publish_approvals(
        self, tenant_id: str, *, keep_draft_hash: str, at: datetime, reason: str,
        event_for: ApprovalEventFactory,
    ) -> list[Approval]:  # fmt: skip
        """Cancel every open ``publish`` approval whose draft hash is not ``keep_draft_hash``
        (the draft changed), with one ``cancelled`` event each. Returns what it cancelled."""
        ...

    async def record(self, tenant_id: str, event: ApprovalEvent) -> None:
        """Append a stand-alone class A event (``notified``)."""
        ...

    async def list_approvals(
        self,
        tenant_id: str,
        *,
        status: str | None = None,
        after: ApprovalPosition | None = None,
        limit: int = DEFAULT_LIST_LIMIT,
    ) -> list[Approval]:
        """Up to ``limit`` approvals, newest request first (by ``requested_at``, then id),
        strictly after the position ``after`` in that order, optionally only one ``status``."""
        ...

    async def events(self, tenant_id: str) -> list[ApprovalEvent]: ...


class ApprovalEventFactory(Protocol):
    def __call__(self, approval: Approval) -> ApprovalEvent: ...


class ScopedApprovalStores(Protocol):
    def scoped(self, scope: TenantScope) -> ApprovalStore: ...


# --------------------------------------------------------------------------- memory store


@dataclass
class InMemoryApprovalStore:
    """For tests and local runs. A lifecycle store built with it consumes approvals from it."""

    _rows: dict[tuple[str, str], Approval] = field(default_factory=dict)
    _events: list[ApprovalEvent] = field(default_factory=list)
    fail_events: bool = False
    """Test hook: every write that needs its class A event fails, and writes nothing."""

    def scoped(self, scope: TenantScope) -> ApprovalStore:
        if not isinstance(scope, TenantScope):
            raise TypeError("scoped() takes a TenantScope")
        return _ScopedMemoryApprovals(self, scope)

    # Used by the in-memory lifecycle store, in the step of the publish that uses the approval.

    def consume(self, tenant_id: str, use: ApprovalUse) -> Approval:
        """Check and spend the approval (single use) and append its ``consumed`` event, as one
        step. Returns the approval as it was, so the caller can :meth:`restore` it if the
        lifecycle write then fails."""
        if self.fail_events:
            raise ConnectionError("audit store down")
        row = self._rows.get((tenant_id, use.approval_id))
        if row is None:
            raise ApprovalNotFoundError()
        check_usable(row, use)
        self._rows[(tenant_id, use.approval_id)] = replace(
            row, status="consumed", consumed_by=use.actor, consumed_at=use.at
        )
        self._events.append(
            ApprovalEvent(
                use.at, use.actor, tenant_id, "consumed", row.id, row.draft_hash,
                use.for_version if use.for_version is not None else row.version,
                f"used by {use.action}", use.cross_tenant, use.operator,
            )
        )  # fmt: skip
        return row

    def restore(self, tenant_id: str, previous: Approval) -> None:
        self._rows[(tenant_id, previous.id)] = previous
        if self._events and self._events[-1].action == "consumed":
            self._events.pop()


class _ScopedMemoryApprovals:
    def __init__(self, store: InMemoryApprovalStore, scope: TenantScope) -> None:
        self._store = store
        self._scope = scope

    def _check(self, tenant_id: str, event: ApprovalEvent | None = None) -> None:
        if tenant_id != self._scope.tenant_id or (
            event is not None and event.tenant_id != tenant_id
        ):
            raise ScopeMismatchError()

    def _guard(self) -> None:
        if self._store.fail_events:
            raise ConnectionError("audit store down")

    async def get(self, tenant_id: str, approval_id: str) -> Approval | None:
        self._check(tenant_id)
        return self._store._rows.get((tenant_id, approval_id))

    async def request(self, tenant_id: str, approval: Approval, event: ApprovalEvent) -> None:
        self._check(tenant_id, event)
        if approval.tenant_id != tenant_id:
            raise ScopeMismatchError()
        self._guard()
        self._store._rows[(tenant_id, approval.id)] = approval
        self._store._events.append(event)

    async def approve(
        self,
        tenant_id: str,
        approval_id: str,
        *,
        approver: str,
        at: datetime,
        expires_at: datetime,
        event: ApprovalEvent,
    ) -> Approval:
        self._check(tenant_id, event)
        row = self._store._rows.get((tenant_id, approval_id))
        if row is None:
            raise ApprovalNotFoundError()
        check_approvable(row, at)
        if approver == row.requested_by:
            raise SelfApprovalError()
        self._guard()
        approved = replace(
            row, status="approved", approved_by=approver, approved_at=at, expires_at=expires_at
        )
        self._store._rows[(tenant_id, approval_id)] = approved
        self._store._events.append(event)
        return approved

    async def expire(
        self, tenant_id: str, approval_id: str, *, at: datetime, event: ApprovalEvent
    ) -> bool:
        self._check(tenant_id, event)
        row = self._store._rows.get((tenant_id, approval_id))
        if row is None or row.status not in ("pending", "approved") or at < row.expires_at:
            return False
        self._guard()
        self._store._rows[(tenant_id, approval_id)] = replace(
            row, status="expired", closed_at=at, close_reason="expired"
        )
        self._store._events.append(event)
        return True

    async def cancel(
        self, tenant_id: str, approval_id: str, *, at: datetime, reason: str, event: ApprovalEvent
    ) -> bool:
        self._check(tenant_id, event)
        row = self._store._rows.get((tenant_id, approval_id))
        if row is None or row.status not in ("pending", "approved"):
            return False
        self._guard()
        self._store._rows[(tenant_id, approval_id)] = replace(
            row, status="cancelled", closed_at=at, close_reason=reason
        )
        self._store._events.append(event)
        return True

    async def cancel_publish_approvals(
        self, tenant_id: str, *, keep_draft_hash: str, at: datetime, reason: str,
        event_for: ApprovalEventFactory,
    ) -> list[Approval]:  # fmt: skip
        self._check(tenant_id)
        doomed = [
            r
            for (t, _), r in self._store._rows.items()
            if t == tenant_id
            and r.action == "publish"
            and r.status in ("pending", "approved")
            and r.draft_hash != keep_draft_hash
        ]
        if doomed:
            self._guard()
        cancelled = []
        for r in doomed:
            done = replace(r, status="cancelled", closed_at=at, close_reason=reason)
            self._store._rows[(tenant_id, r.id)] = done
            self._store._events.append(event_for(done))
            cancelled.append(done)
        return cancelled

    async def record(self, tenant_id: str, event: ApprovalEvent) -> None:
        self._check(tenant_id, event)
        self._guard()
        self._store._events.append(event)

    async def events(self, tenant_id: str) -> list[ApprovalEvent]:
        self._check(tenant_id)
        return [e for e in self._store._events if e.tenant_id == tenant_id]

    async def list_approvals(
        self,
        tenant_id: str,
        *,
        status: str | None = None,
        after: ApprovalPosition | None = None,
        limit: int = DEFAULT_LIST_LIMIT,
    ) -> list[Approval]:
        self._check(tenant_id)
        rows = sorted(
            (
                r
                for (t, _), r in self._store._rows.items()
                if t == tenant_id and (status is None or r.status == status)
            ),
            key=lambda r: (r.requested_at, r.id),
            reverse=True,
        )
        if after is not None:
            rows = [r for r in rows if (r.requested_at, r.id) < (after.requested_at, after.id)]
        return rows[:limit]


__all__ = [
    "ACTIONS",
    "APPROVAL_ID_PATTERN",
    "APPROVAL_TTL",
    "DEFAULT_LIST_LIMIT",
    "EVENT_ACTIONS",
    "MAX_LIST_LIMIT",
    "STATUSES",
    "Approval",
    "ApprovalCancelledError",
    "ApprovalEvent",
    "ApprovalEventFactory",
    "ApprovalExpiredError",
    "ApprovalNotFoundError",
    "ApprovalNotPendingError",
    "ApprovalNotRequiredError",
    "ApprovalPage",
    "ApprovalPendingError",
    "ApprovalPosition",
    "ApprovalStaleError",
    "ApprovalStore",
    "ApprovalUse",
    "ApprovalUsedError",
    "ApproverPublishError",
    "InMemoryApprovalStore",
    "InvalidApprovalCursorError",
    "InvalidApprovalQueryError",
    "OperatorApprovalError",
    "ScopedApprovalStores",
    "SelfApprovalError",
    "ServiceAccountApprovalError",
    "ServiceAccountPublishError",
    "ServiceAccountRequestError",
    "approval_required",
    "check_approvable",
    "check_usable",
    "decode_approval_cursor",
    "encode_approval_cursor",
    "new_approval_id",
    "parse_list_limit",
]  # fmt: skip
