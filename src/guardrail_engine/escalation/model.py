"""The escalation item and its values (M4-05).

An **escalation item** is one check whose verdict was ``escalate``: the content is held for a
reviewer. It is R3 class D data. The item never holds a probability: only the keys, actions and
modes of the rules that fired, so no floor ``p`` (or a floor-derived one) can reach a list, a
webhook or a label.

States: ``open`` (waiting for a reviewer) and ``resolved`` (a reviewer decided ``allow`` or
``block``; the decision, the reason, the actor and the time are on the item and in the class A
audit). An item is **insert-only except for its resolution**: the fields that identify it and
hold its content never change, and a resolution can be set once.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
from dataclasses import dataclass, field, replace
from datetime import datetime
from typing import Final

from guardrail_engine.admin.service import DraftServiceError
from guardrail_engine.tenant_scope import TenantScope

STATUS_OPEN: Final = "open"
STATUS_RESOLVED: Final = "resolved"
STATUSES: Final = (STATUS_OPEN, STATUS_RESOLVED)

TARGET_QUEUE: Final = "queue"
TARGET_WEBHOOK: Final = "webhook"

DECISION_ALLOW: Final = "allow"
DECISION_BLOCK: Final = "block"
DECISIONS: Final = (DECISION_ALLOW, DECISION_BLOCK)

LABEL_CONTENT: Final = "content"
"""The golden label carries the (post-redaction) content: class C is on, or a reviewer promoted
the item (R3)."""
LABEL_HASH_ONLY: Final = "hash_only"
"""The golden label is a placeholder holding the content hash, quarantined so it is never sent
and never counted as evidence: the label is recorded, the content is not (R3)."""
LABEL_MODES: Final = (LABEL_CONTENT, LABEL_HASH_ONLY)

STORE_FULL: Final = "full"
STORE_HASH_ONLY: Final = "hash_only"

MAX_CONTENT_CHARS: Final = 100_000
"""The most content an item holds; longer content is cut and the item says so
(``content_truncated``), and a truncated item never becomes a content label."""
MAX_REASON_CHARS: Final = 500
MAX_LIST_LIMIT: Final = 200
DEFAULT_LIST_LIMIT: Final = 50
MAX_RULES: Final = 64
ITEM_ID_PREFIX: Final = "esc_"

CLASS_D_DAYS: Final = 30
"""R3 class D: 30 days after resolution (all tiers but healthcare) or 30 days in all
(healthcare). It is also the floor of the deletion function's ``p_days``."""

RETENTION_AFTER_RESOLUTION: Final = "resolved_plus"
"""Class D, all tiers but healthcare: an item goes ``CLASS_D_DAYS`` after it was **resolved**. An
item nobody has resolved stays."""
RETENTION_FROM_CREATION: Final = "total"
"""Class D, healthcare: an item goes ``CLASS_D_DAYS`` after it was **created**, resolved or not; an
unresolved one is counted as expired in the receipt."""
RETENTION_MODES: Final = (RETENTION_AFTER_RESOLUTION, RETENTION_FROM_CREATION)


def item_id_for(
    tenant_id: str, request_id: str, guard_point: str, content_sha256: str | None = None
) -> str:
    """A stable id: the same check routed twice (a retry with the same request id **and the same
    content**) is one item, and one webhook (the outbox keeps it by this key). The content hash is
    part of the id: a caller that reuses a request id for different content gets a second
    item, not a silently lost one."""
    digest = hashlib.sha256(
        f"{tenant_id}\x00{request_id}\x00{guard_point}\x00{content_sha256 or ''}".encode()
    ).hexdigest()
    return ITEM_ID_PREFIX + digest[:24]


def content_sha256(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()


@dataclass(frozen=True, slots=True)
class RuleRef:
    """A rule that fired: its key, the action it called for and how it ran. Never a ``p``."""

    key: str
    action: str
    mode: str = "enforce"
    layer: str = ""


@dataclass(frozen=True, slots=True)
class EscalationItem:
    id: str
    tenant_id: str
    request_id: str
    guard_point: str
    created_at: datetime
    target: str
    reason: str
    """The verdict's reason (``policy``, ``deterministic``...), a fixed word."""
    bundle_version: int | None
    rules: tuple[RuleRef, ...]
    content_sha256: str | None
    """``sha256:<hex>`` of the **pre-redaction** content (PF-14), as in the decision record."""
    store_content: str
    """The tenant's ``audit.store_content`` when the item was routed (``hash_only`` or ``full``)."""
    retention_mode: str = RETENTION_AFTER_RESOLUTION
    """The class D term this item gets (R3), fixed when it was routed from the tenant's profile,
    as ``store_content`` is: ``resolved_plus`` (until resolved, plus 30 days) or ``total``
    (healthcare: 30 days from creation). The deletion function applies **each row's own** mode,
    so "until resolved" is enforced by the database and not by whoever calls it."""
    content: str | None = None
    """The post-redaction text held for the reviewer (class D). None when it isn't held: a
    webhook tenant on ``hash_only`` (R3 doesn't allow it, so we don't hold it), or a content-less
    verdict."""
    content_truncated: bool = False
    triggered_by: str | None = None
    """Who triggered the check, if the request said (``issuer#subject``). The check context
    carries no end-user identity today, so the engine leaves this None; the resolver is refused
    when it equals the actor, so a source that does know can use it (see the docs)."""
    seq: int = 0
    """The store's insertion order: the pagination cursor. Set by the store."""
    status: str = STATUS_OPEN
    decision: str | None = None
    resolution_reason: str | None = None
    resolved_by: str | None = None
    resolved_at: datetime | None = None
    label_set_id: str | None = None
    label_mode: str | None = None

    @property
    def resolved(self) -> bool:
        return self.status == STATUS_RESOLVED

    @property
    def content_held(self) -> bool:
        return self.content is not None


@dataclass(frozen=True, slots=True)
class EscalationRequest:
    """What the check path hands the router: the item to create and where it goes."""

    scope: TenantScope = field(repr=False)
    item: EscalationItem
    url: str | None = None
    """The webhook url from the bundle (target ``webhook`` only)."""


@dataclass(frozen=True, slots=True)
class Resolution:
    decision: str
    reason: str
    actor: str
    at: datetime


@dataclass(frozen=True, slots=True)
class ItemFilter:
    status: str | None = None
    guard_point: str | None = None
    rule: str | None = None
    since: datetime | None = None
    until: datetime | None = None


@dataclass(frozen=True, slots=True)
class ItemPage:
    items: tuple[EscalationItem, ...]
    next_cursor: str | None


@dataclass(frozen=True, slots=True)
class EscalationAuditEvent:
    """A class A event: who did what to which item. Identifiers and fixed words only: no
    content, and the reviewer's free-text reason only as a hash."""

    at: datetime
    tenant_id: str
    item_id: str
    action: str
    """``resolved`` or ``label_created``."""
    actor: str
    decision: str | None = None
    reason_sha256: str | None = None
    label_set_id: str | None = None
    label_mode: str | None = None
    cross_tenant: bool = False
    operator: bool = False


def resolved_copy(item: EscalationItem, resolution: Resolution) -> EscalationItem:
    return replace(
        item,
        status=STATUS_RESOLVED,
        decision=resolution.decision,
        resolution_reason=resolution.reason,
        resolved_by=resolution.actor,
        resolved_at=resolution.at,
    )


def matches(item: EscalationItem, filt: ItemFilter) -> bool:
    if filt.status is not None and item.status != filt.status:
        return False
    if filt.guard_point is not None and item.guard_point != filt.guard_point:
        return False
    if filt.rule is not None and all(r.key != filt.rule for r in item.rules):
        return False
    if filt.since is not None and item.created_at < filt.since:
        return False
    return not (filt.until is not None and item.created_at >= filt.until)


# ------------------------------------------------------------------------------- cursors


def encode_cursor(seq: int) -> str:
    return base64.urlsafe_b64encode(f"v1:{seq}".encode()).decode().rstrip("=")


def decode_cursor(cursor: str) -> int:
    """The ``seq`` a cursor names. Raises :class:`InvalidCursorError`."""
    try:
        raw = base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)).decode("ascii")
        version, _, number = raw.partition(":")
        if version != "v1" or not number.isascii() or not number.isdigit() or len(number) > 18:
            raise ValueError
        return int(number)
    except (ValueError, binascii.Error):
        raise InvalidCursorError() from None


# ------------------------------------------------------------------------------- errors


class EscalationError(DraftServiceError):
    """Base class for what the escalation service raises about a request."""


class InvalidCursorError(EscalationError):
    """The cursor isn't one this API issued (HTTP 400)."""


class InvalidQueryError(EscalationError):
    """A filter or limit is out of range (HTTP 400). ``field`` names it."""

    def __init__(self, field_name: str) -> None:
        self.field = field_name
        super().__init__(field_name)


class EscalationNotFoundError(EscalationError):
    """No such item for the tenant; also another tenant's item (HTTP 404)."""


class OperatorResolutionError(EscalationError):
    """A platform operator tried to resolve a tenant's item (HTTP 403): an operator may
    read across tenants (audited) but may not decide an item or write the tenant's labels."""


class AlreadyResolvedError(EscalationError):
    """The item was resolved already (HTTP 409)."""


class SelfResolutionError(EscalationError):
    """The actor is the person who triggered the item (HTTP 403)."""


class DeidentifiedContentRequiredError(EscalationError):
    """A healthcare tenant promoting an item must supply de-identified content (HTTP 422)."""


class EscalationStoreError(Exception):
    """A store could not do what it was asked (an infrastructure fault, HTTP 500)."""
