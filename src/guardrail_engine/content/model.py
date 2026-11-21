"""Stored content (R3 class C, M5-03): what is kept, and the constants that bound it.

Class C is **off** unless a tenant's bundle sets ``audit.store_content: full``. When it is on, the
Guard Service keeps, per check, the **post-redaction** text the model saw (never the raw content,
never the conversation context), with the hash of the pre-redaction content so the row can be
matched to its decision record. The term is the bundle's ``audit.content_days`` clamped to the R3
cap in force when it is written: 90 days at most, 30 for a tenant whose packs need a BAA, and the
shortest cap wins when a tenant has several packs.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Final

MAX_CLASS_C_DAYS: Final = 90
"""R3's cap for the standard and finance profiles; the database's CHECK says the same."""
MAX_STORED_CHARS: Final = 100_000
"""The most characters of one check's content that is kept (the same bound as an escalation
item's); longer content is cut and ``truncated`` is set."""
MAX_BATCH_SIZE: Final = 100_000
SOURCE_ROW: Final = "row"
"""A class C receipt's ``source``: each row carries its own deletion time."""


@dataclass(frozen=True, slots=True)
class StoredContent:
    tenant_id: str
    request_id: str
    guard_point: str
    ts: datetime
    retain_until: datetime
    content: str
    """The post-redaction text the model saw."""
    truncated: bool
    content_sha256: str
    """``sha256:<hex>`` of the **pre-redaction** content (PF-14)."""
    bundle_version: int | None


@dataclass(frozen=True, slots=True)
class ContentReadEvent:
    """A class A record of one read of stored content (M5-03): who read, which request and guard
    point they asked for, and how many rows they got. **Never the content.**"""

    tenant_id: str
    at: datetime
    actor: str
    """``issuer#subject`` from the principal."""
    request_id: str
    guard_point: str | None
    items: int
    cross_tenant: bool
    operator: bool


@dataclass(frozen=True, slots=True)
class ClassCReceipt:
    """A class A deletion receipt for one class C batch: tenant, class, cutoff, count and run id;
    never content. In Postgres these are rows of ``retention_receipts`` with class ``C``."""

    run_id: str
    at: datetime
    tenant_id: str
    retention_class: str
    cutoff: datetime
    deleted_count: int
    batch: int
    retention_days: int
    source: str
