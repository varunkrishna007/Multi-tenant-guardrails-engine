"""What offboarding deletes, what it keeps, and the receipts it writes (M5-07, R3).

R3: "Offboarding deletes classes B, C, D and E and the golden sets within 30 days. Class A is
kept for its full term." This module is the one place that says, table by table, which of those
a tenant-scoped table is. The Postgres function (migration 043) repeats the same list; a test
reads the database's own catalog and fails if a table with a ``tenant_id`` column is in neither
the deleted list nor the kept list, so a new table can't be forgotten.

Data classes used in receipts (R3's A to E, plus two this story needs a name for):

* ``B`` decision records and what is derived from them (usage, shadow counters, the outbox's
  tenant events);
* ``C`` stored content (post-redaction text a tenant opted to keep, M5-03): the ``stored_content``
  table, and the content an escalation item holds under ``store_content: full`` (counted under
  ``D`` too, as item rows);
* ``D`` escalation items;
* ``E`` calibration data (scores and outcomes, keyed by content hash);
* ``G`` golden sets and their examples (R3 names them next to the classes);
* ``W`` tenant working data that no R3 class names: drafts, the candidate pointer, the tool
  registry, calibration targets. Deleted; their history stays in the class A audit tables.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from decimal import Decimal
from typing import Final

DELETION_DEADLINE_DAYS: Final = 30
"""R3: offboarding deletes within 30 days. Counted from the moment the tenant went
``terminating`` (the request), the earlier of the two statuses, so the clock never starts late."""
DELETION_DEADLINE: Final = timedelta(days=DELETION_DEADLINE_DAYS)
MAX_BATCH_SIZE: Final = 100_000

RESWEEP_DAYS: Final = 7
"""After the completion receipt the job re-sweeps once a day for this many days; after
the last, the tenant is final and nothing looks at it again."""
RESWEEP_INTERVAL: Final = timedelta(days=1)

DEFAULT_PRICE_PER_MILLION_INPUT_TOKENS_USD: Final = Decimal("0.10")
"""The price the usage summary's cost is computed at when none is configured: the gateway's
default (``DEFAULT_PRICE_PER_MILLION_INPUT_TOKENS_USD``). Production passes its configured one."""

CLASSES: Final = ("B", "C", "D", "E", "G", "W")


@dataclass(frozen=True, slots=True)
class OffboardTable:
    name: str
    data_class: str
    note: str


OFFBOARD_TABLES: Final[tuple[OffboardTable, ...]] = (
    OffboardTable("decision_record_rules", "B", "the rule filter index of the decision records"),
    OffboardTable("decision_records", "B", "one record per check: hashes, probabilities, verdict"),
    OffboardTable("usage_events", "B", "the usage meter's rows"),
    OffboardTable("tenant_shadow_agreement", "B", "shadow agreement counters"),
    OffboardTable("delivery_outbox", "B", "the tenant's alert, usage and escalation events"),
    OffboardTable("escalation_items", "D", "items held for a reviewer (and class C content)"),
    OffboardTable(
        "nightly_redteam_results", "B", "the nightly red-team's results for its versions (M5-05)"
    ),
    OffboardTable("stored_content", "C", "post-redaction content a tenant opted to keep (M5-03)"),
    OffboardTable("tenant_golden_examples", "G", "golden-set examples (labelled content)"),
    OffboardTable("tenant_golden_sets", "G", "golden-set headers"),
    OffboardTable("tenant_calibration_scores", "E", "calibration scores by content hash"),
    OffboardTable("tenant_calibration_outcomes", "E", "calibration scoring outcomes"),
    OffboardTable("tenant_calibration_targets", "W", "the tenant's calibration targets"),
    OffboardTable("tenant_drafts", "W", "the working draft bundle"),
    OffboardTable("tenant_candidates", "W", "the rollout candidate pointer"),
    OffboardTable("tenant_tools", "W", "the tool registry (tenant-written descriptions)"),
)
"""In deletion order: a child before its parent (examples before sets). ``decision_records``
also cascades to its rules, which are listed first so they get their own receipt."""

CONTENT_RECEIPT: Final = "escalation_items.content"
"""The class C receipt's table name: items deleted that held stored content."""

DELETED_TABLES: Final = frozenset(t.name for t in OFFBOARD_TABLES)
RECEIPT_TABLES: Final = DELETED_TABLES | {CONTENT_RECEIPT}
TABLE_CLASS: Final = {t.name: t.data_class for t in OFFBOARD_TABLES} | {CONTENT_RECEIPT: "C"}

CLASS_A_TABLES: Final = frozenset(
    {
        "tenants",  # the directory row of a terminated tenant (class A: config and status)
        "tenant_directory_audit",
        "policy_bundle_versions",  # bundle versions, which are also what a candidate points at
        "policy_active_versions",
        "tenant_draft_audit",
        "tenant_publish_audit",
        "tenant_tool_audit",
        "tenant_golden_audit",
        "tenant_calibration_audit",
        "tenant_approvals",  # approvals (R3 class A): hashes and actors, no content
        "tenant_approval_audit",
        "escalation_audit",
        "stored_content_audit",  # M5-03: who read stored content (class A; never the content)
        "platform_audit",  # the platform's own actions (a re-pin names the tenant), append-only
        "retention_receipts",
        "offboarding_receipts",
        "offboarding_completions",
        "offboarding_usage_summaries",  # the billing summary of the deleted usage rows
        "offboarding_sweeps",  # the daily re-sweeps after completion
    }
)
"""Kept. Every one is append-only (or, for versions and approvals, immutable but for a status)
and holds hashes, ids, actors and diffs, never content."""


class OffboardingError(Exception):
    """Base for offboarding failures. The message is fixed text."""


class OffboardingRefused(OffboardingError):
    """The database or store refused a deletion: the tenant is not ``terminated``, or a bound
    was out of range. Nothing was deleted."""


@dataclass(frozen=True, slots=True)
class PendingTenant:
    tenant_id: str
    status: str
    """``terminating`` (refused everywhere, not yet deletable) or ``terminated``."""
    terminating_at: datetime
    """When the termination was requested: the 30-day clock starts here."""
    terminated_at: datetime | None

    @property
    def deadline(self) -> datetime:
        return self.terminating_at + DELETION_DEADLINE

    def overdue(self, now: datetime) -> bool:
        """Strictly past day 30: at exactly 30 days it is the last moment still in time."""
        return now > self.deadline


@dataclass(frozen=True, slots=True)
class OffboardReceipt:
    """A class A deletion receipt: one batch of one table. Tenant, table, class, count and run
    id; never content."""

    run_id: str
    at: datetime
    tenant_id: str
    table: str
    data_class: str
    deleted_count: int
    batch: int
    resweep: bool = False
    """Written by a re-sweep after the completion receipt. Such a receipt exists only
    when the sweep deleted something."""


@dataclass(frozen=True, slots=True)
class UsageSummaryRow:
    """The billing evidence kept when a tenant's ``usage_events`` rows are deleted. One
    row per (batch, UTC calendar month, usage class) of the rows that batch deleted; the
    tenant's totals are the sums. Counts and money only, no content."""

    run_id: str
    at: datetime
    tenant_id: str
    month: str
    """``YYYY-MM``, the UTC calendar month of the event's ``occurred_at``."""
    usage_class: str
    """The usage event kind: ``answered``, ``unknown``, ``unanswered``, ..."""
    events: int
    answered_calls: int
    input_tokens: int
    price_per_million_usd: Decimal
    cost_usd: Decimal
    """``input_tokens * price_per_million_usd / 1,000,000``."""


@dataclass(frozen=True, slots=True)
class ResweepDue:
    """A completed tenant whose daily re-sweep is due."""

    tenant_id: str
    day: int
    """1 to :data:`RESWEEP_DAYS`: the latest day due (a job that was down catches up in one go)."""
    completed_at: datetime


@dataclass(frozen=True, slots=True)
class SweepRecord:
    """A logged re-sweep: it ran on ``day``, whether or not it found anything."""

    tenant_id: str
    day: int
    run_id: str
    at: datetime
    deleted_count: int


@dataclass(frozen=True, slots=True)
class CompletionReceipt:
    """The class A "offboarding complete" receipt, one per tenant, written once. Counts only."""

    tenant_id: str
    run_id: str
    at: datetime
    terminating_at: datetime
    terminated_at: datetime | None
    deadline: datetime
    within_deadline: bool
    counts_by_class: dict[str, int] = field(default_factory=dict)
    counts_by_table: dict[str, int] = field(default_factory=dict)


def sum_receipts(receipts: list[OffboardReceipt]) -> tuple[dict[str, int], dict[str, int]]:
    """(by class, by table) over ``receipts``, every class present (zero if none)."""
    by_class = dict.fromkeys(CLASSES, 0)
    by_table: dict[str, int] = {}
    for r in receipts:
        by_class[r.data_class] += r.deleted_count
        by_table[r.table] = by_table.get(r.table, 0) + r.deleted_count
    return by_class, by_table
