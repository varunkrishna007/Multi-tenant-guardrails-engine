"""The tenant directory's records, errors and ports (M2-01, decided 2026-11-17).

The directory is **platform data**: slug, id, domain, tier, flags and status of every tenant. It
is written only by platform operators (the provisioning path in ``provisioning.py``), never by a
tenant, and read by the Guard Service through the existing ``TenantDirectory`` port
(``cached.CachedTenantDirectory``). Every write records a class A audit event in the same
transaction, and a ``TenantChanged`` event after it so caches invalidate (M2-07 wires the bus).
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field, replace
from datetime import datetime
from typing import Protocol

from guardrail_engine.deterministic.identifiers import (
    IDENTIFIER_PATTERN_MAX_CHARS,
    MAX_PATTERNS_PER_TENANT,
)
from guardrail_engine.guard.tenants import (
    DOMAINS,
    TENANT_SLUG_PATTERN,
    TenantProfile,
    ToolInfo,
    denied_slug_parts,
)
from guardrail_engine.policy.catalog import TenantAttributes, is_regulated_tier
from guardrail_engine.projects import DEFAULT_PROJECT, PROJECT_LABEL_PATTERN, is_valid_project_label
from guardrail_engine.tenant_ids import TENANT_ID_PATTERN, is_valid_tenant_id

TIERS = ("standard", "regulated", "dedicated")
STATUSES = ("active", "suspended", "offboarded", "terminating", "terminated")
TERMINATION_STATUSES = frozenset({"terminating", "terminated"})
"""M5-07: a tenant that is being, or has been, terminated. **One way only**: ``terminating``
(refused everywhere, caches draining), then ``terminated`` (the offboarding job may delete
classes B, C, D and the golden sets), and never back to ``active``. Set by
:meth:`~guardrail_engine.directory.provisioning.TenantProvisioner.terminate` only; the database
refuses any other move out of these two. ``offboarded`` is older, manual and reversible, and
deletes nothing."""
FLAGS = frozenset({"two_person_publish"})
"""Flags platform ops can set. ``two_person_publish``: publishing needs a second approver
(M5-02 enforces it; regulated tiers default to it)."""
PACK_NAME_LIMIT = 64


class DirectoryError(Exception):
    """Base for directory write errors."""


class TenantExists(DirectoryError):
    """A tenant with this id or slug is already in the directory."""


class TenantNotFound(DirectoryError):
    pass


class VersionConflict(DirectoryError):
    """The record changed since the caller read it (optimistic concurrency)."""


class TenantTerminated(DirectoryError):
    """The tenant is terminating or terminated: its directory record can no longer change
    (M5-07). The code is ``tenant_terminated``."""

    code = "tenant_terminated"


class InvalidTenantRecord(DirectoryError, ValueError):
    """The record breaks a directory rule; the message names it (fixed wording, no input)."""


@dataclass(frozen=True, slots=True)
class TenantRecord:
    tenant_id: str
    slug: str
    domain: str
    tier: str = "standard"
    flags: frozenset[str] = frozenset()
    required_packs: frozenset[str] = frozenset()
    baa: bool = False
    status: str = "active"
    version: int = 1
    identifier_patterns: tuple[str, ...] = ()
    """The tenant's registered cross-tenant identifier patterns (M3-01): RE2 patterns for the
    identifiers its data is keyed by, which the floor scan blocks in **other** tenants' content.
    Platform-reviewed: only the operator write path sets them, and it validates them with
    :func:`~guardrail_engine.deterministic.validate_tenant_identifier_patterns`. The record
    only checks their shape, so that a row written some other way can still be read."""
    project: str | None = None
    """M5-06: the label of the dedicated Gemini project the tenant is assigned to, or None for
    the shared pool. Platform-assigned: the provisioner picks it when a tenant is created or
    raised to a regulated tier. A label only (never a key); the database allows one tenant per
    project."""
    created_at: datetime | None = field(default=None, compare=False)
    updated_at: datetime | None = field(default=None, compare=False)

    def __post_init__(self) -> None:
        if (problem := record_problem(self)) is not None:
            raise InvalidTenantRecord(problem)

    def with_changes(self, **changes: object) -> TenantRecord:
        """A copy with ``changes`` and the version raised by one (validated)."""
        return replace(self, version=self.version + 1, **changes)  # type: ignore[arg-type]

    def to_profile(self, tools: Iterable[ToolInfo] = ()) -> TenantProfile:
        """The profile the Guard Service uses. Raises ``ValueError`` if it cannot be built."""
        attributes = TenantAttributes(
            tenant_id=self.tenant_id, tier=self.tier,
            required_packs=self.required_packs, baa=self.baa, project=self.project,
        )  # fmt: skip
        return TenantProfile.build(
            attributes, self.domain, tools, slug=self.slug,
            require_two_person="two_person_publish" in self.flags,
        )  # fmt: skip


def record_problem(record: TenantRecord) -> str | None:
    """What makes ``record`` unfit for the directory, or None. Fixed wording: never echoes the
    value, since the slug is later printed in the trusted header."""
    if not is_valid_tenant_id(record.tenant_id):
        return f"tenant id must match {TENANT_ID_PATTERN.pattern}"
    if not isinstance(record.slug, str) or not TENANT_SLUG_PATTERN.fullmatch(record.slug):
        return f"slug must match {TENANT_SLUG_PATTERN.pattern}"
    if denied_slug_parts(record.slug):
        return "slug contains an instruction-like part"
    if record.domain not in DOMAINS:
        return f"domain must be one of {DOMAINS}"
    if record.tier not in TIERS:
        return f"tier must be one of {TIERS}"
    if not isinstance(record.flags, frozenset) or not record.flags <= FLAGS:
        return f"flags must be a subset of {sorted(FLAGS)}"
    if not isinstance(record.required_packs, frozenset) or any(
        not isinstance(p, str) or not 0 < len(p) <= PACK_NAME_LIMIT for p in record.required_packs
    ):
        return "required_packs must be a set of pack names"
    if not isinstance(record.baa, bool):
        return "baa must be a bool"
    if record.status not in STATUSES:
        return f"status must be one of {STATUSES}"
    if type(record.version) is not int or record.version < 1:
        return "version must be a positive integer"
    if (
        not isinstance(record.identifier_patterns, tuple)
        or len(record.identifier_patterns) > MAX_PATTERNS_PER_TENANT
        or any(
            not isinstance(p, str) or not 0 < len(p) <= IDENTIFIER_PATTERN_MAX_CHARS
            for p in record.identifier_patterns
        )
    ):
        return f"identifier_patterns must be at most {MAX_PATTERNS_PER_TENANT} patterns"
    if record.project is not None and (
        not is_valid_project_label(record.project) or record.project == DEFAULT_PROJECT
    ):
        return f"project must be None or a label matching {PROJECT_LABEL_PATTERN.pattern}"
    return None


@dataclass(frozen=True, slots=True)
class DirectoryAuditEvent:
    """A class A audit event for one directory write (actor, action, before and after). Holds
    directory fields only: no tenant content."""

    tenant_id: str
    version: int
    action: str
    """``create``, ``update``, ``set_status``, ``set_tier`` (M5-01: the tier changed through
    :meth:`~guardrail_engine.directory.provisioning.TenantProvisioner.set_tier`; its ``after``
    also carries the operator's ``reason``), or (M5-07) ``terminating`` / ``terminated``, whose
    ``after`` also carries the operator's ``reason``."""
    actor: str
    at: float
    before: dict[str, object] | None
    after: dict[str, object]


@dataclass(frozen=True, slots=True)
class TenantChanged:
    """The ``tenant.changed`` event: published after a directory write commits."""

    tenant_id: str
    version: int
    kind: str
    """The audit action: ``create``, ``update``, ``set_status``, ``set_tier``, ``terminating``
    or ``terminated``."""


class TenantDirectoryStore(Protocol):
    """The directory's storage. A write and its audit event commit together or not at all."""

    async def insert(self, record: TenantRecord, event: DirectoryAuditEvent) -> TenantRecord:
        """Raises :class:`TenantExists` for a taken id or slug."""
        ...

    async def replace(
        self, record: TenantRecord, expected_version: int, event: DirectoryAuditEvent
    ) -> TenantRecord:
        """Raises :class:`TenantNotFound` or :class:`VersionConflict`;
        ``record.version`` is ``expected_version + 1``."""
        ...

    async def get(self, tenant_id: str) -> TenantRecord | None: ...

    async def list(self) -> list[TenantRecord]: ...

    async def audit_events(self, tenant_id: str) -> list[DirectoryAuditEvent]: ...


class EventBus(Protocol):
    async def publish(self, event: TenantChanged) -> None: ...


def audit_fields(record: TenantRecord) -> dict[str, object]:
    return {
        "slug": record.slug, "domain": record.domain, "tier": record.tier,
        "flags": sorted(record.flags), "required_packs": sorted(record.required_packs),
        "baa": record.baa, "status": record.status, "version": record.version,
        "identifier_patterns": list(record.identifier_patterns), "project": record.project,
    }  # fmt: skip


def tier_is_regulated(record: TenantRecord) -> bool:
    """Whether the record's tier is a regulated one (M5-01)."""
    return is_regulated_tier(record.tier)
