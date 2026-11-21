"""Ports for the nightly red-team (M5-05): which versions are active, where results go, and how an
operator reads them.

Results are written by the job through the **operator** pool (it works across every tenant) and
read back through the same: ``latest_per_tenant`` and ``latest_for_tenant`` serve the platform
route, ``previous_for_config`` serves the next night's comparison. A result belongs to a tenant
version (row-level security by tenant; the operator's policy sees all), is class B for
offboarding (counts about a tenant's version: deleted with it), and holds no content.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol

from guardrail_engine.nightly.model import NightlyResult, QuarantineEvent
from guardrail_engine.policy.document import EXTENDS_REF_PATTERN


@dataclass(frozen=True, slots=True)
class ActiveBundle:
    tenant_id: str
    version: int
    floor_ref: str
    """``platform/floor@<n>``."""
    pack_refs: tuple[str, ...]
    """``domain/<pack>@<n>``, as the bundle names them."""


def bundle_of(tenant_id: str, version: int, extends: Any) -> ActiveBundle | None:
    """The floor and pack references an ``extends`` list holds; None if it names no floor."""
    if isinstance(extends, str):
        extends = json.loads(extends)
    if not isinstance(extends, list):
        return None
    floor = None
    packs = []
    for ref in extends:
        m = EXTENDS_REF_PATTERN.fullmatch(ref) if isinstance(ref, str) else None
        if m is None:
            continue
        if m.group(1):
            floor = ref
        else:
            packs.append(ref)
    return None if floor is None else ActiveBundle(tenant_id, version, floor, tuple(sorted(packs)))


class ActiveBundleSource(Protocol):
    async def active_bundles(self) -> list[ActiveBundle]:
        """Every tenant's active version, with the floor and the packs it extends. Platform-wide
        (the operator role); returns references, never a document."""
        ...


class QuarantineStore(Protocol):
    async def append(self, event: QuarantineEvent) -> None:
        """Append one step. Raises if it can't: an operator's clear that leaves no trail
        does not happen."""
        ...

    async def quarantined(self, mode: str) -> dict[str, QuarantineEvent]:
        """The configurations whose latest event is a ``quarantine``, by configuration key."""
        ...

    async def history(self, config_key: str, mode: str) -> list[QuarantineEvent]: ...


class InMemoryQuarantine:
    def __init__(self) -> None:
        self._events: list[QuarantineEvent] = []

    async def append(self, event: QuarantineEvent) -> None:
        self._events.append(event)

    async def quarantined(self, mode: str) -> dict[str, QuarantineEvent]:
        latest: dict[str, QuarantineEvent] = {}
        for e in self._events:
            if e.mode == mode:
                latest[e.config_key] = e
        return {k: e for k, e in latest.items() if e.action == "quarantine"}

    async def history(self, config_key: str, mode: str) -> list[QuarantineEvent]:
        return [e for e in self._events if e.config_key == config_key and e.mode == mode]


class NightlyResultSink(Protocol):
    async def append_many(self, results: Sequence[NightlyResult]) -> None: ...


class NightlyResultReader(Protocol):
    async def latest_per_tenant(
        self, *, status: str | None, after: str | None, limit: int, project: str | None = None
    ) -> list[NightlyResult]:
        """Each tenant's most recent result, in tenant id order, after ``after`` (only the
        tenants served from ``project`` when given; ``""`` is the shared pool)."""
        ...

    async def latest_for_tenant(self, tenant_id: str) -> list[NightlyResult]:
        """The tenant's most recent results, newest first (at most a week's worth)."""
        ...

    async def previous_for_config(
        self, config_key: str, mode: str, before: datetime
    ) -> NightlyResult | None:
        """The most recent **tested** result (``pass`` or ``regression``) of this configuration
        and mode strictly before ``before`` (any tenant that had it), or None."""
        ...

    async def config_dates(self, config_key: str, mode: str) -> ConfigDates:
        """When the configuration was last tested (``pass`` or ``regression``) and when it was
        first seen (any result, a skipped one included)."""
        ...


@dataclass(frozen=True, slots=True)
class ConfigDates:
    last_tested: datetime | None
    first_seen: datetime | None


TESTED = ("pass", "regression")


class InMemoryNightlyResults:
    def __init__(self) -> None:
        self._rows: list[NightlyResult] = []

    async def append_many(self, results: Sequence[NightlyResult]) -> None:
        self._rows.extend(results)

    def all(self) -> list[NightlyResult]:
        return list(self._rows)

    async def latest_per_tenant(
        self, *, status: str | None, after: str | None, limit: int, project: str | None = None
    ) -> list[NightlyResult]:
        newest: dict[str, NightlyResult] = {}
        for r in self._rows:
            if r.tenant_id not in newest or r.run_at >= newest[r.tenant_id].run_at:
                newest[r.tenant_id] = r
        out = [
            r
            for _, r in sorted(newest.items())
            if (after is None or r.tenant_id > after)
            and (status is None or r.status == status)
            and (project is None or r.project == project)
        ]
        return out[:limit]

    async def latest_for_tenant(self, tenant_id: str) -> list[NightlyResult]:
        mine = [r for r in self._rows if r.tenant_id == tenant_id]
        return sorted(mine, key=lambda r: r.run_at, reverse=True)[:7]

    async def previous_for_config(
        self, config_key: str, mode: str, before: datetime
    ) -> NightlyResult | None:
        found = [
            r
            for r in self._rows
            if r.config_key == config_key
            and r.mode == mode
            and r.run_at < before
            and r.status in TESTED
        ]
        return max(found, key=lambda r: r.run_at, default=None)

    async def config_dates(self, config_key: str, mode: str) -> ConfigDates:
        mine = [r for r in self._rows if r.config_key == config_key and r.mode == mode]
        tested = [r.run_at for r in mine if r.status in TESTED]
        return ConfigDates(max(tested, default=None), min((r.run_at for r in mine), default=None))

    offboard_tables = ("nightly_redteam_results",)

    def offboard_tenant(
        self, tenant_id: str, table: str, limit: int, *, count_only: bool = False
    ) -> dict[str, int]:
        """M5-07: delete (or count) a terminated tenant's results (see ``TenantDataHolder``)."""
        mine = [i for i, r in enumerate(self._rows) if r.tenant_id == tenant_id]
        if count_only:
            return {table: len(mine)}
        for i in reversed(mine[:limit]):
            del self._rows[i]
        return {table: len(mine[:limit])}
