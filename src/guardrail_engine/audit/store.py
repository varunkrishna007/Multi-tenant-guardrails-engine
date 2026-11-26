"""Ports for the decision records (M4-07): where the writer puts a check's audit record and
where the audit query reads them (R3 class B; the table is ``decision_records``, M4-09).

``DecisionRecordSink.append_many`` takes records the writer has already stamped with their
deletion time. ``DecisionRecordReader.page`` is scoped: it returns only the tenant of the
:class:`~guardrail_engine.tenant_scope.TenantScope` it is given (row-level security on
Postgres), newest first, with a keyset position instead of an offset.
"""

from __future__ import annotations

import base64
import binascii
import json
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol

from guardrail_engine.guard.audit import AuditRecord
from guardrail_engine.tenant_scope import TenantScope

DECISIONS = ("allow", "escalate", "block", "forbidden")


class InvalidCursorError(ValueError):
    """The cursor is not one this service issued (HTTP 400)."""


@dataclass(frozen=True, slots=True)
class Position:
    """A place in the newest-first order: records older than this one come next."""

    ts: datetime
    id: int


def encode_cursor(position: Position) -> str:
    raw = json.dumps({"t": position.ts.astimezone(UTC).isoformat(), "i": position.id})
    return base64.urlsafe_b64encode(raw.encode()).decode().rstrip("=")


def decode_cursor(cursor: str) -> Position:
    """Strictly: an unknown shape is refused, never guessed at. The cursor only chooses a
    position inside the caller's own tenant, so it needs no signature."""
    try:
        if not isinstance(cursor, str) or not 1 <= len(cursor) <= 128:
            raise ValueError
        body = json.loads(base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)))
        if not isinstance(body, dict) or set(body) != {"t", "i"}:
            raise ValueError
        ts, ident = body["t"], body["i"]
        if not isinstance(ts, str) or isinstance(ident, bool) or not isinstance(ident, int):
            raise ValueError
        when = datetime.fromisoformat(ts)
        if when.tzinfo is None or ident < 1:
            raise ValueError
        return Position(when, ident)
    except (ValueError, binascii.Error, UnicodeDecodeError):
        raise InvalidCursorError("not a cursor this service issued") from None


@dataclass(frozen=True, slots=True)
class DecisionFilter:
    start: datetime
    """Inclusive."""
    end: datetime
    """Exclusive."""
    rule: str | None = None
    """A rule key that **fired** (escalated or blocked, enforce or shadow) in the record."""
    decision: str | None = None
    guard_point: str | None = None


@dataclass(frozen=True, slots=True)
class StoredDecision:
    id: int
    ts: datetime
    record: dict[str, Any]
    """The audit record as written (the JSON of :class:`AuditRecord`)."""


class DecisionRecordSink(Protocol):
    async def append_many(self, records: Sequence[AuditRecord]) -> None: ...


class KeyedDecisionRecordSink(DecisionRecordSink, Protocol):
    """A sink that can keep a record **once**, by a key the caller chose (M7-04).

    The writer's spill replay uses it: a record is replayed under the id it was spilled with,
    so replaying it again after a crash (written, but not yet marked done) adds no second row.
    Keys are per tenant."""

    async def append_keyed(self, records: Sequence[AuditRecord], keys: Sequence[str]) -> None:
        """Like ``append_many`` for one tenant's records, each with its key; a record whose key
        the tenant already has is skipped."""
        ...


class DecisionRecordReader(Protocol):
    async def page(
        self,
        scope: TenantScope,
        flt: DecisionFilter,
        limit: int,
        after: Position | None,
    ) -> list[StoredDecision]:
        """Up to ``limit`` of the scope's tenant's records matching ``flt``, newest first,
        older than ``after`` when given."""
        ...


def fired_keys(record: AuditRecord) -> list[str]:
    """What the ``fired_rules`` column holds: the keys of the rules that fired, once each."""
    seen: dict[str, None] = {}
    for entry in record.fired:
        seen.setdefault(entry.rule)
    return list(seen)


class InMemoryDecisionRecords:
    """Both ports in memory, for tests and an engine without Postgres. Isolates by tenant the
    way row-level security does: a record with no tenant is stored and never returned, and an
    operator's scope reads the one tenant it names, like everyone's."""

    def __init__(self) -> None:
        self._rows: list[tuple[int, AuditRecord]] = []
        self._next_id = 1
        self._keys: set[tuple[str | None, str]] = set()

    async def append_many(self, records: Sequence[AuditRecord]) -> None:
        for record in records:
            self._rows.append((self._next_id, record))
            self._next_id += 1

    async def append_keyed(self, records: Sequence[AuditRecord], keys: Sequence[str]) -> None:
        for record, key in zip(records, keys, strict=True):
            if (record.tenant_id, key) in self._keys:
                continue
            self._keys.add((record.tenant_id, key))
            await self.append_many([record])

    def all(self) -> list[AuditRecord]:
        return [r for _, r in self._rows]

    offboard_tables = ("decision_records", "decision_record_rules")

    def offboard_tenant(
        self, tenant_id: str, table: str, limit: int, *, count_only: bool = False
    ) -> dict[str, int]:
        """M5-07: delete (or count) a terminated tenant's records (see ``TenantDataHolder``).
        The rule index is derived from the record here, so it goes with it."""
        mine = [i for i, (_, r) in enumerate(self._rows) if r.tenant_id == tenant_id]
        if table != "decision_records":
            return {table: 0}
        if count_only:
            return {table: len(mine)}
        for i in reversed(mine[:limit]):
            del self._rows[i]
        return {table: len(mine[:limit])}

    async def page(
        self, scope: TenantScope, flt: DecisionFilter, limit: int, after: Position | None
    ) -> list[StoredDecision]:
        found = []
        for ident, record in self._rows:
            if record.tenant_id != scope.tenant_id or not flt.start <= record.ts < flt.end:
                continue
            if flt.guard_point is not None and record.guard_point != flt.guard_point:
                continue
            if flt.decision is not None and record.decision.value != flt.decision:
                continue
            if flt.rule is not None and flt.rule not in fired_keys(record):
                continue
            if after is not None and (record.ts, ident) >= (after.ts, after.id):
                continue
            found.append(StoredDecision(ident, record.ts, json.loads(record.model_dump_json())))
        found.sort(key=lambda d: (d.ts, d.id), reverse=True)
        return found[:limit]
