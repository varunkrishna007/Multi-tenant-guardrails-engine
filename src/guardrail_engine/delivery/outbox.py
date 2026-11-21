"""The outbox port (M4-04): where an event waits, durably, until it is delivered.

An event is written once (``enqueue``) and then moves through three states:

* ``pending``: waiting for its next attempt (``next_attempt_at``);
* ``delivered``: a sink accepted it;
* ``dead``: it failed ``max_attempts`` times (the dead-letter state). Dead events stay in the
  table, with the last error code, until an operator re-queues them (``requeue_dead``).

``claim_due`` takes events for delivery under a **lease** (``locked_until``): another
dispatcher skips them until the lease runs out, and if the claiming process dies, they come
back after it. Delivery is therefore **at least once**: an event can be sent twice (after a
crash between delivery and ``mark_delivered``, or a lease that ran out mid-delivery), always
with the same idempotency key, so the receiver can drop the copy.

**The lease is the claim token.** Every ``mark_*`` and ``renew`` changes the event
only if it is still ``pending`` and its ``locked_until`` is the lease the caller's entry was
claimed (or last renewed) under. A worker whose lease ran out, and whose event another
worker has since claimed and finished, therefore changes nothing: it cannot turn a
``delivered`` event ``dead``, or undo a newer worker's retry schedule. Each returns ``True``
if it applied.

Times are epoch seconds (floats) in this port; the stores convert.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Protocol

OFFBOARD_KINDS = ("usage", "escalation")
"""The outbox kinds offboarding deletes (M5-07): the tenant's own usage and escalation
events. A pending ``alert`` that names the tenant is a platform signal and stays."""

STATE_PENDING = "pending"
STATE_DELIVERED = "delivered"
STATE_DEAD = "dead"
_STATE_PURGED = "purged"


@dataclass(frozen=True)
class OutboxEntry:
    id: int
    key: str
    kind: str
    payload: str
    attempts: int
    """Deliveries already tried and failed."""
    created_at: float
    """Epoch seconds when the event was enqueued (the dead-letter age counts from here)."""
    lease: float
    """The ``locked_until`` this entry was claimed under: the claim token the ``mark_*`` calls
    and ``renew`` must present."""


@dataclass(frozen=True)
class OutboxStats:
    pending: int
    delivered: int
    dead: int


class OutboxStore(Protocol):
    """Synchronous: called from the gateway's drainer thread (``enqueue``) and from the
    dispatcher's thread (everything else), never from the event loop."""

    def enqueue(self, kind: str, payload: str, key: str, now: float) -> bool:
        """Store a new pending event, due at once. False if ``key`` is already stored."""
        ...

    def claim_due(
        self, now: float, limit: int, lease_s: float, kinds: tuple[str, ...]
    ) -> list[OutboxEntry]:
        """Up to ``limit`` pending events of ``kinds`` whose time has come and that nobody
        holds, oldest first, now leased until ``now + lease_s``."""
        ...

    def renew(self, entry: OutboxEntry, now: float, lease_s: float) -> OutboxEntry | None:
        """Extend the lease to ``now + lease_s``, if ``entry``'s lease is still the event's.
        Returns the entry under its new lease, or None if the event is no longer ours (another
        worker claimed it, or it was delivered or dead-lettered)."""
        ...

    def mark_delivered(self, entry: OutboxEntry, now: float) -> bool: ...

    def mark_failed(
        self, entry: OutboxEntry, attempts: int, next_attempt_at: float, error: str
    ) -> bool:
        """Release the lease; ``attempts`` failures so far, try again at ``next_attempt_at``."""
        ...

    def mark_dead(self, entry: OutboxEntry, attempts: int, now: float, error: str) -> bool: ...

    def stats(self) -> OutboxStats: ...

    def purge_delivered(self, before: float) -> int:
        """Delete delivered events delivered before ``before``; returns how many."""
        ...

    def requeue_dead(self, now: float) -> int:
        """Put every dead event back to pending with its attempts reset; returns how many."""
        ...


@dataclass
class _Row:
    id: int
    key: str
    kind: str
    payload: str
    state: str = STATE_PENDING
    attempts: int = 0
    next_attempt_at: float = 0.0
    created_at: float = 0.0
    locked_until: float | None = None
    delivered_at: float | None = None
    last_error: str | None = None


class InMemoryOutbox:
    """The port in memory, for tests and for development. It does not survive a restart."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._rows: list[_Row] = []
        self._keys: set[str] = set()

    offboard_tables = ("delivery_outbox",)

    def offboard_tenant(
        self, tenant_id: str, table: str, limit: int, *, count_only: bool = False
    ) -> dict[str, int]:
        """M5-07: delete (or count) a terminated tenant's rows (see ``TenantDataHolder``)."""
        needle = f'"tenant_id":"{tenant_id}"'  # the payloads are compact JSON (delivery.events)
        with self._lock:
            # Only the tenant's own kinds: a pending platform alert naming it stays.
            mine = [r for r in self._rows if r.kind in OFFBOARD_KINDS and needle in r.payload]
            if not count_only:
                mine = mine[:limit]
                gone = {id(r) for r in mine}
                self._rows = [r for r in self._rows if id(r) not in gone]
            return {table: len(mine)}

    def enqueue(self, kind: str, payload: str, key: str, now: float) -> bool:
        with self._lock:
            if key in self._keys:
                return False
            self._keys.add(key)
            self._rows.append(
                _Row(len(self._rows) + 1, key, kind, payload, next_attempt_at=now, created_at=now)
            )
            return True

    def claim_due(
        self, now: float, limit: int, lease_s: float, kinds: tuple[str, ...]
    ) -> list[OutboxEntry]:
        with self._lock:
            due = sorted(
                (
                    r
                    for r in self._rows
                    if r.state == STATE_PENDING
                    and r.kind in kinds
                    and r.next_attempt_at <= now
                    and (r.locked_until is None or r.locked_until <= now)
                ),
                key=lambda r: (r.next_attempt_at, r.id),
            )[:limit]
            for r in due:
                r.locked_until = now + lease_s
            return [self._entry(r) for r in due]

    @staticmethod
    def _entry(r: _Row) -> OutboxEntry:
        return OutboxEntry(
            r.id, r.key, r.kind, r.payload, r.attempts, r.created_at, r.locked_until or 0.0
        )

    def _row(self, entry_id: int) -> _Row:
        return self._rows[entry_id - 1]

    def _held(self, entry: OutboxEntry) -> _Row | None:
        """The row, if it is still pending under the entry's lease (call under the lock)."""
        r = self._row(entry.id)
        if r.state == STATE_PENDING and r.locked_until == entry.lease:
            return r
        return None

    def renew(self, entry: OutboxEntry, now: float, lease_s: float) -> OutboxEntry | None:
        with self._lock:
            r = self._held(entry)
            if r is None:
                return None
            r.locked_until = now + lease_s
            return self._entry(r)

    def mark_delivered(self, entry: OutboxEntry, now: float) -> bool:
        with self._lock:
            r = self._held(entry)
            if r is None:
                return False
            r.state, r.delivered_at, r.locked_until = STATE_DELIVERED, now, None
            return True

    def mark_failed(
        self, entry: OutboxEntry, attempts: int, next_attempt_at: float, error: str
    ) -> bool:
        with self._lock:
            r = self._held(entry)
            if r is None:
                return False
            r.attempts, r.next_attempt_at, r.locked_until = attempts, next_attempt_at, None
            r.last_error = error
            return True

    def mark_dead(self, entry: OutboxEntry, attempts: int, now: float, error: str) -> bool:
        with self._lock:
            r = self._held(entry)
            if r is None:
                return False
            r.state, r.attempts, r.locked_until, r.last_error = (
                STATE_DEAD,
                attempts,
                None,
                error,
            )
            return True

    def stats(self) -> OutboxStats:
        with self._lock:
            counts = {STATE_PENDING: 0, STATE_DELIVERED: 0, STATE_DEAD: 0}
            for r in self._rows:
                if r.state in counts:
                    counts[r.state] += 1
            return OutboxStats(counts[STATE_PENDING], counts[STATE_DELIVERED], counts[STATE_DEAD])

    def purge_delivered(self, before: float) -> int:
        with self._lock:
            old = [
                r
                for r in self._rows
                if r.state == STATE_DELIVERED and (r.delivered_at or 0.0) < before
            ]
            for r in old:  # ids are positions, so a purged row keeps its slot
                r.state = _STATE_PURGED
            return len(old)

    def requeue_dead(self, now: float) -> int:
        with self._lock:
            dead = [r for r in self._rows if r.state == STATE_DEAD]
            for r in dead:
                r.state, r.attempts, r.next_attempt_at, r.locked_until = (
                    STATE_PENDING,
                    0,
                    now,
                    None,
                )
            return len(dead)

    def last_error(self, entry_id: int) -> str | None:
        """For tests: the error code recorded by the last failed attempt."""
        with self._lock:
            return self._row(entry_id).last_error
