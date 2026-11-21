"""The Postgres outbox and usage store (M4-04), behind the synchronous sink ports.

The sinks are called from plain threads (the gateway's drainer, the dispatcher), and the
engine's only Postgres driver (asyncpg, imported by ``store/adapters/postgres.py`` alone) is
asynchronous. :class:`PgBridge` closes that gap: it runs one private event loop in a **daemon
thread**, owns a small connection pool on it, and lets a thread run one coroutine and wait
for it with a timeout. A database that hangs costs the calling thread ``timeout_s``, never a
check, and never process exit (the loop thread is a daemon).

The pool is opened on first use, from ``connect``: a coroutine function returning an asyncpg
pool, e.g. ``lambda: connect_pool(dsn)`` from ``store/adapters/postgres.py``. The role behind
it needs the privileges of ``025_delivery_grants.sql``.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import logging
import threading
from collections.abc import Awaitable, Callable
from dataclasses import replace
from datetime import UTC, datetime
from typing import Any

from guardrail_engine.audit.adapters.postgres import record_connection
from guardrail_engine.delivery.dispatcher import DeliveryError
from guardrail_engine.delivery.events import UsageEvent, new_key
from guardrail_engine.delivery.outbox import (
    STATE_DEAD,
    STATE_DELIVERED,
    STATE_PENDING,
    OutboxEntry,
    OutboxStats,
)
from guardrail_engine.delivery.usage import UsageRecorder

logger = logging.getLogger(__name__)


def _ts(epoch_s: float) -> datetime:
    return datetime.fromtimestamp(epoch_s, UTC)


class PgBridge:
    """A private event loop in a daemon thread with an asyncpg pool on it."""

    def __init__(self, connect: Callable[[], Awaitable[Any]], *, timeout_s: float = 10.0) -> None:
        self._connect = connect
        self._timeout_s = timeout_s
        self._lock = threading.Lock()
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._pool: Any = None
        self._closed = False

    def _start(self) -> asyncio.AbstractEventLoop:
        with self._lock:
            if self._closed:
                raise DeliveryError("closed")
            if self._loop is None:
                loop = asyncio.new_event_loop()
                thread = threading.Thread(
                    target=self._run_loop, args=(loop,), name="guardrail-pg-bridge", daemon=True
                )
                thread.start()
                self._loop, self._thread = loop, thread
            return self._loop

    @staticmethod
    def _run_loop(loop: asyncio.AbstractEventLoop) -> None:
        asyncio.set_event_loop(loop)
        loop.run_forever()

    def run(self, work: Callable[[Any], Awaitable[Any]]) -> Any:
        """Run ``work(pool)`` on the bridge's loop and return its result. Raises
        ``DeliveryError("db_timeout")`` after ``timeout_s`` and ``DeliveryError("db_error")``
        for any database error (the driver's message is logged at debug level only)."""
        loop = self._start()

        async def job() -> Any:
            if self._pool is None:
                self._pool = await self._connect()
            return await work(self._pool)

        future = asyncio.run_coroutine_threadsafe(job(), loop)
        try:
            return future.result(self._timeout_s)
        except concurrent.futures.TimeoutError:
            future.cancel()
            raise DeliveryError("db_timeout") from None
        except DeliveryError:
            raise
        except Exception as exc:
            logger.debug("database call failed: %s", type(exc).__name__, exc_info=True)
            raise DeliveryError("db_error") from exc

    def close(self, timeout: float = 5.0) -> None:
        """Close the pool, stop the loop and join its thread (at most ``timeout`` seconds)."""
        with self._lock:
            already = self._closed
            self._closed = True
            loop, thread = self._loop, self._thread
        if already or loop is None or thread is None:
            return
        pool = self._pool
        if pool is not None:
            closing = asyncio.run_coroutine_threadsafe(pool.close(), loop)
            try:
                closing.result(timeout)
            except Exception:
                logger.warning("the delivery database pool did not close cleanly")
        loop.call_soon_threadsafe(loop.stop)
        thread.join(timeout)
        if not thread.is_alive():
            loop.close()


class PostgresOutbox:
    """The outbox port on Postgres (``delivery_outbox``, migration 024)."""

    def __init__(self, bridge: PgBridge) -> None:
        self._bridge = bridge

    def enqueue(self, kind: str, payload: str, key: str, now: float) -> bool:
        async def work(pool: Any) -> bool:
            row = await pool.fetchrow(
                "INSERT INTO delivery_outbox (idempotency_key, kind, payload, created_at, "
                "next_attempt_at) VALUES ($1, $2, $3, $4, $4) "
                "ON CONFLICT (idempotency_key) DO NOTHING RETURNING id",
                key,
                kind,
                payload,
                _ts(now),
            )
            return row is not None

        return bool(self._bridge.run(work))

    def claim_due(
        self, now: float, limit: int, lease_s: float, kinds: tuple[str, ...]
    ) -> list[OutboxEntry]:
        lease = now + lease_s

        async def work(pool: Any) -> list[Any]:
            return list(
                await pool.fetch(
                    "WITH due AS ("
                    " SELECT id FROM delivery_outbox"
                    " WHERE state = 'pending' AND next_attempt_at <= $1"
                    "   AND (locked_until IS NULL OR locked_until <= $1) AND kind = ANY($4)"
                    " ORDER BY next_attempt_at, id LIMIT $2 FOR UPDATE SKIP LOCKED) "
                    "UPDATE delivery_outbox o SET locked_until = $3 FROM due WHERE o.id = due.id "
                    "RETURNING o.id, o.idempotency_key, o.kind, o.payload, o.attempts, "
                    "extract(epoch FROM o.created_at)::float8 AS created",
                    _ts(now),
                    limit,
                    _ts(lease),
                    list(kinds),
                )
            )

        rows = self._bridge.run(work)
        return [
            OutboxEntry(
                r["id"],
                r["idempotency_key"],
                r["kind"],
                r["payload"],
                r["attempts"],
                r["created"],
                lease,
            )
            for r in sorted(rows, key=lambda r: r["id"])
        ]

    # Every update below is guarded by the claim token: the event is still pending and its
    # locked_until is the lease the caller holds. The lease is compared as the same
    # datetime the claim wrote, so the comparison is exact.

    def _guarded(self, sql: str, entry: OutboxEntry, *args: Any) -> bool:
        async def work(pool: Any) -> str:
            return str(await pool.execute(sql, entry.id, _ts(entry.lease), *args))

        return self._bridge.run(work).rsplit(" ", 1)[-1] == "1"

    def renew(self, entry: OutboxEntry, now: float, lease_s: float) -> OutboxEntry | None:
        lease = now + lease_s
        applied = self._guarded(
            "UPDATE delivery_outbox SET locked_until = $3 "
            "WHERE id = $1 AND state = 'pending' AND locked_until = $2",
            entry,
            _ts(lease),
        )
        return replace(entry, lease=lease) if applied else None

    def mark_delivered(self, entry: OutboxEntry, now: float) -> bool:
        return self._guarded(
            "UPDATE delivery_outbox SET state = 'delivered', delivered_at = $3, "
            "locked_until = NULL WHERE id = $1 AND state = 'pending' AND locked_until = $2",
            entry,
            _ts(now),
        )

    def mark_failed(
        self, entry: OutboxEntry, attempts: int, next_attempt_at: float, error: str
    ) -> bool:
        return self._guarded(
            "UPDATE delivery_outbox SET attempts = $3, next_attempt_at = $4, "
            "locked_until = NULL, last_error = $5 "
            "WHERE id = $1 AND state = 'pending' AND locked_until = $2",
            entry,
            attempts,
            _ts(next_attempt_at),
            error[:200],
        )

    def mark_dead(self, entry: OutboxEntry, attempts: int, now: float, error: str) -> bool:
        return self._guarded(
            "UPDATE delivery_outbox SET state = 'dead', attempts = $3, dead_at = $4, "
            "locked_until = NULL, last_error = $5 "
            "WHERE id = $1 AND state = 'pending' AND locked_until = $2",
            entry,
            attempts,
            _ts(now),
            error[:200],
        )

    def stats(self) -> OutboxStats:
        async def work(pool: Any) -> list[Any]:
            return list(
                await pool.fetch("SELECT state, count(*) AS n FROM delivery_outbox GROUP BY state")
            )

        counts = {r["state"]: r["n"] for r in self._bridge.run(work)}
        return OutboxStats(
            counts.get(STATE_PENDING, 0), counts.get(STATE_DELIVERED, 0), counts.get(STATE_DEAD, 0)
        )

    def purge_delivered(self, before: float) -> int:
        async def work(pool: Any) -> str:
            return str(
                await pool.execute(
                    "DELETE FROM delivery_outbox WHERE state = 'delivered' AND delivered_at < $1",
                    _ts(before),
                )
            )

        return int(self._bridge.run(work).rsplit(" ", 1)[-1])

    def requeue_dead(self, now: float) -> int:
        async def work(pool: Any) -> str:
            return str(
                await pool.execute(
                    "UPDATE delivery_outbox SET state = 'pending', attempts = 0, "
                    "next_attempt_at = $1, locked_until = NULL, dead_at = NULL "
                    "WHERE state = 'dead'",
                    _ts(now),
                )
            )

        return int(self._bridge.run(work).rsplit(" ", 1)[-1])


class PostgresUsageStore(UsageRecorder):
    """The usage store on Postgres (``usage_events``, migration 024).

    As a ``UsageStore`` (``write``) it is the dispatcher's usage sink, idempotent on the
    outbox event's key. As a ``UsageMeter`` (``record``...) it is a direct, **non-durable**
    sink: each call is one insert under a fresh key, so a failing database loses the event.
    Use :class:`~guardrail_engine.delivery.durable.DurableUsageMeter` for the durable path."""

    def __init__(self, bridge: PgBridge) -> None:
        super().__init__()
        self._bridge = bridge

    def write(self, event: UsageEvent, key: str) -> None:
        async def work(pool: Any) -> None:
            # usage_events is tenant-scoped (038): the row is written under its own tenant's
            # setting, taken from the event the gateway raised for a verified tenant.
            async with record_connection(pool, event.tenant_id) as conn:
                await conn.execute(
                    "INSERT INTO usage_events (idempotency_key, kind, tenant_id, guard_point, "
                    "input_tokens, occurred_at, project) VALUES ($1, $2, $3, $4, $5, $6, $7) "
                    "ON CONFLICT (idempotency_key) DO NOTHING",
                    key,
                    event.kind,
                    event.tenant_id,
                    event.guard_point,
                    event.input_tokens,
                    _ts(event.at),
                    event.project,
                )

        self._bridge.run(work)

    def _submit(self, event: UsageEvent) -> None:
        self.write(event, new_key())
