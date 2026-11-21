"""The write-behind writer of decision records (M4-07).

:class:`DecisionRecordWriter` is the engine's :class:`~guardrail_engine.guard.audit.AuditSink`.
``record`` runs on the check path and only builds the audit record and puts it on a **bounded
queue**: it never waits for the database, never raises, and costs one object. A background task
drains the queue in batches, stamps each record's deletion time, and writes it.

* **Deletion time (R3).** ``retain_until`` is the record's timestamp plus the *effective,
  clamped* class B term (:mod:`guardrail_engine.audit.term`: the term the check was decided
  under, moved into the R3 bounds in force for the tenant now; the longest term when it can't be
  worked out), never the raw figure the verdict carried. Terms are cached for
  ``retention_ttl_s``; a record is stamped when it is written.
* **Full queue.** A record that finds the queue full is **dropped and counted** (``dropped``);
  nothing waits. Given ``alerts``, the writer's own task raises ``audit_records_dropped``
  (``monitoring.dropped.DroppedAuditRecordsWatch``, at most one a minute) when the count
  grows. Records the database refused ``max_attempts`` times, and records still queued when
  ``aclose`` runs out of time, count too.
* **A failing database.** A tenant group that can't be written goes back to the front of the
  queue and is tried again after a pause that doubles up to ``retry_cap_s``; records beyond the
  queue's capacity are dropped meanwhile, so a down database costs memory up to the bound and
  no more.
* **No content.** Only the audit record's own fields are written (no content, no provider free
  text; see :mod:`guardrail_engine.guard.audit`).
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from collections import deque
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import timedelta

from guardrail_engine.audit.store import DecisionRecordSink
from guardrail_engine.audit.term import TermResolver
from guardrail_engine.gateway.sinks import AlertSink
from guardrail_engine.guard.audit import AuditRecord
from guardrail_engine.guard.verdict import Verdict
from guardrail_engine.monitoring.dropped import DroppedAuditRecordsWatch

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class _Item:
    record: AuditRecord
    requested_days: int | None
    """The term the check was decided under (``Verdict.retention_days``); not what is written."""
    packs: tuple[str, ...] = ()
    """The packs the deciding version extends, to clamp the term against."""
    attempts: int = 0
    solo: bool = False
    """A group this record was in failed: it is written alone from now on, so one record the
    database refuses can't take its neighbours down with it."""


class DecisionRecordWriter:
    def __init__(
        self,
        sink: DecisionRecordSink,
        terms: TermResolver,
        *,
        capacity: int = 10_000,
        batch_size: int = 200,
        flush_interval_s: float = 0.5,
        retention_ttl_s: float = 300.0,
        max_attempts: int = 5,
        retry_base_s: float = 0.5,
        retry_cap_s: float = 30.0,
        clock: Callable[[], float] = time.monotonic,
        alerts: AlertSink | None = None,
        alert_interval_s: float = 60.0,
    ) -> None:
        if capacity < 1 or batch_size < 1 or max_attempts < 1:
            raise ValueError("capacity, batch_size and max_attempts must be at least 1")
        self._sink = sink
        self._terms_source = terms
        self._capacity = capacity
        self._batch_size = batch_size
        self._flush_interval_s = flush_interval_s
        self._retention_ttl_s = retention_ttl_s
        self._max_attempts = max_attempts
        self._retry_base_s = retry_base_s
        self._retry_cap_s = retry_cap_s
        self._clock = clock
        self._watch = (
            None
            if alerts is None
            else DroppedAuditRecordsWatch(
                lambda: self.dropped, alerts, min_interval_s=alert_interval_s, clock=clock
            )
        )
        self._queue: deque[_Item] = deque()
        self._terms: dict[tuple[str | None, int | None, tuple[str, ...]], tuple[int, float]] = {}
        self._wake = asyncio.Event()
        self._task: asyncio.Task[None] | None = None
        self._closing = False
        self._failures = 0
        self.dropped = 0
        """Records lost: queue full, refused too often, or still queued at shutdown."""
        self.written = 0
        self.failed_writes = 0
        """Tenant groups the database refused (each is retried up to ``max_attempts``)."""

    # ------------------------------------------------------------------ the check path

    def record(self, verdict: Verdict) -> None:
        """Queue the check's record. Never blocks, never raises."""
        try:
            if self._closing or len(self._queue) >= self._capacity:
                self.dropped += 1
                return
            self._queue.append(
                _Item(
                    AuditRecord.from_verdict(verdict),
                    verdict.retention_days,
                    tuple(verdict.retention_packs),
                )
            )
            if len(self._queue) >= self._batch_size:
                self._wake.set()
        except Exception:
            self.dropped += 1
            logger.exception("a decision record could not be queued")

    @property
    def queued(self) -> int:
        return len(self._queue)

    # ------------------------------------------------------------------ lifecycle

    def start(self) -> None:
        """Start the background task. Needs a running loop. Safe to call twice."""
        if self._task is None or self._task.done():
            self._task = asyncio.get_running_loop().create_task(self._run())

    async def aclose(self, timeout_s: float = 5.0) -> None:
        """Stop accepting, write what is queued if it can within ``timeout_s``, and count what
        is left as dropped."""
        self._closing = True
        deadline = self._clock() + timeout_s
        task = self._task
        if task is not None:
            # Let a write in flight finish (cancelling it could leave a group written and
            # queued again: a duplicate). Only a task that outlives half the bound is cancelled.
            self._wake.set()
            await asyncio.wait({task}, timeout=timeout_s / 2)
            if not task.done():
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
            self._task = None
        while self._queue and self._clock() < deadline:
            before = len(self._queue)
            try:
                await asyncio.wait_for(self._write_once(), max(0.05, deadline - self._clock()))
            except Exception:
                break
            if len(self._queue) >= before:
                break
        if self._queue:
            self.dropped += len(self._queue)
            logger.error("%d decision records were not written at shutdown", len(self._queue))
            self._queue.clear()
        await self._alert()

    async def flush(self) -> None:
        """Write what is queued now, for a test or a graceful step; raises nothing."""
        while self._queue:
            before = len(self._queue)
            await self._write_once()
            if len(self._queue) >= before:
                return

    # ------------------------------------------------------------------ the background side

    async def _run(self) -> None:
        pause = 0.0
        while not self._closing:
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(self._wake.wait(), self._flush_interval_s + pause)
            self._wake.clear()
            await self._alert()
            while self._queue and not self._closing:
                ok = await self._write_once()
                if not ok:
                    self._failures += 1
                    pause = min(self._retry_cap_s, self._retry_base_s * 2 ** (self._failures - 1))
                    break
                self._failures = 0
                pause = 0.0

    async def _alert(self) -> None:
        """Raise the dropped-records alert if the count grew. Off the check path and off the
        loop (the sink may be an outbox insert)."""
        if self._watch is None:
            return
        try:
            await asyncio.to_thread(self._watch.tick)
        except Exception:
            logger.exception("the dropped decision records alert could not be raised")

    async def _write_once(self) -> bool:
        """Write one batch: tenant group by tenant group, and a record that was in a failed
        group alone. False if any write failed."""
        batch = [self._queue.popleft() for _ in range(min(self._batch_size, len(self._queue)))]
        by_tenant: dict[str | None, list[_Item]] = {}
        groups: list[tuple[str | None, list[_Item]]] = []
        for item in batch:
            if item.solo:
                groups.append((item.record.tenant_id, [item]))
            else:
                by_tenant.setdefault(item.record.tenant_id, []).append(item)
        groups += list(by_tenant.items())
        ok = True
        for tenant_id, items in groups:
            try:
                stamped = await self._stamp(tenant_id, items)
                await self._sink.append_many(stamped)
                self.written += len(items)
            except asyncio.CancelledError:
                # Cancelled in flight (only past the shutdown bound): whether the group was
                # written is unknown, and writing it again could duplicate it. Counted as lost.
                self.dropped += len(items)
                logger.error(
                    "%d decision records were being written at shutdown; "
                    "they may or may not have been",
                    len(items),
                )
                raise
            except Exception:
                ok = False
                self.failed_writes += 1
                logger.exception("decision records could not be written; will retry")
                self._requeue(items)
        return ok

    def _requeue(self, items: Sequence[_Item]) -> None:
        """Back to the front after a failed write. A failed group is split: from now on each of
        its records is written alone, so one the database refuses costs only itself (it is
        dropped after ``max_attempts`` of its own); a record that failed alone counts an
        attempt."""
        split = len(items) > 1
        for item in reversed(items):
            if split:
                item.solo = True
            else:
                item.attempts += 1
            if item.attempts >= self._max_attempts:
                self.dropped += 1
            elif len(self._queue) < self._capacity:
                self._queue.appendleft(item)
            else:
                self.dropped += 1

    async def _stamp(self, tenant_id: str | None, items: Sequence[_Item]) -> list[AuditRecord]:
        stamped = []
        for item in items:
            days = await self._days(tenant_id, item.requested_days, item.packs)
            stamped.append(
                item.record.model_copy(
                    update={"retain_until": item.record.ts + timedelta(days=days)}
                )
            )
        return stamped

    async def _days(
        self, tenant_id: str | None, requested: int | None, packs: tuple[str, ...]
    ) -> int:
        now = self._clock()
        key = (tenant_id, requested, packs)
        cached = self._terms.get(key)
        if cached is not None and now - cached[1] < self._retention_ttl_s:
            return cached[0]
        term = await self._terms_source.term(tenant_id, requested, packs)  # never raises
        self._terms[key] = (term.days, now)
        if len(self._terms) > 10_000:  # a bound, not a limit anyone reaches
            self._terms.pop(next(iter(self._terms)))
        return term.days
