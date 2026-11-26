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
* **Regulated tenants (M7-04).** A tenant whose tier is not ``standard`` is not dropped. Its
  check, through :meth:`DecisionRecordWriter.arecord`, waits up to ``regulated_wait_s`` for room
  in the queue; if there is none, the record is **spilled** to a local file beside the class A
  audit file, flushed to disk (:mod:`guardrail_engine.audit.spill`), and the writer replays it
  into the store once the queue has room again and at startup. A check that spills waits for
  that wait plus one append and ``fsync`` of the file (done on the writer's own single thread,
  never on the event loop or in the shared pool; appends from many checks queue behind each
  other there). A spilled record has an id and the store keeps one row per id, so a crash
  between the insert and the end of the replay can't duplicate it. Records still queued when
  ``aclose`` runs out of time are spilled too. **The file is capped** (``max_bytes`` of the
  spill): past the cap a regulated record is dropped and counted like a standard one, so a long
  outage can't fill the filesystem the class A file shares; an alert is raised as the file nears
  the cap. Replay reads the file once and writes the records in batches from that read; a record
  whose term has already passed, or whose tenant has ended, is skipped, not written; the file is
  rewritten without what is done once those lines are over half of it, and deleted once nothing
  is pending. Only a failing or full spill file drops a regulated record. The verdict is the
  same either way.
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
import functools
import logging
import time
from collections import deque
from collections.abc import Awaitable, Callable, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from guardrail_engine.audit.spill import DecisionSpill, SpilledRecord, SpillFullError
from guardrail_engine.audit.store import DecisionRecordSink, KeyedDecisionRecordSink
from guardrail_engine.audit.term import TermResolver
from guardrail_engine.gateway.sinks import (
    ALERT_AUDIT_SPILL_NEAR_CAP,
    Alert,
    AlertSeverity,
    AlertSink,
)
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
        spill: DecisionSpill | None = None,
        is_regulated: Callable[[str], Awaitable[bool]] | None = None,
        regulated_wait_s: float = 0.25,
        regulated_ttl_s: float = 60.0,
        is_ended: Callable[[str], Awaitable[bool]] | None = None,
        wall_clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        spill_alert_fraction: float = 0.8,
    ) -> None:
        if capacity < 1 or batch_size < 1 or max_attempts < 1:
            raise ValueError("capacity, batch_size and max_attempts must be at least 1")
        if regulated_wait_s < 0:
            raise ValueError("regulated_wait_s must not be negative")
        if spill is not None and not hasattr(sink, "append_keyed"):
            raise ValueError("a spill needs a sink that keeps a record once (append_keyed)")
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
        self._alerts = alerts
        self._alert_interval_s = alert_interval_s
        self._spill = spill
        self._is_ended = is_ended
        self._wall_clock = wall_clock
        self._spill_alert_fraction = spill_alert_fraction
        self._spill_alert_at: float | None = None
        self._append_pool = ThreadPoolExecutor(1, "decision-spill-append") if spill else None
        self._replay_pool = ThreadPoolExecutor(1, "decision-spill-replay") if spill else None
        """Spill file I/O (open, lock, fsync, read) runs on these two single threads, never on
        the event loop and never in the loop's shared pool (which redaction uses): one for the
        appends of checks, one for the background replay, so a long read can't hold an append."""
        self._spill_inflight: set[asyncio.Future[tuple[str, int, int]]] = set()
        self._spill_bytes = 0
        """The spill file's size as this writer knows it (read at the first replay, then every
        append it makes). Another process appending to the same file is not counted until the
        next read."""
        self._pending: deque[SpilledRecord] | None = None
        """The spilled records not yet written, read once and then kept: records this writer
        spills are added to it as they are written, so replay never re-reads the file per batch."""
        self._pending_bytes = 0
        self._is_regulated = is_regulated
        self._regulated_wait_s = regulated_wait_s
        self._regulated_ttl_s = regulated_ttl_s
        self._regulated: dict[str, tuple[bool, float]] = {}
        self._room = asyncio.Event()
        self._replay_due = spill is not None
        """The spill file may hold records: set at start, and whenever a record is spilled."""
        self._replay_attempts: dict[str, int] = {}
        self._replay_lock = asyncio.Lock()
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
        self.spilled = 0
        """Regulated tenants' records written to the spill file instead of being dropped."""
        self.replayed = 0
        """Spilled records written to the store."""
        self.spill_full = 0
        """Regulated records dropped because the spill file was at its cap (also in ``dropped``)."""
        self.expired_skipped = 0
        """Spilled records not written because their term had already passed."""
        self.ended_skipped = 0
        """Spilled records not written because their tenant has ended (offboarded)."""

    # ------------------------------------------------------------------ the check path

    def record(self, verdict: Verdict) -> None:
        """Queue the check's record. Never blocks, never raises. A full queue drops the record
        (:meth:`arecord` is the path that keeps a regulated tenant's)."""
        try:
            if self._closing or len(self._queue) >= self._capacity:
                self.dropped += 1
                return
            self._enqueue(verdict)
        except Exception:
            self.dropped += 1
            logger.exception("a decision record could not be queued")

    def _enqueue(self, verdict: Verdict) -> None:
        self._queue.append(
            _Item(
                AuditRecord.from_verdict(verdict),
                verdict.retention_days,
                tuple(verdict.retention_packs),
            )
        )
        if len(self._queue) >= self._batch_size:
            self._wake.set()

    async def arecord(self, verdict: Verdict) -> None:
        """Queue the check's record, and keep it if the tenant is regulated (M7-04). Never
        raises. Nothing waits unless the queue is full; then a standard tenant's record is
        dropped as in :meth:`record`, and a regulated tenant's check waits up to
        ``regulated_wait_s`` for room, after which the record is spilled to disk."""
        try:
            if not self._closing and len(self._queue) < self._capacity:
                self._enqueue(verdict)
                return
            if verdict.tenant_id is None or not await self._regulated_tenant(verdict.tenant_id):
                self.dropped += 1
                return
            if await self._wait_for_room():
                self._enqueue(verdict)
                return
            await self._spill_record(AuditRecord.from_verdict(verdict), verdict)
        except asyncio.CancelledError:
            # The caller went away mid-wait: the record is still owed to a regulated tenant.
            self._keep_after_cancel(verdict)
            raise
        except Exception:
            self.dropped += 1
            logger.exception("a decision record could not be kept")

    def _keep_after_cancel(self, verdict: Verdict) -> None:
        """The caller went away: the record is still owed to a regulated tenant. Never blocks
        the loop: a spill is handed to the append thread and finishes on its own (``aclose``
        waits for it)."""
        try:
            if not self._closing and len(self._queue) < self._capacity:
                self._enqueue(verdict)
            elif self._spill is not None and self._is_known_regulated(verdict.tenant_id):
                record = AuditRecord.from_verdict(verdict)
                days, packs = verdict.retention_days, tuple(verdict.retention_packs)
                future = asyncio.get_running_loop().run_in_executor(
                    self._append_pool,
                    functools.partial(self._spill.append, record, days, packs),
                )
                self._spill_inflight.add(future)
                future.add_done_callback(
                    functools.partial(self._cancelled_spill_done, record, days, packs)
                )
            else:
                self.dropped += 1
        except Exception:
            self.dropped += 1
            logger.exception("a decision record could not be kept")

    def _cancelled_spill_done(
        self,
        record: AuditRecord,
        days: int | None,
        packs: tuple[str, ...],
        future: asyncio.Future[tuple[str, int, int]],
    ) -> None:
        self._spill_inflight.discard(future)
        try:
            ident, nbytes, size = future.result()
        except Exception as e:
            self._spill_failed(e)
            return
        self._spilled(ident, record, days, packs, nbytes, size)

    async def _wait_for_room(self) -> bool:
        deadline = self._clock() + self._regulated_wait_s
        while not self._closing:
            if len(self._queue) < self._capacity:
                return True
            left = deadline - self._clock()
            if left <= 0:
                return False
            self._room.clear()
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(self._room.wait(), left)
        return False

    async def _spill_record(self, record: AuditRecord, verdict: Verdict) -> None:
        await self._spill_item(record, verdict.retention_days, tuple(verdict.retention_packs))

    async def _spill_item(
        self, record: AuditRecord, days: int | None, packs: tuple[str, ...]
    ) -> bool:
        """Append one record to the spill file on the append thread. False when it was not kept
        (no spill, the file is full, or the write failed); it is then counted as dropped."""
        if self._spill is None:
            self.dropped += 1
            return False
        try:
            ident, nbytes, size = await asyncio.get_running_loop().run_in_executor(
                self._append_pool,
                functools.partial(self._spill.append, record, days, packs),
            )
        except asyncio.CancelledError:
            raise
        except Exception as e:
            self._spill_failed(e)
            return False
        self._spilled(ident, record, days, packs, nbytes, size)
        return True

    def _spill_failed(self, error: BaseException) -> None:
        self.dropped += 1
        if isinstance(error, SpillFullError):
            self.spill_full += 1
            logger.error("a regulated tenant's decision record was dropped: %s", error)
        else:
            logger.error(
                "a regulated tenant's decision record could not be spilled (%s)",
                type(error).__name__,
            )

    def _spilled(
        self,
        ident: str,
        record: AuditRecord,
        days: int | None,
        packs: tuple[str, ...],
        nbytes: int,
        size: int,
    ) -> None:
        self.spilled += 1
        self._spill_bytes = size  # the file's size when the line was written, other processes' too
        if self._pending is not None:  # known to the replay without reading the file again
            self._pending.append(SpilledRecord(ident, record, days, packs, nbytes))
            self._pending_bytes += nbytes
        self._replay_due = True
        self._wake.set()

    def _is_known_regulated(self, tenant_id: str | None) -> bool:
        cached = self._regulated.get(tenant_id or "")
        return cached is not None and cached[0]

    async def _regulated_tenant(self, tenant_id: str) -> bool:
        """Whether the tenant's tier is not ``standard``; remembered for ``regulated_ttl_s``.
        A directory that can't be read counts as regulated: keeping a record costs a file line,
        dropping one costs the record."""
        if self._is_regulated is None:
            return False
        now = self._clock()
        cached = self._regulated.get(tenant_id)
        if cached is not None and now - cached[1] < self._regulated_ttl_s:
            return cached[0]
        try:
            regulated = await self._is_regulated(tenant_id)
        except Exception:
            logger.exception(
                "the tier of tenant %s could not be read; keeping its record", tenant_id
            )
            return True
        self._regulated[tenant_id] = (regulated, now)
        if len(self._regulated) > 10_000:  # a bound, not a limit anyone reaches
            self._regulated.pop(next(iter(self._regulated)))
        return regulated

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
            await self._keep_what_is_left()
        if self._spill_inflight:
            await asyncio.gather(*self._spill_inflight, return_exceptions=True)
        await self._alert()
        loop = asyncio.get_running_loop()
        for pool in (self._append_pool, self._replay_pool):
            if pool is not None:
                await loop.run_in_executor(None, pool.shutdown)

    async def _keep_what_is_left(self) -> None:
        """Records still queued at shutdown: a regulated tenant's go to the spill file, the rest
        are dropped and counted."""
        left = list(self._queue)
        self._queue.clear()
        regulated: dict[str | None, bool] = {}
        lost = kept = 0
        for item in left:
            tenant = item.record.tenant_id
            if tenant not in regulated:
                regulated[tenant] = tenant is not None and await self._regulated_at_shutdown(tenant)
            if self._spill is not None and regulated[tenant]:
                # a spill that fails counts itself as dropped
                kept += await self._spill_item(item.record, item.requested_days, item.packs)
            else:
                lost += 1
        self.dropped += lost
        if lost or kept < len(left):
            logger.error("%d decision records were not written at shutdown", len(left) - kept)
        if kept:
            logger.warning(
                "%d decision records were spilled at shutdown and are written at the next start",
                kept,
            )

    async def _regulated_at_shutdown(self, tenant_id: str) -> bool:
        try:
            return await asyncio.wait_for(self._regulated_tenant(tenant_id), 1.0)
        except Exception:
            return True

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
            if self._replay_due and not self._closing and len(self._queue) <= self._capacity // 2:
                if await self._replay_once():
                    self._failures = 0
                    pause = 0.0
                    if self._replay_due:
                        self._wake.set()
                else:
                    self._failures += 1
                    pause = min(self._retry_cap_s, self._retry_base_s * 2 ** (self._failures - 1))

    async def replay(self) -> None:
        """Write the spilled records to the store now (a test or a graceful step); raises
        nothing. The background task does this when the queue has room, and at startup."""
        while self._replay_due:
            if not await self._replay_once():
                return

    async def _in_replay_pool(self, fn: Callable[..., Any], *args: Any) -> Any:
        return await asyncio.get_running_loop().run_in_executor(self._replay_pool, fn, *args)

    async def _replay_once(self) -> bool:
        """One pass over the spilled records: read the file once (the first time), then write
        batches from memory while the queue has room. False if a write failed."""
        spill = self._spill
        if spill is None:
            self._replay_due = False
            return True
        async with self._replay_lock:
            try:
                if self._pending is None:
                    state = await self._in_replay_pool(spill.state)
                    self._load(state.pending, state.size)
                ok = True
                while self._pending and not self._closing and self._has_room():
                    ok = await self._replay_batch() and ok
                    if not ok:
                        return False
                    await asyncio.sleep(0)  # let the checks and the drain run between batches
                if self._pending:
                    return ok  # the queue is busy or the writer is closing: the rest waits
                await self._finish_replay(spill)
                return ok
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("the decision spill file could not be replayed; will retry")
                return False

    def _has_room(self) -> bool:
        return len(self._queue) <= self._capacity // 2

    def _load(self, pending: Sequence[SpilledRecord], size: int) -> None:
        self._pending = deque(pending)
        self._pending_bytes = sum(r.size for r in pending)
        self._spill_bytes = size

    async def _finish_replay(self, spill: DecisionSpill) -> None:
        """Nothing pending in memory: read the file once more. If another process spilled
        meanwhile, take those up; else delete the file. A file whose done lines are over half
        of it is rewritten without them."""
        state = await self._in_replay_pool(spill.state)
        if state.pending:
            self._load(state.pending, state.size)
            self._wake.set()
            return
        if state.size and await self._in_replay_pool(spill.retire, state):
            self._spill_bytes = 0
        else:
            self._spill_bytes = state.size
        self._pending, self._pending_bytes = deque(), 0
        self._replay_due = False

    async def _compact_if_needed(self, spill: DecisionSpill) -> None:
        done_bytes = self._spill_bytes - self._pending_bytes
        if self._spill_bytes and done_bytes * 2 > self._spill_bytes:
            self._spill_bytes = await self._in_replay_pool(spill.compact)

    async def _replay_batch(self) -> bool:
        """The next batch of ``_pending`` into the store, tenant by tenant, and the ``done``
        mark for what is written (or skipped). What failed goes back to the front."""
        spill = self._spill
        assert spill is not None and self._pending is not None
        batch = [self._pending.popleft() for _ in range(min(self._batch_size, len(self._pending)))]
        by_tenant: dict[str | None, list[SpilledRecord]] = {}
        for spilled in batch:
            by_tenant.setdefault(spilled.record.tenant_id, []).append(spilled)
        done: list[str] = []
        failed: list[SpilledRecord] = []
        ok = True
        try:
            for tenant_id, group in by_tenant.items():
                ok = await self._replay_group(tenant_id, group, done, failed) and ok
        finally:
            if done:
                finished = set(done)
                self._pending_bytes -= sum(r.size for r in batch if r.id in finished)
                await self._in_replay_pool(spill.mark_done, done)
            for spilled in reversed(failed):
                self._pending.appendleft(spilled)
            if done:
                await self._compact_if_needed(spill)
        return ok

    async def _replay_group(
        self,
        tenant_id: str | None,
        group: Sequence[SpilledRecord],
        done: list[str],
        failed: list[SpilledRecord],
    ) -> bool:
        """One tenant's spilled records into the store, under their ids. A group the store
        refuses is written record by record, so one it refuses costs only itself: after
        ``max_attempts`` of its own it is given up on (marked done, counted as dropped). A record
        of a tenant that has ended, and one whose term has already passed, is skipped."""
        sink: KeyedDecisionRecordSink = self._sink  # type: ignore[assignment]
        if tenant_id is not None and await self._tenant_ended(tenant_id):
            done.extend(s.id for s in group)
            self.ended_skipped += len(group)
            return True
        try:
            stamped = await self._stamp_spilled(tenant_id, group)
            live = self._unexpired(group, stamped, done)
            if live:
                await sink.append_keyed([r for _, r in live], [s.id for s, _ in live])
                done.extend(s.id for s, _ in live)
                self.replayed += len(live)
            return True
        except Exception:
            self.failed_writes += 1
            logger.exception("spilled decision records could not be written; will retry")
        if len(group) == 1:
            self._count_failure(group[0], done, failed)
            return False
        ok = True
        for spilled in group:
            try:
                (stamped_one,) = await self._stamp_spilled(tenant_id, [spilled])
                if self._unexpired([spilled], [stamped_one], done):
                    await sink.append_keyed([stamped_one], [spilled.id])
                    done.append(spilled.id)
                    self.replayed += 1
            except Exception:
                ok = False
                logger.exception("a spilled decision record could not be written")
                self._count_failure(spilled, done, failed)
        return ok

    def _unexpired(
        self,
        group: Sequence[SpilledRecord],
        stamped: Sequence[AuditRecord],
        done: list[str],
    ) -> list[tuple[SpilledRecord, AuditRecord]]:
        """The records of ``group`` whose term hasn't passed; the others are marked done and
        counted: writing them would only be deleted again by the retention job."""
        now = self._wall_clock()
        live = []
        for spilled, record in zip(group, stamped, strict=True):
            if record.retain_until <= now:
                done.append(spilled.id)
                self.expired_skipped += 1
            else:
                live.append((spilled, record))
        return live

    async def _tenant_ended(self, tenant_id: str) -> bool:
        if self._is_ended is None:
            return False
        try:
            return bool(await self._is_ended(tenant_id))
        except Exception:
            logger.exception(
                "whether tenant %s has ended could not be read; its record is kept", tenant_id
            )
            return False

    def _count_failure(
        self, spilled: SpilledRecord, done: list[str], failed: list[SpilledRecord]
    ) -> None:
        attempts = self._replay_attempts.get(spilled.id, 0) + 1
        if attempts >= self._max_attempts:
            self._replay_attempts.pop(spilled.id, None)
            done.append(spilled.id)  # given up on: marked done so it isn't tried for ever
            self.dropped += 1
            logger.error("a spilled decision record was refused %d times; given up on", attempts)
        else:
            self._replay_attempts[spilled.id] = attempts
            failed.append(spilled)

    async def _stamp_spilled(
        self, tenant_id: str | None, group: Sequence[SpilledRecord]
    ) -> list[AuditRecord]:
        return await self._stamp(
            tenant_id, [_Item(s.record, s.requested_days, s.packs) for s in group]
        )

    async def _alert(self) -> None:
        """Raise the dropped-records alert if the count grew, and the spill alert while the file
        is near its cap. Off the check path and off the loop (the sink may be an outbox insert)."""
        if self._watch is None:
            return
        try:
            await asyncio.to_thread(self._watch.tick)
        except Exception:
            logger.exception("the dropped decision records alert could not be raised")
        try:
            await asyncio.to_thread(self._spill_cap_alert)
        except Exception:
            logger.exception("the decision spill alert could not be raised")

    def _spill_cap_alert(self) -> None:
        spill = self._spill
        if spill is None or not spill.max_bytes or self._alerts is None:
            return
        if self._spill_bytes < self._spill_alert_fraction * spill.max_bytes:
            return
        now = self._clock()
        if self._spill_alert_at is not None and now - self._spill_alert_at < self._alert_interval_s:
            return
        self._spill_alert_at = now
        self._alerts.emit(
            Alert(
                severity=AlertSeverity.WARNING,
                kind=ALERT_AUDIT_SPILL_NEAR_CAP,
                message=(
                    "the decision-record spill file is near its size cap; past it, regulated "
                    "tenants' records are dropped. The database is not taking the records, or "
                    "replay is not keeping up."
                ),
                key_id="",
                tenant_id="",
                guard_point="",
            )
        )

    async def _write_once(self) -> bool:
        """Write one batch: tenant group by tenant group, and a record that was in a failed
        group alone. False if any write failed."""
        batch = [self._queue.popleft() for _ in range(min(self._batch_size, len(self._queue)))]
        self._room.set()
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
