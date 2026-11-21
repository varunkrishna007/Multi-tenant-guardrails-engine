"""The write-behind writer of stored content (M5-03, R3 class C).

:class:`StoredContentWriter` is to class C what the decision-record writer is to class B
(:mod:`guardrail_engine.audit.writer`). ``submit`` runs on the check path and only puts a small
object on a **bounded queue**: it never waits for the database, never raises, does no I/O. A
background task drains the queue in batches, works out each row's term (**again, at write time**,
:mod:`guardrail_engine.content.term`), stamps its deletion time and writes it.

* **What is stored.** Exactly the text the Guard Service handed over: the post-redaction content
  the model saw (and nothing else: no context, no conversation, no tool arguments), cut to
  :data:`~guardrail_engine.content.model.MAX_STORED_CHARS` characters. The writer never sees the
  raw content.
* **Not stored on purpose.** A tenant that may not store content now (no BAA, a pack the catalog
  lacks, not in the directory) gets no row. That is counted by reason (``skipped``) and is **not**
  a drop and raises no alert: it is the rule working.
* **Full queue.** A request that finds the queue full is **dropped and counted** (``dropped``);
  nothing waits. Given ``alerts``, the writer's own task raises ``stored_content_dropped``
  (:class:`~guardrail_engine.monitoring.dropped.DroppedStoredContentWatch`, at most one a minute)
  when the count grows. Rows the database refused ``max_attempts`` times, and rows still queued
  when ``aclose`` runs out of time, count too.
* **A failing database.** A tenant group that can't be written goes back to the front of the
  queue and is tried again after a pause that doubles up to ``retry_cap_s``; a group that failed
  is split, so one row the database refuses costs only itself.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from collections import Counter, deque
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta

from guardrail_engine.content.model import MAX_STORED_CHARS, StoredContent
from guardrail_engine.content.store import ContentSink
from guardrail_engine.content.term import ContentTerm, ContentTermResolver
from guardrail_engine.gateway.sinks import AlertSink
from guardrail_engine.monitoring.dropped import DroppedStoredContentWatch

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class ContentRequest:
    """What the check path hands over. ``content`` is **post-redaction**."""

    tenant_id: str
    request_id: str
    guard_point: str
    ts: datetime
    content: str
    content_sha256: str
    bundle_version: int | None
    requested_days: int | None
    """The bundle's ``audit.content_days`` as compiled; not what is written."""
    packs: tuple[str, ...] = ()
    """The packs the deciding version extends, to take the cap from."""
    attempts: int = 0
    solo: bool = False


class StoredContentWriter:
    def __init__(
        self,
        sink: ContentSink,
        terms: ContentTermResolver,
        *,
        capacity: int = 10_000,
        batch_size: int = 100,
        flush_interval_s: float = 0.5,
        term_ttl_s: float = 300.0,
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
        self._term_ttl_s = term_ttl_s
        self._max_attempts = max_attempts
        self._retry_base_s = retry_base_s
        self._retry_cap_s = retry_cap_s
        self._clock = clock
        self._watch = (
            None
            if alerts is None
            else DroppedStoredContentWatch(
                lambda: self.dropped, alerts, min_interval_s=alert_interval_s, clock=clock
            )
        )
        self._queue: deque[ContentRequest] = deque()
        self._terms: dict[tuple[str, int | None, tuple[str, ...]], tuple[ContentTerm, float]] = {}
        self._wake = asyncio.Event()
        self._task: asyncio.Task[None] | None = None
        self._closing = False
        self._failures = 0
        self.dropped = 0
        """Rows lost: queue full, refused too often, or still queued at shutdown."""
        self.written = 0
        self.failed_writes = 0
        self.skipped: Counter[str] = Counter()
        """Requests not stored because the tenant may not store content now, by reason."""

    # ------------------------------------------------------------------ the check path

    def submit(self, request: ContentRequest) -> None:
        """Queue the check's content. Never blocks, never raises."""
        try:
            if self._closing or len(self._queue) >= self._capacity:
                self.dropped += 1
                return
            self._queue.append(request)
            if len(self._queue) >= self._batch_size:
                self._wake.set()
        except Exception:
            self.dropped += 1
            logger.exception("stored content could not be queued")

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
            logger.error("%d stored-content rows were not written at shutdown", len(self._queue))
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
        if self._watch is None:
            return
        try:
            await asyncio.to_thread(self._watch.tick)
        except Exception:
            logger.exception("the dropped stored-content alert could not be raised")

    async def _write_once(self) -> bool:
        """One batch, tenant group by tenant group (a request that was in a failed group alone).
        False if any write failed."""
        batch = [self._queue.popleft() for _ in range(min(self._batch_size, len(self._queue)))]
        by_tenant: dict[str, list[ContentRequest]] = {}
        groups: list[tuple[str, list[ContentRequest]]] = []
        for item in batch:
            if item.solo:
                groups.append((item.tenant_id, [item]))
            else:
                by_tenant.setdefault(item.tenant_id, []).append(item)
        groups += list(by_tenant.items())
        ok = True
        for _tenant, items in groups:
            try:
                rows = await self._stamp(items)
                if rows:
                    await self._sink.append_many(rows)
                self.written += len(rows)
            except asyncio.CancelledError:
                self.dropped += len(items)
                logger.error(
                    "%d stored-content rows were being written at shutdown; "
                    "they may or may not have been",
                    len(items),
                )
                raise
            except Exception:
                ok = False
                self.failed_writes += 1
                logger.exception("stored content could not be written; will retry")
                self._requeue(items)
        return ok

    def _requeue(self, items: Sequence[ContentRequest]) -> None:
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

    async def _stamp(self, items: Sequence[ContentRequest]) -> list[StoredContent]:
        rows = []
        for item in items:
            term = await self._term(item)
            if term.days is None:
                self.skipped[term.reason] += 1
                continue
            text = item.content[:MAX_STORED_CHARS]
            rows.append(
                StoredContent(
                    tenant_id=item.tenant_id,
                    request_id=item.request_id,
                    guard_point=item.guard_point,
                    ts=item.ts,
                    retain_until=item.ts + timedelta(days=term.days),
                    content=text,
                    truncated=len(text) < len(item.content),
                    content_sha256=item.content_sha256,
                    bundle_version=item.bundle_version,
                )
            )
        return rows

    async def _term(self, item: ContentRequest) -> ContentTerm:
        now = self._clock()
        key = (item.tenant_id, item.requested_days, item.packs)
        cached = self._terms.get(key)
        if cached is not None and now - cached[1] < self._term_ttl_s:
            return cached[0]
        term = await self._terms_source.term(item.tenant_id, item.requested_days, item.packs)
        self._terms[key] = (term, now)
        if len(self._terms) > 10_000:
            self._terms.pop(next(iter(self._terms)))
        return term
