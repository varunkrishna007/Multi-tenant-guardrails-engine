"""Routing an ``escalate`` verdict to the tenant's target (M4-05, S1).

The Guard Service hands every ``escalate`` verdict to :meth:`EscalationRouter.submit` after the
audit record is written, and that call is all the check path ever does: a non-blocking put on a
bounded queue. A background task on the service's event loop takes the items off, **off the check
path**, and routes each by the tenant bundle's ``escalation.target``:

* ``queue``: the item (with the post-redaction content held for the reviewer, class D) is stored
  in the tenant's escalation store, and a reviewer lists it through the Admin API.
* ``webhook``: the item is stored too, **so the receiver can resolve it through the API and its
  resolution becomes a label**, and a notice is written to the delivery outbox (kind
  ``escalation``), which the dispatcher posts, signed, with retries and a dead-letter state
  (``escalation/adapters/webhook.py``). The item holds the content only if R3 lets the tenant's
  ``store_content`` hold it (``full``); a webhook tenant on ``hash_only`` gets an item with the
  hash and the rules and no content, and the notice never carries content.

**Never delays or fails a check.** ``submit`` does no I/O. A full queue (the whole queue, or one
tenant's share of it: a tenant that floods escalations cannot crowd out the others), an engine
that is closing, a store that errors or doesn't answer within ``timeout_s`` and an outbox that
fails are all **dropped**: counted (``dropped``, ``dropped_by_reason``), logged by reason only, and
raised as an ``escalation_dropped`` alert per tenant, throttled to one per ``alert_interval_s``
(the next carries the count of those in between). The alert is emitted from a daemon thread of its
own, so a stuck store or a stuck alert sink holds up neither the other nor process exit.
A dropped item is **lost**: the verdict was ``escalate`` and the content was held back by the
caller, but no reviewer will see it. That is why the alert is a page.

A stuck store costs the worker ``timeout_s`` per item; the queue then fills and further items are
dropped at once. The check path is never involved.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import threading
import time
from collections import Counter
from collections.abc import Callable

from guardrail_engine.delivery.events import (
    KIND_ESCALATION,
    EscalationNotice,
    encode_escalation,
)
from guardrail_engine.delivery.outbox import OutboxStore
from guardrail_engine.escalation.model import (
    MAX_CONTENT_CHARS,
    MAX_RULES,
    RETENTION_AFTER_RESOLUTION,
    RETENTION_FROM_CREATION,
    STORE_FULL,
    TARGET_QUEUE,
    TARGET_WEBHOOK,
    EscalationItem,
    EscalationRequest,
    RuleRef,
    item_id_for,
)
from guardrail_engine.escalation.store import EscalationStore, ScopedEscalationStores
from guardrail_engine.gateway.sinks import (
    ALERT_ESCALATION_DROPPED,
    Alert,
    AlertSeverity,
    AlertSink,
)
from guardrail_engine.guard.verdict import Action, Verdict
from guardrail_engine.tenant_scope import TenantScope

logger = logging.getLogger(__name__)

DEFAULT_CAPACITY = 1000
DEFAULT_TIMEOUT_S = 5.0
DEFAULT_ALERT_INTERVAL_S = 60.0

DROP_QUEUE_FULL = "queue_full"
DROP_TENANT_FULL = "tenant_queue_full"
DROP_CLOSED = "closed"
DROP_TIMEOUT = "timeout"
DROP_STORE_ERROR = "store_error"
DROP_WEBHOOK = "webhook_unavailable"
DROP_NO_LOOP = "no_event_loop"


def rules_of(verdict: Verdict) -> tuple[RuleRef, ...]:
    """The rules behind an escalation: those that called for it (key, action, mode, layer), and
    the deterministic rules that escalated. Never a probability."""
    refs: list[RuleRef] = [
        RuleRef(f.key, f.action.value, f.mode, f.layer)
        for f in verdict.fired
        if f.action is Action.ESCALATE
    ]
    refs += [
        RuleRef(h.rule, h.action.value, "enforce", h.layer)
        for h in verdict.deterministic
        if h.action.value == "escalate"
    ]
    return tuple(refs[:MAX_RULES])


def request_from_check(
    scope: TenantScope,
    verdict: Verdict,
    *,
    target: str,
    url: str | None,
    store_content: str,
    content: str | None,
    triggered_by: str | None = None,
    class_d_total: bool = False,
) -> EscalationRequest:
    """The routing request for an ``escalate`` verdict. ``content`` is the **post-redaction**
    text the model saw. It is held only where R3 allows: always for the ``queue`` target (the
    reviewer needs it, class D), and for the ``webhook`` target only when the tenant's
    ``store_content`` is ``full``. ``class_d_total`` is the tenant's R3 class D term, fixed on the
    item now: 30 days from creation (healthcare) or 30 days after resolution."""
    hold = content is not None and (target == TARGET_QUEUE or store_content == STORE_FULL)
    held = content if hold else None
    truncated = held is not None and len(held) > MAX_CONTENT_CHARS
    if held is not None and truncated:
        held = held[:MAX_CONTENT_CHARS]
    item = EscalationItem(
        id=item_id_for(
            scope.tenant_id, verdict.request_id, verdict.guard_point, verdict.content_sha256
        ),
        tenant_id=scope.tenant_id,
        request_id=verdict.request_id,
        guard_point=verdict.guard_point,
        created_at=verdict.checked_at,
        target=target,
        reason=str(verdict.reason.value),
        bundle_version=verdict.bundle_version,
        rules=rules_of(verdict),
        content_sha256=verdict.content_sha256,
        store_content=store_content,
        retention_mode=RETENTION_FROM_CREATION if class_d_total else RETENTION_AFTER_RESOLUTION,
        content=held,
        content_truncated=truncated,
        triggered_by=triggered_by,
    )
    return EscalationRequest(scope=scope, item=item, url=url)


class _Dropped:
    __slots__ = ("count", "guard_point", "reasons")

    def __init__(self) -> None:
        self.count = 0
        self.guard_point = ""
        self.reasons: Counter[str] = Counter()


class EscalationRouter:
    def __init__(
        self,
        store: ScopedEscalationStores,
        *,
        outbox: OutboxStore | None = None,
        alerts: AlertSink | None = None,
        capacity: int = DEFAULT_CAPACITY,
        per_tenant_capacity: int | None = None,
        timeout_s: float = DEFAULT_TIMEOUT_S,
        alert_interval_s: float = DEFAULT_ALERT_INTERVAL_S,
        clock: Callable[[], float] = time.time,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        """``store`` holds the items, ``outbox`` takes the webhook notices (without it a
        ``webhook`` item is stored and counted as dropped, since nothing will notify the
        receiver), ``alerts`` receives ``escalation_dropped`` (hand it a sink that is not behind
        the gateway's queue, such as the durable alert sink). ``capacity`` bounds the whole queue
        and ``per_tenant_capacity`` (default a quarter of it, at least 1) one tenant's share."""
        if capacity < 1 or timeout_s <= 0 or alert_interval_s <= 0:
            raise ValueError("capacity, timeout_s and alert_interval_s must be positive")
        self._store = store
        self._outbox = outbox
        self._alerts = alerts
        self._capacity = capacity
        self._tenant_capacity = (
            max(1, capacity // 4) if per_tenant_capacity is None else per_tenant_capacity
        )
        self._timeout_s = timeout_s
        self._alert_interval_s = alert_interval_s
        self._clock = clock
        self._mono = monotonic
        self._queue: asyncio.Queue[EscalationRequest] = asyncio.Queue()
        self._queued: Counter[str] = Counter()
        self._task: asyncio.Task[None] | None = None
        self._closed = False
        self._lock = threading.Lock()
        self._dropped: dict[str, _Dropped] = {}
        self._last_alert: dict[str, float] = {}
        self._reasons: Counter[str] = Counter()
        self._wake = threading.Event()
        self._alert_thread: threading.Thread | None = None
        self._stop_alerts = False
        self.routed = 0
        """Items stored (and, for a webhook target, queued for delivery)."""
        self.reused_request_ids = 0
        """Items stored for a (tenant, request id, guard point) that already had one: a caller
        reused a request id for different content. Both items are kept (the id includes
        the content hash); this counts the second and later ones."""

    # ------------------------------------------------------------------ check path

    def submit(self, request: EscalationRequest) -> bool:
        """Queue ``request`` for routing. Never blocks, does no I/O and never raises. True if
        queued, False if dropped (counted and alerted)."""
        try:
            return self._submit(request)
        except Exception:
            logger.exception("escalation router: submit failed")
            self._drop(request, DROP_STORE_ERROR)
            return False

    def _submit(self, request: EscalationRequest) -> bool:
        tenant = request.item.tenant_id
        if self._closed:
            self._drop(request, DROP_CLOSED)
            return False
        if self._queue.qsize() >= self._capacity:
            self._drop(request, DROP_QUEUE_FULL)
            return False
        if self._queued[tenant] >= self._tenant_capacity:
            self._drop(request, DROP_TENANT_FULL)
            return False
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            self._drop(request, DROP_NO_LOOP)
            return False
        self._queue.put_nowait(request)
        self._queued[tenant] += 1
        if self._task is None or self._task.done():
            self._task = loop.create_task(self._run(), name="guardrail-escalation-router")
        return True

    # ------------------------------------------------------------------ the worker

    async def _run(self) -> None:
        while True:
            request = await self._queue.get()
            try:
                await asyncio.wait_for(self._route(request), self._timeout_s)
                self.routed += 1
            except TimeoutError:
                self._drop(request, DROP_TIMEOUT)
            except asyncio.CancelledError:
                self._drop(request, DROP_CLOSED)
                raise
            except _WebhookUnavailableError:
                self._drop(request, DROP_WEBHOOK)
            except Exception as exc:
                logger.error("escalation router: could not route an item: %s", type(exc).__name__)
                self._drop(request, DROP_STORE_ERROR)
            finally:
                self._release(request)
                self._queue.task_done()

    def _release(self, request: EscalationRequest) -> None:
        tenant = request.item.tenant_id
        self._queued[tenant] -= 1
        if self._queued[tenant] <= 0:
            del self._queued[tenant]

    async def _route(self, request: EscalationRequest) -> None:
        item = request.item
        store = self._store.scoped(request.scope)
        if await store.insert(item):
            await self._note_reuse(store, item)
        if item.target != TARGET_WEBHOOK:
            return
        if self._outbox is None or not request.url:
            raise _WebhookUnavailableError()
        notice = EscalationNotice(
            item_id=item.id,
            tenant_id=item.tenant_id,
            guard_point=item.guard_point,
            reason=item.reason,
            created_at=item.created_at.timestamp(),
            url=request.url,
            content_sha256=item.content_sha256,
            bundle_version=item.bundle_version,
            rules=tuple((r.key, r.action, r.mode) for r in item.rules),
            content_available=item.content_held,
        )
        # The outbox is synchronous (it may wait on a database): off the loop, so a slow one
        # costs this worker its timeout, not the event loop.
        await asyncio.to_thread(
            self._outbox.enqueue, KIND_ESCALATION, encode_escalation(notice), item.id, self._clock()
        )

    async def _note_reuse(self, store: EscalationStore, item: EscalationItem) -> None:
        """A request id the tenant's caller supplies can be reused. The id of an item
        includes its content hash, so a second item with other content is stored and not lost;
        count it and say so at warning level (never the id or the content). A failure here never
        costs the item."""
        try:
            held = await store.same_check_count(item.tenant_id, item.request_id, item.guard_point)
        except Exception as exc:
            logger.error("escalation router: reuse check failed: %s", type(exc).__name__)
            return
        if held > 1:
            self.reused_request_ids += 1
            logger.warning(
                "escalation router: a second escalation item for a request id that already has "
                "one at the same guard point (tenant %s, guard point %s): the caller reused a "
                "request id for different content",
                item.tenant_id,
                item.guard_point,
            )

    # ------------------------------------------------------------------ drops and alerts

    @property
    def dropped(self) -> int:
        with self._lock:
            return sum(self._reasons.values())

    @property
    def dropped_by_reason(self) -> dict[str, int]:
        with self._lock:
            return dict(self._reasons)

    @property
    def queued(self) -> int:
        return self._queue.qsize()

    def _drop(self, request: EscalationRequest, reason: str) -> None:
        tenant = request.item.tenant_id
        logger.warning("escalation router: an item was dropped (%s)", reason)
        with self._lock:
            self._reasons[reason] += 1
            entry = self._dropped.setdefault(tenant, _Dropped())
            entry.count += 1
            entry.guard_point = request.item.guard_point
            entry.reasons[reason] += 1
        if self._alerts is not None:
            self._start_alert_thread()
            self._wake.set()

    def _start_alert_thread(self) -> None:
        with self._lock:
            if self._alert_thread is not None:
                return
            self._alert_thread = threading.Thread(
                target=self._alert_loop, name="guardrail-escalation-alerts", daemon=True
            )
            self._alert_thread.start()

    def _alert_loop(self) -> None:
        while not self._stop_alerts:
            self._wake.wait(self._alert_interval_s)
            self._wake.clear()
            try:
                self.flush_alerts()
            except Exception:
                logger.exception("escalation router: alert flush failed")

    def flush_alerts(self, *, force: bool = False) -> int:
        """Emit the pending ``escalation_dropped`` alerts that are due (one per tenant per
        ``alert_interval_s``; ``force`` ignores the interval). Returns how many were emitted. Runs
        in the alert thread; public for tests and for a final flush at close."""
        if self._alerts is None:
            return 0
        now = self._mono()
        due: list[tuple[str, _Dropped]] = []
        with self._lock:
            for tenant, entry in list(self._dropped.items()):
                last = self._last_alert.get(tenant)
                if force or last is None or now - last >= self._alert_interval_s:
                    due.append((tenant, entry))
                    del self._dropped[tenant]
                    self._last_alert[tenant] = now
        sent = 0
        for tenant, entry in due:
            reason = entry.reasons.most_common(1)[0][0]
            try:
                self._alerts.emit(
                    Alert(
                        severity=AlertSeverity.PAGE,
                        kind=ALERT_ESCALATION_DROPPED,
                        message=(
                            "escalation items were dropped and will not reach a reviewer or "
                            "the tenant's webhook"
                        ),
                        key_id="",
                        tenant_id=tenant,
                        guard_point=entry.guard_point,
                        reason=reason,
                        count=entry.count,
                    )
                )
                sent += 1
            except Exception:
                logger.error("escalation router: the dropped-items alert could not be sent")
        return sent

    # ------------------------------------------------------------------ shutdown

    async def drain(self, timeout: float = 5.0) -> bool:
        """Wait until the queue is empty and the worker idle. True if it is."""
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(self._queue.join(), timeout)
        return self._queue.empty() and not self._queued

    async def aclose(self, timeout: float = 5.0) -> None:
        """Stop taking items, give the worker ``timeout`` seconds to finish the queue, count
        what is left as dropped (``closed``), send the pending alerts and stop."""
        self._closed = True
        await self.drain(timeout)
        task = self._task
        if task is not None and not task.done():
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task
        while not self._queue.empty():
            request = self._queue.get_nowait()
            self._drop(request, DROP_CLOSED)
            self._release(request)
        self._stop_alerts = True
        self._wake.set()
        thread = self._alert_thread
        if thread is not None:
            await asyncio.to_thread(thread.join, timeout)
        await asyncio.to_thread(self.flush_alerts, force=True)


class _WebhookUnavailableError(Exception):
    """The item is stored, but there is nothing to notify the webhook with."""


__all__ = ["DEFAULT_CAPACITY", "EscalationRouter", "request_from_check", "rules_of"]
