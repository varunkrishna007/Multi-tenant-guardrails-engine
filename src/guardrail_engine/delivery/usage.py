"""The usage store port and the meter that turns the gateway's metering calls into records
(M4-04)."""

from __future__ import annotations

import copy
import threading
import time
from collections.abc import Callable
from typing import Protocol

from guardrail_engine.delivery.events import (
    USAGE_ANSWERED,
    USAGE_MODEL_SKIPPED,
    USAGE_PATTERNS_DROPPED,
    USAGE_PROVIDER_SAFETY,
    USAGE_UNANSWERED,
    USAGE_UNKNOWN,
    UsageEvent,
)
from guardrail_engine.projects import is_valid_project_label


class UsageStore(Protocol):
    def write(self, event: UsageEvent, key: str) -> None:
        """Store one usage record. **Idempotent on ``key``**: a second write with the same
        key changes nothing (delivery is at least once). Raises if it could not be stored."""
        ...


class InMemoryUsageStore:
    """Keeps records by idempotency key, for tests."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.records: dict[str, UsageEvent] = {}
        self.writes = 0
        """Every call to ``write``, duplicates included."""

    def write(self, event: UsageEvent, key: str) -> None:
        with self._lock:
            self.writes += 1
            self.records.setdefault(key, event)

    offboard_tables = ("usage_events",)

    def offboard_tenant(
        self, tenant_id: str, table: str, limit: int, *, count_only: bool = False
    ) -> dict[str, int]:
        """M5-07: delete (or count) a terminated tenant's rows (see ``TenantDataHolder``)."""
        if count_only:
            with self._lock:
                return {table: sum(1 for e in self.records.values() if e.tenant_id == tenant_id)}
        return {table: len(self.offboard_usage_rows(tenant_id, limit))}

    def offboard_usage_rows(self, tenant_id: str, limit: int) -> list[UsageEvent]:
        """M5-07: delete at most ``limit`` of the tenant's rows and return them, so the
        offboarding store can write the billing summary of exactly what was deleted."""
        with self._lock:
            mine = [k for k, e in self.records.items() if e.tenant_id == tenant_id][:limit]
            return [self.records.pop(k) for k in mine]

    def tokens(self, tenant_id: str, guard_point: str) -> int:
        with self._lock:
            return sum(
                e.input_tokens or 0
                for e in self.records.values()
                if e.kind == USAGE_ANSWERED
                and e.tenant_id == tenant_id
                and e.guard_point == guard_point
            )


class UsageRecorder:
    """The gateway's usage meter port (``UsageMeter`` and three of its optional companions):
    each call becomes a :class:`UsageEvent` handed to ``_submit``. Subclasses decide where it
    goes: into the outbox (:class:`~guardrail_engine.delivery.durable.DurableUsageMeter`) or
    straight into a store.

    The other optional meters (timing, token-rate, quota and unrecognised-code counters) are
    not implemented here: a gateway given this meter does not call them. Those are
    high-volume operational counters, not usage that bills."""

    def __init__(self, clock: Callable[[], float] = time.time) -> None:
        self._usage_clock = clock
        self._project = ""

    def with_project(self, project: str) -> UsageRecorder:
        """The same recorder, going to the same place, whose every record carries the label of
        the dedicated Gemini project ``project`` (M5-06): the meter of that project's gateway.
        A copy: this recorder, the shared pool's, keeps recording ``""``."""
        if not is_valid_project_label(project):
            raise ValueError("a project must be a project label")
        view = copy.copy(self)
        view._project = project
        return view

    def _submit(self, event: UsageEvent) -> None:
        raise NotImplementedError

    def _event(
        self, kind: str, tenant_id: str, guard_point: str, tokens: int | None = None
    ) -> UsageEvent:
        return UsageEvent(kind, tenant_id, guard_point, tokens, self._usage_clock(), self._project)

    def record(self, tenant_id: str, guard_point: str, input_tokens: int | None) -> None:
        kind = USAGE_UNKNOWN if input_tokens is None else USAGE_ANSWERED
        self._submit(self._event(kind, tenant_id, guard_point, input_tokens))

    def record_unanswered(self, tenant_id: str, guard_point: str) -> None:
        self._submit(self._event(USAGE_UNANSWERED, tenant_id, guard_point))

    def record_provider_safety(self, tenant_id: str, guard_point: str) -> None:
        self._submit(self._event(USAGE_PROVIDER_SAFETY, tenant_id, guard_point))

    def record_model_skipped(self, tenant_id: str, guard_point: str) -> None:
        self._submit(self._event(USAGE_MODEL_SKIPPED, tenant_id, guard_point))

    def record_identifier_patterns_dropped(self, tenant_id: str) -> None:
        self._submit(self._event(USAGE_PATTERNS_DROPPED, tenant_id, ""))
