"""M5-03 the write-behind writer of stored content, the in-memory store and the class C job.
The same shape as M4-07's writer tests: the check path never waits, drops are counted and
alerted, a failing database costs only what it must."""

import asyncio
import logging
from datetime import UTC, datetime, timedelta

import pytest

from guardrail_engine.content import (
    ClassCJob,
    ContentRequest,
    ContentTerm,
    InMemoryStoredContent,
    StoredContentWriter,
)
from guardrail_engine.content.model import MAX_STORED_CHARS, StoredContent
from guardrail_engine.gateway.sinks import ALERT_STORED_CONTENT_DROPPED, RecordingAlertSink
from guardrail_engine.retention.store import RetentionError
from guardrail_engine.tenant_scope import issue_scope

NOW = datetime(2026, 11, 20, 12, 0, tzinfo=UTC)
ACME, OTHER = "t_acmeins", "t_otherco"
SHA = "sha256:" + "ab" * 32


class Terms:
    """The class C term source: fixed days, or 'do not store' for chosen tenants."""

    def __init__(self, days=30, refuse=()):
        self.days, self.refuse, self.calls = days, set(refuse), []

    async def term(self, tenant_id, requested_days, packs=()):
        self.calls.append((tenant_id, requested_days, tuple(packs)))
        if tenant_id in self.refuse:
            return ContentTerm(None, "baa_missing")
        return ContentTerm(self.days, "bundle")


def request(tenant=ACME, request_id="req-1", content="hello", ts=NOW, **kw):
    return ContentRequest(
        tenant_id=tenant, request_id=request_id, guard_point="output", ts=ts, content=content,
        content_sha256=SHA, bundle_version=1, requested_days=kw.pop("requested_days", 30), **kw,
    )  # fmt: skip


def writer_of(sink, terms=None, **kw):
    return StoredContentWriter(sink, terms or Terms(), flush_interval_s=0.01, **kw)


async def read(sink, tenant=ACME, request_id="req-1", now=NOW):
    sink._clock = lambda: now
    return await sink.get(issue_scope(tenant), request_id, None)


# ------------------------------------------------------------------ the writer


async def test_a_request_is_queued_without_waiting_and_written_behind():
    sink = InMemoryStoredContent(lambda: NOW)
    w = writer_of(sink)
    w.submit(request())
    assert w.queued == 1 and sink.all() == []  # nothing waited for the store
    await w.flush()
    (row,) = sink.all()
    assert (row.tenant_id, row.content, row.truncated, row.content_sha256) == (
        ACME,
        "hello",
        False,
        SHA,
    )
    assert row.retain_until == NOW + timedelta(days=30) and w.written == 1 and w.dropped == 0


async def test_the_term_is_worked_out_when_it_is_written_not_taken_from_the_request():
    sink = InMemoryStoredContent(lambda: NOW)
    terms = Terms(days=12)
    w = writer_of(sink, terms)
    w.submit(request(requested_days=90, packs=("domain/healthcare@1",)))
    await w.flush()
    assert sink.all()[0].retain_until == NOW + timedelta(days=12)
    assert terms.calls == [(ACME, 90, ("domain/healthcare@1",))]


async def test_content_that_may_not_be_stored_now_is_counted_as_skipped_not_dropped():
    alerts = RecordingAlertSink()
    sink = InMemoryStoredContent(lambda: NOW)
    w = writer_of(sink, Terms(refuse={OTHER}), alerts=alerts, alert_interval_s=0)
    w.submit(request(tenant=OTHER))
    w.submit(request(tenant=ACME, request_id="r2"))
    await w.flush()
    await w.aclose()
    assert [r.tenant_id for r in sink.all()] == [ACME]
    assert w.skipped == {"baa_missing": 1} and w.dropped == 0 and alerts.alerts == []


async def test_long_content_is_cut_and_flagged():
    sink = InMemoryStoredContent(lambda: NOW)
    w = writer_of(sink)
    w.submit(request(content="x" * (MAX_STORED_CHARS + 5)))
    await w.flush()
    row = sink.all()[0]
    assert len(row.content) == MAX_STORED_CHARS and row.truncated is True


async def test_a_full_queue_drops_counts_and_alerts_without_waiting():
    alerts = RecordingAlertSink()
    sink = InMemoryStoredContent(lambda: NOW)
    w = writer_of(sink, capacity=2, alerts=alerts, alert_interval_s=0)
    for i in range(5):
        w.submit(request(request_id=f"r{i}"))
    assert w.queued == 2 and w.dropped == 3
    await w.aclose()
    assert [a.kind for a in alerts.alerts] == [ALERT_STORED_CONTENT_DROPPED]
    assert alerts.alerts[0].count == 3
    assert len(sink.all()) == 2  # what was queued was written at close


async def test_the_background_task_drains_the_queue():
    sink = InMemoryStoredContent(lambda: NOW)
    w = writer_of(sink)
    w.start()
    for i in range(5):
        w.submit(request(request_id=f"r{i}"))
    for _ in range(100):
        if len(sink.all()) == 5:
            break
        await asyncio.sleep(0.01)
    await w.aclose()
    assert len(sink.all()) == 5 and w.dropped == 0


class Poison(InMemoryStoredContent):
    """Refuses any batch that holds the poisoned row, and that row alone."""

    async def append_many(self, items):
        if any(i.request_id == "poison" for i in items):
            raise RuntimeError("the database refused it")
        await super().append_many(items)


async def test_one_row_the_database_refuses_costs_only_itself(caplog):
    sink = Poison(lambda: NOW)
    w = writer_of(sink, max_attempts=2, retry_base_s=0.0)
    for rid in ("a", "poison", "b"):
        w.submit(request(request_id=rid))
    with caplog.at_level(logging.ERROR):
        for _ in range(6):
            await w.flush()
    assert sorted(r.request_id for r in sink.all()) == ["a", "b"]
    assert w.dropped == 1 and w.failed_writes >= 1


async def test_a_sink_that_fails_forever_drops_after_the_attempts_and_alerts():
    class Down(InMemoryStoredContent):
        async def append_many(self, items):
            raise ConnectionError("down")

    alerts = RecordingAlertSink()
    w = writer_of(Down(), max_attempts=2, alerts=alerts, alert_interval_s=0)
    w.submit(request())
    for _ in range(4):
        await w.flush()
    await w.aclose()
    assert w.dropped == 1 and w.written == 0
    assert [a.kind for a in alerts.alerts] == [ALERT_STORED_CONTENT_DROPPED]


async def test_submit_after_close_is_dropped_and_never_raises():
    w = writer_of(InMemoryStoredContent(lambda: NOW))
    await w.aclose()
    w.submit(request())
    assert w.dropped == 1


async def test_what_is_still_queued_when_close_runs_out_of_time_is_counted():
    class Stuck(InMemoryStoredContent):
        async def append_many(self, items):
            await asyncio.sleep(10)

    w = writer_of(Stuck(), batch_size=1)
    for i in range(3):
        w.submit(request(request_id=f"r{i}"))
    await w.aclose(timeout_s=0.2)
    assert w.dropped == 3 and w.queued == 0


# ------------------------------------------------------------------ the read port


async def test_a_read_returns_only_the_scopes_tenant_and_only_unexpired_rows():
    sink = InMemoryStoredContent(lambda: NOW)
    w = writer_of(sink, Terms(days=30))
    w.submit(request(tenant=ACME, content="mine"))
    w.submit(request(tenant=OTHER, content="theirs"))
    await w.flush()
    assert [r.content for r in await read(sink, ACME)] == ["mine"]
    assert [r.content for r in await read(sink, OTHER)] == ["theirs"]
    assert await read(sink, ACME, request_id="nope") == []
    at_term = NOW + timedelta(days=30)
    assert len(await read(sink, ACME, now=at_term - timedelta(seconds=1))) == 1
    assert (
        await read(sink, ACME, now=at_term + timedelta(seconds=1)) == []
    )  # expired, not yet deleted


# ------------------------------------------------------------------ the class C job


def job_of(sink, now, **kw):
    return ClassCJob(sink.retention, clock=lambda: now, run_id_factory=lambda: "run1", **kw)


async def stored(days_by_request, tenant=ACME):
    sink = InMemoryStoredContent(lambda: NOW)
    for rid, days in days_by_request.items():
        w = writer_of(sink, Terms(days=days))
        w.submit(request(tenant=tenant, request_id=rid))
        await w.flush()
    return sink


async def test_a_row_goes_after_its_own_term_strictly_and_a_receipt_says_so():
    sink = await stored({"short": 10, "long": 30})
    report = await job_of(
        sink, NOW + timedelta(days=10)
    ).run_once()  # exactly at the short row's end
    assert report.deleted == 0  # strict: at the cutoff is kept
    report = await job_of(sink, NOW + timedelta(days=10, seconds=1)).run_once()
    assert report.deleted == 1 and [r.request_id for r in sink.all()] == ["long"]
    report = await job_of(sink, NOW + timedelta(days=31)).run_once()
    assert report.deleted == 1 and sink.all() == []
    receipts = await sink.retention.receipts("run1")
    assert {r.retention_class for r in receipts} == {"C"} and {r.source for r in receipts} == {
        "row"
    }
    assert all("content" not in r.__slots__ for r in receipts)  # counts, a cutoff, a run id only


async def test_nothing_is_kept_past_ninety_days_whatever_its_own_time_says():
    sink = InMemoryStoredContent(lambda: NOW)
    await sink.append_many(
        [StoredContent(ACME, "old", "output", NOW, NOW + timedelta(days=400), "x", False, SHA, 1)]
    )
    assert (await job_of(sink, NOW + timedelta(days=90, seconds=1)).run_once()).deleted == 1


async def test_the_job_takes_bounded_batches_and_continues_next_run():
    sink = await stored({f"r{i}": 10 for i in range(5)})
    later = NOW + timedelta(days=11)
    first = await job_of(sink, later, batch_size=2, max_batches_per_tenant=2).run_once()
    assert first.deleted == 4 and first.sweeps[0].more_to_do is True
    second = await job_of(sink, later, batch_size=2, max_batches_per_tenant=2).run_once()
    assert second.deleted == 1 and sink.all() == []


async def test_a_batch_size_out_of_bounds_is_refused_by_the_store():
    sink = InMemoryStoredContent(lambda: NOW)
    with pytest.raises(RetentionError):
        await sink.retention.delete_class_c_batch(
            run_id="r", tenant_id=ACME, now=NOW, limit=0, batch=1
        )
    with pytest.raises(ValueError):
        ClassCJob(sink.retention, clock=lambda: NOW, batch_size=0)


async def test_each_tenant_is_swept_alone_and_a_failing_tenant_does_not_stop_the_others():
    sink = InMemoryStoredContent(lambda: NOW)
    for tenant in (ACME, OTHER):
        w = writer_of(sink, Terms(days=10))
        w.submit(request(tenant=tenant))
        await w.flush()
    real = sink.retention.delete_class_c_batch

    async def flaky(*, tenant_id, **kw):
        if tenant_id == ACME:
            raise RuntimeError("boom")
        return await real(tenant_id=tenant_id, **kw)

    sink.retention.delete_class_c_batch = flaky  # type: ignore[method-assign]
    report = await job_of(sink, NOW + timedelta(days=11)).run_once()
    assert report.failed == (ACME,) and report.deleted == 1
    assert [r.tenant_id for r in sink.all()] == [ACME]
