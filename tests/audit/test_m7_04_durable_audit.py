"""M7-04 durable audit for regulated tenants: a full queue makes the check wait a short time and
then spill the record to a local file, instead of dropping it; the writer replays the file into
the store, once, and a standard tenant's record is still dropped and counted."""

import asyncio
import json
import os
import threading
import time
from datetime import UTC, datetime

import pytest
from audit_records import ACME, NOW, OTHER, make_record

from guardrail_engine.audit.spill import SPILL_FILE_NAME, spill_file_beside
from guardrail_engine.audit.store import InMemoryDecisionRecords
from guardrail_engine.audit.term import directory_regulated
from guardrail_engine.audit.writer import DecisionRecordWriter
from guardrail_engine.engine import ClassAAuditFileError
from guardrail_engine.engine.bootstrap import decision_spill_at, decision_spill_beside
from guardrail_engine.gateway.sinks import (
    ALERT_AUDIT_RECORDS_DROPPED,
    ALERT_AUDIT_SPILL_NEAR_CAP,
    RecordingAlertSink,
)
from guardrail_engine.guard.audit import AuditRecord
from guardrail_engine.guard.verdict import Decision, Reason, Verdict
from guardrail_engine.retention.resolver import TenantRetention

REGULATED = ACME
STANDARD = OTHER


class FixedTerm:
    async def term(self, tenant_id, requested_days, packs=()):
        return TenantRetention(395, "bundle")


async def regulated_if_acme(tenant_id: str) -> bool:
    return tenant_id == REGULATED


def verdict_of(tenant=REGULATED, *, request_id=None) -> Verdict:
    record = make_record(tenant, NOW, request_id=request_id)
    return Verdict(
        request_id=record.request_id, tenant_id=tenant, guard_point=record.guard_point,
        decision=Decision.ALLOW, reason=Reason.POLICY, checked_at=NOW, latency_ms=1.0,
        bundle_version=1, rules=record.rules, retention_days=395,
    )  # fmt: skip


@pytest.fixture
def audit_dir(tmp_path):
    d = tmp_path / "audit"
    d.mkdir(mode=0o700)
    d.chmod(0o700)
    return d


@pytest.fixture
def spill(audit_dir):
    return decision_spill_beside(audit_dir / "class_a.jsonl")


@pytest.fixture
def sink():
    return InMemoryDecisionRecords()


def writer_of(sink, spill, **kw):
    kw.setdefault("capacity", 2)
    kw.setdefault("regulated_wait_s", 0.02)
    return DecisionRecordWriter(
        sink,
        FixedTerm(),
        flush_interval_s=0.01,
        spill=spill,
        is_regulated=regulated_if_acme,
        **kw,
    )


async def fill_and_overflow(w, tenant, overflow):
    """Fill the queue (no drain is running), then offer ``overflow`` more records."""
    for _ in range(2):
        await w.arecord(verdict_of(tenant))
    for _ in range(overflow):
        await w.arecord(verdict_of(tenant))


def ids_in_store(sink):
    return sorted(r.request_id for r in sink.all())


# ------------------------------------------------------------------------ a full queue


async def test_no_regulated_record_is_dropped_under_a_full_queue(sink, spill):
    w = writer_of(sink, spill)
    verdicts = [verdict_of() for _ in range(12)]
    for v in verdicts:
        await w.arecord(v)
    assert (w.queued, w.spilled, w.dropped) == (2, 10, 0)
    w.start()
    for _ in range(200):
        if len(sink.all()) == 12 and not spill.path.exists():
            break
        await asyncio.sleep(0.02)
    await w.aclose()
    assert ids_in_store(sink) == sorted(v.request_id for v in verdicts)
    assert w.dropped == 0 and w.replayed == 10


async def test_a_standard_tenants_record_is_still_dropped_and_counted(sink, spill):
    w = writer_of(sink, spill)
    await fill_and_overflow(w, STANDARD, 5)
    assert (w.queued, w.spilled, w.dropped) == (2, 0, 5)
    assert not spill.path.exists()  # nothing was written for it


async def test_a_standard_tenants_overflow_does_not_wait(sink, spill):
    w = writer_of(sink, spill, regulated_wait_s=5.0)
    await fill_and_overflow(w, STANDARD, 1)
    # no wait of 5 s: the test would not have reached here, and the record is dropped
    assert w.dropped == 1


async def test_the_dropped_alert_is_still_raised_for_a_standard_tenant(sink, spill):
    alerts = RecordingAlertSink()
    w = writer_of(sink, spill, capacity=1, alerts=alerts, alert_interval_s=0.0)
    w.start()
    for _ in range(6):
        await w.arecord(verdict_of(STANDARD))
    for _ in range(100):
        if alerts.alerts:
            break
        await asyncio.sleep(0.02)
    await w.aclose()
    assert alerts.alerts and alerts.alerts[0].kind == ALERT_AUDIT_RECORDS_DROPPED
    assert sum(a.count for a in alerts.alerts) == w.dropped >= 1


async def test_the_check_waits_for_room_up_to_the_bound_and_keeps_the_record_queued(sink, spill):
    w = writer_of(sink, spill, regulated_wait_s=2.0)
    w.start()
    for _ in range(2):
        await w.arecord(verdict_of())
    for _ in range(20):
        await w.arecord(verdict_of())  # room comes as the drain works: no spill needed
    await w.flush()
    await w.aclose()
    assert w.dropped == 0 and len(sink.all()) == 22 - w.spilled


async def test_the_wait_is_bounded(sink, spill):
    w = writer_of(sink, spill, regulated_wait_s=0.1)
    await fill_and_overflow(w, REGULATED, 0)
    loop = asyncio.get_running_loop()
    started = loop.time()
    await w.arecord(verdict_of())
    waited = loop.time() - started
    assert 0.05 <= waited < 1.0 and w.spilled == 1


async def test_what_is_spilled_is_the_audit_record_and_nothing_else(sink, spill):
    w = writer_of(sink, spill)
    await fill_and_overflow(w, REGULATED, 0)
    spilled = verdict_of()
    await w.arecord(spilled)
    lines = [json.loads(x) for x in spill.path.read_text().splitlines()]
    (line,) = [x for x in lines if x["k"] == "spill"]
    assert set(line) == {"k", "id", "requested_days", "packs", "record"}
    assert line["record"] == json.loads(AuditRecord.from_verdict(spilled).model_dump_json())
    assert line["requested_days"] == 395


# ------------------------------------------------------------------------ replay


async def test_spilled_records_are_replayed_when_there_is_room_again(sink, spill):
    w = writer_of(sink, spill)
    vs = [verdict_of() for _ in range(6)]
    for v in vs:
        await w.arecord(v)
    assert w.spilled == 4
    await w.flush()  # the queue has room again
    await w.replay()
    assert ids_in_store(sink) == sorted(v.request_id for v in vs)
    assert w.replayed == 4 and not spill.path.exists()  # every line done: the file is deleted


async def test_the_retention_time_is_stamped_when_a_record_is_replayed(sink, spill):
    w = writer_of(sink, spill)
    await fill_and_overflow(w, REGULATED, 1)
    await w.flush()
    await w.replay()
    assert {(r.retain_until - r.ts).days for r in sink.all()} == {395}


async def test_spilled_records_are_replayed_after_a_restart(sink, spill):
    first = writer_of(sink, spill)
    vs = [verdict_of() for _ in range(5)]
    for v in vs:
        await first.arecord(v)  # 2 queued, 3 spilled
    assert first.spilled == 3
    # the process dies: the queued two are lost with it (the standard guarantee), the file stays
    second = writer_of(sink, decision_spill_beside(spill.path.parent / "class_a.jsonl"))
    second.start()
    for _ in range(200):
        if len(sink.all()) == 3 and not spill.path.exists():
            break
        await asyncio.sleep(0.02)
    await second.aclose()
    spilled_ids = {v.request_id for v in vs[2:]}
    assert set(ids_in_store(sink)) == spilled_ids and second.replayed == 3


async def test_a_crash_between_the_store_and_the_done_mark_does_not_duplicate(
    sink, spill, monkeypatch
):
    w = writer_of(sink, spill)
    vs = [verdict_of() for _ in range(5)]
    for v in vs:
        await w.arecord(v)
    marks = []

    def crash(ids):
        marks.append(list(ids))
        raise OSError("the process died before the mark")

    monkeypatch.setattr(spill, "mark_done", crash)
    await w.flush()
    await w.replay()  # the store has the three records; the file does not know
    assert len(sink.all()) == 2 + 3 and marks
    monkeypatch.undo()
    again = writer_of(sink, decision_spill_beside(spill.path.parent / "class_a.jsonl"))
    await again.replay()  # replays the same three under the same ids
    assert len(sink.all()) == 5
    assert ids_in_store(sink) == sorted(v.request_id for v in vs)
    assert not spill.path.exists()


async def test_a_record_the_store_refuses_does_not_hold_up_the_others(sink, spill):
    w = writer_of(sink, spill, max_attempts=2)
    poison = verdict_of(request_id="poison")
    others = [verdict_of() for _ in range(3)]
    for v in [verdict_of(), verdict_of(), poison, *others]:
        await w.arecord(v)
    original = sink.append_keyed

    async def refuse_poison(records, keys):
        if any(r.request_id == "poison" for r in records):
            raise RuntimeError("refused")
        await original(records, keys)

    sink.append_keyed = refuse_poison
    await w.flush()
    for _ in range(4):
        await w.replay()
    assert {r.request_id for r in sink.all()} >= {v.request_id for v in others}
    assert "poison" not in {r.request_id for r in sink.all()}
    assert w.dropped == 1  # given up on after its own attempts, and counted
    assert not spill.path.exists()


async def test_replay_waits_until_the_queue_has_room(sink, spill):
    w = writer_of(sink, spill, capacity=4)
    for _ in range(8):
        await w.arecord(verdict_of())
    assert w.spilled == 4 and w.queued == 4
    w.start()
    await asyncio.sleep(0.05)
    await w.aclose()
    assert w.dropped == 0 and len(sink.all()) + _in_file(spill) == 8


def _in_file(spill) -> int:
    return len(spill.state().pending)


async def test_the_replay_ignores_a_torn_line(sink, spill):
    w = writer_of(sink, spill)
    await fill_and_overflow(w, REGULATED, 2)
    with spill.path.open("ab") as f:
        f.write(b'{"k":"spill","id":"x","rec')  # a short write left a fragment
        f.write(b"\n")
    await w.flush()
    await w.replay()
    assert len(sink.all()) == 4 and w.replayed == 2 and not spill.path.exists()


# ------------------------------------------------------------------------ shutdown and failure


async def test_records_still_queued_at_shutdown_are_spilled_for_a_regulated_tenant(sink, spill):
    w = writer_of(sink, spill, capacity=10)
    await w.arecord(verdict_of(REGULATED))
    await w.arecord(verdict_of(STANDARD))

    async def down(records):
        raise RuntimeError("store down")

    sink.append_many = down
    await w.aclose(timeout_s=0.2)
    assert w.spilled == 1 and w.dropped == 1
    (pending,) = spill.state().pending
    assert pending.record.tenant_id == REGULATED


async def test_a_spill_file_that_fails_drops_the_record_and_counts_it(sink, audit_dir):
    bad = decision_spill_beside(audit_dir / "missing" / "class_a.jsonl")
    w = writer_of(sink, bad)
    await fill_and_overflow(w, REGULATED, 3)
    assert w.dropped == 3 and w.spilled == 0


async def test_a_directory_that_cannot_be_read_counts_as_regulated(sink, spill):
    async def broken(tenant_id):
        raise RuntimeError("directory down")

    w = DecisionRecordWriter(
        sink, FixedTerm(), capacity=1, regulated_wait_s=0.0, spill=spill, is_regulated=broken
    )
    for _ in range(3):
        await w.arecord(verdict_of(STANDARD))
    assert w.spilled == 2 and w.dropped == 0


async def test_a_check_cancelled_while_it_waits_still_keeps_the_record(sink, spill):
    w = writer_of(sink, spill, regulated_wait_s=5.0)
    await fill_and_overflow(w, REGULATED, 0)
    task = asyncio.ensure_future(w.arecord(verdict_of(REGULATED)))
    await asyncio.sleep(0.05)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    await w.aclose()  # the spill was handed to the append thread; close waits for it
    assert w.dropped == 0 and w.spilled == 1


async def test_without_a_spill_a_regulated_record_waits_and_is_then_counted(sink):
    w = DecisionRecordWriter(
        sink, FixedTerm(), capacity=1, regulated_wait_s=0.02, is_regulated=regulated_if_acme
    )
    for _ in range(3):
        await w.arecord(verdict_of())
    assert (w.queued, w.dropped, w.spilled) == (1, 2, 0)


def test_a_spill_needs_a_sink_that_keeps_a_record_once(spill):
    class Plain:
        async def append_many(self, records): ...

    with pytest.raises(ValueError, match="append_keyed"):
        DecisionRecordWriter(Plain(), FixedTerm(), spill=spill)


# ------------------------------------------------------------------------ the file


def test_the_spill_file_sits_beside_the_class_a_file_and_is_private(audit_dir, spill):
    assert spill.path == audit_dir / SPILL_FILE_NAME == spill_file_beside(audit_dir / "x")
    spill.check()
    assert (os.stat(spill.path).st_mode & 0o777) == 0o600


def test_the_spill_file_is_held_to_the_class_a_file_checks(tmp_path):
    loose = tmp_path / "loose"
    loose.mkdir()
    loose.chmod(0o777)
    with pytest.raises(ClassAAuditFileError, match="group- or world-writable"):
        decision_spill_beside(loose / "class_a.jsonl").check()


def test_the_spill_file_is_not_followed_through_a_symbolic_link(audit_dir, tmp_path):
    target = tmp_path / "elsewhere"
    target.write_text("")
    (audit_dir / SPILL_FILE_NAME).symlink_to(target)
    with pytest.raises(ClassAAuditFileError, match="symbolic link"):
        decision_spill_beside(audit_dir / "class_a.jsonl").check()


def test_a_fully_replayed_file_is_deleted_only_if_nothing_was_appended(spill):
    record = make_record(REGULATED, NOW)
    ident, _, _ = spill.append(record, 395, ())
    spill.mark_done([ident])
    state = spill.state()
    assert state.pending == () and state.size > 0
    spill.append(record, 395, ())  # a record arrives after the state was read
    assert spill.retire(state) is False and spill.path.exists()
    assert len(spill.state().pending) == 1


def test_an_appender_that_opened_the_file_before_it_was_deleted_writes_to_a_new_one(spill):
    record = make_record(REGULATED, NOW)
    spill.mark_done([spill.append(record, 395, ())[0]])
    state = spill.state()
    assert spill.retire(state) and not spill.path.exists()
    spill.append(record, 395, ())
    assert len(spill.state().pending) == 1


# ------------------------------------------------------------------------ the tier test


class _Entry:
    def __init__(self, tier):
        self.tier = tier


@pytest.mark.parametrize(
    ("tier", "expected"),
    [("standard", False), ("regulated", True), ("dedicated", True)],
)
async def test_the_tier_test_is_the_catalogs_not_standard_rule(tier, expected):
    class Directory:
        async def get(self, tenant_id):
            return None if tenant_id == "t_gone" else _Entry(tier)

    regulated = directory_regulated(Directory())
    assert await regulated("t_x") is expected
    assert await regulated("t_gone") is False


# ------------------------------------------------------------------------ review fixes: the cap


def capped(audit_dir, max_bytes):
    return decision_spill_at(audit_dir / SPILL_FILE_NAME, max_bytes=max_bytes)


async def test_past_the_cap_a_regulated_record_is_dropped_counted_and_alerted(sink, audit_dir):
    alerts = RecordingAlertSink()
    spill = capped(audit_dir, 6_000)  # room for about four of these lines
    w = writer_of(sink, spill, alerts=alerts, alert_interval_s=0.0)
    for _ in range(12):
        await w.arecord(verdict_of())
    assert w.queued == 2 and w.spilled < 10 and w.spill_full == 10 - w.spilled
    assert w.dropped == w.spill_full and spill.path.stat().st_size <= 6_000
    await w._alert()
    kinds = {a.kind for a in alerts.alerts}
    assert ALERT_AUDIT_SPILL_NEAR_CAP in kinds and ALERT_AUDIT_RECORDS_DROPPED in kinds


async def test_the_near_the_cap_alert_is_raised_before_anything_is_dropped(sink, audit_dir):
    alerts = RecordingAlertSink()
    w = writer_of(sink, capped(audit_dir, 12_000), alerts=alerts, alert_interval_s=0.0)
    for _ in range(11):
        await w.arecord(verdict_of())
    assert w.dropped == 0 and w.spilled == 9
    await w._alert()
    assert [a.kind for a in alerts.alerts] == [ALERT_AUDIT_SPILL_NEAR_CAP]


async def test_replay_frees_the_cap_and_later_records_are_kept_again(sink, audit_dir):
    w = writer_of(sink, capped(audit_dir, 6_000))
    for _ in range(12):
        await w.arecord(verdict_of())
    assert w.spill_full > 0
    await w.flush()
    await w.replay()  # the file is gone, so its size is zero again
    dropped = w.dropped
    await fill_and_overflow(w, REGULATED, 1)
    assert w.dropped == dropped and w.spilled > 0


# ------------------------------------------------------------------------ review fixes: replay


async def test_replay_reads_the_file_once_not_once_a_batch(sink, spill, monkeypatch):
    w = writer_of(sink, spill, batch_size=10)
    for _ in range(2):
        await w.arecord(verdict_of())
    for _ in range(100):
        await w.arecord(verdict_of())
    await w.flush()
    reads = []
    real = spill.state
    monkeypatch.setattr(spill, "state", lambda: reads.append(1) or real())
    await w.replay()
    assert w.replayed == 100 and len(reads) <= 2  # the first read, and one before deleting


def write_lines(spill, count, tenant=REGULATED, ts=NOW):
    """A spill file of ``count`` records, written in one go (the lines of ``spill.append``)."""
    import uuid

    base = AuditRecord.model_validate_json(make_record(tenant, ts).model_dump_json())
    lines = []
    for _ in range(count):
        record = json.loads(
            base.model_copy(update={"request_id": uuid.uuid4().hex}).model_dump_json()
        )
        lines.append(
            json.dumps(
                {"k": "spill", "id": uuid.uuid4().hex, "requested_days": 395, "packs": [],
                 "record": record},
                separators=(",", ":"),
            )
        )  # fmt: skip
    fd = os.open(spill.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        os.write(fd, ("\n".join(lines) + "\n").encode())
    finally:
        os.close(fd)


async def test_a_ten_thousand_record_backlog_is_replayed_in_seconds(sink, spill):
    """It took 27 s when the file was re-read for every batch of 200."""
    write_lines(spill, 10_000)
    w = writer_of(sink, spill, capacity=100_000)
    started = time.perf_counter()
    await w.replay()
    elapsed = time.perf_counter() - started
    assert w.replayed == 10_000 and len(sink.all()) == 10_000
    assert elapsed < 12, f"{elapsed:.1f} s"
    assert not spill.path.exists()


async def test_a_record_past_its_term_is_not_written(sink, spill):
    write_lines(spill, 3, ts=datetime(2020, 1, 1, tzinfo=UTC))  # 2020 plus 395 days: gone
    w = writer_of(sink, spill)
    await w.replay()
    assert sink.all() == [] and w.expired_skipped == 3 and w.replayed == 0
    assert not spill.path.exists()  # marked done, so the file went


async def test_a_record_of_an_ended_tenant_is_not_written(sink, spill):
    write_lines(spill, 2)

    async def ended(tenant_id):
        return tenant_id == REGULATED

    w = writer_of(sink, spill, is_ended=ended)
    await w.replay()
    assert sink.all() == [] and w.ended_skipped == 2 and not spill.path.exists()


async def test_a_tenant_whose_end_cannot_be_read_keeps_its_records(sink, spill):
    write_lines(spill, 1)

    async def broken(tenant_id):
        raise RuntimeError("directory down")

    w = writer_of(sink, spill, is_ended=broken)
    await w.replay()
    assert len(sink.all()) == 1 and w.ended_skipped == 0


def test_compaction_keeps_only_what_is_pending(spill):
    record = make_record(REGULATED, NOW)
    ids = [spill.append(record, 395, ())[0] for _ in range(5)]
    spill.mark_done(ids[:4])
    before = spill.path.stat().st_size
    size = spill.compact()
    assert size == spill.path.stat().st_size < before
    assert [r.id for r in spill.state().pending] == ids[4:]
    spill.mark_done(ids[4:])
    assert spill.compact() == 0 and not spill.path.exists()


async def test_the_writer_compacts_when_done_lines_are_over_half_the_file(sink, spill, monkeypatch):
    w = writer_of(sink, spill, batch_size=10)
    for _ in range(2):
        await w.arecord(verdict_of())
    for _ in range(40):
        await w.arecord(verdict_of())
    await w.flush()
    compactions = []
    real = spill.compact
    monkeypatch.setattr(spill, "compact", lambda: compactions.append(1) or real())
    await w.replay()
    assert w.replayed == 40 and compactions  # at least once while batches were still pending


# ------------------------------------------------------------------------ review fixes: threads


async def test_spill_file_io_runs_on_its_own_threads_never_the_event_loop(sink, spill):
    seen = []
    real_append, real_state = spill.append, spill.state

    def append(*a, **kw):
        seen.append(("append", threading.current_thread().name))
        return real_append(*a, **kw)

    def state():
        seen.append(("state", threading.current_thread().name))
        return real_state()

    spill.append, spill.state = append, state
    w = writer_of(sink, spill)
    for _ in range(4):
        await w.arecord(verdict_of())
    await w.flush()
    await w.replay()
    await w.aclose()
    names = {kind: name for kind, name in seen}
    assert names["append"].startswith("decision-spill-append")
    assert names["state"].startswith("decision-spill-replay")
    assert threading.current_thread().name not in names.values()


async def test_a_spill_after_a_cancel_is_not_written_on_the_event_loop(sink, spill):
    seen = []
    real_append = spill.append

    def append(*a, **kw):
        seen.append(threading.current_thread().name)
        return real_append(*a, **kw)

    spill.append = append
    w = writer_of(sink, spill, regulated_wait_s=5.0)
    await fill_and_overflow(w, REGULATED, 0)
    task = asyncio.ensure_future(w.arecord(verdict_of(REGULATED)))
    await asyncio.sleep(0.05)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    await w.aclose()
    assert seen and all(n.startswith("decision-spill-append") for n in seen)
    assert w.spilled == 1 and w.dropped == 0


# ------------------------------------------------------------------------ the cap is the file's


def test_the_cap_is_judged_on_the_files_size_not_on_what_one_writer_has_counted(audit_dir):
    """Two processes (two sinks) share the spill directory: each is under the cap by its own
    count, together they are over it, and the second one's append is refused."""
    from guardrail_engine.audit.spill import SpillFullError

    one = decision_spill_at(audit_dir / SPILL_FILE_NAME, max_bytes=4_000)
    two = decision_spill_at(audit_dir / SPILL_FILE_NAME, max_bytes=4_000)
    record = make_record(REGULATED, NOW)
    for _ in range(2):
        one.append(record, 395, ())  # about 1.3 KB each
    size = one.path.stat().st_size
    assert 0 < size <= 4_000
    with pytest.raises(SpillFullError):
        for _ in range(3):  # `two` has written nothing: its own count is zero
            two.append(record, 395, ())
    assert one.path.stat().st_size <= 4_000


def test_an_append_returns_the_size_of_the_file_after_it(audit_dir):
    one = decision_spill_at(audit_dir / SPILL_FILE_NAME)
    two = decision_spill_at(audit_dir / SPILL_FILE_NAME)
    record = make_record(REGULATED, NOW)
    _, _, first = one.append(record, 395, ())
    _, nbytes, second = two.append(record, 395, ())  # another sink: the total, not its own
    assert second == first + nbytes == one.path.stat().st_size


async def test_a_writer_that_has_not_read_the_file_yet_cannot_overshoot_the_cap(sink, audit_dir):
    """A process that spills before its first replay read still counts what others wrote."""
    other = decision_spill_at(audit_dir / SPILL_FILE_NAME, max_bytes=5_000)
    record = make_record(REGULATED, NOW)
    for _ in range(3):
        other.append(record, 395, ())  # another process fills most of the file
    w = writer_of(sink, decision_spill_at(audit_dir / SPILL_FILE_NAME, max_bytes=5_000))
    assert w._spill_bytes == 0  # it has not read the file
    await fill_and_overflow(w, REGULATED, 3)
    assert w.spill_full >= 1 and w.dropped == w.spill_full
    assert (audit_dir / SPILL_FILE_NAME).stat().st_size <= 5_000


async def test_the_near_the_cap_alert_counts_what_other_processes_wrote(sink, audit_dir):
    alerts = RecordingAlertSink()
    other = decision_spill_at(audit_dir / SPILL_FILE_NAME, max_bytes=5_000)
    record = make_record(REGULATED, NOW)
    for _ in range(3):
        other.append(record, 395, ())
    spill = decision_spill_at(audit_dir / SPILL_FILE_NAME, max_bytes=5_000)
    w = writer_of(sink, spill, alerts=alerts, alert_interval_s=0.0)
    await fill_and_overflow(w, REGULATED, 1)  # its own spill: one line, 80% of the cap reached
    await w._alert()
    assert ALERT_AUDIT_SPILL_NEAR_CAP in {a.kind for a in alerts.alerts}
