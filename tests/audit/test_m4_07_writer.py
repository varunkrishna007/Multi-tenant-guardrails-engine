"""M4-07 the write-behind writer and the term it stamps."""

import asyncio
import sys
from datetime import timedelta
from pathlib import Path

import pytest
from audit_records import ACME, NOW, OTHER, make_record

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "policy"))
from policy_fixtures import (
    FINANCE_V2_DOCUMENT,
    FLOOR_DOCUMENTS,
    HEALTHCARE_V1_DOCUMENT,
    INSURANCE_V3_DOCUMENT,
)

from guardrail_engine.audit.store import InMemoryDecisionRecords
from guardrail_engine.audit.term import EffectiveTerm
from guardrail_engine.audit.writer import DecisionRecordWriter
from guardrail_engine.directory.model import TenantRecord
from guardrail_engine.gateway.sinks import ALERT_AUDIT_RECORDS_DROPPED, RecordingAlertSink
from guardrail_engine.guard.verdict import Decision, Reason, Verdict
from guardrail_engine.policy import FloorVersion, InMemoryCatalog, PackVersion, PlatformSettings
from guardrail_engine.retention.resolver import TenantRetention


class FixedTerm:
    def __init__(self, days=395):
        self.days, self.calls = days, []

    async def term(self, tenant_id, requested_days, packs=()):
        self.calls.append((tenant_id, requested_days))
        return TenantRetention(self.days, "bundle")


def verdict_of(tenant=ACME, *, ts=NOW, retention_days=395, **kw) -> Verdict:
    record = make_record(tenant, ts, **kw)
    return Verdict(
        request_id=record.request_id, tenant_id=tenant, guard_point=record.guard_point,
        decision=Decision.ALLOW, reason=Reason.POLICY, checked_at=ts, latency_ms=1.0,
        bundle_version=1, rules=record.rules, retention_days=retention_days,
    )  # fmt: skip


@pytest.fixture
def sink():
    return InMemoryDecisionRecords()


def writer_of(sink, terms=None, **kw):
    return DecisionRecordWriter(sink, terms or FixedTerm(), flush_interval_s=0.01, **kw)


async def test_a_record_is_queued_without_waiting_and_written_behind(sink):
    w = writer_of(sink)
    w.record(verdict_of())
    assert w.queued == 1 and sink.all() == []  # nothing waited for the store
    await w.flush()
    (record,) = sink.all()
    assert record.tenant_id == ACME and w.written == 1 and w.dropped == 0


async def test_the_background_task_drains_the_queue(sink):
    w = writer_of(sink)
    w.start()
    for _ in range(5):
        w.record(verdict_of())
    for _ in range(100):
        if len(sink.all()) == 5:
            break
        await asyncio.sleep(0.02)
    assert len(sink.all()) == 5
    await w.aclose()


async def test_retain_until_is_the_effective_term_never_the_raw_value(sink):
    """The verdict carried 30 days; the term in force says 395, and that is written."""
    terms = FixedTerm(395)
    w = writer_of(sink, terms)
    w.record(verdict_of(ts=NOW, retention_days=30))
    await w.flush()
    (record,) = sink.all()
    assert record.retain_until == NOW + timedelta(days=395)
    assert terms.calls == [(ACME, 30)]


async def test_a_full_queue_drops_counts_and_never_waits_or_raises(sink):
    w = writer_of(sink, capacity=3)
    for _ in range(10):
        w.record(verdict_of())  # no loop is running the drain: nothing makes room
    assert (w.queued, w.dropped) == (3, 7)


async def test_dropped_records_raise_the_alert_from_the_writers_own_task(sink):
    alerts = RecordingAlertSink()
    w = writer_of(sink, capacity=1, alerts=alerts, alert_interval_s=0.0)
    w.start()
    for _ in range(5):
        w.record(verdict_of())
    for _ in range(100):
        if alerts.alerts:
            break
        await asyncio.sleep(0.02)
    await w.aclose()
    assert alerts.alerts and alerts.alerts[0].kind == ALERT_AUDIT_RECORDS_DROPPED
    assert sum(a.count for a in alerts.alerts) == w.dropped >= 4


class FlakySink(InMemoryDecisionRecords):
    def __init__(self, fail_times):
        super().__init__()
        self.fail_times, self.attempts = fail_times, 0

    async def append_many(self, records):
        self.attempts += 1
        if self.attempts <= self.fail_times:
            raise ConnectionError("db down")
        await super().append_many(records)


async def test_a_failing_database_is_retried_and_loses_nothing_while_it_recovers():
    sink = FlakySink(2)
    w = writer_of(sink, retry_base_s=0.01, retry_cap_s=0.02)
    for _ in range(3):
        w.record(verdict_of())
    w.start()
    for _ in range(200):
        if len(sink.all()) == 3:
            break
        await asyncio.sleep(0.02)
    await w.aclose()
    assert len(sink.all()) == 3 and w.dropped == 0 and w.failed_writes == 2


async def test_records_the_database_keeps_refusing_are_dropped_and_counted():
    sink = FlakySink(10_000)
    w = writer_of(sink, max_attempts=3)
    w.record(verdict_of())
    for _ in range(5):
        await w.flush()
    assert (w.dropped, w.queued, sink.all()) == (1, 0, [])


async def test_groups_are_written_one_tenant_at_a_time():
    seen = []

    class Spy(InMemoryDecisionRecords):
        async def append_many(self, records):
            seen.append({r.tenant_id for r in records})
            await super().append_many(records)

    w = writer_of(Spy())
    for t in (ACME, OTHER, ACME, None):
        w.record(verdict_of(t))
    await w.flush()
    assert len(seen) == 3 and all(len(s) == 1 for s in seen)  # three tenants, three writes
    assert {next(iter(s)) for s in seen} == {ACME, OTHER, None}


async def test_close_writes_what_it_can_and_counts_the_rest(sink):
    w = writer_of(sink)
    for _ in range(4):
        w.record(verdict_of())
    await w.aclose()
    assert len(sink.all()) == 4 and w.dropped == 0
    w.record(verdict_of())  # after close: dropped, never raised
    assert w.dropped == 1


async def test_a_record_holds_no_content_only_the_audit_records_own_fields(sink):
    w = writer_of(sink)
    w.record(verdict_of())
    await w.flush()
    dumped = sink.all()[0].model_dump_json()
    assert "content_sha256" in dumped and '"content"' not in dumped


# ------------------------------------------------------------------ the term


def catalog():
    return InMemoryCatalog(
        floors=[FloorVersion.from_document(d) for d in FLOOR_DOCUMENTS],
        packs=[
            PackVersion.from_document(d)
            for d in (INSURANCE_V3_DOCUMENT, FINANCE_V2_DOCUMENT, HEALTHCARE_V1_DOCUMENT)
        ],
        tier_required_packs={"regulated": ["finance"]},
    )


class Directory:
    def __init__(self, *records):
        self.by_id = {r.tenant_id: r for r in records}

    async def get(self, tenant_id):
        return self.by_id.get(tenant_id)


def term_of(*records):
    return EffectiveTerm(
        catalog=catalog(), settings=PlatformSettings(min_floor_version=2),
        directory=Directory(*records),
    )  # fmt: skip


def tenant(tier="standard", tid=ACME):
    return TenantRecord(tenant_id=tid, slug="acme", domain="insurance", tier=tier)


@pytest.mark.parametrize(
    ("tier", "requested", "days", "source"),
    [
        ("standard", 395, 395, "bundle"),
        ("standard", 90, 90, "bundle"),  # the standard minimum
        ("standard", 30, 90, "clamped"),  # raised: never deleted before R3's minimum
        ("standard", 5000, 7 * 365, "clamped"),  # and lowered to the maximum
        ("regulated", 90, 395, "clamped"),  # the finance pack the tier requires
        ("regulated", 7 * 365, 7 * 365, "bundle"),
    ],
)
async def test_the_term_is_moved_into_the_bounds_in_force(tier, requested, days, source):
    got = await term_of(tenant(tier)).term(ACME, requested)
    assert got == TenantRetention(days, source)


@pytest.mark.parametrize("tid", [None, OTHER])
async def test_a_tenant_that_cannot_be_resolved_gets_the_longest_term(tid):
    got = await term_of(tenant()).term(tid, 90)
    assert got == TenantRetention(7 * 365, "fallback")  # not in the directory, or none


async def test_no_term_on_the_verdict_means_the_longest(sink=None):
    assert await term_of(tenant()).term(ACME, None) == TenantRetention(7 * 365, "fallback")


async def test_a_directory_failure_means_the_longest_term():
    class Down:
        async def get(self, tenant_id):
            raise ConnectionError("down")

    t = EffectiveTerm(catalog=catalog(), settings=PlatformSettings(min_floor_version=2),
                      directory=Down())  # fmt: skip
    assert await t.term(ACME, 90) == TenantRetention(7 * 365, "fallback")


async def test_the_writer_stamps_with_the_effective_term_end_to_end(sink):
    w = DecisionRecordWriter(sink, term_of(tenant("regulated")), flush_interval_s=0.01)
    w.record(verdict_of(ts=NOW, retention_days=30))  # the raw value is below the pack's minimum
    await w.flush()
    assert sink.all()[0].retain_until == NOW + timedelta(days=395)


# ------------------------------------------------------------------
def profile_of(tier="standard", tid=ACME, required=()):
    from guardrail_engine.guard.tenants import TenantProfile
    from guardrail_engine.policy.catalog import TenantAttributes

    return TenantProfile.build(
        TenantAttributes(tenant_id=tid, tier=tier, required_packs=frozenset(required)),
        "insurance", slug="acme",
    )  # fmt: skip


async def test_the_term_reads_the_tier_from_the_guards_tenant_profile(caplog):
    """The directory the engine hands over returns a TenantProfile, not a TenantRecord.
    The regulated tier's finance pack (minimum 395) must apply, not the 7-year fallback."""

    class ProfileDirectory:
        async def get(self, tenant_id):
            return profile_of("regulated")

    t = EffectiveTerm(
        catalog=catalog(), settings=PlatformSettings(min_floor_version=2),
        directory=ProfileDirectory(),
    )  # fmt: skip
    assert await t.term(ACME, 395) == TenantRetention(395, "bundle")
    assert await t.term(ACME, 90) == TenantRetention(395, "clamped")
    assert t.fallback_counts() == {}  # it did not fall back


async def test_a_term_that_falls_back_is_warned_about_and_counted_per_tenant(caplog):
    import logging

    t = term_of(tenant())
    with caplog.at_level(logging.WARNING, logger="guardrail_engine.audit.term"):
        assert (await t.term(OTHER, 90)).source == "fallback"  # not in the directory
        assert (await t.term(OTHER, 90)).source == "fallback"
        assert (await t.term(ACME, None)).source == "fallback"  # no term on the verdict
        assert (await t.term(None, 90)).source == "fallback"
    assert t.fallback_counts() == {
        (OTHER, "not_in_directory"): 2, (ACME, "no_term_on_verdict"): 1, ("", "no_tenant"): 1,
    }  # fmt: skip
    messages = [r.getMessage() for r in caplog.records]
    assert any(OTHER in m and "not_in_directory" in m for m in messages)


async def test_a_directory_entry_of_the_wrong_shape_is_not_silent():
    class Odd:
        async def get(self, tenant_id):
            return object()  # neither a profile nor a record

    t = EffectiveTerm(catalog=catalog(), settings=PlatformSettings(min_floor_version=2),
                      directory=Odd())  # fmt: skip
    assert (await t.term(ACME, 90)).source == "fallback"
    assert t.fallback_counts() == {(ACME, "AttributeError"): 1}


@pytest.mark.parametrize(
    ("extends", "requested", "days"),
    [
        ((), 30, 90),  # no pack: the standard minimum
        (("domain/finance@2",), 30, 395),  # a pack the bundle extends: its minimum
        (("domain/healthcare@1",), 395, 395),
        (("domain/finance@2",), 9000, 7 * 365),  # and its maximum
    ],
)
async def test_the_packs_the_bundle_extends_set_the_bounds(extends, requested, days):
    got = await term_of(tenant()).term(ACME, requested, extends)
    assert got.days == days


async def test_when_the_packs_bounds_conflict_the_minimum_wins():
    """R3: the longest retention. A pack whose minimum is above another's maximum."""
    import copy

    doc = copy.deepcopy(FINANCE_V2_DOCUMENT)
    doc["name"] = "short"
    doc["version"] = 1
    doc["retention"] = {
        "records_min_days": 90, "records_max_days": 200, "records_default_days": 120,
        "content_max_days": 30,
    }  # fmt: skip
    finance, short = PackVersion.from_document(FINANCE_V2_DOCUMENT), PackVersion.from_document(doc)
    cat = InMemoryCatalog(
        floors=[FloorVersion.from_document(d) for d in FLOOR_DOCUMENTS],
        packs=[finance, short], tier_required_packs={},
    )  # fmt: skip
    t = EffectiveTerm(catalog=cat, settings=PlatformSettings(min_floor_version=2),
                      directory=Directory(tenant()))  # fmt: skip
    # finance's minimum is 395, the short pack's maximum 200: 395 wins, never the 200
    assert (await t.term(ACME, 150, ("domain/finance@2", "domain/short@1"))).days == 395


async def test_the_writer_clamps_against_the_packs_of_the_deciding_version(sink):
    from guardrail_engine.guard.verdict import Verdict as V

    w = DecisionRecordWriter(sink, term_of(tenant()), flush_interval_s=0.01)
    base = verdict_of(ts=NOW, retention_days=30)
    w.record(V(**{**base.model_dump(), "retention_packs": ("domain/finance@2",)}))
    await w.flush()
    assert sink.all()[0].retain_until == NOW + timedelta(days=395)


class PoisonSink(InMemoryDecisionRecords):
    """Refuses any batch that holds the poisoned record, and the poisoned record alone."""

    def __init__(self, poison):
        super().__init__()
        self.poison = poison

    async def append_many(self, records):
        if any(r.request_id == self.poison for r in records):
            raise ConnectionError("this record is refused")
        await super().append_many(records)


async def test_one_bad_record_costs_only_itself():
    """A group fails, so its records are tried alone; only the bad one is dropped."""
    sink = PoisonSink("bad")
    w = writer_of(sink, max_attempts=3, batch_size=50)
    for i in range(20):
        w.record(verdict_of(request_id="bad" if i == 7 else f"ok-{i}"))
    for _ in range(12):
        await w.flush()
    assert sorted(r.request_id for r in sink.all()) == sorted(
        f"ok-{i}" for i in range(20) if i != 7
    )
    assert w.dropped == 1 and w.queued == 0


async def test_close_lets_a_write_in_flight_finish_and_writes_it_once():
    """Cancelling an append that already committed would write the group again."""
    import asyncio

    gate = asyncio.Event()
    commits = []

    class Slow(InMemoryDecisionRecords):
        async def append_many(self, records):
            await gate.wait()  # in flight until released
            commits.append([r.request_id for r in records])
            await super().append_many(records)

    sink = Slow()
    w = writer_of(sink)
    w.start()
    for i in range(3):
        w.record(verdict_of(request_id=f"r{i}"))
    await asyncio.sleep(0.1)  # the background task has the group in flight
    closing = asyncio.ensure_future(w.aclose(timeout_s=5.0))
    await asyncio.sleep(0.05)
    gate.set()
    await closing
    assert len(commits) == 1 and sorted(commits[0]) == ["r0", "r1", "r2"]  # once, not twice
    assert sorted(r.request_id for r in sink.all()) == ["r0", "r1", "r2"] and w.dropped == 0
