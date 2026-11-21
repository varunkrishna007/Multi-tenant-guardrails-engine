"""M5-07: the offboarding job. Every behaviour test runs against the in-memory environment and,
when ``GUARDRAIL_TEST_PG_DSN`` is set, the Postgres one (migrations 043 and 044, the job connected
as the retention role, the schema owned by a non-superuser so row-level security applies).

The clocks are injected: the provisioner's (``env.clock``, read at each directory write) and the
job's (a ``datetime`` the test passes). Everything is in the past, so the database's bound on the
job's clock is met."""

import asyncio
from datetime import timedelta

import pytest
from offboarding_env import (
    ALL_TABLES,
    DAY,
    HELD_CONTENT,
    OPS,
    T0,
    MemoryEnv,
    by_class,
    expected,
    make_pg_env,
)

from guardrail_engine.gateway.sinks import (
    ALERT_OFFBOARDING_OVERDUE,
    AlertSeverity,
    RecordingAlertSink,
)
from guardrail_engine.offboarding import OffboardingJob, OffboardingRefused
from guardrail_engine.offboarding.model import CONTENT_RECEIPT, OFFBOARD_TABLES


@pytest.fixture(params=["memory", "postgres"])
async def env(request):
    if request.param == "memory":
        yield MemoryEnv()
        return
    pg, cleanup = await make_pg_env()
    try:
        yield pg
    finally:
        await cleanup()


def job(env, days=0.0, seconds=0.0, **kw) -> OffboardingJob:
    now = env.at(days, seconds)
    kw.setdefault("quiesce", timedelta(0))  # the quiet period has its own test
    return OffboardingJob(env.off, clock=lambda: now, **kw)


async def terminated_tenant(env, slug="acme-co", records=3) -> str:
    tid = await env.new_tenant(slug)
    await env.seed(tid, records)
    await env.terminate(tid)
    return tid


# ----------------------------------------------------------------------------- the deletion


async def test_a_terminated_tenants_data_goes_and_the_receipts_say_how_much(env):
    tid = await terminated_tenant(env)
    assert await env.counts(tid) == expected()

    report = await job(env, days=1).run_once()

    assert report.failed == () and report.overdue == ()
    [result] = report.tenants
    assert result.completed and not result.more_to_do
    assert result.deleted == expected()
    assert await env.counts(tid) == dict.fromkeys(ALL_TABLES, 0)

    receipts = await env.off.receipts(tid)
    per_table = {r.table: r.deleted_count for r in receipts}
    assert per_table == {**expected(), CONTENT_RECEIPT: HELD_CONTENT}
    assert {r.table: r.data_class for r in receipts} == {
        **{t.name: t.data_class for t in OFFBOARD_TABLES},
        CONTENT_RECEIPT: "C",
    }
    assert {r.run_id for r in receipts} == {report.run_id}

    done = await env.off.completion(tid)
    assert done is not None
    assert done.counts_by_class == by_class()
    assert done.counts_by_table == {**expected(), CONTENT_RECEIPT: HELD_CONTENT}
    assert done.within_deadline is True
    assert done.terminating_at == T0 and done.deadline == T0 + 30 * DAY


async def test_receipts_hold_no_content(env):
    tid = await terminated_tenant(env)
    await job(env).run_once()
    fields = {
        "run_id", "at", "tenant_id", "table", "data_class", "deleted_count", "batch", "resweep",
    }  # fmt: skip
    for r in await env.off.receipts(tid):
        assert set(r.__slots__) == fields
        assert isinstance(r.deleted_count, int) and "held text" not in repr(r)
    done = await env.off.completion(tid)
    assert "held text" not in repr(done) and "labelled text" not in repr(done)
    for row in await env.off.usage_summary(tid):  # counts and money, no content
        assert "held text" not in repr(row) and "labelled text" not in repr(row)
    if env.kind == "postgres":
        text = await env.owner.fetchval(
            "SELECT string_agg(o::text, ' ') FROM offboarding_receipts o"
        )
        text += await env.owner.fetchval(
            "SELECT string_agg(o::text, ' ') FROM offboarding_completions o"
        )
        assert "held text" not in text and "labelled text" not in text


async def test_class_a_is_kept(env):
    tid = await terminated_tenant(env)
    before = await env.class_a(tid)
    assert all(n >= 1 for n in before.values()), before
    await job(env).run_once()
    assert await env.class_a(tid) == before


async def test_another_tenants_data_is_untouched(env):
    gone = await terminated_tenant(env, "gone-co")
    kept = await env.new_tenant("kept-co")
    await env.seed(kept, 5)
    kept_class_a = await env.class_a(kept)

    await job(env).run_once()

    assert await env.counts(gone) == dict.fromkeys(ALL_TABLES, 0)
    assert await env.counts(kept) == expected(5)
    assert await env.class_a(kept) == kept_class_a
    assert await env.off.receipts(kept) == []
    assert await env.off.completion(kept) is None


async def test_an_active_tenant_is_never_touched_by_the_job(env):
    tid = await env.new_tenant("active-co")
    await env.seed(tid)

    report = await job(env, days=400).run_once()

    assert report.tenants == () and report.overdue == ()
    assert await env.counts(tid) == expected()
    assert await env.off.receipts(tid) == []


async def test_a_suspended_or_offboarded_tenant_is_not_a_terminated_one(env):
    for i, status in enumerate(("suspended", "offboarded")):
        tid = await env.new_tenant(f"s{i}-co")
        await env.seed(tid)
        await env.prov.set_status(OPS, tid, 1, status)
        assert (await job(env, days=400).run_once()).tenants == ()
        assert await env.counts(tid) == expected()
        with pytest.raises(OffboardingRefused):
            await env.off.delete_batch(
                run_id="r", tenant_id=tid, table="tenant_drafts", now=env.at(), limit=10, batch=1
            )


async def test_a_direct_call_for_an_active_tenant_is_refused_and_deletes_nothing(env):
    tid = await env.new_tenant("direct-co")
    await env.seed(tid)
    for table in ALL_TABLES:
        with pytest.raises(OffboardingRefused):
            await env.off.delete_batch(
                run_id="r", tenant_id=tid, table=table, now=env.at(), limit=10, batch=1
            )
    with pytest.raises(OffboardingRefused):
        await env.off.complete(run_id="r", tenant_id=tid, now=env.at())
    assert await env.counts(tid) == expected()
    assert await env.off.receipts(tid) == [] and await env.off.completion(tid) is None


async def test_a_terminating_tenant_waits_and_nothing_is_deleted(env):
    tid = await env.new_tenant("slow-co")
    await env.seed(tid)

    async def crash(_):
        raise RuntimeError("the process died between terminating and terminated")

    env.prov._sleep = crash
    with pytest.raises(RuntimeError):
        await env.prov.terminate(OPS, tid, "contract ended")
    assert (await env.directory.get(tid)).status == "terminating"

    report = await job(env, days=2).run_once()

    [result] = report.tenants
    assert result.waiting and not result.completed and result.deleted == {}
    assert await env.counts(tid) == expected()
    with pytest.raises(OffboardingRefused):
        await env.off.delete_batch(
            run_id="r", tenant_id=tid, table="tenant_drafts", now=env.at(), limit=10, batch=1
        )


# ----------------------------------------------------------------------------- the 30 days


async def test_the_30_day_boundary_is_strict(env):
    """Day 30 exactly is still in time; one second later, an unfinished tenant pages."""
    tid = await terminated_tenant(env)
    alerts = RecordingAlertSink()

    # Held back to one batch per run so the tenant is still unfinished at each run.
    def slow(days, seconds=0.0):
        return job(env, days, seconds, alerts=alerts, batch_size=1, max_batches_per_table=1)

    at_day_30 = await slow(30).run_once()
    assert at_day_30.overdue == () and alerts.alerts == []
    assert at_day_30.tenants[0].more_to_do and not at_day_30.tenants[0].overdue

    just_after = await slow(30, 1).run_once()
    assert just_after.overdue == (tid,)
    [page] = alerts.pages()
    assert page.kind == ALERT_OFFBOARDING_OVERDUE == "offboarding_overdue"
    assert page.severity is AlertSeverity.PAGE and tid in page.message
    assert page.tenant_id == ""  # not under the tenant whose rows are being deleted

    await slow(30, 2).run_once()  # still unfinished: pages again
    assert len(alerts.pages()) == 2

    # The rest is done late: the completion receipt says so.
    while (await env.off.completion(tid)) is None:
        await job(env, 31, alerts=alerts).run_once()
    done = await env.off.completion(tid)
    assert done.within_deadline is False


async def test_finishing_on_day_30_exactly_is_within_the_deadline(env):
    tid = await terminated_tenant(env)
    alerts = RecordingAlertSink()
    report = await job(env, days=30, alerts=alerts).run_once()
    assert report.overdue == () and alerts.alerts == []
    done = await env.off.completion(tid)
    assert done.within_deadline is True


async def test_the_clock_is_the_injected_one_and_must_be_aware(env):
    await terminated_tenant(env)
    naive = OffboardingJob(env.off, clock=lambda: T0.replace(tzinfo=None))
    with pytest.raises(ValueError, match="aware"):
        await naive.run_once()


async def test_a_stuck_terminating_tenant_pages_after_30_days_too(env):
    tid = await env.new_tenant("stuck-co")

    async def crash(_):
        raise RuntimeError("stuck")

    env.prov._sleep = crash
    with pytest.raises(RuntimeError):
        await env.prov.terminate(OPS, tid, "contract ended")
    alerts = RecordingAlertSink()
    assert (await job(env, 30, alerts=alerts).run_once()).overdue == ()
    report = await job(env, 30, 1, alerts=alerts).run_once()
    assert report.overdue == (tid,) and len(alerts.pages()) == 1


# ----------------------------------------------------------------------------- idempotency


async def test_a_second_run_does_nothing_and_there_is_one_completion(env):
    tid = await terminated_tenant(env)
    first = await job(env).run_once()
    receipts = await env.off.receipts(tid)
    second = await job(env, days=1).run_once()

    assert first.deleted == sum(expected().values()) and second.tenants == ()
    assert await env.off.receipts(tid) == receipts  # no new rows at all
    done = await env.off.completion(tid)
    assert done is not None and done.run_id == first.run_id
    assert await env.off.complete(run_id="again", tenant_id=tid, now=env.at()) == (
        "already_complete"
    )
    assert (await env.off.completion(tid)).run_id == first.run_id


async def test_a_run_that_stops_half_way_is_continued_by_the_next(env):
    tid = await terminated_tenant(env, records=7)
    first = await job(env, batch_size=2, max_batches_per_table=1).run_once()
    assert first.tenants[0].more_to_do and not first.tenants[0].completed
    assert await env.off.completion(tid) is None

    runs = 0
    while await env.off.completion(tid) is None:
        runs += 1
        assert runs < 20
        await job(env, batch_size=2, max_batches_per_table=1).run_once()

    assert await env.counts(tid) == dict.fromkeys(ALL_TABLES, 0)
    done = await env.off.completion(tid)
    assert done.counts_by_class == by_class(7)  # the sum over every run


async def test_batches_are_bounded_and_numbered(env):
    tid = await terminated_tenant(env, records=5)
    report = await job(env, batch_size=2).run_once()
    batches = [
        r.batch for r in await env.off.receipts(tid, report.run_id) if r.table == "decision_records"
    ]
    assert batches == [1, 2, 3]  # 2 + 2 + 1
    sizes = [
        r.deleted_count
        for r in await env.off.receipts(tid, report.run_id)
        if r.table == "decision_records"
    ]
    assert sizes == [2, 2, 1] and max(sizes) <= 2


async def test_a_table_with_nothing_in_it_still_leaves_a_zero_receipt(env):
    tid = await env.new_tenant("empty-co")
    await env.terminate(tid)
    report = await job(env).run_once()
    receipts = await env.off.receipts(tid, report.run_id)
    assert {r.table for r in receipts} == {t.name for t in OFFBOARD_TABLES} | {CONTENT_RECEIPT}
    assert all(r.deleted_count == 0 and r.batch == 1 for r in receipts)
    done = await env.off.completion(tid)
    assert done.counts_by_class == dict.fromkeys("BCDEGW", 0)


# ----------------------------------------------------------------------------- concurrency


async def test_replicas_running_at_once_delete_each_row_once_and_complete_once(env):
    tid = await terminated_tenant(env, records=40)
    other = await terminated_tenant(env, "second-co", records=11)

    reports = await asyncio.gather(*(job(env, batch_size=3).run_once() for _ in range(4)))

    assert all(r.failed == () for r in reports)
    assert await env.counts(tid) == dict.fromkeys(ALL_TABLES, 0)
    assert await env.counts(other) == dict.fromkeys(ALL_TABLES, 0)
    for t, records in ((tid, 40), (other, 11)):
        receipts = await env.off.receipts(t)
        total = {}
        for r in receipts:
            total[r.table] = total.get(r.table, 0) + r.deleted_count
        assert total == {**expected(records), CONTENT_RECEIPT: HELD_CONTENT}
        done = await env.off.completion(t)
        assert done is not None and done.counts_by_class == by_class(records)
    # Replicas that found nothing left still wrote zero receipts; none wrote a second completion.
    if env.kind == "postgres":
        assert await env.owner.fetchval("SELECT count(*) FROM offboarding_completions") == 2


async def test_one_tenant_failing_does_not_stop_the_others(env):
    bad = await terminated_tenant(env, "bad-co")
    good = await terminated_tenant(env, "good-co")

    class Flaky:
        def __init__(self, inner):
            self.inner = inner

        def __getattr__(self, name):
            return getattr(self.inner, name)

        async def delete_batch(self, **kw):
            if kw["tenant_id"] == bad:
                raise RuntimeError("database down")
            return await self.inner.delete_batch(**kw)

    now = env.at()
    report = await OffboardingJob(
        Flaky(env.off), clock=lambda: now, quiesce=timedelta(0)
    ).run_once()

    assert report.failed == (bad,)
    assert await env.off.completion(good) is not None
    assert await env.off.completion(bad) is None
    again = await job(env).run_once()  # the next run picks the failed one up
    assert again.failed == () and await env.off.completion(bad) is not None


# ----------------------------------------------------------------------------- bounds


@pytest.mark.parametrize(
    ("kw", "message"),
    [
        ({"limit": 0}, "batch size"),
        ({"limit": 100_001}, "batch size"),
        ({"batch": 0}, "batch"),
        ({"table": "tenants"}, "not an offboarding table"),
        ({"table": "tenant_golden_audit"}, "not an offboarding table"),
        ({"table": "escalation_items.content"}, "not an offboarding table"),
        ({"tenant_id": "acme"}, "tenant id"),
    ],
)
async def test_the_store_refuses_out_of_range_calls(env, kw, message):
    tid = await terminated_tenant(env)
    args = {"run_id": "r", "tenant_id": tid, "table": "tenant_drafts", "now": env.at(),
            "limit": 10, "batch": 1}  # fmt: skip
    args.update(kw)
    with pytest.raises(OffboardingRefused, match=message):
        await env.off.delete_batch(**args)
    assert (await env.counts(tid))["tenant_drafts"] == 1


async def test_the_job_refuses_bad_settings(env):
    with pytest.raises(ValueError):
        job(env, batch_size=0)
    with pytest.raises(ValueError):
        job(env, batch_size=100_001)
    with pytest.raises(ValueError):
        job(env, max_batches_per_table=0)
    assert timedelta(days=30) == T0 + 30 * DAY - T0


async def test_completion_waits_while_rows_remain(env):
    tid = await terminated_tenant(env)
    run = "manual"
    assert await env.off.complete(run_id=run, tenant_id=tid, now=env.at()) == "remaining"
    assert await env.off.completion(tid) is None


async def test_the_overdue_check_alone_pages_and_deletes_nothing(env):
    """A watcher that runs apart from the deletion job (which may be what is broken)."""
    tid = await terminated_tenant(env)
    alerts = RecordingAlertSink()
    assert await job(env, 30, alerts=alerts).check_overdue() == ()
    assert await job(env, 30, 1, alerts=alerts).check_overdue() == (tid,)
    [page] = alerts.pages()
    assert page.kind == "offboarding_overdue" and tid in page.message
    assert await env.counts(tid) == expected()  # nothing deleted
    assert await env.off.receipts(tid) == []


async def test_completion_waits_for_a_quiet_period_and_a_late_row_is_swept_before_it(env):
    """An in-flight write admitted before the termination can land after the first sweep: the
    receipt is written only by a run that, after the quiet period, finds nothing left."""
    tid = await terminated_tenant(env)
    hour = timedelta(hours=1)

    def run(seconds):
        now = env.at(seconds=seconds)
        return OffboardingJob(env.off, clock=lambda: now, quiesce=hour).run_once()

    first = await run(10)
    assert first.tenants[0].quiescing and not first.tenants[0].completed
    assert sum(first.tenants[0].deleted.values()) == sum(expected().values())
    assert await env.off.completion(tid) is None

    await env.seed(tid, 1)  # the straggler lands after the first sweep
    mid = await run(1800)
    assert mid.tenants[0].quiescing and mid.deleted > 0  # swept again, still not complete

    last = await run(3600)  # exactly the quiet period: enough
    assert last.tenants[0].completed and not last.tenants[0].quiescing
    done = await env.off.completion(tid)
    assert done.counts_by_class["B"] == by_class()["B"] + by_class(1)["B"]
    assert await env.counts(tid) == dict.fromkeys(ALL_TABLES, 0)
