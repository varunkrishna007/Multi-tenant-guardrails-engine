"""M5-07: the usage summary kept when usage rows go, the daily re-sweep after
the completion receipt and the outbox delete limited to the tenant's own kinds.
The unreadable directory is in ``tests/directory/test_m5_07_termination.py``.

Every behaviour test runs against the in-memory environment and, with ``GUARDRAIL_TEST_PG_DSN``,
against Postgres (migrations 043 and 044, the retention role). The job's clock is injected."""

from collections import Counter
from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest
from offboarding_env import (
    ALL_TABLES,
    DAY,
    SEEDED_USAGE,
    MemoryEnv,
    expected,
    make_pg_env,
)

from guardrail_engine.offboarding import (
    RESWEEP_DAYS,
    InMemoryOffboardingStore,
    OffboardingJob,
    OffboardingRefused,
)
from guardrail_engine.offboarding.adapters.postgres import PostgresOffboardingStore


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


def job_at(env, now: datetime, **kw) -> OffboardingJob:
    kw.setdefault("quiesce", timedelta(0))
    return OffboardingJob(env.off, clock=lambda: now, **kw)


async def terminated_tenant(env, slug="acme-co", records=3) -> str:
    tid = await env.new_tenant(slug)
    await env.seed(tid, records)
    await env.terminate(tid)
    return tid


def with_price(env, price) -> None:
    """Swap the env's offboarding store for one that computes the usage cost at ``price``."""
    if env.kind == "memory":
        env.off = InMemoryOffboardingStore(
            env.directory, [env.holder], price_per_million_input_tokens_usd=price
        )
    else:
        env.off = PostgresOffboardingStore(
            env.retention_pool, price_per_million_input_tokens_usd=price
        )


# ------------------------------------------------------------------------------------
def T(y, mo, d, h=0, mi=0):
    return datetime(y, mo, d, h, mi, tzinfo=UTC)


EXTRA_USAGE = (
    ("answered", 1_000_000, T(2026, 1, 15)),
    ("answered", 250_000, T(2026, 2, 3)),
    ("unknown", None, T(2026, 2, 3, 12)),
    ("unanswered", None, T(2026, 2, 28, 23, 59)),
    ("provider_safety", None, T(2026, 3, 1, 0, 0)),
    ("model_skipped", None, T(2026, 3, 1, 0, 1)),
    ("answered", 40, T(2026, 3, 31, 23, 59)),
)


def summarised(rows, price):
    """What the summary must say about ``rows`` ((kind, tokens, at) triples): {(month, class):
    (events, answered_calls, tokens, cost)}."""
    out: dict[tuple[str, str], list] = {}
    for kind, tokens, at in rows:
        agg = out.setdefault((at.strftime("%Y-%m"), kind), [0, 0, 0])
        agg[0] += 1
        agg[1] += kind == "answered"
        agg[2] += tokens or 0
    return {k: (e, a, t, Decimal(t) * Decimal(price) / 1_000_000) for k, (e, a, t) in out.items()}


async def totals(env, tid):
    got: dict[tuple[str, str], list] = {}
    for r in await env.off.usage_summary(tid):
        agg = got.setdefault((r.month, r.usage_class), [0, 0, 0, Decimal(0)])
        agg[0] += r.events
        agg[1] += r.answered_calls
        agg[2] += r.input_tokens
        agg[3] += r.cost_usd
    return {k: tuple(v) for k, v in got.items()}


@pytest.mark.parametrize("batch_size", [1000, 3, 1])
async def test_the_usage_summary_totals_equal_the_deleted_rows(env, batch_size):
    price = Decimal("0.10")
    tid = await terminated_tenant(env)
    await env.add_usage(tid, EXTRA_USAGE)
    rows = [*SEEDED_USAGE, *EXTRA_USAGE]
    other = await env.new_tenant("other-co")
    await env.seed(other)  # another tenant's usage must not leak into this summary
    assert (await env.counts(tid))["usage_events"] == len(rows)

    await job_at(env, env.at(1), batch_size=batch_size).run_once()

    assert (await env.counts(tid))["usage_events"] == 0
    want = summarised(rows, price)
    got = await totals(env, tid)
    assert got == want
    # The summary is the deleted rows: events, answered calls and tokens add up to them exactly.
    assert sum(v[0] for v in got.values()) == len(rows)
    assert sum(v[0] for v in got.values()) == sum(
        r.deleted_count for r in await env.off.receipts(tid) if r.table == "usage_events"
    )
    assert sum(v[1] for v in got.values()) == sum(1 for k, _, _ in rows if k == "answered")
    assert sum(v[2] for v in got.values()) == sum(t or 0 for _, t, _ in rows)
    assert sum(v[3] for v in got.values()) == Decimal(sum(t or 0 for _, t, _ in rows)) / 10_000_000
    assert await env.off.usage_summary(other) == []  # untouched, and nothing written for it


async def test_months_are_utc_calendar_months_and_split_at_midnight(env):
    tid = await terminated_tenant(env)
    await job_at(env, env.at(1)).run_once()
    got = await totals(env, tid)
    # the seeded rows are 23:30 UTC on 31 January and 00:30 UTC on 1 February
    assert got[("2026-01", "answered")][:3] == (1, 1, 5)
    assert got[("2026-02", "answered")][:3] == (1, 1, 7)


async def test_the_cost_is_at_the_configured_price_which_is_kept_beside_it(env):
    with_price(env, "2.50")
    tid = await terminated_tenant(env)
    await env.add_usage(
        tid, [("answered", 2_000_000, T(2026, 1, 2)), ("unknown", None, T(2026, 1, 2))]
    )
    await job_at(env, env.at(1)).run_once()
    rows = await env.off.usage_summary(tid)
    assert {r.price_per_million_usd for r in rows} == {Decimal("2.50")}
    jan = [r for r in rows if r.month == "2026-01"]
    assert (
        sum(r.cost_usd for r in jan)
        == Decimal("5.000000") + Decimal("5") * Decimal("2.5") / 1_000_000
    )
    unknown = [r for r in rows if r.usage_class == "unknown"]
    assert unknown and all(r.cost_usd == 0 and r.input_tokens == 0 for r in unknown)


async def test_a_zero_price_is_allowed_and_a_bad_price_is_refused(env):
    with_price(env, "0")
    tid = await terminated_tenant(env)
    await job_at(env, env.at(1)).run_once()
    assert {r.cost_usd for r in await env.off.usage_summary(tid)} == {Decimal(0)}
    for bad in ("-1", "1000001"):
        with pytest.raises(ValueError):
            with_price(env, bad)


async def test_the_summary_holds_no_content_and_the_raw_rows_are_gone(env):
    tid = await terminated_tenant(env)
    await job_at(env, env.at(1)).run_once()
    assert (await env.counts(tid))["usage_events"] == 0
    for r in await env.off.usage_summary(tid):
        assert set(r.__slots__) == {
            "run_id", "at", "tenant_id", "month", "usage_class", "events", "answered_calls",
            "input_tokens", "price_per_million_usd", "cost_usd",
        }  # fmt: skip


async def test_usage_rows_that_land_late_are_summarised_too(env):
    tid = await terminated_tenant(env)
    base = env.at(1)
    await job_at(env, base).run_once()
    first = await totals(env, tid)
    late = [("answered", 90, T(2026, 1, 9))]
    await env.add_usage(tid, late)
    # (a day after completion: the daily re-sweep deletes it and summarises it)
    done = await env.off.completion(tid)
    if env.kind == "postgres":
        await backdate(env, tid)
        done = await env.off.completion(tid)
    await job_at(env, done.at + DAY).run_once()
    after = await totals(env, tid)
    assert after[("2026-01", "answered")][:3] == (
        first[("2026-01", "answered")][0] + 1,
        first[("2026-01", "answered")][1] + 1,
        first[("2026-01", "answered")][2] + 90,
    )


async def test_postgres_usage_summaries_are_class_a_append_only_and_read_only_to_the_role(env):
    if env.kind != "postgres":
        pytest.skip("Postgres only")
    import asyncpg

    tid, base = await completed(env)
    await job_at(env, base + DAY).run_once()  # one sweep logged
    assert await env.owner.fetchval("SELECT count(*) FROM offboarding_sweeps") == 1
    assert await env.owner.fetchval("SELECT count(*) FROM offboarding_usage_summaries") > 0
    for sql in (
        "UPDATE offboarding_usage_summaries SET events = 9",
        "DELETE FROM offboarding_usage_summaries",
        "TRUNCATE offboarding_usage_summaries",
        "UPDATE offboarding_sweeps SET day = 2",
        "DELETE FROM offboarding_sweeps",
        "TRUNCATE offboarding_sweeps",
    ):
        with pytest.raises(asyncpg.exceptions.RestrictViolationError):
            await env.owner.execute(sql)
    for sql in (
        "DELETE FROM offboarding_usage_summaries",
        f"INSERT INTO offboarding_sweeps VALUES ('{tid}', 1, 'r', now(), 0)",
    ):
        with pytest.raises(asyncpg.InsufficientPrivilegeError):
            await env.retention_pool.execute(sql)
    await env.retention_pool.fetch("SELECT * FROM offboarding_usage_summaries")
    await env.retention_pool.fetch("SELECT * FROM offboarding_sweeps")
    for table in ("offboarding_usage_summaries", "offboarding_sweeps"):
        with pytest.raises(asyncpg.InsufficientPrivilegeError):
            await env.app.fetch(f"SELECT * FROM {table}")


# ------------------------------------------------------------------------------------
async def backdate(env, tid, days=30):
    """Postgres only: the completion receipt's ``at`` is the database's own clock, so to run the
    job's injected clock days after it, move the receipt back (as a superuser, bypassing the
    append-only trigger, which a test may and production never does)."""
    q = f'"{env.schema}".offboarding_completions'
    async with env.admin.transaction():
        await env.admin.execute(f"ALTER TABLE {q} DISABLE TRIGGER USER")
        await env.admin.execute(
            f"UPDATE {q} SET at = at - make_interval(days => $1) WHERE tenant_id = $2", days, tid
        )
        await env.admin.execute(f"ALTER TABLE {q} ENABLE TRIGGER USER")


async def completed(env, slug="acme-co") -> tuple[str, datetime]:
    """A tenant offboarded and completed; returns (tenant id, the completion receipt's time),
    the base the re-sweep days count from."""
    tid = await terminated_tenant(env, slug)
    report = await job_at(env, env.at(0, 5)).run_once()
    assert report.tenants[0].completed
    if env.kind == "postgres":
        await backdate(env, tid)
    return tid, (await env.off.completion(tid)).at


def resweep_receipts(receipts):
    return [r for r in receipts if r.resweep]


async def test_a_late_row_is_deleted_by_the_daily_resweep_with_a_receipt_and_a_log(env):
    tid, base = await completed(env)
    receipts_before = await env.off.receipts(tid)
    assert not resweep_receipts(receipts_before)
    await env.seed(tid, 1)  # a late arrival after the completion receipt
    assert (await env.counts(tid))["decision_records"] == 1

    # not due before day 1
    report = await job_at(env, base + DAY - timedelta(seconds=1)).run_once()
    assert report.resweeps == () and (await env.counts(tid))["decision_records"] == 1
    assert await env.off.sweeps(tid) == []

    report = await job_at(env, base + DAY).run_once()
    [sweep] = report.resweeps
    assert sweep.tenant_id == tid and sweep.day == 1 and sweep.logged and not sweep.more_to_do
    assert sweep.deleted["decision_records"] == 1 and report.deleted == sum(expected(1).values())
    assert await env.counts(tid) == dict.fromkeys(ALL_TABLES, 0)
    late = resweep_receipts(await env.off.receipts(tid))
    assert late and all(r.resweep and r.deleted_count > 0 for r in late)  # none for empty tables
    assert Counter(r.table for r in late)["decision_records"] == 1
    assert {r.table for r in late} == {t for t, n in expected(1).items() if n} | {
        "escalation_items.content"
    }
    assert [(s.day, s.deleted_count) for s in await env.off.sweeps(tid)] == [
        (1, sum(expected(1).values()))
    ]
    # The late usage rows were summarised too, and the completion receipt is untouched
    assert await env.off.completion(tid) is not None


async def test_a_resweep_that_finds_nothing_logs_the_day_and_writes_no_receipt(env):
    tid, base = await completed(env)
    before = await env.off.receipts(tid)
    summary = await env.off.usage_summary(tid)
    report = await job_at(env, base + DAY).run_once()
    [sweep] = report.resweeps
    assert sweep.day == 1 and sweep.logged and sweep.found == 0
    assert await env.off.receipts(tid) == before  # no receipt: nothing was deleted
    assert await env.off.usage_summary(tid) == summary
    assert [(s.day, s.deleted_count) for s in await env.off.sweeps(tid)] == [(1, 0)]


async def test_once_a_day_not_once_a_run(env):
    tid, base = await completed(env)
    for now in (base + DAY, base + DAY + timedelta(hours=1), base + 2 * DAY - timedelta(seconds=1)):
        report = await job_at(env, now).run_once()
        assert len(report.resweeps) == (1 if now == base + DAY else 0)
    assert [s.day for s in await env.off.sweeps(tid)] == [1]
    report = await job_at(env, base + 2 * DAY).run_once()
    assert [r.day for r in report.resweeps] == [2]
    assert [s.day for s in await env.off.sweeps(tid)] == [1, 2]


async def test_seven_daily_sweeps_then_the_tenant_is_final(env):
    tid, base = await completed(env)
    for day in range(1, RESWEEP_DAYS + 1):
        await env.seed(tid, 1)  # something arrives every day
        report = await job_at(env, base + day * DAY).run_once()
        [sweep] = report.resweeps
        assert sweep.day == day and sweep.found == sum(expected(1).values())
        assert await env.counts(tid) == dict.fromkeys(ALL_TABLES, 0)
    assert [s.day for s in await env.off.sweeps(tid)] == list(range(1, 8))
    assert len(resweep_receipts(await env.off.receipts(tid))) > 0

    # After day 7 the tenant is final: a row landing later stays, and nothing looks again.
    await env.seed(tid, 1)
    receipts = await env.off.receipts(tid)
    for later in (7.5, 8, 30, 400):
        report = await job_at(env, base + later * DAY).run_once()
        assert report.resweeps == () and report.deleted == 0
    assert (await env.counts(tid))["decision_records"] == 1
    assert await env.off.receipts(tid) == receipts
    assert [s.day for s in await env.off.sweeps(tid)] == list(range(1, 8))


async def test_a_job_that_was_down_catches_up_with_one_sweep_for_the_latest_day(env):
    tid, base = await completed(env)
    await env.seed(tid, 1)
    report = await job_at(env, base + 4 * DAY + timedelta(hours=3)).run_once()
    [sweep] = report.resweeps
    assert sweep.day == 4 and sweep.found > 0
    assert [s.day for s in await env.off.sweeps(tid)] == [4]
    assert (await job_at(env, base + 4 * DAY + timedelta(hours=4)).run_once()).resweeps == ()
    # long after day 7 without any sweep in between: the day-7 sweep still runs once
    report = await job_at(env, base + 20 * DAY).run_once()
    assert [r.day for r in report.resweeps] == [7]
    assert (await job_at(env, base + 21 * DAY).run_once()).resweeps == ()


async def test_a_tenant_that_is_not_complete_is_not_resweept_and_others_are_untouched(env):
    done_id, base = await completed(env, "done-co")
    active = await env.new_tenant("live-co")
    await env.seed(active)
    waiting = await terminated_tenant(env, "wait-co")  # terminated, not yet completed
    report = await job_at(env, base + DAY, quiesce=timedelta(days=365)).run_once()
    assert [r.tenant_id for r in report.resweeps] == [done_id]
    assert await env.counts(active) == expected()
    assert await env.off.sweeps(active) == [] and await env.off.sweeps(waiting) == []


async def test_a_resweep_that_hits_the_batch_cap_is_not_logged_and_the_next_run_continues(env):
    tid, base = await completed(env)
    await env.seed(tid, 5)
    now = base + DAY
    first = await job_at(env, now, batch_size=2, max_batches_per_table=1).run_once()
    [sweep] = first.resweeps
    assert sweep.more_to_do and not sweep.logged
    assert await env.off.sweeps(tid) == []
    for _ in range(60):
        report = await job_at(env, now, batch_size=2, max_batches_per_table=1).run_once()
        if report.resweeps and report.resweeps[0].logged:
            break
    assert [s.day for s in await env.off.sweeps(tid)] == [1]
    assert await env.counts(tid) == dict.fromkeys(ALL_TABLES, 0)


async def test_a_failing_resweep_is_reported_and_retried(env):
    tid, base = await completed(env)
    await env.seed(tid, 1)

    class Flaky:
        def __init__(self, inner):
            self.inner = inner

        def __getattr__(self, name):
            return getattr(self.inner, name)

        async def delete_batch(self, **kw):
            raise RuntimeError("database down")

    now = base + DAY
    report = await OffboardingJob(Flaky(env.off), clock=lambda: now).run_once()
    assert report.failed == (tid,) and report.resweeps == ()
    assert await env.off.sweeps(tid) == []
    again = await job_at(env, now).run_once()
    assert again.failed == () and [r.day for r in again.resweeps] == [1]


async def test_the_store_refuses_to_log_a_sweep_that_is_not_due_or_for_no_completion(env):
    tid, base = await completed(env)
    other = await terminated_tenant(env, "wait-co")
    args = {"run_id": "r", "deleted": 0}
    with pytest.raises(OffboardingRefused):
        await env.off.log_sweep(tenant_id=tid, day=2, now=base + DAY, **args)  # day 2 not due yet
    with pytest.raises(OffboardingRefused):
        await env.off.log_sweep(tenant_id=other, day=1, now=base + DAY, **args)  # not complete
    for day in (0, 8):
        with pytest.raises(OffboardingRefused):
            await env.off.log_sweep(tenant_id=tid, day=day, now=base + 9 * DAY, **args)
    assert await env.off.log_sweep(tenant_id=tid, day=1, now=base + DAY, **args) is True
    assert await env.off.log_sweep(tenant_id=tid, day=1, now=base + DAY, **args) is False
    assert [s.day for s in await env.off.sweeps(tid)] == [1]


async def test_postgres_sweep_log_refuses_a_clock_ahead_of_the_database(env):
    if env.kind != "postgres":
        pytest.skip("Postgres only")
    tid, _base = await completed(env)
    ahead = datetime.now(UTC) + timedelta(hours=1)
    with pytest.raises(OffboardingRefused):
        await env.off.log_sweep(run_id="r", tenant_id=tid, day=1, deleted=0, now=ahead)
    assert await env.off.sweeps(tid) == []


async def test_the_resweep_receipt_flag_is_false_for_the_first_pass(env):
    tid = await terminated_tenant(env)
    await job_at(env, env.at(0, 5)).run_once()
    assert not any(r.resweep for r in await env.off.receipts(tid))
    done = await env.off.completion(tid)
    assert done.counts_by_class["B"] > 0  # completion counts are those of the first pass


# ------------------------------------------------------------------------------------
async def test_postgres_the_outbox_delete_is_limited_to_usage_and_escalation(env):
    if env.kind != "postgres":
        pytest.skip("Postgres only")
    tid = await terminated_tenant(env)
    other = await env.new_tenant("other-co")
    body = '{"at":1.0,"tenant_id":"%s"}'
    async with env.owner.acquire() as conn:
        for key, kind, who in (
            ("a-alert", "alert", tid),
            ("a-alert2", "alert", tid),
            ("a-esc", "escalation", tid),
            ("a-usage", "usage", tid),
            ("o-alert", "alert", other),
            ("o-usage", "usage", other),
        ):
            await conn.execute(
                "INSERT INTO delivery_outbox (idempotency_key, kind, payload, created_at, "
                "next_attempt_at) VALUES ($1, $2, $3, now(), now())",
                key,
                kind,
                body % who,
            )
    report = await job_at(env, env.at(1)).run_once()
    assert report.tenants[0].completed  # the pending platform alerts don't hold completion up
    left = {
        r["idempotency_key"]: r["state"]
        for r in await env.owner.fetch("SELECT idempotency_key, state FROM delivery_outbox")
    }
    assert left == {
        "a-alert": "pending",
        "a-alert2": "pending",
        "o-alert": "pending",
        "o-usage": "pending",
    }
    receipts = {r.table: r.deleted_count for r in await env.off.receipts(tid)}
    assert receipts["delivery_outbox"] == 2 + 2  # the seed's two usage rows, plus a-esc, a-usage
    # and the direct call agrees: even asked again, the function leaves the platform alerts
    n = await env.retention_pool.fetchval(
        "SELECT offboarding_delete_batch('r2', $1, 'delivery_outbox', 100, 5)", tid
    )
    assert n == 0
    assert (
        await env.owner.fetchval("SELECT count(*) FROM delivery_outbox WHERE kind = 'alert'") == 3
    )
