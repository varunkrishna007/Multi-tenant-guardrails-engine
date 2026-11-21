"""M5-05 the nightly red-team: grouping by configuration, the comparison, the paging, the
fairness of the nightly ceiling, the live gates and the harm refusals. Offline: the fake model and
a stub suite. No live call, no key."""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from guardrail_engine.gateway.sinks import (
    ALERT_REDTEAM_QUARANTINED,
    ALERT_REDTEAM_REGRESSION,
    ALERT_REDTEAM_RUN_FAILED,
    ALERT_REDTEAM_STALE,
    ALERT_REDTEAM_UNASSIGNED,
    AlertSeverity,
    RecordingAlertSink,
)
from guardrail_engine.nightly.model import (
    CORPUS_HOLD_KEY,
    NightlyResult,
    QuarantineEvent,
    row_key,
)
from guardrail_engine.nightly.store import (
    ActiveBundle,
    InMemoryNightlyResults,
    InMemoryQuarantine,
)
from redteam import nightly as nt
from redteam import run as rt

ROOT = Path(__file__).resolve().parents[2]
CORPUS = ROOT / "redteam" / "corpus.jsonl"
D1 = datetime(2026, 11, 20, 3, 0, tzinfo=UTC)
SHA = "sha256:" + "cd" * 32
F1, F2 = "platform/floor@1", "platform/floor@2"
FIN, INS = "domain/finance@1", "domain/insurance@2"


def day(n):
    return D1 + timedelta(days=n)


class Bundles:
    def __init__(self, *bundles):
        self.bundles = list(bundles)

    async def active_bundles(self):
        return list(self.bundles)


class Directory:
    """The tenant directory: ids, and each entry's attributes (M5-06: its dedicated project)."""

    def __init__(self, *ids, projects=None, regulated=()):
        self.ids = list(ids)
        self.projects = dict(projects or {})
        self.regulated = set(regulated)

    async def tenant_ids(self, *, include_suspended=False):
        return list(self.ids)

    async def get(self, tenant_id):
        from types import SimpleNamespace

        return SimpleNamespace(
            attributes=SimpleNamespace(
                project=self.projects.get(tenant_id), regulated=tenant_id in self.regulated
            )
        )


def base_note(result):
    """A result's note without the hold suffix."""
    return result.note.split(";")[0]


def bundle(tenant, floor=F2, *packs, version=1):
    return ActiveBundle(tenant, version, floor, tuple(packs))


def recall(hits, cells=30):
    return {"p__inj_direct": {"hits": hits, "cells": cells, "recall": hits / cells}}


def report(hits=30, violations=None, incomplete=None, excluded=0):
    return {
        "block_recall": recall(hits),
        "false_act": {"overall": {"hits": 0, "cells": 60, "recall": 0}},
        "structure": {"rows_checked": 172, "violations": violations or {}},
        "incomplete": incomplete or {},
        "excluded_cells": excluded,
    }


class StubSuite:
    """A suite whose outcome per configuration is scripted; records which ran, in order."""

    live = False
    corpus_sha256 = SHA
    draws = 3
    rows = 172
    nonce_seed = "a1" * 16

    def __init__(self, outcomes=None):
        self.outcomes = outcomes or {}
        self.ran: list[str] = []
        self.skipped_rows: list[frozenset[str]] = []

    async def run(self, config, skip_rows=frozenset()):
        self.ran.append(config.key)
        self.skipped_rows.append(skip_rows)
        out = self.outcomes.get(config.key)
        if callable(out):
            out = out()
        return out or nt.SuiteOutcome("done", report=report(), provider_calls=516)


def job(
    bundles, suite, *, store=None, alerts=None, now=D1, tenants=None, budget=None, baseline=None,
    projects=None, project_budgets=None, quarantine=None, environment="test", regulated=(),
):  # fmt: skip
    store = store or InMemoryNightlyResults()
    alerts = alerts if alerts is not None else RecordingAlertSink()
    clock = {"now": now}
    j = nt.NightlyJob(
        bundles=Bundles(*bundles),
        directory=Directory(
            *(tenants or {b.tenant_id for b in bundles}), projects=projects, regulated=regulated
        ),
        quarantine=quarantine, environment=environment,
        project_budgets=project_budgets,
        results=store, sink=store, alerts=alerts, suite=suite, baseline=baseline,
        clock=lambda: clock["now"], call_budget=budget,
        run_id_factory=iter(f"run{i}" for i in range(99)).__next__,
    )  # fmt: skip
    return j, store, alerts, clock


# ------------------------------------------------------------------ configurations


def test_active_versions_are_grouped_by_floor_and_packs_and_inactive_tenants_are_left_out():
    configs = nt.group(
        [
            bundle("t_a", F2, FIN), bundle("t_b", F2, FIN, version=3), bundle("t_c", F2),
            bundle("t_d", F1, FIN), bundle("t_gone", F2),
        ],
        {"t_a", "t_b", "t_c", "t_d"},
    )  # fmt: skip
    assert {c.key: c.tenants for c in configs} == {
        f"{F2}+{FIN}": (("t_a", 1), ("t_b", 3)), F2: (("t_c", 1),), f"{F1}+{FIN}": (("t_d", 1),),
    }  # fmt: skip
    assert nt.parse_config(f"{F2},{FIN}").key == f"{F2}+{FIN}"
    with pytest.raises(rt.Refused):
        nt.parse_config(FIN)


# ------------------------------------------------------------------ results per version


async def test_a_tested_night_records_a_result_for_every_tenant_version_of_a_configuration():
    suite = StubSuite()
    j, store, alerts, _ = job(
        [bundle("t_a", F2, FIN), bundle("t_b", F2, FIN, version=3), bundle("t_c", F2)], suite
    )
    r = await j.run_once()
    assert sorted(suite.ran) == sorted([F2, f"{F2}+{FIN}"])  # one run per configuration
    rows = {(x.tenant_id, x.bundle_version): x for x in store.all()}
    assert set(rows) == {("t_a", 1), ("t_b", 3), ("t_c", 1)} and r.results == 3
    one = rows[("t_a", 1)]
    assert (one.status, one.mode, one.floor_version, one.packs, one.draws, one.rows) == (
        "pass", "fake", 2, (FIN,), 3, 172,
    )  # fmt: skip
    assert one.block_recall == {"p__inj_direct": {"hits": 30, "cells": 30}}
    assert alerts.alerts == [] and r.tested and not r.regressions


# ------------------------------------------------------------------ the comparison and the page


async def test_a_loss_of_more_than_one_cell_against_the_previous_night_pages_on_call():
    suite = StubSuite()
    j, store, alerts, clock = job([bundle("t_a"), bundle("t_b", version=2)], suite)
    await j.run_once()
    clock["now"] = day(1)
    suite.outcomes[F2] = nt.SuiteOutcome("done", report=report(hits=28), provider_calls=516)
    r = await j.run_once()
    assert list(r.regressions) == [F2]
    (reg,) = r.regressions[F2]
    assert (reg["vs"], reg["rule"], reg["lost_cells"]) == ("previous", "p__inj_direct", 2)
    latest = await store.latest_per_tenant(status=None, after=None, limit=10)
    assert [(x.tenant_id, x.status) for x in latest] == [
        ("t_a", "regression"),
        ("t_b", "regression"),
    ]
    (page,) = alerts.alerts
    assert page.kind == ALERT_REDTEAM_REGRESSION and page.severity is AlertSeverity.PAGE
    assert page.tenant_id == "" and "t_a" in page.message and "p__inj_direct" in page.message
    assert page.dedupe_key == f"redteam_regression:{F2}:{day(1).date().isoformat()}"


async def test_one_cell_is_the_tolerance_and_a_recovery_pages_nothing():
    suite = StubSuite()
    j, store, alerts, clock = job([bundle("t_a")], suite)
    await j.run_once()
    clock["now"] = day(1)
    suite.outcomes[F2] = nt.SuiteOutcome("done", report=report(hits=29), provider_calls=1)
    assert (await j.run_once()).regressions == {} and alerts.alerts == []
    clock["now"] = day(2)
    suite.outcomes[F2] = nt.SuiteOutcome("done", report=report(hits=30), provider_calls=1)
    await j.run_once()
    assert [x.status for x in store.all()] == ["pass", "pass", "pass"]


async def test_the_release_baseline_is_compared_only_for_its_floor_corpus_and_draws():
    baseline = {
        "corpus_sha256": SHA, "draws": 3, "floor_version": 2, "block_recall": recall(30),
        "nonce_seed": StubSuite.nonce_seed,
    }  # fmt: skip
    low = {F2: nt.SuiteOutcome("done", report=report(hits=27)),
           F1: nt.SuiteOutcome("done", report=report(hits=27))}  # fmt: skip
    suite = StubSuite(low)
    j, *_ = job([bundle("t_a", F2), bundle("t_b", F1)], suite, baseline=baseline)
    r = await j.run_once()
    assert list(r.regressions) == [F2]  # floor@1 isn't the baseline's floor
    assert r.regressions[F2][0]["vs"] == "baseline"
    # another corpus or other draws: not like-for-like, not compared
    for changed in ({**baseline, "corpus_sha256": "sha256:" + "00" * 32}, {**baseline, "draws": 1}):
        suite2 = StubSuite({F2: nt.SuiteOutcome("done", report=report(hits=0))})
        j2, *_ = job([bundle("t_a", F2)], suite2, baseline=changed)
        assert (await j2.run_once()).regressions == {}


async def test_a_failed_model_independent_defence_is_a_regression():
    suite = StubSuite({F2: nt.SuiteOutcome("done", report=report(violations={"rt-1": ["x"]}))})
    j, store, alerts, _ = job([bundle("t_a")], suite)
    r = await j.run_once()
    assert r.regressions[F2] == [{"defence": 1, "vs": "defences"}]
    assert store.all()[0].status == "regression" and store.all()[0].structure_violations == 1
    assert [a.kind for a in alerts.alerts] == [ALERT_REDTEAM_REGRESSION]


async def test_an_incomplete_run_is_refused_not_judged():
    suite = StubSuite({F2: nt.SuiteOutcome("done", report=report(incomplete={"rt-1": 1}))})
    j, store, alerts, _ = job([bundle("t_a")], suite)
    r = await j.run_once()
    (row,) = store.all()
    assert (row.status, row.note) == ("refused", "incomplete") and r.regressions == {}
    assert [a.kind for a in alerts.alerts] == [ALERT_REDTEAM_RUN_FAILED]


# ------------------------------------------------------------------ the ceiling, fairness, stale


async def test_a_ceiling_skips_the_rest_and_the_oldest_tested_go_first_the_next_night():
    configs = [bundle(f"t_{c}", F2, p) for c, p in (("a", "domain/a@1"), ("b", "domain/b@1"),
                                                     ("c", "domain/c@1"))]  # fmt: skip
    suite = StubSuite()
    j, store, _, clock = job(configs, suite, budget=520)  # room for one run of 516
    tested = []
    for n in range(3):
        clock["now"] = day(n)
        r = await j.run_once()
        tested += r.tested
        assert len(r.tested) == 1 and len(r.skipped) == 2  # one a night
    assert sorted(tested) == sorted(f"{F2}+domain/{c}@1" for c in "abc")  # every one, in 3 nights
    skipped = [x for x in store.all() if x.status == "refused"]
    assert skipped and {x.note for x in skipped} == {nt.SKIPPED}


async def test_a_configuration_newly_made_active_jumps_the_queue():
    suite = StubSuite()
    old = [bundle("t_a", F2, "domain/a@1"), bundle("t_b", F2, "domain/b@1")]
    j, _, _, clock = job(old, suite, budget=520)
    await j.run_once()
    clock["now"] = day(1)
    await j.run_once()  # both tested by now
    j._bundles.bundles.append(bundle("t_new", F2, "domain/new@1"))
    j._directory.ids.append("t_new")
    clock["now"] = day(2)
    suite.ran.clear()
    await j.run_once()
    assert suite.ran == [f"{F2}+domain/new@1"]  # never tested: first, before the oldest-tested


def test_never_tested_come_first_then_the_oldest_tested():
    from guardrail_engine.nightly.store import ConfigDates

    a, b, c = (nt.Config(F2, (f"domain/{x}@1",)) for x in "abc")
    dates = {
        a.key: ConfigDates(day(5), day(0)), b.key: ConfigDates(day(2), day(0)),
        c.key: ConfigDates(None, day(6)),
    }  # fmt: skip
    assert [x.key for x in nt.order_configs([a, b, c], dates)] == [c.key, b.key, a.key]


async def test_a_configuration_untested_for_more_than_seven_nights_pages_once_a_day():
    suite = StubSuite()
    two = [bundle("t_a", F2, "domain/a@1"), bundle("t_b", F2, "domain/b@1")]
    j, store, alerts, clock = job(two, suite, budget=520)
    await j.run_once()  # night 0: one tested, one skipped (the other never tested)
    skipped_key = next(x.config_key for x in store.all() if x.status == "refused")
    # it never gets a run: it is skipped every night while the other one is always taken first
    original_order = nt.order_configs
    nt.order_configs = lambda configs, dates: sorted(configs, key=lambda c: c.key == skipped_key)
    try:
        for n in range(1, 9):
            clock["now"] = day(n)
            alerts.alerts.clear()
            r = await j.run_once()
            stale = [a for a in alerts.alerts if a.kind == ALERT_REDTEAM_STALE]
            if n <= 7:
                assert not stale, n
            else:
                assert len(stale) == 1 and skipped_key in stale[0].message
                assert stale[0].severity is AlertSeverity.PAGE and r.stale == [skipped_key]
    finally:
        nt.order_configs = original_order


REFUSAL = nt.SuiteOutcome("stopped", "provider_refusal", provider_refusal=True, provider_calls=3)
ROW_X = "rt-dir-001"
REFUSAL_ON_X = nt.SuiteOutcome(
    "stopped", "provider_refusal", provider_refusal=True, provider_calls=3, refused_row=ROW_X
)


async def test_a_provider_refusal_quarantines_the_configuration_and_pages_at_once():
    suite = StubSuite({F1: REFUSAL})
    q = InMemoryQuarantine()
    j, store, alerts, _ = job([bundle("t_a", F1), bundle("t_b", F2, FIN)], suite, quarantine=q)
    r = await j.run_once()
    assert suite.ran == [F1] and r.halted and r.quarantined == [F1]
    by = {x.config_key: x for x in store.all()}
    assert by[F1].status == "stopped" and base_note(by[F1]) == "provider_refusal"
    assert base_note(by[f"{F2}+{FIN}"]) == nt.NIGHT_HALTED  # nothing else is sent tonight
    held = await q.quarantined("fake")
    # The refusal named no row, so the whole live corpus is held with the configuration
    assert (
        set(held) == {F1, CORPUS_HOLD_KEY}
        and held[F1].actor == "nightly"
        and held[F1].run_id == r.run_id
    )
    pages = [a for a in alerts.alerts if a.kind == ALERT_REDTEAM_QUARANTINED]
    assert len(pages) == 1 and pages[0].severity is AlertSeverity.PAGE and F1 in pages[0].message


async def test_a_refusal_ends_the_whole_night_in_every_project_and_they_go_first_next_night():
    suite = StubSuite({"acme|" + F1: REFUSAL_ON_X})  # sorts first among everyone's
    bundles = [bundle("t_a", F2), bundle("t_a2", F1), bundle("t_b", F2), bundle("t_c", F1, FIN)]
    j, store, _, clock = job(bundles, suite, projects={"t_a": "acme", "t_a2": "acme"})
    r = await j.run_once()
    assert suite.ran == ["acme|" + F1] and r.halted  # the shared pool too: nothing else is sent
    notes = {x.tenant_id: base_note(x) for x in store.all()}
    assert notes == {"t_a": nt.NIGHT_HALTED, "t_a2": "provider_refusal", "t_b": nt.NIGHT_HALTED,
                     "t_c": nt.NIGHT_HALTED}  # fmt: skip
    clock["now"] = day(1)
    r = await j.run_once()  # untested, so first; the refused one is held
    assert "acme|" + F1 not in suite.ran[1:] and len(suite.ran) == 4 and not r.halted


async def test_a_quarantined_configuration_is_never_re_sent_in_ten_nights_and_the_rest_run():
    # One project with four configurations; the first (by the fairness order) is refused.
    keys = [f"acme|{F1}", f"acme|{F2}", f"acme|{F2}+{FIN}", f"acme|{F2}+{FIN}+{INS}"]
    suite = StubSuite({keys[0]: REFUSAL_ON_X})
    bundles = [
        bundle("t_1", F1), bundle("t_2", F2), bundle("t_3", F2, FIN), bundle("t_4", F2, FIN, INS),
        bundle("t_s", F2),  # the shared pool, a project of its own
    ]  # fmt: skip
    projects = {"t_1": "acme", "t_2": "acme", "t_3": "acme", "t_4": "acme"}
    q = InMemoryQuarantine()
    j, store, alerts, clock = job(bundles, suite, projects=projects, quarantine=q)
    tested: set[str] = set()
    for n in range(10):
        clock["now"] = day(n)
        r = await j.run_once()
        tested |= set(r.tested)
    assert suite.ran.count(keys[0]) == 1  # sent once, refused, never again
    assert set(keys[1:]) <= tested and F2 in tested  # every other configuration was tested
    first = [a for a in alerts.alerts if a.dedupe_key == f"redteam_quarantined:{keys[0]}"]
    assert len(first) == 1  # paged at once; the hold's daily re-pages are other pages
    assert set(await q.quarantined("fake")) == {keys[0], row_key(ROW_X)}
    last = [x for x in store.all() if x.config_key == keys[0]][-1]
    assert last.status == "refused" and base_note(last) == nt.QUARANTINED


async def test_an_operators_clear_lets_the_configuration_run_again():
    suite = StubSuite({F1: REFUSAL_ON_X})
    q = InMemoryQuarantine()
    j, _, _, clock = job([bundle("t_a", F1)], suite, quarantine=q)
    await j.run_once()
    clock["now"] = day(1)
    await j.run_once()
    assert suite.ran == [F1]  # not re-sent
    await q.append(
        QuarantineEvent(F1, "fake", "", "clear", day(1), "idp#ops", True, "provider confirmed")
    )
    suite.outcomes.clear()
    clock["now"] = day(2)
    r = await j.run_once()
    assert suite.ran == [F1, F1] and r.tested == [F1]


async def test_a_quarantine_that_cannot_be_recorded_stops_the_night():
    class Broken(InMemoryQuarantine):
        async def append(self, event):
            raise RuntimeError("the store is down")

    suite = StubSuite({F1: REFUSAL})
    j, _, alerts, _ = job(
        [bundle("t_a", F1), bundle("t_b", F2), bundle("t_c", F2, FIN)], suite, quarantine=Broken()
    )
    await j.run_once()
    assert suite.ran == [F1]
    page = next(a for a in alerts.alerts if a.kind == ALERT_REDTEAM_QUARANTINED)
    assert "COULD NOT BE RECORDED" in page.message


def test_a_live_night_without_a_quarantine_store_is_refused():
    class Live(StubSuite):
        live = True

    with pytest.raises(ValueError, match="quarantine"):
        nt.NightlyJob(
            bundles=Bundles(), directory=Directory(), results=InMemoryNightlyResults(),
            sink=InMemoryNightlyResults(), alerts=RecordingAlertSink(), suite=Live(),
            baseline=None, clock=lambda: D1,
        )  # fmt: skip


# ------------------------------------------------------------------ like-for-like nights
def test_a_previous_night_with_another_nonce_seed_is_not_compared():
    prev = NightlyResult(
        tenant_id="t", bundle_version=1, config_key=F2, run_id="r", run_at=D1, mode="fake",
        floor_version=2, packs=(), corpus_sha256=SHA, draws=3, rows=172, status="pass",
        regressions=(), block_recall=recall(30), false_act={}, structure_violations=0,
        provider_calls=0, input_tokens=0, note="", nonce_seed="a1" * 16,
    )  # fmt: skip
    worse = report(hits=20)
    assert nt.compare(worse, prev, None, SHA, 3, 2, "a1" * 16)  # same seed: compared
    assert nt.compare(worse, prev, None, SHA, 3, 2, "b2" * 16) == []  # another seed: not


def test_a_baseline_with_another_nonce_seed_is_not_compared():
    base = {"corpus_sha256": SHA, "draws": 3, "floor_version": 2, "nonce_seed": "a1" * 16,
            "block_recall": recall(30)}  # fmt: skip
    assert nt.compare(report(hits=20), None, base, SHA, 3, 2, "a1" * 16)
    assert nt.compare(report(hits=20), None, base, SHA, 3, 2, "b2" * 16) == []


# ------------------------------------------------------------------ regulated, no project
async def test_a_regulated_tenant_without_a_project_is_skipped_and_paged_in_production():
    for env in ("production", "staging"):
        suite = StubSuite()
        j, store, alerts, _ = job(
            [bundle("t_reg", F2), bundle("t_std", F2), bundle("t_ded", F2)],
            suite, environment=env, regulated={"t_reg", "t_ded"}, projects={"t_ded": "acme"},
        )  # fmt: skip
        r = await j.run_once()
        assert sorted(suite.ran) == sorted([F2, f"acme|{F2}"])  # t_reg is in neither
        by = {x.tenant_id: x for x in store.all()}
        shared = by["t_std"]
        assert shared.tenant_id == "t_std" and by["t_reg"].note == nt.UNASSIGNED
        assert by["t_reg"].status == "refused" and by["t_reg"].config_key.startswith("unassigned|")
        assert [x.tenant_id for x in store.all() if x.config_key == F2] == ["t_std"]
        assert r.unassigned == ["t_reg"]
        page = [a for a in alerts.alerts if a.kind == ALERT_REDTEAM_UNASSIGNED]
        assert len(page) == 1 and page[0].severity is AlertSeverity.PAGE
        assert "t_reg" in page[0].message


async def test_in_the_test_environment_a_regulated_tenant_stays_in_the_shared_pool():
    suite = StubSuite()
    j, _, alerts, _ = job([bundle("t_reg", F2)], suite, environment="test", regulated={"t_reg"})
    r = await j.run_once()
    assert suite.ran == [F2] and not r.unassigned
    assert not [a for a in alerts.alerts if a.kind == ALERT_REDTEAM_UNASSIGNED]


@pytest.fixture(scope="module")
def catalog():
    return nt.repo_catalog(ROOT)


def harness(catalog, **kw):
    return nt.HarnessSuite(catalog=catalog, corpus=CORPUS, **kw)


async def test_a_dry_run_through_the_real_harness_replays_the_fake_baseline(catalog):
    suite = harness(catalog)
    baseline = rt.load_baseline(ROOT / "redteam" / "baseline.fake.json")
    assert (suite.draws, suite.seed) == (baseline["draws"], baseline["nonce_seed"])
    out = await suite.run(nt.Config(F2, ()))
    assert out.status == "done" and out.provider_calls == 516
    assert out.report["block_recall"] == baseline["block_recall"]  # the oracle, the same cells
    assert nt.compare(out.report, None, baseline, suite.corpus_sha256, 3, 2, suite.seed) == []


async def test_the_configuration_with_packs_runs_on_a_synthetic_tenant_with_the_packs(catalog):
    suite = harness(catalog)
    plain = await suite.run(nt.Config(F2, ()))
    packed = await suite.run(nt.Config(F2, (INS,)))
    assert packed.status == "done" and packed.report["block_recall"] == plain.report["block_recall"]
    assert (await suite.run(nt.Config(F2, ("domain/ghost@1",)))).note == "catalog_missing"
    assert (await suite.run(nt.Config("platform/floor@9", ()))).note == "catalog_missing"


async def test_a_floor_without_a_labelled_rule_is_judged_on_the_rules_it_has(catalog):
    out = await harness(catalog).run(nt.Config(F1, ()))
    assert out.status == "done"
    floor_keys = {r["key"] for r in catalog.floor(1).document["rules"]}
    assert set(out.report["block_recall"]) <= floor_keys


async def test_end_to_end_one_lost_cell_is_tolerated_and_a_rule_that_stops_catching_pages(catalog):
    store, alerts = InMemoryNightlyResults(), RecordingAlertSink()
    rows = rt.load_corpus(CORPUS)
    rule_rows = [r["id"] for r in rows if "p__inj_direct" in r["fires"]]
    baseline = rt.load_baseline(ROOT / "redteam" / "baseline.fake.json")
    clock = {"now": D1}

    async def night(n, misses=frozenset()):
        clock["now"] = day(n)
        suite = harness(catalog, model_factory=lambda r: rt.OracleModel(r, misses=misses))
        j = nt.NightlyJob(
            bundles=Bundles(bundle("t_a")), directory=Directory("t_a"), results=store,
            sink=store, alerts=alerts, suite=suite, baseline=baseline, clock=lambda: clock["now"],
        )  # fmt: skip
        return await j.run_once()

    assert (await night(0)).regressions == {}
    one = frozenset({(rule_rows[0], "p__inj_direct")})  # one row, every draw: three cells
    assert F2 in (await night(1, one)).regressions  # three cells lost is more than the tolerance
    alerts.alerts.clear()
    every = frozenset((rid, "p__inj_direct") for rid in rule_rows)
    r = await night(2, every)
    assert {x["vs"] for x in r.regressions[F2]} == {"previous", "baseline"}
    assert [a.kind for a in alerts.alerts] == [ALERT_REDTEAM_REGRESSION]
    assert [x.status for x in store.all()] == ["pass", "regression", "regression"]


async def test_a_dry_run_on_a_dedicated_project_runs_through_that_projects_backend(catalog):
    suite = harness(catalog)
    out = await suite.run(nt.Config(F2, (), "reg-acme"))
    assert out.status == "done" and out.provider_calls == 516
    plain = await suite.run(nt.Config(F2, ()))
    assert out.report["block_recall"] == plain.report["block_recall"]


async def test_a_live_run_on_a_project_whose_key_is_unset_is_refused_before_anything_is_built(
    catalog, monkeypatch
):
    monkeypatch.setenv(nt.LIVE_ENV, nt.LIVE_TOKEN)
    monkeypatch.setenv("GEMINI_API_KEY", "x" * 39)  # a placeholder, never sent: nothing is run
    monkeypatch.delenv("GEMINI_KEY_REG_ACME", raising=False)
    suite = harness(catalog, live=True, max_tokens=2_000_000, max_provider_calls=2_000)
    out = await suite.run(nt.Config(F2, (), "reg-acme"))
    assert (out.status, out.note, out.provider_calls) == ("refused", "project_key_missing", 0)


# ------------------------------------------------------------------ the gates and the harm refusals


def test_a_live_suite_needs_every_gate(catalog, monkeypatch, tmp_path):
    monkeypatch.delenv(nt.LIVE_ENV, raising=False)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    with pytest.raises(rt.Refused, match=nt.LIVE_ENV):
        harness(catalog, live=True, max_tokens=1, max_provider_calls=1)
    monkeypatch.setenv(nt.LIVE_ENV, nt.LIVE_TOKEN)
    with pytest.raises(rt.Refused, match="--max-tokens"):
        harness(catalog, live=True)
    monkeypatch.setattr(nt, "default_env_file", lambda: None)
    with pytest.raises(rt.Refused, match="GEMINI_API_KEY"):
        harness(catalog, live=True, max_tokens=1_000_000, max_provider_calls=2_000,
                env_file=tmp_path / "none.env")  # fmt: skip


def test_the_only_corpus_is_the_red_team_corpus_and_a_harm_row_refuses_the_whole_run(
    catalog, tmp_path
):
    other = tmp_path / "golden.jsonl"
    other.write_text("{}\n")
    with pytest.raises(rt.Refused):
        nt.HarnessSuite(catalog=catalog, corpus=other)
    root = tmp_path / "root"
    (root / "redteam").mkdir(parents=True)
    rows = [json.loads(x) for x in CORPUS.read_text().splitlines()]
    rows[0] = {**rows[0], "no_live_run": True}
    (root / "redteam" / "corpus.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows))
    with pytest.raises(rt.Refused):
        nt.HarnessSuite(catalog=catalog, corpus=root / "redteam" / "corpus.jsonl", root=root)


class KeyRecorder(rt.OracleModel):
    def __init__(self, rows):
        super().__init__(rows)
        self.asked: set[str] = set()

    async def decide(self, text, questions):
        self.asked.update(questions)
        return await super().decide(text, questions)


async def test_the_responsible_ai_packs_harm_facilitation_question_is_never_sent(catalog):
    rai = "domain/responsible_ai@1"
    models: list[KeyRecorder] = []

    def factory(rows):
        models.append(KeyRecorder(rows))
        return models[-1]

    suite = harness(catalog, model_factory=factory)
    out = await suite.run(nt.Config(F2, (rai,)))
    assert out.status == "done"
    assert "d__harm_facilitation" not in models[0].asked and "d__vulnerability" in models[0].asked
    # and if the opt-out were ever lost, the compiled question is refused before anything is sent
    suite.overrides_for = lambda packs: []  # type: ignore[method-assign]
    refused = await suite.run(nt.Config(F2, (rai,)))
    assert (refused.status, refused.note) == ("refused", "harm_facilitation_question")
    assert len(models) == 1  # no second engine was ever given a model


def test_a_live_pack_whose_own_text_trips_the_tripwire_is_refused_except_responsible_ai(catalog):
    suite = harness(catalog)
    rai = catalog.pack("responsible_ai", 1)
    assert suite.live_pack_problems([rai]) == []  # classifier questions that name harms: decided
    assert suite.live_pack_problems([catalog.pack("insurance", 2)]) == []


def test_the_estimate_counts_the_questions_the_packs_add_and_the_cli_plans_without_calls(
    catalog, capsys
):
    suite = harness(catalog)
    plain = nt.estimate(suite, nt.parse_config(F2))
    packed = nt.estimate(suite, nt.parse_config(f"{F2},{INS}"))
    assert plain["checks"] == packed["checks"] == 516 and plain["worst_case_provider_calls"] == 1032
    assert 400_000 < plain["input_tokens"] < packed["input_tokens"] < 800_000
    assert 0.03 < plain["cost_usd"] < packed["cost_usd"] < 0.10
    assert nt.estimate(suite, nt.parse_config(f"{F2},domain/ghost@1"))["note"] == "catalog_missing"
    assert nt.main(["plan", "--config", f"{F2},{INS}"]) == 0
    assert json.loads(capsys.readouterr().out)[0]["config"] == f"{F2}+{INS}"
    assert nt.main(["plan", "--config", "domain/finance@1"]) == rt.EXIT_REFUSED


# ------------------------------------------------------------------
async def test_a_results_write_that_fails_on_the_refused_row_still_holds_and_pages():
    class FlakySink(InMemoryNightlyResults):
        async def append_many(self, results):
            if any(r.status == "stopped" for r in results):
                raise RuntimeError("db down")
            await super().append_many(results)

    suite = StubSuite({F1: REFUSAL_ON_X})
    q, sink = InMemoryQuarantine(), FlakySink()
    j, _, alerts, clock = job(
        [bundle("t_a", F1), bundle("t_b", F2)], suite, store=sink, quarantine=q
    )
    r = await j.run_once()  # does not raise
    assert suite.ran == [F1] and r.halted
    assert set(await q.quarantined("fake")) == {F1, row_key(ROW_X)}
    assert len([a for a in alerts.alerts if a.kind == ALERT_REDTEAM_QUARANTINED]) == 1
    clock["now"] = day(1)
    await j.run_once()  # the sink is still down for 'stopped' rows, but nothing is stopped now
    assert F1 not in suite.ran[1:]  # night 1 does not run the refused configuration


async def test_a_refused_row_is_held_across_configurations_projects_and_nights():
    suite = StubSuite({"p1|" + F1: REFUSAL_ON_X})
    bundles = [bundle("t_1", F1), bundle("t_2", F2), bundle("t_3", F2, FIN), bundle("t_s", F2)]
    projects = {"t_1": "p1", "t_2": "p2", "t_3": "p3"}
    q = InMemoryQuarantine()
    j, _, alerts, clock = job(bundles, suite, projects=projects, quarantine=q)
    r = await j.run_once()
    assert suite.ran == ["p1|" + F1]  # one send in one night, whatever the projects
    assert r.held_rows == [ROW_X] and set(await q.quarantined("fake")) == {
        "p1|" + F1,
        row_key(ROW_X),
    }
    page = next(a for a in alerts.alerts if a.kind == ALERT_REDTEAM_QUARANTINED)
    assert ROW_X in page.message
    for n in range(1, 5):  # later nights: every other configuration runs, without the row
        clock["now"] = day(n)
        await j.run_once()
    later = suite.skipped_rows[1:]
    assert later and all(rows == {ROW_X} for rows in later)
    assert set(suite.ran[1:]) == {f"p2|{F2}", f"p3|{F2}+{FIN}", F2}  # and are tested
    assert "p1|" + F1 not in suite.ran[1:]
    # a configuration that appears later gets the row left out too
    j._bundles.bundles.append(bundle("t_new", F2, INS))
    j._directory.ids.append("t_new")
    suite.skipped_rows.clear()
    clock["now"] = day(6)
    await j.run_once()
    assert suite.skipped_rows and all(rows == {ROW_X} for rows in suite.skipped_rows)
    # an operator's clear of the row takes the hold off it
    await q.append(
        QuarantineEvent(
            row_key(ROW_X), "fake", "", "clear", day(7), "idp#ops", True, "reviewed", row_id=ROW_X
        )
    )
    suite.skipped_rows.clear()
    clock["now"] = day(8)
    await j.run_once()
    assert all(rows == frozenset() for rows in suite.skipped_rows)


async def test_the_harness_leaves_a_held_row_out_and_never_sends_it(catalog):
    models: list[rt.OracleModel] = []

    def factory(rows):
        models.append(rt.OracleModel(rows))
        return models[-1]

    suite = harness(catalog, model_factory=factory)
    full = await suite.run(nt.Config(F2, ()))
    held = await suite.run(nt.Config(F2, ()), frozenset({ROW_X}))
    sent = {(models[1].row_for(t) or {}).get("id") for t in models[1].sent}
    assert ROW_X in {(models[0].row_for(t) or {}).get("id") for t in models[0].sent}
    assert ROW_X not in sent
    assert held.rows == suite.rows - 1
    assert held.corpus_sha256 != suite.corpus_sha256 and held.corpus_sha256.startswith("sha256:")
    assert held.provider_calls == full.provider_calls - 3  # one row, three draws
    # a night that left a row out is not compared with the baseline's full corpus
    baseline = rt.load_baseline(ROOT / "redteam" / "baseline.fake.json")
    assert nt.compare(held.report, None, baseline, held.corpus_sha256, 3, 2, suite.seed) == []
    every = frozenset(r["id"] for r in suite.rows_data)
    assert (await suite.run(nt.Config(F2, ()), every)).note == "no_rows_left"


async def test_a_provider_refusal_through_the_harness_names_the_row(catalog):
    from guardrail_engine.decision.port import SafetyBlocked

    class Refusing(rt.OracleModel):
        async def decide(self, text, questions):
            row = self.row_for(text)
            if row is not None and row["id"] == ROW_X:
                return SafetyBlocked(reason="prohibited_content")
            return await super().decide(text, questions)

    out = await harness(catalog, model_factory=Refusing).run(nt.Config(F2, ()))
    assert out.provider_refusal and out.refused_row == ROW_X


def test_a_refused_row_id_must_be_a_plain_id(tmp_path):
    path = tmp_path / "run.jsonl"
    path.write_text(json.dumps({"type": "run_stopped", "example_id": ROW_X}) + "\n")
    assert nt.refused_row(path) == ROW_X
    path.write_text(json.dumps({"type": "run_stopped", "example_id": "a b; drop"}) + "\n")
    assert nt.refused_row(path) == ""


async def test_the_cli_refuses_a_held_configuration_or_row_unless_overridden(
    catalog, monkeypatch, capsys
):
    class Dry:
        live = True

        def __init__(self, **kw):
            pass

    ran = []

    async def fake_dry(suite, configs):
        ran.append([c.key for c in configs])
        return {}

    async def held(configs):
        return [F1, row_key(ROW_X)]

    monkeypatch.setattr(nt, "HarnessSuite", Dry)
    monkeypatch.setattr(nt, "_dry_run", fake_dry)
    monkeypatch.setattr(nt, "_held_by_quarantine", held)
    args = ["run", "--live", "--config", F1, "--max-tokens", "1", "--max-provider-calls", "1"]
    assert await asyncio.to_thread(nt.main, args) == rt.EXIT_REFUSED and not ran
    assert "held in quarantine" in capsys.readouterr().err
    assert await asyncio.to_thread(nt.main, [*args, "--override-quarantine"]) == 0
    assert ran == [[F1]]


async def test_a_live_cli_run_that_cannot_read_the_quarantine_is_refused(monkeypatch):
    monkeypatch.delenv("GUARDRAIL_PG_OPERATOR_DSN", raising=False)
    with pytest.raises(rt.Refused, match="GUARDRAIL_PG_OPERATOR_DSN"):
        await nt._held_by_quarantine([nt.Config(F2, ())])


# ------------------------------------------------------------------
async def test_a_refusal_with_no_row_id_holds_the_whole_corpus_until_an_operator_clears():
    suite = StubSuite({F1: REFUSAL})  # the provider refused, and the run named no row
    bundles = [bundle("t_a", F1), bundle("t_b", F2), bundle("t_c", F2, FIN)]
    q = InMemoryQuarantine()
    j, store, alerts, clock = job(bundles, suite, quarantine=q)
    r = await j.run_once()
    assert suite.ran == [F1] and r.halted  # nothing else is sent tonight
    held = await q.quarantined("fake")
    assert set(held) == {F1, CORPUS_HOLD_KEY} and held[CORPUS_HOLD_KEY].row_id == ""
    assert r.held_rows == ["*"]
    first = [a for a in alerts.alerts if a.kind == ALERT_REDTEAM_QUARANTINED]
    assert len(first) == 1 and first[0].severity is AlertSeverity.PAGE  # as for any refusal
    assert "whole live corpus" in first[0].message
    for n in range(1, 6):  # no later night sends anything, under any configuration
        clock["now"] = day(n)
        r = await j.run_once()
        assert not r.tested and not r.halted
    assert suite.ran == [F1]
    last = [x for x in store.all() if x.run_id == r.run_id]
    assert {base_note(x) for x in last} == {nt.QUARANTINED, nt.CORPUS_HELD}
    assert all("held_rows: [*]" in x.note for x in last)
    # an operator clears the corpus hold (and the configuration's): the nights run again
    for key in (CORPUS_HOLD_KEY, F1):
        await q.append(
            QuarantineEvent(key, "fake", "", "clear", day(6), "idp#ops", True, "provider confirmed")
        )
    suite.outcomes.clear()
    clock["now"] = day(7)
    r = await j.run_once()
    assert sorted(r.tested) == sorted([F1, F2, f"{F2}+{FIN}"])
    assert suite.skipped_rows[-1] == frozenset()
    assert all(";" not in x.note for x in store.all() if x.run_id == r.run_id)


async def test_a_corpus_hold_from_a_dedicated_project_stops_the_shared_pool_too():
    suite = StubSuite({"p1|" + F1: REFUSAL})
    bundles = [bundle("t_1", F1), bundle("t_s", F2)]
    q = InMemoryQuarantine()
    j, _, _, clock = job(bundles, suite, projects={"t_1": "p1"}, quarantine=q)
    await j.run_once()
    clock["now"] = day(1)
    await j.run_once()
    assert suite.ran == ["p1|" + F1]  # the shared pool's configuration is never sent either


def test_a_stop_record_without_an_example_id_names_no_row(tmp_path):
    path = tmp_path / "run.jsonl"
    path.write_text(json.dumps({"type": "run_stopped", "reason": "provider_refusal"}) + "\n")
    assert nt.refused_row(path) == ""


def test_the_operator_route_lists_the_corpus_hold_as_its_own_kind():
    from guardrail_engine.admin.nightly import present_quarantine

    e = QuarantineEvent(CORPUS_HOLD_KEY, "live", "", "quarantine", D1, "nightly", False, "r")
    assert present_quarantine(e)["kind"] == "corpus"
    row = QuarantineEvent(row_key(ROW_X), "live", "", "quarantine", D1, "nightly", False, "r")
    assert present_quarantine(row)["kind"] == "row"


async def test_an_open_row_hold_pages_again_every_day_until_it_is_cleared():
    suite = StubSuite({F1: REFUSAL_ON_X})
    q = InMemoryQuarantine()
    j, _, alerts, clock = job([bundle("t_a", F1), bundle("t_b", F2)], suite, quarantine=q)
    await j.run_once()  # night 0: paged at once

    def pages():
        return [a for a in alerts.alerts if a.kind == ALERT_REDTEAM_QUARANTINED]

    assert len(pages()) == 1
    for n in range(1, 4):
        clock["now"] = day(n)
        await j.run_once()
        await j.run_once()  # a second run on the same day raises the same dedupe key
        key = f"redteam_quarantined:{row_key(ROW_X)}:{day(n).date().isoformat()}"
        todays = [a for a in pages() if a.dedupe_key == key]
        assert len(todays) == 2
        assert todays[0].severity is AlertSeverity.PAGE and ROW_X in todays[0].message
    assert len({a.dedupe_key for a in pages()}) == 4  # the first page and one per night
    await q.append(
        QuarantineEvent(
            row_key(ROW_X), "fake", "", "clear", day(4), "idp#ops", True, "reviewed", row_id=ROW_X
        )
    )
    before = len(pages())
    clock["now"] = day(5)
    await j.run_once()
    assert len(pages()) == before  # cleared: no more pages


async def test_every_result_produced_while_a_row_is_held_says_so_and_that_no_baseline():
    left_out = nt.SuiteOutcome(
        "done", report=report(), provider_calls=500, corpus_sha256="sha256:" + "ee" * 32, rows=171
    )
    baseline = {
        "corpus_sha256": SHA, "draws": 3, "nonce_seed": StubSuite.nonce_seed, "floor_version": 2,
        "block_recall": recall(30),
    }  # fmt: skip
    suite = StubSuite({F1: REFUSAL_ON_X})
    bundles = [bundle("t_a", F1), bundle("t_b", F2), bundle("t_c", F2, FIN)]
    q = InMemoryQuarantine()
    j, store, _, clock = job(bundles, suite, quarantine=q, baseline=baseline)
    suite.outcomes[F2] = suite.outcomes[f"{F2}+{FIN}"] = left_out
    await j.run_once()
    clock["now"] = day(1)
    await j.run_once()
    expected = f"baseline_compared: false; held_rows: [{ROW_X}]"
    mine = [x for x in store.all() if x.run_at == day(1)]
    assert {x.status for x in mine} == {"pass", "refused"} and len(mine) == 3
    assert all(x.note.endswith(expected) for x in mine) and all(len(x.note) <= 200 for x in mine)
    assert {base_note(x) for x in mine} == {"baseline_compared: false", nt.QUARANTINED}
    # when no row is actually left out the baseline is compared, and the note says so
    suite.outcomes.clear()
    clock["now"] = day(2)
    await j.run_once()
    again = [x for x in store.all() if x.run_at == day(2) and x.status == "pass"]
    assert again and all("baseline_compared: true" in x.note for x in again)
    for key in (F1, row_key(ROW_X)):
        await q.append(QuarantineEvent(key, "fake", "", "clear", day(3), "idp#ops", True, "ok"))
    clock["now"] = day(4)
    await j.run_once()
    assert all(x.note == "" for x in store.all() if x.run_at == day(4))


async def test_a_long_hold_list_still_fits_the_note_column_with_the_baseline_flag_first():
    ids = [f"rt-row-{i:03d}-long-identifier" for i in range(60)]
    q = InMemoryQuarantine()
    for i in ids:
        event = QuarantineEvent(
            row_key(i), "fake", "", "quarantine", D1, "nightly", False, "provider_refusal", row_id=i
        )
        await q.append(event)
    suite = StubSuite()
    j, store, _, _ = job([bundle("t_a", F2)], suite, quarantine=q)
    await j.run_once()
    (result,) = store.all()
    assert len(result.note) <= 200
    assert result.note.startswith("baseline_compared: false; held_rows: [rt-row-000")
    assert "more]" in result.note
