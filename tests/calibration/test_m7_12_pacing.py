"""M7-12 attempt 2: the pacing, the stop rule for the engine's own refusals, and the second attempt.

Run 1 of the redaction trial spaced its checks by the mean of their sizes. The calibration
consumer's token allowance is a bucket of 5,230 tokens refilling at 1,046 a second, and 18 of the
137 rows are larger than the bucket (the largest is 14,176 tokens by estimate): such a check needs
a full bucket and leaves it in debt, so the checks around it were refused by the engine's own
limiter, with no provider call. 45 of 492 were, and the run stopped on the failure rate.

These tests give the harness the real limiter (``ConsumerAllowances`` over the in-process store)
behind a fake clock, check that it reproduces run 1's refusals from run 1's own records, and check
that the new pacing, run on the whole approved manifest, is never refused by it.
"""

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from calibration.engine_path import SeededNonces, StopRun, calibration_engine

from calibration import redaction_trial as rt
from guardrail_engine.decision import FakeDecisionModel
from guardrail_engine.gateway.tenant_quota import QuotaCharge, QuotaRefusal

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "calibration" / "results" / "m7-12-trial-manifest.json"
RUN1 = ROOT / "calibration" / "results" / "m7-12-trial-run1" / "records.jsonl"
CONSUMER = rt.USAGE_CLASS
DEADLINE = datetime(2026, 11, 26, 10, 0, tzinfo=UTC)


@pytest.fixture(scope="module")
def manifest():
    return rt.load_manifest(MANIFEST)


@pytest.fixture(scope="module")
def rows(manifest):
    return rt.verify_manifest(manifest)


@pytest.fixture(scope="module")
def planned(rows, manifest):
    return rt.plan(rows, order_seed=manifest["nonce_seed"])


def fake_model():
    return FakeDecisionModel(responder=lambda text, key, question: 0.2)


# ----- what run 1 shows about the limiter


def run1_calls():
    return [r for r in map(json.loads, RUN1.read_text().splitlines()) if r["type"] == "call"]


def replay_run1(planned, pace_by):
    """Run 1's checks, in its order, through the real limiter at the times ``pace_by`` gives:
    the indices of those it refused. Each check is charged the estimate of its row and, if it is
    admitted, settled a second later at the usage run 1 recorded (a check run 1 never got an
    answer for keeps its reservation)."""
    allowances = rt.consumer_allowances()
    refused = []
    for i, r in enumerate(run1_calls()):
        now = pace_by(i, r)
        size = max(1, planned["estimates"][r["example_id"]])
        charge = allowances.charge(
            tenant_id="t", tier=None, consumer=CONSUMER, tokens=size, now=now
        )
        if isinstance(charge, QuotaRefusal):
            refused.append(i)
        elif r["usage_input_tokens"]:
            allowances.reconcile(charge, r["usage_input_tokens"], now=now + 1.0)
    return refused


def test_the_limiter_model_refuses_exactly_the_checks_run_1_was_refused(planned):
    """The same 45 checks, by their place in run 1's order: not merely as many."""
    calls = run1_calls()
    recorded = [i for i, r in enumerate(calls) if r["failure_reason"] == "token_rate"]
    assert len(recorded) == 45
    started = [datetime.fromisoformat(r["started_at"]).timestamp() for r in calls]
    assert replay_run1(planned, lambda i, r: started[i]) == recorded


def test_run_1s_pacing_by_the_mean_alone_is_refused_by_the_limiter(planned):
    """The same checks spaced 2.089 s apart, as run 1 planned: the limiter refuses dozens."""
    assert len(replay_run1(planned, lambda i, r: 2.089 * i)) >= 25


# ----- the model of the limiter in the plan


def test_a_run_of_small_checks_is_paced_by_the_floor_alone():
    model = rt.pace_model([800] * 40)
    assert model["waits"] == 0
    assert model["seconds"] == pytest.approx(39 * rt.LIVE_MIN_INTERVAL_S + rt.MODEL_CHECK_S, abs=1)


def test_a_check_larger_than_the_bucket_waits_for_a_full_one_and_the_next_waits_for_its_debt():
    model = rt.pace_model([800, 14_000, 800, 800])
    assert model["bucket_tokens"] == 5230
    assert model["waits"] >= 1 and 4.0 < model["longest_wait_s"] <= 10.0


def test_the_plan_refuses_a_check_the_allowance_cannot_carry(monkeypatch):
    monkeypatch.setattr(rt, "MAX_ADMISSION_WAIT_S", 1.0)
    with pytest.raises(rt.Refused, match="cannot carry it"):
        rt.pace_model([5000, 5000])


def test_the_plan_of_the_approved_manifest(planned):
    assert planned["checks"] == 822 and planned["rows_larger_than_the_bucket"] == 18
    assert planned["bucket_tokens"] == 5230 and planned["largest_estimate"] > 5230
    assert 24 < planned["estimated_minutes"] < 40  # the 1.56 million tokens at 1,046 a second
    assert planned["estimated_input_tokens"] <= rt.CEILING_INPUT_TOKENS
    assert planned["checks"] <= rt.CEILING_CALLS
    assert planned["longest_wait_s"] <= rt.MAX_ADMISSION_WAIT_S
    assert planned["min_interval_s"] == rt.LIVE_MIN_INTERVAL_S


# ----- the whole manifest through the limiter


class Clock:
    """A fake clock that moves only when something sleeps or a check takes its time."""

    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t

    async def sleep(self, seconds):
        self.t += seconds


def local_refusal():
    """What the engine returns for a check its limiter refused: no provider call."""
    value = lambda v: SimpleNamespace(value=v)  # noqa: E731
    return SimpleNamespace(
        reason=value("model_failure"), decision=value("block"), failure_kind=value("unavailable"),
        failure_reason="token_rate", model_called=False, rules=[], probabilities={},
        probabilities_raw={}, problem_kinds={}, pii_redacted={}, provider_calls=0, usage=None,
        latency_ms=0.3, model_latency_ms=0.0, queue_wait_ms=0.1, context_items_dropped=0,
        bundle_hash="sha256:" + "0" * 64,
    )  # fmt: skip


class LimitedEngine:
    """A real (offline) engine behind the real calibration allowance and a fake clock: each check
    is charged ``charge_factor`` times its estimate (the engine's own figure may differ from the
    harness's), takes one second, and settles at ``usage_factor`` times its estimate."""

    def __init__(self, inner, clock, sizes, *, charge_factor=1.0, usage_factor=0.75):
        self.inner, self.clock, self.sizes = inner, clock, sizes
        self.charge_factor, self.usage_factor = charge_factor, usage_factor
        self.allowances = rt.consumer_allowances()
        self.refused = 0
        self.gateway = SimpleNamespace(
            consumer_admission_wait=lambda consumer, tokens: self.allowances.admission_wait(
                consumer, tokens, now=self.clock()
            )
        )

    @property
    def settings(self):
        return self.inner.settings

    async def check(self, ctx, guard_point, content):
        size = self.sizes[(guard_point, content)]
        charged = max(1, round(size * self.charge_factor))
        charge = self.allowances.charge(
            tenant_id="t", tier=None, consumer=CONSUMER, tokens=charged, now=self.clock()
        )
        if isinstance(charge, QuotaRefusal):
            self.refused += 1
            return local_refusal()
        assert isinstance(charge, QuotaCharge)
        verdict = await self.inner.check(ctx, guard_point, content)
        self.clock.t += 1.0  # the check takes its time; the bucket refills meanwhile
        self.allowances.reconcile(charge, max(1, round(size * self.usage_factor)), now=self.clock())
        return verdict


async def run_through_limiter(tmp_path, rows, manifest, planned, *, paced, **engine_kwargs):
    """The whole manifest through the trial's own runner, order and arms, against a limited
    engine. ``paced`` is the new pacing; otherwise run 1's (a fixed interval, the mean)."""
    clock = Clock()
    sizes = {}
    for row in rows:
        key = (row["guard_point"], row["content"])
        sizes[key] = max(sizes.get(key, 0), planned["estimates"][row["id"]])
    nonces = SeededNonces(manifest["nonce_seed"])
    detector = rt.ArmDetector()
    out = tmp_path / "records.jsonl"
    async with calibration_engine(
        rt.engine_setup(), rows, model=fake_model(), nonces=nonces, pii_detector=detector
    ) as (engine, verifier):
        limited = LimitedEngine(engine, clock, sizes, **engine_kwargs)
        runner = rt.TrialRunner(
            out=out, engine=limited, verifier=verifier, nonces=nonces, detector=detector,
            token_estimates=planned["estimates"], clock=clock, sleep=clock.sleep,
            usage_class=CONSUMER,
            min_interval_s=planned["min_interval_s"] if paced else 2.089,
            admission_wait=limited.gateway.consumer_admission_wait if paced else None,
            admission_margin=rt.ADMISSION_MARGIN if paced else 1.0,
        )  # fmt: skip
        stopped = None
        try:
            await rt.run_trial(runner, rows, order_seed=manifest["nonce_seed"], log=lambda s: None)
        except StopRun as e:
            stopped = str(e)
    return limited, runner, rt.read_records(out), clock, stopped


async def test_run_1s_pacing_is_stopped_by_the_first_refusal_the_engine_makes_itself(
    tmp_path, rows, manifest, planned
):
    limited, _, records, _, stopped = await run_through_limiter(
        tmp_path, rows, manifest, planned, paced=False
    )
    assert stopped and "the pacing is wrong" in stopped
    last = records[-1]
    assert last["type"] == "run_stopped" and last["reason"] == "local_refusal"
    assert last["failure_reason"] == "token_rate"
    refusals = [r for r in records if r["type"] == "call" and r["outcome"] == "failed"]
    assert len(refusals) == 1 == limited.refused  # recorded, and the run stopped there
    assert refusals[0]["provider_calls"] == 0


@pytest.mark.parametrize("usage_factor", [0.75, 1.0, 1.3])
async def test_the_new_pacing_is_never_refused_and_makes_every_check(
    tmp_path, rows, manifest, planned, usage_factor
):
    limited, runner, records, clock, stopped = await run_through_limiter(
        tmp_path, rows, manifest, planned, paced=True, usage_factor=usage_factor
    )
    assert stopped is None and limited.refused == 0
    made = [r for r in records if r["type"] == "call"]
    assert len(made) == 822 and all(r["outcome"] == "answered" for r in made)
    assert not any(r["type"] == "run_stopped" for r in records)
    assert runner.admission_waits > 0  # the large checks did wait for the limiter
    if usage_factor <= 1.0:  # the plan is the estimate; the real run is no longer than it
        assert clock.t <= planned["estimated_minutes"] * 60 * 1.02
    assert clock.t > 24 * 60  # and it can't beat the refill: 1.56 million tokens at 1,046 a second


async def test_a_gateway_that_charges_far_more_than_the_estimate_stops_the_run_at_the_first_refusal(
    tmp_path, rows, manifest, planned
):
    """Within the margin (1.25) the pacing holds; far outside it, the stop rule is the backstop:
    a check the engine refused itself ends the run, whatever the failure rate."""
    limited, _, records, _, stopped = await run_through_limiter(
        tmp_path, rows, manifest, planned, paced=True, charge_factor=2.0
    )
    assert limited.refused == 1 and stopped
    assert records[-1]["reason"] == "local_refusal"
    assert sum(r["type"] == "call" for r in records) < 822


async def test_a_charge_a_fifth_above_the_estimate_is_still_inside_the_margin(
    tmp_path, rows, manifest, planned
):
    limited, _, records, _, stopped = await run_through_limiter(
        tmp_path, rows, manifest, planned, paced=True, charge_factor=1.2
    )
    assert stopped is None and limited.refused == 0 and len(records) == 822


# ----- the stop rule


def runner_for(tmp_path):
    return rt.TrialRunner(
        out=tmp_path / "r.jsonl", engine=None, verifier=None, nonces=SeededNonces("a" * 32)
    )


def failed(reason, kind="unavailable", calls=0):
    return {"outcome": "failed", "provider_calls": calls, "failure_reason": reason, "kind": kind}


def test_a_check_the_engine_refused_itself_is_not_a_provider_failure(tmp_path):
    runner = runner_for(tmp_path)
    for reason in rt.LOCAL_REFUSALS:
        assert rt.locally_refused(failed(reason))
        assert not runner.counts_as_failure(failed(reason))
    assert runner.counts_as_failure(failed(None, kind="timeout", calls=2))  # still counts
    assert runner.counts_as_failure(failed("provider_degraded"))
    assert runner.counts_as_failure(failed("token_rate", calls=1))  # it reached the provider
    assert not runner.counts_as_failure({"outcome": "answered", "provider_calls": 1})


def test_the_local_refusals_are_the_gateways_capacity_reasons_but_the_orphan_cap():
    from guardrail_engine.gateway import gateway as gw

    assert gw.CAPACITY_REASONS - {gw.REASON_ORPHAN_CAP} == rt.LOCAL_REFUSALS
    assert gw.REASON_ADMISSION_WAIT in rt.LOCAL_REFUSALS
    assert gw.REASON_ORPHAN_CAP not in rt.LOCAL_REFUSALS


def test_an_admission_wait_refusal_stops_the_run_with_local_refusal(tmp_path):
    """The gateway's refusal of a check whose budget can't cover the predicted queue wait."""
    runner = runner_for(tmp_path)
    record = {**failed("admission_wait"), "type": "call"}
    assert not runner.counts_as_failure(record)
    with pytest.raises(StopRun, match="admission_wait, no provider call"):
        runner.screen_record(record, {"id": "row-1"}, 1)
    stop = rt.read_records(tmp_path / "r.jsonl")[-1]
    assert stop["reason"] == "local_refusal" and stop["failure_reason"] == "admission_wait"
    # after a provider call it is a provider failure like any other, and counts
    runner.screen_record(failed("admission_wait", calls=1), {"id": "row-2"}, 1)
    assert runner.counts_as_failure(failed("admission_wait", calls=1))


async def test_a_limiter_that_never_admits_stops_the_run_with_a_record_and_sends_nothing(tmp_path):
    from calibration.engine_path import ADMISSION_ROUNDS

    slept, asked = [], []

    async def sleep(seconds):
        slept.append(seconds)

    def never(consumer, tokens):
        asked.append((consumer, tokens))
        return 2.0

    runner = runner_for(tmp_path)  # it has no engine: a send would fail loudly
    runner.admission_wait, runner.sleep = never, sleep
    runner.token_estimates = {"row-1": 1000}
    with pytest.raises(StopRun, match="would not admit"):
        await runner.check_arm({"id": "row-1", "group": "affected_positive"}, 1, "raw")
    assert len(slept) == len(asked) == ADMISSION_ROUNDS
    assert asked[0] == (runner.usage_class, 1250)  # the estimate raised by the one margin
    [stop] = rt.read_records(tmp_path / "r.jsonl")
    assert stop["type"] == "run_stopped" and stop["reason"] == "admission_gave_up"
    assert stop["example_id"] == "row-1" and stop["before_sending"] is True
    assert stop["tokens_asked"] == 1250 and stop["waited_s"] == pytest.approx(16.08)
    assert stop["arm"] == "raw" and stop["group"] == "affected_positive"
    assert runner.calls == 0


def test_there_is_one_margin_figure(tmp_path):
    from calibration import engine_path

    assert rt.ADMISSION_MARGIN is engine_path.ADMISSION_MARGIN == 1.25
    assert runner_for(tmp_path).admission_margin == rt.ADMISSION_MARGIN
    assert engine_path.EngineRunner.__dataclass_fields__["admission_margin"].default == 1.25


def test_a_local_refusal_stops_the_run_and_is_recorded(tmp_path):
    runner = runner_for(tmp_path)
    record = {**failed("token_rate"), "type": "call"}
    with pytest.raises(StopRun, match="the pacing is wrong"):
        runner.screen_record(record, {"id": "row-1"}, 2)
    stop = rt.read_records(tmp_path / "r.jsonl")[-1]
    assert stop["type"] == "run_stopped" and stop["reason"] == "local_refusal"
    assert stop["example_id"] == "row-1" and stop["draw"] == 2
    runner.screen_record({"outcome": "answered", "provider_calls": 1}, {"id": "r"}, 1)  # no stop
    runner.screen_record(failed(None, kind="timeout", calls=2), {"id": "r"}, 1)  # a timeout isn't


# ----- the second attempt

KEY = rt.APPROVED_ROWS_SHA256


def spend(directory, number, **extra):
    attempt = rt.Attempt(directory, KEY, number)
    attempt.acquire()
    attempt.mark({"started_at": "x", **extra})
    attempt.release()


def test_attempt_1_keeps_the_names_it_always_had(tmp_path):
    spend(tmp_path, 1)
    stem = KEY.removeprefix("sha256:")[:16]
    assert (tmp_path / f"{stem}.started").exists() and not (
        tmp_path / f"{stem}.attempt-2.started"
    ).exists()
    assert json.loads((tmp_path / f"{stem}.started").read_text())["attempt"] == 1


def test_attempt_2_is_refused_unless_attempt_1_has_started(tmp_path):
    with pytest.raises(rt.Refused, match="attempt 1, which has not started"):
        rt.Attempt(tmp_path, KEY, 2).acquire()
    spend(tmp_path, 1)
    second = rt.Attempt(tmp_path, KEY, 2)
    second.acquire()  # now it may
    second.mark({"started_at": "later"})
    second.release()
    assert second.marker != rt.Attempt(tmp_path, KEY, 1).marker  # a marker of its own


def test_attempt_2_is_refused_once_it_has_started_and_while_it_runs(tmp_path):
    spend(tmp_path, 1)
    running = rt.Attempt(tmp_path, KEY, 2)
    running.acquire()
    try:
        with pytest.raises(rt.Refused, match="in progress"):
            rt.Attempt(tmp_path, KEY, 2).acquire()
        running.mark({"started_at": "later"})
    finally:
        running.release()
    with pytest.raises(rt.Refused, match="attempt 2 of this manifest has started"):
        rt.Attempt(tmp_path, KEY, 2).acquire()
    with pytest.raises(rt.Refused, match="has started"):
        rt.Attempt(tmp_path, KEY, 2).mark({})  # the marker is written once


def test_attempt_1_stays_spent_whatever_attempt_2_does(tmp_path):
    spend(tmp_path, 1)
    spend(tmp_path, 2)
    with pytest.raises(rt.Refused, match="attempt 1 of this manifest has started"):
        rt.Attempt(tmp_path, KEY, 1).acquire()


@pytest.mark.parametrize("number", [0, 3, -1, True, "2", None])
def test_there_are_two_attempts_and_no_more(tmp_path, number):
    with pytest.raises(rt.Refused, match="attempts 1 to 2"):
        rt.Attempt(tmp_path, KEY, number)


async def test_a_live_attempt_2_is_refused_before_anything_is_sent_unless_attempt_1_started(
    tmp_path,
):
    state = tmp_path / "state"
    out = tmp_path / "second" / "records.jsonl"
    soon = lambda: DEADLINE - timedelta(hours=1)  # noqa: E731
    code = await rt.execute(
        rt.Args(MANIFEST, out, True, DEADLINE, attempt=2), now=soon, attempts=state
    )
    assert code == rt.EXIT_REFUSED and not out.parent.exists()
    assert not list(state.glob("*.started"))  # nothing was marked either
    spend(state, 1)
    code = await rt.execute(
        rt.Args(MANIFEST, out, True, DEADLINE, attempt=3), now=soon, attempts=state
    )
    assert code == rt.EXIT_REFUSED


async def test_an_offline_run_records_which_attempt_it_is_and_the_pacing(tmp_path):
    out = tmp_path / "records.jsonl"
    code = await rt.execute(
        rt.Args(MANIFEST, out, False, attempt=2), model_factory=fake_model, attempts=tmp_path / "s"
    )
    first = rt.read_records(out)[0]
    assert code == rt.EXIT_DONE and first["type"] == "run_started"
    assert first["attempt"] == 2 and first["pacing"] == "none"
    assert rt.read_records(out)[-1]["type"] == "run_finished"


def test_the_command_line_takes_an_attempt(tmp_path, capsys):
    assert (
        rt.main(
            [
                "run",
                "--manifest",
                str(MANIFEST),
                "--out",
                str(tmp_path / "r.jsonl"),
                "--attempt",
                "2",
            ]
        )
        == rt.EXIT_REFUSED
    )  # without --live: refused, whatever the attempt
