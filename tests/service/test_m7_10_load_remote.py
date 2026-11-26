"""M7-10 step 4: the load test's remote mode runs the same turns against the in-process engine and
the guard service as a separate process, and reports the boundary."""

import pytest

pytest.importorskip("uvicorn")

from capacity import load_remote


def test_the_arrival_schedule_is_seeded():
    a = load_remote.schedule(5.0, 10.0, 7)
    assert a == load_remote.schedule(5.0, 10.0, 7)
    assert a != load_remote.schedule(5.0, 10.0, 8)
    arrivals, loops = a
    assert arrivals == sorted(arrivals) and arrivals[-1] < 10.0
    assert len(arrivals) == len(loops) and set(loops) <= {1, 2}


def test_the_summary_counts_the_clients_own_outcome_apart():
    samples = [
        load_remote.Sample("input", 0.010, "allow", "policy", None),
        load_remote.Sample("input", 0.030, "block", "model_failure", "admission_wait"),
        load_remote.Sample("output", 0.020, "block", "model_failure", "guard_unreachable"),
    ]
    out = load_remote.summarise(samples, 1.0)
    assert out["checks"] == 3 and out["guard_unreachable"] == 1
    assert out["outcomes"]["block/model_failure/admission_wait"] == 1
    assert out["outcomes"]["block/model_failure/guard_unreachable"] == 1
    assert set(out["latency_ms"]) == {"input", "output"}


def args(**more):
    base = dict(
        turns_per_second=3.0, seconds=3.0, model_latency_s=0.05, mode="both",
        pool=64, margin_s=0.25, seed=3, mixed=False, in_flight=64,
    )  # fmt: skip
    return load_remote.argparse.Namespace(**{**base, **more})


def test_a_short_run_goes_through_both_modes_and_the_boundary_adds_little():
    report = load_remote.asyncio.run(load_remote.run(args()))
    local, remote = report["in_process"], report["remote"]
    assert report["turns"] >= 3
    assert local["checks"] == remote["checks"] > 0
    assert remote["guard_unreachable"] == 0
    assert local["outcomes"] == remote["outcomes"]
    for point, (p50, _, _) in remote["latency_ms"].items():
        assert p50 < local["latency_ms"][point][0] + 150  # the boundary is milliseconds, not more
    assert "remote" in load_remote.render(report)


def test_a_mixed_run_decides_every_kind_of_outcome_the_same_in_both_modes():
    """The fake decides by markers in the text, so the two modes see the same allows, blocks,
    escalations, provider refusals and failures; comparing counts of allows alone would not catch
    a mapping that differs for the others."""
    report = load_remote.asyncio.run(
        load_remote.run(args(mixed=True, turns_per_second=8.0, seconds=4.0))
    )
    local, remote = report["in_process"], report["remote"]
    kinds = {
        "allow/policy",
        "block/policy",
        "escalate/policy",
        "block/provider_safety",
        "block/model_failure/unavailable",
    }
    assert kinds <= set(local["outcomes"]) and kinds <= set(remote["outcomes"])
    assert local["outcomes"] == remote["outcomes"]
    assert remote["guard_unreachable"] == 0
