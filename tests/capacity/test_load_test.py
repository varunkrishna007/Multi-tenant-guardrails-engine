"""M3-09 load-test harness (capacity/load_test.py), offline: the engine on a virtual clock with a
fake model. No key, no network, no provider call."""

from __future__ import annotations

import asyncio
import json
import socket
import time

import pytest
from capacity.load_test import (
    DEFAULT_SHAPES,
    LatencyModel,
    LoadConfig,
    TenantSpec,
    TurnShape,
    VirtualLoop,
    analyse_pool,
    benign_text,
    percentile,
    render_markdown,
    run_virtual,
    simulate,
    summarise,
)
from capacity.model import Workload, capacity, tier

from guardrail_engine.tokens import estimate_tokens

STEADY = LatencyModel(sigma=0.0, tail_probability=0.0)
"""No spread and no tail: every call takes its median, well inside its attempt deadline, so
nothing is retried and the counts are exact."""


@pytest.fixture(autouse=True)
def no_provider_call(monkeypatch):
    """The whole suite: nothing may reach a socket, and the Gemini adapter is never built."""

    def refuse(*args, **kwargs):
        raise AssertionError("a provider call was attempted in an offline test")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket.socket, "connect_ex", refuse)
    from guardrail_engine.decision.adapters.gemini import GeminiDecisionModel

    monkeypatch.setattr(GeminiDecisionModel, "__init__", refuse)


def small(**kwargs) -> LoadConfig:
    base = {
        "minutes": 3, "turns_per_minute": 4, "latency": STEADY, "quotas": False,
        "tenants": (TenantSpec("t_a", 1.0, "chat"),),
    }  # fmt: skip
    return LoadConfig(**{**base, **kwargs})


# ------------------------------------------------------------------ turn-shape accounting


@pytest.mark.parametrize("loops", [0, 1, 2, 5])
def test_a_turn_is_three_checks_plus_two_per_tool_loop(loops):
    assert TurnShape("x", tool_loops=loops).checks(loops) == 3 + 2 * loops


def test_five_guard_points_at_one_tool_loop():
    assert DEFAULT_SHAPES["chat"].checks(1) == 5


def test_a_result_over_the_chunk_size_is_several_provider_calls():
    doc = DEFAULT_SHAPES["document"]
    assert doc.tool_result_tokens == 30_000
    assert doc.chunks_per_result() == 3  # 12,000-token chunks that overlap by 256
    assert doc.requests(2) == 7 + 2 * 2  # seven checks, two extra chunks for each result
    assert DEFAULT_SHAPES["chat"].chunks_per_result() == 1
    assert DEFAULT_SHAPES["chat"].requests(1) == 5


def test_synthetic_text_has_exactly_the_requested_tokens_and_no_digits():
    for tokens in (0, 1, 60, 4_000, 13_308):
        text = benign_text(tokens, salt=7)
        assert estimate_tokens(text) == tokens
        assert not any(ch.isdigit() for ch in text)
    assert benign_text(100, 1) != benign_text(100, 2)


def test_every_turn_makes_the_checks_and_requests_its_shape_says():
    """Through the engine, with no retries and no refusals: the measured checks and provider
    calls of each turn are exactly what the shape predicts, chunks and tool loops included."""
    shapes = {
        **DEFAULT_SHAPES,
        "varied": TurnShape("varied", tool_loops=(1, 3), tool_result_tokens=20_000),
    }
    config = small(
        minutes=4, turns_per_minute=3, shapes=shapes, tier="Tier 3", in_flight=32,
        tenants=(TenantSpec("t_a", 1.0, "varied"), TenantSpec("t_b", 1.0, "document")),
    )  # fmt: skip
    data = simulate(config)
    assert len(data.turns) >= 5
    assert {t.loops for t in data.turns if t.shape == "varied"} <= {1, 2, 3}
    for turn in data.turns:
        shape = shapes[turn.shape]
        assert turn.checks == shape.checks(turn.loops)
    expected_calls = sum(shapes[t.shape].requests(t.loops) for t in data.turns)
    assert len(data.calls) == expected_calls
    report = summarise(data)
    assert report["provider_calls"] == expected_calls
    assert report["retried_checks"] == 0
    assert report["refusals"] == dict.fromkeys(report["refusals"], 0)
    for name, row in report["shapes"].items():
        mine = [t for t in data.turns if t.shape == name]
        assert row["checks_per_turn"] == sum(shapes[name].checks(t.loops) for t in mine) / len(mine)


def test_the_five_guard_points_are_all_driven_in_order():
    data = simulate(small(minutes=1, turns_per_minute=2))
    first = [c.guard_point for c in data.checks if c.turn == data.turns[0].turn]
    assert first == ["input", "plan", "tool_call", "tool_result", "output"]


def test_requests_and_tokens_per_turn_are_counted_at_the_model():
    data = simulate(small())
    report = summarise(data)
    pool = report["pools"]["shared"]
    assert pool["requests"] == len(data.calls)
    assert pool["requests_per_turn"] == len(data.calls) / len(data.turns)
    assert pool["tokens_per_turn"] == sum(c.tokens for c in data.calls) / len(data.turns)
    assert report["turn_cost"]["requests_per_turn"] == pool["requests_per_turn"]


# ------------------------------------------------------------------ the binding limit


def test_at_pf4s_planning_figure_the_daily_cap_binds_and_tokens_bind_per_minute():
    """PF-4: 5 checks of 4,000 tokens at Tier 1 is about 300 turns/min by requests, 50 by
    tokens and 10,000 turns/day by the daily cap."""
    a = analyse_pool(
        tier("Tier 1"), requests_per_turn=5, tokens_per_turn=20_000, offered_turns_per_minute=10
    )
    by_name = {r["name"]: r for r in a["limits"]}
    assert by_name["requests/min"]["max_turns_per_minute"] == 300
    assert by_name["tokens/min"]["max_turns_per_minute"] == 50
    assert by_name["requests/day"]["max_turns_per_day"] == 10_000
    assert a["binding"] == "requests/day"
    assert a["binding_per_minute"] == "tokens/min"
    assert a["binding_per_day"] == "requests/day"
    assert a["max_turns_per_minute"] == 50
    assert a["max_turns_per_day"] == 10_000


def test_the_monthly_cap_is_named_beside_the_three_pf4_limits():
    """Above about 1,667 tokens a check the monthly cap allows fewer turns a day than the daily
    request cap (M0-03). It is not one of PF-4's three, so ``binding`` stays among those three
    and ``binding_all`` names it."""
    a = analyse_pool(
        tier("Tier 1"), requests_per_turn=5, tokens_per_turn=20_000, offered_turns_per_minute=1
    )
    assert a["binding"] == "requests/day"
    assert a["binding_all"] == "monthly spend cap"
    assert a["s3"]["monthly_cap_binds_first"] is True
    assert a["max_turns_per_day_all_limits"] == pytest.approx(4_166.67, rel=1e-4)
    short = analyse_pool(
        tier("Tier 1"), requests_per_turn=5, tokens_per_turn=5 * 800, offered_turns_per_minute=1
    )
    assert short["binding_all"] == "requests/day"
    assert short["s3"]["monthly_cap_binds_first"] is False


def test_large_checks_make_tokens_the_binding_limit_even_per_day():
    a = analyse_pool(
        tier("Tier 1"), requests_per_turn=5, tokens_per_turn=150_000, offered_turns_per_minute=1
    )
    assert a["max_turns_per_day"] == pytest.approx(1_000_000 * 1_440 / 150_000)  # 9,600
    assert a["binding_per_day"] == "tokens/min x 1,440"
    assert a["binding"] == "tokens/min"


def test_without_a_daily_cap_the_per_minute_limits_bind():
    """Tier 2 has no requests/day. Small checks hit requests/min; large ones tokens/min."""
    small_checks = analyse_pool(
        tier("Tier 2"), requests_per_turn=5, tokens_per_turn=2_500, offered_turns_per_minute=1
    )
    assert small_checks["binding"] == "requests/min"
    assert small_checks["max_turns_per_minute"] == 1_000  # 5,000 / 5
    assert not any(r["name"] == "requests/day" for r in small_checks["limits"])
    large_checks = analyse_pool(
        tier("Tier 2"), requests_per_turn=5, tokens_per_turn=20_000, offered_turns_per_minute=1
    )
    assert large_checks["binding"] == "tokens/min"
    assert large_checks["max_turns_per_minute"] == 200  # 4,000,000 / 20,000


def test_headroom_is_the_configured_load_against_each_limit():
    a = analyse_pool(
        tier("Tier 1"),
        requests_per_turn=5,
        tokens_per_turn=20_000,
        offered_turns_per_minute=10,
        peak_minute_requests=90,
        peak_minute_tokens=600_000,
    )
    by_name = {r["name"]: r for r in a["limits"]}
    assert by_name["requests/min"]["used"] == pytest.approx(50 / 1_500)
    assert by_name["tokens/min"]["used"] == pytest.approx(200_000 / 1_000_000)
    assert by_name["tokens/min"]["peak_used"] == pytest.approx(0.6)
    # The daily cap is projected, never burned: 10 turns a minute for a day is 72,000 requests.
    assert by_name["requests/day"]["used"] == pytest.approx(5 * 10 * 1_440 / 50_000)
    assert by_name["requests/day"]["headroom"] == pytest.approx(1 - 1.44)


def test_the_model_agrees_with_the_harness_arithmetic():
    cap = capacity(tier("Tier 1"), Workload(5, 4_000))
    a = analyse_pool(
        tier("Tier 1"), requests_per_turn=5, tokens_per_turn=20_000, offered_turns_per_minute=1
    )
    assert a["max_turns_per_minute"] == cap.turns_per_minute
    assert a["max_turns_per_day_all_limits"] == pytest.approx(cap.turns_per_day)


# ------------------------------------------------------------------ the S3 cap


def test_the_onboarding_cap_is_70_percent_of_the_binding_limit():
    """S3: about 7,000 turns/day per pool at 5 checks per turn (the daily cap binds)."""
    a = analyse_pool(
        tier("Tier 1"), requests_per_turn=5, tokens_per_turn=20_000, offered_turns_per_minute=1
    )
    s3 = a["s3"]
    assert s3["fraction"] == 0.70
    assert s3["turns_per_day"] == pytest.approx(7_000)
    assert s3["turns_per_minute_sustained"] == pytest.approx(7_000 / 1_440)
    assert s3["turns_per_minute_peak"] == pytest.approx(0.70 * 50)
    assert s3["turns_per_day_all_limits"] == pytest.approx(0.70 * 4_166.67, rel=1e-4)


def test_the_cap_follows_whichever_limit_binds_and_a_custom_fraction():
    a = analyse_pool(
        tier("Tier 1"),
        requests_per_turn=5,
        tokens_per_turn=150_000,
        offered_turns_per_minute=1,
        onboarding_fraction=0.5,
    )
    assert a["s3"]["turns_per_day"] == pytest.approx(0.5 * 9_600)
    with pytest.raises(ValueError):
        analyse_pool(
            tier("Tier 1"), requests_per_turn=0, tokens_per_turn=1, offered_turns_per_minute=1
        )


def test_the_report_names_the_cap_and_the_binding_limit():
    text = render_markdown(summarise(simulate(small())))
    assert "Binding PF-4 limit: requests/day" in text
    assert "S3 onboarding cap (70% of the binding limit)" in text
    assert "monthly spend cap" in text
    assert "Queue waits and refusals" in text
    assert "token_rate" in text and "admission_wait" in text


def test_the_daily_cap_is_projected_from_requests_per_turn_not_burned():
    data = simulate(small(minutes=2, turns_per_minute=6))
    report = summarise(data)
    pool = report["pools"]["shared"]
    offered = pool["turns"] / 2
    assert pool["projected_requests_per_day"] == pytest.approx(
        pool["requests_per_turn"] * offered * 1_440
    )
    assert pool["requests"] < 1_000  # two minutes of calls, not a day's


# ------------------------------------------------------------------ queue waits and refusals


def test_admission_refusals_are_counted_when_the_load_exceeds_the_in_flight_limit():
    data = simulate(small(minutes=2, turns_per_minute=120, in_flight=1))
    report = summarise(data)
    assert report["refusals"]["admission_wait"] > 0
    assert report["refusal_rate"] > 0
    assert report["capacity_limited"] >= report["refusals"]["admission_wait"]
    assert sum(t["refused"] for t in report["tenants"].values()) == sum(report["refusals"].values())


def test_a_tenants_own_share_is_refused_as_token_rate():
    """M3-07: with the shares on, one tenant sending several chunks of a large result at once
    spends its token bucket and is refused with no provider call."""
    config = small(
        minutes=2, turns_per_minute=3, quotas=True, tenants=(TenantSpec("t_a", 1.0, "document"),)
    )
    report = summarise(simulate(config))
    assert report["refusals"]["token_rate"] > 0
    assert report["tenants"]["t_a"]["refused"] > 0


def test_the_pools_are_reported_apart():
    config = small(
        minutes=2, turns_per_minute=6,
        tenants=(TenantSpec("t_a", 1.0, "chat"), TenantSpec("t_r", 1.0, "chat", project="reg-1")),
    )  # fmt: skip
    report = summarise(simulate(config))
    assert set(report["pools"]) == {"shared", "reg-1"}
    assert report["pools"]["shared"]["turns"] + report["pools"]["reg-1"]["turns"] == report["turns"]
    assert report["tenants"]["t_r"]["pool"] == "reg-1"


def test_percentile_is_nearest_rank():
    assert percentile([], 95) is None
    assert percentile([5, 1, 3, 2, 4], 50) == 3
    assert percentile(list(range(1, 101)), 95) == 95


# ------------------------------------------------------------------ the virtual clock


def test_the_same_seed_gives_the_same_report_and_another_gives_another():
    config = small(minutes=3, turns_per_minute=8, latency=LatencyModel())
    a = json.dumps(summarise(simulate(config)), sort_keys=True)
    b = json.dumps(summarise(simulate(config)), sort_keys=True)
    assert a == b
    other = json.dumps(summarise(simulate(small(minutes=3, turns_per_minute=8, seed=1))))
    assert a != other


def test_an_hour_of_load_takes_seconds():
    started = time.monotonic()
    data = simulate(small(minutes=60, turns_per_minute=2))
    assert data.virtual_seconds >= 3_600
    assert time.monotonic() - started < 60  # an hour of virtual time in about a second
    assert len(data.turns) > 60


def test_the_loop_jumps_to_the_next_timer_and_keeps_its_own_clock():
    async def main():
        loop = asyncio.get_running_loop()
        t0 = loop.time()
        await asyncio.sleep(3_600)
        await asyncio.sleep(0.5)
        return loop.time() - t0

    started = time.monotonic()
    assert run_virtual(main()) == pytest.approx(3_600.5)
    assert time.monotonic() - started < 5


def test_work_in_a_thread_is_waited_for_not_skipped_over():
    """A timeout on the virtual clock must not expire because a thread is still running."""

    async def main():
        def slow():
            time.sleep(0.2)
            return "done"

        return await asyncio.wait_for(asyncio.to_thread(slow), timeout=1.0)

    assert run_virtual(main()) == "done"


def test_a_loop_with_nothing_to_wake_it_is_called_deadlocked():
    class Quick(VirtualLoop):
        IDLE_POLL_S = 0.001
        IDLE_POLLS = 5

    async def main():
        await asyncio.get_running_loop().create_future()

    with asyncio.Runner(loop_factory=Quick) as runner, pytest.raises(RuntimeError, match="idle"):
        runner.run(main())


def test_the_latency_model_is_the_r63_model():
    from guardrail_engine.gateway import GatewayConfig

    model = LatencyModel(window_s=0.0)
    cfg = GatewayConfig()
    # the expected p50 of R6.3 is the median plus the time-window allowance
    for tokens, questions in ((500, 5), (4_000, 12), (16_000, 50)):
        assert model.median_s(tokens, questions) == pytest.approx(
            cfg.expected_p50_for(input_tokens=tokens, question_count=questions)
            - cfg.time_window_allowance_s
        )
    assert LatencyModel().window_s == pytest.approx(cfg.time_window_allowance_s / 2)
