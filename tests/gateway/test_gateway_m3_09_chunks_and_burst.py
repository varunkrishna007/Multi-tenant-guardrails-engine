"""M3-09 findings, decided 2026-11-18: a tenant's burst is 60 s of its share and its bucket is never
smaller than the largest single check; the chunks of one check are charged together (all or
none) and take one place in the fair queue. Virtual time, no provider."""

import asyncio

import pytest
from test_gateway import QUESTIONS
from test_gateway_m3_07 import (
    BIG,
    LONG_QUEUE,
    QRig,
    TierQuota,
    answered,
    estimate_of,
    refused,
    share_of,
    text,
    tiers,
)

from guardrail_engine.decision import Failed
from guardrail_engine.gateway import QuotaConfig
from guardrail_engine.gateway.gateway import USAGE_CHECK

CHUNKS = 3


async def chunk_check(rig, *, tenant_id="t_a", n=CHUNKS, guard_point="tool_result", gateway=0):
    """The chunk calls of one check, submitted together as the Guard Service does."""
    g = rig.gateways[gateway]
    inputs = [f"{i:04d}" + rig.input[4:] for i in range(n)]
    group = g.check_group(inputs, QUESTIONS)
    return await asyncio.gather(
        *(
            g.decide_timed(
                tenant_id=tenant_id,
                guard_point=guard_point,
                input=text_i,
                questions=QUESTIONS,
                usage_class=USAGE_CHECK,
                group=group,
                group_index=i,
            )
            for i, text_i in enumerate(inputs)
        )
    )


class TestBurst:
    async def test_a_burst_is_sixty_seconds_of_the_share_and_refills_at_the_shares_rate(self):
        est = estimate_of(text(0))
        rig = QRig(QuotaConfig(tiers=tiers(standard=share_of(est, 60))), project=BIG)
        status = rig.status()
        assert status.tokens_capacity == pytest.approx(est * 60)  # a whole minute's share
        for _ in range(60):
            assert isinstance(answered([await rig.check()])[0].result, object)
        assert rig.status().tokens_available == pytest.approx(0, abs=est)
        refusal = await rig.check()
        assert refused([refusal])  # empty: refused until it refills
        await rig.vt.sleep(30)
        # 30 s at the share's own rate (a minute's share per minute) is half the share
        assert rig.status().tokens_available == pytest.approx(est * 30, rel=0.02)

    async def test_a_tenant_at_half_its_share_is_not_refused_even_in_bursts(self):
        est = estimate_of(text(0))
        rig = QRig(QuotaConfig(tiers=tiers(standard=share_of(est, 60))), project=BIG)
        results = []
        for _minute in range(5):  # 30 checks a minute, in bursts of 10 every 20 s
            for _burst in range(3):
                results += [await rig.check() for _ in range(10)]
                await rig.vt.sleep(20)
        assert len(results) == 150 and not refused(results)


class TestLargestCheck:
    async def test_the_bucket_is_never_smaller_than_one_whole_check(self):
        small = TierQuota(tokens_per_minute=1_000, checks_per_minute=10**7, requests_per_day=10**9)
        plain = QRig(QuotaConfig(tiers=tiers(standard=small)))
        assert plain.status().tokens_capacity == pytest.approx(1_000)  # the burst alone
        floored = QRig(QuotaConfig(tiers=tiers(standard=small), largest_check_tokens=50_000))
        assert floored.status().tokens_capacity == 50_000
        assert floored.status().tokens_per_minute == 1_000  # the share is unchanged

    def test_the_engine_derives_it_from_the_platform_settings(self):
        from guardrail_engine.engine import EngineSettings

        s = EngineSettings()
        p = s.platform
        want = p.max_chunks_per_result * (
            p.token_budget
            + p.question_text_tokens_per_budgeted_question * p.question_budgets.tool_result
        )
        assert s.effective_quotas().largest_check_tokens == want == 94_000
        assert s.effective_quotas().largest_check_calls == p.max_chunks_per_result == 4
        # a standard tenant's default bucket holds a minute of 170,000, more than the check
        assert s.effective_quotas().tiers["standard"].tokens_per_minute > want

    def test_it_is_validated(self):
        with pytest.raises(ValueError, match="largest_check_tokens"):
            QuotaConfig(largest_check_tokens=-1)


class TestChunkGroup:
    async def test_a_three_chunk_check_is_answered_whole_for_a_standard_tenant(self):
        est = estimate_of(text(0))
        # a bucket that holds exactly three chunks
        rig = QRig(QuotaConfig(tiers=tiers(standard=share_of(est, CHUNKS))))
        results = await chunk_check(rig)
        assert len(answered(results)) == CHUNKS and rig.model.started == CHUNKS

    async def test_chunks_are_charged_together_and_never_refused_piecemeal(self):
        est = estimate_of(text(0))
        rig = QRig(QuotaConfig(tiers=tiers(standard=share_of(est, 2))))  # holds two, not three
        before = rig.status().tokens_available
        results = await chunk_check(rig)
        assert len(refused(results)) == CHUNKS and rig.model.started == 0  # all or none
        assert rig.status().tokens_available == pytest.approx(before)  # nothing was kept
        hints = {r.retry_after_ms for r in results}
        assert len(hints) == 1 and None not in hints  # one retry hint for the whole check
        # and the same bucket still serves a two-chunk check
        assert len(answered(await chunk_check(rig, n=2))) == 2

    async def test_the_chunks_of_a_bucket_too_small_for_the_check_wait_for_the_floor(self):
        est = estimate_of(text(0))
        floored = QuotaConfig(
            tiers=tiers(standard=share_of(est, 1)), largest_check_tokens=est * CHUNKS
        )
        rig = QRig(floored)
        assert len(answered(await chunk_check(rig))) == CHUNKS  # never "too big for the bucket"

    async def test_a_groups_charge_is_the_sum_of_what_each_call_would_have_taken(self):
        est = estimate_of(text(0))
        rig = QRig(QuotaConfig(tiers=tiers(standard=share_of(est, 60))))
        group = rig.gateway.check_group([rig.input] * CHUNKS, QUESTIONS)
        assert group.tokens == (rig.gateway.estimate_call_tokens(rig.input, QUESTIONS),) * CHUNKS
        before = rig.status().tokens_available
        await chunk_check(rig)
        solo = QRig(QuotaConfig(tiers=tiers(standard=share_of(est, 60))))
        solo_before = solo.status().tokens_available
        for _ in range(CHUNKS):
            await solo.check()
        spent, solo_spent = (
            before - rig.status().tokens_available,
            solo_before - solo.status().tokens_available,
        )
        assert spent == pytest.approx(solo_spent, rel=0.01)

    async def test_the_chunks_share_one_fair_queue_place_but_each_needs_a_slot(self):
        est = estimate_of(text(0))
        rig = QRig(
            QuotaConfig(tiers=tiers(standard=share_of(est, 10**4))),
            gateway_kwargs={"max_in_flight_per_key": 2, **LONG_QUEUE},
            model_kwargs={"latency_s": 0.2},
        )
        results = await chunk_check(rig)
        assert len(answered(results)) == CHUNKS
        starts = sorted(t for t, _ in rig.model.starts)
        # two slots: the third chunk starts after one of the first two ends, never earlier
        assert starts[1] - starts[0] < 0.01 and starts[2] - starts[0] >= 0.19

    async def test_chunks_of_one_check_are_not_queued_behind_each_other(self):
        """One place in the fair queue: tenant A's three chunks, submitted before B's one call,
        are served before it, in a row, instead of B being interleaved after the first (which is
        what a per-chunk virtual finish time does, and what makes a later chunk time out)."""
        est = estimate_of(text(0))

        async def order(grouped: bool) -> list[str]:
            rig = QRig(
                QuotaConfig(tiers=tiers(standard=share_of(est, 10**4))),
                gateway_kwargs={"max_in_flight_per_key": 1, **LONG_QUEUE},
                model_kwargs={"latency_s": 0.1},
            )
            g = rig.gateway
            inputs = [f"A{i}" + rig.input[2:] for i in range(CHUNKS)]
            group = g.check_group(inputs, QUESTIONS) if grouped else None
            holder = rig.start(input="H0" + rig.input[2:], tenant_id="t_h")  # holds the slot
            await rig.vt.sleep(0.01)
            calls = [
                asyncio.ensure_future(
                    g.decide_timed(
                        tenant_id="t_a",
                        guard_point="tool_result",
                        input=x,
                        questions=QUESTIONS,
                        group=group,
                        group_index=i,
                    )
                )
                for i, x in enumerate(inputs)
            ]
            await rig.vt.sleep(0.01)
            other = rig.start("tool_result", input="B0" + rig.input[2:], tenant_id="t_b")
            await asyncio.gather(holder, other, *calls)
            return [t[:2] for _, t in rig.model.starts]

        assert await order(True) == ["H0", "A0", "A1", "A2", "B0"]
        assert await order(False) == ["H0", "A0", "B0", "A1", "A2"]

    def test_the_group_takes_one_start_and_one_finish_in_the_fair_queue(self):
        from guardrail_engine.gateway.tenant_quota import CheckGroup, FairClock

        clock = FairClock()
        group = CheckGroup((100, 100, 100))
        first = clock.tag(2, 0.0, group.total_tokens, 1)
        group.tag = first
        # a later sibling reuses it: the same start, not behind its siblings
        assert group.tag == first and first[1] - first[0] == 300


class TestSiblingAwareAllowance:
    async def test_a_chunk_never_waits_out_other_tenants_tokens(self):
        """A chunk never waits out other tenants' calls (the sibling-aware allowance was tried
        and dropped): when others drew the project's tokens, a chunk waiting for tokens is
        refused at its allowance, as any call is, and the others aren't starved."""
        from test_gateway_m3_10 import config_for

        est = estimate_of(text(0))
        # a project bucket that holds three calls and refills one every 1.67 s
        project = config_for(est, 1.67)
        quotas = QuotaConfig(tiers=tiers(standard=share_of(est, 10**9)))

        async def run(others: bool):
            rig = QRig(
                quotas,
                project=project,
                gateways=4,
                gateway_kwargs={"max_in_flight_per_key": 1},
                model_kwargs={"latency_s": 1.0},
            )
            g = rig.gateways[0]
            inputs = [f"{i:04d}" + rig.input[4:] for i in range(2)]
            group = g.check_group(inputs, QUESTIONS)
            calls = [
                asyncio.ensure_future(
                    g.decide_timed(
                        tenant_id="t_a",
                        guard_point="tool_result",
                        input=x,
                        questions=QUESTIONS,
                        group=group,
                        group_index=i,
                    )
                )
                for i, x in enumerate(inputs)
            ]
            extra = []
            if others:
                await rig.vt.sleep(0.9)
                extra = [
                    asyncio.ensure_future(
                        rig.gateways[k].decide_timed(
                            tenant_id=f"t_{k}",
                            guard_point="tool_result",
                            input=f"B{k}" + rig.input[2:],
                            questions=QUESTIONS,
                        )
                    )
                    for k in (1, 2, 3)
                ]
            results = await asyncio.gather(*calls, *extra)
            return results[:2], results[2:], rig

        mine, theirs, _rig = await run(others=True)
        late = mine[1]
        assert isinstance(late.result, Failed) and late.result.reason in (
            "admission_wait",
            "token_rate",
        )  # waiting on other tenants' tokens: refused, not waited out on the budget
        assert late.timing.queue_wait_ms <= 1_500
        assert len(answered(theirs)) >= 2  # and the other tenants weren't starved by it

    async def test_the_checks_bucket_holds_at_least_one_check_per_chunk(self):
        est = estimate_of(text(0))
        tiny = TierQuota(tokens_per_minute=10**9, checks_per_minute=2, requests_per_day=10**9)
        plain = QRig(QuotaConfig(tiers=tiers(standard=tiny)))
        assert plain.status().checks_capacity == pytest.approx(2)
        floored = QRig(QuotaConfig(tiers=tiers(standard=tiny), largest_check_calls=4))
        assert floored.status().checks_capacity == 4
        assert len(answered(await chunk_check(floored, n=4))) == 4  # not refused for its checks
        assert est > 0

    async def test_the_queue_cap_counts_waiters_not_places(self):
        est = estimate_of(text(0))
        quotas = QuotaConfig(
            tiers=tiers(standard=share_of(est, 10**9)), max_queued_fraction_per_tenant=0.5
        )
        rig = QRig(
            quotas,
            gateway_kwargs={"max_in_flight_per_key": 1, "max_queued_per_key": 4, **LONG_QUEUE},
            model_kwargs={"latency_s": 0.5},
        )
        holder = rig.start(input="H0" + rig.input[2:], tenant_id="t_h")
        await rig.vt.sleep(0.01)
        # a tenant may hold half of a 4-place queue: two waiters. A group of 4 chunks is 4.
        results = await chunk_check(rig, n=4)
        await holder
        assert {r.result.reason for r in refused(results)} == {"admission_queue_full"}
        assert len(refused(results)) >= 2

    async def test_a_store_that_fails_mid_group_fails_the_whole_group_cleanly(self):
        est = estimate_of(text(0))
        rig = QRig(QuotaConfig(tiers=tiers(standard=share_of(est, 60))))
        limiter = rig.gateway.quota_limiter
        real = limiter.charge
        calls = {"n": 0}

        def flaky(**kw):
            calls["n"] += 1
            if calls["n"] == 3:
                raise RuntimeError("the store is down")
            return real(**kw)

        limiter.charge = flaky
        before = rig.status().tokens_available
        results = await chunk_check(rig, n=3)
        assert len(refused(results)) == 3 and rig.model.started == 0  # no IndexError, none sent
        assert all(r.result.reason == "token_rate" for r in results)
        limiter.charge = real
        assert rig.status().tokens_available == pytest.approx(before)  # the part-charge is back


class TestGroupQueueRoom:
    """A chunk group's places in the queue are decided for the whole group at its first
    chunk, so no chunk is sent when a later one would be refused ``admission_queue_full``."""

    async def crowded(self, n_chunks: int, tenants: int = 16):
        est = estimate_of(text(0))
        rig = QRig(
            QuotaConfig(tiers=tiers(standard=share_of(est, 10**9))),
            gateway_kwargs={"max_in_flight_per_key": 1, "max_queued_per_key": 64, **LONG_QUEUE},
            model_kwargs={"latency_s": 0.5},
        )
        holder = rig.start(input="H0" + rig.input[2:], tenant_id="t_h")
        await rig.vt.sleep(0.01)
        queued = []
        for k in range(tenants):  # one waiter each: with 16 tenants queued a tenant may hold 3
            queued.append(rig.start(input=f"Q{k:03d}" + rig.input[4:], tenant_id=f"t_q{k}"))
            await asyncio.sleep(0)
        results = await chunk_check(rig, n=n_chunks)
        await holder
        await asyncio.gather(*queued)
        return results

    async def test_no_chunk_is_sent_when_a_later_one_would_be_refused(self):
        results = await self.crowded(4)  # 64 // 17 = 3 places for the tenant: the 4th has none
        assert [r.result.reason for r in refused(results)] == ["admission_queue_full"] * 4
        assert all(r.timing.provider_calls == 0 for r in results)  # nothing was sent
        assert all("4 chunks not sent" in r.result.message for r in results)

    async def test_a_group_that_fits_is_sent_whole(self):
        results = await self.crowded(3)
        assert len(answered(results)) == 3

    async def test_a_refused_group_gives_its_charge_back(self):
        est = estimate_of(text(0))
        rig = QRig(
            QuotaConfig(tiers=tiers(standard=share_of(est, 60))),
            gateway_kwargs={"max_in_flight_per_key": 1, "max_queued_per_key": 4, **LONG_QUEUE},
            model_kwargs={"latency_s": 0.5},
        )
        holder = rig.start(input="H0" + rig.input[2:], tenant_id="t_h")
        await rig.vt.sleep(0.01)
        before = rig.status().tokens_available
        results = await chunk_check(rig, n=4)  # a tenant may hold 2 of 4: the group can't fit
        await holder
        assert {r.result.reason for r in refused(results)} == {"admission_queue_full"}
        assert rig.status().tokens_available == pytest.approx(before, abs=1)
        assert all(r.timing.provider_calls == 0 for r in results)

    async def test_a_group_that_starts_at_once_takes_no_place_for_its_first_chunk(self):
        est = estimate_of(text(0))
        rig = QRig(
            QuotaConfig(
                tiers=tiers(standard=share_of(est, 10**9)), max_queued_fraction_per_tenant=0.5
            ),
            gateway_kwargs={"max_in_flight_per_key": 1, "max_queued_per_key": 4, **LONG_QUEUE},
            model_kwargs={"latency_s": 0.5},
        )
        # an idle key: chunk 1 takes the slot, chunks 2 and 3 take the tenant's two places
        assert len(answered(await chunk_check(rig, n=3))) == 3
