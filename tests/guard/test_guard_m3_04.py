"""M3-04: ``tool_result`` chunking (AC-G5, PF-17, PF-5).

Content over ``chunk_tokens`` is split into chunks overlapping by 256 tokens. The chunk calls
are submitted together, and each goes through the gateway's admission control. Their answers
are merged by the maximum p per question key before fusion. If any chunk fails, the guard
point is a model failure resolved by layer (B1): one of three failing is a block. Redaction
and the deterministic checks run once, on the whole content, before chunking.

All content is invented filler; the "injection" is a benign marker string a test responder
reacts to, and nothing here is harmful.
"""

from __future__ import annotations

import asyncio
import itertools

import pytest
from guard_fixtures import ALPHA, Env, bundle, rule
from hypothesis import given
from hypothesis import strategies as st

from guardrail_engine.decision import (
    Failed,
    FailureKind,
    FakeDecisionModel,
    ProblemKind,
    SafetyBlocked,
)
from guardrail_engine.decision.port import Answered, AnswerProblem
from guardrail_engine.decision.types import ChoiceAnswer, NoulAnswer, ScoreAnswer, Usage
from guardrail_engine.gateway import GatewayConfig
from guardrail_engine.gateway.gateway import (
    DEFAULT_MAX_IN_FLIGHT_PER_KEY,
    CheckTiming,
    TimedDecision,
)
from guardrail_engine.guard import Decision, GuardConfig, Reason
from guardrail_engine.guard.audit import AUDIT_RECORD_SCHEMA_VERSION
from guardrail_engine.guard.chunking import (
    CHUNK_OVERLAP_TOKENS,
    chunk_bounds,
    combine,
    merge_answers,
    overlap_tokens,
    split_chunks,
)
from guardrail_engine.guard.verdict import Basis
from guardrail_engine.policy import (
    DEFAULT_CHUNK_TOKENS,
    DEFAULT_MAX_CHUNKS,
    PlatformSettings,
    PolicyInvalidError,
)
from guardrail_engine.tokens import estimate_tokens

TR = "tool_result"
CHUNK = 1000  # tokens: 4,000 ASCII characters
SIZE = 4 * CHUNK
OVERLAP = 4 * CHUNK_OVERLAP_TOKENS  # 1,024 characters
STEP = SIZE - OVERLAP  # 2,976
THREE = 9_000  # characters: three chunks, [0, 4000], [2976, 6976], [5952, 9000]
FIVE = SIZE + 4 * STEP  # five chunks: the fifth ends exactly at the end


def numbered(chars: int) -> str:
    """Filler of exactly ``chars`` ASCII characters in which every 10 are distinct."""
    text = "".join(f"s{i:05d}abcd" for i in range(chars // 10 + 1))
    return text[:chars]


def put(text: str, at: int, marker: str) -> str:
    return text[:at] + marker + text[at + len(marker) :]


def three_marked() -> str:
    """Three chunks with one marker in each and in no overlap: chunk 0, 1 and 2."""
    content = numbered(THREE)
    for at, marker in ((500, "MARK-A"), (4500, "MARK-B"), (8000, "MARK-C")):
        content = put(content, at, marker)
    return content


def tr_bundle(**kwargs) -> dict:
    return bundle(
        ALPHA,
        rules=[rule("adv", gps=(TR,))],
        guard_points={TR: {"chunk_tokens": CHUNK}},
        **kwargs,
    )


async def check(env: Env, content: str, **kwargs):
    return await env.check(ALPHA, TR, content, **kwargs)


class Reacts(FakeDecisionModel):
    """A fake whose p for ``p__inj_direct`` is the largest of the values of the markers its
    input holds, and which fails (or refuses) a call whose input holds a marked text."""

    def __init__(
        self, p_by_marker=None, *, fail_on=None, refuse_on=None, fail_after=None, **kwargs
    ) -> None:
        super().__init__(**kwargs)
        self.p_by_marker = dict(p_by_marker or {})
        self.fail_on, self.refuse_on, self.fail_after = fail_on, refuse_on, fail_after
        self.in_flight = self.peak = self.attempts = 0

    async def decide(self, input, questions):
        self.in_flight += 1
        self.attempts += 1
        self.peak = max(self.peak, self.in_flight)
        try:
            if self.fail_on and self.fail_on in input:
                await asyncio.sleep(self.latency_s if self.fail_after is None else self.fail_after)
                return Failed(kind=FailureKind.OTHER)
            if self.refuse_on and self.refuse_on in input:
                await asyncio.sleep(self.latency_s)
                return SafetyBlocked(reason="safety")
            self.responder = lambda text, key, q: (
                max([p for m, p in self.p_by_marker.items() if m in text], default=None)
                if key == "p__inj_direct"
                else None
            )
            return await super().decide(input, questions)
        finally:
            self.in_flight -= 1


# ------------------------------------------------------------------ splitting


def test_the_defaults_are_the_rulings():
    assert CHUNK_OVERLAP_TOKENS == 256  # PF-17
    assert DEFAULT_CHUNK_TOKENS == 12_000  # AC-G5, up from 8,000
    assert PlatformSettings().default_chunk_tokens == 12_000
    assert PlatformSettings().max_chunks_per_result == DEFAULT_MAX_CHUNKS == 4
    assert DEFAULT_MAX_CHUNKS == DEFAULT_MAX_IN_FLIGHT_PER_KEY  # every chunk can be in flight


def test_content_that_fits_one_chunk_is_not_split():
    assert chunk_bounds("x" * SIZE, CHUNK) == [(0, SIZE)]
    assert split_chunks("", CHUNK) == [""]
    assert split_chunks("short", CHUNK) == ["short"]


def test_ascii_chunks_overlap_by_exactly_256_tokens():
    text = numbered(THREE)
    bounds = chunk_bounds(text, CHUNK)
    assert bounds == [(0, 4000), (STEP, STEP + 4000), (2 * STEP, THREE)]
    for (_, end), (start, _) in itertools.pairwise(bounds):
        assert end - start == OVERLAP
        assert estimate_tokens(text[start:end]) == CHUNK_OVERLAP_TOKENS
    assert all(estimate_tokens(text[a:b]) <= CHUNK for a, b in bounds)


def test_one_token_over_the_chunk_size_makes_two_chunks_and_nothing_is_dropped():
    text = numbered(SIZE + 4)  # CHUNK + 1 tokens
    chunks = split_chunks(text, CHUNK)
    assert len(chunks) == 2
    assert chunks[0] == text[:SIZE] and chunks[1].endswith(text[-4:])
    assert text[: len(chunks[0])] + chunks[1][OVERLAP:] == text  # coverage, no gap


def test_a_small_chunk_size_overlaps_by_half_so_the_window_moves():
    assert overlap_tokens(1000) == 256 and overlap_tokens(400) == 200 and overlap_tokens(1) == 0
    assert len(split_chunks(numbered(400), 10)) > 1


@given(
    text=st.text(alphabet=st.sampled_from([*"abc  xyz\n", "é", "日", "😀"]), max_size=1500),
    chunk_tokens=st.integers(min_value=1, max_value=60),
)
def test_chunks_cover_the_text_fit_the_size_and_overlap(text, chunk_tokens):
    bounds = chunk_bounds(text, chunk_tokens)
    assert bounds[0][0] == 0 and bounds[-1][1] == len(text)
    for a, b in bounds:
        assert estimate_tokens(text[a:b]) <= chunk_tokens
    for (a1, b1), (a2, b2) in itertools.pairwise(bounds):
        assert a1 < a2 <= b1 < b2  # moves forward, and never leaves a gap
        if chunk_tokens != 2:  # (a 2-token chunk may overlap less to keep moving)
            assert estimate_tokens(text[a2:b1]) >= overlap_tokens(chunk_tokens)


def test_non_ascii_text_is_cut_by_its_heavier_weight():
    text = "日" * 2500  # one token per character
    chunks = split_chunks(text, 1000)
    assert len(chunks) == 4 and all(len(c) <= 1000 for c in chunks)
    assert chunks[1][:256] == chunks[0][-256:]  # the 256-token overlap, as 256 characters


# ------------------------------------------------------------------ merging (PF-5)


def noul(p: float, confidence: float = 0.9) -> NoulAnswer:
    return NoulAnswer(noul=p, confidence=confidence)


def answered(answers=None, problems=None, tokens: int | None = 100) -> Answered:
    return Answered(
        answers=answers or {},
        problems=problems or {},
        usage=None if tokens is None else Usage(total_input_tokens=tokens),
    )


def test_the_merge_takes_the_maximum_p_per_key():
    merged = merge_answers(
        [
            answered({"a": noul(0.2), "b": noul(0.9)}),
            answered({"a": noul(0.7), "b": noul(0.1)}),
            answered({"a": noul(0.4), "b": noul(0.5)}),
        ]
    )
    assert merged.noul("a") == 0.7 and merged.noul("b") == 0.9
    assert merged.problems == {}


def test_the_merge_keeps_the_whole_answer_that_had_the_maximum():
    merged = merge_answers([answered({"a": noul(0.2, 0.99)}), answered({"a": noul(0.7, 0.55)})])
    assert merged.answers["a"] == noul(0.7, 0.55)


def test_a_problem_in_any_chunk_stays_a_problem():
    bad = AnswerProblem(kind=ProblemKind.MISSING, detail="x")
    merged = merge_answers(
        [answered({"a": noul(0.2)}), answered({}, {"a": bad}), answered({"a": noul(0.99)})]
    )
    assert "a" not in merged.answers and merged.problems == {"a": bad}


def test_a_key_one_chunk_said_nothing_about_has_neither_answer_nor_problem():
    merged = merge_answers([answered({"a": noul(0.2)}), answered({})])
    assert "a" not in merged.answers and "a" not in merged.problems


def test_routers_and_scorers_keep_the_most_confident_chunks_answer():
    def choice(option: str, confidence: float) -> ChoiceAnswer:
        return ChoiceAnswer(
            choice=option, probabilities={"x": 0.5, "y": 0.5}, confidence=confidence
        )

    def score(level: int, confidence: float) -> ScoreAnswer:
        return ScoreAnswer(
            score=float(level), probabilities={"0": 0.5, "1": 0.5}, confidence=confidence
        )

    merged = merge_answers(
        [
            answered({"r": choice("x", 0.6), "s": score(0, 0.9)}),
            answered({"r": choice("y", 0.8), "s": score(1, 0.7)}),
        ]
    )
    assert merged.answers["r"].choice == "y" and merged.answers["s"].score == 0.0


def test_mixed_answer_types_for_one_key_are_not_merged():
    merged = merge_answers(
        [
            answered({"a": noul(0.2)}),
            answered({"a": ScoreAnswer(score=0.0, probabilities={"0": 1.0}, confidence=0.9)}),
        ]
    )
    assert "a" not in merged.answers


def test_usage_is_summed_and_unknown_if_any_chunk_has_none():
    assert merge_answers([answered(tokens=100), answered(tokens=250)]).usage == Usage(
        total_input_tokens=350
    )
    unknown = merge_answers([answered(tokens=100), answered(tokens=None)])
    assert unknown.usage is None and unknown.usage_problem


def timed(result, *, wait=0.0, latency=10.0, calls=1, retry=None, capacity=False, in_flight=0):
    return TimedDecision(
        result=result,
        timing=CheckTiming(wait, latency, calls, in_flight),
        retry_after_ms=retry,
        capacity_limited=capacity,
    )


def test_combine_merges_answers_and_adds_up_the_timing():
    out = combine(
        [
            timed(answered({"a": noul(0.2)}), wait=5, latency=100, in_flight=3),
            timed(answered({"a": noul(0.6)}), wait=7, latency=80, calls=2, in_flight=4),
        ]
    )
    assert out.result.noul("a") == 0.6
    assert (out.timing.queue_wait_ms, out.timing.provider_latency_ms) == (12, 180)
    assert out.timing.provider_calls == 3 and out.timing.in_flight_at_start == 3


def test_combine_any_failure_fails_the_whole_check():
    failed = Failed(kind=FailureKind.OTHER, reason="admission_wait")
    out = combine(
        [
            timed(answered({"a": noul(0.99)})),
            timed(failed, retry=250, capacity=True),
            timed(Failed(kind=FailureKind.TIMEOUT), retry=900),
        ]
    )
    assert out.result is failed  # the first failure, in chunk order
    assert out.retry_after_ms == 900 and out.capacity_limited is True


def test_combine_a_safety_refusal_beats_a_failure():
    refused = SafetyBlocked(reason="safety")
    out = combine([timed(Failed(kind=FailureKind.TIMEOUT)), timed(refused)])
    assert out.result is refused


# ------------------------------------------------------------------ the pipeline


async def test_content_at_the_chunk_size_is_one_call():
    async with Env(fake=Reacts()) as env:
        await env.publish(tr_bundle())
        verdict = await check(env, numbered(SIZE))
    assert verdict.decision is Decision.ALLOW and len(env.fake.calls) == 1
    assert verdict.chunks == 1 and verdict.provider_calls == 1


async def test_content_over_the_chunk_size_is_one_call_per_chunk_each_with_every_question():
    content = numbered(THREE)
    expected = split_chunks(content, CHUNK)
    assert len(expected) == 3
    async with Env(fake=Reacts()) as env:
        await env.publish(tr_bundle())
        verdict = await check(env, content)
        policy = (
            await env.service.policy_cache.get(
                env.verifier.verify(env.ctx(ALPHA).signed_context).scope, TR
            )
        ).policy
    assert verdict.decision is Decision.ALLOW and verdict.reason is Reason.POLICY
    assert verdict.chunks == 3 and verdict.provider_calls == 3 and len(env.fake.calls) == 3
    inputs = [c.input for c in env.fake.calls]
    for piece in expected:  # every chunk was sent, whole
        assert sum(piece in text for text in inputs) >= 1
    assert all(c.questions == dict(policy.questions) for c in env.fake.calls)
    assert verdict.content_tokens == estimate_tokens(content)  # of the whole content
    record = env.audit.records[0]
    assert record.chunks == 3 and record.schema_version == AUDIT_RECORD_SCHEMA_VERSION
    assert verdict.usage is not None and verdict.usage.total_input_tokens > 0


async def test_every_chunk_has_its_own_nonce():
    async with Env(fake=Reacts()) as env:
        await env.publish(tr_bundle())
        await check(env, numbered(THREE))
    nonces = {c.input.split("nonce ")[1].split()[0] for c in env.fake.calls}
    assert len(nonces) == 3


async def test_an_injection_straddling_a_chunk_boundary_is_whole_in_one_chunk():
    """PF-17. The marker spans the first hard boundary (character 4,000): neither half
    contains it, but the overlap puts all of it in the second chunk."""
    marker = "STRADDLE-" + "z" * 190
    content = put(numbered(THREE), SIZE - 100, marker)
    assert marker not in content[:SIZE] and marker not in content[SIZE:]  # a hard cut hides it
    async with Env(fake=Reacts({marker: 0.95})) as env:
        await env.publish(tr_bundle())
        verdict = await check(env, content)
    assert (verdict.decision, verdict.reason) == (Decision.BLOCK, Reason.POLICY)
    assert verdict.probabilities["p__inj_direct"] == 0.95
    assert sum(marker in c.input for c in env.fake.calls) == 1


async def test_chunk_answers_are_merged_by_maximum_p_before_fusion():
    content = three_marked()
    async with Env(fake=Reacts({"MARK-A": 0.30, "MARK-B": 0.90, "MARK-C": 0.10})) as env:
        await env.publish(tr_bundle())
        verdict = await check(env, content)
    assert verdict.decision is Decision.BLOCK
    assert (
        verdict.probabilities["p__inj_direct"] == 0.90 == verdict.probabilities_raw["p__inj_direct"]
    )
    assert [(f.key, f.p) for f in verdict.fired] == [("p__inj_direct", 0.90)]
    assert len(verdict.rules) == len({r.key for r in verdict.rules})  # one evaluation per rule


async def test_the_maximum_is_taken_not_the_mean_or_the_last():
    content = put(put(numbered(THREE), 500, "MARK-A"), 4500, "MARK-B")
    async with Env(fake=Reacts({"MARK-A": 0.60, "MARK-B": 0.20})) as env:
        await env.publish(tr_bundle())
        verdict = await check(env, content)
    assert verdict.decision is Decision.ESCALATE  # 0.60 >= escalate_at 0.55; the mean is 0.4
    assert verdict.probabilities["p__inj_direct"] == 0.60


async def test_a_clean_result_is_allowed_whatever_its_length():
    async with Env(fake=Reacts()) as env:  # default settings: four chunks fit the default cap
        await env.publish(tr_bundle())
        verdict = await check(env, numbered(4 * SIZE - 3 * OVERLAP))  # exactly four chunks
    assert verdict.decision is Decision.ALLOW and verdict.chunks == 4


# -- the chunk cap


async def test_a_result_needing_more_chunks_than_the_cap_is_refused_with_no_model_call():
    async with Env(fake=Reacts()) as env:
        await env.publish(tr_bundle())
        over = await check(env, numbered(5 * SIZE))  # five chunks of raw tokens: over the cap
        near = await check(env, numbered(4 * SIZE - 3 * OVERLAP + 4))  # a fifth chunk, barely
    for verdict in (over, near):
        assert (verdict.decision, verdict.reason) == (Decision.BLOCK, Reason.CONTENT_TOO_LARGE)
        assert not verdict.model_called and verdict.chunks == 0
    assert env.fake.calls == []
    assert [h.rule for h in over.deterministic] == ["size_limit"]
    assert near.detail is not None and "5 chunks" in near.detail


async def test_the_chunk_cap_is_a_platform_setting():
    settings = PlatformSettings(min_chunk_tokens=1, max_chunks_per_result=2)
    async with Env(settings=settings, fake=Reacts()) as env:
        await env.publish(tr_bundle())
        two = await check(env, numbered(SIZE + STEP))
        three = await check(env, numbered(SIZE + STEP + 4))
    assert two.decision is Decision.ALLOW and two.chunks == 2
    assert three.reason is Reason.CONTENT_TOO_LARGE


async def test_the_default_chunk_size_is_12000_tokens():
    async with Env(fake=Reacts()) as env:
        await env.publish(bundle(ALPHA, rules=[rule("adv", gps=(TR,))]))
        fits = await check(env, numbered(4 * 12_000))
        over = await check(env, numbered(4 * 12_000 + 4))
    assert fits.chunks == 1 and over.chunks == 2


@pytest.mark.parametrize("guard_point", ["input", "plan", "tool_call", "output"])
async def test_other_guard_points_never_chunk(guard_point):
    async with Env(fake=Reacts()) as env:
        await env.publish(
            bundle(
                ALPHA,
                rules=[rule("adv", gps=(guard_point,))],
                guard_points={guard_point: {"max_input_tokens": CHUNK}},
            )
        )
        verdict = await env.check(ALPHA, guard_point, numbered(SIZE + 4))
    assert verdict.reason is Reason.CONTENT_TOO_LARGE and env.fake.calls == []


# -- failure of a chunk (B1)


@pytest.mark.parametrize("failing", ["MARK-A", "MARK-B", "MARK-C"])
async def test_one_of_three_chunks_failing_blocks_the_whole_check(failing):
    content = three_marked()
    async with Env(fake=Reacts(fail_on=failing)) as env:
        await env.publish(tr_bundle())
        verdict = await check(env, content)
    assert (verdict.decision, verdict.reason) == (Decision.BLOCK, Reason.MODEL_FAILURE)
    assert verdict.failure_kind is FailureKind.OTHER and verdict.retryable
    assert env.fake.attempts == 3 and verdict.chunks == 3  # every chunk was sent
    assert {f.key for f in verdict.fired} >= {"p__inj_direct", "p__ai_addressed"}
    assert all(f.basis is Basis.FAIL_MODE for f in verdict.fired)  # none from the answers
    assert not verdict.probabilities  # the answering chunks' p's aren't used


@pytest.mark.parametrize(
    ("tenant_fail_mode", "decision"), [("closed", Decision.BLOCK), ("open", Decision.ALLOW)]
)
async def test_a_failed_chunk_is_resolved_by_each_rules_layer_fail_mode(tenant_fail_mode, decision):
    """With an open floor, the tenant rule's own fail mode decides, as for a single call."""
    content = put(numbered(THREE), 4500, "MARK-B")
    settings = PlatformSettings(min_chunk_tokens=1, floor_fail_mode="open")
    async with Env(settings=settings, fake=Reacts(fail_on="MARK-B")) as env:
        await env.publish(tr_bundle(defaults={"fail_mode": tenant_fail_mode}))
        verdict = await check(env, content)
    assert (verdict.decision, verdict.reason) == (decision, Reason.MODEL_FAILURE)
    assert verdict.retryable is (decision is Decision.BLOCK)
    for ev in verdict.rules:
        assert ev.basis is Basis.FAIL_MODE
        assert ev.fail_mode == ("open" if ev.layer == "floor" else tenant_fail_mode)


async def test_the_answers_of_the_other_chunks_cant_outvote_a_failed_one():
    """Chunk A answers ``p = 0`` for everything and chunk B fails: not an allow."""
    content = put(numbered(THREE), 4500, "MARK-B")
    async with Env(fake=Reacts(fail_on="MARK-B")) as env:
        await env.publish(tr_bundle())
        verdict = await check(env, content)
    assert verdict.decision is Decision.BLOCK and not verdict.released


async def test_a_provider_safety_refusal_of_any_chunk_is_a_block():
    content = put(numbered(THREE), 4500, "MARK-B")
    async with Env(fake=Reacts(refuse_on="MARK-B")) as env:
        await env.publish(tr_bundle())
        verdict = await check(env, content)
    assert (verdict.decision, verdict.reason) == (Decision.BLOCK, Reason.PROVIDER_SAFETY)
    assert verdict.failure_reason == "safety"


async def test_an_unusable_answer_in_one_chunk_resolves_that_key_by_its_fail_mode():
    """PF-6 across chunks: the bad answer isn't hidden by the other chunks' good ones."""
    async with Env() as env:
        await env.publish(tr_bundle())
        env.fake.malformed_next(missing=["p__inj_direct"])
        verdict = await check(env, numbered(THREE))
    assert verdict.reason is Reason.CONTRACT_VIOLATION and verdict.decision is Decision.BLOCK
    assert [v.key for v in verdict.contract_violations] == ["p__inj_direct"]


# -- admission control


async def test_every_chunk_call_goes_through_admission_control():
    """One slot on the key and a short budget: the first chunk is sent, the others are
    refused by the gateway rather than sent beside it. Any chunk refused fails the check, as
    a capacity failure with a retry hint."""
    gateway = GatewayConfig(max_in_flight_per_key=1, default_budget_s=0.3, expected_latency_s=0.2)
    async with Env(
        fake=Reacts(latency_s=0.05), config=GuardConfig(pointer_ttl_s=60.0, gateway=gateway)
    ) as env:
        await env.publish(tr_bundle())
        verdict = await check(env, numbered(THREE))
    assert (verdict.decision, verdict.reason) == (Decision.BLOCK, Reason.MODEL_FAILURE)
    assert verdict.failure_reason == "admission_wait"
    assert verdict.capacity_limited is True and verdict.retry_after_ms is not None
    assert len(env.fake.calls) == 1 and verdict.provider_calls == 1  # only one chunk got through
    assert verdict.chunks == 3 and verdict.retryable


async def test_the_chunks_share_the_keys_in_flight_limit_and_wait_for_a_slot():
    """No assumed parallelism: five chunks on a key with two slots never have more than two
    calls at the provider at once, and all five are answered when the queue allows it."""
    gateway = GatewayConfig(
        max_in_flight_per_key=2,
        default_budget_s=5.0,
        expected_latency_s=0.05,
        queue_waits_s={TR: 5.0},
    )
    fake = Reacts(latency_s=0.05)
    config = GuardConfig(pointer_ttl_s=60.0, gateway=gateway)
    settings = PlatformSettings(
        min_chunk_tokens=1, max_chunks_per_result=8
    )  # past the default cap of 4
    async with Env(fake=fake, config=config, settings=settings) as env:
        await env.publish(tr_bundle())
        verdict = await check(env, numbered(FIVE))
    assert verdict.decision is Decision.ALLOW and verdict.chunks == 5
    assert len(fake.calls) == 5 and fake.peak == 2
    assert verdict.queue_wait_ms > 0  # the later chunks waited for a slot


async def test_the_chunk_calls_are_submitted_together():
    """With enough slots the five calls overlap: the check takes about one call's time."""
    gateway = GatewayConfig(max_in_flight_per_key=8, default_budget_s=5.0)
    fake = Reacts(latency_s=0.2)
    config = GuardConfig(pointer_ttl_s=60.0, gateway=gateway)
    settings = PlatformSettings(
        min_chunk_tokens=1, max_chunks_per_result=8
    )  # past the default cap of 4
    async with Env(fake=fake, config=config, settings=settings) as env:
        await env.publish(tr_bundle())
        verdict = await check(env, numbered(FIVE))
    assert fake.peak == 5 and verdict.model_latency_ms < 0.5 * 5 * 200


# -- whole-content work happens once, before chunking


async def test_a_deny_pattern_is_matched_on_the_whole_content_even_across_a_boundary():
    document = tr_bundle()
    document["deterministic"] = {
        "deny_patterns": [{"id": "phrase", "regex": "banned phrase here", "action": "block"}]
    }
    content = put(numbered(THREE), SIZE - 9, "banned phrase here")  # straddles character 4,000
    assert "banned phrase here" not in content[:SIZE]
    assert "banned phrase here" not in content[SIZE:]
    async with Env(fake=Reacts()) as env:
        await env.publish(document)
        verdict = await check(env, content)
    assert (verdict.decision, verdict.reason) == (Decision.BLOCK, Reason.DETERMINISTIC)
    assert [h.rule for h in verdict.deterministic] == ["deny__phrase"]
    assert env.fake.calls == [] and verdict.chunks == 0  # AC-G1: no model call at all


async def test_redaction_runs_once_on_the_whole_content_before_chunking():
    email = "ann.lee@example.org"
    # One address in the overlap of the first two chunks (it is sent in both), and one across
    # the first hard boundary.
    content = put(put(numbered(THREE), 3300, f" {email} "), SIZE - 8, f" {email} ")
    async with Env(fake=Reacts()) as env:
        await env.publish(tr_bundle())
        verdict = await check(env, content)
    assert verdict.decision is Decision.ALLOW and verdict.chunks == 3
    assert verdict.pii_redacted == {"email": 2}  # counted once each, not once per chunk
    for call in env.fake.calls:  # the local part never reaches the model; the host does (AC-G2)
        assert "ann.lee" not in call.input
    assert any("[EMAIL]@example.org" in call.input for call in env.fake.calls)


async def test_chunks_are_cut_from_the_redacted_content_and_the_hash_is_of_the_original():
    from guardrail_engine.guard.service import content_sha256

    content = put(numbered(THREE), 100, "ann.lee@example.org")
    async with Env(fake=Reacts()) as env:
        await env.publish(tr_bundle())
        verdict = await check(env, content)
    assert verdict.content_sha256 == content_sha256(content)  # PF-14: pre-redaction


async def test_the_context_goes_to_every_chunk_that_has_room_for_it():
    from guardrail_engine.guard import Turn

    async with Env(fake=Reacts()) as env:
        await env.publish(tr_bundle())
        short_last = numbered(SIZE + 400)  # a short second chunk leaves room for context
        verdict = await env.check(
            ALPHA, TR, short_last, conversation=(Turn("user", "what is my claim status"),)
        )
    assert verdict.chunks == 2
    with_context = [c for c in env.fake.calls if "what is my claim status" in c.input]
    assert len(with_context) == 1  # a full chunk has no room: the oldest context is cut first
    assert verdict.context_items_dropped == 1  # the worst case over the chunks


async def test_a_draft_test_chunks_the_same_way():
    """The Admin API's test endpoint runs the same pipeline (``evaluate_draft``). Its calls
    queue behind production (M3-08), so the queue allowance is made generous here."""
    gateway = GatewayConfig(default_budget_s=5.0, queue_waits_s={TR: 5.0})
    config = GuardConfig(pointer_ttl_s=60.0, gateway=gateway)
    async with Env(fake=Reacts(), config=config) as env:
        await env.publish(tr_bundle())
        scope = env.verifier.verify(env.verifier.issue(ALPHA)).scope
        policy = (await env.service.policy_cache.get(scope, TR)).policy
        verdict = await env.service.evaluate_draft(scope, policy, numbered(THREE))
    assert verdict.chunks == 3 and len(env.fake.calls) == 3 and env.audit.verdicts == []


# -- queued chunks are cancelled on the first failure

QUEUED = GatewayConfig(
    max_in_flight_per_key=1,
    default_budget_s=5.0,
    expected_latency_s=0.05,
    queue_waits_s={TR: 5.0},
)


async def test_the_first_failure_cancels_the_chunk_calls_still_queued():
    """One slot, four chunks, the first (admitted) one fails: the three queued chunks are
    cancelled before they reach the provider."""
    content = put(numbered(FIVE - STEP), 500, "MARK-A")  # four chunks; MARK-A is in the first
    assert len(split_chunks(content, CHUNK)) == 4
    fake = Reacts(fail_on="MARK-A", latency_s=0.05)
    config = GuardConfig(pointer_ttl_s=60.0, gateway=QUEUED)
    async with Env(fake=fake, config=config) as env:
        await env.publish(tr_bundle())
        verdict = await check(env, content)
    assert (verdict.decision, verdict.reason) == (Decision.BLOCK, Reason.MODEL_FAILURE)
    # The queued chunks were cancelled: at most the one admitted in the instant the failed
    # call freed its slot was sent as well.
    assert 1 <= fake.attempts <= 2
    assert verdict.chunks == 4 and verdict.provider_calls == fake.attempts
    assert env.service.gateway.queued() == 0  # nothing left waiting for a slot


async def test_chunk_calls_already_in_flight_are_left_to_end_when_another_fails():
    gateway = GatewayConfig(
        max_in_flight_per_key=2,
        default_budget_s=5.0,
        expected_latency_s=0.05,
        queue_waits_s={TR: 5.0},
    )
    content = put(numbered(FIVE - STEP), 500, "MARK-A")
    fake = Reacts(fail_on="MARK-A", fail_after=0.01, latency_s=0.15)  # the failure comes first
    config = GuardConfig(pointer_ttl_s=60.0, gateway=gateway)
    async with Env(fake=fake, config=config) as env:
        await env.publish(tr_bundle())
        verdict = await check(env, content)
    assert verdict.reason is Reason.MODEL_FAILURE
    assert fake.attempts < 4  # not every chunk was sent: queued ones were cancelled
    assert len(fake.calls) >= 1  # the admitted sibling ran to its end, it wasn't cancelled
    assert verdict.provider_calls == fake.attempts


async def test_a_safety_refusal_also_cancels_the_queued_chunks():
    content = put(numbered(FIVE - STEP), 500, "MARK-A")
    fake = Reacts(refuse_on="MARK-A", latency_s=0.05)
    config = GuardConfig(pointer_ttl_s=60.0, gateway=QUEUED)
    async with Env(fake=fake, config=config) as env:
        await env.publish(tr_bundle())
        verdict = await check(env, content)
    assert verdict.reason is Reason.PROVIDER_SAFETY and fake.attempts <= 2


async def test_cancelling_the_caller_cancels_every_chunk_call():
    fake = Reacts(latency_s=5.0)
    config = GuardConfig(pointer_ttl_s=60.0, gateway=QUEUED)
    async with Env(fake=fake, config=config) as env:
        await env.publish(tr_bundle())
        task = asyncio.ensure_future(check(env, numbered(THREE)))
        await asyncio.sleep(0.1)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert env.service.gateway.queued() == 0


# -- a tenant's chunk_tokens has a floor


@pytest.mark.parametrize(("chunk_tokens", "ok"), [(2047, False), (1, False), (2048, True)])
async def test_a_tenants_chunk_tokens_is_at_least_2048(chunk_tokens, ok):
    document = bundle(
        ALPHA, rules=[rule("adv", gps=(TR,))], guard_points={TR: {"chunk_tokens": chunk_tokens}}
    )
    async with Env(settings=PlatformSettings()) as env:  # the platform's own minimum
        if ok:
            await env.publish(document)
        else:
            with pytest.raises(PolicyInvalidError) as error:
                await env.publish(document)
            assert [e.code for e in error.value.errors] == ["guard_point.chunk_tokens_too_small"]
            assert error.value.errors[0].path == "$.guard_points.tool_result.chunk_tokens"


def test_the_platform_minimum_is_2048_and_unset_uses_the_default():
    assert PlatformSettings().min_chunk_tokens == 2_048 <= DEFAULT_CHUNK_TOKENS
