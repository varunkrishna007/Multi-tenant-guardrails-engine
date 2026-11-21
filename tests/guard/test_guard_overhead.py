"""M1-05 overhead: with the fake at zero latency, the whole check's p95 time apart from the
model call is <= 50 ms **at the largest call the compiler accepts under default settings**.

**The largest call (R6).** The compiler bounds a guard point three ways: the question
budget (50 on the critical path, 200 on ``input``), the content bound
``ceil(1.20 x (max content + render overhead)) + 30 <= token_budget`` and the question-text
bound (150 API tokens per budgeted question, at most 400 per question). Here every size is
derived from the compiler's own settings and compiled figures:

* content cap: the largest ``max_input_tokens`` the content bound accepts (cap + 1 is
  refused with ``guard_point.token_budget_exceeded``);
* questions: exactly the guard point's question budget (one more is refused with
  ``guard_point.too_many_questions``), sized so the question text fills its bound to
  within one token per question.

So the binding limit is the question count, as R6 expects, and the call is the largest in
both questions and tokens.

**What runs where.**

* The default suite runs the structural tests: the size really is the largest the compiler
  accepts, the call made at that size carries every question and the whole content and
  agrees with the compiler's content bound, and the measured latency covers the service's
  work. (A cache hit doing no compile work is ``test_guard_policy_cache``.)
* The absolute 50 ms bounds are marked ``perf`` and deselected by default, because wall-time
  bounds fail on a busy machine. Run them on a quiet runner: ``uv run pytest -m perf -s``.
  Each prints the size it used and its numbers. The 16K-token x 200-question test from the
  earlier wording is kept as an extra ``perf`` stress test with raised settings.

What is measured: each check's ``latency_ms``, the wall time of the whole check
(verification, cached policy lookup, floor check, size check, hashing, rendering, the
gateway, the fake's request validation, response building and parsing, resolution, fusion
and the verdict). The fake's latency is zero, so this is everything apart from the model
call; ``overhead_ms`` (everything except the gateway call) is reported alongside.
"""

import statistics
import time
from dataclasses import dataclass

import pytest
from guard_fixtures import ALPHA, FLOOR_V1, Env, bundle, noul_document, profile
from policy_fixtures import make_pack, pack_rule

from guardrail_engine.decision import NoulQuestion
from guardrail_engine.guard import Decision, GuardConfig, Plan, ToolResult, Turn
from guardrail_engine.policy import (
    CompiledGuardPoint,
    ErrorCode,
    InMemoryCatalog,
    PlatformSettings,
    PolicyCompiler,
    PolicyInvalidError,
    QuestionBudgets,
    TenantAttributes,
    content_api_tokens,
    parse_bundle,
    question_api_tokens,
)
from guardrail_engine.tokens import estimate_question_tokens, estimate_tokens

BOUND_MS = 50.0
WARMUP = 20
RUNS = 200


def p95(values):
    return statistics.quantiles(values, n=20, method="inclusive")[18]


def compile_gp(catalog, settings, document, guard_point) -> CompiledGuardPoint:
    compiler = PolicyCompiler(catalog, profile(ALPHA), settings)
    compiled = compiler.compile(parse_bundle(document), TenantAttributes(tenant_id=ALPHA))
    return compiled.guard_points[guard_point]


def refused_codes(catalog, settings, document) -> set[ErrorCode]:
    with pytest.raises(PolicyInvalidError) as refused:
        compile_gp(catalog, settings, document, "output")
    return {e.code for e in refused.value.errors}


def fill_question(i: int, pad: int) -> dict:
    return noul_document(
        f"Does the content break fill rule {i:04d} about regulated claims?",
        "States or implies something this rule forbids. " + "x" * pad,
        "Says nothing this rule forbids.",
    )


def question_cost(question: dict) -> int:
    """API tokens of one question as the compiler counts them (R6.7)."""
    return question_api_tokens(
        estimate_question_tokens({"d__q0000": NoulQuestion.model_validate(question)}), 1
    )


def largest_content_cap(settings: PlatformSettings) -> int:
    """The largest content cap the compiler's content bound accepts."""
    cap = settings.token_budget
    while content_api_tokens(cap + settings.render_overhead_tokens) > settings.token_budget:
        cap -= 1
    return cap


@dataclass
class LargestCall:
    guard_point: str
    settings: PlatformSettings
    catalog: InMemoryCatalog
    document: dict
    rules: list[dict]
    cap: int
    compiled: CompiledGuardPoint
    question_text_limit: int


def largest_call(guard_point: str) -> LargestCall:
    settings = PlatformSettings()  # defaults
    budget = settings.question_budgets.for_guard_point(guard_point)
    cap = largest_content_cap(settings)
    gp_config = {guard_point: {"max_input_tokens": cap}}
    floor_only = compile_gp(
        InMemoryCatalog(floors=[FLOOR_V1]), settings, bundle(ALPHA, guard_points=gp_config),
        guard_point,
    )  # fmt: skip
    fill = budget - len(floor_only.questions)
    limit = settings.question_text_tokens_per_budgeted_question * budget
    share = min((limit - floor_only.question_api_tokens) // fill, settings.max_question_tokens)
    pad = 0
    while question_cost(fill_question(0, pad + 1)) <= share:
        pad += 1
    rules = [pack_rule(f"d__q{i:04d}", (guard_point,), question=fill_question(i, pad))
             for i in range(fill)]  # fmt: skip
    catalog = InMemoryCatalog(floors=[FLOOR_V1], packs=[make_pack("fill", 1, *rules)])
    document = bundle(ALPHA, packs=["domain/fill@1"], guard_points=gp_config)
    compiled = compile_gp(catalog, settings, document, guard_point)
    return LargestCall(guard_point, settings, catalog, document, rules, cap, compiled, limit)


def content_of(tokens: int) -> str:
    return ("The policy covers water damage, fire and theft. " * 2000)[: 4 * tokens]


CONTEXT = (
    Turn("user", "What does my policy cover? " * 20),
    Plan('{"steps": ["look up the policy", "summarise the cover"]}'),
    ToolResult("cms.search", '{"hits": ["water damage", "fire", "theft"]} ' * 20),
)


# ------------------------------------------------------------------ default suite: structure


@pytest.mark.parametrize("guard_point", ["output", "input"])
async def test_largest_call_is_the_largest_the_compiler_accepts_and_is_sent_whole(guard_point):
    call = largest_call(guard_point)
    s, gp = call.settings, call.compiled
    budget = s.question_budgets.for_guard_point(guard_point)

    # The size binds on every axis: questions, content and question text.
    assert len(gp.questions) == budget == (50 if guard_point == "output" else 200)
    assert gp.max_content_tokens == call.cap
    assert gp.content_api_tokens == content_api_tokens(call.cap + s.render_overhead_tokens)
    assert gp.content_api_tokens <= s.token_budget
    assert call.question_text_limit - gp.question_api_tokens < len(call.rules)
    assert gp.question_api_tokens <= call.question_text_limit

    one_more_question = InMemoryCatalog(
        floors=[FLOOR_V1],
        packs=[
            make_pack(
                "fill",
                1,
                *call.rules,
                pack_rule("d__q9999", (guard_point,), question=call.rules[0]["question"]),
            )
        ],
    )
    with pytest.raises(PolicyInvalidError) as refused:
        compile_gp(one_more_question, s, call.document, guard_point)
    assert ErrorCode.GP_TOO_MANY_QUESTIONS in {e.code for e in refused.value.errors}
    bigger_cap = {
        **call.document,
        "guard_points": {guard_point: {"max_input_tokens": call.cap + 1}},
    }
    with pytest.raises(PolicyInvalidError) as refused:
        compile_gp(call.catalog, s, bigger_cap, guard_point)
    assert ErrorCode.GP_TOKEN_BUDGET in {e.code for e in refused.value.errors}

    # The call made at that size: every question, the whole content, context cut to fit.
    content = content_of(call.cap)
    async with Env(catalog=call.catalog, settings=s) as env:
        await env.publish(call.document)
        verdict = await env.check(ALPHA, guard_point, content, conversation=CONTEXT)
        sent = env.fake.calls[-1]
    assert verdict.decision is Decision.ALLOW and verdict.content_tokens == call.cap
    assert verdict.context_items_dropped == len(CONTEXT)  # no room left at the cap
    assert len(sent.questions) == budget and content in sent.input

    # Consistent with the compiler's content bound (M1-05 x R6.7): what the service renders
    # never exceeds the max content + render overhead the compiler bounded.
    rendered = estimate_tokens(sent.input)
    assert rendered <= call.cap + s.render_overhead_tokens
    assert content_api_tokens(rendered) <= gp.content_api_tokens <= s.token_budget
    print(
        f"\nM1-05 largest call [{guard_point}]: {len(sent.questions)} questions "
        f"({gp.question_api_tokens} question API tokens of {call.question_text_limit}), "
        f"content cap {call.cap} tokens, rendered input {rendered} tokens "
        f"({content_api_tokens(rendered)} content API tokens of {s.token_budget})"
    )


async def test_overhead_measurement_includes_the_service_work():
    """The latency the overhead tests assert on is real wall time around the whole check,
    not a number that leaves the expensive parts out."""
    async with Env() as env:
        await env.publish(bundle(ALPHA))
        start = time.perf_counter()
        verdict = await env.check(ALPHA, "output", "x" * 4000)
        wall_ms = (time.perf_counter() - start) * 1000
    assert 0 < verdict.latency_ms <= wall_ms
    assert verdict.model_latency_ms < verdict.latency_ms


# ------------------------------------------------------------------ perf: absolute bounds


async def measure(env, guard_point, content, context=()):
    latencies, overheads = [], []
    for i in range(WARMUP + RUNS):
        verdict = await env.check(ALPHA, guard_point, content, conversation=context)
        if i >= WARMUP:
            latencies.append(verdict.latency_ms)
            overheads.append(verdict.overhead_ms)
    return verdict, latencies, overheads


def report(label, call, latencies, overheads):
    print(
        f"\nM1-05 overhead [{label}] over {RUNS} checks: {len(call.questions)} questions + "
        f"{estimate_tokens(call.input)}-token input; whole check p50 "
        f"{statistics.median(latencies):.2f} ms, p95 {p95(latencies):.2f} ms; service only "
        f"(excluding the gateway call) p50 {statistics.median(overheads):.2f} ms, "
        f"p95 {p95(overheads):.2f} ms; bound {BOUND_MS} ms"
    )


@pytest.mark.perf
@pytest.mark.parametrize("guard_point", ["output", "input"])
async def test_perf_overhead_p95_within_50ms_at_the_largest_call(guard_point):
    call = largest_call(guard_point)
    config = GuardConfig(pointer_ttl_s=60)
    async with Env(catalog=call.catalog, settings=call.settings, config=config) as env:
        await env.publish(call.document)
        verdict, latencies, overheads = await measure(env, guard_point, content_of(call.cap))
        sent = env.fake.calls[-1]
    assert verdict.decision is Decision.ALLOW
    report(f"largest call, {guard_point}", sent, latencies, overheads)
    assert p95(latencies) <= BOUND_MS


STRESS_QUESTIONS = 200
STRESS_INPUT_TOKENS = 16_000


@pytest.mark.perf
async def test_perf_stress_16k_tokens_and_200_questions_on_output_with_raised_settings():
    """Stress test, not the criterion: 16K tokens of content and context with 200 questions
    on ``output``. The default settings refuse this (question budget 50; content bound), so
    this test raises ``question_budgets.output`` to 200 and ``token_budget`` to 40,000."""
    settings = PlatformSettings(
        question_budgets=QuestionBudgets(output=STRESS_QUESTIONS), token_budget=40_000
    )
    fill = STRESS_QUESTIONS - 3
    pack = make_pack(
        "big", 1, *(pack_rule(f"d__q{i:04d}", ("output",), question=fill_question(i, 0))
                    for i in range(fill))
    )  # fmt: skip
    catalog = InMemoryCatalog(floors=[FLOOR_V1], packs=[pack])
    document = bundle(
        ALPHA,
        packs=["domain/big@1"],
        guard_points={"output": {"max_input_tokens": STRESS_INPUT_TOKENS}},
    )
    content = content_of(STRESS_INPUT_TOKENS - 520)  # room for CONTEXT as rendered
    config = GuardConfig(pointer_ttl_s=60)
    async with Env(catalog=catalog, settings=settings, config=config) as env:
        await env.publish(document)
        verdict, latencies, overheads = await measure(env, "output", content, CONTEXT)
        sent = env.fake.calls[-1]
    assert verdict.decision is Decision.ALLOW and verdict.context_items_dropped == 0
    assert len(sent.questions) == STRESS_QUESTIONS
    report("stress, raised settings", sent, latencies, overheads)
    assert p95(latencies) <= BOUND_MS
