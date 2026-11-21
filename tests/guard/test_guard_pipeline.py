"""M1-05 pipeline: the order of the stages, the size limit (content over the cap is never
truncated), one gateway call per check, one audited verdict per check, the verdict's fields,
and the service's ownership of the gateway."""

import asyncio
from datetime import datetime

import pytest
from guard_fixtures import (
    ALPHA,
    CLAIMS_V1,
    FLOOR_KEYS,
    Env,
    bundle,
    rule,
)
from policy_fixtures import floor_rule, make_floor

import guardrail_engine.guard.service as service_module
from guardrail_engine.decision import Failed, FailureKind
from guardrail_engine.gateway import InMemoryUsageMeter
from guardrail_engine.guard import CheckContext, Decision, GuardService, PolicySource, Reason, Turn
from guardrail_engine.policy import GUARD_POINTS, InMemoryCatalog

CAP = 50


def capped_bundle():
    gps = {gp: {"max_input_tokens": CAP} for gp in GUARD_POINTS if gp != "tool_result"}
    gps["tool_result"] = {"chunk_tokens": CAP, "max_input_tokens": 10_000}
    return bundle(ALPHA, rules=[rule("adv", gps=GUARD_POINTS)], guard_points=gps)


@pytest.mark.parametrize("guard_point", [gp for gp in GUARD_POINTS if gp != "tool_result"])
async def test_content_one_token_over_the_cap_is_a_deterministic_block_with_no_model_call(
    guard_point,
):
    """Every guard point that doesn't chunk, never truncated. ``tool_result`` is split into
    chunks instead (M3-04: ``test_guard_m3_04.py``), and blocked only past the chunk cap."""
    over = "x" * (4 * CAP + 1)  # CAP + 1 tokens
    async with Env() as env:
        await env.publish(capped_bundle())
        verdict = await env.check(ALPHA, guard_point, over)
    assert (verdict.decision, verdict.reason) == (Decision.BLOCK, Reason.CONTENT_TOO_LARGE)
    assert verdict.content_tokens == CAP + 1
    assert not verdict.model_called and env.fake.calls == []
    assert env.audit.verdicts == [verdict]
    assert verdict.bundle_version == 1 and verdict.content_sha256 is not None


@pytest.mark.parametrize("guard_point", GUARD_POINTS)
async def test_content_exactly_at_the_cap_is_sent_whole(guard_point):
    at_cap = "x" * (4 * CAP)
    async with Env() as env:
        await env.publish(capped_bundle())
        verdict = await env.check(ALPHA, guard_point, at_cap)
    assert verdict.decision is Decision.ALLOW and verdict.model_called
    assert at_cap in env.fake.calls[0].input


async def test_size_limit_blocks_even_when_the_model_is_down():
    """B1 rule 3: deterministic checks count whether or not the model answers."""
    async with Env() as env:
        await env.publish(capped_bundle())
        env.fake.always(Failed(kind=FailureKind.UNAVAILABLE))
        verdict = await env.check(ALPHA, "output", "x" * (4 * CAP + 4))
    assert verdict.reason is Reason.CONTENT_TOO_LARGE


async def test_order_size_limit_then_redact_then_render_then_one_decide_then_fusion(monkeypatch):
    """M1-14 ("Order with sizes and tokens"): the size bound on the raw content, then
    redaction, then the redacted content is sized for rendering."""
    events: list[str] = []

    def spy(name, fn):
        def wrapper(*args, **kwargs):
            events.append(name)
            return fn(*args, **kwargs)

        return wrapper

    monkeypatch.setattr(service_module, "count_tokens", spy("size", service_module.count_tokens))
    redact = spy("redact", service_module.redact_request)
    monkeypatch.setattr(service_module, "redact_request", redact)
    monkeypatch.setattr(service_module, "render_input", spy("render", service_module.render_input))
    monkeypatch.setattr(service_module, "fuse", spy("fuse", service_module.fuse))
    async with Env() as env:
        await env.publish(bundle(ALPHA, rules=[rule("adv")]))
        real_decide = env.service.gateway.decide_timed

        async def decide(**kwargs):
            events.append("decide")
            return await real_decide(**kwargs)

        monkeypatch.setattr(env.service.gateway, "decide_timed", decide)
        await env.check(ALPHA)
    assert events == ["size", "redact", "size", "render", "decide", "fuse"]


async def test_one_decide_call_per_check_with_the_guard_points_compiled_questions():
    async with Env() as env:
        await env.publish(bundle(ALPHA, rules=[rule("adv")], packs=["domain/claims@1"]))
        await env.check(ALPHA, "output")
        await env.check(ALPHA, "input")
    output_call, input_call = env.fake.calls
    assert set(output_call.questions) == FLOOR_KEYS | {"p__secret", "d__claim_promise", "t__adv"}
    assert set(input_call.questions) == FLOOR_KEYS | {"d__route"}
    assert output_call.questions["d__claim_promise"] == CLAIMS_V1.rules[0].question


async def test_guard_point_with_no_questions_is_allowed_without_a_model_call():
    floor = make_floor(
        1,
        floor_rule(
            "p__only_output",
            ("output",),
            question="Does it leak a secret?",
            true_description="Leaks one.",
            false_description="Leaks none.",
            block_at=0.85,
            escalate_at=0.55,
        ),
    )
    catalog = InMemoryCatalog(floors=[floor])
    async with Env(catalog=catalog) as env:
        await env.publish(bundle(ALPHA, guard_points={"plan": {"enabled": False}}))
        verdict = await env.check(ALPHA, "plan", "Step 1: look it up.")
        too_big = await env.check(ALPHA, "plan", "x" * 40_000)
    assert (verdict.decision, verdict.reason) == (Decision.ALLOW, Reason.NO_QUESTIONS)
    assert env.fake.calls == []
    assert too_big.reason is Reason.CONTENT_TOO_LARGE  # the size limit still applies


@pytest.mark.parametrize("guard_point", ["", "OUTPUT", "final", None, 3])
async def test_unknown_guard_point_is_an_invalid_request(guard_point):
    async with Env() as env:
        await env.publish(bundle(ALPHA))
        verdict = await env.service.check(env.ctx(ALPHA), guard_point, "x")
    assert (verdict.decision, verdict.reason) == (Decision.BLOCK, Reason.INVALID_REQUEST)
    assert env.fake.calls == [] and env.audit.verdicts == [verdict]


@pytest.mark.parametrize("content", [None, b"bytes", 42, ["x"]])
async def test_content_that_is_not_text_is_an_invalid_request(content):
    async with Env() as env:
        await env.publish(bundle(ALPHA))
        verdict = await env.service.check(env.ctx(ALPHA), "output", content)
    assert (verdict.decision, verdict.reason) == (Decision.BLOCK, Reason.INVALID_REQUEST)


async def test_audit_sink_receives_exactly_one_verdict_per_check_for_every_outcome():
    async with Env() as env:
        await env.publish(capped_bundle())
        verdicts = [
            await env.check(ALPHA, "output", "fine"),  # allow
            await env.check(ALPHA, "output", "x" * 4000),  # deterministic block
            await env.service.check(env.ctx(ALPHA, payload_tenant_id="t_other"), "output", "x"),
            await env.service.check(CheckContext("forged"), "output", "x"),
        ]
        env.fake.always(Failed(kind=FailureKind.AUTH))
        verdicts.append(await env.check(ALPHA, "output", "fine"))
        env.fake.always(None)
        verdicts.append(await env.service.check(env.ctx("t_gamma"), "output", "x"))
    assert env.audit.verdicts == verdicts
    assert [(v.decision, v.reason) for v in verdicts] == [
        (Decision.ALLOW, Reason.POLICY),
        (Decision.BLOCK, Reason.CONTENT_TOO_LARGE),
        (Decision.FORBIDDEN, Reason.TENANT_MISMATCH),
        (Decision.FORBIDDEN, Reason.CONTEXT_INVALID),
        (Decision.BLOCK, Reason.MODEL_FAILURE),
        (Decision.BLOCK, Reason.POLICY_UNAVAILABLE),
    ]
    assert len({v.request_id for v in verdicts}) == len(verdicts)


async def test_verdict_carries_what_the_audit_record_needs():
    async with Env() as env:
        bundle_hash = await env.publish(bundle(ALPHA, rules=[rule("adv")]))
        env.fake.set_noul("t__adv", 0.9).set_noul("p__inj_direct", 0.6)
        verdict = await env.check(
            ALPHA, "output", "Buy now.", request_id="req-123", conversation=(Turn("user", "hi"),)
        )

    assert verdict.request_id == "req-123"
    assert verdict.tenant_id == ALPHA and verdict.guard_point == "output"
    assert (verdict.decision, verdict.reason) == (Decision.BLOCK, Reason.POLICY)
    assert (verdict.bundle_version, verdict.bundle_hash) == (1, bundle_hash)
    assert verdict.policy_source is PolicySource.ACTIVE
    assert verdict.model_called and verdict.model_id == "fake-decision"
    assert verdict.usage is not None and verdict.input_tokens > 0
    assert verdict.usage.total_output_tokens == 0
    assert verdict.latency_ms >= verdict.model_latency_ms >= 0
    assert verdict.overhead_ms >= 0
    assert isinstance(verdict.checked_at, datetime) and verdict.checked_at.tzinfo is not None
    assert verdict.content_sha256.startswith("sha256:") and verdict.content_tokens == 2
    assert (verdict.context_items, verdict.context_items_dropped) == (1, 0)
    fired = {f.key: f for f in verdict.fired}
    assert set(fired) == {"t__adv", "p__inj_direct"}
    assert (fired["t__adv"].action, fired["t__adv"].mode, fired["t__adv"].layer) == (
        "block",
        "enforce",
        "tenant",
    )
    assert fired["p__inj_direct"].provisional and not fired["t__adv"].provisional
    assert (fired["p__inj_direct"].p, fired["p__inj_direct"].action) == (0.6, "escalate")
    assert set(verdict.provisional_rules) == {"p__inj_direct", "p__ai_addressed"}
    assert len(verdict.rules) == len(verdict.probabilities) == 4
    assert verdict.failure_kind is None
    # The verdict serialises for the audit record.
    dumped = verdict.model_dump(mode="json")
    assert dumped["decision"] == "block" and dumped["fired"][0]["key"]


async def test_request_id_is_generated_when_missing_or_unusable():
    async with Env() as env:
        await env.publish(bundle(ALPHA))
        a = await env.check(ALPHA)
        b = await env.check(ALPHA, request_id="x" * 500)
    assert len(a.request_id) == 32 and len(b.request_id) == 32 and a.request_id != b.request_id


async def test_service_owns_the_gateway_and_passes_it_the_key_id():
    meter = InMemoryUsageMeter()
    async with Env(meter=meter) as env:
        await env.publish(bundle(ALPHA))
        await env.check(ALPHA)
        await env.service.gateway.drain()
        assert meter.input_tokens(ALPHA, "output") > 0
        env.fake.always(Failed(kind=FailureKind.AUTH))
        await env.check(ALPHA)
        assert env.service.gateway.breaker_open("secret-version-1")
    for _ in range(5):  # let released timers finish being cancelled
        await asyncio.sleep(0)
    assert len(asyncio.all_tasks()) == 1  # aclose() left nothing running


def test_key_id_is_required():
    with pytest.raises(TypeError):
        GuardService(
            model=None,
            key_id=None,
            verifier=None,
            store=None,
            tenants=None,
            catalog=None,
        )
