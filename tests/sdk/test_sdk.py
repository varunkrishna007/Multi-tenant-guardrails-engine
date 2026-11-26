"""M1-07: the Python Guard SDK. Offline: verdicts are built directly or come from an engine
with the fake model."""

from __future__ import annotations

import dataclasses
import inspect
import json
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

from guardrail_engine import gateway
from guardrail_engine.decision import FakeDecisionModel
from guardrail_engine.decision.port import FailureKind
from guardrail_engine.guard.request import CheckContext, ToolResult, Turn
from guardrail_engine.guard.verdict import Action, Basis, Decision, FiredRule, Reason, Verdict
from guardrail_engine.sdk import (
    CAPACITY_REASONS,
    MESSAGES,
    CheckedItem,
    ContextNotClearedError,
    FailureReason,
    Guard,
    GuardContext,
    GuardResult,
    Source,
    retry_request_id,
)
from guardrail_engine.sdk.client import DEFAULT_RETRY_WAIT_MS

SIGNED = "v1.signed-context-sentinel"


def verdict(decision=Decision.BLOCK, reason=Reason.POLICY, **fields) -> Verdict:
    return Verdict(
        request_id=fields.pop("request_id", "req-1"),
        tenant_id="t_1042",
        guard_point=fields.pop("guard_point", "input"),
        decision=decision,
        reason=reason,
        checked_at=datetime.now(UTC),
        latency_ms=1.0,
        **fields,
    )


class Stub:
    """A checker returning scripted verdicts and recording what it was sent."""

    def __init__(self, *verdicts) -> None:
        self.verdicts = list(verdicts)
        self.sent: list[tuple[CheckContext, str, str]] = []

    async def check(self, ctx, guard_point, content):
        self.sent.append((ctx, guard_point, content))
        v = self.verdicts.pop(0) if len(self.verdicts) > 1 else self.verdicts[0]
        return v


async def check(v, ctx=None):
    return await Guard(Stub(v)).check("input", "c", ctx or GuardContext(SIGNED))


# ------------------------------------------------------------------ release only on allow


@pytest.mark.parametrize(
    "decision, reason, released, held",
    [
        (Decision.ALLOW, Reason.POLICY, True, False),
        (Decision.ESCALATE, Reason.POLICY, False, True),
        (Decision.BLOCK, Reason.POLICY, False, False),
        (Decision.FORBIDDEN, Reason.CONTEXT_INVALID, False, False),
    ],
)
async def test_only_allow_releases_and_escalate_holds(decision, reason, released, held):
    r = await check(verdict(decision, reason))
    assert (r.released, r.held_for_escalation) == (released, held)
    assert (r.user_message is None) == released


async def test_an_unknown_decision_withholds_the_content():
    """A decision value this SDK doesn't know (a newer engine) is never treated as allow,
    and is never retried."""
    newer = SimpleNamespace(decision="quarantine", reason="model_failure", request_id="r",
                            guard_point="output", fired=(), failure_kind="timeout",
                            failure_reason=None, retry_after_ms=500,
                            capacity_limited=False)  # fmt: skip
    r = await check(newer)
    assert r.decision == "quarantine" and not r.released and not r.held_for_escalation
    assert not r.retryable and r.user_message == MESSAGES["neutral"]


# ------------------------------------------------------------------ retryable and messages


@pytest.mark.parametrize(
    "reason, retryable",
    [
        (Reason.MODEL_FAILURE, True),
        (Reason.POLICY_UNAVAILABLE, True),
        (Reason.ENGINE_CLOSED, True),
        (Reason.POLICY, False),
        (Reason.PROVIDER_SAFETY, False),
        (Reason.CONTRACT_VIOLATION, False),
        (Reason.CONTENT_TOO_LARGE, False),
        (Reason.INVALID_REQUEST, False),
        (Reason.INTERNAL_ERROR, False),
    ],
)
async def test_retryable_matches_the_verdict(reason, retryable):
    v = verdict(Decision.BLOCK, reason)
    r = await check(v)
    assert r.retryable is retryable is v.retryable
    assert (r.user_message == MESSAGES["retryable"]) is retryable


async def test_quota_exhausted_is_not_retryable_and_keeps_its_long_hint():
    """The daily or monthly cap is used up. The hint is the time until the Pacific
    midnight or the 1st, not clamped to 10 s, and the SDK doesn't retry it: ``retryable`` is
    false (``check_with_retry`` would otherwise wait for hours)."""
    v = failed(FailureKind.UNAVAILABLE, "quota_exhausted", True, 68_400_000)
    r = await check(v)
    assert r.failure_reason is FailureReason.QUOTA_EXHAUSTED and r.capacity_limited
    assert r.retry_after_ms == 68_400_000
    assert not r.retryable
    assert r.user_message == MESSAGES["neutral"]
    # the ordinary hints keep R8's clamp
    with pytest.raises(ValueError, match="retry_after_ms must be"):
        failed(FailureKind.UNAVAILABLE, "token_rate", True, 68_400_000)


async def test_a_provider_refusal_is_final_with_a_neutral_message():
    """R10: provider_safety is never retryable, and the message is neither "temporarily
    unavailable" nor a policy message."""
    r = await check(verdict(Decision.BLOCK, Reason.PROVIDER_SAFETY, failure_reason="safety"))
    assert not r.retryable and r.failure_reason is None and not r.capacity_limited
    assert r.retry_after_ms is None
    assert r.user_message == MESSAGES["neutral"] == "This request can't be processed."
    assert r.user_message not in (MESSAGES["retryable"], MESSAGES["policy"])


async def test_a_policy_block_says_policy_and_names_what_fired():
    fired = FiredRule(key="p__inj_direct", p=0.97, action=Action.BLOCK, mode="enforce",
                      layer="floor", provisional=True, basis=Basis.ANSWER)  # fmt: skip
    r = await check(verdict(Decision.BLOCK, Reason.POLICY, fired=(fired,)))
    assert r.user_message == MESSAGES["policy"] and r.failure_reason is None
    assert [(f.key, f.action, f.mode) for f in r.fired] == [("p__inj_direct", "block", "enforce")]


# ------------------------------------------------------------------ the capacity signal (R8)


def failed(kind, code=None, capacity=False, retry_after=None, **fields):
    return verdict(Decision.BLOCK, Reason.MODEL_FAILURE, failure_kind=kind, failure_reason=code,
                   capacity_limited=capacity, retry_after_ms=retry_after, **fields)  # fmt: skip


@pytest.mark.parametrize(
    "v, expected, capacity",
    [
        (failed(FailureKind.UNAVAILABLE, "admission_wait", True, 400),
         FailureReason.ADMISSION_WAIT, True),
        (failed(FailureKind.UNAVAILABLE, "admission_queue_full", True, 1_000),
         FailureReason.ADMISSION_QUEUE_FULL, True),
        (failed(FailureKind.UNAVAILABLE, "orphan_cap", True, 1_000),
         FailureReason.ORPHAN_CAP, True),
        (failed(FailureKind.UNAVAILABLE, "token_rate", True, 1_000),
         FailureReason.TOKEN_RATE, True),
        (failed(FailureKind.UNAVAILABLE, "quota_exhausted", True, 68_400_000),
         FailureReason.QUOTA_EXHAUSTED, True),
        (failed(FailureKind.AUTH, "API_KEY_INVALID", False, 5_000), FailureReason.AUTH, False),
        (failed(FailureKind.TIMEOUT), FailureReason.TIMEOUT, False),
        (failed(FailureKind.UNAVAILABLE), FailureReason.UNAVAILABLE, False),
        (failed(FailureKind.RATE_LIMITED), FailureReason.UNAVAILABLE, False),
        (failed(FailureKind.LIMIT_EXCEEDED), FailureReason.OTHER, False),
        (failed(FailureKind.OTHER, "blocklist"), FailureReason.OTHER, False),
        (verdict(Decision.BLOCK, Reason.CONTRACT_VIOLATION),
         FailureReason.CONTRACT_VIOLATION, False),
    ],
)  # fmt: skip
async def test_each_failure_maps_to_the_stable_enum(v, expected, capacity):
    r = await check(v)
    assert r.failure_reason is expected
    assert r.capacity_limited is capacity is (expected in CAPACITY_REASONS)
    assert r.retry_after_ms == v.retry_after_ms


def test_the_enum_is_the_agreed_contract_and_covers_the_gateway():
    assert [r.value for r in FailureReason] == [
        "admission_wait", "admission_queue_full", "token_rate", "quota_exhausted", "orphan_cap",
        "auth", "provider_degraded", "guard_unreachable", "timeout", "unavailable", "other",
        "contract_violation",
    ]  # fmt: skip
    assert {r.value for r in CAPACITY_REASONS} >= gateway.CAPACITY_REASONS
    assert {r.value for r in CAPACITY_REASONS} == gateway.CAPACITY_REASONS
    assert DEFAULT_RETRY_WAIT_MS == gateway.gateway.FALLBACK_RETRY_AFTER_MS


async def test_no_failure_reason_on_a_check_that_did_not_fail():
    r = await check(verdict(Decision.ALLOW, Reason.POLICY))
    assert r.failure_reason is None and not r.capacity_limited and r.retry_after_ms is None


# ------------------------------------------------------------------ the retry helper


class Sleeps:
    def __init__(self) -> None:
        self.waits: list[float] = []

    async def __call__(self, seconds: float) -> None:
        self.waits.append(seconds)


async def retried(*verdicts, ctx=None, **kw):
    stub, sleeps = Stub(*verdicts), Sleeps()
    guard = Guard(stub)
    result = await guard.check_with_retry(
        "input", "c", ctx or GuardContext(SIGNED, request_id="abc"), sleep=sleeps,
        rand=lambda: 0.5, **kw,
    )  # fmt: skip
    return result, stub, sleeps


async def test_a_retryable_result_is_retried_once_after_the_hint_plus_jitter():
    first = failed(FailureKind.UNAVAILABLE, "admission_wait", True, 800)
    ok = verdict(Decision.ALLOW, Reason.POLICY, request_id="req-1-retry")
    result, stub, sleeps = await retried(first, ok, jitter_ms=200)
    assert len(stub.sent) == 2 and sleeps.waits == [pytest.approx(0.9)]  # 800 + 0.5 * 200
    assert result.released and result.retry_of == "req-1"
    # The retry id follows the first verdict's id (what the engine used), not the caller's.
    assert [ctx.request_id for ctx, _, _ in stub.sent] == ["abc", "req-1-retry"]


async def test_the_retry_happens_at_most_once():
    again = failed(FailureKind.TIMEOUT)
    result, stub, sleeps = await retried(again, again, again)
    assert len(stub.sent) == 2 and len(sleeps.waits) == 1
    assert result.retryable and not result.released  # still withheld; not retried again


async def test_without_a_hint_the_default_wait_is_used():
    _, _, sleeps = await retried(failed(FailureKind.TIMEOUT), verdict(Decision.ALLOW),
                                 jitter_ms=0)  # fmt: skip
    assert sleeps.waits == [DEFAULT_RETRY_WAIT_MS / 1000]


@pytest.mark.parametrize(
    "v",
    [verdict(Decision.BLOCK, Reason.PROVIDER_SAFETY), verdict(Decision.BLOCK, Reason.POLICY),
     verdict(Decision.BLOCK, Reason.CONTRACT_VIOLATION), verdict(Decision.ALLOW),
     verdict(Decision.ESCALATE), verdict(Decision.FORBIDDEN, Reason.TENANT_MISMATCH)],
)  # fmt: skip
async def test_a_non_retryable_result_is_never_retried(v):
    result, stub, sleeps = await retried(v)
    assert len(stub.sent) == 1 and sleeps.waits == [] and result.retry_of is None


def test_the_retry_request_id_fits_the_service_limit():
    assert retry_request_id(None) is None
    assert retry_request_id("abc") == "abc-retry"
    assert len(retry_request_id("x" * 128)) == 128


# ------------------------------------------------------------------ tenant context only


async def test_the_signed_context_is_passed_through_and_no_tenant_id_is_sent():
    stub = Stub(verdict(Decision.ALLOW))
    await Guard(stub).check("plan", "content", GuardContext(SIGNED, request_id="r-7"))
    ctx, gp, content = stub.sent[0]
    assert (ctx.signed_context, ctx.request_id, gp, content) == (SIGNED, "r-7", "plan", "content")
    assert ctx.payload_tenant_id is None


def test_nothing_on_the_sdk_surface_takes_a_tenant_id():
    names = {f.name for f in dataclasses.fields(GuardContext)}
    for method in (Guard.check, Guard.check_source, Guard.check_with_retry):
        names |= set(inspect.signature(method).parameters)
    assert not any("tenant" in n for n in names)


async def test_a_bare_signed_context_string_is_refused():
    with pytest.raises(TypeError, match="GuardContext"):
        await Guard(Stub(verdict())).check("input", "c", SIGNED)


# ------------------------------------------------------------------ no privileged operations


def test_the_guard_exposes_checking_only():
    """No compile, store, publish or activate operation, and no way back to the
    wrapped engine."""
    public = {n for n in dir(Guard) if not n.startswith("_")}
    assert public == {
        "aclose",
        "check",
        "check_source",
        "check_with_retry",
        "plan_with_input_guard",
        "start_input_guard",
        "stream_output",
    }
    guard = Guard(Stub(verdict()))
    assert not hasattr(guard, "__dict__")  # slots only: nothing can be attached
    assert repr(guard) == "Guard()"
    assert not any(hasattr(guard, n) for n in ("bootstrap_publish", "engine", "store"))


# ------------------------------------------------------------------ context sources


@pytest.mark.parametrize(
    "source, guard_point",
    [(Source.MEMORY, "input"), (Source.UPLOAD, "input"), (Source.RETRIEVAL, "tool_result")],
)
async def test_context_sources_are_routed_through_their_guard_point(source, guard_point):
    stub = Stub(verdict(Decision.ALLOW, guard_point=guard_point, request_id="src-1"))
    checked = await Guard(stub).check_source(source, "remembered text", GuardContext(SIGNED))
    assert stub.sent[0][1] == guard_point
    item = checked.context_item(tool="history.search")
    assert isinstance(item, CheckedItem)
    assert (item.request_id, item.guard_point) == ("src-1", guard_point)
    expected = (ToolResult("history.search", "remembered text") if source is Source.RETRIEVAL
                else Turn("user", "remembered text"))  # fmt: skip
    assert item.item == expected


@pytest.mark.parametrize("decision", [Decision.BLOCK, Decision.ESCALATE, Decision.FORBIDDEN])
async def test_a_source_that_was_not_allowed_cannot_become_context(decision):
    reason = Reason.CONTEXT_INVALID if decision is Decision.FORBIDDEN else Reason.POLICY
    checked = await Guard(Stub(verdict(decision, reason))).check_source(
        Source.UPLOAD, "doc", GuardContext(SIGNED)
    )
    with pytest.raises(ContextNotClearedError):
        checked.context_item()


async def test_retrieval_needs_the_tool_that_retrieved_it():
    checked = await Guard(Stub(verdict(Decision.ALLOW))).check_source(
        Source.RETRIEVAL, "old", GuardContext(SIGNED)
    )
    with pytest.raises(ValueError, match="tool"):
        checked.context_item()


async def test_checked_items_reach_the_engine_as_plain_context_items():
    """The tag is for the integrator's records; the engine sees the item itself."""
    tagged = CheckedItem(Turn("user", "memory"), "src-1", "input")
    stub = Stub(verdict(Decision.ALLOW))
    ctx = GuardContext(SIGNED, conversation=(Turn("user", "hi"), tagged))
    await Guard(stub).check("output", "reply", ctx)
    assert stub.sent[0][0].conversation == (Turn("user", "hi"), Turn("user", "memory"))


# ------------------------------------------------------------------ against the real engine


ROOT = Path(__file__).resolve().parents[2]


async def test_end_to_end_through_the_engine():
    """The SDK over a real engine (fake model): an allow releases, a floor block withholds
    with a policy message, and a forged context is forbidden."""
    import secrets

    from guardrail_engine.engine import EngineSettings, build_engine
    from guardrail_engine.guard import HmacContextVerifier, InMemoryTenantDirectory, TenantProfile
    from guardrail_engine.guard.audit import NullAuditSink
    from guardrail_engine.policy import TenantAttributes

    floor = ROOT / "floor" / "rules.json"
    settings = EngineSettings.from_mapping(
        {"environment": "test", "catalog": {"floor_files": [str(floor)]},
         "gemini": {"paid_tier": True}}
    )  # fmt: skip
    # Scores p__inj_direct high only for content carrying the marker.
    fake = FakeDecisionModel(
        responder=lambda t, k, q: 0.97 if k == "p__inj_direct" and "MARKER-7" in t else 0.01
    )
    verifier = HmacContextVerifier(secrets.token_bytes(32))
    tenants = InMemoryTenantDirectory(
        [TenantProfile.build(TenantAttributes(tenant_id="t_1042"), "insurance", slug="acme")]
    )
    engine = await build_engine(settings, verifier=verifier, tenants=tenants, model=fake,
                                audit=NullAuditSink())  # fmt: skip
    try:
        version = json.loads(floor.read_text()).get("version", 1)
        await engine.bootstrap_publish({"schema_version": 1, "tenant_id": "t_1042", "version": 1,
                                        "extends": [f"platform/floor@{version}"]})  # fmt: skip
        guard = Guard(engine)
        ctx = GuardContext(verifier.issue("t_1042"))
        allowed = await guard.check("input", "What does my policy cover?", ctx)
        assert allowed.released and allowed.request_id and allowed.failure_reason is None
        blocked = await guard.check("input", "MARKER-7", ctx)
        assert not blocked.released and blocked.reason == "policy"
        assert "p__inj_direct" in {f.key for f in blocked.fired}
        assert blocked.user_message == MESSAGES["policy"]
        forbidden = await guard.check("input", "content", GuardContext("forged"))
        assert forbidden.decision == "forbidden" and not forbidden.retryable
    finally:
        await engine.shutdown()


def test_the_guard_result_is_read_only():
    r = GuardResult.from_verdict(verdict())
    with pytest.raises(dataclasses.FrozenInstanceError):
        r.decision = "allow"  # type: ignore[misc]


# ------------------------------------------------------------------
@pytest.mark.parametrize("code", ["admission_wait", "admission_queue_full", "orphan_cap",
                                  "token_rate"])  # fmt: skip
async def test_a_capacity_code_without_the_capacity_signal_reads_by_kind(code):
    """Only the gateway's capacity_limited signal makes a capacity reason; a
    provider reason that spells one is read by its failure kind."""
    r = await check(failed(FailureKind.UNAVAILABLE, code, capacity=False))
    assert r.failure_reason is FailureReason.UNAVAILABLE and not r.capacity_limited
    r = await check(failed(FailureKind.TIMEOUT, code, capacity=False))
    assert r.failure_reason is FailureReason.TIMEOUT


@pytest.mark.parametrize("caller_id", [None, "", "y" * 200])
async def test_the_retry_id_follows_the_id_the_engine_used(caller_id):
    """The engine replaces an empty or over-long caller id; the retry id derives
    from the first check's actual request id."""
    first = failed(FailureKind.TIMEOUT, request_id="engine-generated-id")
    ok = verdict(Decision.ALLOW, Reason.POLICY)
    result, stub, _ = await retried(first, ok, ctx=GuardContext(SIGNED, request_id=caller_id))
    assert stub.sent[1][0].request_id == "engine-generated-id-retry"
    assert result.retry_of == "engine-generated-id"


async def test_limit_exceeded_is_not_retryable_and_gets_the_neutral_message():
    """Deterministic, so never retried, and not "temporarily unavailable"."""
    v = failed(FailureKind.LIMIT_EXCEEDED)
    r = await check(v)
    assert not r.retryable and r.failure_reason is FailureReason.OTHER
    assert r.user_message == MESSAGES["neutral"]
    _, stub, sleeps = await retried(v)
    assert len(stub.sent) == 1 and sleeps.waits == []


# ------------------------------------------------------------------ tool_call tool


@pytest.mark.skipif(
    "tool" not in {f.name for f in dataclasses.fields(CheckContext)},
    reason="CheckContext.tool arrives with M3-01 (tool allow-list)",
)
async def test_the_tool_reaches_the_check_context():
    """The tool the runtime will execute is passed through, so a tenant's tool
    allow-list has something to check."""
    stub = Stub(verdict(Decision.ALLOW, guard_point="tool_call"))
    guard = Guard(stub)
    await guard.check("tool_call", '{"id": 7}', GuardContext(SIGNED, tool="claims.status"))
    assert stub.sent[0][0].tool == "claims.status"
    await guard.check("tool_call", "{}", GuardContext(SIGNED))
    assert stub.sent[1][0].tool is None


async def test_the_tool_is_optional_and_never_breaks_a_check():
    stub = Stub(verdict(Decision.ALLOW, guard_point="tool_call"))
    r = await Guard(stub).check("tool_call", "{}", GuardContext(SIGNED, tool="claims.status"))
    assert r.released and stub.sent[0][0].signed_context == SIGNED
