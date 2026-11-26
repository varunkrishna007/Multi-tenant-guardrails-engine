"""M7-08: where a guard point has an enforce rule that may only escalate (the responsible-AI
pack's self-harm and vulnerability rules at ``input``), a provider refusal goes to a person
instead of being blocked, within a per-tenant cap and only if the engine can route an
escalation. Nothing here calls a provider: the fake model's refusal stands in."""

import asyncio

import pytest
from engine_fixtures import TENANT, ctx, settings, verifier
from test_engine_m4_10 import build, doc, rai_settings

from guardrail_engine.decision import FakeDecisionModel
from guardrail_engine.engine import SettingsError
from guardrail_engine.escalation import InMemoryEscalationStore
from guardrail_engine.gateway.sinks import (
    ALERT_REFUSAL_ESCALATIONS_CAPPED,
    RecordingAlertSink,
)
from guardrail_engine.guard import Decision, Reason
from guardrail_engine.guard.audit import InMemoryAuditSink
from guardrail_engine.guard.refusal import (
    InMemoryRefusalCap,
    RefusalConfig,
    RefusalEscalations,
)

ESCALATE_ONLY = ("d__self_harm_risk", "d__vulnerability")


async def with_router(model=None, **kw):
    store = InMemoryEscalationStore()
    engine = await build(model=model or FakeDecisionModel(), escalation_store=store, **kw)
    await engine.bootstrap_publish(doc())
    return engine, store


# ------------------------------------------------------------------------ the rule


async def test_a_refusal_at_a_guard_point_with_an_escalate_only_rule_goes_to_a_person():
    model = FakeDecisionModel()
    audit = InMemoryAuditSink()
    engine, store = await with_router(model, audit=audit)
    try:
        model.safety_block_next(message="the provider's own words", reason="PROHIBITED_CONTENT")
        verdict = await engine.check(ctx(verifier()), "input", "a message")
        assert (verdict.decision, verdict.reason) == (Decision.ESCALATE, Reason.PROVIDER_SAFETY)
        assert verdict.fired == () and verdict.retryable is False and verdict.model_called
        assert await engine.escalation_router.drain(2.0)
        [item] = store.items(TENANT)
        assert item.reason == "provider_safety" and item.rules == ()  # nothing fired
        assert item.candidate_rules == ESCALATE_ONLY
        assert item.content == "a message" and item.guard_point == "input"
        dumped = repr(item) + verdict.model_dump_json() + audit.records[-1].model_dump_json()
        assert "the provider's own words" not in dumped  # never the provider's text
        assert audit.records[-1].decision is Decision.ESCALATE and audit.records[-1].fired == ()
    finally:
        await engine.shutdown()


async def test_a_refusal_at_a_guard_point_without_one_is_still_a_block():
    model = FakeDecisionModel()
    engine, store = await with_router(model)
    try:
        model.safety_block_next()
        verdict = await engine.check(ctx(verifier()), "output", "a message")
        assert (verdict.decision, verdict.reason) == (Decision.BLOCK, Reason.PROVIDER_SAFETY)
        assert await engine.escalation_router.drain(2.0) and store.items(TENANT) == []
    finally:
        await engine.shutdown()


async def test_a_shadow_rule_does_not_make_a_refusal_an_escalation():
    """``d__harm_facilitation`` is observe-only at input and output; it never acts, so a refusal
    at ``output`` (where only blocking rules and that shadow rule run) stays a block."""
    model = FakeDecisionModel()
    engine, _ = await with_router(model)
    try:
        model.safety_block_next()
        verdict = await engine.check(ctx(verifier()), "output", "a message")
        assert verdict.decision is Decision.BLOCK
    finally:
        await engine.shutdown()


async def test_without_a_router_to_send_it_to_a_refusal_stays_a_block():
    """No router attached: an escalation would go nowhere. It fails closed."""
    model = FakeDecisionModel()
    engine = await build(model=model)
    try:
        await engine.bootstrap_publish(doc())
        engine.guard.attach_escalations(None)  # nowhere to send an escalation
        model.safety_block_next()
        verdict = await engine.check(ctx(verifier()), "input", "a message")
        assert (verdict.decision, verdict.reason) == (Decision.BLOCK, Reason.PROVIDER_SAFETY)
    finally:
        await engine.shutdown()


async def test_a_refusal_the_router_cannot_store_is_still_withheld_and_is_paged():
    """The existing failure path: the verdict is an escalation, the content is held back by the
    caller, and the item is dropped, counted and alerted (a page) when the store fails."""

    class Failing(InMemoryEscalationStore):
        def scoped(self, scope):
            raise RuntimeError("store down")

    alerts = RecordingAlertSink()
    model = FakeDecisionModel()
    engine = await build(
        model=model, escalation_store=Failing(), alerts=alerts, escalation_alerts=alerts
    )
    try:
        await engine.bootstrap_publish(doc())
        model.safety_block_next()
        verdict = await engine.check(ctx(verifier()), "input", "a message")
        assert verdict.decision is Decision.ESCALATE  # held, not released
        await engine.escalation_router.drain(2.0)
        assert engine.escalation_router.dropped_by_reason.get("store_error") == 1
    finally:
        await engine.shutdown()


# ------------------------------------------------------------------------ the flood cap


async def test_past_the_cap_a_refusal_is_a_block_and_one_alert_is_raised():
    model = FakeDecisionModel()
    alerts = RecordingAlertSink()
    store = InMemoryEscalationStore()
    engine = await build(
        model=model,
        escalation_store=store,
        alerts=alerts,
        settings=settings("test", guard={"refusal_escalation_cap": 3}, catalog=rai_catalog()),
    )
    try:
        await engine.bootstrap_publish(doc())
        decisions = []
        for i in range(8):  # distinct texts: the repeat counter isn't what is under test
            model.safety_block_next()
            decisions.append((await engine.check(ctx(verifier()), "input", f"text {i}")).decision)
        assert decisions == [Decision.ESCALATE] * 3 + [Decision.BLOCK] * 5
        await asyncio.sleep(0.1)  # the alert goes out from a worker thread
        capped = [a for a in alerts.alerts if a.kind == ALERT_REFUSAL_ESCALATIONS_CAPPED]
        assert len(capped) == 1 and capped[0].tenant_id == TENANT
        assert capped[0].guard_point == "input"
        assert await engine.escalation_router.drain(2.0) and len(store.items(TENANT)) == 3
    finally:
        await engine.shutdown()


def rai_catalog():
    return rai_settings().catalog.model_dump(mode="json")


async def test_a_cap_of_zero_keeps_the_old_behaviour():
    model = FakeDecisionModel()
    engine = await build(
        model=model,
        escalation_store=InMemoryEscalationStore(),
        settings=settings("test", guard={"refusal_escalation_cap": 0}, catalog=rai_catalog()),
    )
    try:
        await engine.bootstrap_publish(doc())
        model.safety_block_next()
        verdict = await engine.check(ctx(verifier()), "input", "a message")
        assert (verdict.decision, verdict.reason) == (Decision.BLOCK, Reason.PROVIDER_SAFETY)
    finally:
        await engine.shutdown()


async def test_a_failing_cap_store_means_block_never_escalate():
    class Broken:
        async def take(self, tenant_id, guard_point, now):
            raise RuntimeError("down")

    model = FakeDecisionModel()
    engine, store = await with_router(model)
    try:
        engine.guard._refusals._store = Broken()
        model.safety_block_next()
        verdict = await engine.check(ctx(verifier()), "input", "a message")
        assert (verdict.decision, verdict.reason) == (Decision.BLOCK, Reason.PROVIDER_SAFETY)
        assert await engine.escalation_router.drain(2.0) and store.items(TENANT) == []
    finally:
        await engine.shutdown()


async def test_the_settings_reach_the_service_and_are_checked():
    engine, _ = await with_router()
    try:
        config = engine.guard._config.refusal
        assert (config.cap, config.window_s) == (20, 900.0)
    finally:
        await engine.shutdown()
    with pytest.raises(SettingsError):
        settings("test", guard={"refusal_escalation_cap": -1})
    with pytest.raises(SettingsError):
        settings("test", guard={"refusal_escalation_window_s": 0})


# ------------------------------------------------------------------------ with repeat counting


async def test_an_escalated_refusal_counts_towards_repeat_refusal_so_it_is_not_sent_again():
    model = FakeDecisionModel()
    engine, _ = await with_router(model)
    try:
        for _ in range(2):
            model.safety_block_next()
            first = await engine.check(ctx(verifier()), "input", "the same text")
            assert first.decision is Decision.ESCALATE
        calls = len(model.calls)
        again = await engine.check(ctx(verifier()), "input", "the same text")
        assert (again.decision, again.reason) == (Decision.BLOCK, Reason.DETERMINISTIC)
        assert len(model.calls) == calls  # not sent to the provider again
    finally:
        await engine.shutdown()


async def test_an_escalated_refusal_neither_opens_the_slot_nor_survives_an_earlier_allow():
    model = FakeDecisionModel()
    engine, _ = await with_router(model)
    try:
        text = "the same text again"
        allowed = await engine.check(ctx(verifier()), "input", text)
        assert allowed.decision is Decision.ALLOW  # an allow opens the slot
        for _ in range(2):  # then the provider refuses it twice: escalated, and counted
            model.safety_block_next()
            held = await engine.check(ctx(verifier()), "input", text)
            assert held.decision is Decision.ESCALATE
        calls = len(model.calls)
        refused = await engine.check(ctx(verifier()), "input", text)
        assert (refused.decision, refused.reason) == (Decision.BLOCK, Reason.DETERMINISTIC)
        assert len(model.calls) == calls
    finally:
        await engine.shutdown()


# ------------------------------------------------------------------------ production path only


async def draft_world(cap=3):
    model = FakeDecisionModel()
    alerts = RecordingAlertSink()
    store = InMemoryEscalationStore()
    engine = await build(
        model=model,
        escalation_store=store,
        alerts=alerts,
        settings=settings("test", guard={"refusal_escalation_cap": cap}, catalog=rai_catalog()),
    )
    await engine.bootstrap_publish(doc())
    v = verifier()
    scope = v.verify(v.issue(TENANT)).scope
    policy = (await engine.guard.policy_cache.get(scope, "input")).policy
    return engine, model, store, alerts, scope, policy


async def test_refused_draft_tests_are_blocks_and_leave_the_cap_for_production():
    engine, model, store, _, scope, policy = await draft_world(cap=3)
    try:
        for i in range(5):  # the Admin API's test endpoint, calibration, a gate: all drafts
            model.safety_block_next()
            draft = await engine.guard.evaluate_draft(scope, policy, f"draft {i}")
            assert (draft.decision, draft.reason) == (Decision.BLOCK, Reason.PROVIDER_SAFETY)
        for i in range(3):  # the cap is whole: three production refusals still escalate
            model.safety_block_next()
            v = await engine.check(ctx(verifier()), "input", f"production {i}")
            assert v.decision is Decision.ESCALATE
        assert await engine.escalation_router.drain(2.0) and len(store.items(TENANT)) == 3
    finally:
        await engine.shutdown()


async def test_a_shadow_candidates_refusal_takes_no_token_and_is_a_block():
    engine, model, store, _, scope, policy = await draft_world(cap=1)
    try:
        model.safety_block_next()
        shadow = await engine.guard.evaluate_draft(scope, policy, "same text", usage_class="shadow")
        assert (shadow.decision, shadow.reason) == (Decision.BLOCK, Reason.PROVIDER_SAFETY)
        model.safety_block_next()
        v = await engine.check(ctx(verifier()), "input", "same text")
        assert v.decision is Decision.ESCALATE  # the one token was still there
        assert await engine.escalation_router.drain(2.0) and len(store.items(TENANT)) == 1
    finally:
        await engine.shutdown()


async def test_a_calibration_sized_run_of_refused_rows_does_not_affect_production():
    engine, model, store, alerts, scope, policy = await draft_world(cap=20)
    try:
        for i in range(30):
            model.safety_block_next()
            await engine.guard.evaluate_draft(scope, policy, f"row {i}", usage_class="calibration")
        model.safety_block_next()
        v = await engine.check(ctx(verifier()), "input", "a real refusal")
        assert v.decision is Decision.ESCALATE
        await asyncio.sleep(0.1)
        assert [a for a in alerts.alerts if a.kind == ALERT_REFUSAL_ESCALATIONS_CAPPED] == []
        assert await engine.escalation_router.drain(2.0) and len(store.items(TENANT)) == 1
    finally:
        await engine.shutdown()


# ------------------------------------------------------------------------ the cap's store


async def test_the_cap_allows_n_per_tenant_and_guard_point_in_the_window():
    store = InMemoryRefusalCap(RefusalConfig(cap=2, window_s=10))
    assert [(await store.take("t_a", "input", t)).allowed for t in (0.0, 1.0, 2.0)] == [
        True,
        True,
        False,
    ]
    assert (await store.take("t_a", "plan", 2.0)).allowed  # another guard point has its own
    assert (await store.take("t_b", "input", 2.0)).allowed  # and another tenant
    assert (await store.take("t_a", "input", 10.5)).allowed  # the first aged out


async def test_one_alert_per_tenant_per_window():
    store = InMemoryRefusalCap(RefusalConfig(cap=1, window_s=10))
    await store.take("t_a", "input", 0.0)
    firsts = [(await store.take("t_a", "input", t)).first_denial for t in (1.0, 2.0, 3.0)]
    assert firsts == [True, False, False]
    other_point = await store.take("t_a", "plan", 3.0)
    assert other_point.allowed  # a fresh guard point, not capped
    await store.take("t_a", "plan", 3.5)
    plan_again = await store.take("t_a", "plan", 4.0)
    assert plan_again.first_denial is False  # same tenant, same window
    assert (await store.take("t_a", "input", 12.0)).allowed is True  # the window passed
    assert (
        await store.take("t_a", "input", 13.0)
    ).first_denial is True  # a new window, a new alert


async def test_the_cap_store_is_bounded():
    store = InMemoryRefusalCap(RefusalConfig(cap=1, window_s=100, max_keys=5))
    for i in range(50):
        await store.take(f"t_{i}", "input", float(i))
    assert store.size <= 5


def test_only_enforce_rules_that_may_only_escalate_are_candidates():
    class R:
        def __init__(self, mode, max_action):
            self.mode, self.max_action = mode, max_action

    rules = {
        "a": R("enforce", "escalate"),
        "b": R("shadow", "escalate"),
        "c": R("enforce", None),
        "d": R("enforce", "escalate"),
    }
    assert RefusalEscalations().candidate_rules(rules) == ("a", "d")
    assert RefusalEscalations().candidate_rules({}) == ()


async def test_the_candidate_rules_reach_the_api_view_and_the_webhook_notice():
    from guardrail_engine.delivery.events import (
        EscalationNotice,
        decode_escalation,
        encode_escalation,
    )
    from guardrail_engine.escalation.service import item_view

    model = FakeDecisionModel()
    engine, store = await with_router(model)
    try:
        model.safety_block_next()
        await engine.check(ctx(verifier()), "input", "a message")
        assert await engine.escalation_router.drain(2.0)
        [item] = store.items(TENANT)
        view = item_view(item, reviewer=True)
        assert view["candidate_rules"] == list(ESCALATE_ONLY) and view["rules"] == []
    finally:
        await engine.shutdown()
    notice = EscalationNotice(
        item_id="esc_" + "0" * 24,
        tenant_id=TENANT,
        guard_point="input",
        reason="provider_safety",
        created_at=1.0,
        url="https://hooks.example/x",
        candidate_rules=ESCALATE_ONLY,
    )
    assert decode_escalation(encode_escalation(notice)).candidate_rules == ESCALATE_ONLY
