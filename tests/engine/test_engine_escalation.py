"""M4-05 in the composition root: the engine builds the escalation router and service, routes an
``escalate`` verdict to the tenant's queue and closes the router at shutdown."""

from __future__ import annotations

from engine_fixtures import TENANT, bundle, ctx, directory, settings, verifier

from guardrail_engine.decision import FakeDecisionModel
from guardrail_engine.engine import build_engine
from guardrail_engine.escalation import EscalationRequest, InMemoryEscalationStore
from guardrail_engine.guard import Decision
from guardrail_engine.tenant_scope import issue_scope


async def test_the_engine_routes_an_escalate_verdict_to_the_queue_and_closes_the_router():
    v = verifier()
    store = InMemoryEscalationStore()
    fake = FakeDecisionModel(
        responder=lambda text, key, q: 0.6 if key == "p__ai_addressed" else None
    )
    engine = await build_engine(
        settings(), verifier=v, tenants=directory(), model=fake, escalation_store=store
    )
    try:
        await engine.bootstrap_publish(bundle())
        verdict = await engine.check(ctx(v), "output", "some content")
        assert verdict.decision is Decision.ESCALATE, verdict
        assert engine.escalation_router is not None and engine.escalation_service is not None
        assert await engine.escalation_router.drain(2.0)
        [item] = store.items(TENANT)
        assert item.request_id == verdict.request_id and item.content == "some content"
        assert [(r.key, r.action) for r in item.rules] == [("p__ai_addressed", "escalate")]
    finally:
        await engine.shutdown()
    # closed: a later item is dropped and counted, never raised
    router = engine.escalation_router
    assert router.submit(EscalationRequest(scope=issue_scope(TENANT), item=item)) is False
    assert router.dropped_by_reason == {"closed": 1}
