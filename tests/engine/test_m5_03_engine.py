"""M5-03 through the composition root: the engine builds the stored-content writer, wires it to
the Guard Service, writes what is queued at shutdown, and keeps the default off."""

from engine_fixtures import bundle, ctx, directory, settings, verifier

from guardrail_engine.content import InMemoryStoredContent, StoredContentWriter
from guardrail_engine.decision import FakeDecisionModel
from guardrail_engine.engine import build_engine
from guardrail_engine.guard import Decision

EMAIL = "jo.smith@example.com"


def full(days=14):
    doc = bundle()
    doc["audit"] = {"store_content": "full", "content_days": days}
    return doc


async def test_the_engine_stores_the_post_redaction_content_of_a_tenant_that_asked():
    v = verifier()
    store = InMemoryStoredContent()
    async with await build_engine(
        settings(), verifier=v, tenants=directory(), model=FakeDecisionModel(), stored_content=store
    ) as engine:
        assert isinstance(engine.content_writer, StoredContentWriter)
        await engine.bootstrap_publish(full(14))
        verdict = await engine.check(ctx(v), "output", f"write to {EMAIL} about the claim")
        assert verdict.decision is Decision.ALLOW
    # shutdown wrote what was queued
    (row,) = store.all()
    assert row.content == "write to [EMAIL]@example.com about the claim"
    assert EMAIL not in row.content and row.request_id == verdict.request_id
    assert (row.retain_until - row.ts).days == 14


async def test_the_default_engine_keeps_nothing_and_a_memory_engine_has_a_store_to_keep_it_in():
    v = verifier()
    async with await build_engine(
        settings(), verifier=v, tenants=directory(), model=FakeDecisionModel()
    ) as engine:
        assert engine.content_writer is not None and engine.stored_content_service is not None
        await engine.bootstrap_publish(bundle())  # no audit section: hash_only
        await engine.check(ctx(v), "output", "an ordinary message")
        assert engine.content_writer.queued == 0 and engine.content_writer.written == 0
