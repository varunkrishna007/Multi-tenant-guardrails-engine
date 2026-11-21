"""M4-07 on the engine: a check's record is written behind it to the decision store, the audit
query reads it back for the tenant, and shutdown writes what is still queued."""

from datetime import timedelta

from engine_fixtures import bundle
from test_engine_propagation import (
    TENANT,
    admin_of,
    build,
    check,
    decide,
    draft_and_publish,
)

from guardrail_engine.audit.store import InMemoryDecisionRecords
from guardrail_engine.authz import Principal, Role


def auditor_of(tenant):
    return Principal("ada", tenant, frozenset({Role.AUDITOR}), issuer="https://i/")


async def read(engine, tenant=TENANT, params=None):
    d = await engine.authorizer.authorize(
        auditor_of(tenant), "GET", "/v1/tenants/{tid}/guardrails/decisions", tenant_id=tenant
    )
    return await engine.decisions_service.query(d, params or {})


async def test_a_check_is_written_behind_the_verdict_and_read_back_by_the_audit_query():
    records = InMemoryDecisionRecords()
    engine = await build(decision_records=records)
    try:
        await draft_and_publish(engine, bundle(TENANT))
        verdict = await check(engine)
        assert verdict.bundle_version == 1
        await engine.decision_writer.flush()
        (stored,) = records.all()
        assert (stored.request_id, stored.tenant_id) == (verdict.request_id, TENANT)
        # The stored term is exactly the one the check was decided under: the engine's
        # directory gives the writer a tenant profile, and the writer must be able to read it
        # (a fall-back to the 7-year term would show here as 2555 days)
        assert verdict.retention_days == 395
        assert stored.retain_until - stored.ts == timedelta(days=verdict.retention_days)
        assert engine.decision_writer._terms_source.fallback_counts() == {}
        page = await read(engine)
        assert [i["request_id"] for i in page["items"]] == [verdict.request_id]
        assert page["items"][0]["bundle_version"] == 1
    finally:
        await engine.shutdown()


async def test_shutdown_writes_the_records_still_queued():
    records = InMemoryDecisionRecords()
    engine = await build(decision_records=records)
    await draft_and_publish(engine, bundle(TENANT))
    for _ in range(3):
        await check(engine)
    await engine.shutdown()
    assert len(records.all()) >= 3 and engine.decision_writer.queued == 0


async def test_a_second_audit_sink_still_sees_every_verdict():
    from guardrail_engine.guard.audit import InMemoryAuditSink

    mine, records = InMemoryAuditSink(), InMemoryDecisionRecords()
    engine = await build(audit=mine, decision_records=records)
    try:
        await draft_and_publish(engine, bundle(TENANT))
        await check(engine)
        await engine.decision_writer.flush()
        assert len(mine.verdicts) >= 1 and len(records.all()) >= 1
    finally:
        await engine.shutdown()


async def test_without_a_decision_store_there_is_no_writer_and_no_route():
    engine = await build()  # memory store, none given
    try:
        assert engine.decision_writer is None and engine.decisions_service is None
        assert decide and admin_of  # (helpers imported for the other tests)
    finally:
        await engine.shutdown()
