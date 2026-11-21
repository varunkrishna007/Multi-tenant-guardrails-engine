"""M4-06 on the engine: tokens and cost per guard point agree with the metered totals within 1%.

Real checks go through the engine. The decision records are written behind them, the usage events
are metered by the gateway into a usage store, and the metrics report reads both. The record
tokens (what each check reported) and the metered tokens (what billing counts) are two paths to
the same number; the report says how far apart they are."""

from datetime import UTC, datetime, timedelta

from engine_fixtures import TENANT, bundle
from test_engine_propagation import build, check, draft_and_publish

from guardrail_engine.audit.store import InMemoryDecisionRecords
from guardrail_engine.authz import Principal, Role
from guardrail_engine.delivery.events import new_key
from guardrail_engine.delivery.usage import InMemoryUsageStore, UsageRecorder
from guardrail_engine.metrics.store import InMemoryUsageMetrics


class DirectMeter(UsageRecorder):
    """The gateway's usage meter, writing straight into a usage store."""

    def __init__(self, store: InMemoryUsageStore) -> None:
        super().__init__()
        self._store = store

    def _submit(self, event):
        self._store.write(event, new_key())


def viewer_of(tenant):
    return Principal("vic", tenant, frozenset({Role.VIEWER}), issuer="https://i/")


async def report(engine, params=None, tenant=TENANT):
    d = await engine.authorizer.authorize(
        viewer_of(tenant), "GET", "/v1/tenants/{tid}/guardrails/metrics", tenant_id=tenant
    )
    window = {
        "from": (datetime.now(UTC) - timedelta(hours=1)).isoformat(),
        "to": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
    }
    return await engine.metrics_service.report(d, {**window, **(params or {})})


async def engine_with_sources():
    records, usage = InMemoryDecisionRecords(), InMemoryUsageStore()
    engine = await build(
        decision_records=records,
        usage_metrics=InMemoryUsageMetrics(usage),
        meter=DirectMeter(usage),
    )
    return engine, records, usage


async def test_tokens_and_cost_per_guard_point_agree_with_the_metered_totals():
    engine, _records, usage = await engine_with_sources()
    try:
        await draft_and_publish(engine, bundle(TENANT))
        for _ in range(40):
            await check(engine)  # the output guard point
        for _ in range(15):
            await engine.check((await _ctx()), "input", "a question about my claim")
        await engine.guard.gateway.drain()
        await engine.decision_writer.flush()
        out = await report(engine)
        metered = usage.tokens(TENANT, "output") + usage.tokens(TENANT, "input")
        assert metered > 0
        by_gp = {g["guard_point"]: g for g in out["guard_points"]}
        assert set(by_gp) == {"input", "output"}
        for name in ("input", "output"):
            g = by_gp[name]
            assert g["input_tokens"] == usage.tokens(TENANT, name)  # reported from the meter
            # the records' own figure is within 1% of the metered one, per guard point
            assert abs(g["record_input_tokens"] - g["input_tokens"]) <= 0.01 * g["input_tokens"]
            assert g["cost_usd"] == round(g["input_tokens"] * 0.10 / 1_000_000, 8)
        assert by_gp["output"]["checks"] == 40 and by_gp["input"]["checks"] == 15
        recon = out["reconciliation"]
        assert recon["within_tolerance"] is True and recon["difference_pct"] <= 1.0
        assert out["cost"]["input_tokens"] == metered
        assert out["cost"]["price_per_million_input_tokens_usd"] == 0.10
        assert out["checks"]["total"] == 55 and out["latency_ms"]["p95"] >= out["latency_ms"]["p50"]
    finally:
        await engine.shutdown()


async def test_a_lost_record_shows_in_the_reconciliation():
    """Records and usage events travel separately; when records are lost the report says so."""
    engine, records, _usage = await engine_with_sources()
    try:
        await draft_and_publish(engine, bundle(TENANT))
        for _ in range(30):
            await check(engine)
        await engine.guard.gateway.drain()
        await engine.decision_writer.flush()
        kept = records.all()
        records._rows = [(i, r) for i, r in records._rows if i % 3]  # a third are lost
        assert len(records.all()) < len(kept)
        recon = (await report(engine))["reconciliation"]
        assert recon["within_tolerance"] is False and recon["difference_pct"] > 20
    finally:
        await engine.shutdown()


async def test_the_price_is_the_configured_one():
    engine, _, _ = await engine_with_sources()
    try:
        assert engine.metrics_service._price == 0.10  # the project's price, test default
        assert "token_rate" in engine.metrics_service._price_source
    finally:
        await engine.shutdown()


async def test_without_both_sources_there_is_no_metrics_service():
    engine = await build()
    try:
        assert engine.metrics_service is None
    finally:
        await engine.shutdown()


async def _ctx():
    from engine_fixtures import verifier

    from guardrail_engine.guard import CheckContext

    return CheckContext(signed_context=verifier().issue(TENANT))


async def test_non_production_calls_are_reported_apart_and_never_reconciled():
    """A draft test, a calibration run and a shadow evaluation are metered
    under ``<class>:<guard point>`` and have no decision record. They must not make the report
    look as if records were lost, and they are reported (and priced) by class."""
    from guardrail_engine.decision import NoulQuestion

    engine, _records, usage = await engine_with_sources()
    try:
        await draft_and_publish(engine, bundle(TENANT))
        for _ in range(40):
            await check(engine)
        question = {"t__q": NoulQuestion(instructions="Is this a question about a claim?")}
        for usage_class, n in (("test", 5), ("calibration", 3), ("shadow", 2)):
            for _ in range(n):
                await engine.guard.gateway.decide(
                    tenant_id=TENANT, guard_point="output", input="a claim question",
                    questions=question, usage_class=usage_class,
                )  # fmt: skip
        await engine.guard.gateway.drain()
        await engine.decision_writer.flush()
        out = await report(engine)
        assert [g["guard_point"] for g in out["guard_points"]] == ["output"]  # production only
        recon = out["reconciliation"]
        assert recon["within_tolerance"] is True and recon["difference_pct"] <= 1.0
        other = out["non_production"]
        assert set(other["classes"]) == {"test", "calibration", "shadow"}
        assert other["classes"]["test"]["guard_points"][0]["guard_point"] == "output"
        tokens = {c: v["input_tokens"] for c, v in other["classes"].items()}
        assert all(t > 0 for t in tokens.values()) and tokens["test"] > tokens["shadow"]
        assert other["input_tokens"] == sum(tokens.values())
        assert out["cost"]["non_production_usd"] == other["cost_usd"] > 0
        assert out["cost"]["all_usd"] == round(out["cost"]["total_usd"] + other["cost_usd"], 8)
        assert out["cost"]["input_tokens"] == usage.tokens(TENANT, "output")  # production only
    finally:
        await engine.shutdown()
