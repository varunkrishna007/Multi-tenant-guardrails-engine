"""M5-07: the real in-memory stores take part in offboarding (each implements ``TenantDataHolder``).
The job and the receipts are tested against a counting stand-in in ``test_m5_07_offboarding.py``;
this runs the job over the actual stores, so a store that forgot a table, or deletes another
tenant's rows, fails here."""

import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "audit"))
from audit_records import make_record
from offboarding_env import OPS, T0, _no_sleep

from guardrail_engine.admin.calibration_store import InMemoryCalibrationStore
from guardrail_engine.admin.drafts import InMemoryDraftStore
from guardrail_engine.admin.golden import InMemoryGoldenStore
from guardrail_engine.admin.lifecycle import InMemoryLifecycleStore
from guardrail_engine.admin.tool_registry import InMemoryToolStore
from guardrail_engine.audit.store import InMemoryDecisionRecords
from guardrail_engine.content import InMemoryStoredContent, StoredContent
from guardrail_engine.delivery.events import UsageEvent, encode_usage
from guardrail_engine.delivery.outbox import InMemoryOutbox
from guardrail_engine.delivery.usage import InMemoryUsageStore
from guardrail_engine.directory import InMemoryDirectoryStore, InMemoryEventBus, TenantProvisioner
from guardrail_engine.escalation import InMemoryEscalationStore
from guardrail_engine.guard.shadow import InMemoryShadowStats, Tally
from guardrail_engine.nightly.model import NightlyResult
from guardrail_engine.nightly.store import InMemoryNightlyResults
from guardrail_engine.offboarding import InMemoryOffboardingStore, OffboardingJob
from guardrail_engine.offboarding.model import OFFBOARD_TABLES
from guardrail_engine.retention import InMemoryDecisionStore

GONE, KEPT = "t_gone", "t_kept"


class World:
    def __init__(self) -> None:
        self.retention_records = InMemoryDecisionStore()
        self.records = InMemoryDecisionRecords()
        self.drafts = InMemoryDraftStore()
        self.golden = InMemoryGoldenStore()
        self.lifecycle = InMemoryLifecycleStore(object())  # type: ignore[arg-type]
        self.tools = InMemoryToolStore()
        self.calibration = InMemoryCalibrationStore()
        self.usage = InMemoryUsageStore()
        self.shadow = InMemoryShadowStats()
        self.outbox = InMemoryOutbox()
        self.escalations = InMemoryEscalationStore()
        self.stored_content = InMemoryStoredContent()
        self.nightly = InMemoryNightlyResults()
        self.holders = [
            self.retention_records, self.records, self.drafts, self.golden, self.lifecycle,
            self.tools, self.calibration, self.usage, self.shadow, self.outbox, self.escalations,
            self.stored_content,
            self.nightly,
        ]  # fmt: skip

    async def seed(self, t: str) -> None:
        await self.retention_records.append(make_record(t))
        await self.retention_records.append(make_record(t))
        await self.records.append_many([make_record(t), make_record(t), make_record(t)])
        self.drafts._drafts[t] = object()
        for s in range(2):
            self.golden._sets[(t, f"gs_{s}")] = (object(), (object(), object()))
        self.lifecycle._candidates[t] = object()
        for n in ("a", "b"):
            self.tools._entries[(t, n)] = object()
        self.calibration._targets[t] = object()
        for n in ("a", "b", "c"):
            self.calibration._scores[(t, "s", "output", n)] = {}
            self.calibration._outcomes[(t, "s", "output", n)] = []
        self.usage.write(UsageEvent("answered", t, "output", 5, 1.0), f"{t}-u1")
        self.usage.write(UsageEvent("unknown", t, "output", None, 2.0), f"{t}-u2")
        self.shadow._tallies[(t, 1, 2)] = Tally()
        self.shadow._tallies[(t, 1, 3)] = Tally()
        self.outbox.enqueue("usage", encode_usage(UsageEvent("answered", t, "output", 5, 1.0)),
                            f"{t}-o1", 1.0)  # fmt: skip
        for i in range(2):  # class C (M5-03): the stored-content store
            await self.stored_content.append_many(
                [
                    StoredContent(
                        t, f"sc{i}", "output", T0, T0 + timedelta(days=30), "kept", False,
                        "sha256:" + "ab" * 32, 1,
                    )
                ]
            )  # fmt: skip
        await self.nightly.append_many(  # class B (M5-05): the nightly red-team's results
            [
                NightlyResult(
                    t,
                    1,
                    "platform/floor@2",
                    f"run{i}",
                    T0,
                    "fake",
                    2,
                    (),
                    "sha256:" + "ab" * 32,
                    3,
                    172,
                    "pass",
                    (),
                    {},
                    {},
                    0,
                    0,
                    0,
                )
                for i in range(2)
            ]
        )
        for i in range(3):
            held = i < 2
            self.escalations._items[(t, f"esc_{i}")] = SimpleNamespace(
                id=f"esc_{i}", seq=i, content="held" if held else None,
                store_content="full" if held else "hash_only",
            )  # fmt: skip

    def counts(self, t: str) -> dict[str, int]:
        out: dict[str, int] = {}
        for table in OFFBOARD_TABLES:
            out[table.name] = sum(
                h.offboard_tenant(t, table.name, 1, count_only=True).get(table.name, 0)
                for h in self.holders
                if table.name in h.offboard_tables
            )
        return out


async def test_the_real_in_memory_stores_are_offboarded_and_only_the_terminated_tenants():
    world = World()
    directory, bus = InMemoryDirectoryStore(), InMemoryEventBus()
    ids = iter([GONE, KEPT])
    prov = TenantProvisioner(
        directory,
        bus,
        clock=lambda: T0.timestamp(),
        sleep=_no_sleep,
        drain_s=0,
        id_factory=lambda: next(ids),
    )
    await prov.create(OPS, slug="gone-co", domain="insurance")
    await prov.create(OPS, slug="kept-co", domain="insurance")
    await world.seed(GONE)
    await world.seed(KEPT)
    before_kept = world.counts(KEPT)
    seeded = world.counts(GONE)
    assert seeded == before_kept
    assert all(n > 0 for t, n in seeded.items() if t != "decision_record_rules"), seeded
    await prov.terminate(OPS, GONE, "contract ended")

    store = InMemoryOffboardingStore(directory, world.holders)
    now = T0 + timedelta(days=3)
    report = await OffboardingJob(store, clock=lambda: now, batch_size=2).run_once()

    assert report.failed == () and [t.tenant_id for t in report.tenants] == [GONE]
    assert all(n == 0 for n in world.counts(GONE).values()), world.counts(GONE)
    assert world.counts(KEPT) == before_kept
    done = await store.completion(GONE)
    assert done is not None and done.counts_by_class["C"] == 4 and done.counts_by_class["D"] == 3
    assert done.counts_by_class["B"] == (
        seeded["decision_records"] + seeded["usage_events"] + seeded["tenant_shadow_agreement"]
        + seeded["delivery_outbox"] + seeded["nightly_redteam_results"]
    )  # fmt: skip
    assert await store.completion(KEPT) is None
    assert datetime(2026, 1, 1, tzinfo=UTC) < done.at


async def test_the_in_memory_outbox_deletes_usage_and_escalation_but_not_platform_alerts():
    """A pending alert that names the tenant stays; its own usage and escalation go."""
    world = World()
    for kind, key in (("usage", "u"), ("escalation", "e"), ("alert", "a")):
        world.outbox.enqueue(kind, f'{{"kind":"x","tenant_id":"{GONE}"}}', key, 1.0)
    world.outbox.enqueue("alert", f'{{"kind":"x","tenant_id":"{KEPT}"}}', "k", 1.0)
    counted = world.outbox.offboard_tenant(GONE, "delivery_outbox", 10, count_only=True)
    assert counted == {"delivery_outbox": 2}
    assert world.outbox.offboard_tenant(GONE, "delivery_outbox", 10) == {"delivery_outbox": 2}
    assert sorted(r.key for r in world.outbox._rows) == ["a", "k"]


async def test_the_decision_stores_leave_other_tenants_and_untenanted_records_alone():
    world = World()
    await world.records.append_many([make_record(GONE), make_record(KEPT), make_record(None)])
    await world.retention_records.append(make_record(None))
    for holder in (world.records, world.retention_records):
        assert holder.offboard_tenant(GONE, "decision_records", 10) == {
            "decision_records": (1 if holder is world.records else 0)
        }
    assert len(world.records.all()) == 2 and len(world.retention_records.records(None)) == 1
