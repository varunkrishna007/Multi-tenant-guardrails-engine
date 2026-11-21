"""M5-01 on the directory's write path: only a platform operator sets the tier (every path),
every change is a class A event with the actor, before and after, and a raise alerts when the
active version no longer meets the new requirements."""

from __future__ import annotations

from pathlib import Path

import pytest
from guard_fixtures import CLAIMS_V1, FLOOR_V1

from guardrail_engine.authz import Principal, Role
from guardrail_engine.directory import (
    InMemoryDirectoryStore,
    InMemoryEventBus,
    NotAPlatformOperator,
    TenantProvisioner,
    TenantTerminated,
)
from guardrail_engine.directory.tier import CatalogTierImpact
from guardrail_engine.floor_file import load_floor_file
from guardrail_engine.gateway.sinks import (
    ALERT_TIER_RAISE_UNMET,
    AlertSeverity,
    RecordingAlertSink,
)
from guardrail_engine.pack_file import load_pack_file
from guardrail_engine.policy import InMemoryCatalog
from guardrail_engine.policy.document import parse_bundle

ROOT = Path(__file__).resolve().parents[2]
OPS = Principal("ops-1", None, frozenset(), True)
ALICE = Principal("alice", "t_alpha", frozenset({Role.GUARDRAIL_ADMIN}))
OPS_ADMIN = Principal("ops-2", "t_alpha", frozenset({Role.GUARDRAIL_ADMIN}), False)
RAI = "domain/responsible_ai@1"
JUSTIFICATION = "Age is a lawful rating factor for this product in the markets we sell to."


def doc(tenant_id, *extends, overrides=()):
    return {
        "schema_version": 1, "tenant_id": tenant_id, "version": 1,
        "extends": ["platform/floor@1", *extends], "overrides": list(overrides),
    }  # fmt: skip


class Active:
    """A stand-in for the lifecycle store: each tenant's active bundle, or none."""

    def __init__(self):
        self.documents: dict[str, dict] = {}
        self.fails = False

    async def __call__(self, tenant_id):
        if self.fails:
            raise RuntimeError("store down")
        found = self.documents.get(tenant_id)
        return None if found is None else parse_bundle(found)


def claims_catalog() -> InMemoryCatalog:
    return InMemoryCatalog(
        floors=[FLOOR_V1], packs=[CLAIMS_V1], tier_required_packs={"regulated": ["claims"]}
    )


def rai_catalog() -> InMemoryCatalog:
    return InMemoryCatalog(
        floors=[load_floor_file(ROOT / "floor" / "rules.json")],
        packs=[load_pack_file(ROOT / "packs" / "responsible_ai" / "pack.json")],
        tier_required_packs={"regulated": ["responsible_ai"]},
    )


def build(catalog=None, *, active=None):
    store, bus, alerts = InMemoryDirectoryStore(), InMemoryEventBus(), RecordingAlertSink()
    active = active if active is not None else Active()
    prov = TenantProvisioner(
        store, bus, clock=lambda: 1_700_000_000.0, alerts=alerts,
        impact=None if catalog is None else CatalogTierImpact(catalog, active),
    )  # fmt: skip
    return prov, store, bus, alerts, active


# ---------------------------------------------------------------- only platform ops, every path


async def test_a_tenants_admin_can_not_set_the_tier_through_any_write_path():
    prov, store, bus, _, _ = build()
    record = await prov.create(OPS, slug="acme", domain="insurance")
    t = record.tenant_id
    calls = (
        prov.create(ALICE, slug="other", domain="insurance", tier="regulated"),
        prov.create(OPS_ADMIN, slug="other", domain="insurance", tier="regulated"),
        prov.update(ALICE, t, 1, tier="regulated"),
        prov.set_tier(ALICE, t, 1, "regulated", "contract"),
        prov.set_tier(OPS_ADMIN, t, 1, "dedicated", "contract"),  # an admin, not an operator
        prov.set_status(ALICE, t, 1, "suspended"),
    )
    for call in calls:
        with pytest.raises(NotAPlatformOperator):
            await call
    stored = await store.get(t)
    assert (stored.tier, stored.version) == ("standard", 1)
    assert len(await store.list()) == 1 and len(bus.published) == 1  # nothing else was written


# ---------------------------------------------------------------- class A: actor, before, after


async def test_a_tier_change_is_a_class_a_event_with_actor_reason_before_and_after():
    prov, store, bus, _, _ = build()
    record = await prov.create(OPS, slug="acme", domain="finance")
    change = await prov.set_tier(OPS, record.tenant_id, 1, "regulated", "contract signed 2026-11")
    assert (change.record.tier, change.previous_tier, change.record.version) == (
        "regulated", "standard", 2,
    )  # fmt: skip
    created, event = await store.audit_events(record.tenant_id)
    assert (created.action, event.action, event.actor, event.version) == (
        "create", "set_tier", "ops-1", 2,
    )  # fmt: skip
    assert event.before["tier"] == "standard" and event.after["tier"] == "regulated"
    assert event.after["reason"] == "contract signed 2026-11" and "reason" not in event.before
    assert event.at == 1_700_000_000.0
    assert [(e.kind, e.version) for e in bus.published] == [("create", 1), ("set_tier", 2)]


async def test_a_change_through_update_is_audited_too_and_setting_the_same_tier_writes_nothing():
    prov, store, _, _, _ = build()
    record = await prov.create(OPS, slug="acme", domain="finance")
    again = await prov.set_tier(OPS, record.tenant_id, 1, "standard", "no change")
    assert again.record.version == 1 and len(await store.audit_events(record.tenant_id)) == 1
    await prov.update(OPS, record.tenant_id, 1, tier="dedicated")
    last = (await store.audit_events(record.tenant_id))[-1]
    assert (last.action, last.actor, last.before["tier"], last.after["tier"]) == (
        "update", "ops-1", "standard", "dedicated",
    )  # fmt: skip


@pytest.mark.parametrize(
    ("tier", "reason"),
    [("gold", "ok"), ("regulated", ""), ("regulated", "  "), ("regulated", "x" * 501),
     ("regulated", "bell\x07")],
)  # fmt: skip
async def test_a_bad_tier_or_reason_is_refused_before_anything_is_written(tier, reason):
    prov, store, _, _, _ = build()
    record = await prov.create(OPS, slug="acme", domain="finance")
    with pytest.raises(ValueError):
        await prov.set_tier(OPS, record.tenant_id, 1, tier, reason)
    assert (await store.get(record.tenant_id)).version == 1


async def test_a_terminated_tenants_tier_can_not_change():
    prov, _, _, _, _ = build()
    prov._drain_s = 0.0
    record = await prov.create(OPS, slug="acme", domain="finance")
    await prov.terminate(OPS, record.tenant_id, "contract ended")
    with pytest.raises(TenantTerminated):
        await prov.set_tier(OPS, record.tenant_id, 3, "regulated", "late")


# ---------------------------------------------------------------- a raise alerts on a gap


async def test_a_raise_alerts_when_the_active_version_lacks_a_required_pack():
    prov, _, _, alerts, active = build(claims_catalog())
    record = await prov.create(OPS, slug="acme", domain="insurance")
    active.documents[record.tenant_id] = doc(record.tenant_id)  # runs without the pack
    change = await prov.set_tier(OPS, record.tenant_id, 1, "regulated", "contract")
    assert change.gaps == ("pack:claims",)
    [alert] = alerts.warnings(ALERT_TIER_RAISE_UNMET)
    assert (alert.severity, alert.kind, alert.tenant_id) == (
        AlertSeverity.WARNING, "tier_raise_unmet", record.tenant_id,
    )  # fmt: skip
    assert alert.reason == "pack:claims" and "keeps running" in alert.message
    assert "next publish" in alert.message and alert.dedupe_key.endswith(":2")


async def test_a_raise_alerts_when_the_active_version_opted_out_of_a_required_rule():
    prov, _, _, alerts, active = build(rai_catalog())
    record = await prov.create(OPS, slug="acme", domain="insurance")
    optout = {"rule": "d__harassment", "enabled": False, "justification": JUSTIFICATION}
    active.documents[record.tenant_id] = doc(record.tenant_id, RAI, overrides=[optout])
    change = await prov.set_tier(OPS, record.tenant_id, 1, "regulated", "contract")
    assert change.gaps == ("rule:d__harassment",)
    [alert] = alerts.warnings(ALERT_TIER_RAISE_UNMET)
    assert alert.reason == "rule:d__harassment" and JUSTIFICATION not in alert.message


async def test_no_alert_when_the_version_meets_the_new_tier_or_there_is_none_or_the_tier_drops():
    prov, _, _, alerts, active = build(claims_catalog())
    meets = await prov.create(OPS, slug="meets", domain="insurance")
    none = await prov.create(OPS, slug="none", domain="insurance")
    lower = await prov.create(OPS, slug="lower", domain="insurance", tier="regulated")
    active.documents[meets.tenant_id] = doc(meets.tenant_id, "domain/claims@1")
    active.documents[lower.tenant_id] = doc(lower.tenant_id)  # lacks it, but is being lowered
    for record, tier in ((meets, "regulated"), (none, "regulated"), (lower, "standard")):
        change = await prov.set_tier(OPS, record.tenant_id, 1, tier, "contract")
        assert change.gaps == ()
    assert alerts.alerts == []


async def test_a_gap_that_already_existed_is_not_alerted_again_when_the_tier_moves_on():
    prov, _, _, alerts, active = build(claims_catalog())
    record = await prov.create(OPS, slug="acme", domain="insurance", tier="regulated")
    active.documents[record.tenant_id] = doc(record.tenant_id)
    change = await prov.set_tier(OPS, record.tenant_id, 1, "dedicated", "bigger contract")
    assert change.gaps == () and alerts.alerts == []  # the gap was there under the old tier


async def test_an_unreadable_active_version_does_not_undo_the_change():
    prov, store, _, alerts, active = build(claims_catalog())
    record = await prov.create(OPS, slug="acme", domain="insurance")
    active.fails = True
    change = await prov.set_tier(OPS, record.tenant_id, 1, "regulated", "contract")
    assert change.record.tier == "regulated" and change.gaps == () and alerts.alerts == []
    assert (await store.get(record.tenant_id)).tier == "regulated"
