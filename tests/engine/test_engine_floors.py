"""M2-09 on the engine: the factory builds the floor services, applies the stored releases and
minimum at start, and reloads them when another replica announces a change."""

import asyncio
import json
from datetime import UTC, datetime

from engine_fixtures import (
    FLOOR_FILE,
    directory,
    settings,
    verifier,
)

from guardrail_engine.admin.floors import Approval, FloorRelease, PlatformEvent
from guardrail_engine.admin.lifecycle import GuardrailPublished, InMemoryPublishBus
from guardrail_engine.authz import InMemoryAuthzAudit
from guardrail_engine.decision import FakeDecisionModel
from guardrail_engine.directory import InMemoryDirectoryStore
from guardrail_engine.engine import build_engine
from guardrail_engine.engine.factory import _corpus_hasher, _lister_of
from guardrail_engine.policy.catalog import FloorVersion

NOW = datetime(2026, 11, 20, tzinfo=UTC)


def floor2_file(tmp_path):
    doc = json.loads(FLOOR_FILE.read_text())
    doc["floor_version"] = 2
    path = tmp_path / "floor2.json"
    path.write_text(json.dumps(doc))
    return path, FloorVersion.from_document(doc)


async def build(tmp_path, **kw):
    path, floor2 = floor2_file(tmp_path)
    s = settings("test", catalog={"floor_files": [str(FLOOR_FILE), str(path)]})
    engine = await build_engine(
        s, verifier=verifier(), tenants=directory(), model=FakeDecisionModel(),
        authz_audit=InMemoryAuthzAudit(), **kw,
    )  # fmt: skip
    return engine, floor2


async def release_directly(platform, floor2):
    now = NOW
    r = FloorRelease(2, floor2.content_hash(), {}, "a", now, approvals=(Approval("a", False, now),))
    await platform.propose(r, PlatformEvent(now, "a", "release_proposed", 2))
    await platform.approve(
        2, Approval("b", False, now), PlatformEvent(now, "b", "release_approved", 2),
        PlatformEvent(now, "b", "released", 2),
    )  # fmt: skip


async def test_the_engine_builds_the_floor_services_and_holds_unreleased_floors_back(tmp_path):
    engine, _ = await build(tmp_path)
    try:
        assert engine.floor_service is not None and engine.repin_service is not None
        assert engine.catalog.is_released(1) and not engine.catalog.is_released(2)
        assert engine.catalog.minimum_floor_version() == 1
    finally:
        await engine.shutdown()


async def test_the_stored_releases_and_minimum_are_applied_at_start(tmp_path):
    from guardrail_engine.admin.floors import InMemoryPlatformStore

    platform = InMemoryPlatformStore()
    _, floor2 = floor2_file(tmp_path)
    await release_directly(platform, floor2)
    await platform.set_minimum(
        2, expected=None, by="x", at=NOW, event=PlatformEvent(NOW, "x", "raise_minimum", 2)
    )
    engine, _ = await build(tmp_path, platform_store=platform)
    try:
        assert engine.catalog.is_released(2) and engine.catalog.minimum_floor_version() == 2
    finally:
        await engine.shutdown()


async def test_a_floor_event_from_another_replica_reloads_the_release_state(tmp_path):
    bus = InMemoryPublishBus()
    engine, floor2 = await build(tmp_path, publish_bus=bus)
    try:
        platform = engine.floor_service._platform
        await release_directly(platform, floor2)
        assert not engine.catalog.is_released(2)  # this replica hasn't heard yet
        await bus.publish(GuardrailPublished("t_platform", 0, "floor"))
        await asyncio.gather(*engine._reload_tasks)
        assert engine.catalog.is_released(2)
        before = len(engine._reload_tasks)
        await bus.publish(GuardrailPublished("t_alpha", 3, "publish"))  # an ordinary event
        assert len(engine._reload_tasks) == before  # no reload for a tenant's publish
    finally:
        await engine.shutdown()


async def test_the_lister_and_corpus_helpers():
    class NoList:
        pass

    assert await _lister_of(NoList()).tenant_ids() == []
    d = directory()
    assert _lister_of(d) is d and "t_dogfood" in await d.tenant_ids()
    s = settings("test")
    assert _corpus_hasher(s)() is not None  # the repository's corpus
    s2 = settings("test", catalog={"redteam_corpus": "/nonexistent/corpus.jsonl"})
    assert _corpus_hasher(s2)() is None
    assert InMemoryDirectoryStore  # the cached directory's lister is tested with the directory


async def test_the_cached_directory_lists_tenants_for_bulk_platform_steps():
    from test_engine_propagation import OPS, tenant_with_directory

    prov, _, record, cached = await tenant_with_directory(ttl_s=30)
    other = await prov.create(OPS, slug="beta-co", domain="insurance")
    await prov.set_status(OPS, other.tenant_id, other.version, "suspended")
    assert await cached.tenant_ids() == [record.tenant_id]
    assert await cached.tenant_ids(include_suspended=True) == sorted(
        [record.tenant_id, other.tenant_id]
    )


# ----------------------------------------------------------------------------
async def test_an_engine_starts_closed_whatever_stores_it_was_given(tmp_path):
    """With no platform store at all, a floor above the baseline is still not
    extendable: a draft extending it gets floor.not_released."""
    from guardrail_engine.admin.floors import InMemoryPlatformStore  # noqa: F401

    engine, _ = await build(tmp_path)
    try:
        engine.floor_service = None  # an engine that was built without the release state
        catalog = engine.catalog
        assert catalog.is_released(1) and not catalog.is_released(2)
        from guardrail_engine.policy.catalog import PlatformSettings, TenantAttributes
        from guardrail_engine.policy.compiler import PolicyCompiler

        profile = await engine.tenants.get("t_dogfood")
        doc = {"schema_version": 1, "tenant_id": "t_dogfood", "version": 1,
               "extends": ["platform/floor@2"]}  # fmt: skip
        errors = PolicyCompiler(catalog, profile, PlatformSettings()).validate(
            doc, TenantAttributes(tenant_id="t_dogfood")
        )
        assert [str(e.code) for e in errors] == ["floor.not_released"]
    finally:
        await engine.shutdown()


async def test_a_directly_built_catalog_stays_open_but_the_engine_closes_the_one_it_uses(tmp_path):
    from guardrail_engine.policy.catalog import InMemoryCatalog

    _, floor2 = floor2_file(tmp_path)
    from guardrail_engine.floor_file import load_floor_file

    own = InMemoryCatalog(floors=[load_floor_file(FLOOR_FILE), floor2])
    assert own.is_released(2)  # a library catalog has no release process
    engine = await build_engine(
        settings("test"), verifier=verifier(), tenants=directory(),
        model=FakeDecisionModel(), catalog=own,
    )  # fmt: skip
    try:
        assert not own.is_released(2) and own.is_released(1)  # closed by the engine
    finally:
        await engine.shutdown()


async def test_production_refuses_an_unclosable_catalog_and_a_publisher_without_platform_store(
    tmp_path,
):
    import pytest
    from engine_fixtures import real_catalog

    from guardrail_engine.admin.lifecycle import InMemoryLifecycleStore
    from guardrail_engine.engine import SettingsError
    from guardrail_engine.store import InMemoryPolicyStore

    class Opaque:
        def __getattr__(self, name):
            return getattr(real_catalog(), name)

    prod = settings("production", signed_context={"allow_v1_hmac": True})
    with pytest.raises(SettingsError, match="InMemoryCatalog"):
        await build_engine(
            prod, verifier=verifier(), tenants=directory(), model=FakeDecisionModel(),
            catalog=Opaque(),
        )  # fmt: skip
    store = InMemoryPolicyStore(catalog=real_catalog())
    with pytest.raises(SettingsError, match="platform store"):
        await build_engine(
            prod, verifier=verifier(), tenants=directory(), model=FakeDecisionModel(),
            store=store, lifecycle_store=InMemoryLifecycleStore(store),
            authz_audit=type("D", (InMemoryAuthzAudit,), {"durable": True})(),
        )  # fmt: skip


async def test_a_dropped_floor_event_is_covered_by_the_periodic_reload(tmp_path):
    """A replica that never hears the event reloads at the pointer TTL."""
    path, floor2 = floor2_file(tmp_path)
    s = settings(
        "test", catalog={"floor_files": [str(FLOOR_FILE), str(path)]},
        guard={"pointer_ttl_s": 0.05},
    )  # fmt: skip
    engine = await build_engine(
        s, verifier=verifier(), tenants=directory(), model=FakeDecisionModel(),
        authz_audit=InMemoryAuthzAudit(),
    )  # fmt: skip
    try:
        await release_directly(engine.floor_service._platform, floor2)
        assert not engine.catalog.is_released(2)
        for _ in range(40):
            await asyncio.sleep(0.05)
            if engine.catalog.is_released(2):
                break
        assert engine.catalog.is_released(2)  # no event was sent
    finally:
        await engine.shutdown()
    assert engine._floor_refresher.cancelled() or engine._floor_refresher.done()


async def test_a_failing_reload_is_logged_and_tried_again(tmp_path, caplog):
    path, floor2 = floor2_file(tmp_path)
    s = settings(
        "test", catalog={"floor_files": [str(FLOOR_FILE), str(path)]},
        guard={"pointer_ttl_s": 0.05},
    )  # fmt: skip
    engine = await build_engine(
        s, verifier=verifier(), tenants=directory(), model=FakeDecisionModel(),
        authz_audit=InMemoryAuthzAudit(),
    )  # fmt: skip
    try:
        platform = engine.floor_service._platform
        real = platform.releases
        calls = {"n": 0}

        async def flaky():
            calls["n"] += 1
            if calls["n"] == 1:
                raise ConnectionError("db down")
            return await real()

        platform.releases = flaky
        await release_directly(platform, floor2)
        for _ in range(60):
            await asyncio.sleep(0.05)
            if engine.catalog.is_released(2):
                break
        assert engine.catalog.is_released(2) and calls["n"] >= 2
        assert "could not be reloaded" in caplog.text
    finally:
        await engine.shutdown()
