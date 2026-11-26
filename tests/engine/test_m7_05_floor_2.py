"""M7-05 floor@2: the file the engine loads is the floor the held-out evidence measured; it sits
in the catalog beside floor@1 and is not extendable until the platform releases it; and what
picks "the newest floor" (a new tenant's starter, tool-description screening) never picks one
that isn't released. These tests run an engine with no release record, which is the engine
before the release; ``test_m7_05_release.py`` is the released one."""

import json
from pathlib import Path

import pytest
from calibration.run import assemble_floor
from engine_fixtures import TENANT, directory, profile, settings, verifier
from floor import derive_v2

from guardrail_engine.admin.tool_registry import ToolScreener
from guardrail_engine.authz import InMemoryAuthzAudit, Principal, Role
from guardrail_engine.decision import FakeDecisionModel
from guardrail_engine.engine import build_engine
from guardrail_engine.floor_file import load_floor_file
from guardrail_engine.policy import PlatformSettings
from guardrail_engine.policy.catalog import FloorVersion

ROOT = Path(__file__).resolve().parents[2]
RULES = ROOT / "floor" / "rules.json"
RULES_V2 = ROOT / "floor" / "rules.v2.json"
ADDITIONS = ROOT / "floor" / "next" / "additions.json"
REWORDED = {"p__ai_addressed", "p__xtenant_probe"}


# ------------------------------------------------------------------------ the file


def test_the_floor_2_file_is_what_the_derivation_writes():
    assert RULES_V2.read_text() == derive_v2.render()


def test_the_floor_2_file_hashes_to_what_the_harnesses_report_as_the_floor_they_measured():
    """The release checks a report's ``floor_content_hash`` against the catalog's floor@2: the
    harnesses hash the floor they assemble in memory, so the file must hash the same."""
    assembled = FloorVersion.from_document(dict(assemble_floor(RULES, ADDITIONS)))
    assert load_floor_file(RULES_V2).content_hash() == assembled.content_hash()


def test_floor_2_differs_from_floor_1_in_the_two_reworded_rules_and_nothing_else():
    one, two = json.loads(RULES.read_text()), json.loads(RULES_V2.read_text())
    assert (one["floor_version"], two["floor_version"]) == (1, 2)
    assert one["schema_version"] == two["schema_version"]
    assert [r["key"] for r in one["rules"]] == [r["key"] for r in two["rules"]]
    changed = {a["key"] for a, b in zip(one["rules"], two["rules"], strict=True) if a != b}
    assert changed == REWORDED
    for a, b in zip(one["rules"], two["rules"], strict=True):
        for field in ("guard_points", "severity", "block_at", "escalate_at", "mode", "provisional"):
            assert a[field] == b[field], (a["key"], field)  # the thresholds stay provisional
    assert all(r["provisional"] for r in two["rules"])


def test_the_additions_still_say_what_the_held_out_run_measured():
    """The replacements the held-out validation measured (additions.json differs from the file
    it hashed only in its ``note``)."""
    additions = json.loads(ADDITIONS.read_text())
    assert {r["key"] for r in additions["replacements"]} == REWORDED
    assert additions["rules"] == [] and additions["target_floor_version"] == 2


# ------------------------------------------------------------------------ in the engine


def doc(floor: int):
    return {
        "schema_version": 1, "tenant_id": TENANT, "version": 1,
        "extends": [f"platform/floor@{floor}"],
    }  # fmt: skip


async def build():
    return await build_engine(
        settings(
            "test", catalog={"floor_files": [str(RULES), str(RULES_V2)], "release_records": []}
        ),
        verifier=verifier(),
        tenants=directory(),
        model=FakeDecisionModel(),
        authz_audit=InMemoryAuthzAudit(),
    )


async def starter_of(engine) -> dict:
    principal = Principal("vic", TENANT, frozenset({Role.VIEWER}), issuer="https://i/")
    d = await engine.authorizer.authorize(
        principal, "GET", "/v1/tenants/{tid}/guardrails/catalog", tenant_id=TENANT
    )
    return (await engine.catalog_service.view(d))["starter_bundle"]


async def test_the_engine_loads_both_floors_and_only_floor_1_is_extendable_at_start():
    engine = await build()
    try:
        assert engine.catalog.floor_versions() == (1, 2)
        assert engine.catalog.is_released(1) and not engine.catalog.is_released(2)
    finally:
        await engine.shutdown()


async def test_a_bundle_extending_floor_2_is_refused_until_it_is_released():
    engine = await build()
    try:
        with pytest.raises(Exception) as refused:
            await engine.bootstrap_publish(doc(2))
        assert "floor.not_released" in repr(refused.value) or "released" in str(refused.value)
        engine.catalog.set_released({1, 2})  # what the platform's release does
        await engine.bootstrap_publish(doc(2))
        assert await engine.store.get_active_version(TENANT) == 1
    finally:
        await engine.shutdown()


async def catalog_floors(engine) -> dict[int, bool]:
    principal = Principal("vic", TENANT, frozenset({Role.VIEWER}), issuer="https://i/")
    d = await engine.authorizer.authorize(
        principal, "GET", "/v1/tenants/{tid}/guardrails/catalog", tenant_id=TENANT
    )
    view = await engine.catalog_service.view(d)
    return {f["version"]: f["extendable"] for f in view["floors"]}


async def test_the_catalog_shows_floor_2_as_extendable_only_once_it_is_released():
    engine = await build()
    try:
        assert await catalog_floors(engine) == {1: True, 2: False}
        engine.catalog.set_released({1, 2})
        assert await catalog_floors(engine) == {1: True, 2: True}
    finally:
        await engine.shutdown()


async def test_a_new_tenants_starter_compiles_with_an_unreleased_floor_2_present():
    engine = await build()
    try:
        starter = await starter_of(engine)
        assert starter["extends"] == ["platform/floor@1"]
        await engine.bootstrap_publish(starter)  # the starter is a valid first bundle
        assert await engine.store.get_active_version(TENANT) == 1
    finally:
        await engine.shutdown()


async def test_once_floor_2_is_released_a_new_tenants_starter_extends_it_and_compiles():
    engine = await build()
    try:
        engine.catalog.set_released({1, 2})
        starter = await starter_of(engine)
        assert starter["extends"] == ["platform/floor@2"]
        await engine.bootstrap_publish(starter)
        assert await engine.store.get_active_version(TENANT) == 1
    finally:
        await engine.shutdown()


async def test_tool_screening_uses_the_newest_released_floor_not_the_newest_loaded():
    engine = await build()
    try:
        screener = ToolScreener(None, engine.catalog, PlatformSettings())  # type: ignore[arg-type]
        before = screener.policy(profile())
        assert before is not None and before.version == 1
        assert before.bundle_hash == engine.catalog.floor(1).content_hash()
        engine.catalog.set_released({1, 2})
        after = screener.policy(profile())
        assert after is not None and after.version == 2
        assert after.bundle_hash == engine.catalog.floor(2).content_hash()
    finally:
        await engine.shutdown()
