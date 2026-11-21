"""The ``PolicyStore`` contract (M1-02), run against the in-memory and the Postgres store.

Sections follow the story's criteria: storing and listing versions, the active-version
pointer, immutability, hash verification on load, and tenant isolation.
"""

from datetime import datetime

import pytest
from policy_fixtures import FINANCE_V2, FLOOR_V2, INSURANCE_V3
from store_harness import ACME, OTHER, make_bundle

from guardrail_engine.policy import FloorVersion, InMemoryCatalog
from guardrail_engine.store import (
    BundleIntegrityError,
    IntegrityAlert,
    IntegrityFailure,
    InvalidTenantIdError,
    TenantMismatchError,
    VersionConflictError,
    VersionInfo,
    VersionNotFoundError,
)

WRONG_HASH = "sha256:" + "0" * 64


async def put(store, tenant_id=ACME, version=1, **changes):
    bundle, bundle_hash = make_bundle(tenant_id, version, **changes)
    await store.put_version(tenant_id, bundle, bundle_hash=bundle_hash)
    return bundle, bundle_hash


# --------------------------------------------------------------------------- store and load


async def test_stored_version_loads_back_equal_with_its_bundle_hash(harness):
    store = harness.store()
    bundle, bundle_hash = make_bundle(version=14)

    info = await store.put_version(ACME, bundle, bundle_hash=bundle_hash)
    loaded = await store.get_version(ACME, 14)

    assert info == VersionInfo(ACME, 14, bundle_hash, info.created_at)
    assert isinstance(info.created_at, datetime) and info.created_at.tzinfo is not None
    assert loaded.parsed == bundle
    assert loaded.bundle == bundle.bundle
    assert loaded.document == bundle.document
    assert (loaded.tenant_id, loaded.version, loaded.bundle_hash) == (ACME, 14, bundle_hash)
    assert loaded.info == info


async def test_put_takes_the_version_number_from_the_bundle(harness):
    store = harness.store()
    await put(store, version=7)
    assert [v.version for v in await store.list_versions(ACME)] == [7]


async def test_put_refuses_a_bundle_whose_tenant_id_is_not_the_callers(harness):
    store = harness.store()
    bundle, bundle_hash = make_bundle(OTHER, 1)

    with pytest.raises(TenantMismatchError):
        await store.put_version(ACME, bundle, bundle_hash=bundle_hash)

    assert await store.list_versions(ACME) == []
    assert await store.list_versions(OTHER) == []


async def test_put_refuses_a_hash_that_is_not_the_bundles_hash_and_stores_nothing(harness):
    store = harness.store()
    bundle, _ = make_bundle()

    with pytest.raises(BundleIntegrityError) as e:
        await store.put_version(ACME, bundle, bundle_hash=WRONG_HASH)

    assert e.value.reason is IntegrityFailure.HASH_MISMATCH
    assert await store.list_versions(ACME) == []


async def test_put_with_no_catalog_is_refused_and_stores_nothing(harness):
    bundle, bundle_hash = make_bundle()

    with pytest.raises(BundleIntegrityError) as e:
        await harness.store(catalog=None).put_version(ACME, bundle, bundle_hash=bundle_hash)

    assert e.value.reason is IntegrityFailure.NO_CATALOG
    assert await harness.store().list_versions(ACME) == []


async def test_get_unknown_version_raises_version_not_found(harness):
    store = harness.store()
    await put(store, version=1)
    for missing in (2, 0, -1, 2**70):
        with pytest.raises(VersionNotFoundError):
            await store.get_version(ACME, missing)


async def test_list_versions_is_oldest_first_and_carries_each_hash(harness):
    store = harness.store()
    hashes = {}
    for version in (3, 1, 2):
        _, hashes[version] = await put(store, version=version)

    listed = await store.list_versions(ACME)

    assert [(v.tenant_id, v.version, v.bundle_hash) for v in listed] == [
        (ACME, 1, hashes[1]),
        (ACME, 2, hashes[2]),
        (ACME, 3, hashes[3]),
    ]
    assert len(set(hashes.values())) == 3  # the version number is part of the hashed bundle


async def test_list_versions_of_a_tenant_with_none_is_empty(harness):
    assert await harness.store().list_versions(ACME) == []


# --------------------------------------------------------------------------- active pointer


async def test_active_version_is_none_until_set(harness):
    store = harness.store()
    await put(store, version=1)
    assert await store.get_active_version(ACME) is None
    assert await store.load_active(ACME) is None


async def test_set_active_version_then_load_active_returns_that_version(harness):
    store = harness.store()
    bundle, bundle_hash = await put(store, version=1)
    await put(store, version=2)

    await store.set_active_version(ACME, 1)

    assert await store.get_active_version(ACME) == 1
    active = await store.load_active(ACME)
    assert (active.version, active.parsed, active.bundle_hash) == (1, bundle, bundle_hash)


async def test_active_pointer_moves_forward_and_rolls_back(harness):
    store = harness.store()
    await put(store, version=1)
    await put(store, version=2)

    await store.set_active_version(ACME, 2)
    assert (await store.load_active(ACME)).version == 2
    await store.set_active_version(ACME, 1)  # rollback
    assert await store.get_active_version(ACME) == 1
    assert (await store.load_active(ACME)).version == 1


async def test_set_active_to_a_version_that_does_not_exist_is_refused_and_pointer_unchanged(
    harness,
):
    store = harness.store()
    await put(store, version=1)
    await store.set_active_version(ACME, 1)

    for missing in (2, 0, 2**70):
        with pytest.raises(VersionNotFoundError):
            await store.set_active_version(ACME, missing)

    assert await store.get_active_version(ACME) == 1


async def test_storing_a_new_version_does_not_move_the_active_pointer(harness):
    store = harness.store()
    await put(store, version=1)
    await store.set_active_version(ACME, 1)
    await put(store, version=2)
    assert await store.get_active_version(ACME) == 1


# --------------------------------------------------------------------------- immutability


async def test_storing_different_content_under_an_existing_version_is_refused(harness):
    store = harness.store()
    original, original_hash = await put(store, version=1)
    changed, changed_hash = make_bundle(version=1, rules=[])
    assert changed_hash != original_hash

    with pytest.raises(VersionConflictError):
        await store.put_version(ACME, changed, bundle_hash=changed_hash)

    loaded = await store.get_version(ACME, 1)
    assert (loaded.parsed, loaded.bundle_hash) == (original, original_hash)
    assert len(await store.list_versions(ACME)) == 1


async def test_storing_identical_content_again_is_a_no_op_that_keeps_the_first_record(harness):
    store = harness.store()
    bundle, bundle_hash = make_bundle(version=1)
    first = await store.put_version(ACME, bundle, bundle_hash=bundle_hash)

    again = await store.put_version(ACME, bundle, bundle_hash=bundle_hash)

    assert again == first
    assert await store.list_versions(ACME) == [first]


async def test_the_port_offers_no_way_to_update_or_delete_a_version(harness):
    store = harness.store()
    public = {name for name in dir(store) if not name.startswith("_")} - {"scoped"}
    assert public == {
        "put_version",
        "get_version",
        "list_versions",
        "get_active_version",
        "set_active_version",
        "load_active",
    }


async def test_changing_a_loaded_or_stored_bundle_object_does_not_change_the_store(harness):
    store = harness.store()
    bundle, bundle_hash = make_bundle(version=1)
    submitted = bundle.document
    await store.put_version(ACME, bundle, bundle_hash=bundle_hash)

    bundle.bundle.rules.clear()  # the caller's model, after storing
    bundle.document["rules"].clear()
    loaded = await store.get_version(ACME, 1)
    loaded.bundle.rules.clear()  # a loaded model
    loaded.bundle.extends.append("domain/healthcare@1")
    loaded.document["rules"].clear()

    fresh = await store.get_version(ACME, 1)
    assert fresh.document == submitted
    assert len(fresh.bundle.rules) == len(submitted["rules"]) == 1
    assert fresh.bundle.extends == ["platform/floor@2", "domain/insurance@3", "domain/finance@2"]


# --------------------------------------------------------------------------- hash on load


def _alerts():
    received: list[IntegrityAlert] = []
    return received, received.append


async def test_load_passes_and_does_not_alert_when_the_hash_matches(harness):
    alerts, hook = _alerts()
    store = harness.store(hook=hook)
    await put(store, version=1)
    await store.set_active_version(ACME, 1)

    await store.get_version(ACME, 1)
    await store.load_active(ACME)

    assert alerts == []


async def test_load_refuses_and_alerts_when_the_stored_bundle_was_changed(harness):
    alerts, hook = _alerts()
    store = harness.store(hook=hook)
    _, bundle_hash = await put(store, version=1)

    def weaken(document):
        document["rules"] = []

    await harness.tamper_document(ACME, 1, weaken)

    with pytest.raises(BundleIntegrityError) as e:
        await store.get_version(ACME, 1)

    assert e.value.reason is IntegrityFailure.HASH_MISMATCH
    assert (e.value.tenant_id, e.value.version) == (ACME, 1)
    assert e.value.expected_hash == bundle_hash
    assert e.value.recomputed_hash not in (None, bundle_hash)
    assert alerts == [
        IntegrityAlert(
            tenant_id=ACME,
            version=1,
            reason=IntegrityFailure.HASH_MISMATCH,
            stored_hash=bundle_hash,
            recomputed_hash=e.value.recomputed_hash,
            detail=e.value.detail,
        )
    ]


async def test_load_refuses_and_alerts_when_the_stored_hash_was_changed(harness):
    alerts, hook = _alerts()
    store = harness.store(hook=hook)
    _, bundle_hash = await put(store, version=1)
    await harness.tamper_hash(ACME, 1, WRONG_HASH)

    with pytest.raises(BundleIntegrityError) as e:
        await store.get_version(ACME, 1)

    assert e.value.reason is IntegrityFailure.HASH_MISMATCH
    assert e.value.expected_hash == WRONG_HASH
    assert e.value.recomputed_hash == bundle_hash
    assert [a.reason for a in alerts] == [IntegrityFailure.HASH_MISMATCH]


async def test_load_active_refuses_and_alerts_on_a_mismatch(harness):
    alerts, hook = _alerts()
    store = harness.store(hook=hook)
    await put(store, version=1)
    await store.set_active_version(ACME, 1)
    await harness.tamper_hash(ACME, 1, WRONG_HASH)

    with pytest.raises(BundleIntegrityError):
        await store.load_active(ACME)

    assert len(alerts) == 1


async def test_load_refuses_when_an_extended_catalog_versions_content_changed(harness):
    """AC-C2.2: the bundle is byte-identical, but floor@2 no longer has the content it had
    when the version was stored."""
    await put(harness.store(), version=1)
    weaker_floor = FloorVersion.from_document(
        {**FLOOR_V2.document, "rules": FLOOR_V2.document["rules"][:1]}
    )
    changed_catalog = InMemoryCatalog(floors=[weaker_floor], packs=[INSURANCE_V3, FINANCE_V2])
    alerts, hook = _alerts()

    with pytest.raises(BundleIntegrityError) as e:
        await harness.store(catalog=changed_catalog, hook=hook).get_version(ACME, 1)

    assert e.value.reason is IntegrityFailure.HASH_MISMATCH
    assert [a.reason for a in alerts] == [IntegrityFailure.HASH_MISMATCH]


async def test_load_with_no_catalog_is_refused_as_a_failed_verification(harness):
    _, bundle_hash = await put(harness.store(), version=1)
    await harness.store().set_active_version(ACME, 1)
    alerts, hook = _alerts()
    store = harness.store(catalog=None, hook=hook)

    with pytest.raises(BundleIntegrityError) as e:
        await store.get_version(ACME, 1)
    with pytest.raises(BundleIntegrityError):
        await store.load_active(ACME)

    assert e.value.reason is IntegrityFailure.NO_CATALOG
    assert (e.value.expected_hash, e.value.recomputed_hash) == (bundle_hash, None)
    assert [a.reason for a in alerts] == [IntegrityFailure.NO_CATALOG] * 2


@pytest.mark.parametrize(
    "catalog",
    [
        InMemoryCatalog(floors=[FLOOR_V2], packs=[INSURANCE_V3]),  # finance@2 missing
        InMemoryCatalog(packs=[INSURANCE_V3, FINANCE_V2]),  # floor@2 missing
        InMemoryCatalog(),
    ],
    ids=["pack-missing", "floor-missing", "empty-catalog"],
)
async def test_load_with_an_extended_version_missing_from_the_catalog_is_refused(harness, catalog):
    await put(harness.store(), version=1)
    alerts, hook = _alerts()

    with pytest.raises(BundleIntegrityError) as e:
        await harness.store(catalog=catalog, hook=hook).get_version(ACME, 1)

    assert e.value.reason is IntegrityFailure.CATALOG_VERSION_MISSING
    assert e.value.recomputed_hash is None
    assert [a.reason for a in alerts] == [IntegrityFailure.CATALOG_VERSION_MISSING]


async def test_load_refuses_a_stored_document_that_is_no_longer_a_valid_bundle(harness):
    alerts, hook = _alerts()
    store = harness.store(hook=hook)
    await put(store, version=1)

    def corrupt(document):
        document["rules"] = "not a list"

    await harness.tamper_document(ACME, 1, corrupt)

    with pytest.raises(BundleIntegrityError) as e:
        await store.get_version(ACME, 1)

    assert e.value.reason is IntegrityFailure.BUNDLE_UNREADABLE
    assert [a.reason for a in alerts] == [IntegrityFailure.BUNDLE_UNREADABLE]


async def test_load_refuses_a_stored_document_with_a_malformed_extends_entry(harness):
    store = harness.store()
    await put(store, version=1)

    def corrupt(document):
        document["extends"] = ["platform/floor@2", "domain/insurance"]

    await harness.tamper_document(ACME, 1, corrupt)

    with pytest.raises(BundleIntegrityError) as e:
        await store.get_version(ACME, 1)

    assert e.value.reason is IntegrityFailure.BUNDLE_UNREADABLE


async def test_a_failing_alert_hook_does_not_hide_the_refusal(harness, caplog):
    def broken_hook(alert):
        raise RuntimeError("pager is down")

    store = harness.store(hook=broken_hook)
    await put(store, version=1)
    await harness.tamper_hash(ACME, 1, WRONG_HASH)

    with pytest.raises(BundleIntegrityError):
        await store.get_version(ACME, 1)

    assert "alert hook failed" in caplog.text


async def test_list_versions_does_not_verify_so_history_stays_readable_after_tampering(harness):
    alerts, hook = _alerts()
    store = harness.store(hook=hook)
    await put(store, version=1)
    await harness.tamper_hash(ACME, 1, WRONG_HASH)

    assert [(v.version, v.bundle_hash) for v in await store.list_versions(ACME)] == [
        (1, WRONG_HASH)
    ]
    assert alerts == []


# --------------------------------------------------------------------------- tenant isolation


async def test_one_tenant_cannot_read_another_tenants_version(harness):
    store = harness.store()
    await put(store, ACME, version=1)

    with pytest.raises(VersionNotFoundError):
        await store.get_version(OTHER, 1)
    assert await store.list_versions(OTHER) == []
    assert await store.load_active(OTHER) is None


async def test_one_tenant_cannot_point_at_another_tenants_version(harness):
    store = harness.store()
    await put(store, ACME, version=5)
    await put(store, OTHER, version=1)
    await store.set_active_version(OTHER, 1)

    with pytest.raises(VersionNotFoundError):
        await store.set_active_version(OTHER, 5)  # only ACME has a version 5

    assert await store.get_active_version(OTHER) == 1
    assert await store.get_active_version(ACME) is None


async def test_tenants_with_the_same_version_number_get_their_own_bundle_and_pointer(harness):
    store = harness.store()
    acme_bundle, acme_hash = await put(store, ACME, version=1)
    other_bundle, other_hash = await put(store, OTHER, version=1, rules=[])
    await put(store, ACME, version=2)
    await store.set_active_version(ACME, 2)
    await store.set_active_version(OTHER, 1)

    assert acme_hash != other_hash
    assert (await store.get_version(ACME, 1)).parsed == acme_bundle
    assert (await store.get_version(OTHER, 1)).parsed == other_bundle
    assert [v.version for v in await store.list_versions(ACME)] == [1, 2]
    assert [v.version for v in await store.list_versions(OTHER)] == [1]
    assert await store.get_active_version(ACME) == 2
    assert (await store.load_active(OTHER)).parsed == other_bundle


# --------------------------------------------------------------------------- tenant id rule


@pytest.mark.parametrize("key", ["t_acme_ins", "t_Acme", "t-acme", "t_" + "a" * 33])
async def test_a_store_key_outside_the_tenant_id_rule_is_refused(harness, key):
    """B3: every store key follows the one tenant id rule. The id is not repeated
    in the error."""
    store = harness.store()
    bundle, bundle_hash = make_bundle()
    with pytest.raises(InvalidTenantIdError) as e:
        await store.put_version(key, bundle, bundle_hash=bundle_hash)
    assert key not in str(e.value)
    assert await store.list_versions(key) == []
