"""M1-09 at the store: a stored version keeps verifying when the catalog rule model changes.

This is the failure the story prevents. Before M1-09, floor and pack content hashes were
taken over the parsed models, so adding one defaulted field to the catalog rule model
changed every catalog hash, and so every stored bundle failed its integrity re-check.
"""

from policy_fixtures import grow_the_catalog_rule_model, make_catalog
from store_harness import ACME, make_bundle


async def test_m1_09_stored_versions_still_verify_after_the_catalog_rule_model_grows(
    harness, monkeypatch
):
    bundle, bundle_hash = make_bundle(version=1)
    alerts = []
    await harness.store(hook=alerts.append).put_version(ACME, bundle, bundle_hash=bundle_hash)

    grow_the_catalog_rule_model(monkeypatch)
    catalog = make_catalog()  # the same source documents, read by the grown models
    assert "probe_field" in catalog.floor(2).rules[0].model_dump()
    store = harness.store(catalog=catalog, hook=alerts.append)

    loaded = await store.get_version(ACME, 1)
    await store.set_active_version(ACME, 1)
    active = await store.load_active(ACME)

    assert loaded.bundle_hash == active.bundle_hash == bundle_hash
    assert alerts == []
