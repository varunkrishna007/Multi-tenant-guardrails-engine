"""In-memory policy store: behaviour beyond the shared contract in test_store_contract.py."""

import asyncio
import subprocess
import sys
from datetime import UTC, datetime

import pytest
from policy_fixtures import make_catalog
from store_harness import ACME, OTHER, MemoryHarness, make_bundle

from guardrail_engine.store import (
    BundleIntegrityError,
    InMemoryPolicyStore,
    IntegrityFailure,
    PolicyStore,
)


def test_in_memory_store_satisfies_the_policy_store_port():
    store: PolicyStore = InMemoryPolicyStore(catalog=make_catalog())
    for method in (
        "put_version",
        "get_version",
        "list_versions",
        "get_active_version",
        "set_active_version",
        "load_active",
    ):
        assert asyncio.iscoroutinefunction(getattr(store, method))


def test_catalog_must_be_passed_explicitly_so_it_cannot_be_forgotten():
    with pytest.raises(TypeError):
        InMemoryPolicyStore()


async def test_created_at_comes_from_the_injected_clock():
    at = datetime(2026, 11, 16, 12, 0, tzinfo=UTC)
    store = InMemoryPolicyStore(catalog=make_catalog(), clock=lambda: at)
    bundle, bundle_hash = make_bundle()

    info = await store.put_version(ACME, bundle, bundle_hash=bundle_hash)

    assert info.created_at == at
    assert (await store.get_version(ACME, 1)).created_at == at


async def test_a_bundle_filed_under_another_tenant_is_refused_on_load():
    """Even with a matching hash, a document that names a different tenant than the row it
    is filed under is refused. (Postgres refuses the row itself: see the constraint test.)"""
    harness = MemoryHarness()
    alerts = []
    store = harness.store(hook=alerts.append)
    bundle, bundle_hash = make_bundle(ACME, 1)
    await store.put_version(ACME, bundle, bundle_hash=bundle_hash)
    other_bundle, other_hash = make_bundle(OTHER, 1)

    def swap(document):
        document.clear()
        document.update(other_bundle.document)

    await harness.tamper_document(ACME, 1, swap)
    await harness.tamper_hash(ACME, 1, other_hash)

    with pytest.raises(BundleIntegrityError) as e:
        await store.get_version(ACME, 1)

    assert e.value.reason is IntegrityFailure.BUNDLE_UNREADABLE
    assert len(alerts) == 1


def test_importing_the_store_package_does_not_load_a_database_driver():
    code = (
        "import sys, guardrail_engine.store, guardrail_engine.store.memory\n"
        "loaded = sorted(m for m in sys.modules if m.split('.')[0] in "
        "{'asyncpg', 'psycopg', 'psycopg2', 'sqlalchemy'})\n"
        "assert not loaded, loaded\n"
    )
    subprocess.run([sys.executable, "-c", code], check=True)
