"""As contract tests run against both stores.

* The store persists and hashes the document as submitted, never a model dump.
* The active pointer only moves to a version that verifies.
* ``expected_current`` makes a pointer move a compare-and-set.
* The compiler and the store share one ``extends`` pattern.

(Role separation is Postgres-only: see test_store_postgres_roles.py.)
"""

import copy
import json

import pytest
from policy_fixtures import FLOOR_V2, INSURANCE_V3, valid_bundle
from pydantic import create_model
from store_harness import ACME, catalog_hashes, make_bundle

from guardrail_engine.policy import Bundle, InMemoryCatalog, parse_bundle
from guardrail_engine.policy import document as document_module
from guardrail_engine.store import (
    UNCHECKED,
    ActivePointerConflictError,
    BundleIntegrityError,
    IntegrityFailure,
    UnstorableDocumentError,
    VersionNotFoundError,
)

WRONG_HASH = "sha256:" + "0" * 64


async def put(store, version=1, **changes):
    bundle, bundle_hash = make_bundle(ACME, version, **changes)
    await store.put_version(ACME, bundle, bundle_hash=bundle_hash)
    return bundle, bundle_hash


def from_text(text: str):
    """A bundle submitted as JSON text, with its hash computed without the compiler."""
    parsed = parse_bundle(text)
    return parsed, parsed.bundle_hash(extends=catalog_hashes())


# ---------------------------------------------------------------------------
async def test_store_persists_the_document_as_submitted_with_no_defaults_filled_in(harness):
    store = harness.store()
    bundle, _ = await put(store)
    assert "origin" not in bundle.document["rules"][0]  # the tenant never wrote it

    loaded = await store.get_version(ACME, 1)

    assert loaded.parsed.canonical_document == bundle.canonical_document
    assert loaded.document == bundle.document
    assert "origin" not in loaded.document["rules"][0]
    assert "template_unedited" not in loaded.document["rules"][0]
    assert loaded.bundle.rules[0].origin == "custom"  # the model still reads the default


async def test_adding_a_defaulted_field_to_the_model_leaves_a_stored_version_loadable(
    harness, monkeypatch
):
    """The probe: a later build adds a defaulted field to ``Bundle``."""
    alerts = []
    store = harness.store(hook=alerts.append)
    _, bundle_hash = await put(store)
    await store.set_active_version(ACME, 1)

    grown = create_model("Bundle", __base__=Bundle, probe_field=(str | None, None))
    monkeypatch.setitem(document_module._READERS, 1, grown.model_validate)

    loaded = await store.load_active(ACME)
    assert "probe_field" in loaded.bundle.model_dump()  # the new model really is in use
    assert loaded.bundle_hash == bundle_hash
    assert alerts == []


AWKWARD_TEXT_PARTS = {
    '"block_at": 0.85': '"block_at": 0.850',
    '"escalate_at": 0.55': '"escalate_at": 55e-2',
    '"max_input_tokens": 12000': '"max_input_tokens": 123456789012345678901234567890',
    '"chunk_tokens": 8000': '"chunk_tokens": 8.0e3',
    # Not a sensible threshold, but the store doesn't judge policy: it must hand back
    # exactly what it was given. A jsonb column returns this one as an integer.
    '"block_at": 0.7': '"block_at": 1e22',
    '"records_days": 2555': '"records_days": 2.555E3',
}


def awkward_text() -> str:
    raw = copy.deepcopy(valid_bundle())
    raw["version"] = 1
    raw["rules"][0]["true_description"] = (
        'Quote " backslash ' + chr(0x5C) + " tab " + chr(9) + chr(0xE9) + chr(0x2028) + chr(0x1F512)
    )
    raw["rules"][0]["block_at"] = 0.8  # written as 0.80 below
    raw["rules"][0]["escalate_at"] = 0.01  # written as 1e-2 below
    text = json.dumps(raw, indent=2)
    for plain, awkward in {
        **AWKWARD_TEXT_PARTS,
        '"block_at": 0.8,': '"block_at": 0.80,',
        '"escalate_at": 0.01': '"escalate_at": 1e-2',
    }.items():
        assert plain in text, plain
        text = text.replace(plain, awkward)
    return text


async def test_awkward_numbers_and_strings_survive_the_round_trip_and_still_verify(harness):
    """0.80, 1e-2, a float with a huge exponent, a 30-digit integer and unusual characters.
    (A jsonb column would hand 1e22 back as an integer and break the hash.)"""
    alerts = []
    store = harness.store(hook=alerts.append)
    bundle, bundle_hash = from_text(awkward_text())
    assert b'"block_at":1e+22' in bundle.canonical_document
    assert b'"chunk_tokens":8000.0' in bundle.canonical_document
    assert b'"block_at":0.8,' in bundle.canonical_document

    await store.put_version(ACME, bundle, bundle_hash=bundle_hash)
    await store.set_active_version(ACME, 1)
    loaded = await store.load_active(ACME)

    assert loaded.parsed.canonical_document == bundle.canonical_document
    assert loaded.bundle_hash == bundle_hash
    assert loaded.parsed.bundle_hash(extends=catalog_hashes()) == bundle_hash
    limits = loaded.document["guard_points"]
    assert limits["input"]["max_input_tokens"] == 123456789012345678901234567890
    assert type(limits["tool_result"]["chunk_tokens"]) is float
    assert type(loaded.document["overrides"][0]["block_at"]) is float
    assert chr(0x2028) + chr(0x1F512) in loaded.document["rules"][0]["true_description"]
    assert alerts == []


async def test_put_refuses_a_model_because_it_carries_no_submitted_document(harness):
    store = harness.store()
    bundle, bundle_hash = make_bundle()

    with pytest.raises(TypeError, match="ParsedBundle"):
        await store.put_version(ACME, bundle.bundle, bundle_hash=bundle_hash)
    with pytest.raises(TypeError, match="ParsedBundle"):
        await store.put_version(ACME, bundle.document, bundle_hash=bundle_hash)

    assert await store.list_versions(ACME) == []


@pytest.mark.parametrize(
    "spelling",
    ['"version": 1.0', '"version": "1"', '"version": true'],
    ids=["float", "str", "bool"],
)
async def test_put_refuses_a_document_whose_version_is_not_written_as_an_integer(harness, spelling):
    """The model would read all of these as 1. The database ties the row to the version the
    document states, so both stores refuse them the same way."""
    store = harness.store()
    raw = {**valid_bundle(), "version": 1}
    text = json.dumps(raw).replace('"version": 1', spelling)
    bundle, bundle_hash = from_text(text)
    assert bundle.bundle.version == 1

    with pytest.raises(UnstorableDocumentError):
        await store.put_version(ACME, bundle, bundle_hash=bundle_hash)

    assert await store.list_versions(ACME) == []


async def test_put_refuses_a_document_with_a_nul_character_or_an_oversized_version(harness):
    store = harness.store()
    with_nul = {**valid_bundle(), "version": 1}
    with_nul["escalation"] = {"target": "webhook", "url": "https://hooks.example/a\x00b"}
    too_big = {**valid_bundle(), "version": 2**63}

    for raw in (with_nul, too_big):
        bundle, bundle_hash = from_text(json.dumps(raw))
        with pytest.raises(UnstorableDocumentError):
            await store.put_version(ACME, bundle, bundle_hash=bundle_hash)

    assert await store.list_versions(ACME) == []


# ---------------------------------------------------------------------------
async def test_set_active_refuses_a_tampered_version_and_leaves_the_pointer_unchanged(
    harness,
):
    alerts = []
    store = harness.store(hook=alerts.append)
    await put(store, version=1)
    await put(store, version=2)
    await store.set_active_version(ACME, 1)

    def weaken(document):
        document["defaults"]["block_at"] = 0.99

    await harness.tamper_document(ACME, 2, weaken)

    with pytest.raises(BundleIntegrityError) as e:
        await store.set_active_version(ACME, 2)

    assert e.value.reason is IntegrityFailure.HASH_MISMATCH
    assert [(a.version, a.reason) for a in alerts] == [(2, IntegrityFailure.HASH_MISMATCH)]
    assert await store.get_active_version(ACME) == 1
    assert (await store.load_active(ACME)).version == 1  # the tenant still has a policy


async def test_set_active_refuses_a_tampered_hash_when_no_pointer_was_set(harness):
    store = harness.store()
    await put(store, version=1)
    await harness.tamper_hash(ACME, 1, WRONG_HASH)

    with pytest.raises(BundleIntegrityError):
        await store.set_active_version(ACME, 1)
    with pytest.raises(BundleIntegrityError):
        await store.set_active_version(ACME, 1, expected_current=None)

    assert await store.get_active_version(ACME) is None


@pytest.mark.parametrize(
    ("catalog", "reason"),
    [
        (InMemoryCatalog(floors=[FLOOR_V2], packs=[INSURANCE_V3]), "catalog_version_missing"),
        (None, "no_catalog"),
    ],
    ids=["catalog-version-missing", "no-catalog"],
)
async def test_set_active_refuses_a_version_that_cannot_be_verified_against_the_catalog(
    harness, catalog, reason
):
    """A rollback targets an old version, the kind most likely to extend a catalog version
    that has since gone missing."""
    good = harness.store()
    await put(good, version=1)
    await put(good, version=2)
    await good.set_active_version(ACME, 2)
    alerts = []
    store = harness.store(catalog=catalog, hook=alerts.append)

    with pytest.raises(BundleIntegrityError) as e:
        await store.set_active_version(ACME, 1)

    assert e.value.reason == reason
    assert len(alerts) == 1
    assert await store.get_active_version(ACME) == 2


# ---------------------------------------------------------------------------
async def test_compare_and_set_moves_the_pointer_when_it_is_where_expected(harness):
    store = harness.store()
    for version in (1, 2, 3):
        await put(store, version=version)

    await store.set_active_version(ACME, 1, expected_current=None)  # first publish
    await store.set_active_version(ACME, 2, expected_current=1)
    await store.set_active_version(ACME, 2, expected_current=2)  # already there: fine
    await store.set_active_version(ACME, 3, expected_current=UNCHECKED)

    assert await store.get_active_version(ACME) == 3


async def test_compare_and_set_refuses_when_the_pointer_has_moved(harness):
    store = harness.store()
    for version in (1, 2, 3):
        await put(store, version=version)
    await store.set_active_version(ACME, 1)
    await store.set_active_version(ACME, 2)  # someone else's rollback or publish

    with pytest.raises(ActivePointerConflictError) as e:
        await store.set_active_version(ACME, 3, expected_current=1)

    assert (e.value.tenant_id, e.value.expected, e.value.actual) == (ACME, 1, 2)
    assert await store.get_active_version(ACME) == 2


async def test_compare_and_set_expecting_no_pointer_refuses_when_one_is_set(harness):
    store = harness.store()
    await put(store, version=1)
    await put(store, version=2)
    await store.set_active_version(ACME, 1)

    with pytest.raises(ActivePointerConflictError) as e:
        await store.set_active_version(ACME, 2, expected_current=None)

    assert (e.value.expected, e.value.actual) == (None, 1)
    assert await store.get_active_version(ACME) == 1


@pytest.mark.parametrize("expected", [1, 7, 0, 2**70])
async def test_compare_and_set_expecting_a_version_refuses_when_no_pointer_is_set(
    harness, expected
):
    store = harness.store()
    await put(store, version=1)

    with pytest.raises(ActivePointerConflictError) as e:
        await store.set_active_version(ACME, 1, expected_current=expected)

    assert (e.value.expected, e.value.actual) == (expected, None)
    assert await store.get_active_version(ACME) is None


async def test_compare_and_set_to_a_missing_version_is_version_not_found(harness):
    store = harness.store()
    await put(store, version=1)
    await store.set_active_version(ACME, 1)

    with pytest.raises(VersionNotFoundError):
        await store.set_active_version(ACME, 9, expected_current=1)

    assert await store.get_active_version(ACME) == 1


def test_compiler_and_store_share_one_extends_pattern():
    """The compiler and the store read ``extends`` with the very same compiled pattern, so
    they can't drift on which references are valid. Neither keeps a private copy."""
    from guardrail_engine import policy
    from guardrail_engine.policy import compiler
    from guardrail_engine.store import verification

    assert compiler.EXTENDS_REF_PATTERN is policy.EXTENDS_REF_PATTERN
    assert verification.EXTENDS_REF_PATTERN is policy.EXTENDS_REF_PATTERN
    assert not hasattr(compiler, "_EXTENDS")
    assert not hasattr(verification, "_EXTENDS")
