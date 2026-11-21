"""A startup check that every pack version an active (or candidate) bundle names is in
the catalog. Dropping an old pack file from ``catalog.pack_files`` would otherwise make every
bundle that extends it fail to compile (``policy_unavailable``) with nothing said at startup."""

import logging
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "guard"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "policy"))
from guard_fixtures import CLAIMS_V1

from guardrail_engine.engine.factory import EngineStartError, check_stored_pack_versions
from guardrail_engine.policy import InMemoryCatalog
from guardrail_engine.policy.catalog import PackVersion


def claims(version):
    document = dict(CLAIMS_V1.document)
    document["version"] = version
    return PackVersion.from_document(document)


class Refs:
    def __init__(self, refs):
        self.refs = refs

    async def active_pack_refs(self):
        return frozenset(self.refs)


def catalog_of(*versions):
    return InMemoryCatalog(floors=[], packs=[claims(v) for v in versions])


@pytest.mark.parametrize("environment", ["production", "staging"])
async def test_a_missing_pack_version_stops_a_production_or_staging_engine(environment):
    refs = Refs({"domain/claims@1", "domain/claims@2"})
    with pytest.raises(EngineStartError) as stopped:
        await check_stored_pack_versions(refs, catalog_of(2), environment)
    text = str(stopped.value)
    assert "domain/claims@1" in text and "domain/claims@2" not in text
    assert "catalog.pack_files" in text
    assert "t_" not in text  # references only: never a tenant


@pytest.mark.parametrize("environment", ["test", "development"])
async def test_elsewhere_it_is_a_warning(environment, caplog):
    with caplog.at_level(logging.WARNING):
        await check_stored_pack_versions(Refs({"domain/claims@1"}), catalog_of(2), environment)
    assert "domain/claims@1" in caplog.text


async def test_nothing_missing_is_silent(caplog):
    with caplog.at_level(logging.WARNING):
        await check_stored_pack_versions(
            Refs({"domain/claims@1", "domain/claims@2"}), catalog_of(1, 2), "production"
        )
        await check_stored_pack_versions(Refs(set()), catalog_of(), "production")
    assert caplog.text == ""


async def test_a_malformed_reference_counts_as_missing():
    with pytest.raises(EngineStartError):
        await check_stored_pack_versions(Refs({"domain/Claims@x"}), catalog_of(1), "production")


class Broken:
    async def active_pack_refs(self):
        raise RuntimeError("no operator pool: secret-dsn-detail")


@pytest.mark.parametrize("environment", ["production", "staging"])
@pytest.mark.parametrize("references", [Broken(), object()], ids=["raises", "no such method"])
async def test_a_store_that_cannot_answer_stops_a_production_or_staging_engine(
    environment, references
):
    """Decided: a guard that is skipped when it can't look is not a guard. The message names the
    exception type only, never its text."""
    with pytest.raises(EngineStartError) as stopped:
        await check_stored_pack_versions(references, catalog_of(1), environment)
    assert "could not be checked" in str(stopped.value)
    assert "secret-dsn-detail" not in str(stopped.value)


async def test_a_postgres_store_with_no_operator_pool_stops_a_production_engine():
    from guardrail_engine.store.adapters.postgres import PostgresCatalogReferences

    with pytest.raises(EngineStartError) as stopped:
        await check_stored_pack_versions(
            PostgresCatalogReferences(None), catalog_of(1), "production"
        )
    assert "OperatorPoolUnavailableError" in str(stopped.value)


@pytest.mark.parametrize("environment", ["test", "development"])
@pytest.mark.parametrize("references", [Broken(), object()], ids=["raises", "no such method"])
async def test_elsewhere_a_store_that_cannot_answer_is_skipped_with_a_warning(
    environment, references, caplog
):
    with caplog.at_level(logging.WARNING):
        await check_stored_pack_versions(references, catalog_of(1), environment)
    assert "were not checked" in caplog.text and "secret-dsn-detail" not in caplog.text
