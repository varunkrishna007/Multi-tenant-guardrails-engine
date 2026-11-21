"""M2-03: the catalog is append-only. A floor, pack or template version that a stored bundle
uses is never removed; an unused one can be, and only through ``CatalogAdmin``."""

import json
import re
from pathlib import Path

import pytest
from admin_fixtures import ALPHA, BETA, Admin, bundle, rule, who
from test_catalog import REFUNDS, template

from guardrail_engine.admin.catalog import (
    CatalogAdmin,
    CatalogItemInUseError,
    CatalogItemNotFoundError,
)
from guardrail_engine.authz import Role
from guardrail_engine.policy.catalog import InMemoryCatalog
from guardrail_engine.store.memory import MemoryCatalogReferences
from guardrail_engine.tenant_scope import issue_scope

BASE = "/v1/tenants/{tid}/guardrails"
ADMIN = who(Role.GUARDRAIL_ADMIN, issuer="https://i/")
SRC = Path(__file__).parents[2] / "src" / "guardrail_engine"


@pytest.fixture
async def a():
    admin = Admin(templates=(REFUNDS, template(version=2)))
    yield admin
    await admin.aclose()


async def decide(a, method, route, principal=ADMIN, tid=ALPHA):
    return await a.decide(principal, method, BASE + route, tid)


async def save_and_publish(a, doc, *, first=True):
    d = await decide(a, "PUT", "/draft")
    saved = await a.service.put_draft(d, ADMIN, json.dumps(doc).encode(), None if first else "*")
    d = await decide(a, "POST", "/draft/publish")
    body = json.dumps({"mode": "enforce"}).encode()
    return await a.publisher.publish(d, ADMIN, body, saved.etag)


def admin_of(a):
    return CatalogAdmin(a.catalog, MemoryCatalogReferences(a.policies))


async def test_a_floor_pack_or_template_a_stored_bundle_uses_cannot_be_removed(a):
    doc = bundle(ALPHA, packs=["domain/claims@1"], rules=[rule("plain", mode="shadow")])
    await save_and_publish(a, doc)
    assert type(a.catalog) is InMemoryCatalog
    await a.catalog_service.apply_template(
        await decide(a, "POST", "/draft/templates/{template_id}"), ADMIN, "refunds",
        b'{"version": 1}', "*",
    )  # fmt: skip
    # a candidate that uses the template copy, in a stored version
    await save_and_publish_candidate(a)
    admin = admin_of(a)
    with pytest.raises(CatalogItemInUseError) as floor:
        await admin.remove_floor(1)
    assert (floor.value.ref, floor.value.bundles) == ("platform/floor@1", 2)
    with pytest.raises(CatalogItemInUseError, match="domain/claims@1"):
        await admin.remove_pack("claims", 1)
    with pytest.raises(CatalogItemInUseError, match="template:refunds@1"):
        await admin.remove_template("refunds", 1)
    # nothing was removed, and the stored bundles still load and verify
    assert a.catalog.floor(1) and a.catalog.pack("claims", 1) and a.catalog.template("refunds", 1)
    loaded = await a.policies.scoped(issue_scope(ALPHA)).get_version(ALPHA, 1)
    assert loaded.version == 1


async def save_and_publish_candidate(a):
    d = await decide(a, "POST", "/draft/publish")
    stored = await a.drafts.scoped(issue_scope(ALPHA)).get(ALPHA)
    body = json.dumps({"mode": "enforce", "rollout_percent": 100}).encode()
    return await a.publisher.publish(d, ADMIN, body, stored.etag)


async def test_an_unused_version_can_be_removed_once_and_a_missing_one_is_reported(a):
    await save_and_publish(a, bundle(ALPHA, rules=[rule("plain", mode="shadow")]))
    admin = admin_of(a)
    await admin.remove_template("refunds", 2)  # no bundle uses it
    assert a.catalog.template("refunds", 2) is None and a.catalog.template("refunds", 1)
    with pytest.raises(CatalogItemNotFoundError):
        await admin.remove_template("refunds", 2)
    with pytest.raises(CatalogItemNotFoundError):
        await admin.remove_floor(9)
    with pytest.raises(CatalogItemNotFoundError):
        await admin.remove_pack("nope", 1)
    with pytest.raises(CatalogItemInUseError):
        await admin.remove_floor(1)  # the one stored bundle extends it


async def test_references_count_every_tenants_stored_bundles(a):
    await save_and_publish(a, bundle(ALPHA, packs=["domain/claims@1"]))
    beta = who(Role.GUARDRAIL_ADMIN, tenant=BETA, issuer="https://i/")
    d = await a.decide(beta, "PUT", BASE + "/draft", BETA)
    saved = await a.service.put_draft(d, beta, json.dumps(bundle(BETA)).encode(), None)
    d = await a.decide(beta, "POST", BASE + "/draft/publish", BETA)
    await a.publisher.publish(d, beta, b'{"mode": "enforce"}', saved.etag)
    refs = MemoryCatalogReferences(a.policies)
    assert await refs.count("platform/floor@1") == 2
    assert await refs.count("domain/claims@1") == 1
    assert await refs.count("domain/claims@2") == 0
    assert await refs.count("template:refunds@1") == 0


async def test_the_memory_store_reports_the_pack_versions_its_active_versions_extend(a):
    """What the startup check asks (the tenants' active versions, not every stored one)."""
    await save_and_publish(
        a, bundle(ALPHA, packs=["domain/claims@1"], rules=[rule("plain", mode="shadow")])
    )
    assert await MemoryCatalogReferences(a.policies).active_pack_refs() == frozenset(
        {"domain/claims@1"}
    )


async def test_a_failing_reference_check_refuses_the_removal(a):
    class Broken:
        async def count(self, ref):
            raise RuntimeError("database down")

    admin = CatalogAdmin(a.catalog, Broken())
    with pytest.raises(RuntimeError):
        await admin.remove_template("refunds", 2)
    assert a.catalog.template("refunds", 2) is not None


def test_nothing_but_catalog_admin_removes_catalog_items():
    callers = []
    for path in SRC.rglob("*.py"):
        text = path.read_text()
        if re.search(r"\.discard_(floor|pack|template)\(", text):
            callers.append(path.relative_to(SRC).as_posix())
    assert callers == ["admin/catalog.py"]


def test_the_catalog_has_no_other_way_to_remove_an_item():
    public = {n for n in dir(InMemoryCatalog) if not n.startswith("_")}
    removers = {n for n in public if n.startswith(("remove", "delete", "retire", "drop", "clear"))}
    assert removers == set()
