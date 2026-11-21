"""M4-05: the class D term from R3 (by the tenant's packs), and a resolution's golden label on
Postgres (migrations 034 and 035 with the golden tables), outside the upload cap."""

import json
from datetime import UTC, datetime

import pytest
from test_m4_05_escalation_store import ACME, make_item, pg_stores  # noqa: F401  (a fixture)
from test_m4_09_retention import Directory, bundle_with, resolver, tenant

from guardrail_engine.admin.golden import MAX_SETS, GoldenService
from guardrail_engine.authz import Authorizer, InMemoryAuthzAudit, Principal, Role
from guardrail_engine.escalation import CatalogClassDResolver, EscalationService
from guardrail_engine.escalation.retention import (
    FALLBACK_TERM,
    HEALTHCARE_TERM,
    STANDARD_TERM,
)
from guardrail_engine.tenant_scope import issue_scope

NOW = datetime(2026, 11, 1, 12, 0, 0, tzinfo=UTC)


@pytest.mark.parametrize(
    ("extends", "expected"),
    [
        ([], STANDARD_TERM),  # until resolved, plus 30 days
        (["domain/insurance@3"], STANDARD_TERM),
        (["domain/finance@2"], STANDARD_TERM),  # finance: the same
        (["domain/healthcare@1"], HEALTHCARE_TERM),  # 30 days in all
        (["domain/healthcare@1", "domain/finance@2"], HEALTHCARE_TERM),  # the stricter one wins
    ],
)
async def test_the_class_d_term_comes_from_the_tenants_packs(extends, expected):
    term = await CatalogClassDResolver(resolver(Directory(tenant()), bundle_with(extends))).resolve(
        ACME
    )
    assert term == expected


async def test_a_tenant_that_cannot_be_resolved_keeps_the_longer_standard_rule():
    unknown = CatalogClassDResolver(resolver(Directory(), bundle_with([])))
    assert await unknown.resolve(ACME) == FALLBACK_TERM
    broken = CatalogClassDResolver(resolver(Directory(tenant()), RuntimeError("store down")))
    assert await broken.resolve(ACME) == FALLBACK_TERM
    assert await broken.needs_deidentification(ACME) is True  # the stricter answer for a promotion
    healthcare = CatalogClassDResolver(
        resolver(Directory(tenant()), bundle_with(["domain/healthcare@1"]))
    )
    assert await healthcare.needs_deidentification(ACME) is True
    standard = CatalogClassDResolver(resolver(Directory(tenant()), bundle_with([])))
    assert await standard.needs_deidentification(ACME) is False


async def test_a_resolution_makes_its_golden_label_on_postgres_outside_the_upload_cap(pg_stores):  # noqa: F811
    from guardrail_engine.store.adapters.postgres import PostgresGoldenStore

    s = pg_stores
    golden_store = PostgresGoldenStore(s.app_pool)
    golden = GoldenService(golden_store)
    service = EscalationService(s.store, golden, clock=lambda: NOW)
    authorizer = Authorizer(InMemoryAuthzAudit())
    rita = Principal("rita", ACME, frozenset({Role.GUARDRAIL_REVIEWER}), False, "https://idp/")
    base = "/v1/tenants/{tid}/guardrails"

    async def resolve(item, **body):
        d = await authorizer.authorize(rita, "POST", base + "/escalations/{id}/resolve", ACME)
        payload = {"decision": "block", "reason": "no", **body}
        return await service.resolve(d, rita, item.id, json.dumps(payload).encode())

    plain = make_item(n=1, content="a clean example", store_content="full")
    await s.scoped().insert(plain)
    content = await resolve(plain)
    assert (content.label.mode, content.label.quarantined) == ("content", False)
    held = make_item(n=2, content="a private text")  # hash_only: a placeholder
    await s.scoped().insert(held)
    placeholder = await resolve(held)
    assert placeholder.label.mode == "hash_only"
    harmed = make_item(n=3, content="how to kill a stuck process", store_content="full")
    await s.scoped().insert(harmed)
    assert (await resolve(harmed)).label.quarantined is True  # the harm vocabulary: stored, held

    scoped = golden_store.scoped(issue_scope(ACME))
    one = await scoped.examples(ACME, content.label.set_id, "output", offset=0, limit=5)
    assert [(e.label, e.content) for e in one.items] == [("block", "a clean example")]
    ph = await scoped.examples(ACME, placeholder.label.set_id, "output", offset=0, limit=5)
    assert (ph.items, ph.quarantined) == ([], 1)  # never sent
    assert await scoped.label_counts(ACME) == {"output": {"block": 1}}  # only the clean one counts

    # sets of escalation labels don't use up the tenant's uploads
    for n in range(10, 10 + MAX_SETS + 2):
        item = make_item(n=n, content=f"example {n}", store_content="full")
        await s.scoped().insert(item)
        await resolve(item)
    d = await authorizer.authorize(rita, "POST", base + "/golden-sets", ACME)
    upload = {
        "name": "mine",
        "examples": [{"id": "e1", "guard_point": "output", "label": "allow", "content": "hello"}],
    }
    await golden.upload(d, rita, json.dumps(upload).encode())
    events = await s.scoped().audit_events(ACME)
    assert {e.actor for e in events} == {"https://idp/#rita"}
    assert [e.action for e in events[:2]] == ["resolved", "label_created"]
