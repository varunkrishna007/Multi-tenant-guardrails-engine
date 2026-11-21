"""M2-02 draft lifecycle, through the real authorizer: AC-A1 (draft, If-Match, rules) and AC-A2
(a class A event with actor, diff and resulting hash for every write)."""

import json

import pytest
from admin_fixtures import ALPHA, BETA, DRAFT, GUARDRAILS, RULE, Admin, bundle, rule, who

from guardrail_engine.admin import (
    DecisionError,
    DraftConflictError,
    DraftInvalidError,
    NoDraftError,
    PreconditionRequiredError,
    RuleNotFoundError,
    TenantUnavailableError,
    etag_of,
)
from guardrail_engine.authz import Role
from guardrail_engine.store.port import ScopeMismatchError

ADMIN = who(Role.GUARDRAIL_ADMIN)


def body(doc) -> bytes:
    return json.dumps(doc).encode()


async def put(a, doc, *, if_match=None, principal=ADMIN, tid=ALPHA):
    decision = await a.decide(principal, "PUT", DRAFT, tid)
    return await a.service.put_draft(decision, principal, body(doc), if_match)


async def test_the_first_draft_is_stored_with_an_etag_and_its_audit_event():
    a = Admin()
    doc = bundle(ALPHA, rules=[rule("refunds")])
    stored = await put(a, doc)
    assert stored.tenant_id == ALPHA and stored.updated_by == "alice"
    assert stored.etag == etag_of(json.loads(stored.document))
    (event,) = await a.drafts.scoped(await _scope(a)).audit_events(ALPHA)
    assert (event.actor, event.tenant_id, event.action) == ("alice", ALPHA, "draft.put")
    assert event.before_hash is None and event.resulting_hash == stored.etag.strip('"')
    assert any(d.path == "/rules" for d in event.diff)  # the diff is the whole new document


async def test_replacing_a_draft_needs_if_match_and_a_wrong_one_is_412():
    a = Admin()
    first = await put(a, bundle(ALPHA))
    with pytest.raises(PreconditionRequiredError):
        await put(a, bundle(ALPHA, rules=[rule("a")]))
    with pytest.raises(DraftConflictError) as stale:
        await put(a, bundle(ALPHA, rules=[rule("a")]), if_match='"sha256:stale"')
    assert stale.value.current == first.etag
    with pytest.raises(DraftConflictError):  # a weak validator never matches
        await put(a, bundle(ALPHA, rules=[rule("a")]), if_match="W/" + first.etag)
    second = await put(a, bundle(ALPHA, rules=[rule("a")]), if_match=first.etag)
    assert second.etag != first.etag
    again = await put(a, bundle(ALPHA, rules=[rule("b")]), if_match="*")  # * matches any draft
    assert again.etag != second.etag
    with pytest.raises(DraftConflictError):  # the old ETag is stale now
        await put(a, bundle(ALPHA), if_match=first.etag)


async def test_a_precondition_on_a_draft_that_does_not_exist_is_412():
    a = Admin()
    with pytest.raises(DraftConflictError) as e:
        await put(a, bundle(ALPHA), if_match="*")
    assert e.value.current is None


async def test_an_invalid_draft_is_rejected_with_all_errors_and_nothing_is_stored():
    a = Admin()
    broken = bundle(ALPHA, rules=[rule("x", block_at=0.2, escalate_at=0.9)])  # inverted
    broken["unknown_field"] = 1
    with pytest.raises(DraftInvalidError) as e:
        await put(a, broken)
    assert e.value.errors and all(x.code and x.path for x in e.value.errors)
    assert a.drafts._drafts == {} and a.drafts._events == []


async def test_all_shape_errors_come_together_then_semantic_ones_only_for_a_valid_shape():
    a = Admin()
    with pytest.raises(DraftInvalidError) as shape:
        await a.service.put_draft(
            await a.decide(ADMIN, "PUT", DRAFT), ADMIN, b'{"schema_version": 1, "extra": 1}', None
        )
    assert len(shape.value.errors) >= 2  # several missing fields and the unknown one, together
    with pytest.raises(DraftInvalidError) as semantic:
        await put(a, bundle(ALPHA, rules=[rule("a", block_at=0.1, escalate_at=0.9)]))
    assert all(x.code != "schema.invalid" for x in semantic.value.errors)


@pytest.mark.parametrize(
    "raw",
    [b"not json", b'{"a": 1, "a": 2}', b'{"a": NaN}', b"[1]", b""],
)
async def test_text_that_is_not_one_json_object_is_a_validation_error_not_a_crash(raw):
    a = Admin()
    with pytest.raises(DraftInvalidError):
        await a.service.put_draft(await a.decide(ADMIN, "PUT", DRAFT), ADMIN, raw, None)


async def test_a_draft_that_names_another_tenant_is_rejected():
    a = Admin()
    with pytest.raises(DraftInvalidError) as e:
        await put(a, bundle(BETA))  # alpha's admin, beta's document
    assert any(x.code == "bundle.tenant_mismatch" for x in e.value.errors)


async def test_an_oversized_draft_is_refused_before_it_is_parsed():
    a = Admin()
    huge = b'{"x": "' + b"a" * (300 * 1024) + b'"}'
    with pytest.raises(DraftInvalidError) as e:
        await a.service.put_draft(await a.decide(ADMIN, "PUT", DRAFT), ADMIN, huge, None)
    assert e.value.errors[0].code == "draft.too_large"


async def test_a_tenant_missing_from_the_directory_cannot_be_written():
    a = Admin()
    a.tenants._profiles.pop(ALPHA)
    with pytest.raises(TenantUnavailableError):
        await put(a, bundle(ALPHA))


# ---------------------------------------------------------------------------- rules


async def patch(a, rule_id, patch_body, *, if_match, principal=ADMIN, tid=ALPHA):
    decision = await a.decide(principal, "PATCH", RULE, tid)
    return await a.service.patch_rule(decision, principal, rule_id, body(patch_body), if_match)


async def test_patch_creates_then_merges_a_rule_and_each_write_is_audited():
    a = Admin()
    base = await put(a, bundle(ALPHA))
    created = await patch(
        a, "refunds",
        {k: v for k, v in rule("refunds").items() if k != "id"}, if_match=base.etag,
    )  # fmt: skip
    rules = json.loads(created.document)["rules"]
    assert [r["id"] for r in rules] == ["refunds"]
    edited = await patch(
        a, "refunds", {"block_at": 0.95, "severity": "high"}, if_match=created.etag
    )
    (r,) = json.loads(edited.document)["rules"]
    assert (
        r["block_at"] == 0.95 and r["severity"] == "high" and r["question"]
    )  # merged, not replaced
    removed_member = await patch(a, "refunds", {"escalate_at": None}, if_match=edited.etag)
    assert "escalate_at" not in json.loads(removed_member.document)["rules"][0]
    actions = [e.action for e in a.drafts._events]
    assert actions == ["draft.put", "draft.rule.put", "draft.rule.put", "draft.rule.put"]
    chain = [(e.before_hash, e.resulting_hash) for e in a.drafts._events]
    assert all(chain[i][1] == chain[i + 1][0] for i in range(len(chain) - 1))  # a hash chain


async def test_patch_needs_a_draft_if_match_and_a_matching_id():
    a = Admin()
    with pytest.raises(NoDraftError):
        await patch(a, "r", {"question": "q"}, if_match="*")
    base = await put(a, bundle(ALPHA))
    with pytest.raises(PreconditionRequiredError):
        await patch(a, "r", {"question": "q"}, if_match=None)
    with pytest.raises(DraftConflictError):
        await patch(a, "r", {"question": "q"}, if_match='"sha256:stale"')
    with pytest.raises(DraftInvalidError) as e:
        await patch(a, "r", {"id": "other"}, if_match=base.etag)
    assert e.value.errors[0].code == "draft.rule_id_mismatch"


async def test_an_invalid_rule_edit_is_rejected_whole_and_the_draft_is_unchanged():
    a = Admin()
    base = await put(a, bundle(ALPHA, rules=[rule("r")]))
    with pytest.raises(DraftInvalidError) as e:
        await patch(a, "r", {"block_at": 0.1, "escalate_at": 0.9}, if_match=base.etag)
    assert e.value.errors
    assert (await a.drafts.scoped(await _scope(a)).get(ALPHA)).etag == base.etag
    assert len(a.drafts._events) == 1


async def _scope(a, tid=ALPHA):
    return (await a.decide(ADMIN, "GET", GUARDRAILS, tid)).scope


async def test_delete_removes_a_tenant_rule_and_an_unknown_rule_is_404():
    a = Admin()
    base = await put(a, bundle(ALPHA, rules=[rule("a"), rule("b")]))
    decision = await a.decide(ADMIN, "DELETE", RULE)
    after = await a.service.delete_rule(decision, ADMIN, "a", base.etag)
    assert [r["id"] for r in json.loads(after.document)["rules"]] == ["b"]
    assert a.drafts._events[-1].action == "draft.rule.delete"
    with pytest.raises(RuleNotFoundError):
        await a.service.delete_rule(decision, ADMIN, "a", after.etag)
    with pytest.raises(PreconditionRequiredError):
        await a.service.delete_rule(decision, ADMIN, "b", None)


# ---------------------------------------------------------------------------- the decision


async def test_the_tenant_is_the_decisions_scope_never_the_documents_or_a_caller_string():
    """An operator crossing into BETA writes BETA's draft; the document must be BETA's too."""
    a = Admin()
    operator = who(Role.GUARDRAIL_ADMIN, tenant=None, operator=True, subject="ops-1")
    stored = await put(a, bundle(BETA), principal=operator, tid=BETA)
    assert stored.tenant_id == BETA and stored.updated_by == "ops-1"
    assert a.drafts._events[0].tenant_id == BETA
    assert [e.target_tenant_id for e in a.audit.events] == [BETA]  # the crossing was audited
    with pytest.raises(DraftInvalidError):  # the document names ALPHA but the scope is BETA
        await put(a, bundle(ALPHA), principal=operator, tid=BETA, if_match="*")


async def test_a_denied_decision_or_one_for_another_endpoint_is_refused():
    a = Admin()
    viewer = who(Role.VIEWER)
    denied = await a.decide(viewer, "PUT", DRAFT)
    assert not denied.allowed
    with pytest.raises(DecisionError):
        await a.service.put_draft(denied, ADMIN, body(bundle(ALPHA)), None)
    other_tenant = await a.decide(ADMIN, "PUT", DRAFT, BETA)  # tenant mismatch: denied
    assert not other_tenant.allowed
    with pytest.raises(DecisionError):
        await a.service.put_draft(other_tenant, ADMIN, body(bundle(ALPHA)), None)
    read = await a.decide(viewer, "GET", GUARDRAILS)
    with pytest.raises(DecisionError):  # a read decision can't authorize a write
        await a.service.put_draft(read, ADMIN, body(bundle(ALPHA)), None)


async def test_the_store_refuses_a_write_for_another_tenant_even_with_a_scope():
    a = Admin()
    view = a.drafts.scoped(await _scope(a))
    from datetime import UTC, datetime

    from guardrail_engine.admin import DraftAuditEvent

    event = DraftAuditEvent(datetime.now(UTC), "x", BETA, "draft.put", None, "sha256:0", ())
    with pytest.raises(ScopeMismatchError):
        await view.replace(BETA, b"{}", expected_etag=None, event=event)
    with pytest.raises(ScopeMismatchError):
        await view.get(BETA)


# ---------------------------------------------------------------------------- reads


async def test_get_guardrails_returns_the_draft_and_the_published_version():
    a = Admin()
    viewer = who(Role.VIEWER)
    empty = await a.service.get_guardrails(await a.decide(viewer, "GET", GUARDRAILS))
    assert empty.draft is None and empty.published is None and empty.rollout is None
    stored = await put(a, bundle(ALPHA))
    view = await a.service.get_guardrails(await a.decide(viewer, "GET", GUARDRAILS))
    assert view.draft.etag == stored.etag and view.tenant_id == ALPHA


async def test_one_tenants_draft_is_invisible_to_another():
    a = Admin()
    await put(a, bundle(ALPHA, rules=[rule("secret")]))
    beta_admin = who(Role.GUARDRAIL_ADMIN, tenant=BETA)
    view = await a.service.get_guardrails(await a.decide(beta_admin, "GET", GUARDRAILS, BETA))
    assert view.draft is None


async def test_the_same_subject_from_two_issuers_is_two_actors_in_the_audit():
    """A subject is unique only within its issuer."""
    a = Admin()
    one = who(Role.GUARDRAIL_ADMIN, subject="ops-1", issuer="https://platform.example/")
    two = who(Role.GUARDRAIL_ADMIN, subject="ops-1", issuer="https://sso.tenant-a.example/")
    first = await put(a, bundle(ALPHA), principal=one)
    await put(a, bundle(ALPHA, rules=[rule("r")]), principal=two, if_match=first.etag)
    actors = [e.actor for e in a.drafts._events]
    assert actors == ["https://platform.example/#ops-1", "https://sso.tenant-a.example/#ops-1"]
    assert len(set(actors)) == 2 and first.updated_by == actors[0]


async def test_an_operators_cross_tenant_write_is_marked_in_the_draft_audit():
    a = Admin()
    operator = who(Role.GUARDRAIL_ADMIN, tenant=None, operator=True, subject="ops-1")
    await put(a, bundle(BETA), principal=operator, tid=BETA)
    await put(a, bundle(ALPHA))  # the tenant's own admin
    own = a.drafts._events[1]
    crossing = a.drafts._events[0]
    assert (crossing.cross_tenant, crossing.operator) == (True, True)
    assert (own.cross_tenant, own.operator) == (False, False)


async def test_the_authorizers_cross_tenant_event_names_the_issuer_too():
    a = Admin()
    operator = who(
        Role.GUARDRAIL_ADMIN, tenant=None, operator=True, subject="ops-1", issuer="https://p/"
    )
    await put(a, bundle(BETA), principal=operator, tid=BETA)
    assert [e.actor for e in a.audit.events] == ["https://p/#ops-1"]


async def test_a_merge_patch_drops_nested_nulls_instead_of_storing_them():
    """RFC 7396: a patch object over a member that isn't an object patches an empty
    one, so a null inside it is removed, not stored."""
    from guardrail_engine.admin.service import _merge_patch

    assert _merge_patch({"a": 1}, {"a": {"b": None, "c": 2}}) == {"a": {"c": 2}}
    assert _merge_patch({"a": {"b": 1, "c": 2}}, {"a": {"b": None}}) == {"a": {"c": 2}}
    assert _merge_patch({}, {"a": {"b": {"c": None}}}) == {"a": {"b": {}}}


async def test_the_store_reports_whether_it_created_the_draft():
    a = Admin()
    first = await put(a, bundle(ALPHA))
    assert first.created is True
    second = await put(a, bundle(ALPHA, rules=[rule("a")]), if_match=first.etag)
    assert second.created is False
