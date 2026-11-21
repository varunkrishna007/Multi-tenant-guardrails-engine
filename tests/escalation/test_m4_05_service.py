"""M4-05: listing, reading and resolving escalations; the golden label under the R3 content rules;
isolation between tenants."""

import hashlib
import json
from dataclasses import replace

import pytest
from esc_fixtures import ALPHA, BETA, NOW, Rig, doc, item_of, who

from guardrail_engine.admin.golden import (
    ESCALATION_SET_PREFIX,
    HASH_ONLY_VIEW,
    MAX_SETS,
)
from guardrail_engine.admin.service import DraftInvalidError
from guardrail_engine.authz import Role
from guardrail_engine.escalation.model import (
    AlreadyResolvedError,
    DeidentifiedContentRequiredError,
    EscalationItem,
    EscalationNotFoundError,
    InvalidCursorError,
    InvalidQueryError,
    OperatorResolutionError,
    SelfResolutionError,
    content_sha256,
    item_id_for,
)
from guardrail_engine.escalation.service import item_view
from guardrail_engine.tenant_scope import issue_scope

REVIEWER = who(Role.GUARDRAIL_REVIEWER)
VIEWER = who(Role.VIEWER, subject="vera")
BETA_REVIEWER = who(Role.GUARDRAIL_REVIEWER, tenant=BETA)


async def seed(rig: Rig, n: int, tenant: str = ALPHA, **kw) -> list[EscalationItem]:
    """Items inserted straight into the store (no check needed)."""
    store = rig.items.scoped(issue_scope(tenant))
    out = []
    for i in range(n):
        request_id = f"seed-{tenant}-{i}-{kw.get('tag', '')}"
        item = EscalationItem(
            id=item_id_for(tenant, request_id, "output"),
            tenant_id=tenant,
            request_id=request_id,
            guard_point=kw.get("guard_point", "output"),
            created_at=NOW,
            target="queue",
            reason="policy",
            bundle_version=1,
            rules=(),
            content_sha256=content_sha256(f"text {i}"),
            store_content=kw.get("store_content", "hash_only"),
            content=kw.get("content", f"text {i}"),
            content_truncated=kw.get("truncated", False),
            triggered_by=kw.get("triggered_by"),
        )
        await store.insert(item)
        out.append(item)
    return out


async def golden_examples(rig: Rig, set_id: str, tenant: str = ALPHA):
    store = rig.golden_store.scoped(issue_scope(tenant))
    return await store.examples(tenant, set_id, "output", offset=0, limit=10)


# ----------------------------------------------------------------------------- list and read


async def test_a_list_is_paginated_oldest_first_by_cursor():
    async with Rig() as rig:
        items = await seed(rig, 5)
        first = await rig.list(VIEWER, limit="2")
        second = await rig.list(VIEWER, limit="2", cursor=first.next_cursor)
        third = await rig.list(VIEWER, limit="2", cursor=second.next_cursor)
        seen = [i.id for page in (first, second, third) for i in page.items]
        assert seen == [i.id for i in items]  # every item once, in order
        assert [len(p.items) for p in (first, second, third)] == [2, 2, 1]
        assert third.next_cursor is None


async def test_the_filters_narrow_the_list():
    async with Rig() as rig:
        await rig.publish()
        await rig.escalate(content="one p=0.6")
        await rig.escalate(content="two p=0.6")
        await rig.escalate(content="three p=0.6")
        first = item_of(rig)
        await rig.resolve(REVIEWER, first.id)
        assert len((await rig.list(VIEWER)).items) == 3
        assert [i.id for i in (await rig.list(VIEWER, status="resolved")).items] == [first.id]
        assert len((await rig.list(VIEWER, status="open")).items) == 2
        assert len((await rig.list(VIEWER, guard_point="output")).items) == 3
        assert (await rig.list(VIEWER, guard_point="input")).items == ()
        assert len((await rig.list(VIEWER, rule="t__x")).items) == 3
        assert (await rig.list(VIEWER, rule="t__other")).items == ()
        assert (await rig.list(VIEWER, since="2999-01-01T00:00:00+00:00")).items == ()
        assert (await rig.list(VIEWER, until="2000-01-01T00:00:00")).items == ()
        assert len((await rig.list(VIEWER, since="2000-01-01T00:00:00Z")).items) == 3


async def test_bad_filters_and_cursors_are_refused():
    async with Rig() as rig:
        for field, value in (
            ("status", "pending"),
            ("guard_point", "nowhere"),
            ("limit", "0"),
            ("limit", "201"),
            ("limit", "ten"),
            ("since", "yesterday"),
            ("rule", ""),
        ):
            with pytest.raises(InvalidQueryError):
                await rig.list(VIEWER, **{field: value})
        with pytest.raises(InvalidCursorError):
            await rig.list(VIEWER, cursor="not-a-cursor")


async def test_a_viewer_sees_metadata_and_only_a_reviewer_sees_content_and_the_reason():
    async with Rig() as rig:
        await rig.publish()
        await rig.escalate(content="held text p=0.6")
        item = item_of(rig)
        await rig.resolve(REVIEWER, item.id, reason="the customer asked politely")
        item = await rig.get(VIEWER, item.id)
        as_viewer = item_view(item, reviewer=False, with_content=True)
        as_reviewer = item_view(item, reviewer=True, with_content=True)
        assert "content" not in as_viewer and "resolution_reason" not in as_viewer
        assert as_viewer["content_held"] is True and as_viewer["resolved_by"] == "https://idp/#rita"
        assert as_reviewer["content"] == "held text p=0.6"
        assert as_reviewer["resolution_reason"] == "the customer asked politely"
        # a list never carries content, even for a reviewer
        assert "content" not in item_view(item, reviewer=True)
        # and no probability anywhere in a view
        assert "p=" not in json.dumps({k: v for k, v in as_viewer.items()})


async def test_an_unknown_or_malformed_id_is_not_found():
    async with Rig() as rig:
        for bad in ("esc_" + "0" * 24, "nope", "esc_xyz"):
            with pytest.raises(EscalationNotFoundError):
                await rig.get(VIEWER, bad)
            with pytest.raises(EscalationNotFoundError):
                await rig.resolve(REVIEWER, bad)


# ----------------------------------------------------------------------------- isolation


async def test_tenants_never_see_or_resolve_each_others_items():
    async with Rig() as rig:
        [alpha_item] = await seed(rig, 1, ALPHA)
        [beta_item] = await seed(rig, 1, BETA)
        beta_viewer = who(Role.VIEWER, tenant=BETA)
        assert [i.id for i in (await rig.list(VIEWER)).items] == [alpha_item.id]
        assert [i.id for i in (await rig.list(beta_viewer)).items] == [beta_item.id]
        with pytest.raises(EscalationNotFoundError):
            await rig.get(beta_viewer, alpha_item.id)
        with pytest.raises(EscalationNotFoundError):
            await rig.resolve(BETA_REVIEWER, alpha_item.id)
        assert not (await rig.get(VIEWER, alpha_item.id)).resolved
        # a scope for one tenant refuses the other tenant's id outright
        store = rig.items.scoped(issue_scope(ALPHA))
        from guardrail_engine.store.port import ScopeMismatchError

        with pytest.raises(ScopeMismatchError):
            await store.get(BETA, beta_item.id)


async def test_the_same_request_id_in_two_tenants_is_two_items():
    async with Rig() as rig:
        await rig.env.publish(doc(ALPHA))
        await rig.env.publish(doc(BETA))
        await rig.escalate(ALPHA, request_id="shared")
        await rig.escalate(BETA, request_id="shared")
        assert item_of(rig, ALPHA).id != item_of(rig, BETA).id


# ----------------------------------------------------------------------------- resolve


async def test_a_resolution_records_the_decision_the_reason_and_the_actor():
    async with Rig() as rig:
        [item] = await seed(rig, 1)
        result = await rig.resolve(REVIEWER, item.id, decision="block", reason="phishing")
        done = result.item
        assert (done.status, done.decision, done.resolution_reason) == (
            "resolved",
            "block",
            "phishing",
        )
        assert done.resolved_by == "https://idp/#rita"  # issuer#subject, never from the body
        assert done.resolved_at == NOW


async def test_the_actor_cannot_be_chosen_in_the_body():
    async with Rig() as rig:
        [item] = await seed(rig, 1)
        with pytest.raises(DraftInvalidError):
            await rig.resolve(REVIEWER, item.id, resolved_by="someone-else")


async def test_a_second_resolution_is_refused_and_changes_nothing():
    async with Rig() as rig:
        [item] = await seed(rig, 1)
        await rig.resolve(REVIEWER, item.id, decision="allow")
        other = who(Role.GUARDRAIL_REVIEWER, subject="rob")
        with pytest.raises(AlreadyResolvedError):
            await rig.resolve(other, item.id, decision="block")
        assert (await rig.get(VIEWER, item.id)).decision == "allow"


@pytest.mark.parametrize(
    "body",
    [
        {"decision": "maybe"},
        {"decision": "allow", "reason": ""},
        {"decision": "allow", "reason": "x" * 501},
        {"decision": "allow", "reason": "ok", "promote_content": "yes"},
        {"decision": "allow", "reason": "ok", "extra": 1},
    ],
)
async def test_a_bad_resolution_body_is_refused_with_every_problem(body):
    async with Rig() as rig:
        [item] = await seed(rig, 1)
        d = await rig.decide(REVIEWER, "POST", "/escalations/{id}/resolve")
        with pytest.raises(DraftInvalidError):
            await rig.service.resolve(d, REVIEWER, item.id, json.dumps(body).encode())
        assert not (await rig.get(VIEWER, item.id)).resolved


async def test_the_person_who_triggered_the_item_cannot_resolve_it():
    async with Rig() as rig:
        [item] = await seed(rig, 1, triggered_by="https://idp/#rita")
        with pytest.raises(SelfResolutionError):
            await rig.resolve(REVIEWER, item.id)
        assert not (await rig.get(VIEWER, item.id)).resolved
        colleague = who(Role.GUARDRAIL_REVIEWER, subject="rob")
        assert (await rig.resolve(colleague, item.id)).item.resolved_by == "https://idp/#rob"


async def test_the_engine_records_no_trigger_today_because_the_context_names_no_user():
    async with Rig() as rig:
        await rig.publish()
        await rig.escalate()
        assert item_of(rig).triggered_by is None


# ----------------------------------------------------------------------------- the golden label


async def test_on_hash_only_the_label_is_a_placeholder_that_is_never_sent_or_counted():
    async with Rig() as rig:
        [item] = await seed(rig, 1, store_content="hash_only", content="private words")
        result = await rig.resolve(REVIEWER, item.id, decision="block")
        assert result.label.mode == "hash_only"
        page = await golden_examples(rig, result.label.set_id)
        assert page.items == [] and page.quarantined == 1  # held back: not sendable
        info = await rig.golden_store.scoped(issue_scope(ALPHA)).get(ALPHA, result.label.set_id)
        assert info.name == ESCALATION_SET_PREFIX + item.id
        assert info.counts == {"output": {"block": 1}}
        assert info.quarantined == ((item.id, (HASH_ONLY_VIEW,)),)
        # the row holds the hash, not the words, and no evidence count sees it
        row = rig.golden_store._sets[(ALPHA, info.set_id)][1][0]
        assert row.content == item.content_sha256 and "private" not in row.content
        assert await rig.golden_store.scoped(issue_scope(ALPHA)).label_counts(ALPHA) == {}
        assert result.item.label_set_id == info.set_id and result.item.label_mode == "hash_only"


async def test_on_full_the_label_carries_the_content_and_counts_as_evidence():
    async with Rig() as rig:
        [item] = await seed(rig, 1, store_content="full", content="a fine example")
        result = await rig.resolve(REVIEWER, item.id, decision="allow")
        assert (result.label.mode, result.label.quarantined) == ("content", False)
        page = await golden_examples(rig, result.label.set_id)
        [example] = page.items
        assert (example.label, example.content, example.guard_point) == (
            "allow",
            "a fine example",
            "output",
        )
        counts = await rig.golden_store.scoped(issue_scope(ALPHA)).label_counts(ALPHA)
        assert counts == {"output": {"allow": 1}}


async def test_a_reviewer_can_promote_the_content_on_a_hash_only_tenant():
    async with Rig() as rig:
        [item] = await seed(rig, 1, store_content="hash_only", content="promoted words")
        result = await rig.resolve(REVIEWER, item.id, promote_content=True)
        assert result.label.mode == "content"
        [example] = (await golden_examples(rig, result.label.set_id)).items
        assert example.content == "promoted words"


async def test_a_healthcare_tenant_must_deidentify_before_promoting():
    async with Rig() as rig:
        rig.deid = True
        [item] = await seed(rig, 1, store_content="hash_only", content="Jane Roe, MRN 12345")
        with pytest.raises(DeidentifiedContentRequiredError):
            await rig.resolve(REVIEWER, item.id, promote_content=True)
        assert not (await rig.get(VIEWER, item.id)).resolved  # nothing changed, nothing stored
        assert rig.golden_store._sets == {}
        result = await rig.resolve(
            REVIEWER, item.id, promote_content=True, deidentified_content="[patient], MRN [id]"
        )
        [example] = (await golden_examples(rig, result.label.set_id)).items
        assert example.content == "[patient], MRN [id]"  # the de-identified text, not the held one
        # without promotion a healthcare label is still only a placeholder
        [second] = await seed(rig, 1, tag="b", store_content="hash_only", content="Jane Roe")
        assert (await rig.resolve(REVIEWER, second.id)).label.mode == "hash_only"


async def test_deidentified_content_without_promotion_is_refused():
    async with Rig() as rig:
        [item] = await seed(rig, 1)
        with pytest.raises(DraftInvalidError):
            await rig.resolve(REVIEWER, item.id, deidentified_content="text")
        assert not (await rig.get(VIEWER, item.id)).resolved


async def test_an_item_with_no_usable_content_gets_a_placeholder_even_on_full():
    async with Rig() as rig:
        [cut] = await seed(rig, 1, store_content="full", truncated=True, tag="cut")
        [none] = await seed(rig, 1, store_content="full", content=None, tag="none")
        assert (await rig.resolve(REVIEWER, none.id, promote_content=True)).label.mode == (
            "hash_only"
        )  # nothing held, nothing to promote
        result = await rig.resolve(REVIEWER, cut.id, promote_content=True)
        assert result.label.mode == "hash_only"  # a cut text is never labelled as the example


async def test_the_harm_vocabulary_quarantine_applies_to_a_label_with_content():
    async with Rig() as rig:
        [item] = await seed(rig, 1, store_content="full", content="how to kill a stuck process")
        result = await rig.resolve(REVIEWER, item.id)
        assert (result.label.mode, result.label.quarantined) == ("content", True)
        page = await golden_examples(rig, result.label.set_id)
        assert page.items == [] and page.quarantined == 1  # stored, but never sent
        assert await rig.golden_store.scoped(issue_scope(ALPHA)).label_counts(ALPHA) == {}


async def test_labels_do_not_use_up_the_upload_cap_and_stay_out_of_the_golden_list():
    async with Rig() as rig:
        items = await seed(rig, MAX_SETS + 5, store_content="full")
        for item in items:
            await rig.resolve(REVIEWER, item.id)
        golden_d = await rig.decide(who(Role.GUARDRAIL_REVIEWER), "POST", "/golden-sets", ALPHA)
        body = json.dumps(
            {"name": "mine", "examples": [{"id": "e1", "guard_point": "output", "label": "allow",
                                           "content": "hello"}]}
        ).encode()  # fmt: skip
        await rig.golden.upload(golden_d, REVIEWER, body)  # still allowed
        list_d = await rig.decide(VIEWER, "GET", "/golden-sets")
        assert [i.name for i in await rig.golden.list_sets(list_d)] == ["mine"]
        reserved = json.dumps(
            {"name": "escalation-x", "examples": [{"id": "e1", "guard_point": "output",
                                                    "label": "allow", "content": "hi"}]}
        ).encode()  # fmt: skip
        with pytest.raises(DraftInvalidError):
            await rig.golden.upload(golden_d, REVIEWER, reserved)


async def test_one_item_makes_one_label_set_however_often_it_is_resolved_or_retried():
    async with Rig() as rig:
        [item] = await seed(rig, 1, store_content="full")
        await rig.resolve(REVIEWER, item.id)
        with pytest.raises(AlreadyResolvedError):
            await rig.resolve(REVIEWER, item.id)
        assert len(rig.golden_store._sets) == 1


async def test_a_label_that_failed_is_finished_by_the_same_reviewer_retrying():
    async with Rig() as rig:
        [item] = await seed(rig, 1, store_content="full")
        real = rig.golden.add_escalation_label
        calls = []

        async def flaky(*a, **kw):
            calls.append(1)
            if len(calls) == 1:
                raise RuntimeError("golden store down")
            return await real(*a, **kw)

        rig.golden.add_escalation_label = flaky
        with pytest.raises(RuntimeError):
            await rig.resolve(REVIEWER, item.id, decision="block")
        stuck = await rig.get(VIEWER, item.id)
        assert stuck.resolved and stuck.label_set_id is None  # resolved, label pending
        other = who(Role.GUARDRAIL_REVIEWER, subject="rob")
        with pytest.raises(AlreadyResolvedError):
            await rig.resolve(other, item.id, decision="block")  # not someone else's to finish
        with pytest.raises(AlreadyResolvedError):
            await rig.resolve(REVIEWER, item.id, decision="allow")  # nor a different decision
        done = await rig.resolve(REVIEWER, item.id, decision="block")
        assert done.item.label_set_id is not None and len(rig.golden_store._sets) == 1


# ----------------------------------------------------------------------------- class A audit


async def test_the_resolution_and_the_label_are_audited_with_the_actor_and_no_free_text():
    async with Rig() as rig:
        [item] = await seed(rig, 1, store_content="full", content="clean words")
        result = await rig.resolve(REVIEWER, item.id, decision="allow", reason="secret reason")
        events = await rig.items.scoped(issue_scope(ALPHA)).audit_events(ALPHA)
        assert [e.action for e in events] == ["resolved", "label_created"]
        resolved, labelled = events
        assert resolved.actor == labelled.actor == "https://idp/#rita"
        assert resolved.decision == "allow"
        assert resolved.reason_sha256 == hashlib.sha256(b"secret reason").hexdigest()
        assert "secret reason" not in repr(events)  # the class A trail holds a hash only
        assert (labelled.label_set_id, labelled.label_mode) == (result.label.set_id, "content")
        # the golden set's own class A event records the same actor
        [golden_event] = await rig.golden_store.scoped(issue_scope(ALPHA)).audit_events(ALPHA)
        assert golden_event.actor == "https://idp/#rita"
        assert golden_event.set_id == result.label.set_id


async def test_a_platform_operator_cannot_resolve_a_tenants_item():
    """Decision: operators may not resolve tenant escalations or write tenant labels."""
    async with Rig() as rig:
        [item] = await seed(rig, 1, store_content="full")
        operator = who(Role.GUARDRAIL_REVIEWER, tenant=None, subject="ops")
        operator = replace(operator, platform_operator=True)
        d = await rig.authorizer.authorize(
            operator, "POST", "/v1/tenants/{tid}/guardrails/escalations/{id}/resolve", ALPHA
        )
        assert d.allowed and d.cross_tenant and d.scope.operator
        with pytest.raises(OperatorResolutionError):
            await rig.service.resolve(
                d, operator, item.id, json.dumps({"decision": "allow", "reason": "ok"}).encode()
            )
        # nothing changed: the item is open, no event, no label set
        held = await rig.items.scoped(issue_scope(ALPHA)).get(ALPHA, item.id)
        assert held is not None and not held.resolved
        assert await rig.items.scoped(issue_scope(ALPHA)).audit_events(ALPHA) == []
        assert await rig.golden_store.scoped(issue_scope(ALPHA)).list(ALPHA) == []
