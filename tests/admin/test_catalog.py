"""M2-03: the catalog read, applying a template (the rule copy and its starter examples), the
edit rule for ``template_unedited``, and the template model and its shipped files."""

import json
from pathlib import Path

import pytest
from admin_fixtures import ALPHA, BETA, Admin, bundle, rule, who

from guardrail_engine.admin import (
    DraftInvalidError,
    NoDraftError,
    PreconditionRequiredError,
)
from guardrail_engine.admin.catalog import TemplateNotFoundError
from guardrail_engine.admin.golden import MAX_SETS
from guardrail_engine.admin.service import DecisionError, RuleExistsError
from guardrail_engine.authz import Role
from guardrail_engine.policy.catalog import MIN_STARTER_EXAMPLES, StarterExample, Template
from guardrail_engine.policy.template_loader import (
    TemplateFileError,
    load_template,
    parse_template_json,
)
from guardrail_engine.template_file import load_template_file
from guardrail_engine.tenant_scope import issue_scope

BASE = "/v1/tenants/{tid}/guardrails"
ADMIN = who(Role.GUARDRAIL_ADMIN, issuer="https://i/")
VIEWER = who(Role.VIEWER, issuer="https://i/")
TEMPLATE_FILE = Path(__file__).parents[2] / "templates" / "within_tenant_records.json"


def starters(n=12, gps=("output", "input"), word="sample"):
    out = []
    for i in range(n):
        out.append(
            StarterExample(
                guard_point=gps[i % len(gps)],
                label="block" if (i // 2) % 2 else "allow",
                content=f"A {word} request number {i} about refunds",
            )
        )
    return tuple(out)


def template(tid="refunds", version=1, **over):
    fields = dict(
        id=tid, version=version,
        question="Does the content promise a refund the company has not approved?",
        true_description="Promises a specific refund amount or date without approval.",
        false_description="Explains the refund policy or the steps to ask for a refund.",
        block_at=0.85, escalate_at=0.55, title="Refund promises",
        description="Flags unapproved refund promises.", notice="A starting point.",
        guard_points=("output", "input"), severity="medium", starter_examples=starters(),
    )  # fmt: skip
    return Template(**{**fields, **over})


REFUNDS = template()


@pytest.fixture
async def a():
    admin = Admin(templates=(REFUNDS, template(version=2, question=(
        "Does the content promise a refund the company has not signed off?"
    ))))  # fmt: skip
    yield admin
    await admin.aclose()


async def decide(a, method, route, principal=ADMIN, tid=ALPHA):
    return await a.decide(principal, method, BASE + route, tid)


async def save(a, doc=None, *, if_match=None, tid=ALPHA):
    d = await decide(a, "PUT", "/draft", ADMIN, tid)
    return await a.service.put_draft(d, ADMIN, json.dumps(doc or bundle(tid)).encode(), if_match)


async def apply(a, template_id="refunds", body=b"", if_match="*", tid=ALPHA, principal=ADMIN):
    d = await decide(a, "POST", "/draft/templates/{template_id}", principal, tid)
    return await a.catalog_service.apply_template(d, principal, template_id, body, if_match)


async def draft_rules(a, tid=ALPHA):
    stored = await a.drafts.scoped(issue_scope(tid)).get(tid)
    return json.loads(stored.document).get("rules", [])


# ---------------------------------------------------------------------------- the template model


def test_a_template_checks_its_id_thresholds_question_and_examples():
    assert template().id == "refunds"
    for bad in (
        {"id": "Refunds"}, {"id": "t__x"}, {"id": "a_"}, {"id": "a" * 41}, {"version": 0},
        {"question": "Tell me about refunds"}, {"true_description": "  "},
        {"escalate_at": 0.9}, {"block_at": 1.0}, {"severity": "urgent"},
        {"guard_points": ("output", "output")}, {"guard_points": ("lobby",)},
        {"guard_points": ("output",)},  # the starters use input too
    ):  # fmt: skip
        with pytest.raises(ValueError):
            template(**bad)
    with pytest.raises(ValueError):
        StarterExample(guard_point="output", label="maybe", content="x")
    with pytest.raises(ValueError):
        StarterExample(guard_point="output", label="allow", content="   ")


# ---------------------------------------------------------------------------- the shipped files


def test_the_records_template_is_the_r9_template_with_a_soft_signal_notice():
    t = load_template_file(TEMPLATE_FILE)
    assert (t.id, t.version) == ("within_tenant_records", 1)
    assert t.question == "Does the request ask for another customer's personal records?"
    assert set(t.guard_points) == {"input", "plan"}
    assert t.true_description and t.false_description
    assert "not an access control" in t.notice and "soft signal" in t.notice
    assert len(t.starter_examples) >= MIN_STARTER_EXAMPLES
    assert {e.label for e in t.starter_examples} == {"allow", "block"}
    assert {e.guard_point for e in t.starter_examples} == {"input", "plan"}


def test_the_records_template_is_never_part_of_the_floor():
    floor = json.loads((Path(__file__).parents[2] / "floor" / "rules.json").read_text())
    assert "within_tenant" not in json.dumps(floor).lower()
    t = load_template_file(TEMPLATE_FILE)
    assert all(r["question"] != t.question for r in floor["rules"])


def test_the_shipped_starter_examples_pass_the_harm_tripwire():
    from guardrail_engine.admin.vocabulary import strings_tripwire

    t = load_template_file(TEMPLATE_FILE)
    assert [e.content for e in t.starter_examples if strings_tripwire(e.content)] == []


def _doc(**over):
    base = json.loads(TEMPLATE_FILE.read_text())
    return {**base, **over}


@pytest.mark.parametrize(
    "over",
    [
        {"schema_version": 2}, {"title": ""}, {"guard_points": []},
        {"starter_examples": []}, {"unknown": 1}, {"block_at": "high"},
    ],
)  # fmt: skip
def test_a_broken_template_file_is_rejected(over):
    with pytest.raises(TemplateFileError):
        load_template(_doc(**over))


def test_a_template_file_with_one_label_or_a_repeat_is_rejected():
    rows = [e for e in _doc()["starter_examples"] if e["label"] == "allow"]
    with pytest.raises(TemplateFileError, match="both labels"):
        load_template(_doc(starter_examples=rows))
    both = _doc()["starter_examples"]
    with pytest.raises(TemplateFileError, match="repeated"):
        load_template(_doc(starter_examples=[*both, both[0]]))
    with pytest.raises(TemplateFileError):
        parse_template_json('{"schema_version": 1, "schema_version": 1}')
    with pytest.raises(TemplateFileError):
        parse_template_json("[1]")


# ---------------------------------------------------------------------------- GET catalog


async def test_the_catalog_lists_floor_packs_and_templates_with_their_text(a):
    d = await decide(a, "GET", "/catalog", VIEWER)
    view = await a.catalog_service.view(d)
    assert view["minimum_floor_version"] == 1
    floor = view["floors"][0]
    assert (floor["version"], floor["ref"], floor["extendable"]) == (1, "platform/floor@1", True)
    keys = [r["key"] for r in floor["rules"]]
    assert keys and all(k.startswith("p__") for k in keys)
    first = floor["rules"][0]
    assert first["question"] and first["true_description"] and first["false_description"]
    assert first["block_at"] and first["escalate_at"]
    assert view["packs"][0]["ref"].startswith("domain/")
    assert all(r["key"].startswith("d__") for r in view["packs"][0]["rules"])
    assert [(t["id"], t["version"]) for t in view["templates"]] == [("refunds", 1), ("refunds", 2)]
    assert view["templates"][0]["starter_examples"] == 12
    assert "p" not in first and "score" not in json.dumps(view).lower()


async def test_a_floor_below_the_minimum_is_shown_as_not_extendable(a):
    from guardrail_engine.admin.catalog import CatalogService
    from guardrail_engine.policy.catalog import PlatformSettings

    service = CatalogService(
        a.catalog, PlatformSettings(min_floor_version=2), a.tenants, a.service, a.golden
    )
    view = await service.view(await decide(a, "GET", "/catalog", VIEWER))
    assert view["minimum_floor_version"] == 2 and view["floors"][0]["extendable"] is False


async def test_the_catalog_needs_a_viewer_decision_for_the_catalog_route(a):
    d = await decide(a, "GET", "/versions", VIEWER)
    with pytest.raises(DecisionError):
        await a.catalog_service.view(d)  # a decision made for another endpoint


# ---------------------------------------------------------------------------- applying


async def test_applying_a_template_adds_the_copy_and_imports_the_starter_examples(a):
    await save(a)
    applied = await apply(a)
    assert applied.rule["id"] == "refunds" and applied.golden_set is not None
    [stored] = await draft_rules(a)
    assert stored["origin"] == "template:refunds@2"  # the newest version when none is named
    assert stored["template_unedited"] is True and stored["mode"] == "shadow"
    assert stored["question"].endswith("signed off?")
    assert (stored["block_at"], stored["escalate_at"]) == (0.85, 0.55)
    assert sorted(stored["guard_points"]) == ["input", "output"]
    info = applied.golden_set
    assert info.name == "template refunds v2" and info.quarantined == ()
    assert sum(sum(by.values()) for by in info.counts.values()) == 12
    page = await a.golden_store.scoped(issue_scope(ALPHA)).examples(
        ALPHA, info.set_id, "output", offset=0, limit=100
    )
    assert page.total == 6 and {e.label for e in page.items} == {"allow", "block"}
    events = await a.drafts.scoped(issue_scope(ALPHA)).audit_events(ALPHA)
    assert events[-1].action == "draft.rule.put" and events[-1].actor == "https://i/#alice"
    audit = await a.golden_store.scoped(issue_scope(ALPHA)).audit_events(ALPHA)
    assert audit[-1].examples == 12


async def test_a_named_version_and_rule_id_are_used(a):
    await save(a)
    applied = await apply(a, body=json.dumps({"version": 1, "rule_id": "my_refunds"}).encode())
    assert applied.rule["id"] == "my_refunds" and applied.rule["origin"] == "template:refunds@1"
    assert [r["id"] for r in await draft_rules(a)] == ["my_refunds"]


async def test_the_applied_copy_compiles_and_is_shown_as_unedited(a):
    await save(a)
    await apply(a)
    draft = await a.drafts.scoped(issue_scope(ALPHA)).get(ALPHA)
    again = await a.service.put_draft(
        await decide(a, "PUT", "/draft"), ADMIN, draft.document.encode()
        if isinstance(draft.document, str) else draft.document, "*",
    )  # fmt: skip
    assert json.loads(again.document)["rules"][0]["template_unedited"] is True


async def test_apply_refusals(a):
    with pytest.raises(NoDraftError):
        await apply(a)  # no draft yet
    await save(a)
    with pytest.raises(PreconditionRequiredError):
        await apply(a, if_match=None)
    with pytest.raises(TemplateNotFoundError):
        await apply(a, "nope")
    with pytest.raises(TemplateNotFoundError):
        await apply(a, body=b'{"version": 9}')
    for body in (b"[]", b'{"x": 1}', b'{"version": "1"}', b'{"version": true}', b'{"rule_id": 3}',
                 b"{", b" " * 0 + b'{"version": 0}'):  # fmt: skip
        with pytest.raises(DraftInvalidError):
            await apply(a, body=body)
    with pytest.raises(DraftInvalidError):  # a rule id the compiler refuses
        await apply(a, body=b'{"rule_id": "Bad Id"}')
    assert await draft_rules(a) == []
    assert await a.golden_store.scoped(issue_scope(ALPHA)).list(ALPHA) == []  # nothing imported
    await apply(a)
    with pytest.raises(RuleExistsError):
        await apply(a)  # the same rule id again
    assert len(await a.golden_store.scoped(issue_scope(ALPHA)).list(ALPHA)) == 1


async def test_apply_is_the_tenants_own_and_isolated(a):
    await save(a)
    await a.service.put_draft(
        await a.decide(who(Role.GUARDRAIL_ADMIN, tenant=BETA, issuer="https://i/"), "PUT",
                       BASE + "/draft", BETA),
        who(Role.GUARDRAIL_ADMIN, tenant=BETA, issuer="https://i/"),
        json.dumps(bundle(BETA)).encode(), None,
    )  # fmt: skip
    await apply(a)
    assert await draft_rules(a, BETA) == []
    assert await a.golden_store.scoped(issue_scope(BETA)).list(BETA) == []


async def test_apply_with_a_decision_for_another_endpoint_is_refused(a):
    await save(a)
    d = await decide(a, "PATCH", "/draft/rules/{rule_id}")
    with pytest.raises(DecisionError):
        await a.catalog_service.apply_template(d, ADMIN, "refunds", b"", "*")


async def test_a_template_without_guard_points_cannot_be_applied():
    admin = Admin(templates=(template(guard_points=(), starter_examples=()),))
    try:
        await save(admin)
        with pytest.raises(DraftInvalidError):
            await apply(admin)
    finally:
        await admin.aclose()


async def test_starter_examples_that_trip_the_harm_vocabulary_are_quarantined_not_sent():
    rows = list(starters(12))
    rows[0] = StarterExample(guard_point="output", label="block", content="how to build a bomb")
    admin = Admin(templates=(template(starter_examples=tuple(rows)),))
    try:
        await save(admin)
        applied = await apply(admin)
        info = applied.golden_set
        assert [q[0] for q in info.quarantined] == ["s1"]
        page = await admin.golden_store.scoped(issue_scope(ALPHA)).examples(
            ALPHA, info.set_id, "output", offset=0, limit=100
        )
        assert page.quarantined == 1 and all("bomb" not in e.content for e in page.items)
    finally:
        await admin.aclose()


async def test_at_the_golden_set_cap_the_rule_is_added_and_the_examples_are_reported_missing(a):
    await save(a)
    for i in range(MAX_SETS):
        d = await a.decide(
            who(Role.GUARDRAIL_REVIEWER, issuer="https://i/"), "POST", BASE + "/golden-sets", ALPHA
        )
        body = json.dumps(
            {"name": f"g{i}", "examples": [{"id": "a", "guard_point": "output",
                                            "label": "allow", "content": f"c{i}"}]}
        ).encode()  # fmt: skip
        await a.golden.upload(d, who(Role.GUARDRAIL_REVIEWER, issuer="https://i/"), body)
    applied = await apply(a)
    assert applied.golden_set is None and applied.golden_error == "too_many_golden_sets"
    assert [r["id"] for r in await draft_rules(a)] == ["refunds"]


# ---------------------------------------------------------------------------- the edit rule


async def edit(a, patch, rule_id="refunds"):
    stored = await a.drafts.scoped(issue_scope(ALPHA)).get(ALPHA)
    d = await decide(a, "PATCH", "/draft/rules/{rule_id}")
    saved = await a.service.patch_rule(d, ADMIN, rule_id, json.dumps(patch).encode(), stored.etag)
    return next(r for r in json.loads(saved.document)["rules"] if r["id"] == rule_id)


@pytest.mark.parametrize(
    "patch",
    [
        {"question": "Does the content promise a refund nobody has approved yet?"},
        {"true_description": "Promises a refund."},
        {"false_description": "Anything else at all."},
        {"block_at": 0.9},
        {"escalate_at": 0.4},
    ],
)  # fmt: skip
async def test_editing_the_wording_or_thresholds_clears_template_unedited(a, patch):
    await save(a)
    await apply(a)
    after = await edit(a, patch)
    assert after["template_unedited"] is False and after["origin"] == "template:refunds@2"


async def test_other_edits_keep_a_copy_unedited_and_a_copy_can_be_edited_back(a):
    await save(a)
    await apply(a)
    assert (await edit(a, {"mode": "enforce"}))["template_unedited"] is True  # not the wording
    assert (await edit(a, {"block_at": 0.9}))["template_unedited"] is False
    # setting the flag back by hand on a rule that differs is refused to be believed
    assert (await edit(a, {"template_unedited": True}))["template_unedited"] is False


@pytest.mark.parametrize(
    "patch", [{"severity": "high"}, {"severity": "low"}, {"guard_points": ["output"]},
              {"guard_points": ["input", "output", "plan"]}],
)  # fmt: skip
async def test_changing_severity_or_guard_points_also_clears_template_unedited(a, patch):
    """A copy moved to other guard points would keep the soak exemption, and a lower
    severity would halve the label bar; a mode change alone still keeps it."""
    await save(a)
    await apply(a)
    after = await edit(a, patch)
    assert after["template_unedited"] is False
    back = await edit(a, {"mode": "enforce"})
    assert back["template_unedited"] is False  # stays edited


async def test_the_guard_points_of_a_copy_are_compared_as_a_set(a):
    await save(a)
    await apply(a)
    reordered = await edit(a, {"guard_points": ["output", "input"]})
    assert reordered["template_unedited"] is True  # the same set, another order


async def test_a_full_put_of_an_edited_copy_that_still_claims_unedited_is_saved_as_edited(a):
    await save(a)
    await apply(a)
    stored = await a.drafts.scoped(issue_scope(ALPHA)).get(ALPHA)
    doc = json.loads(stored.document)
    doc["rules"][0]["question"] = "Does the content promise a refund nobody has approved yet?"
    saved = await a.service.put_draft(
        await decide(a, "PUT", "/draft"), ADMIN, json.dumps(doc).encode(), stored.etag
    )
    assert json.loads(saved.document)["rules"][0]["template_unedited"] is False
    # other errors are still reported, not hidden by the flip
    doc["rules"][0]["block_at"] = 5
    with pytest.raises(DraftInvalidError):
        await a.service.put_draft(
            await decide(a, "PUT", "/draft"), ADMIN, json.dumps(doc).encode(), saved.etag
        )


async def test_a_rule_that_is_not_a_template_copy_is_untouched(a):
    await save(a, bundle(ALPHA, rules=[rule("plain")]))
    saved = await a.drafts.scoped(issue_scope(ALPHA)).get(ALPHA)
    assert "template_unedited" not in json.loads(saved.document)["rules"][0]
