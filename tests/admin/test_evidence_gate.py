"""M2-07 R1: the evidence gate, with an injected clock. Counts of labelled examples per guard
point and 72 hours in shadow, for each enforcing tenant rule."""

import json
from dataclasses import replace
from datetime import timedelta

import pytest
from admin_fixtures import ALPHA, BETA, Admin, bundle, rule, who

from guardrail_engine.admin import DraftInvalidError
from guardrail_engine.admin.evidence import (
    HIGH_SEVERITY,
    NO_PRECISION_GATE,
    SOAK,
    STANDARD,
    EvidenceGate,
)
from guardrail_engine.admin.lifecycle import PublishEvent, rule_snapshots
from guardrail_engine.authz import Role
from guardrail_engine.tenant_scope import issue_scope

BASE = "/v1/tenants/{tid}/guardrails"
ADMIN = who(Role.GUARDRAIL_ADMIN, issuer="https://i/")
REVIEWER = who(Role.GUARDRAIL_REVIEWER, issuer="https://i/")


@pytest.fixture
async def a():
    admin = Admin()
    yield admin
    await admin.aclose()


async def decide(a, method, route, principal=ADMIN, tid=ALPHA):
    return await a.decide(principal, method, BASE + route, tid)


async def save(a, doc, *, if_match=None):
    d = await decide(a, "PUT", "/draft")
    return await a.service.put_draft(d, ADMIN, json.dumps(doc).encode(), if_match)


async def publish(a, mode="enforce", percent=100):
    draft = await a.drafts.scoped(issue_scope(ALPHA)).get(ALPHA)
    d = await decide(a, "POST", "/draft/publish")
    body = json.dumps({"mode": mode, "rollout_percent": percent}).encode()
    return await a.publisher.publish(d, ADMIN, body, draft.etag)


async def upload(a, rows, name="g", tid=ALPHA, principal=REVIEWER):
    body = json.dumps({"name": name, "examples": rows}).encode()
    d = await a.decide(principal, "POST", BASE + "/golden-sets", tid)
    return await a.golden.upload(d, principal, body)


_n = [0]


def examples(block, allow, gp="output", prefix="x"):
    out = []
    for label, n in (("block", block), ("allow", allow)):
        for _ in range(n):
            _n[0] += 1
            out.append({"id": f"{prefix}{_n[0]}", "guard_point": gp, "label": label,
                        "content": f"{prefix} sample number {_n[0]} {label}"})  # fmt: skip
    return out


def snap_event(
    a, rule_id, mode, at, *, version=1, active=True, version_mode="enforce", document=None
):
    """A publish event of ``version`` whose rule ``rule_id`` has rule mode ``mode`` (whatever the
    document says). ``active`` makes it an activation (a first publish); a candidate is
    ``active=False``."""
    document = document or bundle(ALPHA, rules=[rule(rule_id, gps=("output",))])
    rules = tuple(replace(r, mode=mode) for r in rule_snapshots(document))
    return PublishEvent(
        at, "x", ALPHA, "publish", version, mode=version_mode, rules=rules, becomes_active=active
    )


def activation(action, version, at):
    """A promotion or rollback event: the version that became active."""
    return PublishEvent(at, "x", ALPHA, action, version, becomes_active=True)


def doc_with(rule_id="r", **fields):
    """A bundle with one tenant rule; ``fields`` override or add rule fields."""
    return bundle(ALPHA, rules=[{**rule(rule_id, gps=("output",)), **fields}])


async def check(a, document, history=(), now=None):
    gate = EvidenceGate(a.golden_store, NO_PRECISION_GATE)
    return await gate.check(issue_scope(ALPHA), document, list(history), now or a.now)


# ---------------------------------------------------------------------------- label counts


async def test_a_rule_without_enough_examples_fails_the_label_gate_at_each_guard_point(a):
    document = bundle(
        ALPHA, rules=[rule("two_places", gps=("output", "input"))],
    )  # fmt: skip
    await upload(a, examples(4, 10, "output") + examples(5, 15, "input"))
    old = snap_event(a, "two_places", "shadow", a.now - timedelta(hours=100), document=document)
    failures = await check(a, document, [old])
    counts = [f for f in failures if f.gate == "label_counts"]
    assert [(f.rule_id, f.guard_point) for f in counts] == [("two_places", "output")]
    assert "14 labelled examples (4 block, 10 allow)" in counts[0].message
    assert "needs 20 with at least 5 of each" in counts[0].message


@pytest.mark.parametrize(
    ("block", "allow", "ok"),
    [(5, 15, True), (4, 16, False), (15, 5, True), (16, 4, False), (10, 9, False), (10, 10, True)],
)
async def test_the_standard_thresholds_are_20_with_5_each_side(a, block, allow, ok):
    await upload(a, examples(block, allow))
    document = doc_with()
    old = snap_event(a, "r", "shadow", a.now - timedelta(hours=100), document=document)
    failures = [f for f in await check(a, document, [old]) if f.gate == "label_counts"]
    assert (failures == []) is ok
    assert STANDARD == (20, 5)


@pytest.mark.parametrize(
    ("block", "allow", "ok"), [(15, 35, True), (14, 36, False), (25, 24, False)]
)
async def test_a_high_severity_rule_needs_50_with_15_each_side(a, block, allow, ok):
    await upload(a, examples(block, allow))
    document = doc_with(severity="high")
    old = snap_event(a, "r", "shadow", a.now - timedelta(hours=100), document=document)
    failures = [f for f in await check(a, document, [old]) if f.gate == "label_counts"]
    assert (failures == []) is ok
    assert HIGH_SEVERITY == (50, 15)


async def test_examples_are_counted_across_all_the_tenants_sets_without_duplicates(a):
    shared = examples(3, 3)
    await upload(a, shared + examples(2, 8), "one")
    await upload(a, shared + examples(5, 8), "two")  # the 6 shared rows are the same content
    counts = await a.golden_store.scoped(issue_scope(ALPHA)).label_counts(ALPHA)
    assert counts == {"output": {"block": 3 + 2 + 5, "allow": 3 + 8 + 8}}


async def test_content_differing_only_in_case_spacing_or_format_characters_counts_once(a):
    """``x1``, ``X1 `` and ``x\u200b1`` are the same example; a different word isn't."""
    rows = [
        {"id": f"r{i}", "guard_point": "output", "label": "allow", "content": c}
        for i, c in enumerate(["refund policy", "Refund  Policy ", "refund\u200b policy",
                               "refund\tpolicy", "refund policies"])
    ]  # fmt: skip
    await upload(a, rows)
    counts = await a.golden_store.scoped(issue_scope(ALPHA)).label_counts(ALPHA)
    assert counts == {"output": {"allow": 2}}  # "refund policy" once, "refund policies" once
    flip = [{"id": "f", "guard_point": "output", "label": "block", "content": "REFUND POLICY"}]
    await upload(a, flip, "two")  # the same content, labelled the other way: proves nothing
    counts = await a.golden_store.scoped(issue_scope(ALPHA)).label_counts(ALPHA)
    assert counts == {"output": {"allow": 1}}


async def test_quarantined_rows_and_contradictory_content_do_not_count(a):
    rows = examples(5, 15)
    rows.append({"id": "q", "guard_point": "output", "label": "block", "content": "a bomb"})
    both = [
        {"id": "c1", "guard_point": "output", "label": "block", "content": "ambiguous text"},
        {"id": "c2", "guard_point": "output", "label": "allow", "content": "ambiguous text"},
    ]
    await upload(a, rows + both)
    counts = await a.golden_store.scoped(issue_scope(ALPHA)).label_counts(ALPHA)
    assert counts == {"output": {"block": 5, "allow": 15}}  # the quarantined and the clash left out


async def test_another_tenants_examples_are_not_evidence(a):
    beta = who(Role.GUARDRAIL_REVIEWER, tenant=BETA, issuer="https://i/")
    await upload(a, examples(30, 30), tid=BETA, principal=beta)
    counts = await a.golden_store.scoped(issue_scope(ALPHA)).label_counts(ALPHA)
    assert counts == {}


# ---------------------------------------------------------------------------- shadow soak


async def test_a_rule_never_live_in_shadow_fails_the_soak(a):
    await upload(a, examples(10, 10))
    failures = await check(a, doc_with())
    assert [(f.rule_id, f.gate) for f in failures] == [("r", "shadow_soak")]
    assert "not live in the active version" in failures[0].message


@pytest.mark.parametrize(("hours", "ok"), [(0, False), (71.9, False), (72, True), (500, True)])
async def test_the_soak_is_72_hours_by_the_injected_clock(a, hours, ok):
    await upload(a, examples(10, 10))
    document = doc_with()
    since = a.now - timedelta(hours=hours)
    failures = await check(a, document, [snap_event(a, "r", "shadow", since, document=document)])
    assert (failures == []) is ok
    if not ok:
        assert failures[0].gate == "shadow_soak" and "more hours of the 72" in failures[0].message
    assert timedelta(hours=72) == SOAK


async def test_a_shadow_version_with_the_rule_enforcing_does_not_count(a):
    """Only the rule's own mode inside the active version counts."""
    await upload(a, examples(10, 10))
    document = doc_with()  # rule mode is the default, enforce
    event = snap_event(
        a, "r", "enforce", a.now - timedelta(hours=80), version_mode="shadow", document=document
    )
    assert [f.gate for f in await check(a, document, [event])] == ["shadow_soak"]


async def test_a_candidate_never_counts_even_in_shadow_and_even_if_not_abandoned(a):
    await upload(a, examples(10, 10))
    document = doc_with()
    event = snap_event(
        a, "r", "shadow", a.now - timedelta(hours=500), active=False,
        version_mode="shadow", document=document,
    )  # fmt: skip
    assert [f.gate for f in await check(a, document, [event])] == ["shadow_soak"]


async def test_the_soak_runs_across_activations_that_keep_the_rule_and_restarts_otherwise(a):
    await upload(a, examples(10, 10))
    document = doc_with()
    v1 = snap_event(a, "r", "shadow", a.now - timedelta(hours=200), document=document)
    v2 = snap_event(a, "r", "shadow", a.now - timedelta(hours=190), version=2, active=False,
                    document=document)  # fmt: skip
    kept = [v1, v2, activation("promote", 2, a.now - timedelta(hours=100))]
    assert await check(a, document, kept) == []  # live since v1, kept through the promotion
    without = snap_event(a, "other", "enforce", a.now - timedelta(hours=190), version=2,
                         active=False)  # fmt: skip
    dropped = [v1, without, activation("promote", 2, a.now - timedelta(hours=100))]
    assert [f.gate for f in await check(a, document, dropped)] == ["shadow_soak"]
    back = [*dropped, snap_event(a, "r", "shadow", a.now - timedelta(hours=95), version=3,
                                 active=False, document=document),
            activation("promote", 3, a.now - timedelta(hours=10))]  # fmt: skip
    failures = await check(a, document, back)  # removed and re-added: restarts at the promotion
    assert [f.gate for f in failures] == ["shadow_soak"] and "62.0 more hours" in failures[
        0
    ].message
    rollback = [*back, activation("rollback", 1, a.now - timedelta(hours=5))]
    failures = await check(a, document, rollback)  # v1 carries it too: continuous since v3
    assert [f.gate for f in failures] == ["shadow_soak"] and "62.0 more hours" in failures[
        0
    ].message


async def test_editing_the_rule_restarts_the_soak(a):
    await upload(a, examples(10, 10))
    old_text = doc_with(question="Is this the old wording of the question we ask?")
    new_text = doc_with(question="Is this the reworded question that we ask now?")
    long_ago = snap_event(a, "r", "shadow", a.now - timedelta(hours=200), document=old_text)
    assert await check(a, old_text, [long_ago]) == []
    failures = await check(a, new_text, [long_ago])  # same id, new fingerprint
    assert [f.gate for f in failures] == ["shadow_soak"]
    thresholds = doc_with(block_at=0.9, escalate_at=0.4)
    assert [f.gate for f in await check(a, thresholds, [long_ago])] == ["shadow_soak"]
    # a later activation of the *same* wording keeps the start
    again = snap_event(a, "r", "shadow", a.now - timedelta(hours=100), version=2, active=False,
                       document=old_text)  # fmt: skip
    promoted = [long_ago, again, activation("promote", 2, a.now - timedelta(hours=1))]
    assert await check(a, old_text, promoted) == []


async def test_a_template_copy_is_exempt_from_the_soak_but_not_from_the_counts(a):
    document = doc_with(template_unedited=True, origin="template:refunds@1")
    assert [f.gate for f in await check(a, document)] == ["label_counts"]
    await upload(a, examples(10, 10))
    assert await check(a, document) == []


async def test_a_rule_in_shadow_mode_and_a_document_without_rules_are_exempt(a):
    assert await check(a, doc_with(mode="shadow")) == []
    assert await check(a, bundle(ALPHA)) == []


async def test_every_failing_rule_is_listed_together(a):
    document = bundle(ALPHA, rules=[rule("a", gps=("output",)), rule("b", gps=("input",))])
    failures = await check(a, document)
    assert sorted((f.rule_id, f.gate) for f in failures) == [
        ("a", "label_counts"), ("a", "shadow_soak"), ("b", "label_counts"), ("b", "shadow_soak"),
    ]  # fmt: skip


# ---------------------------------------------------------------------------- in the service


async def test_an_enforce_publish_and_a_promotion_are_refused_with_every_failing_rule(a):
    await save(a, bundle(ALPHA))
    await publish(a)  # version 1, no tenant rules: nothing to gate
    await save(a, bundle(ALPHA, rules=[rule("r", gps=("output",))]), if_match="*")
    with pytest.raises(DraftInvalidError) as refused:
        await publish(a, "enforce", 100)
    codes = sorted(e.code for e in refused.value.errors)
    assert codes == ["evidence_gate.label_counts", "evidence_gate.shadow_soak"]
    assert all(e.path == "$.rules[r]" for e in refused.value.errors)
    assert (await a.lifecycle.scoped(issue_scope(ALPHA)).state(ALPHA)).candidate is None


async def test_the_whole_path_shadow_live_soak_then_enforce_with_evidence(a):
    await save(a, bundle(ALPHA))
    await publish(a)  # v1 active
    await upload(a, examples(10, 10))
    shadowed = bundle(ALPHA, rules=[rule("r", gps=("output",), mode="shadow")])
    await save(a, shadowed, if_match="*")
    await publish(a)  # v2: the rule in rule-mode shadow, exempt from the gate, a candidate
    await a.publisher.promote(await decide(a, "POST", "/candidate/promote"), ADMIN)  # live: T0
    await save(a, bundle(ALPHA, rules=[rule("r", gps=("output",))]), if_match="*")
    a.now += timedelta(hours=71)
    with pytest.raises(DraftInvalidError) as early:
        await publish(a)
    assert [e.code for e in early.value.errors] == ["evidence_gate.shadow_soak"]
    a.now += timedelta(hours=1, minutes=1)
    assert (await publish(a)).state == "candidate"  # v3, now enforcing with the evidence
    result = await a.publisher.promote(await decide(a, "POST", "/candidate/promote"), ADMIN)
    assert (result.version, result.state) == (3, "active")


async def test_an_abandoned_shadow_candidate_leaves_no_soak_behind(a):
    """The probe: a 1% shadow candidate dropped at once, then 72 hours."""
    await save(a, bundle(ALPHA))
    await publish(a)  # v1 active
    await upload(a, examples(10, 10))
    await save(a, bundle(ALPHA, rules=[rule("r", gps=("output",))]), if_match="*")
    assert (await publish(a, "shadow", 1)).state == "candidate"
    await a.publisher.abandon(await decide(a, "POST", "/candidate/abandon"), ADMIN)
    a.now += timedelta(hours=72, minutes=1)
    with pytest.raises(DraftInvalidError) as refused:
        await publish(a)
    assert [e.code for e in refused.value.errors] == ["evidence_gate.shadow_soak"]
    assert (await a.lifecycle.scoped(issue_scope(ALPHA)).state(ALPHA)).candidate is None


# ---------------------------------------------------------------------------- the carry-over
# Decided 2026-11-18: a rule that enforces in the active version, as it is, has its soak.


async def test_a_rule_enforcing_in_the_active_version_keeps_its_soak_for_an_unrelated_edit(a):
    """The evidence: v1 soaks the rule in shadow, v2 enforces it and is promoted; a later
    enforce publish that keeps the rule as it is must not ask for 72 hours in shadow again."""
    await upload(a, examples(10, 10))
    document = doc_with()
    v1 = snap_event(a, "r", "shadow", a.now - timedelta(hours=200), document=document)
    v2 = snap_event(a, "r", "enforce", a.now - timedelta(hours=100), version=2, active=False,
                    document=document)  # fmt: skip
    history = [v1, v2, activation("promote", 2, a.now - timedelta(hours=90))]
    assert await check(a, document, history) == []  # live since v1's shadow start, carried on


async def test_a_chain_of_three_versions_keeps_the_soak_from_the_first_shadow_start(a):
    await upload(a, examples(10, 10))
    document = doc_with()
    shadow_start = a.now - timedelta(hours=300)
    history = [snap_event(a, "r", "shadow", shadow_start, document=document)]
    for version, hours_ago in ((2, 200), (3, 100), (4, 1)):
        history.append(
            snap_event(a, "r", "enforce", a.now - timedelta(hours=hours_ago + 5), version=version,
                       active=False, document=document)
        )  # fmt: skip
        history.append(activation("promote", version, a.now - timedelta(hours=hours_ago)))
        assert await check(a, document, history) == [], f"after v{version}"
    # the start is still the first shadow start, not the last activation an hour ago
    from guardrail_engine.admin.evidence import _live_shadow_since

    (since,) = _live_shadow_since(history).values()
    assert since == shadow_start


async def test_a_rule_that_enforces_with_no_shadow_history_has_its_soak_from_its_activation(a):
    """Counted from when that version activated: an hour of enforcing is an hour of soak."""
    await upload(a, examples(10, 10))
    document = doc_with()
    only = [snap_event(a, "r", "enforce", a.now - timedelta(hours=10), document=document)]
    failures = await check(a, document, only)
    assert [f.gate for f in failures] == ["shadow_soak"] and "62.0 more hours" in failures[
        0
    ].message
    old = [snap_event(a, "r", "enforce", a.now - timedelta(hours=80), document=document)]
    assert await check(a, document, old) == []


async def test_changing_a_rule_that_enforces_still_restarts_the_soak(a):
    await upload(a, examples(10, 10))
    document = doc_with()
    history = [
        snap_event(a, "r", "shadow", a.now - timedelta(hours=300), document=document),
        snap_event(a, "r", "enforce", a.now - timedelta(hours=205), version=2, active=False,
                   document=document),
        activation("promote", 2, a.now - timedelta(hours=200)),
    ]  # fmt: skip
    for changed in (
        doc_with(block_at=0.9, escalate_at=0.4),
        doc_with(question="Is this the reworded question that we ask now?"),
    ):
        assert [f.gate for f in await check(a, changed, history)] == ["shadow_soak"]
    # an edit to something else in the bundle is not a change of the rule
    other = {**document, "escalation": {"target": "queue"}}
    assert await check(a, other, history) == []


async def test_a_candidate_that_enforces_is_not_live_and_a_promotion_makes_it_so(a):
    await upload(a, examples(10, 10))
    document = doc_with()
    candidate = snap_event(a, "r", "enforce", a.now - timedelta(hours=100), active=False,
                           version_mode="shadow", document=document)  # fmt: skip
    assert [f.gate for f in await check(a, document, [candidate])] == ["shadow_soak"]
    promoted = [candidate, activation("promote", 1, a.now - timedelta(hours=90))]
    assert await check(a, document, promoted) == []  # promotion makes it decide all traffic


async def test_an_enforcing_rule_is_not_live_after_a_version_without_it_activates(a):
    await upload(a, examples(10, 10))
    document = doc_with()
    history = [
        snap_event(a, "r", "enforce", a.now - timedelta(hours=300), document=document),
        snap_event(a, "other", "enforce", a.now - timedelta(hours=200), version=2, active=False),
        activation("promote", 2, a.now - timedelta(hours=100)),
    ]  # v2 doesn't carry r: its soak ended
    assert [f.gate for f in await check(a, document, history)] == ["shadow_soak"]


async def test_through_the_publisher_an_unrelated_edit_after_the_rule_enforces_publishes(a):
    """The reproduction of the failure, on the real publisher with the injected clock."""
    scope = issue_scope(ALPHA)

    async def current():
        return await a.drafts.scoped(scope).get(ALPHA)

    async def publish_draft():
        d = await decide(a, "POST", "/draft/publish")
        body = b'{"mode": "enforce", "rollout_percent": 100}'
        return await a.publisher.publish(d, ADMIN, body, (await current()).etag)

    await upload(a, examples(10, 10))
    await save(a, bundle(ALPHA, rules=[rule("r", gps=("output",), mode="shadow")]))
    await publish_draft()  # v1: the rule in shadow, active
    a.now += timedelta(hours=80)
    doc = json.loads((await current()).document)
    doc["rules"][0]["mode"] = "enforce"
    await save(a, doc, if_match=(await current()).etag)
    await publish_draft()  # v2: candidate, enforcing
    await a.publisher.promote(await decide(a, "POST", "/candidate/promote"), ADMIN)
    doc = json.loads((await current()).document)
    doc["escalation"] = {"target": "queue"}  # unrelated to the rule
    await save(a, doc, if_match=(await current()).etag)
    assert (await publish_draft()).state == "candidate"  # before: refused by the soak
