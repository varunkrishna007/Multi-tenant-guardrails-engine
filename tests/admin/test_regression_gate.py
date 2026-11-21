"""M4-02, AC-A3: the regression gate. A version that enforces may not lose more golden-set recall
than the tenant's tolerance against the active one, per tenant rule, computed from stored
scores at each version's thresholds. The model is the fake one: a rule's probability for an
example is read from the example's text (``p=0.93``), so every number is known."""

import json
import re
from datetime import timedelta

import pytest
from admin_fixtures import ALPHA, Admin, bundle, rule, who

from guardrail_engine.admin import DraftInvalidError
from guardrail_engine.admin.evidence import NO_PRECISION_GATE
from guardrail_engine.authz import Role
from guardrail_engine.tenant_scope import issue_scope

BASE = "/v1/tenants/{tid}/guardrails"
ADMIN = who(Role.GUARDRAIL_ADMIN, issuer="https://i/")
REVIEWER = who(Role.GUARDRAIL_REVIEWER, issuer="https://i/")
KEY = "t__refunds"
P = re.compile(r"p=([0-9.]+)")
POSITIVES = (0.5, 0.6, 0.7, 0.8, 0.9, 0.95)  # six positives: each is 16.67 points of recall
NEGATIVES = (0.05, 0.1, 0.2, 0.3, 0.4, 0.55)


@pytest.fixture
async def a():
    admin = Admin(regression_gate=True)
    admin.fake.responder = lambda text, key, q: (
        float(P.search(text).group(1)) if key == KEY and P.search(text) else None
    )
    yield admin
    await admin.aclose()


def ex(i, label, p):
    return {
        "id": f"e{i}",
        "guard_point": "output",
        "label": label,
        "content": f"case {i:03d} p={p}",
    }


def known_set():
    rows = [ex(i, "block", p) for i, p in enumerate(POSITIVES)]
    return rows + [ex(10 + i, "allow", p) for i, p in enumerate(NEGATIVES)]


async def decide(a, method, route, principal=ADMIN, tid=ALPHA):
    return await a.decide(principal, method, BASE + route, tid)


async def save(a, doc, *, if_match=None):
    d = await decide(a, "PUT", "/draft")
    return await a.service.put_draft(d, ADMIN, json.dumps(doc).encode(), if_match)


async def upload(a, rows, name="g"):
    d = await decide(a, "POST", "/golden-sets", REVIEWER)
    return await a.golden.upload(d, REVIEWER, json.dumps({"name": name, "examples": rows}).encode())


async def calibrate(a, version=None):
    body = {"guard_point": "output", **({} if version is None else {"version": version})}
    d = await decide(a, "POST", "/draft/calibrate", REVIEWER)
    return await a.calibration.calibrate(d, json.dumps(body).encode())


async def scored(a, doc):
    """Save ``doc`` as the draft, upload the known set and score it."""
    await save(a, doc)
    await upload(a, known_set())
    return await calibrate(a)


def doc_with(**thresholds):
    return bundle(ALPHA, rules=[rule("refunds", **thresholds)])


async def regress(a, new, old, version=3):
    return await a.calibration.regression_gate(issue_scope(ALPHA), new, version, old)


# ------------------------------------------------------------------ the comparison


async def test_the_first_publish_has_nothing_to_compare_and_its_record_says_so(a):
    failures, record = await regress(a, doc_with(), None, None)
    assert (
        failures == [] and record == "regression gate: first publish, no active version to compare"
    )


async def test_a_version_that_keeps_the_recall_passes_and_the_record_names_both_numbers(a):
    old = doc_with(block_at=0.8, escalate_at=0.5)
    await scored(a, old)
    failures, record = await regress(a, doc_with(block_at=0.9, escalate_at=0.5), old)
    assert failures == []
    assert record == "regression gate: tolerance 2 pt vs v3; refunds 1.00->1.00 n=12 pos=6 neg=6"


async def test_a_version_that_loses_more_than_the_tolerance_is_refused_with_both_recalls(a):
    old = doc_with(block_at=0.8, escalate_at=0.5)
    await scored(a, old)
    # escalate_at 0.7: 0.5 and 0.6 are no longer acted on: 4 of 6 positives instead of 6 of 6
    failures, record = await regress(a, doc_with(block_at=0.9, escalate_at=0.7), old)
    (f,) = failures
    assert f.rule_id == "refunds" and f.code == "evidence_gate.regression"
    assert "recall fell 33.3 points, over the tolerance of 2" in f.message
    assert "1.000 on the active version v3 (acting at p >= 0.5)" in f.message
    assert "0.667 on this one (p >= 0.7)" in f.message and "over 6 golden positives" in f.message
    assert record == "regression gate: tolerance 2 pt vs v3; no rule compared"


async def test_a_fall_exactly_at_the_tolerance_passes_and_one_over_it_does_not(a):
    old = doc_with(block_at=0.8, escalate_at=0.5)
    await scored(a, old)
    new = doc_with(block_at=0.9, escalate_at=0.6)  # 5 of 6: a fall of 16.67 points
    d = await decide(a, "PUT", "/calibration/targets")
    await a.calibration.set_targets(d, ADMIN, b'{"recall_tolerance": 17}')
    assert (await regress(a, new, old))[0] == []
    d = await decide(a, "PUT", "/calibration/targets")
    await a.calibration.set_targets(d, ADMIN, b'{"recall_tolerance": 16.5}')
    (f,) = (await regress(a, new, old))[0]
    assert "fell 16.7 points, over the tolerance of 16.5" in f.message
    d = await decide(a, "PUT", "/calibration/targets")
    await a.calibration.set_targets(d, ADMIN, b'{"recall_tolerance": 0}')
    same = doc_with(block_at=0.95, escalate_at=0.5)  # no loss passes even at zero tolerance
    assert (await regress(a, same, old))[0] == []


async def test_raising_recall_is_never_a_regression(a):
    old = doc_with(block_at=0.8, escalate_at=0.7)
    await scored(a, old)
    failures, record = await regress(a, doc_with(block_at=0.9, escalate_at=0.5), old)
    assert failures == [] and "refunds 0.67->1.00" in record


async def test_a_rule_that_was_not_enforcing_before_or_is_not_now_is_not_compared(a):
    old = doc_with(block_at=0.8, escalate_at=0.5)
    await scored(a, old)
    # shadow now; new rule; shadow before; floor-derived
    cases = [
        (doc_with(block_at=0.95, escalate_at=0.9, mode="shadow"), old),
        (bundle(ALPHA, rules=[rule("other", block_at=0.95, escalate_at=0.9)]), old),
        (doc_with(block_at=0.95, escalate_at=0.9), doc_with(mode="shadow")),
        (
            bundle(
                ALPHA,
                rules=[
                    {
                        **rule("refunds", block_at=0.95, escalate_at=0.9),
                        "origin": "fork:p__inj_direct",
                    }
                ],
            ),
            bundle(ALPHA, rules=[{**rule("refunds"), "origin": "fork:p__inj_direct"}]),
        ),
    ]
    for new, before in cases:
        failures, record = await regress(a, new, before)
        assert failures == [] and record.endswith("no rule compared")


async def test_unscored_examples_fail_closed_and_say_which_version_and_what_to_run(a):
    old = doc_with(block_at=0.8, escalate_at=0.5)
    await save(a, old)
    await upload(a, known_set())  # nothing scored yet
    failures, _ = await regress(a, doc_with(escalate_at=0.5), old)
    (f,) = failures
    assert f.rule_id == "refunds" and f.code == "evidence_gate.regression"
    assert (
        'under the active version v3\'s wording: POST /draft/calibrate with "version": 3'
        in f.message
    )
    assert "under this draft's wording: POST /draft/calibrate" in f.message
    assert f.message.startswith("recall can't be compared")


async def test_a_reworded_active_rule_needs_its_own_scores_and_calibrate_version_gets_them():
    """The active version asks another question than the draft: its scores are under another
    identity, so the gate says so, and POST /draft/calibrate with its version scores it."""
    big = [ex(i, "block", 0.9) for i in range(25)] + [ex(100 + i, "allow", 0.1) for i in range(25)]
    big = [{**r, "content": f"{r['content']} #{r['id']}"} for r in big]
    admin = Admin(regression_gate=True)  # the precision gate is off: v2 needs no scores
    admin.fake.responder = lambda text, key, q: (
        float(P.search(text).group(1)) if key == KEY and P.search(text) else None
    )
    scope = issue_scope(ALPHA)

    async def current():
        return await admin.drafts.scoped(scope).get(ALPHA)

    async def publish_draft():
        d = await decide(admin, "POST", "/draft/publish")
        return await admin.publisher.publish(
            d, ADMIN, b'{"mode": "enforce", "rollout_percent": 100}', (await current()).etag
        )

    try:
        await save(admin, bundle(ALPHA, rules=[rule("refunds", mode="shadow")]))
        await upload(admin, big)
        await publish_draft()  # v1: shadow, active
        admin.now += timedelta(hours=80)
        doc = json.loads((await current()).document)
        doc["rules"][0]["mode"] = "enforce"
        await save(admin, doc, if_match=(await current()).etag)
        v2 = await publish_draft()  # candidate
        await admin.publisher.promote(await decide(admin, "POST", "/candidate/promote"), ADMIN)
        # the draft re-words the rule (a new question) and is scored, under its own identity
        doc = json.loads((await current()).document)
        doc["rules"][0]["question"] = "Does the content discuss refunds in any way at all?"
        await save(admin, doc, if_match=(await current()).etag)
        await calibrate(admin)
        with pytest.raises(DraftInvalidError) as refused:
            await publish_draft()
        (error,) = [e for e in refused.value.errors if e.code == "evidence_gate.regression"]
        assert f'"version": {v2.version}' in error.message
        assert "50 golden examples have no stored score under the active version" in error.message
        assert "under this draft" not in error.message  # the draft is scored
        # score the active version's own document, and the comparison can be made
        report = await calibrate(admin, version=v2.version)
        assert (report.version, report.scored_now, report.unscored_remaining) == (v2.version, 50, 0)
        active = await admin.lifecycle.scoped(scope).document(ALPHA, v2.version)
        drafted = json.loads((await current()).document)
        failures, record = await admin.calibration.regression_gate(
            scope, {**drafted, "version": 3}, v2.version, active
        )
        assert failures == [] and "refunds 1.00->1.00" in record  # recall is the same: passes
    finally:
        await admin.aclose()


async def test_calibrate_with_a_version_refuses_one_the_tenant_does_not_have(a):
    await save(a, doc_with())
    await upload(a, known_set())
    with pytest.raises(DraftInvalidError) as e:
        await calibrate(a, version=7)
    assert e.value.errors[0].code == "calibrate.version"
    d = await decide(a, "POST", "/draft/calibrate", REVIEWER)
    for bad in (0, -1, "2", True, 1.5):
        with pytest.raises(DraftInvalidError):
            await a.calibration.calibrate(
                d, json.dumps({"guard_point": "output", "version": bad}).encode()
            )


# ------------------------------------------------------------------ the tolerance setting


@pytest.mark.parametrize("value", [-1, 20.5, 25, 0.25, 1.3, "2", True, None])
async def test_a_tolerance_outside_0_to_20_in_half_points_is_refused(a, value):
    d = await decide(a, "PUT", "/calibration/targets")
    with pytest.raises(DraftInvalidError):
        await a.calibration.set_targets(d, ADMIN, json.dumps({"recall_tolerance": value}).encode())
    assert (await a.calibration.targets_for(issue_scope(ALPHA))).targets.recall_tolerance == 2.0


async def test_the_tolerance_is_audited_beside_the_other_targets(a):
    d = await decide(a, "PUT", "/calibration/targets")
    await a.calibration.set_targets(d, ADMIN, b'{"recall_tolerance": 5.5}')
    now = await a.calibration.targets_for(issue_scope(ALPHA))
    assert now.targets.recall_tolerance == 5.5 and now.targets.block_precision == 0.95
    (event,) = await a.calibration_store.scoped(issue_scope(ALPHA)).audit_events(ALPHA)
    assert event.detail["before"]["recall_tolerance"] == 2.0
    assert event.detail["after"]["recall_tolerance"] == 5.5 and event.actor.endswith("alice")


# ------------------------------------------------------------------ through the publisher


async def test_a_publish_that_regresses_is_refused_through_the_publisher():
    """v1 soaks the rule in shadow; v2 enforces it (candidate) and is promoted; then v3 with a
    worse escalate_at is refused with the regression failure (beside the soak's: a rule whose
    thresholds changed needs its own soak, which is the evidence gate's, not this gate's)."""
    big = [ex(i, "block", 0.9) for i in range(25)] + [ex(100 + i, "allow", 0.1) for i in range(25)]
    big = [{**r, "content": f"{r['content']} #{r['id']}"} for r in big]
    admin = Admin(precision_gate=True, regression_gate=True)
    admin.fake.responder = lambda text, key, q: (
        float(P.search(text).group(1)) if key == KEY and P.search(text) else None
    )
    scope = issue_scope(ALPHA)
    try:
        shadow = bundle(
            ALPHA, rules=[rule("refunds", mode="shadow", block_at=0.85, escalate_at=0.5)]
        )
        await save(admin, shadow)
        await upload(admin, big)

        async def publish_draft(note=None):
            draft = await admin.drafts.scoped(scope).get(ALPHA)
            d = await decide(admin, "POST", "/draft/publish")
            body = {"mode": "enforce", "rollout_percent": 100, **({"note": note} if note else {})}
            return await admin.publisher.publish(d, ADMIN, json.dumps(body).encode(), draft.etag)

        first = await publish_draft()  # v1: first publish, the rule in shadow
        assert first.state == "active"
        admin.now += timedelta(hours=80)  # the soak
        doc = json.loads((await admin.drafts.scoped(scope).get(ALPHA)).document)
        doc["rules"][0]["mode"] = "enforce"
        await save(admin, doc, if_match=(await admin.drafts.scoped(scope).get(ALPHA)).etag)
        await calibrate(admin)
        v2 = await publish_draft()  # v2 candidate: the active v1 had the rule in shadow
        d = await decide(admin, "POST", "/candidate/promote")
        await admin.publisher.promote(d, ADMIN)  # v2 active, enforcing
        # a v3 that acts on far fewer of the golden positives: escalate_at above every score
        worse = json.loads((await admin.drafts.scoped(scope).get(ALPHA)).document)
        worse["rules"][0]["block_at"], worse["rules"][0]["escalate_at"] = 0.98, 0.95
        await save(admin, worse, if_match=(await admin.drafts.scoped(scope).get(ALPHA)).etag)
        await calibrate(admin)
        with pytest.raises(DraftInvalidError) as refused:
            await publish_draft()
        codes = {e.code for e in refused.value.errors}
        assert "evidence_gate.regression" in codes
        text = " ".join(e.message for e in refused.value.errors)
        assert "recall fell 100.0 points" in text and f"v{v2.version}" in text
    finally:
        await admin.aclose()


async def test_the_evidence_gate_joins_both_records_each_clipped_for_the_events_note(a):
    from guardrail_engine.admin.evidence import RECORD_CHARS, EvidenceGate

    old = doc_with(block_at=0.8, escalate_at=0.5)
    await scored(a, old)
    gate = EvidenceGate(a.golden_store, a.calibration, a.calibration)
    scope = issue_scope(ALPHA)
    failures, record = await gate.evaluate(
        scope, doc_with(block_at=0.56, escalate_at=0.5), [], a.now,
        active_version=4, active_document=old,
    )  # fmt: skip
    precision, regression = record.split("\n")
    assert precision.startswith("precision gate: targets p>=0.95 r>=0.90")
    assert (
        regression == "regression gate: tolerance 2 pt vs v4; refunds 1.00->1.00 n=12 pos=6 neg=6"
    )
    assert "evidence_gate.regression" not in {f.code for f in failures}
    # the first publish: the record says so
    _, first = await gate.evaluate(scope, doc_with(), [], a.now)
    assert first.endswith("regression gate: first publish, no active version to compare")
    assert all(len(part) <= RECORD_CHARS for part in first.split("\n"))
    # without a regression source the record is the precision gate's alone, as in M4-01
    only = EvidenceGate(a.golden_store, a.calibration)
    _, alone = await only.evaluate(scope, doc_with(), [], a.now)
    assert "regression" not in alone


# ------------------------------------------------------------------ the soak, replaced (b)


def big_set(n=25):
    """n positives at p=0.9 and n negatives at p=0.1, each content distinct."""
    rows = [ex(i, "block", 0.9) for i in range(n)] + [ex(100 + i, "allow", 0.1) for i in range(n)]
    return [{**r, "content": f"{r['content']} #{r['id']}"} for r in rows]


async def scored_big(a, doc, n=25):
    await save(a, doc)
    await upload(a, big_set(n))
    return await calibrate(a)


async def replacement(a, new, old):
    return await a.calibration.soak_replacement(issue_scope(ALPHA), new, old)


async def test_a_thresholds_only_change_to_an_enforcing_rule_is_exempt_when_the_golden_gates_pass(
    a,
):
    old = doc_with(block_at=0.85, escalate_at=0.5)
    await scored_big(a, old)
    new = doc_with(block_at=0.9, escalate_at=0.6)
    exempt = await replacement(a, new, old)
    assert exempt == {"refunds": "refunds p=1.00@0.9 r=1.00->1.00 n=50 pos=25 neg=25"}


async def test_a_pool_under_twenty_keeps_the_soak(a):
    old = doc_with(block_at=0.85, escalate_at=0.5)
    await scored_big(a, old, n=9)  # 18 examples scored
    assert await replacement(a, doc_with(block_at=0.9, escalate_at=0.6), old) == {}
    await upload(a, [ex(900, "block", 0.9), ex(901, "allow", 0.1)], name="two more")
    await calibrate(a)  # 20: enough
    assert list(await replacement(a, doc_with(block_at=0.9, escalate_at=0.6), old)) == ["refunds"]


async def test_an_unscored_example_keeps_the_soak(a):
    old = doc_with(block_at=0.85, escalate_at=0.5)
    await scored_big(a, old)
    await upload(a, [ex(900, "block", 0.9)], name="new")  # not scored yet
    assert await replacement(a, doc_with(block_at=0.9, escalate_at=0.6), old) == {}


@pytest.mark.parametrize(
    "new",
    [
        doc_with(block_at=0.05, escalate_at=0.04),  # precision: everything is predicted: 0.5
        doc_with(block_at=0.99, escalate_at=0.98),  # recall falls to 0
        {**doc_with(block_at=0.9, escalate_at=0.6), "rules": [{
            **rule("refunds", block_at=0.9, escalate_at=0.6), "severity": "high"}]},  # not only
    ],
    ids=["precision_fails", "regression_fails", "another_field_changed"],
)  # fmt: skip
async def test_a_failing_gate_or_another_change_keeps_the_soak(a, new):
    old = doc_with(block_at=0.85, escalate_at=0.5)
    await scored_big(a, old)
    assert await replacement(a, new, old) == {}


async def test_a_floor_derived_a_shadow_and_a_not_enforcing_before_rule_get_no_exemption(a):
    old = doc_with(block_at=0.85, escalate_at=0.5)
    await scored_big(a, old)
    new = doc_with(block_at=0.9, escalate_at=0.6)
    forked = {"origin": "fork:p__inj_direct"}
    assert await replacement(a, {**new, "rules": [{**new["rules"][0], **forked}]}, old) == {}
    assert (
        await replacement(a, {**new, "rules": [{**new["rules"][0], "mode": "shadow"}]}, old) == {}
    )
    shadow_before = {**old, "rules": [{**old["rules"][0], "mode": "shadow"}]}
    assert await replacement(a, new, shadow_before) == {}
    assert await replacement(a, new, None) == {}  # nothing active


async def test_the_evidence_gate_drops_only_the_exempt_rules_soak_failure_and_records_it(a):
    from guardrail_engine.admin.evidence import EvidenceGate, GateFailure

    old = bundle(
        ALPHA,
        rules=[rule("refunds", block_at=0.85, escalate_at=0.5),
               rule("other", gps=("input",), block_at=0.85, escalate_at=0.5)],
    )  # fmt: skip
    await scored_big(a, old)
    new = bundle(
        ALPHA,
        rules=[rule("refunds", block_at=0.9, escalate_at=0.6),  # thresholds only: replaced
               {**rule("other", gps=("input",), block_at=0.85, escalate_at=0.5),
                "question": "Is this the reworded question that we ask now?"}],  # reworded: soaks
    )  # fmt: skip
    gate = EvidenceGate(a.golden_store, a.calibration, a.calibration)
    history = []  # nothing live: both rules would fail the soak
    failures, record = await gate.evaluate(
        issue_scope(ALPHA), new, history, a.now, active_version=3, active_document=old
    )
    soaks = {f.rule_id for f in failures if f.gate == "shadow_soak"}
    assert soaks == {"other"}  # refunds' soak is replaced
    assert isinstance(failures[0], GateFailure)
    assert "soak replaced by golden gates: refunds p=1.00@0.9 r=1.00->1.00 n=50" in record


async def test_through_the_publisher_a_thresholds_only_change_publishes_without_a_new_soak():
    """v1 soaks in shadow, v2 enforces and is promoted; v3 moves only the thresholds, and the
    golden gates carry it."""
    admin = Admin(precision_gate=True, regression_gate=True)
    admin.fake.responder = lambda text, key, q: (
        float(P.search(text).group(1)) if key == KEY and P.search(text) else None
    )
    scope = issue_scope(ALPHA)

    async def current():
        return await admin.drafts.scoped(scope).get(ALPHA)

    async def publish_draft(note=None):
        d = await decide(admin, "POST", "/draft/publish")
        body = {"mode": "enforce", "rollout_percent": 100, **({"note": note} if note else {})}
        return await admin.publisher.publish(
            d, ADMIN, json.dumps(body).encode(), (await current()).etag
        )

    try:
        shadow = bundle(
            ALPHA, rules=[rule("refunds", mode="shadow", block_at=0.85, escalate_at=0.5)]
        )
        await save(admin, shadow)
        await upload(admin, big_set())
        await publish_draft()  # v1
        admin.now += timedelta(hours=80)
        doc = json.loads((await current()).document)
        doc["rules"][0]["mode"] = "enforce"
        await save(admin, doc, if_match=(await current()).etag)
        await calibrate(admin)
        await publish_draft()  # v2 candidate
        await admin.publisher.promote(await decide(admin, "POST", "/candidate/promote"), ADMIN)
        # v3: only the thresholds move (a new fingerprint: before this, a new 72-hour soak)
        tuned = json.loads((await current()).document)
        tuned["rules"][0].update(block_at=0.9, escalate_at=0.6)
        await save(admin, tuned, if_match=(await current()).etag)
        await calibrate(admin)  # same questions: nothing new to score
        v3 = await publish_draft("tune")
        events = await admin.lifecycle.scoped(scope).events(ALPHA)
        note = next(e.note for e in events if e.action == "publish" and e.version == v3.version)
        assert note.startswith("tune\n") and "soak replaced by golden gates: refunds" in note
        assert "regression gate: tolerance 2 pt vs v2" in note and len(note) <= 500
        # but a reworded rule still soaks
        worded = json.loads((await current()).document)
        worded["rules"][0]["question"] = "Does the content discuss refunds at all?"
        await save(admin, worded, if_match=(await current()).etag)
        await admin.publisher.promote(await decide(admin, "POST", "/candidate/promote"), ADMIN)
        await calibrate(admin)
        with pytest.raises(DraftInvalidError) as refused:
            await publish_draft()
        assert "evidence_gate.shadow_soak" in {e.code for e in refused.value.errors}
    finally:
        await admin.aclose()


# ------------------------------------------------------------------
def with_tool_allowlist(doc, *tools):
    return {**doc, "guard_points": {"tool_call": {"tool_allowlist": list(tools)}}}


async def test_an_active_version_naming_a_tool_the_registry_lost_is_still_measured(a):
    """The allow-list names a tool the tenant's registry no longer has (the compile
    would say tool_not_registered); recall doesn't depend on it, so the gate measures the
    version with a stub for the tool, and a recall drop is refused."""
    old = doc_with(block_at=0.8, escalate_at=0.5)
    await scored(a, old)
    old_with_gone_tool = with_tool_allowlist(old, "gone.tool")
    failures, _ = await regress(a, doc_with(block_at=0.9, escalate_at=0.7), old_with_gone_tool)
    (f,) = failures
    assert f.code == "evidence_gate.regression" and "recall fell 33.3 points" in f.message
    # and the same version with no recall drop passes: measured, not skipped
    ok, record = await regress(a, doc_with(block_at=0.9, escalate_at=0.5), old_with_gone_tool)
    assert ok == [] and "refunds 1.00->1.00" in record and "not compared" not in record


async def test_a_version_that_cannot_be_measured_for_another_reason_fails_closed(a):
    old = doc_with(block_at=0.8, escalate_at=0.5)
    await scored(a, old)
    # a tool name the profile refuses as a stub (a denylisted part): the compile says why
    unmeasurable = with_tool_allowlist(old, "ignore.previous")
    failures, record = await regress(a, doc_with(block_at=0.9, escalate_at=0.5), unmeasurable)
    (f,) = failures
    assert f.rule_id == "refunds" and "can't be measured" in f.message
    assert "tool_not_registered" in f.message and "can't be measured" in record


async def test_only_a_floor_the_platform_moved_is_not_compared_and_the_record_says_so():
    from floor_fixtures import FLOOR_V2

    admin = Admin(regression_gate=True, extra_floors=(FLOOR_V2,))
    admin.fake.responder = lambda text, key, q: (
        float(P.search(text).group(1)) if key == KEY and P.search(text) else None
    )
    try:
        old = doc_with(block_at=0.8, escalate_at=0.5)  # extends floor@1
        await scored(admin, old)
        admin.catalog.set_released({1, 2})
        admin.catalog.raise_minimum(2)  # the platform moved: floor@1 is below the minimum
        new = {**doc_with(block_at=0.9, escalate_at=0.7), "extends": ["platform/floor@2"]}
        failures, record = await admin.calibration.regression_gate(issue_scope(ALPHA), new, 3, old)
        assert failures == []
        assert "below the minimum or unreleased, not compared" in record
    finally:
        await admin.aclose()


async def test_a_positive_a_deny_pattern_blocks_counts_as_acted_on_in_the_version_where_it_is(a):
    """ "case 000 p=0.5" is a positive. The draft adds a deny pattern that blocks it
    before the model, so it is acted on there whatever p would say. The escalate_at moves to
    0.7: of the six positives, 0.7, 0.8, 0.9 and 0.95 are acted on by the model, and the blocked
    one by the deny pattern: 5 of 6, not 4 of 5."""
    old = doc_with(block_at=0.8, escalate_at=0.5)
    await scored(a, old)
    deny = {"deny_patterns": [{"id": "d", "regex": "case 000", "action": "block"}]}
    new = {**doc_with(block_at=0.9, escalate_at=0.7), "deterministic": deny}
    await save(a, new, if_match=(await a.drafts.scoped(issue_scope(ALPHA)).get(ALPHA)).etag)
    report = await calibrate(a)
    assert report.terminal_now == {"deterministic": 1}
    failures, _ = await regress(a, new, old)
    (f,) = failures
    assert "recall fell 16.7 points" in f.message  # 1.000 -> 0.833: five of six
    assert "1.000 on the active version" in f.message and "0.833 on this one" in f.message
    assert "over 6 golden positives" in f.message


async def test_a_positive_unscorable_for_another_reason_is_left_out_of_both_versions(a):
    """ "case 000" is too large for the draft's guard point (say its content budget shrank):
    the draft has no score for it, so it is compared on neither side: five positives, and the
    record says one was left out."""
    from types import SimpleNamespace

    old = doc_with(block_at=0.8, escalate_at=0.5)
    await scored(a, old)
    other_deny = {
        "deny_patterns": [{"id": "d", "regex": "nothing-matches-this", "action": "block"}]
    }
    new = {**doc_with(block_at=0.9, escalate_at=0.5), "deterministic": other_deny}  # new identity
    await save(a, new, if_match=(await a.drafts.scoped(issue_scope(ALPHA)).get(ALPHA)).etag)
    real = a.evaluator.evaluate

    async def evaluate(scope, policy, content, tool=None, usage_class="test"):
        if "case 000" in content:
            return SimpleNamespace(
                reason="content_too_large", model_called=False, rules=(), usage=None,
                decision="block",
            )  # fmt: skip
        return await real(scope, policy, content, tool, usage_class)

    a.evaluator.evaluate = evaluate
    report = await calibrate(a)
    assert report.terminal_now == {"too_large": 1}
    failures, record = await regress(a, new, old)
    assert failures == []
    assert "refunds 1.00->1.00" in record and "left_out=too_large:1" in record
    assert "excl=too_large:1" in record


async def test_the_records_show_the_pools_composition_and_what_was_left_out(a):
    old = doc_with(block_at=0.8, escalate_at=0.5)
    await scored(a, old)
    await upload(
        a,
        [{"id": "dup", "guard_point": "output", "label": "allow", "content": "case 000 p=0.5"}],
        name="conflict",
    )  # the same content as a positive, labelled the other way: out of the pool
    failures, record = await regress(a, doc_with(block_at=0.9, escalate_at=0.5), old)
    assert failures == []
    assert "refunds 1.00->1.00 n=11 pos=5 neg=6 excl=both_labels:1" in record


async def test_a_missing_regression_source_fails_closed_once_there_is_an_active_version(a):
    from guardrail_engine.admin.evidence import NO_REGRESSION_GATE, EvidenceGate

    old = doc_with(block_at=0.8, escalate_at=0.5)
    gate = EvidenceGate(a.golden_store, NO_PRECISION_GATE)
    scope = issue_scope(ALPHA)
    first, _ = await gate.evaluate(scope, old, [], a.now)  # no active version: nothing to compare
    assert "evidence_gate.regression" not in {f.code for f in first}
    later, _ = await gate.evaluate(scope, old, [], a.now, active_version=3, active_document=old)
    (missing,) = [f for f in later if f.code == "evidence_gate.regression"]
    assert "no regression source is configured" in missing.message
    opted = EvidenceGate(a.golden_store, NO_PRECISION_GATE, NO_REGRESSION_GATE)
    later, _ = await opted.evaluate(scope, old, [], a.now, active_version=3, active_document=old)
    assert "evidence_gate.regression" not in {f.code for f in later}


async def test_a_pool_of_only_one_side_keeps_the_soak(a):
    """24 positives and 6 negatives is 30 examples but no gate has anything to say
    about false positives; the exemption wants ten of each."""
    old = doc_with(block_at=0.85, escalate_at=0.5)
    rows = [ex(i, "block", 0.9) for i in range(24)] + [ex(100 + i, "allow", 0.1) for i in range(6)]
    rows = [{**r, "content": f"{r['content']} #{r['id']}"} for r in rows]
    await save(a, old)
    await upload(a, rows)
    await calibrate(a)
    assert await replacement(a, doc_with(block_at=0.9, escalate_at=0.6), old) == {}
    await upload(
        a,
        [{**r, "id": f"x{r['id']}", "content": r["content"] + " more"}
         for r in rows[24:]],
        name="more negatives",
    )  # fmt: skip
    # still short: 12 negatives would pass, so add enough to reach ten each side
    more = [ex(300 + i, "allow", 0.1) for i in range(6)]
    more = [{**r, "content": f"{r['content']} #{r['id']}"} for r in more]
    await upload(a, more, name="even more")
    await calibrate(a)
    assert list(await replacement(a, doc_with(block_at=0.9, escalate_at=0.6), old)) == ["refunds"]


async def test_the_unscored_hint_mentions_a_reworded_neighbour(a):
    old = doc_with(block_at=0.8, escalate_at=0.5)
    await save(a, old)
    await upload(a, known_set())
    failures, _ = await regress(a, doc_with(block_at=0.9, escalate_at=0.5), old)
    assert "a rule reworded at the same guard point changes the scoring identity" in (
        failures[0].message
    )


async def test_calibrate_with_a_version_scores_one_that_names_a_tool_the_tenant_lost():
    """The published version's allow-list names a tool the registry no longer has; it
    is scored with the same stub registry the gate measures it with."""
    from admin_fixtures import Admin as Fixture

    from guardrail_engine.admin.lifecycle import PublishEvent  # noqa: F401 (the store is real)

    admin = Fixture(regression_gate=True)
    admin.fake.responder = lambda text, key, q: (
        float(P.search(text).group(1)) if key == KEY and P.search(text) else None
    )
    scope = issue_scope(ALPHA)
    try:
        from guardrail_engine.guard.tenants import TenantProfile, ToolInfo

        base = await admin.tenants.get(ALPHA)
        with_tool = TenantProfile.build(
            base.attributes, base.domain, [ToolInfo("gone.tool")], slug=base.slug
        )
        admin.tenants.put(with_tool)  # the tool is registered when the version is published
        doc = with_tool_allowlist(
            doc_with(block_at=0.8, escalate_at=0.5, mode="shadow"), "gone.tool"
        )  # shadow: publishing it needs no soak
        await save(admin, doc)
        await upload(admin, known_set())
        draft = await admin.drafts.scoped(scope).get(ALPHA)
        d = await decide(admin, "POST", "/draft/publish")
        v1 = await admin.publisher.publish(
            d, ADMIN, b'{"mode": "enforce", "rollout_percent": 100}', draft.etag
        )
        admin.tenants.put(base)  # ... and then the tenant loses it (no tools in the profile)
        report = await calibrate(admin, version=v1.version)
        assert (report.version, report.scored_now, report.unscored_remaining) == (1, 12, 0)
        # the draft path would not have compiled it (the registry lacks the tool)
        with pytest.raises(DraftInvalidError):
            await calibrate(admin)  # the draft names it too: the real registry refuses
        # and the gate measures it from those scores
        active = await admin.lifecycle.scoped(scope).document(ALPHA, v1.version)
        active = {**active, "rules": [{**r, "mode": "enforce"} for r in active["rules"]]}
        failures, _ = await admin.calibration.regression_gate(
            scope, doc_with(block_at=0.9, escalate_at=0.7), v1.version, active
        )
        assert [f.code for f in failures] == ["evidence_gate.regression"]
        assert "recall fell 33.3 points" in failures[0].message
    finally:
        await admin.aclose()
