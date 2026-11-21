"""M4-01: the calibration job, the suggestions in /validate, accept and override, the targets
and the R1 precision gate. The model is the fake one (no network): its probability for the
tenant rule is read from the example's own text (``p=0.93``), so every answer is known."""

import json
import re
from datetime import timedelta

import pytest
from admin_fixtures import ALPHA, BETA, Admin, bundle, rule, who

from guardrail_engine.admin import DraftInvalidError
from guardrail_engine.admin.calibration import (
    MAX_NEW_SCORES,
    CalibrationInProgressError,
    StaleSuggestionError,
    content_hash,
    scoring_hash,
)
from guardrail_engine.admin.evidence import EvidenceGate
from guardrail_engine.admin.service import DecisionError, PreconditionRequiredError
from guardrail_engine.authz import Role
from guardrail_engine.tenant_scope import issue_scope

BASE = "/v1/tenants/{tid}/guardrails"
ADMIN = who(Role.GUARDRAIL_ADMIN, issuer="https://i/")
REVIEWER = who(Role.GUARDRAIL_REVIEWER, issuer="https://i/")
VIEWER = who(Role.VIEWER, issuer="https://i/")
KEY = "t__refunds"
P = re.compile(r"p=([0-9.]+)")


@pytest.fixture
async def a():
    admin = Admin()
    admin.fake.responder = lambda text, key, q: (
        float(P.search(text).group(1)) if key == KEY and P.search(text) else None
    )
    yield admin
    await admin.aclose()


def ex(i, label, p, gp="output"):
    return {"id": f"e{i}", "guard_point": gp, "label": label,
            "content": f"case {i:03d} p={p}"}  # fmt: skip


# the synthetic golden set whose answers are worked out in test_sweep.py
POSITIVES = (0.5, 0.6, 0.7, 0.8, 0.9, 0.95)
NEGATIVES = (0.05, 0.1, 0.2, 0.3, 0.4, 0.55)


def known_set(gp="output", start=0):
    rows = [ex(start + i, "block", p, gp) for i, p in enumerate(POSITIVES)]
    rows += [ex(start + 10 + i, "allow", p, gp) for i, p in enumerate(NEGATIVES)]
    return rows


async def decide(a, method, route, principal=ADMIN, tid=ALPHA):
    return await a.decide(principal, method, BASE + route, tid)


async def save(a, doc, *, if_match=None, tid=ALPHA):
    d = await decide(a, "PUT", "/draft", tid=tid)
    return await a.service.put_draft(d, ADMIN, json.dumps(doc).encode(), if_match)


async def upload(a, rows, name="g", tid=ALPHA):
    body = json.dumps({"name": name, "examples": rows}).encode()
    d = await decide(a, "POST", "/golden-sets", REVIEWER, tid)
    return await a.golden.upload(d, REVIEWER, body)


async def calibrate(a, gp="output", principal=REVIEWER, tid=ALPHA):
    d = await decide(a, "POST", "/draft/calibrate", principal, tid)
    return await a.calibration.calibrate(d, json.dumps({"guard_point": gp}).encode())


async def validate(a, tid=ALPHA):
    return await a.tools.validate(await decide(a, "POST", "/draft/validate", tid=tid))


def suggestion(report, rule_id="refunds"):
    return next(r for r in report.calibration["rules"] if r["rule"] == rule_id)


async def prepared(a, rows=None):
    await save(a, bundle(ALPHA, rules=[rule("refunds")]))
    await upload(a, rows or known_set())


# ------------------------------------------------------------------ the job and /validate


async def test_the_job_scores_the_examples_and_validate_shows_the_b2_suggestion(a):
    await prepared(a)
    report = await calibrate(a)
    assert (report.pool, report.scored_now, report.already_scored) == (12, 12, 0)
    assert report.unscored_remaining == 0 and report.held_back == 0 and report.not_scored == 0
    assert len(a.fake.calls) == 12
    s = suggestion(await validate(a))
    # worked out by hand in test_sweep: block_at 0.56 (the 0.55 negative is just out), escalate_at
    # 0.50 (all six positives are needed for recall 0.90)
    assert (s["block_at"], s["escalate_at"], s["band_empty"]) == (0.56, 0.50, False)
    assert (s["precision"], s["recall"], s["examples"], s["positives"]) == (1.0, 1.0, 12, 6)
    assert (s["scored"], s["unscored"], s["available"]) == (12, 0, True)
    assert s["current"] == {"block_at": 0.8, "escalate_at": 0.5}


async def test_validate_sends_nothing_to_the_model_and_says_how_much_is_unscored(a):
    await prepared(a)
    s = suggestion(await validate(a))
    assert a.fake.calls == []
    assert (s["scored"], s["unscored"], s["available"]) == (0, 12, False)
    assert s["reason"] == "no_examples"
    await calibrate(a)
    calls = len(a.fake.calls)
    await validate(a)
    assert len(a.fake.calls) == calls  # still nothing from validate


async def test_the_job_replays_stored_scores_and_calls_the_model_only_for_new_examples(a):
    await prepared(a)
    await calibrate(a)
    assert len(a.fake.calls) == 12
    again = await calibrate(a)
    assert (again.scored_now, again.already_scored, again.unscored_remaining) == (0, 12, 0)
    assert len(a.fake.calls) == 12  # nothing sent: replayed from the store
    await upload(a, [ex(40, "block", 0.99), ex(41, "allow", 0.02)], name="more")
    more = await calibrate(a)
    assert (more.scored_now, more.already_scored) == (2, 12) and len(a.fake.calls) == 14


async def test_the_same_content_in_two_sets_is_one_example(a):
    await prepared(a)
    again = [{**r, "id": "again-" + r["id"]} for r in known_set()]  # same contents, other ids
    await upload(a, again, name="again")
    report = await calibrate(a)
    assert report.pool == 12 and len(a.fake.calls) == 12


async def test_a_content_labelled_both_ways_is_left_out(a):
    await prepared(a)
    await upload(a, [{"id": "c1", "guard_point": "output", "label": "allow",
                      "content": "case 000 p=0.5"}], name="conflict")  # fmt: skip
    report = await calibrate(a)
    assert report.pool == 11  # case 000 carries both labels now


async def test_editing_a_threshold_keeps_the_scores_and_rewording_the_rule_drops_them(a):
    await prepared(a)
    await calibrate(a)
    draft = await a.drafts.scoped(issue_scope(ALPHA)).get(ALPHA)
    doc = json.loads(draft.document)
    doc["rules"][0]["block_at"] = 0.9
    saved = await save(a, doc, if_match=draft.etag)
    s = suggestion(await validate(a))
    assert (s["scored"], s["unscored"]) == (12, 0)  # thresholds aren't part of the identity
    doc = json.loads(saved.document)
    doc["rules"][0]["question"] = "Does the content discuss refund policy in any way?"
    await save(a, doc, if_match=saved.etag)
    s = suggestion(await validate(a))
    assert (s["scored"], s["unscored"]) == (0, 12)  # a new question: scored again


async def test_only_tenant_rules_are_stored_never_a_floor_rules_probability(a):
    await prepared(a)
    await calibrate(a)
    stored = a.calibration_store._scores
    assert len(stored) == 12
    for by_rule in stored.values():
        assert set(by_rule) == {KEY}  # no p__ key, no d__ key
    report = await validate(a)
    assert "p__" not in json.dumps(report.calibration)


async def test_a_floor_derived_rule_gets_no_suggestion(a):
    doc = bundle(ALPHA, rules=[rule("refunds"), {**rule("copy", gps=("output",)),
                                                  "origin": "fork:p__inj_direct"}])  # fmt: skip
    await save(a, doc)
    await upload(a, known_set())
    report = await validate(a)
    assert [r["rule"] for r in report.calibration["rules"]] == ["refunds"]


async def test_a_rule_runs_on_several_guard_points_and_its_pool_covers_them_all(a):
    await save(a, bundle(ALPHA, rules=[rule("refunds", gps=("output", "input"))]))
    await upload(a, known_set("output") + known_set("input", start=200)[:6], name="both")
    await calibrate(a, "output")
    s = suggestion(await validate(a))
    assert (s["unscored"] == 6 and not s["available"]) or s["examples"] == 12
    await calibrate(a, "input")
    s = suggestion(await validate(a))
    assert s["unscored"] == 0 and s["scored"] == 18 and s["guard_points"] == ["input", "output"]


async def test_the_job_is_bounded_per_request_and_picks_up_where_it_left_off(a):
    rows = [ex(i, "block" if i % 2 else "allow", 0.9 if i % 2 else 0.1) for i in range(60)]
    await prepared(a, rows)
    first = await calibrate(a)
    assert (first.scored_now, first.unscored_remaining) == (MAX_NEW_SCORES, 10)
    second = await calibrate(a)
    assert (second.scored_now, second.unscored_remaining, second.already_scored) == (10, 0, 50)
    assert len(a.fake.calls) == 60


async def test_a_second_run_for_the_tenant_while_one_goes_is_refused(a):
    import asyncio

    await prepared(a)
    gate = asyncio.Event()
    real = a.fake.decide

    async def slow(*args, **kwargs):
        await gate.wait()
        return await real(*args, **kwargs)

    a.fake.decide = slow
    first = asyncio.ensure_future(calibrate(a))
    await asyncio.sleep(0.05)
    with pytest.raises(CalibrationInProgressError):
        await calibrate(a)
    gate.set()
    assert (await first).scored_now == 12


async def test_the_job_refuses_a_guard_point_with_no_tenant_rule_and_runs_as_reviewer(a):
    await prepared(a)
    with pytest.raises(DraftInvalidError) as e:
        await calibrate(a, "tool_call")
    assert e.value.errors[0].code == "calibrate.no_rules"
    with pytest.raises(DecisionError):
        await calibrate(a, principal=VIEWER)  # the model is paid for: reviewers and up
    with pytest.raises(DecisionError):
        await a.calibration.calibrate(await decide(a, "POST", "/draft/test", REVIEWER), b"{}")


async def test_the_calls_are_metered_as_test_traffic(a):
    await prepared(a)
    await calibrate(a)
    meter = await a.drained_meter()
    assert meter.answered and all(t == ALPHA for t, _, _ in meter.answered)


async def test_the_scoring_identity_changes_with_the_questions_and_the_floor_version():
    from guardrail_engine.decision.types import NoulCriteria, NoulQuestion

    q = NoulQuestion(
        instructions="Is this about refunds?",
        criteria=NoulCriteria(true_description="yes", false_description="no"),
    )
    base = scoring_hash("output", {"t__x": q}, ["platform/floor@2"])
    assert base == scoring_hash("output", {"t__x": q}, ["platform/floor@2"])
    assert base != scoring_hash("input", {"t__x": q}, ["platform/floor@2"])
    assert base != scoring_hash("output", {"t__x": q}, ["platform/floor@3"])
    assert base != scoring_hash("output", {"t__y": q}, ["platform/floor@2"])
    assert content_hash("Case  1") == content_hash("case 1") != content_hash("case 2")


async def test_stored_scores_are_per_tenant(a):
    await prepared(a)
    await calibrate(a)
    beta = who(Role.GUARDRAIL_ADMIN, tenant=BETA, issuer="https://i/")
    d = await a.decide(beta, "PUT", BASE + "/draft", BETA)
    doc = json.dumps(bundle(BETA, rules=[rule("refunds")])).encode()
    await a.service.put_draft(d, beta, doc, None)
    d = await a.decide(beta, "POST", BASE + "/draft/validate", BETA)
    other = suggestion(await a.tools.validate(d))
    assert (other["scored"], other["unscored"]) == (0, 0)  # BETA has no golden set of its own


# ------------------------------------------------------------------ the targets


async def test_the_targets_default_to_the_agreed_values_and_tenant_changes_are_audited(a):
    d = await decide(a, "GET", "/calibration/targets", VIEWER)
    view = await a.calibration.read_targets(d)
    assert (view.targets.block_precision, view.targets.escalate_recall) == (0.95, 0.90)
    assert view.is_default
    d = await decide(a, "PUT", "/calibration/targets")
    view = await a.calibration.set_targets(
        d, ADMIN, json.dumps({"block_precision": 0.9, "escalate_recall": 0.8}).encode()
    )
    assert view.targets.as_dict() == {
        "block_precision": 0.9,
        "escalate_recall": 0.8,
        "recall_tolerance": 2.0,
    }
    assert not view.is_default
    d = await decide(a, "PUT", "/calibration/targets")
    await a.calibration.set_targets(d, ADMIN, json.dumps({"block_precision": 0.99}).encode())
    now = await a.calibration.read_targets(await decide(a, "GET", "/calibration/targets", VIEWER))
    assert now.targets.as_dict() == {
        "block_precision": 0.99,
        "escalate_recall": 0.8,
        "recall_tolerance": 2.0,
    }  # merged
    events = await a.calibration_store.scoped(issue_scope(ALPHA)).audit_events(ALPHA)
    assert [e.kind for e in events] == ["targets", "targets"]
    assert events[0].actor == "https://i/#alice" or events[0].actor.endswith("alice")
    assert events[0].detail == {
        "before": {"block_precision": 0.95, "escalate_recall": 0.9, "recall_tolerance": 2.0},
        "before_is_default": True,
        "after": {"block_precision": 0.9, "escalate_recall": 0.8, "recall_tolerance": 2.0},
    }  # fmt: skip
    assert events[1].detail["before"]["block_precision"] == 0.9
    assert events[1].detail["after"]["block_precision"] == 0.99 and not events[1].operator


@pytest.mark.parametrize(
    "body",
    [b"{}", b"[]", b'{"block_precision": 0.4}', b'{"block_precision": 1.01}',
     b'{"escalate_recall": "high"}', b'{"block_precision": 0.955}', b'{"other": 0.9}',
     b'{"block_precision": true}', b"not json"],
)  # fmt: skip
async def test_bad_targets_are_refused_and_nothing_is_written(a, body):
    d = await decide(a, "PUT", "/calibration/targets")
    with pytest.raises(DraftInvalidError):
        await a.calibration.set_targets(d, ADMIN, body)
    assert await a.calibration_store.scoped(issue_scope(ALPHA)).audit_events(ALPHA) == []


async def test_only_an_admin_changes_targets_and_another_tenants_are_not_reachable(a):
    with pytest.raises(DecisionError):
        await a.calibration.set_targets(
            await decide(a, "PUT", "/calibration/targets", REVIEWER), REVIEWER, b"{}"
        )
    d = await decide(a, "PUT", "/calibration/targets")
    await a.calibration.set_targets(d, ADMIN, b'{"block_precision": 0.9}')
    other = await a.calibration.read_targets(
        await decide(a, "GET", "/calibration/targets", who(Role.VIEWER, tenant=BETA), BETA)
    )
    assert other.is_default  # ALPHA's change isn't BETA's


async def test_the_targets_change_the_suggestion(a):
    await prepared(a)
    await calibrate(a)
    # recall 0.8 (five of six positives: p >= 0.60) is above block_at 0.56: the band is empty
    d = await decide(a, "PUT", "/calibration/targets")
    await a.calibration.set_targets(d, ADMIN, b'{"escalate_recall": 0.8}')
    s = suggestion(await validate(a))
    assert (s["block_at"], s["escalate_at"], s["band_empty"]) == (0.56, 0.55, True)
    assert (await validate(a)).calibration["targets"]["escalate_recall"] == 0.8


# ------------------------------------------------------------------ accept and override


async def current_digest(a, tid=ALPHA):
    """The digest /validate returns for the draft as it stands."""
    return (await validate(a, tid)).calibration["digest"]


async def decide_thresholds(a, rules, *, principal=ADMIN, if_match=None, tid=ALPHA, digest="auto"):
    draft = await a.drafts.scoped(issue_scope(tid)).get(tid)
    if digest == "auto":
        digest = await current_digest(a, tid)
    d = await decide(a, "POST", "/draft/thresholds", principal, tid)
    body = {"rules": rules, **({} if digest is None else {"digest": digest})}
    return await a.calibration.decide_thresholds(
        d, principal, json.dumps(body).encode(), if_match or draft.etag
    )


async def threshold_events(a):
    """The decisions, as the draft's own audit events (action draft.thresholds)."""
    return [
        e
        for e in await a.drafts.scoped(issue_scope(ALPHA)).audit_events(ALPHA)
        if e.action == "draft.thresholds"
    ]


async def stored_rule(a):
    draft = await a.drafts.scoped(issue_scope(ALPHA)).get(ALPHA)
    return next(r for r in json.loads(draft.document)["rules"] if r["id"] == "refunds")


async def test_accepting_a_suggestion_writes_it_into_the_draft_and_audits_it_with_the_actor(a):
    await prepared(a)
    await calibrate(a)
    before = await validate(a)
    result = await decide_thresholds(a, {"refunds": {"action": "accept"}})
    stored = await stored_rule(a)
    assert (stored["block_at"], stored["escalate_at"]) == (0.56, 0.50)
    (done,) = result["decisions"]
    assert done["action"] == "accept" and done["applied"] == {"block_at": 0.56, "escalate_at": 0.5}
    assert done["previous"] == {"block_at": 0.8, "escalate_at": 0.5}
    assert done["suggested"]["block_at"] == 0.56 and done["suggested"]["precision"] == 1.0
    assert result["targets"] == {
        "block_precision": 0.95, "escalate_recall": 0.9, "recall_tolerance": 2.0,
        "is_default": True,
    }  # fmt: skip
    assert result["floor"] == ["platform/floor@1"] and result["draft_hash"] != before.draft_hash
    # The decision is in the draft write's own audit event: one event, one transaction
    (event,) = await threshold_events(a)
    assert event.actor.endswith("alice") and event.before_hash == before.draft_hash
    assert event.resulting_hash == result["draft_hash"]
    (logged,) = event.detail["decisions"]
    assert logged["rule"] == "refunds" and logged["action"] == "accept"
    assert event.detail["targets"]["block_precision"] == 0.95
    assert event.detail["bundle_hash"].startswith("sha256:") and event.detail["digest"]
    assert event.detail["floor"] == ["platform/floor@1"]
    # the scores were kept: validate now suggests the same, and nothing was sent
    calls = len(a.fake.calls)
    assert suggestion(await validate(a))["current"] == {"block_at": 0.56, "escalate_at": 0.5}
    assert len(a.fake.calls) == calls


async def test_an_override_writes_the_tenants_values_and_audits_it_beside_the_suggestion(a):
    await prepared(a)
    await calibrate(a)
    result = await decide_thresholds(
        a,
        {
            "refunds": {
                "action": "override",
                "block_at": 0.7,
                "escalate_at": 0.4,
                "reason": "legal wants a wider review band",
            }
        },
    )
    stored = await stored_rule(a)
    assert (stored["block_at"], stored["escalate_at"]) == (0.7, 0.4)
    (done,) = result["decisions"]
    assert done["action"] == "override" and done["reason"] == "legal wants a wider review band"
    assert done["suggested"]["block_at"] == 0.56 and done["applied"]["block_at"] == 0.7
    (event,) = await threshold_events(a)
    assert event.detail["decisions"][0]["action"] == "override"
    assert event.actor.endswith("alice")


async def test_an_override_needs_no_suggestion_and_records_that_there_was_none(a):
    await save(a, bundle(ALPHA, rules=[rule("refunds")]))  # nothing scored yet
    result = await decide_thresholds(
        a, {"refunds": {"action": "override", "block_at": 0.9, "escalate_at": 0.6}}
    )
    assert result["decisions"][0]["suggested"] == {"available": False, "reason": "no_examples"}


async def test_accepting_with_no_suggestion_is_refused(a):
    await save(a, bundle(ALPHA, rules=[rule("refunds")]))
    with pytest.raises(DraftInvalidError) as e:
        await decide_thresholds(a, {"refunds": {"action": "accept"}})
    assert e.value.errors[0].code == "thresholds.no_suggestion"


@pytest.mark.parametrize(
    "decision",
    [
        {"action": "override", "block_at": 0.5, "escalate_at": 0.5},
        {"action": "override", "block_at": 0.5, "escalate_at": 0.6},
        {"action": "override", "block_at": 1.0, "escalate_at": 0.5},
        {"action": "override", "block_at": 0.5, "escalate_at": 0.0},
    ],
)
async def test_an_override_must_keep_escalate_below_block_inside_0_01_to_0_99(a, decision):
    await save(a, bundle(ALPHA, rules=[rule("refunds")]))
    with pytest.raises(DraftInvalidError) as e:
        await decide_thresholds(a, {"refunds": decision})
    assert e.value.errors[0].code == "thresholds.invalid"
    assert (await stored_rule(a))["block_at"] == 0.8  # nothing written


@pytest.mark.parametrize(
    "rules",
    [
        {},
        {"nope": {"action": "accept"}},
        {"refunds": {"action": "maybe"}},
        {"refunds": {"action": "accept", "block_at": 0.9}},
        {"refunds": {"action": "override", "block_at": "x", "escalate_at": 0.1}},
        {"refunds": {"action": "override", "block_at": 0.9}},
        {"refunds": {"action": "override", "block_at": 0.9, "escalate_at": 0.5, "reason": ""}},
        {"bad id!": {"action": "accept"}},
    ],
)
async def test_a_malformed_or_unknown_decision_is_refused_whole(a, rules):
    await save(a, bundle(ALPHA, rules=[rule("refunds")]))
    with pytest.raises(DraftInvalidError):
        await decide_thresholds(a, rules)
    assert (await stored_rule(a))["block_at"] == 0.8
    assert await threshold_events(a) == []  # a refused decision leaves no event


async def test_a_decision_on_a_stale_draft_or_without_if_match_is_refused(a):
    await prepared(a)
    await calibrate(a)
    draft = await a.drafts.scoped(issue_scope(ALPHA)).get(ALPHA)
    doc = json.loads(draft.document)
    doc["rules"][0]["severity"] = "high"
    await save(a, doc, if_match=draft.etag)  # the draft moved on
    with pytest.raises(StaleSuggestionError):
        await decide_thresholds(a, {"refunds": {"action": "accept"}}, if_match=draft.etag)
    d = await decide(a, "POST", "/draft/thresholds")
    with pytest.raises(PreconditionRequiredError):
        await a.calibration.decide_thresholds(
            d, ADMIN, b'{"rules": {"refunds": {"action": "accept"}}}', None
        )


async def test_only_an_admin_decides_thresholds(a):
    await prepared(a)
    with pytest.raises(DecisionError):
        await decide_thresholds(a, {"refunds": {"action": "accept"}}, principal=REVIEWER)


# ------------------------------------------------------------------ the R1 precision gate


def enforcing(a, tid=ALPHA):
    return EvidenceGate(a.golden_store, a.calibration)


async def gate(a, document):
    return await a.calibration.precision_gate(issue_scope(ALPHA), document)


async def test_an_enforcing_rule_with_unscored_examples_fails_the_precision_gate(a):
    await prepared(a)
    failures, record = await gate(a, bundle(ALPHA, rules=[rule("refunds")]))
    (f,) = failures
    assert f.rule_id == "refunds" and f.code == "evidence_gate.precision"
    assert "12 of the rule's golden examples have no stored score" in f.message
    assert "calibrate" in f.message
    assert "targets p>=0.95 r>=0.90" in record


async def test_the_gate_checks_precision_at_the_rules_own_block_at(a):
    await prepared(a)
    await calibrate(a)
    ok, record = await gate(a, bundle(ALPHA, rules=[rule("refunds", block_at=0.56)]))
    assert ok == []
    assert "refunds 1.00@0.56 n=12" in record and "targets p>=0.95 r>=0.90" in record
    assert "floor platform/floor@1" in record.replace(";", "") or "platform/floor@1" in record
    # at 0.55 the 0.55 negative is in: 5 of 6 predicted... below the target of 0.95
    bad, _ = await gate(a, bundle(ALPHA, rules=[rule("refunds", block_at=0.5, escalate_at=0.3)]))
    (f,) = bad
    assert "precision 0.857" in f.message and "6 of 7" in f.message and "0.95" in f.message
    # a block_at above every score predicts nothing: that fails too
    nothing, _ = await gate(a, bundle(ALPHA, rules=[rule("refunds", block_at=0.99)]))
    assert "nothing is predicted" in nothing[0].message


async def test_the_gate_uses_the_tenants_targets_and_records_them(a):
    await prepared(a)
    await calibrate(a)
    d = await decide(a, "PUT", "/calibration/targets")
    await a.calibration.set_targets(d, ADMIN, b'{"block_precision": 0.85}')
    ok, record = await gate(
        a, bundle(ALPHA, rules=[rule("refunds", block_at=0.5, escalate_at=0.3)])
    )
    assert ok == [] and "targets p>=0.85" in record  # 6 of 7 = 0.857 meets 0.85


async def test_a_shadow_rule_and_a_floor_derived_rule_are_exempt(a):
    await prepared(a)
    doc = bundle(ALPHA, rules=[rule("refunds", mode="shadow"),
                               {**rule("copy"), "origin": "fork:p__inj_direct"}])  # fmt: skip
    failures, record = await gate(a, doc)
    assert failures == [] and "no enforcing tenant rule" in record


async def test_the_evidence_gate_lists_a_precision_failure_beside_the_others(a):
    await prepared(a)
    g = enforcing(a)
    failures, record = await g.evaluate(
        issue_scope(ALPHA), bundle(ALPHA, rules=[rule("refunds")]), [], a.now
    )
    codes = {f.code for f in failures}
    assert {"evidence_gate.label_counts", "evidence_gate.shadow_soak",
            "evidence_gate.precision"} <= codes  # fmt: skip
    assert "targets" in record
    # No precision source: the gate fails closed rather than skipping the check
    without = EvidenceGate(a.golden_store)
    failures, record = await without.evaluate(
        issue_scope(ALPHA), bundle(ALPHA, rules=[rule("refunds")]), [], a.now
    )
    (missing,) = [f for f in failures if f.code == "evidence_gate.precision"]
    assert "no precision source is configured" in missing.message and record == ""
    # ... and an explicit opt-out is the way to skip it
    from guardrail_engine.admin.evidence import NO_PRECISION_GATE

    opted = EvidenceGate(a.golden_store, NO_PRECISION_GATE)
    failures, _ = await opted.evaluate(
        issue_scope(ALPHA), bundle(ALPHA, rules=[rule("refunds")]), [], a.now
    )
    assert "evidence_gate.precision" not in {f.code for f in failures}


async def test_a_publish_that_passes_the_gate_records_the_targets_in_its_event(a):
    """End to end: shadow soak, calibration, accepted thresholds, then an enforcing publish."""
    big = [ex(i, "block", 0.9) for i in range(25)] + [ex(100 + i, "allow", 0.1) for i in range(25)]
    # distinct contents
    big = [{**r, "content": f"{r['content']} #{r['id']}"} for r in big]
    admin = Admin(precision_gate=True)
    admin.fake.responder = a.fake.responder
    try:
        await save(
            admin,
            bundle(ALPHA, rules=[rule("refunds", mode="shadow", block_at=0.85, escalate_at=0.5)]),
        )
        await upload(admin, big)
        draft = await admin.drafts.scoped(issue_scope(ALPHA)).get(ALPHA)
        d = await decide(admin, "POST", "/draft/publish")
        await admin.publisher.publish(d, ADMIN, b'{"mode": "enforce", "rollout_percent": 100}',
                                      draft.etag)  # fmt: skip
        admin.now += timedelta(hours=80)  # the soak
        await calibrate(admin)
        doc = json.loads((await admin.drafts.scoped(issue_scope(ALPHA)).get(ALPHA)).document)
        doc["rules"][0]["mode"] = "enforce"
        # only the mode changes: the rule, as worded and tuned, has soaked in shadow
        saved = await save(admin, doc, if_match=(
            await admin.drafts.scoped(issue_scope(ALPHA)).get(ALPHA)).etag)  # fmt: skip
        d = await decide(admin, "POST", "/draft/publish")
        result = await admin.publisher.publish(
            d, ADMIN, b'{"mode": "enforce", "rollout_percent": 100, "note": "go"}', saved.etag
        )
        events = await admin.lifecycle.scoped(issue_scope(ALPHA)).events(ALPHA)
        published = [e for e in events if e.action == "publish" and e.version == result.version]
        note = published[0].note
        assert note.startswith("go\n") and "precision gate: targets p>=0.95 r>=0.90" in note
        assert "refunds 1.00@0.85 n=50" in note and len(note) <= 500
    finally:
        await admin.aclose()
