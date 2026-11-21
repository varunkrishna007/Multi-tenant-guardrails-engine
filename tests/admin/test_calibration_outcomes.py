"""Examples that can never be scored, the scoring identity, the
suggestion digest, the decision's audit, and the gate with no source.
The model is the fake one; a rule's probability is read from the example's text (``p=0.93``)."""

import json
import re
from types import SimpleNamespace

import pytest
from admin_fixtures import ALPHA, Admin, bundle, rule, who

from guardrail_engine.admin import calibration as cal
from guardrail_engine.admin.calibration import StaleSuggestionError
from guardrail_engine.admin.evidence import NO_PRECISION_GATE, EvidenceGate
from guardrail_engine.admin.service import DraftInvalidError
from guardrail_engine.authz import Role
from guardrail_engine.tenant_scope import issue_scope

BASE = "/v1/tenants/{tid}/guardrails"
ADMIN = who(Role.GUARDRAIL_ADMIN, issuer="https://i/")
REVIEWER = who(Role.GUARDRAIL_REVIEWER, issuer="https://i/")
KEY = "t__refunds"
P = re.compile(r"p=([0-9.]+)")
DENY = {"deny_patterns": [{"id": "block_marker", "regex": "BLOCKME", "action": "block"}]}


@pytest.fixture
async def a():
    admin = Admin()
    admin.fake.responder = lambda text, key, q: (
        float(P.search(text).group(1)) if key == KEY and P.search(text) else None
    )
    yield admin
    await admin.aclose()


def ex(i, label, p, extra=""):
    return {"id": f"e{i}", "guard_point": "output", "label": label,
            "content": f"case {i:03d} p={p} {extra}".strip()}  # fmt: skip


POSITIVES = (0.5, 0.6, 0.7, 0.8, 0.9, 0.95)
NEGATIVES = (0.05, 0.1, 0.2, 0.3, 0.4, 0.55)


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


async def calibrate(a):
    d = await decide(a, "POST", "/draft/calibrate", REVIEWER)
    return await a.calibration.calibrate(d, b'{"guard_point": "output"}')


async def validate(a):
    return await a.tools.validate(await decide(a, "POST", "/draft/validate"))


def with_deny(doc):
    return {**doc, "deterministic": DENY}


def pool_gate(a, doc):
    return a.calibration.precision_gate(issue_scope(ALPHA), doc)


# ------------------------------------------------------------------
async def test_an_example_a_deny_pattern_blocks_leaves_the_pool_and_the_gate_can_pass(a):
    """The probe: known_set plus a deny pattern that catches "case 000"."""
    deny = {**DENY, "deny_patterns": [{"id": "d", "regex": "case 000", "action": "block"}]}
    doc = {**bundle(ALPHA, rules=[rule("refunds", block_at=0.56, escalate_at=0.5)]),
           "deterministic": deny}  # fmt: skip
    await save(a, doc)
    await upload(a, known_set())
    report = await calibrate(a)
    assert (report.scored_now, report.terminal_now, report.unscored_remaining) == (
        11, {"deterministic": 1}, 0,
    )  # fmt: skip
    assert report.excluded == {"deterministic": 1} and report.failed_now == 0
    calls = len(a.fake.calls)
    again = await calibrate(a)
    assert (again.scored_now, again.unscored_remaining) == (0, 0)  # settled
    assert len(a.fake.calls) == calls  # and nothing is sent again
    failures, record = await pool_gate(a, doc)
    assert failures == []  # before the fix this failed for good ("run calibrate" couldn't help)
    assert "refunds 1.00@0.56 n=11 excl=deterministic:1" in record
    suggestion = (await validate(a)).calibration["rules"][0]
    assert suggestion["excluded"] == {"deterministic": 1} and suggestion["unscored"] == 0
    assert suggestion["examples"] == 11 and suggestion["available"]


async def test_sixty_unscorable_examples_ahead_of_ten_scorable_ones_do_not_stop_the_ten(a):
    unscorable = [ex(100 + i, "block", 0.9, "BLOCKME") for i in range(60)]
    scorable = [ex(i, "block" if i % 2 else "allow", 0.9 if i % 2 else 0.1) for i in range(10)]
    await save(a, with_deny(bundle(ALPHA, rules=[rule("refunds")])))
    await upload(a, unscorable + scorable)
    first = await calibrate(a)  # 50 of the 60: all terminal now
    assert (first.scored_now, first.terminal_now) == (0, {"deterministic": 50})
    second = await calibrate(a)  # the other 10, then the scorable ten, in one batch
    assert second.scored_now == 10 and second.terminal_now == {"deterministic": 10}
    assert (second.unscored_remaining, second.excluded) == (0, {"deterministic": 60})
    assert len(a.fake.calls) == 10


async def test_with_one_example_a_call_every_unscorable_one_still_clears(a, monkeypatch):
    """The other probe: MAX_NEW_SCORES = 1 and an unscorable example at the head."""
    monkeypatch.setattr(cal, "MAX_NEW_SCORES", 1)
    deny = {"deny_patterns": [{"id": "d", "regex": "case 000", "action": "block"}]}
    await save(a, {**bundle(ALPHA, rules=[rule("refunds")]), "deterministic": deny})
    await upload(a, known_set())
    scored = 0
    for _ in range(12):
        scored += (await calibrate(a)).scored_now
    assert scored == 11  # one call cleared the unscorable one, eleven scored the rest
    assert (await calibrate(a)).unscored_remaining == 0


def stub_evaluate(a, outcome):
    """Replace the engine's evaluation for contents matching a marker: ``outcome(content)`` is
    None to use the real one, or (reason, model_called) for a stub verdict."""
    real = a.evaluator.evaluate

    async def evaluate(scope, policy, content, tool=None, usage_class="test"):
        stub = outcome(content)
        if stub is None:
            return await real(scope, policy, content, tool, usage_class)
        reason, called = stub
        return SimpleNamespace(
            reason=reason, model_called=called, rules=(), usage=None, decision="block"
        )

    a.evaluator.evaluate = evaluate


async def test_a_provider_refusal_is_terminal_on_the_second_attempt_not_the_first(a):
    await save(a, bundle(ALPHA, rules=[rule("refunds")]))
    await upload(a, known_set())
    stub_evaluate(a, lambda c: ("provider_safety", False) if "case 003" in c else None)
    first = await calibrate(a)
    assert first.scored_now == 11 and first.failed_now == 1 and first.terminal_now == {}
    assert first.unscored_remaining == 1  # it will be tried once more
    second = await calibrate(a)
    assert second.terminal_now == {"refused": 1} and second.unscored_remaining == 0
    assert second.excluded == {"refused": 1}
    assert (await calibrate(a)).unscored_remaining == 0


async def test_a_too_large_example_is_terminal_at_once(a):
    await save(a, bundle(ALPHA, rules=[rule("refunds")]))
    await upload(a, known_set())
    stub_evaluate(a, lambda c: ("content_too_large", False) if "case 004" in c else None)
    report = await calibrate(a)
    assert report.terminal_now == {"too_large": 1} and report.unscored_remaining == 0


async def test_failures_are_retried_behind_the_examples_never_tried(a, monkeypatch):
    monkeypatch.setattr(cal, "MAX_NEW_SCORES", 2)
    rows = [ex(0, "block", 0.9, "FLAKY"), ex(1, "allow", 0.1, "FLAKY")]
    rows += [ex(10 + i, "block" if i % 2 else "allow", 0.9 if i % 2 else 0.1) for i in range(4)]
    await save(a, bundle(ALPHA, rules=[rule("refunds")]))
    await upload(a, rows)
    stub_evaluate(a, lambda c: ("model_failure", True) if "FLAKY" in c else None)
    one = await calibrate(a)  # the two flaky ones are tried first (never tried, pool order)
    assert (one.scored_now, one.failed_now, one.unscored_remaining) == (0, 2, 6)
    two = await calibrate(a)  # now the never-tried four come before the two that failed
    assert (two.scored_now, two.failed_now) == (2, 0)
    three = await calibrate(a)
    assert (three.scored_now, three.unscored_remaining) == (2, 2)  # the two that failed
    four = await calibrate(a)  # only the flaky ones are left: tried again, still failing
    assert (four.scored_now, four.failed_now, four.unscored_remaining) == (0, 2, 2)
    assert four.terminal_now == {}  # a transient failure is never terminal


async def test_a_held_example_is_out_of_the_pool_counted_and_never_sent(a, monkeypatch):
    real = cal.strings_tripwire
    monkeypatch.setattr(
        cal, "strings_tripwire", lambda *s: ["raw"] if "HOLDME" in s[0] else real(*s)
    )
    doc = bundle(ALPHA, rules=[rule("refunds", block_at=0.56, escalate_at=0.5)])
    await save(a, doc)
    rows = known_set()
    rows[1] = {**rows[1], "content": rows[1]["content"] + " HOLDME"}
    await upload(a, rows)
    report = await calibrate(a)
    assert (report.held_back, report.scored_now, report.excluded) == (1, 11, {"held": 1})
    assert all("HOLDME" not in str(c) for c in a.fake.calls)
    failures, record = await pool_gate(a, doc)
    assert "excl=held:1" in record and failures == []
    assert (await validate(a)).calibration["rules"][0]["excluded"] == {"held": 1}


async def test_a_gate_failure_names_the_left_out_examples_by_cause_only(a):
    doc = with_deny(bundle(ALPHA, rules=[rule("refunds")]))
    await save(a, doc)
    await upload(a, [ex(1, "block", 0.9, "BLOCKME"), ex(2, "allow", 0.1)])
    await calibrate(a)
    failures, _ = await pool_gate(a, doc)
    (f,) = failures
    assert "deterministic:1 left out of the pool" in f.message and "BLOCKME" not in f.message


# ------------------------------------------------------------------
async def identity_survives(a, change):
    """Calibrate, apply ``change`` to the draft, and say whether the 12 scores still replay."""
    await save(a, bundle(ALPHA, rules=[rule("refunds")]))
    await upload(a, known_set())
    await calibrate(a)
    draft = await a.drafts.scoped(issue_scope(ALPHA)).get(ALPHA)
    doc = json.loads(draft.document)
    change(doc)
    await save(a, doc, if_match=draft.etag)
    s = (await validate(a)).calibration["rules"][0]
    return (s["scored"], s["unscored"]) == (12, 0)


async def test_a_threshold_change_keeps_the_scores(a):
    assert await identity_survives(a, lambda d: d["rules"][0].update(block_at=0.9))


@pytest.mark.parametrize(
    "change",
    [
        lambda d: (
            d["deterministic"].update(pii={"detect": ["EMAIL", "PHONE"], "action": "redact"})
            if "deterministic" in d
            else d.update(deterministic={"pii": {"detect": ["EMAIL", "PHONE"], "action": "redact"}})
        ),
        lambda d: d.update(guard_points={"output": {"max_input_tokens": 2000}}),
        lambda d: d.update(deterministic=DENY),
        lambda d: d["rules"][0].update(question="Does the content discuss refunds at all?"),
    ],
    ids=["pii", "max_content_tokens", "deny_pattern", "question"],
)
async def test_each_of_these_changed_alone_forces_re_scoring(a, change):
    assert not await identity_survives(a, change)


async def test_the_render_version_is_part_of_the_identity(a, monkeypatch):
    await save(a, bundle(ALPHA, rules=[rule("refunds")]))
    await upload(a, known_set())
    await calibrate(a)
    assert (await validate(a)).calibration["rules"][0]["unscored"] == 0
    monkeypatch.setattr(cal, "RENDER_VERSION", "2")
    assert (await validate(a)).calibration["rules"][0]["unscored"] == 12


def test_the_identity_covers_the_inputs_named_in_the_review():
    from guardrail_engine.decision.types import NoulCriteria, NoulQuestion

    q = NoulQuestion(
        instructions="x?", criteria=NoulCriteria(true_description="y", false_description="n")
    )
    base = cal.scoring_hash("output", {"t__x": q}, ["platform/floor@2"])
    with_args = lambda **kw: cal.scoring_hash("output", {"t__x": q}, ["platform/floor@2"], **kw)  # noqa: E731
    assert base == with_args()  # no extra inputs: the same as the plain call
    assert base != with_args(max_content_tokens=2000)
    assert with_args(max_content_tokens=2000) != with_args(max_content_tokens=3000)
    assert base != with_args(deterministic={"pii": {"detect": ["EMAIL"], "action": "redact"}})
    assert base != with_args(deterministic=DENY)


# ------------------------------------------------------------------
async def test_accept_names_the_digest_validate_returned_and_a_changed_one_is_a_409(a):
    await save(a, bundle(ALPHA, rules=[rule("refunds")]))
    await upload(a, known_set())
    await calibrate(a)
    digest = (await validate(a)).calibration["digest"]
    assert digest.startswith("sha256:") and digest == (await validate(a)).calibration["digest"]
    draft = await a.drafts.scoped(issue_scope(ALPHA)).get(ALPHA)
    d = await decide(a, "POST", "/draft/thresholds")

    async def accept(body):
        return await a.calibration.decide_thresholds(
            d, ADMIN, json.dumps(body).encode(), draft.etag
        )

    rules = {"refunds": {"action": "accept"}}
    with pytest.raises(DraftInvalidError) as missing:
        await accept({"rules": rules})
    assert missing.value.errors[0].code == "thresholds.digest"
    with pytest.raises(StaleSuggestionError):
        await accept({"digest": "sha256:" + "0" * 64, "rules": rules})
    with pytest.raises(DraftInvalidError):
        await accept({"digest": "nope", "rules": rules})
    # the targets change what the suggestion would be: the digest the tenant saw is stale
    dt = await decide(a, "PUT", "/calibration/targets")
    await a.calibration.set_targets(dt, ADMIN, b'{"escalate_recall": 0.8}')
    with pytest.raises(StaleSuggestionError):
        await accept({"digest": digest, "rules": rules})
    assert (await accept({"digest": (await validate(a)).calibration["digest"], "rules": rules}))[
        "decisions"
    ]


async def test_an_override_needs_no_digest(a):
    await save(a, bundle(ALPHA, rules=[rule("refunds")]))
    d = await decide(a, "POST", "/draft/thresholds")
    draft = await a.drafts.scoped(issue_scope(ALPHA)).get(ALPHA)
    body = {"rules": {"refunds": {"action": "override", "block_at": 0.9, "escalate_at": 0.4}}}
    done = await a.calibration.decide_thresholds(d, ADMIN, json.dumps(body).encode(), draft.etag)
    assert done["decisions"][0]["applied"] == {"block_at": 0.9, "escalate_at": 0.4}


# ------------------------------------------------------------------
async def test_a_refused_decision_leaves_neither_a_draft_change_nor_an_event(a):
    await save(a, bundle(ALPHA, rules=[rule("refunds")]))
    d = await decide(a, "POST", "/draft/thresholds")
    draft = await a.drafts.scoped(issue_scope(ALPHA)).get(ALPHA)
    bad = {"rules": {"refunds": {"action": "override", "block_at": 0.4, "escalate_at": 0.6}}}
    with pytest.raises(DraftInvalidError):
        await a.calibration.decide_thresholds(d, ADMIN, json.dumps(bad).encode(), draft.etag)
    events = await a.drafts.scoped(issue_scope(ALPHA)).audit_events(ALPHA)
    assert [e.action for e in events] == ["draft.put"]  # the first save only
    assert (await a.drafts.scoped(issue_scope(ALPHA)).get(ALPHA)).etag == draft.etag


async def test_the_gate_with_no_precision_source_fails_closed_and_the_opt_out_is_explicit(a):
    doc = bundle(ALPHA, rules=[rule("refunds")])
    failures, _ = await EvidenceGate(a.golden_store).evaluate(issue_scope(ALPHA), doc, [], a.now)
    assert "evidence_gate.precision" in {f.code for f in failures}
    failures, _ = await EvidenceGate(a.golden_store, NO_PRECISION_GATE).evaluate(
        issue_scope(ALPHA), doc, [], a.now
    )
    assert "evidence_gate.precision" not in {f.code for f in failures}
