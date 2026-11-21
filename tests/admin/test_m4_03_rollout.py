"""M4-03: progressive rollout at runtime (PF-7), the shadow candidate, and the agreement report.

The Admin fixture's Guard Service is given the lifecycle as its candidate source. A tenant has
v1 active and v2 a candidate; the model is the fake one, and what a rule answers is read from
the content (``p=0.7``) so every comparison is known."""

import json
import re
from collections import Counter

import pytest
from admin_fixtures import ALPHA, BETA, Admin, bundle, rule, who

from guardrail_engine.admin.lifecycle import NoCandidateError
from guardrail_engine.admin.rollout import LifecycleCandidates
from guardrail_engine.authz import Role
from guardrail_engine.guard import Decision, Reason
from guardrail_engine.guard.audit import InMemoryAuditSink
from guardrail_engine.guard.rollout import BUCKETS, rollout_bucket, sampled
from guardrail_engine.tenant_scope import issue_scope

BASE = "/v1/tenants/{tid}/guardrails"
ADMIN = who(Role.GUARDRAIL_ADMIN, issuer="https://i/")
VIEWER = who(Role.VIEWER, issuer="https://i/")
GUARD_POINTS = ("input", "plan", "tool_call", "tool_result", "output")
P = re.compile(r"p=([0-9.]+)")


@pytest.fixture
async def a():
    admin = Admin()
    admin.fake.responder = lambda text, key, q: (
        float(P.search(text).group(1)) if key == "t__refunds" and P.search(text) else None
    )
    admin.audit_sink = InMemoryAuditSink()
    service = admin.env.service
    service._audit = admin.audit_sink
    service.attach_rollout(LifecycleCandidates(admin.lifecycle), admin.shadow_stats)
    yield admin
    await service.drain_shadow()
    await admin.aclose()


async def decide(a, method, route, principal=ADMIN, tid=ALPHA):
    return await a.decide(principal, method, BASE + route, tid)


async def publish_doc(a, doc, mode="enforce", percent=100):
    d = await decide(a, "PUT", "/draft")
    current = await a.drafts.scoped(issue_scope(ALPHA)).get(ALPHA)
    saved = await a.service.put_draft(
        d, ADMIN, json.dumps(doc).encode(), None if current is None else current.etag
    )
    d = await decide(a, "POST", "/draft/publish")
    body = json.dumps({"mode": mode, "rollout_percent": percent}).encode()
    return await a.publisher.publish(d, ADMIN, body, saved.etag)


def v1_doc(**kw):
    return bundle(
        ALPHA, rules=[rule("refunds", mode="shadow", block_at=0.8, escalate_at=0.5, **kw)]
    )


def v2_doc(**kw):
    return bundle(
        ALPHA, rules=[rule("refunds", mode="shadow", block_at=0.6, escalate_at=0.3, **kw)]
    )


async def rollout(a, mode="shadow", percent=100, v2=None):
    """v1 active, v2 a candidate in ``mode`` at ``percent``."""
    await publish_doc(a, v1_doc())
    await publish_doc(a, v2 or v2_doc(), mode, percent)
    a.env.service.rollout.invalidate(ALPHA)


async def check(a, conversation, guard_point="output", content="plain p=0.7", tid=ALPHA):
    return await a.env.check(tid, guard_point, content, conversation_id=conversation)


# ------------------------------------------------------------------ the key


def test_the_bucket_is_deterministic_in_range_and_spread():
    assert rollout_bucket("t_a", "c1") == rollout_bucket("t_a", "c1")
    buckets = Counter(rollout_bucket("t_alpha", f"conv-{i}") for i in range(20_000))
    assert set(buckets) == set(range(BUCKETS))
    assert min(buckets.values()) > 120 and max(buckets.values()) < 290  # about 200 each
    # the tenant is part of the key: the same conversation id lands elsewhere for another tenant
    assert any(rollout_bucket("t_a", f"c{i}") != rollout_bucket("t_b", f"c{i}") for i in range(20))


def test_raising_the_percentage_never_moves_a_conversation_back():
    ids = [f"conv-{i}" for i in range(500)]
    at10 = {c for c in ids if sampled("t_alpha", c, 10)}
    at20 = {c for c in ids if sampled("t_alpha", c, 20)}
    assert at10 <= at20 and len(at10) < len(at20)
    assert not any(sampled("t_alpha", c, 0) for c in ids)
    assert all(sampled("t_alpha", c, 100) for c in ids)
    assert 20 < len(at10) < 90  # about 10% of 500


# --------------------------------------------- PF-7: one version a conversation


async def test_every_guard_point_of_a_conversation_is_decided_by_the_same_version(a):
    await rollout(a, mode="enforce", percent=50)
    decided: dict[str, set[int]] = {}
    by_version: Counter[int] = Counter()
    for i in range(40):
        conversation = f"conv-{i}"
        for gp in GUARD_POINTS:
            verdict = await check(a, conversation, gp)
            decided.setdefault(conversation, set()).add(verdict.bundle_version)
        by_version[next(iter(decided[conversation]))] += 1
    assert all(len(versions) == 1 for versions in decided.values())  # never mixed in one
    assert set(by_version) == {1, 2}  # and both versions decide some conversations
    assert 8 <= by_version[2] <= 32  # about half
    # the same conversation, asked again later, gets the same version
    again = {c: (await check(a, c)).bundle_version for c in list(decided)[:10]}
    assert again == {c: next(iter(decided[c])) for c in again}


async def test_an_enforce_candidate_at_1_percent_decides_few_and_at_100_decides_all(a):
    await rollout(a, mode="enforce", percent=1)
    ids = [f"c{i}" for i in range(300)]
    chosen = {c for c in ids if sampled(ALPHA, c, 1)}
    assert len(chosen) < 15
    sample = ids[:40]
    versions = {c: (await check(a, c)).bundle_version for c in sample}
    assert all(v == (2 if c in chosen else 1) for c, v in versions.items())
    d = await decide(a, "PATCH", "/candidate")
    await a.publisher.set_percent(d, ADMIN, b'{"rollout_percent": 100}')
    a.env.service.rollout.invalidate(ALPHA)
    assert {(await check(a, c)).bundle_version for c in sample} == {2}


async def test_with_no_conversation_id_the_active_version_decides_and_no_candidate_runs(a):
    await rollout(a, mode="enforce", percent=100)
    calls = len(a.fake.calls)
    verdict = await a.env.check(ALPHA, "output", "plain p=0.7")
    assert verdict.bundle_version == 1 and verdict.candidate_version is None
    assert len(a.fake.calls) == calls + 1  # one evaluation: the active version's


async def test_the_audit_names_the_deciding_version_and_the_candidate_when_it_decides(a):
    await rollout(a, mode="enforce", percent=100)
    verdict = await check(a, "conv-1")
    assert (verdict.bundle_version, verdict.candidate_version) == (2, 2)
    record = a.audit_sink.records[-1]
    assert (record.bundle_version, record.candidate_version) == (2, 2)
    assert record.candidate_decision is None  # it decided: there is nothing alongside


async def test_a_conversation_id_that_is_not_valid_is_refused(a):
    await rollout(a, mode="shadow", percent=100)
    for bad in ("", "x" * 129, "line\nbreak"):
        verdict = await a.env.check(ALPHA, "output", "x", conversation_id=bad)
        assert (verdict.decision, verdict.reason) == (Decision.BLOCK, Reason.INVALID_REQUEST)


async def test_no_candidate_at_all_changes_nothing(a):
    await publish_doc(a, v1_doc())
    a.env.service.rollout.invalidate(ALPHA)
    verdict = await check(a, "conv-1")
    assert verdict.bundle_version == 1 and verdict.candidate_version is None
    assert len(a.fake.calls) == 1


# ------------------------------------------------------------------ the shadow candidate


async def test_a_shadow_candidate_is_evaluated_and_logged_and_never_acts(a):
    """v1 and v2 differ: at p=0.7 v1 calls for escalate (0.5 <= p < 0.8) and v2 for block
    (p >= 0.6). The verdict is v1's, the audit record holds v2's decision beside it."""
    await rollout(a, mode="shadow", percent=100)
    verdict = await check(a, "conv-1")
    await a.env.service.drain_shadow()
    assert verdict.bundle_version == 1  # the active version decided
    assert verdict.candidate_version == 2
    assert verdict.candidate_decision == "allow"  # its rule is in shadow mode: it calls, never acts
    assert len(a.fake.calls) == 2  # the active evaluation and the candidate's, beside it
    record = a.audit_sink.records[-1]
    assert (record.bundle_version, record.candidate_version) == (1, 2)
    assert record.candidate_decision == verdict.candidate_decision
    assert record.candidate_reason == "policy"
    assert len(a.audit_sink.records) == 1  # one record per check, the candidate has none of its own


async def test_a_candidate_that_would_block_does_not_change_the_verdict(a):
    """The candidate lowers a floor threshold below what the content scores: it would block;
    the verdict is the active version's allow."""
    a.fake.set_noul("p__inj_direct", 0.5)  # v1: 0.5 is under the floor's 0.55: allow
    candidate = {
        **v2_doc(),
        "overrides": [{"rule": "p__inj_direct", "block_at": 0.45, "escalate_at": 0.2}],
    }
    await rollout(a, mode="shadow", percent=100, v2=candidate)
    verdict = await check(a, "conv-9", content="plain")
    await a.env.service.drain_shadow()
    assert verdict.decision == Decision.ALLOW and verdict.bundle_version == 1
    assert verdict.candidate_decision == "block"  # recorded, not acted on
    assert a.audit_sink.records[-1].candidate_decision == "block"


async def test_a_conversation_outside_the_sample_runs_no_candidate(a):
    await rollout(a, mode="shadow", percent=10)
    outside = next(c for c in (f"c{i}" for i in range(200)) if not sampled(ALPHA, c, 10))
    inside = next(c for c in (f"c{i}" for i in range(200)) if sampled(ALPHA, c, 10))
    calls = len(a.fake.calls)
    out = await check(a, outside)
    assert out.candidate_version is None and len(a.fake.calls) == calls + 1
    inn = await check(a, inside)
    await a.env.service.drain_shadow()
    assert inn.candidate_version == 2 and len(a.fake.calls) == calls + 3


async def test_a_provider_refusal_of_the_candidate_is_only_logged(a, caplog):
    """PF-12: the active verdict stands, the record says provider_safety, and the comparison is
    counted as incomparable, not as a disagreement."""
    import logging

    await rollout(a, mode="shadow", percent=100)
    service = a.env.service
    real = service.evaluate_draft

    async def refused(scope, policy, content, **kw):
        verdict = await real(scope, policy, content, **kw)
        return verdict.model_copy(
            update={"reason": Reason.PROVIDER_SAFETY, "decision": Decision.BLOCK, "rules": ()}
        )

    service.evaluate_draft = refused
    with caplog.at_level(logging.INFO, logger="guardrail_engine.guard.service"):
        verdict = await check(a, "conv-1")
        await service.drain_shadow()
    assert verdict.decision == Decision.ALLOW and verdict.bundle_version == 1
    assert verdict.candidate_reason == "provider_safety"
    assert any("refused by the provider" in r.message for r in caplog.records)
    tally = await a.shadow_stats.tally(issue_scope(ALPHA), 1, 2)
    assert (tally.checks, tally.incomparable) == (0, 1) and tally.rules == {}


async def test_a_candidate_that_cannot_be_compiled_is_skipped_and_the_active_version_decides(
    a, caplog
):
    await rollout(a, mode="enforce", percent=100)
    service = a.env.service

    async def broken(scope, version):
        raise RuntimeError("the store is down")

    service.policy_cache.candidate_policies = broken
    service.rollout.invalidate(ALPHA)
    verdict = await check(a, "conv-1")
    assert verdict.bundle_version == 1 and verdict.candidate_version is None
    assert any("can't be served" in r.message for r in caplog.records)


async def test_a_failing_candidate_source_means_the_active_version_decides(a):
    await rollout(a, mode="enforce", percent=100)

    class Down:
        async def candidate(self, scope):
            raise ConnectionError("lifecycle store down")

    a.env.service.attach_rollout(Down(), a.shadow_stats)
    verdict = await check(a, "conv-1")
    assert verdict.bundle_version == 1


async def test_a_slow_candidate_does_not_hold_the_verdict_past_the_wait(a):
    import asyncio
    import time

    await rollout(a, mode="shadow", percent=100)
    service = a.env.service
    real = service.evaluate_draft

    async def slow(scope, policy, content, **kw):
        await asyncio.sleep(1.0)
        return await real(scope, policy, content, **kw)

    service.evaluate_draft = slow
    started = time.perf_counter()
    verdict = await check(a, "conv-1")
    took = time.perf_counter() - started
    assert took < 0.8  # the wait is shadow_wait_s (0.2 s), not the candidate's second
    assert verdict.candidate_version == 2 and verdict.candidate_decision is None  # not in time
    await service.drain_shadow()
    tally = await a.shadow_stats.tally(issue_scope(ALPHA), 1, 2)
    assert tally.checks == 1  # but it was counted when it finished


# ------------------------------------------------------------------ the agreement report


async def comparison(a, tid=ALPHA, principal=VIEWER):
    d = await a.decide(principal, "GET", BASE + "/candidate/comparison", tid)
    return await a.rollout.comparison(d)


async def test_the_report_counts_per_rule_agreement_between_the_versions(a):
    await rollout(a, mode="shadow", percent=100)
    # p=0.1: both allow. p=0.4: v1 allow (< 0.5), v2 escalate (>= 0.3). p=0.7: v1 escalate, v2
    # block. p=0.9: both block.
    for i, p in enumerate((0.1, 0.1, 0.4, 0.7, 0.7, 0.9)):
        await check(a, f"conv-{i}", content=f"plain p={p}")
    await a.env.service.drain_shadow()
    report = await comparison(a)
    assert (report["active_version"], report["candidate_version"]) == (1, 2)
    assert (report["mode"], report["rollout_percent"]) == ("shadow", 100)
    assert (report["checks_compared"], report["checks_incomparable"]) == (6, 0)
    rules = {r["rule"]: r for r in report["rules"]}
    refunds = rules["t__refunds"]
    assert refunds["layer"] == "tenant"
    assert (refunds["n"], refunds["agree"], refunds["candidate_stricter"]) == (6, 3, 3)
    assert refunds["candidate_looser"] == 0 and refunds["agreement_rate"] == 0.5
    # the floor rules are the same in both versions: they agree every time
    floor = [r for k, r in rules.items() if k.startswith("p__")]
    assert floor and all(r["agreement_rate"] == 1.0 and r["layer"] == "floor" for r in floor)
    # the decisions agree (rule-mode shadow: nothing acts)
    assert report["decision"]["agreement_rate"] == 1.0


async def test_the_report_has_counts_and_rates_never_a_probability_or_content(a):
    await rollout(a, mode="shadow", percent=100)
    a.fake.set_noul("p__inj_direct", 0.42)
    await check(a, "conv-1", content="a secret content p=0.7")
    await a.env.service.drain_shadow()
    report = await comparison(a)
    text = json.dumps(report)
    assert (
        "0.42" not in text
        and "secret content" not in text
        and "0.7" not in text.replace("0.75", "").replace("agreement_rate", "")
    )
    allowed = {
        "n", "agree", "agreement_rate", "candidate_stricter", "candidate_looser",
        "only_active", "only_candidate", "rule", "layer",
    }  # fmt: skip
    for entry in report["rules"]:
        assert set(entry) == allowed
    assert set(report["decision"]) == allowed - {"rule", "layer"}


async def test_a_rule_only_one_version_has_is_counted_apart(a):
    await rollout(
        a,
        mode="shadow",
        percent=100,
        v2=bundle(
            ALPHA,
            rules=[rule("refunds", mode="shadow"), rule("extra", mode="shadow")],
        ),
    )
    await check(a, "conv-1", content="plain p=0.7")
    await a.env.service.drain_shadow()
    rules = {r["rule"]: r for r in (await comparison(a))["rules"]}
    assert rules["t__extra"]["only_candidate"] == 1 and rules["t__extra"]["n"] == 0
    assert rules["t__refunds"]["n"] == 1


async def test_the_report_is_the_tenants_own_and_needs_a_candidate(a):
    with pytest.raises(NoCandidateError):
        await comparison(a)  # nothing published
    await rollout(a, mode="shadow", percent=100)
    await check(a, "conv-1")
    await a.env.service.drain_shadow()
    other = who(Role.VIEWER, tenant=BETA, issuer="https://i/")
    with pytest.raises(NoCandidateError):
        await comparison(a, tid=BETA, principal=other)  # BETA has no candidate, and no counts
    assert (await comparison(a))["checks_compared"] == 1


async def test_promoting_starts_a_new_comparison_and_the_old_counts_stay_with_their_pair(a):
    await rollout(a, mode="shadow", percent=100)
    await check(a, "conv-1")
    await a.env.service.drain_shadow()
    first = await a.shadow_stats.tally(issue_scope(ALPHA), 1, 2)
    assert first.checks == 1
    d = await decide(a, "POST", "/candidate/promote")
    await a.publisher.promote(d, ADMIN)
    a.env.service.rollout.invalidate(ALPHA)
    await check(a, "conv-2")  # no candidate now: nothing is compared
    assert (await a.shadow_stats.tally(issue_scope(ALPHA), 1, 2)).checks == 1


# ------------------------------------------------------------------ follow-ups


async def test_a_promotion_whose_event_was_missed_never_sends_a_conversation_v2_v1_v2(a):
    """The candidate pointer and the active pointer are cached separately. When the
    candidate pointer is read again and shows the candidate gone (it was promoted), the active
    pointer is read again with it, so the sampled conversation stays on version 2."""
    await rollout(a, mode="enforce", percent=100)
    service = a.env.service
    assert (await check(a, "conv-1")).bundle_version == 2  # decided by the candidate
    d = await decide(a, "POST", "/candidate/promote")
    await a.publisher.promote(d, ADMIN)  # no invalidate: the event was missed
    service.rollout._entries[ALPHA].fresh_until = float("-inf")  # the candidate pointer expires
    seen = [(await check(a, "conv-1")).bundle_version for _ in range(3)]
    assert seen == [2, 2, 2]  # never 1 in between


async def test_a_candidate_that_could_not_be_used_is_counted_by_tenant_and_cause(a):
    await rollout(a, mode="enforce", percent=100)
    service = a.env.service
    assert service.rollout.fallback_counts() == {}

    async def broken(scope, version):
        raise RuntimeError("down")

    service.policy_cache.candidate_policies = broken
    service.rollout.invalidate(ALPHA)
    await check(a, "conv-1")
    await check(a, "conv-2")
    assert service.rollout.fallback_counts() == {(ALPHA, "compile_failed"): 2}

    class Down:
        async def candidate(self, scope):
            raise ConnectionError("down")

    service.attach_rollout(Down(), a.shadow_stats)
    await check(a, "conv-3")
    assert service.rollout.fallback_counts() == {(ALPHA, "source_failed"): 1}


async def test_a_deterministic_block_does_not_wait_for_the_shadow_candidate(a):
    import asyncio
    import time

    doc = bundle(ALPHA, rules=[rule("refunds", mode="shadow")])
    doc["deterministic"] = {"deny_patterns": [{"id": "no_secret", "regex": "secret-word"}]}
    await publish_doc(a, doc)
    await publish_doc(a, v2_doc(), "shadow", 100)
    service = a.env.service
    service.rollout.invalidate(ALPHA)
    real = service.evaluate_draft

    async def slow(scope, policy, content, **kw):
        await asyncio.sleep(1.0)
        return await real(scope, policy, content, **kw)

    service.evaluate_draft = slow
    started = time.perf_counter()
    verdict = await check(a, "conv-1", content="this has secret-word in it")
    took = time.perf_counter() - started
    assert verdict.decision == Decision.BLOCK and verdict.reason == Reason.DETERMINISTIC
    assert took < 0.15  # no 0.2 s wait: the verdict took no model call
    assert verdict.candidate_version == 2 and verdict.candidate_decision is None
    await service.drain_shadow()
    tally = await a.shadow_stats.tally(issue_scope(ALPHA), 1, 2)
    assert tally.checks + tally.incomparable == 1  # still counted (no rules: incomparable)
