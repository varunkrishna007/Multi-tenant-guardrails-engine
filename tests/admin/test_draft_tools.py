"""M2-04 validate and M2-05 test, through the real authorizer, the real compiler and the real
Guard Service pipeline over the fake model (no network)."""

import asyncio
import json

import pytest
from admin_fixtures import ALPHA, BETA, Admin, bundle, rule, who

from guardrail_engine.admin import DraftInvalidError, NoDraftError, TenantUnavailableError
from guardrail_engine.admin.service import DecisionError
from guardrail_engine.admin.tools import (
    MAX_SAMPLES,
    PRICE_USD_PER_1M_INPUT_TOKENS,
    DraftTestInProgressError,
    EvaluatorUnavailableError,
)
from guardrail_engine.authz import Role
from guardrail_engine.decision import FakeDecisionModel

DRAFT = "/v1/tenants/{tid}/guardrails/draft"
VALIDATE = DRAFT + "/validate"
TEST = DRAFT + "/test"
ADMIN = who(Role.GUARDRAIL_ADMIN)
REVIEWER = who(Role.GUARDRAIL_REVIEWER)


@pytest.fixture
async def a():
    admin = Admin()
    yield admin
    await admin.aclose()


async def save(a, doc, *, principal=ADMIN, tid=ALPHA, if_match=None):
    decision = await a.decide(principal, "PUT", DRAFT, tid)
    return await a.service.put_draft(decision, principal, json.dumps(doc).encode(), if_match)


async def validate(a, principal=ADMIN, tid=ALPHA):
    return await a.tools.validate(await a.decide(principal, "POST", VALIDATE, tid))


async def run_test(a, body, principal=REVIEWER, tid=ALPHA):
    raw = body if isinstance(body, bytes) else json.dumps(body).encode()
    return await a.tools.test(await a.decide(principal, "POST", TEST, tid), raw)


# ---------------------------------------------------------------------------- M2-04 validate


async def test_a_valid_draft_gets_a_preview_per_guard_point_with_tokens_and_cost(a):
    await save(a, bundle(ALPHA, rules=[rule("refunds", gps=("output",))]))
    report = await validate(a)
    assert report.valid and report.errors == () and report.token_budget == 16_000
    assert report.price_usd_per_1m_input_tokens == PRICE_USD_PER_1M_INPUT_TOKENS == 0.10
    out = report.guard_points["output"]
    keys = [q["key"] for q in out.questions]
    assert "t__refunds" in keys and any(k.startswith("p__") for k in keys)  # floor and tenant
    mine = next(q for q in out.questions if q["key"] == "t__refunds")
    assert mine["layer"] == "tenant" and mine["question"]["instructions"]
    assert out.question_count == len(out.questions) <= out.question_budget
    assert out.api_tokens == out.content_api_tokens + out.question_api_tokens > 0
    assert out.within_budget and out.headroom_tokens == 16_000 - out.content_api_tokens
    assert out.est_cost_usd_per_check == pytest.approx(out.api_tokens * 0.10 / 1e6, abs=1e-8)
    # a guard point the floor doesn't cover is listed with no questions and no call
    assert set(report.guard_points) == {"input", "plan", "tool_call", "tool_result", "output"}


async def test_a_draft_over_the_token_budget_is_reported_with_errors_and_no_preview(a):
    """A draft that was within the budget when written is over it after the platform tightens
    the budget: validate says so, with the compiler's code, and previews nothing."""
    from guardrail_engine.admin.tools import DraftTools
    from guardrail_engine.policy.catalog import PlatformSettings

    await save(a, bundle(ALPHA))
    tight = DraftTools(a.drafts, a.tenants, a.catalog, PlatformSettings(token_budget=1_000))
    report = await tight.validate(await a.decide(ADMIN, "POST", VALIDATE))
    assert not report.valid and report.token_budget == 1_000
    assert any(e.code == "guard_point.token_budget_exceeded" for e in report.errors)
    assert report.guard_points == {}


async def test_validate_needs_a_draft_and_an_active_tenant_and_the_right_decision(a):
    with pytest.raises(NoDraftError):
        await validate(a)
    await save(a, bundle(ALPHA))
    a.tenants._profiles.pop(ALPHA)
    with pytest.raises(TenantUnavailableError):
        await validate(a)
    read = await a.decide(who(Role.VIEWER), "GET", "/v1/tenants/{tid}/guardrails")
    with pytest.raises(DecisionError):  # a read decision can't authorize a validate
        await a.tools.validate(read)


async def test_a_catalog_change_after_the_write_shows_up_as_errors(a):
    await save(a, bundle(ALPHA, packs=()))
    stored = a.drafts._drafts[ALPHA]
    doc = json.loads(stored.document)
    doc["extends"] = ["platform/floor@1", "domain/insurance@99"]  # a pack that does not exist
    a.drafts._drafts[ALPHA] = type(stored)(
        ALPHA, json.dumps(doc).encode(), stored.etag, stored.updated_at, stored.updated_by
    )
    report = await validate(a)
    assert not report.valid and report.errors


# ---------------------------------------------------------------------------- M2-05 test


def samples(*pairs):
    return [{"id": f"s{i}", "content": c, "expected": e} for i, (c, e) in enumerate(pairs, 1)]


async def test_samples_run_through_the_draft_and_report_decision_rules_and_expected_met(a):
    await save(a, bundle(ALPHA, rules=[rule("refunds", gps=("output",), block_at=0.8)]))
    a.fake.set_noul("t__refunds", 0.95)  # every sample "matches" the tenant rule
    report = await run_test(
        a,
        {
            "guard_point": "output",
            "samples": samples(
                ("You can claim a refund.", "block"), ("A deductible is...", "allow")
            ),
        },
    )
    assert report.guard_point == "output" and len(report.results) == 2
    first, second = report.results
    assert first.decision == "block" and first.expected_met is True
    assert second.decision == "block" and second.expected_met is False  # expected allow
    assert {"rule", "p", "block_at", "action"} <= set(first.rules[0])
    mine = next(r for r in first.rules if r["rule"] == "t__refunds")
    assert mine["p"] == pytest.approx(0.95, abs=0.05) and mine["layer"] == "tenant"
    assert any(f["rule"] == "t__refunds" for f in first.fired)
    assert report.input_tokens >= 0 and report.est_cost_usd == pytest.approx(
        report.input_tokens * 0.10 / 1e6, abs=1e-8
    )


async def test_a_sample_without_an_expected_verdict_has_no_expected_met(a):
    await save(a, bundle(ALPHA))
    report = await run_test(
        a, {"guard_point": "output", "samples": [{"id": "x", "content": "hello there"}]}
    )
    (only,) = report.results
    assert only.expected is None and only.expected_met is None


async def test_test_calls_are_metered_apart_from_production(a):
    """M2-05: the meter sees ``test:output``, never plain ``output``; nothing is audited."""
    await save(a, bundle(ALPHA))
    await run_test(a, {"guard_point": "output", "samples": samples(("hello there", "allow"))})
    meter = await a.drained_meter()
    assert meter.answered or meter.unanswered  # the model was called
    labels = {g for _, g, _ in meter.answered} | {g for _, g in meter.unanswered}
    assert labels == {"test:output"}
    assert a.env.audit.records == []  # drafts are not production traffic: no audit record
    # a production check on the same tenant needs a published version: not published here
    assert all(t == ALPHA for t, _, _ in meter.answered)


async def test_the_samples_are_redacted_before_the_model_sees_them(a):
    await save(a, bundle(ALPHA))
    await run_test(
        a,
        {
            "guard_point": "output",
            "samples": [{"id": "pii", "content": "mail bob@example.com now"}],
        },
    )
    sent = " ".join(str(c) for c in a.fake.calls[-1].__dict__.values())
    assert "bob@example.com" not in sent  # the same redaction as a production check


@pytest.mark.parametrize(
    ("body", "code"),
    [
        ({"guard_point": "nowhere", "samples": [{"id": "a", "content": "x"}]}, "test.guard_point"),
        ({"guard_point": "output", "samples": []}, "test.samples"),
        ({"guard_point": "output"}, "test.samples"),
        ({"guard_point": "output", "samples": [{"id": "a"}]}, "test.sample_content"),
        ({"guard_point": "output", "samples": [{"id": "a", "content": "x", "expected": "maybe"}]},
         "test.sample_expected"),
        ({"guard_point": "output", "samples": [{"id": "a", "content": "x"},
                                                {"id": "a", "content": "y"}]}, "test.sample_id"),
        ({"guard_point": "output", "samples": [{"id": "a", "content": "x", "tenant_id": BETA}]},
         "test.unknown_field"),
        ({"guard_point": "output", "tenant_id": BETA, "samples": [{"id": "a", "content": "x"}]},
         "test.unknown_field"),
        ({"guard_point": "output", "golden_set": "gs_0123456789abcdef",
          "samples": [{"id": "a", "content": "x"}]}, "test.samples_or_golden_set"),
        ({"guard_point": "output", "golden_set": "gs1"}, "test.golden_set"),
        ({"guard_point": "output", "golden_set": "gs_0123456789abcdef", "offset": -1},
         "test.offset"),
        ({"guard_point": "output", "offset": 3, "samples": [{"id": "a", "content": "x"}]},
         "test.offset"),
        ({"guard_point": "output", "samples": [{"id": f"s{i}", "content": "x"}
                                                for i in range(MAX_SAMPLES + 1)]}, "test.samples"),
    ],
)  # fmt: skip
async def test_a_bad_request_is_refused_whole_with_a_code_and_nothing_is_sent(a, body, code):
    await save(a, bundle(ALPHA))
    with pytest.raises(DraftInvalidError) as e:
        await run_test(a, body)
    assert code in {x.code for x in e.value.errors}
    assert a.fake.calls == []


@pytest.mark.parametrize("raw", [b"not json", b'{"a": 1, "a": 2}', b"[1]", b""])
async def test_a_body_that_is_not_one_json_object_is_a_validation_error(a, raw):
    await save(a, bundle(ALPHA))
    with pytest.raises(DraftInvalidError):
        await run_test(a, raw)


async def test_a_guard_point_with_no_questions_is_refused_before_anything_is_sent(a):
    await save(a, bundle(ALPHA))
    real = a.evaluator.compile

    def without_questions(tenant_id, parsed, profile):
        from dataclasses import replace

        return {k: replace(v, questions={}) for k, v in real(tenant_id, parsed, profile).items()}

    a.evaluator.compile = without_questions
    with pytest.raises(DraftInvalidError) as e:
        await run_test(a, {"guard_point": "output", "samples": samples(("x", None))})
    assert e.value.errors[0].code == "test.no_questions" and a.fake.calls == []


async def test_a_tenant_has_one_test_run_at_a_time(a):
    await save(a, bundle(ALPHA))
    gate = asyncio.Event()
    started = asyncio.Event()
    real = a.fake.decide

    async def slow(*args, **kwargs):
        started.set()
        await gate.wait()
        return await real(*args, **kwargs)

    a.fake.decide = slow
    first = asyncio.ensure_future(
        run_test(a, {"guard_point": "output", "samples": samples(("hello", "allow"))})
    )
    await started.wait()
    with pytest.raises(DraftTestInProgressError):
        await run_test(a, {"guard_point": "output", "samples": samples(("again", "allow"))})
    gate.set()
    assert (await first).results
    # the lock is released: a later run works
    a.fake.decide = real
    assert (
        await run_test(a, {"guard_point": "output", "samples": samples(("ok", "allow"))})
    ).results


async def test_a_test_needs_a_draft_the_right_decision_and_a_running_evaluator(a):
    with pytest.raises(NoDraftError):
        await run_test(a, {"guard_point": "output", "samples": samples(("x", None))})
    await save(a, bundle(ALPHA))
    admin_decision = await a.decide(ADMIN, "POST", VALIDATE)  # a validate decision
    with pytest.raises(DecisionError):
        await a.tools.test(admin_decision, b"{}")
    a.evaluator.open = False  # the engine is shutting down
    with pytest.raises(EvaluatorUnavailableError):
        await run_test(a, {"guard_point": "output", "samples": samples(("x", None))})


async def test_one_tenants_test_never_touches_another_tenants_draft(a):
    await save(a, bundle(ALPHA, rules=[rule("alpha_only", gps=("output",))]))
    beta = who(Role.GUARDRAIL_REVIEWER, tenant=BETA)
    with pytest.raises(NoDraftError):  # beta has no draft; alpha's is not visible
        await run_test(a, {"guard_point": "output", "samples": samples(("x", None))},
                       principal=beta, tid=BETA)  # fmt: skip
    assert a.fake.calls == []


def test_the_fake_model_is_what_the_tests_run_on(a):
    assert isinstance(a.fake, FakeDecisionModel)


# ----------------------------------------------------------------------------
async def test_no_floor_rule_probability_appears_in_a_test_response(a):
    """The test endpoint must not be a gradient oracle for the floor's thresholds."""
    await save(a, bundle(ALPHA, rules=[rule("refunds", gps=("output",), block_at=0.8)]))
    a.fake.default_noul = 0.97  # every question, floor rules included, says "yes"
    a.fake.set_noul("t__refunds", 0.91)
    report = await run_test(a, {"guard_point": "output", "samples": samples(("anything", "block"))})
    (result,) = report.results
    assert result.decision == "block"
    layers = {r["layer"] for r in result.rules}
    assert layers == {"tenant"}  # floor rules are not listed with their p at all
    assert all(not r["rule"].startswith("p__") for r in result.rules)
    floor_fired = [f for f in result.fired if f["rule"].startswith("p__")]
    assert floor_fired, "the floor fired, as it would in production"
    for f in floor_fired:
        assert set(f) == {"rule", "action", "mode"}  # exactly what production shows: no p
    mine = next(f for f in result.fired if f["rule"] == "t__refunds")
    assert mine["p"] == pytest.approx(0.91, abs=0.05)
    blob = json.dumps([{"rules": result.rules, "fired": result.fired}], default=str)
    assert "p__" not in "".join(r["rule"] for r in result.rules)
    assert all(f["rule"].startswith(("t__", "d__")) or "p" not in f for f in result.fired)
    assert blob.count('"p"') == len([r for r in result.rules]) + sum(
        1 for f in result.fired if "p" in f
    )


async def test_the_tenants_deny_patterns_and_tool_allow_list_apply_to_a_draft_test(a):
    """M3-01 inside the pipeline, in AC-G1 order: a deterministic block makes no model call."""
    doc = bundle(
        ALPHA,
        rules=[rule("refunds", gps=("output", "tool_call"))],
        guard_points={"tool_call": {"tool_allowlist": ["cms.search"]}},
    )
    doc["deterministic"] = {
        "deny_patterns": [{"id": "codename", "regex": r"(?i)project\s+falcon", "action": "block"}]
    }
    await save(a, doc)
    out = await run_test(
        a, {"guard_point": "output", "samples": samples(("about Project Falcon", "block"))}
    )
    assert out.results[0].decision == "block" and a.fake.calls == []
    call = json.dumps({"tool": "mail.send", "args": {}})
    blocked = await run_test(
        a,
        {"guard_point": "tool_call",
         "samples": [{"id": "t1", "content": call, "tool": "mail.send", "expected": "block"}]},
    )  # fmt: skip
    assert blocked.results[0].decision == "block" and blocked.results[0].expected_met is True
    assert a.fake.calls == []  # the allow-list refused it before any model call


async def test_a_sample_tool_must_be_short_text(a):
    await save(a, bundle(ALPHA))
    for tool in ("", "x" * 129, 7):
        with pytest.raises(DraftInvalidError) as e:
            await run_test(
                a,
                {"guard_point": "tool_call",
                 "samples": [{"id": "t", "content": "{}", "tool": tool}]},
            )  # fmt: skip
        assert "test.sample_tool" in {x.code for x in e.value.errors}


async def test_calls_without_usage_are_counted_not_treated_as_zero_tokens(a):
    """An answer that carries no usage figure is an unknown, and is reported as one."""
    await save(a, bundle(ALPHA))
    original = a.fake.build_raw_response
    a.fake.build_raw_response = lambda i, q: {
        k: v for k, v in original(i, q).items() if k != "usage"
    }
    report = await run_test(
        a, {"guard_point": "output", "samples": samples(("one", None), ("two", None))}
    )
    assert report.calls_without_usage == 2 and report.input_tokens == 0
    assert all(r.model_called and r.input_tokens is None for r in report.results)
    a.fake.build_raw_response = original
    again = await run_test(a, {"guard_point": "output", "samples": samples(("three", None))})
    assert again.calls_without_usage == 0 and again.input_tokens > 0


async def test_a_deterministic_block_is_not_a_call_without_usage(a):
    doc = bundle(ALPHA, rules=[rule("refunds", gps=("output",))])
    doc["deterministic"] = {"deny_patterns": [{"id": "c", "regex": "falcon", "action": "block"}]}
    await save(a, doc)
    report = await run_test(a, {"guard_point": "output", "samples": samples(("falcon", None))})
    assert report.calls_without_usage == 0 and not report.results[0].model_called


# ----------------------------------------------------------------------------
def floor_wording(a):
    """The first floor rule's question and descriptions at the output guard point."""
    floor = a.catalog.floor(1)
    chosen = next(r for r in floor.rules if "output" in r.guard_points)
    q = chosen.question
    return chosen.key, q.instructions, q.criteria.true_description, q.criteria.false_description


async def run_with(a, doc):
    await save(a, doc)
    a.fake.default_noul = 0.97  # every question says "yes": the floor and the copies all fire
    return (
        await run_test(a, {"guard_point": "output", "samples": samples(("anything", "block"))})
    ).results[0]


def assert_floor_like(result, key):
    assert key not in {r["rule"] for r in result.rules}  # no p, no thresholds listed
    entry = next(f for f in result.fired if f["rule"] == key)
    assert set(entry) == {"rule", "action", "mode"}  # exactly what a floor rule shows


async def test_a_fork_of_a_floor_rule_is_reported_like_the_floor_without_p(a):
    key, *_ = floor_wording(a)
    doc = bundle(
        ALPHA,
        rules=[{
            "id": "myfork", "guard_points": ["output"], "origin": f"fork:{key}",
            "question": "Does this look like something we'd want to review before sending it?",
            "true_description": "It does.", "false_description": "It does not.",
            "block_at": 0.8, "escalate_at": 0.5,
        }],
    )  # fmt: skip
    result = await run_with(a, doc)
    assert_floor_like(result, "t__myfork")


async def test_a_verbatim_copy_of_a_floor_rule_without_an_origin_is_floor_derived(a):
    _, question, *_ = floor_wording(a)
    doc = bundle(
        ALPHA,
        rules=[{
            "id": "copycat", "guard_points": ["output"], "question": question,
            "true_description": "It does.", "false_description": "It does not.",
            "block_at": 0.8, "escalate_at": 0.5,
        }],
    )  # fmt: skip
    assert_floor_like(await run_with(a, doc), "t__copycat")


@pytest.mark.parametrize("field", ["question", "true_description", "false_description"])
async def test_a_case_whitespace_or_zero_width_variant_is_caught_in_any_text_field(a, field):
    _, question, true_d, false_d = floor_wording(a)
    original = {"question": question, "true_description": true_d, "false_description": false_d}
    disguised = "  " + original[field].upper().replace(" ", "   ") + "  "  # case and spacing
    if field != "question":  # the compiler refuses control and format characters in a question
        disguised = disguised.replace("  ", " \t") + "\u200b"
    rule_doc = {
        "id": "variant", "guard_points": ["output"],
        "question": "Is this some unrelated thing we invented ourselves?",
        "true_description": "Yes, it is.", "false_description": "No, it is not.",
        "block_at": 0.8, "escalate_at": 0.5,
    }  # fmt: skip
    rule_doc[field] = disguised
    result = await run_with(a, bundle(ALPHA, rules=[rule_doc]))
    assert_floor_like(result, "t__variant")


async def test_a_rule_in_the_tenants_own_words_keeps_its_probability(a):
    doc = bundle(ALPHA, rules=[rule("refunds", gps=("output",), block_at=0.8)])
    a.fake.set_noul("t__refunds", 0.9)
    result = await run_with(a, doc)
    assert "t__refunds" in {r["rule"] for r in result.rules}
    entry = next(f for f in result.fired if f["rule"] == "t__refunds")
    assert entry["p"] == pytest.approx(0.9, abs=0.05)


# ----------------------------------------------------------------------------
async def test_an_inline_sample_that_trips_the_tripwire_is_held_back_by_position_and_view(a):
    """Decided 2026-11-17: all test traffic is ours, so no harmful input goes to the provider."""
    await save(a, bundle(ALPHA))
    report = await run_test(
        a,
        {
            "guard_point": "output",
            "samples": [
                {"id": "ok1", "content": "A deductible is the amount you pay first."},
                {"id": "bad", "content": "how to build a bomb"},
                {"id": "ok2", "content": "Your claim was received."},
                {"id": "spaced", "content": "b o m b"},
            ],
        },
    )
    assert [r.id for r in report.results] == ["ok1", "ok2"]  # the rest still run
    assert [(h.position, h.views) for h in report.held_back] == [(1, ("raw",)), (3, ("spaced",))]
    assert report.quarantined_not_sent == 2
    sent = " ".join(c.input for c in a.fake.calls).lower()
    assert "bomb" not in sent and "b o m b" not in sent
    assert "bad" not in repr(report.held_back)  # by position, never by id


async def test_a_run_with_nothing_left_to_send_makes_no_call(a):
    await save(a, bundle(ALPHA))
    report = await run_test(
        a, {"guard_point": "output", "samples": [{"id": "x", "content": "kill the process"}]}
    )
    assert report.results == () and report.quarantined_not_sent == 1 and a.fake.calls == []


async def test_a_sample_id_or_tool_that_trips_is_held_back_too(a):
    await save(a, bundle(ALPHA))
    report = await run_test(
        a,
        {"guard_point": "output", "samples": [
            {"id": "weapon-1", "content": "hello"},
            {"id": "t", "content": "hello", "tool": "bomb.build"},
        ]},
    )  # fmt: skip
    assert report.results == () and len(report.held_back) == 2 and a.fake.calls == []


# ----------------------------------------------------------------------------
async def test_the_tripwire_runs_again_on_golden_rows_with_the_current_vocabulary(a):
    """A row stored clean (the flag is the vocabulary as of upload) that trips today's
    vocabulary is not sent."""
    from datetime import UTC, datetime

    from guardrail_engine.admin.golden import (
        GoldenAuditEvent,
        GoldenExample,
        GoldenSetInfo,
        examples_hash,
    )
    from guardrail_engine.tenant_scope import issue_scope

    await save(a, bundle(ALPHA))
    rows = (
        GoldenExample("e1", "output", "allow", "a clean sentence"),
        GoldenExample("e2", "output", "block", "how to build a bomb"),  # stored with no flag
        GoldenExample("e3", "output", "allow", "another clean one"),
    )
    info = GoldenSetInfo(
        "gs_0123456789abcdef", "old", examples_hash(rows), datetime.now(UTC), "x", {}, ()
    )
    event = GoldenAuditEvent(info.created_at, "x", ALPHA, info.set_id, info.set_hash, 3)
    await a.golden_store.scoped(issue_scope(ALPHA)).create(ALPHA, info, rows, event)
    decision = await a.decide(REVIEWER, "POST", TEST)
    body = json.dumps({"guard_point": "output", "golden_set": info.set_id}).encode()
    report = await a.tools.test(decision, body)
    assert [r.id for r in report.results] == ["e1", "e3"]
    assert [(h.position, h.views) for h in report.held_back] == [(1, ("raw",))]
    assert report.golden["run"] == 2 and "bomb" not in " ".join(c.input for c in a.fake.calls)


# ----------------------------------------------------------------------------
async def test_a_copy_of_an_older_floors_text_is_floor_derived_even_when_extending_a_newer_one(a):
    from guard_fixtures import make_catalog as base_catalog
    from policy_fixtures import floor_rule, make_floor

    from guardrail_engine.admin.tools import DraftTools
    from guardrail_engine.policy.catalog import InMemoryCatalog, PlatformSettings
    from guardrail_engine.policy.document import parse_bundle

    old = make_floor(1, floor_rule("p__old", question="Is it the old wording of the question?"))
    new = make_floor(2, floor_rule("p__new", question="Is it the new wording of the question?"))
    catalog = InMemoryCatalog(floors=[old, new])
    assert base_catalog().floor_versions() == (1,)  # the fixture catalog lists its versions
    assert catalog.floor_versions() == (1, 2)
    doc = bundle(
        ALPHA, rules=[{**rule("copy"), "question": "IS IT THE OLD WORDING OF THE QUESTION?"}]
    )
    doc["extends"] = ["platform/floor@2"]
    tools = DraftTools(a.drafts, a.tenants, catalog, PlatformSettings(), a.evaluator)
    assert tools._floor_derived_keys(parse_bundle(doc)) == {"t__copy"}
