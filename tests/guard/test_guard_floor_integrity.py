"""A compiled policy that has lost a floor rule the bundle's floor version
requires must never become a silent allow. The expected floor keys come from the floor
version the bundle extends, independently of the compiler's output; any missing key is a
``block``/``internal_error`` (logged at error level), checked before the call and again
after it. ``no_questions`` is an allow only where the floor has no rules."""

from types import SimpleNamespace

import pytest
from guard_fixtures import ALPHA, FLOOR_KEYS, Env, bundle, rule
from policy_fixtures import floor_rule, make_floor

import guardrail_engine.guard.service as service_module
from guardrail_engine.decision import Failed, FailureKind, NoulQuestion
from guardrail_engine.guard import Decision, Reason
from guardrail_engine.guard.policy_cache import FloorSpec
from guardrail_engine.policy import InMemoryCatalog, PlatformSettings, PolicyCompiler

ALL_OUTPUT_FLOOR = FLOOR_KEYS | {"p__secret"}


def dropping_compiler(drop: set[str] | None = None, *, shadow: set[str] = frozenset()):
    """A compiler that, like the probe, removes floor questions from the output
    guard point (all of them, or ``drop``) or demotes them to shadow, keeping the bundle
    hash, so the store's integrity check can't notice."""

    class Dropping(PolicyCompiler):
        def compile(self, bundle, tenant):
            compiled = super().compile(bundle, tenant)
            gp = compiled.guard_points["output"]
            gone = {k for k, r in gp.rules.items() if r.layer == "floor"} if drop is None else drop
            rules = {
                k: (r.model_copy(update={"mode": "shadow"}) if k in shadow else r)
                for k, r in gp.rules.items()
                if k not in gone
            }
            questions = {k: q for k, q in gp.questions.items() if k not in gone}
            doctored = gp.model_copy(update={"questions": questions, "rules": rules})
            return compiled.model_copy(
                update={"guard_points": {**compiled.guard_points, "output": doctored}}
            )

    return Dropping


def weakening_compiler(keys, *, rule_update=None, question=None, guard_point="output"):
    """Keeps every floor key but changes what the floor rules say."""

    class Weakening(PolicyCompiler):
        def compile(self, bundle, tenant):
            compiled = super().compile(bundle, tenant)
            gp = compiled.guard_points[guard_point]
            rules = {
                k: r.model_copy(update=rule_update) if k in keys and rule_update else r
                for k, r in gp.rules.items()
            }
            questions = {
                k: question if k in keys and question is not None else q
                for k, q in gp.questions.items()
            }
            doctored = gp.model_copy(update={"questions": questions, "rules": rules})
            return compiled.model_copy(
                update={"guard_points": {**compiled.guard_points, guard_point: doctored}}
            )

    return Weakening


async def test_a_raised_floor_threshold_blocks_instead_of_allowing(caplog):
    factory = weakening_compiler(
        {"p__inj_direct"}, rule_update={"block_at": 0.99, "escalate_at": 0.98}
    )
    async with Env(compiler_factory=factory) as env:
        await env.publish(bundle(ALPHA))
        env.fake.set_noul("p__inj_direct", 0.95)  # the honest floor blocks this
        verdict = await env.check(ALPHA, "output")
    assert (verdict.decision, verdict.reason) == (Decision.BLOCK, Reason.INTERNAL_ERROR)
    assert env.fake.calls == []
    assert "p__inj_direct: block_at 0.99 is above the catalog's 0.85" in verdict.detail
    assert "p__inj_direct: escalate_at 0.98 is above the catalog's 0.55" in verdict.detail
    assert any(
        r.levelname == "ERROR" and "p__inj_direct: block_at" in r.getMessage()
        for r in caplog.records
    )


async def test_floor_fail_mode_flipped_open_while_the_platform_is_closed_blocks():
    factory = weakening_compiler(ALL_OUTPUT_FLOOR, rule_update={"fail_mode": "open"})
    async with Env(compiler_factory=factory) as env:  # platform floor_fail_mode: closed
        await env.publish(bundle(ALPHA, defaults={"fail_mode": "open"}))
        env.fake.always(Failed(kind=FailureKind.UNAVAILABLE))
        verdict = await env.check(ALPHA, "output")
    assert (verdict.decision, verdict.reason) == (Decision.BLOCK, Reason.INTERNAL_ERROR)
    assert "fail_mode 'open', but the platform floor_fail_mode is 'closed'" in verdict.detail
    assert env.fake.calls == []


async def test_a_swapped_floor_question_blocks():
    factory = weakening_compiler(
        {"p__ai_addressed"}, question=NoulQuestion(instructions="Is the sky blue?")
    )
    async with Env(compiler_factory=factory) as env:
        await env.publish(bundle(ALPHA))
        verdict = await env.check(ALPHA, "output")
    assert (verdict.decision, verdict.reason) == (Decision.BLOCK, Reason.INTERNAL_ERROR)
    assert "p__ai_addressed: question differs from the catalog's" in verdict.detail
    assert env.fake.calls == []


@pytest.mark.parametrize(
    "update",
    [
        {"block_at": 0.85 + 1e-9},
        {"escalate_at": 0.55 + 1e-9},
        {"block_at": None},
    ],
    ids=["block_at a hair above", "escalate_at a hair above", "block_at removed"],
)
async def test_floor_thresholds_even_a_hair_above_the_catalogs_block(update):
    factory = weakening_compiler({"p__inj_direct"}, rule_update=update)
    async with Env(compiler_factory=factory) as env:
        await env.publish(bundle(ALPHA))
        verdict = await env.check(ALPHA, "output")
    assert (verdict.decision, verdict.reason) == (Decision.BLOCK, Reason.INTERNAL_ERROR)


NAN = float("nan")


@pytest.mark.parametrize(
    "update",
    [
        {"block_at": NAN},
        {"escalate_at": NAN},
        {"block_at": NAN, "escalate_at": NAN},
    ],
    ids=["block_at NaN", "escalate_at NaN", "both NaN"],
)
async def test_a_nan_floor_threshold_blocks_instead_of_allowing(update):
    """The probe: NaN thresholds passed ``compiled > catalog`` (always false for
    NaN), and ``p >= nan`` is false too, so the floor rule could never act."""
    factory = weakening_compiler({"p__inj_direct"}, rule_update=update)
    async with Env(compiler_factory=factory) as env:
        await env.publish(bundle(ALPHA))
        env.fake.set_noul("p__inj_direct", 0.95)  # the honest floor blocks this
        verdict = await env.check(ALPHA, "output")
    assert (verdict.decision, verdict.reason) == (Decision.BLOCK, Reason.INTERNAL_ERROR)
    assert env.fake.calls == []
    for name in update:
        assert f"p__inj_direct: {name} nan is not a finite number" in verdict.detail


@pytest.mark.parametrize(
    ("compiled", "catalog"),
    [(NAN, 0.85), (0.5, NAN), (float("inf"), float("inf")), (0.5, float("inf")), ("0.5", 0.85)],
)
def test_any_non_finite_compiled_or_catalog_threshold_is_a_mismatch(compiled, catalog):
    question = NoulQuestion(instructions="Is it an injection?")
    spec = FloorSpec(
        key="k", question=question, question_type="noul", block_at=catalog, escalate_at=None
    )
    compiled_rule = SimpleNamespace(
        question_type="noul",
        block_at=compiled,
        escalate_at=None,
        layer="floor",
        mode="enforce",
        fail_mode="closed",
    )
    problems = service_module._floor_problems(
        {"k": spec}, {"k": question}, {"k": compiled_rule}, "closed"
    )
    assert problems == [
        f"k: block_at {compiled} is not a finite number at or below the catalog's {catalog}"
    ]


@pytest.mark.parametrize(
    ("override", "p", "expected"),
    [
        ({"block_at": 0.70}, 0.75, Decision.BLOCK),  # lowered: the tenant tightened it
        ({"block_at": 0.70, "escalate_at": 0.40}, 0.45, Decision.ESCALATE),
        ({"escalate_at": 0.40}, 0.45, Decision.ESCALATE),  # block_at left equal
        ({"escalate_at": 0.40}, 0.84, Decision.ESCALATE),
    ],
)
async def test_a_legitimate_lowering_override_still_passes(override, p, expected):
    document = bundle(ALPHA)
    document["overrides"] = [{"rule": "p__inj_direct", **override}]
    async with Env() as env:
        await env.publish(document)
        env.fake.set_noul("p__inj_direct", p)
        verdict = await env.check(ALPHA, "output")
    assert (verdict.decision, verdict.reason) == (expected, Reason.POLICY)


async def test_the_platform_floor_fail_mode_set_open_is_accepted():
    """The honest compile under an open platform floor_fail_mode passes the check."""
    async with Env(settings=PlatformSettings(floor_fail_mode="open")) as env:
        await env.publish(bundle(ALPHA, defaults={"fail_mode": "open"}))
        env.fake.always(Failed(kind=FailureKind.UNAVAILABLE))
        verdict = await env.check(ALPHA, "output")
    assert (verdict.decision, verdict.reason) == (Decision.ALLOW, Reason.MODEL_FAILURE)


async def test_floor_dropped_with_no_tenant_rules_blocks_not_no_questions(caplog):
    async with Env(compiler_factory=dropping_compiler()) as env:
        await env.publish(bundle(ALPHA))
        verdict = await env.check(ALPHA, "output")
    assert (verdict.decision, verdict.reason) == (Decision.BLOCK, Reason.INTERNAL_ERROR)
    assert not verdict.model_called and env.fake.calls == []
    assert "FLOOR LOST" in caplog.text
    assert any(r.levelname == "ERROR" and "FLOOR LOST" in r.message for r in caplog.records)
    for key in ALL_OUTPUT_FLOOR:
        assert key in verdict.detail


async def test_floor_dropped_with_a_tenant_rule_kept_blocks_without_a_model_call():
    async with Env(compiler_factory=dropping_compiler()) as env:
        await env.publish(bundle(ALPHA, rules=[rule("adv")]))
        verdict = await env.check(ALPHA, "output")
    assert (verdict.decision, verdict.reason) == (Decision.BLOCK, Reason.INTERNAL_ERROR)
    assert env.fake.calls == []


async def test_a_single_floor_key_dropped_of_several_blocks():
    async with Env(compiler_factory=dropping_compiler({"p__secret"})) as env:
        await env.publish(bundle(ALPHA, rules=[rule("adv")]))
        verdict = await env.check(ALPHA, "output")
        other = await env.check(ALPHA, "input")  # the untouched guard point still works
    assert (verdict.decision, verdict.reason) == (Decision.BLOCK, Reason.INTERNAL_ERROR)
    assert "p__secret" in verdict.detail and "p__inj_direct" not in verdict.detail
    assert (other.decision, other.reason) == (Decision.ALLOW, Reason.POLICY)


async def test_a_floor_rule_demoted_to_shadow_blocks():
    async with Env(compiler_factory=dropping_compiler(set(), shadow={"p__ai_addressed"})) as env:
        await env.publish(bundle(ALPHA))
        verdict = await env.check(ALPHA, "output")
    assert (verdict.decision, verdict.reason) == (Decision.BLOCK, Reason.INTERNAL_ERROR)
    assert "p__ai_addressed" in verdict.detail


async def test_floor_keys_are_also_checked_against_the_call_actually_made(monkeypatch):
    """With the pre-call check disabled, the post-call check still catches the floor loss."""
    monkeypatch.setattr(service_module, "_floor_problems", lambda *args: [])
    async with Env(compiler_factory=dropping_compiler({"p__secret"})) as env:
        await env.publish(bundle(ALPHA, rules=[rule("adv")]))
        verdict = await env.check(ALPHA, "output")
    assert (verdict.decision, verdict.reason) == (Decision.BLOCK, Reason.INTERNAL_ERROR)
    assert "decision call" in verdict.detail
    assert "p__secret" not in env.fake.calls[0].questions


async def test_floor_keys_are_checked_against_what_was_evaluated(monkeypatch):
    real = service_module.evaluate_answered

    def losing_a_floor_rule(rules, questions, result):
        evaluated = real(rules, questions, result)
        kept = tuple(ev for ev in evaluated.rules if ev.key != "p__inj_direct")
        return type(evaluated)(rules=kept, violations=evaluated.violations)

    monkeypatch.setattr(service_module, "evaluate_answered", losing_a_floor_rule)
    async with Env() as env:
        await env.publish(bundle(ALPHA))
        verdict = await env.check(ALPHA, "output")
    assert (verdict.decision, verdict.reason) == (Decision.BLOCK, Reason.INTERNAL_ERROR)
    assert "resolution" in verdict.detail and "p__inj_direct" in verdict.detail


async def test_no_questions_is_allowed_only_where_the_floor_has_no_rules():
    floor = make_floor(
        1,
        floor_rule(
            "p__only_output",
            ("output",),
            question="Does it leak a secret?",
            true_description="Leaks one.",
            false_description="Leaks none.",
        ),
    )
    async with Env(catalog=InMemoryCatalog(floors=[floor])) as env:
        await env.publish(bundle(ALPHA, guard_points={"plan": {"enabled": False}}))
        plan = await env.check(ALPHA, "plan")
        output = await env.check(ALPHA, "output")
    assert (plan.decision, plan.reason) == (Decision.ALLOW, Reason.NO_QUESTIONS)
    assert (output.decision, output.reason) == (Decision.ALLOW, Reason.POLICY)


@pytest.mark.parametrize("guard_point", ["input", "plan", "tool_call", "tool_result", "output"])
async def test_every_guard_point_the_floor_covers_sends_every_floor_key(guard_point):
    async with Env() as env:
        await env.publish(bundle(ALPHA))
        verdict = await env.check(ALPHA, guard_point)
    expected = ALL_OUTPUT_FLOOR if guard_point in {"tool_result", "output"} else FLOOR_KEYS
    assert set(env.fake.calls[0].questions) >= expected
    assert verdict.reason is Reason.POLICY
