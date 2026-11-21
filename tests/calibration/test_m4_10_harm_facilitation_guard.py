"""A live harness refuses a bundle whose compiled questions include the harm-facilitation
rule (its question names harms). Opting the rule out, or leaving the pack out, passes."""

from pathlib import Path

import pytest
from calibration.engine_path import EngineSetup, SeededNonces, calibration_engine
from calibration.run import StopRun, harm_facilitation_questions, refuse_harm_facilitation

from calibration import engine_path, run
from guardrail_engine.decision import FakeDecisionModel
from guardrail_engine.floor_file import load_floor_file
from guardrail_engine.pack_file import load_pack_file
from guardrail_engine.policy import (
    InMemoryCatalog,
    InMemoryToolRegistry,
    PlatformSettings,
    PolicyCompiler,
    TenantAttributes,
)

ROOT = Path(__file__).resolve().parents[2]
FLOOR = load_floor_file(ROOT / "floor" / "rules.json")
RAI = load_pack_file(ROOT / "packs" / "responsible_ai" / "pack.json")


def questions_of(*overrides, pack=True):
    compiler = PolicyCompiler(
        InMemoryCatalog(floors=[FLOOR], packs=[RAI]),
        InMemoryToolRegistry(),
        PlatformSettings(min_floor_version=FLOOR.version),
    )
    document = {
        "schema_version": 1, "tenant_id": "t_x", "version": 1,
        "extends": [f"platform/floor@{FLOOR.version}", *([RAI.ref] if pack else [])],
        "overrides": list(overrides),
    }  # fmt: skip
    policy = compiler.compile(document, TenantAttributes(tenant_id="t_x"))
    return {gp: dict(c.questions) for gp, c in policy.guard_points.items()}


def test_the_responsible_ai_pack_puts_the_question_at_its_guard_points_and_it_is_refused():
    found = harm_facilitation_questions(questions_of())
    assert found
    with pytest.raises(StopRun, match="harm-facilitation"):
        refuse_harm_facilitation(questions_of())


def test_opting_the_rule_out_or_leaving_the_pack_out_passes():
    optout = {"rule": "d__harm_facilitation", "enabled": False, "justification": "live run"}
    refuse_harm_facilitation(questions_of(optout))
    refuse_harm_facilitation(questions_of(pack=False))
    assert harm_facilitation_questions(questions_of(optout)) == []


async def test_a_live_engine_is_refused_before_any_engine_or_key_is_built(monkeypatch):
    setup = EngineSetup(floor_doc={}, files={}, validation=False, max_input_tokens=None)
    monkeypatch.setattr(engine_path, "compile_floor", lambda doc: (questions_of(), None))
    nonces = SeededNonces("ab" * 16)
    with pytest.raises(StopRun, match="harm-facilitation"):
        async with calibration_engine(setup, [], model=None, nonces=nonces):
            pytest.fail("the engine must not be built")


async def test_an_offline_engine_is_not_refused_by_it(monkeypatch):
    """A fake model sends nothing anywhere, so the offline demos and tests keep working."""
    floor_doc = run.assemble_floor(
        ROOT / "floor" / "rules.json", ROOT / "floor" / "next" / "additions.json"
    )
    setup = EngineSetup(floor_doc=floor_doc, files={}, validation=False, max_input_tokens=None)
    monkeypatch.setattr(engine_path, "compile_floor", lambda doc: (questions_of(), None))
    async with calibration_engine(
        setup, [], model=FakeDecisionModel(default_noul=0.05), nonces=SeededNonces("cd" * 16)
    ):
        pass
