"""The closed-question lint (AC-C1.6) and non-blank descriptions hold for every catalog
``noul`` rule, floor and pack, on every construction path, not only in the floor file
loader. One ``is_closed_question`` serves the catalog, the compiler and the loader.

Floor file text is parsed by the same strict parser as bundle text; only the error
mapping differs.
"""

from pathlib import Path

import pytest
from policy_fixtures import floor_document, floor_rule, pack_document, pack_rule
from pydantic import ValidationError

from guardrail_engine.policy import (
    FloorFileError,
    FloorVersion,
    PackVersion,
    catalog,
    compiler,
    floor_loader,
    json_document,
    lint,
    parse_floor_json,
)

OPEN_QUESTIONS = ["Tell me about it.", "What data does it reach?", "Does it reach data", "?"]
BLANK = ["", "   ", "\n\t"]


def floor_with(**fields) -> dict:
    return floor_document(1, [floor_rule("p__a"), floor_rule("p__b", **fields)])


def pack_with(question: dict) -> dict:
    return pack_document("p", 1, [pack_rule("d__a"), pack_rule("d__b", question=question)])


@pytest.mark.parametrize("question", OPEN_QUESTIONS)
def test_floor_document_with_an_open_question_is_refused_by_from_document(question):
    with pytest.raises(ValidationError, match=r"p__b: the question must be a closed yes/no"):
        FloorVersion.from_document(floor_with(question=question))


@pytest.mark.parametrize("blank", BLANK)
@pytest.mark.parametrize("field", ["true_description", "false_description"])
def test_floor_document_with_a_blank_description_is_refused_by_from_document(field, blank):
    # (An empty string was already refused by NoulCriteria; whitespace was not.)
    with pytest.raises(ValidationError, match=field):
        FloorVersion.from_document(floor_with(**{field: blank}))


@pytest.mark.parametrize("question", OPEN_QUESTIONS)
def test_pack_document_with_an_open_noul_question_is_refused_by_from_document(question):
    with pytest.raises(ValidationError, match=r"d__b: the question must be a closed yes/no"):
        PackVersion.from_document(pack_with({"type": "noul", "instructions": question}))


@pytest.mark.parametrize("blank", ["   ", "\n\t"])
@pytest.mark.parametrize("field", ["true_description", "false_description"])
def test_pack_document_with_a_blank_description_is_refused_by_from_document(field, blank):
    criteria = {"true_description": "It is.", "false_description": "It is not.", field: blank}
    question = {"type": "noul", "instructions": "Is it?", "criteria": criteria}
    with pytest.raises(ValidationError, match=rf"d__b: {field}"):
        PackVersion.from_document(pack_with(question))


def test_pack_noul_question_without_descriptions_is_still_allowed():
    pack = PackVersion.from_document(pack_with({"type": "noul", "instructions": "Is it?"}))
    assert pack.rules[1].question.criteria is None


def test_routers_and_scorers_are_not_yes_no_questions_and_are_not_linted():
    pack = PackVersion.from_document(
        pack_document(
            "p",
            1,
            [
                pack_rule("d__r", question={"type": "choice", "instructions": "Route it.",
                                            "criteria": {"a": "A", "b": "B"}}),
                pack_rule("d__s", question={"type": "score", "instructions": "Grade it.",
                                            "criteria": ["lo", "hi"]}),
            ],
        )
    )  # fmt: skip
    assert [r.question.type for r in pack.rules] == ["choice", "score"]


def test_catalog_compiler_and_loader_share_one_closed_question_lint():
    assert catalog.is_closed_question is lint.is_closed_question
    assert compiler.is_closed_question is lint.is_closed_question
    assert floor_loader.is_closed_question is lint.is_closed_question
    assert not hasattr(compiler, "CLOSED_QUESTION_STARTS")  # defined once, in lint


# ---------------------------------------------------------------------------
RULES_JSON = Path(__file__).resolve().parents[2] / "floor" / "rules.json"
TEXT = RULES_JSON.read_text(encoding="utf-8")


def _floor_text_errors(text: str) -> list[tuple[str, str | None, str | None]]:
    with pytest.raises(FloorFileError) as info:
        parse_floor_json(text)
    return [(e.path, e.key, e.field) for e in info.value.errors]


def test_parse_floor_json_uses_the_shared_strict_parser():
    assert floor_loader.scan_json_text is json_document.scan_json_text
    assert "json" not in vars(floor_loader)  # no second json.loads with its own hooks


def test_a_repeated_member_is_reported_at_its_object_with_the_rule_key_and_member():
    text = TEXT.replace('"block_at": 0.85,', '"block_at": 0.85, "block_at": 0.99,', 1)
    assert _floor_text_errors(text) == [("$.rules[0]", "p__inj_direct", "block_at")]


def test_nan_is_reported_at_its_value_with_the_rule_key_and_field():
    text = TEXT.replace('"escalate_at": 0.55', '"escalate_at": NaN', 1)
    assert _floor_text_errors(text) == [("$.rules[0].escalate_at", "p__inj_direct", "escalate_at")]


def test_every_text_problem_is_reported_in_document_order():
    text = TEXT.replace('"floor_version": 1,', '"floor_version": 1, "floor_version": 1,', 1)
    text = text.replace('"escalate_at": 0.55', '"escalate_at": Infinity', 1)
    text = text.replace('"mode": "enforce",', '"mode": "enforce", "mode": "shadow",', 2)
    assert _floor_text_errors(text) == [
        ("$", None, "floor_version"),
        ("$.rules[0]", "p__inj_direct", "mode"),
        ("$.rules[0].escalate_at", "p__inj_direct", "escalate_at"),
        ("$.rules[1]", "p__inj_indirect", "mode"),
    ]


@pytest.mark.parametrize(
    "text",
    [
        TEXT.replace('"rules": [', '"rules": [], "rules": [', 1),
        TEXT.replace('"block_at": 0.85', '"block_at": -Infinity', 1),
        "[" * 100_000 + "]" * 100_000,
        "{",
    ],
    ids=["duplicate", "infinity", "too-deep", "not-json"],
)
def test_bundles_and_the_floor_refuse_the_same_text_for_the_same_reason(text):
    _, bundle_errors = json_document.parse_json_text(text)
    floor_errors = _floor_text_errors(text)
    assert len(floor_errors) == len(bundle_errors) == 1
    assert floor_errors[0][0] == bundle_errors[0].path
