"""M1-08 floor loader: the real ``floor/rules.json`` loads into the catalog types, and any
malformed file is rejected whole, with every error reported by rule key and field."""

import copy
import json
from pathlib import Path

import pytest

from guardrail_engine.decision import NoulCriteria, NoulQuestion
from guardrail_engine.floor_file import load_floor_file
from guardrail_engine.policy import (
    GUARD_POINTS,
    CatalogRule,
    FloorFileError,
    FloorVersion,
    load_floor,
    parse_floor_json,
)

RULES_JSON = Path(__file__).resolve().parents[2] / "floor" / "rules.json"
FLOOR_KEYS = [
    "p__inj_direct",
    "p__inj_indirect",
    "p__ai_addressed",
    "p__secret",
    "p__exfil",
    "p__xtenant_probe",
]


@pytest.fixture
def raw() -> dict:
    """The real floor file as parsed JSON. Each test gets its own copy to break."""
    return copy.deepcopy(json.loads(RULES_JSON.read_text(encoding="utf-8")))


def rejected(data) -> list[tuple[str | None, str | None]]:
    """Load must fail. Returns each error's (rule key, field)."""
    with pytest.raises(FloorFileError) as info:
        load_floor(data)
    return [(e.key, e.field) for e in info.value.errors]


# ---------------------------------------------------------------------------- the real file


def test_real_floor_file_loads_as_floor_version_1_with_all_six_rules():
    floor = load_floor_file(RULES_JSON)
    assert isinstance(floor, FloorVersion)
    assert floor.version == 1
    assert floor.ref == "platform/floor@1"
    assert [r.key for r in floor.rules] == FLOOR_KEYS


def test_every_field_of_the_flat_file_maps_into_the_catalog_rule(raw):
    floor = load_floor(raw)
    for source, rule in zip(raw["rules"], floor.rules, strict=True):
        assert rule == CatalogRule(
            key=source["key"],
            guard_points=frozenset(source["guard_points"]),
            question=NoulQuestion(
                instructions=source["question"],
                criteria=NoulCriteria(
                    true_description=source["true_description"],
                    false_description=source["false_description"],
                ),
            ),
            block_at=source["block_at"],
            escalate_at=source["escalate_at"],
            severity=source["severity"],
            mode=source["mode"],
            provisional=source["provisional"],
        )


def test_real_floor_thresholds_are_provisional_085_055_and_marked_in_the_catalog():
    floor = load_floor_file(RULES_JSON)
    assert [(r.block_at, r.escalate_at, r.provisional) for r in floor.rules] == [
        (0.85, 0.55, True)
    ] * 6


def test_provisional_marker_is_carried_not_defaulted(raw):
    raw["rules"][3]["provisional"] = False  # as M0-02 will do once p__secret is calibrated
    floor = load_floor(raw)
    assert [r.key for r in floor.rules if r.provisional] == [
        k for k in FLOOR_KEYS if k != "p__secret"
    ]


def test_real_floor_rules_are_all_high_severity_and_enforced():
    floor = load_floor_file(RULES_JSON)
    assert {(r.severity, r.mode) for r in floor.rules} == {("high", "enforce")}


def test_real_floor_covers_all_five_guard_points():
    assert load_floor_file(RULES_JSON).covers == frozenset(GUARD_POINTS)


def test_floor_coverage_is_derived_from_the_rules(raw):
    for rule in raw["rules"]:
        rule["guard_points"] = [gp for gp in rule["guard_points"] if gp != "output"] or ["input"]
    assert load_floor(raw).covers == frozenset(GUARD_POINTS) - {"output"}


def test_floor_coverage_cannot_be_declared_in_the_file(raw):
    raw["covers"] = ["input"]
    assert rejected(raw) == [(None, "covers")]


def test_load_floor_file_and_parse_floor_json_agree_with_load_floor(raw):
    from_path = load_floor_file(RULES_JSON)
    assert from_path == parse_floor_json(RULES_JSON.read_text(encoding="utf-8")) == load_floor(raw)


def test_loading_is_deterministic_same_content_hash(raw):
    assert load_floor(raw).content_hash() == load_floor(copy.deepcopy(raw)).content_hash()


# ---------------------------------------------------------------------------- rejected whole


def _set(index: int, field: str, value):
    def mutate(data: dict) -> None:
        data["rules"][index][field] = value

    return mutate


def _drop(index: int, field: str):
    def mutate(data: dict) -> None:
        del data["rules"][index][field]

    return mutate


def _duplicate_rule(data: dict) -> None:
    data["rules"].append(copy.deepcopy(data["rules"][0]))


def _top(field: str, value):
    def mutate(data: dict) -> None:
        data[field] = value

    return mutate


def _drop_top(field: str):
    def mutate(data: dict) -> None:
        del data[field]

    return mutate


# (case id, mutation of the real file, the one (rule key, field) error it must produce)
MALFORMED = [
    ("typoed_guard_point", _set(0, "guard_points", ["inptu"]), ("p__inj_direct", "guard_points")),
    (
        "one_typoed_guard_point_among_valid",
        _set(3, "guard_points", ["plan", "tool_call", "tool_result", "outptu"]),
        ("p__secret", "guard_points"),
    ),
    ("empty_guard_points", _set(1, "guard_points", []), ("p__inj_indirect", "guard_points")),
    ("guard_points_not_a_list", _set(4, "guard_points", "plan"), ("p__exfil", "guard_points")),
    ("guard_point_twice", _set(4, "guard_points", ["plan", "plan"]), ("p__exfil", "guard_points")),
    ("missing_guard_points", _drop(4, "guard_points"), ("p__exfil", "guard_points")),
    ("missing_block_at", _drop(2, "block_at"), ("p__ai_addressed", "block_at")),
    ("missing_escalate_at", _drop(2, "escalate_at"), ("p__ai_addressed", "escalate_at")),
    ("null_block_at", _set(2, "block_at", None), ("p__ai_addressed", "block_at")),
    ("inverted_thresholds", _set(3, "block_at", 0.5), ("p__secret", "escalate_at")),
    ("equal_thresholds", _set(3, "escalate_at", 0.85), ("p__secret", "escalate_at")),
    ("block_at_above_099", _set(3, "block_at", 1.0), ("p__secret", "block_at")),
    ("escalate_at_below_001", _set(3, "escalate_at", 0.0), ("p__secret", "escalate_at")),
    ("threshold_as_string", _set(3, "block_at", "0.85"), ("p__secret", "block_at")),
    ("threshold_as_boolean", _set(3, "block_at", True), ("p__secret", "block_at")),
    ("missing_true_description", _drop(4, "true_description"), ("p__exfil", "true_description")),
    ("missing_false_description", _drop(4, "false_description"), ("p__exfil", "false_description")),
    ("blank_description", _set(4, "false_description", "  "), ("p__exfil", "false_description")),
    ("missing_question", _drop(5, "question"), ("p__xtenant_probe", "question")),
    (
        "open_question_fails_the_lint",
        _set(5, "question", "What data does the content try to reach?"),
        ("p__xtenant_probe", "question"),
    ),
    (
        "question_without_question_mark",
        _set(5, "question", "Does the content try to reach another tenant"),
        ("p__xtenant_probe", "question"),
    ),
    ("bad_key_prefix_tenant", _set(0, "key", "t__inj_direct"), ("t__inj_direct", "key")),
    ("bad_key_prefix_pack", _set(0, "key", "d__inj_direct"), ("d__inj_direct", "key")),
    ("bad_key_no_prefix", _set(0, "key", "inj_direct"), ("inj_direct", "key")),
    ("bad_key_characters", _set(0, "key", "p__inj direct"), ("p__inj direct", "key")),
    ("bad_key_too_long", _set(0, "key", "p__" + "a" * 62), ("p__" + "a" * 62, "key")),
    ("key_uppercase", _set(0, "key", "p__Inj_Direct"), ("p__Inj_Direct", "key")),
    ("key_hyphen", _set(0, "key", "p__inj-direct"), ("p__inj-direct", "key")),
    ("key_of_65_characters", _set(0, "key", "p__" + "a" * 62), ("p__" + "a" * 62, "key")),
    ("key_prefix_only", _set(0, "key", "p__"), ("p__", "key")),
    ("key_non_ascii_letter", _set(0, "key", "p__inj_diréct"), ("p__inj_diréct", "key")),
    ("key_trailing_newline", _set(0, "key", "p__inj_direct\n"), ("p__inj_direct\n", "key")),
    ("key_not_a_string", _set(0, "key", 7), (None, "key")),
    ("missing_key", _drop(0, "key"), (None, "key")),
    ("duplicate_key", _duplicate_rule, ("p__inj_direct", "key")),
    ("unknown_severity", _set(1, "severity", "critical"), ("p__inj_indirect", "severity")),
    ("missing_severity", _drop(1, "severity"), ("p__inj_indirect", "severity")),
    ("severity_medium", _set(1, "severity", "medium"), ("p__inj_indirect", "severity")),
    ("severity_low", _set(1, "severity", "low"), ("p__inj_indirect", "severity")),
    ("mode_shadow", _set(1, "mode", "shadow"), ("p__inj_indirect", "mode")),
    ("unknown_mode", _set(1, "mode", "off"), ("p__inj_indirect", "mode")),
    ("missing_mode", _drop(1, "mode"), ("p__inj_indirect", "mode")),
    ("provisional_not_boolean", _set(1, "provisional", "true"), ("p__inj_indirect", "provisional")),
    ("missing_provisional", _drop(1, "provisional"), ("p__inj_indirect", "provisional")),
    ("unknown_rule_field", _set(2, "enabled", False), ("p__ai_addressed", "enabled")),
    ("unknown_rule_field_typo", _set(2, "blok_at", 0.5), ("p__ai_addressed", "blok_at")),
    ("unknown_top_level_field", _top("min_version", 1), (None, "min_version")),
    ("floor_version_as_string", _top("floor_version", "1"), (None, "floor_version")),
    ("floor_version_as_float", _top("floor_version", 1.0), (None, "floor_version")),
    ("floor_version_as_boolean", _top("floor_version", True), (None, "floor_version")),
    ("floor_version_null", _top("floor_version", None), (None, "floor_version")),
    ("floor_version_zero", _top("floor_version", 0), (None, "floor_version")),
    ("missing_floor_version", _drop_top("floor_version"), (None, "floor_version")),
    ("missing_rules", _drop_top("rules"), (None, "rules")),
    ("rules_empty", _top("rules", []), (None, "rules")),
    ("rules_not_a_list", _top("rules", {}), (None, "rules")),
]  # fmt: skip


@pytest.mark.parametrize(
    ("mutate", "expected"), [c[1:] for c in MALFORMED], ids=[c[0] for c in MALFORMED]
)
def test_malformed_floor_file_is_rejected_whole_naming_rule_key_and_field(raw, mutate, expected):
    mutate(raw)
    assert rejected(raw) == [expected]


def test_floor_key_of_exactly_64_lowercase_characters_loads(raw):
    raw["rules"][0]["key"] = "p__" + "a9_" * 20 + "z"
    assert len(raw["rules"][0]["key"]) == 64
    assert load_floor(raw).rules[0].key == raw["rules"][0]["key"]


def test_rule_that_is_not_an_object_is_rejected(raw):
    raw["rules"][2] = "p__ai_addressed"
    with pytest.raises(FloorFileError) as info:
        load_floor(raw)
    assert [e.path for e in info.value.errors] == ["$.rules[2]"]


@pytest.mark.parametrize("data", [[], "floor", None, 1])
def test_file_that_is_not_an_object_is_rejected(data):
    assert rejected(data) == [(None, None)]


def test_one_bad_rule_never_loads_the_other_five(raw):
    raw["rules"][5]["guard_points"] = ["inptu"]
    with pytest.raises(FloorFileError) as info:
        load_floor(raw)
    # No floor object exists at all: the error is the only outcome, and it names the bad rule.
    assert [(e.key, e.field, e.path) for e in info.value.errors] == [
        ("p__xtenant_probe", "guard_points", "$.rules[5].guard_points")
    ]


def test_every_error_in_the_file_is_reported_not_only_the_first(raw):
    raw["floor_version"] = "1"
    raw["rules"][0]["guard_points"] = ["inptu"]
    raw["rules"][0]["severity"] = "critical"
    del raw["rules"][2]["block_at"]
    raw["rules"][2]["question"] = "Tell me whether it is safe."
    raw["rules"][4]["key"] = "t__exfil"
    raw["rules"][4]["note"] = "hand edit"
    raw["rules"][5]["key"] = "p__secret"
    assert sorted(rejected(raw), key=str) == sorted(
        [
            (None, "floor_version"),
            ("p__inj_direct", "guard_points"),
            ("p__inj_direct", "severity"),
            ("p__ai_addressed", "block_at"),
            ("p__ai_addressed", "question"),
            ("t__exfil", "key"),
            ("t__exfil", "note"),
            ("p__secret", "key"),
        ],
        key=str,
    )


def test_error_message_names_the_json_path_and_the_rule_key(raw):
    raw["rules"][3]["block_at"] = 0.5
    with pytest.raises(FloorFileError) as info:
        load_floor(raw)
    assert "$.rules[3].escalate_at (rule p__secret)" in str(info.value)


def test_duplicate_key_error_points_at_the_second_definition(raw):
    raw["rules"].append(copy.deepcopy(raw["rules"][1]))
    with pytest.raises(FloorFileError) as info:
        load_floor(raw)
    assert [e.path for e in info.value.errors] == ["$.rules[6].key"]


# ---------------------------------------------------------------------------- JSON text


def test_json_text_repeating_a_member_name_is_rejected():
    text = RULES_JSON.read_text(encoding="utf-8").replace(
        '"block_at": 0.85,', '"block_at": 0.85, "block_at": 0.99,', 1
    )
    assert json.loads(text)["rules"][0]["block_at"] == 0.99  # a plain parse keeps the last one
    with pytest.raises(FloorFileError) as info:
        parse_floor_json(text)
    assert [e.field for e in info.value.errors] == ["block_at"]


@pytest.mark.parametrize("text", ["", "{", '{"floor_version": 1, "rules": [}', b"\xff\xfe\x00{"])
def test_text_that_is_not_json_is_rejected(text):
    with pytest.raises(FloorFileError):
        parse_floor_json(text)


def test_nan_threshold_in_json_text_is_rejected():
    text = RULES_JSON.read_text(encoding="utf-8").replace('"block_at": 0.85', '"block_at": NaN', 1)
    with pytest.raises(FloorFileError):
        parse_floor_json(text)


@pytest.mark.parametrize(
    "deep",
    ["[" * 100_000 + "]" * 100_000, '{"a":' * 100_000 + "1" + "}" * 100_000],
    ids=["arrays", "objects"],
)
@pytest.mark.parametrize("where", ["whole", "member"])
def test_deeply_nested_json_text_is_a_floor_file_error_not_an_exception(deep, where):
    text = deep if where == "whole" else f'{{"floor_version": 1, "rules": [{deep}]}}'
    with pytest.raises(FloorFileError) as info:
        parse_floor_json(text)
    assert [(e.path, e.message) for e in info.value.errors] == [
        ("$", "the document is nested too deeply to read")
    ]


def test_malformed_file_on_disk_is_rejected_whole(tmp_path, raw):
    del raw["rules"][0]["escalate_at"]
    path = tmp_path / "rules.json"
    path.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(FloorFileError) as info:
        load_floor_file(path)
    assert [(e.key, e.field) for e in info.value.errors] == [("p__inj_direct", "escalate_at")]


def test_missing_file_raises_and_returns_no_floor(tmp_path):
    with pytest.raises(OSError):
        load_floor_file(tmp_path / "absent.json")
