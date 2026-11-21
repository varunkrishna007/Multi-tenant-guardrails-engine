"""The bundle document, ``schema_version`` and the hash over the document as submitted
(AC-C2.2)."""

import copy
import dataclasses
import json

import pytest
from policy_fixtures import FINANCE_V2, FLOOR_V2, INSURANCE_V3, TOOLS
from pydantic import create_model

from guardrail_engine.policy import (
    CURRENT_SCHEMA_VERSION,
    SUPPORTED_SCHEMA_VERSIONS,
    Bundle,
    ErrorCode,
    FloorVersion,
    InMemoryCatalog,
    InMemoryToolRegistry,
    PackVersion,
    ParsedBundle,
    PlatformSettings,
    PolicyCompiler,
    PolicyInvalidError,
    bundle_hash,
    parse_bundle,
)
from guardrail_engine.policy import document as document_module
from guardrail_engine.policy.canonical import canonical_json

E = ErrorCode

EXTENDS = {"platform/floor@2": "sha256:" + "a" * 64, "domain/insurance@3": "sha256:" + "b" * 64}

GOLDEN_DOCUMENT = {
    "schema_version": 1,
    "tenant_id": "t_golden",
    "version": 3,
    "extends": ["platform/floor@2", "domain/insurance@3"],
    "defaults": {"block_at": 0.8, "escalate_at": 0.5},
    "rules": [
        {
            "id": "competitor",
            "guard_points": ["output"],
            "question": "Does the response mention a competitor?",
            "true_description": "Names a competitor.",
            "false_description": "Names no competitor.",
        }
    ],
}
GOLDEN_HASH = "sha256:c0689802a38cf38c1fb7762a0bc0bd003a987cef196fc94b9ee4c0079847bc4d"


# --------------------------------------------------------------------------- the hash


def test_bundle_hash_of_a_fixed_document_is_pinned():
    """A golden value. If this fails, the hash definition changed, and every hash already
    stored anywhere stops verifying. Don't update the value without a decision."""
    assert bundle_hash(GOLDEN_DOCUMENT, extends=EXTENDS) == GOLDEN_HASH
    assert parse_bundle(GOLDEN_DOCUMENT).bundle_hash(extends=EXTENDS) == GOLDEN_HASH


def test_compiled_bundle_hash_is_the_hash_of_the_submitted_document(compiler, tenant, bundle):
    extends = {v.ref: v.content_hash() for v in (FLOOR_V2, INSURANCE_V3, FINANCE_V2)}
    assert compiler.compile(bundle, tenant).bundle_hash == bundle_hash(bundle, extends=extends)


def test_adding_a_defaulted_field_to_the_model_does_not_change_the_hash(
    compiler, tenant, bundle, monkeypatch
):
    """A later build adds a defaulted field (a stand-in field, ``probe_field``)
    to the model. A document submitted before that must keep its hash."""
    before = compiler.compile(bundle, tenant).bundle_hash
    parsed_before = parse_bundle(bundle)

    grown = create_model("Bundle", __base__=Bundle, probe_field=(str | None, None))
    monkeypatch.setitem(document_module._READERS, 1, grown.model_validate)

    parsed_after = parse_bundle(bundle)
    assert "probe_field" in parsed_after.bundle.model_dump()  # the model really did change
    assert parsed_after.bundle.model_dump() != parsed_before.bundle.model_dump()
    assert parsed_after.canonical_document == parsed_before.canonical_document
    assert compiler.compile(bundle, tenant).bundle_hash == before


def test_stating_a_default_explicitly_is_a_different_document_with_a_different_hash(
    compiler, tenant, bundle
):
    assert "mode" in bundle["rules"][0]
    omitted = copy.deepcopy(bundle)
    del omitted["rules"][0]["mode"]  # "enforce" is the default
    explicit, implicit = compiler.compile(bundle, tenant), compiler.compile(omitted, tenant)

    assert explicit.guard_points == implicit.guard_points  # same meaning
    assert explicit.bundle_hash != implicit.bundle_hash  # different submitted documents


def test_key_order_whitespace_and_json_text_do_not_change_the_hash(compiler, tenant, bundle):
    base = compiler.compile(bundle, tenant).bundle_hash
    reordered = dict(reversed(list(bundle.items())))
    reordered["rules"] = [dict(reversed(list(r.items()))) for r in bundle["rules"]]
    as_text = json.dumps(reordered, indent=7)

    assert compiler.compile(reordered, tenant).bundle_hash == base
    assert compiler.compile(as_text, tenant).bundle_hash == base
    assert compiler.compile(as_text.encode(), tenant).bundle_hash == base
    assert compiler.compile(parse_bundle(as_text), tenant).bundle_hash == base


def test_number_spelling_does_not_change_the_hash_but_a_different_number_does():
    def with_block_at(text):
        document = json.dumps(GOLDEN_DOCUMENT).replace('"block_at": 0.8', f'"block_at": {text}')
        assert document != json.dumps(GOLDEN_DOCUMENT) or text == "0.8"
        return parse_bundle(document).bundle_hash(extends=EXTENDS)

    assert with_block_at("0.80") == with_block_at("8e-1") == GOLDEN_HASH
    assert with_block_at("0.81") != GOLDEN_HASH


def _keep_rules(version, n: int):
    """The same floor or pack version, read from its document with only the first n rules."""
    document = version.document
    return type(version).from_document({**document, "rules": document["rules"][:n]})


@pytest.mark.parametrize(
    "change",
    [
        lambda v: _keep_rules(v["floor"], 2),
        lambda v: _keep_rules(v["insurance"], 1),
    ],
    ids=["floor", "pack"],
)
def test_a_change_to_an_extended_catalog_versions_content_changes_the_hash(
    compiler, tenant, bundle, change
):
    changed = change({"floor": FLOOR_V2, "insurance": INSURANCE_V3})
    floors = [changed] if isinstance(changed, FloorVersion) else [FLOOR_V2]
    packs = [FINANCE_V2, changed if isinstance(changed, PackVersion) else INSURANCE_V3]
    other = PolicyCompiler(
        InMemoryCatalog(floors=floors, packs=packs),
        InMemoryToolRegistry(TOOLS),
        PlatformSettings(min_floor_version=2),
    )
    bundle["overrides"] = []
    assert compiler.compile(bundle, tenant).bundle_hash != other.compile(bundle, tenant).bundle_hash


def test_bundle_hash_refuses_a_model_so_defaults_cannot_leak_into_the_hash(bundle):
    parsed = parse_bundle(bundle)
    with pytest.raises(TypeError, match="submitted bundle document"):
        bundle_hash(parsed.bundle, extends=EXTENDS)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        bundle_hash(parsed, extends=EXTENDS)  # type: ignore[arg-type]


# --------------------------------------------------------------------------- the document


def test_parsed_bundle_keeps_the_document_exactly_as_submitted(bundle):
    parsed = parse_bundle(bundle)
    assert isinstance(parsed, ParsedBundle)
    assert parsed.document == bundle
    assert json.loads(parsed.canonical_document) == bundle
    # Nothing is filled in: the fixture's rule states no origin, and neither does the document.
    assert "origin" not in parsed.document["rules"][0]
    assert parsed.bundle.rules[0].origin == "custom"


def test_changing_the_submitted_object_afterwards_does_not_change_the_parsed_bundle(bundle):
    parsed = parse_bundle(bundle)
    before = parsed.bundle_hash(extends=EXTENDS)

    bundle["rules"].clear()
    parsed.document["rules"].clear()  # a copy each time

    assert len(parsed.document["rules"]) == 1
    assert parsed.bundle_hash(extends=EXTENDS) == before


@pytest.mark.parametrize("not_an_object", ["[1, 2]", "not json", [1, 2], 7, None])
def test_a_document_that_is_not_a_json_object_is_a_schema_error(compiler, tenant, not_an_object):
    errors = compiler.validate(not_an_object, tenant)
    assert [(e.code, e.path) for e in errors] == [(E.SCHEMA_INVALID, "$")]


@pytest.mark.parametrize("value", [float("nan"), {1, 2}, object()])
def test_a_document_with_a_non_json_value_is_a_schema_error(compiler, tenant, bundle, value):
    bundle["escalation"]["url"] = value
    assert [(e.code, e.path) for e in compiler.validate(bundle, tenant)] == [
        (E.SCHEMA_INVALID, "$")
    ]


# --------------------------------------------------------------------------- schema_version


def test_current_schema_version_is_1():
    assert CURRENT_SCHEMA_VERSION == 1
    assert SUPPORTED_SCHEMA_VERSIONS == (1,)


def test_missing_schema_version_is_rejected_with_its_own_code(compiler, tenant, bundle):
    del bundle["schema_version"]
    errors = compiler.validate(bundle, tenant)
    assert [(e.code, e.path) for e in errors] == [(E.SCHEMA_VERSION_MISSING, "$.schema_version")]
    assert E.SCHEMA_VERSION_MISSING == "bundle.schema_version_missing"
    with pytest.raises(PolicyInvalidError):
        compiler.compile(bundle, tenant)
    with pytest.raises(PolicyInvalidError):
        parse_bundle(bundle)


@pytest.mark.parametrize("value", [0, 2, 99, -1, "1", 1.0, True, None, [1]])
def test_unknown_schema_version_is_rejected_with_its_own_code(compiler, tenant, bundle, value):
    bundle["schema_version"] = value
    errors = compiler.validate(bundle, tenant)
    assert [(e.code, e.path) for e in errors] == [
        (E.SCHEMA_VERSION_UNSUPPORTED, "$.schema_version")
    ]
    assert E.SCHEMA_VERSION_UNSUPPORTED == "bundle.schema_version_unsupported"
    with pytest.raises(PolicyInvalidError):
        compiler.compile(bundle, tenant)


def test_schema_version_is_part_of_the_hashed_document():
    other = {**GOLDEN_DOCUMENT, "schema_version": 2}
    assert bundle_hash(other, extends=EXTENDS) != GOLDEN_HASH


# One of everything, stating only required fields, so every default the reader fills shows.
# The tenant id is an input echoed back, not a default: "t_1" follows the B3 id rule.
MINIMAL_V1 = {
    "schema_version": 1,
    "tenant_id": "t_1",
    "version": 1,
    "extends": ["platform/floor@1"],
    "guard_points": {"output": {}},
    "rules": [{"id": "r", "guard_points": ["output"]}],
    "overrides": [{"rule": "p__x"}],
    "deterministic": {"pii": {}, "deny_patterns": [{"id": "d", "regex": "x"}]},
}
NO_THRESHOLDS = {"block_at": None, "escalate_at": None}
DEFAULTS_BY_SCHEMA_VERSION = {
    1: {
        "schema_version": 1,
        "tenant_id": "t_1",
        "version": 1,
        "extends": ["platform/floor@1"],
        "defaults": {**NO_THRESHOLDS, "fail_mode": None},
        "guard_points": {
            "output": {
                "enabled": True,
                "max_input_tokens": None,
                "chunk_tokens": None,
                "fail_mode": None,
                "tool_allowlist": None,
                "stream_window": None,
            }
        },
        "rules": [
            {
                **NO_THRESHOLDS,
                "id": "r",
                "guard_points": ["output"],
                "question": None,
                "true_description": None,
                "false_description": None,
                "severity": "medium",
                "mode": "enforce",
                "origin": "custom",
                "template_unedited": False,
            }
        ],
        "overrides": [
            {
                **NO_THRESHOLDS,
                "rule": "p__x",
                "enabled": None,
                "mode": None,
                "question": None,
                "true_description": None,
                "false_description": None,
            }
        ],
        "deterministic": {
            "pii": {"detect": [], "action": "redact"},
            "deny_patterns": [{"id": "d", "regex": "x", "action": "block"}],
        },
        "escalation": {"target": "queue", "url": None},
        "audit": {"records_days": None, "store_content": "hash_only", "content_days": None},
    },
}


def test_every_supported_schema_version_has_a_defaults_snapshot():
    assert set(DEFAULTS_BY_SCHEMA_VERSION) == set(SUPPORTED_SCHEMA_VERSIONS)


def test_defaults_filled_in_for_schema_version_1_are_frozen():
    """Guard: the meaning of a stored version 1 document must never change. If this fails
    because a default changed or a field was added, don't update the snapshot: add a new
    schema version and pin version 1's value in its reader (see ``policy/document.py``)."""
    filled = parse_bundle(MINIMAL_V1).bundle.model_dump(mode="json")
    assert filled == DEFAULTS_BY_SCHEMA_VERSION[1]


# ---------------------------------------------------------------------------
def _strict_and_weak() -> tuple[dict, dict]:
    """Two documents differing only in one tenant rule's threshold (the probe)."""
    strict = copy.deepcopy(GOLDEN_DOCUMENT)
    weak = copy.deepcopy(GOLDEN_DOCUMENT)
    weak["rules"][0]["block_at"] = 0.99
    return strict, weak


def test_a_document_cannot_be_paired_with_a_model_read_from_another_document():
    strict, weak = _strict_and_weak()
    weak_model = parse_bundle(weak).bundle
    with pytest.raises(TypeError):
        ParsedBundle(canonical_json(strict), weak_model)  # type: ignore[call-arg]
    with pytest.raises(TypeError):
        ParsedBundle(canonical_document=canonical_json(strict), bundle=weak_model)  # type: ignore[call-arg]
    with pytest.raises(ValueError, match="init=False"):
        dataclasses.replace(parse_bundle(strict), _bundle=weak_model)  # type: ignore[call-arg]


def test_a_hand_built_parsed_bundle_reads_its_model_from_its_own_document():
    strict, weak = _strict_and_weak()
    by_hand = ParsedBundle(canonical_json(weak))
    assert by_hand == parse_bundle(weak)
    assert by_hand.bundle == parse_bundle(weak).bundle
    assert by_hand.bundle.rules[0].block_at == 0.99
    assert by_hand.bundle_hash(extends=EXTENDS) == parse_bundle(weak).bundle_hash(extends=EXTENDS)
    # replace() reads the model again, from the new document.
    swapped = dataclasses.replace(parse_bundle(strict), canonical_document=canonical_json(weak))
    assert swapped.bundle.rules[0].block_at == 0.99


@pytest.mark.parametrize(
    "raw, error",
    [
        (json.dumps(GOLDEN_DOCUMENT).encode(), ValueError),  # not canonical: whitespace
        (canonical_json(GOLDEN_DOCUMENT).replace(b"{", b'{"version":3,', 1), ValueError),
        (b"not json", ValueError),
        (b"NaN", ValueError),
        (canonical_json(GOLDEN_DOCUMENT).decode(), TypeError),  # str, not bytes
        (canonical_json([1, 2]), PolicyInvalidError),
        (canonical_json({**GOLDEN_DOCUMENT, "schema_version": 9}), PolicyInvalidError),
        (canonical_json({**GOLDEN_DOCUMENT, "rules": "none"}), PolicyInvalidError),
    ],
    ids=["whitespace", "repeated-member", "not-json", "nan", "str", "array", "version", "invalid"],
)
def test_a_parsed_bundle_cannot_be_built_from_bytes_that_are_not_a_canonical_bundle(raw, error):
    with pytest.raises(error):
        ParsedBundle(raw)


def test_changing_the_model_afterwards_cannot_change_what_is_compiled(compiler, tenant, bundle):
    parsed = parse_bundle(bundle)
    honest = compiler.compile(bundle, tenant)

    # The models are frozen, but their lists are not. A copy each time, like ``document``.
    parsed.bundle.rules.clear()
    parsed.bundle.extends.remove("domain/finance@2")

    assert len(parsed.bundle.rules) == 1
    assert "domain/finance@2" in parsed.bundle.extends
    assert compiler.compile(parsed, tenant) == honest


def _golden_text(old: str, new: str) -> str:
    text = json.dumps(GOLDEN_DOCUMENT)
    assert old in text
    return text.replace(old, new, 1)


@pytest.mark.parametrize(
    "text, path",
    [
        # The probe: a second "defaults" placed before the real one
        (_golden_text('"defaults": {', '"defaults": {"block_at": 0.1}, "defaults": {'), "$"),
        (_golden_text('"block_at": 0.8', '"block_at": 0.1, "block_at": 0.8'), "$.defaults"),
        (_golden_text('"id": "competitor"', '"id": "a", "id": "competitor"'), "$.rules[0]"),
        (_golden_text('"version": 3', '"version": 3, "version": 3'), "$"),  # even the same value
    ],
    ids=["top-level", "defaults", "rule", "same-value"],
)
def test_a_repeated_member_name_is_rejected_at_the_objects_path(text, path):
    for submitted in (text, text.encode()):
        parsed, errors = document_module.read_bundle(submitted)
        assert parsed is None
        assert [(e.code, e.path) for e in errors] == [(E.SCHEMA_DUPLICATE_MEMBER, path)]
        with pytest.raises(PolicyInvalidError) as raised:
            parse_bundle(submitted)
        assert [e.code for e in raised.value.errors] == [E.SCHEMA_DUPLICATE_MEMBER]


def test_repeated_members_have_their_own_stable_error_code(compiler, tenant, bundle):
    assert E.SCHEMA_DUPLICATE_MEMBER == "schema.duplicate_member"
    text = json.dumps(bundle).replace('"audit": {', '"audit": {"store_content": "full", ', 1)
    assert [(e.code, e.path) for e in compiler.validate(text, tenant)] == [
        (E.SCHEMA_DUPLICATE_MEMBER, "$.audit")
    ]
    with pytest.raises(PolicyInvalidError):
        compiler.compile(text, tenant)


def test_every_repeated_member_is_reported_in_document_order():
    text = _golden_text('"block_at": 0.8', '"block_at": 0.1, "block_at": 0.8')
    text = text.replace('"guard_points": [', '"guard_points": [], "guard_points": [', 1)
    text = text.replace('"tenant_id": ', '"tenant_id": "x", "tenant_id": ', 1)
    _, errors = document_module.read_bundle(text)
    assert [(e.code, e.path) for e in errors] == [
        (E.SCHEMA_DUPLICATE_MEMBER, "$"),
        (E.SCHEMA_DUPLICATE_MEMBER, "$.defaults"),
        (E.SCHEMA_DUPLICATE_MEMBER, "$.rules[0]"),
    ]
    assert "'tenant_id'" in errors[0].message


@pytest.mark.parametrize("literal", ["NaN", "Infinity", "-Infinity"])
def test_nan_and_infinity_literals_are_rejected_at_their_path(literal):
    text = _golden_text('"block_at": 0.8', f'"block_at": {literal}')
    parsed, errors = document_module.read_bundle(text)
    assert parsed is None
    assert [(e.code, e.path) for e in errors] == [(E.SCHEMA_INVALID, "$.defaults.block_at")]
    assert literal in errors[0].message


DEPTH = 100_000  # far past the JSON parser's recursion limit


def _deep_text(kind: str) -> str:
    if kind == "arrays":
        return "[" * DEPTH + "]" * DEPTH
    return '{"a":' * DEPTH + "1" + "}" * DEPTH


@pytest.mark.parametrize("kind", ["arrays", "objects"])
@pytest.mark.parametrize("where", ["whole", "member"])
def test_r7_deeply_nested_json_text_is_a_validation_error_not_an_exception(
    compiler, tenant, bundle, kind, where
):
    deep = _deep_text(kind)
    text = deep if where == "whole" else json.dumps(bundle).replace("{", '{"x": ' + deep + ",", 1)
    expected = [(E.SCHEMA_INVALID, "$")]
    for submitted in (text, text.encode()):
        parsed, errors = document_module.read_bundle(submitted)
        assert parsed is None
        assert [(e.code, e.path) for e in errors] == expected
        assert "nested too deeply" in errors[0].message
        assert [(e.code, e.path) for e in compiler.validate(submitted, tenant)] == expected
        with pytest.raises(PolicyInvalidError):
            parse_bundle(submitted)
        with pytest.raises(PolicyInvalidError):
            compiler.compile(submitted, tenant)


def test_r7_a_deeply_nested_object_or_canonical_bytes_are_a_validation_error(bundle):
    deep: list = []
    for _ in range(DEPTH):
        deep = [deep]
    bundle["x"] = deep
    parsed, errors = document_module.read_bundle(bundle)
    assert parsed is None
    assert [(e.code, e.path) for e in errors] == [(E.SCHEMA_INVALID, "$")]
    with pytest.raises(PolicyInvalidError) as raised:
        ParsedBundle(b'{"x":' + _deep_text("arrays").encode() + b"}")
    assert "nested too deeply" in raised.value.errors[0].message


def test_the_same_name_in_different_objects_is_not_a_repeat():
    document = copy.deepcopy(GOLDEN_DOCUMENT)
    document["rules"][0]["block_at"] = 0.8  # "block_at" is also a member of "defaults"
    assert parse_bundle(json.dumps(document, indent=2)) == parse_bundle(document)
    assert parse_bundle(json.dumps(GOLDEN_DOCUMENT)).bundle_hash(extends=EXTENDS) == GOLDEN_HASH
