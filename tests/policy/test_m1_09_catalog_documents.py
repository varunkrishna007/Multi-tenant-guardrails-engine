"""M1-09: floor and pack content hashes over the catalog source document as loaded.

The content hash of a floor or pack version (an input to every ``bundle_hash``, AC-C2.2)
covers the canonical JSON of its source document as written, never the model read from it.
Source documents carry a required ``schema_version``, and the defaults a reader fills in are
fixed per schema version. The same mechanism as the bundle document.
"""

import copy
import dataclasses
import hashlib
import json
from pathlib import Path

import pytest
from policy_fixtures import (
    FINANCE_V2,
    FLOOR_V2,
    INSURANCE_V3,
    INSURANCE_V3_DOCUMENT,
    TOOLS,
    floor_document,
    floor_rule,
    grow_the_catalog_rule_model,
    make_catalog,
    valid_bundle,
)
from pydantic import ValidationError

from guardrail_engine.floor_file import load_floor_file
from guardrail_engine.policy import (
    CURRENT_FLOOR_SCHEMA_VERSION,
    CURRENT_PACK_SCHEMA_VERSION,
    SUPPORTED_FLOOR_SCHEMA_VERSIONS,
    SUPPORTED_PACK_SCHEMA_VERSIONS,
    CatalogDocumentError,
    ErrorCode,
    FloorFileError,
    FloorVersion,
    InMemoryCatalog,
    InMemoryToolRegistry,
    PackVersion,
    PlatformSettings,
    PolicyCompiler,
    TenantAttributes,
    bundle_hash,
    canonical_json,
    load_floor,
    parse_floor_json,
    sha256_of,
)

E = ErrorCode
RULES_JSON = Path(__file__).resolve().parents[2] / "floor" / "rules.json"

FLOOR_1_CONTENT_HASH = "sha256:6be8bf5708e5fbcec61d6089494157effdbf13d05aaf0bc5f18ecd7347842b23"
"""Golden: the content hash of the real ``floor/rules.json`` (``platform/floor@1``). If this
fails, either the file changed (which needs a new floor version, never an edit to floor@1)
or the hash definition changed, and every stored bundle extending floor@1 stops verifying.
Don't update it without a decision."""

DOGFOOD = TenantAttributes(tenant_id="t_dogfood")
ACME = TenantAttributes(tenant_id="t_acmeins")


def raw_floor() -> dict:
    return json.loads(RULES_JSON.read_text(encoding="utf-8"))


def dogfood_bundle() -> dict:
    return {
        "schema_version": 1,
        "tenant_id": "t_dogfood",
        "version": 1,
        "extends": ["platform/floor@1"],
    }


def dogfood_bundle_hash(floor: FloorVersion) -> str:
    compiler = PolicyCompiler(InMemoryCatalog(floors=[floor]), InMemoryToolRegistry())
    return compiler.compile(dogfood_bundle(), DOGFOOD).bundle_hash


def fixture_bundle_hash(bundle: dict | None = None) -> str:
    """The fixture bundle (extends floor@2, insurance@3, finance@2) against a catalog read
    afresh from its documents."""
    compiler = PolicyCompiler(
        make_catalog(), InMemoryToolRegistry(TOOLS), PlatformSettings(min_floor_version=2)
    )
    return compiler.compile(bundle or valid_bundle(), ACME).bundle_hash


def reordered(value):
    """The same JSON value with every object's keys in reverse order."""
    if isinstance(value, dict):
        return {k: reordered(v) for k, v in reversed(list(value.items()))}
    if isinstance(value, list):
        return [reordered(v) for v in value]
    return value


# --------------------------------------------------------------------------- story test (1)


def test_m1_09_adding_a_defaulted_field_to_the_catalog_rule_model_leaves_floor_1s_hash_unchanged(
    monkeypatch,
):
    before = load_floor_file(RULES_JSON)
    model_hash_before = sha256_of(before.content.model_dump(mode="json"))

    grow_the_catalog_rule_model(monkeypatch)
    after = load_floor_file(RULES_JSON)

    assert "probe_field" in after.rules[0].model_dump()  # the model really did change
    # ...so a hash over the model (the definition before M1-09) would have moved:
    assert sha256_of(after.content.model_dump(mode="json")) != model_hash_before
    assert after.canonical_document == before.canonical_document
    assert after.content_hash() == before.content_hash() == FLOOR_1_CONTENT_HASH


def test_m1_09_adding_a_defaulted_field_to_the_catalog_rule_model_leaves_bundle_hashes_unchanged(
    monkeypatch,
):
    floor_before = load_floor_file(RULES_JSON)
    dogfood_before = dogfood_bundle_hash(floor_before)
    fixture_before = fixture_bundle_hash()
    catalog_before = make_catalog()
    refs = [("floor", 1), ("floor", 2), ("insurance", 3), ("finance", 2), ("healthcare", 1)]

    def content_hashes(catalog):
        return [
            (catalog.floor(n) if name == "floor" else catalog.pack(name, n)).content_hash()
            for name, n in refs
        ]

    hashes_before = content_hashes(catalog_before)

    grow_the_catalog_rule_model(monkeypatch)
    catalog_after = make_catalog()

    assert "probe_field" in catalog_after.pack("insurance", 3).rules[0].model_dump()
    assert content_hashes(catalog_after) == hashes_before  # every floor and pack version
    assert dogfood_bundle_hash(load_floor_file(RULES_JSON)) == dogfood_before  # floor@1
    assert fixture_bundle_hash() == fixture_before  # floor@2 + two packs


# --------------------------------------------------------------------------- story test (2)


def test_m1_09_real_floor_content_hash_is_pinned():
    assert load_floor_file(RULES_JSON).content_hash() == FLOOR_1_CONTENT_HASH


def test_m1_09_content_hash_is_sha256_over_the_canonical_source_document():
    floor = load_floor_file(RULES_JSON)
    document = raw_floor()
    assert floor.document == document  # as written: nothing added, nothing filled in
    assert floor.canonical_document == canonical_json(document)
    expected = "sha256:" + hashlib.sha256(canonical_json(document)).hexdigest()
    assert floor.content_hash() == sha256_of(document) == expected
    for pack in (INSURANCE_V3, FINANCE_V2):
        assert pack.content_hash() == sha256_of(pack.document)


@pytest.mark.parametrize("indent", [None, 1, 7])
def test_m1_09_key_order_and_whitespace_do_not_change_the_real_floor_hash(indent):
    text = json.dumps(reordered(raw_floor()), indent=indent, ensure_ascii=indent is None)
    assert parse_floor_json(text).content_hash() == FLOOR_1_CONTENT_HASH
    assert parse_floor_json(text.encode()).content_hash() == FLOOR_1_CONTENT_HASH
    assert load_floor(json.loads(text)).content_hash() == FLOOR_1_CONTENT_HASH


def test_m1_09_number_spelling_does_not_change_the_hash_as_for_bundles():
    text = RULES_JSON.read_text(encoding="utf-8")
    assert '"block_at": 0.85,' in text
    respelled = text.replace('"block_at": 0.85,', '"block_at": 0.850,').replace(
        '"escalate_at": 0.55,', '"escalate_at": 55e-2,'
    )
    assert parse_floor_json(respelled).content_hash() == FLOOR_1_CONTENT_HASH


def test_m1_09_key_order_does_not_change_a_pack_hash():
    assert PackVersion.from_document(reordered(INSURANCE_V3_DOCUMENT)) == INSURANCE_V3
    assert (
        PackVersion.from_document(reordered(INSURANCE_V3_DOCUMENT)).content_hash()
        == INSURANCE_V3.content_hash()
    )


def _rule(i: int, field: str, value):
    def change(document: dict) -> None:
        document["rules"][i][field] = value

    return change


def _swap_rules(document: dict) -> None:
    document["rules"][0], document["rules"][1] = document["rules"][1], document["rules"][0]


def _reverse_guard_points(document: dict) -> None:
    rule = document["rules"][2]  # p__ai_addressed: input, tool_result, output
    assert len(rule["guard_points"]) == 3
    rule["guard_points"].reverse()


FLOOR_CHANGES = [
    ("block_at", _rule(0, "block_at", 0.84)),
    ("escalate_at", _rule(5, "escalate_at", 0.54)),
    ("provisional", _rule(3, "provisional", False)),
    (
        "question_one_character",
        _rule(1, "question", raw_floor()["rules"][1]["question"][:-1] + " ?"),
    ),
    ("true_description", _rule(4, "true_description", "Sends data out.")),
    ("false_description", _rule(4, "false_description", "Sends nothing out.")),
    ("guard_point_added", _rule(0, "guard_points", ["input", "output"])),
    # Same meaning (guard points are a set), different document: a content change all the same.
    ("guard_point_order", _reverse_guard_points),
    ("rule_order", _swap_rules),
    ("rule_removed", lambda d: d["rules"].pop()),
    ("floor_version", lambda d: d.update(floor_version=2)),
]


@pytest.mark.parametrize("change", [c[1] for c in FLOOR_CHANGES], ids=[c[0] for c in FLOOR_CHANGES])
def test_m1_09_any_content_change_to_the_floor_document_changes_its_hash(change):
    document = raw_floor()
    change(document)
    changed = load_floor(document)  # still a valid floor
    assert changed.content_hash() != FLOOR_1_CONTENT_HASH


def test_m1_09_every_floor_content_change_gives_its_own_hash():
    hashes = set()
    for _, change in FLOOR_CHANGES:
        document = raw_floor()
        change(document)
        hashes.add(load_floor(document).content_hash())
    assert len(hashes) == len(FLOOR_CHANGES)


def _pack_rule(i: int, **changes):
    def change(document: dict) -> None:
        document["rules"][i].update(changes)

    return change


PACK_CHANGES = [
    ("threshold", _pack_rule(0, block_at=0.79)),
    ("criteria_text", lambda d: d["rules"][1]["question"]["criteria"].update(in_scope="Claims.")),
    ("severity", _pack_rule(1, severity="medium")),
    # Stating a default explicitly is a different document (AC-C2.2), as for bundles.
    ("default_stated", _pack_rule(0, mode="enforce")),
    ("retention_added", lambda d: d.update(retention=FINANCE_V2.document["retention"])),
    ("name", lambda d: d.update(name="insurance_b")),
]


@pytest.mark.parametrize("change", [c[1] for c in PACK_CHANGES], ids=[c[0] for c in PACK_CHANGES])
def test_m1_09_any_content_change_to_a_pack_document_changes_its_hash(change):
    document = copy.deepcopy(INSURANCE_V3_DOCUMENT)
    change(document)
    assert PackVersion.from_document(document).content_hash() != INSURANCE_V3.content_hash()


def test_m1_09_a_floor_content_change_changes_the_hash_of_every_bundle_extending_it():
    document = raw_floor()
    document["rules"][0]["block_at"] = 0.84
    assert dogfood_bundle_hash(load_floor(document)) != dogfood_bundle_hash(
        load_floor_file(RULES_JSON)
    )


# --------------------------------------------------------------------------- story test (3)


def test_m1_09_the_real_floor_file_states_schema_version_1():
    assert raw_floor()["schema_version"] == 1
    assert next(iter(raw_floor())) == "schema_version"  # the one member added, placed first


def test_m1_09_floor_file_without_schema_version_is_rejected():
    document = raw_floor()
    del document["schema_version"]
    with pytest.raises(FloorFileError) as info:
        load_floor(document)
    # Reported on its own: without a schema version the rest of the file can't be read.
    assert [(e.path, e.key, e.field) for e in info.value.errors] == [
        ("$.schema_version", None, "schema_version")
    ]
    assert "missing required field" in str(info.value)
    with pytest.raises(FloorFileError):
        parse_floor_json(json.dumps(document))


def test_m1_09_floor_or_pack_document_without_schema_version_is_rejected():
    for build, document in (
        (FloorVersion.from_document, raw_floor()),
        (PackVersion.from_document, copy.deepcopy(INSURANCE_V3_DOCUMENT)),
    ):
        del document["schema_version"]
        with pytest.raises(CatalogDocumentError) as info:
            build(document)
        assert [(e.code, e.path) for e in info.value.errors] == [
            (E.CATALOG_SCHEMA_VERSION_MISSING, "$.schema_version")
        ]
    assert E.CATALOG_SCHEMA_VERSION_MISSING == "catalog.schema_version_missing"


UNSUPPORTED = [0, 3, 99, -1, "1", 1.0, True, None, [1]]
"""Not supported by a floor or a pack (a floor has only version 1; a pack has 1 and 2)."""


@pytest.mark.parametrize("floor_only", [2])
def test_m1_09_floor_has_no_schema_version_2(floor_only):
    document = raw_floor()
    document["schema_version"] = floor_only
    with pytest.raises(FloorFileError):
        load_floor(document)


@pytest.mark.parametrize("value", UNSUPPORTED)
def test_m1_09_floor_file_with_unsupported_schema_version_is_rejected(value):
    document = raw_floor()
    document["schema_version"] = value
    with pytest.raises(FloorFileError) as info:
        load_floor(document)
    assert [(e.path, e.field) for e in info.value.errors] == [
        ("$.schema_version", "schema_version")
    ]
    assert "not supported" in str(info.value)


@pytest.mark.parametrize("value", UNSUPPORTED)
def test_m1_09_floor_or_pack_document_with_unsupported_schema_version_is_rejected(value):
    for build, document in (
        (FloorVersion.from_document, raw_floor()),
        (PackVersion.from_document, copy.deepcopy(INSURANCE_V3_DOCUMENT)),
    ):
        document["schema_version"] = value
        with pytest.raises(CatalogDocumentError) as info:
            build(document)
        assert [(e.code, e.path) for e in info.value.errors] == [
            (E.CATALOG_SCHEMA_VERSION_UNSUPPORTED, "$.schema_version")
        ]


# --------------------------------------------------------------------------- defaults per version


def test_m1_09_current_catalog_schema_versions():
    """Floors: 1. Packs: 1, and 2 (M4-10: max_action, per_rule_optional, description)."""
    assert SUPPORTED_FLOOR_SCHEMA_VERSIONS == (1,) and CURRENT_FLOOR_SCHEMA_VERSION == 1
    assert SUPPORTED_PACK_SCHEMA_VERSIONS == (1, 2) and CURRENT_PACK_SCHEMA_VERSION == 2


# Each pair is a document stating only what its schema version requires, and the content the
# reader fills in from it, so every default shows. A version 1 floor document has no
# optional field; its snapshot still catches a catalog rule field the flat format lacks.
FLOOR_DEFAULTS_BY_SCHEMA_VERSION = {
    1: [
        (
            {
                "schema_version": 1,
                "floor_version": 1,
                "rules": [
                    {
                        "key": "p__r",
                        "question": "Is it?",
                        "true_description": "Yes.",
                        "false_description": "No.",
                        "guard_points": ["output", "input"],
                        "severity": "high",
                        "block_at": 0.8,
                        "escalate_at": 0.5,
                        "mode": "enforce",
                        "provisional": True,
                    }
                ],
            },
            {
                "version": 1,
                "rules": [
                    {
                        "key": "p__r",
                        "guard_points": ["input", "output"],
                        "question": {
                            "type": "noul",
                            "instructions": "Is it?",
                            "criteria": {"true_description": "Yes.", "false_description": "No."},
                        },
                        "block_at": 0.8,
                        "escalate_at": 0.5,
                        "severity": "high",
                        "mode": "enforce",
                        "provisional": True,
                    }
                ],
            },
        ),
    ],
}
PACK_DEFAULTS_BY_SCHEMA_VERSION = {
    1: [
        (
            {
                "schema_version": 1,
                "name": "p",
                "version": 1,
                "rules": [
                    {
                        "key": "d__n",
                        "guard_points": ["output"],
                        "question": {"type": "noul", "instructions": "Is it?"},
                        "block_at": 0.8,
                        "escalate_at": 0.5,
                    },
                    {
                        "key": "d__c",
                        "guard_points": ["input"],
                        "question": {
                            "type": "choice",
                            "instructions": "Route?",
                            "criteria": {"a": "A", "b": "B"},
                        },
                    },
                ],
            },
            {
                "name": "p",
                "version": 1,
                "rules": [
                    {
                        "key": "d__n",
                        "guard_points": ["output"],
                        "question": {"type": "noul", "instructions": "Is it?", "criteria": None},
                        "block_at": 0.8,
                        "escalate_at": 0.5,
                        "severity": "high",
                        "mode": "enforce",
                        "provisional": False,
                    },
                    {
                        "key": "d__c",
                        "guard_points": ["input"],
                        "question": {
                            "type": "choice",
                            "instructions": "Route?",
                            "criteria": {"a": "A", "b": "B"},
                        },
                        "block_at": None,
                        "escalate_at": None,
                        "severity": "high",
                        "mode": "enforce",
                        "provisional": False,
                    },
                ],
                "retention": None,
            },
        ),
        (
            {
                "schema_version": 1,
                "name": "p",
                "version": 1,
                "rules": [],
                "retention": {
                    "records_min_days": 1,
                    "records_max_days": 3,
                    "records_default_days": 2,
                    "content_max_days": 4,
                },
            },
            {
                "name": "p",
                "version": 1,
                "rules": [],
                "retention": {
                    "records_min_days": 1,
                    "records_max_days": 3,
                    "records_default_days": 2,
                    "content_max_days": 4,
                    "content_default_days": 30,
                    "content_requires_baa": False,
                },
            },
        ),
    ],
    2: [
        (
            {
                "schema_version": 2,
                "name": "p",
                "version": 1,
                "rules": [
                    {
                        "key": "d__n",
                        "guard_points": ["output"],
                        "question": {"type": "noul", "instructions": "Is it?"},
                        "block_at": 0.8,
                        "escalate_at": 0.5,
                    },
                ],
            },
            {
                "name": "p",
                "version": 1,
                "rules": [
                    {
                        "key": "d__n",
                        "guard_points": ["output"],
                        "question": {"type": "noul", "instructions": "Is it?", "criteria": None},
                        "block_at": 0.8,
                        "escalate_at": 0.5,
                        "severity": "high",
                        "mode": "enforce",
                        "provisional": False,
                    },
                ],
                "retention": None,
            },
        ),
        (  # what version 2 adds, stated: the defaults of its three new fields are not dumped
            {
                "schema_version": 2,
                "name": "p",
                "version": 1,
                "per_rule_optional": True,
                "description": "A pack.",
                "rules": [
                    {
                        "key": "d__n",
                        "guard_points": ["output"],
                        "question": {"type": "noul", "instructions": "Is it?"},
                        "block_at": 0.99,
                        "escalate_at": 0.5,
                        "max_action": "escalate",
                    },
                ],
            },
            {
                "name": "p",
                "version": 1,
                "per_rule_optional": True,
                "description": "A pack.",
                "rules": [
                    {
                        "key": "d__n",
                        "guard_points": ["output"],
                        "question": {"type": "noul", "instructions": "Is it?", "criteria": None},
                        "block_at": 0.99,
                        "escalate_at": 0.5,
                        "severity": "high",
                        "mode": "enforce",
                        "provisional": False,
                        "max_action": "escalate",
                    },
                ],
                "retention": None,
            },
        ),
    ],
}


def test_m1_09_every_supported_catalog_schema_version_has_a_defaults_snapshot():
    assert set(FLOOR_DEFAULTS_BY_SCHEMA_VERSION) == set(SUPPORTED_FLOOR_SCHEMA_VERSIONS)
    assert set(PACK_DEFAULTS_BY_SCHEMA_VERSION) == set(SUPPORTED_PACK_SCHEMA_VERSIONS)


@pytest.mark.parametrize(
    ("build", "document", "filled"),
    [
        *((FloorVersion, d, f) for d, f in FLOOR_DEFAULTS_BY_SCHEMA_VERSION[1]),
        *((PackVersion, d, f) for d, f in PACK_DEFAULTS_BY_SCHEMA_VERSION[1]),
    ],
    ids=["floor", "pack", "pack-retention"],
)
def test_m1_09_defaults_filled_in_for_catalog_schema_version_1_are_frozen(build, document, filled):
    """Guard: the meaning of a registered version 1 floor or pack document must never change.
    If this fails because a default changed or a field was added to a catalog model, don't
    update the snapshot: add a new schema version and pin version 1's value in its reader
    (see "source documents" in ``policy/catalog.py``)."""
    version = build.from_document(document)
    assert version.content.model_dump(mode="json") == filled
    assert version.document == document  # and nothing was filled into the document


@pytest.mark.parametrize(
    ("document", "filled"), PACK_DEFAULTS_BY_SCHEMA_VERSION[2], ids=["bare", "full"]
)
def test_m1_09_defaults_filled_in_for_pack_schema_version_2_are_frozen(document, filled):
    version = PackVersion.from_document(document)
    assert version.content.model_dump(mode="json") == filled
    assert version.document == document


@pytest.mark.parametrize(
    "extra",
    [{"per_rule_optional": True}, {"description": "x"}],
    ids=["per_rule_optional", "description"],
)
def test_m1_09_a_version_1_pack_document_cannot_name_what_version_2_added(extra):
    document = copy.deepcopy(INSURANCE_V3_DOCUMENT) | extra
    with pytest.raises(ValueError, match="schema version 1"):
        PackVersion.from_document(document)
    document = copy.deepcopy(INSURANCE_V3_DOCUMENT)
    document["rules"][0]["max_action"] = "escalate"
    with pytest.raises(ValueError, match="schema version 1"):
        PackVersion.from_document(document)


def test_m1_09_a_version_1_pack_means_block_with_no_cap_whatever_the_model_defaults_to():
    version = PackVersion.from_document(copy.deepcopy(INSURANCE_V3_DOCUMENT))
    assert {r.max_action for r in version.rules} == {"block"}
    assert version.per_rule_optional is False and version.description == ""


# --------------------------------------------------------------------------- document and model


def test_m1_09_a_floor_or_pack_cannot_be_built_from_a_model_any_more():
    floor = load_floor_file(RULES_JSON)
    with pytest.raises(TypeError):
        FloorVersion(version=1, rules=floor.rules)  # type: ignore[call-arg]
    with pytest.raises(TypeError):
        PackVersion(name="insurance", version=3, rules=INSURANCE_V3.rules)  # type: ignore[call-arg]


def _strict_and_weak() -> tuple[dict, dict]:
    """Two floor documents differing only in one rule's threshold."""
    strict, weak = raw_floor(), raw_floor()
    weak["rules"][0]["block_at"] = 0.99
    return strict, weak


def test_m1_09_a_floor_cannot_pair_its_document_with_content_read_from_another_document():
    strict, weak = _strict_and_weak()
    weak_content = FloorVersion.from_document(weak).content
    with pytest.raises(TypeError):
        FloorVersion(canonical_json(strict), weak_content)  # type: ignore[call-arg]
    with pytest.raises(TypeError):
        FloorVersion(canonical_document=canonical_json(strict), _content=weak_content)  # type: ignore[call-arg]
    with pytest.raises(ValueError, match="init=False"):
        dataclasses.replace(FloorVersion.from_document(strict), _content=weak_content)  # type: ignore[call-arg]


def test_m1_09_a_pack_cannot_pair_its_document_with_content_read_from_another_document():
    other = PackVersion.from_document({**INSURANCE_V3_DOCUMENT, "rules": []})
    with pytest.raises(TypeError):
        PackVersion(INSURANCE_V3.canonical_document, other.content)  # type: ignore[call-arg]
    with pytest.raises(ValueError, match="init=False"):
        dataclasses.replace(INSURANCE_V3, _content=other.content)  # type: ignore[call-arg]


def test_m1_09_a_hand_built_version_reads_its_content_from_its_own_document():
    strict, weak = _strict_and_weak()
    by_hand = FloorVersion(canonical_json(weak))
    assert by_hand == FloorVersion.from_document(weak)
    assert by_hand.rules[0].block_at == 0.99
    assert by_hand.content_hash() == sha256_of(weak)
    swapped = dataclasses.replace(
        FloorVersion.from_document(strict), canonical_document=canonical_json(weak)
    )
    assert swapped.rules[0].block_at == 0.99
    assert PackVersion(canonical_json(INSURANCE_V3_DOCUMENT)) == INSURANCE_V3


DEEP = 100_000  # far past the JSON parser's recursion limit


@pytest.mark.parametrize(
    ("raw", "error"),
    [
        (json.dumps(INSURANCE_V3_DOCUMENT).encode(), ValueError),  # not canonical: whitespace
        (canonical_json(INSURANCE_V3_DOCUMENT).replace(b"{", b'{"version":3,', 1), ValueError),
        (b"not json", ValueError),
        (b"NaN", ValueError),
        (canonical_json(INSURANCE_V3_DOCUMENT).decode(), TypeError),  # str, not bytes
        (canonical_json([1, 2]), CatalogDocumentError),
        (canonical_json({**INSURANCE_V3_DOCUMENT, "schema_version": 9}), CatalogDocumentError),
        (b'{"x":' + b"[" * DEEP + b"]" * DEEP + b"}", CatalogDocumentError),
        (canonical_json({**INSURANCE_V3_DOCUMENT, "rules": "none"}), ValidationError),
        (canonical_json({**INSURANCE_V3_DOCUMENT, "covers": ["output"]}), ValidationError),
    ],
    ids=[
        "whitespace",
        "repeated-member",
        "not-json",
        "nan",
        "str",
        "array",
        "version",
        "too-deep",
        "invalid",
        "unknown-member",
    ],
)
def test_m1_09_a_pack_cannot_be_built_from_bytes_that_are_not_a_canonical_pack(raw, error):
    with pytest.raises(error):
        PackVersion(raw)


@pytest.mark.parametrize(
    "document",
    [[1, 2], "floor", {"x": float("nan")}, {"x": {1, 2}}],
    ids=["array", "text", "nan", "set"],
)
def test_m1_09_from_document_rejects_what_has_no_canonical_json(document):
    for build in (FloorVersion.from_document, PackVersion.from_document):
        with pytest.raises(CatalogDocumentError) as info:
            build(document)
        assert [(e.code, e.path) for e in info.value.errors] == [(E.SCHEMA_INVALID, "$")]


def test_m1_09_a_deeply_nested_document_is_a_catalog_document_error_not_an_exception():
    deep: list = []
    for _ in range(DEEP):
        deep = [deep]
    for build, document in (
        (FloorVersion.from_document, raw_floor()),
        (PackVersion.from_document, copy.deepcopy(INSURANCE_V3_DOCUMENT)),
    ):
        document["x"] = deep
        with pytest.raises(CatalogDocumentError) as info:
            build(document)
        assert "nested too deeply" in info.value.errors[0].message


def test_m1_09_a_floor_document_states_every_field_with_its_json_type():
    """The flat format requires every field (``floor/README.md``), also when a floor is
    built without the file loader, and reads JSON types strictly."""
    document = floor_document(1, [floor_rule("p__a")])
    del document["rules"][0]["provisional"]
    with pytest.raises(ValidationError, match="provisional"):
        FloorVersion.from_document(document)
    for field, value in (("provisional", "true"), ("block_at", "0.8"), ("block_at", True)):
        with pytest.raises(ValidationError, match=field):
            FloorVersion.from_document(floor_document(1, [floor_rule("p__a", **{field: value})]))
    with pytest.raises(ValidationError, match="floor_version"):
        FloorVersion.from_document(floor_document(0, [floor_rule("p__a")]))


def test_m1_09_changing_the_submitted_object_or_the_content_afterwards_changes_nothing():
    document = copy.deepcopy(INSURANCE_V3_DOCUMENT)
    pack = PackVersion.from_document(document)
    before = pack.content_hash()

    document["rules"].clear()
    pack.document["rules"].clear()  # a copy each time
    pack.rules[1].question.criteria["in_scope"] = "Anything."  # a copy each time, too
    pack.content.rules[1].question.criteria.clear()

    assert pack.content_hash() == before
    assert pack.rules[1].question.criteria == INSURANCE_V3.rules[1].question.criteria
    assert len(pack.document["rules"]) == 2


def test_m1_09_a_floor_and_a_pack_are_never_equal():
    floor_like = {k: v for k, v in INSURANCE_V3_DOCUMENT.items()}
    assert PackVersion.from_document(floor_like) != FloorVersion.from_document(raw_floor())
    assert FLOOR_V2 != INSURANCE_V3


# --------------------------------------------------------------------------- the catalog


def test_m1_09_catalog_accepts_the_same_document_however_it_was_formatted():
    catalog = InMemoryCatalog(
        floors=[load_floor_file(RULES_JSON), parse_floor_json(json.dumps(reordered(raw_floor())))],
        packs=[INSURANCE_V3, PackVersion.from_document(reordered(INSURANCE_V3_DOCUMENT))],
    )
    assert catalog.floor(1).content_hash() == FLOOR_1_CONTENT_HASH


def test_m1_09_catalog_refuses_a_second_registration_whose_document_differs():
    document = raw_floor()
    document["rules"][0]["block_at"] = 0.84
    with pytest.raises(ValueError, match=r"floor@1 .* different content"):
        InMemoryCatalog(floors=[load_floor_file(RULES_JSON), load_floor(document)])


def test_m1_09_catalog_refuses_a_pack_document_that_only_states_a_default_explicitly():
    """Same meaning, different document, different hash: a version number names one
    document (AC-C2.2), so the second registration is refused."""
    stated = copy.deepcopy(INSURANCE_V3_DOCUMENT)
    stated["rules"][0]["mode"] = "enforce"
    restated = PackVersion.from_document(stated)
    assert restated.content == INSURANCE_V3.content
    with pytest.raises(ValueError, match=r"insurance@3 .* different content"):
        InMemoryCatalog(packs=[INSURANCE_V3, restated])


def test_m1_09_compiled_bundle_hash_uses_the_document_content_hashes(compiler, tenant, bundle):
    extends = {v.ref: sha256_of(v.document) for v in (FLOOR_V2, INSURANCE_V3, FINANCE_V2)}
    assert compiler.compile(bundle, tenant).bundle_hash == bundle_hash(bundle, extends=extends)
