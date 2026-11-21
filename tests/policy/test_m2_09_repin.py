"""M2-09 re-pin: the pure transform. ``extends`` moves to the new floor, the tenant's own
content is byte-identical, and a floor override is carried only for the thresholds that are
still strictly stricter than the new floor."""

import copy
import json

import pytest
from policy_fixtures import floor_rule, make_floor

from guardrail_engine.policy.catalog import InMemoryCatalog, PlatformSettings, TenantAttributes
from guardrail_engine.policy.compiler import PolicyCompiler
from guardrail_engine.policy.document import parse_bundle
from guardrail_engine.policy.repin import (
    NOT_STRICTER,
    PAIR_INVALID,
    RULE_REMOVED,
    RepinError,
    floor_version_of,
    repin_document,
)

FLOOR1 = make_floor(1, floor_rule("p__a", block_at=0.85, escalate_at=0.55),
                    floor_rule("p__b", block_at=0.85, escalate_at=0.55))  # fmt: skip


def floor2(a=(0.85, 0.55), b=(0.85, 0.55), extra=()):
    return make_floor(
        2,
        floor_rule("p__a", block_at=a[0], escalate_at=a[1]),
        floor_rule("p__b", block_at=b[0], escalate_at=b[1]),
        *extra,
    )


def document(overrides=(), **members):
    doc = {
        "schema_version": 1, "tenant_id": "t_alpha", "version": 3,
        "extends": ["platform/floor@1", "domain/claims@1"],
        "rules": [{"id": "r", "guard_points": ["output"], "question": "Is it?",
                   "true_description": "Yes.", "false_description": "No.", "mode": "shadow"}],
        "defaults": {"block_at": 0.8, "escalate_at": 0.4},
        "guard_points": {"output": {"enabled": True}},
        "deterministic": {"deny_patterns": [{"id": "d", "regex": "x+", "action": "block"}]},
        "escalation": {"target": "queue"},
        "audit": {"records_days": 400},
        **members,
    }  # fmt: skip
    if overrides:
        doc["overrides"] = list(overrides)
    return doc


def kept(result):
    return result.document.get("overrides", [])


# ---------------------------------------------------------------------------- carry-over


BOTH = [("block_at", NOT_STRICTER), ("escalate_at", NOT_STRICTER)]
CASES = [
    # lower than the new floor: kept
    ({"block_at": 0.70, "escalate_at": 0.40}, (0.85, 0.55),
     {"block_at": 0.70, "escalate_at": 0.40}, []),
    # equal: not stricter, dropped
    ({"block_at": 0.85, "escalate_at": 0.55}, (0.85, 0.55), {}, BOTH),
    # higher than the new floor (the floor itself was lowered): dropped
    ({"block_at": 0.80, "escalate_at": 0.50}, (0.70, 0.45), {}, BOTH),
    # one field still stricter, the other not
    ({"block_at": 0.60, "escalate_at": 0.50}, (0.85, 0.45), {"block_at": 0.60},
     [("escalate_at", NOT_STRICTER)]),
    # a single threshold
    ({"escalate_at": 0.30}, (0.85, 0.55), {"escalate_at": 0.30}, []),
    # a kept block below the floor's escalate would not make a valid pair: dropped whole
    ({"block_at": 0.30}, (0.85, 0.55), {}, [("block_at", PAIR_INVALID)]),
    # a kept block just over the floor's escalate is a valid pair
    ({"block_at": 0.56}, (0.85, 0.55), {"block_at": 0.56}, []),
]  # fmt: skip


@pytest.mark.parametrize(("override", "floor", "carried", "drops"), CASES)
def test_a_floor_override_keeps_only_the_thresholds_still_stricter(override, floor, carried, drops):
    result = repin_document(document([{"rule": "p__a", **override}]), floor2(a=floor))
    if carried:
        assert kept(result) == [{"rule": "p__a", **carried}]
    else:
        assert kept(result) == []
    assert [(d.field, d.reason) for d in result.drops] == drops
    for d in result.drops:
        assert d.rule == "p__a"


def test_a_drop_lists_the_old_and_the_new_floor_value():
    result = repin_document(document([{"rule": "p__a", "block_at": 0.8}]), floor2(a=(0.7, 0.45)))
    (drop,) = result.drops
    assert (drop.old, drop.floor, drop.reason) == (0.8, 0.7, NOT_STRICTER)
    assert drop.as_dict() == {
        "rule": "p__a", "field": "block_at", "old": 0.8, "floor": 0.7, "reason": NOT_STRICTER,
    }  # fmt: skip


def test_an_override_on_a_rule_the_new_floor_dropped_is_dropped_and_listed():
    floor_without_b = make_floor(2, floor_rule("p__a"))
    result = repin_document(
        document([{"rule": "p__b", "block_at": 0.6}, {"rule": "p__a", "block_at": 0.6}]),
        floor_without_b,
    )
    assert kept(result) == [{"rule": "p__a", "block_at": 0.6}]
    assert [(d.rule, d.field, d.reason) for d in result.drops] == [
        ("p__b", "override", RULE_REMOVED)
    ]


def test_pack_overrides_and_other_floor_override_fields_are_handled_as_stated():
    pack = {"rule": "d__route", "block_at": 0.9}
    floor_override = {"rule": "p__a", "block_at": 0.6, "enabled": True, "mode": "enforce"}
    result = repin_document(document([pack, floor_override]), floor2())
    assert kept(result) == [pack, {"rule": "p__a", "block_at": 0.6}]  # restating fields not carried
    assert result.drops == ()


# ---------------------------------------------------------------------------- what is untouched


def test_extends_moves_to_the_new_floor_and_the_packs_stay_where_they_are():
    result = repin_document(document(), floor2())
    assert result.document["extends"] == ["platform/floor@2", "domain/claims@1"]
    assert (result.from_floor, result.to_floor) == (1, 2)
    only_floor = repin_document(document(extends=["platform/floor@1"]), floor2())
    assert only_floor.document["extends"] == ["platform/floor@2"]


def test_the_input_is_never_changed():
    doc = document([{"rule": "p__a", "block_at": 0.95}])
    before = copy.deepcopy(doc)
    repin_document(doc, floor2())
    assert doc == before


@pytest.mark.parametrize(
    "overrides",
    [
        [],
        [{"rule": "p__a", "block_at": 0.6}],
        [{"rule": "p__a", "block_at": 0.99}, {"rule": "d__x", "escalate_at": 0.2}],
        [
            {"rule": "p__a", "block_at": 0.6, "escalate_at": 0.4},
            {"rule": "p__gone", "block_at": 0.1},
        ],
    ],
)  # fmt: skip
def test_tenant_rules_packs_and_settings_are_byte_identical_before_and_after(overrides):
    """The property: every member but ``extends`` and the floor overrides is the same bytes."""
    doc = document(overrides)
    result = repin_document(doc, floor2(a=(0.7, 0.45)))
    for member in doc:
        if member in ("extends", "overrides"):
            continue
        assert json.dumps(result.document[member], sort_keys=True) == json.dumps(
            doc[member], sort_keys=True
        ), member
    assert set(result.document) - set(doc) == set()
    assert [o for o in result.document.get("overrides", []) if not o["rule"].startswith("p__")] == [
        o for o in doc.get("overrides", []) if not o["rule"].startswith("p__")
    ]


def test_the_result_compiles_on_the_new_floor():
    catalog = InMemoryCatalog(floors=[FLOOR1, floor2()])
    from guardrail_engine.guard.tenants import TenantProfile

    doc = document(
        [{"rule": "p__a", "block_at": 0.7}, {"rule": "p__b", "escalate_at": 0.9}],
        extends=["platform/floor@1"],
    )
    result = repin_document(doc, floor2())
    prof = TenantProfile.build(TenantAttributes(tenant_id="t_alpha"), "insurance", (), slug="alpha")
    compiled = PolicyCompiler(catalog, prof, PlatformSettings()).compile(
        parse_bundle(result.document), TenantAttributes(tenant_id="t_alpha")
    )
    assert compiled.version == 3 and [d.field for d in result.drops] == ["escalate_at"]


def test_a_bundle_must_extend_exactly_one_floor():
    for extends in ([], ["platform/floor@1", "platform/floor@2"], ["domain/claims@1"]):
        with pytest.raises(RepinError):
            repin_document(document(extends=extends), floor2())
    assert floor_version_of(document()) == 1
