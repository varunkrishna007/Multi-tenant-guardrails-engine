"""AC-C2 (compiled keys), AC-C2.1 (wire shape) and AC-C2.2 (determinism and hashing)."""

import json
import re

import pytest
from policy_fixtures import (
    FIN_ADVICE_TEMPLATE,
    FINANCE_V2,
    FLOOR_V2,
    HEALTHCARE_V1,
    INSURANCE_V3,
    TOOLS,
    make_pack,
    pack_rule,
)
from pydantic import ValidationError

from guardrail_engine.decision import (
    QUESTION_ADAPTER,
    Answered,
    ChoiceQuestion,
    FakeDecisionModel,
    NoulQuestion,
    ScoreQuestion,
)
from guardrail_engine.policy import (
    CatalogRule,
    ErrorCode,
    InMemoryCatalog,
    InMemoryToolRegistry,
    PackContent,
    PackVersion,
    PlatformSettings,
    PolicyCompiler,
    bundle_hash,
    canonical_json,
    sha256_of,
)
from guardrail_engine.policy.schema import Bundle

KEY = re.compile(r"[A-Za-z0-9_-]+")


# ---------------------------------------------------------------------------- AC-C2


def test_ac_c2_every_key_namespaced_short_valid_and_unique(compiler, tenant, bundle):
    bundle["rules"][0]["id"] = "a" * 40  # the longest tenant id
    bundle["extends"].append("domain/healthcare@1")
    bundle["audit"] = {"records_days": 2555}
    policy = compiler.compile(bundle, tenant)
    for gp in policy.guard_points.values():
        keys = list(gp.questions)
        assert len(keys) == len(set(keys))
        assert set(keys) == set(gp.rules)
        for key in keys:
            assert key[:3] in {"p__", "d__", "t__"}
            assert len(key) <= 64
            assert KEY.fullmatch(key)
            assert gp.rules[key].layer == {"p__": "floor", "d__": "pack", "t__": "tenant"}[key[:3]]


def compiler_with_pack(pack: PackVersion) -> PolicyCompiler:
    catalog = InMemoryCatalog(floors=[FLOOR_V2], packs=[INSURANCE_V3, FINANCE_V2, pack])
    return PolicyCompiler(
        catalog, InMemoryToolRegistry(TOOLS), PlatformSettings(min_floor_version=2)
    )


def bad_pack(*keys: str, construct: bool = False) -> PackVersion:
    """``construct=True`` skips the catalog validators, to reach the compiler's own checks:
    the version is read from a valid document, then its content is swapped for unvalidated
    content. Only a test can do this; it is not a way to build a catalog version."""
    if not construct:
        return make_pack("bad", 1, *(pack_rule(k, severity="high") for k in keys))
    pack = make_pack("bad", 1, pack_rule("d__placeholder"))
    rules = tuple(
        CatalogRule.model_construct(
            key=k,
            guard_points=frozenset({"output"}),
            question=NoulQuestion(instructions="Is it?"),
            block_at=0.8,
            escalate_at=0.5,
            severity="high",
            mode="enforce",
            provisional=False,
        )
        for k in keys
    )
    content = PackContent.model_construct(name="bad", version=1, rules=rules, retention=None)
    object.__setattr__(pack, "_content", content)
    return pack


@pytest.mark.parametrize("key", ["p__pretends_floor", "d__has space", "d__" + "x" * 62])
def test_ac_c2_catalog_key_in_wrong_namespace_is_a_catalog_error(key):
    # Caught when the catalog is built, before any bundle is compiled.
    with pytest.raises(ValidationError):
        bad_pack(key)


@pytest.mark.parametrize("key", ["p__pretends_floor", "d__has space", "d__" + "x" * 62])
def test_ac_c2_compiler_still_rejects_a_bad_key_that_bypassed_validation(tenant, bundle, key):
    bundle["extends"].append("domain/bad@1")
    errors = compiler_with_pack(bad_pack(key, construct=True)).validate(bundle, tenant)
    assert [e.code for e in errors] == [ErrorCode.KEY_INVALID]


def test_ac_c2_catalog_key_defined_twice_rejected(tenant, bundle):
    bundle["extends"].append("domain/bad@1")
    errors = compiler_with_pack(bad_pack("d__ins_claim_promise")).validate(bundle, tenant)
    assert [e.code for e in errors] == [ErrorCode.KEY_DUPLICATE]


# ---------------------------------------------------------------------------- AC-C2.1


def test_ac_c2_1_questions_match_the_request_shape(compiler, tenant, bundle):
    out = compiler.compile(bundle, tenant).guard_points["output"]
    wire = {k: q.model_dump(mode="json", exclude_none=True) for k, q in out.questions.items()}

    # A tenant rule with both descriptions carries criteria, as in §Runtime flow.
    assert wire["t__fin_adv_01"] == {
        "type": "noul",
        "instructions": FIN_ADVICE_TEMPLATE.question,
        "criteria": {
            "true_description": FIN_ADVICE_TEMPLATE.true_description,
            "false_description": FIN_ADVICE_TEMPLATE.false_description,
        },
    }
    # A noul rule without descriptions carries no criteria at all. (A floor rule always has
    # both, since the floor file requires them, so this is a pack rule.)
    assert wire["d__fin_guarantee"] == {
        "type": "noul",
        "instructions": "Does the response guarantee an investment return?",
    }
    # Every entry round-trips through the M1-03 domain types.
    for value in wire.values():
        assert (
            QUESTION_ADAPTER.validate_python(value).model_dump(mode="json", exclude_none=True)
            == value
        )


def test_ac_c2_1_choice_and_score_keep_the_pack_definition(compiler, tenant, bundle):
    bundle["extends"].append("domain/healthcare@1")
    bundle["audit"] = {"records_days": 2555}
    policy = compiler.compile(bundle, tenant)
    router = policy.guard_points["input"].questions["d__ins_route"]
    scorer = policy.guard_points["output"].questions["d__hc_severity"]
    assert isinstance(router, ChoiceQuestion)
    assert router == INSURANCE_V3.rules[1].question
    assert isinstance(scorer, ScoreQuestion)
    assert scorer == HEALTHCARE_V1.rules[1].question


async def test_ac_c2_1_compiled_questions_are_accepted_by_the_model_port(compiler, tenant, bundle):
    policy = compiler.compile(bundle, tenant)
    fake = FakeDecisionModel()
    for gp in policy.guard_points.values():
        if gp.questions:
            result = await fake.decide("content", gp.questions)
            assert isinstance(result, Answered) and result.ok, gp.name


# ---------------------------------------------------------------------------- AC-C2.2


def test_ac_c2_2_compiling_twice_is_byte_identical(compiler, tenant, bundle):
    a = compiler.compile(bundle, tenant)
    b = compiler.compile(bundle, tenant)
    assert a.to_canonical_json() == b.to_canonical_json()
    assert a.bundle_hash == b.bundle_hash


def test_ac_c2_2_key_order_and_whitespace_do_not_change_the_hash(compiler, tenant, bundle):
    reordered = json.loads(json.dumps(bundle, sort_keys=True, indent=4))
    reordered = dict(reversed(list(reordered.items())))
    reordered["guard_points"] = dict(reversed(list(reordered["guard_points"].items())))
    a = compiler.compile(bundle, tenant)
    b = compiler.compile(reordered, tenant)
    assert a.bundle_hash == b.bundle_hash
    assert a.to_canonical_json() == b.to_canonical_json()


def test_ac_c2_2_any_content_change_changes_the_hash(compiler, tenant, bundle):
    base = compiler.compile(bundle, tenant).bundle_hash
    for mutate in (
        lambda b: b["rules"][0].update(block_at=0.81),
        lambda b: b["rules"][0].update(
            question=b["rules"][0]["question"].replace("buying", "purchasing")
        ),
        lambda b: b["overrides"][0].update(block_at=0.69),
        lambda b: b.update(version=15),
        lambda b: b["guard_points"]["plan"]["tool_allowlist"].pop(),
    ):
        changed = json.loads(json.dumps(bundle))
        mutate(changed)
        assert compiler.compile(changed, tenant).bundle_hash != base


def test_ac_c2_2_hash_is_sha256_over_canonical_bundle_and_extended_versions(
    compiler, tenant, bundle
):
    policy = compiler.compile(bundle, tenant)
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", policy.bundle_hash)
    extends = {v.ref: v.content_hash() for v in (FLOOR_V2, INSURANCE_V3, FINANCE_V2)}
    # Over the document as submitted, not over the model with defaults filled in.
    assert policy.bundle_hash == bundle_hash(bundle, extends=extends)
    assert policy.bundle_hash == sha256_of({"bundle": bundle, "extends": extends})
    assert policy.bundle_hash != sha256_of(
        {"bundle": Bundle.model_validate(bundle).model_dump(mode="json"), "extends": extends}
    )


def test_ac_c2_2_canonical_json_is_sorted_and_compact():
    assert (
        canonical_json({"b": 1, "a": [1, {"d": 2, "c": "é"}]})
        == '{"a":[1,{"c":"é","d":2}],"b":1}'.encode()
    )


def test_ac_c2_2_questions_are_ordered_floor_pack_tenant(compiler, tenant, bundle):
    keys = list(compiler.compile(bundle, tenant).guard_points["output"].questions)
    assert keys == [
        "p__ai_addressed",
        "p__inj_direct",
        "p__secrets",
        "d__fin_guarantee",
        "d__ins_claim_promise",
        "t__fin_adv_01",
    ]


def test_ac_c2_2_bundle_hash_requires_the_extended_catalog_content(bundle):
    # No default, so no caller can get a valid-looking hash without catalog content.
    with pytest.raises(TypeError):
        bundle_hash(bundle)  # type: ignore[call-arg]
    with pytest.raises(TypeError):
        bundle_hash(bundle, {})  # type: ignore[misc]
