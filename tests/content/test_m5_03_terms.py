"""M5-03 the class C term: table-driven across the packs a tenant has (R3: with several packs the
**longest** record retention and the **shortest** content cap apply), at compile time (the
bundle is refused) and again at write time (the content is not stored). Offline."""

import copy
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "policy"))
from policy_fixtures import (
    FINANCE_V2_DOCUMENT,
    FLOOR_DOCUMENTS,
    HEALTHCARE_V1_DOCUMENT,
    INSURANCE_V3_DOCUMENT,
)

from guardrail_engine.content.term import EffectiveContentTerm
from guardrail_engine.guard.tenants import TenantProfile
from guardrail_engine.policy import (
    ErrorCode,
    FloorVersion,
    InMemoryCatalog,
    InMemoryToolRegistry,
    PackVersion,
    PlatformSettings,
    PolicyCompiler,
    TenantAttributes,
)

TENANT = "t_acmeins"
FLOOR = "platform/floor@2"


def narrow_document():
    """A pack with a short content cap of its own (10 days) and a short record maximum."""
    doc = copy.deepcopy(FINANCE_V2_DOCUMENT)
    doc["name"], doc["version"] = "narrow", 1
    doc["rules"][0]["key"] = "d__nar_guarantee"
    doc["retention"] = {
        "records_min_days": 90, "records_max_days": 200, "records_default_days": 120,
        "content_max_days": 10, "content_default_days": 10,
    }  # fmt: skip
    return doc


def catalog():
    packs = [
        PackVersion.from_document(d)
        for d in (
            INSURANCE_V3_DOCUMENT,
            FINANCE_V2_DOCUMENT,
            HEALTHCARE_V1_DOCUMENT,
            narrow_document(),
        )
    ]
    return InMemoryCatalog(
        floors=[FloorVersion.from_document(d) for d in FLOOR_DOCUMENTS],
        packs=packs, tier_required_packs={},
    )  # fmt: skip


class Directory:
    def __init__(self, attributes=None):
        self.attributes = attributes

    async def get(self, tenant_id):
        if self.attributes is None:
            return None
        return TenantProfile.build(self.attributes, "insurance", slug="acmeins")


def resolver(**attrs):
    attributes = (
        None
        if attrs.get("absent")
        else TenantAttributes(tenant_id=TENANT, **{k: v for k, v in attrs.items() if k != "absent"})
    )
    return EffectiveContentTerm(
        catalog=catalog(),
        settings=PlatformSettings(min_floor_version=2),
        directory=Directory(attributes),
    )


def compiler():
    return PolicyCompiler(catalog(), InMemoryToolRegistry(), PlatformSettings(min_floor_version=2))


def bundle(packs, **audit):
    return {
        "schema_version": 1, "tenant_id": TENANT, "version": 1,
        "extends": [FLOOR, *packs], "audit": {"store_content": "full", **audit},
    }  # fmt: skip


INS, FIN, HC, NARROW = (
    "domain/insurance@3",
    "domain/finance@2",
    "domain/healthcare@1",
    "domain/narrow@1",
)

# (packs the bundle extends, the bundle's content_days or None, the tenant's BAA flag,
#  the days that are stored, or None when the content may not be stored at all, and why)
CASES = [
    pytest.param((), None, False, 30, None, id="no pack: the default of 30"),
    pytest.param((), 30, False, 30, None, id="no pack: the bundle's 30"),
    pytest.param((), 90, False, 90, None, id="no pack: 90 is the cap"),
    pytest.param((INS,), 60, False, 60, None, id="insurance: standard profile"),
    pytest.param((FIN,), 90, False, 90, None, id="finance: 90"),
    pytest.param((HC,), 30, True, 30, None, id="healthcare with a BAA: 30"),
    pytest.param((HC,), None, True, 30, None, id="healthcare with a BAA: the default is 30"),
    pytest.param((HC, FIN), 30, True, 30, None, id="healthcare and finance: the shortest cap, 30"),
    pytest.param((FIN, NARROW), 10, False, 10, None, id="finance and a pack capped at 10: 10"),
    pytest.param((FIN, NARROW), None, False, 10, None, id="the default is cut to the cap, 10"),
    pytest.param((HC, NARROW), 10, True, 10, None, id="healthcare and the 10-day pack: 10"),
]
REFUSED = [
    pytest.param((), 91, False, ErrorCode.AUDIT_CONTENT_DAYS_OUT_OF_RANGE, 90, id="no pack: 91"),
    pytest.param((), 0, False, ErrorCode.AUDIT_CONTENT_DAYS_OUT_OF_RANGE, 90, id="no pack: 0"),
    pytest.param(
        (HC,), 31, True, ErrorCode.AUDIT_CONTENT_DAYS_OUT_OF_RANGE, 30, id="healthcare: 31"
    ),
    pytest.param((HC, FIN), 60, True, ErrorCode.AUDIT_CONTENT_DAYS_OUT_OF_RANGE, 30, id="both: 60"),
    pytest.param((FIN, NARROW), 11, False, ErrorCode.AUDIT_CONTENT_DAYS_OUT_OF_RANGE, 10, id="11"),
    pytest.param(
        (HC,), 30, False, ErrorCode.AUDIT_CONTENT_REQUIRES_BAA, None, id="healthcare, no BAA"
    ),
    pytest.param(
        (HC, FIN), None, False, ErrorCode.AUDIT_CONTENT_REQUIRES_BAA, None, id="both, no BAA"
    ),
]


@pytest.mark.parametrize(("packs", "requested", "baa", "days", "_"), CASES)
def test_the_compiler_accepts_it_and_fixes_the_effective_days(packs, requested, baa, days, _):
    audit = {} if requested is None else {"content_days": requested}
    compiled = compiler().compile(
        bundle(packs, **audit), TenantAttributes(tenant_id=TENANT, baa=baa)
    )
    assert compiled.audit.store_content == "full" and compiled.audit.content_days == days


@pytest.mark.parametrize(("packs", "requested", "baa", "days", "_"), CASES)
async def test_the_writer_stores_the_same_days_at_write_time(packs, requested, baa, days, _):
    term = await resolver(baa=baa).term(TENANT, requested, packs)
    assert (term.days, term.reason in ("bundle", "clamped")) == (days, True)


@pytest.mark.parametrize(("packs", "requested", "baa", "code", "cap"), REFUSED)
def test_the_compiler_refuses_what_the_caps_and_the_baa_rule_forbid(
    packs, requested, baa, code, cap
):
    audit = {} if requested is None else {"content_days": requested}
    errors = compiler().validate(
        bundle(packs, **audit), TenantAttributes(tenant_id=TENANT, baa=baa)
    )
    assert [e.code for e in errors] == [code]
    if cap is not None:
        assert f"between 1 and {cap} days" in errors[0].message


@pytest.mark.parametrize(
    ("packs", "baa", "reason"),
    [
        pytest.param((HC,), False, "baa_missing", id="healthcare, no BAA flag"),
        pytest.param((HC, FIN), False, "baa_missing", id="healthcare with finance, no BAA flag"),
        pytest.param(("domain/ghost@1",), False, "pack_missing", id="a pack the catalog lacks"),
        pytest.param(("domain/Insurance@x",), False, "malformed_pack_ref", id="a malformed ref"),
    ],
)
async def test_content_is_not_stored_when_the_tenant_may_not_store_it_now(packs, baa, reason):
    """A published bundle can be behind: a BAA flag taken away, a pack that applies now. The
    direction of every doubt is not to store."""
    term = await resolver(baa=baa).term(TENANT, 30, packs)
    assert (term.days, term.reason) == (None, reason)


async def test_a_tenant_that_is_not_in_the_directory_or_a_failing_directory_stores_nothing():
    assert (await resolver(absent=True).term(TENANT, 30, ())).reason == "not_in_directory"

    class Down:
        async def get(self, tenant_id):
            raise ConnectionError("down")

    t = EffectiveContentTerm(
        catalog=catalog(), settings=PlatformSettings(min_floor_version=2), directory=Down()
    )
    got = await t.term(TENANT, 30, ())
    assert got.days is None and got.reason == "ConnectionError"


async def test_a_pack_the_tenants_contract_requires_applies_though_the_bundle_does_not_extend_it():
    """The healthcare pack comes from the tenant's own required packs: the cap is 30 and the BAA
    flag is needed, whatever the bundle says."""
    with_baa = resolver(baa=True, required_packs=frozenset({"healthcare"}))
    assert (await with_baa.term(TENANT, 90, ())).days == 30
    without = resolver(baa=False, required_packs=frozenset({"healthcare"}))
    assert (await without.term(TENANT, 30, ())).reason == "baa_missing"


async def test_no_pack_can_raise_the_cap_above_the_r3_ninety():
    doc = copy.deepcopy(FINANCE_V2_DOCUMENT)
    doc["name"], doc["version"] = "generous", 1
    doc["retention"] = {**doc["retention"], "content_max_days": 400}
    cat = InMemoryCatalog(
        floors=[FloorVersion.from_document(d) for d in FLOOR_DOCUMENTS],
        packs=[PackVersion.from_document(doc)], tier_required_packs={},
    )  # fmt: skip
    t = EffectiveContentTerm(
        catalog=cat, settings=PlatformSettings(min_floor_version=2),
        directory=Directory(TenantAttributes(tenant_id=TENANT)),
    )  # fmt: skip
    assert (await t.term(TENANT, 400, ("domain/generous@1",))).days == 90
