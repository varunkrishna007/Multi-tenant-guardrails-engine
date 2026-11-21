"""The labels that resolved escalations make count toward the R1 gate and are hidden from
the default golden-set list, so a tenant can't see what is moving its counts. The list takes a
filter (``?include=escalation``) and the gate's message counts them apart."""

import json

import pytest
from admin_fixtures import ALPHA, Admin, bundle, rule, who

from guardrail_engine.admin.evidence import NO_PRECISION_GATE, EvidenceGate
from guardrail_engine.admin.golden import ESCALATION_SET_PREFIX, INCLUDE_ESCALATION
from guardrail_engine.authz import Role
from guardrail_engine.escalation.model import InvalidQueryError
from guardrail_engine.escalation.service import RESOLVE_ESCALATION
from guardrail_engine.tenant_scope import issue_scope

BASE = "/v1/tenants/{tid}/guardrails"
REVIEWER = who(Role.GUARDRAIL_REVIEWER, issuer="https://i/")
VIEWER = who(Role.VIEWER, subject="vera")

_n = [0]


def uploaded(block, allow, gp="output"):
    rows = []
    for label, n in (("block", block), ("allow", allow)):
        for _ in range(n):
            _n[0] += 1
            rows.append(
                {"id": f"u{_n[0]}", "guard_point": gp, "label": label,
                 "content": f"uploaded sample {_n[0]} {label}"}
            )  # fmt: skip
    return rows


@pytest.fixture
async def a():
    admin = Admin()
    yield admin
    await admin.aclose()


async def upload(a, rows, name="mine"):
    body = json.dumps({"name": name, "examples": rows}).encode()
    d = await a.decide(REVIEWER, "POST", BASE + "/golden-sets", ALPHA)
    return await a.golden.upload(d, REVIEWER, body)


async def escalation_label(a, n, label="block", gp="output", content=True):
    _n[0] += 1
    d = await a.decide(REVIEWER, "POST", RESOLVE_ESCALATION[1], ALPHA)
    info, _ = await a.golden.add_escalation_label(
        d,
        REVIEWER,
        RESOLVE_ESCALATION,
        item_id=f"esc_{_n[0]:024x}",
        guard_point=gp,
        label=label,
        content=f"escalated text {_n[0]} {label}" if content else None,
        content_sha256="sha256:" + "a" * 64,
    )
    return info


async def listing(a, include=None):
    d = await a.decide(VIEWER, "GET", BASE + "/golden-sets", ALPHA)
    return await a.golden.list_sets(d, include=include)


async def test_the_default_list_shows_uploads_and_the_filter_shows_the_escalation_labels(a):
    mine = await upload(a, uploaded(3, 3))
    first = await escalation_label(a, 1)
    second = await escalation_label(a, 2, "allow")
    assert [i.set_id for i in await listing(a)] == [mine.set_id]
    only = await listing(a, INCLUDE_ESCALATION)
    assert {i.set_id for i in only} == {first.set_id, second.set_id}
    assert all(i.name.startswith(ESCALATION_SET_PREFIX) for i in only)
    assert all(i.total == 1 for i in only)  # one example each, metadata only


async def test_an_unknown_include_is_a_query_error(a):
    for bad in ("", "uploads", "ESCALATION", "all"):
        with pytest.raises(InvalidQueryError) as exc:
            await listing(a, bad)
        assert exc.value.field == "include"


async def test_escalation_label_counts_are_kept_apart_from_the_totals(a):
    await upload(a, uploaded(2, 2))
    await escalation_label(a, 1, "block")
    await escalation_label(a, 2, "allow")
    await escalation_label(a, 3, "allow", gp="input")
    await escalation_label(a, 4, "block", content=False)  # a hash-only placeholder: no count
    store = a.golden_store.scoped(issue_scope(ALPHA))
    assert await store.label_counts(ALPHA) == {
        "output": {"block": 3, "allow": 3},
        "input": {"allow": 1},
    }
    assert await store.escalation_label_counts(ALPHA) == {
        "output": {"block": 1, "allow": 1},
        "input": {"allow": 1},
    }


def doc_with():
    return bundle(ALPHA, rules=[rule("r", gps=("output",))])


async def test_the_gate_message_counts_escalation_labels_separately(a):
    await upload(a, uploaded(2, 2))
    for _ in range(3):
        await escalation_label(a, 0, "block")
    await escalation_label(a, 0, "allow")
    gate = EvidenceGate(a.golden_store, NO_PRECISION_GATE)
    failures = await gate.check(issue_scope(ALPHA), doc_with(), [], a.now)
    [counts] = [f for f in failures if f.gate == "label_counts"]
    assert (
        "8 labelled examples (5 block, 3 allow, of which 4 from escalation labels" in counts.message
    )
    assert "(3 block, 1 allow))" in counts.message
    assert "needs 20 with at least 5 of each" in counts.message


async def test_a_gate_message_without_escalation_labels_is_unchanged(a):
    await upload(a, uploaded(2, 2))
    gate = EvidenceGate(a.golden_store, NO_PRECISION_GATE)
    failures = await gate.check(issue_scope(ALPHA), doc_with(), [], a.now)
    [counts] = [f for f in failures if f.gate == "label_counts"]
    assert "4 labelled examples (2 block, 2 allow); an enforcing rule needs" in counts.message
    assert "escalation" not in counts.message
