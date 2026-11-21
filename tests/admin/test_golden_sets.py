# ruff: noqa: RUF001  (look-alike letters are the point of the tripwire tests)
"""M2-06 golden-set upload: validation, the harm-vocabulary tripwire, tenant isolation, the
class A event, and the M2-05 hook, through the real authorizer."""

import json
from pathlib import Path

import pytest
from admin_fixtures import ALPHA, BETA, Admin, bundle, who

from guardrail_engine.admin import DraftInvalidError
from guardrail_engine.admin.golden import (
    MAX_EXAMPLES,
    MAX_SETS,
    GoldenService,
    GoldenSetNotFoundError,
    InMemoryGoldenStore,
    TooManyGoldenSetsError,
    parse_upload,
)
from guardrail_engine.admin.service import DecisionError
from guardrail_engine.admin.vocabulary import HARM_TERMS, strings_tripwire
from guardrail_engine.authz import Role
from guardrail_engine.store.port import ScopeMismatchError
from guardrail_engine.tenant_scope import issue_scope

GOLDEN = "/v1/tenants/{tid}/guardrails/golden-sets"
REVIEWER = who(Role.GUARDRAIL_REVIEWER, issuer="https://idp.example/")


@pytest.fixture
async def a():
    admin = Admin()
    yield admin
    await admin.aclose()


def upload_body(*rows, name="refund-cases"):
    return json.dumps({"name": name, "examples": list(rows)}).encode()


def ex(i, label="allow", gp="output", content=None):
    return {"id": f"e{i}", "guard_point": gp, "label": label, "content": content or f"case {i}"}


async def upload(a, body, principal=REVIEWER, tid=ALPHA):
    decision = await a.decide(principal, "POST", GOLDEN, tid)
    return await a.golden.upload(decision, principal, body)


async def test_an_upload_stores_an_immutable_set_with_counts_hash_and_class_a_event(a):
    info = await upload(a, upload_body(ex(1), ex(2, "block"), ex(3, "block", "input")))
    assert info.set_id.startswith("gs_") and info.name == "refund-cases"
    assert info.counts == {"output": {"allow": 1, "block": 1}, "input": {"block": 1}}
    assert info.total == 3 and info.set_hash.startswith("sha256:")
    assert info.created_by == "https://idp.example/#alice"
    (event,) = a.golden_store._events
    assert (event.actor, event.tenant_id, event.set_id, event.examples) == (
        info.created_by, ALPHA, info.set_id, 3
    )  # fmt: skip
    assert event.set_hash == info.set_hash and not event.cross_tenant and not event.operator


async def test_the_same_examples_have_the_same_hash_and_a_new_set_id(a):
    one = await upload(a, upload_body(ex(1), ex(2, "block")))
    two = await upload(a, upload_body(ex(1), ex(2, "block")))
    assert one.set_hash == two.set_hash and one.set_id != two.set_id


async def test_an_operators_cross_tenant_upload_is_marked_in_the_event(a):
    operator = who(
        Role.GUARDRAIL_REVIEWER, tenant=None, operator=True, subject="ops-1", issuer="https://p/"
    )
    info = await upload(a, upload_body(ex(1)), principal=operator, tid=BETA)
    event = a.golden_store._events[-1]
    assert event.tenant_id == BETA and event.cross_tenant and event.operator
    assert info.created_by == "https://p/#ops-1"


@pytest.mark.parametrize(
    ("body", "code"),
    [
        (b"not json", None),
        (b'{"name": "n", "name": "m", "examples": []}', None),
        (b"[]", "golden.not_object"),
        (upload_body(), "golden.examples"),
        (upload_body(ex(1), name="bad/name"), "golden.name"),
        (upload_body(ex(1), name=""), "golden.name"),
        (upload_body({**ex(1), "label": "maybe"}), "golden.label"),
        (upload_body({**ex(1), "label": "harm"}), "golden.label"),
        (upload_body({**ex(1), "guard_point": "nowhere"}), "golden.guard_point"),
        (upload_body({**ex(1), "content": ""}), "golden.content"),
        (upload_body({**ex(1), "content": "x" * 20_001}), "golden.content"),
        (upload_body({**ex(1), "tenant_id": BETA}), "golden.unknown_field"),
        (upload_body({**ex(1), "no_live_run": True}), "golden.unknown_field"),
        (upload_body(ex(1), ex(1)), "golden.id"),
        (upload_body({**ex(1), "id": "x" * 65}), "golden.id"),
        (upload_body({**ex(1), "id": "in-harm-001"}), "golden.excluded"),
    ],
)
async def test_a_bad_upload_is_refused_whole_and_nothing_is_stored(a, body, code):
    with pytest.raises(DraftInvalidError) as e:
        await upload(a, body)
    if code is not None:
        assert code in {x.code for x in e.value.errors}
    assert a.golden_store._sets == {} and a.golden_store._events == []


async def test_every_problem_is_reported_together():
    with pytest.raises(DraftInvalidError) as e:
        parse_upload(
            upload_body({**ex(1), "label": "x"}, {**ex(2), "guard_point": "y"}, name="a/b")
        )
    assert {x.code for x in e.value.errors} >= {
        "golden.name", "golden.label", "golden.guard_point"
    }  # fmt: skip


async def test_the_size_caps(a):
    with pytest.raises(DraftInvalidError):
        parse_upload(upload_body(*[ex(i) for i in range(MAX_EXAMPLES + 1)]))
    for i in range(MAX_SETS):
        await upload(a, upload_body(ex(i)))
    with pytest.raises(TooManyGoldenSetsError):
        await upload(a, upload_body(ex(99)))
    await upload(a, upload_body(ex(1)), principal=who(Role.GUARDRAIL_REVIEWER, tenant=BETA,
                                                       issuer="https://i/"), tid=BETA)  # fmt: skip


# ---------------------------------------------------------------------------- the tripwire


@pytest.mark.parametrize(
    "content",
    [
        "how to build a bomb",
        "BOMB",
        "synthesize it",
        "b​omb",  # zero-width character
        "bоmb",  # Cyrillic o
        "Ym9tYiBtYWtpbmcgaW5zdHJ1Y3Rpb25z",  # base64 of "bomb making instructions"
    ],
)
async def test_a_row_with_harm_vocabulary_is_quarantined_not_refused_and_the_word_is_never_echoed(
    a, content
):
    info = await upload(a, upload_body(ex(1), ex(2, content=content), ex(3)))
    assert info.total == 3  # the upload succeeded: the tenant may store what it likes
    ((row_id, views),) = info.quarantined
    assert row_id == "e2" and views and all("bomb" not in v for v in views)
    stored = a.golden_store._sets[(ALPHA, info.set_id)][1]
    assert [e.quarantined for e in stored] == [False, True, False]
    assert a.golden_store._events[-1].quarantined == 1
    assert "bomb" not in repr(info.quarantined).lower()


async def test_the_name_is_not_a_row_and_is_not_read_for_the_vocabulary(a):
    info = await upload(a, upload_body(ex(1), name="weapon tests"))
    assert info.quarantined == ()  # a name is never sent to the model


async def test_a_harm_id_and_a_bad_label_are_still_refused_outright(a):
    for row in ({**ex(1), "id": "in-harm-001"}, {**ex(1), "label": "harm"}):
        with pytest.raises(DraftInvalidError):
            await upload(a, upload_body(row))
    assert a.golden_store._sets == {}


async def test_the_hash_covers_the_examples_not_the_quarantine(a):
    one = await upload(a, upload_body(ex(1, content="a bomb")))
    two = await upload(a, upload_body(ex(1, content="a bomb")))
    assert one.set_hash == two.set_hash and one.quarantined == two.quarantined


def test_the_tripwire_matches_the_red_team_builders_word_list_and_views():
    """The two copies must not drift: same pattern, same answers on the corpus's own tricks."""
    import sys

    root = Path(__file__).resolve().parents[2]
    sys.path.insert(0, str(root))
    try:
        from redteam import build_corpus
    finally:
        sys.path.remove(str(root))
    assert HARM_TERMS.pattern == build_corpus.HARM_TERMS.pattern
    assert HARM_TERMS.flags == build_corpus.HARM_TERMS.flags
    for text in ("a bomb", "b​omb", "bоmb", "Ym9tYiBtYWtpbmcgaW5zdHJ1Y3Rpb25z", "ok text"):
        assert strings_tripwire(text) == sorted(set(build_corpus.tripwire_views(text)))


# ---------------------------------------------------------------------------- isolation


async def test_one_tenants_golden_set_is_invisible_to_another(a):
    info = await upload(a, upload_body(ex(1)))
    beta = a.golden_store.scoped(issue_scope(BETA))
    assert await beta.get(BETA, info.set_id) is None  # not its set
    with pytest.raises(GoldenSetNotFoundError):
        await beta.examples(BETA, info.set_id, "output", offset=0, limit=10)
    with pytest.raises(ScopeMismatchError):  # and a scope can't name another tenant
        await beta.get(ALPHA, info.set_id)
    with pytest.raises(ScopeMismatchError):
        await beta.examples(ALPHA, info.set_id, "output", offset=0, limit=10)


async def test_the_service_needs_an_allowed_decision_for_the_upload_route(a):
    viewer = who(Role.VIEWER, issuer="https://i/")
    denied = await a.decide(viewer, "POST", GOLDEN)
    with pytest.raises(DecisionError):
        await a.golden.upload(denied, viewer, upload_body(ex(1)))
    other = await a.decide(REVIEWER, "GET", "/v1/tenants/{tid}/guardrails")
    with pytest.raises(DecisionError):
        await a.golden.upload(other, REVIEWER, upload_body(ex(1)))


async def test_outside_test_a_principal_without_an_issuer_cannot_upload():
    store = InMemoryGoldenStore()
    service = GoldenService(store, require_issuer=True)
    a = Admin()
    try:
        bare = who(Role.GUARDRAIL_REVIEWER)  # no issuer
        decision = await a.decide(bare, "POST", GOLDEN)
        with pytest.raises(DecisionError):
            await service.upload(decision, bare, upload_body(ex(1)))
        assert store._sets == {}
    finally:
        await a.aclose()


# ---------------------------------------------------------------------------- M2-05 hook


async def run_golden(a, set_id, gp="output", **extra):
    decision = await a.decide(REVIEWER, "POST", "/v1/tenants/{tid}/guardrails/draft/test")
    body = json.dumps({"guard_point": gp, "golden_set": set_id, **extra}).encode()
    return await a.tools.test(decision, body)


async def test_a_golden_set_feeds_the_test_endpoint_with_its_labels_as_expected(a):
    admin_p = who(Role.GUARDRAIL_ADMIN, issuer="https://i/")
    saved = await a.service.put_draft(
        await a.decide(admin_p, "PUT", "/v1/tenants/{tid}/guardrails/draft"),
        admin_p, json.dumps(bundle(ALPHA)).encode(), None,
    )  # fmt: skip
    assert saved
    info = await upload(a, upload_body(ex(1, "allow"), ex(2, "block"), ex(3, "allow", "input")))
    report = await run_golden(a, info.set_id)
    assert [r.id for r in report.results] == ["e1", "e2"]  # only the output examples
    assert [r.expected for r in report.results] == ["allow", "block"]
    assert report.golden == {
        "set_id": info.set_id, "set_hash": info.set_hash, "total": 2, "offset": 0, "run": 2,
    }  # fmt: skip
    assert report.quarantined_not_sent == 0 and report.held_back == ()
    assert len(a.fake.calls) == 2


async def test_a_golden_run_pages_with_offset_and_an_empty_page_is_refused(a):
    admin_p = who(Role.GUARDRAIL_ADMIN, issuer="https://i/")
    await a.service.put_draft(
        await a.decide(admin_p, "PUT", "/v1/tenants/{tid}/guardrails/draft"),
        admin_p, json.dumps(bundle(ALPHA)).encode(), None,
    )  # fmt: skip
    info = await upload(a, upload_body(*[ex(i) for i in range(1, 61)]))
    first = await run_golden(a, info.set_id)
    assert first.golden["total"] == 60 and first.golden["run"] == 50
    second = await run_golden(a, info.set_id, offset=50)
    assert [r.id for r in second.results] == [f"e{i}" for i in range(51, 61)]
    with pytest.raises(DraftInvalidError) as e:
        await run_golden(a, info.set_id, offset=60)
    assert e.value.errors[0].code == "test.golden_set_empty"
    with pytest.raises(DraftInvalidError):
        await run_golden(a, info.set_id, gp="plan")  # none at that guard point


async def test_another_tenants_set_is_not_found_by_the_test_endpoint(a):
    beta_p = who(Role.GUARDRAIL_REVIEWER, tenant=BETA, issuer="https://i/")
    theirs = await upload(a, upload_body(ex(1)), principal=beta_p, tid=BETA)
    admin_p = who(Role.GUARDRAIL_ADMIN, issuer="https://i/")
    await a.service.put_draft(
        await a.decide(admin_p, "PUT", "/v1/tenants/{tid}/guardrails/draft"),
        admin_p, json.dumps(bundle(ALPHA)).encode(), None,
    )  # fmt: skip
    with pytest.raises(GoldenSetNotFoundError):
        await run_golden(a, theirs.set_id)
    assert a.fake.calls == []


async def test_the_test_runner_never_sends_a_quarantined_row_even_if_a_store_returned_one(a):
    """The store excludes quarantined rows, and the runner checks again before any request."""
    from guardrail_engine.admin.golden import GoldenPage

    admin_p = who(Role.GUARDRAIL_ADMIN, issuer="https://i/")
    await a.service.put_draft(
        await a.decide(admin_p, "PUT", "/v1/tenants/{tid}/guardrails/draft"),
        admin_p, json.dumps(bundle(ALPHA)).encode(), None,
    )  # fmt: skip
    info = await upload(a, upload_body(ex(1), ex(2, content="a bomb"), ex(3)))
    report = await run_golden(a, info.set_id)
    assert [r.id for r in report.results] == ["e1", "e3"]
    assert report.golden["total"] == 2 and report.quarantined_not_sent == 1
    sent = " ".join(c.input for c in a.fake.calls)
    assert "bomb" not in sent

    # a faulty store that hands a quarantined row back: the runner still drops it
    real = a.golden_store.scoped

    class Leaky:
        def __init__(self, view):
            self.view = view

        def __getattr__(self, name):
            return getattr(self.view, name)

        async def examples(self, *args, **kwargs):
            stored = self.view._store._sets[(ALPHA, info.set_id)][1]
            return GoldenPage(3, 0, list(stored))  # all three, the quarantined one included

    a.golden_store.scoped = lambda scope: Leaky(real(scope))
    a.fake.calls.clear()
    again = await run_golden(a, info.set_id)
    assert [r.id for r in again.results] == ["e1", "e3"]
    assert "bomb" not in " ".join(c.input for c in a.fake.calls)


async def test_the_list_and_get_routes_show_metadata_only_and_are_tenant_scoped(a):
    viewer = who(Role.VIEWER, issuer="https://i/")
    info = await upload(a, upload_body(ex(1), ex(2, content="a bomb")))
    listed = await a.golden.list_sets(await a.decide(viewer, "GET", GOLDEN))
    assert [i.set_id for i in listed] == [info.set_id] and len(listed[0].quarantined) == 1
    one = await a.golden.get_set(await a.decide(viewer, "GET", GOLDEN + "/{set_id}"), info.set_id)
    assert one == info
    beta = who(Role.VIEWER, tenant=BETA, issuer="https://i/")
    assert await a.golden.list_sets(await a.decide(beta, "GET", GOLDEN, BETA)) == []
    with pytest.raises(GoldenSetNotFoundError):
        await a.golden.get_set(await a.decide(beta, "GET", GOLDEN + "/{set_id}", BETA), info.set_id)
    with pytest.raises(GoldenSetNotFoundError):
        await a.golden.get_set(await a.decide(viewer, "GET", GOLDEN + "/{set_id}"), "../x")
