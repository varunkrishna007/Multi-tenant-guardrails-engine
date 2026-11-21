"""``GuardrailPublished`` says what the publish did (mode, whether it became the active
version, when), so the block-rate detector can ignore a shadow candidate."""

import json

import pytest
from admin_fixtures import ALPHA, Admin, bundle, rule, who

from guardrail_engine.admin.lifecycle import GuardrailPublished
from guardrail_engine.authz import Role
from guardrail_engine.gateway.sinks import RecordingAlertSink
from guardrail_engine.monitoring import BadPublishDetector
from guardrail_engine.store.adapters.postgres import event_payload, parse_event
from guardrail_engine.tenant_scope import issue_scope

BASE = "/v1/tenants/{tid}/guardrails"
ADMIN = who(Role.GUARDRAIL_ADMIN, issuer="https://i/")


@pytest.fixture
async def a():
    admin = Admin()
    yield admin
    await admin.aclose()


async def publish(a, doc, mode="enforce", percent=100):
    d = await a.decide(ADMIN, "PUT", BASE + "/draft", ALPHA)
    cur = await a.drafts.scoped(issue_scope(ALPHA)).get(ALPHA)
    saved = await a.service.put_draft(
        d, ADMIN, json.dumps(doc).encode(), None if cur is None else cur.etag
    )
    d = await a.decide(ADMIN, "POST", BASE + "/draft/publish", ALPHA)
    body = json.dumps({"mode": mode, "rollout_percent": percent}).encode()
    return await a.publisher.publish(d, ADMIN, body, saved.etag)


def doc():
    return bundle(ALPHA, rules=[rule("refunds", mode="shadow")])


async def test_each_action_says_its_mode_whether_it_is_active_and_when(a):
    await publish(a, doc())
    await publish(a, doc(), "shadow", 100)
    d = await a.decide(ADMIN, "POST", BASE + "/candidate/promote", ALPHA)
    await a.publisher.promote(d, ADMIN)
    first, candidate, promoted = a.bus.published
    assert (first.action, first.mode, first.active) == ("publish", "enforce", True)
    assert (candidate.action, candidate.mode, candidate.active) == ("publish", "shadow", False)
    assert (promoted.action, promoted.active) == ("promote", True)
    assert all(isinstance(e.at, float) and e.at > 0 for e in a.bus.published)
    assert first.at == a.now.timestamp()  # the fixture's clock, not the wall's


async def test_the_detector_on_the_bus_ignores_a_shadow_candidate_and_watches_the_promote(a):
    detector = BadPublishDetector(RecordingAlertSink())
    a.bus.subscribe(detector.on_published)
    await publish(a, doc())  # active v1: a watch starts
    assert detector._watches[ALPHA].version == 1
    await publish(a, doc(), "shadow", 100)  # a candidate: no new watch, v1 still the active one
    assert detector._watches[ALPHA].version == 1 and detector._active[ALPHA] == 1
    d = await a.decide(ADMIN, "POST", BASE + "/candidate/promote", ALPHA)
    await a.publisher.promote(d, ADMIN)  # now it decides traffic
    assert detector._watches[ALPHA].version == 2 and detector._active[ALPHA] == 2


def test_the_postgres_payload_carries_the_fields_and_round_trips():
    events = (
        GuardrailPublished("t_alpha", 2, "publish", "shadow", False, 1_800_000_000.5),
        GuardrailPublished("t_alpha", 3, "promote", None, True, 1_800_000_001.0),
        GuardrailPublished("t_alpha", 3, "set_percent"),  # an older shape: nothing extra
    )
    for event in events:
        payload = event_payload(event)
        assert parse_event(payload) == event and len(payload) < 200
    assert "mode" not in event_payload(events[2])


@pytest.mark.parametrize(
    "extra",
    [{"mode": "weird"}, {"active": "yes"}, {"at": "now"}, {"at": -1}, {"at": True}],
)
def test_a_payload_with_a_bad_extra_field_is_ignored(extra):
    base = json.loads(event_payload(GuardrailPublished("t_alpha", 2, "publish")))
    assert parse_event(json.dumps({**base, **extra})) is None


def test_a_payload_with_an_unknown_key_is_read_and_the_key_ignored():
    """A newer writer may add fields; an older reader still gets the event."""
    event = GuardrailPublished("t_alpha", 2, "publish", "enforce", True, 1_800_000_000.0)
    body = json.loads(event_payload(event))
    assert parse_event(json.dumps({**body, "future": {"a": 1}})) == event
    del body["action"]
    assert parse_event(json.dumps({**body, "future": 1})) is None  # a required key still counts
