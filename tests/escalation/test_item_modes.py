"""The class D mode is fixed on the item when it is routed; a reused request id
with other content is neither lost nor silent."""

import logging
import time

from esc_fixtures import ALPHA, BETA, Rig, doc, item_of
from guard_fixtures import CLAIMS_V1, FLOOR_V1, noul_document
from policy_fixtures import make_pack, pack_rule

from guardrail_engine.escalation.model import (
    RETENTION_AFTER_RESOLUTION,
    RETENTION_FROM_CREATION,
    item_id_for,
)
from guardrail_engine.policy import InMemoryCatalog

HASH_A = "sha256:" + "a" * 64
HASH_B = "sha256:" + "b" * 64

HEALTHCARE = make_pack(
    "healthcare",
    1,
    pack_rule(
        "d__hc_note",
        ("output",),
        question=noul_document("Does the response give a diagnosis?", "Diagnoses.", "Does not."),
        severity="low",
    ),
    retention={
        "records_min_days": 395,
        "records_max_days": 7 * 365,
        "records_default_days": 6 * 365,
        "content_max_days": 30,
        "content_requires_baa": True,
    },
)


# -----------------------------------------------------------------------------
async def test_a_standard_tenants_item_is_routed_until_resolved_plus_30_days():
    async with Rig() as rig:
        await rig.publish(target="queue")
        await rig.escalate()
        assert item_of(rig).retention_mode == RETENTION_AFTER_RESOLUTION == "resolved_plus"


async def test_a_healthcare_tenants_item_is_routed_30_days_from_creation():
    catalog = InMemoryCatalog(floors=[FLOOR_V1], packs=[CLAIMS_V1, HEALTHCARE])
    async with Rig(env_kwargs={"catalog": catalog}) as rig:
        document = doc(ALPHA, target="queue")
        document["extends"] = [*document["extends"], "domain/healthcare@1"]
        await rig.env.publish(document)
        await rig.escalate()
        assert item_of(rig).retention_mode == RETENTION_FROM_CREATION == "total"
        # another tenant on no pack is not affected
        await rig.env.publish(doc(BETA, target="queue"))
        await rig.escalate(BETA)
        assert item_of(rig, BETA).retention_mode == "resolved_plus"


# -----------------------------------------------------------------------------
def test_the_item_id_includes_the_content_hash():
    base = item_id_for(ALPHA, "req-1", "output", HASH_A)
    assert item_id_for(ALPHA, "req-1", "output", HASH_A) == base  # an identical retry
    assert item_id_for(ALPHA, "req-1", "output", HASH_B) != base  # other content
    assert item_id_for(ALPHA, "req-1", "input", HASH_A) != base
    assert item_id_for(BETA, "req-1", "output", HASH_A) != base
    assert item_id_for(ALPHA, "req-2", "output", HASH_A) != base
    assert item_id_for(ALPHA, "req-1", "output", None) == item_id_for(ALPHA, "req-1", "output")


async def test_an_identical_retry_is_still_one_item_and_is_not_counted_as_a_reuse(caplog):
    async with Rig() as rig:
        await rig.publish(target="queue")
        caplog.set_level(logging.WARNING)
        await rig.escalate(request_id="req-1", content="same text p=0.6")
        await rig.escalate(request_id="req-1", content="same text p=0.6")
        assert len(rig.items.items(ALPHA)) == 1
        assert rig.router.reused_request_ids == 0
        assert "reused a request id" not in caplog.text


async def test_a_reused_request_id_with_other_content_is_kept_counted_and_logged(caplog):
    async with Rig() as rig:
        await rig.publish(target="queue")
        caplog.set_level(logging.WARNING)
        await rig.escalate(request_id="req-1", content="first text p=0.6")
        await rig.escalate(request_id="req-1", content="a different text p=0.7")
        first, second = rig.items.items(ALPHA)
        assert first.id != second.id and first.request_id == second.request_id == "req-1"
        assert first.content == "first text p=0.6" and second.content == "a different text p=0.7"
        assert rig.router.reused_request_ids == 1
        assert rig.router.dropped == 0  # nothing was lost
        [record] = [r for r in caplog.records if "reused a request id" in r.getMessage()]
        assert record.levelno == logging.WARNING
        assert "req-1" not in record.getMessage()  # never the id or the content
        assert "different text" not in caplog.text
        # a third one counts again
        await rig.escalate(request_id="req-1", content="and a third p=0.65")
        assert rig.router.reused_request_ids == 2 and len(rig.items.items(ALPHA)) == 3


async def test_a_reused_request_id_on_a_webhook_tenant_notifies_for_each_item():
    from guardrail_engine.delivery.events import KIND_ESCALATION

    async with Rig() as rig:
        await rig.publish(target="webhook", store_content="full")
        await rig.escalate(request_id="req-9", content="one p=0.6")
        await rig.escalate(request_id="req-9", content="two p=0.6")
        assert len(rig.items.items(ALPHA)) == 2
        entries = rig.outbox.claim_due(time.time() + 1, 10, 60, (KIND_ESCALATION,))
        assert len(entries) == 2 and len({e.key for e in entries}) == 2


async def test_the_same_request_id_at_another_guard_point_or_tenant_is_not_a_reuse():
    async with Rig() as rig:
        await rig.env.publish(doc(ALPHA, target="queue"))
        await rig.env.publish(doc(BETA, target="queue"))
        await rig.escalate(ALPHA, request_id="shared", content="x p=0.6")
        await rig.escalate(BETA, request_id="shared", content="x p=0.6")
        assert rig.router.reused_request_ids == 0


async def test_the_reuse_check_failing_never_costs_the_item():
    async with Rig() as rig:
        await rig.publish(target="queue")

        async def broken(*args, **kw):
            raise RuntimeError("store hiccup")

        real = rig.items.scoped

        def scoped(scope):
            view = real(scope)
            view.same_check_count = broken
            return view

        rig.items.scoped = scoped  # type: ignore[method-assign]
        await rig.escalate(request_id="req-1", content="kept anyway p=0.6")
        assert len(rig.items.items(ALPHA)) == 1 and rig.router.dropped == 0
        assert rig.router.reused_request_ids == 0
