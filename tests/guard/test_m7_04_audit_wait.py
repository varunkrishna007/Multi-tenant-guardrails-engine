"""M7-04: the audit may wait (a regulated tenant's record waits for room in a full queue), so the
check routes its escalation and stores its content *before* it, and a caller cancelled during the
wait has lost neither."""

import asyncio

import pytest
from guard_fixtures import ALPHA, Env, bundle, rule

from guardrail_engine.guard import Decision


class WaitingAudit:
    """An audit sink whose ``arecord`` waits, as the decision-record writer does when the queue
    is full."""

    def __init__(self, wait_s: float = 0.3) -> None:
        self.wait_s, self.kept = wait_s, []

    def record(self, verdict):
        self.kept.append(verdict)

    async def arecord(self, verdict):
        try:
            await asyncio.sleep(self.wait_s)
        finally:
            self.kept.append(verdict)  # as the writer does on a cancel: the record is kept


class Collector:
    def __init__(self) -> None:
        self.items = []

    def submit(self, request) -> None:
        self.items.append(request)


def document():
    d = bundle(ALPHA, rules=[rule("x")])
    d["audit"] = {"store_content": "full", "content_days": 30}
    return d


async def escalate(env, **kw):
    env.fake.set_noul("t__x", 0.6)  # between escalate_at and block_at
    return await env.check(ALPHA, "output", **kw)


async def test_an_escalation_and_the_stored_content_do_not_wait_for_the_audit():
    routed, stored = Collector(), Collector()
    async with Env(audit=WaitingAudit(), escalations=routed, content=stored) as env:
        await env.publish(document())
        task = asyncio.ensure_future(escalate(env))
        await asyncio.sleep(0.1)  # the audit is waiting
        assert not task.done()
        assert (len(routed.items), len(stored.items)) == (1, 1)  # both already done
        verdict = await task
        assert verdict.decision is Decision.ESCALATE


async def test_a_caller_cancelled_during_the_audit_wait_still_has_its_escalation_routed():
    audit, routed, stored = WaitingAudit(), Collector(), Collector()
    async with Env(audit=audit, escalations=routed, content=stored) as env:
        await env.publish(document())
        task = asyncio.ensure_future(escalate(env))
        await asyncio.sleep(0.1)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert (len(routed.items), len(stored.items), len(audit.kept)) == (1, 1, 1)
