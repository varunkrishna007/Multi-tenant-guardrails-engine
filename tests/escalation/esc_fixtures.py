"""A Guard Service, the escalation router and the escalation service, over in-memory ports."""

from __future__ import annotations

import asyncio
import json
import re
from datetime import UTC, datetime
from typing import Any

from guard_fixtures import ALPHA, BETA, Env, bundle, rule

from guardrail_engine.admin.golden import GoldenService, InMemoryGoldenStore
from guardrail_engine.authz import Authorizer, InMemoryAuthzAudit, Principal, Role
from guardrail_engine.delivery import InMemoryOutbox
from guardrail_engine.escalation import (
    EscalationRouter,
    EscalationService,
    InMemoryEscalationStore,
)
from guardrail_engine.guard import Decision

__all__ = ["ALPHA", "BETA", "NOW", "Rig", "Sink", "doc", "item_of", "who"]

NOW = datetime(2026, 11, 20, 12, 0, tzinfo=UTC)
P = re.compile(r"p=([0-9.]+)")
HOOK = "https://hooks.acme.example/guardrail"
BASE = "/v1/tenants/{tid}/guardrails"


def who(*roles: Role, tenant: str | None = ALPHA, subject="rita", issuer="https://idp/"):
    return Principal(subject, tenant, frozenset(roles), False, issuer)


def doc(
    tenant: str = ALPHA, *, target: str = "queue", store_content: str = "hash_only", url=HOOK
) -> dict[str, Any]:
    """A bundle with one enforced rule ``t__x`` (escalate from 0.5, block from 0.8) and the
    tenant's escalation target and content setting."""
    d = bundle(tenant, rules=[rule("x")])
    d["escalation"] = {"target": target, **({"url": url} if target == "webhook" else {})}
    if store_content != "hash_only":
        d["audit"] = {"store_content": store_content, "content_days": 30}
    return d


class Sink:
    """An alert sink that remembers what it got."""

    def __init__(self) -> None:
        self.alerts: list[Any] = []

    def emit(self, alert: Any) -> None:
        self.alerts.append(alert)


class Rig:
    def __init__(self, env_kwargs: dict[str, Any] | None = None, **router_kwargs: Any) -> None:
        self.items = InMemoryEscalationStore()
        self.outbox = InMemoryOutbox()
        self.alerts = Sink()
        router_kwargs.setdefault("alert_interval_s", 0.01)
        self.router = EscalationRouter(
            self.items, outbox=self.outbox, alerts=self.alerts, **router_kwargs
        )
        self.env = Env(escalations=self.router, **(env_kwargs or {}))
        self.env.fake.responder = lambda text, key, q: (
            float(P.search(text).group(1)) if key == "t__x" and P.search(text) else None
        )
        self.golden_store = InMemoryGoldenStore()
        self.golden = GoldenService(self.golden_store)
        self.audit = InMemoryAuthzAudit()
        self.authorizer = Authorizer(self.audit)
        self.clock_now = NOW
        self.deid = False

        async def needs_deid(scope: Any) -> bool:
            return self.deid

        self.service = EscalationService(
            self.items,
            self.golden,
            needs_deidentification=needs_deid,
            clock=lambda: self.clock_now,
        )

    async def __aenter__(self) -> Rig:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.router.aclose(timeout=1.0)
        await self.env.service.aclose()

    async def publish(self, **kw: Any) -> None:
        await self.env.publish(doc(**kw))

    async def escalate(self, tenant: str = ALPHA, content: str = "hello p=0.6", **kw: Any):
        """A check that escalates (and is routed); waits for the router to finish."""
        verdict = await self.env.check(tenant, "output", content, **kw)
        assert verdict.decision is Decision.ESCALATE, verdict
        assert await self.router.drain(2.0)
        return verdict

    async def decide(self, principal: Principal, method: str, route: str, tid: str | None = None):
        tid = principal.tenant_id if tid is None else tid
        decision = await self.authorizer.authorize(principal, method, BASE + route, tid)
        assert decision.allowed, decision.reason
        return decision

    # the three calls, as the REST layer makes them

    async def list(self, principal: Principal, **query: str):
        d = await self.decide(principal, "GET", "/escalations")
        return await self.service.list_items(d, **query)

    async def get(self, principal: Principal, item_id: str):
        d = await self.decide(principal, "GET", "/escalations/{id}")
        return await self.service.get_item(d, item_id)

    async def resolve(self, principal: Principal, item_id: str, **body: Any):
        body = {"decision": "allow", "reason": "looked fine", **body}
        d = await self.decide(principal, "POST", "/escalations/{id}/resolve")
        return await self.service.resolve(d, principal, item_id, json.dumps(body).encode())


def item_of(rig: Rig, tenant: str = ALPHA, n: int = 0):
    return rig.items.items(tenant)[n]


async def wait_until(predicate, timeout: float = 2.0) -> None:
    deadline = asyncio.get_running_loop().time() + timeout
    while not predicate():
        if asyncio.get_running_loop().time() > deadline:
            raise AssertionError("condition not reached")
        await asyncio.sleep(0.005)
