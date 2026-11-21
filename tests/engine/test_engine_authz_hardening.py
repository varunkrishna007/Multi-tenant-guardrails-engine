"""Factory delta: a durable cross-tenant audit sink and the Postgres role
check at startup (tests with a database in tests/store/test_store_app_role_check.py)."""

from __future__ import annotations

import json

import pytest
from engine_fixtures import directory, settings, verifier

from guardrail_engine.authz import InMemoryAuthzAudit, Principal, Role
from guardrail_engine.decision import FakeDecisionModel
from guardrail_engine.engine import SettingsError, build_engine

ALPHA, BETA = "t_alpha1", "t_beta2"
ROUTE = ("GET", "/v1/tenants/{tid}/guardrails")


class DurableStub:
    durable = True

    def __init__(self):
        self.events = []

    async def record(self, event):
        self.events.append(event)


async def build(environment="test", **kwargs):
    return await build_engine(
        kwargs.pop("settings", None) or settings(environment),
        verifier=verifier(), tenants=directory(), model=FakeDecisionModel(), **kwargs,
    )  # fmt: skip


@pytest.mark.parametrize("environment", ["production", "staging"])
async def test_an_in_memory_cross_tenant_sink_is_refused_outside_test(environment):
    with pytest.raises(SettingsError, match="authz_audit") as info:
        await build(environment, authz_audit=InMemoryAuthzAudit())
    assert "durable" in str(info.value) and "environment is 'test'" in str(info.value)


async def test_an_in_memory_cross_tenant_sink_is_accepted_in_test():
    engine = await build("test", authz_audit=InMemoryAuthzAudit())
    try:
        assert engine.authorizer is not None
    finally:
        await engine.shutdown()


async def test_a_durable_sink_is_accepted_in_production():
    engine = await build("production", authz_audit=DurableStub())
    try:
        assert engine.authorizer is not None
    finally:
        await engine.shutdown()


async def test_the_class_a_file_becomes_the_cross_tenant_sink_and_is_written_before_the_answer(
    tmp_path,
):
    path = tmp_path / "class_a.jsonl"
    engine = await build(settings=settings("staging", class_a_audit={"file": str(path)}))
    try:
        assert engine.authorizer is not None
        operator = Principal("ops-1", None, frozenset({Role.VIEWER}), True, "https://idp.example/")
        decision = await engine.authorizer.authorize(operator, *ROUTE, tenant_id=BETA)
        assert decision.allowed and decision.cross_tenant
        lines = [json.loads(line) for line in path.read_text().splitlines()]
        assert [(e["event"], e["actor"], e["target_tenant_id"], e["allowed"]) for e in lines] == [
            ("cross_tenant_access", "https://idp.example/#ops-1", BETA, True)
        ]
        assert set(lines[0]) == {
            "event", "at", "actor", "actor_tenant_id", "target_tenant_id", "method", "route",
            "allowed", "reason",
        }  # fmt: skip
    finally:
        await engine.shutdown()


async def test_a_failed_write_to_the_file_refuses_the_cross_tenant_access(tmp_path):
    path = tmp_path / "class_a.jsonl"
    engine = await build(settings=settings("staging", class_a_audit={"file": str(path)}))
    try:
        path.unlink()
        path.mkdir()  # the file can no longer be opened for append
        operator = Principal("ops-1", None, frozenset({Role.VIEWER}), True, "https://idp.example/")
        decision = await engine.authorizer.authorize(operator, *ROUTE, tenant_id=ALPHA)
        assert not decision.allowed and decision.reason == "audit_unavailable"
        assert decision.scope is None
    finally:
        await engine.shutdown()


async def test_production_with_a_postgres_store_requires_the_operator_role(monkeypatch):
    """Without it the membership check would be skipped by omission."""
    monkeypatch.setenv("GUARDRAIL_PG_DSN", "postgresql://app@db/guardrails")
    with pytest.raises(SettingsError, match=r"store\.operator_role: required in production"):
        await build(settings=settings("production", store={"kind": "postgres"}))
    # Staging takes production-shaped traffic, so it needs it too
    with pytest.raises(SettingsError, match=r"store\.operator_role: required in staging"):
        await build(settings=settings("staging", store={"kind": "postgres"}))
    # test doesn't require it
    problems = [
        p
        for p in await _problems(settings("test", store={"kind": "postgres"}))
        if "operator_role" in p
    ]
    assert problems == []


async def _problems(s):
    try:
        await build(settings=s)
    except SettingsError as e:
        return e.problems
    except Exception:  # the stand-in DSN can't connect: the settings problems passed
        return []
    return []
