"""Shared helpers for the M2-09 floor tests: a floor@2, release reports, operators."""

import json

from admin_fixtures import ALPHA, BETA, CORPUS_HASH, Admin, bundle, who
from guard_fixtures import FLOOR_V1

from guardrail_engine.authz import Role
from guardrail_engine.policy.catalog import FloorVersion
from guardrail_engine.tenant_scope import issue_scope

TENANT_BASE = "/v1/tenants/{tid}/guardrails"


def _floor2() -> FloorVersion:
    doc = FLOOR_V1.document
    doc["floor_version"] = 2
    new = {"p__inj_direct": (0.75, 0.50), "p__ai_addressed": (0.80, 0.40)}
    for rule in doc["rules"]:
        if rule["key"] in new:
            rule["block_at"], rule["escalate_at"] = new[rule["key"]]
    return FloorVersion.from_document(doc)


FLOOR_V2 = _floor2()


def report(version=2, **over):
    """An M2-08 JSON report that passes."""
    base = {
        "mode": "live", "floor_version": version, "floor_content_hash": FLOOR_V2.content_hash(),
        "corpus_sha256": CORPUS_HASH, "rows": 172, "draws": 3, "nonce_seed": "ab" * 16,
        "incomplete": [], "excluded_cells": 0, "structure": {"rows_checked": 172, "violations": {}},
        "gate": {"exit_code": 0, "passed": True},
    }  # fmt: skip
    return {**base, **over}


def operator(subject="op1"):
    return who(Role.VIEWER, tenant=None, operator=True, subject=subject, issuer="https://i/")


def new_admin(**kw) -> Admin:
    return Admin(extra_floors=(FLOOR_V2,), **kw)


async def pdecide(a, principal, method, route):
    return await a.authorizer.authorize(principal, method, route, tenant_id=None)


async def release(a, *, urgent=(False, False), rep=None, proposer="op1", approver="op2"):
    """Propose floor@2 by ``proposer`` and approve it by ``approver``."""
    p, q = operator(proposer), operator(approver)
    d = await pdecide(a, p, "POST", "/v1/platform/floors/{version}/release")
    body = json.dumps({"report": rep or report(), "security_urgent": urgent[0]}).encode()
    proposed = await a.floors.propose(d, p, 2, body)
    d = await pdecide(a, q, "POST", "/v1/platform/floors/{version}/approve")
    named = {"security_urgent": urgent[1], "report_sha256": proposed.evidence["report_sha256"]}
    return await a.floors.approve(d, q, 2, json.dumps(named).encode())


async def active_tenant(a, tid=ALPHA, doc=None):
    """Tenant ``tid`` with version 1 active and a draft at the same content (via the services)."""
    principal = who(Role.GUARDRAIL_ADMIN, tenant=tid, issuer="https://i/")
    d = await a.decide(principal, "PUT", TENANT_BASE + "/draft", tid)
    saved = await a.service.put_draft(d, principal, json.dumps(doc or bundle(tid)).encode(), None)
    d = await a.decide(principal, "POST", TENANT_BASE + "/draft/publish", tid)
    return await a.publisher.publish(d, principal, b'{"mode": "enforce"}', saved.etag)


def lifecycle(a, tid=ALPHA):
    return a.lifecycle.scoped(issue_scope(tid))


async def docs(a, tid, version):
    return await lifecycle(a, tid).document(tid, version)


__all__ = ["ALPHA", "BETA", "FLOOR_V2", "TENANT_BASE"]
