"""Through the calibration service: a tenant rule that forks a capped pack rule can only
escalate, so the suggestion sets only ``escalate_at``, accepting it keeps the rule's own
``block_at``, and the precision gate (which measures blocks) has nothing to measure."""

import json
import re

import admin_fixtures
import pytest
from admin_fixtures import ALPHA, Admin, bundle, rule
from guard_fixtures import FLOOR_V1
from test_calibration import (
    calibrate,
    decide_thresholds,
    known_set,
    save,
    stored_rule,
    suggestion,
    upload,
    validate,
)

from guardrail_engine.policy import InMemoryCatalog
from guardrail_engine.policy.catalog import PackVersion
from guardrail_engine.tenant_scope import issue_scope

P = re.compile(r"p=([0-9.]+)")
QUESTION = "Does the message show that the person may be at risk?"


def capped_catalog(templates=(), extra_floors=()):
    pack = PackVersion.from_document(
        {
            "schema_version": 2, "name": "claims", "version": 1,
            "rules": [
                {
                    "key": "d__at_risk", "guard_points": ["output"], "max_action": "escalate",
                    "question": {"type": "noul", "instructions": QUESTION},
                    "block_at": 0.9, "escalate_at": 0.5,
                }
            ],
        }
    )  # fmt: skip
    return InMemoryCatalog(floors=[FLOOR_V1, *extra_floors], packs=[pack], templates=templates)


@pytest.fixture
async def a(monkeypatch):
    monkeypatch.setattr(admin_fixtures, "make_catalog", capped_catalog)
    admin = Admin(precision_gate=True)
    admin.fake.responder = lambda text, key, q: (
        float(P.search(text).group(1)) if key == "t__refunds" and P.search(text) else None
    )
    yield admin
    await admin.aclose()


def forked(**changes):
    return rule("refunds", question="Is the person who wrote this at risk of harm?") | {
        "origin": "fork:d__at_risk",
        **changes,
    }


async def prepared(a, **changes):
    await save(a, bundle(ALPHA, rules=[forked(**changes)], packs=["domain/claims@1"]))
    await upload(a, known_set())
    await calibrate(a)


async def test_a_capped_forks_suggestion_sets_only_escalate_at(a):
    await prepared(a)
    s = suggestion(await validate(a))
    assert s["block_at"] is None and s["available"] is True
    assert s["escalate_at"] == 0.50 and s["reason"] is None  # worked out in test_sweep: recall 0.90


async def test_accepting_it_keeps_the_rules_own_block_at_and_writes_escalate_at(a):
    await prepared(a, escalate_at=0.3)
    (done,) = (await decide_thresholds(a, {"refunds": {"action": "accept"}}))["decisions"]
    stored = await stored_rule(a)
    assert (stored["block_at"], stored["escalate_at"]) == (0.8, 0.5)
    assert done["applied"] == {"block_at": 0.8, "escalate_at": 0.5}
    assert done["previous"] == {"block_at": 0.8, "escalate_at": 0.3}


async def test_the_precision_gate_has_nothing_to_measure_for_a_rule_that_cannot_block(a):
    await prepared(a)
    draft = await a.drafts.scoped(issue_scope(ALPHA)).get(ALPHA)
    failures, record = await a.calibration.precision_gate(
        issue_scope(ALPHA), json.loads(draft.document)
    )
    assert failures == [] and "refunds escalate-only, no precision gate" in record
