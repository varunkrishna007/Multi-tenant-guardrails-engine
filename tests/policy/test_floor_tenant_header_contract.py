"""The ``TENANT`` header is part of the floor contract.

A floor rule's text may name "the TENANT header" to tell the model which tenant is the
caller's own. That couples the rule text to the renderer's layout: if the header's label or
format changed without a new floor version (R5), the rule would silently refer to something
that no longer exists. This test pins the coupling: every rule in ``floor/rules.json`` and in
the staged floor@2 assembly whose text names the header is rendered, at each of its guard
points, with a trusted ``TENANT: <slug> (<id>)`` line.

**If this test fails because the header changed, the change needs a new floor version.**
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from calibration.run import assemble_floor, compile_floor

from guardrail_engine.guard.render import render_input, tenant_line

ROOT = Path(__file__).resolve().parents[2]
RULES = ROOT / "floor" / "rules.json"
ADDITIONS = ROOT / "floor" / "next" / "additions.json"

HEADER_NAME = "TENANT header"
SLUG, TENANT_ID = "acme-insurance", "t_1042"
PINNED_LINE = f"TENANT: {SLUG} ({TENANT_ID})"
"""The header's label and format as floor texts know them. Pinned as a literal, not built
with ``tenant_line``, so a renderer change fails here."""
UNTRUSTED_OPEN = "<<<UNTRUSTED:"
NONCE = "0123456789abcdef0123456789abcdef"


def floors() -> dict[str, dict]:
    return {
        "floor/rules.json": json.loads(RULES.read_text()),
        "staged floor@2": assemble_floor(RULES, ADDITIONS),
    }


def naming_rules(floor: dict) -> list[dict]:
    return [rule for rule in floor["rules"] if HEADER_NAME in json.dumps(rule)]


def trusted_part(text: str) -> str:
    """The rendered input before the first untrusted section: only platform-set lines."""
    return text.split(UNTRUSTED_OPEN, 1)[0]


def test_the_contract_is_exercised():
    """At least one staged rule names the header (``p__xtenant_probe``), so the test below
    can't pass by finding nothing to check."""
    assert "p__xtenant_probe" in {r["key"] for r in naming_rules(floors()["staged floor@2"])}


def test_the_renderer_still_prints_the_pinned_line():
    assert tenant_line(SLUG, TENANT_ID) == PINNED_LINE


@pytest.mark.parametrize("name", ["floor/rules.json", "staged floor@2"])
def test_every_rule_naming_the_tenant_header_is_rendered_with_one(name):
    floor = floors()[name]
    questions, _ = compile_floor(floor)
    for rule in naming_rules(floor):
        for guard_point in rule["guard_points"]:
            # The text the model receives at this guard point still names the header...
            asked = questions[guard_point][rule["key"]]
            assert HEADER_NAME in json.dumps(asked.model_dump(mode="json"))
            # ...and the input it is asked about carries it, in the trusted part, once.
            rendered = render_input(
                domain="insurance",
                tenant_slug=SLUG,
                tenant_id=TENANT_ID,
                guard_point=guard_point,
                content="c",
                conversation=(),
                tools={},
                max_content_tokens=1_000,
                nonce_source=lambda: NONCE,
            )
            lines = trusted_part(rendered.text).splitlines()
            assert lines.count(PINNED_LINE) == 1, (rule["key"], guard_point)
            assert sum(bool(re.match(r"TENANT: ", line)) for line in lines) == 1
