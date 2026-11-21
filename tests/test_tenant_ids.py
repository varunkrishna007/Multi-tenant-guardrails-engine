"""The one tenant id rule (B3): ``t_[0-9a-z]{1,32}``, generated at random."""

import pytest

from guardrail_engine.guard import context
from guardrail_engine.tenant_ids import (
    GENERATED_ID_CHARS,
    TENANT_ID_PATTERN,
    is_valid_tenant_id,
    new_tenant_id,
)

BAD_IDS = ["t_acme_ins", "t_Acme", "t-acme", "t_" + "a" * 33, "", "t_", None, 7]


def test_a_generated_id_matches_the_pattern():
    ids = {new_tenant_id() for _ in range(200)}
    assert all(is_valid_tenant_id(i) for i in ids)
    assert all(len(i) == 2 + GENERATED_ID_CHARS for i in ids)
    assert len(ids) == 200  # random, not sequential: no collisions in a small sample


@pytest.mark.parametrize("value", BAD_IDS)
def test_ids_outside_the_rule_are_refused(value):
    assert not is_valid_tenant_id(value)


def test_the_signed_context_imports_the_shared_rule():
    """guard/context.py keeps no copy of the pattern: it imports this module's (M1 integration,
    the follow-up recorded under B3's tenant creation item)."""
    assert context.TENANT_ID_PATTERN is TENANT_ID_PATTERN
    assert context.is_valid_tenant_id is is_valid_tenant_id
