"""The use-case cards are built from the committed live records and the @2 packs: no network."""

from __future__ import annotations

import pytest

from demo import render_usecases as uc


@pytest.mark.parametrize("name", sorted(uc.TENANTS))
def test_each_pair_is_stopped_on_one_side_and_allowed_on_the_other(name: str) -> None:
    html, audit = uc.card(name, uc.TENANTS[name])
    assert len(audit) == 4
    for pair in audit:
        assert pair["bad_verdict"] in {"block", "escalate"}
        assert pair["good_verdict"] == "allow"
        # the platform floor doesn't change the verdict shown
        assert pair["floor_max_bad"] < 0.30 and pair["floor_max_good"] < 0.30
    assert f"{name}@2 thresholds, provisional" in html
    assert "synthetic test data" in html


def test_escalate_only_rules_never_block() -> None:
    rule = {
        "guard_points": ["input"],
        "block_at": 0.5,
        "escalate_at": 0.3,
        "max_action": "escalate",
    }
    row = {"guard_point": "input"}
    assert uc.verdict(row, {"r": 0.99}, {"r": rule})[0] == "escalate"


def test_only_rows_that_were_sent_are_shown() -> None:
    cfg = dict(uc.TENANTS["finance"])
    cfg["pairs"] = [("fin-ret-pos-001", "no-such-row", "x")]
    with pytest.raises((AssertionError, KeyError)):
        uc.card("finance", cfg)
