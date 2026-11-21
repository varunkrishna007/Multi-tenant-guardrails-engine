"""Moving a tenant's bundle to a new floor version (R5, M2-09): the pure transform.

A re-pin changes the bundle's ``extends`` entry for the floor and **nothing else of the
tenant's**: rules, packs, defaults, guard points, deterministic rules, escalation and audit
settings are copied as they are. The one place the new floor can reach into the tenant's own
content is a **floor override**, which is only legitimate while it is still stricter than the
floor it sits on:

* an override's ``block_at`` and ``escalate_at`` are each kept only if **strictly lower** than
  the new floor's value for that rule (lower fires sooner, so it is stricter); otherwise the
  floor value applies and the drop is listed;
* an override on a floor rule the new floor no longer has is dropped and listed;
* if the kept thresholds can't make a valid pair with the new floor's other threshold
  (``0.01 <= escalate_at < block_at <= 0.99``), the whole override is dropped and listed;
* the other fields of a floor override (``enabled``, ``mode``, restated text) can only ever
  restate the floor, never change it, so they are not carried: an override is its thresholds.

The caller validates the result with the compiler and sets the version; this module doesn't
read a catalog beyond the :class:`FloorVersion` it is given, and does no I/O.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from guardrail_engine.policy.catalog import FloorVersion
from guardrail_engine.policy.document import EXTENDS_REF_PATTERN

THRESHOLDS = ("block_at", "escalate_at")
NOT_STRICTER = "not_stricter"
RULE_REMOVED = "rule_removed"
PAIR_INVALID = "pair_invalid"


class RepinError(ValueError):
    """The bundle can't be re-pinned: it doesn't extend exactly one floor version."""


@dataclass(frozen=True, slots=True)
class OverrideDrop:
    rule: str
    field: str
    """``block_at``, ``escalate_at`` or ``override`` (the whole entry)."""
    old: float | None
    """What the tenant's override said."""
    floor: float | None
    """What the new floor says for that field (``None``: the rule is gone)."""
    reason: str
    """``not_stricter``, ``rule_removed`` or ``pair_invalid``."""

    def as_dict(self) -> dict[str, Any]:
        return {
            "rule": self.rule, "field": self.field, "old": self.old, "floor": self.floor,
            "reason": self.reason,
        }  # fmt: skip


@dataclass(frozen=True, slots=True)
class Repin:
    document: dict[str, Any]
    from_floor: int
    to_floor: int
    drops: tuple[OverrideDrop, ...]


def floor_version_of(document: dict[str, Any]) -> int:
    """The version of the one floor the document extends. Raises :class:`RepinError`."""
    found = []
    for ref in document.get("extends", []):
        m = EXTENDS_REF_PATTERN.fullmatch(ref) if isinstance(ref, str) else None
        if m is not None and m.group(1):
            found.append(int(m.group(3)))
    if len(found) != 1:
        raise RepinError("the bundle does not extend exactly one floor version")
    return found[0]


def repin_document(document: dict[str, Any], new_floor: FloorVersion) -> Repin:
    """``document`` (a stored bundle, left untouched) on ``new_floor``, with the carry-over."""
    from_floor = floor_version_of(document)
    out = _clone(document)
    out["extends"] = [
        new_floor.ref if _is_floor_ref(ref) else ref for ref in document.get("extends", [])
    ]
    rules = {r.key: r for r in new_floor.content.rules}
    kept: list[dict[str, Any]] = []
    drops: list[OverrideDrop] = []
    for override in document.get("overrides", []):
        key = override.get("rule") if isinstance(override, dict) else None
        if not isinstance(key, str) or not key.startswith("p__"):
            kept.append(_clone(override))  # a pack override: not the floor's business
            continue
        rule = rules.get(key)
        if rule is None:
            drops.append(OverrideDrop(key, "override", None, None, RULE_REMOVED))
            continue
        carried: dict[str, float] = {}
        for name in THRESHOLDS:
            old = override.get(name)
            if old is None:
                continue
            floor_value = getattr(rule, name)
            if floor_value is not None and old < floor_value:
                carried[name] = old
            else:
                drops.append(OverrideDrop(key, name, old, floor_value, NOT_STRICTER))
        if not carried:
            continue
        block = carried.get("block_at", rule.block_at)
        escalate = carried.get("escalate_at", rule.escalate_at)
        if block is None or escalate is None or not 0.01 <= escalate < block <= 0.99:
            for name, value in carried.items():
                drops.append(OverrideDrop(key, name, value, getattr(rule, name), PAIR_INVALID))
            continue
        kept.append({"rule": key, **carried})
    if "overrides" in document:
        out["overrides"] = kept
    return Repin(out, from_floor, new_floor.version, tuple(drops))


def _clone(value: Any) -> Any:
    """A deep copy of JSON data (the policy package imports no ``copy``)."""
    return json.loads(json.dumps(value))


def _is_floor_ref(ref: object) -> bool:
    m = EXTENDS_REF_PATTERN.fullmatch(ref) if isinstance(ref, str) else None
    return m is not None and bool(m.group(1))


__all__ = [
    "NOT_STRICTER", "PAIR_INVALID", "RULE_REMOVED", "OverrideDrop", "Repin", "RepinError",
    "floor_version_of", "repin_document",
]  # fmt: skip
