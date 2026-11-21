"""What the audit query accepts and what it returns (M4-07).

**Parameters** (``GET /v1/tenants/{tid}/guardrails/decisions``): ``from`` and ``to`` (ISO 8601
with a time zone; default the last 24 hours; at most 31 days apart, ``to`` exclusive),
``rule`` (a rule key that fired), ``decision`` (allow, escalate, block, forbidden),
``guard_point``, ``limit`` (1 to 200, default 50) and ``cursor`` (the ``next_cursor`` of the
page before). Anything else, or a bad value, is refused with the field named.

**What a record shows.** The stored record is the engine's whole audit record. The response is a
projection of it, and it never carries the floor, or what is derived from it:

* a floor rule appears only in ``fired``, as key, action and mode: its probability and its
  thresholds would be a gradient to tune content just under the floor;
* a tenant rule that is a copy of a floor rule (``floor_derived_keys``) shows no
  probability or thresholds either, and neither does any rule of a record whose bundle can't be
  read now (fail closed);
* ``answers`` (the whole probability map), ``floor_fail_mode`` and the other platform fields
  are not part of the response at all.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from guardrail_engine.audit.store import (
    DECISIONS,
    DecisionFilter,
    InvalidCursorError,
    Position,
    StoredDecision,
    decode_cursor,
    encode_cursor,
)

DEFAULT_WINDOW = timedelta(hours=24)
MAX_WINDOW = timedelta(days=31)
DEFAULT_LIMIT = 50
MAX_LIMIT = 200
MAX_TEXT = 128
PARAMETERS = frozenset({"from", "to", "rule", "decision", "guard_point", "limit", "cursor"})
SHOWN_LAYERS = ("tenant", "pack")
"""Layers whose probability and thresholds an auditor sees: the tenant's own rules and the
packs it enabled. The floor shows key, action and mode when it fired, nothing more."""


class BadParameterError(ValueError):
    """A parameter is not acceptable (HTTP 400); ``field`` names it."""

    def __init__(self, field: str, message: str) -> None:
        super().__init__(f"{field}: {message}")
        self.field = field
        self.message = message


@dataclass(frozen=True, slots=True)
class DecisionQuery:
    flt: DecisionFilter
    limit: int
    after: Position | None


def _time(params: Mapping[str, str], name: str) -> datetime | None:
    raw = params.get(name)
    if raw is None:
        return None
    try:
        when = datetime.fromisoformat(raw)
    except ValueError:
        raise BadParameterError(name, "an ISO 8601 time with a time zone") from None
    if when.tzinfo is None:
        raise BadParameterError(name, "an ISO 8601 time with a time zone")
    return when.astimezone(UTC)


def _text(params: Mapping[str, str], name: str) -> str | None:
    raw = params.get(name)
    if raw is None:
        return None
    if not 1 <= len(raw) <= MAX_TEXT or not raw.isprintable():
        raise BadParameterError(name, f"1 to {MAX_TEXT} printable characters")
    return raw


def parse_query(params: Mapping[str, str], now: datetime) -> DecisionQuery:
    unknown = sorted(set(params) - PARAMETERS)
    if unknown:
        raise BadParameterError(unknown[0], "not a parameter of this query")
    end = _time(params, "to") or now.astimezone(UTC)
    start = _time(params, "from") or end - DEFAULT_WINDOW
    if start >= end:
        raise BadParameterError("from", "must be before to")
    if end - start > MAX_WINDOW:
        raise BadParameterError("from", f"at most {MAX_WINDOW.days} days before to")
    decision = _text(params, "decision")
    if decision is not None and decision not in DECISIONS:
        raise BadParameterError("decision", f"one of {', '.join(DECISIONS)}")
    limit = DEFAULT_LIMIT
    if "limit" in params:
        try:
            limit = int(params["limit"])
        except ValueError:
            raise BadParameterError("limit", f"a whole number, 1 to {MAX_LIMIT}") from None
        if not 1 <= limit <= MAX_LIMIT:
            raise BadParameterError("limit", f"a whole number, 1 to {MAX_LIMIT}")
    after = None
    if "cursor" in params:
        try:
            after = decode_cursor(params["cursor"])
        except InvalidCursorError:
            raise BadParameterError("cursor", "not a cursor this service issued") from None
    flt = DecisionFilter(start, end, _text(params, "rule"), decision, _text(params, "guard_point"))
    return DecisionQuery(flt, limit, after)


def next_cursor(rows: list[StoredDecision], limit: int) -> str | None:
    """A cursor when the page was full (there may be more), else None."""
    if len(rows) < limit or not rows:
        return None
    last = rows[-1]
    return encode_cursor(Position(last.ts, last.id))


def present(record: dict[str, Any], hidden: frozenset[str] | None) -> dict[str, Any]:
    """The response entry for one stored record. ``hidden`` is the set of the record's tenant
    rules that are floor-derived, or None when it is not known (every rule's numbers are then
    hidden)."""
    fired = []
    for entry in record.get("fired", ()):
        item: dict[str, Any] = {
            "rule": entry["rule"], "action": entry["action"], "mode": entry["mode"],
        }  # fmt: skip
        if _numbers_shown(entry["layer"], entry["rule"], hidden):
            item.update(p=entry["p"], block_at=entry["block_at"], escalate_at=entry["escalate_at"])
        fired.append(item)
    rules = []
    for ev in record.get("rules", ()):
        if ev["layer"] not in SHOWN_LAYERS:
            continue  # the floor's evaluations are not listed: only what fired, above
        item = {
            "rule": ev["key"], "layer": ev["layer"], "mode": ev["mode"], "action": ev["action"],
            "basis": ev["basis"], "provisional": ev["provisional"],
        }  # fmt: skip
        if _numbers_shown(ev["layer"], ev["key"], hidden):
            item.update(p=ev["p"], block_at=ev["block_at"], escalate_at=ev["escalate_at"])
        rules.append(item)
    return {
        "request_id": record["request_id"],
        "ts": record["ts"],
        "guard_point": record["guard_point"],
        "decision": record["decision"],
        "reason": record["reason"],
        "retryable": record["retryable"],
        "detail": _detail(record),
        "bundle_version": record["bundle_version"],
        "candidate_version": record.get("candidate_version"),
        "candidate_decision": record.get("candidate_decision"),
        "fired": fired,
        "rules": rules,
        "deterministic": record.get("deterministic", []),
        "model_called": record["model_called"],
        "failure_kind": record["failure_kind"],
        "latency_ms": record["latency_ms"],
        "content_sha256": record["content_sha256"],
        "retain_until": record["retain_until"],
    }


def _numbers_shown(layer: str, key: str, hidden: frozenset[str] | None) -> bool:
    return layer in SHOWN_LAYERS and hidden is not None and key not in hidden


INTERNAL_DETAIL = "the check failed inside the engine"


def _detail(record: dict[str, Any]) -> str | None:
    """The engine-authored detail, except for an internal error: a floor-integrity failure's
    text carries the catalog's floor thresholds and ``floor_fail_mode``, so it is replaced by a
    fixed sentence (the reason, ``internal_error``, stays)."""
    if record.get("reason") == "internal_error":
        return INTERNAL_DETAIL
    return record["detail"]
