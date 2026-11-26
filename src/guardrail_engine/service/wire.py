"""The wire contract of the check endpoint (M7-10): what crosses between the agent runtime and
the guard service, and nothing more.

**The request** is ``POST /v1/check``. The signed tenant context (M2-01) is in the
``Guard-Context`` header, never in the body, and **the body has no tenant id**: the tenant comes
only from the verified context (AC-T1). The body is one JSON object with these members, and no
others (an unknown member is a 400, so a ``tenant_id`` can't be smuggled in):

* ``guard_point``, ``content``: what the in-process call takes. Their types are the engine's to
  judge (a non-text value gets the engine's ``invalid_request`` block, as in process);
* ``conversation``: a list of items, oldest first, each ``{"type": "turn", "role", "text"}``,
  ``{"type": "plan", "text"}``, ``{"type": "tool_call", "tool", "arguments"}`` or
  ``{"type": "tool_result", "tool", "result"}``;
* ``conversation_id``, ``tool``, ``request_id``: optional text.

**The response** is the public :class:`~guardrail_engine.sdk.result.GuardResult` as JSON, and
nothing of the verdict beyond it: not the rules' probabilities, thresholds or per-rule evaluation
(the platform's numbers are never shown to a tenant, and the runtime is tenant-side code), not
the failure's free text. The HTTP status is the transport's and the authentication's: ``200``
for every verdict, ``401`` for a context that is missing, malformed, forged or expired (the body
is the same public result, a ``forbidden``) and ``403`` for the other ``forbidden`` verdicts.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from guardrail_engine.guard.request import (
    CheckContext,
    ContextItem,
    Plan,
    ToolCall,
    ToolResult,
    Turn,
)
from guardrail_engine.sdk.result import FailureReason, FiredRule, GuardResult

CHECK_PATH = "/v1/check"
HEALTH_PATH = "/healthz"
CONTEXT_HEADER = "Guard-Context"
REQUEST_ID_HEADER = "Guard-Request-Id"
"""The request id also travels in this header. The service echoes it on an answer it gives before
it reads the body (a 401), so every answer carries the caller's id; if the body has a
``request_id`` it must equal the header's, else 400."""
MAX_REQUEST_ID_CHARS = 128

REQUEST_MEMBERS = frozenset(
    {"guard_point", "content", "conversation", "conversation_id", "tool", "request_id"}
)

RESULT_MEMBERS = (
    "decision",
    "reason",
    "request_id",
    "guard_point",
    "fired",
    "retryable",
    "failure_reason",
    "capacity_limited",
    "retry_after_ms",
    "degraded",
)


class WireError(ValueError):
    """The body is not a well-formed request (or response). The message says which member, never
    its value."""


def item_to_wire(item: ContextItem) -> dict[str, str]:
    if isinstance(item, Turn):
        return {"type": "turn", "role": item.role, "text": item.text}
    if isinstance(item, Plan):
        return {"type": "plan", "text": item.text}
    if isinstance(item, ToolCall):
        return {"type": "tool_call", "tool": item.tool, "arguments": item.arguments}
    if isinstance(item, ToolResult):
        return {"type": "tool_result", "tool": item.tool, "result": item.result}
    raise WireError(f"not a context item: {type(item).__name__}")


def _text(doc: Mapping[str, Any], member: str, where: str) -> str:
    value = doc.get(member)
    if not isinstance(value, str):
        raise WireError(f"{where}.{member} must be text")
    return value


def item_from_wire(doc: object, index: int) -> ContextItem:
    where = f"conversation[{index}]"
    if not isinstance(doc, dict):
        raise WireError(f"{where} must be an object")
    kind = doc.get("type")
    if kind == "turn":
        _only(doc, {"type", "role", "text"}, where)
        role = _text(doc, "role", where)
        if role not in ("user", "assistant", "system", "tool"):
            raise WireError(f"{where}.role is not a role")
        return Turn(role=role, text=_text(doc, "text", where))  # type: ignore[arg-type]
    if kind == "plan":
        _only(doc, {"type", "text"}, where)
        return Plan(text=_text(doc, "text", where))
    if kind == "tool_call":
        _only(doc, {"type", "tool", "arguments"}, where)
        return ToolCall(tool=_text(doc, "tool", where), arguments=_text(doc, "arguments", where))
    if kind == "tool_result":
        _only(doc, {"type", "tool", "result"}, where)
        return ToolResult(tool=_text(doc, "tool", where), result=_text(doc, "result", where))
    raise WireError(f"{where}.type is not a known item type")


def _only(doc: Mapping[str, Any], allowed: set[str], where: str) -> None:
    if set(doc) - allowed:
        raise WireError(f"{where} has a member that is not part of the contract")


def _optional_text(doc: Mapping[str, Any], member: str) -> str | None:
    value = doc.get(member)
    if value is not None and not isinstance(value, str):
        raise WireError(f"{member} must be text or null")
    return value


def request_to_body(
    guard_point: str,
    content: str,
    *,
    conversation: tuple[ContextItem, ...] = (),
    conversation_id: str | None = None,
    tool: str | None = None,
    request_id: str | None = None,
) -> dict[str, Any]:
    return {
        "guard_point": guard_point,
        "content": content,
        "conversation": [item_to_wire(i) for i in conversation],
        "conversation_id": conversation_id,
        "tool": tool,
        "request_id": request_id,
    }


def request_from_body(doc: object) -> tuple[Any, Any, dict[str, Any]]:
    """The guard point, the content and the keyword members of a ``CheckContext``, from a parsed
    body. Raises :class:`WireError`."""
    if not isinstance(doc, dict):
        raise WireError("the body must be a JSON object")
    unknown = set(doc) - REQUEST_MEMBERS
    if unknown:
        raise WireError("the body has a member that is not part of the contract")
    for required in ("guard_point", "content"):
        if required not in doc:
            raise WireError(f"{required} is required")
    conversation = doc.get("conversation", [])
    if not isinstance(conversation, list):
        raise WireError("conversation must be a list")
    return (
        doc["guard_point"],
        doc["content"],
        {
            "conversation": tuple(item_from_wire(item, i) for i, item in enumerate(conversation)),
            "conversation_id": _optional_text(doc, "conversation_id"),
            "tool": _optional_text(doc, "tool"),
            "request_id": _optional_text(doc, "request_id"),
        },
    )


def check_context(signed_context: str, members: Mapping[str, Any]) -> CheckContext:
    return CheckContext(signed_context=signed_context, **members)


def result_to_wire(result: GuardResult) -> dict[str, Any]:
    """The public result as JSON-ready data: exactly :data:`RESULT_MEMBERS`."""
    return {
        "decision": result.decision,
        "reason": result.reason,
        "request_id": result.request_id,
        "guard_point": result.guard_point,
        "fired": [{"key": f.key, "action": f.action, "mode": f.mode} for f in result.fired],
        "retryable": result.retryable,
        "failure_reason": None if result.failure_reason is None else result.failure_reason.value,
        "capacity_limited": result.capacity_limited,
        "retry_after_ms": result.retry_after_ms,
        "degraded": result.degraded,
    }


def _flag(doc: Mapping[str, Any], member: str) -> bool:
    value = doc.get(member)
    if not isinstance(value, bool):
        raise WireError(f"{member} must be true or false")
    return value


def result_from_wire(
    doc: object, *, request_id: str | None = None, guard_point: str | None = None
) -> GuardResult:
    """The result a response body holds, as an answer to **this** request: every member of
    :data:`RESULT_MEMBERS` is present with its type, and when ``request_id`` and ``guard_point``
    are given they equal the response's. Members a newer service adds are dropped, never surfaced
    and never a reason to refuse. A failure reason this SDK doesn't know reads as ``other``: still
    withheld. Raises :class:`WireError`."""
    if not isinstance(doc, dict):
        raise WireError("the response must be a JSON object")
    if any(member not in doc for member in RESULT_MEMBERS):
        raise WireError("the response lacks a member of the contract")
    fired = doc.get("fired")
    if not isinstance(fired, list):
        raise WireError("fired must be a list")
    rules = []
    for entry in fired:
        if not (
            isinstance(entry, dict)
            and all(isinstance(entry.get(k), str) for k in ("key", "action", "mode"))
        ):
            raise WireError("fired holds an entry that is not a rule")
        rules.append(FiredRule(key=entry["key"], action=entry["action"], mode=entry["mode"]))
    failure = doc.get("failure_reason")
    if failure is not None and not isinstance(failure, str):
        raise WireError("failure_reason must be text or null")
    retry_after = doc.get("retry_after_ms")
    if retry_after is not None and (
        isinstance(retry_after, bool) or not isinstance(retry_after, int)
    ):
        raise WireError("retry_after_ms must be a whole number or null")
    known = {r.value for r in FailureReason}
    answered_id = _text(doc, "request_id", "response")
    answered_point = _text(doc, "guard_point", "response")
    if request_id is not None and answered_id != request_id:
        raise WireError("the response answers another request")
    if guard_point is not None and answered_point != guard_point:
        raise WireError("the response answers another guard point")
    return GuardResult(
        decision=_text(doc, "decision", "response"),
        reason=_text(doc, "reason", "response"),
        request_id=answered_id,
        guard_point=answered_point,
        fired=tuple(rules),
        retryable=_flag(doc, "retryable"),
        failure_reason=None
        if failure is None
        else FailureReason(failure)
        if failure in known
        else FailureReason.OTHER,
        capacity_limited=_flag(doc, "capacity_limited"),
        retry_after_ms=retry_after,
        degraded=_flag(doc, "degraded"),
    )
