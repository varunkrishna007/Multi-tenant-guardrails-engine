"""What a caller hands to ``GuardService.check``: the request context.

Everything here except ``signed_context`` is **untrusted**: it comes from the agent and,
through it, from users, documents and tools. The tenant is never read from here; the payload
tenant id is carried only so that a mismatch can be refused (AC-T1).

The conversation context is a sequence of items, **oldest first**: prior turns, the plan,
tool calls and tool results. All of it is rendered inside nonce-delimited untrusted sections
(B3), and the oldest items are dropped first when it doesn't fit the content budget.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

ROLES = ("user", "assistant", "system", "tool")
Role = Literal["user", "assistant", "system", "tool"]


@dataclass(frozen=True, slots=True)
class Turn:
    """A prior conversation turn."""

    role: Role
    text: str


@dataclass(frozen=True, slots=True)
class Plan:
    """The agent's plan, as the JSON text it produced."""

    text: str


@dataclass(frozen=True, slots=True)
class ToolCall:
    """A tool call: the tool's name and its arguments as sent (usually JSON text)."""

    tool: str
    arguments: str


@dataclass(frozen=True, slots=True)
class ToolResult:
    """A tool's result, as returned."""

    tool: str
    result: str


ContextItem = Turn | Plan | ToolCall | ToolResult


@dataclass(frozen=True, slots=True)
class CheckContext:
    """The request context of one check."""

    signed_context: str
    """The signed tenant context the API gateway issued, passed through unchanged."""
    payload_tenant_id: str | None = None
    """A tenant id the request payload carried, if any. Never used as the tenant: a value
    that differs from the verified one gets a ``forbidden`` verdict."""
    request_id: str | None = None
    """The caller's request id. The service generates one when it is missing."""
    conversation: tuple[ContextItem, ...] = ()
    """Conversation context, oldest first."""
    conversation_id: str | None = None
    """The caller's id for the conversation this check belongs to (M4-03, PF-7). With a
    candidate version, ``hash(tenant_id, conversation_id)`` picks the version that decides, so
    every guard point of one conversation gets the same one. Without it the active version
    decides. Chosen by the runtime that owns the conversation; the signed tenant context has
    no such claim, so it is a rollout control, not a security boundary."""
    tool: str | None = None
    """The tool a ``tool_call`` check is about: **the tool the runtime will actually
    execute** (the SDK sets it). The tool allow-list (M3-01) is checked against it:
    with an allow-list configured, a ``tool_call`` check that names no tool, or a tool outside
    the list, is blocked. So is content that is a JSON object naming a different tool, in a
    top-level ``"tool"`` member (rule ``tool_mismatch``). Ignored at
    other guard points."""


def context_item_problem(item: object) -> str | None:
    """Why ``item`` is not a well-formed context item, or None if it is."""
    if isinstance(item, Turn):
        if item.role not in ROLES:
            return f"turn role must be one of {ROLES}"
        fields = (item.text,)
    elif isinstance(item, Plan):
        fields = (item.text,)
    elif isinstance(item, ToolCall):
        fields = (item.tool, item.arguments)
    elif isinstance(item, ToolResult):
        fields = (item.tool, item.result)
    else:
        return f"not a context item: {type(item).__name__}"
    if not all(isinstance(f, str) for f in fields):
        return f"{type(item).__name__} fields must be text"
    return None
