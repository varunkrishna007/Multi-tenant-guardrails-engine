"""The compiled deterministic rules of a guard point (M3-01).

The policy compiler turns a bundle's ``deterministic.deny_patterns`` and a guard point's
``tool_allowlist`` into these, once, when the bundle compiles: an invalid pattern is a
validation error then, so nothing is compiled on the check path. The Guard Service
(:mod:`guardrail_engine.guard.deterministic`) runs them before the model call.

**Rule ids.** A fired rule is reported by id and nothing else, never by the text it matched:

=====================  ==============================================================
``deny__<id>``         a tenant's deny pattern (``deterministic.deny_patterns[].id``)
``tool_allowlist``     a ``tool_call`` for a tool outside the guard point's allow-list
``tool_mismatch``      a ``tool_call`` whose content names a different tool than the
                       check's ``tool``
``tool_schema``        a ``tool_call`` whose arguments don't satisfy the JSON Schema the
                       tool registry holds for the tool (M3-03)
``xtenant_identifier`` another tenant's identifier in a ``tool_result`` or ``output``
``size_limit``         content over the guard point's maximum content tokens
=====================  ==============================================================

This module imports nothing from ``guard`` or ``policy``, so both can depend on it.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from guardrail_engine.deterministic.regex import CompiledRegex


class DeterministicAction(StrEnum):
    """What a deterministic rule does."""

    BLOCK = "block"
    """Content is not released and **no model call is made**."""
    ESCALATE = "escalate"
    """The model still runs; the more severe of the two results wins."""
    REDACT = "redact"
    """Each match is replaced by :data:`REDACTION_PLACEHOLDER` before rendering."""
    LOG = "log"
    """Recorded only."""


class DeterministicKind(StrEnum):
    DENY_PATTERN = "deny_pattern"
    TOOL_ALLOWLIST = "tool_allowlist"
    TOOL_MISMATCH = "tool_mismatch"
    TOOL_SCHEMA = "tool_schema"
    CROSS_TENANT = "cross_tenant"
    SIZE_LIMIT = "size_limit"


REDACTION_PLACEHOLDER = "[REDACTED]"
"""What a ``redact`` deny pattern's match is replaced by. The same for every rule, so the
placeholder says nothing about what was removed."""

DENY_RULE_PREFIX = "deny__"
TOOL_ALLOWLIST_RULE = "tool_allowlist"
TOOL_MISMATCH_RULE = "tool_mismatch"
TOOL_SCHEMA_RULE = "tool_schema"
CROSS_TENANT_RULE = "xtenant_identifier"
SIZE_LIMIT_RULE = "size_limit"


@dataclass(frozen=True, slots=True)
class DenyRule:
    """One compiled deny pattern."""

    id: str
    action: DeterministicAction
    regex: CompiledRegex

    @property
    def rule_id(self) -> str:
        return DENY_RULE_PREFIX + self.id


@dataclass(frozen=True, slots=True)
class GuardPointChecks:
    """The deterministic rules that apply at one guard point."""

    deny_rules: tuple[DenyRule, ...] = ()
    tool_allowlist: tuple[str, ...] | None = None
    """Enforced at ``tool_call`` (M3-01) and ``plan`` (M3-03), each against its own guard
    point's list. ``None`` means no allow-list: any tool may be called or planned. An empty
    tuple allows no tool."""

    @property
    def empty(self) -> bool:
        return not self.deny_rules and self.tool_allowlist is None


NO_CHECKS = GuardPointChecks()
