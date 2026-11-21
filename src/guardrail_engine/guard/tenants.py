"""Tenant configuration the Guard Service needs besides the bundle: the ``TenantDirectory``
port and an in-memory implementation (M1-05, "Tenant directory port").

The bundle schema carries no tenant domain, and the compiler's ``ToolRegistry`` only answers
"is this tool registered". Rendering (B3) needs the tenant's domain and the tool registry's
metadata (name, description, ``read_only``), and compiling needs the tenant's attributes.
All of it is platform configuration, never request data.

**What is trusted (B3, amended 2026-11-17).**

* The **domain** is a tenant attribute set by platform ops from a fixed list
  (:data:`DOMAINS`). The tenant can't edit it. A profile with any other value can't be
  built, and the policy cache re-checks it, so a directory that bypasses the constructor
  still can't put free text in the ``TENANT DOMAIN`` header.
* The tenant's **identity** (B3 amendment, 2026-11-17): its **slug** and its **id**, printed
  as ``TENANT: <slug> (<id>)``. Both are set by platform ops; the tenant can't edit either.
  The slug must match :data:`TENANT_SLUG_PATTERN` and the id :data:`TENANT_ID_PATTERN` (the
  same rule the signed context enforces), so neither can carry a newline, a control
  character, a delimiter or a header. The slug also may not contain an instruction-like
  part from :data:`SLUG_DENYLIST`: a pattern blocks structure, not meaning. A
  profile with any other value can't be built, and the policy cache re-checks both, as for
  the domain. The id is the profile's ``attributes.tenant_id``; the policy cache also checks
  it is the tenant the check authenticated, so the header's id has one source: the verified
  signed context.
* A tool **name** is trusted, and printed outside the untrusted sections, only when it is a
  validated identifier matching :data:`TOOL_NAME_PATTERN`. Any other registered name is
  accepted here but always rendered inside an untrusted section.
* A tool **description** is tenant-written free text. It is always rendered inside the
  untrusted ``tool_metadata`` section, so it may contain anything.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Protocol

from guardrail_engine.guard.tool_schema import freeze_schema, schema_problem
from guardrail_engine.policy.catalog import TenantAttributes
from guardrail_engine.tenant_ids import TENANT_ID_PATTERN, is_valid_tenant_id

DOMAINS = ("insurance", "energy", "finance", "healthcare", "general")
"""The tenant domains platform ops can set (backlog M1-01 inputs, B3)."""

TOOL_NAME_PATTERN = re.compile(r"[a-z0-9_.]{1,64}")
"""A tool name that may be rendered as trusted text (B3). Use with ``fullmatch``."""


TENANT_SLUG_PATTERN = re.compile(r"[a-z0-9-]{1,40}")
"""A tenant slug (B3 data format), e.g. ``acme-insurance``: at most 40 characters.
Use with ``fullmatch``."""

SLUG_DENYLIST = frozenset(
    {
        "ignore", "skip", "bypass", "override", "approve", "approved", "allow", "safe",
        "exempt", "verdict", "check", "checks", "filter", "guardrail", "classifier",
        "moderator", "system", "prompt", "admin", "instruction", "instructions",
    }
)  # fmt: skip
"""Instruction-like tokens a slug may not contain as a hyphen-separated part (B3).
The slug is printed in the trusted header, and a pattern blocks structure, not meaning, so a
slug such as ``ignore-previous-rules`` would steer the model from a trusted position. Checked
when a profile is built (and again by the policy cache); the directory write path checks it
too (M2-01)."""


def is_trusted_tool_name(name: object) -> bool:
    return isinstance(name, str) and TOOL_NAME_PATTERN.fullmatch(name) is not None


def is_valid_tenant_slug(value: object) -> bool:
    return isinstance(value, str) and TENANT_SLUG_PATTERN.fullmatch(value) is not None


def denied_slug_parts(slug: str) -> list[str]:
    """The hyphen-separated parts of ``slug`` that are in :data:`SLUG_DENYLIST`, in order."""
    return [part for part in slug.split("-") if part in SLUG_DENYLIST]


_NAME_SEPARATORS = re.compile(r"[._-]")


def denied_name_parts(name: str) -> list[str]:
    """The parts of a tool ``name`` (split at ``.``, ``_`` and ``-``) that are in
    :data:`SLUG_DENYLIST`: a registered tool name is printed on a trusted line of the
    rendered prompt, so it gets the slug's instruction-like-token check."""
    return [part for part in _NAME_SEPARATORS.split(name) if part in SLUG_DENYLIST]


@dataclass(frozen=True, slots=True)
class ToolInfo:
    """A tool from the tenant's tool registry."""

    name: str
    description: str = ""
    """Tenant-written free text. Rendered only inside an untrusted section."""
    read_only: bool = False
    """The registry marks the tool read-only."""
    skip_model: bool = False
    """M3-03: at ``tool_call`` the **tenant's and packs' questions are
    skipped** for this tool; **the floor's are always asked**. There is no full skip, so
    flagging a tool, whoever does it, can't loosen the floor. Only the registry (platform
    ops or the tenant, through the tool directory) sets it, never a request or a bundle, and
    only for a tool the registry marks ``read_only``. The deterministic checks (the schema,
    allow-list, mismatch and deny patterns) still run, and the verdict, the audit record, the
    span and the usage meter say the skip applied. It applies at ``tool_call`` only: what a
    tool returns is still checked in full at ``tool_result``."""
    arguments_schema: Mapping[str, Any] | bool | None = None
    """M3-03: a JSON Schema for the tool's arguments (a subset, see
    :mod:`guardrail_engine.guard.tool_schema`). At ``tool_call`` the ``arguments`` member of
    the content (``{"tool", "arguments"}``; ``args`` is a deprecated alias) is validated
    against it first, and a failure is a deterministic ``block`` (rule ``tool_schema``) with
    no model call. None: no schema, nothing to validate. Stored read-only."""

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name:
            raise ValueError(f"tool name must be non-empty text, got {self.name!r}")
        if not isinstance(self.description, str):
            raise ValueError(f"description of tool {self.name!r} must be text")
        if not isinstance(self.read_only, bool):
            raise ValueError(f"read_only of tool {self.name!r} must be a bool")
        if not isinstance(self.skip_model, bool):
            raise ValueError(f"skip_model of tool {self.name!r} must be a bool")
        if self.skip_model and not self.read_only:
            raise ValueError(f"tool {self.name!r}: skip_model needs a tool marked read_only")
        if self.arguments_schema is not None:
            if (problem := schema_problem(self.arguments_schema)) is not None:
                raise ValueError(f"arguments_schema of tool {self.name!r}: {problem}")
            object.__setattr__(self, "arguments_schema", freeze_schema(self.arguments_schema))


@dataclass(frozen=True, slots=True)
class TenantProfile:
    """One tenant's platform configuration. Also serves as the compiler's ``ToolRegistry``.

    Raises ``ValueError`` when built with a domain outside :data:`DOMAINS`, a slug that
    doesn't match :data:`TENANT_SLUG_PATTERN` or has a part in :data:`SLUG_DENYLIST`, or a
    tenant id that doesn't match :data:`TENANT_ID_PATTERN`.
    """

    attributes: TenantAttributes
    domain: str
    """Printed in the ``TENANT DOMAIN`` header; one of :data:`DOMAINS`."""
    tools: Mapping[str, ToolInfo] = field(default_factory=dict)
    slug: str = field(kw_only=True)
    """Printed in the ``TENANT`` header with the tenant id; matches
    :data:`TENANT_SLUG_PATTERN`."""
    require_two_person: bool = field(default=False, kw_only=True)
    """The tenant opted in to two-person approval to enforce (R2, the directory's
    ``two_person_publish`` flag). Not part of the trusted header."""

    def __post_init__(self) -> None:
        if (problem := profile_problem(self)) is not None:
            raise ValueError(problem)
        tools = dict(self.tools)
        for name, info in tools.items():
            if not isinstance(info, ToolInfo) or name != info.name:
                raise ValueError(f"tool registry entry {name!r} is not a ToolInfo of that name")
        object.__setattr__(self, "tools", MappingProxyType(tools))

    @classmethod
    def build(
        cls,
        attributes: TenantAttributes,
        domain: str,
        tools: Iterable[ToolInfo] = (),
        *,
        slug: str,
        require_two_person: bool = False,
    ) -> TenantProfile:
        return cls(
            attributes, domain, {t.name: t for t in tools}, slug=slug,
            require_two_person=require_two_person,
        )  # fmt: skip

    @property
    def tenant_id(self) -> str:
        return self.attributes.tenant_id

    def has_tool(self, name: str) -> bool:
        return name in self.tools


def profile_problem(profile: object) -> str | None:
    """What makes ``profile`` unusable as a tenant directory entry, or None. Checked when a
    profile is built and again by the policy cache on every entry the directory returns, so
    a profile mutated after construction can't reach the trusted header either."""
    if not isinstance(profile, TenantProfile):
        return f"not a TenantProfile: {type(profile).__name__}"
    if profile.domain not in DOMAINS:
        return f"tenant domain must be one of {DOMAINS}, got {_short(profile.domain)}"
    if not is_valid_tenant_slug(profile.slug):
        return f"tenant slug must match {TENANT_SLUG_PATTERN.pattern}, got {_short(profile.slug)}"
    if denied := denied_slug_parts(profile.slug):
        return f"tenant slug contains instruction-like part(s) {denied}, got {_short(profile.slug)}"
    for name in profile.tools:
        if denied_name_parts(name):
            return f"tool name contains instruction-like part(s), got {_short(name)}"
    tenant_id = getattr(profile.attributes, "tenant_id", None)
    if not is_valid_tenant_id(tenant_id):
        return f"tenant id must match {TENANT_ID_PATTERN.pattern}, got {_short(tenant_id)}"
    return None


def _short(value: object, limit: int = 80) -> str:
    text = repr(value)
    return text if len(text) <= limit else text[:limit] + "..."


class TenantDirectory(Protocol):
    async def get(self, tenant_id: str) -> TenantProfile | None:
        """The tenant's profile, or None for an unknown tenant. May raise if the backing
        store is unavailable; the Guard Service treats that like a policy store failure."""
        ...


class InMemoryTenantDirectory:
    def __init__(self, profiles: Iterable[TenantProfile] = ()) -> None:
        self._profiles = {p.tenant_id: p for p in profiles}

    def put(self, profile: TenantProfile) -> None:
        self._profiles[profile.tenant_id] = profile

    def remove(self, tenant_id: str) -> None:
        """Offboard or suspend a tenant: ``get`` answers None from now on."""
        self._profiles.pop(tenant_id, None)

    async def get(self, tenant_id: str) -> TenantProfile | None:
        return self._profiles.get(tenant_id)

    async def tenant_ids(self, *, include_suspended: bool = False) -> list[str]:
        """The tenants with a profile (this directory holds active ones only)."""
        return sorted(self._profiles)
