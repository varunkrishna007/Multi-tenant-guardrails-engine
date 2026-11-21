"""What a stored version lacks under a tenant's **current** tier (M5-01).

A version published while the tenant was standard, then looked at after a raise: the compiler
that loads stored versions leaves the tier's requirements out so the running version keeps
running. A version that is about to *become* active (a promotion) or to come back (a rollback on
a regulated tenant) is held to them. :func:`tier_requirement_errors` is the one place that says
what is missing: the errors the strict compiler gives that the relaxed one does not, so only the
tier's own refusals (``pack.required_missing``, ``pack.rule_required``) and never an unrelated
problem of an old version.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from guardrail_engine.policy.catalog import (
    Catalog,
    PlatformSettings,
    TenantAttributes,
    ToolRegistry,
)
from guardrail_engine.policy.compiler import PolicyCompiler
from guardrail_engine.policy.document import ParsedBundle, parse_bundle
from guardrail_engine.policy.errors import PolicyError


def tier_requirement_errors(
    catalog: Catalog,
    tools: ToolRegistry,
    settings: PlatformSettings,
    tenant: TenantAttributes,
    document: Mapping[str, Any] | ParsedBundle,
) -> list[PolicyError]:
    """The tier's refusals for ``document`` under ``tenant``'s current tier and contract:
    exactly what a publish of it would get (same codes, paths and messages), minus every error
    the version already has with the tier left out. Empty when it meets them."""
    parsed = document if isinstance(document, ParsedBundle) else parse_bundle(dict(document))
    strict = PolicyCompiler(catalog, tools, settings).validate(parsed, tenant)
    if not strict:
        return []
    relaxed = PolicyCompiler(catalog, tools, settings, enforce_tier_requirements=False).validate(
        parsed, tenant
    )
    known = {(e.code, e.path, e.message) for e in relaxed}
    return [e for e in strict if (e.code, e.path, e.message) not in known]
