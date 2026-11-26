"""The catalog as the Admin API shows and uses it (M2-03): ``GET catalog`` and applying a
template. Framework-independent, like the other admin services.

**``GET catalog``** (viewer) is read-only. It lists every floor version with its rules and their
text, every pack version, and every template, with where each can be used: a floor version
below the platform minimum, or not yet released, is shown as ``extendable: false`` (it stays
in the catalog because stored bundles extend it, see :class:`CatalogAdmin`), and the packs
the tenant's tier requires are marked. A floor rule's thresholds and text are shown; no
score of any kind is.

**Applying a template** (guardrail_admin) copies it into the tenant's draft as a ``t__`` rule
that records ``origin: "template:<id>@<version>"`` and ``template_unedited: true``, and imports
the template's starter examples into the tenant's golden set, through the same harm tripwire as
an upload (quarantined, never sent). The copy starts in rule mode ``shadow``: a template copy is
exempt from the 72-hour soak but not from the label counts, and a tenant turns it on by editing
the mode, which is the tenant's choice to make. Any edit to the copy's wording or thresholds
sets ``template_unedited`` to ``false`` (the draft service does it on every write). The draft
write and the golden import are two steps: if the golden set can't be created (the tenant is at
its cap of sets), the rule is still in the draft and the reply says the examples were not
imported, so a retry would be refused with ``rule_exists`` and the tenant uploads them itself.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from guardrail_engine.admin.drafts import StoredDraft
from guardrail_engine.admin.golden import GoldenService, GoldenSetInfo, TooManyGoldenSetsError
from guardrail_engine.admin.service import (
    DraftError,
    DraftInvalidError,
    DraftService,
    DraftServiceError,
    TenantUnavailableError,
    _scope_of,
)
from guardrail_engine.authz.authorizer import AuthzDecision
from guardrail_engine.authz.model import Principal
from guardrail_engine.guard.tenants import TenantDirectory
from guardrail_engine.policy.catalog import (
    Catalog,
    CatalogRule,
    PlatformSettings,
    Template,
    TenantAttributes,
)
from guardrail_engine.policy.json_document import parse_json_text
from guardrail_engine.store.port import CatalogReferences

GET_CATALOG = ("GET", "/v1/tenants/{tid}/guardrails/catalog")
APPLY_TEMPLATE = ("POST", "/v1/tenants/{tid}/guardrails/draft/templates/{template_id}")

MAX_APPLY_BODY_BYTES = 1_000


class TemplateNotFoundError(DraftServiceError):
    """The catalog has no such template or version (HTTP 404)."""


@dataclass(frozen=True, slots=True)
class AppliedTemplate:
    draft: StoredDraft
    rule: dict[str, Any]
    golden_set: GoldenSetInfo | None
    """The set the starter examples went into, or ``None`` if it could not be created."""
    golden_error: str | None = None
    """``too_many_golden_sets`` when the tenant is at its cap."""


def rule_view(rule: CatalogRule) -> dict[str, Any]:
    question = rule.question.model_dump(mode="json")
    criteria = question.get("criteria")
    noul = question["type"] == "noul" and isinstance(criteria, dict)
    view: dict[str, Any] = {
        "key": rule.key,
        "type": question["type"],
        "guard_points": sorted(rule.guard_points),
        "question": question["instructions"],
        "true_description": criteria["true_description"] if noul else None,
        "false_description": criteria["false_description"] if noul else None,
        "block_at": rule.block_at,
        "escalate_at": rule.escalate_at,
        "severity": rule.severity,
        "mode": rule.mode,
        "provisional": rule.provisional,
        "max_action": rule.max_action,
    }
    if question["type"] in ("choice", "score"):
        view["criteria"] = criteria  # a router's options, or a scorer's levels
    return view


def template_view(template: Template) -> dict[str, Any]:
    return {
        "id": template.id,
        "version": template.version,
        "ref": f"template:{template.id}@{template.version}",
        "title": template.title,
        "description": template.description,
        "notice": template.notice,
        "question": template.question,
        "true_description": template.true_description,
        "false_description": template.false_description,
        "block_at": template.block_at,
        "escalate_at": template.escalate_at,
        "guard_points": list(template.guard_points),
        "severity": template.severity,
        "starter_examples": len(template.starter_examples),
    }


class CatalogService:
    def __init__(
        self,
        catalog: Catalog,
        settings: PlatformSettings,
        tenants: TenantDirectory,
        drafts: DraftService,
        golden: GoldenService | None,
    ) -> None:
        self._catalog = catalog
        self._settings = settings
        self._tenants = tenants
        self._drafts = drafts
        self._golden = golden

    async def view(self, decision: AuthzDecision) -> dict[str, Any]:
        scope = _scope_of(decision, GET_CATALOG)
        profile = await self._tenants.get(scope.tenant_id)
        if profile is None:
            raise TenantUnavailableError()
        required = self._catalog.packs_required_for_tier(profile.attributes.tier)
        default_on = self._catalog.default_on_packs()
        floors = []
        for version in self._catalog.floor_versions():
            floor = self._catalog.floor(version)
            if floor is None:  # not reachable: the catalog lists what it holds
                continue
            floors.append(
                {
                    "version": version,
                    "ref": floor.ref,
                    "extendable": version >= self._settings.min_floor_version
                    and self._catalog.is_released(version),
                    "rules": [rule_view(r) for r in floor.content.rules],
                }
            )
        packs = []
        for name, version in self._catalog.pack_versions():
            pack = self._catalog.pack(name, version)
            if pack is None:
                continue
            packs.append(
                {
                    "name": name,
                    "version": version,
                    "ref": pack.ref,
                    "description": pack.description,
                    "per_rule_optional": pack.per_rule_optional,
                    "default_on": name in default_on,
                    "required_for_your_tier": name in required,
                    "rules": [rule_view(r) for r in pack.content.rules],
                }
            )
        templates = []
        for tid, version in self._catalog.template_versions():
            template = self._catalog.template(tid, version)
            if template is not None:
                templates.append(template_view(template))
        return {
            "minimum_floor_version": self._settings.min_floor_version,
            "floors": floors,
            "packs": packs,
            "templates": templates,
            "starter_bundle": self._starter(scope.tenant_id, profile.attributes),
        }

    def _starter(self, tenant_id: str, attributes: TenantAttributes) -> dict[str, Any] | None:
        """The bundle a new tenant starts from (M4-10, R4.1): the newest floor a tenant may
        extend (one the platform has released, M7-05), and the packs that are **on by default**,
        plus those its tier and contract require (each at its newest version). A tenant that
        opts out of a default-on pack leaves it out of ``extends``, which the publish's class A
        diff records; a required one can't be left out (the compiler refuses). None when no
        floor can be extended."""
        floors = [
            v
            for v in self._catalog.floor_versions()
            if v >= self._settings.min_floor_version and self._catalog.is_released(v)
        ]  # a floor the platform hasn't released can't be extended: the starter would not compile
        if not floors:
            return None
        wanted = (
            self._catalog.default_on_packs()
            | self._catalog.packs_required_for_tier(attributes.tier)
            | attributes.required_packs
        )
        extends = [f"platform/floor@{max(floors)}"]
        for name in sorted(wanted):
            held = [v for n, v in self._catalog.pack_versions() if n == name]
            if held:  # a default-on pack the catalog doesn't hold is skipped
                extends.append(f"domain/{name}@{max(held)}")
        return {"schema_version": 1, "tenant_id": tenant_id, "version": 1, "extends": extends}

    async def apply_template(
        self,
        decision: AuthzDecision,
        principal: Principal,
        template_id: str,
        body: bytes,
        if_match: str | None,
    ) -> AppliedTemplate:
        _scope_of(decision, APPLY_TEMPLATE)
        version, rule_id = _parse_apply(body)
        if version is None:
            held = [v for t, v in self._catalog.template_versions() if t == template_id]
            version = max(held, default=None)
        template = None if version is None else self._catalog.template(template_id, version)
        if template is None:
            raise TemplateNotFoundError()
        if not template.guard_points:
            raise DraftInvalidError(
                [DraftError("template.no_guard_points", "$", "the template names no guard point")]
            )
        rule = {
            "id": rule_id or template.id,
            "guard_points": list(template.guard_points),
            "question": template.question,
            "true_description": template.true_description,
            "false_description": template.false_description,
            "block_at": template.block_at,
            "escalate_at": template.escalate_at,
            "severity": template.severity,
            "mode": "shadow",
            "origin": f"template:{template.id}@{template.version}",
            "template_unedited": True,
        }
        draft = await self._drafts.add_rule(
            decision, principal, APPLY_TEMPLATE, rule, if_match, "draft.rule.put"
        )
        golden_set: GoldenSetInfo | None = None
        golden_error: str | None = None
        if template.starter_examples and self._golden is not None:
            rows = tuple(
                (f"s{i}", e.guard_point, e.label, e.content)
                for i, e in enumerate(template.starter_examples, 1)
            )
            try:
                golden_set = await self._golden.import_examples(
                    decision, principal, APPLY_TEMPLATE,
                    f"template {template.id} v{template.version}", rows,
                )  # fmt: skip
            except TooManyGoldenSetsError:
                golden_error = "too_many_golden_sets"
        return AppliedTemplate(draft, rule, golden_set, golden_error)


class CatalogItemInUseError(DraftServiceError):
    """A stored bundle uses the catalog item, so it can't be removed (the catalog is
    append-only)."""

    def __init__(self, ref: str, bundles: int) -> None:
        super().__init__(f"{ref} is used by {bundles} stored bundle(s)")
        self.ref = ref
        self.bundles = bundles


class CatalogItemNotFoundError(DraftServiceError):
    """The catalog holds no such item."""


class CatalogAdmin:
    """The only way anything leaves the catalog (M2-03, "the catalog is append-only").

    A floor version, a pack version or a template version that **any stored bundle** uses (in
    its ``extends``, or a rule's ``origin``) is never removed: those bundles could no longer be
    compiled, loaded or verified. Raising the minimum floor version doesn't remove the old floor
    either; it only stops new publishes extending it. The reference count comes from every
    tenant's stored versions, published or not, candidates and rolled-back ones included. If it
    can't be read (no operator pool, a database error) the removal is refused too. This is a
    platform operation: no HTTP route calls it.
    """

    def __init__(self, catalog: Any, references: CatalogReferences) -> None:
        self._catalog = catalog
        self._references = references

    async def _guard(self, ref: str, held: bool) -> None:
        if not held:
            raise CatalogItemNotFoundError(ref)
        used = await self._references.count(ref)
        if used:
            raise CatalogItemInUseError(ref, used)

    async def remove_floor(self, version: int) -> None:
        ref = f"platform/floor@{version}"
        await self._guard(ref, self._catalog.floor(version) is not None)
        self._catalog.discard_floor(version)

    async def remove_pack(self, name: str, version: int) -> None:
        ref = f"domain/{name}@{version}"
        await self._guard(ref, self._catalog.pack(name, version) is not None)
        self._catalog.discard_pack(name, version)

    async def remove_template(self, template_id: str, version: int) -> None:
        ref = f"template:{template_id}@{version}"
        await self._guard(ref, self._catalog.template(template_id, version) is not None)
        self._catalog.discard_template(template_id, version)


def _parse_apply(body: bytes) -> tuple[int | None, str | None]:
    """``{version?, rule_id?}``; an empty body means the newest version under the template's id."""
    if len(body) > MAX_APPLY_BODY_BYTES:
        raise DraftInvalidError([DraftError("template.too_large", "$", "the body is too large")])
    if not body.strip():
        return None, None
    doc, problems = parse_json_text(body)
    if problems:
        raise DraftInvalidError([DraftError(str(p.code), p.path, p.message) for p in problems])
    errors: list[DraftError] = []
    if not isinstance(doc, dict):
        raise DraftInvalidError([DraftError("template.not_object", "$", "the body is an object")])
    for extra in sorted(set(doc) - {"version", "rule_id"}):
        errors.append(DraftError("template.unknown_field", f"$.{extra}", "not a field"))
    version = doc.get("version")
    if version is not None and (
        isinstance(version, bool) or not isinstance(version, int) or not 1 <= version <= 10**6
    ):
        errors.append(DraftError("template.version", "$.version", "a positive integer"))
    rule_id = doc.get("rule_id")
    if rule_id is not None and not isinstance(rule_id, str):
        errors.append(DraftError("template.rule_id", "$.rule_id", "text"))
    if errors:
        raise DraftInvalidError(errors)
    return version, rule_id


__all__ = [
    "APPLY_TEMPLATE", "GET_CATALOG", "AppliedTemplate", "CatalogAdmin", "CatalogItemInUseError",
    "CatalogItemNotFoundError", "CatalogService",
    "TemplateNotFoundError", "rule_view", "template_view",
]  # fmt: skip
