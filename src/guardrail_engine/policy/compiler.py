"""The policy compiler (M1-01): validates a tenant bundle and compiles it into one question
set per guard point, with per-key metadata.

A pure library: no I/O. The catalog, tool registry, tenant attributes and platform settings
come in through the interfaces in :mod:`guardrail_engine.policy.catalog`.

    compiler = PolicyCompiler(catalog, tools, settings)
    errors = compiler.validate(bundle_json, tenant)        # every error, each with a path
    policy = compiler.compile(bundle_json, tenant)         # raises PolicyInvalidError

Effective values (AC-C9.1):

* thresholds: floor and pack rules carry their own in the catalog (a catalog rule without
  them can't be built); overrides can only lower them. Tenant rules use their own value,
  else the bundle ``defaults``, else the platform default. Tenant ``defaults`` never reach
  floor or pack rules.
* fail mode: ``settings.floor_fail_mode`` for floor keys (B1); for pack and tenant keys,
  the guard point's ``fail_mode``, else ``defaults.fail_mode``, else
  ``settings.default_fail_mode`` (``closed``, S5).
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, PrivateAttr, model_serializer

from guardrail_engine.decision.limits import KEY_PATTERN, MAX_KEY_LENGTH
from guardrail_engine.decision.types import NoulCriteria, NoulQuestion, Question
from guardrail_engine.deterministic.regex import (
    CompiledRegex,
    RegexEngine,
    RegexError,
    default_regex_engine,
)
from guardrail_engine.deterministic.rules import (
    NO_CHECKS,
    DenyRule,
    DeterministicAction,
    GuardPointChecks,
)
from guardrail_engine.net_safety import literal_host_problem, url_host
from guardrail_engine.policy.api_tokens import (
    API_TOKENS_PER_CALL,
    API_TOKENS_PER_QUESTION,
    API_TOKENS_TEXT_PERCENT,
    content_api_tokens,
    question_api_tokens,
)
from guardrail_engine.policy.canonical import canonical_json
from guardrail_engine.policy.catalog import (
    Catalog,
    CatalogRule,
    FloorVersion,
    PackVersion,
    PlatformSettings,
    RetentionProfile,
    TenantAttributes,
    ToolRegistry,
)
from guardrail_engine.policy.document import EXTENDS_REF_PATTERN, ParsedBundle, read_bundle
from guardrail_engine.policy.errors import ErrorCode, PolicyError, PolicyInvalidError
from guardrail_engine.policy.lint import CLOSED_QUESTION_RULE, is_blank, is_closed_question
from guardrail_engine.policy.schema import (
    DETERMINISTIC_ACTIONS,
    ESCALATION_TARGETS,
    FAIL_MODES,
    GUARD_POINTS,
    RULE_MODES,
    SEVERITIES,
    STORE_CONTENT,
    Bundle,
    Deterministic,
    Escalation,
    GuardPointConfig,
    Override,
    Rule,
)
from guardrail_engine.tokens import estimate_question_tokens

Layer = Literal["floor", "pack", "tenant"]
_LAYER_RANK = {"floor": 0, "pack": 1, "tenant": 2}
_PREFIX = {"floor": "p__", "pack": "d__", "tenant": "t__"}

RULE_ID_PATTERN = re.compile(r"[a-z0-9_]{1,40}")
_TEMPLATE_ORIGIN = re.compile(r"template:([A-Za-z0-9_.-]+)@([1-9][0-9]*)")
_FORK_ORIGIN = re.compile(r"fork:(?:p__|d__)[A-Za-z0-9_-]+")
_HTTPS_URL = re.compile(r"https://[^/\s?#]+(?:[/?#]\S*)?")

# --------------------------------------------------------------------------- output


class _Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class CompiledRule(_Frozen):
    """Metadata for one compiled key (AC-C9)."""

    key: str
    layer: Layer
    source: str
    """Where the rule came from: ``platform/floor@7``, ``domain/insurance@3`` or ``tenant``."""
    question_type: str
    block_at: float | None
    escalate_at: float | None
    mode: str
    severity: str
    fail_mode: str
    max_action: str | None = None
    """``escalate`` when the rule may escalate but never block (M4-10, R4.3); None: no cap (the
    catalog rule's default ``block``). None is left out of the canonical JSON, so a policy with
    no capped rule compiles to the bytes it did before the field existed."""
    provisional: bool
    """The catalog rule's thresholds are not calibrated yet (M1-08, M0-02). The catalog's
    value for floor and pack rules, even when a tenant override lowered them; always False
    for tenant rules. Lets the Guard Service and audit mark decisions taken on provisional
    thresholds. Part of the compiled canonical JSON, but not an input to
    ``bundle_hash``, which already covers it through the catalog version's content hash."""

    @model_serializer(mode="wrap")
    def _omit_no_cap(self, handler: Any) -> dict[str, Any]:
        data: dict[str, Any] = handler(self)
        if data.get("max_action") is None:
            data.pop("max_action", None)
        return data


class CompiledGuardPoint(_Frozen):
    name: str
    enabled: bool
    questions: dict[str, Question]
    """The Decisions API ``questions`` object for this guard point (AC-C2.1)."""
    rules: dict[str, CompiledRule]
    max_content_tokens: int
    question_tokens: int
    """Shared-estimator tokens of ``questions`` as sent on the wire (AC-M1-6)."""
    api_tokens: int
    """The fitted API-token estimate (R6.6) of the largest call this guard point can make:
    content at ``max_content_tokens`` plus the render overhead, and all its questions. It is
    ``content_api_tokens + question_api_tokens``; R6.7 bounds those two parts separately,
    not this sum. 0 when the guard point has no questions (no call is made)."""
    content_api_tokens: int
    """AC-C1.8(a): ``ceil(1.20 x (max content + render overhead)) + 30``, bounded by
    ``token_budget`` (16,000). 0 when the guard point has no questions."""
    question_api_tokens: int
    """AC-C1.8(c): ``question_tokens + 25 x questions``, bounded by 150 x the question
    budget."""
    tool_allowlist: tuple[str, ...] | None = None


class EffectiveAudit(_Frozen):
    records_days: int
    store_content: str
    content_days: int | None
    content_requires_baa: bool = False
    """The tenant's packs need a BAA to store content (the healthcare profile, R3). M4-05 reads it
    to fix an escalation item's class D mode when the item is routed."""


class CompiledPolicy(_Frozen):
    tenant_id: str
    version: int
    bundle_hash: str
    floor: str
    packs: tuple[str, ...]
    guard_points: dict[str, CompiledGuardPoint]
    deterministic: Deterministic
    escalation: Escalation
    audit: EffectiveAudit
    _deny_rules: tuple[DenyRule, ...] = PrivateAttr(default=())
    """The bundle's deny patterns, compiled (M3-01). Runtime objects, not part of the
    document: they are not in the canonical JSON, and a policy rebuilt from that JSON has
    none, so a policy is always taken from the compiler."""

    def checks_for(self, guard_point: str) -> GuardPointChecks:
        """The deterministic rules that apply at ``guard_point`` (M3-01): the bundle's deny
        patterns, and at ``plan`` and ``tool_call`` each guard point's own tool allow-list
        (M3-03 added ``plan``). None for a guard point the tenant disabled (the floor covers
        its own guard points, PF-15)."""
        gp = self.guard_points.get(guard_point)
        if gp is None or not gp.enabled:
            return NO_CHECKS
        allowlist = gp.tool_allowlist if guard_point in ("plan", "tool_call") else None
        if not self._deny_rules and allowlist is None:
            return NO_CHECKS
        return GuardPointChecks(deny_rules=self._deny_rules, tool_allowlist=allowlist)

    def to_canonical_json(self) -> bytes:
        """Byte-identical for identical inputs (AC-C2.2)."""
        return canonical_json(self.model_dump(mode="json", exclude_none=True))


# --------------------------------------------------------------------------- compiler


class PolicyCompiler:
    def __init__(
        self,
        catalog: Catalog,
        tools: ToolRegistry,
        settings: PlatformSettings | None = None,
        regex: RegexEngine | None = None,
        *,
        enforce_tier_requirements: bool = True,
    ) -> None:
        """``regex`` compiles the bundle's deny patterns (RE2, M3-01). Default: the
        platform's RE2 adapter.

        ``enforce_tier_requirements`` (M5-01): the tier's required packs and required rules
        are checked when a **new** version is validated or published, which is the default. A
        version that was already published (the Guard Service loading the active version, a
        rollback, a floor re-pin) is compiled without them: a tier raised on a live tenant
        takes effect at its next publish, and the version that is running keeps running, also
        after a restart. Nothing else is relaxed: floor, packs, overrides, thresholds and
        retention bounds are checked as always."""
        self.catalog = catalog
        self.tools = tools
        self.settings = settings or PlatformSettings()
        self.regex = regex if regex is not None else default_regex_engine()
        self.enforce_tier_requirements = enforce_tier_requirements

    def validate(
        self, bundle: Mapping[str, Any] | str | bytes | ParsedBundle, tenant: TenantAttributes
    ) -> list[PolicyError]:
        """Every error in ``bundle``, in a stable order. An empty list means it is valid."""
        return _Run(self, tenant, self.enforce_tier_requirements).run(bundle).errors

    def compile(
        self, bundle: Mapping[str, Any] | str | bytes | ParsedBundle, tenant: TenantAttributes
    ) -> CompiledPolicy:
        """Compile the submitted document (a JSON object or JSON text), or one already read
        with ``parse_bundle``. ``bundle_hash`` is computed over the document as submitted."""
        run = _Run(self, tenant, self.enforce_tier_requirements).run(bundle)
        if run.errors or run.result is None:
            raise PolicyInvalidError(run.errors)
        return run.result


MAX_JUSTIFICATION_CHARS = 1_000
"""The longest justification a tenant may give for opting out of a pack rule (M4-10)."""


@dataclass
class _PlatformRule:
    rule: CatalogRule
    layer: Layer
    source: str
    block_at: float | None
    escalate_at: float | None
    optional: bool = False
    """The rule's pack is per-rule-optional (M4-10): the tenant may switch this rule off."""
    disabled: bool = False
    """The tenant opted out of this rule (with a justification): it is not compiled."""


@dataclass
class _Run:
    compiler: PolicyCompiler
    tenant: TenantAttributes
    enforce_tier: bool = True
    errors: list[PolicyError] = field(default_factory=list)
    result: CompiledPolicy | None = None
    deny_rules: list[DenyRule] = field(default_factory=list)

    def err(self, code: ErrorCode, path: str, message: str) -> None:
        self.errors.append(PolicyError(code=code, path=path, message=message))

    @property
    def settings(self) -> PlatformSettings:
        return self.compiler.settings

    # ------------------------------------------------------------------ driver

    def run(self, raw: Mapping[str, Any] | str | bytes | ParsedBundle) -> _Run:
        if isinstance(raw, ParsedBundle):
            parsed = raw
        elif isinstance(raw, Bundle):
            # A model has no submitted document, so there would be nothing to hash.
            raise TypeError("pass the submitted document or a ParsedBundle, not a Bundle model")
        else:
            parsed, shape_errors = read_bundle(raw)
            if parsed is None:
                self.errors.extend(shape_errors)
                return self
        bundle = parsed.bundle

        if bundle.tenant_id != self.tenant.tenant_id:
            self.err(
                ErrorCode.TENANT_MISMATCH,
                "$.tenant_id",
                f"bundle is for {bundle.tenant_id!r}, not {self.tenant.tenant_id!r}",
            )

        floor, packs = self._resolve_extends(bundle)
        if self.enforce_tier:
            self._check_required_packs(packs)
        default_block, default_escalate = self._check_defaults(bundle)
        self._check_guard_point_configs(bundle, floor)
        platform = self._platform_rules(floor, packs)
        self._apply_overrides(bundle, platform)
        tenant_rules = self._check_tenant_rules(bundle, default_block, default_escalate)
        self._check_deterministic(bundle.deterministic)
        self._check_escalation(bundle.escalation)
        audit = self._check_audit(bundle, packs)
        guard_points = self._assemble(bundle, platform, tenant_rules)

        if not self.errors and floor is not None and audit is not None:
            self.result = CompiledPolicy(
                tenant_id=bundle.tenant_id,
                version=bundle.version,
                bundle_hash=parsed.bundle_hash(
                    extends={v.ref: v.content_hash() for v in (floor, *packs.values())},
                ),
                floor=floor.ref,
                packs=tuple(p.ref for p in sorted(packs.values(), key=lambda p: p.name)),
                guard_points=guard_points,
                deterministic=bundle.deterministic,
                escalation=bundle.escalation,
                audit=audit,
            )
            self.result._deny_rules = tuple(self.deny_rules)
        return self

    # ------------------------------------------------------------------ extends (C1.4, C1.5)

    def _resolve_extends(
        self, bundle: Bundle
    ) -> tuple[FloorVersion | None, dict[str, PackVersion]]:
        floor: FloorVersion | None = None
        floor_seen = False
        packs: dict[str, PackVersion] = {}
        for i, ref in enumerate(bundle.extends):
            path = f"$.extends[{i}]"
            m = EXTENDS_REF_PATTERN.fullmatch(ref)
            if not m:
                self.err(
                    ErrorCode.EXTENDS_INVALID,
                    path,
                    f"{ref!r} is not 'platform/floor@<n>' or 'domain/<pack>@<n>'",
                )
                continue
            is_floor, pack_name, version = m.group(1), m.group(2), int(m.group(3))
            if is_floor:
                if floor_seen:
                    self.err(
                        ErrorCode.EXTENDS_DUPLICATE, path, "the floor is extended more than once"
                    )
                    continue
                floor_seen = True
                catalog = self.compiler.catalog
                minimum = max(self.settings.min_floor_version, catalog.minimum_floor_version())
                if version < minimum:
                    self.err(
                        ErrorCode.FLOOR_BELOW_MINIMUM,
                        path,
                        f"floor@{version} is below the platform minimum floor@{minimum}",
                    )
                elif not catalog.is_released(version):
                    self.err(
                        ErrorCode.FLOOR_NOT_RELEASED,
                        path,
                        f"floor@{version} has not been released (R5): it needs a passing "
                        "red-team run and two platform approvals",
                    )
                # Still loaded when below the minimum, so later checks don't cascade into
                # "unknown rule" errors. The bundle is rejected either way.
                floor = self.compiler.catalog.floor(version)
                if floor is None:
                    self.err(ErrorCode.EXTENDS_UNKNOWN, path, f"no floor version {version}")
            else:
                if pack_name in packs:
                    self.err(
                        ErrorCode.EXTENDS_DUPLICATE,
                        path,
                        f"pack {pack_name!r} is extended more than once",
                    )
                    continue
                pack = self.compiler.catalog.pack(pack_name, version)
                if pack is None:
                    self.err(ErrorCode.EXTENDS_UNKNOWN, path, f"no pack {pack_name}@{version}")
                    continue
                packs[pack_name] = pack
        if not floor_seen:
            self.err(
                ErrorCode.FLOOR_MISSING, "$.extends", "every bundle must extend the platform floor"
            )
        return floor, packs

    def _check_required_packs(self, packs: dict[str, PackVersion]) -> None:
        required = (
            self.compiler.catalog.packs_required_for_tier(self.tenant.tier)
            | self.tenant.required_packs
        )
        for name in sorted(required - packs.keys()):
            self.err(
                ErrorCode.PACK_REQUIRED_MISSING,
                "$.extends",
                f"pack {name!r} is required (tier {self.tenant.tier!r} or contract)",
            )

    # ------------------------------------------------------------------ defaults (C1.2)

    def _check_defaults(self, bundle: Bundle) -> tuple[float, float]:
        d = bundle.defaults
        if d.fail_mode is not None and d.fail_mode not in FAIL_MODES:
            self.err(
                ErrorCode.FAIL_MODE_INVALID, "$.defaults.fail_mode", f"must be one of {FAIL_MODES}"
            )
        block = d.block_at if d.block_at is not None else self.settings.default_block_at
        escalate = d.escalate_at if d.escalate_at is not None else self.settings.default_escalate_at
        self._check_pair(block, escalate, "$.defaults")
        return block, escalate

    def _check_pair(self, block: float | None, escalate: float | None, path: str) -> bool:
        if block is None or escalate is None or not (0.01 <= escalate < block <= 0.99):
            self.err(
                ErrorCode.THRESHOLD_INVALID,
                path,
                f"need 0.01 <= escalate_at < block_at <= 0.99, got escalate_at={escalate}, "
                f"block_at={block}",
            )
            return False
        return True

    # ------------------------------------------------------------------ guard points (C1.9, C1.11)

    def _check_guard_point_configs(self, bundle: Bundle, floor: FloorVersion | None) -> None:
        for name, cfg in bundle.guard_points.items():
            path = f"$.guard_points.{name}"
            if name not in GUARD_POINTS:
                self.err(
                    ErrorCode.GP_UNKNOWN,
                    path,
                    f"unknown guard point; expected one of {GUARD_POINTS}",
                )
                continue
            if cfg.fail_mode is not None and cfg.fail_mode not in FAIL_MODES:
                self.err(
                    ErrorCode.FAIL_MODE_INVALID, f"{path}.fail_mode", f"must be one of {FAIL_MODES}"
                )
            if not cfg.enabled and floor is not None and name in floor.covers:
                self.err(
                    ErrorCode.GP_FLOOR_COVERED_DISABLED,
                    f"{path}.enabled",
                    f"the platform floor covers {name!r}; it can't be disabled",
                )
            if (
                name == "tool_result"
                and cfg.chunk_tokens is not None
                and cfg.chunk_tokens < self.settings.min_chunk_tokens
            ):
                self.err(
                    ErrorCode.GP_CHUNK_TOKENS_TOO_SMALL,
                    f"{path}.chunk_tokens",
                    f"chunk_tokens {cfg.chunk_tokens} is under the platform minimum of "
                    f"{self.settings.min_chunk_tokens}",
                )
            for j, tool in enumerate(cfg.tool_allowlist or ()):
                if not self.compiler.tools.has_tool(tool):
                    self.err(
                        ErrorCode.TOOL_NOT_REGISTERED,
                        f"{path}.tool_allowlist[{j}]",
                        f"tool {tool!r} is not in the tenant's tool registry",
                    )

    # ------------------------------------------------------------------ floor and pack rules (C2)

    def _platform_rules(
        self,
        floor: FloorVersion | None,
        packs: dict[str, PackVersion],
    ) -> dict[str, _PlatformRule]:
        """Floor and pack rules with their catalog thresholds. Tenant ``defaults`` are not an
        input here, so they can never reach these rules."""
        sources: list[tuple[Layer, str, tuple[CatalogRule, ...], bool]] = []
        if floor is not None:
            sources.append(("floor", floor.ref, floor.rules, False))
        for pack in sorted(packs.values(), key=lambda p: p.name):
            sources.append(("pack", pack.ref, pack.rules, pack.per_rule_optional))

        rules: dict[str, _PlatformRule] = {}
        for layer, source, catalog_rules, optional in sources:
            for cr in catalog_rules:
                if not self._check_key(cr.key, layer, f"$.extends[{source}]"):
                    continue
                if cr.key in rules:
                    self.err(
                        ErrorCode.KEY_DUPLICATE,
                        f"$.extends[{source}]",
                        f"key {cr.key!r} is defined twice",
                    )
                    continue
                rules[cr.key] = _PlatformRule(
                    rule=cr,
                    layer=layer,
                    source=source,
                    block_at=cr.block_at,
                    escalate_at=cr.escalate_at,
                    optional=optional,
                )
        return rules

    def _check_key(self, key: str, layer: Layer, path: str) -> bool:
        if (
            not key.startswith(_PREFIX[layer])
            or len(key) > MAX_KEY_LENGTH
            or not KEY_PATTERN.fullmatch(key)
        ):
            self.err(
                ErrorCode.KEY_INVALID,
                path,
                f"compiled key {key!r} must start with {_PREFIX[layer]!r}, be at most "
                f"{MAX_KEY_LENGTH} characters and match [A-Za-z0-9_-]+",
            )
            return False
        return True

    # ------------------------------------------------------------------ overrides (C1.2-C1.5)

    def _apply_overrides(self, bundle: Bundle, platform: dict[str, _PlatformRule]) -> None:
        for i, ov in enumerate(bundle.overrides):
            path = f"$.overrides[{i}]"
            target = platform.get(ov.rule)
            if target is None:
                self.err(
                    ErrorCode.OVERRIDE_UNKNOWN_RULE,
                    f"{path}.rule",
                    f"{ov.rule!r} is not a floor or pack rule in this bundle",
                )
                continue
            floor = target.layer == "floor"
            self._check_override_changes(ov, target, path, floor)

            noul = target.rule.question.type == "noul"
            if not noul and (ov.block_at is not None or ov.escalate_at is not None):
                self.err(
                    ErrorCode.THRESHOLD_INVALID,
                    path,
                    f"{ov.rule!r} is not a noul rule and has no thresholds",
                )
                continue
            raises = ErrorCode.FLOOR_OVERRIDE_RAISES if floor else ErrorCode.PACK_OVERRIDE_RAISES
            for name in ("block_at", "escalate_at"):
                new, old = getattr(ov, name), getattr(target, name)
                if new is not None and old is not None and new > old:
                    self.err(
                        raises, f"{path}.{name}", f"{name} can only be lowered ({old} -> {new})"
                    )
            if ov.block_at is not None:
                target.block_at = ov.block_at
            if ov.escalate_at is not None:
                target.escalate_at = ov.escalate_at
            if noul:
                # C1.2: checked after the override is applied.
                self._check_pair(target.block_at, target.escalate_at, path)

    def _check_override_changes(
        self, ov: Override, target: _PlatformRule, path: str, floor: bool
    ) -> None:
        q = target.rule.question
        current = {
            "question": q.instructions,
            "true_description": q.criteria.true_description
            if isinstance(q, NoulQuestion) and q.criteria
            else None,
            "false_description": q.criteria.false_description
            if isinstance(q, NoulQuestion) and q.criteria
            else None,
        }
        text_code = ErrorCode.FLOOR_TEXT_EDITED if floor else ErrorCode.PACK_TEXT_EDITED
        for name, value in current.items():
            new = getattr(ov, name)
            if new is not None and new != value:
                self.err(
                    text_code,
                    f"{path}.{name}",
                    "platform rule text can't be edited; fork it into a tenant rule",
                )

        if ov.max_action is not None and ov.max_action != target.rule.max_action:
            self.err(
                ErrorCode.OVERRIDE_MAX_ACTION_EDITED,
                f"{path}.max_action",
                "a rule's max_action is set by the platform and can't be changed",
            )
        if ov.mode is not None and ov.mode not in RULE_MODES:
            self.err(ErrorCode.RULE_MODE_INVALID, f"{path}.mode", f"must be one of {RULE_MODES}")
        if floor:
            if ov.enabled is False:
                self.err(
                    ErrorCode.FLOOR_RULE_DISABLED,
                    f"{path}.enabled",
                    "floor rules can't be disabled",
                )
            if ov.mode == "shadow":
                self.err(
                    ErrorCode.FLOOR_RULE_SHADOWED, f"{path}.mode", "floor rules can't be shadowed"
                )
        else:
            if ov.enabled is False:
                self._opt_out_of_rule(ov, target, path)
            if ov.mode is not None and ov.mode != target.rule.mode:
                self.err(
                    ErrorCode.PACK_OVERRIDE_NOT_ALLOWED,
                    f"{path}.mode",
                    (
                        "an opted-out rule is either on or off; it can't be shadowed instead"
                        if target.optional and ov.enabled is False
                        else "a pack rule's mode can't be changed"
                    ),
                )

    def _opt_out_of_rule(self, ov: Override, target: _PlatformRule, path: str) -> None:
        """A tenant switches one pack rule off (R4.6, M4-10). Allowed only in a pack that is
        per-rule-optional, with a written justification, and never for a rule the tenant's
        tier requires; every other pack is whole-pack opt-in or opt-out."""
        if not target.optional:
            self.err(
                ErrorCode.PACK_OVERRIDE_NOT_ALLOWED,
                f"{path}.enabled",
                "pack rules can't be disabled one by one; opt out of the pack instead",
            )
            return
        required = (
            self.compiler.catalog.rules_required_for_tier(self.tenant.tier)
            if self.enforce_tier
            else frozenset()
        )
        if target.rule.key in required:
            self.err(
                ErrorCode.PACK_RULE_REQUIRED,
                f"{path}.enabled",
                f"tier {self.tenant.tier!r} requires this rule: it can't be opted out of",
            )
            return
        text = ov.justification
        if is_blank(text) or len(text or "") > MAX_JUSTIFICATION_CHARS:
            self.err(
                ErrorCode.PACK_JUSTIFICATION_REQUIRED,
                f"{path}.justification",
                f"opting out of a rule needs a written justification of 1 to "
                f"{MAX_JUSTIFICATION_CHARS} characters",
            )
            return
        target.disabled = True

    # ------------------------------------------------------- tenant rules (C1.1, C1.6, C1.14)

    def _check_tenant_rules(
        self, bundle: Bundle, default_block: float, default_escalate: float
    ) -> list[tuple[Rule, float, float]]:
        seen: set[str] = set()
        valid: list[tuple[Rule, float, float]] = []
        for i, rule in enumerate(bundle.rules):
            path = f"$.rules[{i}]"
            ok = True
            if not RULE_ID_PATTERN.fullmatch(rule.id):
                self.err(
                    ErrorCode.RULE_ID_INVALID, f"{path}.id", "rule id must match [a-z0-9_]{1,40}"
                )
                ok = False
            elif rule.id in seen:
                self.err(
                    ErrorCode.RULE_ID_DUPLICATE, f"{path}.id", f"duplicate rule id {rule.id!r}"
                )
                ok = False
            seen.add(rule.id)

            if not rule.guard_points:
                self.err(
                    ErrorCode.RULE_NO_GUARD_POINTS,
                    f"{path}.guard_points",
                    "a rule needs at least one guard point",
                )
            for j, gp in enumerate(rule.guard_points):
                if gp not in GUARD_POINTS:
                    self.err(
                        ErrorCode.RULE_UNKNOWN_GUARD_POINT,
                        f"{path}.guard_points[{j}]",
                        f"unknown guard point {gp!r}; expected one of {GUARD_POINTS}",
                    )

            if not rule.question or not rule.question.strip():
                self.err(
                    ErrorCode.RULE_QUESTION_MISSING,
                    f"{path}.question",
                    "a tenant rule needs a question",
                )
                ok = False
            elif not is_closed_question(rule.question):
                self.err(
                    ErrorCode.RULE_QUESTION_NOT_CLOSED,
                    f"{path}.question",
                    f"the question must {CLOSED_QUESTION_RULE}",
                )
            for name in ("true_description", "false_description"):
                value = getattr(rule, name)
                if not value or not value.strip():
                    self.err(
                        ErrorCode.RULE_DESCRIPTION_MISSING,
                        f"{path}.{name}",
                        f"a tenant rule needs {name}",
                    )
                    ok = False

            if rule.severity not in SEVERITIES:
                self.err(
                    ErrorCode.RULE_SEVERITY_INVALID,
                    f"{path}.severity",
                    f"must be one of {SEVERITIES}",
                )
            if rule.mode not in RULE_MODES:
                self.err(
                    ErrorCode.RULE_MODE_INVALID, f"{path}.mode", f"must be one of {RULE_MODES}"
                )

            block = rule.block_at if rule.block_at is not None else default_block
            escalate = rule.escalate_at if rule.escalate_at is not None else default_escalate
            self._check_pair(block, escalate, path)
            self._check_origin(rule, path, block, escalate)
            if ok:
                valid.append((rule, block, escalate))
        return valid

    def _check_origin(self, rule: Rule, path: str, block: float, escalate: float) -> None:
        template_ref = _TEMPLATE_ORIGIN.fullmatch(rule.origin)
        if rule.origin != "custom" and not template_ref and not _FORK_ORIGIN.fullmatch(rule.origin):
            self.err(
                ErrorCode.ORIGIN_INVALID,
                f"{path}.origin",
                "origin must be 'custom', 'template:<id>@<version>' or 'fork:<rule key>'",
            )
            return
        if rule.template_unedited and not template_ref:
            self.err(
                ErrorCode.TEMPLATE_ORIGIN_INVALID,
                f"{path}.template_unedited",
                "template_unedited is only valid on a rule whose origin is a template",
            )
            return
        if not template_ref:
            return
        template = self.compiler.catalog.template(template_ref.group(1), int(template_ref.group(2)))
        if template is None:
            self.err(
                ErrorCode.TEMPLATE_UNKNOWN,
                f"{path}.origin",
                f"no template {template_ref.group(0)[9:]!r}",
            )
            return
        if rule.template_unedited:
            differs = [
                name
                for name, ours, theirs in (
                    ("question", rule.question, template.question),
                    ("true_description", rule.true_description, template.true_description),
                    ("false_description", rule.false_description, template.false_description),
                    ("block_at", block, template.block_at),
                    ("escalate_at", escalate, template.escalate_at),
                    ("severity", rule.severity, template.severity),
                    (
                        "guard_points",
                        sorted(rule.guard_points),
                        sorted(template.guard_points) if template.guard_points else None,
                    ),
                )
                if theirs is not None and ours != theirs
            ]
            if differs:
                self.err(
                    ErrorCode.TEMPLATE_MISMATCH,
                    f"{path}.template_unedited",
                    f"template_unedited is true but {', '.join(differs)} differ from the template",
                )

    # ------------------------------------------------------------------ deterministic (C1.10)

    def _check_deterministic(self, det: Deterministic) -> None:
        if det.pii is not None:
            for j, kind in enumerate(det.pii.detect):
                if kind not in self.settings.supported_pii_types:
                    self.err(
                        ErrorCode.PII_TYPE_UNSUPPORTED,
                        f"$.deterministic.pii.detect[{j}]",
                        f"unsupported PII type {kind!r}",
                    )
            self._check_action(det.pii.action, "$.deterministic.pii.action")
        limit = self.settings.max_deny_patterns
        if len(det.deny_patterns) > limit:
            self.err(
                ErrorCode.DENY_PATTERNS_TOO_MANY,
                "$.deterministic.deny_patterns",
                f"{len(det.deny_patterns)} deny patterns; the limit is {limit}",
            )
        seen: set[str] = set()
        for j, pattern in enumerate(det.deny_patterns):
            path = f"$.deterministic.deny_patterns[{j}]"
            id_ok = RULE_ID_PATTERN.fullmatch(pattern.id) is not None
            if not id_ok:
                self.err(
                    ErrorCode.DENY_PATTERN_ID_INVALID,
                    f"{path}.id",
                    f"must match {RULE_ID_PATTERN.pattern}",
                )
            elif pattern.id in seen:
                self.err(
                    ErrorCode.DENY_PATTERN_ID_DUPLICATE,
                    f"{path}.id",
                    f"deny pattern id {pattern.id!r} appears twice",
                )
            seen.add(pattern.id)
            action_ok = self._check_action(pattern.action, f"{path}.action")
            compiled = self._compile_deny_pattern(pattern.regex, f"{path}.regex")
            if compiled is not None and id_ok and action_ok:
                self.deny_rules.append(
                    DenyRule(
                        id=pattern.id, action=DeterministicAction(pattern.action), regex=compiled
                    )
                )

    def _compile_deny_pattern(self, regex: str, path: str) -> CompiledRegex | None:
        """AC-C1.10, PF-11: the pattern compiles under RE2, is within the size limit and can't
        match the empty string (which would match everywhere). Compiled here, once."""
        max_chars = self.settings.max_deny_pattern_chars
        if len(regex) > max_chars:
            self.err(
                ErrorCode.DENY_PATTERN_TOO_LONG,
                path,
                f"{len(regex)} characters; the limit is {max_chars}",
            )
            return None
        try:
            compiled = self.compiler.regex.compile(regex)
        except RegexError as e:
            self.err(ErrorCode.DENY_PATTERN_INVALID, path, f"not valid RE2: {e.detail}")
            return None
        if compiled.search(""):
            self.err(ErrorCode.DENY_PATTERN_INVALID, path, "matches the empty string")
            return None
        return compiled

    def _check_action(self, action: str, path: str) -> bool:
        if action in DETERMINISTIC_ACTIONS:
            return True
        self.err(
            ErrorCode.DETERMINISTIC_ACTION_INVALID,
            path,
            f"must be one of {DETERMINISTIC_ACTIONS}",
        )
        return False

    # ------------------------------------------------------------------ escalation (C1.12)

    def _check_escalation(self, esc: Escalation) -> None:
        if esc.target not in ESCALATION_TARGETS:
            self.err(
                ErrorCode.ESCALATION_TARGET_INVALID,
                "$.escalation.target",
                f"must be one of {ESCALATION_TARGETS}",
            )
            return
        if esc.target == "webhook":
            if not esc.url:
                self.err(
                    ErrorCode.ESCALATION_WEBHOOK_URL_MISSING,
                    "$.escalation.url",
                    "a webhook target needs a url",
                )
            elif not _HTTPS_URL.fullmatch(esc.url):
                self.err(
                    ErrorCode.ESCALATION_WEBHOOK_NOT_HTTPS,
                    "$.escalation.url",
                    "the webhook url must be https",
                )
            elif (problem := literal_host_problem(url_host(esc.url))) is not None:
                # Judged without a network call; the sender resolves the name when it
                # sends and refuses a private answer then too.
                self.err(
                    ErrorCode.ESCALATION_WEBHOOK_HOST_NOT_PUBLIC,
                    "$.escalation.url",
                    f"{problem}; use a public https host",
                )

    # ------------------------------------------------------------------ audit (C1.13)

    def _check_audit(self, bundle: Bundle, packs: dict[str, PackVersion]) -> EffectiveAudit | None:
        profile = combined_retention(self.settings, packs.values())
        audit = bundle.audit
        ok = True
        if audit.records_days is not None and not records_days_in_bounds(
            profile, audit.records_days
        ):
            self.err(
                ErrorCode.AUDIT_RECORDS_DAYS_OUT_OF_RANGE,
                "$.audit.records_days",
                f"must be between {profile.records_min_days} and {profile.records_max_days} days "
                "for this tenant's packs",
            )
            ok = False
        if audit.store_content not in STORE_CONTENT:
            self.err(
                ErrorCode.AUDIT_STORE_CONTENT_INVALID,
                "$.audit.store_content",
                f"must be one of {STORE_CONTENT}",
            )
            return None
        content_days = None
        if audit.store_content != "hash_only":
            if profile.content_requires_baa and not self.tenant.baa:
                self.err(
                    ErrorCode.AUDIT_CONTENT_REQUIRES_BAA,
                    "$.audit.store_content",
                    "storing content needs a BAA flag on this tenant (healthcare)",
                )
                ok = False
            if audit.content_days is not None and not (
                1 <= audit.content_days <= profile.content_max_days
            ):
                self.err(
                    ErrorCode.AUDIT_CONTENT_DAYS_OUT_OF_RANGE,
                    "$.audit.content_days",
                    f"must be between 1 and {profile.content_max_days} days for these packs",
                )
                ok = False
            content_days = (
                audit.content_days
                if audit.content_days is not None
                else min(profile.content_default_days, profile.content_max_days)
            )
        if not ok:
            return None
        return EffectiveAudit(
            records_days=audit.records_days
            if audit.records_days is not None
            else profile.records_default_days,
            store_content=audit.store_content,
            content_days=content_days,
            content_requires_baa=profile.content_requires_baa,
        )

    # ------------------------------------------------------- assembly (C1.7, C1.8, C2, C9)

    def _assemble(
        self,
        bundle: Bundle,
        platform: dict[str, _PlatformRule],
        tenant_rules: list[tuple[Rule, float, float]],
    ) -> dict[str, CompiledGuardPoint]:
        s = self.settings
        default_fail = (
            bundle.defaults.fail_mode if bundle.defaults.fail_mode in FAIL_MODES else None
        )
        tenant_paths: dict[str, str] = {}
        for i, rule in enumerate(bundle.rules):
            tenant_paths.setdefault(f"t__{rule.id}", f"$.rules[{i}]")
        sized: set[str] = set()  # keys whose own size was checked (AC-C1.8(b))
        capped_keys, capped_texts = _capped_platform_rules(platform)
        out: dict[str, CompiledGuardPoint] = {}
        for gp in GUARD_POINTS:
            cfg = bundle.guard_points.get(gp, GuardPointConfig())
            path = f"$.guard_points.{gp}"
            gp_fail = cfg.fail_mode if cfg.fail_mode in FAIL_MODES else None
            fail_mode = gp_fail or default_fail or s.default_fail_mode
            content = cfg.chunk_tokens if gp == "tool_result" else cfg.max_input_tokens
            default_content = (
                s.default_chunk_tokens if gp == "tool_result" else s.default_max_content_tokens
            )
            max_content = content if content is not None else default_content

            entries: list[tuple[CompiledRule, Question]] = []
            if cfg.enabled:
                for pr in platform.values():
                    if gp in pr.rule.guard_points and not pr.disabled:
                        entries.append(
                            (
                                CompiledRule(
                                    key=pr.rule.key,
                                    layer=pr.layer,
                                    source=pr.source,
                                    question_type=pr.rule.question.type,
                                    block_at=pr.block_at,
                                    escalate_at=pr.escalate_at,
                                    mode=pr.rule.mode,
                                    severity=pr.rule.severity,
                                    fail_mode=s.floor_fail_mode
                                    if pr.layer == "floor"
                                    else fail_mode,
                                    provisional=pr.rule.provisional,
                                    max_action=None
                                    if pr.rule.max_action == "block"
                                    else pr.rule.max_action,
                                ),
                                pr.rule.question,
                            )
                        )
                for rule, block, escalate in tenant_rules:
                    if gp in rule.guard_points:
                        entries.append(
                            (
                                CompiledRule(
                                    key=f"t__{rule.id}",
                                    layer="tenant",
                                    source="tenant",
                                    question_type="noul",
                                    block_at=block,
                                    escalate_at=escalate,
                                    mode=rule.mode,
                                    severity=rule.severity,
                                    fail_mode=fail_mode,
                                    provisional=False,
                                    max_action=_inherited_cap(rule, capped_keys, capped_texts),
                                ),
                                _tenant_question(rule),
                            )
                        )
            entries.sort(key=lambda e: (_LAYER_RANK[e[0].layer], e[0].key))

            questions: dict[str, Question] = {}
            rules: dict[str, CompiledRule] = {}
            for meta, question in entries:
                if meta.key in questions:  # AC-C2: unique within the guard point
                    self.err(ErrorCode.KEY_DUPLICATE, path, f"key {meta.key!r} appears twice")
                    continue
                questions[meta.key] = question
                rules[meta.key] = meta

            for key, question in questions.items():
                if key not in sized:
                    sized.add(key)
                    meta = rules[key]
                    where = tenant_paths.get(key, path) if meta.layer == "tenant" else None
                    self._check_question_size(key, question, where or f"$.extends[{meta.source}]")
            self._check_question_budget(gp, path, rules)
            question_tokens = estimate_question_tokens(questions)
            content_tokens = question_text = 0
            if questions:
                content_tokens = content_api_tokens(max_content + s.render_overhead_tokens)
                if content_tokens > s.token_budget:
                    self.err(
                        ErrorCode.GP_TOKEN_BUDGET,
                        path,
                        f"content bound: estimated API tokens {content_tokens} = "
                        f"{API_TOKENS_TEXT_PERCENT / 100:.2f} x (max content {max_content} + "
                        f"render overhead {s.render_overhead_tokens}) + {API_TOKENS_PER_CALL}; "
                        f"limit is {s.token_budget}",
                    )
                question_text = question_api_tokens(question_tokens, len(questions))
                budget = s.question_budgets.for_guard_point(gp)
                limit = s.question_text_tokens_per_budgeted_question * budget
                if question_text > limit:
                    self.err(
                        ErrorCode.GP_QUESTION_TEXT_BUDGET,
                        path,
                        f"question text: estimated API tokens {question_text} = questions "
                        f"{question_tokens} + {API_TOKENS_PER_QUESTION} x {len(questions)} "
                        f"questions; limit is {limit} "
                        f"({s.question_text_tokens_per_budgeted_question} x question budget "
                        f"{budget})",
                    )

            out[gp] = CompiledGuardPoint(
                name=gp,
                enabled=cfg.enabled,
                questions=questions,
                rules=rules,
                max_content_tokens=max_content,
                question_tokens=question_tokens,
                api_tokens=content_tokens + question_text,
                content_api_tokens=content_tokens,
                question_api_tokens=question_text,
                tool_allowlist=tuple(cfg.tool_allowlist)
                if cfg.tool_allowlist is not None
                else None,
            )
        return out

    def _check_question_size(self, key: str, question: Question, path: str) -> None:
        """AC-C1.8(b) / R6.7: one compiled question, as sent (its ``{key: question}`` wire
        JSON) plus the per-question term, is at most ``max_question_tokens``."""
        tokens = question_api_tokens(estimate_question_tokens({key: question}), 1)
        limit = self.settings.max_question_tokens
        if tokens > limit:
            self.err(
                ErrorCode.QUESTION_TOKENS_EXCEEDED,
                path,
                f"question {key!r}: estimated API tokens {tokens} (its text and criteria "
                f"+ {API_TOKENS_PER_QUESTION}); limit is {limit} per question",
            )

    def _check_question_budget(self, gp: str, path: str, rules: Mapping[str, CompiledRule]) -> None:
        """AC-C1.7 / R6.1-R6.2: every compiled question counts, whatever its layer, type or
        mode. The floor and packs come first; tenant rules get what they leave, and the
        error says how much that is."""
        budget = self.settings.question_budgets.for_guard_point(gp)
        if len(rules) <= budget:
            return
        used = {layer: 0 for layer in _LAYER_RANK}
        for meta in rules.values():
            used[meta.layer] += 1
        remaining = max(0, budget - used["floor"] - used["pack"])
        self.err(
            ErrorCode.GP_TOO_MANY_QUESTIONS,
            path,
            f"{len(rules)} compiled questions; the question budget at {gp} is {budget}. "
            f"The floor uses {used['floor']} and packs use {used['pack']}, which leaves "
            f"{remaining} for tenant rules; this bundle has {used['tenant']}",
        )


# --------------------------------------------------------------------------- helpers


def _normalised_question(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip().lower().rstrip(".?! ")


def _capped_platform_rules(
    platform: Mapping[str, _PlatformRule],
) -> tuple[dict[str, str], dict[str, str]]:
    """The extended platform rules whose ``max_action`` is not ``block``: by key and by their
    question's normalised text."""
    by_key: dict[str, str] = {}
    by_text: dict[str, str] = {}
    for key, pr in platform.items():
        cap = pr.rule.max_action
        if cap == "block":
            continue
        by_key[key] = cap
        text = getattr(pr.rule.question, "instructions", None)
        if isinstance(text, str) and text.strip():
            by_text[_normalised_question(text)] = cap
    return by_key, by_text


def _inherited_cap(rule: Rule, by_key: Mapping[str, str], by_text: Mapping[str, str]) -> str | None:
    """A tenant rule that forks a capped platform rule (origin ``fork:<key>``) or asks the very
    same question inherits its ``max_action``: a copy of a rule that must never refuse a person
    in crisis can't be made to refuse one (R4.3). Reworded questions are not detected."""
    if rule.origin.startswith("fork:") and (cap := by_key.get(rule.origin[5:])):
        return cap
    return by_text.get(_normalised_question(rule.question or ""))


def _tenant_question(rule: Rule) -> NoulQuestion:
    criteria = None
    if rule.true_description and rule.false_description:  # AC-C2.1
        criteria = NoulCriteria(
            true_description=rule.true_description, false_description=rule.false_description
        )
    return NoulQuestion(instructions=rule.question or "", criteria=criteria)


def combined_retention(
    settings: PlatformSettings, packs: Iterable[PackVersion]
) -> RetentionProfile:
    """The R3 bounds that apply to a tenant whose bundle extends ``packs``: the platform's
    standard profile combined with each pack's own (AC-C1.13). The one place the bounds are
    worked out, shared by the compiler and the retention engine (M4-09)."""
    return _combine_retention(
        [settings.standard_retention, *(p.retention for p in packs if p.retention)]
    )


def records_days_in_bounds(profile: RetentionProfile, days: int) -> bool:
    """AC-C1.13: ``days`` is a permitted class B retention under ``profile``."""
    return profile.records_min_days <= days <= profile.records_max_days


def _combine_retention(profiles: list[RetentionProfile]) -> RetentionProfile:
    """R3 with several packs: the longest record retention and the shortest content cap."""
    return RetentionProfile(
        records_min_days=max(p.records_min_days for p in profiles),
        records_max_days=min(p.records_max_days for p in profiles),
        records_default_days=max(p.records_default_days for p in profiles),
        content_max_days=min(p.content_max_days for p in profiles),
        content_default_days=min(p.content_default_days for p in profiles),
        content_requires_baa=any(p.content_requires_baa for p in profiles),
    )
