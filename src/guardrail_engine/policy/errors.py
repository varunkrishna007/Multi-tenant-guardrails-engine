"""Validation errors for policy bundles (AC-C0).

Each error has a stable ``code`` and a JSON ``path`` (``$.rules[0].block_at``). The codes
are part of the Admin API contract (M2): add new ones, but never rename or reuse one.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict


class ErrorCode(StrEnum):
    # structure
    SCHEMA_INVALID = "schema.invalid"
    """Wrong JSON type, unknown field or missing required field."""
    SCHEMA_DUPLICATE_MEMBER = "schema.duplicate_member"
    """JSON text with an object that names the same member twice. The path is the object's."""
    TENANT_MISMATCH = "bundle.tenant_mismatch"
    SCHEMA_VERSION_MISSING = "bundle.schema_version_missing"
    SCHEMA_VERSION_UNSUPPORTED = "bundle.schema_version_unsupported"
    """Not an integer, or not a schema version this build can read."""
    CATALOG_SCHEMA_VERSION_MISSING = "catalog.schema_version_missing"
    """A floor or pack source document without ``schema_version`` (M1-09)."""
    CATALOG_SCHEMA_VERSION_UNSUPPORTED = "catalog.schema_version_unsupported"
    """A floor or pack source document whose ``schema_version`` this build can't read."""

    # extends
    EXTENDS_INVALID = "extends.invalid"
    EXTENDS_UNKNOWN = "extends.unknown"
    EXTENDS_DUPLICATE = "extends.duplicate"

    # AC-C1.1
    RULE_ID_INVALID = "rule.id_invalid"
    RULE_ID_DUPLICATE = "rule.id_duplicate"
    # AC-C1.2
    THRESHOLD_INVALID = "threshold.invalid"
    # AC-C1.3
    FLOOR_OVERRIDE_RAISES = "floor.override_raises"
    OVERRIDE_UNKNOWN_RULE = "override.unknown_rule"
    # AC-C1.4
    FLOOR_RULE_DISABLED = "floor.rule_disabled"
    FLOOR_RULE_SHADOWED = "floor.rule_shadowed"
    FLOOR_TEXT_EDITED = "floor.text_edited"
    FLOOR_MISSING = "floor.missing"
    FLOOR_BELOW_MINIMUM = "floor.below_minimum"
    FLOOR_NOT_RELEASED = "floor.not_released"
    # AC-C1.5
    PACK_TEXT_EDITED = "pack.text_edited"
    PACK_OVERRIDE_RAISES = "pack.override_raises"
    PACK_REQUIRED_MISSING = "pack.required_missing"
    PACK_OVERRIDE_NOT_ALLOWED = "pack.override_not_allowed"
    """Disabling or shadowing a pack rule. Tenants may only opt out of the whole pack, except in
    a pack that declares ``per_rule_optional`` (M4-10), and even there a rule can't be shadowed
    instead of switched off."""
    # M4-10 (R4.3, R4.6)
    OVERRIDE_MAX_ACTION_EDITED = "override.max_action_edited"
    """A tenant's override names a ``max_action`` other than the catalog rule's."""
    PACK_JUSTIFICATION_REQUIRED = "pack.justification_required"
    """Opting out of one rule of a per-rule-optional pack needs a written justification."""
    PACK_RULE_REQUIRED = "pack.rule_required"
    """The tenant's tier requires this pack rule: it can't be opted out of."""
    # AC-C1.6
    RULE_QUESTION_MISSING = "rule.question_missing"
    RULE_DESCRIPTION_MISSING = "rule.description_missing"
    RULE_QUESTION_NOT_CLOSED = "rule.question_not_closed"
    # AC-C1.7
    GP_TOO_MANY_QUESTIONS = "guard_point.too_many_questions"
    """More compiled questions than the guard point's question budget (R6.1)."""
    GP_TOO_MANY_TENANT_RULES = "guard_point.too_many_tenant_rules"
    """Retired by R6.2: the fixed limit of 100 tenant rules per guard point was withdrawn,
    and tenant rules now count against the question budget (``GP_TOO_MANY_QUESTIONS``).
    Never emitted; kept so the code is never reused with another meaning."""
    # M3-04
    GP_CHUNK_TOKENS_TOO_SMALL = "guard_point.chunk_tokens_too_small"
    """``tool_result`` ``chunk_tokens`` is under the platform's minimum
    (``PlatformSettings.min_chunk_tokens``, 2,048). A tiny chunk would hand the floor
    fragments with little context. The remedy is a larger chunk size, or leaving it unset."""
    # AC-C1.8
    GP_TOKEN_BUDGET = "guard_point.token_budget_exceeded"
    """(a) R6.7 content bound: the input text at the content cap is over ``token_budget``
    (16,000). Before R6.7 this budget also counted question text; the code, the setting and
    the limit are the same, and the remedy is a smaller content cap."""
    QUESTION_TOKENS_EXCEEDED = "question.token_limit_exceeded"
    """(b) R6.7: one compiled question is over ``max_question_tokens`` (400)."""
    GP_QUESTION_TEXT_BUDGET = "guard_point.question_text_budget_exceeded"
    """(c) R6.7: a guard point's question text is over 150 x its question budget."""
    # AC-C1.9
    TOOL_NOT_REGISTERED = "guard_point.tool_not_registered"
    # AC-C1.10
    DENY_PATTERN_INVALID = "deterministic.deny_pattern_invalid"
    DETERMINISTIC_ACTION_INVALID = "deterministic.action_invalid"
    PII_TYPE_UNSUPPORTED = "deterministic.pii_type_unsupported"
    # M3-01 (PF-11): deny pattern identity and size
    DENY_PATTERN_ID_INVALID = "deterministic.deny_pattern_id_invalid"
    DENY_PATTERN_ID_DUPLICATE = "deterministic.deny_pattern_id_duplicate"
    DENY_PATTERN_TOO_LONG = "deterministic.deny_pattern_too_long"
    DENY_PATTERNS_TOO_MANY = "deterministic.deny_patterns_too_many"
    # AC-C1.11
    GP_FLOOR_COVERED_DISABLED = "guard_point.floor_covered_disabled"
    RULE_UNKNOWN_GUARD_POINT = "rule.unknown_guard_point"
    GP_UNKNOWN = "guard_point.unknown"
    RULE_NO_GUARD_POINTS = "rule.no_guard_points"
    # AC-C1.12
    ESCALATION_TARGET_INVALID = "escalation.target_invalid"
    ESCALATION_WEBHOOK_NOT_HTTPS = "escalation.webhook_not_https"
    ESCALATION_WEBHOOK_HOST_NOT_PUBLIC = "escalation.webhook_host_not_public"
    ESCALATION_WEBHOOK_URL_MISSING = "escalation.webhook_url_missing"
    # AC-C1.13
    AUDIT_RECORDS_DAYS_OUT_OF_RANGE = "audit.records_days_out_of_range"
    AUDIT_CONTENT_DAYS_OUT_OF_RANGE = "audit.content_days_out_of_range"
    AUDIT_STORE_CONTENT_INVALID = "audit.store_content_invalid"
    AUDIT_CONTENT_REQUIRES_BAA = "audit.content_requires_baa"
    # AC-C1.14
    TEMPLATE_MISMATCH = "rule.template_mismatch"
    TEMPLATE_UNKNOWN = "rule.template_unknown"
    TEMPLATE_ORIGIN_INVALID = "rule.template_origin_invalid"
    ORIGIN_INVALID = "rule.origin_invalid"

    # enums
    RULE_MODE_INVALID = "rule.mode_invalid"
    RULE_SEVERITY_INVALID = "rule.severity_invalid"
    FAIL_MODE_INVALID = "fail_mode.invalid"

    # AC-C2 (only reachable through a bad catalog entry; tenant keys are always valid)
    KEY_INVALID = "compiled.key_invalid"
    KEY_DUPLICATE = "compiled.key_duplicate"


class PolicyError(BaseModel):
    model_config = ConfigDict(frozen=True)

    code: ErrorCode
    path: str
    message: str


class PolicyInvalidError(ValueError):
    """Raised by ``compile`` when the bundle has validation errors."""

    def __init__(self, errors: list[PolicyError]) -> None:
        self.errors = errors
        summary = "; ".join(f"{e.path}: {e.code}" for e in errors[:5])
        more = f" (+{len(errors) - 5} more)" if len(errors) > 5 else ""
        super().__init__(f"{len(errors)} policy error(s): {summary}{more}")


class CatalogDocumentError(ValueError):
    """A floor or pack source document that can't be read as one (M1-09): not a JSON
    object, not representable as canonical JSON, nested too deeply, or with a missing or
    unsupported ``schema_version``. ``errors`` lists the problems.

    A document that is readable but whose content is invalid (a bad key, inverted
    thresholds, ...) raises the catalog model's ``pydantic.ValidationError`` instead.
    """

    def __init__(self, errors: list[PolicyError]) -> None:
        self.errors = errors
        summary = "; ".join(f"{e.path}: {e.code}: {e.message}" for e in errors)
        super().__init__(f"catalog document rejected: {summary}")
