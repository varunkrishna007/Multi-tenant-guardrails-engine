"""The tenant policy bundle schema (design §Config model, plus backlog M1-01 additions).

Pydantic checks only JSON shape: types, unknown fields and required fields. Every product
rule (AC-C1) lives in the compiler, so it gets its own stable error code. That is why
enum-like fields are plain ``str`` here.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_serializer

from guardrail_engine.tenant_ids import TENANT_ID_PATTERN, is_valid_tenant_id

GUARD_POINTS = ("input", "plan", "tool_call", "tool_result", "output")
FAIL_MODES = ("closed", "open")
RULE_MODES = ("enforce", "shadow")
SEVERITIES = ("low", "medium", "high")
DETERMINISTIC_ACTIONS = ("block", "escalate", "redact", "log")  # PF-11
ESCALATION_TARGETS = ("queue", "webhook")  # S1
STORE_CONTENT = ("hash_only", "full")  # R3: "full" is post-redaction content (class C)


class _Strict(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class Thresholds(_Strict):
    block_at: float | None = None
    escalate_at: float | None = None


class Defaults(Thresholds):
    fail_mode: str | None = None


class GuardPointConfig(_Strict):
    enabled: bool = True
    max_input_tokens: int | None = Field(default=None, ge=1)
    chunk_tokens: int | None = Field(default=None, ge=1)
    fail_mode: str | None = None
    tool_allowlist: list[str] | None = None
    stream_window: str | None = None


class Rule(Thresholds):
    """A tenant rule, compiled to the ``noul`` question ``t__<id>``."""

    id: str
    guard_points: list[str]
    question: str | None = None
    true_description: str | None = None
    false_description: str | None = None
    severity: str = "medium"
    mode: str = "enforce"
    origin: str = "custom"
    """``custom``, ``template:<id>@<version>`` or ``fork:<pack rule key>`` (R1)."""
    template_unedited: bool = False


class Override(Thresholds):
    """Changes to a floor (``p__``) or pack (``d__``) rule.

    Only lowering ``block_at`` and ``escalate_at`` is allowed. The other fields exist so
    that attempts to disable, shadow or reword a platform rule get a specific error code.
    """

    rule: str
    enabled: bool | None = None
    mode: str | None = None
    question: str | None = None
    true_description: str | None = None
    false_description: str | None = None
    max_action: str | None = None
    """Never changeable by a tenant: naming it with a different value than the catalog's gets
    ``override.max_action_edited`` (M4-10). Exists so the attempt has a specific error."""
    justification: str | None = None
    """Why the tenant opts out of this rule. Required with ``enabled: false`` on a rule of a
    per-rule-optional pack (R4.6, M4-10), and kept in the class A audit event of the publish."""

    @model_serializer(mode="wrap")
    def _omit_unset_m4_10_fields(self, handler: Any) -> dict[str, Any]:
        """The two fields M4-10 added are optional and left out of a dump when unset, so the
        content a version 1 bundle document means (and its frozen defaults snapshot) is the
        one it had before them."""
        data: dict[str, Any] = handler(self)
        for name in ("max_action", "justification"):
            if data.get(name) is None:
                data.pop(name, None)
        return data


class PiiConfig(_Strict):
    detect: list[str] = Field(default_factory=list)
    action: str = "redact"


class DenyPattern(_Strict):
    id: str
    regex: str
    action: str = "block"


class Deterministic(_Strict):
    pii: PiiConfig | None = None
    deny_patterns: list[DenyPattern] = Field(default_factory=list)


URL_FORMAT = {"format": "uri"}
"""Marks a bundle field that holds a URL (JSON Schema ``format: uri``). Such a value may be a
bearer secret (a webhook with a token in its path or query), so anything that records bundle
content outside the policy store (the class A diff, M1-11) records only its scheme, host and
hash. Metadata only: it changes no validation, default or hash."""


class Escalation(_Strict):
    target: str = "queue"
    url: str | None = Field(default=None, json_schema_extra=URL_FORMAT)


class Audit(_Strict):
    records_days: int | None = None
    store_content: str = "hash_only"
    content_days: int | None = None


class Bundle(_Strict):
    """The model the compiler works on: a document read under its ``schema_version``.

    Defaults here belong to schema version 1 and are frozen with it. Don't change a default
    or add a defaulted field without a new schema version: see ``policy/document.py``.
    """

    schema_version: int
    tenant_id: str
    version: int = Field(ge=1)
    extends: list[str]
    defaults: Defaults = Field(default_factory=Defaults)
    guard_points: dict[str, GuardPointConfig] = Field(default_factory=dict)
    rules: list[Rule] = Field(default_factory=list)
    overrides: list[Override] = Field(default_factory=list)
    deterministic: Deterministic = Field(default_factory=Deterministic)
    escalation: Escalation = Field(default_factory=Escalation)
    audit: Audit = Field(default_factory=Audit)

    @field_validator("tenant_id")
    @classmethod
    def _tenant_id_format(cls, value: str) -> str:
        """One id rule everywhere (B3): a clear error at publish rather than a
        tenant that can be published but never authenticate."""
        if not is_valid_tenant_id(value):
            raise ValueError(f"tenant_id must match {TENANT_ID_PATTERN.pattern}")
        return value
