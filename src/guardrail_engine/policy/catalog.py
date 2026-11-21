"""The compiler's inputs, as interfaces with in-memory implementations (M1-01).

* :class:`Catalog`: platform floor versions, domain pack versions and rule templates. A floor
  or pack version is built from its source document, and its content hash covers that
  document as written, never the model read from it (M1-09, see "source documents" below).
* :class:`ToolRegistry`: the tools a tenant has registered.
* :class:`TenantAttributes`: the tenant's tier, contract-required packs and BAA flag.
* :class:`PlatformSettings`: platform-wide values such as the minimum floor version and
  ``floor_fail_mode`` (B1). B1 is a setting, not code.

Production implementations (Postgres-backed catalog, tenant registry) come with M1-02 and
M2. The compiler depends only on these interfaces.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any, ClassVar, Generic, Literal, Protocol, Self, TypeVar

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_serializer,
    model_serializer,
    model_validator,
)

from guardrail_engine.decision.limits import MAX_KEY_LENGTH, DecisionLimitError, validate_key
from guardrail_engine.decision.types import Question
from guardrail_engine.policy.errors import CatalogDocumentError, ErrorCode
from guardrail_engine.policy.json_document import canonicalize, load_canonical, select_reader
from guardrail_engine.policy.lint import CLOSED_QUESTION_RULE, is_blank, is_closed_question
from guardrail_engine.policy.schema import GUARD_POINTS, RULE_MODES, SEVERITIES


class _Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


# --------------------------------------------------------------------------- catalog content


MAX_ACTIONS = ("block", "escalate")
"""What a rule's ``max_action`` may be (M4-10)."""


class CatalogRule(_Frozen):
    """A floor (``p__``) or pack (``d__``) question. ``key`` is the full compiled key.

    Validated when built, so a hand-edited catalog file fails at load:

    * ``key`` starts with ``p__`` or ``d__`` and is a valid Decisions API key;
    * ``guard_points`` is a non-empty subset of the five guard points;
    * ``severity`` and ``mode`` are known values;
    * a ``noul`` rule carries both thresholds, with ``0.01 <= escalate_at < block_at <= 0.99``.
      Its thresholds always come from the catalog, never from a tenant's ``defaults``.
    * a ``noul`` rule's question is a closed yes/no question (AC-C1.6), and its criteria, when
      it has them, have two non-blank descriptions. Checked here, so it holds
      for floor and pack rules on every construction path, not only the floor file loader.
    * routers (``choice``) and scorers (``score``) carry no thresholds.
    """

    key: str
    guard_points: frozenset[str]
    question: Question
    block_at: float | None = None
    escalate_at: float | None = None
    severity: str = "high"
    mode: str = "enforce"
    provisional: bool = False
    """True until thresholds come from calibration (M1-08, M0-02)."""
    max_action: str = "block"
    """The most severe action this rule may take (M4-10, R4.3): ``block`` (the default: no
    cap) or ``escalate`` (it may hold content for a person, never refuse it: for people at
    risk, refusing is the wrong outcome). Fusion caps the rule's action at it, so a
    probability of 0.99 on an escalate-only rule still escalates. Only a pack document of
    schema version 2 can state it; version 1 documents mean ``block``. Omitted from dumps when
    it is the default, so a version 1 document's content is unchanged by the field."""

    @field_serializer("guard_points")
    def _sorted_guard_points(self, value: frozenset[str]) -> list[str]:
        return sorted(value)  # deterministic dumps, whatever PYTHONHASHSEED is

    @model_serializer(mode="wrap")
    def _omit_default_max_action(self, handler: Any) -> dict[str, Any]:
        data: dict[str, Any] = handler(self)
        if data.get("max_action") == "block":
            del data["max_action"]
        return data

    @model_validator(mode="after")
    def _validate(self) -> CatalogRule:
        if not self.key.startswith(("p__", "d__")):
            raise ValueError(f"catalog rule key {self.key!r} must start with p__ or d__")
        try:
            validate_key(self.key)
        except DecisionLimitError as e:
            raise ValueError(f"catalog rule key {self.key!r}: {e.reason}") from None
        if not self.guard_points:
            raise ValueError(f"{self.key}: needs at least one guard point")
        unknown = sorted(self.guard_points - set(GUARD_POINTS))
        if unknown:
            raise ValueError(f"{self.key}: unknown guard point(s) {unknown}")
        if self.severity not in SEVERITIES:
            raise ValueError(f"{self.key}: severity must be one of {SEVERITIES}")
        if self.mode not in RULE_MODES:
            raise ValueError(f"{self.key}: mode must be one of {RULE_MODES}")
        if self.max_action not in MAX_ACTIONS:
            raise ValueError(f"{self.key}: max_action must be one of {MAX_ACTIONS}")
        if self.max_action != "block" and self.question.type != "noul":
            raise ValueError(f"{self.key}: only a noul rule acts, so only it has a max_action")
        if self.question.type == "noul":
            if not is_closed_question(self.question.instructions):
                raise ValueError(
                    f"{self.key}: the question must be a closed yes/no question: "
                    f"{CLOSED_QUESTION_RULE}"
                )
            criteria = self.question.criteria
            if criteria is not None:
                for name in ("true_description", "false_description"):
                    if is_blank(getattr(criteria, name)):
                        raise ValueError(f"{self.key}: {name} must not be blank")
            if self.block_at is None or self.escalate_at is None:
                raise ValueError(f"{self.key}: a noul rule needs both block_at and escalate_at")
            if not 0.01 <= self.escalate_at < self.block_at <= 0.99:
                raise ValueError(
                    f"{self.key}: need 0.01 <= escalate_at < block_at <= 0.99, got "
                    f"escalate_at={self.escalate_at}, block_at={self.block_at}"
                )
        elif self.block_at is not None or self.escalate_at is not None:
            raise ValueError(f"{self.key}: a {self.question.type} question has no thresholds")
        return self


def _check_version_rules(rules: tuple[CatalogRule, ...], prefix: str, label: str) -> None:
    seen: set[str] = set()
    for rule in rules:
        if not rule.key.startswith(prefix):
            raise ValueError(f"{label}: rule {rule.key!r} must start with {prefix!r}")
        if rule.key in seen:
            raise ValueError(f"{label}: key {rule.key!r} is defined more than once")
        seen.add(rule.key)


def _covers(rules: tuple[CatalogRule, ...]) -> frozenset[str]:
    return frozenset().union(*(r.guard_points for r in rules))


class RetentionProfile(_Frozen):
    """R3 bounds for decision records (class B) and stored content (class C), in days."""

    records_min_days: int
    records_max_days: int
    records_default_days: int
    content_max_days: int
    content_default_days: int = 30
    content_requires_baa: bool = False


STANDARD_RETENTION = RetentionProfile(
    records_min_days=90,
    records_max_days=7 * 365,
    records_default_days=395,
    content_max_days=90,
)


FLOOR_MODE = "enforce"
FLOOR_SEVERITY = "high"
FLOOR_KEY_PATTERN = re.compile(r"p__[a-z0-9_]+")
"""Floor keys use the narrower alphabet that ``floor/README.md`` states, the same one as tenant rule
ids, and are at most ``MAX_KEY_LENGTH`` characters.
ASCII-only, applied with ``fullmatch``. The one definition, shared with the file loader."""


class FloorContent(_Frozen):
    """What a floor source document means: the model read from it under its
    ``schema_version`` (see :class:`FloorVersion`). Never hashed and never stored.

    Every floor rule is ``enforce`` and ``high`` (a platform decision).
    A shadowed floor rule is evaluated but never acts, so it is a disabled floor rule, and
    severity drives escalation priority. This is checked here, not only in the file loader,
    so no catalog source can build a weaker floor. Pack rules may still use ``shadow``.
    """

    version: int
    rules: tuple[CatalogRule, ...]

    @model_validator(mode="after")
    def _validate(self) -> FloorContent:
        label = f"floor@{self.version}"
        _check_version_rules(self.rules, "p__", label)
        for rule in self.rules:
            if len(rule.key) > MAX_KEY_LENGTH or not FLOOR_KEY_PATTERN.fullmatch(rule.key):
                raise ValueError(
                    f"{label}: floor rule key {rule.key!r} must match p__[a-z0-9_]+ and be at "
                    f"most {MAX_KEY_LENGTH} characters"
                )
            if rule.mode != FLOOR_MODE:
                raise ValueError(
                    f"{label}: floor rule {rule.key!r} must have mode {FLOOR_MODE!r}, "
                    f"got {rule.mode!r}"
                )
            if rule.severity != FLOOR_SEVERITY:
                raise ValueError(
                    f"{label}: floor rule {rule.key!r} must have severity {FLOOR_SEVERITY!r}, "
                    f"got {rule.severity!r}"
                )
        return self


class PackContent(_Frozen):
    """What a pack source document means: the model read from it under its
    ``schema_version`` (see :class:`PackVersion`). Never hashed and never stored."""

    name: str
    version: int
    rules: tuple[CatalogRule, ...]
    retention: RetentionProfile | None = None
    """R3 bounds this pack imposes. None means the standard profile."""
    per_rule_optional: bool = False
    """A tenant may opt out of one rule of this pack, with a written justification (R4.6, M4-10).
    Every other pack is whole-pack opt-in or opt-out. Schema version 2 only."""
    description: str = ""
    """What the pack is for, in the catalog's own words (M4-10: the responsible-AI pack's states
    the claims boundary of R4.4). Not part of what the compiler reads. Schema version 2 only."""

    @model_serializer(mode="wrap")
    def _omit_defaults(self, handler: Any) -> dict[str, Any]:
        data: dict[str, Any] = handler(self)
        if data.get("per_rule_optional") is False:
            del data["per_rule_optional"]
        if data.get("description") == "":
            del data["description"]
        return data

    @model_validator(mode="after")
    def _validate(self) -> PackContent:
        _check_version_rules(self.rules, "d__", f"{self.name}@{self.version}")
        return self


# --------------------------------------------------------------------------- source documents
#
# A floor or pack version exists in two forms, kept together like a bundle's (M1-09, the
# catalog side of AC-C2.2; see ``policy/document.py``):
#
# * the **source document**: the JSON object exactly as written, with nothing filled in.
#   Its canonical JSON is what ``content_hash()`` covers, and so what every bundle hash
#   that extends the version covers.
# * the **content** (FloorContent, PackContent): the document read under its
#   ``schema_version``, with that version's defaults filled in. The compiler works on this.
#   It is never hashed.
#
# So adding a field to CatalogRule, or changing one of its defaults, can't change the hash
# of a floor or pack document that didn't change, nor the hash of any bundle extending it.
#
# **Schema versions.** Every catalog source document carries a required integer
# ``schema_version``. _FLOOR_READERS and _PACK_READERS map each supported version to the
# function that reads a document of that version into the current content model, and the
# defaults a reader fills in are fixed for good. To add schema version 2 of either kind:
#
# 1. Change the content models (CatalogRule, FloorContent, PackContent) as needed.
# 2. Add the version 2 reader and register it in the readers map.
# 3. Make the version 1 reader state explicitly the value version 1 documents get for
#    anything that changed (for a new field, the value that keeps a v1 document meaning what
#    it meant), instead of inheriting the model's new default.
# 4. Add version 2 to the defaults snapshot in ``tests/policy/test_m1_09_catalog_documents.py``.
#    The version 1 snapshot must still pass unchanged; if it doesn't, step 3 is incomplete.
#
# A registered catalog version then keeps both its content hash (the bytes didn't change)
# and its meaning (its reader didn't change). Changing what a floor or pack says means
# registering a new version (floor@2, ...), never re-reading an old one differently.


class _FloorRuleV1(BaseModel):
    """One rule of a schema version 1 floor document: the flat format of
    ``floor/rules.json`` (``floor/README.md``). Every field is required and none has a
    default, so a version 1 floor document states everything it means. JSON types are
    strict: a threshold is a number, ``provisional`` a boolean, never a string."""

    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    key: str
    question: str
    true_description: str
    false_description: str
    guard_points: list[str]
    severity: str
    block_at: float
    escalate_at: float
    mode: str
    provisional: bool


class _FloorDocumentV1(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    schema_version: Literal[1]
    floor_version: int = Field(ge=1)
    rules: list[_FloorRuleV1]


def _read_floor_v1(document: Mapping[str, Any]) -> FloorContent:
    """Floor schema version 1: the flat file format, mapped one to one onto the catalog
    rule. ``question`` and the two descriptions become a ``noul`` question with criteria.
    Any catalog rule field the flat format doesn't have keeps the model's own default."""
    flat = _FloorDocumentV1.model_validate(document)
    return FloorContent.model_validate(
        {
            "version": flat.floor_version,
            "rules": [
                {
                    "key": r.key,
                    "guard_points": r.guard_points,
                    "question": {
                        "type": "noul",
                        "instructions": r.question,
                        "criteria": {
                            "true_description": r.true_description,
                            "false_description": r.false_description,
                        },
                    },
                    "block_at": r.block_at,
                    "escalate_at": r.escalate_at,
                    "severity": r.severity,
                    "mode": r.mode,
                    "provisional": r.provisional,
                }
                for r in flat.rules
            ],
        }
    )


_PACK_V2_PACK_FIELDS = ("per_rule_optional", "description")
_PACK_V2_RULE_FIELDS = ("max_action",)


def _read_pack_v1(document: Mapping[str, Any]) -> PackContent:
    """Pack schema version 1: the ``PackContent`` model's own shape and defaults, plus
    ``schema_version``. Rules are catalog rules, with the question as on the wire. Version 1
    has no ``max_action``, ``per_rule_optional`` or ``description``: a document that names one
    is refused, and the values a version 1 document gets are stated here (no cap, not
    per-rule-optional, no description), not inherited from the model."""
    if not isinstance(document, Mapping):
        return PackContent.model_validate(document)  # refused, in the model's own words
    named = [f for f in _PACK_V2_PACK_FIELDS if f in document]
    rules = document.get("rules", ())
    for rule in rules if isinstance(rules, list | tuple) else ():
        if isinstance(rule, Mapping):
            named += [f for f in _PACK_V2_RULE_FIELDS if f in rule]
    if named:
        raise ValueError(f"pack schema version 1 has no {sorted(set(named))}: use version 2")
    body = {k: v for k, v in document.items() if k != "schema_version"}
    body["per_rule_optional"] = False
    body["description"] = ""
    if isinstance(rules, list | tuple):
        body["rules"] = [
            {**r, "max_action": "block"} if isinstance(r, Mapping) else r for r in rules
        ]
    return PackContent.model_validate(body)


def _read_pack_v2(document: Mapping[str, Any]) -> PackContent:
    """Pack schema version 2 (M4-10): version 1 plus ``max_action`` on a rule (default
    ``block``), ``per_rule_optional`` (default false) and ``description`` (default empty)."""
    return PackContent.model_validate({k: v for k, v in document.items() if k != "schema_version"})


_FLOOR_READERS: dict[int, Callable[[Mapping[str, Any]], FloorContent]] = {1: _read_floor_v1}
_PACK_READERS: dict[int, Callable[[Mapping[str, Any]], PackContent]] = {
    1: _read_pack_v1,
    2: _read_pack_v2,
}

SUPPORTED_FLOOR_SCHEMA_VERSIONS: tuple[int, ...] = tuple(sorted(_FLOOR_READERS))
CURRENT_FLOOR_SCHEMA_VERSION: int = SUPPORTED_FLOOR_SCHEMA_VERSIONS[-1]
SUPPORTED_PACK_SCHEMA_VERSIONS: tuple[int, ...] = tuple(sorted(_PACK_READERS))
CURRENT_PACK_SCHEMA_VERSION: int = SUPPORTED_PACK_SCHEMA_VERSIONS[-1]

_C = TypeVar("_C", FloorContent, PackContent)


@dataclass(frozen=True, slots=True)
class _CatalogVersion(Generic[_C]):
    """A catalog source document and the content read from it. Build one with
    ``from_document``.

    The document is held as its canonical JSON bytes, so nothing the caller does to the
    object it passed in can change what is hashed. The content can't be supplied: it is
    always read from ``canonical_document`` when the version is constructed, so a version
    can't pair one document's hash with content read from another. Constructing one
    directly raises ``TypeError`` for anything but ``bytes``, ``ValueError`` for bytes that
    aren't canonical JSON, :class:`CatalogDocumentError` for a document with a missing or
    unsupported ``schema_version``, and ``pydantic.ValidationError`` for invalid content.

    Two versions are equal when their documents are, so the catalog's refusal to
    re-register a version with different content (AC-C2.2) compares documents.
    """

    canonical_document: bytes
    """Canonical JSON of the source document as written. This is what is hashed."""
    _content: _C = field(init=False, repr=False, compare=False)

    _KIND: ClassVar[str]
    _READERS: ClassVar[Mapping[int, Callable[[Mapping[str, Any]], Any]]]

    def __post_init__(self) -> None:
        snapshot = load_canonical(
            self.canonical_document,
            invalid=CatalogDocumentError,
            hint=f"use {type(self).__name__}.from_document() to read a source document",
        )
        reader, errors = select_reader(
            snapshot,
            self._READERS,
            what=f"{self._KIND} document",
            missing=ErrorCode.CATALOG_SCHEMA_VERSION_MISSING,
            unsupported=ErrorCode.CATALOG_SCHEMA_VERSION_UNSUPPORTED,
        )
        if reader is None:
            raise CatalogDocumentError(errors)
        object.__setattr__(self, "_content", reader(snapshot))

    @classmethod
    def from_document(cls, document: Mapping[str, Any]) -> Self:
        """Read a source document (a parsed JSON object). Raises as the constructor does,
        and :class:`CatalogDocumentError` for an object that has no canonical JSON."""
        canonical, errors = canonicalize(document, what=f"{cls._KIND} document")
        if canonical is None:
            raise CatalogDocumentError(errors)
        return cls(canonical)

    @property
    def document(self) -> dict[str, Any]:
        """A fresh copy of the source document."""
        return json.loads(self.canonical_document)

    @property
    def content(self) -> _C:
        """A fresh copy of the content read from the document. For the compiler, not for
        hashing. A copy each time: the models are frozen, but a question's ``criteria`` is a
        dict or list, and changing it must not change what a later caller compiles."""
        return self._content.model_copy(deep=True)

    @property
    def version(self) -> int:
        return self._content.version

    @property
    def rules(self) -> tuple[CatalogRule, ...]:
        """A fresh copy of the rules (see :attr:`content`)."""
        return self.content.rules

    def content_hash(self) -> str:
        """``sha256:<hex>`` over the canonical JSON of the source document as written
        (AC-C2.2, M1-09), the same as ``sha256_of(self.document)``. Never over the content
        model, so a change to the model's fields or defaults can't change it."""
        return "sha256:" + hashlib.sha256(self.canonical_document).hexdigest()


@dataclass(frozen=True, slots=True)
class FloorVersion(_CatalogVersion[FloorContent]):
    """A version of the platform floor: its source document (the flat format of
    ``floor/rules.json``) and the :class:`FloorContent` read from it. Build one with
    ``FloorVersion.from_document`` or, from a file, the floor loader."""

    _KIND: ClassVar[str] = "floor"
    _READERS: ClassVar[Mapping[int, Callable[[Mapping[str, Any]], Any]]] = _FLOOR_READERS

    @property
    def covers(self) -> frozenset[str]:
        """Guard points where at least one floor rule runs. A tenant can't disable these
        (PF-15, AC-C1.11). Derived from the rules, never declared, so the two can't drift."""
        return _covers(self._content.rules)

    @property
    def ref(self) -> str:
        return f"platform/floor@{self.version}"


@dataclass(frozen=True, slots=True)
class PackVersion(_CatalogVersion[PackContent]):
    """A version of a domain pack: its source document and the :class:`PackContent` read
    from it. Build one with ``PackVersion.from_document``."""

    _KIND: ClassVar[str] = "pack"
    _READERS: ClassVar[Mapping[int, Callable[[Mapping[str, Any]], Any]]] = _PACK_READERS

    @property
    def name(self) -> str:
        return self._content.name

    @property
    def retention(self) -> RetentionProfile | None:
        """R3 bounds this pack imposes. None means the standard profile."""
        return self._content.retention

    @property
    def per_rule_optional(self) -> bool:
        """A tenant may opt out of one rule of this pack, with a justification (R4.6)."""
        return self._content.per_rule_optional

    @property
    def description(self) -> str:
        return self._content.description

    @property
    def covers(self) -> frozenset[str]:
        """Guard points where at least one of the pack's rules runs (derived)."""
        return _covers(self._content.rules)

    @property
    def ref(self) -> str:
        return f"domain/{self.name}@{self.version}"


TEMPLATE_ID_PATTERN = re.compile(r"(?=.{1,40}\Z)[a-z][a-z0-9]*(?:_[a-z0-9]+)*")
"""A template id is also the tail of the ``t__<id>`` rule it creates, so it uses the rule id
alphabet (lower case, digits, single underscores between words) and leaves room for the prefix."""
MIN_STARTER_EXAMPLES = 10
"""A catalog template ships at least this many starter examples (R1)."""
MAX_STARTER_EXAMPLES = 200
MAX_STARTER_CONTENT_CHARS = 2_000


class StarterExample(_Frozen):
    """One labelled example a template brings to the tenant's golden set when it is applied."""

    guard_point: str
    label: str
    content: str

    @model_validator(mode="after")
    def _validate(self) -> StarterExample:
        if self.guard_point not in GUARD_POINTS:
            raise ValueError(f"starter example: unknown guard point {self.guard_point!r}")
        if self.label not in ("allow", "block"):
            raise ValueError("starter example: label must be 'allow' or 'block'")
        if is_blank(self.content) or len(self.content) > MAX_STARTER_CONTENT_CHARS:
            raise ValueError(
                f"starter example: content must be 1 to {MAX_STARTER_CONTENT_CHARS} characters"
            )
        return self


class Template(_Frozen):
    """A curated starting point for a tenant rule (R1). Using it copies it into a ``t__`` rule.

    The first seven fields are what the copy takes. The rest is catalog text and the starter
    examples: ``title`` and ``description`` say what the template is for, ``notice`` is a caveat
    shown with it (the within-tenant records template says it is a soft signal and **not an
    access control**, R9), ``guard_points`` are where the copy runs, ``severity`` is the copy's,
    and ``starter_examples`` are imported into the tenant's golden set on apply.
    """

    id: str
    version: int
    question: str
    true_description: str
    false_description: str
    block_at: float
    escalate_at: float
    title: str = ""
    description: str = ""
    notice: str = ""
    guard_points: tuple[str, ...] = ()
    severity: str = "medium"
    starter_examples: tuple[StarterExample, ...] = ()

    @model_validator(mode="after")
    def _validate(self) -> Template:
        ref = f"template {self.id}@{self.version}"
        if not TEMPLATE_ID_PATTERN.fullmatch(self.id):
            raise ValueError(f"{ref}: the id must match {TEMPLATE_ID_PATTERN.pattern}")
        if self.version < 1:
            raise ValueError(f"{ref}: the version must be at least 1")
        if not is_closed_question(self.question):
            raise ValueError(f"{ref}: the question must be closed: {CLOSED_QUESTION_RULE}")
        for name in ("true_description", "false_description"):
            if is_blank(getattr(self, name)):
                raise ValueError(f"{ref}: {name} must not be blank")
        if not 0.01 <= self.escalate_at < self.block_at <= 0.99:
            raise ValueError(
                f"{ref}: need 0.01 <= escalate_at < block_at <= 0.99, got "
                f"escalate_at={self.escalate_at}, block_at={self.block_at}"
            )
        unknown = sorted(set(self.guard_points) - set(GUARD_POINTS))
        if unknown or len(set(self.guard_points)) != len(self.guard_points):
            raise ValueError(f"{ref}: guard_points must be distinct known guard points")
        if self.severity not in SEVERITIES:
            raise ValueError(f"{ref}: severity must be one of {SEVERITIES}")
        if len(self.starter_examples) > MAX_STARTER_EXAMPLES:
            raise ValueError(f"{ref}: at most {MAX_STARTER_EXAMPLES} starter examples")
        stray = {e.guard_point for e in self.starter_examples} - set(self.guard_points)
        if self.starter_examples and stray:
            raise ValueError(f"{ref}: starter examples at {sorted(stray)} the rule doesn't run on")
        return self


class Catalog(Protocol):
    """Catalog versions are immutable: a version number always means the same content."""

    def floor(self, version: int) -> FloorVersion | None: ...

    def floor_versions(self) -> tuple[int, ...]:
        """Every floor version the catalog holds, ascending (the catalog is append-only)."""
        ...

    def minimum_floor_version(self) -> int:
        """The lowest floor version a bundle may extend, as the platform has raised it (R5.5);
        the configured ``min_floor_version`` applies as well, and the larger wins."""
        ...

    def is_released(self, version: int) -> bool:
        """Whether tenants may extend floor ``version``: the baseline and every floor the
        platform released (R5.1). A floor in the catalog that isn't released can be read and
        verified, never extended."""
        ...

    def pack(self, name: str, version: int) -> PackVersion | None: ...

    def pack_versions(self) -> tuple[tuple[str, int], ...]:
        """Every (pack name, version) the catalog holds, sorted."""
        ...

    def template(self, template_id: str, version: int) -> Template | None: ...

    def template_versions(self) -> tuple[tuple[str, int], ...]:
        """Every (template id, version) the catalog holds, sorted."""
        ...

    def packs_required_for_tier(self, tier: str) -> frozenset[str]:
        """Pack names every tenant of ``tier`` must extend."""
        ...

    def rules_required_for_tier(self, tier: str) -> frozenset[str]:
        """Compiled keys of pack rules that a tenant of ``tier`` can't opt out of one by one,
        even in a per-rule-optional pack (M4-10)."""
        ...

    def default_on_packs(self) -> frozenset[str]:
        """Pack names a **new** tenant's starter bundle extends (M4-10, R4: the responsible-AI
        pack is on by default). A tenant may leave one out, unless its tier requires it; the
        change is in the publish's class A diff."""
        ...


def _register(registry: dict, key: object, item: object, label: str) -> None:
    """Add ``item``. Re-registering identical content is a no-op; different content under the
    same version raises (AC-C2.2), so the last registration can never silently win. For a
    floor or pack, content is the source document (M1-09)."""
    existing = registry.get(key)
    if existing is not None and existing != item:
        raise ValueError(f"{label} is already registered with different content")
    registry[key] = item


class InMemoryCatalog:
    def __init__(
        self,
        *,
        floors: Iterable[FloorVersion] = (),
        packs: Iterable[PackVersion] = (),
        templates: Iterable[Template] = (),
        tier_required_packs: Mapping[str, Iterable[str]] | None = None,
        tier_required_rules: Mapping[str, Iterable[str]] | None = None,
        default_on_packs: Iterable[str] = (),
    ) -> None:
        self._floors: dict[int, FloorVersion] = {}
        self._packs: dict[tuple[str, int], PackVersion] = {}
        self._templates: dict[tuple[str, int], Template] = {}
        for f in floors:
            _register(self._floors, f.version, f, f"floor@{f.version}")
        for p in packs:
            _register(self._packs, (p.name, p.version), p, f"{p.name}@{p.version}")
        for t in templates:
            _register(self._templates, (t.id, t.version), t, f"template {t.id}@{t.version}")
        self._tier_packs = {k: frozenset(v) for k, v in (tier_required_packs or {}).items()}
        self._tier_rules = {k: frozenset(v) for k, v in (tier_required_rules or {}).items()}
        self._default_on = frozenset(default_on_packs)
        self._minimum = 1
        self._released: frozenset[int] | None = None

    def floor(self, version: int) -> FloorVersion | None:
        return self._floors.get(version)

    def floor_versions(self) -> tuple[int, ...]:
        return tuple(sorted(self._floors))

    def minimum_floor_version(self) -> int:
        return self._minimum

    def raise_minimum(self, version: int) -> None:
        """Only :class:`~guardrail_engine.admin.floors.FloorService` calls this, after the
        platform checked that every tenant is on a floor at or above ``version``. It never
        goes down."""
        if version > self._minimum:
            self._minimum = version

    def restore_minimum(self, version: int) -> None:
        """Undo a raise that was applied before its checks passed (``RepinService.raise_minimum``
        applies the minimum first, so no tenant can move below it while it checks, and takes it
        back if a tenant is behind). The only way the minimum goes down."""
        self._minimum = version

    def is_released(self, version: int) -> bool:
        if self._released is None:
            return True
        # Once restricted, the baseline (the lowest floor version) is always extendable.
        return version in self._released or (bool(self._floors) and version == min(self._floors))

    def set_released(self, versions: Iterable[int] | None) -> None:
        """``None``: every floor in the catalog is extendable (the default for a catalog built
        directly: a library or a test with no release process). Otherwise only these versions
        and the baseline are. The engine factory restricts the catalog it uses at build, so an
        engine never starts open."""
        self._released = None if versions is None else frozenset(versions)

    def pack(self, name: str, version: int) -> PackVersion | None:
        return self._packs.get((name, version))

    def pack_versions(self) -> tuple[tuple[str, int], ...]:
        return tuple(sorted(self._packs))

    def template(self, template_id: str, version: int) -> Template | None:
        return self._templates.get((template_id, version))

    def template_versions(self) -> tuple[tuple[str, int], ...]:
        return tuple(sorted(self._templates))

    def packs_required_for_tier(self, tier: str) -> frozenset[str]:
        return self._tier_packs.get(tier, frozenset())

    def rules_required_for_tier(self, tier: str) -> frozenset[str]:
        """The rules named for the tier, **plus every rule of every pack the tier requires**
        (M5-01: R4 names no individual rule of the responsible-AI pack, so a required pack is
        required whole). All versions of the pack count, so a rule renamed in a later version
        is still protected in the version a tenant extends."""
        keys = set(self._tier_rules.get(tier, ()))
        for name in self._tier_packs.get(tier, ()):
            for (pack_name, _), pack in self._packs.items():
                if pack_name == name:
                    keys.update(rule.key for rule in pack.rules)
        return frozenset(keys)

    def default_on_packs(self) -> frozenset[str]:
        return self._default_on

    # The catalog is append-only (M2-03): these are the only ways an item leaves it, and
    # ``CatalogAdmin`` (``admin/catalog.py``) is their only caller, after it has checked that no
    # stored bundle uses the item. ``tests/admin/test_catalog_admin.py`` fails on any other.

    def discard_floor(self, version: int) -> bool:
        return self._floors.pop(version, None) is not None

    def discard_pack(self, name: str, version: int) -> bool:
        return self._packs.pop((name, version), None) is not None

    def discard_template(self, template_id: str, version: int) -> bool:
        return self._templates.pop((template_id, version), None) is not None


# --------------------------------------------------------------------------- tenant inputs


class ToolRegistry(Protocol):
    def has_tool(self, name: str) -> bool: ...


class InMemoryToolRegistry:
    def __init__(self, tools: Iterable[str] = ()) -> None:
        self._tools = frozenset(tools)

    def has_tool(self, name: str) -> bool:
        return name in self._tools


REGULATED_TIERS = frozenset({"regulated", "dedicated"})
"""M5-01 (R2): the tiers that count as **regulated**: every tier but ``standard``. ``dedicated``
was already treated like ``regulated`` by two-person approval (M5-02) and the quota shares
(M3-07); the one definition is here, so the approval gate, the required packs and the dedicated
Gemini project (M5-06) agree."""
REGULATED_REQUIRED_PACKS = frozenset({"responsible_ai"})
"""M5-01 (R4.1): the packs the regulated tiers require by default, besides any the platform
settings add (``catalog.tier_required_packs``). R4 names no rule of the pack, so the whole pack
is required: every rule of it is a tier-required rule (:meth:`Catalog.rules_required_for_tier`)."""


def is_regulated_tier(tier: str) -> bool:
    """Whether ``tier`` is a regulated tier (R2): anything but ``standard``."""
    return tier in REGULATED_TIERS


class TenantAttributes(_Frozen):
    """Set by platform ops from the contract. Tenants can't edit these."""

    tenant_id: str
    tier: str = "standard"
    """``standard``, ``regulated`` or ``dedicated``. Only a platform operator sets it (M5-01)."""
    required_packs: frozenset[str] = frozenset()
    """Packs the contract requires, on top of those the tier requires."""
    baa: bool = False
    """A BAA is in place, so healthcare content storage may be enabled (R3)."""
    project: str | None = None
    """M5-06: the label of the Gemini project the tenant is assigned to (a dedicated one), or
    None for the shared pool. A label only: never a key or a project secret."""

    @property
    def regulated(self) -> bool:
        """The tier is a regulated one (R2, M5-01)."""
        return is_regulated_tier(self.tier)


# --------------------------------------------------------------------------- platform


DEFAULT_CHUNK_TOKENS = 12_000
"""AC-G5 (M3-04): the default ``tool_result`` chunk size, in raw estimated tokens."""
MIN_CHUNK_TOKENS = 2_048
"""M3-04: the default minimum of a tenant's ``chunk_tokens``."""
DEFAULT_MAX_CHUNKS = 4
"""M3-04: the default bound on chunks (decision calls) per ``tool_result`` check, set to the
default in-flight limit per key (``DEFAULT_MAX_IN_FLIGHT_PER_KEY``, 4), so every chunk of an
accepted result can be in flight at once. At 12,000 tokens a chunk (256 shared) it admits
results of about 47,000 raw tokens (some 190 KB of English text). **A result needing more is
blocked as ``content_too_large`` with no model call**, not left for admission control to
refuse as a retryable capacity failure. A platform setting, raised together with the
in-flight limit."""

RENDER_OVERHEAD_TOKENS = 512
"""Tokens reserved for what the Guard Service adds around the content: the TENANT DOMAIN,
TENANT and GUARD POINT header lines, the nonce instruction line, and the nonce-delimited
section markers for each untrusted section (B3). Used by the AC-C1.8 budget, where it counts
as input text alongside the content (shared-estimator tokens, before the R6.6 fit). The fixed
part is about 108 tokens at its longest (64-character slug), so 512 leaves ample room."""

CRITICAL_PATH_QUESTION_BUDGET = 50
"""R6.1: compiled questions allowed on ``plan``, ``tool_call``, ``tool_result`` (per chunk)
and ``output``, which are on the agent's critical path (about 370 ms p50 at 4K input)."""
INPUT_QUESTION_BUDGET = 200
"""R6.1: compiled questions allowed on ``input``, which runs alongside the planner (about
670 ms p50 at 4K input)."""


class QuestionBudgets(_Frozen):
    """R6.1: the most compiled questions each guard point may have, counting every question
    of every type and layer (floor, pack and tenant; ``noul``, routers and scorers;
    ``shadow`` rules too). Platform settings, never tenant settings. They replace the
    earlier 900-question cap and the fixed limit of 100 tenant rules per guard point
    (R6.2): a tenant's rules get whatever the budget leaves after the floor and packs."""

    input: int = Field(default=INPUT_QUESTION_BUDGET, ge=1)
    plan: int = Field(default=CRITICAL_PATH_QUESTION_BUDGET, ge=1)
    tool_call: int = Field(default=CRITICAL_PATH_QUESTION_BUDGET, ge=1)
    tool_result: int = Field(default=CRITICAL_PATH_QUESTION_BUDGET, ge=1)
    """Per chunk: every chunk of a tool result is checked with the same question set."""
    output: int = Field(default=CRITICAL_PATH_QUESTION_BUDGET, ge=1)

    def for_guard_point(self, guard_point: str) -> int:
        if guard_point not in GUARD_POINTS:
            raise KeyError(guard_point)
        return getattr(self, guard_point)


DEFAULT_PII_TYPES = frozenset(
    {
        "SSN",
        "CREDIT_CARD",
        "EMAIL",
        "PHONE",
        "IBAN",
        "IP_ADDRESS",
        "PERSON_NAME",
        "POSTAL_ADDRESS",
        "DATE_OF_BIRTH",
    }
)


class PlatformSettings(_Frozen):
    min_floor_version: int = 1
    floor_fail_mode: str = "closed"
    """B1: floor rules fail closed. A setting, so a sign-off change needs no code change."""
    default_fail_mode: str = "closed"
    """S5: used for pack and tenant rules when neither the guard point nor the bundle sets one."""
    default_block_at: float = 0.85
    default_escalate_at: float = 0.55
    question_budgets: QuestionBudgets = Field(default_factory=QuestionBudgets)
    """R6.1 / AC-C1.7: compiled questions allowed per guard point (50, and 200 on input)."""
    token_budget: int = 16_000
    """AC-C1.8(a) / R6.7 content bound: the most estimated API tokens a guard point's input
    text may take, ``ceil(1.20 x (max content + render overhead)) + 30``. Questions do not
    count toward it (they have their own bounds below and in ``question_budgets``)."""
    max_question_tokens: int = 400
    """AC-C1.8(b) / R6.7: the most estimated API tokens one compiled question may take, its
    wire JSON (key, type, instructions, criteria) plus 25."""
    question_text_tokens_per_budgeted_question: int = 150
    """AC-C1.8(c) / R6.7: a guard point's question text (``estimate(question text) + 25 x
    questions``) may take at most this many estimated API tokens per question in its
    question budget: 7,500 on the critical path, 30,000 on input."""
    render_overhead_tokens: int = RENDER_OVERHEAD_TOKENS
    default_max_content_tokens: int = 8_000
    """Content cap for a guard point that sets no ``max_input_tokens``. (``tool_result`` has
    :attr:`default_chunk_tokens` instead: it is chunked, not capped.)"""
    default_chunk_tokens: int = Field(default=DEFAULT_CHUNK_TOKENS, ge=1)
    """M3-04 (AC-G5): the ``tool_result`` chunk size when the bundle sets no ``chunk_tokens``:
    content over it is split into chunks overlapping by 256 tokens. Raised from 8,000 to
    12,000 raw tokens, just inside the R6.7 content bound, to cut the number of chunks."""
    min_chunk_tokens: int = Field(default=MIN_CHUNK_TOKENS, ge=1)
    """M3-04: the smallest ``chunk_tokens`` a bundle may set for
    ``tool_result``. A smaller chunk would hand the floor fragments with little context, and
    the tenant would mostly hurt itself (a result over ``chunk_tokens x max_chunks_per_result``
    is blocked). Tests of small chunks lower it in their own settings."""
    max_chunks_per_result: int = Field(default=DEFAULT_MAX_CHUNKS, ge=1)
    """M3-04: the most chunks (so decision calls) one ``tool_result`` check may need. A
    result that would need more is a deterministic block, ``content_too_large``, with no model
    call: without a bound, one tool result could fan out into any number of calls. A platform
    setting, never a tenant's."""
    supported_pii_types: frozenset[str] = DEFAULT_PII_TYPES
    max_deny_patterns: int = Field(default=100, ge=0)
    """M3-01 (PF-11): the most deny patterns one bundle may carry. Every check scans the
    content with each, so the number is bounded."""
    max_deny_pattern_chars: int = Field(default=500, ge=1)
    """M3-01 (PF-11): the longest a deny pattern's regex may be, in characters."""
    standard_retention: RetentionProfile = Field(default=STANDARD_RETENTION)
