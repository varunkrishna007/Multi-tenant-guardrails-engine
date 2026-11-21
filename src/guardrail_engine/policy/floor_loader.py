"""Loader for the platform floor's flat data format (M1-08).

``floor/rules.json`` keeps its flat format (see ``floor/README.md``). The file is the floor's
source document: the loader checks it and builds a :class:`FloorVersion` from it, whose
content hash covers the file as written (M1-09). The catalog's schema version 1 floor reader
maps it into :class:`CatalogRule` values:

* ``schema_version`` (required, an integer) picks the reader; only version 1 exists;
* ``floor_version`` becomes ``version``;
* ``question``, ``true_description`` and ``false_description`` become
  ``NoulQuestion(instructions, criteria=NoulCriteria(...))``;
* ``key``, ``guard_points``, ``severity``, ``block_at``, ``escalate_at``, ``mode`` and
  ``provisional`` map one to one. Nothing is dropped.

Floor coverage is not read from the file. It is :attr:`FloorVersion.covers`, derived from
the rules, and a file that declares it is rejected as carrying an unknown field.

**All or nothing.** A partially loaded floor is a weakened floor, so any error rejects the
whole file. :class:`FloorFileError` lists every error found, each with the rule key and the
field. No rule is ever skipped.

The floor is held to more than a general catalog rule: its keys match
``p__[a-z0-9_]+``, and every rule is ``enforce`` and ``high``.

The checks here use the same constants and helpers as the catalog and the compiler, and the
file is then built as a :class:`FloorVersion`, so the catalog's own reader and validators
 run on it as well. The loader checks first, field by field, only because the
catalog validator stops at its first error and the loader must report them all. A missing
or unsupported ``schema_version`` is reported on its own: without it, the rest of the file
can't be read.

This module is pure: it takes parsed JSON or JSON text. Reading a path lives outside the
policy package, in :mod:`guardrail_engine.floor_file` (AC-P1).
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from pydantic import ValidationError

from guardrail_engine.decision.limits import MAX_KEY_LENGTH, NOUL_MAX, NOUL_MIN
from guardrail_engine.policy.catalog import (
    FLOOR_KEY_PATTERN,
    FLOOR_MODE,
    FLOOR_SEVERITY,
    SUPPORTED_FLOOR_SCHEMA_VERSIONS,
    FloorVersion,
)
from guardrail_engine.policy.errors import CatalogDocumentError
from guardrail_engine.policy.json_document import (
    TOO_DEEP_MESSAGE,
    JsonTextProblem,
    json_path,
    scan_json_text,
)
from guardrail_engine.policy.lint import CLOSED_QUESTION_RULE, is_blank, is_closed_question
from guardrail_engine.policy.schema import GUARD_POINTS

FLOOR_KEY_PREFIX = "p__"

TOP_LEVEL_FIELDS = ("schema_version", "floor_version", "rules")
RULE_FIELDS = (
    "key",
    "question",
    "true_description",
    "false_description",
    "guard_points",
    "severity",
    "block_at",
    "escalate_at",
    "mode",
    "provisional",
)
"""Every field of a rule. All are required (``floor/README.md``), and no other is allowed."""


@dataclass(frozen=True)
class FloorError:
    """One problem in a floor file."""

    path: str
    """JSON path of the problem, for example ``$.rules[2].block_at``."""
    key: str | None
    """The rule's ``key``, when the problem is inside a rule and its key is a string."""
    field: str | None
    """The field at fault. None when the problem is the rule or the file as a whole."""
    message: str

    def __str__(self) -> str:
        where = f" (rule {self.key})" if self.key is not None else ""
        return f"{self.path}{where}: {self.message}"


class FloorFileError(ValueError):
    """The floor file was rejected. ``errors`` holds every problem found, not only the first."""

    def __init__(self, errors: list[FloorError]) -> None:
        self.errors = tuple(errors)
        super().__init__(
            f"floor file rejected with {len(errors)} error(s): " + "; ".join(map(str, errors))
        )


def load_floor(data: Mapping[str, Any]) -> FloorVersion:
    """Map a parsed floor file to a :class:`FloorVersion`.

    Raises :class:`FloorFileError` listing every error if anything at all is wrong.
    """
    errors: list[FloorError] = []
    if not isinstance(data, Mapping):
        raise FloorFileError([FloorError("$", None, None, "the floor file must be a JSON object")])

    # The schema version says how to read everything else, so nothing else is checked
    # without a supported one (as for bundles, AC-C2.2).
    if "schema_version" not in data:
        raise FloorFileError([_missing("$", None, "schema_version")])
    schema_version = data["schema_version"]
    if not _is_int(schema_version) or schema_version not in SUPPORTED_FLOOR_SCHEMA_VERSIONS:
        raise FloorFileError(
            [
                FloorError(
                    "$.schema_version",
                    None,
                    "schema_version",
                    f"schema_version {schema_version!r} is not supported; supported: "
                    f"{list(SUPPORTED_FLOOR_SCHEMA_VERSIONS)}",
                )
            ]
        )

    for name in data:
        if name not in TOP_LEVEL_FIELDS:
            errors.append(FloorError(f"$.{name}", None, str(name), "unknown top-level field"))

    version = data.get("floor_version")
    if "floor_version" not in data:
        errors.append(_missing("$", None, "floor_version"))
    elif not _is_int(version):
        errors.append(
            FloorError("$.floor_version", None, "floor_version", "must be a JSON integer")
        )
    elif version < 1:
        errors.append(FloorError("$.floor_version", None, "floor_version", "must be 1 or more"))

    raw_rules = data.get("rules")
    if "rules" not in data:
        errors.append(_missing("$", None, "rules"))
    elif not isinstance(raw_rules, list):
        errors.append(FloorError("$.rules", None, "rules", "must be a JSON array"))
    elif not raw_rules:
        errors.append(FloorError("$.rules", None, "rules", "a floor needs at least one rule"))
    else:
        first_index: dict[str, int] = {}
        for i, raw in enumerate(raw_rules):
            _check_rule(raw, f"$.rules[{i}]", errors)
            key = raw.get("key") if isinstance(raw, Mapping) else None
            if isinstance(key, str):
                if key in first_index:
                    errors.append(
                        FloorError(
                            f"$.rules[{i}].key",
                            key,
                            "key",
                            f"duplicate key; already defined by $.rules[{first_index[key]}]",
                        )
                    )
                else:
                    first_index[key] = i

    if errors:
        raise FloorFileError(errors)
    try:
        return FloorVersion.from_document(data)
    except ValidationError as e:
        # The catalog found something the checks above did not. Never load the floor anyway.
        raise FloorFileError(_catalog_errors(e, raw_rules)) from None
    except CatalogDocumentError as e:
        raise FloorFileError(
            [FloorError(x.path, None, None, x.message) for x in e.errors]
        ) from None


def parse_floor_json(text: str | bytes) -> FloorVersion:
    """Parse floor JSON text and load it with :func:`load_floor`.

    Stricter than ``json.loads``, through the shared strict parser
    (:func:`~guardrail_engine.policy.json_document.scan_json_text`, the one bundles use):
    an object that repeats a member name is rejected (a plain parse keeps the last value
    silently, which could hide a second ``block_at``), and so are the non-standard numbers
    ``NaN`` and ``Infinity``. Text nested too deeply to parse is rejected too, as a
    :class:`FloorFileError` rather than a ``RecursionError``. Only the mapping of those
    problems to :class:`FloorError` is the floor's own.
    """
    data, problems = scan_json_text(text)
    if problems:
        raise FloorFileError([_text_error(p, data) for p in problems])
    return load_floor(data)


def _text_error(problem: JsonTextProblem, data: Any) -> FloorError:
    """A text problem as a floor error: at its JSON path, naming the rule key when it is
    inside a rule, and the field (the repeated member, or the member holding ``NaN``)."""
    match problem.kind:
        case "not_json":
            return FloorError("$", None, None, f"not valid JSON: {problem.detail}")
        case "too_deep":
            return FloorError("$", None, None, TOO_DEEP_MESSAGE)
    loc = problem.loc
    key = None
    if len(loc) >= 2 and loc[0] == "rules" and isinstance(loc[1], int):
        rule = data["rules"][loc[1]]
        key = (
            rule.get("key")
            if isinstance(rule, Mapping) and isinstance(rule.get("key"), str)
            else None
        )
    if problem.kind == "duplicate_member":
        name = problem.detail
        return FloorError(json_path(loc), key, name, f"member {name!r} appears twice in one object")
    field = loc[-1] if loc and isinstance(loc[-1], str) else None
    return FloorError(json_path(loc), key, field, f"{problem.detail} is not a valid JSON number")


# --------------------------------------------------------------------------- one rule


def _check_rule(raw: Any, path: str, errors: list[FloorError]) -> None:
    """Check one rule, appending every problem to ``errors``."""
    if not isinstance(raw, Mapping):
        errors.append(FloorError(path, None, None, "a rule must be a JSON object"))
        return

    key = raw.get("key") if isinstance(raw.get("key"), str) else None

    def bad(field: str, message: str) -> None:
        errors.append(FloorError(f"{path}.{field}", key, field, message))

    for name in raw:
        if name not in RULE_FIELDS:
            bad(str(name), "unknown field")
    for name in RULE_FIELDS:
        if name not in raw:
            errors.append(_missing(path, key, name))

    if "key" in raw:
        _check_key(raw["key"], bad)
    if "question" in raw:
        question = raw["question"]
        if not _is_text(question):
            bad("question", "must be a non-empty string")
        elif not is_closed_question(question):
            bad("question", f"must be a closed yes/no question: {CLOSED_QUESTION_RULE}")
    for name in ("true_description", "false_description"):
        if name in raw and not _is_text(raw[name]):
            bad(name, "must be a non-empty string")
    if "guard_points" in raw:
        _check_guard_points(raw["guard_points"], bad)
    # The floor is all "enforce" and "high": a shadowed floor rule never acts.
    for name, required in (("severity", FLOOR_SEVERITY), ("mode", FLOOR_MODE)):
        if name in raw and not (isinstance(raw[name], str) and raw[name] == required):
            bad(name, f"a floor rule's {name} must be {required!r}")
    _check_thresholds(raw, bad)
    if "provisional" in raw and not isinstance(raw["provisional"], bool):
        bad("provisional", "must be true or false")


def _check_key(value: Any, bad: Any) -> None:
    if not isinstance(value, str):
        bad("key", "must be a string")
        return
    if not value.startswith(FLOOR_KEY_PREFIX):
        bad("key", f"a floor rule key must start with {FLOOR_KEY_PREFIX!r}")
    elif len(value) > MAX_KEY_LENGTH:
        bad("key", f"a floor rule key is at most {MAX_KEY_LENGTH} characters, got {len(value)}")
    elif not FLOOR_KEY_PATTERN.fullmatch(value):
        bad("key", "a floor rule key must match p__[a-z0-9_]+")


def _check_guard_points(value: Any, bad: Any) -> None:
    if not isinstance(value, list):
        bad("guard_points", "must be a JSON array of guard point names")
        return
    if not value:
        bad("guard_points", "needs at least one guard point")
    seen: set[str] = set()
    for item in value:
        if not isinstance(item, str) or item not in GUARD_POINTS:
            bad("guard_points", f"unknown guard point {item!r}; expected one of {GUARD_POINTS}")
        elif item in seen:
            bad("guard_points", f"guard point {item!r} is listed twice")
        else:
            seen.add(item)


def _check_thresholds(raw: Mapping[str, Any], bad: Any) -> None:
    numbers: dict[str, float] = {}
    for name in ("block_at", "escalate_at"):
        if name not in raw:
            continue
        value = raw[name]
        if isinstance(value, bool) or not isinstance(value, int | float):
            bad(name, "must be a JSON number")
        elif not NOUL_MIN <= value <= NOUL_MAX:
            bad(name, f"must be between {NOUL_MIN} and {NOUL_MAX}, got {value}")
        else:
            numbers[name] = value
    if len(numbers) == 2 and not numbers["escalate_at"] < numbers["block_at"]:
        bad(
            "escalate_at",
            f"escalate_at must be below block_at, got escalate_at={numbers['escalate_at']}, "
            f"block_at={numbers['block_at']}",
        )


# --------------------------------------------------------------------------- helpers


def _missing(path: str, key: str | None, field: str) -> FloorError:
    return FloorError(f"{path}.{field}", key, field, "missing required field")


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_text(value: Any) -> bool:
    return isinstance(value, str) and not is_blank(value)


def _catalog_errors(e: ValidationError, raw_rules: list[Any]) -> list[FloorError]:
    """The catalog's validation errors, each at its rule (with the rule's key) when it has
    one, else at the file."""
    found = []
    for item in e.errors():
        loc, message = item["loc"], "catalog validation failed: " + item["msg"]
        if len(loc) >= 2 and loc[0] == "rules" and isinstance(loc[1], int):
            raw = raw_rules[loc[1]]
            key = raw.get("key") if isinstance(raw.get("key"), str) else None
            found.append(FloorError(f"$.rules[{loc[1]}]", key, None, message))
        else:
            found.append(FloorError("$", None, None, message))
    return found
