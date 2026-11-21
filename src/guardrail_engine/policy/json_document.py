"""Reading submitted JSON documents and holding them as canonical bytes (AC-C2.2, M1-09).

Shared by the two kinds of hashed document, so they are read and held the same way:

* the tenant's bundle document (:mod:`guardrail_engine.policy.document`);
* the catalog's floor and pack source documents (:mod:`guardrail_engine.policy.catalog`).

Each is hashed over the canonical JSON of the document as submitted, never over a model
read from it, and each carries a required integer ``schema_version`` that picks the reader
(and so the defaults) for it. The helpers here are the parts that don't depend on what the
document describes: strict JSON text parsing, canonicalising a parsed document, checking
canonical bytes, and choosing a reader by ``schema_version``. Problems are reported as
:class:`PolicyError` values with a JSON path.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Literal, TypeVar

from guardrail_engine.policy.canonical import canonical_json
from guardrail_engine.policy.errors import ErrorCode, PolicyError

R = TypeVar("R")


def error(code: ErrorCode, path: str, message: str) -> PolicyError:
    return PolicyError(code=code, path=path, message=message)


TOO_DEEP_MESSAGE = "the document is nested too deeply to read"


def too_deep() -> PolicyError:
    """Nesting beyond what the JSON parser and encoder can recurse through. Documents can
    come from tenants, so this is a validation error, never a ``RecursionError``."""
    return error(ErrorCode.SCHEMA_INVALID, "$", TOO_DEEP_MESSAGE)


def json_path(loc: tuple[int | str, ...]) -> str:
    path = "$"
    for part in loc:
        path += f"[{part}]" if isinstance(part, int) else f".{part}"
    return path


# --------------------------------------------------------------------------- parsed documents


def canonicalize(document: Any, *, what: str) -> tuple[bytes | None, list[PolicyError]]:
    """The canonical JSON bytes of a parsed document, or None and the reason it has none:
    it isn't a JSON object, holds a value JSON can't represent (``NaN``, a set, ...), or is
    nested too deeply. ``what`` names the document in messages (``"bundle"``)."""
    if not isinstance(document, Mapping):
        return None, [error(ErrorCode.SCHEMA_INVALID, "$", f"a {what} must be a JSON object")]
    try:
        return canonical_json(document), []
    except RecursionError:
        return None, [too_deep()]
    except (TypeError, ValueError) as e:  # a non-JSON value, NaN, or an unencodable string
        return None, [error(ErrorCode.SCHEMA_INVALID, "$", f"not a JSON document: {e}")]


def load_canonical(
    raw: bytes, *, invalid: Callable[[list[PolicyError]], Exception], hint: str
) -> Any:
    """Parse bytes that must already be canonical JSON, and return the parsed value.

    Raises ``TypeError`` for anything but ``bytes``, ``ValueError`` for bytes that aren't
    canonical JSON (key order, whitespace, number spelling, a repeated member, or not JSON
    at all), and ``invalid([...])`` for a document nested too deeply to read. ``hint`` tells
    the caller what to use instead.
    """
    if type(raw) is not bytes:
        raise TypeError(f"canonical_document must be bytes, not {type(raw).__name__}; {hint}")
    try:
        snapshot = json.loads(raw)
        canonical = canonical_json(snapshot)
    except RecursionError:
        raise invalid([too_deep()]) from None
    except (TypeError, ValueError) as e:  # not UTF-8, not JSON, or NaN
        raise ValueError(f"canonical_document is not canonical JSON: {e}") from None
    if canonical != raw:
        raise ValueError(
            "canonical_document is not canonical JSON (key order, whitespace, number "
            f"spelling or a repeated member); {hint}"
        )
    return snapshot


def select_reader(
    snapshot: Any,
    readers: Mapping[int, R],
    *,
    what: str,
    missing: ErrorCode,
    unsupported: ErrorCode,
) -> tuple[R | None, list[PolicyError]]:
    """The reader for a parsed document's required ``schema_version``, or None and the one
    error saying why there is none. ``readers`` maps each supported version to its reader."""
    if not isinstance(snapshot, dict):
        return None, [error(ErrorCode.SCHEMA_INVALID, "$", f"a {what} must be a JSON object")]
    supported = sorted(readers)
    if "schema_version" not in snapshot:
        return None, [
            error(
                missing,
                "$.schema_version",
                f"schema_version is required; the current version is {supported[-1]}",
            )
        ]
    schema_version = snapshot["schema_version"]
    # bool is an int in Python; True must not read as version 1.
    reader = readers.get(schema_version) if type(schema_version) is int else None
    if reader is None:
        return None, [
            error(
                unsupported,
                "$.schema_version",
                f"schema_version {schema_version!r} is not supported; supported: {supported}",
            )
        ]
    return reader, []


# --------------------------------------------------------------------------- JSON text


class _Object(dict[str, Any]):
    """A JSON object parsed from text that remembers the member names it repeated."""

    __slots__ = ("repeated",)

    def __init__(self, pairs: list[tuple[str, Any]]) -> None:
        super().__init__()
        self.repeated: list[str] = []
        for name, value in pairs:
            if name in self and name not in self.repeated:
                self.repeated.append(name)
            self[name] = value


@dataclass(frozen=True, slots=True)
class _NonFinite:
    """Stands in for a ``NaN``, ``Infinity`` or ``-Infinity`` literal until it is reported."""

    literal: str


@dataclass(frozen=True, slots=True)
class JsonTextProblem:
    """One reason strict JSON text parsing refuses some text, before any caller-specific
    error mapping. ``kind`` is one of:

    * ``"not_json"``: not JSON at all; ``detail`` is the parser's message;
    * ``"too_deep"``: nested too deeply to parse;
    * ``"duplicate_member"``: ``loc`` is the object, ``detail`` the repeated member name;
    * ``"non_finite"``: ``loc`` is the value, ``detail`` the literal (``NaN``, ``Infinity``,
      ``-Infinity``).
    """

    kind: Literal["not_json", "too_deep", "duplicate_member", "non_finite"]
    loc: tuple[int | str, ...] = ()
    detail: str = ""


def scan_json_text(text: str | bytes | bytearray) -> tuple[Any, list[JsonTextProblem]]:
    """Parse JSON text more strictly than ``json.loads``: an object that repeats a member
    name is a problem (a plain parse keeps the last value silently, so two readers of the
    same text could see different values, or a second ``block_at`` could hide), and so are
    the non-standard numbers ``NaN`` and ``Infinity``. Text nested too deeply to parse is a
    problem, never a ``RecursionError``.

    Returns the parsed value and every problem, in document order. The one strict parser
    for bundle text (:func:`parse_json_text`) and floor file text (``parse_floor_json``),
    which differ only in how they report problems.
    """
    try:
        value = json.loads(text, object_pairs_hook=_Object, parse_constant=_NonFinite)
    except ValueError as e:  # includes JSONDecodeError and UnicodeDecodeError
        return None, [JsonTextProblem("not_json", detail=str(e))]
    except RecursionError:
        return None, [JsonTextProblem("too_deep")]

    problems: list[JsonTextProblem] = []
    # Iterative, in document order, so a deeply nested document can't exhaust the stack.
    stack: list[tuple[tuple[int | str, ...], Any]] = [((), value)]
    while stack:
        loc, item = stack.pop()
        if isinstance(item, _NonFinite):
            problems.append(JsonTextProblem("non_finite", loc, item.literal))
        elif isinstance(item, _Object):
            problems.extend(JsonTextProblem("duplicate_member", loc, n) for n in item.repeated)
            stack.extend(((*loc, k), v) for k, v in reversed(item.items()))
        elif isinstance(item, list):
            stack.extend(((*loc, i), v) for i, v in reversed(list(enumerate(item))))
    return value, problems


def parse_json_text(text: str | bytes | bytearray) -> tuple[Any, list[PolicyError]]:
    """:func:`scan_json_text`, with each problem as a :class:`PolicyError` at its JSON path:
    a repeated member is ``SCHEMA_DUPLICATE_MEMBER`` at the object's path, a ``NaN`` or
    ``Infinity`` is ``SCHEMA_INVALID`` at the value's path, and text that isn't JSON or is
    nested too deeply is one ``SCHEMA_INVALID`` error at ``$``.
    """
    value, problems = scan_json_text(text)
    return value, [_policy_error(p) for p in problems]


def _policy_error(problem: JsonTextProblem) -> PolicyError:
    path = json_path(problem.loc)
    match problem.kind:
        case "not_json":
            return error(ErrorCode.SCHEMA_INVALID, "$", f"not valid JSON: {problem.detail}")
        case "too_deep":
            return too_deep()
        case "duplicate_member":
            return error(
                ErrorCode.SCHEMA_DUPLICATE_MEMBER,
                path,
                f"member {problem.detail!r} appears more than once in this object",
            )
        case "non_finite":
            return error(
                ErrorCode.SCHEMA_INVALID, path, f"{problem.detail} is not a valid JSON number"
            )
