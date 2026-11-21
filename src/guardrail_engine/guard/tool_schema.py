"""Tool-argument schema validation (M3-03, design §Latency strategy: "`tool_call`: schema
validation first").

A tool in the tenant's registry may carry a **JSON Schema for its arguments**
(:attr:`~guardrail_engine.guard.tenants.ToolInfo.arguments_schema`). At ``tool_call`` the
content follows the **SDK's contract**::

    {"tool": "<name>", "arguments": {...}}

``args`` is accepted as a deprecated alias for ``arguments`` (not both). The schema validates
the ``arguments`` member only, never the wrapper; the mismatch check
(:func:`~guardrail_engine.guard.deterministic.check_tool_mismatch`) reads ``tool``. Content
that isn't such an object, or that has no ``arguments``, fails a tool that has a schema (a
call with no arguments says ``"arguments": {}``). Before anything else is judged, the
arguments are validated against the schema. A failure is a deterministic ``block``, rule
``tool_schema``, with **no model call** (AC-G1). Only the registry sets a schema: nothing in
the request can supply, loosen or remove it.

**A deliberate subset of JSON Schema**, evaluated by this module and nothing else (the
engine takes no schema library): a schema that uses any other keyword is **refused when the
tool is registered** (:func:`schema_problem`), never ignored, so a schema can't look stricter
than it is. Supported:

* ``type`` (one name or a list of them: ``object``, ``array``, ``string``, ``integer``,
  ``number``, ``boolean``, ``null``; a ``bool`` is never a number, and ``2.0`` is an integer),
  ``enum``, ``const``;
* objects: ``properties``, ``required``, ``additionalProperties`` (``true``, ``false`` or a
  schema);
* arrays: ``items`` (one schema), ``minItems``, ``maxItems``;
* strings: ``minLength``, ``maxLength`` (code points);
* numbers: ``minimum``, ``maximum``, ``exclusiveMinimum``, ``exclusiveMaximum``;
* ``anyOf``, ``oneOf``, ``allOf`` (non-empty lists of schemas);
* annotations that change nothing: ``title``, ``description``, ``default``, ``examples``,
  ``$schema``, ``$comment``.

Left out on purpose: ``$ref`` (no recursion, so validation is bounded by the schema's depth,
itself capped at :data:`MAX_SCHEMA_DEPTH`), ``pattern`` (a tenant-written regex on the
request path; RE2 deny patterns are the engine's regex surface), ``format`` and the rest.

**What is validated is what the tool receives.** The content is parsed strictly: a duplicate
object key, ``NaN`` or an infinity is a failure (a parser that picks the last duplicate would
let a validator and a tool disagree), and content that isn't JSON at all fails a tool that
has a schema.

A failure reports **nothing about the content**: the verdict carries the rule id only.
"""

from __future__ import annotations

import json
import math
from collections.abc import Mapping, Sequence
from types import MappingProxyType
from typing import Any

MAX_SCHEMA_DEPTH = 16
"""Deepest nesting of schemas a registry entry may have."""
MAX_SCHEMA_NODES = 2000
"""Most schema nodes (objects and arrays) in one registered schema."""

_TYPES = frozenset({"object", "array", "string", "integer", "number", "boolean", "null"})
_ANNOTATIONS = frozenset({"title", "description", "default", "examples", "$schema", "$comment"})
_SCHEMA_LISTS = ("anyOf", "oneOf", "allOf")
_KEYWORDS = _ANNOTATIONS | {
    "type", "enum", "const",
    "properties", "required", "additionalProperties",
    "items", "minItems", "maxItems",
    "minLength", "maxLength",
    "minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum",
    *_SCHEMA_LISTS,
}  # fmt: skip


# --------------------------------------------------------------------------- registration


def schema_problem(schema: object) -> str | None:
    """Why ``schema`` can't be a tool's argument schema, or None if it can. Checked when a
    registry entry is built. Refuses an unsupported keyword, a malformed supported one, and
    a schema deeper than :data:`MAX_SCHEMA_DEPTH` or larger than :data:`MAX_SCHEMA_NODES`."""
    nodes = [0]
    return _problem(schema, "$", 1, nodes)


def _problem(schema: object, path: str, depth: int, nodes: list[int]) -> str | None:
    if isinstance(schema, bool):
        return None
    if not isinstance(schema, Mapping):
        return f"{path}: a schema must be an object or a boolean"
    if depth > MAX_SCHEMA_DEPTH:
        return f"{path}: schema nesting is deeper than {MAX_SCHEMA_DEPTH}"
    nodes[0] += 1
    if nodes[0] > MAX_SCHEMA_NODES:
        return f"schema has more than {MAX_SCHEMA_NODES} nodes"
    for key in schema:
        if not isinstance(key, str) or key not in _KEYWORDS:
            return f"{path}: unsupported schema keyword {_short(key)}"
    if (found := _type_problem(schema, path)) is not None:
        return found
    if "enum" in schema:
        options = schema["enum"]
        if isinstance(options, str | Mapping) or not isinstance(options, Sequence) or not options:
            return f"{path}.enum: must be a non-empty list"
    if "required" in schema:
        required = schema["required"]
        if (
            isinstance(required, str)
            or not isinstance(required, Sequence)
            or not all(isinstance(r, str) for r in required)
        ):
            return f"{path}.required: must be a list of property names"
    for name in ("minItems", "maxItems", "minLength", "maxLength"):
        if name in schema and not _is_count(schema[name]):
            return f"{path}.{name}: must be a non-negative integer"
    for name in ("minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum"):
        if name in schema and not _is_number(schema[name]):
            return f"{path}.{name}: must be a finite number"
    if "properties" in schema:
        props = schema["properties"]
        if not isinstance(props, Mapping) or not all(isinstance(k, str) for k in props):
            return f"{path}.properties: must be an object"
        for name, sub in props.items():
            if (found := _problem(sub, f"{path}.properties.{name}", depth + 1, nodes)) is not None:
                return found
    if "additionalProperties" in schema:
        found = _problem(
            schema["additionalProperties"], f"{path}.additionalProperties", depth + 1, nodes
        )
        if found is not None:
            return found
    if "items" in schema:
        found = _problem(schema["items"], f"{path}.items", depth + 1, nodes)
        if found is not None:
            return found
    for name in _SCHEMA_LISTS:
        if name not in schema:
            continue
        subs = schema[name]
        if isinstance(subs, str | Mapping) or not isinstance(subs, Sequence) or not subs:
            return f"{path}.{name}: must be a non-empty list of schemas"
        for i, sub in enumerate(subs):
            if (found := _problem(sub, f"{path}.{name}[{i}]", depth + 1, nodes)) is not None:
                return found
    return None


def _type_problem(schema: Mapping[str, Any], path: str) -> str | None:
    if "type" not in schema:
        return None
    declared = schema["type"]
    names = [declared] if isinstance(declared, str) else declared
    if (
        isinstance(declared, Mapping)
        or not isinstance(names, Sequence)
        or not names
        or not all(isinstance(n, str) and n in _TYPES for n in names)
    ):
        return f"{path}.type: must be one of {sorted(_TYPES)} or a list of them"
    return None


def _is_count(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _is_number(value: object) -> bool:
    return isinstance(value, int | float) and not isinstance(value, bool) and math.isfinite(value)


def _short(value: object, limit: int = 40) -> str:
    text = repr(value)
    return text if len(text) <= limit else text[:limit] + "..."


def freeze_schema(schema: Any) -> Any:
    """A deep, read-only copy: objects become mappings that can't be assigned to, lists
    become tuples. Call it on a schema that passed :func:`schema_problem`."""
    if isinstance(schema, Mapping):
        return MappingProxyType({k: freeze_schema(v) for k, v in schema.items()})
    if isinstance(schema, list | tuple):
        return tuple(freeze_schema(v) for v in schema)
    return schema


# --------------------------------------------------------------------------- validation


class _NotStrict(ValueError):
    pass


def _reject_constant(name: str) -> Any:
    raise _NotStrict(name)


def _strict_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise _NotStrict("duplicate key")
        out[key] = value
    return out


def parse_arguments(content: str) -> tuple[bool, Any]:
    """``(True, value)`` for strictly valid JSON (no duplicate keys, ``NaN`` or infinities;
    deep nesting included), else ``(False, None)``."""
    try:
        return True, json.loads(
            content, object_pairs_hook=_strict_pairs, parse_constant=_reject_constant
        )
    except (ValueError, RecursionError):
        return False, None


def arguments_valid(schema: Any, content: str) -> bool:
    """Whether ``content`` is JSON that satisfies ``schema``. Never raises: a schema the
    validator doesn't understand (one that bypassed :func:`schema_problem`) and content that
    isn't strict JSON both fail."""
    ok, value = parse_arguments(content)
    return ok and _satisfies(schema, value)


ARGUMENT_KEYS = ("arguments", "args")
"""The members of a ``tool_call`` content that hold the arguments: ``arguments``, and ``args``
as a deprecated alias. Exactly one may be present."""


def call_arguments(content: str) -> tuple[bool, Any]:
    """``(True, arguments)`` when ``content`` is a ``tool_call`` content in the SDK's shape:
    strict JSON, an object with exactly one of ``arguments`` and ``args``. Else ``(False,
    None)``."""
    ok, value = parse_arguments(content)
    if not ok or not isinstance(value, dict):
        return False, None
    present = [k for k in ARGUMENT_KEYS if k in value]
    if len(present) != 1:
        return False, None
    return True, value[present[0]]


def call_valid(schema: Any, content: str) -> bool:
    """Whether the **arguments** of a ``tool_call`` content satisfy ``schema``
    (:func:`call_arguments` gives the contract). Never raises."""
    ok, arguments = call_arguments(content)
    return ok and _satisfies(schema, arguments)


def _satisfies(schema: Any, value: Any) -> bool:
    try:
        return _valid(schema, value, 1)
    except (KeyError, TypeError, ValueError, RecursionError, OverflowError):
        return False  # a malformed schema is never a pass


def _valid(schema: Any, value: Any, depth: int) -> bool:
    if schema is True:
        return True
    if schema is False:
        return False
    if depth > MAX_SCHEMA_DEPTH + 1:
        return False
    if not isinstance(schema, Mapping):
        raise TypeError("schema")
    if any(k not in _KEYWORDS for k in schema):
        raise ValueError("unsupported keyword")  # never ignored
    if "type" in schema and not _type_ok(schema["type"], value):
        return False
    if "enum" in schema and not any(_same(value, option) for option in schema["enum"]):
        return False
    if "const" in schema and not _same(value, schema["const"]):
        return False
    if _is_number_value(value):
        if "minimum" in schema and not value >= schema["minimum"]:
            return False
        if "maximum" in schema and not value <= schema["maximum"]:
            return False
        if "exclusiveMinimum" in schema and not value > schema["exclusiveMinimum"]:
            return False
        if "exclusiveMaximum" in schema and not value < schema["exclusiveMaximum"]:
            return False
    if isinstance(value, str):
        if "minLength" in schema and len(value) < schema["minLength"]:
            return False
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            return False
    if isinstance(value, list):
        if "minItems" in schema and len(value) < schema["minItems"]:
            return False
        if "maxItems" in schema and len(value) > schema["maxItems"]:
            return False
        if "items" in schema and not all(_valid(schema["items"], v, depth + 1) for v in value):
            return False
    if isinstance(value, dict) and not _object_ok(schema, value, depth):
        return False
    if "allOf" in schema and not all(_valid(s, value, depth + 1) for s in schema["allOf"]):
        return False
    if "anyOf" in schema and not any(_valid(s, value, depth + 1) for s in schema["anyOf"]):
        return False
    return "oneOf" not in schema or sum(_valid(s, value, depth + 1) for s in schema["oneOf"]) == 1


def _object_ok(schema: Mapping[str, Any], value: dict[str, Any], depth: int) -> bool:
    if any(name not in value for name in schema.get("required", ())):
        return False
    properties = schema.get("properties", {})
    for name, member in value.items():
        if name in properties:
            if not _valid(properties[name], member, depth + 1):
                return False
        elif "additionalProperties" in schema and not _valid(
            schema["additionalProperties"], member, depth + 1
        ):
            return False
    return True


def _is_number_value(value: Any) -> bool:
    return isinstance(value, int | float) and not isinstance(value, bool)


def _type_ok(declared: Any, value: Any) -> bool:
    names = [declared] if isinstance(declared, str) else declared
    return any(_is_type(name, value) for name in names)


def _is_type(name: str, value: Any) -> bool:
    if name == "object":
        return isinstance(value, dict)
    if name == "array":
        return isinstance(value, list)
    if name == "string":
        return isinstance(value, str)
    if name == "boolean":
        return isinstance(value, bool)
    if name == "null":
        return value is None
    if name == "number":
        return _is_number_value(value)
    if name == "integer":
        return _is_number_value(value) and (
            isinstance(value, int) or (math.isfinite(value) and value.is_integer())
        )
    raise ValueError("unknown type")


def _same(a: Any, b: Any) -> bool:
    """JSON equality: ``true`` is not ``1``, ``1`` equals ``1.0``, deep for containers."""
    if isinstance(a, bool) or isinstance(b, bool):
        return isinstance(a, bool) and isinstance(b, bool) and a == b
    if _is_number_value(a) and _is_number_value(b):
        return a == b
    if isinstance(a, dict) and isinstance(b, Mapping):
        return a.keys() == b.keys() and all(_same(a[k], b[k]) for k in a)
    if isinstance(a, list) and isinstance(b, Sequence) and not isinstance(b, str):
        return len(a) == len(b) and all(_same(x, y) for x, y in zip(a, b, strict=True))
    return type(a) is type(b) and a == b
