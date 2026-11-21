"""The submitted bundle document: reading it and hashing it (AC-C2.2).

A bundle exists in two forms, and they are kept together in a :class:`ParsedBundle`:

* the **document**: the JSON object exactly as it was submitted, with nothing filled in.
  This is what is hashed and what a policy store persists.
* the **model** (:class:`~guardrail_engine.policy.schema.Bundle`): the document read under
  its ``schema_version``, with that version's defaults filled in. This is what the compiler
  works on. It is never hashed and never stored.

``bundle_hash`` is therefore a function of the document, not of the model. Canonical JSON
makes key order and whitespace irrelevant, but leaving an optional field out and writing its
default explicitly are different documents with different hashes. That is intended.

**Schema versions.** Every document carries a required integer ``schema_version``. The
defaults filled in when a document is read are a function of that number and are fixed for
good: ``_READERS`` maps each supported version to the function that turns a document of that
version into the current ``Bundle`` model. Changing a default or adding a field never edits
an existing reader's behaviour. To add schema version 2:

1. Change the ``Bundle`` model as needed.
2. Add ``_read_v2`` and register it in ``_READERS``.
3. Make ``_read_v1`` state explicitly the value version 1 documents get for anything that
   changed (for a new field, the value that keeps a v1 document meaning what it meant),
   instead of inheriting the model's new default.
4. Add version 2 to the defaults snapshot in ``tests/policy/test_bundle_document.py``. The
   version 1 snapshot must still pass unchanged; if it doesn't, step 3 is incomplete.

A stored document then keeps both its hash (the bytes didn't change) and its meaning (its
reader didn't change). Moving a tenant to a new schema version means publishing a new bundle
version, never rewriting an old one.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

from pydantic import ValidationError

from guardrail_engine.policy.canonical import sha256_of
from guardrail_engine.policy.errors import ErrorCode, PolicyError, PolicyInvalidError
from guardrail_engine.policy.json_document import (
    canonicalize,
    error,
    json_path,
    load_canonical,
    parse_json_text,
    select_reader,
)
from guardrail_engine.policy.schema import Bundle


def _read_v1(document: Mapping[str, Any]) -> Bundle:
    """Schema version 1: the ``Bundle`` model as it stands, with its own defaults."""
    return Bundle.model_validate(document)


_READERS: dict[int, Callable[[Mapping[str, Any]], Bundle]] = {1: _read_v1}

SUPPORTED_SCHEMA_VERSIONS: tuple[int, ...] = tuple(sorted(_READERS))
CURRENT_SCHEMA_VERSION: int = SUPPORTED_SCHEMA_VERSIONS[-1]
"""The version new documents should be written in."""

EXTENDS_REF_PATTERN: re.Pattern[str] = re.compile(
    r"(?:platform/(floor)|domain/([a-z0-9_]+))@([1-9][0-9]*)"
)
"""The grammar of one ``extends`` entry: ``platform/floor@<n>`` or ``domain/<pack>@<n>``.
Use with ``fullmatch``. Groups: 1 is ``"floor"`` for the floor (else None), 2 is the pack
name for a pack (else None), 3 is the version number. The compiler and the policy store
both read ``extends`` with this one object, so they can't disagree about which references
are valid."""


def bundle_hash(document: Mapping[str, Any], *, extends: Mapping[str, str]) -> str:
    """``sha256:<hex>`` over the canonical JSON of the bundle **document as submitted**
    together with the content hash of every catalog version it extends (AC-C2.2)::

        sha256(canonical({"bundle": <document>, "extends": {"platform/floor@7": <hash>, ...}}))

    So a changed catalog version can't hide behind an unchanged bundle, and a change to the
    schema's defaults can't change the hash of a document that didn't change.

    ``document`` must be the parsed JSON object. A ``Bundle`` model is refused: hashing a
    re-serialised model would bake the current defaults into the hash.
    """
    if not isinstance(document, Mapping):
        raise TypeError(
            "bundle_hash takes the submitted bundle document (a JSON object), not "
            f"{type(document).__name__}; use ParsedBundle.bundle_hash() or parse_bundle()"
        )
    return sha256_of({"bundle": document, "extends": dict(extends)})


@dataclass(frozen=True, slots=True)
class ParsedBundle:
    """A submitted document and the model read from it. Build one with :func:`parse_bundle`.

    The document is held as its canonical JSON bytes, so nothing the caller does to the
    object it submitted can change what is hashed or stored.

    The model can't be supplied: it is always read from ``canonical_document`` when the
    ``ParsedBundle`` is constructed. So a ``ParsedBundle`` can't pair one
    document's hash with a model read from another document. Constructing one directly
    from bytes that aren't the canonical JSON of a readable bundle raises: ``TypeError``
    for anything but ``bytes``, ``ValueError`` for bytes that aren't canonical JSON, and
    :class:`PolicyInvalidError` for a canonical document that isn't a valid bundle.
    """

    canonical_document: bytes
    """Canonical JSON of the document as submitted. This is what a store persists."""
    _bundle: Bundle = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        snapshot = load_canonical(
            self.canonical_document,
            invalid=PolicyInvalidError,
            hint="use parse_bundle() to read a submitted document",
        )
        bundle, errors = _read_snapshot(snapshot)
        if bundle is None:
            raise PolicyInvalidError(errors)
        object.__setattr__(self, "_bundle", bundle)

    @property
    def bundle(self) -> Bundle:
        """A fresh copy of the model read from the document under its ``schema_version``.
        For the compiler, not for hashing.

        A copy each time, like :attr:`document`: the models are frozen but their lists are
        not, and changing a list in the model must not change what a later caller compiles.
        """
        return self._bundle.model_copy(deep=True)

    @property
    def document(self) -> dict[str, Any]:
        """A fresh copy of the submitted document."""
        return json.loads(self.canonical_document)

    def bundle_hash(self, *, extends: Mapping[str, str]) -> str:
        return bundle_hash(self.document, extends=extends)


def read_bundle(
    document: Mapping[str, Any] | str | bytes,
) -> tuple[ParsedBundle | None, list[PolicyError]]:
    """Phase 1 of validation (AC-C0): the document's shape. Returns the parsed bundle, or
    None and every shape error. ``document`` is a JSON object, or JSON text of one.

    JSON text is read strictly: an object that repeats a member name is
    rejected with ``SCHEMA_DUPLICATE_MEMBER`` at the object's path, and ``NaN``,
    ``Infinity`` and ``-Infinity`` with ``SCHEMA_INVALID`` at the value's path. A document
    (text or object) nested too deeply to read is ``SCHEMA_INVALID`` at ``$``: hostile
    input gets a validation error, never an exception.
    """
    if isinstance(document, str | bytes | bytearray):
        document, text_errors = parse_json_text(document)
        if text_errors:
            return None, text_errors
    canonical, errors = canonicalize(document, what="bundle")
    if canonical is None:
        return None, errors
    # ParsedBundle reads the model from the canonical bytes, so the model and the hash come
    # from the same content.
    try:
        return ParsedBundle(canonical), []
    except PolicyInvalidError as e:
        return None, e.errors


def parse_bundle(document: Mapping[str, Any] | str | bytes) -> ParsedBundle:
    """Read a submitted document. Raises :class:`PolicyInvalidError` with every shape error."""
    parsed, errors = read_bundle(document)
    if parsed is None:
        raise PolicyInvalidError(errors)
    return parsed


def _read_snapshot(snapshot: Any) -> tuple[Bundle | None, list[PolicyError]]:
    """Read a parsed JSON value under its ``schema_version``. Returns the model, or None and
    every shape error."""
    reader, errors = select_reader(
        snapshot,
        _READERS,
        what="bundle",
        missing=ErrorCode.SCHEMA_VERSION_MISSING,
        unsupported=ErrorCode.SCHEMA_VERSION_UNSUPPORTED,
    )
    if reader is None:
        return None, errors
    try:
        return reader(snapshot), []
    except ValidationError as e:
        return None, [
            error(ErrorCode.SCHEMA_INVALID, json_path(item["loc"]), item["msg"])
            for item in e.errors()
        ]
