"""Reads a domain pack file from disk (M4-08).

The file is a pack **source document** (``packs/<name>/pack.json``): exactly what
:meth:`~guardrail_engine.policy.catalog.PackVersion.from_document` takes, so its canonical JSON
is what every bundle that extends the pack hashes over. Like the floor's reader this is the only
file I/O for packs, outside :mod:`guardrail_engine.policy` (which imports no filesystem module),
and it is as strict: a repeated member name, ``NaN`` and text nested too deeply are refused
(:func:`~guardrail_engine.policy.json_document.scan_json_text`), and the content must pass the
catalog's own validation (closed questions, thresholds, guard points, severity and mode).

The pack's **retention** is what R3 says for it. The insurance and energy packs set none: R3's
standard profile applies to them (class B default 395 days, tenant-settable from 90 days to 7
years), so the loaded pack's ``retention`` is None.
"""

from __future__ import annotations

import os
from pathlib import Path

from pydantic import ValidationError

from guardrail_engine.policy.catalog import CatalogDocumentError, PackVersion
from guardrail_engine.policy.json_document import scan_json_text


class PackFileError(ValueError):
    """The pack file was rejected; no pack is returned."""


def load_pack_file(path: str | os.PathLike[str]) -> PackVersion:
    """Read ``path`` (for example ``packs/insurance/pack.json``) and return its
    :class:`PackVersion`. Raises :class:`PackFileError` if the content is rejected and ``OSError``
    if the file can't be read."""
    data, problems = scan_json_text(Path(path).read_bytes())
    if problems:
        raise PackFileError(
            "pack file rejected: " + "; ".join(f"{p.kind}: {p.detail}" for p in problems)
        )
    if not isinstance(data, dict):
        raise PackFileError("pack file rejected: the document is not a JSON object")
    try:
        return PackVersion.from_document(data)
    except (CatalogDocumentError, ValidationError, ValueError, TypeError) as e:
        raise PackFileError(f"pack file rejected: {type(e).__name__}: {e}") from None
