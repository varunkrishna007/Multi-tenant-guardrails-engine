"""Canonical JSON and content hashing, shared by the catalog and the compiler (AC-C2.2)."""

from __future__ import annotations

import hashlib
import json
from typing import Any


def canonical_json(value: Any) -> bytes:
    """Sorted keys, no whitespace, UTF-8. Key order and formatting never change the bytes."""
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def sha256_of(value: Any) -> str:
    """``sha256:<hex>`` over the canonical JSON of ``value``."""
    return "sha256:" + hashlib.sha256(canonical_json(value)).hexdigest()
