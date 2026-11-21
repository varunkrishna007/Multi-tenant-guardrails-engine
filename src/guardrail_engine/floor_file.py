"""Reads a platform floor file from disk (M1-08).

This is the only file I/O for the floor. It lives outside ``guardrail_engine.policy``
because the policy package is a pure library that imports no filesystem module (AC-P1).
All parsing and validation is in :mod:`guardrail_engine.policy.floor_loader`.
"""

from __future__ import annotations

import os
from pathlib import Path

from guardrail_engine.policy.catalog import FloorVersion
from guardrail_engine.policy.floor_loader import parse_floor_json


def load_floor_file(path: str | os.PathLike[str]) -> FloorVersion:
    """Read ``path`` (for example ``floor/rules.json``) and return its :class:`FloorVersion`.

    Raises :class:`~guardrail_engine.policy.floor_loader.FloorFileError` if the content is
    rejected, and ``OSError`` if the file can't be read. Either way no floor is returned.
    """
    return parse_floor_json(Path(path).read_bytes())
