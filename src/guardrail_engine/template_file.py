"""Reads a catalog template file from disk (M2-03). The only file I/O for templates; the
parsing is in :mod:`guardrail_engine.policy.template_loader` (the policy package is pure)."""

from __future__ import annotations

import os
from pathlib import Path

from guardrail_engine.policy.catalog import Template
from guardrail_engine.policy.template_loader import parse_template_json


def load_template_file(path: str | os.PathLike[str]) -> Template:
    """Raises ``OSError`` if the file can't be read and ``TemplateFileError`` if it is rejected."""
    return parse_template_json(Path(path).read_bytes())
