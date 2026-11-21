"""Reads a catalog template from JSON text (M2-03).

Like the floor loader, this is pure: it takes text and returns a :class:`Template` or raises
:class:`TemplateFileError`. The file I/O is in ``guardrail_engine/template_file.py``.

A template file is one JSON object: the :class:`Template` fields, plus ``schema_version: 1``.
Beyond what the model checks, a file template must carry what the catalog shows and the apply
step needs: a title, a description, at least one guard point, and at least
``MIN_STARTER_EXAMPLES`` starter examples with both labels.
"""

from __future__ import annotations

from typing import Any

from pydantic import ValidationError

from guardrail_engine.policy.catalog import MIN_STARTER_EXAMPLES, Template
from guardrail_engine.policy.json_document import scan_json_text
from guardrail_engine.policy.lint import is_blank

TEMPLATE_SCHEMA_VERSION = 1


class TemplateFileError(ValueError):
    """A template file that is rejected, with every reason."""

    def __init__(self, problems: list[str]) -> None:
        self.problems = problems
        super().__init__("; ".join(problems))


def parse_template_json(text: str | bytes) -> Template:
    data, problems = scan_json_text(text)
    if problems:
        raise TemplateFileError([f"{p.kind}: {p.detail}" for p in problems])
    return load_template(data)


def load_template(data: Any) -> Template:
    if not isinstance(data, dict):
        raise TemplateFileError(["a template file is one JSON object"])
    if data.get("schema_version") != TEMPLATE_SCHEMA_VERSION:
        raise TemplateFileError([f"schema_version must be {TEMPLATE_SCHEMA_VERSION}"])
    body = {k: v for k, v in data.items() if k != "schema_version"}
    try:
        template = Template.model_validate(body)
    except ValidationError as e:
        raise TemplateFileError(
            [f"{'.'.join(str(p) for p in err['loc']) or '$'}: {err['msg']}" for err in e.errors()]
        ) from None
    problems = []
    if is_blank(template.title) or is_blank(template.description):
        problems.append("a catalog template needs a title and a description")
    if not template.guard_points:
        problems.append("a catalog template needs at least one guard point")
    examples = template.starter_examples
    if len(examples) < MIN_STARTER_EXAMPLES:
        problems.append(
            f"a catalog template needs at least {MIN_STARTER_EXAMPLES} starter examples"
        )
    if {e.label for e in examples} != {"allow", "block"}:
        problems.append("the starter examples need both labels, allow and block")
    if len({(e.guard_point, e.content) for e in examples}) != len(examples):
        problems.append("a starter example is repeated")
    if problems:
        raise TemplateFileError(problems)
    return template
