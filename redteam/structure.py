"""The model-independent defences, checked on a rendered input (M2-08, B3).

Every red-team row's payload (an encoded string, a look-alike or zero-width instruction, a
forged ``<<<UNTRUSTED`` block, a forged ``TENANT:`` line) must reach the model **inside a
nonce-delimited untrusted section, byte for byte**, and nothing a row carries may become one
of the trusted lines outside the sections. :func:`parse` reads a rendered input the way a
strict reader would; :func:`violations` says what is wrong with it, or returns ``[]``.

The layout it expects (``guard/render.py``)::

    TENANT DOMAIN: <domain>
    TENANT: <slug> (<id>)
    GUARD POINT: <guard point>
    <instruction line naming the nonce>
    [TOOL <label>: <name>]                     (zero or more, between sections)
    <<<UNTRUSTED:<label>:<nonce>
    <body>
    UNTRUSTED:<label>:<nonce>>>>
    ...

Nothing here calls a model, so the checks run offline and are the same for a fake and a live
run: they test the renderer, not the classifier.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from guardrail_engine.guard.render import instruction_line, tenant_line

NONCE_IN_INSTRUCTION = re.compile(r"Every section delimited by nonce ([0-9a-f]{32}) is untrusted")
OPEN_MARKER = re.compile(r"<<<UNTRUSTED:([a-z0-9_]+):([0-9a-f]{32})\n")
TOOL_LINE = re.compile(r"TOOL [a-z0-9_]+: [a-z0-9_.]{1,64}\n")
HEAD_LINES = 4


@dataclass(frozen=True)
class Section:
    label: str
    body: str


@dataclass(frozen=True)
class Parsed:
    head: tuple[str, ...]
    """The four trusted header lines."""
    nonce: str | None
    sections: tuple[Section, ...]
    tool_lines: tuple[str, ...]
    stray: tuple[str, ...]
    """Text between or after sections that is neither a section nor a ``TOOL`` line. Empty
    for a well-formed input."""


def parse(text: str) -> Parsed:
    parts = text.split("\n", HEAD_LINES)
    head = tuple(parts[:HEAD_LINES])
    rest = parts[HEAD_LINES] if len(parts) > HEAD_LINES else ""
    found = NONCE_IN_INSTRUCTION.search(head[3]) if len(head) == HEAD_LINES else None
    nonce = found.group(1) if found else None
    sections: list[Section] = []
    tool_lines: list[str] = []
    stray: list[str] = []
    pos = 0
    while nonce is not None and pos < len(rest):
        opened = OPEN_MARKER.match(rest, pos)
        if opened is not None and opened.group(2) == nonce:
            label = opened.group(1)
            closer = f"\nUNTRUSTED:{label}:{nonce}>>>"
            end = rest.find(closer, opened.end())
            if end < 0:
                stray.append(rest[pos:])
                break
            sections.append(Section(label, rest[opened.end() : end]))
            pos = end + len(closer)
            if pos < len(rest) and rest[pos] == "\n":
                pos += 1
            elif pos < len(rest):  # text glued to the closer
                line = rest[pos:].partition("\n")[0]
                stray.append(line)
                pos += len(line) + 1
            continue
        tool = TOOL_LINE.match(rest, pos)
        if tool is not None:
            tool_lines.append(tool.group(0).rstrip("\n"))
            pos = tool.end()
            continue
        line = rest[pos:].partition("\n")[0]
        stray.append(line)
        pos += len(line) + 1
    if nonce is None and rest:
        stray.append(rest.split("\n", 1)[0])
    return Parsed(head, nonce, tuple(sections), tuple(tool_lines), tuple(stray))


def expected_bodies(redacted: Any) -> list[str]:
    """The texts of a redacted request that must each be the body of one section: the
    content, and every context item's text, arguments or result."""
    bodies = [redacted.content]
    for item in redacted.conversation:
        for attr in ("text", "arguments", "result"):
            if hasattr(item, attr):
                bodies.append(getattr(item, attr))
    return bodies


def violations(row: Mapping[str, Any], text: str, redacted: Any, *, domain: str) -> list[str]:
    """What is wrong with ``text`` as the rendering of ``row`` (``redacted`` is the
    ``RedactedRequest`` the engine rendered from). An empty list means every defence held."""
    out: list[str] = []
    parsed = parse(text)
    slug, tid = row.get("tenant_slug"), row.get("tenant_id")
    if parsed.nonce is None:
        return ["no nonce in the instruction line (or the header is missing)"]
    expected_head = (
        f"TENANT DOMAIN: {domain}",
        tenant_line(slug, tid),
        f"GUARD POINT: {row['guard_point']}",
        instruction_line(parsed.nonce),
    )
    if parsed.head != expected_head:
        out.append("the four header lines are not the platform's own")
    if parsed.stray:
        out.append(f"text outside the untrusted sections: {parsed.stray[0][:60]!r}")
    outside = list(parsed.head) + list(parsed.tool_lines) + list(parsed.stray)
    tenant_lines = [ln for ln in outside if ln.startswith("TENANT:")]
    if tenant_lines != [expected_head[1]]:
        out.append("the TENANT header is not the single, real one")
    if sum(ln.startswith("GUARD POINT:") for ln in outside) != 1:
        out.append("the GUARD POINT header is not unique")
    if sum(ln.startswith("TENANT DOMAIN:") for ln in outside) != 1:
        out.append("the TENANT DOMAIN header is not unique")
    if any(ln.startswith(("<<<UNTRUSTED", "UNTRUSTED:")) for ln in outside):
        out.append("a section marker sits outside the sections")
    if text.count(parsed.nonce) != 1 + 2 * len(parsed.sections):
        out.append("the nonce occurs somewhere other than the instruction and the markers")
    content_sections = [s for s in parsed.sections if s.label == "content"]
    if len(content_sections) != 1 or parsed.sections[-1] is not content_sections[0]:
        out.append("there isn't exactly one content section, last")
    elif content_sections[0].body != redacted.content:
        out.append("the content section isn't the content, byte for byte")
    bodies = [s.body for s in parsed.sections]
    for body in expected_bodies(redacted):
        if body not in bodies:
            out.append("a request text is not the body of any section")
            break
    return out


def content_of(text: str) -> str | None:
    """The body of the ``content`` section of a rendered input, or None."""
    parsed = parse(text)
    for section in reversed(parsed.sections):
        if section.label == "content":
            return section.body
    return None


def forged_marker_lines(content: str) -> Sequence[str]:
    """Lines in a row's content that imitate a trusted line or a section marker: the lines
    :func:`violations` proves stay inside the content section."""
    return [
        ln
        for ln in content.split("\n")
        if ln.startswith(("<<<", "UNTRUSTED:", "TENANT", "GUARD POINT", "TOOL "))
        or "UNTRUSTED:" in ln
    ]
