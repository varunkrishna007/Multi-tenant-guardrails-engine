"""PII redaction before the model call (M1-14; AC-G2).

The Guard Service redacts every untrusted text of a check **before rendering**, so no raw
PII of a configured kind (:mod:`guardrail_engine.guard.pii`) appears in a ``decide`` input:

* the content under evaluation;
* every conversation context item: a turn's text, a plan's text, a tool call's arguments, a
  tool result's result, and the tool name of a tool call or result whose tool **isn't** in
  the tenant's registry (it is rendered as untrusted request data);
* the description of each registered tool the conversation refers to (tenant-written free
  text, rendered in the ``tool_metadata`` section).

**Credentials** (M7-01): each credential in a known format is replaced by ``[SECRET]`` in
the same texts, so a user's own key never reaches the provider
(:mod:`guardrail_engine.deterministic.secret_formats`). A credential in the *content* at
``plan``, ``tool_call``, ``tool_result`` or ``output`` never gets this far: it is a floor
block first. The model question ``p__secret`` stays for the formats no pattern recognises.

Not redacted: the trusted header lines (``TENANT DOMAIN``, ``TENANT``, ``GUARD POINT``, the
instruction line), which carry only platform-validated values, the names of registered
tools (registry identifiers, needed to find the tool), and the questions (rule text).

**One function for production and calibration.** :func:`redact_request` is what the Guard
Service calls; a harness that renders inputs itself calls it with the same arguments and
renders what it returns, so a calibration run scores exactly what production sends (M1-14,
"Ordering"). It is pure: no network, no model, no randomness, no logging of what it finds.

**Counts, never values.** The result carries how many spans of each kind were replaced, the
only thing about the PII that reaches the audit record and the span. Values, positions and
lengths are never recorded.

There is **no off switch** (decided 2026-11-17): no setting or tenant option disables
redaction. A test may give the Guard Service another :class:`PiiDetector`; the engine's
factory refuses one when ``environment`` is ``production``.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field, replace

from guardrail_engine.deterministic.secret_formats import SecretDetector
from guardrail_engine.guard.pii import (
    DEFAULT_PII_DETECTOR,
    PLACEHOLDERS,
    PiiDetector,
    PiiKind,
    PiiMatch,
)
from guardrail_engine.guard.request import ContextItem, Plan, ToolCall, ToolResult, Turn
from guardrail_engine.guard.tenants import ToolInfo

DenyRedactor = Callable[[str], tuple[str, Mapping[str, int]]]
"""M3-01: a function from a text to that text with a tenant's ``redact`` deny patterns
replaced, and the matches per rule id (``guard.deterministic.redact_deny_patterns``)."""

REDACT_OFF_LOOP_CHARS = 16_384
"""A request whose content and context exceed this many characters is redacted in a
worker thread (``asyncio.to_thread``), so a crafted input can't hold the event loop. Smaller
ones are redacted inline: at most about 21 ms for a crafted 16 KB input and 5 ms for
realistic text (measured; see :mod:`guardrail_engine.guard.pii`, "Cost")."""


def request_chars(content: str, conversation: Sequence[ContextItem]) -> int:
    """Characters of a check's content and context texts: what redaction scans, apart from
    the referenced tools' descriptions (tenant-sized, not request-sized)."""
    total = len(content)
    for item in conversation:
        if isinstance(item, Turn | Plan):
            total += len(item.text)
        elif isinstance(item, ToolCall):
            total += len(item.tool) + len(item.arguments)
        elif isinstance(item, ToolResult):
            total += len(item.tool) + len(item.result)
    return total


class RedactionError(Exception):
    """The detector returned something redaction can't apply. The check fails closed. The
    message names the problem only, never the text."""


@dataclass(frozen=True, slots=True)
class RedactedText:
    text: str
    counts: Mapping[PiiKind, int]


@dataclass(frozen=True, slots=True)
class RedactedRequest:
    """What a check sends, after redaction."""

    content: str
    conversation: tuple[ContextItem, ...]
    tools: Mapping[str, ToolInfo]
    """The registered tools the conversation refers to, with redacted descriptions. Pass it
    to ``render_input`` in place of the full registry: the renderer only looks up the tools
    the conversation refers to, so the rendering is the same."""
    counts: Mapping[PiiKind, int]
    """Spans replaced per kind, over every text above; kinds with none are left out."""
    deny_counts: Mapping[str, int] = field(default_factory=dict)
    """M3-01: matches replaced per ``redact`` deny pattern id, over the same texts. Counts
    only; empty without a ``deny_redactor``."""
    secret_count: int = 0
    """M7-01: credentials in a known format replaced by ``[SECRET]``, over the same texts.
    A count only; 0 without a ``secrets`` detector."""


def redact_text(text: str, detector: PiiDetector = DEFAULT_PII_DETECTOR) -> RedactedText:
    """``text`` with every span ``detector`` finds replaced by its kind's placeholder.
    Returns the same string object when nothing is found. Raises :class:`RedactionError` if
    the detector returns spans that are out of range, overlapping or of an unknown kind, and
    lets anything the detector raises propagate."""
    found = list(detector.find(text))
    if not found:
        return RedactedText(text, {})
    for m in found:
        if not isinstance(m, PiiMatch) or not isinstance(m.kind, PiiKind):
            raise RedactionError(f"detector returned {type(m).__name__}, not a PiiMatch")
    pieces: list[str] = []
    counts: Counter[PiiKind] = Counter()
    pos = 0
    for m in sorted(found, key=lambda m: (m.start, m.end)):
        if not (
            isinstance(m.start, int) and isinstance(m.end, int) and pos <= m.start < m.end
        ) or m.end > len(text):
            raise RedactionError("detector returned an empty, out-of-range or overlapping span")
        pieces += (text[pos : m.start], PLACEHOLDERS[m.kind])
        counts[m.kind] += 1
        pos = m.end
    pieces.append(text[pos:])
    return RedactedText("".join(pieces), dict(counts))


def redact_request(
    *,
    content: str,
    conversation: Sequence[ContextItem],
    tools: Mapping[str, ToolInfo],
    detector: PiiDetector = DEFAULT_PII_DETECTOR,
    deny_redactor: DenyRedactor | None = None,
    secrets: SecretDetector | None = None,
) -> RedactedRequest:
    """Redact a check's content, its conversation and the descriptions of the registered
    tools it refers to (see the module docstring for exactly which fields). ``conversation``
    must already be well formed (``context_item_problem`` is None for every item).

    ``deny_redactor`` (M3-01) is applied to each of those texts **before** the PII detector:
    it returns the text with a tenant's ``redact`` deny patterns replaced, and the matches
    per rule id.

    ``secrets`` (M7-01) is applied first, before the deny patterns and the PII detector: each
    credential of a known format (:mod:`guardrail_engine.deterministic.secret_formats`) is
    replaced by ``[SECRET]``. It is off when None, which is what a harness that scores rows
    as written passes; the Guard Service always passes one."""
    counts: Counter[PiiKind] = Counter()
    deny_counts: Counter[str] = Counter()
    secret_count = 0

    def red(text: str) -> str:
        nonlocal secret_count
        if secrets is not None:
            text, replaced = secrets.redact(text)
            secret_count += replaced
        if deny_redactor is not None:
            text, matched = deny_redactor(text)
            deny_counts.update(matched)
        out = redact_text(text, detector)
        counts.update(out.counts)
        return out.text

    def tool_name(name: str) -> str:
        return name if name in tools else red(name)

    items: list[ContextItem] = []
    referenced: dict[str, ToolInfo] = {}
    for item in conversation:
        if isinstance(item, Turn):
            items.append(Turn(role=item.role, text=red(item.text)))
        elif isinstance(item, Plan):
            items.append(Plan(text=red(item.text)))
        elif isinstance(item, ToolCall | ToolResult):
            info = tools.get(item.tool)
            if info is not None and item.tool not in referenced:
                referenced[item.tool] = replace(info, description=red(info.description))
            if isinstance(item, ToolCall):
                items.append(ToolCall(tool=tool_name(item.tool), arguments=red(item.arguments)))
            else:
                items.append(ToolResult(tool=tool_name(item.tool), result=red(item.result)))
        else:
            raise TypeError(f"not a context item: {type(item).__name__}")
    redacted_content = red(content)
    return RedactedRequest(
        content=redacted_content,
        conversation=tuple(items),
        tools=referenced,
        counts={kind: counts[kind] for kind in PiiKind if counts[kind]},
        deny_counts=dict(deny_counts),
        secret_count=secret_count,
    )
