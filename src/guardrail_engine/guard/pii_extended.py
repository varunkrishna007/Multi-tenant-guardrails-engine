"""A richer PII detector on the M1-14 port (M3-01; backlog M1-14, "M3-01 keeps richer
detection ... on the same port").

:class:`~guardrail_engine.guard.pii.PiiDetector` has one method, ``find(text)``, returning
typed spans. Redaction (:mod:`guardrail_engine.guard.redaction`) is the same whichever
detector finds them, so a richer detector changes what is found and nothing else: no change to
rendering, the audit record or the no-raw-PII test (AC-G2), which checks the model's input.

**Extension points** (a detector is just an object with ``find``):

* :class:`CompositePiiDetector` runs several detectors and merges their spans, so a new
  detector is added next to the default instead of replacing it.
* :class:`ExtendedPiiDetector` (below) is the default plus the shapes once listed as
  too ambiguous for the default.
* A pluggable engine such as Presidio goes in an ``adapters/`` module (the vendor library is
  imported only there, ``tests/test_imports.py``) as a ``PiiDetector`` that maps the engine's
  entities onto :class:`~guardrail_engine.guard.pii.PiiKind` spans, then composes with the
  default the same way. A **new kind** (another country's national id, say) also needs its
  ``PiiKind`` member, its placeholder, its span attribute name
  (``guardrail.pii_redacted.<kind>`` in the telemetry port) and a place in the catalog's
  supported PII types; none of that changes redaction itself.

**Default unchanged.** The engine's detector stays
:data:`~guardrail_engine.guard.pii.DEFAULT_PII_DETECTOR` (M1-14's decision: no off switch, and
the factory refuses a detector override in production). ``tests/guard/test_guard_pii_extended.py``
shows this one is safe to promote (every M1-14 near miss and credential/URL guarantee holds,
idempotent, linear), but making it the default is a decision for the product owner: it
redacts shapes that are also order numbers and ids, which the default leaves for the model.

**What the extension adds**, each opt-in because of how often the shape is something else:

* ``02079460018``: a compact UK landline (``01``, ``02`` or ``03`` and nine digits).
* ``447700900123``: a UK number in E.164 without its ``+`` (``44``, a nonzero digit and nine
  more).
* ``gb82 west 1234 5698 7654 32``: an IBAN in lower or mixed case (same length and mod-97
  check as the default's).

Not added, because they can't be told from an ID without context: a compact North American
number (``2015550123``), and other countries' national ids (they need new kinds, above).
"""

from __future__ import annotations

from collections.abc import Sequence

from guardrail_engine.guard.pii import (
    DEFAULT_PII_DETECTOR,
    PiiDetector,
    PiiKind,
    PiiMatch,
    _iban_span,
    _non_overlapping,
    _pattern,
)

_COMPACT_UK_LANDLINE = _pattern(r"0[123][0-9]{9}")
_UK_E164_WITHOUT_PLUS = _pattern(r"44[1-9][0-9]{9}")
_ANY_CASE_IBAN = _pattern(
    r"(?ia:[a-z]{2}[0-9]{2}[a-z0-9]{11,30}"
    r"|[a-z]{2}[0-9]{2}(?: [a-z0-9]{4}){2,7}(?: [a-z0-9]{1,3})?)"
)


class CompositePiiDetector:
    """The union of several detectors' spans. Where spans overlap the earliest wins, and at the
    same start the longest (the default detector's own rule), so the result is a valid input
    for redaction whatever the parts return. A part that raises fails the whole find: the
    check then fails closed, as for any detector."""

    def __init__(self, *detectors: PiiDetector) -> None:
        if not detectors:
            raise ValueError("a composite detector needs at least one detector")
        self._detectors = detectors

    def find(self, text: str) -> Sequence[PiiMatch]:
        found: list[PiiMatch] = []
        for detector in self._detectors:
            found.extend(detector.find(text))
        return _non_overlapping(found) if len(self._detectors) > 1 else found


class _ExtraShapes:
    """Only what the default leaves: see the module docstring."""

    def find(self, text: str) -> Sequence[PiiMatch]:
        if not any(ch.isdigit() for ch in text):
            return ()
        found = []
        for pattern in (_COMPACT_UK_LANDLINE, _UK_E164_WITHOUT_PLUS):
            found.extend(PiiMatch(PiiKind.PHONE, *m.span()) for m in pattern.finditer(text))
        for m in _ANY_CASE_IBAN.finditer(text):
            candidate = m.group().upper()
            if len(candidate) != len(m.group()):  # an upper-casing that moved characters
                continue
            span = _iban_span(candidate, 0, len(candidate))
            if span is not None:
                found.append(PiiMatch(PiiKind.IBAN, m.start() + span[0], m.start() + span[1]))
        return found


class ExtendedPiiDetector(CompositePiiDetector):
    """The M1-14 default plus the shapes in the module docstring. Pure and stateless."""

    def __init__(self) -> None:
        super().__init__(DEFAULT_PII_DETECTOR, _ExtraShapes())


EXTENDED_PII_DETECTOR = ExtendedPiiDetector()
