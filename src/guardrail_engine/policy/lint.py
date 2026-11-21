"""The closed-question lint (AC-C1.6), shared by every kind of rule.

A leaf module with no engine imports, so the catalog (floor and pack rules), the compiler
(tenant rules) and the floor file loader all apply the one definition without an import
cycle.
"""

from __future__ import annotations

CLOSED_QUESTION_STARTS = frozenset(
    [
        "does",
        "do",
        "is",
        "are",
        "has",
        "have",
        "can",
        "could",
        "will",
        "would",
        "should",
        "did",
        "was",
        "were",
    ]
)

CLOSED_QUESTION_RULE = "end with '?' and start with one of " + ", ".join(
    sorted(w.capitalize() for w in CLOSED_QUESTION_STARTS)
)
"""What :func:`is_closed_question` requires, for error messages."""


def is_closed_question(question: str) -> bool:
    """A closed yes/no question: it ends with ``?`` and its first word is one of
    :data:`CLOSED_QUESTION_STARTS` (case-insensitive)."""
    text = question.strip()
    words = text.split(maxsplit=1)
    return text.endswith("?") and bool(words) and words[0].lower() in CLOSED_QUESTION_STARTS


def is_blank(text: str | None) -> bool:
    """None, empty, or whitespace only."""
    return not text or not text.strip()
