"""The RE2 adapter (M3-01): :class:`~guardrail_engine.deterministic.regex.RegexEngine` over
``google-re2``. The only module that imports an RE2 binding."""

from __future__ import annotations

import re
from collections.abc import Sequence
from typing import Any

import re2

from guardrail_engine.deterministic.regex import RegexError

_LONE_SURROGATE = re.compile("[\ud800-\udfff]")

PATTERN_MAX_MEM = 8 * 1024 * 1024
"""RE2's bound on one compiled pattern's program (its default). A pattern over it is refused
at compile time, which is what stops a small pattern with huge counted repeats."""
SET_MAX_MEM = 64 * 1024 * 1024
"""The bound for a set of patterns: the cross-tenant scan compiles one pattern per tenant."""


def _options(max_mem: int) -> Any:
    options = re2.Options()
    options.log_errors = False  # RE2 would otherwise write its error to stderr
    options.max_mem = max_mem
    return options


def _detail(error: Exception) -> str:
    arg = error.args[0] if error.args else error
    return arg.decode("utf-8", "replace") if isinstance(arg, bytes) else str(arg)


def _encodable(text: str) -> str:
    """``text`` with each lone surrogate (possible in text decoded from JSON) replaced by one
    U+FFFD, which RE2 can take. One character for one, so spans stay valid."""
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        return _LONE_SURROGATE.sub("�", text)
    return text


class Re2Regex:
    """A compiled pattern. Two are equal when compiled from the same source text, so a
    compiled policy compares equal to another compile of the same bundle."""

    __slots__ = ("_pattern", "_source")

    def __init__(self, pattern: Any, source: str) -> None:
        self._pattern = pattern
        self._source = source

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Re2Regex) and other._source == self._source

    def __hash__(self) -> int:
        return hash(self._source)

    def __repr__(self) -> str:
        return "Re2Regex(...)"  # not the pattern: it can be as sensitive as what it matches

    def search(self, text: str) -> bool:
        return self._pattern.search(_encodable(text)) is not None

    def spans(self, text: str) -> list[tuple[int, int]]:
        found = []
        for m in self._pattern.finditer(_encodable(text)):
            start, end = m.span()
            if end > start:
                found.append((start, end))
        return found


class Re2Set:
    __slots__ = ("_set",)

    def __init__(self, compiled: Any) -> None:
        self._set = compiled

    def matching(self, text: str) -> frozenset[int]:
        return frozenset(self._set.Match(_encodable(text)) or ())


class Re2RegexEngine:
    """Stateless apart from its memory bounds: one instance can be shared by every check."""

    def __init__(
        self, *, pattern_max_mem: int = PATTERN_MAX_MEM, set_max_mem: int = SET_MAX_MEM
    ) -> None:
        self._pattern_options = _options(pattern_max_mem)
        self._set_options = _options(set_max_mem)

    def compile(self, pattern: str) -> Re2Regex:
        try:
            return Re2Regex(re2.compile(pattern, self._pattern_options), pattern)
        except re2.error as e:
            raise RegexError(_detail(e)) from None

    def compile_set(self, patterns: Sequence[str]) -> Re2Set:
        compiled = re2.Set.SearchSet(self._set_options)
        try:
            for pattern in patterns:
                compiled.Add(pattern)
            compiled.Compile()
        except re2.error as e:
            raise RegexError(_detail(e)) from None
        return Re2Set(compiled)
