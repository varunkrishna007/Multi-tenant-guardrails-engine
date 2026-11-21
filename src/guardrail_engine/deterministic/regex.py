"""The regex port (M3-01, PF-11): the one way the engine matches patterns.

Tenant deny patterns and the cross-tenant identifier scan are matched with **RE2**: linear
time in the text, no backreferences and no lookaround, so a tenant's
pattern can't hold a check hostage. The engine depends on the port only; the one module that
imports an RE2 binding is :mod:`guardrail_engine.deterministic.adapters.google_re2`.

**Which binding.** ``google-re2`` (Google's own ``re2`` Python package, built on the RE2
C++ library) rather than the older ``pyre2`` bindings: it is the maintained one, ships wheels
for current CPython, reports match positions in characters for ``str`` input, and was
already the engine's dependency for the compiler's validation (AC-C1.10). Its ``Set`` type
matches many patterns in one pass, which the cross-tenant scan needs.

**Contract of an engine.**

* ``compile`` and ``compile_set`` raise :class:`RegexError` for a pattern the engine can't
  run: a syntax error, an RE2-unsupported construct (backreference, lookaround) or a pattern
  over the engine's memory bound. Nothing else is raised for a bad pattern.
* Matching never raises for any ``str``, lone surrogates included, and runs in time linear
  in the text.
* Spans are ``(start, end)`` in characters, non-empty and non-overlapping, in text order.
"""

from __future__ import annotations

import functools
import importlib
from collections.abc import Sequence
from typing import Protocol


class RegexError(ValueError):
    """The pattern can't be compiled. ``detail`` is the engine's own wording (it may quote
    part of the pattern, so it is fit for the author of the pattern, not for a log line
    about someone else's content)."""

    def __init__(self, detail: str) -> None:
        self.detail = detail
        super().__init__(detail)


class CompiledRegex(Protocol):
    def search(self, text: str) -> bool:
        """Whether the pattern matches anywhere in ``text``."""
        ...

    def spans(self, text: str) -> list[tuple[int, int]]:
        """Every non-empty, non-overlapping match, as character offsets, in text order."""
        ...


class RegexSet(Protocol):
    def matching(self, text: str) -> frozenset[int]:
        """The indexes (in the order given to ``compile_set``) of the patterns that match
        anywhere in ``text``."""
        ...


class RegexEngine(Protocol):
    def compile(self, pattern: str) -> CompiledRegex: ...

    def compile_set(self, patterns: Sequence[str]) -> RegexSet: ...


ADAPTER_MODULE = "guardrail_engine.deterministic.adapters.google_re2"


@functools.cache
def default_regex_engine() -> RegexEngine:
    """The platform's RE2 engine, built on first use.

    The adapter is resolved by name here so that no engine module outside an ``adapters``
    package imports it (``tests/test_imports.py``): the compiler can then work without being
    handed an engine, the way every existing caller builds it. A composition root that wants
    another engine (a test double, a different binding) passes one to ``PolicyCompiler`` and
    ``GuardService`` instead.
    """
    module = importlib.import_module(ADAPTER_MODULE)
    engine: RegexEngine = module.Re2RegexEngine()
    return engine
