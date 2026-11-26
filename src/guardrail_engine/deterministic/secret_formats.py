"""Credentials in a known format (M7-01): deterministic, high confidence, no model.

The floor rule ``p__secret`` asks the model whether content holds a credential. That stays,
for the formats nothing here can recognise. This module covers the formats whose shape is
unmistakable, so that

* at ``plan``, ``tool_call``, ``tool_result`` and ``output`` content holding one is a floor
  ``block`` with **no model call** (:data:`SECRET_BLOCK_GUARD_POINTS`), and
* at every guard point each one is replaced by :data:`~.rules.SECRET_PLACEHOLDER` in the
  content and every context section before rendering, so a user's own key never reaches the
  provider (:func:`guardrail_engine.guard.redaction.redact_request`).

**Formats** (a match needs the full documented shape, not only a prefix):

=====================  ====================================================================
AWS access key id      ``AKIA`` or ``ASIA`` and 16 of ``A-Z0-9``
GitHub token           ``ghp_`` ``gho_`` ``ghu_`` ``ghs_`` ``ghr_`` and 36 or more
                       alphanumerics; ``github_pat_`` and 40 or more of ``A-Za-z0-9_``
Google API key         ``AIza`` and 35 of ``A-Za-z0-9_-``
Slack token            ``xoxa-`` ``xoxb-`` ``xoxp-`` ``xoxr-`` ``xoxs-``, one to three
                       numeric segments, then 8 or more alphanumerics (a template made of
                       words has no digits and is left alone)
Stripe live key        ``sk_live_`` or ``rk_live_`` and 24 to 99 alphanumerics (publishable
                       ``pk_live_`` keys are public and not matched)
PEM private key        ``-----BEGIN [...] PRIVATE KEY-----`` **followed by key material**
                       (a base64 line of 16 or more characters, or the ``Proc-Type`` /
                       ``DEK-Info`` / ``Version`` / ``Comment`` header lines of an encrypted
                       or PGP key); a header with ``...`` or nothing after it is prose
URL with a password    ``scheme://user:password@host`` (the user may be empty)
=====================  ====================================================================

**What is not matched.** A token must stand alone: not preceded by a letter or digit, and not
followed by a character that could continue it (so a longer identifier or hash that merely
contains one is left alone). A JSON escape or a percent-encoding in front of a token is a
separator, not a letter: after ``\\n``, ``\\t``, ``\\r\\n``, ``\\u000a`` or ``%0A``, ``%20``,
``%3D``,
``%2C`` a token is found (``\\n`` is a line break in JSON text, two characters; ``%XX`` must
encode a non-alphanumeric ASCII character; an escaped backslash followed by ``n`` is a word
and is not a separator, nor is ``%41``, which is the letter ``A``). The body of a token is a
placeholder, and not matched, when it uses three distinct characters or fewer (an all-``X``
key id, an all-zero live key), contains ``EXAMPLE`` in capitals (so AWS's documented
``AKIA...EXAMPLE`` key id, quoted in documentation, passes), or is an obvious ``your...``
phrase (``ghp_yourTokenGoesHere...``).

For a URL the **password** is judged: it runs from the first ``:`` after the user to the last
``@`` before the host, so it may hold a raw ``:`` or ``@``. These are templates, not
credentials: ``{PASSWORD}``, ``<your-password>``, ``${DB_PASS}`` or a whole ``$NAME``,
``[pw]``, ``%s`` or ``%(pw)s``, a mask (``****``, ``xxxx``, ``....``), the words ``password``,
``pass``, ``pwd``, ``secret``, ``token``, ``changeme`` and the like, the phrases
``your-password``, ``your_password``, ``yourpassword`` (and ``-token``, ``-key``, ``-secret``
forms), and two shapes that are **deliberate trade-offs**: a screaming-snake name
(``DB_PASSWORD``: an environment-variable name far more often than a password) and a number
of up to five digits (``host:8080@`` is a host and port, not a login; a real five-digit PIN
is missed). So ``USER:PASSWORD@HOST`` and ``postgres://{USER}:{PASSWORD}@{HOST}`` pass, and
a password that merely starts with ``your`` or ``(``, or with ``$`` and is not a bare name,
is still a credential.

**Left to** ``p__secret`` **on purpose**: ``password: hunter2``, ``api_key = "..."`` and other
assignments, and bare high-entropy strings. Nothing in the text tells a real value from a
type annotation (``password: str``), a schema key, a prompt (``password: required``), a
masked or hashed value or ordinary prose, and a rule that guessed would block legitimate
traffic. Those are the model's judgement.

**What is replaced.** For a URL only the password (``postgres://app:[SECRET]@db.example``),
because the host is what ``p__exfil`` judges. A PEM block is replaced from its header to its
footer; a block without a footer is replaced through the key lines it shows.

Matching uses the engine's :class:`~.regex.RegexEngine` (RE2: linear time, no backtracking).
One pass over a text through a regex set answers the usual case, nothing found; the patterns
that matched are then run for their spans and checked (boundaries, placeholders). Counts
only: the matched text, positions and lengths are never reported by a caller.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass

from guardrail_engine.deterministic.regex import CompiledRegex, RegexEngine, RegexSet
from guardrail_engine.deterministic.rules import SECRET_PLACEHOLDER

SECRET_BLOCK_GUARD_POINTS = frozenset({"plan", "tool_call", "tool_result", "output"})
"""Where a known-format credential is a floor block: the guard points of the floor rule
``p__secret``. At ``input`` it is redacted instead."""

_ALNUM = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
_WITH_DASH_UNDERSCORE = _ALNUM | {"-", "_"}

_B64 = r"[A-Za-z0-9+/=]"
_SEP = r"(?:\s|\\[nr]|%0[AaDd])"  # whitespace, a JSON-escaped or percent-encoded line break
_PEM_NAME = r"(?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?"
_PEM_HEADERS = r"(?:(?:Proc-Type|DEK-Info|Version|Comment):[^\r\n\\]*" + _SEP + r"+)*"

_AUTHORITY = r"[^\s/?#\"'<>\\]"
_URL_PATTERN = rf"[A-Za-z][A-Za-z0-9+.-]{{1,19}}://{_AUTHORITY}*:{_AUTHORITY}*@{_AUTHORITY}+"

_PEM_PATTERN = (
    rf"-----BEGIN {_PEM_NAME}-----{_SEP}*{_PEM_HEADERS}{_B64}{{16,}}"
    rf"(?:{_SEP}+{_B64}{{16,}})*"
    rf"(?:{_SEP}*{_B64}*{_SEP}*-----END {_PEM_NAME}-----)?"
)


@dataclass(frozen=True, slots=True)
class SecretMatch:
    """A credential found: the format's name and the span to replace (character offsets)."""

    kind: str
    start: int
    end: int


Check = Callable[[str, int, int], "tuple[int, int] | None"]
"""Confirms a candidate span of the text and returns the span to replace, or None when the
candidate is not a credential (a boundary or a placeholder)."""


_HEX = frozenset("0123456789abcdefABCDEF")


def _after_backslash(text: str, end: int) -> bool:
    """Whether a backslash sits just before index ``end``. Any run counts, odd or even: JSON
    nested inside a JSON string doubles each escape (``\\\\n``), and a tool's body argument or a
    plan field often carries serialised JSON. Treating the literal text ``\\n`` before a token
    as a break costs no realistic false positive."""
    return end > 0 and text[end - 1] == "\\"


def _starts_cleanly(text: str, start: int) -> bool:
    """Whether nothing before ``start`` makes a token there part of a longer word: not a letter
    or digit, unless that is the end of a JSON escape (``\\n`` ``\\r`` ``\\t`` ``\\f`` ``\\b``, or
    ``\\uXXXX`` of a non-alphanumeric character) or of a percent-encoded non-alphanumeric
    ASCII character (``%0A``, ``%20``)."""
    if start == 0:
        return True
    previous = text[start - 1]
    if previous not in _ALNUM:
        return True
    if previous in "nrtfb" and _after_backslash(text, start - 1):
        return True
    if start >= 6 and text[start - 5] == "u" and _after_backslash(text, start - 5):
        digits = text[start - 4 : start]
        if all(c in _HEX for c in digits):
            return not chr(int(digits, 16)).isalnum()
    if start >= 3 and text[start - 3] == "%" and all(c in _HEX for c in text[start - 2 : start]):
        code = int(text[start - 2 : start], 16)
        return code < 0x80 and not chr(code).isalnum()
    return False


_YOUR_PLACEHOLDER = re.compile(r"your(?:token|key|secret|api|access|pat|id)")


def _placeholder_body(body: str) -> bool:
    """A token body that is a placeholder: three distinct characters or fewer, ``EXAMPLE`` in
    capitals, or an obvious ``your...`` phrase."""
    lowered = body.lower()
    return (
        len(set(body)) <= 3
        or "EXAMPLE" in body
        or lowered.startswith("your")
        or _YOUR_PLACEHOLDER.search(lowered) is not None
    )


def _token(prefix_len: int, after: frozenset[str]) -> Check:
    """A token that stands alone, with a body that isn't a placeholder. ``after`` is the set
    of characters that would make the candidate part of something longer."""

    def check(text: str, start: int, end: int) -> tuple[int, int] | None:
        if not _starts_cleanly(text, start):
            return None
        if end < len(text) and text[end] in after:
            return None
        if _placeholder_body(text[start + prefix_len : end]):
            return None
        return start, end

    return check


_SNAKE = re.compile(r"[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+")
_MASK = frozenset("*xX.•·#_-?")
_PLACEHOLDER_WORDS = frozenset(
    {
        "password", "passwd", "pass", "pwd", "pw", "secret", "token", "changeme", "change-me",
        "change_me", "redacted", "masked", "hidden", "example", "placeholder", "userpass",
        "mypassword", "yourpassword",
    }
)  # fmt: skip
_TEMPLATE_START = ("{", "<", "[")
_SHELL_TEMPLATE = re.compile(r"\$\{[^}]*\}.*|\$[A-Za-z_][A-Za-z0-9_]*|\$\([^)]*\)")
_YOUR_PASSWORD = re.compile(
    r"your[-_]?(?:[a-z]+[-_])?(?:password|passwd|pass|pwd|secret|token|key)(?:[-_]?here)?"
)
_PERCENT_ESCAPE = re.compile(r"%[0-9A-Fa-f]{2}")


def _placeholder_password(password: str) -> bool:
    return (
        password.lower() in _PLACEHOLDER_WORDS
        or _YOUR_PASSWORD.fullmatch(password.lower()) is not None
        or password.startswith(_TEMPLATE_START)
        or _SHELL_TEMPLATE.fullmatch(password) is not None
        or (password.startswith("%") and _PERCENT_ESCAPE.match(password) is None)
        or set(password) <= _MASK
        or _SNAKE.fullmatch(password) is not None  # deliberate: see the module docstring
        or (password.isdigit() and len(password) <= 5)  # deliberate: a port, not a login
    )


_HOST = re.compile(r"[A-Za-z0-9._\[\]-]+")


def _url_password(text: str, start: int, end: int) -> tuple[int, int] | None:
    """The password of ``scheme://user:password@host``: from the first ``:`` after the user to
    the last ``@`` before the host. The span to replace is the password alone."""
    authority_start = text.index("://", start, end) + 3
    authority = text[authority_start:end]
    at = authority.rindex("@")
    colon = authority.find(":", 0, at)
    if colon < 0 or _HOST.match(authority, at + 1) is None:
        return None
    password = authority[colon + 1 : at]
    if not password or _placeholder_password(password):
        return None
    return authority_start + colon + 1, authority_start + at


def _pem(text: str, start: int, end: int) -> tuple[int, int] | None:
    return start, end


@dataclass(frozen=True, slots=True)
class _Format:
    kind: str
    pattern: str
    check: Check


_FORMATS: tuple[_Format, ...] = (
    _Format("aws_access_key", r"(?:AKIA|ASIA)[0-9A-Z]{16}", _token(4, _ALNUM)),
    _Format("github_token", r"gh[pousr]_[A-Za-z0-9]{36,255}", _token(4, _ALNUM)),
    _Format("github_pat", r"github_pat_[A-Za-z0-9_]{40,255}", _token(11, _WITH_DASH_UNDERSCORE)),
    _Format("google_api_key", r"AIza[0-9A-Za-z_-]{35}", _token(4, _WITH_DASH_UNDERSCORE)),
    _Format(
        "slack_token",
        r"xox[abprs]-(?:[0-9]+-){1,3}[0-9A-Za-z]{8,}(?:-[0-9A-Za-z]+)*",
        _token(5, _ALNUM),
    ),
    _Format("stripe_live_key", r"[rs]k_live_[0-9A-Za-z]{24,99}", _token(8, _ALNUM)),
    _Format("pem_private_key", _PEM_PATTERN, _pem),
    _Format("url_password", _URL_PATTERN, _url_password),
)


class SecretDetector:
    """Finds and replaces credentials in a known format, on the engine's regex port.

    Pure and deterministic: no network, no state, no logging of what it finds. Build one per
    engine; the patterns are compiled once, at construction."""

    def __init__(self, engine: RegexEngine) -> None:
        self._compiled: tuple[CompiledRegex, ...] = tuple(
            engine.compile(f.pattern) for f in _FORMATS
        )
        self._set: RegexSet = engine.compile_set([f.pattern for f in _FORMATS])

    def find(self, text: str) -> list[SecretMatch]:
        """The credentials in ``text``, in text order, non-overlapping."""
        found: list[SecretMatch] = []
        for index in sorted(self._set.matching(text)):
            fmt = _FORMATS[index]
            for start, end in self._compiled[index].spans(text):
                span = fmt.check(text, start, end)
                if span is not None:
                    found.append(SecretMatch(fmt.kind, *span))
        found.sort(key=lambda m: (m.start, m.end))
        merged: list[SecretMatch] = []
        for match in found:
            if merged and match.start < merged[-1].end:  # overlapping: one credential
                last = merged[-1]
                merged[-1] = SecretMatch(last.kind, last.start, max(last.end, match.end))
            else:
                merged.append(match)
        return merged

    def count(self, text: str) -> int:
        """How many credentials ``text`` holds (0: none)."""
        return len(self.find(text)) if self._set.matching(text) else 0

    def redact(self, text: str) -> tuple[str, int]:
        """``text`` with each credential replaced by the placeholder, and how many were
        replaced. Returns ``text`` itself when there is none."""
        matches = self.find(text) if self._set.matching(text) else []
        if not matches:
            return text, 0
        pieces: list[str] = []
        pos = 0
        for m in matches:
            pieces += (text[pos : m.start], SECRET_PLACEHOLDER)
            pos = m.end
        pieces.append(text[pos:])
        return "".join(pieces), len(matches)
