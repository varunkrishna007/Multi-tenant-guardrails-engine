"""PII detection (M1-14): the ``PiiDetector`` port and the engine's deterministic detector.

A detector only **finds** personal data: it returns typed spans. Replacing them with
placeholders is :mod:`guardrail_engine.guard.redaction`'s job, so every detector (this one,
or M3-01's richer engine on the same port) redacts the same way.

**Kinds and placeholders** (backlog M1-14, "Scope" and "Details decided ahead of the build")::

    email              [EMAIL]           the local part only; the domain is kept
    phone              [PHONE]
    card               [CARD]            payment card numbers, Luhn-checked
    iban               [IBAN]
    uk_sort_code       [SORT_CODE]       only next to an account number
    uk_account_number  [ACCOUNT_NUMBER]  only next to a sort code
    uk_nino            [NINO]            UK National Insurance number
    us_ssn             [SSN]

**What this detector never redacts**: hostnames and credentials, because ``p__exfil``
judges whether a destination is external and credentials are not personal data. Credentials
in a known format (keys, tokens, private-key blocks, a URL's password) are handled before
this detector runs, by :mod:`guardrail_engine.deterministic.secret_formats` (M7-01): a block
at the guard points of ``p__secret``, and ``[SECRET]`` at ``input``. Any other credential is
left for ``p__secret`` to judge. A URL's scheme and authority (host, port and any
``user:password@`` userinfo) are left exactly as written by this detector. Its path, query
and fragment go through every detector like any other text (AC-G2 decision, backlog 0105b0a):
``?email=a@b.example&card=4111111111111111`` becomes ``?email=[EMAIL]@b.example&card=[CARD]``;
over-redacting a numeric id there is accepted.
Outside URLs, ``word:secret@host`` is treated as userinfo too (``mailto:`` excepted).

**The detection rules**, chosen to be conservative, because a false positive destroys text
the floor rules judge:

* **Email:** ``local@domain``. The local part is 1 to 64 of ``[A-Za-z0-9._%+-]`` or
  non-ASCII letters and digits, and must start a token: a local part preceded by
  ``!#$&*^`|~`` (the rest of a longer token, such as a password; ``&`` and ``#`` are
  delimiters inside a URL) or by ``word:`` (userinfo) is not an email. The domain is 2 or
  more labels of letters, digits (ASCII or not) and hyphens, at most 253 characters, ending
  in a top-level label of 2+ letters (a punycode ``xn--`` top-level label is not
  recognised; its Unicode form is). Quoted local parts and IP-literal
  domains are not detected.
* **Card:** 13 to 19 digits, unseparated or in the printed groupings (4-4-4-4[-1..3],
  4-4-4-1..3, 4-6-4/5) with one consistent space or hyphen, starting with an issuer prefix
  of a major network at a length that network issues (Visa, Mastercard, Amex, Discover,
  JCB, Diners, UnionPay, Maestro), and passing the Luhn check.
* **Phone:** only shapes that are unmistakably phone numbers: ``+`` and a country code with
  8 to 15 digits in all (E.164); North American ``(201) 555-0123``, ``201-555-0123``,
  ``201.555.0123`` or ``201 555 0123`` (area code and exchange starting 2 to 9, separators
  required and consistent); UK national ``020 7946 0018`` or ``07700 900123`` (a leading
  ``0`` not followed by ``0``, 10 or 11 digits, separators required), and a compact UK
  mobile ``07700900123`` (``07[1-9]`` and 8 more digits). Other bare digit runs are never
  phones, nor are dates, times, versions or IP addresses.
* **IBAN:** a country code, two check digits and the BBAN, compact or in groups of four,
  upper case, the exact length the country's IBAN has, and a valid ISO 7064 mod-97 check.
* **UK sort code with account number:** ``12-34-56`` (or ``12 34 56``) and an 8-digit
  number within 30 characters of each other, in either order, with no digit or line break
  between. Either alone is not personal data and is left alone.
* **UK NINO:** two letters, six digits and ``A`` to ``D``, in any letter case, compact or as
  ``QQ 12 34 56 C`` or ``QQ 123456 C``. Allocation rules aren't applied (an unallocated
  prefix is still redacted, so test data needn't be a real number).
* **US SSN:** ``123-45-6789`` or ``123 45 6789`` (one separator throughout), area not
  ``000``, ``666`` or ``9xx``, group not ``00``, serial not ``0000``.

Every digit-based kind must stand alone: not inside a word, and not joined by ``-.+`` to
letters or digits around it (so UUIDs, hashes, tokens, versions, dates, IP addresses and
base64 never yield a match). ``/`` separates, as in a URL path. Only ASCII digits are
considered.

**Known gaps, for M3-01**: shapes too ambiguous with ids and order numbers to
redact without context are not detected: a compact North American number (``2015550123``),
a compact UK landline (``02079460018``) and E.164 without its ``+`` (``447700900123``).
Lower-case IBANs, non-ASCII digits, quoted email local parts and IP-literal domains aren't
either. M3-01 closes the first three and the lower-case IBAN in an **opt-in** detector on this
same port, :mod:`guardrail_engine.guard.pii_extended` (which also documents how to add a
pluggable engine such as Presidio); this one stays the engine's default.

**Cost.** Linear in the text: every pattern has bounded repetition and its boundaries are
lookarounds, so no match attempt scans further than a fixed width, and emails are found from
each ``@`` with bounded scans either side. Deterministic: no locale, no randomness, no state.
Measured (x86_64, CPython 3.12, best of 3), worst case over the adversarial inputs
in ``tests/guard/test_guard_pii.py`` (the worst is ``a@`` repeated) against realistic text
(the floor's golden set, which is dense in addresses and numbers):

    16 KB:              worst  21 ms   realistic   5 ms
    64 KB (16K tokens): worst  83 ms   realistic  19 ms
    80 KB:              worst 102 ms

A request above 16 KB is redacted in a worker thread, so the event loop is held for
at most about 21 ms by a crafted input and 5 ms by realistic text; the check's own latency
still includes the whole time, which counts towards the live gate's overhead budget.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol


class PiiKind(StrEnum):
    """The configured PII kinds. The values are the keys the audit record and span count."""

    EMAIL = "email"
    PHONE = "phone"
    CARD = "card"
    IBAN = "iban"
    UK_SORT_CODE = "uk_sort_code"
    UK_ACCOUNT_NUMBER = "uk_account_number"
    UK_NINO = "uk_nino"
    US_SSN = "us_ssn"


PLACEHOLDERS: dict[PiiKind, str] = {
    PiiKind.EMAIL: "[EMAIL]",
    PiiKind.PHONE: "[PHONE]",
    PiiKind.CARD: "[CARD]",
    PiiKind.IBAN: "[IBAN]",
    PiiKind.UK_SORT_CODE: "[SORT_CODE]",
    PiiKind.UK_ACCOUNT_NUMBER: "[ACCOUNT_NUMBER]",
    PiiKind.UK_NINO: "[NINO]",
    PiiKind.US_SSN: "[SSN]",
}
"""Each kind's placeholder. An email's span is its local part, so ``a@b.example`` becomes
``[EMAIL]@b.example``."""


@dataclass(frozen=True, slots=True)
class PiiMatch:
    """``text[start:end]`` is personal data of ``kind``, to be replaced by its placeholder."""

    kind: PiiKind
    start: int
    end: int


class PiiDetector(Protocol):
    """Finds personal data in a text. Must be deterministic and must not keep, log or send
    what it finds. Returns spans in any order; overlapping spans are an error the redaction
    step refuses (the check then fails closed)."""

    def find(self, text: str) -> Sequence[PiiMatch]: ...


# ------------------------------------------------------------------ boundaries

# A digit-based match must not continue a word, or be joined by -.+ to one. (``/`` is a
# separator, as in a URL path ``/4111111111111111/``.) A placeholder's bracket counts as part
# of a word, so text that only touched a match before redaction can't become a match after
# it (redaction is idempotent).
_BEFORE = r"(?<![\w\]])(?<![\w\]][-.+])"
_AFTER = r"(?![\w\[])(?![-.+][\w\[])"


def _pattern(body: str) -> re.Pattern[str]:
    return re.compile(_BEFORE + "(?:" + body + ")" + _AFTER)


# ------------------------------------------------------------------ cards

_CARD = _pattern(
    r"[0-9]{13,19}"
    r"|[0-9]{4}(?P<s1>[ -])[0-9]{4}(?P=s1)[0-9]{4}(?P=s1)[0-9]{1,4}(?:(?P=s1)[0-9]{1,3})?"
    r"|[0-9]{4}(?P<s2>[ -])[0-9]{6}(?P=s2)[0-9]{4,5}"
)

_ANY_13_19 = frozenset(range(13, 20))
_16_19 = frozenset(range(16, 20))
_14_19 = frozenset(range(14, 20))

# (first digits, lengths issued). The longest matching prefix decides.
_CARD_PREFIXES: dict[str, frozenset[int]] = {
    "4": frozenset({13, 16, 19}),  # Visa
    "34": frozenset({15}),  # American Express
    "37": frozenset({15}),
    **{str(p): frozenset({16}) for p in range(51, 56)},  # Mastercard
    **{str(p): frozenset({16}) for p in range(2221, 2721)},  # Mastercard 2-series
    "6011": _16_19,  # Discover
    "65": _16_19,
    **{str(p): _16_19 for p in range(644, 650)},
    "62": _16_19,  # UnionPay
    **{str(p): _16_19 for p in range(3528, 3590)},  # JCB
    **{str(p): _14_19 for p in range(300, 306)},  # Diners Club
    "36": _14_19,
    "38": _14_19,
    "39": _14_19,
    # Maestro (12-digit cards exist but aren't detected: too close to other numbers).
    "50": _ANY_13_19,
    "56": _ANY_13_19,
    "57": _ANY_13_19,
    "58": _ANY_13_19,
    "63": _ANY_13_19,
    "67": _ANY_13_19,
}


def luhn_valid(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = ord(ch) - 48
        if i % 2:
            d = d * 2 - 9 if d > 4 else d * 2
        total += d
    return total % 10 == 0


def _card_span(text: str, start: int, end: int) -> tuple[int, int] | None:
    """The card number at ``text[start:end]``. A space-grouped number whose optional fifth
    group was a separate number that followed it is cut back to its four groups."""
    candidate = text[start:end]
    if is_card_number(re.sub(r"[ -]", "", candidate)):
        return start, end
    groups = candidate.split(" ")
    if len(groups) == 5:
        cut = start + len(" ".join(groups[:4]))
        if is_card_number("".join(groups[:4])):
            return start, cut
    return None


def is_card_number(digits: str) -> bool:
    """``digits`` (digits only) has a major network's prefix and length and passes Luhn."""
    for size in (4, 3, 2, 1):
        lengths = _CARD_PREFIXES.get(digits[:size])
        if lengths is not None:
            return len(digits) in lengths and luhn_valid(digits)
    return False


# ------------------------------------------------------------------ phones

_PHONE = _pattern(
    # International: +, country code, groups each after a separator, or compact.
    r"\+[0-9]{1,3}(?:[ .-](?:\([0-9]{1,4}\)[ .-]?)?[0-9]{1,6}){1,6}"
    r"|\+[0-9]{8,15}"
    # North American.
    r"|\([2-9][0-9]{2}\) ?[2-9][0-9]{2}[-. ][0-9]{4}"
    r"|[2-9][0-9]{2}(?P<s>[-. ])[2-9][0-9]{2}(?P=s)[0-9]{4}"  # spaces too
    # UK national.
    r"|0[1-9][0-9]{1,3}(?P<u>[ -])[0-9]{3,4}(?:(?P=u)[0-9]{3,4})?"
    r"|0[1-9][0-9]{3}(?P<v>[ -])[0-9]{6}"
    r"|07[1-9][0-9]{8}"  # a compact UK mobile
)


def _phone_digits_ok(match: str) -> bool:
    count = sum(ch.isdigit() for ch in match)
    if match.startswith("+"):
        return 8 <= count <= 15
    if match.startswith("0"):
        return count in (10, 11)
    return True  # North American shapes have exactly 10 by construction


def _phone_span(text: str, start: int, end: int) -> tuple[int, int] | None:
    """The phone number at ``text[start:end]``. An international number that ran on into
    a following number (more than 15 digits) is cut back, a whole group at a time, to the
    longest prefix that is a valid number ending at a clean boundary."""
    if _phone_digits_ok(text[start:end]):
        return start, end
    if text[start] != "+":
        return None
    for cut in range(end - 1, start, -1):
        if text[cut] in " .-" and text[cut - 1].isdigit():
            joined = text[cut] in ".-" and cut + 1 < len(text) and text[cut + 1].isdigit()
            if not joined and _phone_digits_ok(text[start:cut]):
                return start, cut
    return None


# ------------------------------------------------------------------ IBAN

# ISO 13616 IBAN lengths by country (SWIFT IBAN registry).
IBAN_LENGTHS: dict[str, int] = {
    "AD": 24, "AE": 23, "AL": 28, "AT": 20, "AZ": 28, "BA": 20, "BE": 16, "BG": 22,
    "BH": 22, "BR": 29, "BY": 28, "CH": 21, "CR": 22, "CY": 28, "CZ": 24, "DE": 22,
    "DK": 18, "DO": 28, "EE": 20, "EG": 29, "ES": 24, "FI": 18, "FO": 18, "FR": 27,
    "GB": 22, "GE": 22, "GI": 23, "GL": 18, "GR": 27, "GT": 28, "HR": 21, "HU": 28,
    "IE": 22, "IL": 23, "IQ": 23, "IS": 26, "IT": 27, "JO": 30, "KW": 30, "KZ": 20,
    "LB": 28, "LC": 32, "LI": 21, "LT": 20, "LU": 20, "LV": 21, "MC": 27, "MD": 24,
    "ME": 22, "MK": 19, "MR": 27, "MT": 31, "MU": 30, "NL": 18, "NO": 15, "PK": 24,
    "PL": 28, "PS": 29, "PT": 25, "QA": 29, "RO": 24, "RS": 22, "SA": 24, "SC": 31,
    "SE": 24, "SI": 19, "SK": 24, "SM": 27, "ST": 25, "SV": 28, "TL": 23, "TN": 24,
    "TR": 26, "UA": 29, "VA": 22, "VG": 24, "XK": 20,
}  # fmt: skip

_IBAN = _pattern(
    r"[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}"
    r"|[A-Z]{2}[0-9]{2}(?: [A-Z0-9]{4}){2,7}(?: [A-Z0-9]{1,3})?"
)


def is_iban(compact: str) -> bool:
    """``compact`` (no spaces) has its country's IBAN length and a valid mod-97 check."""
    if IBAN_LENGTHS.get(compact[:2]) != len(compact):
        return False
    rearranged = compact[4:] + compact[:4]
    number = "".join(str(int(ch, 36)) for ch in rearranged)
    return int(number) % 97 == 1


def _iban_span(text: str, start: int, end: int) -> tuple[int, int] | None:
    """The IBAN at ``text[start:end]``, trimmed to its country's length when it was printed
    in groups and ran into a following group."""
    candidate = text[start:end]
    compact = candidate.replace(" ", "")
    expected = IBAN_LENGTHS.get(compact[:2])
    if expected is None or len(compact) < expected:
        return None
    if len(compact) > expected:
        if " " not in candidate:
            return None
        # Keep the first ``expected`` characters, and only at a group boundary.
        kept = 0
        for i, ch in enumerate(candidate):
            if ch != " ":
                kept += 1
                if kept == expected:
                    cut = i + 1
                    break
        if candidate[cut] != " ":
            return None
        end = start + cut
        compact = compact[:expected]
    return (start, end) if is_iban(compact) else None


# ------------------------------------------------------------------ UK bank details, NINO, SSN

_SORT_CODE = _pattern(r"[0-9]{2}(?P<s>[- ])[0-9]{2}(?P=s)[0-9]{2}")
_ACCOUNT_NUMBER = _pattern(r"[0-9]{8}")
SORT_CODE_ACCOUNT_GAP = 30
"""Most characters between a sort code and its account number (no digits or line breaks)."""

_NINO = _pattern(  # any letter case, and the "QQ 123456 C" spacing
    r"(?i:[A-Z]{2}[0-9]{6}[A-D]"
    r"|[A-Z]{2} [0-9]{2} [0-9]{2} [0-9]{2} [A-D]"
    r"|[A-Z]{2} [0-9]{6} [A-D])"
)

_SSN = _pattern(  # hyphens or spaces, consistently
    r"(?P<area>[0-9]{3})(?P<sep>[- ])(?P<group>[0-9]{2})(?P=sep)(?P<serial>[0-9]{4})"
)


def _ssn_ok(m: re.Match[str]) -> bool:
    area = m["area"]
    return (
        area != "000"
        and area != "666"
        and not area.startswith("9")
        and m["group"] != "00"
        and m["serial"] != "0000"
    )


# ------------------------------------------------------------------ URLs and emails

_URL = re.compile(r"[A-Za-z][A-Za-z0-9+.\-]{0,31}://[^\s<>\"'`\[\]]*")
"""A URL runs to whitespace, a quote, an angle bracket or a square bracket. Stopping at a
bracket means a placeholder ends a URL, so redacting a spaced phone or card inside one can't
lengthen the URL on a second pass (idempotence). An IPv6 host in brackets is left outside
the URL; it holds no PII shape."""
_TRIGGER = re.compile(r"[0-9@]")

LOCAL_PART_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._%+-")
DOMAIN_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-")
_TOKEN_CONTINUES = frozenset("!#$&*^`|~")
MAX_LOCAL_PART = 64
MAX_DOMAIN = 253


@dataclass(frozen=True, slots=True)
class _Url:
    start: int
    end: int
    authority_end: int
    """End of ``scheme://authority``: an ``@`` before it is userinfo, never an email."""


def _urls(text: str) -> list[_Url]:
    urls = []
    for m in _URL.finditer(text):
        body = m.start() + m.group().index("://") + 3
        authority_end = m.end()
        for i in range(body, m.end()):
            if text[i] in "/?#":
                authority_end = i
                break
        urls.append(_Url(m.start(), m.end(), authority_end))
    return urls


def _valid_label(label: str) -> bool:
    return 1 <= len(label) <= 63 and label[0] != "-" and label[-1] != "-"


def _valid_tld(label: str) -> bool:
    return len(label) >= 2 and label.isalpha()


def _has_domain(scanned: str) -> bool:
    """Whether ``scanned`` (domain characters after an ``@``) starts with a domain: two or
    more valid labels, at most 253 characters, ending at a top-level label of letters.
    Judged on its leading labels only, up to the first that isn't valid, so text after the
    domain that a later match replaces can't change the answer (a match can only start
    after a ``.`` or a ``-`` that doesn't follow a letter or digit, and both end the run of
    valid labels as seen on either pass)."""
    labels: list[str] = []
    size = -1
    for label in scanned.split("."):
        if not _valid_label(label):
            break
        size += 1 + len(label)
        if size > MAX_DOMAIN:
            break
        labels.append(label)
    return any(_valid_tld(label) for label in labels[1:])


def _local_char(ch: str) -> bool:
    return ch in LOCAL_PART_CHARS or (ch > "\x7f" and ch.isalnum())


def _domain_char(ch: str) -> bool:
    return ch in DOMAIN_CHARS or (ch > "\x7f" and ch.isalnum())


def _email_local_part(text: str, at: int, in_url: bool) -> tuple[int, int] | None:
    """The span of the local part of an email whose ``@`` is at ``at``, or None. ``in_url``:
    the ``@`` is in a URL's path, query or fragment, where ``&`` and ``#`` are delimiters."""
    # Left: the local part.
    start = at
    while start > 0 and at - start <= MAX_LOCAL_PART and _local_char(text[start - 1]):
        start -= 1
    if at - start > MAX_LOCAL_PART:
        return None  # longer than any local part: not an email
    scanned = start  # where the scan stopped: the boundary is judged here, before dots go
    while start < at and text[start] == ".":
        start += 1
    if start == at:
        return None
    if scanned > 0:
        prev = text[scanned - 1]
        if prev in _TOKEN_CONTINUES and not (in_url and prev in "&#"):
            return None  # the tail of a longer token (e.g. a password)
        if prev == "]":
            return None  # touches a placeholder: what it continues was judged on pass one
        if (
            prev == ":"
            and scanned >= 2
            and not text[scanned - 2].isspace()
            and text[max(0, scanned - 7) : scanned - 1].lower() != "mailto"
        ):
            return None  # word:secret@host is userinfo, a credential
    # Right: the domain.
    end = at + 1
    limit = min(len(text), at + 1 + MAX_DOMAIN + 1)
    while end < limit and _domain_char(text[end]):
        end += 1
    return (start, at) if _has_domain(text[at + 1 : end]) else None


# ------------------------------------------------------------------ the detector


class DeterministicPiiDetector:
    """The engine's detector for the configured kinds (see the module docstring). Pure and
    stateless: one instance can be shared by every check."""

    def find(self, text: str) -> Sequence[PiiMatch]:
        if not _TRIGGER.search(text):
            return ()
        # Per character: 0 outside URLs, 1 in a URL, 2 in a URL's scheme://authority.
        urls = _urls(text)
        mask = bytearray(len(text) if urls else 0)
        for url in urls:
            mask[url.start : url.authority_end] = b"\x02" * (url.authority_end - url.start)
            mask[url.authority_end : url.end] = b"\x01" * (url.end - url.authority_end)

        def in_url(pos: int) -> bool:
            return bool(urls) and mask[pos] != 0

        def touches_authority(start: int, end: int) -> bool:
            """Any of ``text[start:end]`` is a URL's scheme or authority (kept as written)."""
            return bool(urls) and 2 in mask[start:end]

        found: list[PiiMatch] = []

        at = text.find("@")
        while at != -1:
            if (
                not touches_authority(at, at + 1)
                and (span := _email_local_part(text, at, in_url(at))) is not None
            ):
                found.append(PiiMatch(PiiKind.EMAIL, *span))
            at = text.find("@", at + 1)

        # AC-G2 (decided 2026-11-17, backlog 0105b0a): every kind is redacted in a URL's path,
        # query and fragment; only its scheme and authority are kept byte for byte.
        def add(kind: PiiKind, start: int, end: int) -> None:
            if not touches_authority(start, end):
                found.append(PiiMatch(kind, start, end))

        for kind, pattern, accept in _SCANS:
            for span in _scan(pattern, text, accept):
                add(kind, *span)
        for sort_code, account in _bank_pairs(text):
            if not touches_authority(*sort_code) and not touches_authority(*account):
                found.append(PiiMatch(PiiKind.UK_SORT_CODE, *sort_code))
                found.append(PiiMatch(PiiKind.UK_ACCOUNT_NUMBER, *account))
        return _non_overlapping(found)


Span = tuple[int, int]
Accept = Callable[[str, "re.Match[str]"], "Span | None"]


def _scan(pattern: re.Pattern[str], text: str, accept: Accept) -> list[Span]:
    """Every accepted span of ``pattern``. Searched rather than iterated: a candidate that is
    refused, or accepted cut short, doesn't hide another one starting inside it (so text
    that only touched a refused candidate can't become a match once its neighbour is
    redacted). Linear: every pattern's matches have a bounded width."""
    spans = []
    pos = 0
    while (m := pattern.search(text, pos)) is not None:
        if (span := accept(text, m)) is not None:
            spans.append(span)
            pos = span[1]
        else:
            pos = m.start() + 1
    return spans


_SCANS: tuple[tuple[PiiKind, re.Pattern[str], Accept], ...] = (
    (PiiKind.CARD, _CARD, lambda t, m: _card_span(t, m.start(), m.end())),
    (PiiKind.PHONE, _PHONE, lambda t, m: _phone_span(t, m.start(), m.end())),
    (PiiKind.IBAN, _IBAN, lambda t, m: _iban_span(t, m.start(), m.end())),
    (PiiKind.UK_NINO, _NINO, lambda t, m: m.span()),
    (PiiKind.US_SSN, _SSN, lambda t, m: m.span() if _ssn_ok(m) else None),
)


def _bank_pairs(text: str) -> list[tuple[tuple[int, int], tuple[int, int]]]:
    """Each sort code paired with the nearest account number within the gap, either side,
    with no digit or line break between; each used once."""
    codes = [(m.start(), m.end()) for m in _SORT_CODE.finditer(text)]
    if not codes:
        return []
    accounts = [(m.start(), m.end()) for m in _ACCOUNT_NUMBER.finditer(text)]
    used: set[int] = set()
    pairs = []
    i = 0
    for code in codes:  # both lists are in text order
        while i < len(accounts) and accounts[i][0] < code[1]:
            i += 1
        options = []
        if i < len(accounts):  # the next account number after the code
            options.append((code[1], accounts[i][0], i))
        if i > 0:  # the last account number before it
            options.append((accounts[i - 1][1], code[0], i - 1))
        for left, right, j in sorted(options, key=lambda o: o[1] - o[0]):
            gap, between = right - left, text[left:right]
            if (
                j not in used
                and 0 <= gap <= SORT_CODE_ACCOUNT_GAP
                # Nothing between that is, or was, other PII: digits and @ before redaction,
                # a placeholder's brackets after it (so redaction is idempotent).
                and not any(ch.isdigit() or ch in "\r\n@[]" for ch in between)
            ):
                used.add(j)
                pairs.append((code, accounts[j]))
                break
    return pairs


_PRIORITY = {kind: i for i, kind in enumerate(PiiKind)}


def _non_overlapping(found: list[PiiMatch]) -> list[PiiMatch]:
    """Earliest first; at the same start the longest, then by kind order; anything
    overlapping a match already kept is dropped, except that an email local part running
    on past it keeps its remainder (so no part of an address is left, and a second pass,
    which sees the placeholder's bracket, finds nothing more)."""
    found.sort(key=lambda m: (m.start, m.start - m.end, _PRIORITY[m.kind]))
    kept: list[PiiMatch] = []
    end = -1
    for m in found:
        if m.start < end < m.end and m.kind is PiiKind.EMAIL:
            m = PiiMatch(PiiKind.EMAIL, end, m.end)
        if m.start >= end:
            kept.append(m)
            end = m.end
    return kept


DEFAULT_PII_DETECTOR = DeterministicPiiDetector()
