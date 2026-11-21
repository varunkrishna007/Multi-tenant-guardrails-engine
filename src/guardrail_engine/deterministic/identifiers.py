"""The cross-tenant identifier scan's port (M3-01, floor, deterministic).

At ``tool_result`` and ``output`` the engine scans the content for identifiers that belong to
**other** tenants: their tenant ids, plus the tenant-scoped identifier patterns they have
registered (order numbers, account ids, anything a tenant's data is keyed by). A match is a
deterministic ``block`` that no tenant can disable or loosen, and it is made before and
without the model: the model can't know which records belong to which tenant, so this is how
the floor stops cross-tenant *leakage*. (``p__xtenant_probe`` covers *probing*.)

**Identifier patterns are platform-reviewed, not tenant self-service.** A pattern one
tenant registers is matched against **every other tenant's** content, so a careless one (``.``,
``[0-9]``, ``e``) would block them all. Every source implementation therefore refuses a
pattern at registration unless :func:`validate_identifier_pattern` passes it: it is within
:data:`IDENTIFIER_PATTERN_MAX_CHARS`, compiles under RE2, can't match the empty string, has no
top-level alternation, starts with a literal of at least :data:`MIN_LITERAL_PREFIX` characters
(``ORD-[0-9]{6,10}``, not ``[0-9]+``), needs a digit or a separator character in every match
(``account`` is a word, ``ACC-1`` is an identifier), has only small repeats
(every counted repeat at most :data:`MAX_REPEAT`, and no unbounded repeat except of one plain
character; and the repeats of one pattern add up to at most :data:`MAX_REPEAT_WEIGHT`),
holds at least :data:`MIN_TAIL_MARKERS` required digits or separators beyond its literal prefix
(``ORD-[0-9]{6}``, not ``2025-`` or ``page [0-9]``), and matches nothing in
:data:`BENIGN_REFERENCE_TEXT` (which includes generated ordinary forms: years, ``noun N``,
``#1234``, ``mailto:``, ``tel:``). A tenant registers at most
:data:`MAX_PATTERNS_PER_TENANT` patterns (:func:`validate_tenant_identifier_patterns`).
:class:`InMemoryOtherTenantIdentifiers` does this, and so does the directory's operator write
path (``TenantProvisioner.set_identifier_patterns``); the directory's source checks again on
read.
The scanner's own second line is per tenant, and its third is sharding: see
``CrossTenantScanner``.

:class:`OtherTenantIdentifiers` is the port. It reports a **version** and, for **every**
tenant, its RE2 patterns; the scanner keeps one compiled set of all of them and rebuilds it
only when the version changes, leaving the caller's own patterns out at match time (so the
caller's own identifiers pass). The real implementation is
:class:`~guardrail_engine.directory.DirectoryIdentifiers` (M3-01 wiring), which the engine uses
when its directory is a ``CachedTenantDirectory``; :class:`InMemoryOtherTenantIdentifiers`
serves tests and embedders that hold the identifiers themselves.
:class:`NoOtherTenantIdentifiers` is the default for anything else (the in-memory directory): it
scans for nothing, so **the scan does nothing unless the engine's directory, or the composition
root, supplies a source**.

A source that raises fails the check closed (``internal_error``): a floor scan that can't run
must not become a silent allow. A tenant whose patterns don't compile is another matter: it
is dropped from the scan and alerted on, and the other tenants' checks go on (see the scanner).
"""

from __future__ import annotations

import re
from collections.abc import Hashable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Protocol

from guardrail_engine.deterministic.regex import RegexEngine, RegexError, default_regex_engine
from guardrail_engine.tenant_ids import is_valid_tenant_id

_RE2_SPECIAL = frozenset("\\.+*?()|[]{}^$")
_ID_BEFORE = "(?:^|[^0-9A-Za-z])"
_ID_AFTER = "(?:[^0-9A-Za-z]|$)"

IDENTIFIER_PATTERN_MAX_CHARS = 500
"""The longest identifier pattern a source may register (the same bound as a deny pattern)."""
MIN_LITERAL_PREFIX = 4
"""Characters of plain literal a registered pattern must start with (after any leading flags
and zero-width ``^`` / ``\\b``). A character that a quantifier follows doesn't count."""
MAX_PATTERNS_PER_TENANT = 20
"""Registered patterns one tenant may hold (its id pattern, which the platform adds, isn't
counted). Bounds what one tenant adds to the combined compiled set."""
MAX_REPEAT = 64
"""The largest repeat count a registered pattern may use. A counted repeat
``{n,m}`` needs ``m`` at most this, ``{n}`` and ``{n,}`` need ``n`` at most this, and nested
repeats multiply (``(?:x{9}){9}`` is 81). Identifiers are short, and a pattern like
``[0-9a-z]{1,1000}-[0-9a-z]{1,1000}`` is what makes the combined set too big to compile."""
MAX_REPEAT_WEIGHT = 128
"""The most the repeats of one pattern may add up to: the sum, over the pattern's
top-level atoms, of how many copies of itself each can expand to. :data:`MAX_REPEAT` bounds one
repeat; twenty of them in a row (``ORD-`` and 20 x ``[0-9a-z]{1,64}-``) are what made a
rebuild of 100 tenants take 5 s. ``ORD-[0-9]{6,10}`` weighs 10."""
MIN_TAIL_MARKERS = 4
"""Digit or separator characters a registered pattern must require **beyond** its literal
prefix: ``ORD-[0-9]{6}`` requires 6, ``2025-`` and ``(?i)page [0-9]`` require none or
one, and would match ordinary text in every other tenant's content. A class like ``[A-Z0-9]``
doesn't count: a match may hold no digit."""
SEPARATORS = "-_/:#."
"""The punctuation that, like a digit, makes a pattern an identifier and not a word."""

BENIGN_REFERENCE_TEXT = """\
Good morning, and thank you for writing. The meeting is on Tuesday, 14 March 2023, at 10:30 in
the main office, and the notes from last week are attached. Please let me know if the time does
not suit you. We have 12 people coming, about 3 of them from the north, and the budget for the
project is 4,500 dollars, which is a little more than the 3,900 we spent in 2021. The report
runs to 27 pages and 5 sections. In the first section we describe what we did and why; in the
second, how the work was carried out between 2022-01-10 and 2022-06-30; in the third, what we
found. The results were better than expected: 98 percent of the items were delivered on time,
and 1 in 40 had to be sent again. The next steps are to review the figures, to write the
summary, and to send everything to the board by the 1st of April. If you have any questions
about the order of events, call 555 0142 or write to the team at any time. Thanks again, and
have a lovely week. Monday 2024-02-05, Friday 31/12/1999, 7 June, April 3rd, 12:00, 00:15.
The quick brown fox jumps over the lazy dog. A total of 1234567 items, 0.5 of them damaged.
"""
"""Ordinary English with digits, dates and times. A registered identifier pattern that matches
anything in it would match ordinary text, so it is refused."""

COMMON_WORDS = (
    # the commonest English words
    "the be to of and a in that have it for not on with he as you do at this but his by from "
    "they we say her she or an will my one all would there their what so up out if about who "
    "get which go me when make can like time no just him know take people into year your good "
    "some could them see other than then now look only come its over think also back after use "
    "two how our work first well way even new want because any these give day most us "
    "is are was were been being has had does did done said made went got put "
    "here where why while still every each both few more many much such very too own same "
    "before again under between through during without within against around "
    # business, support and web words
    "account accounts customer customers client clients user users member members invoice "
    "invoices bill billing payment payments pay paid price prices cost costs total amount "
    "balance refund refunds return returns order orders purchase purchases shipping delivery "
    "address phone email mail message messages ticket tickets request requests support help "
    "service services product products item items cart checkout card credit debit bank "
    "company business team manager office department project projects report reports meeting "
    "meetings notes document documents file files page pages site website link links click "
    "login logout password username profile settings update updates status active inactive "
    "pending open closed complete completed failed error errors warning success result "
    "results data info information details summary description title name names number "
    "numbers date dates today tomorrow yesterday monday tuesday wednesday thursday friday "
    "saturday sunday january february march april may june july august september october "
    "november december hello hi dear regards thanks thank please sorry welcome yes no ok "
    "http https ftp www com org net edu gov html json xml api url uri app "
    "http:// https:// ftp:// www. .com .org .net .edu .io .co.uk "
    "@gmail.com @yahoo.com @outlook.com @hotmail.com @example.com @example.org "
    "e-mail log-in sign-in sign-up follow-up well-known up-to-date real-time "
    "https://www.example.com/help http://example.com/index.html"
)
"""Common English, business and web words and fragments (``http``, ``https://``, ``www.``,
``@gmail.com``), added to the reference text a pattern is matched against."""

_ORDINARY_NOUNS = (  # noqa: SIM905
    "page step room order invoice item section chapter figure table line row ticket case floor "
    "unit apt suite version level week day article paragraph part volume appendix exhibit "
    "schedule form box lot seat gate flight track bus route platform building block plot "
    "number no ref reference id code serial model type grade rev revision draft"
).split()


_NUMBER_LEAD_WORDS = (  # noqa: SIM905
    "year since copyright copyrighted circa about around over under nearly roughly approx "
    "from until before after during by in on at for of to as dated due issued created updated "
    "expires expired born established founded est inc room suite apt apartment unit floor "
    "invoice order bill receipt ticket case claim policy account ref reference confirmation "
    "page pages step steps section chapter figure table version release build rev revision "
    "number no code pin zip postcode phone tel fax call mobile cell extension ext amount "
    "total balance price cost fee rate tax usd eur gbp dollars euros pounds"
).split()
_DATE_LEAD_WORDS = (  # noqa: SIM905
    "date: dated on from until by as of updated created issued due expires born since "
    "last first next today yesterday monday friday 1st"
).split()


def _ordinary_forms() -> str:
    """Generated ordinary text: years with ``-`` and ``/``, dates, a common noun
    followed by 1 to 99, ``#1234``, and the stock prefixes of contact details."""
    years = " ".join(f"{y}- {y}/ {y}-01-15 {y}/12/31" for y in range(1990, 2100))
    numbered = " ".join(f"{noun} {n} {noun} #{n} {noun}-{n} {noun}: {n}"
                        for noun in _ORDINARY_NOUNS for n in range(1, 100))  # fmt: skip
    hashes = " ".join(f"#{n}" for n in (1, 12, 123, 1234, 12345, 123456))
    words = [
        w for w in (*COMMON_WORDS.split(), *_ORDINARY_NOUNS, *_NUMBER_LEAD_WORDS) if w.isalpha()
    ]
    counts = ("1234", "5678", "2024", "12345", "123456", "000123")
    worded = " ".join(
        f"{w} {n} {w} #{n} {w}: {n}" for w in dict.fromkeys(words) for n in counts
    )  # "the 1234", "since 2024", "invoice #123456"
    phones = " ".join(
        f"{lead} {shape}"
        for lead in ("phone:", "tel:", "fax:", "call", "mobile:", "cell:", "ph.", "")
        for shape in (
            "555-123-4567", "(555) 123-4567", "555.123.4567", "+1 555 123 4567",
            "+44 20 7946 0958", "555 123 4567", "5551234567",
        )
    )  # fmt: skip
    dates = " ".join(
        f"{lead} {shape}"
        for lead in _DATE_LEAD_WORDS
        for shape in (
            "2024-05-06", "2024/05/06", "05/06/2024", "06-05-2024", "06.05.2024",
            "2024-05-06T10:30:15Z", "10:30:15", "2024-05", "20240506",
        )
    )  # fmt: skip
    addresses = " ".join(
        f"{lead}{shape}"
        for lead in ("http://", "https://", "ip: ", "host ", "")
        for shape in (
            "192.168.1.1",
            "10.0.0.1",
            "127.0.0.1:8080",
            "172.16.254.1",
            "8.8.8.8",
            "255.255.255.0",
            "1.2.3.4",
            "192.168.100.100",
            "10.100.100.100",
            "255.255.255.255",
            "192.168.001.001",
            "100.100.100.100",
        )
    )
    contact = (
        "mailto: tel: fax: ref: phone: cell: mobile: call: ext: ext. 1-800-555-0100 "
        "1-888-555-0199 +1 555 0100 (555) 555-0100 555-0100 ISO 9001 ISO 27001 RFC 2119 "
        "ISO/IEC 27001 IEEE 802.11 version 2.0.1 v1.2.3 24/7 9-5 3-4 10-15 2-3 5-10"
    )
    return "\n".join((years, numbered, hashes, contact, worded, phones, dates, addresses))


_BENIGN_HAYSTACK = "\n".join(
    (
        BENIGN_REFERENCE_TEXT,
        COMMON_WORDS,
        COMMON_WORDS.upper(),
        COMMON_WORDS.title(),
        BENIGN_REFERENCE_TEXT.upper(),
        _ordinary_forms(),
        _ordinary_forms().upper(),
    )
)
"""What a pattern is tried against: the reference text and the word list as written, in upper
case and in title case, so a case-sensitive ``Account`` is caught as ``account`` is."""

_LEADING_ZERO_WIDTH = re.compile(r"(?:\(\?[imsU-]+\)|\\[bB]|\^)*")
_QUANTIFIERS = "*+?{"

REASON_TOO_LONG = "too_long"
REASON_INVALID = "invalid_regex"
REASON_EMPTY_MATCH = "empty_match"
REASON_ALTERNATION = "alternation"
REASON_SHORT_PREFIX = "short_literal_prefix"
REASON_BENIGN_MATCH = "matches_benign_text"
REASON_REPEAT = "repeat_too_large"
REASON_NO_MARKER = "no_digit_or_separator"
REASON_FEW_MARKERS = "too_few_digits_or_separators"
REASON_TOO_MANY = "too_many_patterns"


class IdentifierPatternError(ValueError):
    """A pattern isn't acceptable as a registered identifier pattern. ``reason`` is one of the
    ``REASON_*`` codes; the message never quotes the pattern."""

    def __init__(self, reason: str, message: str) -> None:
        self.reason = reason
        super().__init__(f"{reason}: {message}")


def literal_prefix(pattern: str) -> str:
    """The plain literal text ``pattern`` starts with, after any leading flag groups
    (``(?i)``) and zero-width ``^``, ``\\b``, ``\\B``: text every match must begin with (after
    those). An escaped punctuation character (``\\-``) is one literal (``-``); a character
    followed by a quantifier is left out (it may repeat or be absent), and the prefix stops
    at the first metacharacter."""
    match = _LEADING_ZERO_WIDTH.match(pattern)
    i = match.end() if match else 0
    chars: list[str] = []
    while i < len(pattern):
        ch = pattern[i]
        if ch == "\\":
            if i + 1 >= len(pattern) or pattern[i + 1].isalnum():
                break  # \d, \w, \pL, \n ...: a class or an escape, not a plain character
            width = 2
            ch = pattern[i + 1]
        elif ch in _RE2_SPECIAL:
            break
        else:
            width = 1
        if i + width < len(pattern) and pattern[i + width] in _QUANTIFIERS:
            break
        chars.append(ch)
        i += width
    return "".join(chars)


def literal_prefix_length(pattern: str) -> int:
    """How many plain literal characters ``pattern`` starts with (see :func:`literal_prefix`)."""
    return len(literal_prefix(pattern))


def _is_marker(ch: str) -> bool:
    """A digit or a separator (:data:`SEPARATORS`): what an identifier has and a word hasn't."""
    return ch in SEPARATORS or "0" <= ch <= "9"


_COUNTED_REPEAT = re.compile(r"\{(\d+)(?:(,)(\d*))?\}")
_GROUP_HEADER = re.compile(r"\(\?(?:P?<[^>]*>|[a-zA-Z-]*:)")
_FLAG_GROUP = re.compile(r"\(\?[a-zA-Z-]*\)")
_MARKER_CLASS_BODY = re.compile(r"-?(?:\\d|\\[_/:#.-]|[0-9]-[0-9]|[0-9]|[_/:#.])*-?")
"""The inside of a class every member of which is a digit or a separator: ``0-9``, ``\\d``,
``-_`` ... A ``-`` counts only first or last, where it is a character and not a range (in
``[#--]`` it is the range ``#`` to ``-``, which holds ``$`` and ``,``)."""


@dataclass(slots=True)
class _Atom:
    literal: bool  # one plain, unrepeated character: repeating it costs nothing
    weight: int  # how many copies of itself the repeats around it can expand to
    marker: bool  # every match of it holds a digit or a separator
    top: bool  # stands outside every group
    count: int = 1  # the fewest times it occurs in a match


def _escape_end(pattern: str, i: int) -> int:
    """The index after the escape that starts at ``pattern[i]`` (a backslash)."""
    nxt = pattern[i + 1 : i + 2]
    if nxt in ("p", "P", "x") and pattern[i + 2 : i + 3] == "{":
        close = pattern.find("}", i + 3)
        return len(pattern) if close < 0 else close + 1
    if nxt in ("p", "P"):
        return i + 3  # \pL
    if nxt == "x":
        return i + 4  # \x41
    return i + 2


def _class_end(pattern: str, i: int) -> int:
    """The index after the character class that starts at ``pattern[i]`` (a ``[``), or -1."""
    j = i + 1
    if pattern[j : j + 1] == "^":
        j += 1
    if pattern[j : j + 1] == "]":
        j += 1
    while j < len(pattern):
        if pattern[j] == "\\":
            j += 2
        elif pattern.startswith("[:", j) and pattern.find(":]", j + 2) >= 0:
            j = pattern.find(":]", j + 2) + 2
        elif pattern[j] == "]":
            return j + 1
        else:
            j += 1
    return -1


_REFUSED = (False, False, 0, 0)


def analyse_repeats(pattern: str) -> tuple[bool, bool]:
    """``(repeats_ok, needs_marker)``: see :func:`_analyse`."""
    ok, needs_marker, _, _ = _analyse(pattern)
    return ok, needs_marker


def _analyse(pattern: str) -> tuple[bool, bool, int, int]:
    """``(repeats_ok, needs_marker, marker_count, weight)`` for an RE2 pattern that already
    compiles. One pass over the tokens, no syntax tree.

    ``repeats_ok`` is false when a repeat count is over :data:`MAX_REPEAT` (``m`` of
    ``{n,m}``, ``n`` of ``{n}`` and ``{n,}``), when nested repeats multiply to more than that,
    or when an unbounded repeat (``*``, ``+``, ``{n,}``) follows anything but one plain
    character: a class, ``.``, an escape like ``\\d``, a group or an already repeated atom.
    Those are what blow up the compiled set; a repeated plain character costs one state.
    ``\\Q..\\E`` is refused outright.

    ``needs_marker`` is true when some top-level atom that must occur at least once is a digit,
    a separator, ``\\d`` or a class made only of those, so every match holds one
    (``ORDER[0-9]{6}``). Atoms inside a group don't count: an alternation may skip them.

    ``marker_count`` is how many digits and separators the top-level atoms make every match hold
    (``ORD-[0-9]{6}`` holds 7: the ``-`` and six digits). ``weight`` is the sum of the weights of
    the top-level atoms that repeat; over :data:`MAX_REPEAT_WEIGHT` the pattern is refused
    (``repeats_ok`` false) as well."""
    stack: list[int] = []  # the weight so far of each enclosing frame, outermost first
    frame = 0  # the sum of the weights of the repeating atoms in the current frame
    last: _Atom | None = None
    top_atoms: list[_Atom] = []
    after_quantifier = False
    i = 0
    n = len(pattern)

    def new_atom(literal: bool, marker: bool) -> _Atom:
        nonlocal last, after_quantifier
        atom = _Atom(literal, 1, marker, not stack)
        last = atom
        after_quantifier = False
        if atom.top:
            top_atoms.append(atom)
        return atom

    while i < n:
        ch = pattern[i]
        if ch == "\\":
            nxt = pattern[i + 1 : i + 2]
            if nxt in ("Q", "E"):
                return _REFUSED
            if nxt == "d":
                new_atom(False, True)
            elif nxt and not nxt.isalnum():
                new_atom(True, _is_marker(nxt))
            else:
                new_atom(False, False)
            i = _escape_end(pattern, i)
        elif ch == "[":
            end = _class_end(pattern, i)
            if end < 0:
                return _REFUSED
            body = pattern[i + 1 : end - 1]
            marker = bool(body) and _MARKER_CLASS_BODY.fullmatch(body) is not None
            new_atom(False, marker)
            i = end
        elif ch == "(":
            flags = _FLAG_GROUP.match(pattern, i)
            if flags:
                i = flags.end()
                continue  # flags only: no atom, so nothing for a repeat to bind to
            header = _GROUP_HEADER.match(pattern, i)
            stack.append(frame)
            frame = 0
            last = None
            after_quantifier = False
            i = header.end() if header else i + 1
        elif ch == ")":
            if not stack:
                return _REFUSED
            inner = frame  # a group weighs the sum of what repeats inside it, not the largest
            frame = stack.pop()
            group = new_atom(False, False)
            group.weight = max(1, inner)
            if group.weight > 1:
                frame += group.weight
            i += 1
        elif ch in "*+?{":
            counted = _COUNTED_REPEAT.match(pattern, i) if ch == "{" else None
            if ch == "{" and counted is None:
                new_atom(True, False)  # a brace that isn't a repeat is a plain character
                i += 1
                continue
            if ch == "?" and after_quantifier:
                i += 1  # lazy: the modifier of the repeat before it
                continue
            if last is None:
                return _REFUSED
            high: int | None
            if counted:
                low = int(counted.group(1))
                if counted.group(2) is None:
                    high = low
                else:
                    high = int(counted.group(3)) if counted.group(3) else None
                i = counted.end()
            else:
                low, high = {"*": (0, None), "+": (1, None), "?": (0, 1)}[ch]
                i += 1
            if high is None and not last.literal:
                return _REFUSED  # unbounded, and not after one plain character
            bound = max(low if high is None else high, 1)
            if bound > MAX_REPEAT or last.weight * bound > MAX_REPEAT:
                return _REFUSED
            before = last.weight
            last.weight *= bound
            frame += (last.weight if last.weight > 1 else 0) - (before if before > 1 else 0)
            last.count *= low
            last.literal = False
            last.marker = last.marker and low >= 1
            after_quantifier = True
        elif ch in ".^$":
            new_atom(False, False)  # any character, or zero-width: never a plain literal
            i += 1
        elif ch == "|":
            last = None  # a new branch: nothing before it for a repeat to bind to
            after_quantifier = False
            i += 1
        else:
            new_atom(True, _is_marker(ch))
            i += 1
    if stack:
        return _REFUSED
    weight = sum(atom.weight for atom in top_atoms if atom.weight > 1)
    if weight > MAX_REPEAT_WEIGHT:
        return _REFUSED
    markers = sum(atom.count for atom in top_atoms if atom.marker)
    return True, any(atom.marker for atom in top_atoms), markers, weight


def _has_top_level_alternation(pattern: str) -> bool:
    """Whether a ``|`` stands outside every group and character class: then the literal
    prefix would bind only one branch."""
    depth = 0
    in_class = False
    i = 0
    while i < len(pattern):
        ch = pattern[i]
        if ch == "\\":
            i += 2
            continue
        if in_class:
            in_class = ch != "]"
        elif ch == "[":
            in_class = True
            if pattern[i + 1 : i + 2] == "^":
                i += 1
            if pattern[i + 1 : i + 2] == "]":
                i += 1
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        elif ch == "|" and depth == 0:
            return True
        i += 1
    return False


def validate_identifier_pattern(pattern: str, engine: RegexEngine | None = None) -> None:
    """Raise :class:`IdentifierPatternError` unless ``pattern`` may be registered as a
    tenant's identifier pattern. Every source implementation must call this for each
    pattern it accepts. Checks, in order: within the length cap; compiles under RE2; doesn't
    match the empty string; no top-level alternation; a literal prefix of at least
    :data:`MIN_LITERAL_PREFIX` characters; small repeats (:func:`analyse_repeats`);
    no match anywhere in :data:`BENIGN_REFERENCE_TEXT` or :data:`COMMON_WORDS`; and a digit or
    separator in every match, at least :data:`MIN_TAIL_MARKERS` of them beyond the
    literal prefix, and the repeats add up to at most :data:`MAX_REPEAT_WEIGHT`.

    **How "a digit or separator in every match" is proved** (no sampling): either the literal
    prefix (:func:`literal_prefix`, text every match begins with) holds a digit or one of
    :data:`SEPARATORS`, or a top-level atom that must occur at least once is one (a digit, a
    separator, ``\\d``, or a class of only those: ``ORDER[0-9]{6}``). ``account``,
    ``(?i)your`` and ``(?:A|B)[a-z]{4}`` have neither and are refused. A word with a separator
    in it (``https://``, ``@gmail.com``) is caught by the word list instead."""
    if not isinstance(pattern, str):
        raise IdentifierPatternError(REASON_INVALID, "not text")
    if len(pattern) > IDENTIFIER_PATTERN_MAX_CHARS:
        raise IdentifierPatternError(
            REASON_TOO_LONG,
            f"{len(pattern)} characters; the limit is {IDENTIFIER_PATTERN_MAX_CHARS}",
        )
    try:
        compiled = (engine or default_regex_engine()).compile(pattern)
    except RegexError as e:
        raise IdentifierPatternError(REASON_INVALID, "not valid RE2") from e
    if compiled.search(""):
        raise IdentifierPatternError(REASON_EMPTY_MATCH, "matches the empty string")
    if _has_top_level_alternation(pattern):
        raise IdentifierPatternError(REASON_ALTERNATION, "a top-level | needs a group")
    if literal_prefix_length(pattern) < MIN_LITERAL_PREFIX:
        raise IdentifierPatternError(
            REASON_SHORT_PREFIX,
            f"must start with at least {MIN_LITERAL_PREFIX} literal characters",
        )
    repeats_ok, class_marker, markers, _ = _analyse(pattern)
    if not repeats_ok:
        raise IdentifierPatternError(
            REASON_REPEAT,
            f"a repeat is over {MAX_REPEAT}, the repeats add up to more than "
            f"{MAX_REPEAT_WEIGHT}, or one is unbounded after something other than one plain "
            "character",
        )
    if compiled.search(_BENIGN_HAYSTACK):
        raise IdentifierPatternError(REASON_BENIGN_MATCH, "matches ordinary text")
    prefix = literal_prefix(pattern)
    if not (class_marker or any(_is_marker(ch) for ch in prefix)):
        raise IdentifierPatternError(
            REASON_NO_MARKER, "every match must hold a digit or one of " + SEPARATORS
        )
    if markers - sum(_is_marker(ch) for ch in prefix) < MIN_TAIL_MARKERS:
        raise IdentifierPatternError(
            REASON_FEW_MARKERS,
            f"after its literal start, every match must hold at least {MIN_TAIL_MARKERS} "
            "digits or separators (ORD-[0-9]{6}, not 2025- or page [0-9])",
        )


def validate_tenant_identifier_patterns(
    patterns: Sequence[str], engine: RegexEngine | None = None
) -> None:
    """Raise :class:`IdentifierPatternError` unless ``patterns`` may be one tenant's whole
    set: at most :data:`MAX_PATTERNS_PER_TENANT` of them, each passing
    :func:`validate_identifier_pattern`. The tenant's own id pattern isn't among them. Every
    source implementation must call this with the tenant's complete list."""
    if len(patterns) > MAX_PATTERNS_PER_TENANT:
        raise IdentifierPatternError(
            REASON_TOO_MANY,
            f"{len(patterns)} patterns; the limit is {MAX_PATTERNS_PER_TENANT} per tenant",
        )
    for pattern in patterns:
        validate_identifier_pattern(pattern, engine)


def literal_pattern(text: str) -> str:
    """An RE2 pattern that matches ``text`` exactly."""
    return "".join("\\" + ch if ch in _RE2_SPECIAL else ch for ch in text)


def tenant_id_pattern(tenant_id: str) -> str:
    """The pattern for a tenant id: the id, in any letter case, not part of a longer
    alphanumeric run (``t_acme`` is found in ``see t_acme_orders`` but not in ``t_acmeco``).
    Built by the platform from a valid tenant id, so it isn't subject to
    :func:`validate_identifier_pattern`."""
    return f"(?i){_ID_BEFORE}{literal_pattern(tenant_id)}{_ID_AFTER}"


class OtherTenantIdentifiers(Protocol):
    """Where the cross-tenant scan gets its patterns: every tenant's, with a version."""

    async def version(self) -> Hashable:
        """Changes whenever any tenant's patterns (or the set of tenants) change. Called on
        every ``tool_result`` and ``output`` check, so it must be cheap (a counter, an etag).
        The scanner rebuilds its compiled set only when this differs from the last one it
        built from. May raise if its backing store is unavailable: the check then fails
        closed."""
        ...

    async def patterns_by_tenant(self) -> Mapping[str, Sequence[str]]:
        """Each tenant's RE2 identifier patterns, keyed by tenant id: the tenant's id pattern
        (:func:`tenant_id_pattern`) and its registered patterns, **the caller's included**
        (the scanner leaves the caller's own out at match time). Every registered pattern
        must have passed :func:`validate_identifier_pattern`. Called only when ``version()``
        has changed. May raise: the check then fails closed."""
        ...


class NoOtherTenantIdentifiers:
    """Scans for nothing. The default until a real source is wired (after M2-01)."""

    async def version(self) -> Hashable:
        return 0

    async def patterns_by_tenant(self) -> Mapping[str, Sequence[str]]:
        return {}


class InMemoryOtherTenantIdentifiers:
    """Identifiers held in memory, for tests. Every tenant registered here is "another
    tenant" to everyone else: its id (``include_tenant_ids``) and its own patterns, each
    validated by :func:`validate_identifier_pattern` when it is registered."""

    def __init__(
        self,
        patterns: Mapping[str, Iterable[str]] | None = None,
        *,
        include_tenant_ids: bool = True,
        engine: RegexEngine | None = None,
    ) -> None:
        self._patterns: dict[str, tuple[str, ...]] = {}
        self._include_ids = include_tenant_ids
        self._engine = engine
        self._version = 0
        for tenant_id, own in (patterns or {}).items():
            self.register(tenant_id, *own)

    def register(self, tenant_id: str, *patterns: str) -> None:
        """Add a tenant (and its identifier patterns). Registers the tenant even with none.
        Raises :class:`IdentifierPatternError` for a pattern that isn't acceptable, or when
        the tenant would hold more than :data:`MAX_PATTERNS_PER_TENANT`, and registers
        nothing then."""
        if not is_valid_tenant_id(tenant_id):
            raise ValueError(f"not a tenant id: {tenant_id!r}")
        validate_tenant_identifier_patterns(
            (*self._patterns.get(tenant_id, ()), *patterns), self._engine
        )
        self._patterns[tenant_id] = (*self._patterns.get(tenant_id, ()), *patterns)
        self._version += 1

    def remove(self, tenant_id: str) -> None:
        self._patterns.pop(tenant_id, None)
        self._version += 1

    async def version(self) -> Hashable:
        return self._version

    async def patterns_by_tenant(self) -> Mapping[str, Sequence[str]]:
        return {
            tenant_id: ((tenant_id_pattern(tenant_id), *own) if self._include_ids else own)
            for tenant_id, own in sorted(self._patterns.items())
        }
