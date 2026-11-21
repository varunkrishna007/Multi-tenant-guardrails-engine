"""What the identifier-pattern validator refuses beyond the basic pattern checks.

A tenant holds at most 20 patterns, every repeat count is at most 64, and an unbounded
repeat is allowed only after one plain character. Every match must hold a digit or a
separator, so a common word (``account``, ``(?i)your``, ``https://``) is refused.
"""

from __future__ import annotations

import pytest

from guardrail_engine.deterministic import (
    COMMON_WORDS,
    MAX_PATTERNS_PER_TENANT,
    MAX_REPEAT,
    IdentifierPatternError,
    InMemoryOtherTenantIdentifiers,
    validate_identifier_pattern,
    validate_tenant_identifier_patterns,
)
from guardrail_engine.deterministic.adapters.google_re2 import Re2RegexEngine
from guardrail_engine.deterministic.identifiers import (
    REASON_BENIGN_MATCH,
    REASON_FEW_MARKERS,
    REASON_NO_MARKER,
    REASON_REPEAT,
    REASON_TOO_MANY,
    analyse_repeats,
    literal_prefix,
)

ENGINE = Re2RegexEngine()


def reason_of(pattern: str) -> str:
    with pytest.raises(IdentifierPatternError) as refused:
        validate_identifier_pattern(pattern, ENGINE)
    return refused.value.reason


# ------------------------------------------------------------------ the cap per tenant


def test_the_cap_is_twenty_patterns_per_tenant():
    assert MAX_PATTERNS_PER_TENANT == 20 and MAX_REPEAT == 64


def test_twenty_patterns_are_fine_and_a_twenty_first_is_refused():
    twenty = [f"ORD{n}-[0-9]{{4}}" for n in range(20)]
    validate_tenant_identifier_patterns(twenty, ENGINE)
    with pytest.raises(IdentifierPatternError) as refused:
        validate_tenant_identifier_patterns([*twenty, "ORD99-[0-9]{4}"], ENGINE)
    assert refused.value.reason == REASON_TOO_MANY


async def test_a_tenant_over_the_cap_is_refused_at_registration_and_nothing_is_registered():
    source = InMemoryOtherTenantIdentifiers({"t_a": ["ALP-[0-9]{4}"]}, engine=ENGINE)
    with pytest.raises(IdentifierPatternError) as refused:
        source.register("t_b", *[f"BET{n}-[0-9]{{4}}" for n in range(21)])
    assert refused.value.reason == REASON_TOO_MANY
    with pytest.raises(IdentifierPatternError):
        InMemoryOtherTenantIdentifiers({"t_c": [f"GAM{n}-[0-9]{{4}}" for n in range(21)]})
    assert (await source.patterns_by_tenant()).keys() == {"t_a"}


async def test_the_cap_counts_what_the_tenant_already_holds():
    source = InMemoryOtherTenantIdentifiers(engine=ENGINE)
    source.register("t_a", *[f"ALP{n}-[0-9]{{4}}" for n in range(15)])
    source.register("t_a", *[f"ALQ{n}-[0-9]{{4}}" for n in range(5)])  # exactly 20
    with pytest.raises(IdentifierPatternError) as refused:
        source.register("t_a", "ALR-[0-9]{4}")
    assert refused.value.reason == REASON_TOO_MANY
    assert len((await source.patterns_by_tenant())["t_a"]) == 21  # 20 plus the id pattern


def test_the_refusal_for_too_many_never_quotes_a_pattern():
    with pytest.raises(IdentifierPatternError) as refused:
        validate_tenant_identifier_patterns(["SECRET-[0-9]{4}"] * 21, ENGINE)
    assert "SECRET" not in str(refused.value)


# ------------------------------------------------------------------ repeats


@pytest.mark.parametrize(
    "pattern",
    [
        "ORD-[0-9]+",
        "ORD-[0-9]*",
        "ORD-[0-9a-z]{4,}",
        "ORD-.+",
        "ORD-.*",
        r"ORD-\d+",
        r"ORD-\w*",
        r"ORD-\pL+",
        "ORD-(?:[0-9])+",
        "ORD-(?:[0-9]{2})*",
        "ORD-[0-9]+?",  # lazy is still unbounded
        "ORD-[0-9]{1,}",
        "ORD-[0-9]{2,}-1",
        "ORD-[0-9]{1,1000}",
        "ORD-[0-9]{1,65}",
        "ORD-[0-9]{65}",
        "ORD-[0-9]{0,200}-[0-9]{1,200}",
        r"Q000[0-9a-z]{1,1000}-[0-9a-z]{1,1000}",  # the probe for repeat counts
        "ORD-(?:[0-9]{9}){9}",  # nested repeats multiply to 81
        "ORD-(?:(?:[0-9]{5}){5}){3}",  # 75
        r"ORD-\Q12\E",
    ],
)
def test_an_unbounded_or_oversized_repeat_is_refused(pattern):
    assert reason_of(pattern) == REASON_REPEAT


@pytest.mark.parametrize(
    "pattern",
    [
        "ORD-[0-9]{4,64}",
        "ORD-[0-9]{64}",
        "ORD-[0-9]{4}[0-9]{0,60}",
        "ORD-[0-9]{6,10}",
        "ORD-[0-9]{4}(?:[0-9]{8}){8}",  # 64 in the group
        "ORD-[0-9]{4}(?:[0-9]{2}-){4}",
        "ORD-[0-9]{64}-[0-9]{64}",  # separate repeats don't multiply
        "ORD-[0-9]{4}[0-9]?",
        "ORD-(?:A|B)?[0-9]{4}",
        "ORD-[0-9]{4}1+",  # one plain character: costs one state however often it repeats
        "ORD-[0-9]{4}1*",
        "ORD-[0-9]{4}1{2,}",
        r"ORD-[0-9]{4}\-+1",
        r"ORD-[0-9]{4}\.*1",
        "ORD-[0-9]{4}x{3}-1",
        "ORDE-{-[0-9]{4}",  # a brace that isn't a repeat is a plain character
    ],
)
def test_a_small_bounded_repeat_and_a_repeat_of_one_plain_character_are_accepted(pattern):
    validate_identifier_pattern(pattern, ENGINE)


def test_the_repeat_check_is_not_fooled_by_a_class_that_holds_brackets_or_escapes():
    assert analyse_repeats(r"ORDE[]a]+") == (False, False)
    assert analyse_repeats(r"ORDE[^]a]{3}") == (True, False)
    assert analyse_repeats(r"ORDE[[:alpha:]]+") == (False, False)
    assert analyse_repeats(r"ORDE[\]]+") == (False, False)
    assert analyse_repeats(r"ORDE\++") == (True, False)  # an escaped plus, repeated: a literal
    assert analyse_repeats(r"ORDE\p{Greek}{3}") == (True, False)
    assert analyse_repeats(r"ORDE\p{Greek}+") == (False, False)
    assert analyse_repeats(r"ORDE\x{41}{70}") == (False, False)


def test_a_repeat_hidden_in_a_group_is_still_seen():
    assert analyse_repeats("ORD-(a|[0-9]+)") == (False, False)
    assert analyse_repeats("ORD-(?i:[0-9]+)") == (False, False)
    assert analyse_repeats("ORD-(?P<n>[0-9]+)") == (False, False)
    assert analyse_repeats("ORD-(?:x|[0-9]{70})") == (False, False)
    assert analyse_repeats("ORD-(?:x|[0-9]{7})") == (True, True)


def test_the_repeat_refusal_never_quotes_the_pattern():
    with pytest.raises(IdentifierPatternError) as refused:
        validate_identifier_pattern("SECRET-[0-9]+", ENGINE)
    assert "SECRET" not in str(refused.value)


# ------------------------------------------------------------------ words


@pytest.mark.parametrize(
    "word",
    [
        "account",
        "customer",
        "invoice",
        "refund",
        "(?i)your",
        "http",
        "https://",
        "@gmail.com",
        "(?i)account",
        "Account",
        "ACCOUNT",
        "(?i)customer",
        "(?i)https?://",
        "https?://",
        "(?i)www\\.",
        "@yahoo\\.com",
        "(?i)e-mail",
        "(?i)refund",
        "Invoice",
    ],
)
def test_a_common_word_is_refused_at_registration(word):
    with pytest.raises(IdentifierPatternError):
        validate_identifier_pattern(word, ENGINE)
    source = InMemoryOtherTenantIdentifiers({"t_a": ["ALP-[0-9]{4}"]}, engine=ENGINE)
    with pytest.raises(IdentifierPatternError):
        source.register("t_b", word)


@pytest.mark.parametrize(
    ("pattern", "reason"),
    [
        ("account", REASON_BENIGN_MATCH),  # it is in the word list
        ("(?i)your", REASON_BENIGN_MATCH),
        ("https://", REASON_BENIGN_MATCH),  # has separators, but it is in the list
        ("@gmail.com", REASON_BENIGN_MATCH),
        ("zebras", REASON_NO_MARKER),  # not in any list: no digit or separator
        ("(?i)Quartz", REASON_NO_MARKER),
        ("Quartz[a-z]{4}", REASON_NO_MARKER),
        ("Quartz(?:[0-9]|-)", REASON_NO_MARKER),  # inside a group: may be skipped
        ("Quartz[a-z0-9]{4}", REASON_NO_MARKER),  # a class that can match a letter only
        ("Quartz[0-9]?", REASON_NO_MARKER),  # optional
        ("Quartz[0-9]{0,4}", REASON_NO_MARKER),
        ("Quartz[^a-z]{3}", REASON_NO_MARKER),  # negated: any non-letter, even a space
        ("Quartz[#--]{3}", REASON_NO_MARKER),  # the range # to -, which holds $ and ,
        ("Quartz.{3}", REASON_NO_MARKER),
        ("Quartz\\w{3}", REASON_NO_MARKER),
    ],
)
def test_a_pattern_with_no_digit_or_separator_in_every_match_is_refused(pattern, reason):
    assert reason_of(pattern) == reason


@pytest.mark.parametrize(
    "pattern",
    [
        "Quartz-1",  # a separator in the literal prefix
        "Quartz_",
        "Quartz/",
        "Quartz:",
        "Quartz#",
        r"Quartz\.",
        r"Quartz\-",
        "Quartz1",  # a digit in the prefix
        "(?i)^Quartz-[a-z]{4}",
        r"\bQuartz-[a-z]{4}",
        "Quartz[0-9]{3}",  # the digits come after the prefix, and are required
        "Quartz\\d{3}",
        "Quartz[-_]",
        "Quartz[0-9-]{2}",
        "Quartz[0-9_/:#.]{2}",
        "Quartz[a-z]{3}[0-9]",
        "Quartz[a-z]{3}-",
        "Quartz(?:A|B)[0-9]{2}",
        "Quartz(?:[a-z]{2}-)?[0-9]{4}",
    ],
)
def test_a_pattern_that_needs_a_digit_or_separator_passes_the_marker_proof(pattern):
    """Not refused for want of a marker; the tail rule has its own tests."""
    try:
        validate_identifier_pattern(pattern, ENGINE)
    except IdentifierPatternError as e:
        assert e.reason == REASON_FEW_MARKERS


def test_the_literal_prefix_is_the_text_every_match_starts_with():
    assert literal_prefix("(?i)^ORD-[0-9]{3}") == "ORD-"
    assert literal_prefix(r"\bTKT\.[0-9]") == "TKT."
    assert literal_prefix("ORDE?-1") == "ORD"
    assert literal_prefix("ab+cd") == "a"
    assert literal_prefix("(ORDER)-1") == ""


def test_the_word_list_holds_the_words_of_the_review_and_is_ordinary_text():
    for word in ("account", "customer", "invoice", "refund", "your", "http", "https://"):
        assert word in COMMON_WORDS
    assert "@gmail.com" in COMMON_WORDS
    assert COMMON_WORDS.isascii() and len(COMMON_WORDS.split()) > 200


@pytest.mark.parametrize(
    "pattern",
    [
        "ORD-[0-9]{6,10}",
        "ALP-ORD-[0-9]{4}",
        r"(?i)acct_[0-9]{8}",
        r"\bINV-[0-9]{5}",
        r"^TKT\.[0-9]{4,12}",
        "ORD-(?:A|B)[0-9]{4}",
        "CASE-[0-9]{4}-[A-Z]{3}",
        "ZX9-[0-9]{4}",
    ],
)
def test_real_identifier_shapes_are_still_accepted(pattern):
    validate_identifier_pattern(pattern, ENGINE)
