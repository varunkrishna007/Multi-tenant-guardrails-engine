"""The pattern side: generic structural patterns are refused, and the
repeats of one pattern may not add up to more than MAX_REPEAT_WEIGHT."""

import pytest

from guardrail_engine.deterministic import IdentifierPatternError, validate_identifier_pattern
from guardrail_engine.deterministic.adapters.google_re2 import Re2RegexEngine
from guardrail_engine.deterministic.identifiers import (
    MAX_REPEAT_WEIGHT,
    MIN_TAIL_MARKERS,
    REASON_BENIGN_MATCH,
    REASON_FEW_MARKERS,
    REASON_REPEAT,
)

ENGINE = Re2RegexEngine()


def reason_of(pattern: str) -> str:
    with pytest.raises(IdentifierPatternError) as refused:
        validate_identifier_pattern(pattern, ENGINE)
    return refused.value.reason


@pytest.mark.parametrize(
    "pattern",
    [
        "2025-",
        "(?i)page [0-9]",
        "(?i)step [0-9]",
        "(?i)room [0-9]",
        "(?i)mailto:",
        "(?i)tel: ",
        "(?i)ref: ",
        "(?i)invoice #",
        "(?i)order #[0-9]",
        "1-800-",
        "(?i)iso 9001",
    ],
)
def test_the_generic_patterns_from_the_review_are_refused(pattern):
    assert reason_of(pattern) in (REASON_BENIGN_MATCH, REASON_FEW_MARKERS)


@pytest.mark.parametrize(
    "pattern",
    [
        "(?i)zxqv [0-9]",  # nothing ordinary, but one digit after the prefix
        "Quartz-1",
        "Quartz-[0-9]{3}",
        "Quartz-[a-z]{8}",  # letters, not digits: a match need hold no marker beyond the prefix
        "Quartz-[0-9a-f]{8}",  # a class that may match a letter only
        "Quartz-2024-",  # digits in the literal prefix don't count towards it
        "Quartz-(?:[0-9]{4})",  # inside a group: may be skipped
        "Quartz-[0-9]{2}[0-9]?[0-9]?",  # optional atoms don't count
        "Quartz-[0-9]{0,8}",
    ],
)
def test_a_pattern_with_fewer_than_four_required_digits_after_its_prefix_is_refused(pattern):
    assert reason_of(pattern) == REASON_FEW_MARKERS


@pytest.mark.parametrize(
    "pattern",
    [
        "Quartz-[0-9]{4}",
        "Quartz-[0-9]{2}-[0-9]{2}",  # 2 + 1 + 2
        r"Quartz-\d{4}",
        r"Quartz-[0-9]{4,12}",
        "Quartz-[0-9]{2}[0-9]{2}",
        "Quartz-[0-9-]{4}",
        "Quartz[a-z]{3}-[0-9]{3}",
    ],
)
def test_a_pattern_with_four_required_digits_or_separators_after_its_prefix_is_accepted(pattern):
    assert MIN_TAIL_MARKERS == 4
    validate_identifier_pattern(pattern, ENGINE)


@pytest.mark.parametrize(
    "text",
    [
        "see page 12",
        "in the year 2025-",
        "step 3 of 9",
        "tel: 555 0100",
        "mailto: a@b.c",
        "call 1-800-555-0100",
        "ISO 9001 compliant",
        "invoice #1234",
        "Room 101",
        "ref: 77",
        "fax: 555",
        "order #45",
        "2031/06/01",
    ],
)
def test_the_haystack_holds_the_ordinary_forms_the_review_named(text):
    """A pattern that is literally one of these is refused as matching ordinary text."""
    from guardrail_engine.deterministic.identifiers import literal_pattern

    assert reason_of("(?i)" + literal_pattern(text)) in (REASON_BENIGN_MATCH, REASON_FEW_MARKERS)


def test_the_repeats_of_one_pattern_may_add_up_to_128_and_not_more():
    assert MAX_REPEAT_WEIGHT == 128
    validate_identifier_pattern("ORD-[0-9]{64}-[0-9]{64}", ENGINE)  # 64 + 64
    assert reason_of("ORD-[0-9]{64}-[0-9]{64}[0-9]{4}") == REASON_REPEAT  # 132


def test_twenty_heavy_repeats_in_a_row_are_refused_though_each_is_small():
    pattern = "ORD-" + "[0-9a-z]{1,64}-" * 20  # the review's rebuild-stalling pattern
    assert reason_of(pattern) == REASON_REPEAT
    assert reason_of("ORD-" + "[0-9]{1,32}-" * 5) == REASON_REPEAT  # 5 x 32 = 160


def test_a_realistic_pattern_weighs_little():
    validate_identifier_pattern("ORD-[0-9]{6,10}", ENGINE)
    validate_identifier_pattern("INV-[0-9]{4}-[0-9]{4}-[A-Z]{2}", ENGINE)


# ------------------------------------------------------------------
@pytest.mark.parametrize(
    "pattern",
    [
        "(?i)the [0-9]{4}",  # the review's examples
        "(?i)since [0-9]{4}",
        r"(?i)phone: [0-9]{3}-[0-9]{3}-[0-9]{4}",
        r"(?i)date: [0-9]{4}-[0-9]{2}-[0-9]{2}",
        "(?i)year [0-9]{4}",
        "(?i)copyright [0-9]{4}",
        "(?i)room [0-9]{4}",
        "(?i)invoice #[0-9]{4}",
        "(?i)order #[0-9]{5}",
        "(?i)page [0-9]{4}",
        "(?i)version [0-9]{4}",
        "(?i)ref: [0-9]{6}",
        r"(?i)tel: \([0-9]{3}\) [0-9]{3}-[0-9]{4}",
        r"(?i)fax: [0-9]{3}\.[0-9]{3}\.[0-9]{4}",
        r"(?i)due [0-9]{4}-[0-9]{2}-[0-9]{2}",
        r"(?i)dated [0-9]{2}/[0-9]{2}/[0-9]{4}",
        r"http://[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}",
        r"(?i)http://192\.[0-9]{3}\.[0-9]{3}\.[0-9]{3}",
        r"(?i)ip: [0-9]{3}\.[0-9]{3}\.[0-9]{3}\.[0-9]{3}",
    ],
)
def test_a_common_word_or_contact_shape_followed_by_digits_is_refused(pattern):
    """Ordinary text a pattern would match in every other tenant's content."""
    assert reason_of(pattern) == REASON_BENIGN_MATCH


@pytest.mark.parametrize(
    "pattern",
    [
        "ORD-[0-9]{4}",
        "ORD-[0-9]{6,10}",
        "ACME-STORE-[0-9]{4}",
        "INV-[0-9]{4}-[0-9]{4}",
        "BET-INV-[0-9]{4}",
        "(?i)acct_[0-9]{8}",
        "CASE-[0-9]{4}-[A-Z]{3}",
        "Quartz-[0-9]{4}",
    ],
)
def test_the_real_identifier_shapes_are_still_accepted(pattern):
    validate_identifier_pattern(pattern, ENGINE)


def test_a_group_weighs_the_sum_of_what_repeats_inside_it():
    """Twenty repeats in a group are not "one repeat of 64"."""
    bypass = "ORD-(?:" + "[0-9a-z]{1,64}-" * 20 + ")[0-9]{4}"
    assert reason_of(bypass) == REASON_REPEAT
    assert reason_of("ORD-(?:[0-9]{9}[0-9]{9}){9}[0-9]{4}") == REASON_REPEAT  # 18 x 9
    assert reason_of("ORD-(?:" + "[0-9]{20}" * 7 + ")[0-9]{4}") == REASON_REPEAT  # 140 + 4
    validate_identifier_pattern("ORD-(?:[0-9]{8}){8}[0-9]{4}", ENGINE)  # 8 x 8 = 64, + 4
    validate_identifier_pattern("ORD-[0-9]{4}(?:[0-9]{2}-){4}", ENGINE)
    validate_identifier_pattern("ORD-[0-9]{64}-[0-9]{64}", ENGINE)  # 128 exactly
