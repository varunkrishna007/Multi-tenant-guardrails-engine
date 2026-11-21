"""M3-01: the regex port with its RE2 adapter, and the cross-tenant identifier port."""

from __future__ import annotations

import re
import time

import pytest

from guardrail_engine.deterministic import (
    BENIGN_REFERENCE_TEXT,
    IdentifierPatternError,
    InMemoryOtherTenantIdentifiers,
    NoOtherTenantIdentifiers,
    RegexError,
    default_regex_engine,
    literal_pattern,
    tenant_id_pattern,
    validate_identifier_pattern,
)
from guardrail_engine.deterministic.adapters.google_re2 import Re2RegexEngine
from guardrail_engine.deterministic.identifiers import (
    REASON_ALTERNATION,
    REASON_BENIGN_MATCH,
    REASON_EMPTY_MATCH,
    REASON_INVALID,
    REASON_SHORT_PREFIX,
    REASON_TOO_LONG,
    literal_prefix_length,
)

ENGINE = Re2RegexEngine()


# ------------------------------------------------------------------ the RE2 adapter


def test_spans_are_character_offsets_in_text_order():
    pattern = ENGINE.compile(r"(?i)project\s+falcon")
    text = "héllo ✓ Project  Falcon and project falcon"
    assert [text[s:e] for s, e in pattern.spans(text)] == ["Project  Falcon", "project falcon"]
    assert pattern.spans(text)[0][0] == 8  # characters, not bytes


def test_matches_are_non_overlapping_and_never_empty():
    assert ENGINE.compile("aa").spans("aaaaa") == [(0, 2), (2, 4)]
    assert ENGINE.compile("a*").spans("baaab") == [(1, 4)]  # the empty matches are dropped
    assert ENGINE.compile("x").spans("") == []
    assert ENGINE.compile("a*").search("") is True  # the compiler refuses such a pattern


def test_search_and_spans_agree():
    pattern = ENGINE.compile("tok_[a-z]{4}")
    assert pattern.search("a tok_abcd b") and pattern.spans("a tok_abcd b") == [(2, 10)]
    assert not pattern.search("a tok_ab b") and pattern.spans("a tok_ab b") == []


@pytest.mark.parametrize(
    "text", ["a \ud800 Project Falcon", "\udfff\udfffProject Falcon", "\ud83d"]
)
def test_text_with_lone_surrogates_never_raises_and_spans_stay_valid(text):
    """Text decoded from JSON can hold lone surrogates, which UTF-8 can't encode."""
    pattern = ENGINE.compile("(?i)project falcon")
    spans = pattern.spans(text)
    assert [text[s:e] for s, e in spans] == (["Project Falcon"] if "Project" in text else [])
    assert pattern.search(text) is bool(spans)
    assert ENGINE.compile_set(["(?i)falcon"]).matching(text) == (
        frozenset({0}) if "Falcon" in text else frozenset()
    )


@pytest.mark.parametrize(
    "bad", ["(a)\\1", "(?=a)", "(?!a)", "(?<=a)b", "(?<!a)b", "[a-", "a{1001}", "(", "*a"]
)
def test_what_re2_cannot_run_is_a_regex_error_with_its_detail(bad):
    with pytest.raises(RegexError) as raised:
        ENGINE.compile(bad)
    assert raised.value.detail and isinstance(raised.value.detail, str)
    with pytest.raises(RegexError):
        ENGINE.compile_set(["fine", bad])


def test_a_pattern_over_the_memory_bound_is_refused_at_compile_time():
    small = Re2RegexEngine(pattern_max_mem=64 * 1024)
    with pytest.raises(RegexError):
        small.compile(r"(\pL{200}){200}")
    ENGINE.compile(r"\pL{10}")  # and a modest one is fine


def test_matching_is_linear_where_a_backtracking_engine_would_not_be():
    """The classic catastrophic pattern finishes at once: RE2 has no backtracking."""
    pattern = ENGINE.compile("(a+)+$")
    text = "a" * 5_000 + "!"
    started = time.perf_counter()
    assert pattern.search(text) is False
    assert time.perf_counter() - started < 1.0


def test_a_set_reports_the_indexes_of_the_patterns_that_match():
    matches = ENGINE.compile_set([r"foo[0-9]+", "bar", r"(?i)BAZ"])
    assert matches.matching("xx foo12 baz") == frozenset({0, 2})
    assert matches.matching("nothing") == frozenset()
    assert ENGINE.compile_set([]).matching("anything") == frozenset()


def test_compiled_patterns_compare_by_source_and_do_not_show_it():
    assert ENGINE.compile("abc") == ENGINE.compile("abc") != ENGINE.compile("abd")
    assert "abc" not in repr(ENGINE.compile("abc"))
    assert len({ENGINE.compile("abc"), ENGINE.compile("abc")}) == 1


def test_the_default_engine_is_one_shared_adapter_instance():
    assert isinstance(default_regex_engine(), Re2RegexEngine)
    assert default_regex_engine() is default_regex_engine()


# ------------------------------------------------------------------ identifier patterns


def test_literal_pattern_matches_exactly_that_text():
    text = "a.b+c*d?(e)[f]{g}|h^i$j\\k"
    assert ENGINE.compile(literal_pattern(text)).spans(f"x {text} y") == [(2, 2 + len(text))]
    assert not ENGINE.compile(literal_pattern("a.b")).search("axb")


@pytest.mark.parametrize(
    ("text", "found"),
    [
        ("t_acme", True),
        ("see t_acme.", True),
        ("T_ACME", True),
        ("a/t_acme/b", True),
        ("t_acme_orders", True),  # a tenant id has no underscore after the prefix
        ("t_acmeco", False),
        ("not_t_acme", True),
        ("xt_acme", False),
        ("t_acm", False),
        ("", False),
    ],
)
def test_a_tenant_id_pattern_finds_the_id_standing_alone(text, found):
    assert ENGINE.compile(tenant_id_pattern("t_acme")).search(text) is found


# ------------------------------------------------------------------ registration validator


@pytest.mark.parametrize(
    "pattern",
    [
        r"ORD-[0-9]{6,10}",
        r"ALP-ORD-[0-9]{4}",
        r"(?i)acct_[0-9]{8}",
        r"\bINV-[0-9]{5}",
        r"^TKT\.[0-9]{4,12}",
        r"ORD-(?:A|B)[0-9]{4}",
        r"A\-B\-C\-D[0-9]{4}[0-9]{0,8}",
        r"ORDER[0-9]{6}",  # no separator, but every match holds a digit
        r"ORD-[0-9]{4}1+",  # an unbounded repeat of one plain character is cheap
        r"(?i)ORD-[0-9]{4}(?:[0-9]{3}-){2}[a-z]{2}",
    ],
)
def test_a_reviewable_identifier_pattern_is_accepted(pattern):
    validate_identifier_pattern(pattern, ENGINE)


@pytest.mark.parametrize(
    ("pattern", "reason"),
    [
        (".", REASON_SHORT_PREFIX),
        ("[0-9]", REASON_SHORT_PREFIX),
        ("e", REASON_SHORT_PREFIX),
        ("[0-9]+", REASON_SHORT_PREFIX),
        (r"\d{6}", REASON_SHORT_PREFIX),
        ("ORD[0-9]{6}", REASON_SHORT_PREFIX),  # three literals only
        ("ORDE?-[0-9]{6}", REASON_SHORT_PREFIX),  # E is optional: "ORD" only
        ("(ORDER)-[0-9]+", REASON_SHORT_PREFIX),  # a group isn't a literal prefix
        ("a*", REASON_EMPTY_MATCH),
        ("(?:ORDER-1)?", REASON_EMPTY_MATCH),
        ("ORDER-1|.", REASON_ALTERNATION),
        ("ORDER-1|x[0-9]", REASON_ALTERNATION),
        ("(?i)the ", REASON_BENIGN_MATCH),
        ("Thanks[ a-z]{0,20}", REASON_BENIGN_MATCH),
        ("2023[-0-9]{0,20}", REASON_BENIGN_MATCH),
        ("(?i)MARCH", REASON_BENIGN_MATCH),
        ("(?=lookahead)", REASON_INVALID),
        ("(", REASON_INVALID),
        ("ORDER-" + "x" * 500, REASON_TOO_LONG),
    ],
)
def test_a_careless_identifier_pattern_is_refused_at_registration(pattern, reason):
    with pytest.raises(IdentifierPatternError) as refused:
        validate_identifier_pattern(pattern, ENGINE)
    assert refused.value.reason == reason


def test_the_refusal_never_quotes_the_pattern():
    with pytest.raises(IdentifierPatternError) as refused:
        validate_identifier_pattern("SECRETWORD(", ENGINE)
    assert "SECRETWORD" not in str(refused.value)


def test_the_benign_reference_text_is_ordinary_english_with_digits_and_dates():
    assert len(BENIGN_REFERENCE_TEXT) > 800
    assert re.search(r"\d{4}-\d{2}-\d{2}", BENIGN_REFERENCE_TEXT)
    assert re.search(r"\b(?:the|and|of)\b", BENIGN_REFERENCE_TEXT)
    assert BENIGN_REFERENCE_TEXT.isascii()


@pytest.mark.parametrize("pattern", [".", "[0-9]", "e", "[0-9]+", "ORD|."])
async def test_the_in_memory_source_refuses_a_careless_pattern_and_registers_nothing(pattern):
    source = InMemoryOtherTenantIdentifiers({"t_a": [r"ALP-[0-9]{4}"]})
    with pytest.raises(IdentifierPatternError):
        source.register("t_b", r"BET-[0-9]{4}", pattern)
    with pytest.raises(IdentifierPatternError):
        InMemoryOtherTenantIdentifiers({"t_c": [pattern]})
    assert (await source.patterns_by_tenant()).keys() == {"t_a"}


@pytest.mark.parametrize(
    ("pattern", "count"),
    [("ORD-[0-9]{6}", 4), (r"(?i)ORD-", 4), (r"\bORD-", 4), ("ORD-", 4), ("OR", 2), ("", 0),
     (r"\d+ORD-", 0), (r"AB\.CD", 5), ("ab+cd", 1), ("abc{2}", 2)],
)  # fmt: skip
def test_literal_prefix_length(pattern, count):
    assert literal_prefix_length(pattern) == count


# ------------------------------------------------------------------ the in-memory source


async def test_every_tenants_id_and_patterns_are_reported_with_a_version():
    source = InMemoryOtherTenantIdentifiers(
        {"t_a": [r"ALP-[0-9]{4,8}"], "t_b": [r"BET-[0-9]{4,8}", r"BET2-[0-9]{4,8}"], "t_c": []}
    )
    by_tenant = await source.patterns_by_tenant()
    assert set(by_tenant) == {"t_a", "t_b", "t_c"}
    assert by_tenant["t_a"] == (tenant_id_pattern("t_a"), r"ALP-[0-9]{4,8}")
    assert by_tenant["t_b"] == (tenant_id_pattern("t_b"), r"BET-[0-9]{4,8}", r"BET2-[0-9]{4,8}")
    assert by_tenant["t_c"] == (tenant_id_pattern("t_c"),)


async def test_the_source_can_leave_tenant_ids_out_and_the_version_moves_on_every_change():
    source = InMemoryOtherTenantIdentifiers({"t_a": ["ALP-[0-9]{4}"]}, include_tenant_ids=False)
    assert await source.patterns_by_tenant() == {"t_a": ("ALP-[0-9]{4}",)}
    first = await source.version()
    assert await source.version() == first  # stable while nothing changes
    source.register("t_a", "ALP-[0-9]{5}")
    second = await source.version()
    assert await source.patterns_by_tenant() == {"t_a": ("ALP-[0-9]{4}", "ALP-[0-9]{5}")}
    source.remove("t_a")
    assert len({first, second, await source.version()}) == 3
    assert await source.patterns_by_tenant() == {}


def test_only_valid_tenant_ids_can_be_registered():
    with pytest.raises(ValueError, match="not a tenant id"):
        InMemoryOtherTenantIdentifiers().register("Not A Tenant")


async def test_the_default_source_has_nothing_to_scan_for():
    source = NoOtherTenantIdentifiers()
    assert await source.patterns_by_tenant() == {}
    assert await source.version() == await source.version()
