"""M3-01: a richer PII detector on the M1-14 port.

The default stays M1-14's. These tests show the extension is safe to use in its place: it keeps
every M1-14 guarantee (near misses, credentials and URL hosts, the exfil and secret rows of the
floor's golden set, idempotence, cost), adds only the shapes pinned as gaps, and the
Guard Service's no-raw-PII property (AC-G2, checked against what the fake model receives) holds
with it. Values are synthetic, as in ``test_guard_pii``.
"""

from __future__ import annotations

import re
import time

import pytest
from guard_fixtures import ALPHA, Env, bundle, profile, rule
from hypothesis import given, settings
from hypothesis import strategies as st
from test_guard_pii import (
    ADVERSARIAL,
    CREDENTIALS_AND_URLS,
    FRAGMENTS,
    IDEMPOTENCE_CASES,
    NEAR_MISSES,
    POSITIVES,
    SIXTEEN_K_TOKENS,
    TEXTS,
    URL_PII,
    _golden_rows,
    _rule_signals,
)

from guardrail_engine.guard import DEFAULT_PII_DETECTOR, Decision, PiiKind, PiiMatch
from guardrail_engine.guard.pii import DeterministicPiiDetector
from guardrail_engine.guard.pii_extended import (
    EXTENDED_PII_DETECTOR,
    CompositePiiDetector,
    ExtendedPiiDetector,
)
from guardrail_engine.guard.redaction import RedactionError, redact_text


def ext(text: str) -> str:
    return redact_text(text, EXTENDED_PII_DETECTOR).text


def default(text: str) -> str:
    return redact_text(text).text


# ------------------------------------------------------------------ the default is unchanged


def test_the_engines_default_detector_is_still_m1_14s():
    assert isinstance(DEFAULT_PII_DETECTOR, DeterministicPiiDetector)
    assert not isinstance(DEFAULT_PII_DETECTOR, ExtendedPiiDetector)


async def test_the_guard_service_uses_m1_14s_detector_unless_one_is_given():
    async with Env() as env:
        assert env.service._pii_detector is DEFAULT_PII_DETECTOR


# ------------------------------------------------------------------ what it adds

GAPS = [
    ("compact UK landline 02079460018", "compact UK landline [PHONE]"),
    ("call 01632960123 now", "call [PHONE] now"),
    ("E.164 without its plus 447700900123", "E.164 without its plus [PHONE]"),
    ("iban gb82west12345698765432 lower", "iban [IBAN] lower"),
    ("mixed Gb82 West 1234 5698 7654 32 case", "mixed [IBAN] case"),
]


@pytest.mark.parametrize(("text", "expected"), GAPS)
def test_it_closes_the_gaps_review_26_pinned_and_the_default_leaves_them(text, expected):
    assert ext(text) == expected
    assert default(text) == text


def test_what_it_still_leaves_alone_is_too_ambiguous_to_redact_without_context():
    for text in ["compact North American 2015550123", "an id 1234567890", "ref 04079460018"]:
        assert ext(text) == text


# ------------------------------------------------------------------ M1-14 guarantees kept


@pytest.mark.parametrize(("kind", "text", "expected"), POSITIVES)
def test_every_m1_14_positive_is_redacted_the_same(kind, text, expected):
    assert ext(text) == expected


@pytest.mark.parametrize("text", NEAR_MISSES)
def test_every_m1_14_near_miss_is_still_left_alone(text):
    assert ext(text) == text


@pytest.mark.parametrize("text", CREDENTIALS_AND_URLS)
def test_credentials_and_url_hosts_still_pass_through_byte_for_byte(text):
    assert ext(text) == text


@pytest.mark.parametrize(("text", "expected"), URL_PII)
def test_pii_in_urls_is_redacted_and_the_host_kept(text, expected):
    assert ext(text) == expected


def test_the_golden_sets_exfil_and_secret_rows_keep_every_signal():
    checked = 0
    for row in _golden_rows():
        content = row["content"]
        if "p__secret" in row["fires"]:
            assert ext(content) == content, row["id"]
        elif "p__exfil" in row["fires"]:
            expected = re.sub(r"[A-Za-z0-9._%+-]+@(?=[A-Za-z0-9-]+\.)", "[EMAIL]@", content)
            assert ext(content) == expected, row["id"]
        if {"p__exfil", "p__secret"} & set(row["fires"]):
            checked += 1
            for signal in _rule_signals(content):
                assert signal in ext(content), (row["id"], signal)
    assert checked >= 40


def test_on_the_golden_set_it_changes_only_what_the_default_leaves():
    """Every difference from the default is one of the added shapes."""
    added = re.compile(r"\[PHONE\]|\[IBAN\]")
    for row in _golden_rows():
        content = row["content"]
        if ext(content) != default(content):
            assert added.search(ext(content)), row["id"]


@pytest.mark.parametrize("text", IDEMPOTENCE_CASES)
def test_redaction_settles_in_one_pass_on_the_known_hard_cases(text):
    assert ext(ext(text)) == ext(text)


EXTENDED_FRAGMENTS = [*FRAGMENTS, "02079460018", "447700900123", "gb82west12345698765432", "Gb82 "]


@settings(max_examples=500, deadline=None)
@given(
    st.lists(
        st.one_of(
            st.sampled_from(EXTENDED_FRAGMENTS),
            st.text(alphabet="0123456789 -.+@:/()#abcxyzQGBW", max_size=12),
        ),
        max_size=12,
    ).map("".join)
)
def test_redaction_is_idempotent_and_deterministic(text):
    once = ext(text)
    assert ext(once) == once == redact_text(text, ExtendedPiiDetector()).text


@settings(max_examples=100, deadline=None)
@given(TEXTS)
def test_it_never_redacts_less_than_the_default(text):
    """Everything the default replaces is replaced here too (the extras only add)."""
    for kind, n in redact_text(text).counts.items():
        assert redact_text(text, EXTENDED_PII_DETECTOR).counts[kind] >= n


@pytest.mark.parametrize(
    "name", ["digits", "plus groups", "iban groups", "spaced digits", "at signs"]
)
def test_a_16k_token_adversarial_input_finishes_within_a_generous_bound(name):
    text = ADVERSARIAL[name](SIXTEEN_K_TOKENS)
    started = time.perf_counter()
    redact_text(text, EXTENDED_PII_DETECTOR)
    assert time.perf_counter() - started < 2.0


# ------------------------------------------------------------------ the composite


class Fixed:
    """A detector that returns the spans it was given, whatever the text."""

    def __init__(self, *matches: PiiMatch) -> None:
        self.matches = matches

    def find(self, text):
        return self.matches


def test_a_composite_unions_its_parts_and_the_earliest_longest_span_wins_overlaps():
    text = "0123456789 abcdefghij"
    parts = (
        Fixed(PiiMatch(PiiKind.PHONE, 0, 5), PiiMatch(PiiKind.CARD, 11, 15)),
        Fixed(PiiMatch(PiiKind.IBAN, 3, 8), PiiMatch(PiiKind.EMAIL, 0, 8)),
    )
    found = CompositePiiDetector(*parts).find(text)
    assert [(m.kind, m.start, m.end) for m in found] == [
        (PiiKind.EMAIL, 0, 8),
        (PiiKind.CARD, 11, 15),
    ]
    assert redact_text(text, CompositePiiDetector(*parts)).text == "[EMAIL]89 [CARD]efghij"


def test_a_composite_of_one_detector_is_that_detector():
    one = Fixed(PiiMatch(PiiKind.PHONE, 0, 5))
    assert list(CompositePiiDetector(one).find("x" * 9)) == list(one.matches)


def test_a_composite_needs_a_detector():
    with pytest.raises(ValueError, match="at least one"):
        CompositePiiDetector()


def test_a_part_that_raises_fails_the_whole_find():
    class Broken:
        def find(self, text):
            raise RuntimeError("boom")

    with pytest.raises(RuntimeError):
        CompositePiiDetector(DEFAULT_PII_DETECTOR, Broken()).find("a@b.example")


def test_a_part_that_returns_junk_is_refused_by_redaction_as_before():
    junk = CompositePiiDetector(Fixed(PiiMatch(PiiKind.PHONE, 0, 99)))
    with pytest.raises(RedactionError):
        redact_text("short", junk)


# ------------------------------------------------------------------ AC-G2 through the service

PHONE_LANDLINE = "02079460018"
PHONE_E164 = "447700900123"
IBAN_LOWER = "gb82west12345698765432"
EMAIL = "jo.smith@example.com"
CARD = "4111 1111 1111 1111"


async def test_ac_g2_no_raw_pii_reaches_the_model_with_the_extended_detector():
    async with Env(tenants=[profile(ALPHA)], pii_detector=EXTENDED_PII_DETECTOR) as env:
        await env.publish(bundle(ALPHA, rules=[rule("adv")]))
        verdict = await env.check(
            ALPHA,
            content=(
                f"Ring {PHONE_LANDLINE} or {PHONE_E164}; pay {IBAN_LOWER}; mail {EMAIL}; {CARD}."
            ),
        )
    assert verdict.decision is Decision.ALLOW
    [call] = env.fake.calls
    for raw in (PHONE_LANDLINE, PHONE_E164, IBAN_LOWER, "jo.smith@", CARD):
        assert raw not in call.input, raw
    for placeholder in ("[PHONE]", "[IBAN]", "[EMAIL]@example.com", "[CARD]"):
        assert placeholder in call.input
    assert verdict.pii_redacted == {
        PiiKind.EMAIL: 1,
        PiiKind.PHONE: 2,
        PiiKind.CARD: 1,
        PiiKind.IBAN: 1,
    }


async def test_the_default_service_still_sends_the_gap_shapes_as_they_were_pinned():
    async with Env(tenants=[profile(ALPHA)]) as env:
        await env.publish(bundle(ALPHA, rules=[rule("adv")]))
        await env.check(ALPHA, content=f"Ring {PHONE_LANDLINE}.")
    assert PHONE_LANDLINE in env.fake.calls[0].input
