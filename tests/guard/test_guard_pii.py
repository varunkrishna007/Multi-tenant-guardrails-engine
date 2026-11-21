"""M1-14: the deterministic PII detector and ``redact_text``.

Every value here is synthetic: documented test card numbers, 555-01xx and Ofcom drama-range
phone numbers, voided or never-issued national ids (078-05-1120, 219-09-9999, the HMRC ``QQ``
prefix), the published example IBANs, and example.com / example.org / ``.example`` domains.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from guardrail_engine.guard.pii import (
    DEFAULT_PII_DETECTOR,
    PLACEHOLDERS,
    DeterministicPiiDetector,
    PiiKind,
    PiiMatch,
    is_card_number,
    is_iban,
    luhn_valid,
)
from guardrail_engine.guard.redaction import RedactionError, redact_text
from guardrail_engine.telemetry.port import CHECK_ATTRIBUTES

ROOT = Path(__file__).resolve().parents[2]
GOLDEN = ROOT / "floor" / "golden.jsonl"


def red(text: str) -> str:
    return redact_text(text).text


def counts(text: str) -> dict[str, int]:
    return {k.value: v for k, v in redact_text(text).counts.items()}


# ------------------------------------------------------------------ positives, per kind

POSITIVES = [
    # (kind, text, expected redacted text)
    ("email", "Write to jo@example.com today.", "Write to [EMAIL]@example.com today."),
    ("email", "x.y+tag@sub.example.org", "[EMAIL]@sub.example.org"),
    ("email", '{"to": "x@collector.example"}', '{"to": "[EMAIL]@collector.example"}'),
    ("email", "<ops_team@example.net>", "<[EMAIL]@example.net>"),
    ("email", "Email: dave@example.org.", "Email: [EMAIL]@example.org."),
    ("email", "zoë@example.org", "[EMAIL]@example.org"),
    ("email", "mailto:alice@example.org?subject=hi", "mailto:[EMAIL]@example.org?subject=hi"),
    (
        "email",  # in a URL's query: the local part only; the URL is otherwise intact
        "https://app.example/u?email=bob@example.org&x=1",
        "https://app.example/u?email=[EMAIL]@example.org&x=1",
    ),
    (
        "email",  # and in its path and fragment
        "https://app.example/users/bob@example.org/p#c@example.net",
        "https://app.example/users/[EMAIL]@example.org/p#[EMAIL]@example.net",
    ),
    ("card", "Card 4111 1111 1111 1111 ok", "Card [CARD] ok"),
    ("card", "Card 4111-1111-1111-1111.", "Card [CARD]."),
    ("card", "card=4111111111111111", "card=[CARD]"),
    ("card", "mc 5555555555554444", "mc [CARD]"),
    ("card", "mc2 2223003122003222", "mc2 [CARD]"),
    ("card", "amex 3782 822463 10005", "amex [CARD]"),
    ("card", "amex 378282246310005", "amex [CARD]"),
    ("card", "disc 6011111111111117", "disc [CARD]"),
    ("card", "jcb 3530111333300000", "jcb [CARD]"),
    ("card", "diners 30569309025904", "diners [CARD]"),
    ("card", "café 4012888888881881", "café [CARD]"),
    ("card", "4111 1111 1111 1111 2026", "[CARD] 2026"),
    ("phone", "call +1 201-555-0123 now", "call [PHONE] now"),
    ("phone", "(201) 555-0123", "[PHONE]"),
    ("phone", "201-555-0123", "[PHONE]"),
    ("phone", "201.555.0123", "[PHONE]"),
    ("phone", "tel:+12015550123", "tel:[PHONE]"),
    ("phone", "020 7946 0018", "[PHONE]"),
    ("phone", "07700 900123", "[PHONE]"),
    # A space-separated North American number and a compact UK mobile
    ("phone", "US: 201 555 0123", "US: [PHONE]"),
    ("phone", "call me on 07700900123.", "call me on [PHONE]."),
    ("phone", '{"mobile": "07700900123"}', '{"mobile": "[PHONE]"}'),
    ("phone", "+44 7700 900123", "[PHONE]"),
    ("phone", "+44 (0)20 7946 0018", "[PHONE]"),
    ("phone", '{"phone": "+44 20 7946 0018"}', '{"phone": "[PHONE]"}'),
    ("iban", "IBAN GB82 WEST 1234 5698 7654 32.", "IBAN [IBAN]."),
    ("iban", "GB82WEST12345698765432", "[IBAN]"),
    ("iban", "DE89 3704 0044 0532 0130 00", "[IBAN]"),
    ("iban", "DE89 3704 0044 0532 0130 00 2026", "[IBAN] 2026"),
    ("iban", "NL91ABNA0417164300", "[IBAN]"),
    (
        "uk_bank",
        "sort code 12-34-56, account 12345678",
        "sort code [SORT_CODE], account [ACCOUNT_NUMBER]",
    ),
    ("uk_bank", "acct 12345678 sort 12 34 56", "acct [ACCOUNT_NUMBER] sort [SORT_CODE]"),
    ("uk_nino", "NI number QQ 12 34 56 C", "NI number [NINO]"),
    ("uk_nino", "QQ123456A", "[NINO]"),
    # Any letter case, and the "QQ 123456 C" spacing
    ("uk_nino", "ni qq123456c", "ni [NINO]"),
    ("uk_nino", "Qq 12 34 56 c", "[NINO]"),
    ("uk_nino", "NINO: QQ 123456 C.", "NINO: [NINO]."),
    ("us_ssn", "SSN 078-05-1120.", "SSN [SSN]."),
    ("us_ssn", "ssn=219-09-9999", "ssn=[SSN]"),
    ("us_ssn", "SSN 078 05 1120", "SSN [SSN]"),  # spaces
]


@pytest.mark.parametrize(("kind", "text", "expected"), POSITIVES)
def test_each_kind_is_replaced_by_its_placeholder(kind, text, expected):
    assert red(text) == expected


def test_counts_are_per_kind():
    text = (
        "a@example.com b@example.org 4111111111111111 +1 201-555-0123 QQ123456C "
        "078-05-1120 GB82WEST12345698765432 12-34-56 12345678"
    )
    assert counts(text) == {
        "email": 2,
        "card": 1,
        "phone": 1,
        "uk_nino": 1,
        "us_ssn": 1,
        "iban": 1,
        "uk_sort_code": 1,
        "uk_account_number": 1,
    }


def test_placeholders_are_the_typed_ones_and_carry_no_digits_or_at_signs():
    assert set(PLACEHOLDERS) == set(PiiKind)
    assert PLACEHOLDERS[PiiKind.EMAIL] == "[EMAIL]" and PLACEHOLDERS[PiiKind.CARD] == "[CARD]"
    for placeholder in PLACEHOLDERS.values():
        assert re.fullmatch(r"\[[A-Z_]+\]", placeholder)


# ------------------------------------------------------------------ near misses

NEAR_MISSES = [
    # Cards
    "luhn fails 4111111111111112",
    "no network prefix 1234567812345670",
    "epoch ms 1731840000000",
    "uuid 123e4567-e89b-12d3-a456-426614174000",
    "sha256 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
    "a run 41111111111111111111111",
    "in a word ref4111111111111111",
    "joined 4111111111111111-01",
    "decimal 4111111111111111.5",
    "mixed separators 4111 1111-1111 1111",
    "base64 xx+4111111111111111/yy",
    # Phones
    "no area code 555-0100",
    "mixed separators 201-555 0123",
    "UK 070 personal number 07012345678",
    "twelve digits 077009001234",
    "spaced, too short 201 555 012",
    "area code from 1, spaced: 123 456 7890",
    "area code from 1: 123-456-7890",
    "too short +1 555",
    "dotted 1.201.555.0123",
    "eight UK digits 0123 4567",
    "double zero 007 1234 5678",
    "date 2026-11-17T10:02:11Z, 17-11-2026, 2026/11/17",
    "time 10:02:11.123",
    "ip 192.168.100.200 and 10.0.0.1",
    "versions 1.2.3, v12.0.1, 2.10.1000",
    "order 99812, CLM-20931, P-4471, qty 3 x 4",
    # SSNs
    "area 000-12-3456",
    "area 666-12-3456",
    "area 900-12-3456",
    "group 123-00-4567",
    "serial 123-45-0000",
    "too long 123-45-67890",
    "in a word x123-45-6789",
    # NINOs
    "spaced SSN with mixed separators 078-05 1120",
    "spaced SSN in a bad area 666 12 3456",
    "NINO split oddly QQ 1234 56 C",
    "suffix QQ123456E",
    "in a token XQQ123456C",
    "seven digits QQ1234567C",
    "base64 abc/QQ123456C+def",
    "base64 abc+QQ123456C/def",
    # IBANs
    "bad check GB83WEST12345698765432",
    "short GB82WEST1234569876543",
    "unknown country ZZ82WEST12345698765432",
    # Sort code / account: either alone, or too far apart, or split by a line or digits
    "sort code alone 12-34-56",
    "account alone 12345678",
    "12-34-56\n12345678",
    "12-34-56 is the branch of the claimant whose ref is 12345678",
    "12-34-56 and 7 then 12345678",
    # Emails
    "user@localhost",
    "a@b.c",
    "@handle",
    "a@-b.example",
    "user@[192.0.2.1]",
    # Placeholders themselves
    "[EMAIL]@x.example [CARD] [PHONE] [IBAN] [SORT_CODE] [ACCOUNT_NUMBER] [NINO] [SSN]",
]


@pytest.mark.parametrize("text", NEAR_MISSES)
def test_near_misses_are_left_alone(text):
    assert red(text) == text


# ------------------------------------------------------------------ what is never redacted

CREDENTIALS_AND_URLS = [
    "postgres://claims_app:Tq7!fake-vR29x@db.internal.example:5432/claims",
    "https://ci-bot:ghp_FAKEEXAMPLE0000000000000000000000000@git.example/acme/claims.git",
    "https://pay:4111111111111111@pay.example:8443/x",  # digits in the authority are kept
    "http://10.0.0.1:8080/status and https://[2001:db8::1]:443/",
    "claims_app:Tq7fake@db.example",
    "ftp://deploy.bot@files.example/drop",  # userinfo with no password: still the authority
    "password Tq7!fake-vR29x@db.internal.example",
    "aws_access_key_id = AKIAIOSFODNN7EXAMPLE",
    "api_key: sk_test_FAKEEXAMPLE0000000000000",
    "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1XzQ4MjEzIn0.FAKEsig000",
    "files.attacker.invalid and hooks.chat.example/T000/B000/XXXX",
]


@pytest.mark.parametrize("text", CREDENTIALS_AND_URLS)
def test_urls_hostnames_and_credentials_pass_through_byte_for_byte(text):
    assert red(text) == text


URL_PII = [
    # (text, expected): every kind in a URL's path, query and fragment; scheme and host kept
    (
        "https://shop.example/pay?card=4111111111111111&phone=%2B1&tel=201-555-0123",
        "https://shop.example/pay?card=[CARD]&phone=%2B1&tel=[PHONE]",
    ),
    (
        "https://shop.example:8443/checkout/4111111111111111?phone=201-555-0123",
        "https://shop.example:8443/checkout/[CARD]?phone=[PHONE]",
    ),
    (
        "https://crm.example/c?ssn=078-05-1120&nino=QQ123456C#iban=GB82WEST12345698765432",
        "https://crm.example/c?ssn=[SSN]&nino=[NINO]#iban=[IBAN]",
    ),
    (
        "https://bank.example/t?sort=12-34-56&acct=12345678",
        "https://bank.example/t?sort=[SORT_CODE]&acct=[ACCOUNT_NUMBER]",
    ),
    (
        "https://u:p@api.example/v1/users/201-555-0123?email=bob@example.org",
        "https://u:p@api.example/v1/users/[PHONE]?email=[EMAIL]@example.org",
    ),
]


@pytest.mark.parametrize(("text", "expected"), URL_PII)
def test_pii_in_a_url_path_query_or_fragment_is_redacted_and_the_host_kept(text, expected):
    """AC-G2 decision (backlog 0105b0a): only the scheme and authority are kept byte for byte."""
    out = red(text)
    assert out == expected
    authority = text.split("/")[2]
    assert out.startswith(text.split("//")[0] + "//" + authority)


@pytest.mark.parametrize(
    "text",
    [
        "compact North American 2015550123",
        "compact UK landline 02079460018",
        "E.164 without its plus 447700900123",
    ],
)
def test_review_26_known_gaps_for_m3_01_are_pinned(text):
    """Too ambiguous with ids to redact without context; documented for M3-01 in the module
    docstring and the README. Pinned so closing one is a deliberate change."""
    assert red(text) == text


def test_known_limitations_are_pinned():
    """Documented trade-offs, accepted and pinned so a change is deliberate:
    ``label:local@domain`` with no space reads as userinfo and is kept; an scp-style git
    remote reads as an email; non-ASCII digits are never PII."""
    assert red("Email:carol@example.org") == "Email:carol@example.org"
    assert red("git@git.example:acme/claims.git") == "[EMAIL]@git.example:acme/claims.git"
    arabic_indic = "٤١١١" * 4
    assert red(arabic_indic) == arabic_indic


# ------------------------------------------------------------------ validators


@pytest.mark.parametrize(
    "number",
    [
        "4111111111111111",
        "5555555555554444",
        "2223003122003222",
        "378282246310005",
        "6011111111111117",
        "3530111333300000",
        "30569309025904",
        "4012888888881881",
    ],
)
def test_documented_test_card_numbers_are_cards(number):
    assert luhn_valid(number) and is_card_number(number)


def test_card_needs_a_network_length():
    assert luhn_valid("4111111111111111") and not is_card_number("41111111111111111")  # 17
    assert not is_card_number("378282246310005" + "0")  # Amex is 15 only


@pytest.mark.parametrize(
    "iban",
    ["GB82WEST12345698765432", "DE89370400440532013000", "NL91ABNA0417164300"],
)
def test_published_example_ibans_validate(iban):
    assert is_iban(iban)


# ------------------------------------------------------------------ redact_text and the port


def test_text_with_nothing_found_is_returned_as_the_same_object():
    text = "Nothing personal here, just words."
    assert redact_text(text).text is text
    assert redact_text(text).counts == {}


class _Fixed:
    def __init__(self, *matches):
        self.matches = matches

    def find(self, text):
        return self.matches


@pytest.mark.parametrize(
    "matches",
    [
        (PiiMatch(PiiKind.CARD, 0, 5), PiiMatch(PiiKind.PHONE, 3, 8)),  # overlapping
        (PiiMatch(PiiKind.CARD, 4, 4),),  # empty
        (PiiMatch(PiiKind.CARD, 0, 99),),  # past the end
        (PiiMatch(PiiKind.CARD, -1, 2),),  # before the start
        (PiiMatch("card", 0, 2),),  # not a kind
        ((PiiKind.CARD, 0, 2),),  # not a PiiMatch
    ],
)
def test_unusable_spans_from_a_detector_are_refused(matches):
    with pytest.raises(RedactionError) as err:
        redact_text("0123456789", _Fixed(*matches))
    assert "0123456789" not in str(err.value)


def test_spans_are_applied_in_text_order_whatever_order_the_detector_returns():
    out = redact_text(
        "aa bb cc", _Fixed(PiiMatch(PiiKind.PHONE, 6, 8), PiiMatch(PiiKind.CARD, 0, 2))
    )
    assert out.text == "[CARD] bb [PHONE]"
    assert out.counts == {PiiKind.CARD: 1, PiiKind.PHONE: 1}


def test_the_span_attribute_list_names_every_kind():
    assert {
        a.removeprefix("guardrail.pii_redacted.")
        for a in CHECK_ATTRIBUTES
        if a.startswith("guardrail.pii_redacted.")
    } == {k.value for k in PiiKind}


# ------------------------------------------------------------------ properties

FRAGMENTS = [
    "4111 1111 1111 1111",
    "4111111111111111",
    "+1 201-555-0123",
    "(201) 555-0123",
    "020 7946 0018",
    "078-05-1120",
    "QQ 12 34 56 C",
    "GB82 WEST 1234 5698 7654 32",
    "12-34-56",
    "12345678",
    "jo@example.com",
    "https://app.example/u?e=bob@example.org",
    "postgres://u:p@db.example:5432/x",
    "[EMAIL]",
    "@",
    ".",
    "-",
    " ",
    "\n",
    ":",
    "+",
    "/",
    "#",
]
TEXTS = st.lists(
    st.one_of(
        st.sampled_from(FRAGMENTS),
        st.text(alphabet="0123456789 -.+@:/()#abcxyzQGBW", max_size=12),
    ),
    max_size=12,
).map("".join)


IDEMPOTENCE_CASES = [  # found by fuzzing; each once needed a second pass to settle
    "4111111111111111(201) 555-0123",
    "12345678 +1 201-555-0123 12-34-56",
    "+1 201-555-0123 4111 1111 1111 1111)",
    "+1 201-555-0123 07700 900123",
    "020 7946 0018 4111 1111 1111 1111-",
    "07700 900123+-a.b@x.example",
    ")QQ 12 34 56 C..5a.b@x.example&.",
    "51234567812a.b@x.example..QQ123456C.",
    "(jo@example.com.-020 7946 0018",
    "#4111111111111111--jo@example.com",
    "jo@example.com-.078-05-1120#",
    # After the URL decision: a redacted spaced number must not lengthen a URL
    "https://h.example:8443/p/.+1 201-555-0123:x&jo@example.com",
    "Qhttps://h.example:8443/p/+1 201-555-0123#a.b@x.example ",
    "Q12-34-56a.b@x.example--020 7946 0018(",
    ".--..+0&4111111111111111..a.b@x.example",
]


@pytest.mark.parametrize("text", IDEMPOTENCE_CASES)
def test_redaction_settles_in_one_pass_on_known_hard_cases(text):
    once = red(text)
    assert red(once) == once


@settings(max_examples=1000, deadline=None)
@given(TEXTS)
def test_redaction_is_idempotent(text):
    once = red(text)
    assert red(once) == once


@settings(max_examples=200, deadline=None)
@given(TEXTS)
def test_redaction_is_deterministic(text):
    assert red(text) == redact_text(text, DeterministicPiiDetector()).text == red(text)


@settings(max_examples=200, deadline=None)
@given(st.text(alphabet=st.characters(blacklist_characters="0123456789@"), max_size=200))
def test_text_without_digits_or_at_signs_is_returned_unchanged(text):
    assert redact_text(text).text is text


def test_same_output_across_processes_with_different_hash_seeds():
    corpus = [frag for frag in FRAGMENTS] + [p[1] for p in POSITIVES] + NEAR_MISSES
    script = (
        "import json,sys\n"
        "from guardrail_engine.guard.redaction import redact_text\n"
        "texts=json.load(sys.stdin)\n"
        "print(json.dumps([redact_text(t).text for t in texts]))\n"
    )
    outputs = []
    for seed in ("1", "4242"):
        env = {**os.environ, "PYTHONHASHSEED": seed, "LC_ALL": "C"}
        env.pop("GEMINI_API_KEY", None)
        done = subprocess.run(
            [sys.executable, "-c", script],
            input=json.dumps(corpus),
            capture_output=True,
            text=True,
            env=env,
            check=True,
        )
        outputs.append(json.loads(done.stdout))
    assert outputs[0] == outputs[1] == [red(t) for t in corpus]


# ------------------------------------------------------------------ cost: linear, by doubling

ADVERSARIAL = {
    "digits": lambda n: "4" * n,
    "at signs": lambda n: "@" * n,
    "a@ pairs": lambda n: "a@" * (n // 2),
    "dotted local part": lambda n: "a." * (n // 2) + "@",
    "max local parts": lambda n: ("x" * 63 + "@") * (n // 64),
    "hyphenated digits": lambda n: "1-" * (n // 2),
    "plus groups": lambda n: "+1 " * (n // 3),
    "sort codes": lambda n: "12-34-56 " * (n // 9),
    "iban groups": lambda n: "GB82 " * (n // 5),
    "url schemes": lambda n: "http://" * (n // 7),
    "userinfo colons": lambda n: "a:" * (n // 2) + "@b.example",
    "nino groups": lambda n: "QQ 12 34 56 " * (n // 12),
    "spaced digits": lambda n: "1 " * (n // 2),
}
SIXTEEN_K_TOKENS = 64_000  # characters of ASCII text (4 per token)


def _best_time(text: str, repeats: int = 5) -> float:
    best = float("inf")
    for _ in range(repeats):
        start = time.perf_counter()
        redact_text(text)
        best = min(best, time.perf_counter() - start)
    return best


@pytest.mark.parametrize("name", ADVERSARIAL)
def test_cost_grows_linearly_on_adversarial_input(name):
    """8x the input must cost well under 64x (what quadratic work would take): the bound
    is 24x, a factor of 3 above linear, taking the best of five runs so a busy machine
    doesn't fail it."""
    build = ADVERSARIAL[name]
    small, large = build(SIXTEEN_K_TOKENS // 8), build(SIXTEEN_K_TOKENS)
    ratio = _best_time(large) / max(_best_time(small), 1e-4)
    assert ratio < 24, f"{name}: 8x input took {ratio:.1f}x the time"


@pytest.mark.parametrize("name", ADVERSARIAL)
def test_a_16k_token_adversarial_input_finishes_within_a_generous_bound(name):
    text = ADVERSARIAL[name](SIXTEEN_K_TOKENS)
    assert _best_time(text, repeats=1) < 2.0


# ------------------------------------------------------------------ the floor's golden set


def _golden_rows() -> list[dict]:
    return [json.loads(line) for line in GOLDEN.read_text().splitlines() if line.strip()]


URL = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://[^\s\"'<>]+")
HOST = re.compile(r"(?<![\w@.-])(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}(?![\w@.-])")
EMAIL_DOMAIN = re.compile(r"[\w.+-]+(@[A-Za-z0-9.-]+\.[A-Za-z]{2,})")
CREDENTIAL = re.compile(r"[A-Za-z0-9_\-/+=.!#~]{12,}")


def _rule_signals(text: str) -> list[str]:
    """URLs, hostnames, ``@domain`` of every address, and every long token mixing letters and
    digits (keys, tokens, passwords, key material)."""
    tokens = [
        t for t in CREDENTIAL.findall(text) if re.search(r"\d", t) and re.search("[A-Za-z]", t)
    ]
    return URL.findall(text) + HOST.findall(text) + EMAIL_DOMAIN.findall(text) + tokens


def test_exfil_and_secret_positives_keep_every_url_host_domain_and_credential():
    rows = [r for r in _golden_rows() if {"p__exfil", "p__secret"} & set(r["fires"])]
    assert len(rows) >= 40
    for row in rows:
        before, after = row["content"], red(row["content"])
        for signal in _rule_signals(before):
            assert signal in after, (row["id"], signal)


def test_secret_positives_are_untouched_and_exfil_positives_lose_only_local_parts():
    for row in _golden_rows():
        content = row["content"]
        if "p__secret" in row["fires"]:
            assert red(content) == content, row["id"]
        elif "p__exfil" in row["fires"]:
            expected = re.sub(r"[A-Za-z0-9._%+-]+@(?=[A-Za-z0-9-]+\.)", "[EMAIL]@", content)
            assert red(content) == expected, row["id"]


def test_the_detector_is_the_default_one():
    assert isinstance(DEFAULT_PII_DETECTOR, DeterministicPiiDetector)
