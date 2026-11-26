"""M7-01: credentials in a known format, on the regex port (no Guard Service, no model).

Every value is invented, and none holds the word EXAMPLE (a token body with it is a
placeholder, which has its own tests). The assertions pin what is a credential (the full
documented shape), what is not (a template, a mask, a longer token, a bare prefix) and that the
cost stays linear on crafted input.
"""

from __future__ import annotations

import json
import time

import pytest

from guardrail_engine.deterministic import (
    SECRET_PLACEHOLDER,
    SecretDetector,
    default_regex_engine,
)

DETECTOR = SecretDetector(default_regex_engine())
D = "-----"  # a PEM header is built from parts, so no literal here looks like a real key

AWS = "AKIA" + "Q7ZXW4K9PLM2H8T3"
AWS_DOCUMENTED = "AKIAIOSFODNN7EXAMPLE"  # AWS's documented example key id: a placeholder
AWS_TEMP = "ASIA" + "Q7ZXW4K9PLM2H8T3"
GITHUB_BODY = "Q7zxW4k9PlM2h8T3vB6nR1cY5dF0gJ2aS8eUxK"[:36]
GITHUB = {p: f"{p}_{GITHUB_BODY}" for p in ("ghp", "gho", "ghu", "ghs", "ghr")}
GITHUB_PAT = "github_pat_" + "11Q7zxW4k9PlM2h8T3vB6nR1cY5dF0gJ2aS8eUxK_Hp3Lm9Zq"
GOOGLE = "AIza" + "Sy" + "Q7zxW4k9PlM2h8T3vB6nR1cY5dF0gJ2aS8eUxK"[:33]
SLACK = {p: f"xox{p}-1234567890-1234567890123-Q7zxW4k9PlM2h8T3vB6nR1cY" for p in "abprs"}
STRIPE = {p: f"{p}_live_Q7zxW4k9PlM2h8T3vB6nR1cY5dF0" for p in ("sk", "rk")}
PEM_BODY = (
    "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSj\nQ7zxW4k9PlM2h8T3vB6nR1cY5dF0gJ2aS8eUxKhH\nQUJD=="
)
PEM = D + "BEGIN RSA PRIVATE KEY-----\n" + PEM_BODY + "\n-----END RSA PRIVATE KEY-----"
URL_PASSWORD = "Pw9-fakeValue"
URL = f"postgres://app:{URL_PASSWORD}@db.example.internal:5432/claims"

CREDENTIALS = [
    ("aws", AWS),
    ("aws_temporary", AWS_TEMP),
    *[(f"github_{p}", v) for p, v in GITHUB.items()],
    ("github_pat", GITHUB_PAT),
    ("google", GOOGLE),
    *[(f"slack_xox{p}", v) for p, v in SLACK.items()],
    *[(f"stripe_{p}", v) for p, v in STRIPE.items()],
    ("pem_rsa", PEM),
    ("pem_pkcs8", D + "BEGIN PRIVATE KEY-----\n" + PEM_BODY + "\n-----END PRIVATE KEY-----"),
    (
        "pem_openssh",
        D + "BEGIN OPENSSH PRIVATE KEY-----\n" + PEM_BODY + "\n-----END OPENSSH PRIVATE KEY-----",
    ),
    (
        "pem_encrypted",
        D + "BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\n"
        "DEK-Info: AES-128-CBC,0123456789ABCDEF\n\n" + PEM_BODY + "\n-----END RSA PRIVATE KEY-----",
    ),
    (
        "pem_pgp",
        D
        + "BEGIN PGP PRIVATE KEY BLOCK-----\nVersion: Example 1.0\n\n"
        + PEM_BODY
        + "\n-----END PGP PRIVATE KEY BLOCK-----",
    ),
    ("url", URL),
]


@pytest.mark.parametrize(("name", "value"), CREDENTIALS, ids=[n for n, _ in CREDENTIALS])
@pytest.mark.parametrize(
    "template",
    [
        "{}",
        "key is {} thanks",
        "key={}",
        'key="{}"',
        '{{"k": "{}"}}',
        "line one\n{}\nline three",
        "({}).",
    ],
)
def test_a_credential_is_found_wherever_it_stands_alone(name, value, template):
    text = template.format(value)
    assert DETECTOR.count(text) == 1
    redacted, n = DETECTOR.redact(text)
    assert n == 1 and SECRET_PLACEHOLDER in redacted
    if name != "url":
        assert value not in redacted
    else:
        assert URL_PASSWORD not in redacted


def test_a_url_keeps_its_scheme_user_and_host_and_loses_only_the_password():
    redacted, n = DETECTOR.redact(f"see {URL} now")
    assert n == 1
    assert redacted == "see postgres://app:[SECRET]@db.example.internal:5432/claims now"


def test_an_empty_user_is_still_a_login():
    assert DETECTOR.redact("redis://:Pw9-fakeValue@cache.example")[0] == (
        "redis://:[SECRET]@cache.example"
    )


def test_a_pem_block_is_replaced_from_header_to_footer_and_the_text_after_it_kept():
    redacted, n = DETECTOR.redact(f"key:\n{PEM}\nthat was the key")
    assert (redacted, n) == ("key:\n[SECRET]\nthat was the key", 1)


def test_a_pem_block_in_a_json_string_with_escaped_line_breaks():
    body = PEM.replace("\n", "\\n")
    redacted, n = DETECTOR.redact(f'{{"content": "{body}", "mode": 600}}')
    assert (redacted, n) == ('{"content": "[SECRET]", "mode": 600}', 1)


def test_a_pem_block_with_no_footer_is_replaced_through_its_key_lines():
    cut = D + "BEGIN PRIVATE KEY-----\n" + PEM_BODY.split("\n", 1)[0] + "\nand then prose"
    redacted, n = DETECTOR.redact(cut)
    assert n == 1 and "MIIEvQ" not in redacted and redacted.endswith("and then prose")


def test_several_credentials_are_each_replaced_and_counted():
    text = f"a {AWS} b {GITHUB['ghp']} c {URL} d"
    redacted, n = DETECTOR.redact(text)
    assert n == 3
    assert (
        redacted
        == "a [SECRET] b [SECRET] c postgres://app:[SECRET]@db.example.internal:5432/claims d"
    )


def test_a_text_with_no_credential_is_returned_as_the_same_object():
    text = "Nothing to see: AKIA is a prefix, and ghp_ too."
    redacted, n = DETECTOR.redact(text)
    assert n == 0 and redacted is text


# ------------------------------------------------------------------ what is not a credential

PASSING = [
    # templates and placeholders
    "postgres://USER:PASSWORD@HOST:5432/db",
    "postgres://user:password@localhost/db",
    "postgresql://{USER}:{PASSWORD}@{HOST}/{DB}",
    "https://user:<your-password>@example.com/",
    "https://user:${DB_PASS}@example.com/",
    "https://user:$DB_PASS@example.com/",
    "https://user:[password]@example.com/",
    "https://user:%s@example.com/",
    "https://user:%(password)s@example.com/",
    "https://user:****@example.com/",
    "https://user:xxxxxx@example.com/",
    "https://user:......@example.com/",
    "https://user:your-password@example.com/",
    "https://user:YOUR_PASSWORD_HERE@example.com/",
    "https://user:DB_PASSWORD@example.com/",
    "https://user:changeme@example.com/",
    "https://user:pass@example.com/",
    "https://user:secret@example.com/",
    "ftp://USER:PASS@HOST",
    "AKIA" + "X" * 16,
    AWS_DOCUMENTED,  # AWS's documented example, quoted in documentation
    "ghp_" + "yourTokenGoesHere0123456789abcdefghijk",
    "ghp_" + "Q7zxW4k9PlM2h8T3EXAMPLEdF0gJ2aS8eUxK",
    "AIza" + "SyYourApiKeyGoesHere0123456789abcde",
    # a password that merely starts with your, or with a bracket that isn't a template
    "AKIA****************",
    "AKIA<your-key-id>",
    "AKIA" + "0" * 16,
    "ghp_" + "x" * 36,
    "ghp_<token>",
    "ghp_YOUR_TOKEN_HERE",
    "github_pat_<token>",
    "AIza<your-api-key>",
    "AIza" + "x" * 35,
    "xox" + "b-your-token-here",
    "xoxb-<token>",
    "xox" + "b-0000-0000-0000",
    "sk_live_" + "x" * 24,
    "sk_live_<your-key>",
    "sk_live_****",
    "sk_test_FAKEEXAMPLE0123456789abcdef",  # a test-mode key is not a live credential
    "pk_live_FAKEEXAMPLE0123456789abcdef",  # a publishable key is public by design
    # a header with no key material: prose about keys
    D + "BEGIN PRIVATE KEY-----",
    D + "BEGIN PRIVATE KEY----- ... -----END PRIVATE KEY-----",
    D + "BEGIN RSA PRIVATE KEY-----\n<base64 key here>\n-----END RSA PRIVATE KEY-----",
    D + "BEGIN RSA PRIVATE KEY-----\n(truncated)\n",
    "Paste the whole block, from " + D + "BEGIN PRIVATE KEY----- to the end marker.",
    D + "BEGIN PUBLIC KEY-----\nMIIBIjANBgkqFAKEEXAMPLE\n-----END PUBLIC KEY-----",
    D + "BEGIN CERTIFICATE-----\nMIIDdzCCAl+gAwIBAgIEFAKEEXAMPLE01\n-----END CERTIFICATE-----",
    # a longer token or a word that merely contains the shape
    "X" + AWS,
    AWS + "1",
    AWS + "a",
    "0x" + AWS,
    "ghp_" + GITHUB_BODY + "0123456789" * 30,
    "xghp_" + GITHUB_BODY,
    # URLs that are not a login
    "http://example.com:8080@evil.example/",  # host and port, then @: a spoofed host
    "https://example.com:8080/path",
    "https://example.com/a:b@c",
    "mailto:someone@example.com",
    "see user:secret@host for the account",  # not a URL
    "https://example.com/?a=b&c=d@e",
    # assignments are left to the model question (see the module docstring)
    "password: hunter2",
    'password = "Pw9-fakeValue"',
    "api_key = EXAMPLE0f3a9c2e7b1d4f6a8c0e2b4d6f8a1c3e",
    "Authorization: Bearer eyJhbGciOiJIUzI1NiIs.FAKE.EXAMPLE",
    "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    # everyday text
    "",
    "Please rotate your keys quarterly and never share a password.",
    "The AWS key id starts with AKIA and is 20 characters long.",
    "uuid 123e4567-e89b-12d3-a456-426614174000 sha 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b",
]


@pytest.mark.parametrize("text", PASSING)
def test_templates_and_look_alikes_are_not_credentials(text):
    redacted, n = DETECTOR.redact(text)
    assert n == 0 and redacted is text and DETECTOR.count(text) == 0


def test_a_text_that_mixes_a_template_and_a_real_credential_keeps_only_the_template():
    text = f"template postgres://USER:PASSWORD@HOST/db and real {AWS}"
    assert DETECTOR.redact(text) == (
        "template postgres://USER:PASSWORD@HOST/db and real [SECRET]",
        1,
    )


def test_lone_surrogates_do_not_stop_the_scan():
    assert DETECTOR.count("\ud800 " + AWS) == 1


# ------------------------------------------------------------------ escapes and encodings

TOKEN_NAMES = [n for n, _ in CREDENTIALS if not n.startswith(("pem", "url"))]
BEFORE = [
    "\\n",
    "\\r\\n",
    "\\t",
    "\\f",
    "\\b",
    "\\u000a",
    "\\u0020",
    "\\/",
    '\\"',
    "%0A",
    "%0D%0A",
    "%09",
    "%20",
    "%3D",
    "%2C",
    "%2F",
    "%7E",
]
AFTER = ["\\n", "\\r\\n", "\\t", "\\u000a", "\\/", '\\"', "%0A", "%20", "%3D", "%2C"]
VALUES = dict(CREDENTIALS)


@pytest.mark.parametrize("before", BEFORE)
@pytest.mark.parametrize(("name", "value"), CREDENTIALS, ids=[n for n, _ in CREDENTIALS])
def test_a_json_escape_or_a_percent_encoded_separator_before_a_credential_is_a_boundary(
    name, value, before
):
    text = f"tokens:{before}{value}"
    assert DETECTOR.count(text) == 1, text
    redacted, n = DETECTOR.redact(text)
    assert n == 1
    assert (URL_PASSWORD if name == "url" else value) not in redacted


@pytest.mark.parametrize("after", AFTER)
@pytest.mark.parametrize(("name", "value"), CREDENTIALS, ids=[n for n, _ in CREDENTIALS])
def test_a_json_escape_or_a_percent_encoded_separator_after_a_credential_is_a_boundary(
    name, value, after
):
    text = f"{value}{after}next line"
    assert DETECTOR.count(text) == 1, text
    assert (URL_PASSWORD if name == "url" else value) not in DETECTOR.redact(text)[0]


def test_escaped_json_with_several_breaks_finds_every_credential():
    text = json.dumps({"stdout": f"tokens:\n{GITHUB['ghp']}\r\n{AWS}\t{GOOGLE}\n{STRIPE['sk']}"})
    assert "\\n" in text and DETECTOR.count(text) == 4


def test_json_nested_in_a_json_string_still_finds_every_credential():
    """A tool's body argument often holds serialised JSON, so each escape is doubled."""
    inner = json.dumps({"config": f"region=eu\n{AWS}\n{GITHUB['ghp']}"})
    text = json.dumps({"tool": "http.post", "arguments": {"url": "https://x", "body": inner}})
    assert "\\\\n" in text and DETECTOR.count(text) == 2
    twice = json.dumps({"plan": text})
    assert DETECTOR.count(twice) == 2


@pytest.mark.parametrize("name", TOKEN_NAMES)
@pytest.mark.parametrize("escape", ["\\\\n", "\\\\\\\\t", "\\\\u000a"])
def test_a_doubled_or_quadrupled_escape_before_a_credential_is_a_boundary(name, escape):
    assert DETECTOR.count(f"word{escape}{VALUES[name]}") == 1


@pytest.mark.parametrize("name", TOKEN_NAMES)
@pytest.mark.parametrize(
    "glue",
    [
        "\\u0041",  # the letter A
        "\\u0030",  # the digit 0
        "%41",  # the letter A
        "%30",  # the digit 0
        "%C3%A9",  # a letter outside ASCII
        "\\x",  # a backslash and a letter that is no escape
        "n",
    ],
)
def test_an_escape_that_encodes_a_letter_or_digit_is_not_a_boundary(name, glue):
    assert DETECTOR.count(f"word{glue}{VALUES[name]}") == 0


def test_a_documented_example_key_id_and_your_phrases_are_placeholders():
    for text in (AWS_DOCUMENTED, "ghp_" + "yourTokenGoesHere0123456789abcdefghijk"):
        assert DETECTOR.count(text) == 0
    assert DETECTOR.count(AWS) == 1  # a body without the marker is a credential


# ------------------------------------------------------------------ URL passwords


@pytest.mark.parametrize(
    ("url", "kept"),
    [
        ("postgres://u:ab:cd@host.example/db", "postgres://u:[SECRET]@host.example/db"),
        ("postgres://u:p@ss@host.example/db", "postgres://u:[SECRET]@host.example/db"),
        ("postgres://:a:b:c@host.example:5432/db", "postgres://:[SECRET]@host.example:5432/db"),
        ("postgres://u:yourSecret99@host", "postgres://u:[SECRET]@host"),
        ("postgres://u:yourcat9@host", "postgres://u:[SECRET]@host"),
        ("postgres://u:$3cret!x@host", "postgres://u:[SECRET]@host"),
        ("postgres://u:(abc)d9@host", "postgres://u:[SECRET]@host"),
        ("postgres://u:*abc9x@host", "postgres://u:[SECRET]@host"),
        ("(see http://u:Pw9xqz@host.example).", "(see http://u:[SECRET]@host.example)."),
        ("postgres://u:123456@host", "postgres://u:[SECRET]@host"),
    ],
)
def test_url_password_runs_from_the_first_colon_to_the_last_at_and_only_templates_pass(url, kept):
    assert DETECTOR.redact(url) == (kept, 1)


@pytest.mark.parametrize(
    "url",
    [
        "postgres://u:${DB_PASS}@host",
        "postgres://u:${DB_PASS}x@host",
        "postgres://u:$DB_PASS@host",
        "postgres://u:$(cat /run/pw)@host",
        "postgres://u:{PASSWORD}@host",
        "postgres://u:<password>@host",
        "postgres://u:your-password@host",
        "postgres://u:your_password@host",
        "postgres://u:yourpassword@host",
        "postgres://u:your-db-password-here@host",
        "postgres://u:DB_PASSWORD@host",  # deliberate: a variable name, not a password
        "postgres://u:54321@host",  # deliberate: up to five digits is a port
        "http://example.com:8080@evil.example/",
        "postgres://u:****@host",
    ],
)
def test_url_templates_and_the_deliberate_exceptions_pass(url):
    assert DETECTOR.count(url) == 0


# ------------------------------------------------------------------ cost on crafted input

CRAFTED_CHARS = 256 * 1024
CRAFTED = {
    "repeated key prefix": "AKIA" * (CRAFTED_CHARS // 4),
    "long token body": "ghp_" + "a" * CRAFTED_CHARS,
    "repeated pem header": (D + "BEGIN PRIVATE KEY-----\n") * (CRAFTED_CHARS // 28),
    "long pem body": D + "BEGIN PRIVATE KEY-----\n" + "QUJDREVGR0hJSktMTU5PUA==\n" * 10_000,
    "pem body then prose": D + "BEGIN PRIVATE KEY-----\nQUJDREVGR0hJSktMTU5P " + "word " * 50_000,
    "escaped line breaks": D + "BEGIN PRIVATE KEY-----" + "\\n" * (CRAFTED_CHARS // 2),
    "repeated scheme": "a://" * (CRAFTED_CHARS // 4),
    "repeated userinfo colon": "http://" + "u:" * (CRAFTED_CHARS // 2),
    "repeated userinfo at": "http://" + ":@" * (CRAFTED_CHARS // 2),
    "very long userinfo": "http://" + "a" * CRAFTED_CHARS + ":" + "b" * CRAFTED_CHARS + "@h",
    "many urls": "http://u:Fake9pw@h " * (CRAFTED_CHARS // 18),
    "many keys": (AWS + " ") * (CRAFTED_CHARS // 21),
    "slack segments": "xoxb-" + "1-" * (CRAFTED_CHARS // 2),
    "many slack": ("xox" + "b-1-1-aaaaaaaaaa ") * (CRAFTED_CHARS // 20),
    "long stripe": "sk_live_" + "A" * CRAFTED_CHARS,
    "long pat": "github_pat_" + "a" * CRAFTED_CHARS,
}


@pytest.mark.parametrize("name", CRAFTED)
def test_crafted_input_near_the_size_limit_is_scanned_in_linear_time(name):
    """RE2 has no backtracking, and the per-match checks work on the match only; the bound
    here is generous (seconds, where the measured worst case is about 0.2 s) so a slow CI
    machine passes, and a quadratic scan (minutes) fails."""
    text = CRAFTED[name]
    started = time.perf_counter()
    DETECTOR.count(text)
    DETECTOR.redact(text)
    assert time.perf_counter() - started < 5.0
