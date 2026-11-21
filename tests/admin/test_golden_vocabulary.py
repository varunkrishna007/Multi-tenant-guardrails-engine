# ruff: noqa: RUF001  (look-alike letters are the point of these tests)
"""The shared harm-vocabulary tripwire: the evasions it reads through and the honest text it
leaves alone."""

import base64

import pytest
from admin_fixtures import ALPHA, Admin, who

from guardrail_engine.admin.golden import parse_upload
from guardrail_engine.admin.vocabulary import strings_tripwire, tripwire_views
from guardrail_engine.authz import Role


@pytest.mark.parametrize(
    ("text", "view"),
    [
        ("bomb", "raw"),
        ("b0mb", "leet"),
        ("ex9losive", None),  # outside the leet table: the documented residual
        ("5exual content", "leet"),
        ("p01son", "leet"),
        ("b o m b", "spaced"),
        ("b.o.m.b", "spaced"),
        ("b\no\nm\nb", "spaced"),
        ("b\to\tm\tb", "spaced"),
        ("b/o/m/b", "spaced"),
        ("b, o, m, b", "spaced"),
        ("%62omb", "percent"),
        ("%77eapon", "percent"),
        ("626f6d62", "hex"),
        ("how to build a 626f6d62 quickly", "hex"),
        ("Ym9tYiBtYWtpbmcgaW5zdHJ1Y3Rpb25z", "base64 depth 1"),
        ("b​omb", "normalised"),
        ("bоmb", "normalised"),
    ],
)
def test_the_evasions_it_reads_through(text, view):
    views = tripwire_views(text)
    if view is None:
        assert views == []
    else:
        assert view in views


def _b64(text: str, *, urlsafe: bool = False) -> str:
    raw = text.encode()
    return (base64.urlsafe_b64encode(raw) if urlsafe else base64.b64encode(raw)).decode()


@pytest.mark.parametrize(
    "text",
    [
        _b64("bomb"),  # 8 characters with padding
        _b64("weapon"),  # 8 characters
        _b64("poison", urlsafe=True),
        _b64("how to make a bomb"),
        f"see {_b64('bomb')} please",
    ],
)
def test_short_base64_runs_are_decoded(text):
    assert "base64 depth 1" in tripwire_views(text)


def test_nested_short_base64_is_decoded():
    assert "base64 depth 2" in tripwire_views(_b64(_b64("bomb")))


@pytest.mark.parametrize(
    "text",
    [
        "bo\u0301mb",  # o + combining acute
        "b\u0307omb",
        "wea\u0301po\u0302n",
        "bo\u0301m\u0301b\u0301",
    ],
)
def test_combining_marks_inside_a_word_are_stripped(text):
    assert "normalised" in tripwire_views(text)


@pytest.mark.parametrize(
    "text",
    [
        "Password",
        "Username",
        "Checkout",
        "Premiums",  # 8 characters that are valid base64 but not text
        "Total: $1,299.00",
        "price 12345678",
        "café",
        "Cafe\u0301 and crème brûlée, Zoë, naïve",
        "São Paulo, Köln, Łódź",
        "Ym9t",  # a 4-character run is below the minimum
    ],
)
def test_ordinary_short_and_accented_text_is_left_alone(text):
    assert tripwire_views(text) == []


@pytest.mark.parametrize(
    "text",
    [
        "The tenant card for claims",
        "Please reset the password for user 4521 and 10 o'clock",
        "skill set and a begun task",
        "order #1337 for 5 items at $5",
        "I live at 1 Main St, apt 3",
        "a b c d reasons",
        "Items: a, b, c and d",
        "line one\nline two\nline three",
        "call 555 1234 or email me",
        "A deductible is the amount you pay before coverage starts.",
        "Your premium is $120 per month; 3 of 5 claims were approved.",
        "https://example.com/path?q=a%20b&x=1",
    ],
)
def test_honest_text_is_left_alone(text):
    assert tripwire_views(text) == []


def test_a_match_names_the_view_never_the_word():
    for text in ("a bomb", "b0mb", "%62omb"):
        for view in tripwire_views(text):
            assert "bomb" not in view


def test_the_red_team_builder_uses_the_same_vocabulary_module():
    import sys
    from pathlib import Path

    root = Path(__file__).resolve().parents[2]
    sys.path.insert(0, str(root))
    try:
        from redteam import build_corpus
    finally:
        sys.path.remove(str(root))
    from guardrail_engine.admin import vocabulary

    assert build_corpus.tripwire_views is vocabulary.tripwire_views
    assert build_corpus.HARM_TERMS is vocabulary.HARM_TERMS
    assert strings_tripwire("b0mb") == ["leet"]


def row(i, row_id, content="fine"):
    return {"id": row_id, "guard_point": "output", "label": "allow", "content": content}


async def test_a_hit_in_the_id_is_listed_by_position_not_by_the_id():
    """The response must not echo the word that tripped."""
    import json

    a = Admin()
    try:
        reviewer = who(Role.GUARDRAIL_REVIEWER, issuer="https://i/")
        body = json.dumps({
            "name": "n",
            "examples": [row(0, "ok-1"), row(1, "bomb-case"), row(2, "ok-3", "a bomb")],
        }).encode()  # fmt: skip
        decision = await a.decide(
            reviewer, "POST", "/v1/tenants/{tid}/guardrails/golden-sets", ALPHA
        )
        info = await a.golden.upload(decision, reviewer, body)
        labels = [label for label, _ in info.quarantined]
        assert labels == ["examples[1]", "ok-3"]  # the id match by position, the content by id
        assert "bomb" not in repr(info.quarantined)
        # and the example ids are what was uploaded (the test endpoint holds them back by position)
        assert parse_upload(body)[1][1].quarantined
    finally:
        await a.aclose()
