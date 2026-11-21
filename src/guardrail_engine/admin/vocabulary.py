"""The harm-vocabulary tripwire for uploaded golden sets (M2-06).

A tenant's golden set may later be sent to the model by the test endpoint (M2-05), and the
project rule (user instruction, 2026-11-17) is that no harm-labelled or prohibited content is
ever sent to the provider by our tooling. So an upload is read for harm vocabulary before it is
stored: any string of a row that contains a harm term, as written, after normalisation
(zero-width characters stripped, NFKC, combining marks stripped, look-alike letters mapped to
ASCII) or inside a base64 run decoded up to two levels, refuses the **upload**.

This is a tripwire, not a classifier. It is deliberately coarse, so it will refuse some honest
content that merely mentions a word (a claims example about "child" cover, say); the tenant
rewords it. It never echoes the word: the message names the view it matched in and the row.

The word list and the views are those of the red-team corpus builder's tripwire
(``redteam/build_corpus.py``); ``tests/admin/test_golden_vocabulary.py`` fails if the two drift.
"""

# ruff: noqa: RUF001  (the look-alike table is made of ambiguous letters on purpose)
from __future__ import annotations

import base64
import re
import unicodedata

HARM_TERMS = re.compile(
    r"\b(weapon|explosive|bomb|firearm|gun|poison|suicid|self-harm|overdose|malware|ransomware"
    r"|exploit kit|synthes|narcotic|cocaine|heroin|meth|counterfeit|launder|hack into|kill|murder"
    r"|terror|abuse|child|porn|sexual|fraud scheme|steal)\w*",
    re.IGNORECASE,
)

# The corpus is built around encodings (zero-width characters, look-alike letters, base64), so
# the tripwire also reads each string as a model would after decoding it, not only as written.
_LOOKALIKES = {
    **dict(zip("аеорсіухѕјԁһ", "aeopciyxsjdh", strict=True)),  # Cyrillic, lower case
    **dict(zip("АВЕКМНОРСТХУ", "ABEKMHOPCTXY", strict=True)),  # Cyrillic, upper case
    **dict(zip("αεορινκτυχ", "aeopinktux", strict=True)),  # Greek, lower case
    **dict(zip("ΑΒΕΖΗΙΚΜΝΟΡΤΥΧ", "ABEZHIKMNOPTYX", strict=True)),  # Greek, upper case
}
_LOOKALIKE_TABLE = str.maketrans(_LOOKALIKES)
# A run is 8 or more characters counting its ``=`` padding (``Ym9tYg==`` is "bomb"); shorter
# runs are ordinary words.
_B64_RUN = re.compile(r"[A-Za-z0-9+/_-]{6,}={0,2}")
_B64_MIN = 8
B64_DEPTH = 2


def normalise(text: str) -> str:
    """Strip format characters (category Cf: zero-width characters and joiners), apply NFKC,
    strip combining marks (category Mn, after NFKD: ``o`` + U+0301 is ``o``) and map look-alike
    letters back to ASCII."""
    kept = "".join(ch for ch in text if unicodedata.category(ch) != "Cf")
    decomposed = unicodedata.normalize("NFKD", kept)
    bare = "".join(ch for ch in decomposed if unicodedata.category(ch) != "Mn")
    return unicodedata.normalize("NFKC", bare).translate(_LOOKALIKE_TABLE)


def _decoded_runs(text: str) -> list[str]:
    """The text of every run in ``text`` that is valid base64 (standard or URL-safe) and
    decodes to UTF-8."""
    out = []
    for run in _B64_RUN.findall(text):
        if len(run) < _B64_MIN:
            continue
        body = run.rstrip("=").replace("-", "+").replace("_", "/")
        if len(body) % 4 == 1:
            body = body[:-1]
        try:
            out.append(base64.b64decode(body + "=" * (-len(body) % 4), validate=True).decode())
        except ValueError:  # not base64, or not text (UnicodeDecodeError is a ValueError)
            continue
    return out


_HEX_RUN = re.compile(r"(?:[0-9A-Fa-f]{2}){4,}")
_SPACED_SEP = r"[\s._*/,-]"  # any whitespace (newline, tab) and the usual separators
_SPACED_RUN = re.compile(rf"(?<![^\W_])(?:[^\W_]{_SPACED_SEP}{{1,2}}){{2,}}[^\W_](?![^\W_])")
_LEET_BASE = {"0": "o", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"}
_LEET_TABLES = (
    str.maketrans({**_LEET_BASE, "1": "i"}),
    str.maketrans({**_LEET_BASE, "1": "l"}),
)


_PERCENT_RUN = re.compile(r"(?:%[0-9A-Fa-f]{2})+")


def _percent_decoded(text: str) -> str:
    """``%XX`` runs decoded as UTF-8 (what a URL decoder does; no ``urllib``: the engine's core
    modules import no network-flavoured library)."""
    if "%" not in text:
        return text
    return _PERCENT_RUN.sub(
        lambda m: bytes.fromhex(m.group(0).replace("%", "")).decode("utf-8", errors="replace"),
        text,
    )


def _hex_decoded(text: str) -> list[str]:
    """Every run of at least four hex-encoded bytes that decodes to UTF-8 text."""
    out = []
    for run in _HEX_RUN.findall(text):
        try:
            out.append(bytes.fromhex(run).decode())
        except ValueError:  # not text
            continue
    return out


def _despaced(text: str) -> str:
    """Runs of single characters split by spaces or dots (``b o m b``, ``b.o.m.b``) joined."""
    return _SPACED_RUN.sub(lambda m: re.sub(_SPACED_SEP, "", m.group(0)), text)


def tripwire_views(text: str) -> list[str]:
    """The views of ``text`` in which the harm vocabulary matches: ``raw``, ``normalised``,
    ``percent`` (URL-decoded), ``hex`` (a run of hex-encoded bytes decoded), ``spaced``
    (single characters split by spaces or dots, joined), ``leet`` (0o 1i 1l 3e 4a 5s 7t @a $s)
    and ``base64 (depth n)``. Never the matched text, so a message can't echo it.

    Not caught, and accepted as a residual (decided 2026-11-17): look-alike letters outside the
    table above (Armenian, say), words in other languages or paraphrases, and encodings nested
    in more than the layers listed."""
    views = []
    if HARM_TERMS.search(text):
        views.append("raw")
    flat = normalise(text)
    if flat != text and HARM_TERMS.search(flat):
        views.append("normalised")
    if HARM_TERMS.search(normalise(_percent_decoded(flat))) and _percent_decoded(flat) != flat:
        views.append("percent")
    if any(HARM_TERMS.search(normalise(d)) for d in _hex_decoded(flat)):
        views.append("hex")
    joined = _despaced(flat)
    if joined != flat and HARM_TERMS.search(joined):
        views.append("spaced")
    leets = (flat.translate(table) for table in _LEET_TABLES)
    if any(variant != flat and HARM_TERMS.search(variant) for variant in leets):
        views.append("leet")
    layer = [flat]
    for depth in range(1, B64_DEPTH + 1):
        layer = [normalise(d) for t in layer for d in _decoded_runs(t)]
        if any(HARM_TERMS.search(t) for t in layer):
            views.append(f"base64 depth {depth}")
    return views


def strings_tripwire(*texts: str) -> list[str]:
    """The views in which any of ``texts`` has a harm-vocabulary word, each string on its own
    (so an encoded run is decoded whole). Empty: clean. Never the matched text."""
    found: set[str] = set()
    for text in texts:
        found.update(tripwire_views(text))
    return sorted(found)
