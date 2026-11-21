"""The diff between two bundle documents, and the URL redaction it applies (M1-11, M2-02).

A diff goes into a class A audit event, so a URL field's value (which may carry a bearer secret
in its path or query) is never recorded: only its scheme, host (unless it looks like a token)
and SHA-256 of the full value. Moved here from ``engine/bootstrap.py`` so the Admin API's draft
audit can use it without importing the composition root; that module still re-exports it.
"""

from __future__ import annotations

import hashlib
import json
import re
import typing
from collections.abc import Iterator, Mapping
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict

from guardrail_engine.policy.schema import URL_FORMAT, Bundle


class _Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class DiffEntry(_Frozen):
    """One change between the active bundle document and the published one. ``path`` is a
    JSON pointer (RFC 6901) into the document."""

    path: str
    op: Literal["add", "remove", "replace"]
    before: Any = None
    after: Any = None


# ---------------------------------------------------------------------- the diff


def document_diff(before: Any, after: Any, path: str = "") -> tuple[DiffEntry, ...]:
    """The changes from JSON value ``before`` to ``after``: objects compared key by key,
    arrays index by index, anything else replaced when it differs (``1`` and ``1.0`` differ,
    ``true`` and ``1`` differ, as their canonical JSON does). Values are copied as they are:
    use :func:`bundle_diff` for bundle documents."""
    if _container(before, Mapping) and _container(after, Mapping):
        out: list[DiffEntry] = []
        for key in sorted(set(before) | set(after)):
            sub = f"{path}/{_escape(str(key))}"
            if key not in after:
                out.append(DiffEntry(path=sub, op="remove", before=before[key]))
            elif key not in before:
                out.append(DiffEntry(path=sub, op="add", after=after[key]))
            else:
                out.extend(document_diff(before[key], after[key], sub))
        return tuple(out)
    if isinstance(before, list) and isinstance(after, list):
        out = []
        for i in range(max(len(before), len(after))):
            sub = f"{path}/{i}"
            if i >= len(after):
                out.append(DiffEntry(path=sub, op="remove", before=before[i]))
            elif i >= len(before):
                out.append(DiffEntry(path=sub, op="add", after=after[i]))
            else:
                out.extend(document_diff(before[i], after[i], sub))
        return tuple(out)
    if _canonical(before) == _canonical(after):
        return ()
    return (DiffEntry(path=path, op="replace", before=before, after=after),)


def bundle_diff(before: Mapping[str, Any], after: Mapping[str, Any]) -> tuple[DiffEntry, ...]:
    """:func:`document_diff` of two bundle documents after :func:`redact_urls` on both, so a
    URL field's value is never recorded, only its summary; a changed URL still shows up as a
    change (its hash differs)."""
    return document_diff(redact_urls(before), redact_urls(after))


def _container(value: Any, kind: type) -> bool:
    """A URL summary is a leaf: a changed URL is one ``replace``, not one per summary key."""
    return isinstance(value, kind) and not isinstance(value, UrlSummary)


def _escape(key: str) -> str:
    return key.replace("~", "~0").replace("/", "~1")


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


# ---------------------------------------------------------------------- URL fields

_ANY = "*"


_UNION_TYPE = type(int | str)  # types.UnionType; the policy package imports no ``types``


def url_field_paths(model: type[BaseModel] = Bundle) -> frozenset[tuple[str, ...]]:
    """The document paths of every field ``model``'s schema marks as a URL
    (:data:`~guardrail_engine.policy.schema.URL_FORMAT`), with ``*`` for any list index or
    mapping key. For the bundle schema: ``("escalation", "url")``."""
    found: set[tuple[str, ...]] = set()

    def walk(cls: type[BaseModel], prefix: tuple[str, ...], seen: frozenset[type]) -> None:
        for name, field in cls.model_fields.items():
            key = field.alias or name
            extra = field.json_schema_extra
            if isinstance(extra, dict) and all(extra.get(k) == v for k, v in URL_FORMAT.items()):
                found.add((*prefix, key))
            for sub, suffix in _models_in(field.annotation):
                if sub not in seen:
                    walk(sub, (*prefix, key, *suffix), seen | {sub})

    walk(model, (), frozenset({model}))
    return frozenset(found)


def _models_in(annotation: Any) -> Iterator[tuple[type[BaseModel], tuple[str, ...]]]:
    origin = typing.get_origin(annotation)
    args = typing.get_args(annotation)
    if isinstance(annotation, type) and issubclass(annotation, BaseModel):
        yield annotation, ()
    elif origin in (typing.Union, _UNION_TYPE):
        for arg in args:
            yield from _models_in(arg)
    elif origin in (list, tuple, set, frozenset) and args:
        for arg in args:
            if arg is not Ellipsis:
                for cls, suffix in _models_in(arg):
                    yield cls, (_ANY, *suffix)
    elif origin in (dict, Mapping) and len(args) == 2:
        for cls, suffix in _models_in(args[1]):
            yield cls, (_ANY, *suffix)


BUNDLE_URL_FIELDS = url_field_paths(Bundle)


def redact_urls(document: Any, paths: frozenset[tuple[str, ...]] = BUNDLE_URL_FIELDS) -> Any:
    """A copy of ``document`` with every value at a URL path replaced by
    :func:`summarize_url`. A missing or null URL stays as it is."""

    def walk(value: Any, at: tuple[str, ...]) -> Any:
        if value is not None and any(_matches(p, at) for p in paths):
            return summarize_url(value)
        if isinstance(value, Mapping):
            return {k: walk(v, (*at, str(k))) for k, v in value.items()}
        if isinstance(value, list):
            return [walk(v, (*at, str(i))) for i, v in enumerate(value)]
        return value

    return walk(document, ())


def _matches(pattern: tuple[str, ...], at: tuple[str, ...]) -> bool:
    return len(pattern) == len(at) and all(p in (_ANY, a) for p, a in zip(pattern, at, strict=True))


class UrlSummary(dict[str, str]):
    """What :func:`summarize_url` returns: a plain mapping (it serialises as a JSON object),
    marked so :func:`document_diff` compares it whole."""


_SCHEME_AND_AUTHORITY = re.compile(r"(?P<scheme>[A-Za-z][A-Za-z0-9+.-]*)://(?P<authority>[^/?#]*)")
_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
_REG_NAME = re.compile(rf"{_LABEL}(?:\.{_LABEL})*\.?")
_IP_LITERAL = re.compile(r"\[[0-9A-Fa-f:.]+\]")
_PORT = re.compile(r"[0-9]{1,5}")


def summarize_url(value: Any) -> UrlSummary:
    """What the class A diff records of a URL: ``{"scheme", "host", "sha256"}``, where
    ``sha256`` is over the full value, so a change is visible and a known URL can be matched,
    but no path, query, fragment, user information or port is kept. A value that doesn't
    parse cleanly as ``scheme://host[:port]...`` (control characters, spaces, non-ASCII,
    backslashes, percent-encoding in the authority, an invalid host or port) is recorded as
    ``{"sha256"}`` only.

    **A host that may itself be the secret is withheld**: some webhook services
    issue a random per-endpoint subdomain. Then only ``{"scheme", "sha256"}`` is recorded.
    See :func:`token_like_label` for the rule; an IP address is always kept."""
    text = value if isinstance(value, str) else _canonical(value)
    digest = "sha256:" + hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()
    hashed = UrlSummary(sha256=digest)
    if not isinstance(value, str) or not all("\x21" <= ch <= "\x7e" for ch in value):
        return hashed
    match = _SCHEME_AND_AUTHORITY.match(value)
    if match is None:
        return hashed
    authority = match["authority"]
    if "\\" in authority or "%" in authority:
        return hashed  # parsers disagree on these; the hash alone is safe
    host_port = authority.rpartition("@")[2]  # user information, if any, is dropped
    if host_port.startswith("["):
        end = host_port.find("]")
        host, rest = host_port[: end + 1], host_port[end + 1 :]
        if end < 0 or not _IP_LITERAL.fullmatch(host):
            return hashed
    else:
        host, sep, port = host_port.partition(":")
        rest = sep + port
        if not _REG_NAME.fullmatch(host):
            return hashed
    if rest and not (rest.startswith(":") and _PORT.fullmatch(rest[1:])):
        return hashed
    scheme = match["scheme"].lower()
    if not host.startswith("[") and any(token_like_label(lb) for lb in host.lower().split(".")):
        return UrlSummary(scheme=scheme, sha256=digest)
    return UrlSummary(scheme=scheme, host=host.lower(), sha256=digest)


_HEX = re.compile(r"[0-9a-f]+")
TOKEN_MIN_MIXED = 16
"""A label (hyphens removed) at least this long that mixes letters and digits, or is all hex
digits, looks like a token: 64 bits of hex, more of base32 or base64url."""
TOKEN_MIN_PART = 26
"""A hyphen-separated part at least this long looks like a token whatever its characters:
the length of a 128-bit value in base32, longer than nearly every English word."""


def token_like_label(label: str) -> bool:
    """Whether a lowercase DNS label looks like a random token, so the host is withheld:

    1. the label with its hyphens removed is at least 16 characters long and contains both
       a letter and a digit (``a1b2c3d4e5f6g7h8secret``, ``api-v2-cluster-0042``); or
    2. the label with its hyphens removed is at least 16 characters of hex digits only
       (digits alone included: ``0123456789abcdef``, ``4096409640964096``); or
    3. any hyphen-separated part of it is at least 26 characters long (a 128-bit base32
       token made only of letters).

    So ``hooks.example.com``, ``203.0.113.9`` and long wordy hosts such as
    ``notifications-gateway-service.eu-west-1.example.com`` keep their host; a 16-character
    random subdomain mixing letters and digits doesn't. The rule leans towards withholding:
    a wordy label with a number in it (``service-2024-notifications``) is withheld too, and
    the hash still identifies the URL."""
    compact = label.replace("-", "")
    if len(compact) >= TOKEN_MIN_MIXED:
        if any(ch.isdigit() for ch in compact) and any(ch.isalpha() for ch in compact):
            return True
        if _HEX.fullmatch(compact):
            return True
    return any(len(part) >= TOKEN_MIN_PART for part in label.split("-"))
