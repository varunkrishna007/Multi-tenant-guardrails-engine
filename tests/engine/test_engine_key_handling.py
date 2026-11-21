"""M1-11: key handling. The API key comes from ``GEMINI_API_KEY`` only and never appears in a
log line, a ``repr`` or ``str``, or an exception message, across building, checks (answered,
failed, auth failure) and shutdown. The key is a sentinel set with ``monkeypatch``."""

from __future__ import annotations

import copy
import hashlib
import logging
import pickle
import random
import re
import string

import httpx
import pytest
from engine_fixtures import adapter_settings, answer_everything, bundle, ctx, directory, verifier

from guardrail_engine.decision import FakeDecisionModel
from guardrail_engine.engine import ApiKey, EngineSettings, SettingsError, build_engine
from guardrail_engine.gateway import InMemoryUsageMeter, RecordingAlertSink
from guardrail_engine.guard import Decision, InMemoryAuditSink, Reason

SENTINEL = "AIzaSENTINEL-m1-11-do-not-leak-7f3c9a"


class Seen:
    """Everything the test produced that a key could leak into."""

    def __init__(self) -> None:
        self.texts: list[str] = []

    def add(self, *objects: object) -> None:
        for obj in objects:
            self.texts += [repr(obj), str(obj)]

    def error(self, exc: BaseException) -> None:
        while exc is not None:
            self.add(exc, *exc.args)
            exc = exc.__cause__ or exc.__context__

    def logs(self, caplog: pytest.LogCaptureFixture) -> None:
        formatter = logging.Formatter("%(name)s %(levelname)s %(message)s")
        for record in caplog.records:
            self.texts.append(formatter.format(record))  # includes any traceback

    def assert_clean(self) -> None:
        leaks = [t for t in self.texts if SENTINEL in t]
        assert leaks == [], f"the key leaked into {len(leaks)} outputs"
        assert len(self.texts) > 10  # the test really looked at things


def provider(request: httpx.Request) -> httpx.Response:
    """Stand-in for the Decisions API, steered by the content of the check."""
    assert request.headers["x-goog-api-key"] == SENTINEL  # the key is sent, in the header only
    assert SENTINEL not in str(request.url)
    body = request.content.decode()
    if "please-fail-transport" in body:
        raise httpx.ConnectError("connection refused")
    if "please-fail-500" in body:
        return httpx.Response(500, json={"error": {"code": 500, "status": "INTERNAL"}})
    if "please-fail-auth" in body:
        return httpx.Response(
            400,
            json={
                "error": {
                    "code": 400,
                    "status": "INVALID_ARGUMENT",
                    "message": "API key not valid. Please pass a valid API key.",
                    "details": [{"reason": "API_KEY_INVALID"}],
                }
            },
        )
    return answer_everything(request)


async def test_sentinel_key_never_leaks_through_the_adapter(monkeypatch, caplog):
    caplog.set_level(logging.DEBUG)  # every logger, httpx and httpcore included
    monkeypatch.setenv("GEMINI_API_KEY", SENTINEL)
    seen = Seen()
    alerts, meter, audit = RecordingAlertSink(), InMemoryUsageMeter(), InMemoryAuditSink()
    settings = adapter_settings()
    v = verifier()
    async with httpx.AsyncClient(transport=httpx.MockTransport(provider)) as client:
        engine = await build_engine(
            settings,
            verifier=v,
            tenants=directory(),
            http_client=client,
            alerts=alerts,
            meter=meter,
            audit=audit,
        )
        seen.add(settings, engine, engine.model, engine.model._config, engine.guard)
        seen.add(engine.gateway, engine._api_key, f"{engine._api_key}")
        assert repr(engine._api_key) == "ApiKey('***')" and str(engine._api_key) == "***"
        assert "api_key='***'" in repr(engine)

        await engine.bootstrap_publish(bundle())
        verdicts = [
            await engine.check(ctx(v), "output", content)
            for content in (
                "Hello.",
                "please-fail-transport",
                "please-fail-500",
                "please-fail-auth",  # opens the auth breaker and pages
                "Hello again.",  # fails fast on the open breaker
            )
        ]
        await engine.gateway.drain()
        await engine.shutdown()

    assert [v.decision for v in verdicts] == [Decision.ALLOW] + [Decision.BLOCK] * 4
    assert all(v.reason is Reason.MODEL_FAILURE for v in verdicts[1:])
    assert verdicts[3].failure_kind == "auth"
    assert alerts.pages(), "the auth failure paged"
    for verdict in verdicts:
        seen.add(verdict, verdict.model_dump_json())
    seen.add(*alerts.alerts, meter, *audit.verdicts)
    seen.logs(caplog)
    seen.assert_clean()


async def test_sentinel_key_never_leaks_over_real_sockets(monkeypatch, caplog, server):
    """The same through the adapter's own client and httpcore's debug logging, on a local
    server (127.0.0.1)."""
    caplog.set_level(logging.DEBUG)
    monkeypatch.setenv("GEMINI_API_KEY", SENTINEL)
    seen = Seen()
    v = verifier()
    engine = await build_engine(
        adapter_settings(gemini={"base_url": server.base_url}), verifier=v, tenants=directory()
    )
    seen.add(engine, engine.model, engine.model._client)
    await engine.bootstrap_publish(bundle())
    for _ in range(2):
        verdict = await engine.check(ctx(v), "output", "Hello.")
        assert verdict.decision is Decision.ALLOW
        seen.add(verdict, verdict.model_dump_json())
    await engine.shutdown()
    assert any(r.name.startswith("httpcore") for r in caplog.records)  # debug logs captured
    seen.logs(caplog)
    seen.assert_clean()


async def test_sentinel_key_never_leaks_with_the_fake(monkeypatch, caplog):
    """The criterion's own scenario: a sentinel key set, a check with the fake model."""
    caplog.set_level(logging.DEBUG)
    monkeypatch.setenv("GEMINI_API_KEY", SENTINEL)
    seen = Seen()
    v = verifier()
    engine = await build_engine(
        adapter_settings(), verifier=v, tenants=directory(), model=FakeDecisionModel()
    )
    seen.add(engine, engine.settings, engine.model)
    await engine.bootstrap_publish(bundle())
    verdict = await engine.check(ctx(v), "output", "Hello.")
    seen.add(verdict, verdict.model_dump_json())
    await engine.shutdown()
    seen.logs(caplog)
    seen.assert_clean()
    assert "api_key=None" in repr(engine)  # with a model override the key isn't even read


async def test_sentinel_key_never_leaks_from_startup_errors(monkeypatch, caplog, tmp_path):
    caplog.set_level(logging.DEBUG)
    monkeypatch.setenv("GEMINI_API_KEY", SENTINEL)
    seen = Seen()
    v = verifier()

    attempts = [
        # paid tier not declared
        lambda: build_engine(adapter_settings(gemini={"paid_tier": False}), verifier=v),
        # a floor file that doesn't exist
        lambda: build_engine(
            adapter_settings(catalog={"floor_files": [str(tmp_path / "nope.json")]}), verifier=v
        ),
        # Postgres without a DSN
        lambda: build_engine(adapter_settings(store={"kind": "postgres"}), verifier=v),
    ]
    for attempt in attempts:
        with pytest.raises(SettingsError) as raised:
            await attempt()
        seen.error(raised.value)

    # The key pasted into the settings, in a mapping and in a file.
    for data in ({"gemini": {"api_key": SENTINEL}}, {"gemini": {"model": 1, "x": SENTINEL}}):
        with pytest.raises(SettingsError) as raised:
            EngineSettings.from_mapping(data)
        seen.error(raised.value)
    path = tmp_path / "engine.toml"
    path.write_text(f'[gemini]\napi_key = "{SENTINEL}"\n')
    with pytest.raises(SettingsError) as raised:
        EngineSettings.from_file(path)
    seen.error(raised.value)

    seen.logs(caplog)
    seen.assert_clean()


def test_the_key_object_cannot_be_pickled_or_copied():
    key = ApiKey(SENTINEL)
    for attempt in (lambda: pickle.dumps(key), lambda: copy.copy(key)):
        with pytest.raises(TypeError) as raised:
            attempt()
        assert SENTINEL not in str(raised.value)
    assert key.reveal() == SENTINEL
    assert SENTINEL not in key.fingerprint()


@pytest.mark.parametrize("value", ["", "   ", None])
def test_a_blank_key_is_refused(value):
    with pytest.raises(ValueError, match="non-blank"):
        ApiKey(value)  # type: ignore[arg-type]


# ----------------------------------------------------------------------
def expected_kind(value: str) -> str:
    """The kind of problem the error must name for ``value`` (the first one found)."""
    if value != value.strip():
        return "has surrounding whitespace"
    if any(ch < " " or "\x7f" <= ch <= "\x9f" for ch in value):
        return "has a control character"
    return "has a non-ASCII character"


@pytest.mark.parametrize(
    "value",
    [
        SENTINEL + "\n",  # a secret file's trailing newline: the usual case
        SENTINEL + "\r\n",
        " " + SENTINEL,
        SENTINEL + "\t",
        SENTINEL[:10] + "\x1b" + SENTINEL[10:],  # (a NUL can't be put in the environment)
        SENTINEL[:10] + "\x7f" + SENTINEL[10:],
        SENTINEL[:10] + "\N{LATIN SMALL LETTER E WITH ACUTE}" + SENTINEL[10:],  # non-ASCII
        SENTINEL + "\N{NO-BREAK SPACE}",
    ],
)
async def test_a_key_with_whitespace_or_control_characters_refuses_to_start(
    monkeypatch, caplog, value
):
    """Refused at startup (not stripped), naming the problem, never the key or any part."""
    caplog.set_level(logging.DEBUG)
    monkeypatch.setenv("GEMINI_API_KEY", value)
    with pytest.raises(SettingsError) as raised:
        await build_engine(adapter_settings(), verifier=verifier())
    [problem] = raised.value.problems
    # The error names the kind of problem it found (decided 2026-11-17).
    assert problem.startswith(f"GEMINI_API_KEY: {expected_kind(value)}")
    assert problem.endswith("it is refused, not stripped. Fix the stored secret")
    with pytest.raises(ValueError) as direct:
        ApiKey(value)
    seen = Seen()
    seen.error(raised.value)
    seen.error(direct.value)
    seen.logs(caplog)
    for text in seen.texts:
        for part in (SENTINEL, SENTINEL[:6], SENTINEL[-6:], value.strip()):
            assert part not in text


@pytest.mark.parametrize("bad", ["\x00", "\n", "\x1f", "\x85"])
def test_the_key_object_refuses_control_characters_without_echoing(bad):
    with pytest.raises(ValueError, match="control character") as raised:
        ApiKey(SENTINEL[:10] + bad + SENTINEL[10:])
    assert SENTINEL[:10] not in str(raised.value) and SENTINEL[10:] not in str(raised.value)


async def test_an_inner_space_is_not_refused(monkeypatch):
    """Only surrounding whitespace and control or non-ASCII characters are refused: an inner
    space is a valid header value."""
    monkeypatch.setenv("GEMINI_API_KEY", "sentinel not-a-real-key")
    engine = await build_engine(adapter_settings(), verifier=verifier())
    await engine.shutdown()


async def test_a_whitespace_only_key_is_reported_as_not_set(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", " \n")
    with pytest.raises(SettingsError, match=r"GEMINI_API_KEY: not set in the environment"):
        await build_engine(adapter_settings(), verifier=verifier())


# ---------------------------------------------------------------------- key_id


async def test_key_id_is_the_secret_managers_version_id_when_given(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", SENTINEL)
    version = "projects/p/secrets/gemini-key/versions/7"
    engine = await build_engine(adapter_settings(), verifier=verifier(), key_id=lambda: version)
    try:
        assert engine.gateway._key_id() == version
    finally:
        await engine.shutdown()


async def test_key_id_defaults_to_a_12_hex_digit_fingerprint(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", SENTINEL)
    engine = await build_engine(adapter_settings(), verifier=verifier())
    try:
        key_id = engine.gateway._key_id()
    finally:
        await engine.shutdown()
    assert re.fullmatch(r"sha256:[0-9a-f]{12}", key_id)
    assert key_id == "sha256:" + hashlib.sha256(SENTINEL.encode()).hexdigest()[:12]


# ---------------------------------------------------------------------- sentinel

MARKER = "KyMrkQ7vZ"
KEY_LENGTH = 173
"""Every bad key below is this long, a number no message has a reason to contain."""


def bad_key(offending: str, where: str) -> str:
    """A key holding ``MARKER`` and ``offending``, ``KEY_LENGTH`` characters long, otherwise
    random letters and digits (fixed seed), so no 4-character piece of it is ordinary text."""
    rng = random.Random(20261117)
    body = MARKER + "".join(
        rng.choice(string.ascii_letters + string.digits)
        for _ in range(KEY_LENGTH - len(MARKER) - 1)
    )
    if where == "start":
        return offending + body
    if where == "end":
        return body + offending
    return body[:40] + offending + body[40:]


def leak_texts(exc: BaseException, caplog: pytest.LogCaptureFixture) -> list[str]:
    texts: list[str] = []
    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:  # the whole chain
        seen.add(id(current))
        texts += [str(current), repr(current), *map(repr, current.args), *map(str, current.args)]
        texts += [str(p) for p in getattr(current, "problems", [])]
        current = current.__cause__ or current.__context__
    formatter = logging.Formatter("%(name)s %(levelname)s %(message)s")
    for record in caplog.records:
        texts += [formatter.format(record), repr(record.args), str(record.msg)]
    return texts


@pytest.mark.parametrize(
    ("offending", "where"),
    [
        ("\n", "end"),
        ("\r\n", "end"),
        (" ", "start"),
        ("\t", "end"),
        ("\x1b", "middle"),
        ("\x7f", "middle"),
        ("\N{LATIN SMALL LETTER E WITH ACUTE}", "middle"),
        ("\N{NO-BREAK SPACE}", "end"),
    ],
)
async def test_sentinel_no_part_of_a_refused_key_appears_anywhere(
    monkeypatch, caplog, offending, where
):
    """Decided 2026-11-17 (refuse, never strip): the startup error and the key object's own
    error contain no part of the key: not the marker, no substring of 4 or more characters,
    not its length. Checked in the message, repr, args, the cause/context chain and every
    log record."""
    caplog.set_level(logging.DEBUG)
    key = bad_key(offending, where)
    assert len(key) == KEY_LENGTH + len(offending) - 1
    pieces = {key[i : i + 4] for i in range(len(key) - 3)}
    monkeypatch.setenv("GEMINI_API_KEY", key)
    with pytest.raises(SettingsError) as startup:
        await build_engine(adapter_settings(), verifier=verifier())
    with pytest.raises(ValueError) as direct:
        ApiKey(key)
    texts = leak_texts(startup.value, caplog) + leak_texts(direct.value, caplog)
    assert len(texts) > 6
    for text in texts:
        assert MARKER not in text
        assert str(len(key)) not in text and str(len(key.strip())) not in text
        assert not [p for p in pieces if p in text], "a 4-character piece of the key leaked"
    assert f"GEMINI_API_KEY: {expected_kind(key)}" in str(startup.value)
