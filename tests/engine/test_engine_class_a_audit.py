"""M1-11 (decided 2026-11-17): the class A sink of ``Engine.bootstrap_publish()``.

* In ``staging`` (the dogfood) a **durable** sink is required: the append-only file sink
  (``class_a_audit.file``), flushed to disk before activation. With only the JSON log line
  (acceptable in ``test``) the publish is refused. Sinks declare ``durable`` themselves.
* The file path is checked at startup; a path that can't be opened for append refuses to
  start, naming only the path. A failed write at publish time activates nothing.
* The diff never carries a URL field's value: a webhook URL is recorded
  as scheme, host and SHA-256 only, on both sides, in every sink.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import stat

import pytest
from engine_fixtures import TENANT, adapter_settings, bundle, directory, settings, verifier

from guardrail_engine.decision import FakeDecisionModel
from guardrail_engine.engine import (
    ADMIN_AUDIT_LOGGER,
    BUNDLE_URL_FIELDS,
    AppendOnlyFileAdminAuditSink,
    BootstrapRefusedError,
    ClassAAuditFileError,
    InMemoryAdminAuditSink,
    LoggingAdminAuditSink,
    SettingsError,
    build_engine,
    bundle_diff,
    summarize_url,
)
from guardrail_engine.store import InMemoryPolicyStore

PATH_MARKER = "PathMarkerZq7"
QUERY_MARKER = "QueryMarkerVb3"
WEBHOOK = f"https://hooks.example.com/services/{PATH_MARKER}/notify?token={QUERY_MARKER}"
WEBHOOK_2 = f"https://other.example.org:8443/hook/{PATH_MARKER}2?token={QUERY_MARKER}2"


def sha(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode()).hexdigest()


def webhook_bundle(version: int, url: str) -> dict:
    return {**bundle(version=version), "escalation": {"target": "webhook", "url": url}}


async def build(environment: str = "test", **kwargs):
    store = kwargs.pop("store", None)
    return await build_engine(
        kwargs.pop("settings", None) or settings(environment=environment),
        verifier=verifier(),
        tenants=directory(),
        model=FakeDecisionModel(),
        store=store,
        **kwargs,
    )


def audit_file_settings(environment: str, path) -> object:
    return settings(environment=environment, class_a_audit={"file": str(path)})


# ---------------------------------------------------------------------- environments


@pytest.mark.parametrize("value", ["dogfood", "demo", "development", "Staging", "prod"])
def test_environment_is_production_staging_or_test_only(value):
    with pytest.raises(SettingsError, match=r"^invalid engine configuration") as raised:
        settings(environment=value)
    assert any(p.startswith("environment:") for p in raised.value.problems)


@pytest.mark.parametrize("value", ["production", "staging", "test"])
def test_the_three_environments_are_accepted(value):
    assert settings(environment=value).environment == value


# ---------------------------------------------------------------------- durability


def test_sinks_declare_whether_they_are_durable(tmp_path):
    assert AppendOnlyFileAdminAuditSink(tmp_path / "a.jsonl").durable is True
    assert LoggingAdminAuditSink().durable is False
    assert InMemoryAdminAuditSink().durable is False


@pytest.mark.parametrize("sink", [None, InMemoryAdminAuditSink()])
async def test_staging_refuses_without_a_durable_sink(sink):
    engine = await build("staging", admin_audit=sink)
    try:
        with pytest.raises(BootstrapRefusedError, match="durable class A audit sink"):
            await engine.bootstrap_publish(bundle())
        assert await engine.store.list_versions(TENANT) == []
    finally:
        await engine.shutdown()


async def test_test_accepts_the_log_line_sink():
    engine = await build("test")
    try:
        await engine.bootstrap_publish(bundle())
        assert await engine.store.get_active_version(TENANT) == 1
    finally:
        await engine.shutdown()


async def test_staging_with_the_file_sink_appends_and_fsyncs_before_activation(
    tmp_path, monkeypatch
):
    path = tmp_path / "class_a.jsonl"
    order: list[str] = []
    real_fsync = os.fsync

    def recording_fsync(fd: int) -> None:
        order.append("fsync")
        real_fsync(fd)

    class RecordingStore(InMemoryPolicyStore):
        async def set_active_version(self, *args, **kwargs):
            order.append("activate")
            return await super().set_active_version(*args, **kwargs)

    from engine_fixtures import real_catalog

    monkeypatch.setattr(os, "fsync", recording_fsync)
    engine = await build(
        settings=audit_file_settings("staging", path),
        store=RecordingStore(catalog=real_catalog()),
    )
    try:
        assert path.exists() and path.read_bytes() == b""  # opened at startup, nothing written
        order.clear()
        first = await engine.bootstrap_publish(bundle())
        second = await engine.bootstrap_publish(bundle(version=2))
    finally:
        await engine.shutdown()
    assert order == ["fsync", "activate", "fsync", "activate"]
    lines = path.read_text().splitlines()
    assert [json.loads(line)["bundle_hash"] for line in lines] == [first, second]
    assert all(json.loads(line)["actor"] == "bootstrap" for line in lines)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


async def test_the_file_is_only_appended_to(tmp_path):
    path = tmp_path / "class_a.jsonl"
    path.write_text('{"earlier": "event"}\n')
    path.chmod(0o600)  # an existing file must not be group- or world-writable
    engine = await build(settings=audit_file_settings("staging", path))
    try:
        await engine.bootstrap_publish(bundle())
    finally:
        await engine.shutdown()
    lines = path.read_text().splitlines()
    assert lines[0] == '{"earlier": "event"}' and len(lines) == 2


@pytest.mark.parametrize("make_bad", ["missing_dir", "a_directory"])
async def test_a_file_that_cannot_be_opened_for_append_refuses_to_start(tmp_path, make_bad):
    if make_bad == "missing_dir":
        path = tmp_path / "no-such-dir" / "class_a.jsonl"
    else:
        path = tmp_path / "is-a-dir"
        path.mkdir()
    with pytest.raises(SettingsError) as raised:
        await build(settings=audit_file_settings("staging", path))
    [problem] = raised.value.problems
    assert problem.startswith(f"class_a_audit.file: class A audit file {path}: cannot be opened")
    assert raised.value.__cause__ is None and raised.value.__context__ is None


async def test_a_failed_write_at_publish_time_activates_nothing(tmp_path):
    path = tmp_path / "class_a.jsonl"
    engine = await build(settings=audit_file_settings("staging", path))
    try:
        path.chmod(0o400)  # read-only after startup: the write fails
        if os.access(path, os.W_OK):
            pytest.skip("running with privileges that ignore file permissions")
        with pytest.raises(ClassAAuditFileError, match="cannot be opened for append") as raised:
            await engine.bootstrap_publish(bundle())
        assert raised.value.__cause__ is None and raised.value.__context__ is None
        assert await engine.store.get_active_version(TENANT) is None
    finally:
        path.chmod(0o600)
        await engine.shutdown()


async def test_a_sink_and_a_file_together_are_refused(tmp_path):
    with pytest.raises(SettingsError, match=r"class_a_audit\.file: set, but an admin_audit sink"):
        await build(
            settings=audit_file_settings("test", tmp_path / "a.jsonl"),
            admin_audit=InMemoryAdminAuditSink(),
        )


# ---------------------------------------------------------------------- URL fields


def test_url_fields_come_from_the_bundle_schema():
    assert frozenset({("escalation", "url")}) == BUNDLE_URL_FIELDS


async def test_webhook_url_never_reaches_any_sink(tmp_path, caplog, monkeypatch):
    """Markers in the path and the query of the old and the new webhook URL appear in no event,
    event JSON, file byte or log record; the host and the hash do."""
    caplog.set_level(logging.DEBUG)
    markers = (PATH_MARKER, QUERY_MARKER)
    texts: list[str] = []

    # The durable file sink, in staging.
    path = tmp_path / "class_a.jsonl"
    engine = await build(settings=audit_file_settings("staging", path))
    try:
        await engine.bootstrap_publish(webhook_bundle(1, WEBHOOK))
        await engine.bootstrap_publish(webhook_bundle(2, WEBHOOK_2))
    finally:
        await engine.shutdown()
    file_bytes = path.read_bytes()

    # The log-line sink, in test.
    with caplog.at_level(logging.INFO, logger=ADMIN_AUDIT_LOGGER):
        engine = await build("test")
        try:
            await engine.bootstrap_publish(webhook_bundle(1, WEBHOOK))
            await engine.bootstrap_publish(webhook_bundle(2, WEBHOOK_2))
        finally:
            await engine.shutdown()

    # The in-memory sink: the event objects themselves.
    sink = InMemoryAdminAuditSink()
    engine = await build("test", admin_audit=sink)
    try:
        await engine.bootstrap_publish(webhook_bundle(1, WEBHOOK))
        await engine.bootstrap_publish(webhook_bundle(2, WEBHOOK_2))
    finally:
        await engine.shutdown()

    for event in sink.events:
        texts += [repr(event), str(event), event.model_dump_json()]
    texts.append(file_bytes.decode())
    formatter = logging.Formatter("%(name)s %(levelname)s %(message)s")
    texts += [formatter.format(record) for record in caplog.records]
    for text in texts:
        for marker in markers:
            assert marker not in text
    assert all(m.encode() not in file_bytes for m in markers)

    replaced = [d for d in sink.events[1].diff if d.path == "/escalation/url"]
    assert replaced[0].before == {
        "scheme": "https",
        "host": "hooks.example.com",
        "sha256": sha(WEBHOOK),
    }
    assert replaced[0].after == {
        "scheme": "https",
        "host": "other.example.org",
        "sha256": sha(WEBHOOK_2),
    }
    added = next(d for d in sink.events[0].diff if d.path == "/escalation")
    assert added.after["url"]["host"] == "hooks.example.com"  # inside an added object too
    log_lines = [r.getMessage() for r in caplog.records if r.name == ADMIN_AUDIT_LOGGER]
    for blob in (file_bytes.decode(), "\n".join(log_lines)):
        assert "hooks.example.com" in blob and sha(WEBHOOK) in blob and sha(WEBHOOK_2) in blob


async def test_secrets_from_the_environment_never_reach_an_event(tmp_path, monkeypatch, caplog):
    """The diff holds bundle values only: the key and the DSN can't reach it."""
    key = "AIzaSentinelKeyForClassAAudit-not-real"
    dsn = "postgresql://app:SentinelDsnPassword@db.invalid/guardrails"
    monkeypatch.setenv("GEMINI_API_KEY", key)
    monkeypatch.setenv("GUARDRAIL_PG_DSN", dsn)
    caplog.set_level(logging.DEBUG)
    path = tmp_path / "class_a.jsonl"
    s = adapter_settings(environment="staging", class_a_audit={"file": str(path)})
    engine = await build_engine(s, verifier=verifier(), tenants=directory())
    try:
        await engine.bootstrap_publish(webhook_bundle(1, WEBHOOK))
    finally:
        await engine.shutdown()
    blob = path.read_text() + "\n".join(r.getMessage() for r in caplog.records)
    for secret in (key, "SentinelDsnPassword", PATH_MARKER, QUERY_MARKER):
        assert secret not in blob
    event = json.loads(path.read_text())
    assert set(event) == {
        "schema_version",
        "audit_class",
        "action",
        "actor",
        "environment",
        "tenant_id",
        "version",
        "bundle_hash",
        "previous_version",
        "previous_bundle_hash",
        "activate",
        "diff",
        "at",
        "test_overrides",
    }
    assert event["test_overrides"] == []  # no test-only override in staging


def test_rule_text_stays_in_the_diff():
    before = {**bundle(), "rules": []}
    after = {
        **bundle(version=2),
        "rules": [{"id": "r1", "guard_points": ["output"], "question": "Is it about cats?"}],
    }
    [rules, version] = bundle_diff(before, after)
    assert rules.after["question"] == "Is it about cats?"
    assert version.path == "/version"


@pytest.mark.parametrize(
    ("url", "host"),
    [
        ("https://hooks.example.com/a/b?c=d#e", "hooks.example.com"),
        ("https://user:pass@hooks.example.com/a", "hooks.example.com"),
        ("https://a:b@c@hooks.example.com/x", "hooks.example.com"),  # last @ ends userinfo
        ("https://Hooks.Example.COM:8443/x", "hooks.example.com"),  # port dropped
        ("https://[2001:db8::1]:443/x", "[2001:db8::1]"),
        ("https://203.0.113.9/x", "203.0.113.9"),
    ],
)
def test_summarize_url_keeps_scheme_and_host_only(url, host):
    summary = summarize_url(url)
    assert summary == {"scheme": "https", "host": host, "sha256": sha(url)}


@pytest.mark.parametrize(
    "url",
    [
        "not a url",
        "hooks.example.com/token",
        "https://evil.example\\@hooks.example.com/x",  # backslash: parsers disagree
        "https://hooks%2eexample.com/x",
        "https://hooks.example.com:token/x",  # a "port" that isn't one
        "https://hooks.example.com:/x",
        "https://[not-ipv6]/x",
        "https://exa mple.com/x",
        "https://hooks.example.com/x\n",
        "https://hé.example.com/x",
        "https:///x",
        "https://-bad-.example.com/x",
    ],
)
def test_summarize_url_records_only_the_hash_when_it_does_not_parse(url):
    assert summarize_url(url) == {"sha256": sha(url)}
