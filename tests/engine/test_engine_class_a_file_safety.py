"""Follow-ups on the class A file sink and the URL summary.

* The sink never follows a symbolic link (at the path or in a directory component),
  checks what it opened (a regular file, owned by the engine's user, not group- or
  world-writable, one link) and the directory (owned by the user or root, not group- or
  world-writable, sticky or not), decides "created" with ``O_CREAT | O_EXCL``, and does all
  this at startup and on every write.
* Each event is one ``write()`` under an exclusive ``flock``; a short write fails the
  publish. The fragment is ended with a newline, never truncated.
* A host that looks like a token is withheld from the URL summary.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import threading
from datetime import UTC, datetime

import pytest
from engine_fixtures import TENANT, bundle, directory, settings, verifier

import guardrail_engine.engine.bootstrap as bootstrap
from guardrail_engine.decision import FakeDecisionModel
from guardrail_engine.engine import (
    AppendOnlyFileAdminAuditSink,
    BootstrapPublishEvent,
    ClassAAuditFileError,
    DiffEntry,
    SettingsError,
    build_engine,
    summarize_url,
)
from guardrail_engine.engine.bootstrap import token_like_label

NAME = "class_a.jsonl"


@pytest.fixture
def audit_dir(tmp_path):
    """A directory only the test's user can write, as the sink requires."""
    d = tmp_path / "audit"
    d.mkdir(mode=0o700)
    d.chmod(0o700)
    return d


def refused_at_startup(path) -> str:
    with pytest.raises(ClassAAuditFileError) as raised:
        AppendOnlyFileAdminAuditSink(path).check()
    assert raised.value.__cause__ is None and raised.value.__context__ is None
    message = str(raised.value)
    assert message.startswith(f"class A audit file {path}: ")
    return message.removeprefix(f"class A audit file {path}: ")


async def build(path, environment: str = "staging"):
    return await build_engine(
        settings(environment=environment, class_a_audit={"file": str(path)}),
        verifier=verifier(),
        tenants=directory(),
        model=FakeDecisionModel(),
    )


def event(version: int = 1, text: str = "Is it about cats?") -> BootstrapPublishEvent:
    return BootstrapPublishEvent(
        environment="staging",
        tenant_id=TENANT,
        version=version,
        bundle_hash="sha256:" + "0" * 64,
        previous_version=None,
        previous_bundle_hash=None,
        activate=True,
        diff=(DiffEntry(path="/rules/0/question", op="add", after=text),),
        at=datetime.now(UTC),
    )


# ----------------------------------------------------------------------
def test_a_good_path_is_created_0600(audit_dir):
    path = audit_dir / NAME
    AppendOnlyFileAdminAuditSink(path).check()
    assert path.is_file() and (path.stat().st_mode & 0o777) == 0o600


def test_a_symlink_at_the_path_is_refused_and_not_followed(audit_dir):
    target = audit_dir / "target.txt"
    target.write_text("untouched\n")
    target.chmod(0o600)
    (audit_dir / NAME).symlink_to(target)
    assert refused_at_startup(audit_dir / NAME) == (
        "cannot be opened for append: it is a symbolic link"
    )
    assert target.read_text() == "untouched\n"


def test_a_dangling_symlink_at_the_path_is_refused_and_creates_nothing(audit_dir):
    (audit_dir / NAME).symlink_to(audit_dir / "would-be-created")
    assert "symbolic link" in refused_at_startup(audit_dir / NAME)
    assert not (audit_dir / "would-be-created").exists()


def test_a_symlinked_directory_component_is_refused(audit_dir, tmp_path):
    link = tmp_path / "link-to-audit"
    link.symlink_to(audit_dir, target_is_directory=True)
    assert refused_at_startup(link / NAME) == (
        "cannot be opened for append: a directory component is a symbolic link or not a directory"
    )
    assert not (audit_dir / NAME).exists()


def test_dot_dot_in_the_path_is_refused(audit_dir):
    assert "'..'" in refused_at_startup(audit_dir / ".." / "audit" / NAME)


def test_a_fifo_at_the_path_is_refused_without_blocking(audit_dir):
    os.mkfifo(audit_dir / NAME, 0o600)
    assert refused_at_startup(audit_dir / NAME) == (
        "cannot be opened for append: not a regular file"
    )


def test_a_directory_at_the_path_is_refused(audit_dir):
    (audit_dir / NAME).mkdir()
    assert "not a regular file" in refused_at_startup(audit_dir / NAME)


@pytest.mark.parametrize("mode", [0o620, 0o602, 0o666])
def test_a_group_or_world_writable_file_is_refused(audit_dir, mode):
    path = audit_dir / NAME
    path.write_text("")
    path.chmod(mode)
    assert refused_at_startup(path) == "the file is group- or world-writable"


@pytest.mark.parametrize("mode", [0o770, 0o707, 0o777, 0o1777])
def test_a_group_or_world_writable_directory_is_refused_sticky_or_not(audit_dir, mode):
    audit_dir.chmod(mode)
    try:
        message = refused_at_startup(audit_dir / NAME)
    finally:
        audit_dir.chmod(0o700)
    assert message.startswith("its directory is group- or world-writable")
    assert not (audit_dir / NAME).exists()  # nothing created in it


def test_a_file_with_another_hard_link_is_refused(audit_dir):
    path = audit_dir / NAME
    path.write_text("")
    path.chmod(0o600)
    os.link(path, audit_dir / "second-name")
    assert refused_at_startup(path) == "the file has other hard links"


@pytest.mark.skipif(
    os.getuid() == 0,
    reason="the directory check accepts a root-owned directory, so as root this case can't arise",
)
def test_a_directory_owned_by_another_user_is_refused(audit_dir, monkeypatch):
    monkeypatch.setattr(bootstrap.os, "geteuid", lambda: os.getuid() + 4242)
    assert refused_at_startup(audit_dir / NAME) == "its directory is owned by another user"


def test_a_file_owned_by_another_user_is_refused(audit_dir, monkeypatch):
    """The directory check passes (root may own it); the file must be the engine user's."""
    path = audit_dir / NAME
    path.write_text("")
    path.chmod(0o600)
    real = os.getuid()
    calls = iter([real, real + 4242])  # first the directory check, then the file check
    monkeypatch.setattr(bootstrap.os, "geteuid", lambda: next(calls))
    assert refused_at_startup(path) == "the file is owned by another user"


def test_the_create_race_a_symlink_planted_between_check_and_open(audit_dir, monkeypatch):
    """There is no check-then-open: ``O_CREAT | O_EXCL`` decides "created". A symlink that
    appears just before that call makes it fail, and the fallback open refuses the link."""
    target = audit_dir / "target.txt"
    target.write_text("untouched\n")
    target.chmod(0o600)
    real_open = os.open

    def racing_open(name, flags, *args, **kwargs):
        if name == NAME and flags & os.O_EXCL:
            os.symlink(target, audit_dir / NAME)
        return real_open(name, flags, *args, **kwargs)

    monkeypatch.setattr(bootstrap.os, "open", racing_open)
    assert "symbolic link" in refused_at_startup(audit_dir / NAME)
    assert target.read_text() == "untouched\n"


@pytest.mark.parametrize(("mode", "accepted"), [(0o600, True), (0o666, False)])
def test_the_create_race_a_file_planted_between_check_and_open(
    audit_dir, monkeypatch, mode, accepted
):
    real_open = os.open

    def racing_open(name, flags, *args, **kwargs):
        if name == NAME and flags & os.O_EXCL:
            planted = audit_dir / NAME
            planted.write_text("")
            planted.chmod(mode)
        return real_open(name, flags, *args, **kwargs)

    monkeypatch.setattr(bootstrap.os, "open", racing_open)
    if accepted:
        AppendOnlyFileAdminAuditSink(audit_dir / NAME).check()  # opened as existing
    else:
        assert refused_at_startup(audit_dir / NAME) == "the file is group- or world-writable"


async def test_the_engine_refuses_to_start_on_a_symlink(audit_dir):
    target = audit_dir / "target.txt"
    target.write_text("")
    target.chmod(0o600)
    (audit_dir / NAME).symlink_to(target)
    with pytest.raises(SettingsError) as raised:
        await build(audit_dir / NAME)
    [problem] = raised.value.problems
    assert problem == (
        f"class_a_audit.file: class A audit file {audit_dir / NAME}: cannot be opened for "
        "append: it is a symbolic link"
    )


async def test_every_write_rechecks_a_path_swapped_for_a_symlink_after_startup(audit_dir):
    path = audit_dir / NAME
    engine = await build(path)
    target = audit_dir / "target.txt"
    target.write_text("untouched\n")
    target.chmod(0o600)
    try:
        path.unlink()
        path.symlink_to(target)
        with pytest.raises(ClassAAuditFileError, match="it is a symbolic link"):
            await engine.bootstrap_publish(bundle())
        assert await engine.store.get_active_version(TENANT) is None  # nothing activated
    finally:
        await engine.shutdown()
    assert target.read_text() == "untouched\n"


# ----------------------------------------------------------------------
def test_two_writers_never_interleave_a_line(audit_dir):
    """Two writers, each with its own sink and so its own descriptor per write, append large
    events concurrently. Every line is one complete JSON event."""
    path = audit_dir / NAME
    AppendOnlyFileAdminAuditSink(path).check()
    big = "Is it about cats? " * 20_000  # about 360 KB per event
    per_writer = 15
    errors: list[BaseException] = []

    def writer(offset: int) -> None:
        sink = AppendOnlyFileAdminAuditSink(path)
        try:
            for i in range(per_writer):
                sink.record_admin(event(version=offset + i, text=big))
        except BaseException as e:  # pragma: no cover - reported below
            errors.append(e)

    threads = [threading.Thread(target=writer, args=(o,)) for o in (1, 1001)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(60)
    assert errors == []
    lines = path.read_bytes().split(b"\n")
    assert lines[-1] == b""
    events = [json.loads(line) for line in lines[:-1]]  # each line parses on its own
    assert sorted(e["version"] for e in events) == [
        *range(1, 1 + per_writer),
        *range(1001, 1001 + per_writer),
    ]
    assert all(e["diff"][0]["after"] == big for e in events)


def test_the_write_and_fsync_happen_under_an_exclusive_lock(audit_dir, monkeypatch):
    calls: list[str] = []
    real_flock, real_write, real_fsync = fcntl.flock, os.write, os.fsync

    def flock(fd, op):
        calls.append({fcntl.LOCK_EX: "lock", fcntl.LOCK_UN: "unlock"}.get(op, str(op)))
        return real_flock(fd, op)

    def write(fd, data):
        calls.append("write")
        return real_write(fd, data)

    def fsync(fd):
        calls.append("fsync")
        return real_fsync(fd)

    path = audit_dir / NAME
    AppendOnlyFileAdminAuditSink(path).check()
    monkeypatch.setattr(bootstrap.fcntl, "flock", flock)
    monkeypatch.setattr(bootstrap.os, "write", write)
    monkeypatch.setattr(bootstrap.os, "fsync", fsync)
    AppendOnlyFileAdminAuditSink(path).record_admin(event())
    assert calls == ["lock", "write", "fsync"]  # one write; closing the file unlocks


async def test_a_short_write_fails_the_publish_and_never_truncates(audit_dir, monkeypatch):
    """The earlier bytes are untouched, the fragment is ended with a newline, and the
    next publish appends a complete line after it. Nothing ever shortens the file."""
    path = audit_dir / NAME
    engine = await build(path)
    before = path.read_bytes()
    real_write = os.write
    truncated = []

    def short_write(fd, data):
        data = bytes(data)
        return real_write(fd, data if data == b"\n" else data[:10])

    monkeypatch.setattr(bootstrap.os, "write", short_write)
    monkeypatch.setattr(bootstrap.os, "ftruncate", lambda *a: truncated.append(a))
    try:
        with pytest.raises(ClassAAuditFileError, match="short write"):
            await engine.bootstrap_publish(bundle())
        assert await engine.store.get_active_version(TENANT) is None
        monkeypatch.setattr(bootstrap.os, "write", real_write)
        after_fragment = path.read_bytes()
        assert after_fragment.startswith(before)  # earlier bytes unchanged
        fragment = after_fragment[len(before) :]
        assert len(fragment) == 11 and fragment.endswith(b"\n")  # 10 bytes + "\n"
        with pytest.raises(json.JSONDecodeError):
            json.loads(fragment)  # a reader skips it and counts a failed write
        await engine.bootstrap_publish(bundle())
        assert await engine.store.get_active_version(TENANT) == 1
    finally:
        monkeypatch.undo()
        await engine.shutdown()
    assert truncated == []
    data = path.read_bytes()
    assert data.startswith(after_fragment)
    last = data[len(after_fragment) :]
    assert last.endswith(b"\n") and last.count(b"\n") == 1
    assert json.loads(last)["tenant_id"] == TENANT  # a complete record on its own line


async def test_a_short_write_of_nothing_adds_no_line(audit_dir, monkeypatch):
    """A write that wrote no bytes left no fragment, so no newline is added."""
    path = audit_dir / NAME
    engine = await build(path)
    before = path.read_bytes()
    monkeypatch.setattr(bootstrap.os, "write", lambda fd, data: 0)
    try:
        with pytest.raises(ClassAAuditFileError, match="short write"):
            await engine.bootstrap_publish(bundle())
    finally:
        monkeypatch.undo()
        await engine.shutdown()
    assert path.read_bytes() == before


# ----------------------------------------------------------------------
def sha(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode()).hexdigest()


@pytest.mark.parametrize(
    "url",
    [
        "https://a1b2c3d4e5f6g7h8secret.m.pipedream.net/",  # the probe
        "https://hooks.example.com.a1b2c3d4e5f6g7h8.example.net/x",  # token in the middle
        "https://0123456789abcdef0123.hooks.example.com/",  # hex
        "https://4096409640964096.example.com/",  # digits only, 16
        "https://abcdefghijklmnopqrstuvwxyz.example.com/",  # 26 letters (base32-like)
        "https://a1b2-c3d4-e5f6-g7h8.example.com/",  # hyphenated token
        "https://service-2024-notifications.example.com/",  # wordy, but mixed: withheld
    ],
)
def test_a_token_like_host_is_withheld(url):
    assert summarize_url(url) == {"scheme": "https", "sha256": sha(url)}


@pytest.mark.parametrize(
    ("url", "host"),
    [
        ("https://hooks.example.com/services/x?token=y", "hooks.example.com"),
        ("https://203.0.113.9/hook", "203.0.113.9"),
        (
            "https://notifications-gateway-service.eu-west-1.example.com/hook",
            "notifications-gateway-service.eu-west-1.example.com",
        ),
        ("https://internationalization.example.com/", "internationalization.example.com"),
        ("https://abcdef0123456.example.com/", "abcdef0123456.example.com"),  # 13: kept
        ("https://[2001:db8::1]/hook", "[2001:db8::1]"),
    ],
)
def test_an_ordinary_host_is_kept(url, host):
    assert summarize_url(url) == {"scheme": "https", "host": host, "sha256": sha(url)}


@pytest.mark.parametrize(
    ("label", "token"),
    [
        ("a1b2c3d4e5f6g7h8", True),  # 16, mixed
        ("a1b2c3d4e5f6g7h", False),  # 15
        ("0123456789abcdef", True),  # 16 hex
        ("abcdefabcdefabcd", True),  # 16 hex letters only
        ("abcdefghijklmnopqrstuvwxy", False),  # 25 letters
        ("abcdefghijklmnopqrstuvwxyz", True),  # 26 letters
        ("notifications-gateway-service", False),
        ("eu-west-1", False),
    ],
)
def test_token_like_label_rule(label, token):
    assert token_like_label(label) is token
