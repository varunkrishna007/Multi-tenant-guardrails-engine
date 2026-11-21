"""The bootstrap publish path's class A audit event (M1-11, decided 2026-11-17).

``Engine.bootstrap_publish()`` compiles, stores and activates a tenant bundle **without the
Admin API**, for the dogfood and the demo only. It is privileged: it is never part of the
SDK surface (M1-07), it is refused when ``environment`` is ``production`` or the tenant's
tier isn't ``standard``, and it is removed or disabled once the Admin API (M2-07) ships.
Every publish it makes writes one :class:`BootstrapPublishEvent` (R3 class A: actor
``bootstrap``, the diff against the active version, the resulting hash) to an
:class:`AdminAuditSink`, **before** the version is activated, so nothing is activated
without its record, and a failed write activates nothing.

**Sinks.** Each declares whether it is ``durable``. In ``staging`` (the dogfood) a durable
sink is required: :class:`AppendOnlyFileAdminAuditSink`, an append-only JSON-lines file
flushed to disk (fsync) before activation, configured as ``class_a_audit.file``. The default,
:class:`LoggingAdminAuditSink` (one JSON log line), is acceptable in ``test`` only. (A
Postgres sink would also count as durable; the policy store has no table for it yet.)

**What an event holds.** The fields of :class:`BootstrapPublishEvent`: identifiers (tenant,
versions, bundle hashes), the environment, the activate flag, the time, and the diff. The
diff holds values from the two bundle documents only. The bundle schema forbids unknown
fields, and the API key and the Postgres DSN are never part of a bundle, so neither can reach
an event. Values of URL fields (those the schema marks ``format: uri``, today
``escalation.url``) may be bearer secrets (a webhook token in the path or query), so on both
sides of the diff they are recorded only as scheme, host and SHA-256 of the full value
(:func:`summarize_url`), and the host is left out too when it looks like a token. Rule text
and other tenant-authored configuration are kept as they are.
"""

from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import errno
import fcntl
import json
import logging
import os
import stat
from datetime import datetime
from pathlib import Path
from typing import Literal, Protocol

from pydantic import BaseModel, ConfigDict

from guardrail_engine.authz.authorizer import CrossTenantEvent
from guardrail_engine.policy.diff import (
    BUNDLE_URL_FIELDS as BUNDLE_URL_FIELDS,
)
from guardrail_engine.policy.diff import (
    DiffEntry as DiffEntry,
)
from guardrail_engine.policy.diff import (
    UrlSummary as UrlSummary,
)
from guardrail_engine.policy.diff import (
    bundle_diff as bundle_diff,
)
from guardrail_engine.policy.diff import (
    document_diff as document_diff,
)
from guardrail_engine.policy.diff import (
    redact_urls as redact_urls,
)
from guardrail_engine.policy.diff import (
    summarize_url as summarize_url,
)
from guardrail_engine.policy.diff import (
    token_like_label as token_like_label,
)
from guardrail_engine.policy.diff import (
    url_field_paths as url_field_paths,
)

logger = logging.getLogger(__name__)

ADMIN_AUDIT_LOGGER = "guardrail_engine.audit.class_a"
BOOTSTRAP_ACTOR = "bootstrap"
BOOTSTRAP_EVENT_SCHEMA_VERSION = 2
"""2 (M1 integration): adds ``test_overrides``. A version 1 event is a version 2 event with
none."""


class BootstrapRefusedError(PermissionError):
    """``Engine.bootstrap_publish()`` is not allowed here: the environment is production, the
    environment is staging without a durable class A sink, or the tenant's tier isn't
    ``standard``. Publish through the Admin API (M2-07) instead."""


class ClassAAuditFileError(OSError):
    """The class A audit file can't be opened for append, fails a check, or can't be written.
    The message names the path and the kind of problem only."""


class _Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class BootstrapPublishEvent(_Frozen):
    """The class A audit event of one bootstrap publish (AC-A2's fields: actor, diff and
    resulting hash)."""

    schema_version: int = BOOTSTRAP_EVENT_SCHEMA_VERSION
    audit_class: Literal["A"] = "A"
    action: Literal["bootstrap_publish"] = "bootstrap_publish"
    actor: Literal["bootstrap"] = BOOTSTRAP_ACTOR
    environment: str
    tenant_id: str
    version: int
    bundle_hash: str
    previous_version: int | None
    """The version that was active before, or None if none was."""
    previous_bundle_hash: str | None
    activate: bool
    """Whether this publish activates the version (the event is written before it does)."""
    diff: tuple[DiffEntry, ...]
    """From the previously active document (an empty object if none) to the new one, with
    URL fields summarised (:func:`bundle_diff`)."""
    at: datetime
    test_overrides: tuple[str, ...] = ()
    """The test-only overrides the engine was built with (``nonce_source``, ``pii_detector``;
    :attr:`~guardrail_engine.engine.factory.Engine.test_overrides`), so the record shows a
    publish made by an engine that doesn't behave as production would. Names only."""


# ---------------------------------------------------------------------- sinks


class AdminAuditSink(Protocol):
    durable: bool
    """True only if a recorded event survives a process or machine restart (written to disk
    with fsync, or committed to a database) by the time ``record_admin`` returns."""

    def record_admin(self, event: BootstrapPublishEvent) -> None:
        """Keep ``event``. Raising stops the publish before the version is activated."""
        ...


class LoggingAdminAuditSink:
    """Writes each event as one JSON line at INFO on :data:`ADMIN_AUDIT_LOGGER`. Not durable:
    acceptable in ``test`` only."""

    durable = False

    def __init__(self) -> None:
        self._logger = logging.getLogger(ADMIN_AUDIT_LOGGER)

    def record_admin(self, event: BootstrapPublishEvent) -> None:
        self._logger.info("class A audit event %s", event.model_dump_json())


class InMemoryAdminAuditSink:
    """For tests. Not durable."""

    durable = False

    def __init__(self) -> None:
        self.events: list[BootstrapPublishEvent] = []

    def record_admin(self, event: BootstrapPublishEvent) -> None:
        self.events.append(event)


def _end_fragment(fd: int) -> None:
    """Terminate a partial line left by a short write with ``"\n"`` (best effort), so
    it reads as one line that doesn't parse. Never truncates: the file is append-only."""
    # On failure the publish still fails, and a reader still skips the unterminated fragment.
    with contextlib.suppress(OSError):
        os.write(fd, b"\n")


class AppendOnlyFileAdminAuditSink:
    """A durable sink: each event is appended to ``path`` as one JSON line and flushed to disk
    (``fsync``) before :meth:`record_admin` returns, so before the version is activated.

    **What it will write to** (checked at startup by :meth:`check` and again on every write).
    Anything else is refused with :class:`ClassAAuditFileError`, naming the path and the kind of
    problem only:

    * The path is walked one component at a time from ``/`` with ``O_NOFOLLOW``, so no
      component, the file included, may be a symbolic link. Give the resolved path. ``.``
      and ``..`` components are refused.
    * The directory holding the file must be owned by the engine's effective user or root,
      and not be group- or world-writable. **A sticky-bit directory such as ``/tmp`` is
      refused too:** the sticky bit stops others renaming or deleting the file, but not
      planting files or links under names the engine hasn't created yet, and the class A
      record should live where only the engine's user can create entries.
    * The file is opened with ``O_APPEND | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK`` (so a FIFO
      can't block the engine). It is created with ``O_CREAT | O_EXCL`` and mode 0600, and
      "newly created" is decided by that call, never by a separate existence check; if the
      file already exists it is opened without ``O_CREAT``. The descriptor is then checked
      with ``fstat``: a regular file, owned by the effective user, with no group or other
      write bit, and a single link.

    **Writing**. Each event is one line, written with a single ``write()`` while
    holding an exclusive ``flock`` on the file, followed by ``fsync``; the lock is held until
    after the ``fsync``, so engine processes sharing the file never interleave lines. A newly
    created file's directory is synced too.

    **The file is never shortened**. A short write fails the publish (nothing is
    activated); the sink then writes a single ``"\n"`` (best effort, still under the lock), so
    the fragment ends as one line that doesn't parse and the next record starts on a line of
    its own. Truncating the fragment instead could delete a record appended by a writer that
    doesn't take the lock, and would need more than append rights to the file. **A reader of
    the file skips any line that doesn't parse as JSON and counts it as a failed write.**
    """

    durable = True

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def check(self) -> None:
        """Open the file for append (creating it if needed) and run every check above,
        without writing. Raises :class:`ClassAAuditFileError`."""
        fd = self._open()
        os.close(fd)

    def record_admin(self, event: BootstrapPublishEvent) -> None:
        self.append_line((event.model_dump_json() + "\n").encode("utf-8"))

    def append_line(self, data: bytes) -> None:
        """Append one complete line (ending in a newline) under the rules above. Raises
        :class:`ClassAAuditFileError`. A fragment of a short write is ended as its own line."""
        fd = self._open()
        problem = None
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            written = os.write(fd, data)
            if written != len(data):
                problem = "short write; the publish is not activated"
                if written:
                    _end_fragment(fd)
            os.fsync(fd)
        except OSError as e:
            problem = problem or f"write failed ({_kind(e)})"
        finally:
            os.close(fd)  # also releases the lock
        if problem is not None:
            raise ClassAAuditFileError(f"class A audit file {self.path}: {problem}")

    # ------------------------------------------------------------------ opening

    def _open(self) -> int:
        problem = None
        fd = -1
        try:
            fd = self._open_checked()
        except _Refused as e:
            problem = str(e)
        except OSError as e:
            problem = f"cannot be opened for append: {_kind(e)}"
        if problem is not None:
            # Raised outside ``except``: no chained OS error, whose text could say more.
            raise ClassAAuditFileError(f"class A audit file {self.path}: {problem}")
        return fd

    def _open_checked(self) -> int:
        path = self.path.absolute()  # not resolved: a symlink is refused, never followed
        parts = path.parts[1:]
        if not parts or any(part in (".", "..") for part in parts):
            raise _Refused("cannot be opened for append: '.' or '..' in the path")
        directory = os.open("/", _DIR_FLAGS)
        try:
            for part in parts[:-1]:
                try:
                    child = os.open(part, _DIR_FLAGS | os.O_NOFOLLOW, dir_fd=directory)
                except OSError as e:
                    if e.errno in (errno.ELOOP, errno.ENOTDIR):
                        raise _Refused(
                            "cannot be opened for append: a directory component is a "
                            "symbolic link or not a directory"
                        ) from None
                    raise
                os.close(directory)
                directory = child
            _check_directory(os.fstat(directory))
            fd, created = _open_file(parts[-1], directory)
            try:
                _check_file(os.fstat(fd))
                if created:
                    os.fsync(directory)
            except BaseException:
                os.close(fd)
                raise
            return fd
        finally:
            os.close(directory)


_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
_FILE_FLAGS = os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK


class _Refused(Exception):
    """Engine wording only: the kind of problem with the path."""


def _open_file(name: str, directory: int) -> tuple[int, bool]:
    try:
        return os.open(name, _FILE_FLAGS | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=directory), True
    except FileExistsError:
        pass
    try:
        return os.open(name, _FILE_FLAGS, dir_fd=directory), False
    except OSError as e:
        if e.errno == errno.ELOOP:
            raise _Refused("cannot be opened for append: it is a symbolic link") from None
        if e.errno in (errno.EISDIR, errno.ENXIO):
            raise _Refused("cannot be opened for append: not a regular file") from None
        raise


def _check_directory(st: os.stat_result) -> None:
    if st.st_uid not in (os.geteuid(), 0):
        raise _Refused("its directory is owned by another user")
    if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise _Refused(
            "its directory is group- or world-writable (a sticky-bit directory such as /tmp "
            "is refused too)"
        )


def _check_file(st: os.stat_result) -> None:
    if not stat.S_ISREG(st.st_mode):
        raise _Refused("cannot be opened for append: not a regular file")
    if st.st_uid != os.geteuid():
        raise _Refused("the file is owned by another user")
    if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise _Refused("the file is group- or world-writable")
    if st.st_nlink != 1:
        raise _Refused("the file has other hard links")


def _kind(e: OSError) -> str:
    """An OS error as the kind of problem, never its text (which repeats the path at most,
    but is the OS's wording)."""
    names = {
        errno.EACCES: "permission denied",
        errno.EPERM: "permission denied",
        errno.ENOENT: "its directory does not exist",
        errno.ENOSPC: "no space left",
        errno.EROFS: "read-only file system",
    }
    return names.get(e.errno or 0, type(e).__name__)


class AppendOnlyFileAuthzAudit:
    """The durable sink for cross-tenant access events (AC-T1): the same append-only
    file, with the same safety rules, as the bootstrap publish events. One JSON line per
    event, tagged ``"event": "cross_tenant_access"``, written and flushed to disk before
    :meth:`record` returns, so the authorizer refuses an access it could not record. It holds
    identifiers only (the fields of :class:`CrossTenantEvent`)."""

    durable = True

    def __init__(self, file: AppendOnlyFileAdminAuditSink) -> None:
        self._file = file

    async def record(self, event: CrossTenantEvent) -> None:
        line = json.dumps({"event": "cross_tenant_access", **dataclasses.asdict(event)})
        await asyncio.to_thread(self._file.append_line, (line + "\n").encode("utf-8"))
