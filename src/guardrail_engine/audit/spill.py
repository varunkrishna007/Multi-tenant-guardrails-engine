"""A local spill for the decision records of regulated tenants (M7-04).

The writer's queue is bounded. For a standard tenant a record that finds it full is dropped and
counted. For a regulated tenant (any tier but ``standard``) the check waits a short, bounded
time for room, and then the record is **spilled** here: appended to a file, flushed to disk
(``fsync``), before the check returns. The writer replays the file into the store when it has
room again, and at startup.

**Where.** The file is ``decision_spill.file``, or beside the class A audit file
(``class_a_audit.file``) when that is not set, and is opened
with the same checks (:class:`~guardrail_engine.engine.bootstrap.AppendOnlyFileAdminAuditSink`):
no symbolic link followed, a directory only the engine's user can write, a regular file with one
link and no group or world write bit, one ``write()`` per line under an exclusive lock, then
``fsync``.

**Lines.** One JSON object per line.

* ``{"k": "spill", "id": ..., "requested_days": ..., "packs": [...], "record": {...}}`` is a
  record waiting for the store. ``id`` is minted when the record is spilled and is the record's
  key in the store: replay hands it over with the record and the store keeps one row per key,
  so a record is never written twice, whether the process died before or after it wrote the
  row and before it marked the line done.
* ``{"k": "done", "ids": [...]}`` says those records are in the store (or were given up on).

A line that does not parse is skipped, logged and counted. The record holds what any decision record
holds (hashes, probabilities, the verdict; no content), and the retention clock starts when it
is written to the store, as for every record, so the spill file never keeps a record past its
term: once every line in it is done, the file is deleted.
"""

from __future__ import annotations

import json
import logging
import uuid
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from guardrail_engine.guard.audit import AuditRecord

logger = logging.getLogger(__name__)

SPILL_FILE_NAME = "decision_records.spill.jsonl"


@dataclass(frozen=True, slots=True)
class SpilledRecord:
    id: str
    record: AuditRecord
    requested_days: int | None
    """The term the check was decided under, as :class:`~guardrail_engine.audit.writer`'s items
    carry it; the writer stamps the deletion time from it when it writes the record."""
    packs: tuple[str, ...]
    size: int = 0
    """The bytes its line takes in the file, newline included."""


@dataclass(frozen=True, slots=True)
class SpillState:
    """What the file holds now."""

    pending: tuple[SpilledRecord, ...]
    """Records not yet marked done, oldest first."""
    size: int
    """The file's size in bytes when it was read; 0 if there is none."""
    skipped_lines: int
    """Lines that did not parse (or did not hold a record)."""


class SpillFile(Protocol):
    """The file under the spill: the engine's spill file sink
    (``SpillFileSink``), with the class A file's safety checks."""

    path: Path

    def check(self) -> None: ...

    def append_line(self, data: bytes) -> None: ...

    def append_capped(self, data: bytes, max_bytes: int) -> int: ...

    def read_all(self) -> bytes | None: ...

    def remove_if_size(self, size: int) -> bool: ...

    def rewrite(self, transform: Callable[[bytes], bytes]) -> int: ...


def spill_file_beside(class_a_file: str | Path) -> Path:
    """The default spill file's path: in the directory of the class A audit file."""
    return Path(class_a_file).absolute().parent / SPILL_FILE_NAME


class DecisionSpill:
    """The file, and what the writer does with it. Methods block (disk): the writer calls them
    from its own threads, never on the event loop. The file is the class A file's own kind of
    sink, built by the engine (:func:`guardrail_engine.engine.bootstrap.decision_spill_at`).

    ``max_bytes`` caps the file: an append that would take it past the cap is refused
    (:class:`SpillFullError`), judged on the file's own size under its lock, so a long outage can't
    fill the filesystem the class A file shares however many processes write to it. 0 is no cap."""

    def __init__(self, file: SpillFile, *, max_bytes: int = 0) -> None:
        if max_bytes < 0:
            raise ValueError("max_bytes must not be negative")
        self._file = file
        self.max_bytes = max_bytes

    @property
    def path(self) -> Path:
        return self._file.path

    def check(self) -> None:
        """Open for append, creating the file if needed, and run every file check without
        writing. Raises :class:`~guardrail_engine.engine.bootstrap.ClassAAuditFileError`."""
        self._file.check()

    def append(
        self, record: AuditRecord, requested_days: int | None, packs: Sequence[str]
    ) -> tuple[str, int, int]:
        """Write one record and flush it to disk. Returns its id, the bytes written and the
        file's size afterwards. Raises on any failure (the caller counts the record as dropped),
        and :class:`SpillFullError` when the file, as it is when the write takes the file's lock
        (every process sharing it counted), plus the line would be over the cap."""
        ident = uuid.uuid4().hex
        line = (
            json.dumps(
                {
                    "k": "spill",
                    "id": ident,
                    "requested_days": requested_days,
                    "packs": list(packs),
                    "record": json.loads(record.model_dump_json()),
                },
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8")
        size = self._file.append_capped(line, self.max_bytes)
        return ident, len(line), size

    def mark_done(self, ids: Iterable[str]) -> None:
        ids = list(ids)
        if ids:
            line = json.dumps({"k": "done", "ids": ids}, separators=(",", ":"))
            self._file.append_line((line + "\n").encode("utf-8"))

    def state(self) -> SpillState:
        """Read the file once: the records not yet done."""
        data = self._file.read_all()
        if data is None:
            return SpillState((), 0, 0)
        waiting: dict[str, SpilledRecord] = {}
        done: set[str] = set()
        skipped = 0
        for raw in data.split(b"\n"):
            if not raw.strip():
                continue
            try:
                body = json.loads(raw)
                kind = body["k"]
                if kind == "done":
                    done.update(str(i) for i in body["ids"])
                elif kind == "spill":
                    days = body["requested_days"]
                    if days is not None and (isinstance(days, bool) or not isinstance(days, int)):
                        raise ValueError
                    waiting[str(body["id"])] = SpilledRecord(
                        str(body["id"]),
                        AuditRecord.model_validate(body["record"]),
                        days,
                        tuple(str(p) for p in body["packs"]),
                        len(raw) + 1,
                    )
                else:
                    raise ValueError
            except Exception:
                skipped += 1
        pending = tuple(r for i, r in waiting.items() if i not in done)
        if skipped:
            logger.error("%d lines of the decision spill file could not be read", skipped)
        return SpillState(pending, len(data), skipped)

    def compact(self) -> int:
        """Rewrite the file with only the lines still pending (the ``done`` marks and the
        records they cover go), under the file's lock, so what other writers append meanwhile is
        neither lost nor read half. Returns the new size. A record spilled for a tenant that has
        since gone is dropped here too, once the writer has marked it done."""

        def keep(data: bytes) -> bytes:
            lines: dict[str, bytes] = {}
            done: set[str] = set()
            for raw in data.split(b"\n"):
                if not raw.strip():
                    continue
                try:
                    body = json.loads(raw)
                    if body["k"] == "done":
                        done.update(str(i) for i in body["ids"])
                    elif body["k"] == "spill":
                        lines[str(body["id"])] = raw + b"\n"
                except Exception:
                    continue  # unreadable: it was logged when read, and can't be replayed
            return b"".join(line for i, line in lines.items() if i not in done)

        return self._file.rewrite(keep)

    def retire(self, state: SpillState) -> bool:
        """Delete the file when ``state`` (just read) has nothing pending and nothing was
        appended since. Lines that did not parse were logged when read and can't be replayed, so
        they don't keep the file."""
        if state.pending or state.size == 0:
            return False
        return self._file.remove_if_size(state.size)


class SpillFullError(OSError):
    """The spill file is at its size cap: the record is not kept."""
