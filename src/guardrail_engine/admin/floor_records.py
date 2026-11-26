"""A floor release written down, and replayed into a fresh platform store (M7-05).

A release is state in the platform's store (``platform_floor_releases``). A simulation has no
durable store: an engine in the ``test`` environment starts with an empty in-memory one, so a
release made on one engine is gone on the next. A **release record** keeps what the release path
produced: the floor and its hash, the evidence summary, the two approvals and when. The engine
replays it into its in-memory platform store at start, through the store's own ``propose`` and
``approve``, so the same rules apply (two different operators, one release per floor).

**A record changes nothing about how a deployment releases a floor.** Only the ``test``
environment's in-memory store is seeded; a production or staging engine takes its release state
from the platform tables, and an operator releases there through the routes of
``docs/m2-09-floor-upgrades.md``.

**A record is trusted only after it is checked.** It is refused (the engine doesn't start) if it
isn't a record of this format, names two approvals by one operator, doesn't say the release was
made, contradicts itself (the urgency, the staging window, the floor version in the evidence, the
order of the approvals), or its evidence isn't what the report file it names says today: the
report's hash, and the corpus the run used against the current corpus
(:func:`check_evidence`). A record that names a floor whose content hash differs from the
catalog's floor of that version is **not applied and not refused** (the floor was edited after the
release, so the release no longer describes it; the floor stays unreleased and the engine logs it).
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from guardrail_engine.admin.floors import (
    STANDARD_WINDOW,
    URGENT_WINDOW,
    Approval,
    FloorRelease,
    PlatformEvent,
    PlatformStore,
    evidence_from_report,
    release_json,
    settle,
)
from guardrail_engine.admin.service import DraftInvalidError
from guardrail_engine.policy.catalog import InMemoryCatalog

RECORD_SCHEMA_VERSION = 1
MAX_RECORD_BYTES = 64 * 1024
MAX_REPORT_BYTES = 16 * 1024 * 1024
_FIELDS = frozenset(
    {
        "schema_version", "note", "report_file", "floor_version", "floor_hash", "released",
        "released_at", "security_urgent", "staging_window_hours", "halted", "proposed_by",
        "proposed_at", "approvals", "evidence",
    }
)  # fmt: skip
_EVIDENCE_FIELDS = ("report_sha256", "mode", "floor_content_hash", "corpus_sha256", "gate")


class ReleaseRecordError(ValueError):
    """The record can't be used; the message says why (never any content of the record)."""


def record_of(release: FloorRelease, *, note: str, report_file: str) -> dict[str, Any]:
    """The record of a release that was made (``release.released`` must be true).
    ``report_file`` is the report the release was made on, as a path from the record's own
    directory."""
    if not release.released:
        raise ReleaseRecordError("a release record is written for a release that was made")
    return {
        "schema_version": RECORD_SCHEMA_VERSION, "note": note, "report_file": report_file,
        **release_json(release),
    }  # fmt: skip


def render(record: Mapping[str, Any]) -> str:
    """The file's text: sorted keys, two-space indent, one trailing newline."""
    return json.dumps(record, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def _time(value: Any, where: str) -> datetime:
    if not isinstance(value, str):
        raise ReleaseRecordError(f"{where}: a timestamp is needed")
    try:
        when = datetime.fromisoformat(value)
    except ValueError:
        raise ReleaseRecordError(f"{where}: not an ISO timestamp") from None
    if when.tzinfo is None:
        raise ReleaseRecordError(f"{where}: a timestamp with a zone is needed")
    return when.astimezone(UTC)


def release_of(record: Any) -> FloorRelease:
    """The release a record describes, or :class:`ReleaseRecordError`."""
    if not isinstance(record, dict):
        raise ReleaseRecordError("a JSON object is needed")
    if record.get("schema_version") != RECORD_SCHEMA_VERSION:
        raise ReleaseRecordError(f"schema_version: {RECORD_SCHEMA_VERSION} is the one read")
    unknown = sorted(set(record) - _FIELDS)
    if unknown:
        raise ReleaseRecordError("unknown fields: " + ", ".join(map(str, unknown)))
    version, floor_hash = record.get("floor_version"), record.get("floor_hash")
    if not isinstance(version, int) or isinstance(version, bool) or version < 1:
        raise ReleaseRecordError("floor_version: a whole number from 1 is needed")
    if not isinstance(floor_hash, str) or not floor_hash.startswith("sha256:"):
        raise ReleaseRecordError("floor_hash: a sha256 hash is needed")
    if record.get("released") is not True or record.get("halted") is not False:
        raise ReleaseRecordError("the record must be of a release that was made and isn't halted")
    evidence = record.get("evidence")
    if not isinstance(evidence, dict) or any(k not in evidence for k in _EVIDENCE_FIELDS):
        raise ReleaseRecordError("evidence: the stored summary of the report is needed")
    if evidence.get("floor_content_hash") != floor_hash or evidence.get("mode") != "live":
        raise ReleaseRecordError("evidence: it must be a live run of this floor")
    gate = evidence.get("gate")
    if not isinstance(gate, dict) or gate.get("passed") is not True:
        raise ReleaseRecordError("evidence: the run's gate must have passed")
    raw = record.get("approvals")
    if not isinstance(raw, list) or len(raw) != 2:
        raise ReleaseRecordError("approvals: exactly two are recorded")
    if evidence.get("floor_version") != version:
        raise ReleaseRecordError("evidence: it must be about the floor version of the record")
    approvals = []
    for i, item in enumerate(raw):
        if not isinstance(item, dict) or set(item) != {"operator", "urgent", "at"}:
            raise ReleaseRecordError(f"approvals[{i}]: operator, urgent and at")
        operator = item["operator"]
        if not isinstance(operator, str) or not operator or not isinstance(item["urgent"], bool):
            raise ReleaseRecordError(f"approvals[{i}]: an operator and urgent true or false")
        approvals.append(
            Approval(operator, item["urgent"], _time(item["at"], f"approvals[{i}].at"))
        )
    if approvals[0].operator == approvals[1].operator:
        raise ReleaseRecordError("approvals: two different operators are needed")
    proposed_by = record.get("proposed_by")
    if proposed_by != approvals[0].operator:
        raise ReleaseRecordError("proposed_by: the proposer is the first approval")
    proposed_at = _time(record.get("proposed_at"), "proposed_at")
    released_at = _time(record.get("released_at"), "released_at")
    if released_at != approvals[1].at or proposed_at != approvals[0].at:
        raise ReleaseRecordError("the times don't agree with the approvals")
    if approvals[0].at > approvals[1].at:
        raise ReleaseRecordError("approvals: the proposal comes before the second approval")
    _, urgent = settle(tuple(approvals))
    if record.get("security_urgent") is not urgent:
        raise ReleaseRecordError("security_urgent: it doesn't follow from the approvals")
    window = (URGENT_WINDOW if urgent else STANDARD_WINDOW).total_seconds() / 3600
    hours = record.get("staging_window_hours")
    if isinstance(hours, bool) or not isinstance(hours, (int, float)) or hours != window:
        raise ReleaseRecordError("staging_window_hours: it doesn't follow from the approvals")
    return FloorRelease(
        version, floor_hash, dict(evidence), proposed_by, proposed_at, tuple(approvals),
        released_at, urgent,
    )  # fmt: skip


def _read_json(path: Path, limit: int, what: str) -> Any:
    try:
        with path.open("rb") as fh:
            data = fh.read(limit + 1)
    except OSError as e:
        raise ReleaseRecordError(f"cannot read the {what} ({type(e).__name__})") from None
    if len(data) > limit:
        raise ReleaseRecordError(f"the {what} is too large")
    try:
        return json.loads(data)
    except ValueError:
        raise ReleaseRecordError(f"the {what} is not JSON") from None


@dataclass(frozen=True, slots=True)
class Record:
    """A record read from a file: the release and the report file it names."""

    release: FloorRelease
    report_file: Path


def load(path: Path) -> Record:
    """Read and check the record at ``path`` (its form; :func:`check_evidence` checks the
    evidence against the report)."""
    record = _read_json(path, MAX_RECORD_BYTES, "record")
    release = release_of(record)
    named = record.get("report_file")
    if not isinstance(named, str) or not named or Path(named).is_absolute():
        raise ReleaseRecordError("report_file: a path from the record's directory is needed")
    return Record(release, (path.parent / named).resolve())


def load_record(path: Path) -> FloorRelease:
    """Read and check the record at ``path``."""
    return load(path).release


def check_evidence(record: Record, corpus_sha256: str | None) -> None:
    """The record's evidence must be what the report file it names says today: the report's
    canonical hash, and the corpus the run used against the current one (``corpus_sha256``,
    None when the corpus can't be read). It is the check a release made through the routes passes
    when it is proposed, made again."""
    release = record.release
    report = _read_json(record.report_file, MAX_REPORT_BYTES, "report")
    try:
        again = evidence_from_report(
            report, release.floor_version, release.floor_hash, corpus_sha256, allow_offline=False
        )
    except DraftInvalidError as e:
        raise ReleaseRecordError(
            "the report no longer passes the evidence check: "
            + "; ".join(p.message for p in e.errors)
        ) from None
    if again != release.evidence:
        raise ReleaseRecordError("evidence: it isn't what the report file says")


def check_against(release: FloorRelease, catalog: InMemoryCatalog) -> None:
    """The release must describe the catalog's floor of that version, byte for byte."""
    floor = catalog.floor(release.floor_version)
    if floor is None:
        raise ReleaseRecordError(f"floor@{release.floor_version} is not in the catalog")
    if floor.content_hash() != release.floor_hash:
        raise ReleaseRecordError(
            f"floor@{release.floor_version} has changed since it was released: "
            "the record names a different content hash"
        )


async def replay(store: PlatformStore, release: FloorRelease) -> None:
    """Put the release into ``store`` the way the routes did: the proposal (its proposer's
    approval) and then the second operator's approval, which makes the release."""
    first, second = release.approvals
    proposed = PlatformEvent(
        first.at, first.operator, "release_proposed", release.floor_version, None,
        {"urgent": first.urgent, "evidence": release.evidence},
    )  # fmt: skip
    await store.propose(
        FloorRelease(
            release.floor_version,
            release.floor_hash,
            release.evidence,
            release.proposed_by,
            release.proposed_at,
            approvals=(first,),
        ),
        proposed,
    )
    await store.approve(
        release.floor_version,
        second,
        PlatformEvent(
            second.at,
            second.operator,
            "release_approved",
            release.floor_version,
            None,
            {"urgent": second.urgent},
        ),
        PlatformEvent(second.at, second.operator, "released", release.floor_version),
    )


__all__ = [
    "MAX_RECORD_BYTES", "MAX_REPORT_BYTES", "RECORD_SCHEMA_VERSION", "Record",
    "ReleaseRecordError", "check_against", "check_evidence", "load", "load_record", "record_of",
    "release_of", "render", "replay",
]  # fmt: skip
