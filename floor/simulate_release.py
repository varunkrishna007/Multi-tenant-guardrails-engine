"""Release floor@2 through the platform's own release path, in a simulation (M7-05).

    uv run python -m floor.simulate_release            # make the release, write the record
    uv run python -m floor.simulate_release --check    # fail if the record isn't current

It does what ``POST /v1/platform/floors/2/release`` and ``…/approve`` do, with the real
:class:`~guardrail_engine.admin.floors.FloorService`, the real authorizer (a platform route needs
an operator principal) and the real evidence check: the proposal carries the live red-team report
(``redteam/floor2.live.report.json``); it is refused unless the gate passed, the run was live,
the report measured this floor and this corpus, and nothing was short. A **second, different
operator** then approves the proposal **naming the report's hash**. The two operators are test
identities (``simulation-operator-a`` and ``-b``): nothing here is a real person's approval.

What it writes is the **release record** (``floor/releases/floor-2.release.json``), the state the
release path produced. An engine in the ``test`` environment replays it into its in-memory
platform store at start (``admin/floor_records.py``), which is how floor@2 is the released floor
of the simulation. Offline; sends nothing.

``--check`` does not release anything: it reads the record and requires that it is about the
current floor@2 file, names the report's hash, has two different operators, and that the report
still passes the evidence check against today's corpus.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:  # pragma: no cover - run as a script
    sys.path.insert(0, str(ROOT))

from guardrail_engine.admin.floor_records import (  # noqa: E402
    ReleaseRecordError,
    check_against,
    check_evidence,
    load,
    record_of,
    render,
)
from guardrail_engine.admin.floors import (  # noqa: E402
    APPROVE,
    RELEASE,
    FloorService,
    InMemoryPlatformStore,
)
from guardrail_engine.authz import Authorizer, InMemoryAuthzAudit, Principal, Role  # noqa: E402
from guardrail_engine.floor_file import load_floor_file  # noqa: E402
from guardrail_engine.policy.catalog import InMemoryCatalog  # noqa: E402

VERSION = 2
FLOORS = (ROOT / "floor" / "rules.json", ROOT / "floor" / "rules.v2.json")
REPORT = ROOT / "redteam" / "floor2.live.report.json"
CORPUS = ROOT / "redteam" / "corpus.jsonl"
OUT = ROOT / "floor" / "releases" / "floor-2.release.json"
ISSUER = "https://simulation.invalid/"
PROPOSER, APPROVER = "simulation-operator-a", "simulation-operator-b"
NOTE = (
    "A simulated release: the two operators are test identities, and the report is the live "
    "red-team run of floor@2 (redteam/floor2.live.report.json). Written by "
    "`python -m floor.simulate_release`; an engine in the test environment replays it."
)


def _catalog() -> InMemoryCatalog:
    catalog = InMemoryCatalog(floors=[load_floor_file(path) for path in FLOORS])
    catalog.set_released({min(catalog.floor_versions())})  # closed but for the baseline
    return catalog


def _corpus_hash() -> str:
    import hashlib

    return "sha256:" + hashlib.sha256(CORPUS.read_bytes()).hexdigest()


def _operator(subject: str) -> Principal:
    return Principal(subject, None, frozenset({Role.VIEWER}), True, ISSUER)


async def release(report_path: Path = REPORT) -> dict[str, object]:
    """Propose floor@2 with the report, approve it by a second operator, and return the record."""
    report_text = report_path.read_text()
    catalog = _catalog()
    store = InMemoryPlatformStore()
    service = FloorService(store, catalog, corpus_sha256=_corpus_hash, allow_offline=False)
    await service.load()
    authorizer = Authorizer(InMemoryAuthzAudit())
    proposer, approver = _operator(PROPOSER), _operator(APPROVER)

    decision = await authorizer.authorize(proposer, *RELEASE)
    body = json.dumps({"report": json.loads(report_text), "security_urgent": False}).encode()
    proposed = await service.propose(decision, proposer, VERSION, body)

    decision = await authorizer.authorize(approver, *APPROVE)
    named = {"report_sha256": proposed.evidence["report_sha256"], "security_urgent": False}
    released = await service.approve(decision, approver, VERSION, json.dumps(named).encode())
    assert released.released
    return record_of(released, note=NOTE, report_file=os.path.relpath(report_path, OUT.parent))


def problems_with(out: Path = OUT) -> list[str]:
    """What is wrong with the record at ``out``; empty when it is current. It is the check an
    engine makes at start (the form, the floor file, the report and the corpus), and that the
    record names the report this repository holds."""
    try:
        record = load(out)
        check_against(record.release, _catalog())
        check_evidence(record, _corpus_hash())
    except ReleaseRecordError as e:
        return [f"{out.name}: {e}"]
    if record.report_file != REPORT.resolve():
        return [f"{out.name}: it names a report other than {REPORT.relative_to(ROOT)}"]
    return []


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    if args.check:
        found = problems_with()
        for line in found:
            print(line, file=sys.stderr)
        if not found:
            print(f"ok: {OUT.relative_to(ROOT)} is current")
        return 1 if found else 0
    if OUT.exists():
        print(f"{OUT.relative_to(ROOT)} exists: a release is made once", file=sys.stderr)
        return 1
    record = asyncio.run(release())
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(render(record))
    print(f"wrote {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
