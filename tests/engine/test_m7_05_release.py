"""M7-05: floor@2 is released through the floor release path, and an engine of the simulation
starts with it released. The default floor is the one the held-out evidence describes."""

import hashlib
import json
import logging
from pathlib import Path
from types import SimpleNamespace

import pytest
from calibration.run import assemble_floor
from engine_fixtures import TENANT, directory, profile, settings, verifier
from floor import simulate_release

from guardrail_engine.admin import floor_records
from guardrail_engine.admin.floor_records import ReleaseRecordError, load_record, release_of
from guardrail_engine.admin.floors import (
    InMemoryPlatformStore,
    ReleaseExistsError,
    SecondOperatorRequiredError,
)
from guardrail_engine.admin.service import DraftInvalidError
from guardrail_engine.admin.tool_registry import ToolScreener
from guardrail_engine.authz import InMemoryAuthzAudit, Principal, Role
from guardrail_engine.decision import FakeDecisionModel
from guardrail_engine.engine import SettingsError, build_engine
from guardrail_engine.engine.factory import _release_records
from guardrail_engine.floor_file import FLOOR_FILES, RELEASE_RECORDS, load_floor_file
from guardrail_engine.policy import PlatformSettings
from guardrail_engine.policy.canonical import sha256_of
from guardrail_engine.policy.catalog import FloorVersion

ROOT = Path(__file__).resolve().parents[2]
RULES = ROOT / "floor" / "rules.json"
RULES_V2 = ROOT / "floor" / "rules.v2.json"
ADDITIONS = ROOT / "floor" / "next" / "additions.json"
RECORD = ROOT / "floor" / "releases" / "floor-2.release.json"
REPORT = ROOT / "redteam" / "floor2.live.report.json"
CORPUS = ROOT / "redteam" / "corpus.jsonl"
HELD_OUT = ROOT / "calibration" / "results" / "m0-02-heldout-validation.jsonl"
# What the held-out run measured, pinned from its own record (run_started.files) and from the
# additions file in git at commit c35840f, the one the run read (file sha256 523ccbef…). Today's
# file differs from it only in its "note", which the floor's content hash doesn't cover.
HELD_OUT_ADDITIONS_FILE = "sha256:523ccbefe14920d96ba4f7164af23a96432abe33c4e47338271f11942bef99d2"
HELD_OUT_ADDITIONS_WITHOUT_NOTE = (
    "sha256:fd0e1e2e835dbd81f10f6ed1af7684c0975b8229cc6285116f1886229bcbcbc8"
)
HELD_OUT_FLOOR = "sha256:521acbf359f149a4261d160381f70069ea9f5baff8c8c39c442beb0a6a236af6"
BOTH = [str(RULES), str(RULES_V2)]


def raw() -> dict:
    return json.loads(RECORD.read_text())


async def build(**catalog):
    return await build_engine(
        settings("test", catalog={"floor_files": BOTH, **catalog}),
        verifier=verifier(),
        tenants=directory(),
        model=FakeDecisionModel(),
        authz_audit=InMemoryAuthzAudit(),
    )


def viewer() -> Principal:
    return Principal("vic", TENANT, frozenset({Role.VIEWER}), issuer="https://i/")


# ------------------------------------------------------------------ the record


def test_the_committed_record_is_current():
    """The record is about today's floor@2 file, names the report in the repository, and the
    report still passes the evidence check against today's corpus."""
    assert simulate_release.problems_with() == []


def test_the_released_floor_is_the_floor_the_held_out_run_measured():
    """Anchored on what the run recorded, not on files that have moved since: the run's own
    ``run_started.files`` names the rules and additions it read."""
    started = json.loads(HELD_OUT.read_text().splitlines()[0])
    assert started["type"] == "run_started" and started["floor_version"] == 2
    files = started["files"]
    assert files["additions"] == HELD_OUT_ADDITIONS_FILE  # the pin is the run's own record
    # floor@1 is the file the run read, byte for byte
    assert files["rules"] == "sha256:" + hashlib.sha256(RULES.read_bytes()).hexdigest()
    # the additions are the ones the run read, but for the note
    additions = json.loads(ADDITIONS.read_text())
    additions.pop("note", None)
    assert sha256_of(additions) == HELD_OUT_ADDITIONS_WITHOUT_NOTE
    # the floor the run measured is the floor today's files assemble and the floor released
    record, report = raw(), json.loads(REPORT.read_text())
    assembled = FloorVersion.from_document(dict(assemble_floor(RULES, ADDITIONS))).content_hash()
    assert assembled == HELD_OUT_FLOOR
    assert load_floor_file(RULES_V2).content_hash() == HELD_OUT_FLOOR
    assert record["floor_hash"] == HELD_OUT_FLOOR
    assert (
        report["floor_content_hash"] == record["evidence"]["floor_content_hash"] == HELD_OUT_FLOOR
    )
    assert record["floor_version"] == report["floor_version"] == 2
    assert record["evidence"]["report_sha256"] == sha256_of(report)


def test_the_record_is_of_a_live_run_that_passed_and_of_two_different_operators():
    record = raw()
    assert record["evidence"]["mode"] == "live" and record["evidence"]["gate"]["passed"] is True
    assert record["evidence"]["rows"] == 172 and record["evidence"]["draws"] == 3
    one, two = (a["operator"] for a in record["approvals"])
    assert one != two and record["proposed_by"] == one
    assert record["released"] is True and record["halted"] is False
    assert record["security_urgent"] is False  # the 72-hour window


def test_the_record_reads_back_as_the_release_it_describes():
    release = load_record(RECORD)
    assert release.released and release.floor_version == 2
    assert [a.operator for a in release.approvals] == [
        raw()["approvals"][0]["operator"],
        raw()["approvals"][1]["operator"],
    ]


@pytest.mark.parametrize(
    "mutate, why",
    [
        (lambda r: r.update(schema_version=2), "schema_version"),
        (lambda r: r.update(extra=1), "unknown fields"),
        (lambda r: r.update(floor_version=0), "floor_version"),
        (lambda r: r.update(floor_hash="abc"), "floor_hash"),
        (lambda r: r.update(released=False), "release that was made"),
        (lambda r: r.update(halted=True), "release that was made"),
        (lambda r: r["evidence"].update(mode="fake"), "live run"),
        (lambda r: r["evidence"].update(gate={"passed": False}), "gate"),
        (lambda r: r["evidence"].pop("report_sha256"), "evidence"),
        (lambda r: r.update(approvals=r["approvals"][:1]), "exactly two"),
        (lambda r: r["approvals"][1].update(operator=r["approvals"][0]["operator"]), "different"),
        (lambda r: r.update(proposed_by="someone-else"), "proposer"),
        (lambda r: r["approvals"][0].update(at="not a time"), "ISO"),
        (lambda r: r["approvals"][0].update(at="2026-11-24T09:36:39"), "zone"),
        (lambda r: r.update(released_at="2026-11-25T00:00:00+00:00"), "times"),
        # the fields that follow from the approvals, the evidence and their order
        (lambda r: [a.update(urgent=True) for a in r["approvals"]], "security_urgent"),
        (lambda r: r.update(security_urgent=True), "security_urgent"),
        (lambda r: r.update(staging_window_hours=6), "staging_window_hours"),
        (lambda r: r.pop("staging_window_hours"), "staging_window_hours"),
        (lambda r: r["evidence"].update(floor_version=1), "floor version"),
        (
            lambda r: (
                r["approvals"][0].update(at="2026-11-25T00:00:00+00:00"),
                r.update(proposed_at="2026-11-25T00:00:00+00:00"),
            ),
            "proposal comes before",
        ),
    ],
)
def test_a_record_that_does_not_describe_a_made_release_is_refused(mutate, why):
    record = raw()
    mutate(record)
    with pytest.raises(ReleaseRecordError, match=why):
        release_of(record)


@pytest.mark.parametrize("document", [[], "x", None, 7])
def test_a_record_that_is_not_an_object_is_refused(document):
    with pytest.raises(ReleaseRecordError):
        release_of(document)


async def test_a_replayed_release_goes_through_the_stores_own_rules():
    release = load_record(RECORD)
    store = InMemoryPlatformStore()
    await floor_records.replay(store, release)
    assert [r.released for r in await store.releases()] == [True]
    assert [e.action for e in await store.events()] == [
        "release_proposed", "release_approved", "released",
    ]  # fmt: skip
    with pytest.raises(ReleaseExistsError):  # a floor is released once
        await floor_records.replay(store, release)


async def test_the_store_refuses_a_second_approval_by_the_proposer():
    release = load_record(RECORD)
    first = release.approvals[0]
    store = InMemoryPlatformStore()
    await floor_records.replay(InMemoryPlatformStore(), release)  # a well-formed one is fine
    bad = release.__class__(
        release.floor_version, release.floor_hash, release.evidence, release.proposed_by,
        release.proposed_at, approvals=(first, first), released_at=first.at,
    )  # fmt: skip
    with pytest.raises(SecondOperatorRequiredError):
        await floor_records.replay(store, bad)


# ------------------------------------------------------------------ the release path


async def test_the_release_path_refuses_a_report_whose_gate_failed(tmp_path):
    report = json.loads(REPORT.read_text())
    report["gate"] = {"exit_code": 1, "passed": False}
    path = tmp_path / "report.json"
    path.write_text(json.dumps(report))
    with pytest.raises(DraftInvalidError) as refused:
        await simulate_release.release(path)
    assert [e.code for e in refused.value.errors] == ["release.evidence"]
    assert "gate did not pass" in refused.value.errors[0].message


async def test_the_release_path_refuses_a_report_of_another_floor(tmp_path):
    report = json.loads(REPORT.read_text())
    report["floor_content_hash"] = "sha256:" + "0" * 64
    path = tmp_path / "report.json"
    path.write_text(json.dumps(report))
    with pytest.raises(DraftInvalidError) as refused:
        await simulate_release.release(path)
    assert "content differs" in refused.value.errors[0].message


async def test_running_the_release_path_again_gives_the_recorded_evidence():
    again = await simulate_release.release()
    assert again["evidence"] == raw()["evidence"]
    assert again["floor_hash"] == raw()["floor_hash"]
    assert [a["operator"] for a in again["approvals"]] == [
        a["operator"] for a in raw()["approvals"]
    ]


# ------------------------------------------------------------------ in the engine


async def test_an_engine_of_the_simulation_starts_with_floor_2_released():
    engine = await build()
    try:
        assert engine.catalog.floor_versions() == (1, 2)
        assert engine.catalog.is_released(1) and engine.catalog.is_released(2)
        d = await engine.authorizer.authorize(
            viewer(), "GET", "/v1/tenants/{tid}/guardrails/catalog", tenant_id=TENANT
        )
        view = await engine.catalog_service.view(d)
        assert {f["version"]: f["extendable"] for f in view["floors"]} == {1: True, 2: True}
        assert view["starter_bundle"]["extends"] == ["platform/floor@2"]
    finally:
        await engine.shutdown()


async def test_the_default_floor_of_a_new_tenant_is_the_one_the_report_measured():
    engine = await build()
    try:
        d = await engine.authorizer.authorize(
            viewer(), "GET", "/v1/tenants/{tid}/guardrails/catalog", tenant_id=TENANT
        )
        starter = (await engine.catalog_service.view(d))["starter_bundle"]
        await engine.bootstrap_publish(starter)  # it compiles: floor@2 is extendable
        assert await engine.store.get_active_version(TENANT) == 1
        newest = max(engine.catalog.floor_versions())
        assert starter["extends"] == [f"platform/floor@{newest}"]
        report = json.loads(REPORT.read_text())
        assert engine.catalog.floor(newest).content_hash() == report["floor_content_hash"]
    finally:
        await engine.shutdown()


async def test_the_platform_listing_shows_the_release_with_its_two_operators_and_its_evidence():
    engine = await build()
    try:
        events = await engine.floor_service._platform.events()
        assert [e.action for e in events] == ["release_proposed", "release_approved", "released"]
        assert len({e.actor for e in events}) == 2
        release = await engine.floor_service._platform.release(2)
        assert release is not None and release.released
        assert release.evidence["report_sha256"] == sha256_of(json.loads(REPORT.read_text()))
    finally:
        await engine.shutdown()


async def test_tool_screening_uses_floor_2_once_it_is_released():
    engine = await build()
    try:
        screener = ToolScreener(None, engine.catalog, PlatformSettings())  # type: ignore[arg-type]
        policy = screener.policy(profile())
        assert policy is not None and policy.version == 2
    finally:
        await engine.shutdown()


async def test_a_tenant_still_on_floor_1_keeps_working_and_floor_1_is_still_the_baseline():
    engine = await build()
    try:
        await engine.bootstrap_publish(
            {
                "schema_version": 1, "tenant_id": TENANT, "version": 1,
                "extends": ["platform/floor@1"],
            }
        )  # fmt: skip
        assert await engine.store.get_active_version(TENANT) == 1
        assert engine.catalog.minimum_floor_version() == 1  # nobody is forced up by the release
    finally:
        await engine.shutdown()


async def test_with_no_record_only_the_baseline_is_released():
    engine = await build(release_records=[])
    try:
        assert engine.catalog.is_released(1) and not engine.catalog.is_released(2)
    finally:
        await engine.shutdown()


async def test_a_record_for_a_floor_the_engine_does_not_load_releases_nothing():
    engine = await build_engine(
        settings("test"),  # floor@1 only; the default record names floor@2
        verifier=verifier(),
        tenants=directory(),
        model=FakeDecisionModel(),
        authz_audit=InMemoryAuthzAudit(),
    )
    try:
        assert engine.catalog.floor_versions() == (1,)
        assert await engine.floor_service._platform.releases() == []
    finally:
        await engine.shutdown()


async def test_a_floor_that_changed_after_its_release_is_not_released_and_is_logged(
    tmp_path, caplog
):
    changed = json.loads(RULES_V2.read_text())
    changed["rules"][0]["question"] = changed["rules"][0]["question"].replace("?", " today?")
    path = tmp_path / "rules.v2.json"
    path.write_text(json.dumps(changed))
    caplog.set_level(logging.WARNING)
    engine = await build_engine(
        settings("test", catalog={"floor_files": [str(RULES), str(path)]}),
        verifier=verifier(),
        tenants=directory(),
        model=FakeDecisionModel(),
        authz_audit=InMemoryAuthzAudit(),
    )
    try:
        assert engine.catalog.floor_versions() == (1, 2)
        assert not engine.catalog.is_released(2)
        assert any("has changed since it was released" in r.message for r in caplog.records)
    finally:
        await engine.shutdown()


@pytest.mark.parametrize("content", ["not json", "[]", '{"schema_version": 9}'])
async def test_an_unreadable_or_malformed_record_stops_the_start(tmp_path, content):
    path = tmp_path / "record.json"
    path.write_text(content)
    with pytest.raises(SettingsError) as refused:
        await build(release_records=[str(path)])
    assert "catalog.release_records[0]" in str(refused.value)


async def test_a_missing_record_stops_the_start(tmp_path):
    with pytest.raises(SettingsError) as refused:
        await build(release_records=[str(tmp_path / "gone.json")])
    assert "cannot read" in str(refused.value)


async def test_the_same_floor_released_by_two_records_stops_the_start():
    with pytest.raises(SettingsError) as refused:
        await build(release_records=[str(RECORD), str(RECORD)])
    assert "released twice" in str(refused.value)


def _records_with(tmp_path, *, record=None, report=None, name="report.json"):
    """A record and the report it names, copied to ``tmp_path`` and changed there."""
    record = {**raw(), "report_file": name} if record is None else record
    document = json.loads(REPORT.read_text()) if report is None else report
    (tmp_path / name).write_text(json.dumps(document))
    path = tmp_path / "record.json"
    path.write_text(json.dumps(record))
    return str(path)


async def test_a_copy_of_the_record_and_its_report_starts_the_engine(tmp_path):
    engine = await build(release_records=[_records_with(tmp_path)])
    try:
        assert engine.catalog.is_released(2)
    finally:
        await engine.shutdown()


async def test_a_record_with_made_up_evidence_stops_the_start(tmp_path):
    record = raw()
    record["report_file"] = "report.json"
    record["evidence"].update(
        report_sha256="sha256:" + "0" * 64, corpus_sha256="sha256:" + "0" * 64
    )
    record["evidence"].update(rows=1, draws=1)
    for approval, who in zip(record["approvals"], ("anyone-x", "anyone-y"), strict=True):
        approval["operator"] = who
    record["proposed_by"] = "anyone-x"
    with pytest.raises(SettingsError) as refused:
        await build(release_records=[_records_with(tmp_path, record=record)])
    assert "catalog.release_records[0]" in str(refused.value)
    assert "report" in str(refused.value)


async def test_a_report_edited_since_the_release_stops_the_start(tmp_path):
    report = json.loads(REPORT.read_text())
    report["rows"] = report["rows"] + 1
    with pytest.raises(SettingsError) as refused:
        await build(release_records=[_records_with(tmp_path, report=report)])
    assert "isn't what the report file says" in str(refused.value)


async def test_a_corpus_changed_since_the_release_stops_the_start(tmp_path):
    corpus = tmp_path / "corpus.jsonl"
    corpus.write_bytes(CORPUS.read_bytes() + b"\n")
    with pytest.raises(SettingsError) as refused:
        await build(release_records=[_records_with(tmp_path)], redteam_corpus=str(corpus))
    assert "different corpus" in str(refused.value)


async def test_a_corpus_that_cannot_be_read_stops_the_start(tmp_path):
    with pytest.raises(SettingsError) as refused:
        await build(
            release_records=[_records_with(tmp_path)], redteam_corpus=str(tmp_path / "none")
        )
    assert "corpus is unavailable" in str(refused.value)


async def test_a_missing_report_stops_the_start(tmp_path):
    path = _records_with(tmp_path)
    (tmp_path / "report.json").unlink()
    with pytest.raises(SettingsError) as refused:
        await build(release_records=[path])
    assert "cannot read the report" in str(refused.value)


@pytest.mark.parametrize("named", ["/etc/passwd", "", 7])
async def test_a_record_that_names_no_usable_report_stops_the_start(tmp_path, named):
    record = {**raw(), "report_file": named}
    with pytest.raises(SettingsError) as refused:
        await build(release_records=[_records_with(tmp_path, record=record)])
    assert "report_file" in str(refused.value)


def test_a_production_engine_takes_no_record():
    fake = SimpleNamespace(
        environment="production", catalog=SimpleNamespace(release_records=(RECORD,))
    )
    problems: list[str] = []
    assert _release_records(fake, object(), problems) == [] and problems == []  # type: ignore[arg-type]


# ------------------------------------------------------------------ the local runner


def test_the_local_runner_serves_both_floors_and_the_record():
    assert [Path(p).name for p in FLOOR_FILES] == ["rules.json", "rules.v2.json"]
    assert [Path(p) for p in RELEASE_RECORDS] == [RECORD]
    assert all(Path(p).is_file() for p in [*FLOOR_FILES, *RELEASE_RECORDS])
