"""M7-04 on the engine: with a class A audit file configured, a regulated tenant's decision
records are kept in a spill file beside it when the writer's queue is full, a standard tenant's
are dropped as before, and the verdict is the same either way."""

import asyncio

import pytest
from engine_fixtures import TENANT, directory, profile, settings, verifier

from guardrail_engine.audit.spill import SPILL_FILE_NAME
from guardrail_engine.audit.store import InMemoryDecisionRecords
from guardrail_engine.decision import FakeDecisionModel
from guardrail_engine.engine import SettingsError, build_engine
from guardrail_engine.guard import CheckContext


@pytest.fixture
def audit_dir(tmp_path):
    d = tmp_path / "audit"
    d.mkdir(mode=0o700)
    d.chmod(0o700)
    return d


async def build(audit_dir, tier, records):
    return await build_engine(
        settings("staging", class_a_audit={"file": str(audit_dir / "class_a.jsonl")}),
        verifier=verifier(),
        tenants=directory(profile(TENANT, tier=tier)),
        model=FakeDecisionModel(),
        decision_records=records,
    )


async def check(engine):
    return await engine.check(CheckContext(signed_context=verifier().issue(TENANT)), "output", "hi")


async def stop_the_drain(writer):
    """Stop the drain task, so the queue stays as it is, as a database outage leaves it."""
    task = writer._task
    task.cancel()
    await asyncio.gather(task, return_exceptions=True)
    writer._task = None


async def fill_the_queue(engine):
    """Stop the drain so the queue stays full, as a database outage does."""
    writer = engine.decision_writer
    writer._capacity = 1
    writer._regulated_wait_s = 0.02
    await check(engine)  # takes the one place


async def test_a_regulated_tenants_record_is_spilled_when_the_queue_is_full(audit_dir):
    records = InMemoryDecisionRecords()
    engine = await build(audit_dir, "regulated", records)
    writer = engine.decision_writer
    try:
        await stop_the_drain(writer)
        await fill_the_queue(engine)
        verdicts = [await check(engine) for _ in range(3)]
        assert (writer.spilled, writer.dropped) == (3, 0)
        assert (audit_dir / SPILL_FILE_NAME).stat().st_size > 0
        assert {v.decision for v in verdicts} == {verdicts[0].decision}
    finally:
        await engine.shutdown()


async def test_a_standard_tenants_record_is_dropped_as_before(audit_dir):
    records = InMemoryDecisionRecords()
    engine = await build(audit_dir, "standard", records)
    writer = engine.decision_writer
    try:
        await stop_the_drain(writer)
        await fill_the_queue(engine)
        for _ in range(3):
            await check(engine)
        assert (writer.spilled, writer.dropped) == (0, 3)
    finally:
        await engine.shutdown()


async def test_the_verdict_is_the_same_with_and_without_a_full_queue(audit_dir):
    records = InMemoryDecisionRecords()
    engine = await build(audit_dir, "regulated", records)
    writer = engine.decision_writer
    try:
        before = await check(engine)
        await stop_the_drain(writer)
        await fill_the_queue(engine)
        full = await check(engine)
        assert (full.decision, full.reason, full.bundle_version) == (
            before.decision,
            before.reason,
            before.bundle_version,
        )
    finally:
        await engine.shutdown()


async def test_an_engine_restart_writes_the_spilled_records(audit_dir):
    first_records = InMemoryDecisionRecords()
    first = await build(audit_dir, "regulated", first_records)
    writer = first.decision_writer
    await stop_the_drain(writer)
    await fill_the_queue(first)
    for _ in range(2):
        await check(first)
    assert writer.spilled == 2

    store = InMemoryDecisionRecords()  # the same database, a new process
    second = await build(audit_dir, "regulated", store)
    try:
        await second.decision_writer.replay()
        assert len(store.all()) == 2
        assert not (audit_dir / SPILL_FILE_NAME).exists()
    finally:
        await second.shutdown()


async def test_an_unsafe_spill_file_stops_the_engine_from_starting(audit_dir, tmp_path):
    (audit_dir / SPILL_FILE_NAME).symlink_to(tmp_path / "elsewhere")
    with pytest.raises(SettingsError, match=r"decision_spill\.file"):
        await build(audit_dir, "regulated", InMemoryDecisionRecords())


# ------------------------------------------------------------------------ where the spill is


async def build_with(environment, records, **sections):
    return await build_engine(
        settings(environment, **sections),
        verifier=verifier(),
        tenants=directory(profile(TENANT, tier="regulated")),
        model=FakeDecisionModel(),
        decision_records=records,
    )


@pytest.mark.parametrize("environment", ["production", "staging"])
async def test_production_and_staging_refuse_to_start_without_a_spill_location(environment):
    with pytest.raises(SettingsError, match=r"decision_spill\.file: required"):
        await build_with(environment, InMemoryDecisionRecords())


async def test_the_refusal_is_about_the_configuration_not_the_tenants_today(tmp_path):
    """No tenant is regulated yet (the directory here has none); the engine still refuses, since
    a tier can be raised at runtime."""
    with pytest.raises(SettingsError, match=r"decision_spill\.file: required"):
        await build_engine(
            settings("staging"),
            verifier=verifier(),
            tenants=directory(),
            model=FakeDecisionModel(),
            decision_records=InMemoryDecisionRecords(),
        )


async def test_a_test_engine_needs_no_spill_location():
    engine = await build_with("test", InMemoryDecisionRecords())
    try:
        assert engine.decision_writer._spill is None
    finally:
        await engine.shutdown()


async def test_a_spill_file_of_its_own_stands_in_for_the_class_a_directory(audit_dir):
    path = audit_dir / "records.spill"
    engine = await build_with("test", InMemoryDecisionRecords(), decision_spill={"file": str(path)})
    try:
        assert engine.decision_writer._spill.path == path
    finally:
        await engine.shutdown()


async def test_the_spill_file_setting_wins_over_the_class_a_directory(audit_dir, tmp_path):
    other = tmp_path / "elsewhere"
    other.mkdir(mode=0o700)
    other.chmod(0o700)
    engine = await build_with(
        "staging",
        InMemoryDecisionRecords(),
        class_a_audit={"file": str(audit_dir / "class_a.jsonl")},
        decision_spill={"file": str(other / "s.jsonl")},
    )
    try:
        assert engine.decision_writer._spill.path == other / "s.jsonl"
    finally:
        await engine.shutdown()


async def test_an_unsafe_own_spill_location_is_refused(tmp_path):
    loose = tmp_path / "loose"
    loose.mkdir()
    loose.chmod(0o777)
    with pytest.raises(SettingsError, match=r"decision_spill\.file: .*world-writable"):
        await build_with(
            "test", InMemoryDecisionRecords(), decision_spill={"file": str(loose / "s")}
        )


async def test_the_cap_is_a_setting():
    from guardrail_engine.engine import EngineSettings

    assert EngineSettings().decision_spill.max_bytes == 256 * 1024 * 1024
    with pytest.raises(SettingsError):
        settings("test", decision_spill={"max_bytes": 10})
