"""M3-01 wiring: the directory's identifier patterns (the operator write path, the record, the
store contract) and DirectoryIdentifiers, the scan's source over the directory."""

import pytest

from guardrail_engine.authz import Principal, Role
from guardrail_engine.deterministic import tenant_id_pattern
from guardrail_engine.directory import (
    CachedTenantDirectory,
    DirectoryIdentifiers,
    InMemoryDirectoryStore,
    InMemoryEventBus,
    InvalidTenantRecord,
    NotAPlatformOperator,
    TenantProvisioner,
    TenantRecord,
)
from guardrail_engine.directory.model import DirectoryAuditEvent, audit_fields

OPS = Principal("ops-1", None, frozenset(), True)
ALICE = Principal("alice", "t_alpha", frozenset({Role.GUARDRAIL_ADMIN}))
GOOD = (r"BET-INV-[0-9]{4}", r"BET-ACC-[0-9]{6}")


def provisioner(store=None):
    store = store if store is not None else InMemoryDirectoryStore()
    bus = InMemoryEventBus()
    return TenantProvisioner(store, bus, clock=lambda: 1_700_000_000.0), store, bus


class Clock:
    def __init__(self) -> None:
        self.now = 100.0

    def __call__(self) -> float:
        return self.now


# ------------------------------------------------------------------ the operator write path


async def test_an_operator_registers_patterns_at_creation_and_later_and_both_are_audited():
    prov, store, bus = provisioner()
    record = await prov.create(
        OPS, slug="beta", domain="energy", identifier_patterns=[r"BET-INV-[0-9]{4}"]
    )
    assert record.identifier_patterns == (r"BET-INV-[0-9]{4}",)
    updated = await prov.set_identifier_patterns(OPS, record.tenant_id, record.version, GOOD)
    assert updated.identifier_patterns == GOOD and updated.version == 2
    events = await store.audit_events(record.tenant_id)
    assert [e.action for e in events] == ["create", "update"]
    assert events[1].before["identifier_patterns"] == [r"BET-INV-[0-9]{4}"]
    assert events[1].after["identifier_patterns"] == list(GOOD)
    assert [e.kind for e in bus.published] == ["create", "update"]


async def test_update_takes_identifier_patterns_with_the_other_fields_and_none_clears_them():
    prov, _, _ = provisioner()
    record = await prov.create(OPS, slug="beta", domain="energy", identifier_patterns=GOOD)
    changed = await prov.update(
        OPS, record.tenant_id, 1, tier="regulated", identifier_patterns=[GOOD[0]]
    )
    assert changed.tier == "regulated" and changed.identifier_patterns == (GOOD[0],)
    cleared = await prov.set_identifier_patterns(OPS, record.tenant_id, 2, [])
    assert cleared.identifier_patterns == ()


@pytest.mark.parametrize(
    ("patterns", "reason"),
    [
        (["."], "empty_match|short_literal_prefix|matches_benign_text"),
        (["[0-9]"], "short_literal_prefix"),
        (["account"], "matches_benign_text"),
        (["2025-"], "matches_benign_text|too_few_digits_or_separators"),
        (["ORD-[0-9]{3}"], "too_few_digits_or_separators"),
        (["ORD-[0-9a-z]{1,64}-" * 3], "repeat_too_large"),
        (["ORD-[0-9]+"], "repeat_too_large"),
        (["(?=x)ORD-[0-9]{4}"], "invalid_regex"),
        (["ORD-(?:A|B"], "invalid_regex"),
        ([f"BET-{i:02d}-[0-9]{{4}}" for i in range(21)], "too_many_patterns"),
    ],
)
async def test_a_pattern_the_platform_would_not_review_is_refused_and_nothing_is_written(
    patterns, reason
):
    prov, store, bus = provisioner()
    record = await prov.create(OPS, slug="beta", domain="energy")
    with pytest.raises(InvalidTenantRecord, match="identifier pattern refused: ") as refused:
        await prov.set_identifier_patterns(OPS, record.tenant_id, 1, patterns)
    assert refused.value.args[0].split(": ")[1] in reason.split("|")
    assert patterns[0] not in str(refused.value)  # the message never quotes the pattern
    assert (await store.get(record.tenant_id)).version == 1
    assert len(await store.audit_events(record.tenant_id)) == 1 and len(bus.published) == 1
    with pytest.raises(InvalidTenantRecord):
        await prov.create(OPS, slug="gamma", domain="energy", identifier_patterns=patterns)


async def test_a_bare_string_is_not_a_list_of_patterns():
    prov, _, _ = provisioner()
    with pytest.raises(InvalidTenantRecord, match="list of patterns"):
        await prov.create(OPS, slug="beta", domain="energy", identifier_patterns="BET-INV-1234")


async def test_only_a_platform_operator_registers_patterns():
    prov, _, _ = provisioner()
    record = await prov.create(OPS, slug="beta", domain="energy")
    with pytest.raises(NotAPlatformOperator):
        await prov.set_identifier_patterns(ALICE, record.tenant_id, 1, GOOD)


def test_the_record_checks_the_shape_so_a_row_written_another_way_can_still_be_read():
    TenantRecord("t_beta", "beta", "energy", identifier_patterns=("[0-9]",))  # shape only
    for bad in (
        ["BET-1234"],
        ("",),
        (1,),
        ("x" * 501,),
        tuple("p" * 6 + str(i) for i in range(21)),
    ):
        with pytest.raises(InvalidTenantRecord, match="identifier_patterns"):
            TenantRecord("t_beta", "beta", "energy", identifier_patterns=bad)


def test_the_audit_fields_carry_the_patterns():
    record = TenantRecord("t_beta", "beta", "energy", identifier_patterns=GOOD)
    assert audit_fields(record)["identifier_patterns"] == list(GOOD)
    assert DirectoryAuditEvent  # the event type is unchanged


# ------------------------------------------------------------------ the scan's source


async def populated():
    prov, store, _ = provisioner()
    alpha = await prov.create(OPS, slug="alpha", domain="insurance")
    beta = await prov.create(OPS, slug="beta", domain="energy", identifier_patterns=GOOD)
    return prov, store, alpha, beta


async def test_every_tenant_is_reported_with_its_id_pattern_and_its_registered_ones():
    _, store, alpha, beta = await populated()
    source = DirectoryIdentifiers(store)
    got = await source.patterns_by_tenant()
    assert set(got) == {alpha.tenant_id, beta.tenant_id}
    assert got[alpha.tenant_id] == (tenant_id_pattern(alpha.tenant_id),)
    assert got[beta.tenant_id] == (tenant_id_pattern(beta.tenant_id), *GOOD)


async def test_a_suspended_or_offboarded_tenants_identifiers_are_still_scanned_for():
    prov, store, _, beta = await populated()
    await prov.set_status(OPS, beta.tenant_id, beta.version, "offboarded")
    got = await DirectoryIdentifiers(store).patterns_by_tenant()
    assert beta.tenant_id in got and GOOD[0] in got[beta.tenant_id]


async def test_the_directory_is_read_at_most_every_refresh_and_at_once_after_invalidate():
    prov, store, _, beta = await populated()
    lists = []
    real = store.list

    async def counting():
        lists.append(1)
        return await real()

    store.list = counting
    clock = Clock()
    source = DirectoryIdentifiers(store, refresh_s=5.0, clock=clock)
    first = await source.version()
    for _ in range(50):
        assert await source.version() == first
    assert len(lists) == 1  # fifty checks, one read
    await prov.set_identifier_patterns(OPS, beta.tenant_id, beta.version, [GOOD[0]])
    assert await source.version() == first  # inside the refresh: still the snapshot
    source.invalidate()
    second = await source.version()
    assert second != first and len(lists) == 2
    clock.now += 6
    assert await source.version() == second and len(lists) == 3  # re-read, nothing new
    assert (await source.patterns_by_tenant())[beta.tenant_id][1:] == (GOOD[0],)


async def test_concurrent_checks_share_one_read():
    import asyncio

    _, store, _, _ = await populated()
    reads = []
    real = store.list

    async def slow():
        reads.append(1)
        await asyncio.sleep(0.01)
        return await real()

    store.list = slow
    source = DirectoryIdentifiers(store)
    versions = await asyncio.gather(*(source.version() for _ in range(10)))
    assert len(set(versions)) == 1 and len(reads) == 1


async def test_a_list_that_fails_validation_on_read_is_left_out_and_the_others_are_kept():
    """A row written some way other than the operator path: the scan doesn't trust it."""
    _, store, _, beta = await populated()
    bad = TenantRecord("t_carelesss", "careless", "energy", identifier_patterns=("[0-9]",))
    event = DirectoryAuditEvent(bad.tenant_id, 1, "create", "x", 0.0, None, audit_fields(bad))
    await store.insert(bad, event)
    rejected = []
    source = DirectoryIdentifiers(store, on_rejected=rejected.append)
    got = await source.patterns_by_tenant()
    assert got[bad.tenant_id] == (tenant_id_pattern(bad.tenant_id),)  # its id, not its pattern
    assert got[beta.tenant_id][1:] == GOOD
    assert source.rejected_tenants == {bad.tenant_id} and rejected == [bad.tenant_id]
    source.invalidate()
    await source.version()
    assert rejected == [bad.tenant_id]  # reported once, not on every refresh


async def test_a_failed_hook_for_a_rejected_list_does_not_break_the_read():
    _, store, _, _ = await populated()
    bad = TenantRecord("t_carelesss", "careless", "energy", identifier_patterns=("[0-9]",))
    await store.insert(
        bad, DirectoryAuditEvent(bad.tenant_id, 1, "create", "x", 0.0, None, audit_fields(bad))
    )

    def boom(tenant_id):
        raise RuntimeError("pager down")

    assert await DirectoryIdentifiers(store, on_rejected=boom).version()


async def test_an_unreadable_directory_serves_the_snapshot_for_a_bounded_time_then_fails_closed():
    _, store, _, _ = await populated()
    clock = Clock()
    source = DirectoryIdentifiers(store, refresh_s=5.0, max_stale_s=60.0, clock=clock)
    first = await source.version()

    async def down():
        raise ConnectionError("directory unavailable")

    store.list = down
    clock.now += 6  # a refresh is due and fails
    assert await source.version() == first  # the snapshot goes on
    clock.now += 30
    assert await source.version() == first
    clock.now += 40  # now 76 s since the last good read
    with pytest.raises(ConnectionError):
        await source.version()


async def test_the_first_read_failing_fails_closed_at_once():
    store = InMemoryDirectoryStore()

    async def down():
        raise ConnectionError("directory unavailable")

    store.list = down
    with pytest.raises(ConnectionError):
        await DirectoryIdentifiers(store).version()


async def test_the_cached_directory_hands_out_one_source_and_its_change_event_marks_it():
    prov, store, _, beta = await populated()
    cached = CachedTenantDirectory(store)
    source = cached.other_tenant_identifiers()
    assert cached.other_tenant_identifiers() is source
    first = await source.version()
    record = await prov.set_identifier_patterns(OPS, beta.tenant_id, beta.version, [GOOD[0]])
    assert await source.version() == first  # inside the refresh
    from guardrail_engine.directory import TenantChanged

    cached.on_changed(TenantChanged(record.tenant_id, record.version, "update"))
    assert await source.version() != first


def test_the_options_are_checked():
    with pytest.raises(ValueError):
        DirectoryIdentifiers(InMemoryDirectoryStore(), refresh_s=-1)


# ------------------------------------------------------------------ the store contract


async def test_the_store_keeps_the_patterns_through_insert_replace_get_and_list(store):
    prov, _, _ = provisioner(store)
    record = await prov.create(OPS, slug="beta", domain="energy", identifier_patterns=GOOD)
    assert (await store.get(record.tenant_id)).identifier_patterns == GOOD
    assert [r.identifier_patterns for r in await store.list()] == [GOOD]
    await prov.update(OPS, record.tenant_id, 1, baa=True)  # another field leaves them alone
    assert (await store.get(record.tenant_id)).identifier_patterns == GOOD
    await prov.set_identifier_patterns(OPS, record.tenant_id, 2, [GOOD[1]])
    assert (await store.get(record.tenant_id)).identifier_patterns == (GOOD[1],)
    await prov.set_identifier_patterns(OPS, record.tenant_id, 3, [])
    assert (await store.get(record.tenant_id)).identifier_patterns == ()
    events = await store.audit_events(record.tenant_id)
    assert events[2].after["identifier_patterns"] == [GOOD[1]]


async def test_the_database_holds_the_shape_limits(pg):
    import asyncpg

    row = (
        "INSERT INTO tenants (tenant_id, slug, domain, tier, status, version, identifier_patterns)"
        " VALUES ('t_beta', 'beta', 'energy', 'standard', 'active', 1, $1)"
    )
    for bad in ([f"p{i}" for i in range(21)], [""], ["a", None]):
        with pytest.raises(asyncpg.CheckViolationError):
            await pg.pool.execute(row, bad)
    await pg.pool.execute(row, [f"BET-{i:02d}-[0-9]{{4}}" for i in range(20)])
    assert await pg.pool.fetchval("SELECT cardinality(identifier_patterns) FROM tenants") == 20


# ------------------------------------------------------------------
async def store_with_raw(patterns):
    """A directory store holding a tenant whose patterns got in some way other than the
    operator path (the record checks only their shape)."""
    prov, store, _ = provisioner()
    ok = await prov.create(OPS, slug="beta", domain="energy", identifier_patterns=GOOD)
    raw = TenantRecord("t_carelesss", "careless", "energy", identifier_patterns=tuple(patterns))
    await store.insert(
        raw, DirectoryAuditEvent(raw.tenant_id, 1, "create", "x", 0.0, None, audit_fields(raw))
    )
    return store, ok, raw


async def test_only_the_failing_patterns_of_a_tenant_are_dropped():
    """One careless pattern doesn't cost the tenant its good ones."""
    store, ok, raw = await store_with_raw([r"CAR-INV-[0-9]{4}", "[0-9]", r"CAR-ACC-[0-9]{6}"])
    rejected = []
    source = DirectoryIdentifiers(store, on_rejected=rejected.append)
    got = await source.patterns_by_tenant()
    assert got[raw.tenant_id] == (
        tenant_id_pattern(raw.tenant_id), r"CAR-INV-[0-9]{4}", r"CAR-ACC-[0-9]{6}",
    )  # fmt: skip
    assert got[ok.tenant_id][1:] == GOOD
    assert rejected == [raw.tenant_id] and source.rejected_tenants == {raw.tenant_id}


async def test_the_warning_names_the_tenant_and_never_the_pattern(caplog):
    import logging

    store, _, raw = await store_with_raw(["[0-9]", "account"])
    with caplog.at_level(logging.WARNING, logger="guardrail_engine.directory.identifiers"):
        await DirectoryIdentifiers(store).version()
    text = " ".join(r.getMessage() for r in caplog.records)
    assert raw.tenant_id in text and "2 registered identifier pattern" in text
    assert "[0-9]" not in text and "account" not in text


async def test_a_changed_set_of_bad_patterns_is_reported_again_but_the_same_one_is_not():
    store, _, raw = await store_with_raw(["[0-9]"])
    rejected = []
    source = DirectoryIdentifiers(store, on_rejected=rejected.append)
    await source.version()
    source.invalidate()
    await source.version()
    assert rejected == [raw.tenant_id]  # unchanged: once
    await store.replace(
        TenantRecord(
            raw.tenant_id, "careless", "energy", identifier_patterns=("[0-9]", "account"),
            version=2,
        ),
        1,
        DirectoryAuditEvent(raw.tenant_id, 2, "update", "x", 0.0, None, {}),
    )  # fmt: skip
    source.invalidate()
    await source.version()
    assert rejected == [raw.tenant_id, raw.tenant_id]


async def test_patterns_past_the_twentieth_good_one_are_left_out():
    many = [f"BET-{i:02d}-[0-9]{{4}}" for i in range(20)]
    _, store, _ = provisioner()
    raw = TenantRecord("t_carelesss", "careless", "energy", identifier_patterns=tuple(many))
    await store.insert(
        raw, DirectoryAuditEvent(raw.tenant_id, 1, "create", "x", 0.0, None, audit_fields(raw))
    )
    got = await DirectoryIdentifiers(store).patterns_by_tenant()
    assert len(got[raw.tenant_id]) == 21  # the id pattern and all 20


async def test_a_failing_read_is_retried_at_most_once_a_second_even_when_a_change_waits():
    """invalidate() marks the source dirty, and the store is down."""
    _, store, _, _ = await populated()
    clock = Clock()
    source = DirectoryIdentifiers(store, refresh_s=5.0, max_stale_s=60.0, clock=clock)
    await source.version()
    calls = []

    async def down():
        calls.append(1)
        raise ConnectionError("directory unavailable")

    store.list = down
    source.invalidate()
    for _ in range(20):
        await source.version()  # served from the snapshot
    assert len(calls) == 1  # not one read per check
    clock.now += 1.5
    await source.version()
    assert len(calls) == 2  # and again a second later
    clock.now += 70  # past max_stale_s since the last good read
    with pytest.raises(ConnectionError):
        await source.version()
