"""The network probe, offline: fake connections, a fake clock and a fake sleep. Nothing is sent."""

import asyncio
import json

import pytest
from calibration.network_probe import Probe, fresh_probe, render, summarise

from calibration import network_probe as np_

MINUTE = 1_700_000_040  # a whole minute (divisible by 60)


class FakeReader:
    def __init__(self, ends_with=b"", after: asyncio.Event | None = None):
        self.event = after or asyncio.Event()
        self.ends_with = ends_with

    async def read(self, n):
        await self.event.wait()
        if isinstance(self.ends_with, Exception):
            raise self.ends_with
        return b""


class FakeWriter:
    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True

    def get_extra_info(self, name):
        return None


class World:
    """A fake clock whose sleeps move it; connections open at once unless told otherwise."""

    def __init__(self, start=MINUTE + 50.25):
        self.now = start
        self.readers: list[FakeReader] = []
        self.writers: list[FakeWriter] = []
        self.fail_call: int | None = None  # the nth connection attempt fails
        self.reset_at: float | None = None  # every open connection is reset by the peer then
        self.opened = 0

    async def sleep(self, seconds):
        self.now += seconds
        if self.reset_at is not None and self.now >= self.reset_at and self.readers:
            self.reset_at = None
            for reader in self.readers:  # only the kept connection is being read
                reader.ends_with = ConnectionResetError()
                reader.event.set()
        await asyncio.sleep(0)

    async def opener(self):
        self.opened += 1
        if self.opened == self.fail_call:
            raise ConnectionResetError
        reader, writer = FakeReader(), FakeWriter()
        self.readers.append(reader)
        self.writers.append(writer)
        return reader, writer


def probe(tmp_path, world, **kw):
    return Probe(out=tmp_path / "p.jsonl", opener=world.opener, wall_clock=lambda: world.now,
                 sleep=world.sleep, timer=lambda: world.now, **kw)  # fmt: skip


def records(tmp_path):
    return [json.loads(x) for x in (tmp_path / "p.jsonl").read_text().splitlines()]


async def test_fresh_probe_records_a_success_a_failure_name_and_a_timeout():
    async def ok():
        return FakeReader(), FakeWriter()

    async def reset():
        raise ConnectionResetError("secret detail")

    async def hang():
        await asyncio.sleep(60)

    assert (await fresh_probe(ok))["ok"] is True
    failed = await fresh_probe(reset)
    assert failed["failure"] == "ConnectionResetError" and "secret" not in json.dumps(failed)
    assert (await fresh_probe(hang, timeout=0.01))["failure"] == "timeout"


async def test_run_probes_once_per_whole_second_and_holds_every_seventh(tmp_path):
    world = World()
    await probe(tmp_path, world, hold_every_s=7).run(20)
    recs = records(tmp_path)
    fresh = [r for r in recs if r["type"] == "fresh"]
    assert len(fresh) == 20 and all(r["ok"] for r in fresh)
    seconds = [r["second"] for r in fresh]
    assert seconds[0] == pytest.approx(51.0) and seconds[9] == pytest.approx(0.0)  # crosses :00
    assert [r["type"] for r in recs].count("held_retired") == 3  # ticks 0, 7, 14, all retired
    assert recs[0]["type"] == "probe_started" and "no API call" in recs[0]["note"]
    assert recs[-1]["type"] == "probe_finished"
    assert all(w.closed for w in world.writers)  # nothing left open


async def test_a_failed_fresh_probe_is_recorded_by_exception_name(tmp_path):
    world = World()
    world.fail_call = 5  # calls: fresh0, hold0, fresh1, fresh2, fresh3 (the fifth)
    await probe(tmp_path, world, hold_every_s=1000).run(10)
    failed = [r for r in records(tmp_path) if r["type"] == "fresh" and not r["ok"]]
    assert [r["failure"] for r in failed] == ["ConnectionResetError"]
    assert failed[0]["second"] == pytest.approx(54.0)


async def test_a_kept_connection_closed_by_the_peer_is_recorded_with_age_and_second(tmp_path):
    world = World()  # the first tick is :51 and the kept connection opens then
    world.reset_at = MINUTE + 60.5  # the peer resets it just after the minute turns
    await probe(tmp_path, world, hold_every_s=1000).run(12)
    closed = [r for r in records(tmp_path) if r["type"] == "held_closed"]
    assert len(closed) == 1 and closed[0]["how"] == "ConnectionResetError"
    # noticed within a tick or two of the reset (the fake clock moves between loop turns)
    assert 1.0 <= closed[0]["second"] <= 3.0 and 10.0 <= closed[0]["age_s"] <= 12.0
    assert not any(r["type"] == "held_retired" for r in records(tmp_path))


def test_summary_and_render_bucket_by_second_of_the_minute():
    recs = [{"type": "fresh", "second": 57.0, "ok": True, "total_ms": 90},
            {"type": "fresh", "second": 58.0, "ok": False, "failure": "timeout", "total_ms": 10000},
            {"type": "fresh", "second": 3.0, "ok": True, "total_ms": 2500},
            {"type": "fresh", "second": 3.0, "ok": True, "total_ms": 80},
            {"type": "fresh", "second": 30.0, "ok": True, "total_ms": 70},
            {"type": "held_closed", "second": 0.4, "age_s": 21.0, "how": "eof"}]  # fmt: skip
    s = summarise(recs)
    assert s["fresh"] == 5 and s["failed"] == 1 and s["failures"] == {"timeout": 1}
    top = s["buckets"][(55, 60)]
    assert top["probes"] == 2 and top["failed"] == 1 and top["max_ms"] == 10000
    early = s["buckets"][(0, 10)]
    assert early["slow"] == 1 and early["held_closed"] == 1 and early["median_ms"] == 1290
    assert s["buckets"][(30, 40)]["failed"] == 0
    text = render(recs)
    assert "| :55-:59 | 2 | 1 |" in text and "21.0 | eof" in text


def test_cli_refuses_an_existing_out_file(tmp_path, capsys):
    out = tmp_path / "p.jsonl"
    out.write_text("")
    assert np_.main(["run", "--out", str(out)]) == 2
    assert "new --out" in capsys.readouterr().err


def test_the_probe_module_writes_no_bytes_to_the_connection():
    import inspect

    src = inspect.getsource(np_)
    assert ".write(" not in src.replace("self.write(", "").replace("fh.write(", "")
    assert "drain" not in src
