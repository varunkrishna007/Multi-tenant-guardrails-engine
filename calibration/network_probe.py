"""A zero-API-call network probe: does the provider's edge stall around the top of the minute?

    uv run python -m calibration.network_probe run --out calibration/results/X.jsonl
    uv run python -m calibration.network_probe analyse calibration/results/X.jsonl

M0-02: in two live R7.4 runs, calls stalled (the request written, no response head) in bursts
that began near :55-:05 of the wall-clock minute. This probe separates the network path from
the API. It only opens TCP and TLS connections to the API host and **sends no bytes after the
handshake**: no HTTP request, no key, no header, nothing the API could count as a call.

Every second (aligned to the UTC clock) it opens a **fresh** connection and records the TCP
connect and TLS handshake times, or how it failed (a timeout is a stall). It also holds a
**kept** connection, opened every :data:`HOLD_EVERY_S` seconds and never written to, and
records when the peer closes or resets it (and its age). TCP keep-alive probes (kernel ACKs
with no data: idle 5 s, every 1 s, 3 misses) are switched on for kept connections, so a connection
that a middlebox dropped silently also surfaces (as a reset or ``TimeoutError``) a few seconds
later. A kept connection cannot be *used* without sending bytes, so the idle arm is passive:
did it die, and at which age and second of the minute? Fresh connections are the active arm.
The probe stops by itself after ``--minutes``.

``analyse`` is offline and prints markdown: failures and slow handshakes by second of the minute,
and kept-connection closes by second of the minute.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import ssl
import statistics
import sys
import time
from collections import Counter
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

HOST = "generativelanguage.googleapis.com"
PORT = 443
TIMEOUT_S = 10.0
"""A handshake not done by then is a ``timeout`` (a stall)."""
SLOW_MS = 1000.0
"""A fresh connection that took longer than this (to connect and finish TLS) is slow."""
HOLD_EVERY_S = 7
"""A kept connection is opened this often. 7 is coprime with 60, so over a few minutes the
kept connections meet each minute boundary at every age, and an idle limit (a connection that
dies at a fixed age) can be told from a boundary (every connection dies at :00)."""
MAX_HELD = 12
"""Kept connections open at once (the oldest is closed by us, recorded as ``retired``): ages up
to 84 s, past the adapter's 60 s keep-alive."""
KEEPALIVE_IDLE_S = 5
KEEPALIVE_INTERVAL_S = 1
KEEPALIVE_COUNT = 3

NOTE = "TCP+TLS only: no bytes sent after the handshake, no API call"

Opener = Callable[[], Awaitable[tuple[Any, Any]]]
"""Opens a TCP+TLS connection and returns ``(reader, writer)`` (asyncio streams)."""


async def open_tls(host: str = HOST, port: int = PORT) -> tuple[Any, Any]:
    return await asyncio.open_connection(host, port, ssl=ssl.create_default_context())


def utc_iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, UTC).isoformat(timespec="milliseconds")


async def fresh_probe(
    opener: Opener, clock: Callable[[], float] = time.monotonic, timeout: float = TIMEOUT_S
) -> dict[str, Any]:
    """One fresh TCP+TLS connection, closed straight away. ``connect_ms`` is the whole
    TCP+TLS time (``asyncio.open_connection`` does both); a failure is the exception's class
    name only."""
    began = clock()
    try:
        _, writer = await asyncio.wait_for(opener(), timeout)
    except TimeoutError:
        return {"ok": False, "failure": "timeout", "total_ms": round((clock() - began) * 1e3)}
    except Exception as exc:
        return {"ok": False, "failure": type(exc).__name__,
                "total_ms": round((clock() - began) * 1e3)}  # fmt: skip
    took = round((clock() - began) * 1e3)
    with contextlib.suppress(Exception):
        writer.close()
    return {"ok": True, "total_ms": took}


def enable_keepalive(writer: Any) -> bool:
    """TCP keep-alive on the connection's socket (kernel probes, no application data)."""
    import socket

    sock = writer.get_extra_info("socket")
    if sock is None:
        return False
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, KEEPALIVE_IDLE_S)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, KEEPALIVE_INTERVAL_S)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, KEEPALIVE_COUNT)
    except (OSError, AttributeError):
        return False
    return True


@dataclass
class Held:
    opened_at: float
    reader: Any
    writer: Any
    task: asyncio.Task[str] | None = None
    closed: bool = False


async def _watch(reader: Any) -> str:
    """Returns how the peer ended the connection: ``eof`` (FIN) or the exception's class name
    (a reset, a TLS alert). Data the peer sends (a TLS session ticket) is ignored."""
    try:
        while await reader.read(4096):
            pass
    except Exception as exc:
        return type(exc).__name__
    return "eof"


@dataclass
class Probe:
    out: Path
    opener: Opener = open_tls
    wall_clock: Callable[[], float] = time.time
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep
    timer: Callable[[], float] = time.monotonic
    hold_every_s: int = HOLD_EVERY_S
    max_held: int = MAX_HELD
    held: list[Held] = field(default_factory=list)
    pending: set[asyncio.Task[None]] = field(default_factory=set)

    def write(self, record: Mapping[str, Any]) -> None:
        with self.out.open("a") as fh:
            fh.write(json.dumps(record, sort_keys=True) + "\n")

    async def fresh(self, at: float) -> None:
        result = await fresh_probe(self.opener, self.timer)
        self.write({"type": "fresh", "at": utc_iso(at), "second": round(at % 60, 3), **result})

    async def hold(self, at: float) -> None:
        try:
            reader, writer = await asyncio.wait_for(self.opener(), TIMEOUT_S)
        except Exception as exc:
            self.write({"type": "hold_failed", "at": utc_iso(at),
                        "failure": type(exc).__name__})  # fmt: skip
            return
        held = Held(opened_at=at, reader=reader, writer=writer)
        if not enable_keepalive(writer):
            self.write({"type": "keepalive_unavailable", "opened_at": utc_iso(at)})
        held.task = asyncio.create_task(_watch(reader))
        held.task.add_done_callback(lambda t, h=held: self._closed(h, t))
        self.held.append(held)
        if len(self.held) > self.max_held:
            self._retire(self.held[0])

    def _closed(self, held: Held, task: asyncio.Task[str]) -> None:
        if held.closed or task.cancelled():
            return
        held.closed = True
        now = self.wall_clock()
        self.write({"type": "held_closed", "opened_at": utc_iso(held.opened_at),
                    "closed_at": utc_iso(now), "second": round(now % 60, 3),
                    "age_s": round(now - held.opened_at, 3), "how": task.result()})  # fmt: skip
        if held in self.held:
            self.held.remove(held)

    def _retire(self, held: Held) -> None:
        held.closed = True
        if held.task is not None:
            held.task.cancel()
        with contextlib.suppress(Exception):
            held.writer.close()
        self.held.remove(held)
        self.write({"type": "held_retired", "opened_at": utc_iso(held.opened_at),
                    "age_s": round(self.wall_clock() - held.opened_at, 3)})  # fmt: skip

    def spawn(self, coro: Awaitable[None]) -> None:
        task = asyncio.ensure_future(coro)
        self.pending.add(task)
        task.add_done_callback(self.pending.discard)

    async def run(self, seconds: int) -> None:
        """``seconds`` ticks, each on a whole UTC second; a fresh probe every tick, a kept
        connection every ``hold_every_s`` seconds (first at the first tick)."""
        self.write({"type": "probe_started", "at": utc_iso(self.wall_clock()), "host": HOST,
                    "port": PORT, "seconds": seconds, "timeout_s": TIMEOUT_S,
                    "hold_every_s": self.hold_every_s,
                    "note": NOTE})  # fmt: skip
        tick = int(self.wall_clock()) + 1
        for n in range(seconds):
            if (wait := tick - self.wall_clock()) > 0:
                await self.sleep(wait)
            self.spawn(self.fresh(float(tick)))
            if n % self.hold_every_s == 0:
                self.spawn(self.hold(float(tick)))
            tick += 1
        await self.sleep(TIMEOUT_S + 1)  # let the last probes finish
        if self.pending:
            await asyncio.gather(*self.pending, return_exceptions=True)
        for held in list(self.held):
            self._retire(held)
        self.write({"type": "probe_finished", "at": utc_iso(self.wall_clock())})


def _read(path: Path) -> list[dict[str, Any]]:
    return [json.loads(x) for x in path.read_text().splitlines() if x.strip()]


BUCKETS = ((0, 10), (10, 20), (20, 30), (30, 40), (40, 50), (50, 55), (55, 60))


def bucket_of(second: float) -> tuple[int, int]:
    return next(b for b in BUCKETS if b[0] <= second % 60 < b[1])


def summarise(records: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    fresh = [r for r in records if r.get("type") == "fresh"]
    closed = [r for r in records if r.get("type") == "held_closed"]
    rows: dict[tuple[int, int], dict[str, Any]] = {}
    for b in BUCKETS:
        mine = [r for r in fresh if bucket_of(r["second"]) == b]
        ok = [r for r in mine if r["ok"]]
        rows[b] = {
            "probes": len(mine), "failed": len(mine) - len(ok),
            "slow": sum(r["total_ms"] > SLOW_MS for r in ok),
            "median_ms": statistics.median(r["total_ms"] for r in ok) if ok else None,
            "max_ms": max((r["total_ms"] for r in mine), default=None),
            "held_closed": sum(bucket_of(r["second"]) == b for r in closed),
        }  # fmt: skip
    return {
        "fresh": len(fresh), "failed": sum(not r["ok"] for r in fresh),
        "failures": dict(Counter(r["failure"] for r in fresh if not r["ok"])),
        "held_opened": sum(r.get("type") == "held_retired" or r.get("type") == "held_closed"
                           for r in records),
        "held_closed": [(r["second"], r["age_s"], r["how"]) for r in closed],
        "buckets": rows,
    }  # fmt: skip


def render(records: Sequence[Mapping[str, Any]]) -> str:
    s = summarise(records)
    lines = [
        "### Fresh TCP+TLS connections, one per second",
        "",
        f"- {s['fresh']} probes, {s['failed']} failed {s['failures'] or ''}; slow = over "
        f"{SLOW_MS:.0f} ms.",
        "",
        "| Second of the minute | Probes | Failed | Slow | Median ms | Max ms | Kept closed |",
        "|---|--:|--:|--:|--:|--:|--:|",
    ]
    for (lo, hi), r in s["buckets"].items():
        lines.append(
            f"| :{lo:02d}-:{hi - 1:02d} | {r['probes']} | {r['failed']} | {r['slow']} | "
            f"{r['median_ms'] if r['median_ms'] is not None else '-'} | "
            f"{r['max_ms'] if r['max_ms'] is not None else '-'} | {r['held_closed']} |"
        )
    lines += ["", "### Kept connections closed by the peer", ""]
    if s["held_closed"]:
        lines += ["| Second | Age (s) | How |", "|--:|--:|---|"]
        lines += [f"| {sec} | {age} | {how} |" for sec, age, how in s["held_closed"]]
    else:
        lines.append("None closed by the peer (a silent drop would not show here).")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run")
    run.add_argument("--out", required=True)
    run.add_argument("--minutes", type=float, default=5.75,
                     help="how long to probe (5.75 min crosses 5 minute boundaries)")  # fmt: skip
    ana = sub.add_parser("analyse")
    ana.add_argument("path")
    args = parser.parse_args(argv)
    if args.command == "analyse":
        print(render(_read(Path(args.path))))
        return 0
    out = Path(args.out)
    if out.exists():
        print("start a new --out file", file=sys.stderr)
        return 2
    out.parent.mkdir(parents=True, exist_ok=True)
    asyncio.run(Probe(out=out).run(int(args.minutes * 60)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
