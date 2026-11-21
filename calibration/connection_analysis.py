"""Do the failures of a calibration run line up with new connections, or with connection age?

    uv run python -m calibration.connection_analysis calibration/results/X.jsonl

Offline: reads a results file written by ``calibration.engine_path`` since the connection
diagnostics (M0-02, after the R7.4 run's bursts of timeouts) and prints markdown tables. It
sends nothing. Each check's record carries ``connections``: one entry per provider call, from
the adapter's connection hook (``CallInfo.diagnostics``).

A **bad call** is a provider call that did not end in a response: ``timeout``, ``cancelled``
(the gateway's deadline), ``transport_error``, ``request_error`` or ``error``. A **failed
check** is one whose calls were all bad (the gateway makes one retry). The tables:

* the first call of each check, by whether its connection was new or reused;
* calls on a reused connection by the connection's (estimated) age, and every call by the
  idle gap before it, to test a pool recycling or a keep-alive expiry near 60 s;
* whether a bad call follows a bad call (a cascade: a cancelled call closes its connection);
* connect and first-byte timings, how bad calls failed, and the burst timeline.

The connection age is the adapter's **estimate** (the time since the most recently opened
connection became usable); it is exact when calls run one at a time.
"""

from __future__ import annotations

import argparse
import itertools
import statistics
import sys
from collections.abc import Mapping, Sequence
from datetime import datetime
from pathlib import Path
from typing import Any

from calibration.run import _read

GOOD_END = "response"
AGE_BUCKETS = ((0, 10), (10, 30), (30, 55), (55, 65), (65, float("inf")))
"""Seconds of connection age. The 55 to 65 bucket straddles the adapter's 60 s keep-alive."""
IDLE_BUCKETS = ((0, 0.5), (0.5, 2), (2, 10), (10, float("inf")))
"""Seconds since the previous call ended."""


def provider_calls(records: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Every provider call in the records, in the order made, with its check's context."""
    out: list[dict[str, Any]] = []
    index = 0
    for r in records:
        if r.get("type") != "call":
            continue
        index += 1
        conns = r.get("connections") or []
        for position, c in enumerate(conns, start=1):
            out.append({
                **c,
                "check": index, "example_id": r["example_id"], "draw": r["draw"],
                "attempt": r["attempt"], "call_in_check": position,
                "check_outcome": r["outcome"], "check_started_at": r["started_at"],
                "bad": c.get("ended") != GOOD_END,
            })  # fmt: skip
    return sorted(out, key=lambda c: (c.get("seq") is None, c.get("seq") or 0))


def rate(k: int, n: int) -> str:
    return "-" if n == 0 else f"{k}/{n} ({k / n:.0%})"


def pct(values: Sequence[float], p: float) -> float:
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, round(p * (len(ordered) - 1)))]


def stats(values: Sequence[float]) -> str:
    if not values:
        return "-"
    return (f"n {len(values)}, median {statistics.median(values):,.0f} ms, "
            f"p95 {pct(values, 0.95):,.0f}, max {max(values):,.0f}")  # fmt: skip


def bucket_rows(
    calls: Sequence[Mapping[str, Any]], key: str, buckets: Sequence[tuple[float, float]], unit: str
) -> list[tuple[str, int, int]]:
    rows = []
    for lo, hi in buckets:
        label = f"{lo:g}-{hi:g} {unit}" if hi != float("inf") else f"{lo:g}+ {unit}"
        inside = [c for c in calls if c.get(key) is not None and lo <= c[key] < hi]
        rows.append((label, len(inside), sum(c["bad"] for c in inside)))
    unknown = [c for c in calls if c.get(key) is None]
    rows.append(("unknown", len(unknown), sum(c["bad"] for c in unknown)))
    return rows


def first_call_by_connection(calls: Sequence[Mapping[str, Any]]) -> list[tuple[str, int, int, int]]:
    """For each check's first call: (state, calls, bad first calls, checks that failed)."""
    firsts = [c for c in calls if c["call_in_check"] == 1]
    rows = []
    for state in ("new", "reused", "unknown"):
        group = [c for c in firsts if (c.get("connection") or "unknown") == state]
        rows.append((state, len(group), sum(c["bad"] for c in group),
                     sum(c["check_outcome"] == "failed" for c in group)))  # fmt: skip
    return rows


def cascade(calls: Sequence[Mapping[str, Any]]) -> tuple[tuple[int, int], tuple[int, int]]:
    """((bad, calls) after a bad call, (bad, calls) after a good one), over calls in order."""
    after_bad = [b["bad"] for a, b in itertools.pairwise(calls) if a["bad"]]
    after_good = [b["bad"] for a, b in itertools.pairwise(calls) if not a["bad"]]
    return (sum(after_bad), len(after_bad)), (sum(after_good), len(after_good))


def bursts(records: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Runs of consecutive failed checks: when each began (seconds since the first check),
    how long it was, and the connection state of its first bad call."""
    calls = [r for r in records if r.get("type") == "call"]
    if not calls:
        return []
    t0 = datetime.fromisoformat(calls[0]["started_at"])
    out: list[dict[str, Any]] = []
    run: list[tuple[int, Mapping[str, Any]]] = []
    for i, r in enumerate(calls, start=1):
        if r["outcome"] == "failed":
            run.append((i, r))
        elif run:
            out.append(burst_of(run, t0))
            run = []
    if run:
        out.append(burst_of(run, t0))
    return out


def burst_of(run: Sequence[tuple[int, Mapping[str, Any]]], t0: datetime) -> dict[str, Any]:
    first_index, first = run[0]
    conn = (first.get("connections") or [{}])[0]
    return {
        "first_check": first_index, "length": len(run),
        "at_s": (datetime.fromisoformat(first["started_at"]) - t0).total_seconds(),
        "connection": conn.get("connection"), "age_s": conn.get("connection_age_s"),
        "idle_s": conn.get("idle_s"),
    }  # fmt: skip


def second_of_minute(timestamp: str) -> float:
    moment = datetime.fromisoformat(timestamp)
    return moment.second + moment.microsecond / 1e6


def by_second_of_minute(records: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Checks and failed checks by the second of the clock minute they started in (10 s
    buckets), and the window of 15 s around the top of the minute (:55 to :09) against the
    rest. Needs only each check's start time and outcome, so it works on any engine-path run."""
    checks = [r for r in records if r.get("type") == "call"]
    buckets = []
    for lo in range(0, 60, 10):
        inside = [r for r in checks if lo <= second_of_minute(r["started_at"]) < lo + 10]
        buckets.append((f":{lo:02d}-:{lo + 9:02d}", len(inside),
                        sum(r["outcome"] == "failed" for r in inside)))  # fmt: skip

    def top(r: Mapping[str, Any]) -> bool:
        return (sec := second_of_minute(r["started_at"])) >= 55 or sec < 10

    near = [r for r in checks if top(r)]
    rest = [r for r in checks if not top(r)]
    return {
        "buckets": buckets,
        "top_of_minute": (len(near), sum(r["outcome"] == "failed" for r in near)),
        "elsewhere": (len(rest), sum(r["outcome"] == "failed" for r in rest)),
    }


def onsets(calls: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """The start of each stall: a bad call whose previous call was good, with its connection's
    state and age and the second of the minute. A stall that begins on a reused, young
    connection with no idle gap is not about connection age or a stale connection."""
    out = []
    for previous, c in itertools.pairwise(calls):
        if c["bad"] and not previous["bad"]:
            started = c.get("started_at") or c.get("check_started_at")
            out.append({
                "seq": c.get("seq"), "check": c["check"], "check_outcome": c["check_outcome"],
                "clock": (started or "")[11:19],
                "second_of_minute": second_of_minute(started) if started else None,
                "connection": c.get("connection"), "age_s": c.get("connection_age_s"),
                "idle_s": c.get("idle_s"),
            })  # fmt: skip
    return out


def new_connection_causality(calls: Sequence[Mapping[str, Any]]) -> dict[str, tuple[int, int]]:
    """New-connection calls by whether the call before them was good or bad: (calls, bad).
    A cancelled call closes its connection, so a new one right after it is a consequence of the
    stall, not its cause."""
    after: dict[str, list[Mapping[str, Any]]] = {"after a good call": [], "after a bad call": []}
    for previous, c in itertools.pairwise(calls):
        if c.get("connection") == "new":
            after["after a bad call" if previous["bad"] else "after a good call"].append(c)
    return {k: (len(v), sum(c["bad"] for c in v)) for k, v in after.items()}


def deadline_accuracy(calls: Sequence[Mapping[str, Any]]) -> dict[int, list[float]]:
    """How long calls the gateway cancelled had run, by position in the check: a first call
    cancelled at its attempt deadline to within a few milliseconds, every time, means this
    process's timers fired on time, so its event loop was not blocked."""
    out: dict[int, list[float]] = {}
    for c in calls:
        if c.get("ended") == "cancelled" and c.get("total_ms") is not None:
            out.setdefault(c["call_in_check"], []).append(c["total_ms"])
    return out


def summarise(records: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    calls = provider_calls(records)
    checks = [r for r in records if r.get("type") == "call"]
    new = [c for c in calls if c.get("connection") == "new"]
    reused = [c for c in calls if c.get("connection") == "reused"]
    good = [c for c in calls if not c["bad"]]
    bad = [c for c in calls if c["bad"]]
    return {
        "checks": len(checks),
        "failed_checks": sum(r["outcome"] == "failed" for r in checks),
        "checks_without_diagnostics": sum(not r.get("connections") for r in checks),
        "provider_calls": len(calls),
        "bad_calls": len(bad),
        "ended": _count(c.get("ended") for c in calls),
        "failure_events": _count(c.get("failure") for c in bad),
        "http_versions": _count(c.get("http_version") for c in calls),
        "server_closes": sum(bool(c.get("server_closes")) for c in calls),
        "first_call_by_connection": first_call_by_connection(calls),
        "calls_by_connection": [
            ("new", len(new), sum(c["bad"] for c in new)),
            ("reused", len(reused), sum(c["bad"] for c in reused)),
        ],
        "age_buckets": bucket_rows(reused, "connection_age_s", AGE_BUCKETS, "s"),
        "idle_buckets": bucket_rows(calls, "idle_s", IDLE_BUCKETS, "s"),
        "cascade": cascade(calls),
        "connect_ms": {
            "good": [
                c["connect_ms"] for c in new if not c["bad"] and c.get("connect_ms") is not None
            ],
            "bad": [c["connect_ms"] for c in new if c["bad"] and c.get("connect_ms") is not None],
        },
        "tls_ms": [c["tls_ms"] for c in new if c.get("tls_ms") is not None],
        "to_send_ms": {
            "new": [c["to_send_ms"] for c in new if c.get("to_send_ms") is not None],
            "reused": [c["to_send_ms"] for c in reused if c.get("to_send_ms") is not None],
        },
        "ttfb_ms": {
            "answered": [c["ttfb_ms"] for c in good if c.get("ttfb_ms") is not None],
            "bad_with_response_head": [c["ttfb_ms"] for c in bad if c.get("ttfb_ms") is not None],
            "bad_without": sum(c.get("ttfb_ms") is None for c in bad),
        },
        "bursts": bursts(records),
        "clock": by_second_of_minute(records),
        "onsets": onsets(calls),
        "new_connection_causality": new_connection_causality(calls),
        "deadline_accuracy": deadline_accuracy(calls),
        "send_ms_of_bad_calls": [c["send_ms"] for c in bad if c.get("send_ms") is not None],
    }


def _count(values: Any) -> dict[str, int]:
    out: dict[str, int] = {}
    for v in values:
        out[str(v)] = out.get(str(v), 0) + 1
    return dict(sorted(out.items(), key=lambda kv: -kv[1]))


def render(summary: Mapping[str, Any]) -> str:
    s = summary
    out: list[str] = []
    w = out.append
    w("### Overview\n")
    w(f"- {s['checks']} checks, {s['failed_checks']} failed (every call bad); "
      f"{s['provider_calls']} provider calls, {s['bad_calls']} bad; "
      f"{s['checks_without_diagnostics']} checks without diagnostics.")  # fmt: skip
    w(f"- How calls ended: {s['ended']}. HTTP versions: {s['http_versions']}. "
      f"Responses with `Connection: close`: {s['server_closes']}.")  # fmt: skip
    w("\n### First call of each check, by its connection\n")
    w("| Connection | First calls | First call bad | Check failed |\n|---|--:|--:|--:|")
    for state, n, bad, failed in s["first_call_by_connection"]:
        w(f"| {state} | {n} | {rate(bad, n)} | {rate(failed, n)} |")
    w("\n### Every call, by connection\n")
    w("| Connection | Calls | Bad |\n|---|--:|--:|")
    for state, n, bad in s["calls_by_connection"]:
        w(f"| {state} | {n} | {rate(bad, n)} |")
    w("\n### Calls on a reused connection, by its (estimated) age\n")
    w("| Age | Calls | Bad |\n|---|--:|--:|")
    for label, n, bad in s["age_buckets"]:
        w(f"| {label} | {n} | {rate(bad, n)} |")
    w("\n### Every call, by the idle gap before it\n")
    w("| Idle | Calls | Bad |\n|---|--:|--:|")
    for label, n, bad in s["idle_buckets"]:
        w(f"| {label} | {n} | {rate(bad, n)} |")
    (kb, nb), (kg, ng) = s["cascade"]
    w("\n### Does a bad call follow a bad call?\n")
    w(f"- After a bad call: {rate(kb, nb)} bad. After a good call: {rate(kg, ng)} bad.")
    w("\n### Does a new connection cause a failure?\n")
    for label, (n, bad) in s["new_connection_causality"].items():
        w(f"- New-connection calls {label}: {n}, bad {rate(bad, n)}.")
    w("\n### Failures by the second of the clock minute\n")
    w("| Seconds | Checks started | Failed |\n|---|--:|--:|")
    for label, n, failed in s["clock"]["buckets"]:
        w(f"| {label} | {n} | {rate(failed, n)} |")
    (tn, tf), (en, ef) = s["clock"]["top_of_minute"], s["clock"]["elsewhere"]
    w(f"\nChecks starting between :55 and :09: {rate(tf, tn)} failed. Elsewhere in the minute: "
      f"{rate(ef, en)} failed.")  # fmt: skip
    w("\n### Where each stall began\n")
    if s["onsets"]:
        w("| Call | Clock (UTC) | Second | Connection | Age (s) | Idle (s) | Its check |")
        w("|--:|---|--:|---|--:|--:|---|")
        for o in s["onsets"]:
            sec = "-" if o["second_of_minute"] is None else f"{o['second_of_minute']:.1f}"
            w(f"| {o['seq']} | {o['clock']} | {sec} | {o['connection']} | {o['age_s']} "
              f"| {o['idle_s']} | {o['check']} ({o['check_outcome']}) |")  # fmt: skip
        on_reused = sum(o["connection"] == "reused" for o in s["onsets"])
        w(f"\n{len(s['onsets'])} onsets, {on_reused} on a reused connection.")
    else:
        w("none")
    w("\n### Did this process's timers fire on time?\n")
    for position, values in sorted(s["deadline_accuracy"].items()):
        w(f"- Cancelled call {position} of a check, run time: {stats(values)}")
    w(f"- Bad calls, time to write the request: {stats(s['send_ms_of_bad_calls'])}")
    w("\n### Timings\n")
    w(f"- TCP connect, new connections that answered: {stats(s['connect_ms']['good'])}")
    w(f"- TCP connect, new connections that went bad: {stats(s['connect_ms']['bad'])}")
    w(f"- TLS handshake: {stats(s['tls_ms'])}")
    w(f"- Call start to first request byte, new connection: {stats(s['to_send_ms']['new'])}")
    w(f"- Call start to first request byte, reused connection: {stats(s['to_send_ms']['reused'])}")
    answered = stats(s["ttfb_ms"]["answered"])
    w(f"- Provider time (request written to response head), answered calls: {answered}")
    w(f"- Bad calls that got a response head: {stats(s['ttfb_ms']['bad_with_response_head'])}; "
      f"bad calls with none: {s['ttfb_ms']['bad_without']}")  # fmt: skip
    w(f"\n### How bad calls failed\n\n{s['failure_events'] or 'none'}")
    w("\n### Bursts of consecutive failed checks\n")
    if s["bursts"]:
        w("| First check | Length | Seconds in | Connection of its first call "
          "| Age (s) | Idle (s) |")  # fmt: skip
        w("|--:|--:|--:|---|--:|--:|")
        for b in s["bursts"]:
            w(f"| {b['first_check']} | {b['length']} | {b['at_s']:.0f} | {b['connection']} "
              f"| {b['age_s']} | {b['idle_s']} |")  # fmt: skip
        starts = [b["at_s"] for b in s["bursts"]]
        gaps = [round(b - a) for a, b in itertools.pairwise(starts)]
        w(f"\nGaps between burst starts (seconds): {gaps}")
    else:
        w("none")
    return "\n".join(out)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("input")
    args = parser.parse_args(argv)
    print(render(summarise(_read(Path(args.input)))))
    return 0


if __name__ == "__main__":
    sys.exit(main())
