"""The connection analysis (M0-02): do failures line up with new connections or with
connection age? Offline, on a synthetic run whose answers are worked out by hand."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

from calibration.connection_analysis import (
    bursts,
    by_second_of_minute,
    cascade,
    deadline_accuracy,
    main,
    new_connection_causality,
    onsets,
    provider_calls,
    rate,
    render,
    summarise,
)

T0 = datetime(2026, 11, 17, 14, 0, 0, tzinfo=UTC)
CANCEL = "http11.receive_response_headers.failed:CancelledError"
TIMEOUT = "http11.receive_response_headers.failed:ReadTimeout"


def call(seq, connection, ended, age=None, idle=None, **extra):
    """One provider call's diagnostics, as ``CallInfo.diagnostics`` gives them."""
    out = {"seq": seq, "connection": connection, "ended": ended, "total_ms": 500.0}
    if ended == "response":
        out["ttfb_ms"] = 450.0
        out["http_version"] = "HTTP/1.1"
    if ended == "cancelled":
        out["failure"] = CANCEL
    if ended == "timeout":
        out["failure"] = TIMEOUT
    if connection == "new":
        out["connect_ms"] = 80.0
    if age is not None:
        out["connection_age_s"] = age
    if idle is not None:
        out["idle_s"] = idle
    return {**out, **extra}


def check(i, outcome, *connections, seconds=None):
    when = T0 + timedelta(seconds=i - 1 if seconds is None else seconds)
    return {"type": "call", "example_id": f"ex-{i}", "draw": 1, "attempt": 1, "outcome": outcome,
            "started_at": when.isoformat(), "connections": list(connections)}  # fmt: skip


def run():
    """Eight checks. 1-3 are fine. Check 4's first call goes out on a connection aged 58 s and
    is cancelled; the next calls each open a new connection and go bad too (a cascade: checks
    4 and 5 fail). Check 6 is rescued by its retry. Checks 7 and 8 are fine."""
    return [
        {"type": "run_started", "draws": 1},
        check(1, "answered", call(1, "new", "response", age=0.05)),
        check(2, "answered", call(2, "reused", "response", age=1.0, idle=0.4)),
        check(3, "answered", call(3, "reused", "response", age=2.0, idle=0.4)),
        check(
            4,
            "failed",
            call(4, "reused", "cancelled", age=58.0, idle=0.4),
            call(5, "new", "timeout", age=0.1, idle=0.0, connect_ms=100.0),
        ),
        check(
            5,
            "failed",
            call(6, "new", "timeout", age=0.1, idle=0.0, connect_ms=120.0),
            call(7, "new", "cancelled", age=0.1, idle=0.0, connect_ms=None),
        ),
        check(
            6,
            "answered",
            call(8, "new", "timeout", age=0.1, idle=0.0, connect_ms=110.0),
            call(9, "new", "response", age=0.1, idle=0.0, connect_ms=60.0),
        ),
        check(7, "answered", call(10, "reused", "response", age=1.0, idle=0.3)),
        check(8, "answered", call(11, "reused", "response", age=2.0, idle=0.3)),
    ]


def test_provider_calls_are_flattened_in_order_with_their_checks_context():
    calls = provider_calls(run())
    assert [c["seq"] for c in calls] == list(range(1, 12))
    four = calls[3]
    assert (four["check"], four["call_in_check"], four["check_outcome"]) == (4, 1, "failed")
    assert four["bad"] is True and calls[0]["bad"] is False
    rescued = calls[8]
    assert (rescued["check"], rescued["call_in_check"], rescued["check_outcome"]) == (
        6,
        2,
        "answered",
    )


def test_the_overview_counts():
    s = summarise(run())
    assert (s["checks"], s["failed_checks"], s["checks_without_diagnostics"]) == (8, 2, 0)
    assert (s["provider_calls"], s["bad_calls"]) == (11, 5)
    assert s["ended"] == {"response": 6, "timeout": 3, "cancelled": 2}
    assert s["failure_events"] == {TIMEOUT: 3, CANCEL: 2}
    assert s["http_versions"] == {"HTTP/1.1": 6, "None": 5} and s["server_closes"] == 0


def test_first_calls_split_by_connection():
    rows = {
        state: (n, bad, failed)
        for state, n, bad, failed in summarise(run())["first_call_by_connection"]
    }
    # New: checks 1, 5 and 6 (two bad first calls, one failed check). Reused: 2, 3, 4, 7, 8.
    assert rows == {"new": (3, 2, 1), "reused": (5, 1, 1), "unknown": (0, 0, 0)}
    assert dict((state, (n, bad)) for state, n, bad in summarise(run())["calls_by_connection"]) == {
        "new": (6, 4), "reused": (5, 1),
    }  # fmt: skip


def test_age_and_idle_buckets():
    s = summarise(run())
    ages = {label: (n, bad) for label, n, bad in s["age_buckets"]}
    assert ages["0-10 s"] == (4, 0) and ages["55-65 s"] == (1, 1)  # the one failure at age 58
    assert ages["10-30 s"] == (0, 0) and ages["30-55 s"] == (0, 0) and ages["65+ s"] == (0, 0)
    assert ages["unknown"] == (0, 0)  # the age buckets cover reused connections only
    idles = {label: (n, bad) for label, n, bad in s["idle_buckets"]}
    assert idles["0-0.5 s"] == (10, 5) and idles["unknown"] == (1, 0)  # the first call has no idle


def test_a_bad_call_follows_a_bad_call_more_than_a_good_one():
    (kb, nb), (kg, ng) = cascade(provider_calls(run()))
    assert (kb, nb) == (4, 5) and (kg, ng) == (1, 5)
    assert rate(kb, nb) == "4/5 (80%)" and rate(0, 0) == "-"


def test_timings_split_good_from_bad_connections():
    s = summarise(run())
    assert sorted(s["connect_ms"]["good"]) == [60.0, 80.0]
    assert sorted(s["connect_ms"]["bad"]) == [100.0, 110.0, 120.0]  # check 5's second had none
    assert len(s["ttfb_ms"]["answered"]) == 6 and s["ttfb_ms"]["bad_with_response_head"] == []
    assert s["ttfb_ms"]["bad_without"] == 5


def test_a_burst_is_a_run_of_failed_checks_with_its_first_calls_connection():
    [burst] = bursts(run())
    assert (burst["first_check"], burst["length"], burst["at_s"]) == (4, 2, 3.0)
    assert (burst["connection"], burst["age_s"], burst["idle_s"]) == ("reused", 58.0, 0.4)
    assert bursts([check(1, "answered", call(1, "new", "response"))]) == []
    assert bursts([{"type": "run_started"}]) == []


def test_checks_without_diagnostics_are_counted_not_guessed():
    records = [*run(), check(9, "answered")]  # a fake-model check: no connections
    s = summarise(records)
    assert s["checks"] == 9 and s["checks_without_diagnostics"] == 1
    assert s["provider_calls"] == 11  # unchanged: nothing is invented for it


def test_the_report_names_each_table_and_the_cascade(tmp_path, capsys):
    text = render(summarise(run()))
    headings = (
        "### Overview",
        "### First call of each check, by its connection",
        "### Calls on a reused connection, by its (estimated) age",
        "### Does a bad call follow a bad call?",
        "### Bursts of consecutive failed checks",
    )
    for heading in headings:
        assert heading in text
    assert "After a bad call: 4/5 (80%) bad. After a good call: 1/5 (20%) bad." in text
    assert "| 4 | 2 | 3 | reused | 58.0 | 0.4 |" in text
    path = tmp_path / "r.jsonl"
    path.write_text("".join(json.dumps(r) + "\n" for r in run()))
    assert main([str(path)]) == 0
    assert "### Overview" in capsys.readouterr().out


def test_failures_are_counted_by_the_second_of_the_minute_they_started_in():
    """The synthetic checks start at :00 to :07 of the minute; checks 4 and 5 failed."""
    clock = by_second_of_minute(run())
    assert clock["buckets"][0] == (":00-:09", 8, 2)
    assert all(n == 0 for _, n, _ in clock["buckets"][1:])
    assert clock["top_of_minute"] == (8, 2) and clock["elsewhere"] == (0, 0)
    # A check starting in the middle of the minute is not in the top-of-minute window.
    mid = [check(1, "failed", call(1, "new", "cancelled"), seconds=30),
           check(2, "answered", call(2, "reused", "response"), seconds=56)]  # fmt: skip
    clock = by_second_of_minute(mid)
    assert clock["top_of_minute"] == (1, 0) and clock["elsewhere"] == (1, 1)  # :56 is in, :30 out


def test_a_stall_begins_at_a_bad_call_that_follows_a_good_one():
    [onset] = onsets(provider_calls(run()))
    assert (onset["seq"], onset["check"], onset["connection"]) == (4, 4, "reused")
    assert (onset["age_s"], onset["idle_s"], onset["clock"]) == (58.0, 0.4, "14:00:03")
    assert onset["second_of_minute"] == 3.0 and onset["check_outcome"] == "failed"
    assert onsets(provider_calls([check(1, "answered", call(1, "new", "response"))])) == []


def test_new_connections_follow_bad_calls_so_they_are_a_consequence():
    """After a cancelled call the connection is closed, so the next call opens a new one."""
    result = new_connection_causality(provider_calls(run()))
    assert result == {"after a good call": (0, 0), "after a bad call": (5, 4)}


def test_deadline_accuracy_groups_cancelled_calls_by_position_in_the_check():
    assert deadline_accuracy(provider_calls(run())) == {1: [500.0], 2: [500.0]}


def test_the_report_has_the_clock_onset_and_timer_sections():
    text = render(summarise(run()))
    for heading in ("### Does a new connection cause a failure?",
                    "### Failures by the second of the clock minute",
                    "### Where each stall began",
                    "### Did this process's timers fire on time?"):  # fmt: skip
        assert heading in text
    assert "| :00-:09 | 8 | 2/8 (25%) |" in text
    assert "Checks starting between :55 and :09: 2/8 (25%) failed." in text
    assert "1 onsets, 1 on a reused connection." in text
    assert "New-connection calls after a bad call: 5, bad 4/5 (80%)." in text
