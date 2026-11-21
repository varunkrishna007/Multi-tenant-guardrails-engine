# R7.4 connection diagnostic: do the failures follow new connections or connection age?

Run 2026-11-17 14:51:54-14:56:24 UTC, once. Golden set, floor@2, **draw 1 only**: 339 checks, environment `test`, seed `ebbaaea30f56ce5eff0050eb87f83369`, no re-attempt pass, every stop condition on, ceilings of 400 provider calls and 400,000 input tokens. It ran to the end (exit 0, no stop). No refusals, no quota errors.

- 339 checks, **21 failed** (6.2%); 383 provider calls, 65 bad (every one a call the gateway cancelled at its deadline); API input tokens on answered calls: 256,696.
- The earlier attempt (`m0-02-r74.jsonl`, 641 checks) had 43 failed checks (6.7%). The pattern reproduced.

## Findings

**1. The failures are not about connections.**
- A new connection is cheap: TCP connect median 23 ms (max 272), TLS median 47 ms, 80 ms from the call's start to its first request byte.
- Nothing closed a connection from the server's side: 0 responses with `Connection: close`; 0 resets, early closes or connect errors. All 65 bad calls are `CancelledError` at "waiting for the response head": **the request was written (about 1 ms), and no response byte came before our deadline.**
- **All 26 stall onsets began on a reused connection with no idle gap, at ages of 0.4 to 30 s.** The oldest connection ever seen was 30 s old; none reached the 60 s keep-alive, and an idle expiry can't apply when the idle gap is milliseconds. The keep-alive and pool-recycling hypothesis is not supported.
- **All 65 new-connection calls followed a bad call** (a cancelled call closes its connection, so the next call must open one): new connections are a consequence of a stall, not its cause. 39 of them were bad because they fell inside a stall. Calls after a bad call were bad 60% of the time, after a good call 8%.

**2. They line up with the clock.**
- By the second of the clock minute that a check started in: :00-:09 failed 65% (13 of 20), :10-:19 12%, **:20-:49 0 of 224**, :50-:59 6%. Checks starting between :55 and :09 failed **34%** against **2%** elsewhere.
- The earlier attempt shows the same: **33% against 3%**. It started 20 minutes earlier at a different second, so this is the clock, not the run's own timing.
- The long stalls are bursts of consecutive failed checks (up to 5 here, 11 in the earlier attempt). **6 of 7 bursts here and 11 of 13 in the earlier attempt began within a few seconds of the top of the minute (about :55 to :05).** The other onsets are isolated 1 to 2 s slow calls spread through the minute, mostly rescued by the gateway's retry.

**3. Our side kept its timing.** First calls were cancelled at 1,032 to 1,037 ms against an attempt deadline of about 1,030 ms; failed checks ended at 3.0 s (4.0 s on `input`), the budgets. This process's event loop was not blocked. No scheduled job fires every minute on this host (no user crontab, no per-minute system cron, systemd timers are hourly or daily).

## What this does and doesn't establish

- **Established:** it isn't connection age, a stale or new connection, a server-closed connection, or this process stalling. The stall is after the request is sent, and it recurs at the top of the minute.
- **Not established:** *where* it sits. The provider (a per-minute window or a periodic back-end event), the network path to Google, or this host's network I/O are all consistent with the data. Load doesn't look like the driver: about 85 provider calls and 57K tokens a minute, around 6% of the documented token limit, steady across the minute while failures are not.

## Proposed next steps (none done; each needs explicit approval)

1. **A zero-API-call probe:** TCP connect and TLS handshake only, no HTTP request and no key, to the API host once a second for about 5 minutes, logged against the second of the minute. If the handshake stalls at the top of the minute, it is the network path or the TLS front end. If it doesn't while API calls do, the stall is behind it (the provider's service).
2. **A paced run:** a few dozen checks spread across several minutes at a low rate (for example one every 3 s), to see whether the top-of-minute stalls persist when our load is a fraction of this run's.
3. **Production note:** in fail-closed mode these windows would block about 6% of checks, and a 3 s budget can't ride out stalls of 10 s or more, so only an upstream fix or knowing the windows (and routing or queueing around them) helps.

## Tables (`uv run python -m calibration.connection_analysis calibration/results/m0-02-r74-diagnostic.jsonl`)

### Overview

- 339 checks, 21 failed (every call bad); 383 provider calls, 65 bad; 0 checks without diagnostics.
- How calls ended: {'response': 318, 'cancelled': 65}. HTTP versions: {'HTTP/1.1': 318, 'None': 65}. Responses with `Connection: close`: 0.

### First call of each check, by its connection

| Connection | First calls | First call bad | Check failed |
|---|--:|--:|--:|
| new | 22 | 18/22 (82%) | 14/22 (64%) |
| reused | 317 | 26/317 (8%) | 7/317 (2%) |
| unknown | 0 | - | - |

### Every call, by connection

| Connection | Calls | Bad |
|---|--:|--:|
| new | 66 | 39/66 (59%) |
| reused | 317 | 26/317 (8%) |

### Calls on a reused connection, by its (estimated) age

| Age | Calls | Bad |
|---|--:|--:|
| 0-10 s | 201 | 21/201 (10%) |
| 10-30 s | 115 | 4/115 (3%) |
| 30-55 s | 1 | 1/1 (100%) |
| 55-65 s | 0 | - |
| 65+ s | 0 | - |
| unknown | 0 | - |

### Every call, by the idle gap before it

| Idle | Calls | Bad |
|---|--:|--:|
| 0-0.5 s | 382 | 65/382 (17%) |
| 0.5-2 s | 0 | - |
| 2-10 s | 0 | - |
| 10+ s | 0 | - |
| unknown | 1 | 0/1 (0%) |

### Does a bad call follow a bad call?

- After a bad call: 39/65 (60%) bad. After a good call: 26/317 (8%) bad.

### Does a new connection cause a failure?

- New-connection calls after a good call: 0, bad -.
- New-connection calls after a bad call: 65, bad 39/65 (60%).

### Failures by the second of the clock minute

| Seconds | Checks started | Failed |
|---|--:|--:|
| :00-:09 | 20 | 13/20 (65%) |
| :10-:19 | 42 | 5/42 (12%) |
| :20-:29 | 74 | 0/74 (0%) |
| :30-:39 | 81 | 0/81 (0%) |
| :40-:49 | 69 | 0/69 (0%) |
| :50-:59 | 53 | 3/53 (6%) |

Checks starting between :55 and :09: 15/44 (34%) failed. Elsewhere in the minute: 6/295 (2%) failed.

### Where each stall began

| Call | Clock (UTC) | Second | Connection | Age (s) | Idle (s) | Its check |
|--:|---|--:|---|--:|--:|---|
| 2 | 14:51:55 | 55.7 | reused | 0.798 | 0.002 | 2 (answered) |
| 4 | 14:51:58 | 58.8 | reused | 1.93 | 0.001 | 3 (answered) |
| 7 | 14:52:01 | 1.3 | reused | 1.424 | 0.001 | 5 (failed) |
| 13 | 14:52:12 | 12.5 | reused | 2.047 | 0.002 | 8 (answered) |
| 26 | 14:52:20 | 20.1 | reused | 6.449 | 0.002 | 20 (answered) |
| 83 | 14:52:51 | 51.5 | reused | 30.316 | 0.005 | 76 (answered) |
| 92 | 14:52:57 | 57.2 | reused | 4.568 | 0.004 | 84 (answered) |
| 94 | 14:52:58 | 58.8 | reused | 0.438 | 0.004 | 85 (answered) |
| 97 | 14:53:01 | 2.0 | reused | 2.069 | 0.005 | 87 (failed) |
| 151 | 14:53:40 | 40.8 | reused | 21.712 | 0.004 | 136 (answered) |
| 165 | 14:53:48 | 48.6 | reused | 6.625 | 0.005 | 149 (answered) |
| 172 | 14:53:53 | 53.3 | reused | 3.572 | 0.002 | 155 (answered) |
| 174 | 14:53:54 | 54.9 | reused | 0.53 | 0.002 | 156 (failed) |
| 177 | 14:53:58 | 58.9 | reused | 0.696 | 0.005 | 158 (failed) |
| 189 | 14:54:14 | 14.1 | reused | 1.971 | 0.001 | 165 (answered) |
| 205 | 14:54:21 | 21.9 | reused | 6.778 | 0.002 | 180 (answered) |
| 240 | 14:54:39 | 39.9 | reused | 16.822 | 0.001 | 214 (answered) |
| 278 | 14:54:59 | 59.9 | reused | 18.924 | 0.005 | 251 (failed) |
| 286 | 14:55:11 | 11.3 | reused | 1.242 | 0.002 | 255 (failed) |
| 300 | 14:55:24 | 24.6 | reused | 6.189 | 0.002 | 267 (answered) |
| 340 | 14:55:48 | 48.1 | reused | 22.35 | 0.001 | 306 (answered) |
| 348 | 14:55:54 | 54.1 | reused | 4.904 | 0.004 | 313 (answered) |
| 354 | 14:55:57 | 57.5 | reused | 2.252 | 0.005 | 318 (answered) |
| 357 | 14:56:00 | 0.5 | reused | 1.855 | 0.001 | 320 (answered) |
| 361 | 14:56:03 | 3.7 | reused | 2.104 | 0.004 | 323 (failed) |
| 377 | 14:56:20 | 20.3 | reused | 3.434 | 0.001 | 334 (answered) |

26 onsets, 26 on a reused connection.

### Did this process's timers fire on time?

- Cancelled call 1 of a check, run time: n 44, median 1,035 ms, p95 1,037, max 1,037
- Cancelled call 2 of a check, run time: n 21, median 1,963 ms, p95 2,960, max 2,960
- Bad calls, time to write the request: n 65, median 1 ms, p95 2, max 2

### Timings

- TCP connect, new connections that answered: n 27, median 23 ms, p95 59, max 270
- TCP connect, new connections that went bad: n 39, median 25 ms, p95 103, max 272
- TLS handshake: n 66, median 47 ms, p95 83, max 119
- Call start to first request byte, new connection: n 66, median 80 ms, p95 224, max 334
- Call start to first request byte, reused connection: n 317, median 1 ms, p95 2, max 4
- Provider time (request written to response head), answered calls: n 318, median 532 ms, p95 839, max 2,040
- Bad calls that got a response head: -; bad calls with none: 65

### How bad calls failed

{'http11.receive_response_headers.failed:CancelledError': 65}

### Bursts of consecutive failed checks

| First check | Length | Seconds in | Connection of its first call | Age (s) | Idle (s) |
|--:|--:|--:|---|--:|--:|
| 5 | 2 | 6 | reused | 1.424 | 0.001 |
| 87 | 5 | 67 | reused | 2.069 | 0.005 |
| 156 | 1 | 120 | reused | 0.53 | 0.002 |
| 158 | 4 | 124 | reused | 0.696 | 0.005 |
| 251 | 3 | 185 | reused | 18.924 | 0.005 |
| 255 | 2 | 197 | reused | 1.242 | 0.002 |
| 323 | 4 | 249 | reused | 2.104 | 0.004 |

Gaps between burst starts (seconds): [61, 53, 4, 61, 11, 52]

## The earlier attempt, by the clock

`calibration/results/m0-02-r74.jsonl` recorded no connection data, but its start times and outcomes give the same clock table:

| Seconds | Checks started | Failed |
|---|--:|--:|
| :00-:09 | 28 | 22/28 (79%) |
| :10-:19 | 72 | 9/72 (12%) |
| :20-:29 | 137 | 7/137 (5%) |
| :30-:39 | 130 | 0/130 (0%) |
| :40-:49 | 160 | 0/160 (0%) |
| :50-:59 | 114 | 5/114 (4%) |

Checks starting between :55 and :09: 27/83 (33%) failed. Elsewhere: 16/558 (3%) failed.
