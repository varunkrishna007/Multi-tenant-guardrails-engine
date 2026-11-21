# M0-01 latency profile: warm bursts, staggered release, cold diagnostic and pre-filled window

This report follows up the burst test (`m0-01-bursts.md`). It covers two runs on one machine (local timezone IST), one key, one httpx client per cell (HTTP/1.1), calling `GeminiDecisionModel` directly, so no gateway and no admission limit is involved. Raw records: `m0-01-warm.jsonl` and `m0-01-hot.jsonl`, holding ids, timings, usage and the structured head of any error, with no content, headers or key. Reproduce the tables with `uv run python bench/latency.py warm-report <file>`.

## Runs

| | Warm run (`warmbursts`) | Hot run (`hotbursts`) |
|---|---|---|
| When (UTC, 2026-11-17) | 01:46:40–02:23:44 | 02:31:03–02:42:17 |
| Harness commit | `6a0ea5c` | `c3998f0` |
| Calls | 960: 944 answered, 14 `prohibited_content`, 1 timeout, 1 5xx | 434, all answered |
| API input tokens | 4.70M | 8.02M (stopped at the 8M token budget) |
| Corpus for the filler text | `floor/golden.jsonl`, 360 rows, **unfiltered** | 296 of 360 rows: 32 harm-labelled and 32 harm near-miss rows excluded |

**The harm content in the warm run.** The warm run's inputs were built from the 360-row golden set, which by then included the harm-facilitation examples. 14 inputs were refused with HTTP 400 `prohibited_content` (Google's Prohibited Use policy). *Where that classification comes from:* the warm JSONL predates the structured error field, so its 16 failed records carry only `kind` (14 `other`, 1 `timeout`, 1 `unavailable`) and `reason: null`. The `prohibited_content` code for the 14 comes from a diagnostic resend of those 16 inputs, rebuilt from their seeds, which printed each failure's message to the console: the 14 returned the same 400 again, and the timeout and 5xx were answered. That resend happened before the user's instruction not to send harmful inputs; nothing has been resent since. Failure records written from `7ad794d` on carry `error_code`. Every one of them contained 7–17 harm-labelled examples, but so did 938 inputs that passed: the refusals depend on combinations in long inputs, not single examples. Since then, by the user's instruction, the bench excludes those rows before any input is built, and a `prohibited_content` result stops the whole run. The hot run had a 20-call dry cell first, each call packing the whole filtered corpus about twice. It drew no refusals. The 14 refused calls are excluded from every latency figure below. The 1 timeout and the 1 5xx were transient.

## Design

- **Warm cells** (`warm_4k12`, `warm_1k6`): the burst test again. k = 1, 2, 4 and 8 calls released at once, round-robin over k, 20 bursts per k, 10 s apart, plus one discarded warm-up burst of 8. The difference from the original test: the benchmark's transport keeps idle connections for 120 s (`keepalive_expiry`, set in the benchmark's own transport; the adapter is unchanged), so burst calls reuse warm connections. New connections are recorded per call.
- **Stagger cell** (`stagger_4k12`): groups of 8 calls of 4K × 12 on the same warm client, released one by one either 500 ms apart (the spacing the concurrency sweep's throttle produced) or 75 ms apart (to reach 3–6 in flight at normal latency), alternating, 16 groups each. Per call it records the scheduled release, request sent, response headers and the in-flight count at start.
- **Cold cell** (`cold_4k12`): 10 bursts of 8 calls of 4K × 12, each burst on a fresh client, so every call opens a connection. New per-call events: entry into the transport, TCP connect start and end, TLS start and end, request start, and the connected address family.
- **Hot cell** (`hot_4k12`): k = 4 and 8 bursts of 4K × 12 on warm connections, released while sequential filler calls (16K × 50, about 24K API tokens each) hold the trailing-60 s token window at the throttle's limit (70% of Tier 1's 1M tokens a minute). One loop does both, so no filler call is in flight during a burst. Each burst waits in the throttle for room, so it is released into a nearly full window. 20 dry filler calls ran first. The cell stops at the first `rate_limited` result (none occurred) or at 1,500 calls or 8M tokens. It stopped at the token budget after **22 measured bursts (11 per k), not the planned 40**.

## Measurements

### Warm, stagger and cold cells (`warm-report`, verbatim)

```
Calls: 960 {'answered': 944, 'other': 14, 'timeout': 1, 'unavailable': 1}; API input tokens 4,699,914; stops: none.

Failed measured calls by cell (excluded from the latency statistics below; connection timings still count):

- cold_4k12: 1 of 80 {'other': 1}
- stagger_4k12: 4 of 256 {'other': 4}
- warm_1k6: 2 of 300 {'unavailable': 1, 'other': 1}
- warm_4k12: 7 of 300 {'other': 6, 'timeout': 1}

### warm_1k6: 300 measured calls; new connections 0; window before release (API tokens) median 42,657, min 35,919, max 112,479

| k | Bursts | New conn. | Start spread ms (median / max) | Sent ms after release (median / max) | Bursts with late sends (> 150 ms after first) | Server time ms, pooled median [95% CI] | Completion by finishing order, median ms | Last completion ms (median) |
|--:|--:|--:|---|---|---|---|---|--:|
| 1 | 20 | 0 | 0.0 / 0.0 | 4 / 6 | 0 of 20 {0: 20} | 357 [348-371] | 363 | 363 |
| 2 | 20 | 0 | 2.7 / 4.4 | 7 / 13 | 0 of 20 {0: 20} | 383 [375-395] | 379, 402 | 402 |
| 4 | 20 | 0 | 8.5 / 12.8 | 17 / 28 | 0 of 20 {0: 20} | 375 [367-388] | 373, 386, 406, 427 | 427 |
| 8 | 20 | 0 | 15.7 / 20.5 | 25 / 45 | 0 of 20 {0: 20} | 382 [374-390] | 358, 386, 396, 402, 410, 421, 431, 440 | 440 |

### warm_4k12: 300 measured calls; new connections 1; window before release (API tokens) median 107,539, min 43,576, max 147,381

| k | Bursts | New conn. | Start spread ms (median / max) | Sent ms after release (median / max) | Bursts with late sends (> 150 ms after first) | Server time ms, pooled median [95% CI] | Completion by finishing order, median ms | Last completion ms (median) |
|--:|--:|--:|---|---|---|---|---|--:|
| 1 | 20 | 0 | 0.0 / 0.0 | 2 / 8 | 0 of 20 {0: 20} | 433 [402-532] | 443 | 443 |
| 2 | 20 | 0 | 1.9 / 5.0 | 6 / 14 | 0 of 20 {0: 20} | 442 [432-463] | 442, 467 | 467 |
| 4 | 20 | 0 | 4.3 / 7.0 | 9 / 16 | 0 of 20 {0: 20} | 453 [439-495] | 424, 457, 510, 524 | 524 |
| 8 | 20 | 1 | 7.7 / 25.9 | 16 / 115 | 0 of 20 {0: 20} | 466 [456-472] | 437, 454, 473, 479, 484, 502, 528, 585 | 585 |

### stagger_4k12: 256 measured calls; new connections 2

Client send delay = request sent - scheduled release. Server time = response headers - request sent.

| Spacing ms | In flight at start | Calls | Client send delay ms (median / p90) | Server time ms, median [95% CI] | Wall ms (median / p90) |
|--:|--:|--:|---|---|---|
| 500 | 1 | 103 | 3 / 7 | 432 [421-440] | 436 / 519 |
| 500 | 2 | 24 | 4 / 8 | 478 [431-523] | 483 / 629 |
| 500 | 3 | 1 | 2 / 2 | 488 [488-488] | 491 / 491 |
| 75 | 1 | 16 | 2 / 3 | 408 [397-426] | 413 / 459 |
| 75 | 2 | 16 | 3 / 7 | 438 [412-458] | 441 / 483 |
| 75 | 3 | 16 | 3 / 6 | 437 [400-453] | 441 / 486 |
| 75 | 4 | 16 | 3 / 8 | 401 [395-437] | 408 / 518 |
| 75 | 5 | 20 | 3 / 6 | 419 [400-436] | 422 / 453 |
| 75 | 6 | 35 | 3 / 7 | 412 [404-429] | 419 / 464 |
| 75 | 7 | 8 | 3 / 27 | 414 [388-452] | 418 / 513 |
| 75 | 8 | 1 | 355 / 355 | - | nan / nan |

### cold_4k12: 80 calls in 10 bursts of 8; new connections 80

Per call, ms. Late = request sent more than 150 ms after the burst's first send.

| Group | Calls | IPv4 / IPv6 | Into transport → TCP start | TCP connect | TLS | TLS done → request sent | Sent after release | Server time |
|---|--:|---|---|---|---|---|---|---|
| prompt | 59 | 59 / 0 | 7 (max 14) | 25 (max 93) | 54 (max 110) | 6 (max 24) | 97 | 581 |
| late | 21 | 21 / 0 | 3 (max 7) | 279 (max 523) | 48 (max 82) | 1 (max 13) | 365 | 517 |
```

### Pre-filled window (`warm-report`, verbatim)

```
Calls: 434 {'answered': 434}; API input tokens 8,022,333; stops: [('hot_4k12', 'token budget (8,000,000)')].

Failed measured calls by cell (excluded from the latency statistics below; connection timings still count):

- hot_4k12: 0 of 132 

### hot_4k12: 132 measured calls; new connections 0; window before release (API tokens) median 644,398, min 607,201, max 657,537

| k | Bursts | New conn. | Start spread ms (median / max) | Sent ms after release (median / max) | Bursts with late sends (> 150 ms after first) | Server time ms, pooled median [95% CI] | Completion by finishing order, median ms | Last completion ms (median) |
|--:|--:|--:|---|---|---|---|---|--:|
| 4 | 11 | 0 | 4.5 / 7.9 | 10 / 21 | 0 of 11 {0: 11} | 553 [458-577] | 457, 485, 594, 603 | 603 |
| 8 | 11 | 0 | 13.2 / 31.1 | 34 / 51 | 0 of 11 {0: 11} | 500 [467-519] | 485, 496, 501, 511, 519, 536, 589, 659 | 659 |

### hot_4k12 filler: 274 calls, 6,638,566 API tokens; wall median 580 ms; window before each filler call median 658,317
```

### Two comparisons computed from the raw records

**Cold against warm k = 8 bursts, 4K × 12, same run** (bursts with a failed call excluded: 16 warm, 9 cold):

| | Median wall per call | Request sent after release | Server time | Last completion in the burst |
|---|--:|--:|--:|--:|
| Warm (`warm_4k12`, 01:46–02:01) | 478 ms | 16 ms | 464 ms | 585 ms |
| Cold (`cold_4k12`, 02:22–02:24) | 717 ms | 106 ms | 568 ms | 934 ms |

**Sequential 16K × 50 calls in the hot run, low against high occupancy:**

| | Calls | Window before the call (API tokens) | Wall p50 | Wall p90 |
|---|--:|---|--:|--:|
| Dry cell (02:31:03–02:31:15) | 20 | 0 to 460K, median 230K | 607 ms | 689 ms |
| Filler (02:31:17–02:42:17) | 274 | 536K to 660K, median 658K | 580 ms | 734 ms |

For reference, the same 16K × 50 cell measured sequentially the previous evening (`m0-01-concurrency.md`, 2026-11-16 21:39–21:49 UTC) had a p50 of 469 ms.

## Interpretation

Everything above is measurement. This section is my reading of it.

### 1. Why only 6 of 8 requests left promptly in cold bursts: located

- **Where the time goes:** in TCP connect. Prompt requests connected in 14–93 ms. Late ones took 271–321 ms, and two took 520 and 523 ms. There's nothing in between. The late ones spent no extra time before the connect started, in TLS, or between TLS and sending.
- **The mechanism:** steps of 250 ms are anyio's happy-eyeballs delay. `anyio.connect_tcp` (4.16, used by httpcore) has `happy_eyeballs_delay=0.25`: when a connection attempt hasn't completed within 250 ms, it starts the next address. The late connections are ones whose first attempt stalled, and a second attempt (two steps: a third) connected about 20–70 ms after it started. Every connection ended on IPv4. The API host resolves to 8 IPv4 and 8 IPv6 addresses.
- **What isn't identified:** why the first attempt stalls, or why it's almost exactly 2 of 8 per burst (9 of 10 bursts; the other had 3). Candidates are SYN loss or limiting on this network path, or a particular address. This run can't separate them.
- **What it rules out:** httpx pool limits (100 connections), the thread pool, TLS handshakes on the event loop (TLS took the same time for late and prompt calls), and HTTP/1.1 against HTTP/2 (connect happens before either protocol).
- **What removes it:** warm connections. With connections kept alive, 0 of 80 warm bursts had a late send.

### 2. Warm connections

- **Reuse worked:** 1 new connection in 600 warm-cell calls, and 2 in 256 stagger calls.
- **Cold costs about +240 ms per call, measured in one run:**
  - at k = 8, median wall per call was 717 ms cold against 478 ms warm;
  - about 90 ms of that is connection setup before the request is sent, and about 100 ms is a slower first response on a new connection;
  - the last call in a cold 8-call burst finished at 934 ms against 585 ms warm.
- **Implications for M1-10 (merged) and the R6.3 budgets:** the earlier cross-run estimate of about +200 ms is roughly confirmed, but by different arithmetic. The warm solo figure in this window is about 440 ms, not about 300 ms (see point 5).

### 3. Concurrency at low occupancy, warm connections

- **Calls overlapped well, and slightly less well at the larger size.** k = 8 bursts finished about 80 ms (1K × 6) and 140 ms (4K × 12) after a solo call.
- **Server time barely rose with k:**
  - at 1K × 6, 357 ms at k = 1 and 375–383 ms at k = 2 to 8;
  - at 4K × 12, 433, 442, 453 and 466 ms (the CIs overlap at adjacent k; k = 1 against k = 8 is about +30 ms);
  - no step anywhere near the 1–2 s per call of the sweep.
- **Every request went out within 45 ms of release** (no late sends at all).

### 4. Staggered release (the sweep's pattern) at low occupancy: no slowdown

- **Released 75 ms apart,** calls reached 3–7 in flight. Server time stayed 401–438 ms at every in-flight level, and the client send delay stayed at a median of 3 ms.
- **Released 500 ms apart** (the sweep's spacing), calls rarely overlapped: 103 of 128 started with 1 in flight.
- **The one outlier** was a call that started with 8 in flight, sent 355 ms late on a new connection. That fits point 1.
- **So** the throttle-staggered release pattern, by itself, doesn't reproduce the sweep's slowdown on warm connections.

### 5. Pre-filled window (about 64% occupancy at release): no multi-second slowdown

- **Occupancy at release** was 607K–658K API tokens (61–66% of the limit). The sweep ran at about 69%.
- **Against the low-occupancy warm bursts 30–45 minutes earlier:**
  - k = 4: last completion 603 ms against 524, server time 553 [458–577] against 453 [439–495];
  - k = 8: last completion 659 ms against 585, server time 500 [467–519] against 466 [456–472];
  - so about 10–20% slower, and nowhere near the sweep's 1–2 s per call at 3–6 in flight.
- **That 10–20% is not attributable on this data**: there's no same-window, low-occupancy burst control. What is known:
  - in the same hot run, sequential 16K × 50 calls were no slower at about 66% occupancy (p50 580 ms) than at low occupancy (dry cell, 607 ms);
  - both were well above the previous evening's 469 ms for the same cell, so latency was higher in this time window generally;
  - the warm solo 4K × 12 calls (about 443 ms) were also well above the soak's 285 ms.
- **Caveats:** 11 bursts per k, not 20, because the token budget bound first. One window, one machine.

### 6. What this leaves about the sweep's slowdown

- **Each tested alone, the candidates don't reproduce it:**
  - the staggered release at low occupancy (point 4);
  - simultaneous release at high occupancy (point 5);
  - warm against cold connections (sweep levels were warm).
- **Still untested:**
  - the combination of staggered release, high occupancy and sustained overlap over 200 calls per level;
  - the sweep's own tracing transport (`make_tracing_transport`; these runs used the timing transport);
  - that time window (2026-11-16 21:25–21:35 UTC).
- **Status:** unexplained. The evidence now points away from a load-dependent server-side limit at k ≤ 8 and about 65% occupancy, but it doesn't rule out behaviour that varies over time.

### 7. What this means for the budget

**The k-versus-solo comparison (added later).** The hot run had no solo (k = 1) bursts, so the solo arm below is borrowed from the warm run, 30–45 minutes earlier and at low occupancy. Burst-level cluster bootstrap (bursts resampled with replacement in each arm, 4,000 resamples, 95% interval) of p50(k) − p50(solo) on per-call wall time, 4K × 12:

| k | Bursts (k / solo) | p50(k) − p50(solo) | 95% interval | Per-call p95 at k | Slowest call at k |
|--:|---|--:|---|--:|--:|
| 4 | 11 / 20 | +119 ms | [−3, +177] | 642 ms | 680 ms |
| 8 | 11 / 20 | +77 ms | [−16, +137] | 693 ms | **938 ms** (burst 9, server time 895 ms) |

An independent computation gives +120 [−7, +173] and +67 [−33, +118]; the small differences come from the method. Against R6.3's budget for this shape without the queue allowance (expected p50 425 ms including the 130 ms time-window allowance, plus a 400 ms margin, so 825 ms), the k = 8 slowest call is over budget, and the review-18 reading with the earlier budget (about 695 ms) failed it too. So "doesn't justify holding the limit at 2" must not be read as "supports 8". The same-window rerun (k = 1, 4 and 8 interleaved) is the test for that.

- **Admission limit:** at k ≤ 8 from one key, with warm connections, overlap cost about 30–140 ms per burst at both low occupancy and about 64% occupancy. That doesn't support holding the admission limit at 2 because of provider behaviour. The sweep's unexplained slowdown is the remaining reason for caution, and the dogfood's `admission_wait` and latency rates are the way to watch it.
- **Connections:** cold connections cost about +240 ms per call, and at bursts of 8 some connections wait a further 250 ms in happy-eyeballs fallback on this network. Warm connections (M1-10) remove both.
- **Absolute latency moved between time windows by more than concurrency moved it** (4K × 12 solo about 285 ms on 2026-11-16 evening against about 440 ms on 2026-11-17 early UTC). The budgets should be checked against the dogfood's own distribution.

### What these runs don't show

- Behaviour above 8 in flight, or above about 66% occupancy (the throttle caps at 70%).
- Another time window, region or tier.
- Why the first TCP attempt stalls for about 2 of 8 new connections.
- The cause of the sweep's slowdown.
