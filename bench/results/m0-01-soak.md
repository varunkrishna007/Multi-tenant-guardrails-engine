# M0-01 latency profile: tail soak

Run 2026-11-16, 20:30:52–21:15:51 UTC (45.0 minutes).

**Setup:**
- Cell: 4K input × 12 questions (the six floor rules plus six templated rules with
  descriptions; about a floor plus a small pack).
- One call every 1.5 s, sequential, on one warm connection, through `GeminiDecisionModel`.
- 30 s transport timeout, so slow calls are measured rather than cut off.
- Stop rules: the first `auth` result, or more than 20% failures in the last 50 calls.
  Neither triggered.

Raw records: `m0-01-soak.jsonl` (timestamps, timings and token counts; no content, headers or
key). Reproduce the tables with
`uv run python bench/latency.py soak-report bench/results/m0-01-soak.jsonl`.

**Totals:**
- 1,803 calls (3 warm-ups). All 1,800 measured calls were answered: 0 failures,
  0 `rate_limited`, 0 timeouts.
- 11.65M API input tokens, about $1.16.

**These numbers come from one machine in one location (local timezone IST), with one client
making sequential calls.** Latency at production concurrency isn't measured here; see
`m0-01-concurrency.md`. The network baseline from the same machine is p50 72 ms
(`m0-01-detail.md`).

*Corrected: the "net of baseline" column is removed (percentiles don't
subtract); the slow episode's cause is stated as not established and the hedging
conclusion as a hypothesis; autocorrelation and drift are noted.*

## Percentiles

| Percentile | Raw ms | Sample size | Observations beyond |
|---|--:|--:|--:|
| p50 | 285 | 1,800 | 900 |
| p90 | 368 | 1,800 | 180 |
| p95 | 400 | 1,800 | 90 |
| p99 | 467 | 1,800 | 18 |
| p99.5 | not quoted | 1,800 | 9 |
| p99.9 | not quoted | 1,800 | 1.8 |

- A percentile is quoted only when at least 10 observations lie beyond it. p99.5 would need
  2,000 calls.
- The maximum over all 1,800 calls was 658 ms.
- **The calls aren't independent.** Successive latencies are correlated (lag-1 r = 0.24), and
  the 5-minute windows' p50 drifts from 272 to 316 ms (below). Run-to-run variation is
  therefore wider than an independent-sample interval on these percentiles would suggest.

**Stable across the 45 minutes** (5-minute windows of 200 calls):

| Minutes | 0–5 | 5–10 | 10–15 | 15–20 | 20–25 | 25–30 | 30–35 | 35–40 | 40–45 |
|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|
| p50 | 316 | 308 | 277 | 277 | 272 | 274 | 281 | 276 | 302 |
| p95 | 435 | 408 | 400 | 355 | 372 | 401 | 369 | 370 | 417 |

This cell is close to the engine's realistic case. Its p50 sits just under 300 ms and its
p95 at about 400 ms, so for **one sequential client** on this machine the 400 ms
per-guard-point budget (PF-8) is met at about p95, with no headroom for a retry. Under
concurrency it may not be: see `m0-01-concurrency.md`.

## Slow periods in the soak

A slow call is one that failed or took more than 2× the run's median, which is over 569 ms.

- **Slow calls: 4, all isolated singles (569–658 ms). No slow periods.**
- No call exceeded 1 s, and nothing like the pilot's event occurred.

## Comparison with the pilot's slow period

| | Pilot event (8K × 200 cell) | Soak |
|---|---|---|
| When | 16:47:12–16:49:35 UTC | none in 20:30–21:15 UTC |
| Duration | **about 2.4 min** against neighbouring cells' normal speed; 101 s by the strict 2×-own-median rule, because the event inflated that cell's median to 2.3 s | – |
| Calls affected | 22 of 26 consecutive calls over 2 s (9 by the strict rule) | 0 (4 isolated calls of 0.57–0.66 s) |
| Worst latency | 21,285 ms; 3 timeouts at the 10 s backstop | 658 ms |
| Follow-on | a 2-call period at 16:52:58 in 1K × 900 (a timeout and a slow call, 18 s) | – |

**Across all runs:**
- Observation: **92 minutes** in total and about 3,100 model calls: pilot 35 min, detail
  12 min, soak 45 min.
- **One slow episode** was seen (cause not established: provider, network path or the
  pilot's own load): 16:47–16:53 UTC during the pilot, which the strict
  rule splits into 2 periods.
- **None** occurred in the other 57 minutes.

**One event is not a rate.**
- These data can't say how often such episodes occur, how long they usually last, or
  whether time of day matters.
- The pilot was also running much heavier calls, up to 117K tokens each at about 70% of the
  per-minute token limit. Whether that load contributed can't be told from one event.

## Hedging estimate (no extra calls)

- A hedge fires a duplicate request if the original hasn't answered after a threshold.
- The estimate uses each slow call's next call as a stand-in for the duplicate. The duplicate
  counts as rescuing the slow call if the next call was normal-speed and threshold + its
  latency beat the slow call.
- **This is an estimate.** The real next call started about 1.5 s later, and a real hedge
  runs concurrently with the original. The detail run shows 2–4 concurrent calls barely
  slow each other (`m0-01-detail.md`, section 4), so the concurrency itself is cheap.

| Hedge after | Threshold | Slow calls | Estimated rescues |
|---|--:|--:|--:|
| run p90 | 368 ms | 4 | 0 |
| run p95 | 400 ms | 4 | 0 |

**What it means:**
- In the soak, the slow calls were only marginally slow (at most 658 ms). A hedge at 368 ms
  plus a normal call of about 285 ms finishes at about 650 ms, which is no faster.
- In the pilot's episode, the next calls were slow too, so the stand-in duplicate would
  also have been slow. A hedge can't rescue a period lasting minutes.
- Neither case gives evidence that hedging helps.
- **Hypothesis, not established by one episode:** in an episode like the pilot's, what helps
  is the fail-closed path (B1) staying fast and visible, plus the gateway's alerting
  (M4-04), rather than retries.

## What the soak does and doesn't show

**It shows:**
- At 4K × 12, steady-state latency from this machine is p50 285, p95 400 and p99 467 ms over
  1,800 calls.
- It stays stable over 45 minutes, with no slow periods and no failures.

**It doesn't show:**
- Latency at production concurrency: one sequential client only.
- How often slow episodes happen, or what causes them. Only one has been seen, in 92 minutes.
- Behaviour at other times of day or on other days.
- Another region.
- A real (concurrent) hedge.
