# M0-01 latency profile: concurrency sweep

Run 2026-11-16, 21:25:27–21:35:09 UTC. One machine (local timezone IST). The soak's cell,
4K input × 12 questions, through `GeminiDecisionModel` on one key and one httpx client per
level (HTTP/1.1, connection pool warmed per level). Raw records:
`m0-01-concurrency.jsonl` (no content, headers or key). Reproduce with
`uv run python bench/latency.py concurrency-report bench/results/m0-01-concurrency.jsonl`.

**Totals:**
- 1,062 model calls (1,000 measured), all answered: 0 failures and **0 `rate_limited`** at
  any level. 6.85M API input tokens, about $0.69.
- 64 invalid-key requests, which do no model work and use no quota.

*Corrected: the causal statements in the first version
("queueing past Google's edge", "served one after another", "about 0.4 s per call beyond the
second") weren't established. This section now gives observations and candidate mechanisms.
The controlled burst test (`m0-01-bursts.md`) addresses the question directly.*

## What was observed

**Calls that overlapped with other calls from this key took much longer.** The cause is not
established.

| Calls in flight when the call started | Calls | p50 [95% CI] |
|--:|--:|---|
| 1 | 683 | 304 [298–309] |
| 2 | 92 | 397 [346–474] |
| 3 | 53 | 962 [816–1,037] |
| 4 | 60 | 1,214 [1,087–1,476] |
| 5 | 58 | 1,558 [1,456–1,891] |
| 6 | 42 | 1,940 [1,671–2,188] |
| 7 | 9 | 1,816 (too few calls for an interval) |
| 8 | 3 | too few |

- Pooled over all levels, by the in-flight count at each call's start. Intervals are
  order-statistic 95%. Only the 1-in-flight row has enough calls for a p95: 424 ms.
- **This table is confounded.** The throttle released calls at a roughly fixed rate (about
  1.8 a second at levels 2–16). At a fixed arrival rate, slower calls stay in flight longer
  and so are counted with more company (Little's law). The causation can run either way:
  slow calls may raise the in-flight count, not the reverse. Levels 2 to 16 had the same
  arrival rate but very different latencies, which a simple "one after another at about
  0.3 s each" service can't produce.
- **The 16-call warm-up bursts at the start of level 16** were released by the harness's own
  throttle, not simultaneously.
  - They **started** 0.3–0.5 s apart: over 7.5 s in the first round and 5.2 s in the second.
  - They **completed together**: within 8.0–8.4 s in the first round and 5.6–6.1 s in the
    second, measured from the first start.
  - So the earliest call waited until about the time the last one started, then all
    returned at once.
  - A server-side first-in-first-out queue wouldn't produce that, and neither would plain
    per-call token-rate shaping. Neither a client-side nor a server-side cause is ruled out.
- **The invalid-key control** sent 16 requests truly at once, which completed in 130–460 ms
  when warm, with no stretched pattern. It differs from the model calls in two ways at once,
  though: no throttle stagger and no model work. So it doesn't isolate the cause.

## Candidate mechanisms, and what each predicts for a second key in the same project

| Mechanism | Fits the observations? | A second key in the same project |
|---|---|---|
| Per-key concurrency limit on the serving path | Explains slow overlapping calls; doesn't by itself explain the warm-up burst completing together | Adds capacity |
| Per-project concurrency limit | As above | Adds nothing |
| Token-rate smoothing by the provider (per key or project): 6,455 tokens at 1M a minute is about 387 ms, close to the per-call gaps seen | Explains slower overlapping calls at a fixed token rate; predicts a gap between completions proportional to tokens per call | Adds nothing if per project; adds capacity if per key |
| Client-side cause (event loop, pool or connection handling under the throttle's stagger) | Can't be excluded: the warm-up pattern (all complete when the last starts) is as consistent with it as with any server cause | Irrelevant: the client would need fixing, not more keys |

The controlled burst test (`m0-01-bursts.md`) releases k = 1, 2, 4 and 8 calls truly at once
at two call sizes (about 6.4K and 1.5K tokens). It records when each response arrives, so a
staircase, a common delay and a gap that scales with tokens can be told apart. At 6–18% window
occupancy it found no staircase and no gap scaling with tokens. That strongly disfavours
per-call pacing at 1M tokens a minute and a concurrency limit at or below 8. Smoothing or
limits that engage only near the quota (this sweep ran at about 69%) aren't tested.

## What the sweep was meant to measure, and what it measured

The design was 200 calls at each of 1, 2, 4, 8 and 16 in flight. **The target levels
weren't reached.** That is a flaw in the run design, mine:

| Target in flight | Calls | In flight at start: median / max | p50 | p95 | Achieved calls/min |
|--:|--:|---|--:|--:|--:|
| 1 | 200 | 1 / 1 | 314 [305–324] | 407 | 119 |
| 2 | 200 | 1 / 2 | 291 | 450 | 106 |
| 4 | 200 | 1 / 3 | 299 | 438 | 106 |
| 8 | 200 | 1 / 8 | 372 | 2,057 | 106 |
| 16 | 200 | 4 / 7 | 1,389 | 3,428 | 106 |

- **Why:** the token throttle (70% of Tier 1's 1M tokens per minute) carried its window from
  one level to the next. A 4K × 12 call is about 6,400 API tokens, so the throttle admits
  about 109 calls a minute. After level 1 it released calls one at a time as old entries
  expired, about 106 per minute at every level.
- **So** levels 2 and 4 effectively ran one call at a time. Level 8 did too until its last
  quarter, when calls bunched up (5 in flight, p50 about 1.5 s). Level 16 averaged 4–5 in
  flight.
- The per-level rows above therefore **must not be read as concurrency levels**. The
  headline table, grouped by the in-flight count each call actually saw, is the result.

## The token limit caps concurrency at Tier 1 for this cell

This is a finding in itself:
- Tier 1 allows 1M input tokens a minute. At about 6,400 tokens a call, that is about 156
  calls a minute at 100% of the limit (about 109 at the throttle's 70%).
- At about 0.3 s a call, that sustains **less than one call in flight on average per key**.
- The 5–7 in flight per key that an earlier estimate derived from the request limit (1,500 a
  minute) isn't reachable at Tier 1 for calls this size. Tokens bind first.
- **Concurrency per key at Tier 1 happens only in bursts.** Several guard points of one
  turn, or `tool_result` chunks, are checked at once. Overlapping calls were slower during
  this sweep, at about 69% window occupancy, with the cause unexplained. At low occupancy,
  8 simultaneous calls weren't (`m0-01-bursts.md`).

## Sanity check against the soak

The level-1 cell, sequential and back-to-back, gives p50 314 ms [305–324] and p95 407 ms.
The soak (one call every 1.5 s, 3.5 hours earlier) gave p50 285 and p95 400. The p95s
agree. The p50 is about 30 ms higher here; time of day and back-to-back pacing are both
possible reasons, and this run can't separate them.

## Connections

- HTTP/1.1, so one request per connection at a time. Each level warmed its pool with two
  rounds of k simultaneous calls first.
- New connections during measured calls: 1, 6, 7, 11 and 11 at levels 1, 2, 4, 8 and 16.
  So almost all measured calls reused a warm connection.
- Excluding new-connection calls changes p50 by at most 45 ms (concurrency-report table).
- Connection setup is about 50 ms (TCP 14 ms plus TLS 39 ms, `m0-01-detail.md`). It doesn't
  explain the slowdown.

## What this means for budgets (for the gateway)

**Update: the controlled burst test has reported** (`m0-01-bursts.md`). Under truly
simultaneous release, up to 8 calls from this key showed no server-side slowdown at either
call size. The slowdown observed in this sweep isn't reproduced and remains unexplained.
The two runs differ in three ways that the data can't rank: the release pattern (staggered by
the throttle here, simultaneous there), window occupancy (about 69% of the token quota here
at every level, 6–18% there) and the time window. Overlapping calls at high occupancy
haven't been tested in isolation. The readings below still hold as observations:
- **One sequential client: p50 304 ms, p95 424 ms** at 4K × 12 (this run's 1-in-flight
  calls), close to the soak's 285 / 400.
- **Overlapping calls from this key were much slower** (p50 about 1–2 s at 3–6 in flight),
  with the cause unknown. Don't plan on parallel calls from one key being free.
- **Whether more keys add concurrency depends on the mechanism** (table above). Don't size
  key pools from this run.

## What this run doesn't show

- What causes the slowdown under overlap (see the candidate mechanisms above).
- Behaviour at a higher tier.
- Behaviour from another region.
- Behaviour with HTTP/2 multiplexing (the adapter uses HTTP/1.1).
- A clean 200-call sample at each target level. A rerun that meets the targets needs each
  level's calls to fit inside one throttle window (for example 4K × 12 bursts of k calls
  spaced a minute apart), or a smaller cell.

## Largest compilable calls under R6.7

Run 2026-11-16, 21:39:35–21:49:08 UTC.

**Setup:**
- One client, sequential, warm connection (every call ran with 1 in flight; 0 new
  connections).
- 100 measured calls per cell after 3 warm-ups.
- Content of 16K estimated tokens. Fully described questions, about 88 estimated tokens each.
- 206 calls, 0 failures, 6.65M API input tokens.
- Raw records: `m0-01-bigcells.jsonl`. Command: `bench/latency.py bigcells`.

| Check | Calls | p50 [95% CI] | p90 | p95 (indicative) | max | API tokens per call | Gateway model | p50 against model |
|---|--:|---|--:|--:|--:|--:|--:|---|
| Full input check: 16K × 200 | 100 | 811 [797–823] | 975 | 1,044 | 1,204 | 40,091 | 800 | **+1.4%** (+11 ms) |
| Full critical-path check: 16K × 50 | 100 | 469 [464–485] | 563 | 605 | 800 | 24,420 | 500 | **−6.1%** (−31 ms) |

- **The gateway model** (400 ms at 16K plus 2.0 ms per question) **is close at p50 for both
  cells.** It is slightly optimistic for 200 questions: the model sits just inside the CI's
  lower bound, and the truth is about 1–3% higher. It is pessimistic by about 6% for 50
  questions, where the model is above the CI's upper bound.
- The two cells imply a slope of (811 − 469) / 150 ≈ **2.3 ms per question** at 16K, a little
  above the model's 2.0, and an intercept of about 357 ms at 16K, below the model's 400. The
  model's errors partly cancel in this range.
- **p95 is about 30% above p50 in both cells** (indicative: 100 calls give only 5
  observations beyond p95).
- **Against the R6.3 budget** (expected p50 + 400 ms, capped at 1.5 s), sequential and warm:

  | Check | Budget | Calls over it |
  |---|--:|---|
  | 16K × 200 | 1,200 ms | 1 of 100 (max 1,204) |
  | 16K × 50 | 900 ms | 0 of 100 (max 800) |

- **Cold connections would eat much of that margin.** In the burst test, solo calls on new
  connections took about 510 ms against about 300 ms warm, so about +200 ms. A cold 16K × 200
  call would sit near its budget. This cell depends on warm connections (M1-10).
- These are **single-client sequential** figures. Under overlapping calls from the same key,
  see the observations above and `m0-01-bursts.md`.
