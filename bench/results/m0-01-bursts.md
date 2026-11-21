# M0-01 latency profile: controlled burst test

Run 2026-11-16, 21:49:22–22:18:21 UTC, in one window. One machine (local timezone IST), one
key, one httpx client (HTTP/1.1), through `GeminiDecisionModel`. Raw records:
`m0-01-bursts.jsonl` (no content, headers or key). Reproduce the tables with
`uv run python bench/latency.py bursts-report bench/results/m0-01-bursts.jsonl`.

## Design

- **Bursts:** k = 1, 2, 4 and 8 calls released at once. Each burst's inputs were built first,
  then tokens for the whole burst were reserved in the throttle, then all k calls were
  started together.
  - Measured start spread within a burst: median 0–13 ms, max 23 ms (target < 50 ms).
- **Order:** round-robin over k (1, 2, 4, 8, 1, 2, …), so drift over time doesn't line up
  with k. 20 bursts per k per cell, plus one discarded warm-up burst of 8 per cell.
- **Gaps:** 10 s idle between bursts.
- **Two call sizes:** 4K input × 12 questions (median 6,460 API tokens a call) and 1K × 6
  (median 2,302).
- **Timestamps:** per call, from httpcore's trace events, relative to the burst's release:
  request sent, response headers received, response complete. "Server time" below is
  headers received minus request sent.
- **Totals:** 616 calls, all answered (0 failures, 0 `rate_limited`). 2.70M API input
  tokens.

### Two caveats

1. **Every call opened a new connection** (616 of 616). httpx closes idle connections after
   5 s by default (`keepalive_expiry`), and the bursts were 10 s apart. So the intended "warm
   one connection per concurrent call" wasn't met.
   - Every call paid TCP and TLS setup: request sent at a median of 66–103 ms after release.
     It also paid the extra server time of a first request on a new connection.
   - All k paid this equally, so **comparisons across k and across sizes hold**.
   - **Absolute latencies are not comparable with the warm sequential runs** (about 300 ms).
2. **Window occupancy at release** was 54K tokens (median) for 1K × 6 and 147K for 4K × 12.
   - These are by estimate: this run's throttle didn't learn the API/estimate ratio, so the
     real figures are about 20% higher, about 65K and 176K.
   - That is **about 6% and 18% of the 1M tokens-a-minute limit**: low, but not empty.

## Results

### Completion time by finishing order (median over 20 bursts, ms from release)

| k | 4K × 12 (6.5K tokens a call) | 1K × 6 (2.3K tokens a call) |
|--:|---|---|
| 1 | 507 | 512 |
| 2 | 506, 543 | 505, 545 |
| 4 | 424, 509, 541, 560 | 376, 474, 495, 522 |
| 8 | 381, 520, 530, 542, 586, 621, **772, 785** | 314, 457, 466, 474, 494, 545, **734, 767** |

### Server time (headers received − request sent) by finishing order, median ms

| k | 4K × 12 | 1K × 6 |
|--:|---|---|
| 1 | 433 | 410 |
| 2 | 421, 438 | 421, 451 |
| 4 | 305, 426, 442, 456 | 292, 396, 421, 445 |
| 8 | 288, 430, 441, 445, 452, 484, 428, 439 | 234, 363, 380, 400, 401, 426, 390, 413 |

### When the request was sent, by finishing order at k = 8, median ms from release

| | 1st–6th to finish | 7th and 8th |
|---|---|---|
| 4K × 12 | 88–99 | 345, 346 |
| 1K × 6 | 84–95 | 341, 343 |

## What the data shows

1. **No staircase and no common queueing delay.**
   - Server time stays at about 400–450 ms from k = 1 to k = 8 at both sizes.
   - A k-call burst finishes at roughly the time of one call plus a spread. At k = 8 the
     whole burst completes in a median of about 0.4 s from first to last finisher (range
     0.12–0.75 s).
2. **The k = 8 tail is on the client side.**
   - The 7th and 8th calls to finish had normal server times. Their requests went out about
     250 ms later than the other six.
   - In 36 of the 40 eight-call bursts, exactly two requests went out late (more than
     150 ms after the first send). One burst had none late, and the others had 3, 4 and 5.
     The cause isn't identified here. It isn't Python's default thread pool, which has 12 workers on this
     machine.
3. **Call size doesn't change the pattern.** 4K × 12 calls carry 2.8× the tokens of 1K × 6.
   Server times differ by about 20–40 ms, and the k = 8 burst durations are nearly the same
   (785 against 767 ms for the last finisher).

## Which mechanism the data favours

| Mechanism | What it predicts here | Observed | Verdict |
|---|---|---|---|
| **Per-call token-rate pacing at Tier 1's 1M tokens a minute** (16.7K tokens a second, applied to every call regardless of load) | Completions spaced about 387 ms apart at 4K × 12 and about 138 ms at 1K × 6; an 8-call burst taking at least 3.1 s and 1.1 s; spacing scaling 2.8× with size | Server time flat in k; median gap between completions 6–33 ms; 8-call bursts about 0.77 s at both sizes | **Strongly disfavoured.** Pacing at a rate many times Tier 1 can't be excluded, but it wouldn't matter at Tier 1 volumes |
| **Smoothing that engages only near the quota** (for example a token bucket with burst capacity) | Nothing at this occupancy: a burst of up to about 52K tokens is admitted untouched | - | **Not tested.** Window occupancy at release was 6–18% here, against about 69% in the sweep |
| **Per-key (or per-project) concurrency limit at or below 8** | A staircase with steps of about one service time (about 430 ms); the 8th completion at about 3.4 s; server time rising with finishing rank | No staircase; server time flat across ranks and k | **Strongly disfavoured** at these levels and in this window. A limit above 8 isn't tested |
| **Client-side effects** | Delays before the request is sent, with normal server time | Exactly this for the 7th and 8th calls at k = 8 | **Supported** for the k = 8 tail |

**What the earlier sweep showed is not reproduced.** Under truly simultaneous release, up to 8
overlapping calls from this key didn't slow each other on the server side. The sweep's
slowdown (p50 about 1–2 s at 3–6 in flight) and its warm-up bursts (staggered starts,
completions together) therefore remain unexplained.

The sweep and this test differ in three ways, and this data can't rank them:

| | Sweep (`m0-01-concurrency.md`) | This test |
|---|---|---|
| Release | Staggered by the throttle | Simultaneous |
| Token window at release (API tokens started in the previous 60 s) | About 690K, 69% of the limit, at every level | 6–18% |
| Time window | 21:25–21:35 UTC | 21:49–22:18 UTC |

Occupancy alone doesn't slow a single call: the sweep's levels 1–4 ran at about 69% and
stayed fast (p50 291–314 ms). Neither run tested **several overlapping calls at high
occupancy**, which is the production case for a busy key. So this result can't be read as
"concurrency is free on a key near its quota".

**What would still fit both readings:**
- Server-side behaviour that varies over time.
- Load-dependent behaviour, such as smoothing or queueing that engages only near the quota.
- A limit above 8 in flight.
- Smoothing applied per project at a rate far above our usage.

## What each candidate predicts for a second key in the same project

| Mechanism | A second key in the same project |
|---|---|
| Per-key concurrency limit | Would add capacity, but this data shows no limit at ≤ 8 |
| Per-project concurrency limit | Would add nothing, but none is seen at ≤ 8 |
| Token-rate smoothing per project | Would add nothing. Per-call pacing is strongly disfavoured; smoothing near the quota isn't tested |
| Client-side causes | Irrelevant: a second key wouldn't change the client |

**The binding constraint at Tier 1 is the per-minute token quota, not latency under
concurrency.** Per the design (§Multi-tenancy), it applies per Google project, so a second
key in the same project doesn't raise it. Capacity comes from more projects or a higher tier
(M3-08, M0-03).

## Practical findings

- **Connections go cold after 5 s.** With httpx's default `keepalive_expiry` of 5 s, any key
  idle for more than 5 s pays connection setup again.
  - The cost here: request sent about 70–100 ms after release, plus a slower first request.
    Solo calls took about 510 ms here against about 300 ms warm.
  - At Tier 1 traffic levels (under 2.6 calls a second per key for 4K × 12), gaps of more
    than 5 s are likely at quiet times.
  - **Recommendation for the adapter or gateway:** set a longer `keepalive_expiry` (for
    example 60 s), and consider keeping connections warm.
- **Opening many connections at once costs about 250 ms for some of them.** At 8 new
  connections, two requests went out about 250 ms late in 36 of 40 bursts. A gateway that bursts several guard
  points at once should reuse warm connections.

## What this run doesn't show

- **Warm-connection absolute latencies under bursts.** Every call here opened a new
  connection. A rerun with `keepalive_expiry` above the gap, or gaps under 5 s, would give
  them.
- **Behaviour above 8 in flight.**
- **Overlapping calls at high window occupancy** (about 70%), the case for a busy key. The
  reviewer's suggested follow-up is k = 4 and 8 bursts with the window pre-filled to about
  70% and warm connections.
- **Another time window, region or tier.** This is one 29-minute window.
- **The cause of the earlier sweep's slowdown.**
