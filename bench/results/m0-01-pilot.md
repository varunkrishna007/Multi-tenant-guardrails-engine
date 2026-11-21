# M0-01 latency profile: pilot

Run 2026-11-16, 16:40:02–17:14:59 UTC. Model `gemini-decision-1`, called through
`GeminiDecisionModel` (httpx, HTTP/1.1, one reused client per cell).

Raw per-call records: `m0-01-pilot.jsonl` (sizes, timings, outcomes and token counts only).
Command: see `bench/README.md`.

**Origin:** one machine in one location (local timezone IST). The backlog's "two regions"
isn't done. A deployment in the API's own region would see a smaller network share; the
detail run measures that share (`m0-01-detail.md`).

**Sequential, one client.** Except the 8-concurrent cell, every call was made by one client
waiting for the previous one. Latency at production concurrency isn't measured here; see
`m0-01-concurrency.md`.

*Corrected: p99 isn't quoted on 30-call cells and p95 is indicative;
the concurrency finding and the slow episode's cause are stated with their uncertainty.*

**Design:** sequential calls on a warm connection after 3 discarded warm-ups. 30 measured
calls per cell. Inputs are synthetic, built from `floor/golden.jsonl` and varied per call.
Questions are the six floor rules plus templated variants with both descriptions, about
88 estimated or about 107 API tokens each.

## Results

Wall time around `decide()` in ms, measured calls only. Est./API is `estimate_tokens` over
the API's `usage.total_input_tokens`.

| Cell | Calls | OK | Failed | p50 | p95 (indicative) | min | max | API tokens | Est./API |
|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|
| connect (fresh client, 1K × 1) | 3 | 3 | 0 | 354 | 477 | 347 | 491 | 1,386 | 0.87 |
| 1K × 1 | 30 | 30 | 0 | 290 | 356 | 222 | 397 | 1,505 | 0.80 |
| 4K × 1 | 30 | 30 | 0 | 282 | 410 | 251 | 742 | 5,096 | 0.83 |
| 8K × 1 | 30 | 30 | 0 | 353 | 464 | 292 | 673 | 9,857 | 0.83 |
| 16K × 1 | 30 | 30 | 0 | 397 | 575 | 369 | 687 | 19,426 | 0.83 |
| 1K × 50 | 30 | 30 | 0 | 335 | 504 | 302 | 532 | 6,481 | 0.80 |
| 4K × 50 | 30 | 30 | 0 | 388 | 472 | 349 | 701 | 10,076 | 0.82 |
| 8K × 50 | 30 | 30 | 0 | 473 | 563 | 380 | 682 | 14,860 | 0.82 |
| 16K × 50 | 30 | 30 | 0 | 553 | 1,561 | 448 | 2,593 | 24,420 | 0.83 |
| 1K × 200 | 30 | 30 | 0 | 698 | 1,373 | 624 | 2,127 | 22,157 | 0.81 |
| 4K × 200 | 30 | 30 | 0 | 738 | 988 | 660 | 1,104 | 25,729 | 0.81 |
| 8K × 200 | 30 | 27 | 3 timeout | 2,286 | 9,013 | 711 | 10,499 | 30,531 | 0.82 |
| 16K × 200 | 30 | 30 | 0 | 848 | 1,028 | 763 | 1,915 | 40,091 | 0.82 |
| 1K × 900 | 30 | 29 | 1 timeout | 2,707 | 3,874 | 2,448 | 5,555 | 99,167 | 0.81 |
| 4K × 900 | 30 | 30 | 0 | 2,745 | 2,995 | 2,522 | 3,161 | 102,726 | 0.81 |
| 8K × 900 | 30 | 30 | 0 | 2,725 | 2,867 | 2,584 | 2,897 | 107,540 | 0.81 |
| 16K × 900 | 30 | 30 | 0 | 3,002 | 3,711 | 2,599 | 4,115 | 117,102 | 0.82 |
| 4K × 50, 8 concurrent | 30 | 30 | 0 | 770 | 1,116 | 378 | 1,874 | 10,080 | 0.81 |

**Totals:**
- Calls: 564, of which 51 were warm-ups. A separate 18-call smoke run validated the harness
  beforehand.
- API input tokens: 21.16M, about $2.12 at $0.10 per 1M.
- Outcomes: 0 `rate_limited`, 0 `auth`, 0 safety blocks, 0 answer problems. There were
  4 `timeout`s, all at the adapter's 10 s transport backstop.

## What the pilot shows

1. **No cell meets p95 ≤ 300 ms from this machine.**
   - The best cell is 1K × 1: p50 290 ms, p95 356 ms.
   - The fastest single call of the run took 222 ms.
   - The design's 150–250 ms claim isn't reproduced here. How much of the gap is network
     distance is the detail run's baseline question.
2. **Latency follows question count, and input size matters much less.**
   - At 4K input, p50 by question count: 1 gives 282 ms; 50 gives 388; 200 gives 738;
     900 gives 2,745.
   - At one question, p50 across 1K–16K input moves only from 282 to 397 ms.
   - "Nearly flat from 1 to 100 questions" doesn't hold. 50 questions already costs about
     +100 ms, and 200 costs about +450 ms.
   - 900 questions costs about 2.7–3.0 s whatever the input size.
3. **Concurrency from one key:** 8 concurrent 4K × 50 calls had p50 770 ms (95% CI
   654–908) against 388 ms (376–415) sequential, about 2×. The cause isn't established: the
   client's connection handling, or queueing per key or project. The detail run's 2- and
   4-concurrent cells and the dedicated sweep (`m0-01-concurrency.md`) say more.
4. **Connection setup** adds about 65 ms over a warm call: fresh client p50 354 ms against
   290 ms.
5. **The estimator undercounts, consistently.**
   - The API reports about 1.22× `estimate_tokens` in every cell (Est./API 0.80–0.87).
   - So the compiler's AC-C1.8 budget check (16,000 tokens) is about 20% optimistic: a
     16,000-token estimate is about 19,500 real tokens.
   - The detail run splits the ratio into input-text and question-text parts.

## Tail events

Under the 400 ms per-guard-point budget, each of these calls would have been a gateway
timeout. Floor rules then fail closed (B1), so the check blocks.

**A slow period of about 2.5 minutes, 16:47:12–16:49:35 UTC (8K × 200 cell).**
- From measured call 4 to call 29, 22 of 26 calls took over 2 s: 2.0–21.3 s, with
  3 timeouts.
- The cell's own normal speed is 0.7–1.1 s; its neighbours' p50s are 738 ms and 848 ms.
- The latency decayed over the period: about 10 s at 16:47–16:48, then 2–5 s by 16:49.
- **Cause not established.** Nothing measured during the episode separates the provider
  from the local network or ISP path, or from this run's own load (calls of up to 117K
  tokens at about 70% of the per-minute token limit). No baseline ran at the time.

| Time (UTC) | Call | Latency |
|---|---|---|
| 16:47:12.9 | 4 | timeout (21,285 ms: 10 s backstop on connect and read) |
| 16:47:34.5 | 5 | 6,038 |
| 16:47:41.0 | 6 | timeout (10,026) |
| 16:47:51.4 | 7 | 10,499 |
| 16:48:02.2 | 8 | 8,518 |
| 16:48:12.5 | 10 | timeout (10,022) |
| 16:48:22.8 – 16:48:45.6 | 11–14 | 3,877 – 9,202 |
| 16:48:54.4 – 16:49:19.3 | 15–22 | 2,010 – 5,549 |
| 16:49:30.5 – 16:49:35.0 | 28–29 | 4,146, 2,286 |

**Isolated slow calls:**
- 16:43:32 and 16:43:41: 16K × 50 calls 1 and 5, 2,078 and 2,593 ms. These make that cell's
  fat tail (p95 1,561).
- 16:44:48: 1K × 200 call 4, 2,127 ms.
- 16:52:58: 1K × 900 call 5, a timeout at 10 s against a cell p50 of 2.7 s.

If episodes like this one come from the provider, a hedged duplicate request probably
wouldn't rescue them, since the calls that followed were slow too. One episode doesn't
establish that. 30 calls per cell can't size how often such periods happen; the tail soak
(`m0-01-soak.md`) is designed for that.

## What the pilot doesn't show

- **Latency at production concurrency.** Every cell but one is one sequential client.
- **Percentiles are thin.** Each cell has 30 calls, so p99 is close to the maximum and p95
  rests on one or two calls. The backlog asks for 500 per cell, and that full run hasn't
  been made.
- **Network versus model time.** The detail run's baseline separates these.
- **A second region.** Not measured.
- **Questions below 50.** The detail run adds 6, 12, 25 and 100.
- **Whether latency follows question count or total question tokens.** The detail run
  tests this.
