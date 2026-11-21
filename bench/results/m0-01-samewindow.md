# M0-01: same-window burst rerun (R6.3 flat test), INCONCLUSIVE

**Result: INCONCLUSIVE.** The run stopped at its 4.5M-token cap with **10 solo, 9 k = 4 and 9 k = 8** measured bursts. The decision needs at least 10 bursts per k, so this isn't a pass or a fail for either level. As decided, it hasn't been rerun.

## Run

| | |
|---|---|
| When | 2026-11-17, 07:08:02–07:14:22 UTC (measured bursts 07:08:26–07:14:21) |
| Harness | `c2abe9a` on `m0-01-same-window` (`bench/latency.py hotbursts`) |
| Parameters (recorded in `run_started.hot`) | `--ks 1,4,8 --hot-rounds 10 --hot-gap-s 5 --dry-calls 10 --max-api-tokens 4500000` |
| Shape | 4K × 12 bursts (the text estimates at 3,999 raw tokens, so the 4K band applies), warm connections (keepalive 120 s, 0 new connections in measured calls), adapter called directly |
| Window | Filled by sequential 16K × 50 filler calls held at the throttle's limit; the next burst is released when there is room |
| Corpus | `floor/golden.jsonl`, 338 rows, 0 excluded (recorded) |
| Calls | 282, all answered: 10 dry, 8 warm-up, 118 measured, 146 filler. 0 refusals, 0 `rate_limited` |
| API input tokens | 4,507,975 |
| Raw data | `m0-01-samewindow.jsonl` (no content, headers or key) |

## Measurements (`warm-report`, verbatim)

```
Calls: 282 {'answered': 282}; API input tokens 4,507,975; stops: [('hot_4k12', 'token budget (4,500,000)')].

Failed measured calls by cell (excluded from the latency statistics below; connection timings still count):

- hot_4k12: 0 of 118 

### hot_4k12: 118 measured calls; new connections 0; window before release (API tokens) median 634,008, min 493,326, max 681,189

| k | Bursts | New conn. | Start spread ms (median / max) | Sent ms after release (median / max) | Bursts with late sends (> 150 ms after first) | Server time ms, pooled median [95% CI] | Completion by finishing order, median ms | Last completion ms (median) |
|--:|--:|--:|---|---|---|---|---|--:|
| 1 | 10 | 0 | 0.0 / 0.0 | 2 / 6 | 0 of 10 {0: 10} | 657 [609-858] | 661 | 661 |
| 4 | 9 | 0 | 5.3 / 12.3 | 11 / 32 | 0 of 9 {0: 9} | 619 [583-635] | 576, 631, 641, 733 | 733 |
| 8 | 9 | 0 | 8.9 / 29.3 | 19 / 50 | 0 of 9 {0: 9} | 691 [647-712] | 618, 631, 650, 707, 727, 772, 774, 1,063 | 1,063 |

### hot_4k12: R6.3 flat test against interleaved solo bursts

Budget for the shape without queue allowance: 825 ms. Clause 1: upper bound ≤ +200 ms. Clause 2: per-call p95 ≤ budget. Clause 3: no call over 1,650 ms and every call answered.

| k | Bursts (k / solo) | p50(k) - p50(solo) ms [95% cluster CI] | Clause 1 | Per-call p95 ms | Clause 2 | Slowest call ms | Unanswered | Clause 3 | Peak occupancy incl. the burst (median / max) |
|--:|---|---|---|--:|---|--:|--:|---|---|
| 4 | 9 / 10 | -31 [-247, +24] | pass | 862 | FAIL | 905 | 0 | pass | 66.1% / 68.5% |
| 8 | 9 / 10 | +44 [-167, +156] | pass | 1,092 | FAIL | 1,706 | 0 | FAIL | 68.0% / 68.1% |

### hot_4k12 filler: 146 calls, 3,475,327 API tokens; wall median 800 ms; window before each filler call median 654,752
```

**Per-call wall time by k**, computed from the raw records:

| k | Calls | p50 | p95 | Max |
|--:|--:|--:|--:|--:|
| 1 (solo) | 10 | 663 ms | 951 ms | 951 ms |
| 4 | 36 | 632 ms | 857 ms | 905 ms |
| 8 | 72 | 707 ms | 1,092 ms | 1,706 ms |

Sequential 16K × 50 calls in the same window: the dry cell's median was 853 ms (window filling) and the filler's was 800 ms (window held at about 65%).

## Interpretation

Everything above is measurement. This section is my reading of it.

1. **Not enough bursts for a verdict.** The table's clause results are shown, but with 9 bursts at k = 4 and k = 8 they don't meet the decision's minimum of 10. The token cap bound because the filler keeps the window near 700K tokens a minute for the run's whole length. About 6.3 minutes was enough for 28 of the 30 planned bursts.
2. **This window was much slower than the earlier ones, for every call shape, including solo.** Solo 4K × 12 calls had a median of 663 ms here, against about 443 ms at 01:46 UTC and 285 ms in the 2026-11-16 soak. Sequential 16K × 50 calls had a median of 800–853 ms, against 580–607 ms at 02:31 UTC and 469 ms on 2026-11-16. The solo calls' own p95 (951 ms, from only 10 calls) is above the 825 ms budget. So clause 2 failing at k = 4 is about this time window, not about concurrency.
3. **Within the window, overlap cost little at the median.** p50(k) − p50(solo) was −31 ms at k = 4 and +44 ms at k = 8. Both 95% cluster intervals have upper bounds under +200 ms (+24 and +156), but the solo arm is only 10 bursts, so the intervals are wide.
4. **The k = 8 tail is the one concurrency signal here.** At k = 8, per-call p95 was 1,092 ms and one call took 1,706 ms, above twice the budget (1,650 ms). In the median burst, the last of the 8 completions came at 1,063 ms against 707–774 ms for the 5th to 7th. That fits the earlier hot run, where the k = 8 tail was also the clause that failed (938 ms). It's one window and 9 bursts.
5. **Peak occupancy reached 68.5%** (k = 4) and 68.1% (k = 8), including each burst's own tokens. Nothing above about 68.5% has been tested.

**What would settle it:** the same design with enough bursts per k. With a 4.5M cap that means fewer filler tokens per minute (a lower pre-fill target), or a higher cap of about 5M for 10 bursts per k. Given point 2, it should also be read against a budget that reflects the slow window. Whether and how to rerun is a decision for the maintainer.
