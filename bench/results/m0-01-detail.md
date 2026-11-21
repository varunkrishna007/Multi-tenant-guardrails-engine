# M0-01 latency profile: detail run and network baseline

Run 2026-11-16, 20:18:19–20:30:40 UTC. Model `gemini-decision-1` through
`GeminiDecisionModel` (httpx, HTTP/1.1, one reused client per cell). 30 measured calls per
cell after 3 discarded warm-ups. Inputs and questions are built as in the pilot
(`m0-01-pilot.md`).

Raw records: `m0-01-detail.jsonl`. They contain no content, no headers and no key; the
baseline used a made-up key. Command: `bench/latency.py detail` (see `bench/README.md`).
Reproduce the tables with `uv run python bench/latency.py report bench/results/m0-01-detail.jsonl`.

**Totals:** 726 model calls, all answered: 0 failures, 0 `rate_limited`, 0 `auth`. 8.39M API
input tokens, about $0.84. Plus 34 baseline requests, which do no model work.

**These numbers come from one machine in one location (local timezone IST), with one client
making sequential calls** (except §4). A deployment in another region, or inside Google
Cloud, would see a different baseline. Latency at production concurrency is not measured
here; see `m0-01-concurrency.md`.

*Corrected: "net" figures are relabelled as an upper bound
on time beyond Google's edge, not model time; net-p95 columns are dropped; p99 is not quoted
on 30-call cells and p95 is marked indicative; the concurrency section gives the measured
effect with its uncertainty.*

## 1. Network baseline

The baseline uses plain httpx with a made-up key. Google answers HTTP 400
`API_KEY_INVALID` without running the model, so the request measures round trip plus
Google's front end.

| Measure | Value |
|---|---|
| Host | `generativelanguage.googleapis.com` |
| DNS lookup | 11 ms; 8 IPv4 addresses (172.217.112.4–172.217.119.4) and 8 IPv6 |
| Connected to | 172.217.119.4:443 (reverse DNS gave no name, so no location is inferred) |
| TCP connect (cold) | **14 ms** |
| TLS handshake (cold) | 39 ms |
| First response headers (cold) | 248 ms after the request was sent |
| Cold first request, total | 344 ms |
| Protocol | HTTP/1.1 (the adapter uses httpx without HTTP/2) |
| **Warm round trip, 30 requests** | **p50 72 ms, p95 202 ms** (min 52, max 222) |

- A 14 ms TCP connect means Google's front end is near this machine. Where the model itself
  runs is not observable from here.
- The warm baseline is bimodal: 26 of 30 requests took 52–150 ms, and 4 took 176–222 ms.
- **What the baseline measures:** a tiny body with an invalid key, so the round trip to
  Google's edge plus an early key rejection. It does **not** split model time from the rest.
- In the tables below, **"raw − baseline median"** is the raw p50 minus the baseline p50
  (72 ms). It is an **upper bound on time spent beyond Google's edge**: uploading the body,
  key lookup, quota checks, routing to the serving backend, inference and serialisation.
  It is not the model's own time. Percentiles don't subtract, so no p95 version is given.

## 2. Question count × input size

Wall time around `decide()` in ms.

| Input | Questions | p50 [95% CI] | p95 (indicative) | max | raw − baseline median | API tokens |
|---|--:|--:|--:|--:|--:|--:|
| 1K | 6 | **261** [258–267] | **276** | 290 | ≤ 190 | 2,287 |
| 1K | 12 | 264 [256–275] | 326 | 419 | ≤ 192 | 2,889 |
| 1K | 25 | 282 | 427 | 507 | ≤ 210 | 4,099 |
| 1K | 50 | 349 | 421 | 424 | ≤ 277 | 6,481 |
| 1K | 100 | 450 | 594 | 707 | ≤ 378 | 11,625 |
| 1K | 200 | 657 | 832 | 902 | ≤ 585 | 22,157 |
| 4K | 6 | 274 [269–280] | 331 | 448 | ≤ 202 | 5,869 |
| 4K | 12 | 317 [283–327] | 352 | 372 | ≤ 245 | 6,442 |
| 4K | 25 | 322 [305–338] | 499 | 562 | ≤ 250 | 7,708 |
| 4K | 50 | 364 | 400 | 513 | ≤ 293 | 10,076 |
| 4K | 100 | 469 | 543 | 570 | ≤ 398 | 15,182 |
| 4K | 200 | 684 | 758 | 870 | ≤ 612 | 25,729 |
| 8K | 6 | 322 | 457 | 481 | ≤ 250 | 10,678 |
| 8K | 12 | 338 | 446 | 495 | ≤ 266 | 11,243 |
| 8K | 25 | 363 | 455 | 530 | ≤ 292 | 12,473 |
| 8K | 50 | 435 | 521 | 669 | ≤ 364 | 14,860 |
| 8K | 100 | 566 | 731 | 1,160 | ≤ 495 | 19,972 |
| 8K | 200 | 692 | 840 | 913 | ≤ 620 | 30,530 |

**Linear fit of p50 against question count:**
- 1K input: 244 ms + 2.07 ms per question
- 4K input: 271 ms + 2.07 ms per question
- 8K input: 326 ms + 1.96 ms per question

So each extra question costs about 2 ms at any input size. Input size adds about 10 ms per
1K tokens of content.

**How many questions fit under 300 ms, end to end, from this machine** (30 calls per cell,
so p95 rests on one or two calls; intervals are bootstrap 95%):
- **p95 ≤ 300 ms:** only 1K × 6 is clearly under (p95 276, CI 270–290). 1K × 12 (p95 326,
  CI 288–419) and 4K × 6 (p95 331, CI 294–448) straddle 300 and can't be placed on either
  side.
- **p50 ≤ 300 ms:** up to about 25 questions at 1K (282), 6 at 4K (274; 12 is 317, CI
  283–327), and none at 8K (322 at 6 questions).
- **Against the design's claim:** the claim is 150–250 ms **end to end**. From this machine
  it is not reproduced: the best cell's p50 is 261 ms and no cell's p95 is under 276 ms.
- **Beyond the edge:** time beyond an invalid-key rejection (raw minus the baseline median)
  is at most about 190–250 ms at ≤ 25 questions, 280–360 ms at 50, 380–500 ms at 100 and
  590–620 ms at 200. That is an upper bound on everything past Google's edge, not model
  time.

## 3. Count versus length (4K input)

| Questions | Question tokens (est. / API) | p50 | p95 (indicative) | raw − baseline median |
|---|---|--:|--:|--:|
| 50 with both descriptions | 4,214 / about 5,200 | 364 | 400 | ≤ 293 |
| 50 instructions only | 1,385 / about 2,600 | 350 | 414 | ≤ 278 |
| 100 instructions only, padded to match the 50 long ones | 4,342 / about 6,300 | 442 | 605 | ≤ 371 |

**Latency follows the number of questions, not their length.**
- Cutting the 50 questions to about a third of their tokens saves only 14 ms at p50.
- Doubling the count at the same total tokens adds 78 ms, in line with the about 2 ms per
  question slope.
- So rich descriptions are almost free in latency, and every extra question costs about
  2 ms. That argues for fewer, richer rules over many terse ones.

## 4. Concurrency from one key (4K × 25)

p50 with an order-statistic 95% interval. 30 calls per level.

| Concurrent calls | p50 [95% CI] | p95 (indicative) |
|---|---|--:|
| 1 (sequential) | 322 [305–338] | 499 |
| 2 | 353 [345–370] | 518 |
| 4 | 327 [314–422] | 591 |
| 8 (pilot, 4K × 50; its sequential cell: 388 [376–415]) | 770 [654–908] | 1,116 |

- **2 concurrent: +10% at p50**, measured; the intervals don't overlap.
- **4 concurrent:** the interval is too wide (314–422) to say whether p50 moved.
- **8 concurrent: p50 about doubled.** The cause isn't established: the client's own
  connection handling, or queueing per key or per project on Google's side.
- So splitting a guard point's rules across parallel calls has a measured cost at 2, an
  unknown one at 4 and a large one at 8. **All budget-relevant figures in these reports come
  from one client making sequential calls.** The dedicated sweep, `m0-01-concurrency.md`
  (1, 2, 4, 8 and 16 in flight at 4K × 12, 200 calls each), replaces this section's
  conclusions.

## 5. Estimator against the API's token count

`estimate_tokens` undercounts in every cell. Est./API ranges from 0.80 (question-heavy) to
0.88 (1K × 6), and is 0.72–0.74 for instructions-only questions.

| Fit | Formula |
|---|---|
| Two-term (the `report` command, over all 726 answered calls including warm-ups) | API ≈ 1.192 × est. text + 1.241 × est. questions + 81 |
| With a per-question term, over the 660 measured calls | API ≈ **1.196 × est. text + 0.963 × est. question text + 23 × questions + 28** |

- **One calibration factor isn't enough.** A single ×1.22 is off by between −15% and +12%
  per cell, and ×1.25 by −13% to +15%.
- The per-question fit explains the spread:
  - Input text needs ×1.20.
  - Question text is estimated about right.
  - Each question carries a fixed overhead of about 23 tokens that the estimator doesn't
    see. This is likely the API's own framing per key and type.
- **For the compiler's AC-C1.8 budget**, use `1.20 × text + question text + 25 per
  question` instead of the raw estimate. The 16,000 budget as written is optimistic by
  roughly 20%, and more for many short questions.

## What this run does and doesn't show

**It shows:**
- End to end, from this machine: best p50 261 ms (1K × 6); only 1K × 6 is clearly under
  300 ms at p95.
- At most about 190–250 ms beyond Google's edge at ≤ 25 questions (an upper bound, not
  model time).
- About 2 ms per question.
- Length barely matters; count does.
- 2 concurrent calls cost about +10% at p50; 8 roughly doubled it (cause unknown).
- The estimator needs a per-question term.

**It doesn't show:**
- Latency at production concurrency: everything except §4 is one sequential client. See
  `m0-01-concurrency.md`.
- How much of the time is the model itself. The baseline bounds it from above only.
- Tail behaviour or slow periods. 30 calls per cell, and no slow period occurred in these
  12 minutes. The soak (`m0-01-soak.md`) covers that.
- Another region.
- Whether HTTP/2 or connection pooling would reduce the baseline's 150–220 ms outliers.
