# M1 gate simulation, live: both runs

The simulation is capped at 100 conversations (user). It ran twice, once each, through
`build_engine`, golden attack rows only (14%), all stops on, no held-out or excluded row sent
(`heldout_rows_sent: 0`), and no key value or header name in either results file.

| | Run 1 (`m1-gate-sim.jsonl`) | Run 2 (`m1-gate-sim-2.jsonl`) |
|---|---|---|
| Started | 2026-11-17 15:52:45 UTC | 2026-11-17 17:37:42 UTC |
| Conversations | 31 complete (a 32nd started) | 69, all complete |
| Start of each conversation | every 60 s: **the same second of every minute (:45)** | every 77 s: **17 s later in the minute each time**, so every second of the minute is sampled |
| Checks | 158 of 500 planned (stopped on `failures`: 11 of the last 50) | 345 of 345 |
| Provider calls | 197 (ceiling 600) | 359 (ceiling 400) |
| Input tokens (provider-reported) | 110,008 | 270,416 |
| Failed checks | 18, all `timeout` blocks (first attempt cancelled at its deadline, the retry too) | **0** |
| Checks started at :55-:09 | 8 blocked of 14 | 0 of 92 |
| Checks started elsewhere in the minute | 10 blocked of 144 (all at :46-:54) | 0 of 253 |
| Engine overhead p95 | 2 ms | 1 ms |
| Cold-call rate | 28.9% | 23.1% |
| Day tally after it (UTC 2026-11-17) | about 5,882 | about 8,802 with the held-out run's 2,561 |

Combined, the 503 checks that ran: 556 provider calls, 380,424 input tokens.

## The five gate items

1. **Engine overhead p95 ≤ 50 ms: pass** in both runs and combined (p95 2 ms, max 16 ms).
2. **Per-shape p50 within 20% of the R6.3 expectation (one-sided): pass** in both runs and combined
   (combined ratios 0.85 to 1.14; run 2 alone 0.84 to 1.20, `input` at the edge at 1.20).
   p95 against the attempt deadline is information: 1.0 to 1.95 combined, driven by run 1.
3. **Timeout blocks outside slow episodes ≤ 0.5%: not demonstrated.**
   Run 1: 11/148 outside its two slow-episode minutes. Run 2: 0/345 (upper bound 0.9%).
   Combined: 11/493 (2.2%, upper bound 3.7%): over the limit. Even a clean 503 checks can't show
   0.5% (the bound would be about 0.6%). So the harness cannot pass this item at this size.
4. **Slow episodes (U7):** two one-minute episodes, both in run 1 (15:54 and 16:19 UTC). None in run 2.
5. **Cold-call rate:** 140/556 = 25.2% (upper bound 28.4%) combined. Over 20% with conversations
   starting every 60 or 77 s, which are *less* often than the 60 s keepalive window, so the
   "traffic more often than every 60 s" condition for revisiting M1-10 is not met here.

## What the two runs say about the stalls (R7.4)

* Run 1 put every check in seconds :45-:05 of the minute, and 18 of its 158 failed, all at
  :46-:59 or :03. Run 2 spread the same kind of traffic over the whole minute and **nothing
  failed in 345 checks, none of the 92 that started in the :55-:09 window**.
* So the minute boundary alone does not explain the failures. What this cannot separate is **time
  of day** (the provider or network path was slow in run 1's window, 15:52-16:23, in bursts, and
  fine from 17:37 to 19:05) from **phase** (a fixed second in the minute, as in the R7.4
  diagnostic, where the stalls were at the top of the minute). Run 1's failures also came in
  bursts (16:18-16:20 had 10 of its 18), which looks more like episodes than a clock phase.
* Run 2's 77 s spacing means a conversation's first call finds the pooled connection idle for
  about 70 s, which is why 23% of calls open a new connection; those did not stall either.
* To separate the two explanations needs a third run that holds one phase (as run 1 did) at a
  time when the provider is known to be healthy, or a longer run sampling all phases. The
  100-conversation cap is spent, so that is a decision for the user.

`late` conversations in the report below mean the next one started 0.05-0.08 s after its slot
(sleep jitter), not that one overran another. The per-run reports follow, then the two combined.

Other work ran on the host during run 2 (full test suites, including throwaway Postgres
containers, for about 20 minutes in total); engine overhead stayed at p95 1 ms.

---

## m1-gate-sim.jsonl

### Gate simulation

- 158 checks run of 500 planned (100 conversations, one every 60.0 s); 140 answered, 18 failed; 197 provider calls; stops: ['failures'].
- Mix, fixed before the run: 70 attack checks (14%) from the floor golden (held-out rows are reserved and never sent), by guard point {'input': 14, 'output': 14, 'plan': 14, 'tool_call': 14, 'tool_result': 14}; the rest scripted benign. Benign blocked or escalated: 0 / 0 of 122 answered; attack rows blocked or escalated: 18 / 0 of 18 answered (information, not a gate item).
- 31 conversations started late (the previous one overran).

#### (1) Engine overhead (check wall time minus gateway time)

- 158 checks that called the model: p50 1 ms, **p95 2 ms**, max 9 ms. Gate: ≤ 50 ms p95: **pass**.

#### (2) End-to-end, against the R6.3 expectation

- All 140 answered checks: p50 663 ms, **p95 2,214 ms**; mean expected p50 630 ms. Gate (decided 2026-11-17): every shape's p50 within 20% of its R6.3 expected p50 (band base + 380 ms + 2.0 ms per question), read one-sidedly (faster passes); shapes with fewer than 5 checks are not judged. **pass.** p95 against the attempt deadline is information.

| Guard point | Band base (ms) | Checks | p50 (ms) | Expected p50 | p50 ÷ expected | Result | p95 (ms) | Attempt deadline | p95 ÷ deadline (info) |
|---|--:|--:|--:|--:|--:|---|--:|--:|--:|
| input | 244 | 30 | 651 | 630 | 1.03 | pass | 1,037 | 1,030 | 1.01 |
| output | 244 | 27 | 671 | 628 | 1.07 | pass | 2,648 | 1,028 | 2.58 |
| plan | 244 | 28 | 643 | 630 | 1.02 | pass | 2,214 | 1,030 | 2.15 |
| tool_call | 244 | 29 | 707 | 630 | 1.12 | pass | 2,027 | 1,030 | 1.97 |
| tool_result | 244 | 26 | 700 | 630 | 1.11 | pass | 1,903 | 1,030 | 1.85 |

#### (3) Timeout blocks outside slow episodes

- 11/148 (7.4%; ≤ 12.0%) of checks outside episodes ended in a `timeout` or `unavailable` block (all checks: 18). Gate: ≤ 0.5%. **Over the limit.** Other failed checks: 0.

#### (4) Slow episodes (U7)

| Start (UTC minute) | End | Minutes | Checks | Blocked checks |
|---|---|--:|--:|--:|
| 2026-11-17T15:54Z | 2026-11-17T15:54Z | 1 | 5 | 2 |
| 2026-11-17T16:19Z | 2026-11-17T16:19Z | 1 | 5 | 5 |

#### Where in the minute (information, not a gate item)

- Checks that started at :55-:09: 8/14 ended in a timeout or `unavailable` block (57.1%).
- Checks that started at :10-:54: 10/144 ended in a timeout or `unavailable` block (6.9%).

#### (5) Cold-call rate

- 57/197 (28.9%; ≤ 34.7%) of provider calls opened a new connection (197 calls; 0 unknown). Revisit M1-10's keepalive if over 20% while traffic arrives more often than every 60 s (here a conversation starts every 60.0 s, its checks 1.0 s apart).

## m1-gate-sim-2.jsonl

### Gate simulation

- 345 checks run of 345 planned (69 conversations, one every 77.0 s); 345 answered, 0 failed; 359 provider calls; stops: none.
- Mix, fixed before the run: 50 attack checks (14%) from the floor golden (held-out rows are reserved and never sent), by guard point {'input': 10, 'output': 10, 'plan': 10, 'tool_call': 10, 'tool_result': 10}; the rest scripted benign. Benign blocked or escalated: 0 / 0 of 295 answered; attack rows blocked or escalated: 48 / 2 of 50 answered (information, not a gate item).
- 68 conversations started late (the previous one overran).

#### (1) Engine overhead (check wall time minus gateway time)

- 345 checks that called the model: p50 0 ms, **p95 1 ms**, max 16 ms. Gate: ≤ 50 ms p95: **pass**.

#### (2) End-to-end, against the R6.3 expectation

- All 345 answered checks: p50 586 ms, **p95 956 ms**; mean expected p50 630 ms. Gate (decided 2026-11-17): every shape's p50 within 20% of its R6.3 expected p50 (band base + 380 ms + 2.0 ms per question), read one-sidedly (faster passes); shapes with fewer than 5 checks are not judged. **pass.** p95 against the attempt deadline is information.

| Guard point | Band base (ms) | Checks | p50 (ms) | Expected p50 | p50 ÷ expected | Result | p95 (ms) | Attempt deadline | p95 ÷ deadline (info) |
|---|--:|--:|--:|--:|--:|---|--:|--:|--:|
| input | 244 | 69 | 753 | 630 | 1.20 | pass | 2,011 | 1,030 | 1.95 |
| output | 244 | 69 | 526 | 628 | 0.84 | pass | 781 | 1,028 | 0.76 |
| plan | 244 | 69 | 575 | 630 | 0.91 | pass | 897 | 1,030 | 0.87 |
| tool_call | 244 | 69 | 554 | 630 | 0.88 | pass | 873 | 1,030 | 0.85 |
| tool_result | 244 | 69 | 614 | 630 | 0.97 | pass | 945 | 1,030 | 0.92 |

#### (3) Timeout blocks outside slow episodes

- 0/345 (0.0%; ≤ 0.9%) of checks outside episodes ended in a `timeout` or `unavailable` block (all checks: 0). Gate: ≤ 0.5%. **Within the limit as measured, but 345 checks cannot show the rate is ≤ 0.5% (the bound is 0.9%).** Other failed checks: 0.

#### (4) Slow episodes (U7)

- None: no run of minutes with at least 25% of checks (of at least 5) ending in a timeout or `unavailable` block.

#### Where in the minute (information, not a gate item)

- Checks that started at :55-:09: 0/92 ended in a timeout or `unavailable` block (0.0%).
- Checks that started at :10-:54: 0/253 ended in a timeout or `unavailable` block (0.0%).

#### (5) Cold-call rate

- 83/359 (23.1%; ≤ 27.1%) of provider calls opened a new connection (359 calls; 0 unknown). Revisit M1-10's keepalive if over 20% while traffic arrives more often than every 60 s (here a conversation starts every 77.0 s, its checks 1.0 s apart).

## All runs combined

### Gate simulation

- 503 checks run of 845 planned (101 conversations, one every 60.0 and 77.0 s); 485 answered, 18 failed; 556 provider calls; stops: ['failures'].
- Mix, fixed before the run: 120 attack checks (14%) from the floor golden (held-out rows are reserved and never sent), by guard point {'input': 24, 'output': 24, 'plan': 24, 'tool_call': 24, 'tool_result': 24}; the rest scripted benign. Benign blocked or escalated: 0 / 0 of 417 answered; attack rows blocked or escalated: 66 / 2 of 68 answered (information, not a gate item).
- 99 conversations started late (the previous one overran).

#### (1) Engine overhead (check wall time minus gateway time)

- 503 checks that called the model: p50 1 ms, **p95 2 ms**, max 16 ms. Gate: ≤ 50 ms p95: **pass**.

#### (2) End-to-end, against the R6.3 expectation

- All 485 answered checks: p50 612 ms, **p95 1,710 ms**; mean expected p50 630 ms. Gate (decided 2026-11-17): every shape's p50 within 20% of its R6.3 expected p50 (band base + 380 ms + 2.0 ms per question), read one-sidedly (faster passes); shapes with fewer than 5 checks are not judged. **pass.** p95 against the attempt deadline is information.

| Guard point | Band base (ms) | Checks | p50 (ms) | Expected p50 | p50 ÷ expected | Result | p95 (ms) | Attempt deadline | p95 ÷ deadline (info) |
|---|--:|--:|--:|--:|--:|---|--:|--:|--:|
| input | 244 | 99 | 718 | 630 | 1.14 | pass | 2,011 | 1,030 | 1.95 |
| output | 244 | 96 | 535 | 628 | 0.85 | pass | 1,734 | 1,028 | 1.69 |
| plan | 244 | 97 | 586 | 630 | 0.93 | pass | 1,615 | 1,030 | 1.57 |
| tool_call | 244 | 98 | 589 | 630 | 0.93 | pass | 1,027 | 1,030 | 1.00 |
| tool_result | 244 | 95 | 633 | 630 | 1.00 | pass | 1,660 | 1,030 | 1.61 |

#### (3) Timeout blocks outside slow episodes

- 11/493 (2.2%; ≤ 3.7%) of checks outside episodes ended in a `timeout` or `unavailable` block (all checks: 18). Gate: ≤ 0.5%. **Over the limit.** Other failed checks: 0.

#### (4) Slow episodes (U7)

| Start (UTC minute) | End | Minutes | Checks | Blocked checks |
|---|---|--:|--:|--:|
| 2026-11-17T15:54Z | 2026-11-17T15:54Z | 1 | 5 | 2 |
| 2026-11-17T16:19Z | 2026-11-17T16:19Z | 1 | 5 | 5 |

#### Where in the minute (information, not a gate item)

- Checks that started at :55-:09: 8/106 ended in a timeout or `unavailable` block (7.5%).
- Checks that started at :10-:54: 10/397 ended in a timeout or `unavailable` block (2.5%).

#### (5) Cold-call rate

- 140/556 (25.2%; ≤ 28.4%) of provider calls opened a new connection (556 calls; 0 unknown). Revisit M1-10's keepalive if over 20% while traffic arrives more often than every 60 s (here a conversation starts every 60.0 and 77.0 s, its checks 1.0 s apart).
