# M1 gate simulation, live run (stopped early)

Run on main a8e30dd, once, 2026-11-17 15:52:45–16:23:53 UTC, through `build_engine`, golden attack
rows only (14%), all stops on, ceiling 600 provider calls. **It stopped at 158 of 500 checks (31
of 100 conversations) on the failures stop** (11 of the last 50 checks failed, more than 20%). It
was not resumed. Calls: 197 provider calls this run (ceiling 600). Input tokens reported by the
provider: 110,008 over the answered checks (ceiling 797,926). The results file holds no key value
and no request header names.

## What the stop shows

- All 18 failed checks are `timeout` blocks: the first attempt was cancelled at its deadline
  (~1,034 ms) and the retry was cancelled too (~3,000 ms in all; ~4,000 ms for the two `input`
  checks, whose deadline allows one more second). Nothing else failed: no refusal, auth or
  unclassified failure.
- **Every check in the run fell in clock seconds :45–:05.** The run began at 15:52:45 and a
  conversation starts every 60 s, so each conversation's five checks (about 4 s apart) straddled
  the minute boundary. The planned phase was never varied, so the run could not see traffic away
  from the boundary. Of 158 checks, 158 started in that window and 18 failed (11.4%); there are
  none outside it to compare with. Failure seconds: :46–:59 (16 checks) and :03 (2).
- Two blocks of failures: 15:54–16:08 scattered single failures (7 over 15 minutes), then two
  bursts at 16:18–16:20 (10 failures in 3 minutes, all five checks of two conversations plus one
  more) and one at 16:23 that tripped the stop.
- This matches R7.4/M0-02 (stalls follow the clock minute, not connection age), and it is the
  state the production engine would be in if traffic arrived at that phase. It says nothing about
  traffic at other phases; the gate as built cannot separate the two.

## Gate items (as the harness computes them over the 158 checks)

| # | Item | Result |
|---|---|---|
| 1 | Engine overhead p95 ≤ 50 ms | **pass**: p50 1 ms, p95 2 ms, max 9 ms |
| 2 | Per-shape p50 within 20% of the R6.3 expectation (one-sided) | **pass** on all five shapes (ratios 1.02–1.12); p95 is information: 1.01–2.58 × the attempt deadline |
| 3 | Timeout/unavailable blocks outside slow episodes ≤ 0.5% | **over the limit**: 11/148 (7.4%; upper bound 12.0%); but see below |
| 4 | Slow episodes (U7) | 2 episodes of 1 minute each (15:54 and 16:19) |
| 5 | Cold-call rate | 57/197 (28.9%; upper bound 34.7%); revisit keepalive if over 20% with traffic more often than every 60 s |

On (3): the episode rule needs five checks in a minute, and a conversation puts only five checks
in one minute at the boundary, so the episode minutes are the only ones the rule can see. The 11
"outside" blocks sit in minutes with one or two failures out of five. The number does not mean
the engine blocks 7% of traffic generally: it means 7.4% of checks started at :45–:05 blocked.
The 0.5% bound is not testable from this run.

## Report code fixes made after the run

The report code (not the run) had two bugs, found while reading these results and fixed in the same
branch with a test: the join of a check's slot record and its call record let the call's `kind`
(null, or `timeout`) overwrite the slot's `benign`/`attack`, so the mix counts read 0 of 0; and
"planned" counted checks started rather than the plan. Failed checks (fail-closed blocks) are no
longer counted as verdicts in the mix counts.

## Notes

- Targeted offline test runs for M2-01 (including a throwaway Postgres container) ran on the same
  host while the simulation was live; the full suite was held back until it ended. The engine
  overhead measured here (p95 2 ms) shows no sign of interference.
- The attack rows in the mix are the golden's; no held-out row and no excluded or harm row was
  sent (`heldout_rows_sent: 0` in `run_started`).

## Harness report

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

#### (5) Cold-call rate

- 57/197 (28.9%; ≤ 34.7%) of provider calls opened a new connection (197 calls; 0 unknown). Revisit M1-10's keepalive if over 20% while traffic arrives more often than every 60 s (here a conversation starts every 60.0 s, its checks 1.0 s apart).
