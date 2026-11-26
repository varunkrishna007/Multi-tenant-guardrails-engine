# M7-12 · The redaction trial: result of the one live attempt

**Outcome: the run stopped early and the trial is inconclusive.** One attempt was made, on 25 November 2026. 492 of the 822 planned checks were sent (draw 1 in full, draw 2 in part, draw 3 not at all). The stop rule "more than 20% of the last 50 checks failed" ended it. No usable rows exist under the trial's own rule (a row needs both arms to answer all three draws), so there is no verdict on whether redaction costs decision quality. The design is in [m7-12-redaction-trial-design.md](m7-12-redaction-trial-design.md), the harness in [m7-12-redaction-trial.md](m7-12-redaction-trial.md).

The records, the report and a descriptive draw-1 analysis are in `calibration/results/m7-12-trial-run1/`. A second attempt, with the pacing fixed, completed later the same day: [m7-12-results-2.md](m7-12-results-2.md).

## What was run

| | |
|---|---|
| Commit | `88573e203e8c17d662b427e685ffa8c44f1cfa4a`, detached worktree, clean |
| Manifest | 137 rows (54 affected positives, 43 affected benign, 20 + 20 placebo), 822 checks, row-set hash `sha256:e4f0c800b5c5f6269df1d461684a5545923c6c010411d8f6b3ba8690164c41a9` |
| Window | Approved for 08:00 to 10:00 UTC on 25 November. **The user moved it to start at 06:14 UTC (deadline 08:14:18 UTC).** The run started at 06:14:23 and stopped at 06:31:31. The arming script was a copy with the start set to now; nothing else differed. |
| Ceilings | 900 provider calls, 2.0 million input tokens |
| Used | 457 provider calls, 588,274 input tokens (of the planned 1.56 million) |

## What happened

- 444 of the 492 checks answered. 48 did not, all failures:
  - **45 `token_rate`**: refused by the engine's own token rate limiter before any provider call (`provider_calls` 0 on each). They fell on `plan` (21 checks), `tool_result` (16) and `tool_call` (11), and in both arms and both draws (all 22 failed checks of draw 1 were of this kind; draw 2 had 23 of them and the 3 timeouts).
  - **3 timeouts**, all in draw 2 (two `plan`, one `tool_call`), each after about 3.0 s and two provider calls (the gateway's own retry).
- **No provider refusals.** Nothing was blocked by the provider's filter. Every check that answered ended in `policy`.
- At check 492 (a draw-2 `placebo_positive` row) 11 of the last 50 had failed, and the runner stopped (exit 3). Nothing was resent, as designed. Draw 1 finished with 21 rows having a failed check. Draw 3 never ran, so no row has all three draws, the trial's own report finds 0 usable rows and the section-6 line is **inconclusive**.
- No harm-labelled content was sent: the manifest is the approved one, and the harness refuses any other.

## Which row of the design's table (section 6) applies

**Inconclusive** (reasons: no usable rows, so the loss of all rules together cannot be bounded under 10 points; 97 affected rows incomplete). None of keep, loss or false-positive rise can be claimed. The trial's own report is `report.md`.

## Descriptive look at draw 1 only (not the verdict)

The same analysis code run on draw 1 alone (`draw1-descriptive.md`): 116 rows had both arms answered in draw 1, and 21 had not.

- **Recall at `block_at`, all rules pooled** (42 affected-positive rows with a labelled rule): raw 97.6%, redacted 100.0%. 0 flips against redaction, 1 for it (on `p__ai_addressed`). The exact interval on the difference is [-12.6, +8.4] points, so it does not clear the 10-point margin even before the missing draws.
- **Per rule:** `p__exfil` 25 rows, 100% in both arms; `p__inj_indirect` 14 rows, 100% in both; `p__secret` 1 row, 100% in both; `p__ai_addressed` 2 rows (raw 50%, redacted 100%); `p__xtenant_probe` has no usable affected rows. The intervals for the small rules are very wide.
- **False positives:** affected benign (36 rows) 0.0% raw and 0.0% redacted; placebo 0.0% and 0.0%. Upper 95% bound on the redacted affected rate: 8.0%.
- **Placebo noise:** on identical text the two arms' probabilities were identical in draw 1 (mean absolute change 0.0000 over 40 cells; no placebo flips). On the affected rows the mean absolute change per cell was 0.0258, mean shift on labelled rules +0.0015 [-0.0027, +0.0070].

It points the same way as the earlier golden-pair check (no sign that redaction costs recall), but a single draw cannot be used as the trial's answer: the design counts a row as caught only if every draw reaches the level, and the stated margins need the rows that did not complete.

## What this does and doesn't change

- The one attempt is used. The marker for this row set exists, so another run needs the user's explicit decision to remove it. Phase 2 was not approved and was not started.
- Why the limiter refused is set out in [m7-12-attempt-2.md](m7-12-attempt-2.md): the consumer's
  bucket (5,230 tokens, refilling at 1,046 a second) is smaller than 18 of the 137 rows, and
  attempt 1 spaced its checks by the mean size, not each check's own. The harness was changed for a
  second attempt.
- Nothing about redaction itself is concluded. The roadmap row stays "built, run once, inconclusive" until the user decides what to do.
