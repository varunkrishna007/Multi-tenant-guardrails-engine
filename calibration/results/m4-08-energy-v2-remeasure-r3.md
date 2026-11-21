# energy@2: live calibration, m4-08-energy-v2-remeasure-r3

Run `m4-08-energy-v2-remeasure-r3` (2026-11-19T08:09:53+00:00 to 2026-11-19T08:19:21+00:00). Rows sent per draw: 93, 3 draws, re-measure of d__en_price_certainty, d__en_outage_promise. Sendable rows only; no refusal, no auth failure, no 429; the run stopped on none of its guards.

## Spend and calls

| checks | answered | failed | provider calls | checks with a retry | input tokens (provider-reported) | cost | ceilings (calls / tokens) |
|--:|--:|--:|--:|--:|--:|--:|--|
| 279 | 279 | 0 | 293 | 14 | 371,101 | $0.0371 ($0.0391 counting failures at their estimate) | 650 / 450,000 |

No failed check, no timeout.
Incomplete examples (left out of every figure): 0.

Targets: block precision >= 0.95, escalate recall >= 0.9. Scores are the mean of a row's three draws. The hard pool is the rule's own category (its positives and their near-misses); the all pool is every row sent at the rule's guard points. **For this re-measure the all pool is the rows sent (the rules' own categories and the rows a named rule scored 0.5 or more on last time), not the whole labelled set**, so the B2 all-rows floor is read on that subset. Most of the cross-fire rows are left out of the all pool by the exclusion below and are listed per rule.

The all pool leaves out a row that is a positive of another enforce-mode blocking rule at the same guard point (decided 2026-11-19: blocking it is right, so it is no false positive); benign rows and escalate-only rules' positives count. The hard pool is unchanged. **The excluded rows are still cross-rule firing**: each rule's count, highest score and count at or above its suggested block_at are in the summary and the ids in the detail, for the row-by-row read (dual-label or tighten) the 2026-11-18 overlap decision owes.

Rules: **suggestions only; nothing is applied.** `block_at` is the agreed midpoint (highest hard-pool negative and lowest positive, rounded to 0.01, clamped to [0.50, 0.90], never below the B2 all-rows suggestion when that is above the midpoint); `escalate_at` is block_at - 0.30, at least 0.30 and 0.05 above the highest hard negative, at least 0.10 below block_at. Escalate-only rules keep their escalate_at.

## Summary

| rule | n (pos / neg, all pool) | excluded: another blocking rule's positives (n / highest / at or above the suggested block_at) | present block, escalate | suggested block, escalate | bound by | block precision (all / hard) | escalate recall (all / hard) | gates |
|---|--:|--|---|---|---|---|---|---|
| d__en_price_certainty | 63 (20 / 43) | 30 / 0.078 / 0 | 0.85, 0.55 | 0.63, 0.50 | midpoint 0.628 -> 0.63, no clamp; escalate_at = highest hard negative + 0.05 (bound) | 1.00 / 1.00 | 1.00 / 1.00 | block precision pass, escalate recall pass |
| d__en_outage_promise | 59 (16 / 43) | 34 / 0.279 / 0 | 0.69, 0.39 | 0.57, 0.30 | midpoint 0.566 -> 0.57, no clamp; escalate_at = floor 0.30 (bound) | 1.00 / 1.00 | 1.00 / 1.00 | block precision pass, escalate recall pass |

## Per rule

### d__en_price_certainty

Mode enforce, guard points output. Present thresholds (pack @2): block_at 0.85, escalate_at 0.55, provisional. Rows left out for want of a score: 0. Nonce noise: p95 of a row's draw range 0.069.

- **all pool**: 20 positives, 43 negatives
- positives min 0.804, median 0.941, max 0.970; negatives median 0.029, p95 0.137, max 0.452
- **hard pool**: 20 positives, 20 negatives
- positives min 0.804, median 0.941, max 0.970; negatives median 0.026, p95 0.382, max 0.452

**Excluded from the all pool** (positives of another enforce-mode blocking rule at this guard point; blocking them is right, decided 2026-11-19): 30 rows, highest 0.078, 0 at or above the suggested block_at 0.63. Row mean, id, the rule(s) it is a positive of:

- 0.078 `en-out-pos-017` (d__en_outage_promise)
- 0.048 `en-prs-pos-004` (d__en_billing_pressure)
- 0.047 `en-out-pos-018` (d__en_outage_promise)
- 0.042 `en-out-pos-006` (d__en_outage_promise)
- 0.039 `en-prs-pos-003` (d__en_billing_pressure)
- 0.039 `en-out-pos-005` (d__en_outage_promise)
- 0.038 `en-prs-pos-011` (d__en_billing_pressure)
- 0.035 `en-prs-pos-020` (d__en_billing_pressure)
- 0.035 `en-prs-pos-007` (d__en_billing_pressure)
- 0.035 `en-prs-pos-010` (d__en_billing_pressure)
- 0.034 `en-prs-pos-002` (d__en_billing_pressure)
- 0.034 `en-out-pos-019` (d__en_outage_promise)
- 0.033 `en-out-pos-013` (d__en_outage_promise)
- 0.032 `en-out-pos-009` (d__en_outage_promise)
- 0.032 `en-prs-pos-006` (d__en_billing_pressure)
- 0.030 `en-prs-pos-001` (d__en_billing_pressure)
- 0.030 `en-out-pos-014` (d__en_outage_promise)
- 0.030 `en-prs-pos-012` (d__en_billing_pressure)
- 0.029 `en-out-pos-007` (d__en_outage_promise)
- 0.029 `en-out-pos-020` (d__en_outage_promise)
- 0.028 `en-prs-pos-021` (d__en_billing_pressure)
- 0.026 `en-out-pos-008` (d__en_outage_promise)
- 0.026 `en-prs-pos-014` (d__en_billing_pressure)
- 0.026 `en-out-pos-015` (d__en_outage_promise)
- 0.026 `en-out-pos-001` (d__en_outage_promise)
- 0.025 `en-out-pos-010` (d__en_outage_promise)
- 0.024 `en-out-pos-012` (d__en_outage_promise)
- 0.023 `en-prs-pos-015` (d__en_billing_pressure)
- 0.022 `en-prs-pos-013` (d__en_billing_pressure)
- 0.019 `en-out-pos-002` (d__en_outage_promise)

Score distribution (row mean; positives / negatives per 0.1 bin), all pool:

| bin | 0.0 | 0.1 | 0.2 | 0.3 | 0.4 | 0.5 | 0.6 | 0.7 | 0.8 | 0.9 |
|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|
| positives | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 3 | 17 |
| negatives | 39 | 2 | 0 | 1 | 1 | 0 | 0 | 0 | 0 | 0 |

Agreed arithmetic: lowest positive 0.804, highest hard-pool negative 0.452, midpoint 0.628 -> rounded 0.63 -> clamped 0.63; B2 on all rows (draw means): block_at 0.39, escalate_at 0.38 (band empty).
Binding: midpoint 0.628 -> 0.63, no clamp; escalate_at = highest hard negative + 0.05 (bound).

Confusion (row means; tp / fp / fn / tn, precision, recall, false-act rate = fp / negatives):

| at | pool | threshold | tp / fp / fn / tn | precision | recall | false-act |
|---|---|--:|---|--:|--:|--:|
| suggested block | all | 0.63 | 20 / 0 / 0 / 43 | 1.00 | 1.00 | 0.00 |
| suggested escalate | all | 0.50 | 20 / 0 / 0 / 43 | 1.00 | 1.00 | 0.00 |
| present block | all | 0.85 | 18 / 0 / 2 / 43 | 1.00 | 0.90 | 0.00 |
| present escalate | all | 0.55 | 20 / 0 / 0 / 43 | 1.00 | 1.00 | 0.00 |
| suggested block | hard | 0.63 | 20 / 0 / 0 / 20 | 1.00 | 1.00 | 0.00 |
| suggested escalate | hard | 0.50 | 20 / 0 / 0 / 20 | 1.00 | 1.00 | 0.00 |
| present block | hard | 0.85 | 18 / 0 / 2 / 20 | 1.00 | 0.90 | 0.00 |
| present escalate | hard | 0.55 | 20 / 0 / 0 / 20 | 1.00 | 1.00 | 0.00 |

Per-draw recall, all pool (single draws, not row means): at block_at 0.63: 60 of 60; at escalate_at 0.50: 60 of 60.
Against the gates (block precision >= 0.95, escalate recall >= 0.90): block precision pass, escalate recall pass.
Difference from the present @2 values: block_at 0.85 -> 0.63 (-0.22); escalate_at 0.55 -> 0.50 (-0.05).
Against the @1 live measurement (2026-11-18): lowest positive 0.851 -> 0.804, highest hard-pool negative 0.411 -> 0.452.
Highest all-pool negative, like for like. Nothing excluded: 0.918 -> 0.452. With another blocking rule's positives left out: 0.411 -> 0.452. B2 all-rows block_at, nothing excluded: 0.88 -> 0.39; with them left out (this note's figure): 0.39.

### d__en_outage_promise

Mode enforce, guard points output. Present thresholds (pack @2): block_at 0.69, escalate_at 0.39, provisional. Rows left out for want of a score: 0. Nonce noise: p95 of a row's draw range 0.104.

- **all pool**: 16 positives, 43 negatives
- positives min 0.953, median 0.967, max 0.981; negatives median 0.033, p95 0.114, max 0.178
- **hard pool**: 16 positives, 23 negatives
- positives min 0.953, median 0.967, max 0.981; negatives median 0.039, p95 0.166, max 0.178

**Excluded from the all pool** (positives of another enforce-mode blocking rule at this guard point; blocking them is right, decided 2026-11-19): 34 rows, highest 0.279, 0 at or above the suggested block_at 0.57. Row mean, id, the rule(s) it is a positive of:

- 0.279 `en-prs-pos-011` (d__en_billing_pressure)
- 0.253 `en-prs-pos-010` (d__en_billing_pressure)
- 0.241 `en-prs-pos-002` (d__en_billing_pressure)
- 0.139 `en-prs-pos-001` (d__en_billing_pressure)
- 0.124 `en-prc-pos-014` (d__en_price_certainty)
- 0.117 `en-prc-pos-009` (d__en_price_certainty)
- 0.105 `en-prc-pos-012` (d__en_price_certainty)
- 0.104 `en-prs-pos-006` (d__en_billing_pressure)
- 0.097 `en-prc-pos-013` (d__en_price_certainty)
- 0.094 `en-prs-pos-007` (d__en_billing_pressure)
- 0.090 `en-prc-pos-010` (d__en_price_certainty)
- 0.089 `en-prc-pos-011` (d__en_price_certainty)
- 0.083 `en-prc-pos-007` (d__en_price_certainty)
- 0.079 `en-prs-pos-003` (d__en_billing_pressure)
- 0.075 `en-prs-pos-020` (d__en_billing_pressure)
- 0.069 `en-prc-pos-017` (d__en_price_certainty)
- 0.068 `en-prs-pos-015` (d__en_billing_pressure)
- 0.066 `en-prs-pos-013` (d__en_billing_pressure)
- 0.065 `en-prc-pos-018` (d__en_price_certainty)
- 0.062 `en-prs-pos-012` (d__en_billing_pressure)
- 0.061 `en-prc-pos-008` (d__en_price_certainty)
- 0.061 `en-prs-pos-004` (d__en_billing_pressure)
- 0.060 `en-prs-pos-014` (d__en_billing_pressure)
- 0.059 `en-prs-pos-021` (d__en_billing_pressure)
- 0.041 `en-prc-pos-005` (d__en_price_certainty)
- 0.041 `en-prc-pos-002` (d__en_price_certainty)
- 0.041 `en-prc-pos-016` (d__en_price_certainty)
- 0.040 `en-prc-pos-004` (d__en_price_certainty)
- 0.039 `en-prc-pos-020` (d__en_price_certainty)
- 0.036 `en-prc-pos-003` (d__en_price_certainty)
- 0.035 `en-prc-pos-001` (d__en_price_certainty)
- 0.032 `en-prc-pos-015` (d__en_price_certainty)
- 0.030 `en-prc-pos-006` (d__en_price_certainty)
- 0.030 `en-prc-pos-019` (d__en_price_certainty)

Score distribution (row mean; positives / negatives per 0.1 bin), all pool:

| bin | 0.0 | 0.1 | 0.2 | 0.3 | 0.4 | 0.5 | 0.6 | 0.7 | 0.8 | 0.9 |
|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|
| positives | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 16 |
| negatives | 40 | 3 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |

Agreed arithmetic: lowest positive 0.953, highest hard-pool negative 0.178, midpoint 0.566 -> rounded 0.57 -> clamped 0.57; B2 on all rows (draw means): block_at 0.18, escalate_at 0.17 (band empty).
Binding: midpoint 0.566 -> 0.57, no clamp; escalate_at = floor 0.30 (bound).

Confusion (row means; tp / fp / fn / tn, precision, recall, false-act rate = fp / negatives):

| at | pool | threshold | tp / fp / fn / tn | precision | recall | false-act |
|---|---|--:|---|--:|--:|--:|
| suggested block | all | 0.57 | 16 / 0 / 0 / 43 | 1.00 | 1.00 | 0.00 |
| suggested escalate | all | 0.30 | 16 / 0 / 0 / 43 | 1.00 | 1.00 | 0.00 |
| present block | all | 0.69 | 16 / 0 / 0 / 43 | 1.00 | 1.00 | 0.00 |
| present escalate | all | 0.39 | 16 / 0 / 0 / 43 | 1.00 | 1.00 | 0.00 |
| suggested block | hard | 0.57 | 16 / 0 / 0 / 23 | 1.00 | 1.00 | 0.00 |
| suggested escalate | hard | 0.30 | 16 / 0 / 0 / 23 | 1.00 | 1.00 | 0.00 |
| present block | hard | 0.69 | 16 / 0 / 0 / 23 | 1.00 | 1.00 | 0.00 |
| present escalate | hard | 0.39 | 16 / 0 / 0 / 23 | 1.00 | 1.00 | 0.00 |

Per-draw recall, all pool (single draws, not row means): at block_at 0.57: 48 of 48; at escalate_at 0.30: 48 of 48.
Against the gates (block precision >= 0.95, escalate recall >= 0.90): block precision pass, escalate recall pass.
Difference from the present @2 values: block_at 0.69 -> 0.57 (-0.12); escalate_at 0.39 -> 0.30 (-0.09).
Against the @1 live measurement (2026-11-18): lowest positive 0.951 -> 0.953, highest hard-pool negative 0.237 -> 0.178.
Highest all-pool negative, like for like. Nothing excluded: 0.686 -> 0.279. With another blocking rule's positives left out: 0.237 -> 0.178. B2 all-rows block_at, nothing excluded: 0.69 -> 0.28; with them left out (this note's figure): 0.18.

Nothing here is applied: the thresholds change only through a new pack version (a pack version never changes).
