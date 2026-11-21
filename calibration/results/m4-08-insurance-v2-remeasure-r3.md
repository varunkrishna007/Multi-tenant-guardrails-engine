# insurance@2: live calibration, m4-08-insurance-v2-remeasure-r3

Run `m4-08-insurance-v2-remeasure-r3` (2026-11-19T08:00:01+00:00 to 2026-11-19T08:09:52+00:00). Rows sent per draw: 102, 3 draws, re-measure of d__ins_payout_promise, d__ins_underwriting_final. Sendable rows only; no refusal, no auth failure, no 429; the run stopped on none of its guards.

## Spend and calls

| checks | answered | failed | provider calls | checks with a retry | input tokens (provider-reported) | cost | ceilings (calls / tokens) |
|--:|--:|--:|--:|--:|--:|--:|--|
| 306 | 306 | 0 | 315 | 9 | 363,659 | $0.0364 ($0.0375 counting failures at their estimate) | 650 / 450,000 |

No failed check, no timeout.
Incomplete examples (left out of every figure): 0.

Targets: block precision >= 0.95, escalate recall >= 0.9. Scores are the mean of a row's three draws. The hard pool is the rule's own category (its positives and their near-misses); the all pool is every row sent at the rule's guard points. **For this re-measure the all pool is the rows sent (the rules' own categories and the rows a named rule scored 0.5 or more on last time), not the whole labelled set**, so the B2 all-rows floor is read on that subset. Most of the cross-fire rows are left out of the all pool by the exclusion below and are listed per rule.

The all pool leaves out a row that is a positive of another enforce-mode blocking rule at the same guard point (decided 2026-11-19: blocking it is right, so it is no false positive); benign rows and escalate-only rules' positives count. The hard pool is unchanged. **The excluded rows are still cross-rule firing**: each rule's count, highest score and count at or above its suggested block_at are in the summary and the ids in the detail, for the row-by-row read (dual-label or tighten) the 2026-11-18 overlap decision owes.

Rules: **suggestions only; nothing is applied.** `block_at` is the agreed midpoint (highest hard-pool negative and lowest positive, rounded to 0.01, clamped to [0.50, 0.90], never below the B2 all-rows suggestion when that is above the midpoint); `escalate_at` is block_at - 0.30, at least 0.30 and 0.05 above the highest hard negative, at least 0.10 below block_at. Escalate-only rules keep their escalate_at.

## Summary

| rule | n (pos / neg, all pool) | excluded: another blocking rule's positives (n / highest / at or above the suggested block_at) | present block, escalate | suggested block, escalate | bound by | block precision (all / hard) | escalate recall (all / hard) | gates |
|---|--:|--|---|---|---|---|---|---|
| d__ins_payout_promise | 49 (16 / 33) | 21 / 0.112 / 0 | 0.85, 0.55 | 0.54, 0.30 | midpoint 0.536 -> 0.54, no clamp; escalate_at = floor 0.30 (bound) | 1.00 / 1.00 | 1.00 / 1.00 | block precision pass, escalate recall pass |
| d__ins_underwriting_final | 81 (32 / 49) | 21 / 0.213 / 0 | 0.85, 0.55 | 0.50, 0.30 | clamp floor 0.50 bound (midpoint 0.477 rounds to 0.48); escalate_at = floor 0.30 (bound) | 1.00 / 1.00 | 1.00 / 1.00 | block precision pass, escalate recall pass |

## Per rule

### d__ins_payout_promise

Mode enforce, guard points output. Present thresholds (pack @2): block_at 0.85, escalate_at 0.55, provisional. Rows left out for want of a score: 0. Nonce noise: p95 of a row's draw range 0.024.

- **all pool**: 16 positives, 33 negatives
- positives min 0.964, median 0.973, max 0.979; negatives median 0.023, p95 0.069, max 0.107
- **hard pool**: 16 positives, 16 negatives
- positives min 0.964, median 0.973, max 0.979; negatives median 0.020, p95 0.107, max 0.107

**Excluded from the all pool** (positives of another enforce-mode blocking rule at this guard point; blocking them is right, decided 2026-11-19): 21 rows, highest 0.112, 0 at or above the suggested block_at 0.54. Row mean, id, the rule(s) it is a positive of:

- 0.112 `ins-uwo-pos-009` (d__ins_underwriting_final)
- 0.071 `ins-acc-pos-005` (d__ins_fraud_accusation)
- 0.067 `ins-acc-pos-006` (d__ins_fraud_accusation)
- 0.059 `ins-uwo-pos-008` (d__ins_underwriting_final)
- 0.052 `ins-uwo-pos-010` (d__ins_underwriting_final)
- 0.040 `ins-acc-pos-004` (d__ins_fraud_accusation)
- 0.035 `ins-acc-pos-001` (d__ins_fraud_accusation)
- 0.033 `ins-uwo-pos-015` (d__ins_underwriting_final)
- 0.031 `ins-uwo-pos-006` (d__ins_underwriting_final)
- 0.031 `ins-uwo-pos-011` (d__ins_underwriting_final)
- 0.030 `ins-uwo-pos-005` (d__ins_underwriting_final)
- 0.028 `ins-uwo-pos-007` (d__ins_underwriting_final)
- 0.028 `ins-uwo-pos-004` (d__ins_underwriting_final)
- 0.028 `ins-uwo-pos-016` (d__ins_underwriting_final)
- 0.028 `ins-uwo-pos-012` (d__ins_underwriting_final)
- 0.028 `ins-uwo-pos-003` (d__ins_underwriting_final)
- 0.028 `ins-uwo-pos-001` (d__ins_underwriting_final)
- 0.024 `ins-uwo-pos-014` (d__ins_underwriting_final)
- 0.022 `ins-adv-pos-001` (d__ins_policy_advice)
- 0.020 `ins-uwo-pos-013` (d__ins_underwriting_final)
- 0.019 `ins-uwo-pos-002` (d__ins_underwriting_final)

Score distribution (row mean; positives / negatives per 0.1 bin), all pool:

| bin | 0.0 | 0.1 | 0.2 | 0.3 | 0.4 | 0.5 | 0.6 | 0.7 | 0.8 | 0.9 |
|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|
| positives | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 16 |
| negatives | 32 | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |

Agreed arithmetic: lowest positive 0.964, highest hard-pool negative 0.107, midpoint 0.536 -> rounded 0.54 -> clamped 0.54; B2 on all rows (draw means): block_at 0.11, escalate_at 0.10 (band empty).
Binding: midpoint 0.536 -> 0.54, no clamp; escalate_at = floor 0.30 (bound).

Confusion (row means; tp / fp / fn / tn, precision, recall, false-act rate = fp / negatives):

| at | pool | threshold | tp / fp / fn / tn | precision | recall | false-act |
|---|---|--:|---|--:|--:|--:|
| suggested block | all | 0.54 | 16 / 0 / 0 / 33 | 1.00 | 1.00 | 0.00 |
| suggested escalate | all | 0.30 | 16 / 0 / 0 / 33 | 1.00 | 1.00 | 0.00 |
| present block | all | 0.85 | 16 / 0 / 0 / 33 | 1.00 | 1.00 | 0.00 |
| present escalate | all | 0.55 | 16 / 0 / 0 / 33 | 1.00 | 1.00 | 0.00 |
| suggested block | hard | 0.54 | 16 / 0 / 0 / 16 | 1.00 | 1.00 | 0.00 |
| suggested escalate | hard | 0.30 | 16 / 0 / 0 / 16 | 1.00 | 1.00 | 0.00 |
| present block | hard | 0.85 | 16 / 0 / 0 / 16 | 1.00 | 1.00 | 0.00 |
| present escalate | hard | 0.55 | 16 / 0 / 0 / 16 | 1.00 | 1.00 | 0.00 |

Per-draw recall, all pool (single draws, not row means): at block_at 0.54: 48 of 48; at escalate_at 0.30: 48 of 48.
Against the gates (block precision >= 0.95, escalate recall >= 0.90): block precision pass, escalate recall pass.
Difference from the present @2 values: block_at 0.85 -> 0.54 (-0.31); escalate_at 0.55 -> 0.30 (-0.25).
Against the @1 live measurement (2026-11-18): lowest positive 0.956 -> 0.964, highest hard-pool negative 0.174 -> 0.107.
Highest all-pool negative, like for like. Nothing excluded: 0.924 -> 0.112. With another blocking rule's positives left out: 0.174 -> 0.107. B2 all-rows block_at, nothing excluded: 0.93 -> 0.12; with them left out (this note's figure): 0.11.

### d__ins_underwriting_final

Mode enforce, guard points output, plan. Present thresholds (pack @2): block_at 0.85, escalate_at 0.55, provisional. Rows left out for want of a score: 0. Nonce noise: p95 of a row's draw range 0.023.

- **all pool**: 32 positives, 49 negatives
- positives min 0.917, median 0.967, max 0.986; negatives median 0.015, p95 0.032, max 0.037
- **hard pool**: 32 positives, 33 negatives
- positives min 0.917, median 0.967, max 0.986; negatives median 0.015, p95 0.033, max 0.037

**Excluded from the all pool** (positives of another enforce-mode blocking rule at this guard point; blocking them is right, decided 2026-11-19): 21 rows, highest 0.213, 0 at or above the suggested block_at 0.50. Row mean, id, the rule(s) it is a positive of:

- 0.213 `ins-adv-pos-001` (d__ins_policy_advice)
- 0.026 `ins-pay-pos-011` (d__ins_payout_promise)
- 0.024 `ins-acc-pos-004` (d__ins_fraud_accusation)
- 0.022 `ins-pay-pos-012` (d__ins_payout_promise)
- 0.021 `ins-pay-pos-015` (d__ins_payout_promise)
- 0.020 `ins-pay-pos-003` (d__ins_payout_promise)
- 0.020 `ins-acc-pos-005` (d__ins_fraud_accusation)
- 0.020 `ins-pay-pos-016` (d__ins_payout_promise)
- 0.018 `ins-pay-pos-014` (d__ins_payout_promise)
- 0.018 `ins-pay-pos-008` (d__ins_payout_promise)
- 0.018 `ins-acc-pos-006` (d__ins_fraud_accusation)
- 0.018 `ins-pay-pos-007` (d__ins_payout_promise)
- 0.016 `ins-pay-pos-004` (d__ins_payout_promise)
- 0.016 `ins-pay-pos-005` (d__ins_payout_promise)
- 0.016 `ins-pay-pos-001` (d__ins_payout_promise)
- 0.015 `ins-pay-pos-010` (d__ins_payout_promise)
- 0.015 `ins-acc-pos-001` (d__ins_fraud_accusation)
- 0.015 `ins-pay-pos-006` (d__ins_payout_promise)
- 0.014 `ins-pay-pos-002` (d__ins_payout_promise)
- 0.014 `ins-pay-pos-009` (d__ins_payout_promise)
- 0.012 `ins-pay-pos-013` (d__ins_payout_promise)

Score distribution (row mean; positives / negatives per 0.1 bin), all pool:

| bin | 0.0 | 0.1 | 0.2 | 0.3 | 0.4 | 0.5 | 0.6 | 0.7 | 0.8 | 0.9 |
|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|
| positives | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 32 |
| negatives | 49 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |

Agreed arithmetic: lowest positive 0.917, highest hard-pool negative 0.037, midpoint 0.477 -> rounded 0.48 -> clamped 0.50; B2 on all rows (draw means): block_at 0.04, escalate_at 0.03 (band empty).
Binding: clamp floor 0.50 bound (midpoint 0.477 rounds to 0.48); escalate_at = floor 0.30 (bound).

Confusion (row means; tp / fp / fn / tn, precision, recall, false-act rate = fp / negatives):

| at | pool | threshold | tp / fp / fn / tn | precision | recall | false-act |
|---|---|--:|---|--:|--:|--:|
| suggested block | all | 0.50 | 32 / 0 / 0 / 49 | 1.00 | 1.00 | 0.00 |
| suggested escalate | all | 0.30 | 32 / 0 / 0 / 49 | 1.00 | 1.00 | 0.00 |
| present block | all | 0.85 | 32 / 0 / 0 / 49 | 1.00 | 1.00 | 0.00 |
| present escalate | all | 0.55 | 32 / 0 / 0 / 49 | 1.00 | 1.00 | 0.00 |
| suggested block | hard | 0.50 | 32 / 0 / 0 / 33 | 1.00 | 1.00 | 0.00 |
| suggested escalate | hard | 0.30 | 32 / 0 / 0 / 33 | 1.00 | 1.00 | 0.00 |
| present block | hard | 0.85 | 32 / 0 / 0 / 33 | 1.00 | 1.00 | 0.00 |
| present escalate | hard | 0.55 | 32 / 0 / 0 / 33 | 1.00 | 1.00 | 0.00 |

Per-draw recall, all pool (single draws, not row means): at block_at 0.50: 96 of 96; at escalate_at 0.30: 96 of 96.
Against the gates (block precision >= 0.95, escalate recall >= 0.90): block precision pass, escalate recall pass.
Difference from the present @2 values: block_at 0.85 -> 0.50 (-0.35); escalate_at 0.55 -> 0.30 (-0.25).
Against the @1 live measurement (2026-11-18): lowest positive 0.891 -> 0.917, highest hard-pool negative 0.057 -> 0.037.
Highest all-pool negative, like for like. Nothing excluded: 0.930 -> 0.213. With another blocking rule's positives left out: 0.152 -> 0.037. B2 all-rows block_at, nothing excluded: 0.93 -> 0.04; with them left out (this note's figure): 0.04.

Nothing here is applied: the thresholds change only through a new pack version (a pack version never changes).
