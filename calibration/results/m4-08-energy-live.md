# energy@1: sendable-row calibration (3 draws)

Rows sent per draw: 228. Checks 685 (684 answered, 1 failed), provider calls 722. Input tokens the provider reported 747,078 (**$0.0747** at $0.1/M); counting each failed check at its estimate (the run's ceiling accounting) 790,750 ($0.0791).
Targets: block precision 0.95, escalate recall 0.9.

| rule | mode | pos / neg | present block, escalate | suggestion (draw means) | suggestion (hard pool) | note |
|---|---|---|---|---|---|---|
| d__en_price_certainty | enforce | 20 / 123 | 0.85, 0.55 | block_at 0.88, escalate_at 0.87 | block_at 0.34, escalate_at 0.33 |  |
| d__en_unsafe_advice | enforce | 0 / 143 | 0.80, 0.50 | none (no_positives) | none (no_examples) | no sendable positive rows (every firing row is withheld by the user's rule) |
| d__en_safety_report | enforce | 21 / 24 | 0.99, 0.40 | escalate_at 0.97 | escalate_at 0.97 | max_action escalate;  |
| d__en_outage_promise | enforce | 16 / 127 | 0.85, 0.55 | block_at 0.69, escalate_at 0.68 | block_at 0.24, escalate_at 0.23 |  |
| d__en_billing_pressure | enforce | 21 / 122 | 0.85, 0.55 | block_at 0.12, escalate_at 0.11 | block_at 0.04, escalate_at 0.03 |  |
| d__en_account_change | enforce | 20 / 20 | 0.85, 0.55 | block_at 0.03, escalate_at 0.02 | block_at 0.03, escalate_at 0.02 |  |

## At the present thresholds, and how far apart the scores are

| rule | pool | block: precision / recall | escalate: recall / false-act | positives min / median | negatives p95 / max (category of the max) |
|---|---|---|---|---|---|
| d__en_price_certainty | all (20/123) | 0.83 / 1.00 | 1.00 / 0.11 | 0.85 / 0.95 | 0.80 / 0.92 (billing_pressure) |
| d__en_price_certainty | hard (20/20) | 1.00 / 1.00 | 1.00 / 0.00 | 0.85 / 0.95 | 0.34 / 0.41 (price_certainty) |
| d__en_unsafe_advice | all (0/143) | - / - | - / 0.01 | - / - | 0.33 / 0.61 (outage_promise) |
| d__en_unsafe_advice | hard (0/0) | - / - | - / - | - / - | - / - (None) |
| d__en_safety_report | all (21/24) | capped | 1.00 / 0.00 | 0.96 / 0.98 | 0.08 / 0.31 (safety_report) |
| d__en_safety_report | hard (21/24) | capped | 1.00 / 0.00 | 0.96 / 0.98 | 0.08 / 0.31 (safety_report) |
| d__en_outage_promise | all (16/127) | 1.00 / 1.00 | 1.00 / 0.02 | 0.95 / 0.97 | 0.27 / 0.69 (price_certainty) |
| d__en_outage_promise | hard (16/23) | 1.00 / 1.00 | 1.00 / 0.00 | 0.95 / 0.97 | 0.21 / 0.24 (outage_promise) |
| d__en_billing_pressure | all (21/122) | 1.00 / 1.00 | 1.00 / 0.00 | 0.94 / 0.98 | 0.04 / 0.13 (outage_promise) |
| d__en_billing_pressure | hard (21/22) | 1.00 / 1.00 | 1.00 / 0.00 | 0.94 / 0.98 | 0.04 / 0.04 (billing_pressure) |
| d__en_account_change | all (20/20) | 1.00 / 1.00 | 1.00 / 0.00 | 0.97 / 0.98 | 0.03 / 0.03 (account_change) |
| d__en_account_change | hard (20/20) | 1.00 / 1.00 | 1.00 / 0.00 | 0.97 / 0.98 | 0.03 / 0.03 (account_change) |

A suggestion is computed, not applied: the thresholds change only through a new pack version (a pack version never changes).

