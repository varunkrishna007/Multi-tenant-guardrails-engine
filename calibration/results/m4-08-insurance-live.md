# insurance@1: sendable-row calibration (3 draws)

Rows sent per draw: 227. Checks 713 (681 answered, 32 failed), provider calls 823. Input tokens the provider reported 727,820 (**$0.0728** at $0.1/M); counting each failed check at its estimate (the run's ceiling accounting) 889,650 ($0.0890).
Targets: block precision 0.95, escalate recall 0.9.

| rule | mode | pos / neg | present block, escalate | suggestion (draw means) | suggestion (hard pool) | note |
|---|---|---|---|---|---|---|
| d__ins_payout_promise | enforce | 16 / 114 | 0.85, 0.55 | block_at 0.93, escalate_at 0.92 | block_at 0.18, escalate_at 0.17 |  |
| d__ins_underwriting_final | enforce | 32 / 130 | 0.85, 0.55 | block_at 0.93, escalate_at 0.92 | block_at 0.06, escalate_at 0.05 |  |
| d__ins_policy_advice | enforce | 16 / 114 | 0.80, 0.50 | block_at 0.44, escalate_at 0.43 | block_at 0.04, escalate_at 0.03 |  |
| d__ins_fraud_signal | enforce | 0 / 33 | 0.95, 0.50 | none (no_positives) | none (no_examples) | max_action escalate; no sendable positive rows (every firing row is withheld by the user's rule) |
| d__ins_fraud_accusation | enforce | 16 / 114 | 0.85, 0.55 | block_at 0.07, escalate_at 0.06 | block_at 0.07, escalate_at 0.06 |  |
| d__ins_binding_action | enforce | 16 / 16 | 0.85, 0.55 | block_at 0.02, escalate_at 0.01 | block_at 0.02, escalate_at 0.01 |  |

## At the present thresholds, and how far apart the scores are

| rule | pool | block: precision / recall | escalate: recall / false-act | positives min / median | negatives p95 / max (category of the max) |
|---|---|---|---|---|---|
| d__ins_payout_promise | all (16/114) | 0.94 / 1.00 | 1.00 / 0.02 | 0.96 / 0.97 | 0.35 / 0.92 (underwriting_final) |
| d__ins_payout_promise | hard (16/16) | 1.00 / 1.00 | 1.00 / 0.00 | 0.96 / 0.97 | 0.17 / 0.17 (payout_promise) |
| d__ins_underwriting_final | all (32/130) | 0.73 / 1.00 | 1.00 / 0.15 | 0.89 / 0.97 | 0.90 / 0.93 (payout_promise) |
| d__ins_underwriting_final | hard (32/33) | 1.00 / 1.00 | 1.00 / 0.00 | 0.89 / 0.97 | 0.05 / 0.06 (underwriting_final) |
| d__ins_policy_advice | all (16/114) | 1.00 / 1.00 | 1.00 / 0.00 | 0.96 / 0.96 | 0.24 / 0.43 (underwriting_final) |
| d__ins_policy_advice | hard (16/16) | 1.00 / 1.00 | 1.00 / 0.00 | 0.96 / 0.96 | 0.03 / 0.03 (policy_advice) |
| d__ins_fraud_signal | all (0/33) | capped | - / 0.00 | - / - | 0.33 / 0.34 (fraud_signal) |
| d__ins_fraud_signal | hard (0/0) | capped | - / - | - / - | - / - (None) |
| d__ins_fraud_accusation | all (16/114) | 1.00 / 1.00 | 1.00 / 0.00 | 0.96 / 0.97 | 0.04 / 0.06 (fraud_accusation) |
| d__ins_fraud_accusation | hard (16/17) | 1.00 / 1.00 | 1.00 / 0.00 | 0.96 / 0.97 | 0.06 / 0.06 (fraud_accusation) |
| d__ins_binding_action | all (16/16) | 1.00 / 1.00 | 1.00 / 0.00 | 0.97 / 0.97 | 0.02 / 0.02 (binding_action) |
| d__ins_binding_action | hard (16/16) | 1.00 / 1.00 | 1.00 / 0.00 | 0.97 / 0.97 | 0.02 / 0.02 (binding_action) |

A suggestion is computed, not applied: the thresholds change only through a new pack version (a pack version never changes).

