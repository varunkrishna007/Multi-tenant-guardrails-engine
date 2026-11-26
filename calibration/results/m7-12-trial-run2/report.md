# M7-12 redaction trial: result

Rows {'affected_benign': 43, 'affected_positive': 54, 'placebo_benign': 20, 'placebo_positive': 20}; usable (both arms answered every draw) 137; incomplete 0.

## Recall at block_at, raw against redacted

Positives only; a row is caught only if every draw reaches the level.

| Rule | Rows | Raw | Redacted | Loss (points) | Interval | Flips against / for | One-sided McNemar | Placebo flips |
|---|---|---|---|---|---|---|---|---|
| p__ai_addressed | 3 | 66.7% | 100.0% | -33.3 | [-90.6, +70.8] | 0 / 1 | 1.000 | 0 / 0 (of 1) |
| p__exfil | 32 | 100.0% | 100.0% | +0.0 | [-10.9, +10.9] | 0 / 0 | 1.000 | 0 / 0 (of 2) |
| p__inj_indirect | 20 | 95.0% | 95.0% | +0.0 | [-16.8, +16.8] | 0 / 0 | 1.000 | 0 / 0 (of 6) |
| p__secret | 3 | 100.0% | 100.0% | +0.0 | [-70.8, +70.8] | 0 / 0 | 1.000 | 0 / 0 (of 4) |
| p__xtenant_probe | 0 | n/a | n/a | n/a | n/a | 0 / 0 | 1.000 | 0 / 0 (of 8) |
| all rules together | 58 | 96.6% | 98.3% | -1.7 | [-9.2, +6.2] | 0 / 1 | 1.000 | - |

## False positives on benign rows

A row counts if any rule reaches block_at in any draw.

| Rows | n | Raw | Redacted | Rise (points) | Interval | Flips up / down | Upper 95% (redacted) |
|---|---|---|---|---|---|---|---|
| affected | 43 | 2.3% | 4.7% | +2.3 | [-8.2, +12.3] | 1 / 0 | 13.9% |
| placebo | 20 | 0.0% | 0.0% | +0.0 | [-16.8, +16.8] | 0 / 0 | 13.9% |

## Shift in the model's probability (redacted minus raw)

Mean over draws, then over rows. Cells are n, mean, 95% interval.

| Rows | Labelled rules | All rules | Mean absolute change per cell |
|---|---|---|---|
| affected | 54, +0.0004, [-0.0018, +0.0029] | 97, +0.0027, [-0.0050, +0.0097] | 0.0222 |
| placebo | 20, +0.0000, [+0.0000, +0.0000] | 40, +0.0000, [+0.0000, +0.0000] | 0.0000 |

## Which line of the design's table (section 6): **keep_default_phase_2_may_go_ahead**

- all rules together lose less than 10 points (upper end of the interval), no rule has more than 2 flips against redaction, and the false positive rate rose by less than 5 points

