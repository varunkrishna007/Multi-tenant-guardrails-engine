> **Descriptive only, not the trial verdict.** This is the pre-written analysis run on draw 1 alone (`draws=1`), because the run stopped during draw 2. The trial's own rule needs all three draws; it was not applied here. "Caught" means draw 1 reached `block_at`. Read the interval widths before the point figures.

# M7-12 redaction trial: result

Rows {'affected_benign': 43, 'affected_positive': 54, 'placebo_benign': 20, 'placebo_positive': 20}; usable (both arms answered every draw) 116; incomplete 21.
Checks that did not answer: failed 48

## Recall at block_at, raw against redacted

Positives only; a row is caught only if every draw reaches the level.

| Rule | Rows | Raw | Redacted | Loss (points) | Interval | Flips against / for | One-sided McNemar | Placebo flips |
|---|---|---|---|---|---|---|---|---|
| p__ai_addressed | 2 | 50.0% | 100.0% | -50.0 | [-98.7, +84.2] | 0 / 1 | 1.000 | 0 / 0 (of 1) |
| p__exfil | 25 | 100.0% | 100.0% | +0.0 | [-13.7, +13.7] | 0 / 0 | 1.000 | 0 / 0 (of 2) |
| p__inj_indirect | 14 | 100.0% | 100.0% | +0.0 | [-23.2, +23.2] | 0 / 0 | 1.000 | 0 / 0 (of 6) |
| p__secret | 1 | 100.0% | 100.0% | +0.0 | [-97.5, +97.5] | 0 / 0 | 1.000 | 0 / 0 (of 4) |
| p__xtenant_probe | 0 | n/a | n/a | n/a | n/a | 0 / 0 | 1.000 | 0 / 0 (of 8) |
| all rules together | 42 | 97.6% | 100.0% | -2.4 | [-12.6, +8.4] | 0 / 1 | 1.000 | - |

## False positives on benign rows

A row counts if any rule reaches block_at in any draw.

| Rows | n | Raw | Redacted | Rise (points) | Interval | Flips up / down | Upper 95% (redacted) |
|---|---|---|---|---|---|---|---|
| affected | 36 | 0.0% | 0.0% | +0.0 | [-9.7, +9.7] | 0 / 0 | 8.0% |
| placebo | 20 | 0.0% | 0.0% | +0.0 | [-16.8, +16.8] | 0 / 0 | 13.9% |

## Shift in the model's probability (redacted minus raw)

Mean over draws, then over rows. Cells are n, mean, 95% interval.

| Rows | Labelled rules | All rules | Mean absolute change per cell |
|---|---|---|---|
| affected | 40, +0.0015, [-0.0027, +0.0070] | 76, +0.0048, [-0.0044, +0.0143] | 0.0258 |
| placebo | 20, +0.0000, [+0.0000, +0.0000] | 40, +0.0000, [+0.0000, +0.0000] | 0.0000 |

## Which line of the design's table (section 6): **inconclusive**

- 21 affected rows are incomplete
