# M7-12 redaction trial: result

Rows {'affected_benign': 43, 'affected_positive': 54, 'placebo_benign': 20, 'placebo_positive': 20}; usable (both arms answered every draw) 0; incomplete 137.
Checks that did not answer: failed 48

## Recall at block_at, raw against redacted

Positives only; a row is caught only if every draw reaches the level.

| Rule | Rows | Raw | Redacted | Loss (points) | Interval | Flips against / for | One-sided McNemar | Placebo flips |
|---|---|---|---|---|---|---|---|---|
| p__ai_addressed | 0 | n/a | n/a | n/a | n/a | 0 / 0 | 1.000 | 0 / 0 (of 0) |
| p__exfil | 0 | n/a | n/a | n/a | n/a | 0 / 0 | 1.000 | 0 / 0 (of 0) |
| p__inj_indirect | 0 | n/a | n/a | n/a | n/a | 0 / 0 | 1.000 | 0 / 0 (of 0) |
| p__secret | 0 | n/a | n/a | n/a | n/a | 0 / 0 | 1.000 | 0 / 0 (of 0) |
| p__xtenant_probe | 0 | n/a | n/a | n/a | n/a | 0 / 0 | 1.000 | 0 / 0 (of 0) |
| all rules together | 0 | n/a | n/a | n/a | n/a | 0 / 0 | 1.000 | - |

## False positives on benign rows

A row counts if any rule reaches block_at in any draw.

| Rows | n | Raw | Redacted | Rise (points) | Interval | Flips up / down | Upper 95% (redacted) |
|---|---|---|---|---|---|---|---|
| affected | 0 | n/a | n/a | n/a | n/a | 0 / 0 | n/a |
| placebo | 0 | n/a | n/a | n/a | n/a | 0 / 0 | n/a |

## Shift in the model's probability (redacted minus raw)

Mean over draws, then over rows. Cells are n, mean, 95% interval.

| Rows | Labelled rules | All rules | Mean absolute change per cell |
|---|---|---|---|
| affected | 0, n/a, n/a | 0, n/a, n/a | n/a |
| placebo | 0, n/a, n/a | 0, n/a, n/a | n/a |

## Which line of the design's table (section 6): **inconclusive**

- the loss of all rules together can't be bounded under 10 points (no usable rows)
- 97 affected rows are incomplete

