# M7-12 · The redaction trial: the harness and how a run is armed (as built)

The design is `docs/m7-12-redaction-trial-design.md`. This note is the harness it asks for:
what it sends, what it checks first, how it is analysed, and where it departs from the design's
numbers. **Nothing here sends anything by itself.** The harness is `calibration/redaction_trial.py`,
the statistics are `calibration/redaction_stats.py`, and the manifest of the rows is
`calibration/results/m7-12-trial-manifest.json` (`.md` is the same page for reading).

## What a run sends

One engine (the calibration engine path, floor@2, the production redaction) serves every check, so
the limiter sees one stream. Each row goes twice per draw, three draws, in one interleaved order:

| Arm | What differs |
|---|---|
| `redacted` | exactly what production sends |
| `raw` | the same request with the PII detector switched off. Known-format credentials are still replaced by `[SECRET]` in both arms: that is not PII, and it never leaves the process. |

Both arms of a (row, draw) use the same nonce, so the text is the only thing that differs. The
order of the rows is reshuffled each draw by hash, and which arm goes first is decided per (row,
draw) by hash, so time can't favour one arm.

| Group | Rows | What it answers |
|---|---|---|
| `affected_positive` | 54 | recall: positives whose request redaction changes |
| `affected_benign` | 43 | false positives: benign rows whose request redaction changes |
| `placebo_positive` | 20 | the noise reference: unchanged positives, identical text in both arms |
| `placebo_benign` | 20 | the noise reference: unchanged benign rows |

**137 rows, 822 checks** (137 × 2 arms × 3 draws), at most 900 provider calls and 2.0 million API
input tokens; the plan's estimate is 1.56 million tokens. "Affected" is decided on the whole
request (the content, the conversation, the descriptions of the tools it names), not the content
alone. Placebo rows are chosen deterministically from the golden, held-out and red-team sets to
match the affected rows' guard points; none is a row the tripwire trips on, none is blocked before
a model call, and none has a tool defined differently from an earlier row of its tenant.

## Where it departs from the design's numbers

1. **43 benign rows, not 47.** The design counted by content and included four retired held-out
   rows, which the live exclusions already drop (`retired`). The affected positives are 54, as
   designed. The checks are fewer (822, not 846).
2. **The coarse harm-vocabulary tripwire.** 28 affected rows (19 positive, 9 benign), all
   held-out, trip it: it matches ordinary words in insurance and finance text. They pass the
   approved criteria (no harm label, not `no_live_run`, not retired), and every one was sent in the
   held-out validation without a refusal. The manifest lists the views each trips in and keeps
   them. `python -m calibration.redaction_trial manifest --drop-tripwire` builds the narrower trial
   without them (69 affected rows) if that is preferred; it is the user's choice.
3. **Pace.** Each check waits until the limiter would admit that check's own estimate (attempt 2;
   attempt 1 spaced them by the mean and lost 45 of 492 checks to the limiter, see
   [m7-12-attempt-2.md](m7-12-attempt-2.md)). The plan models the limiter over the run's real order
   and says how long that takes: about **28 minutes**, because the consumer's allowance (1,046
   tokens a second) bounds 1.56 million tokens below 25 minutes whatever the pacing. It fits a
   two-hour window with room.
4. **The margins.** The design's "upper end of the interval on the loss is under 10 points" can't
   be met by a rule with three positives. It is applied to **all rules pooled** (every (row, rule)
   cell of the affected positives); per rule the test is at most **2 flips against redaction**, and
   a confirmed loss (10 points or more, one-sided exact McNemar under 0.05) is looked for per rule,
   per rule and guard point, and pooled. The interval is exact and conservative (each side the
   Clopper-Pearson upper bound on the share of rows that flipped that way), never narrower than the
   data allow. The false positive margin is 5 points on the point estimate for the benign affected
   rows. With about 60 pooled cells, one flip against redaction still passes and two do not.
5. **Two energy rows** (benign, a phone number each) are sent under the floor's rules only, as a
   row of that tenant, with no pack: the trial adds no pack rule.

## What is verified before the first request

`verify_manifest` refuses the run (exit 2, nothing sent) unless: the schema, arms (two) and draws
(three) are the approved ones; the ceilings are 900 and 2.0 million; the hash of every source file,
`rules.json`, `additions.json` and the assembled floor@2 equals the manifest's; the manifest's row
set equals its own hash; every row is still in its source, still sendable, still affected (or still
not, for a placebo) and still labelled as listed; no row is in twice; no tool has two definitions
for a tenant; and the plan is inside the ceilings. The harness also holds **what was approved**,
as constants (`APPROVED_*`): the row set's hash, the group counts (54 affected positives, 43
affected benign rows, 20 and 20 placebo rows), the nonce seed, the margins (10 and 5 points) and
the 822 checks. A manifest that differs in any of them is refused even if its own hash agrees, so
a different row set needs a change to the harness, which is reviewed. The arming script then adds
the commit and a clean tree.

## Stop rules

The standing ones, all in the runner: the first provider refusal (never resent); an `auth` failure;
any unclassified failure; a 429 (a `rate_limited` failure; the pacing should have prevented it);
more than 20% of the last 50 checks failed; a ceiling (provider calls, input tokens); and the
window closing (below). **A check the engine refused itself** (no provider call, reason
`token_rate`, `quota_exhausted`, `admission_wait` or `admission_queue_full`: the gateway's capacity
refusals except `orphan_cap`) is not a provider failure and does not count in the 20% rule, but the
run **stops at the first one** (`run_stopped`, reason `local_refusal`): with the pacing below it
can only mean a bug, so it is never read as noise. A check the limiter would still not admit after 8
waits is not sent, and the run stops (`admission_gave_up`). Timeouts and `unavailable` failures that
reached the provider count as before. A stopped run writes why and exits 3. **Nothing is resent** at
the harness level: a failed check is recorded and the run goes on; the gateway's own single retry
inside a check still happens, as in production.
Records hold sizes, timings, outcomes and scores, the arm and the group: never content, headers,
provider text or the key (a test searches the records of a whole offline run for the rows' text and
for every number redaction replaces).

## Arming a live run

`calibration/redaction_trial_arm.sh <start YYYY-MM-DDTHH:MM, UTC> <attempt 1|2> <head sha>
<worktree> <out dir> <env file>` waits for the start time, refuses outside the two hours from it
(the window is start + 2 h), checks the commit and a clean tree, runs `plan` (which verifies the
manifest), sources the key into its own process only, runs once, then writes the report. Every
attempt writes to a directory of its own. It is armed only when the user has approved the start and
the manifest.

**The window is held by the runner.** A live run needs `--deadline` (the script passes the start
plus two hours): it is refused unless the plan's estimate (about 28 minutes) plus a margin of 5
minutes ends before the deadline, so an arming after about 1 h 27 min into the window sends nothing. During the run, every check is gated
after its pacing wait, just before it is sent: none is sent within 10 seconds of the deadline, and
the run stops with `run_stopped` reason `window_closed` (exit 3). The records so far are kept and
the report reads them (rows without all their checks make the verdict inconclusive).

**One run per attempt.** Before the first request the harness writes a marker, named for the
manifest's row-set hash, in `$XDG_STATE_HOME/guardrails-m7-12-redaction-trial` (default
`~/.local/state/…`), outside the output directory and the worktree, and holds a lock there for the
whole run. A second arming of the same attempt (into any directory, from any worktree) is refused
while the lock is held and after the marker exists, whatever the first run's outcome. The marker
holds the attempt, the start time, the row-set hash, the deadline and the output path, never
content. **Attempt 1** was made on 2026-11-25 and was inconclusive (see
[m7-12-results.md](m7-12-results.md)); its marker, records and report stay as they are. The user
approved **one more**: `--attempt 2` has a marker and lock of its own, is refused unless attempt 1's
marker exists, and is refused once its own exists. There is no attempt 3: that needs a change to the
harness, which is reviewed. No marker is removed or bypassed by any of it; removing one by hand is
the user's decision alone.

**Credentials stay replaced in the raw arm.** The raw arm switches off the PII detector only;
known-format credentials are still replaced by `[SECRET]`. No row of the trial holds one, and a
test sends a synthetic key and an email through the engine in both arms to show that the key is
never sent and the email is sent in the raw arm only. The engine takes a PII detector override
only in the `test` environment (staging is refused, as production is).

## The analysis

`python -m calibration.redaction_trial report records.jsonl --manifest ...` reads the records and
gives, for the affected rows against the placebo rows: recall at `block_at` per rule, per rule and
guard point, and pooled (a positive is caught only if every draw reaches the level; paired by row;
exact McNemar on the flips; the interval above); the false positive rate on the benign rows (a row
counts if any rule reaches `block_at` in any draw) with the rise from redaction and the one-sided
Clopper-Pearson upper bound; the shift in the model's probability row by row with a bootstrap
interval over rows; and which line of the design's table (section 6) the result falls on, with the
reasons. A row enters a figure only if both arms answered every draw of it; the others are listed.
It is tested on synthetic arms and on the recorded golden pair (before and after M1-14), where it
reproduces the design's figures (mean absolute change 0.0132 on the changed rows, 0.0087 on the
unchanged).

## What it can't show

The same as the design: a large cost of redaction can be ruled out, not "no cost at all". A single
run's placebo rows show what the model does to identical input in one run; the golden pair's
unchanged rows, two runs hours apart, show somewhat more. The trial does not widen redaction and
does not send anything under phase 2.
