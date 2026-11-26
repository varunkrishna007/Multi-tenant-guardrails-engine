# M7-12 · Attempt 2: why attempt 1 lost checks, and what changed

Attempt 1 of the redaction trial stopped in draw 2 after 492 of 822 checks, and is
[inconclusive](m7-12-results.md). 45 of the 48 checks that failed were refused by the engine's own
token allowance before any provider call. This note says why, from the limiter's own figures and
attempt 1's records, and what the harness does differently. The rows, manifest, margins and
ceilings are unchanged.

## The cause

**The bucket.** The trial's checks are tagged `calibration`. The gateway holds each non-production
consumer to a tenth of the project's token target (M3-08). At the Tier 1 defaults the target is 68%
of 1,000,000 tokens a minute, and the project bucket holds 5 seconds of it and refills at
`target / (60 + 5)` a second, so that a full bucket plus a minute of refill is exactly the target
(`gateway/token_rate.py`). A tenth of that is the consumer's bucket:

| | |
|---|---|
| Refill | 1,046 tokens a second (62,769 a minute) |
| Capacity | 5,230 tokens (5 seconds of refill) |
| A call's charge | its estimate, **but never more than the capacity**; when the call returns, the charge is corrected to the usage the provider reports, and the bucket may go into debt, down to minus its capacity |
| A call is refused | when the bucket holds less than that charge (no provider call, reason `token_rate`) |

**What attempt 1 did.** It spaced the starts of checks by a fixed interval, 2.089 seconds, from the
mean estimate (1,894 tokens a check) over 80% of the consumer's allowance. Two things were wrong
with that:

1. The allowance it used was 68,000 tokens a minute (the target over 60 seconds), not the limiter's
   62,769 (the target over 65): 8% more than the bucket refills.
2. A mean says nothing about a check that is larger than the mean. The rows are very uneven: median
   870 tokens, mean 1,894, largest 14,176. **18 of the 137 rows (108 of 822 checks, 53% of all the
   tokens) are larger than the bucket**, and 22 are larger than the 2,185 tokens one interval
   refills. A check larger than the bucket is charged the whole bucket, so it needs a full one, and
   it needs 5 seconds idle to get there; when it returns, the provider's usage (up to 10,665 tokens)
   settles it into debt, and the checks after it wait for the debt to clear. At a fixed 2.089 seconds
   the next ones arrive too soon.

**Attempt 1's records fit this.** Charging each check its row's estimate and settling it at the
usage attempt 1 recorded, a model of this limiter (the same `ConsumerAllowances` code behind a fake
clock) refuses 45 of attempt 1's 492 checks at the times it sent them: the very 45 it recorded. By size,
the 70 checks of rows larger than the bucket were refused 38 times; 7 smaller checks were refused
too, right after one of those left the bucket in debt. A test (`tests/calibration/test_m7_12_pacing.py`) replays the records and keeps this true. The estimates themselves are sound:
over the smaller rows the usage is 0.80 to 1.16 times the estimate (median 0.99); over the larger
ones 0.68 to 0.79, so the estimate is on the safe side exactly where it matters.

**Why the floor@2 red-team run had none.** It used the same consumer allowance (`red_team`, the
same tenth) and the same kind of pacing, but its rows are small: the largest is 1,009 tokens by
estimate (mean 905), well under the 1,569 tokens one 1.5-second interval refills, so no check could
outrun the bucket. The held-out rows of this trial are the long `plan`, `tool_call` and
`tool_result` ones, which is what the redaction trial needs to cover.

The other 3 failed checks of attempt 1 were timeouts of about 3.0 seconds (two provider calls
each, all in draw 2). Those are provider failures and count as before.

## What changed

**1. Pacing by each check's own size.** Before each check is sent, the runner asks the gateway's
limiter how long it would make a call of that size wait (`DecisionGateway.consumer_admission_wait`,
which reads the consumer's bucket and takes nothing), and sleeps exactly that long, asking again
until it is told 0. The size is the check's estimate raised by 25% (attempt 1's records show the
usage within 16% above the estimate; the limiter charges the engine's own figure for the request it
builds, which can differ a little from the harness's), and the existing 1.5-second floor between
starts stays. The wait reads the real bucket, so debt left by the check before is waited out
whatever its real usage was.

**2. The plan models the same limiter.** `plan` runs the run's real order (the same reshuffles and
arm order) through the same `ConsumerAllowances` code, each check waiting, being charged and
settling at its estimate, and reports the minutes, the number of checks that wait and the longest
wait (about 9.5 seconds, a check in debt). It refuses if the bucket holds no tokens or if any check
would wait more than 30 seconds.

A check larger than the bucket does not make the plan refuse: the limiter admits it by reserving
the whole bucket, and the debt that follows is in the plan's minutes. What would be unrunnable is a
consumer whose bucket cannot admit any check, or one that makes a check wait for ever, and those
the plan refuses.

**3. The stop rule.** A check the engine refused itself (no provider call, reason `token_rate`,
`quota_exhausted`, `admission_wait` or `admission_queue_full`: the gateway's capacity refusals
except `orphan_cap`) is recorded as before but is not counted in the 20%-of-50 rule, and the run
**stops at the first one** (`run_stopped`, reason `local_refusal`). With the pacing above, a local
refusal means the harness got something wrong, which is a bug and not noise. If instead the limiter
still would not admit a check after being asked and waited for 8 times, the run stops before
sending it and records why (`run_stopped`, reason `admission_gave_up`). Timeouts and `unavailable`
failures that reached the provider count as before.

**4. The second attempt.** `--attempt 2` has its own marker and lock, is refused unless attempt 1's
marker exists, and is refused once its own exists; attempt 1's files are untouched and nothing is
removed or bypassed. The arming script takes the start time (`YYYY-MM-DDTHH:MM`, UTC) and the
attempt as arguments; the window is the start plus two hours; the output directory must be new.

## The plan for the approved rows

| | Attempt 1 plan | Attempt 2 plan |
|---|---|---|
| Rows, checks | 137, 822 | 137, 822 |
| Estimated input tokens | 1,556,874 | 1,556,874 (ceiling 2,000,000) |
| Provider calls | 822 (ceiling 900) | 822 (ceiling 900) |
| Pacing | 2.089 s apart | each check waits for its own size |
| Estimated time | 28.6 minutes | 27.7 minutes |
| Checks that wait for the limiter | not modelled | 128 of 822, longest 9.5 s |

The minimum is set by the allowance, not by the pacing: 1.56 million tokens at 1,046 a second is
24.8 minutes. The real run should be a little faster than the plan, because the plan settles each
check at its estimate and the larger ones really use about 74% of it.

## What it doesn't change

Nothing about what is sent, to whom, or how it is analysed. The limiter and its allowances are as
they were; the harness now asks it instead of guessing. Whether redaction changes decision quality
is still unmeasured.
