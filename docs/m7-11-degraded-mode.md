# M7-11 · A defined degraded mode for a provider outage (as built)

Before this, a provider outage cost every check its whole budget (3 s, 4 s at `input`) plus a
retry, and then blocked it. The floor fails closed at every guard point (B1), so the block is
right; waiting for it was the problem. Now the gateway notices the outage, fails checks **at once**
with a reason that says so, and probes until the provider answers again.

**No guard point falls back to allow during an outage.** The decision is what it always was for a
failed call: every rule by its fail mode, which at the floor is a block. This can be revisited;
it would need its own decision, a list of guard points and a bound on how long it lasts.

## Detection (per key, per process)

The gateway's **provider-health breaker** opens for an API key when:

* **5 calls in a row** timed out or came back `unavailable`; or
* **more than half of the last 20 calls** did, all 20 within **30 s**.

These are provisional platform settings (`gateway.degraded_consecutive`,
`gateway.degraded_window_calls`, `gateway.degraded_window_s`; 0 turns a trigger off).

What counts, and what doesn't:

* Only a call that was **sent** counts. Admission refusals, the orphan cap and token-rate refusals
  are the gateway's own capacity, not the provider.
* An answer (or a provider safety refusal) is a success and breaks the run.
* **Not counted:** a 429 (the provider is up and limiting us), an auth failure (the auth breaker
  has its own and comes first), an answer the engine could not use, and a timeout of a call that
  did not run its **whole attempt deadline** (the expected p50 plus the margin). A call cut
  sooner by the check's own smaller budget (a fixed per-guard-point budget, or the rest of the cap
  a copy has left after waiting under repeat-attempt counting) says nothing about the provider:
  a healthy call is often slower than its p50.
* **More than one tenant.** One tenant's content can make the provider fail for it alone, so a
  trigger needs failures from at least **two tenants**, unless only one tenant called the key
  within the window (a single-tenant or dedicated key trips on its own failures).
* While the breaker is open, calls that were already in flight and end later decide nothing:
  only the probe closes it.

## What a check gets while it is open

* `Failed(unavailable, reason="provider_degraded")` **at once**: no queue, no wait, no provider
  call (`provider_calls` is 0). The deterministic checks before the model (deny patterns, secret
  formats, size, allow-list, repeat refusals) still run, and still block as they did.
* The verdict is the failed-call verdict: `model_failure`, with the decision from the rules' fail
  modes, **marked `degraded`** (new on the verdict and the SDK result), `failure_reason`
  `provider_degraded`, `retryable`, and `retry_after_ms` set to the time until the next probe
  (100–10,000 ms). `capacity_limited` is false: the call would have been made if the provider
  were answering.
* The mark comes from the gateway's own signal (where the refusal was made), never from a reason
  string: a provider that sent the text `provider_degraded` is read like any other `unavailable`.
* A check that was queued, or that would retry, when the breaker opened is refused the same way;
  its first attempt's result stands.

## How it ends

* **Probing.** The first probe is allowed 5 s after it opens; each probe that fails doubles the
  wait, up to 60 s (the auth breaker's schedule). Exactly one check is the probe: it is never
  retried or cut early, and pays its full budget; every other check keeps failing fast. A probe
  the provider answers (an answer or a provider safety refusal) **closes** the breaker, and the
  next checks call the provider normally. A probe that admission refuses doesn't count.
* **Key replaced.** The state belongs to the key; a replaced key starts clean.
* **An operator** can hold the provider degraded and lift the hold (below). Lifting also clears
  any breaker the gateway opened.

## The operator's hold

`GET /v1/platform/provider/degraded` shows each gateway's state (shared pool and each dedicated
project): whether it is degraded, whether held, how it opened, and the seconds to the next probe.
`PUT /v1/platform/provider/degraded` with `{"degraded": true|false, "reason": "..."}` holds or
lifts it for every gateway in the process. Held, every check fails at once as `provider_degraded`
with **no probe** and no `retry_after_ms`, until the operator lifts it.

* **Platform operators only**, like the other `/v1/platform` routes. A tenant credential, with any
  role and on any tenant, gets 403 `not_platform_operator`, and nothing changes (tested).
* Each change is a **class A event** (`provider_degraded_hold`, `provider_degraded_lift`: who,
  when, the reason, in the platform audit table, migration 056). It is recorded **before** the
  gateways change; if it can't be recorded the answer is 503 and nothing changed.

## Marking and alerts

* Verdict `degraded`; audit record `degraded` (schema version 7; earlier records still load);
  span attribute `guardrail.degraded`; SDK `GuardResult.degraded` and `FailureReason`
  `provider_degraded` (retryable: try again after `retry_after_ms`).
* Alerts: `decision_provider_degraded` (a page, reason `consecutive_failures`, `failure_rate` or
  `operator`) when it opens, and `decision_provider_recovered` (a warning, reason `probe` or
  `operator`) when it closes.
* The measurement harnesses (calibration, the load test) turn it off: they measure the provider
  and the gateway's own limits, and failing rows at once would measure the breaker instead.

## Residuals (stated, not fixed)

* **Per process, like the auth breaker.** Each replica learns an outage on its own (5 calls
  each) and probes on its own; an operator's hold is per process too, so with several replicas it
  is set on each. Shared state across service replicas is deferred (M7-10 step 5).
* **One tenant on a quiet key can still trip it.** If only one tenant is calling a key, its own
  failures open it, for about 5 s per cycle until a healthy probe closes it. A real outage that
  only one tenant's traffic sees is also learned a little more slowly on a busy key.
* **A short configured budget never feeds timeouts to the breaker.** A timeout counts only when
  the call had its full attempt deadline, so a guard point whose budget is below that deadline
  never adds one. An outage seen only there doesn't open it; those checks keep their short
  timeout, as before. Unavailable answers there still count, and so do timeouts at guard points
  with a normal budget.
* **A cancelled probe** (the caller disconnects) gives back the wait it had doubled: the provider
  told us nothing.
* **The probe pays full price.** One check per probe interval waits out its whole budget.
* **A flaky provider below the thresholds** (say 40% of calls failing) never opens it; those
  checks keep their budget and retry as before.
* **Thresholds are provisional**: nothing measured them against a real outage.
* **No second provider and no fallback.** A longer outage blocks every check at every guard
  point, quickly and with a label, until it passes.
