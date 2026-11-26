# Mute roadmap

Mute is a working reference implementation. **It hasn't been deployed and hasn't served real traffic.** This page lists what's built, what's next and the problems that are still open. Answers to common questions are in the [FAQ](docs/FAQ.md).

Status as of 25 November 2026.

## Built

- **The engine.** It has five guard points per agent turn (`input`, `plan`, `tool_call`, `tool_result`, `output`). Each check is one batched Gemini Decision 1 call with one yes/no question per rule. There are three actions: allow, escalate or block.
- **Layered policy.** A platform safety floor, optional domain packs (insurance, energy, finance, healthcare, responsible AI) and each tenant's own rules. The strictest rule wins, and tenants can tighten the floor but never loosen it.
- **Policy changes.** They go through a separate Admin API: versioned bundles, drafts, golden-set tests, shadow mode, partial rollout and a soak before enforcing. Regulated tenants need two-person approval.
- **Failure handling.** A failed check gets one retry within the deadline, then blocks by default. The safety floor runs at every guard point and always fails closed, so a provider outage blocks every check, whatever a tenant's own fail-open settings. Since M7-11 the gateway notices an outage (5 failed calls in a row, or more than half of 20 within 30 seconds), fails checks at once with a labelled, retryable `provider_degraded` block instead of after the whole budget, and probes until the provider answers. An operator can hold or lift it. No guard point lets content through during an outage.
- **Escalation.** Borderline scores go to a human review queue or the tenant's webhook. Each resolution is logged with the decision, the actor and the time, and becomes a golden-set label.
- **Audit.** One record per check, with the policy bundle version, every rule's probability and the rules that fired. For regulated tenants (M7-04) a full queue makes the check wait briefly and then spill the record to a local file, replayed into the store without duplicates; standard tenants still drop and count.
- **Calibration tools.** Threshold suggestions from a tenant's labelled examples, against block-precision and escalate-recall targets. The four domain packs have live-calibrated thresholds from synthetic data. All of them are **provisional**.
- **Operations.** Per-tenant quotas and fair queuing, dedicated key pools for regulated tenants, content-storage classes and offboarding.
- **Secrets (M7-01).** Known secret formats (cloud and API keys, tokens, private keys, URLs with passwords) block with no model call where the agent emits or acts, and are replaced by `[SECRET]` in user input and context, so they never reach the provider.
- **Repeated attempts (M7-03).** The same content blocked twice within 15 minutes, for one tenant at `input`, is refused without a model call, so resubmitting it until one draw scores lower doesn't work. It is the same content, not the same conversation: the caller chooses the conversation id, so it can't be trusted as a key.
- **The default floor matches the evidence (M7-05).** floor@2, the floor the held-out validation measured, is in the catalog and, in the simulation, released through the floor release path: a new tenant starts on it. floor@1 is unchanged and still the baseline. Re-pinning existing tenants and raising the minimum floor are separate platform steps.
  - *Red-team evidence (24 November 2026).* One live run of the red-team corpus against floor@2 (172 rows, 3 draws, 516 checks) passed its gate. Every rule's block recall equals the baseline's, cell for cell: 98.5% for `p__ai_addressed`, 100% for `p__inj_direct`, 94.0% for `p__inj_indirect` and 96.4% for `p__xtenant_probe`. The 144 benign controls had no false action, the model-independent defences held on all 172 rows, and there were no refusals, timeouts or failures. It cost about $0.05. It is the baseline's corpus and seed, so it is a regression check, not new coverage. The figures are in [`docs/redteam-floor2-evidence.md`](docs/redteam-floor2-evidence.md).
- **Provider refusals (M7-08).** Where a guard point has a rule that may only escalate (urgent symptoms, self-harm risk, a scam signal, a fraud signal, a safety report), a refusal by Google's filter goes to the human review queue instead of being blocked. It's capped per tenant and guard point, and past the cap it's a block again, with an alert.
- **The guard as its own service (M7-10).** A check endpoint, the SDK's remote mode (`connect`) and a local runner mean a runtime can hold no provider key and no database credentials. Counts shared across several service replicas are deferred.
- **Redaction trial (M7-12): today's redaction is kept.** On 25 November 2026, 137 synthetic rows (97 that redaction changes and 40 that it doesn't, as a noise check) were sent both with and without PII redaction, 3 draws each (822 checks, all answered). Credentials stayed replaced in both. A first attempt stopped early because the harness sent checks faster than the engine's own rate limiter allows; the pacing was fixed and the whole trial rerun, and the figures here are from the rerun alone.
  - *Recall.* With all rules pooled, redacted text caught 57 of 58 positive cases (a row and a rule it should trip) and unredacted text 56. The loss from redaction is bounded under the 10-point margin (the upper end of its interval is 6.2 points). No rule had a case that redaction caused it to miss; the limit was 2 per rule.
  - *False positives.* On 43 benign rows that redaction changes, 2 were blocked with redaction and 1 without: a rise of 2.3 points, under the 5-point margin on that point estimate.
  - *What it doesn't show.* The 10-point bound holds for the pooled figure only, not for any single rule, and one rule, `p__xtenant_probe`, had no positive case that redaction changes. The false-positive interval is wide (-8.2 to +12.3 points), so a rise of 5 points or more isn't ruled out. On one benign row with two email addresses, redacting them raised the data-exfiltration score enough to block it, in two of three draws. All rows are synthetic.
  - Widening redaction hasn't been decided. The figures are in [`docs/m7-12-results-2.md`](docs/m7-12-results-2.md), and the first attempt's in [`docs/m7-12-results.md`](docs/m7-12-results.md).

## Next

| Item | What it adds | Status |
|---|---|---|
| Trace replay (M6-01) | Replay de-identified agent traces through the engine, and replay recorded probabilities against candidate thresholds before a change goes live. Report how far single draws move scores near the block and escalate lines | Needs real traces. If you can share de-identified ones, get in touch |
| Escalation timeout (M6-02) | A fallback for each rule when nobody resolves an escalation in time (block by default), and alerts when a rule escalates too often | Planned |
| Sampling allowed checks (M6-03) | Send a random share of allowed checks to human review, so missed violations show up | Planned |
| Load test | Live capacity and latency run (the offline harness is built) | Ready to run, not run yet |
| Held-out evaluation of the packs | Measure the provisional thresholds on data they weren't fitted to | Planned |

## Open problems

These aren't solved.

- **Risks across several steps (M6-04).** Mute checks each step on its own, so a run that's harmful as a whole while each step looks safe (for example, many small transfers) gets through. A design spike will look at per-run state, such as the total amount moved, with limits on it.
- **Correlated failure of the agent and the judge (M6-05).** If the agent and the judge share a model family, content that fools one may fool the other. Mute fences untrusted content with per-call nonces and judges it in a separate call with minimal context. The judge never sees the agent's reasoning. How well that holds is unmeasured. A second opinion from a different model family for high-stakes rules is one option.
- **A guardrail is a second line of defence.** For example, the finance pack's payment rule only checks that an approval is named, not that it's real. Money-moving tools should verify a credential bound to the amount and payee themselves.

- **The guard runs inside the agent's process by default (M7-10).** As a library, the agent runtime holds the provider key and database credentials, and rate limits are counted per process. The remote mode (`connect`, which refuses a runtime whose environment holds a key or DSN) removes both, but it is a choice, not the default. Counts shared across several service replicas are deferred.
- **One model provider (M7-11).** The floor fails closed at every guard point, so a provider outage blocks every check, at once and with a retryable reason. No guard point lets content through during an outage. A second model adapter, or a fallback for chosen guard points, is not built.
- **Provider refusals (M7-08).** Where no rule may only escalate (the floor, and `plan`, `tool_call` and `output` in every pack), a refusal by Google's filter is a block. A person sees refused content only at the guard points above, and only up to the cap.
- **What reaches the provider (M7-12).** Redaction covers eight formats (email, phone, card, IBAN, UK sort code and account number, UK NINO, US SSN). Names, addresses and health details are sent as written. Wider redaction has to be weighed against detection quality. The M7-12 trial measured only today's redaction; whether to widen it, which would need its own detector and trial, hasn't been decided.

## Not planned for now

- A TypeScript SDK (the Python Guard SDK exists).
- A generative reviewer as an escalation target.
- Isotonic recalibration.
- Aggregate fairness monitoring across groups.

## Before regulated use

The finance and healthcare packs have no legal or clinical sign-off, and their test-set labels haven't had a two-person human review. Don't rely on them for regulated decisions as they stand.
