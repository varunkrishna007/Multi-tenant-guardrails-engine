# Mute roadmap

Mute is a working reference implementation. **It hasn't been deployed and hasn't served real traffic.** This page lists what's built, what's next and the problems that are still open. Answers to common questions are in the [FAQ](docs/FAQ.md).

Status as of 23 November 2026.

## Built

- **The engine.** It has five guard points per agent turn (`input`, `plan`, `tool_call`, `tool_result`, `output`). Each check is one batched Gemini Decision 1 call with one yes/no question per rule. There are three actions: allow, escalate or block.
- **Layered policy.** A platform safety floor, optional domain packs (insurance, energy, finance, healthcare, responsible AI) and each tenant's own rules. The strictest rule wins, and tenants can tighten the floor but never loosen it.
- **Policy changes.** They go through a separate Admin API: versioned bundles, drafts, golden-set tests, shadow mode, partial rollout and a soak before enforcing. Regulated tenants need two-person approval.
- **Failure handling.** A failed check gets one retry within the deadline, then blocks by default. A tenant can let a low-stakes guard point fail open, but the safety floor always fails closed.
- **Escalation.** Borderline scores go to a human review queue or the tenant's webhook. Each resolution is logged with the decision, the actor and the time, and becomes a golden-set label.
- **Audit.** One record per check, with the policy bundle version, every rule's probability and the rules that fired.
- **Calibration tools.** Threshold suggestions from a tenant's labelled examples, against block-precision and escalate-recall targets. The four domain packs have live-calibrated thresholds from synthetic data. All of them are **provisional**.
- **Operations.** Per-tenant quotas and fair queuing, dedicated key pools for regulated tenants, content-storage classes and offboarding.

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

## Not planned for now

- A TypeScript SDK (the Python Guard SDK exists).
- A generative reviewer as an escalation target.
- Isotonic recalibration.
- Aggregate fairness monitoring across groups.

## Before regulated use

The finance and healthcare packs have no legal or clinical sign-off, and their test-set labels haven't had a two-person human review. Don't rely on them for regulated decisions as they stand.
