# Mute FAQ

These are questions readers asked about Mute, with straight answers. Where something isn't built or measured yet, the answer says so, and the [roadmap](../ROADMAP.md) shows what's planned.

The IDs in these answers and in the code (`M6-01`, `PF-12`, `R6.3`) are explained in the [decisions glossary](DECISIONS.md).

**Context for every answer:** Mute hasn't been deployed and hasn't served real traffic. Its thresholds were calibrated on synthetic test data and are provisional.

## Calibration and validation

**Have you replayed real agent traces to tune the escalate band?**
Not yet. It's the next step (M6-01). The thresholds in the domain packs come from live Gemini calls on synthetic golden sets.

**How will you check that calibration holds on real traffic?**
Every check stores the policy bundle version and every rule's probability. A threshold change can therefore be replayed against recorded decisions offline, which is exact because the recorded probabilities don't change. It can then run in shadow mode and on a slice of traffic before it enforces. Until real traffic exists, this is designed but untested at scale.

**How do you validate the escalate-versus-block line without a bad call slipping through first?**
Through the same path: replay recorded probabilities against the new line, then shadow mode, a partial rollout and a soak, before the change enforces. A threshold change can also be made stricter first and relaxed later, which fails safe.

**How often will tenants hit the escalate band?**
Unknown until there's real traffic. The escalate rate is tracked per rule. M6-02 adds an alert when a rule escalates too often.

**Where will calibration be messiest?**
It depends on the domain. Ambiguous tool outputs and escalation fatigue are both likely. Overlapping rules are another: in the finance and healthcare calibration, some rules also scored high on other rules' violations.

**How much does a single draw move a score near the block line?**
Some. On one finance rule, the spread of a row's three draws reached 0.14 at the 95th percentile. The calibration now reports recall on single draws as well as on the three-draw mean. For a sender who resubmits blocked content hoping for a lower draw, the same content blocked twice in 15 minutes is refused without a model call (M7-03), per tenant, at `input`. At the current provisional thresholds, every single draw of every violating example in the finance and healthcare test sets was caught. M6-01 will measure how often a single draw flips the action near each line on real traces.

**Why do the slides show a 0.85 block line?**
That was the placeholder before calibration. After the live calibration, most finance and healthcare block lines moved to about 0.50, with escalation at 0.30. All values are provisional.

**How were the safety-floor thresholds tuned, and do tenants need different settings?**
The platform sets the floor and validated it on a held-out set. It's provisional until real traffic. Tenants can only make the floor stricter. Calibration of a tenant's own rules uses the tenant's labelled examples and suggests thresholds, which the tenant accepts or overrides.

**What happens to thresholds when an agent moves to a new domain pack?**
A bundle pins each pack's version, so a pack upgrade never changes an existing tenant silently. Adopting a new pack or version is a policy change. It goes through the publish path (drafts, golden-set tests, shadow mode, partial rollout), and the tenant's own examples can be re-calibrated against it.

**How do you version thresholds so past decisions can be replayed exactly?**
Each policy change creates a new bundle version, and old versions are kept. Each audit record names the bundle version it ran under and every rule's probability, so a past decision can be recomputed exactly under its own thresholds or any other set.

## Escalation and the human loop

**What happens to a borderline score, say 0.55?**
If it falls between a rule's `escalate_at` and `block_at`, the check escalates. The action is held for a human review queue or the tenant's webhook. There's no silent re-ask of the model.

**What if the provider's own filter refuses the content?**
That is a block with the reason `provider_safety`, and it is never retried. The one exception: where the guard point has a rule that may only escalate (urgent medical symptoms, self-harm risk, a scam signal, a fraud signal, a safety report), the refusal goes to the human review queue instead (M7-08), so a person sees what the provider would not judge. The content is withheld either way. It is capped per tenant and guard point (20 in 15 minutes, provisional), and past the cap it is a block again, with an alert. At such a guard point a refused jailbreak also goes to a person rather than being blocked. Elsewhere (the floor, and `plan`, `tool_call` and `output` in every pack) a refusal is a block.

**Where's the line between escalating and blocking?**
Each rule has its own `block_at` and `escalate_at`. Calibration aims for a block precision of at least 0.95 and an escalate recall of at least 0.90. Some rules, such as urgent medical symptoms or a customer who may be being scammed, can only escalate, never block, because a person should look.

**How do you stop escalations becoming a bottleneck?**
Escalate rates are tracked per rule. A wide band can be narrowed by replaying recorded probabilities and rolling out the change partially. Reviewer decisions become labels, which improve the next calibration. Some finance rules currently escalate from 0.30, which is wide; real traffic will show whether it needs narrowing. M6-02 adds rate alerts.

**Are reviewer overrides logged?**
Yes. Each resolution stores the decision, who made it and when, and becomes a golden-set label. When the guardrail and the reviewer disagree, the reviewer's decision is the label.

**Who answers an escalation at 11 pm?**
The tenant decides who staffs its queue. Mute doesn't guarantee an answer today. M6-02 adds an escalation timeout, with a fallback for each rule (block by default), so an unanswered escalation is safe.

## Failure modes

**If the Gemini call times out, does Mute allow, escalate or block?**
A failed call gets one retry within the deadline. If that fails too, the check blocks by default, with a retryable "temporarily unavailable" result. A tenant can set its own rules at a guard point to fail open, but the platform's safety floor always fails closed, and floor rules run at every guard point. In practice, then, a provider outage blocks every check, and a tenant's fail-open setting doesn't change that.

Since M7-11, an outage is noticed rather than waited out: after 5 failed calls in a row (or more than half of 20 within 30 seconds, from at least two tenants), checks fail at once with a retryable `provider_degraded` result and a hint of when to retry, and Mute probes the provider until it answers. An operator can also hold or lift the state. No guard point lets content through during an outage, and a second provider or a fallback for chosen guard points is not built (see the [roadmap](../ROADMAP.md)).

## Security and adversarial robustness

**Does the agent's process hold the provider key?**
By default, yes: the guard is a library, so the agent runtime holds the provider key and the database credentials, and rate limits are counted per process. Since M7-10 there's another mode. The guard runs as its own service, and the agent uses the SDK's `connect`, which refuses to start if its environment holds a key or a database URL. Then the runtime holds neither. Counts shared across several service replicas aren't built yet.

**What if a prompt or a tool result contains an API key or password?**
Known secret formats (cloud and API keys, tokens, private keys, URLs with passwords) are found without a model call (M7-01). Where the agent emits or acts, the check blocks. In user input and context the secret is replaced by `[SECRET]` before anything is sent to the provider. A secret in a format Mute doesn't know isn't caught.

**Does redacting personal data make the checks worse?**
Not by any large amount on recall, in the one trial so far, and it's kept on. Mute replaces eight formats (email, phone, card, IBAN, UK sort code and account number, UK NINO, US SSN) before a check reaches the provider; names, addresses and health details are sent as written. In November 2026, 137 synthetic rows, 97 of them changed by that redaction, were checked with and without it (M7-12). With all rules pooled, redacted text caught 57 of 58 positive cases (a row and a rule it should trip) and unredacted text 56, and the loss from redaction is bounded under 10 points. No rule had a case that redaction caused it to miss (the limit was 2). On 43 benign rows, false positives were 2 with redaction and 1 without, a rise of 2.3 points against a margin of 5.

The limits matter. The 10-point bound isn't met by any single rule on its own, and `p__xtenant_probe` had no positive case to test. The false-positive interval reaches +12.3 points, so a rise of 5 or more isn't ruled out. On one row with two email addresses, redaction raised the data-exfiltration score enough to block it. The data is synthetic, and this says nothing about redacting more than today. Widening redaction hasn't been decided. A first attempt stopped early on the engine's own rate limiter, which the harness had paced wrongly; it was fixed and the trial rerun. See the [results](m7-12-results-2.md).

**Can a prompt that fools the agent also fool the judge?**
Possibly, and it's unmeasured. Untrusted content goes in a section fenced with per-call nonces and is evaluated, never followed. The judge is a separate call with minimal context, and it never sees the agent's own justification. A floor rule also asks whether the content tries to influence an AI system. Correlated failure when both share a model family is an open problem (M6-05).

**The money rule only checks that an approval reference is named. Can't an injected agent invent one?**
Yes. The rule is a second line of defence. The real control belongs in the money-moving tool: a credential the tool verifies, bound to the amount and the payee. The [finance pack README](../packs/finance/README.md) says so.

**Can the agent change the policies that govern it?**
No. Policies change only through a separate Admin API, with drafts, tests and an audit trail. Publishing needs a person's sign-in with the `guardrail_admin` role, and the agent's guard calls don't carry one. Regulated tenants also need two-person approval.

**What about risks that only appear across several steps?**
That's a real gap. Mute checks each step on its own. M6-04 is a design spike for a check over the run so far, such as the total amount moved.

## Observability

**How do you trace a blocked legitimate action to one rule?**
Each check leaves one audit record: the bundle version, each rule's probability, and the rules that fired. The rule that blocked is named.

**Can audit records be lost?**
For a standard tenant, a full writer queue drops the record and counts it. For a regulated tenant (M7-04) the check waits up to a quarter of a second for room, then writes the record to a local file that is replayed into the store without duplicates. The verdict is final before the audit is attempted and doesn't change.

**Are per-question scores logged? Do you audit allowed items?**
Every rule's probability is logged on every check. Random sampling of allowed checks for human review isn't built yet; it's M6-03.

**Does the guard see what a tool actually returned, including stale data?**
Yes. `tool_result` is one of the five guard points, and a content hash is kept. Whether data is stale is treated as data governance, outside the guardrail's scope.

## Multi-tenancy and policy layering

**What happens when the safety floor and a domain pack disagree?**
The strictest rule wins. Tenants can tighten floor thresholds but never loosen or remove floor rules.

**Who decides which steps need blocking?**
Three layers: the platform floor, the domain packs a tenant turns on, and the tenant's own rules, written as plain yes/no questions. All of it is edited through the Admin API.

## Model and getting started

**Which model is the judge?**
Gemini Decision 1, Google's decision model. One call per check carries all of a guard point's questions.

**Can a beginner try it on a small project?**
Yes. Start with the [README](../README.md), which covers setup and the offline tests (no API key needed). Then read the design doc. The demo cards in `demo/` show it on example tenants.

**What's next?**
Replaying real traces (M6-01) is the main next step. See the [roadmap](../ROADMAP.md).
