# Mute FAQ

These are questions readers asked about Mute, with straight answers. Where something isn't built or measured yet, the answer says so, and the [roadmap](../ROADMAP.md) shows what's planned.

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
Some. On one finance rule, the spread of a row's three draws reached 0.14 at the 95th percentile. The calibration now reports recall on single draws as well as on the three-draw mean. At the current provisional thresholds, every single draw of every violating example in the finance and healthcare test sets was caught. M6-01 will measure how often a single draw flips the action near each line on real traces.

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
A failed call gets one retry within the deadline. If that fails too, the check blocks by default, with a retryable "temporarily unavailable" result. A tenant can let a low-stakes guard point fail open, but the platform's safety floor always fails closed.

## Security and adversarial robustness

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
