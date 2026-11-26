# Decisions glossary

Comments, docstrings, tests and design notes in this repository cite short identifiers such as `PF-8`, `B1`, `S4`, `U7.1`, `R6.3`, `AC-C1.8` and `M1-04`. They point at decisions and work items from the project's internal backlog. That backlog isn't published, so this file is the public record: every identifier cited in the public tree has an entry here, with what was decided and why.

This is a lookup table, not a specification. The design is in [the design doc](../Multi-Tenant%20Guardrail%20Engine%20on%20Gemini%20Decision%201%20%E2%80%94%20Design.md), and the per-feature notes are the `docs/m*.md` files.

## How to read the identifiers

| Family | Looks like | What it is | Section |
| --- | --- | --- | --- |
| Decision groups | `R1` to `R10`, and sub-items such as `R6.3` | Product and engineering questions that were decided once and then cited from code. `R6.3` means item 3 of group `R6`. | [Decision groups](#decision-groups-r) |
| Blockers | `B1`, `B2`, `B3` | Three design flaws that had to be fixed before building could start. | [Blockers](#blockers-b) |
| Platform foundations | `PF-1` to `PF-17` | Numbered design findings raised while checking the first design against the real API and the multi-tenant requirements. `PF-1` to `PF-3` are the blockers `B1` to `B3`. | [Platform foundations](#platform-foundations-pf) |
| Scope calls | `S1` to `S5` | What v1 will and won't do. | [Scope calls](#scope-calls-s) |
| Owner decisions | `U1` to `U7.1` | Questions put to the project owner, with the answer given. | [Owner decisions](#owner-decisions-u) |
| Acceptance criteria | `AC-C1.8`, `AC-G3`, `AC-M1-4` and so on | Testable criteria. The letter says the area: C compiler, G guard service, T tenancy, A admin API, O observability, P portability, M model port. | [Acceptance criteria](#acceptance-criteria-ac) |
| Stories | `M0-01` to `M7-12` | Work items, grouped into eight milestones. | [Stories](#stories-m) |

Words used below:

- **Floor**: the platform rules every tenant gets and can't loosen. **Pack**: a curated set of rules for a domain (insurance, energy, finance, healthcare, responsible AI). **Tenant rule**: a rule a tenant wrote.
- **Guard point**: where a check runs: `input`, `plan`, `tool_call`, `tool_result` or `output`.
- **Provisional**: a threshold or rule that is in use but isn't backed by enough evidence to be called final.
- **Status** in the story tables. *Built*: merged and covered by the offline test suite. *Partly built*: the offline part is built and a live, real-traffic or human-review part isn't. *Not built*: no code. "Built" says nothing about live evidence: nothing here has been deployed or has served real traffic, and every calibrated threshold is provisional.

Some comments in the code also cite numbered findings from internal code reviews. Those are not decisions and have no entry here. Their text says what was fixed.

---

## Decision groups (R)

### R1. Free-text rules and templates

- **R1**. Tenants may write free-text rules. Curated templates are the recommended start, not a requirement. The control is on *enforcing* a rule, not on who wrote it. A rule with no platform calibration (free text, a template copy or a fork of a pack rule) can publish in `shadow` freely and reaches `enforce` only through an evidence gate:
  - at least 20 labelled examples per guard point, with at least 5 `block` and 5 `allow` (a `severity: high` rule needs 50, with 15 on each side);
  - at least 72 hours in shadow, unless the rule is an unedited template;
  - the rule's `block_at` must meet the tenant's precision target on its golden set (see `B2`).

  Why: self-serve configuration with no code deploy is the first design goal, and routing every new use case through the platform team defeats it. The risk with free text is calibration, not authorship, and shadow mode, golden sets and a threshold sweep address calibration. In v1 tenant rules are yes/no (`noul`) questions only; tenant-written routers (`choice`) and scorers (`score`) are deferred. Built in `M1-01`, `M2-03`, `M2-07` and `M4-01`.

### R2. Two-person approval

- **R2**. Publishing in `enforce`, or promoting a shadow candidate to enforce, needs two different people on the regulated tier. On the standard tier it needs one, or two if the tenant opts in with `require_two_person_approval`. Publishing in shadow, raising `rollout_percent` on an already approved version and rolling back need one person; a rollback notifies the other admins.
  - The approver must be a different human with the `guardrail_admin` role in the same tenant. Self-approval, service accounts and platform operators are rejected.
  - An approval is tied to the draft hash, so any edit cancels it, and it expires after 72 hours.
  - "Regulated tier" is a tenant attribute that platform operators set from the contract. Tenants can't edit it.

  Why: regulated buyers expect separation of duties, and making it opt-in would push that question into every deal. Standard tenants are often small teams that a mandatory second approver would stall. Rollback is exempt because the risky direction is shipping a new policy, not returning to one that was already approved. Built in `M5-02`, with the tier in `M5-01`.

### R3. Retention and content storage

- **R3**. Audit data is split into five classes. When a tenant has several packs, the *longest* record retention and the *shortest* content cap among them apply.
  - **A, config audit** (bundle versions, diffs, actors, approvals): 7 years, immutable.
  - **B, decision records** (one per check: hashes, every probability, verdict, latency, tokens; no content): 395 days by default for standard tenants (settable from 90 days to 7 years), 7 years for the finance pack, 6 years for the healthcare pack, with a 395-day minimum.
  - **C, stored content** (post-redaction text): off by default (`hash_only`). Opt-in is 30 days by default and 90 days at most. For healthcare it needs a business-associate-agreement flag set by platform operators and is capped at 30 days.
  - **D, escalation items** (content held for a reviewer): until resolved plus 30 days; healthcare is 30 days in total.
  - **E, calibration sample**: post-redaction content sampled for calibration, for an internal trial tenant only, kept 365 days. Never collected from external tenants. The sampler (`M1-12`) isn't built.

  Stored content is always post-redaction; `content_sha256` hashes the pre-redaction content (`PF-14`). Offboarding deletes classes B, C, D and E and the golden sets within 30 days and keeps class A. Why: decision records hold no content, so keeping them is cheap and low-risk and makes every decision replayable. Content is where the privacy risk is, so it's off by default and short-lived when on. The finance and healthcare figures follow common six- and seven-year record-keeping practice. **They are not legal advice and have had no legal sign-off.**

### R4. Ethical and bias guardrails

- **R4**. Ethical and bias guardrails ship as a curated pack, `domain/responsible_ai`, rather than as part of the floor. The six items below were decided together.
- **R4.1**. The rules live in a pack, on by default for new tenants. Standard-tier tenants can opt out; the regulated tier requires the whole pack. A pack fits the layering: question text stays fixed so calibration holds, and tenants can only tighten thresholds. On a regulated tenant, a publish, a promotion and a rollback target must all meet the tenant's current tier requirements, including the required pack (`M5-01`).
- **R4.2**. Moving a harm-facilitation rule into the floor was first approved, then superseded by `U5`: it is an observe-only (shadow) rule in the pack, `d__harm_facilitation`, and the floor has no harm rule.
- **R4.3**. For people at risk the engine escalates and never blocks. `d__self_harm_risk` and `d__vulnerability` carry `max_action: escalate`, a rule field that fusion honours. Refusing someone in crisis is the wrong outcome.
- **R4.4**. The claim is bounded. The engine judges one message, plan or tool call at a time. It detects stereotyping and decisions that rely on a protected characteristic (or an obvious stand-in) in individual content. It does *not* measure statistical fairness across many decisions, because that needs outcome and demographic data the platform doesn't hold. Docs and demos say "detects biased content and decisions in individual responses", never just "detects bias". Aggregate fairness monitoring is deferred to v1.1 or later.
- **R4.5**. The guardrails must not be biased themselves. Every floor and pack rule is tested on counterfactual pairs that differ only in a protected attribute, dialect or language; a pair must get the same verdict, and a score difference above 0.10 within a pair is flagged.
- **R4.6**. Some uses of a protected characteristic are lawful in some places (for example age in some underwriting). A tenant may opt out of a single rule of this pack, but only with a written justification stored in the class A audit, and on the regulated tier that needs two-person approval. This applies only to packs that declare `per_rule_optional`; in v1 that is `domain/responsible_ai` alone.

### R5. Floor upgrades

- **R5**. Calibrated thresholds and any later floor change ship as a new floor version (`floor@2`, ...), because the bundle hash covers the floor's thresholds and the catalog refuses to re-register a version with different content.
- **R5.1**. A new floor version needs a passing red-team run (`M2-08`) and approval by two different platform operators. Tenants don't approve floor releases: they can't edit the floor and mustn't be able to hold back a security fix.
- **R5.2**. Moving tenants is a platform-initiated publish: a new version of each tenant's active bundle that changes only `extends`. It is recorded in the class A audit with actor `platform`, and tenant admins are notified.
- **R5.3**. A tenant's override on a floor rule carries over only if it is still stricter than the new floor value. Otherwise it is dropped and the drop is listed in the audit event and the notification. Tenant and pack content is never changed.
- **R5.4**. Rollout is staged. Each re-pinned version starts as a shadow candidate at 100%, runs through a shadow window (72 hours by default, shorter only for a release marked security-urgent), and is promoted tenant by tenant. The platform can halt it.
- **R5.5**. The platform's minimum floor version is raised only after every tenant extends the new floor. Old floor versions stay in the catalog permanently, since stored versions still reference them.
- **R5.6**. A rollback to a version that extends a floor below the minimum is re-pinned on the fly, so an old floor can never come back.
- **R5.7**. The first upgrade, `floor@2`, ships the reworded rules with thresholds still provisional. `provisional: false` waits for the evidence listed under `R7.3`. Built in `M2-09`.

### R6. Latency, question budgets and timeouts

Decided from the latency measurements in `M0-01` (one machine, one location, warm connections, several time windows on one day). All values below are settings, not constants.

- **R6**. The group. The measured latency model is roughly a base of 244, 271, 326 or about 400 ms for 1K, 4K, 8K or 16K input tokens, plus about 2.0 ms per question. Question *count* drives latency; question length barely matters. Network is at most about 70 ms of a call.
- **R6.1**. Question budgets per guard point: at most 50 compiled questions on `plan`, `tool_call`, `tool_result` (per chunk) and `output`, which are on the agent's critical path, and at most 200 on `input`, which runs alongside the planner. These are platform settings.
- **R6.2**. A tenant gets whatever the budget leaves after the floor and enabled packs (roughly 25 to 35 rules on the critical path), and the compiler error names the remaining number. This replaced a fixed limit of 100 rules.
- **R6.3**. Gateway budgets and admission defaults. Each check has a total budget equal to its guard point's cap: 3,000 ms on `plan`, `tool_call`, `tool_result` and `output`, and 4,000 ms on `input`. The first model call gets an attempt deadline of the expected p50 plus the larger of 400 ms or 0.6 times that p50, where the expected p50 is the size-band base plus a 380 ms time-window allowance plus 2.0 ms per question. A timed-out or `unavailable` first call is retried once if the remaining budget is at least the expected p50. A check may wait in admission for 100 ms (`plan`, `tool_call`, `output`), 300 ms (`input`) or 400 ms (`tool_result` chunk). At most 4 calls are in flight per key by default; 8 is adopted only if a trial shows admission pressure at 4 and 8 then passes a "flat latency" test. Why relaxed: the project owner chose longer waits over more timeout blocks (`U7`, `U7.1`). The 380 ms allowance was fitted to the slowest of three time windows. A self-adjusting base is a candidate only (`M4-11`).
- **R6.4**. Retry only after `timeout` or `unavailable`, at most once, and only if the remaining budget allows.
- **R6.5**. No hedging and no splitting of calls in v1. Hedging showed no benefit in the measurements, and both multiply requests against the daily cap and re-bill the input. A retry after a deadline (`R6.3`) is sequential, never a second call in flight for the same check.
- **R6.6**. Token estimate for budgets: 1.20 times the estimate of the input text, plus the estimate of the question text, plus 25 per question, plus 30. It replaced a flat factor that was off by -15% to +12%.
- **R6.7**. What the token budget is for. Content is bounded so `1.20 x estimate(max content + render overhead) + 30` stays within 16,000 (inputs above 16K were never measured). Question *count* is the latency control (`R6.1`). Question text has a sanity bound only: each compiled question at most 400 estimated tokens, and the guard point's question text at most 150 tokens times its question budget. This replaced a single 16,000-token cap on content plus questions, which made the 200-question input budget unreachable with real rules.

### R7. Floor calibration

Decided from the first floor calibration runs on a synthetic set. The set is 57% positive and has few hard negatives, so it can't show precision or final thresholds; it can show false-positive rates and wording problems.

- **R7**. The group. Thresholds stay provisional until the evidence in `R7.3` exists.
- **R7.1**. Rule attribution: reword and retest rather than multi-label. Two floor rules (`p__ai_addressed`, `p__xtenant_probe`) also fired on examples labelled for other rules. The reworded questions are adopted into `floor@2` only if a retest shows cross-rule acts at or below 5% and no regression on the rule's own positives, judged per draw with three or more distinct nonces. Both rewordings passed, one exactly at the limit. If a retest fails, the fallback is multi-labelling.
- **R7.2**. Amendment to `B2`: choose thresholds inside the plateau, with the margin expressed as error rates counted across draws instead of a fixed distance. At most 5% of negatives and 5% of positives may have any draw within 0.10 of the threshold, `block_at` goes at the midpoint of the widest plateau and is never below 0.50, and cross-rule examples don't enter the choice.
- **R7.3**. Thresholds stay provisional (0.85 `block_at` and 0.55 `escalate_at` for `floor@2`) until all of: at least 30 hard negatives per rule and guard point; at least 50 production-shaped inputs per guard point; a held-out set written by someone other than the rule author; false-positive rate targets (block at most 1%, escalate at most 3%, as one-sided 95% Clopper-Pearson bounds, which needs roughly 300 negatives per guard point); at least 3 draws per example; at least 7 days of shadow evidence; and the thin-cell and fairness checks. The hard-negative, production-shaped, held-out, repeat-draw and fairness items were met on synthetic data. The false-positive-rate targets and the shadow evidence need real traffic and are open.
- **R7.4**. Rerun on the larger set with the real renderer, redaction and the fairness check. It informs `R7.1` and `R7.3` and doesn't make thresholds final by itself.

### R8. Retry hint and stable capacity signal

- **R8**. When the gateway itself refuses or fails a check for a reason it can time, it returns `retry_after_ms`, clamped to 100 to 10,000 ms. It covers admission waits and a full queue, the token-rate limit, the orphan cap (1,000 ms if it can't be predicted) and an open auth breaker. A provider 429 passes through the provider's own retry delay when it gives one. The hint is absent for failures the gateway can't time. The SDK exposes it with a stable `failure_reason` enum and a `capacity_limited` boolean, which is true only when the gateway itself refused. Why: a client should be able to tell "at capacity, retry later" from a provider failure without matching strings, and capacity refusals shouldn't each invent their own backoff. Built in `M1-04`, `M1-07` and `M1-15`.

### R9. Authorisation within a tenant

- **R9**. The floor doesn't judge whether an end user may see another end customer's records inside the same tenant. The engine doesn't know who the user is or what they may access, so any rule would be guessing, and replacing deterministic authorisation is a design non-goal. `p__xtenant_probe` covers other *platform tenants* only, and its question says so. The catalog offers an optional template ("Does the request ask for another customer's personal records?") that is described as a signal, not an access control. Docs say plainly: the floor detects attempts to reach other platform tenants; it doesn't enforce which records a user may see within a tenant.

### R10. Provider refusals before scoring

- **R10**. The Decisions API can refuse a call outright (HTTP 400 `prohibited_content`) before any of our rules score it. This group says what that means.
- **R10.1**. The check is blocked with reason `provider_safety` at every guard point, with no per-rule answers. It isn't retryable and isn't a provider-health failure. Built in `M1-13`.
- **R10.2**. For calibration, a provider-refused example counts as caught for the gate decision and is reported separately. It is excluded from every per-rule score, threshold and attribution analysis.
- **R10.3**. Keeping the harm rule in `floor@2`, calibrated on content the provider scores, was superseded by `U4` and `U5`.
- **R10.4**. Docs say plainly that the provider applies its own content filter before our rules, that its behaviour can change without notice, that tenants can't configure it, and that the floor never relies on it.
- **R10.5**. What the client sees: decision `block`, reason `provider_safety`, `retryable: false`, `capacity_limited: false`, no `retry_after_ms`, and a neutral message ("This request can't be processed"), never "temporarily unavailable" and never a tenant-policy message.

---

## Blockers (B)

- **B1** (`PF-1`). **The floor fails closed.** Floor rules (`p__`) block whenever the model fails, times out or is shed, at every guard point, and tenants can't change that. A tenant's `fail_mode` applies only to pack (`d__`) and tenant (`t__`) rules. Under quota pressure the gateway queues checks by priority within the guard point's budget instead of skipping them, and deterministic checks run whether or not the model answers. The recorded outcome is still `block`, with reason `model_failure` (shown to users as "temporarily unavailable", never as a policy message), so an integration that only checks for `block` stays safe. Cost: a Decisions API outage or exhausted quota stops guarded agents for every tenant. A platform setting, `floor_fail_mode` (default `closed`), carries the decision. A deterministic degraded mode is not in v1; see `U2` for when it comes back. Built across `M1-01`, `M1-05` and `M3-07`.
- **B2** (`PF-2`). **Calibration direction.** The first design said `block_at` and `escalate_at` should both be "the lowest threshold meeting the target". That is wrong for `escalate_at`: recall falls as the threshold rises, so the lowest value meeting a recall target is always 0.01. The decision: `block_at` is the *lowest* threshold on a 0.01 grid whose precision on the golden set meets the target, `escalate_at` is the *highest* threshold whose recall meets its target, a collision sets `escalate_at = block_at - 0.01` and reports an empty escalation band, and if no threshold meets the precision target there is no suggestion and the rule fails the precision gate. `R7.2` amends how platform floors are chosen. Built in `M4-01`. For pack thresholds, see `M4-08`.
- **B3** (`PF-3`). **Per-request nonce delimiters.** Every untrusted section (the content, prior turns, plan JSON, tool arguments and results, tool descriptions) is wrapped in delimiters that carry a fresh 128-bit random nonce, `<<<UNTRUSTED:{label}:{nonce}` ... `UNTRUSTED:{label}:{nonce}>>>`, and the instruction line names the nonce. If the nonce happens to appear in the content, a new one is drawn. Content is never escaped or altered. Only a few things are trusted and may sit outside the sections: the tenant domain, the guard point, validated tool names and a `TENANT: <slug> (<id>)` header assigned by platform operators. Tenant ids follow `t_[0-9a-z]{1,32}` and slugs are reviewed and screened against instruction-like words, because a tenant must not be able to steer its own floor checks through the header. Why: an attacker can't predict a nonce, and unlike escaping this leaves the evaluated text byte-for-byte intact. Built in `M1-05`.

---

## Platform foundations (PF)

`PF-1` to `PF-3` are `B1` to `B3` above.

- **PF-4**. **Quota has three limits, and the gateway enforces all of them.** Tier 1 of the Decisions API has 1,500 requests/min, 1M tokens/min and 50,000 requests/day. The daily cap looked like the binding one (about 10,000 turns a day at 5 checks per turn), but later capacity work corrected this: it binds first only for short checks (below about 1,667 tokens per check); at 4,000 tokens per check the per-minute token limit and the monthly spend cap bind first. Test, calibration, red-team and shadow-candidate calls use the same project quota, so they get a separate allowance in the gateway. Built in `M0-03`, `M3-07`, `M3-08` and `M3-09`.
- **PF-5**. When a `tool_result` is split into chunks, answers are merged by taking the maximum probability per question key before fusion. If any chunk fails, the guard point counts as a model failure (`B1`). Built in `M3-04`.
- **PF-6**. A missing, wrong-type or out-of-range model answer for an enforced rule counts as a model failure for that rule's layer and is logged as `contract_violation`. For a shadow rule it is only logged. Answers to routers and scorers resolve to `allow`, since they never act. Built in `M1-03` and `M1-05`.
- **PF-7**. Active and candidate versions. A tenant has one active version and at most one candidate. A shadow candidate runs on `rollout_percent` of conversations and is logged but never acts. An enforce candidate decides that share of conversations and the active version decides the rest. The rollout key is a hash of tenant and conversation id, so every guard point in a conversation uses the same version, and the audit record keeps both the deciding and the candidate version. Built in `M2-07` (rules) and `M4-03` (runtime).
- **PF-8**. Each guard point has one total time budget that covers the first call's deadline, any retry and any admission wait. It replaced the design's fixed 500 ms deadline. The values are now set by `R6.3`. Built in `M1-04`.
- **PF-9**. Invariant: no `tool_call` runs, and no `output` is released, before the `input` verdict arrives. The SDK enforces it, so the input guard can run alongside the planner safely. Built in `M3-02`.
- **PF-10**. Every compiled question counts toward the question budget, routers and scorers included, and a token check bounds the call size. Both were later reshaped by `R6.1` and `R6.7`. Built in `M1-01` and `M2-04`.
- **PF-11**. The deny-pattern regex dialect is RE2 (no backreferences or lookaround). The deterministic actions are `block`, `escalate`, `redact` and `log`. A deterministic `block` skips the model call; a deterministic `escalate` doesn't, and the most severe result wins. Built in `M1-01` and `M3-01`.
- **PF-12**. A provider `safety` refusal on a deciding call blocks, whatever the rule modes or fail mode. The one exception (`M7-08`): at a guard point with an enforce rule that may only escalate, it is an `escalate` with the same reason, within a per-tenant cap and only if an escalation can be routed; the content is withheld either way. On a shadow-candidate call it is only logged. It also covers a refusal before scoring (`R10`), is never retried and isn't counted as a provider-health failure. Built in `M1-05` and `M1-13`.
- **PF-13**. Rollback "takes effect within the cache TTL", not immediately. The target is 30 seconds or less through the publish event, with the TTL bound at 60 seconds. Built in `M2-07`.
- **PF-14**. Each `fired[]` entry in the audit record carries its `action`. `content_sha256` hashes the content *before* redaction and is never sent to the model (`R3`). Built in `M1-06`.
- **PF-15**. A tenant can't turn off the floor by disabling a guard point. The floor declares which guard points it covers, and disabling a covered one is a validation error. Tenants can still remove their own rules from it. Built in `M1-01`.
- **PF-16**. A bundle can't pin an old, weaker floor. The platform sets a minimum floor version, and a bundle that extends an older floor is rejected. Built in `M1-01`.
- **PF-17**. Chunks of a long `tool_result` overlap by 256 tokens, so an injection straddling a boundary isn't missed. The cut is deterministic (no random offset), so replay stays exact; that is a known, accepted residual. Built in `M3-04`.

---

## Scope calls (S)

- **S1**. v1 escalation targets are a human queue and a tenant webhook. A generative reviewer moves to v1.1, so "which reviewer model" blocks nothing. Built in `M1-01` (the schema enum) and `M4-05`.
- **S2**. Tenants that need data residency are not onboarded in v1. The self-hosted adapter waits until the provider's regional availability is known. The `DecisionModel` port that would allow it is built anyway.
- **S3**. No real tenant enforces anything until the live-validation gates pass. After that, onboarding is capped at 70% of whichever quota binds first. At Tier 1 that means roughly one small design partner per project, not general availability. A higher provider tier is the recommended route to more. Computed by the capacity harness (`M3-09`); the live gates haven't been run.
- **S4**. Isotonic recalibration moves to v1.1; `recalibrate()` is the identity function in v1. Built in `M1-05`.
- **S5**. The default `fail_mode` for pack and tenant rules is `closed`. Floor rules follow `B1`, so a tenant's fail mode never applies to them.

---

## Owner decisions (U)

Questions that needed the project owner's decision, with the answer. Several replaced earlier design text.

- **U1**. **Latency goal.** Replaces the design's "p95 of 300 ms or less per guard point" with two parts. *Promised:* the engine adds at most 50 ms p95 on top of the model call (measured about 19 ms). *Published, not promised:* end-to-end time per check, which depends on the provider: typically 0.3 to 0.7 s, and 0.5 to 0.85 s for a full critical-path check, varying with time of day. Why: no setup met p95 of 300 ms end to end, not even one question on 1K input, because most of a call's time is spent past the provider's edge.
- **U2**. **Keep `B1` (fail closed), and say what it costs.** Added a re-open trigger: if provider slow episodes total more than 30 minutes in any 30 days, or occur more than once a week, the deterministic degraded-mode alternative comes back for decision. A slow episode is defined by minutes where at least 25% of checks end in a timeout or `unavailable` block, with at least 5 checks in the minute.
- **U3**. **Storing a calibration sample.** Approved exactly as proposed: for the internal trial tenant only, a sample of redacted content, its context, the model's scores and two labels, readable only by a calibration role and deleted after 365 days. External tenants are never included without opt-in and a privacy review. This is retention class E (`R3`). The sampler (`M1-12`) isn't built, because it needs a running deployment.
- **U4**. **No harmful inputs are sent to the provider.** The project's own tests, calibration, benchmarks and demos never send harm-labelled content or inputs known to be refused. Such rows are tagged `no_live_run`, the harnesses filter them, and a live run stops on the first provider refusal. This covers the project's own inputs only. Content real users send through a guarded agent is production traffic, which the engine checks and may report as `provider_safety`.
- **U5**. **Harm facilitation is observe-only.** Because it can't be calibrated under `U4`, it is `d__harm_facilitation`, a shadow rule in the responsible-AI pack: evaluated and logged, never acting, provisional indefinitely, never sent in tests or demos. The floor has no harm rule. Help with serious harm is left to the provider's own filter, to tenants' controls and to this rule's logging.
- **U6**. **Other responsible-AI pack rules aren't "harmful inputs".** Self-harm statements without methods, insults and discriminatory statements were first allowed to be sent. A broader no-harmful-inputs instruction later narrowed this in practice (`M4-10`): examples for the self-harm, harassment, discrimination, protected-basis and harm-facilitation rules are `no_live_run`, so only `d__vulnerability` and `d__manipulation` were calibrated live.
- **U7**. **Relaxed latency.** After slower time windows were measured, the project owner asked for relaxed latency. A check may wait longer before giving up, in exchange for fewer timeout blocks. `U2` stands (the floor still fails closed) and `U1`'s published figures widen. It became the budgets in `R6.3`.
- **U7.1**. The cap is 3 seconds (4 seconds for `input`, which runs while the agent plans). The alternatives offered were 2 s (fewer long waits, a few more blocks) and 5 s (absorbs nearly every slow call, but a 5 s wait whenever the provider is down).

---

## Acceptance criteria (AC)

Testable criteria written before building. Every criterion has an offline test that runs against `FakeDecisionModel` with no network, except those the stories mark as live, which can only be met against the real API.

### Compiler (AC-C)

- **AC-C0**. Validation has two phases. Phase 1 checks shape and returns all shape errors together; only if the shape is valid does phase 2 return all semantic errors together. Each error has a JSON path and a stable error code.
- **AC-C1**. The compiler rejects each case below, one test and one code each.
- **AC-C1.1**. A rule id that doesn't match `[a-z0-9_]{1,40}`, and duplicate rule ids.
- **AC-C1.2**. Thresholds that break `0.01 <= escalate_at < block_at <= 0.99`, in rules, defaults and overrides (overrides are checked after they are applied).
- **AC-C1.3**. A floor override that raises a threshold, and an override naming a rule that doesn't exist.
- **AC-C1.4**. A bundle that removes, disables or shadows a floor rule, edits its question text, has no floor in `extends`, or extends a floor below the platform minimum (`PF-16`).
- **AC-C1.5**. Edited pack question text or descriptions, a pack override that raises a threshold, and opting out of a pack the tenant's tier requires.
- **AC-C1.6**. A tenant rule with no question or a missing description, and a question that fails the closed-question lint: it must end in `?` and start with a word such as Does, Is, Are, Can or Should.
- **AC-C1.7**. More compiled questions than the guard point's question budget (`R6.1`), counting every question type.
- **AC-C1.8**. The token bounds of `R6.7`: content within the 16,000-token bound, each question at most 400 estimated tokens, and question text within 150 tokens times the question budget.
- **AC-C1.9**. A tool in `tool_allowlist` that isn't in the tenant's tool registry.
- **AC-C1.10**. A deny pattern that doesn't compile under RE2, a deterministic action outside the allowed four, or an unsupported PII type (`PF-11`).
- **AC-C1.11**. `enabled: false` on a guard point where any floor rule runs, and a rule naming a guard point that doesn't exist (`PF-15`). Floor coverage is derived from the floor rules, never declared separately.
- **AC-C1.12**. An escalation target other than `queue` or `webhook`, and a webhook URL that isn't `https` (`S1`).
- **AC-C1.13**. Audit settings outside the `R3` bounds for the tenant's tier and packs, and content storage other than `hash_only` on a healthcare tenant without the business-associate flag.
- **AC-C1.14**. A rule marked `template_unedited` whose question, descriptions or thresholds differ from the template version it names (`R1`).
- **AC-C2**. Every compiled key is namespaced `p__` (floor), `d__` (pack) or `t__` (tenant), is at most 64 characters, matches `[A-Za-z0-9_-]+`, and is unique within its guard point.
- **AC-C2.1**. The compiled `questions` object has the shape of the real request, and a yes/no question carries `criteria` only when both descriptions are present.
- **AC-C2.2**. Compiling is deterministic, and `bundle_hash` is a sha256 over the canonical form of the bundle exactly as submitted (no defaults filled in) combined with the content hashes of every catalog version it extends. Defaults are fixed per `schema_version`; a schema change never rewrites or re-hashes a stored version. The catalog refuses to register the same version twice with different content.
- **AC-C3**. Compiled question sets are cached per tenant, version and guard point, and a cache hit does no compile work.
- **AC-C9**. Each compiled key carries metadata: layer (`floor`, `pack`, `tenant`), effective thresholds, mode, severity and effective fail mode.
- **AC-C9.1**. Floor and pack rules carry their own thresholds in the catalog. Bundle `defaults` apply to tenant rules only, and overrides can only lower floor and pack thresholds. This closed a hole where a tenant default of 0.99 could have raised a floor rule's threshold.
- **AC-C9.2**. A guard point a tenant disabled (allowed only where the floor doesn't cover it) compiles to no questions, and shadow rules compile with `mode: shadow` rather than being dropped.

### Guard service (AC-G)

- **AC-G1**. A deterministic `block` makes zero model calls. A deterministic `escalate` still calls the model and the more severe result wins. `log` only records.
- **AC-G2**. No raw PII of any configured type appears in a model call's input. It was brought forward into `M1-14`.
- **AC-G3**. Fusion: a probability at or above `block_at` blocks, at or above `escalate_at` escalates, lower allows, and the most severe result wins. Shadow rules never act.
- **AC-G4**. Every failure (timeout, 429, safety refusal, size limit, `unavailable`, `auth`, other, contract violation, policy store down) ends in a defined verdict, and no exception escapes `check()`. When the policy store is down the last known good version is served.
- **AC-G5**. Content over `chunk_tokens` is split into chunks with a 256-token overlap, each chunk goes through the same admission control, and answers merge by maximum (`PF-5`, `PF-17`).
- **AC-G6**. Delimiter safety (`B3`): content containing `>>>`, a forged guard-point line, a forged closing delimiter, or the nonce itself can't end a section early.

### Model port (AC-M1)

The port is the `DecisionModel` interface. These items cover its types, its fake and its adapter.

- **AC-M1-2**. Question types match the published Decisions API request shapes for `noul`, `choice` and `score`, with the API's bounds (2 to 255 options or levels).
- **AC-M1-3**. Answer types match the published response shapes, and out-of-range values (a yes/no probability outside 0.01 to 0.99, an answer for an undeclared option) are rejected when the type is built.
- **AC-M1-4**. `async decide(input, questions)` returns `Answered`, `SafetyBlocked` or `Failed` with a reason (`timeout`, `rate_limited`, `limit_exceeded`, `unavailable`, `auth`, `other`). Nothing raises out of it except cancellation, and no vendor SDK is imported outside an `adapters/` package.
- **AC-M1-5**. The fake returns `Failed(limit_exceeded)` for more than 1,000 questions, a bad key name, or input plus questions over 262,144 tokens.
- **AC-M1-6**. Token counts come from one deterministic, documented `estimate_tokens` function, shared with the compiler.
- **AC-M1-7**. The fake can be scripted per key to return a given answer, and per call to return each failure reason or `SafetyBlocked`.
- **AC-M1-8**. The fake can return an answer with a missing key, a wrong-type answer or an out-of-range value, through the same raw-response path the real adapter uses, so the parsing path is tested (`PF-6`).
- **AC-M1-9**. The fake records every call so tests can assert on it, and can add scripted latency for budget tests.
- **AC-M1-10**. The fake's answer for a key doesn't depend on which other keys are in the call (question independence).

### Tenancy (AC-T)

- **AC-T1**. The tenant comes only from the verified signed context, and a payload `tenant_id` that differs is rejected as `forbidden` and audited. At the API, a path tenant that doesn't match the token's is a 403, and only platform operators can cross tenants, each time audited.
- **AC-T2**. A property test with interleaved tenants shows no model call ever holds content or questions from more than one tenant.

### Admin API (AC-A)

- **AC-A1**. Draft endpoints work: read guardrails, replace a draft with `If-Match` (412 on a mismatch), and patch or delete a draft rule.
- **AC-A2**. Every write records a class A audit event with the actor, the diff and the resulting hash, and `publish` creates an immutable version.
- **AC-A3**. The regression gate: an enforce publish is refused if golden-set recall falls by more than the tenant's tolerance (default 2 points) against the active version, with per-rule recall for both versions in the refusal.

### Observability (AC-O) and portability (AC-P)

- **AC-O1**. One audit record per check, with every rule's probability, `bundle_version`, `bundle_hash`, each fired rule's `action` and `provisional` flag, and a list of the provisional rules evaluated. That makes "every decision made on provisional thresholds" a single query.
- **AC-O2**. An OpenTelemetry span carries `tenant_id`, `bundle_version`, `guard_point`, latency, input tokens and the decision.
- **AC-P1**. The compiler and the model port import no storage, HTTP or vendor module, so the runtime stays cloud-agnostic. A test checks the imports.

---

## Stories (M)

Work items, in milestone order. Status is as defined at the top. Two things apply throughout: every threshold from a live calibration is provisional, and nothing has been deployed. Where a story's live gate needed a deployment, it was replaced by a simulation of at most 100 conversations (about 500 provider calls). That run showed the engine's own overhead at about 2 ms p95. Timeout blocks varied between its two runs (18 of 158 checks in the first, 0 of 345 in the second), and the 0.5% target couldn't be demonstrated at that size, so it is recorded as not shown rather than as passed.

### M0: Feasibility spike

Confirms the design's central assumptions on the real API.

| ID | What it delivers | Status |
| --- | --- | --- |
| **M0-00** | Access to the provider: a paid-tier key supplied through the environment and never committed. A setup step, not code. | Done (no code) |
| **M0-01** | Latency profile: pilot, detail grid, 45-minute soak, concurrency sweep and burst tests. Source of `R6` and `U1`. One machine and one region. | Built |
| **M0-02** | Floor calibration: the floor golden set, held-out set, attribution retest and threshold runs. Source of `R7`. Floor thresholds remain provisional. | Partly built |
| **M0-03** | Quota path: a capacity model and notes from the provider's own documentation (Tier 1 limits are per project). Several questions for the provider, such as whether a second project gets its own quota, are unanswered. | Partly built |

### M1: Engine core on one guard point

A thin vertical slice: SDK, Guard Service, gateway, model port, fusion and audit.

| ID | What it delivers | Status |
| --- | --- | --- |
| **M1-01** | Bundle schema and policy compiler library: validation, layering, budgets, deterministic compile (`AC-C*`). | Built |
| **M1-02** | Policy store in Postgres: immutable versions, an active-version pointer with compare-and-set, hash re-verification on load, a least-privilege database role. | Built |
| **M1-03** | The `DecisionModel` port, a scriptable fake and the Gemini adapter (`AC-M1-*`). The live smoke test is opt-in. | Built |
| **M1-04** | Decision Gateway: budgets, retry, admission control per key, auth circuit breaker, orphan cap, metering, a background event queue. | Built |
| **M1-05** | Guard Service check pipeline: size check, rendering (`B3`), model call, fusion, failure resolution by layer. | Built |
| **M1-06** | Audit record and telemetry (`AC-O1`, `AC-O2`) and a replay function that recomputes a decision under new thresholds with no model call. | Built |
| **M1-07** | Python Guard SDK: releases content only on `allow`, exposes `reason`, `retryable` and the capacity signal (`R8`). | Built |
| **M1-08** | Platform floor v1: six `p__` rules covering all five guard points, loaded through the same validation as any catalog rule. Thresholds provisional (0.85 and 0.55). | Built |
| **M1-09** | Catalog content hashes computed over the source documents as loaded, with a required `schema_version`. | Built |
| **M1-10** | Warm connections in the Gemini adapter: pooled keep-alive, connection-reuse metering, no synthetic keep-warm requests. | Built |
| **M1-11** | Engine composition root: one factory, validated settings, clean shutdown, `bootstrap_publish` for tests and demos, key handling. | Built |
| **M1-12** | Calibration sample for the internal trial tenant (retention class E, `U3`). Needs a running deployment. | Not built |
| **M1-13** | Provider refusals map to `provider_safety` (`R10`). | Built |
| **M1-14** | PII redaction before the model call, with typed placeholders; email domains and URLs are kept because the floor judges destinations (`AC-G2`). | Built |
| **M1-15** | Gateway budgets per `R6.3` and the retry hint (`R8`). | Built |

### M2: Self-serve policy authoring

Tenant admins manage guardrails through the Admin API. Implements `R1`.

| ID | What it delivers | Status |
| --- | --- | --- |
| **M2-01** | Authentication and tenant scoping: OIDC, Ed25519 signed tenant context with key rotation, tenant directory, row-level security. | Built |
| **M2-02** | Draft lifecycle: read, replace and patch drafts, with validation and audit. | Built |
| **M2-03** | Catalog and templates, a tenant tool registry, and screening of tool descriptions at registration. | Built |
| **M2-04** | Validate endpoint: all errors, compiled question preview, token budget per guard point and estimated cost. | Built |
| **M2-05** | Test endpoint: run a draft on samples or a golden set. Floor scores are not exposed to tenants. | Built |
| **M2-06** | Golden-set upload, tenant-scoped, with a tripwire that quarantines rows that must not be sent. | Built |
| **M2-07** | Publish, versions and rollback: the evidence gate of `R1`, candidates (`PF-7`), cache invalidation events, class A audit in Postgres. | Built |
| **M2-08** | Red-team harness: an offline corpus, a runner and a recall regression gate, with a live baseline. A few cases escalate rather than block at `block_at`. | Built |
| **M2-09** | Floor upgrades (`R5`): release, re-pin, override carry-over, staging, minimum raise and rollback guard. | Built |

### M3: All guard points and fairness

| ID | What it delivers | Status |
| --- | --- | --- |
| **M3-01** | Deterministic checks: tool allow-list, PII, RE2 deny patterns, size limits and a cross-tenant identifier scan. | Built |
| **M3-02** | `input` guard in parallel with the planner, enforcing `PF-9`. | Built |
| **M3-03** | `plan` and `tool_call` guards: plan allow-list, tool-call schema validation, read-only `skip_model` for tenant and pack questions only (floor questions are never skipped). | Built |
| **M3-04** | `tool_result` chunking with overlap and maximum merge (`PF-5`, `PF-17`, `AC-G5`). | Built |
| **M3-05** | Streaming `output` window: each sentence window is checked before release. | Built |
| **M3-06** | TypeScript Guard SDK. Deprioritised: there is no requirement for it. | Not built |
| **M3-07** | Per-tenant quotas (requests/min, tokens/min, requests/day) and weighted fair scheduling. | Built |
| **M3-08** | Key pools: per-consumer allowances so tests, calibration and red-team can't use up production quota. Keys come from environment variables; there is no secret-store integration. | Built |
| **M3-09** | Load test and capacity sign-off. The offline harness and the live gates are built; the live runs haven't been run, so there is no live capacity figure. | Partly built |
| **M3-10** | Per-project token-rate limiter: a token bucket that fails fast with `token_rate` rather than hitting the provider's per-minute quota. | Built |

### M4: Operate and tune

| ID | What it delivers | Status |
| --- | --- | --- |
| **M4-01** | Calibration job and threshold suggestions per `B2`, replaying stored probabilities. | Built |
| **M4-02** | Regression gate on enforce publishes (`AC-A3`), and the threshold-only shortcut past the shadow soak. | Built |
| **M4-03** | Progressive rollout (`PF-7`): shadow and enforce candidates by conversation hash, with a comparison report. | Built |
| **M4-04** | Bad-publish detection: alert on a policy block rate over 2x the 7-day baseline after a publish. Provider failures feed a separate health alert. | Built |
| **M4-05** | Escalation queue: human queue and signed webhook with retries and dead letters (`S1`). | Built |
| **M4-06** | Metrics and cost attribution, reconciled to metered totals. | Built |
| **M4-07** | Audit query (`decision_records`) for the `auditor` role. Large-tenant volume testing is deferred to deployment. | Built |
| **M4-08** | Insurance and energy packs, with versions `@1`, `@2` and `@3`. Thresholds come from live runs on synthetic data and stay provisional; two rules aren't calibrated live. | Built |
| **M4-09** | Retention engine for classes A and B with deletion receipts. | Built |
| **M4-10** | Responsible AI pack (`R4`), the `max_action` field and per-rule opt-out. Only two of its rules were calibrated live (`U6`), and its labels haven't had a two-person human review. | Built |
| **M4-11** | Self-adjusting expected latency. A candidate, scheduled only if a time window slower than the 380 ms allowance covers shows up. | Not built |

### M5: Regulated readiness

| ID | What it delivers | Status |
| --- | --- | --- |
| **M5-01** | Regulated-tier attribute, set only by platform operators, which makes the Responsible AI pack, two-person approval and retention floors apply. | Built |
| **M5-02** | Two-person approval (`R2`): tied to the draft hash, expires after 72 hours, enforced in the database. | Built |
| **M5-03** | Content storage and escalation retention (classes C and D), off by default and bounded by the `R3` caps. | Built |
| **M5-04** | Finance and healthcare packs, with versions `@1` and `@2`. Thresholds provisional. There has been no legal, clinical or human label review, and some risky rows are never sent live. | Built |
| **M5-05** | Nightly red-team against the platform configurations in use, with a hold on any corpus row the provider refuses. The offline part is built and there has been no live run. | Partly built |
| **M5-06** | Dedicated provider projects for regulated tenants, with separate gateways and buckets. Keys come from environment variables. | Built |
| **M5-07** | Offboarding: one-way termination, deletion of classes B, C and D and golden sets, a billing summary kept in class A, and a re-sweep for late data. | Built |

### M6: Reader feedback

Items raised by readers' questions about the first public post. See the [roadmap](../ROADMAP.md) and the [FAQ](FAQ.md).

| ID | What it delivers | Status |
| --- | --- | --- |
| **M6-01** | Replay of de-identified agent traces, and of recorded probabilities against candidate thresholds; a report on how far single draws move scores near each line. Needs real traces. | Not built |
| **M6-02** | An escalation timeout with a per-rule fallback (block by default), and alerts when a rule escalates too often. | Not built |
| **M6-03** | Random sampling of allowed checks for human review, so missed violations show up. | Not built |
| **M6-04** | A design spike for risks that only appear across several steps of a run, such as the total amount moved. | Not built |
| **M6-05** | Measuring whether content that fools the agent also fools the judge when they share a model family. Offline only for now. | Not built |
| **M6-06** | This FAQ, the roadmap, and the note on what the finance pack's payment rule doesn't check. | Built |

### M7: External viability review

Items from an outside review of the public repository (23 November 2026). Its verdict: a viable prototype, not yet a viable production guardrail. New control-plane features are paused until the evidence and data-plane items are done.

| ID | What it delivers | Status |
| --- | --- | --- |
| **M7-01** | Deterministic detection of known secret formats: a block with no model call where the agent emits or acts, and redaction of secrets from input and context so they never reach the provider. | Built |
| **M7-02** | Correcting docs that claimed more than the code does (fail-open in practice, latency target, redaction scope). | Partly built |
| **M7-03** | Counting repeated attempts, so resubmitting blocked content until a draw scores lower doesn't work: the same content blocked twice in 15 minutes is refused without a model call, at `input`, per tenant. | Built |
| **M7-04** | Durable audit for regulated tenants: a full queue makes the check wait briefly and then spill the record to a local file, replayed into the store without duplicates; standard tenants still drop and count. | Built |
| **M7-05** | Making the default floor the one the held-out evidence covers (floor@2), or validating floor@1. floor@2 is in the catalog and, in the simulation, released through the floor release path on a live red-team report that passed its gate: a new tenant starts on it. Re-pinning existing tenants and raising the minimum are separate platform steps. | Built |
| **M7-06** | Skipping a file-ownership test that can't apply when the suite runs as root. | Built |
| **M7-07** | This glossary. | Built |
| **M7-08** | Sending a provider refusal to a person where a rule is meant to escalate, instead of a flat block: at a guard point with an enforce rule that may only escalate, a refusal is an `escalate` (reason `provider_safety`, the rule keys as `candidate_rules`), capped per tenant and guard point, and a block when the cap is spent or nothing can route it. | Built |
| **M7-09** | A shadow pilot on real traffic, and testing with an outside adaptive attack corpus. | Not built |
| **M7-10** | Running the guard as its own service: a check endpoint (HTTP and JSON, the signed context as the credential), the SDK's remote mode (`connect`), and no provider or database credentials in the agent's process. Built: the endpoint, the remote SDK, a local process runner (test environment, fake model), the load test's remote mode and a runtime check that the environment holds no key or DSN. Shared stores across service replicas are deferred. | Built, except shared stores |
| **M7-11** | A defined degraded mode for a provider outage: the gateway notices it (5 failed calls in a row, or over half of 20 in 30 s), fails checks at once with a labelled, retryable block, probes until the provider answers, and an operator can hold or lift it. No guard point falls back to allow (the user's choice); a second provider is not built. | Built |
| **M7-12** | Wider redaction (names, addresses, health identifiers), weighed against detection quality. The first step, a measured trial of whether today's redaction changes decision quality, has been run (25 November 2026): today's redaction is kept. Widening it has not been decided. | Partly built |
