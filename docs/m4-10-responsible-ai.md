# M4-10: the responsible-AI pack, `max_action` and per-rule opt-out (offline part)

`domain/responsible_ai@1` ships seven rules (`packs/responsible_ai/pack.json`): six enforcing, plus
`d__harm_facilitation` in `mode: shadow`. Everything here is offline: no live call was made, and
the [LIVE] calibration (thresholds from M4-01 on the real API) is **not done**: see the last
section.

## What it claims (R4.4)

The pack **detects biased content and decisions in individual responses**: stereotyping, and
decisions that rely on a protected characteristic or an obvious stand-in for one, in one message,
plan or tool call at a time. It does **not** measure statistical fairness across many decisions,
such as approval rates by group: **aggregate fairness is not measured** (v1.1). The wording is the
pack's catalog `description` (returned by `GET catalog`) and is in `packs/responsible_ai/README.md`;
tests pin the three places. Docs, demos and posts say "detects biased content and decisions in
individual responses", never a bare claim of bias detection. **The reviewer is asked to check the wording.**

## Pack schema version 2

Three things the story adds are not in schema version 1, so **a pack document of schema version
2** carries them, and a version 1 document is unchanged (its meaning and its content hash are
pinned by the existing snapshot tests; the version 1 reader refuses any of the new fields and
states what a version 1 document gets):

| Field | Where | Default | Meaning |
|---|---|---|---|
| `max_action` | a rule | `block` | the most severe action the rule may take: `block` or `escalate` |
| `per_rule_optional` | the pack | `false` | a tenant may switch off one rule (R4.6) |
| `description` | the pack | empty | the catalog's own words about the pack |

The three packs (`responsible_ai`, `insurance`, `energy`) are schema version 2. The new model
fields are left out of a dump when they hold their default, so the snapshot of version 1 content
is unchanged. `tests/policy/test_m1_09_catalog_documents.py` pins version 2's defaults too.

## `max_action` (R4.3)

* **The cap.** `fusion.action_ceiling` returns escalate for a rule whose `max_action` is
  `escalate`, and `capped` applies it to every action, from answers **and from fail modes**: a
  `d__self_harm_risk` of 0.99 gives `escalate`; a failed call on a closed escalate-only rule gives
  `escalate`, not `block` (a person looks, nobody is refused). Table-driven in
  `tests/policy/test_m4_10_max_action.py`.
* **Compiled and recorded.** The compiled rule carries it (left out of the canonical JSON when it
  is the default, so a policy with no capped rule compiles to the bytes it did before). Each
  recorded `RuleEvaluation` carries it, so audit replay under new thresholds applies the same
  cap (audit record schema version 6; older records load with no cap).
* **Validation.** The catalog refuses a `max_action` other than `block` or `escalate`, and one on
  a router or scorer (only a `noul` rule acts).
* **Tenants can't change it.** An override that names a `max_action` other than the catalog's
  gets `override.max_action_edited`, in both directions and on floor rules too. Lowering
  `block_at` on a capped rule changes nothing: it still escalates.
* **The B2 sweep never sets `block_at` on a capped rule.** `admin.sweep.sweep(...,
  max_action="escalate")` and the calibration harness's `b2_sweep(..., max_action="escalate")`
  return no `block_at` and no precision target: `escalate_at` is the highest threshold meeting the
  recall target (R4: "escalate_at is set for recall on the two escalate-only rules").
* **M4-08's two rules.** `d__ins_fraud_signal` and `d__en_safety_report` now have `max_action:
  escalate` and are enforcing again (they had been shadow until this
  field existed).

## Per-rule opt-out (R4.6)

A deliberate exception to the merged compiler, **only for a pack that declares
`per_rule_optional`**, which in v1 is `domain/responsible_ai` alone. A test proves every other
pack still gets `pack.override_not_allowed`.

* The tenant switches one rule off with an override `{"rule": ..., "enabled": false,
  "justification": "..."}`. The justification is required and non-blank (at most 1,000
  characters): `pack.justification_required`.
* **A rule the tier requires can't be opted out of**: `pack.rule_required`. The catalog setting
  is `catalog.tier_required_rules` (tier to compiled rule keys). **It is empty by default**: the
  regulated tier's list comes with M5-01, which sets the tier attribute. Until then no rule is
  required for any tier.
* **No shadow instead.** An override that sets `mode` on a pack rule is refused (an opted-out rule
  is either on or off); a rule's mode is the catalog's.
* **Class A.** The publish's class A event carries the diff of the bundle document, so the
  override and its justification are in it (`tests/engine/test_engine_m4_10.py`, through
  `bootstrap_publish` and the same `bundle_diff` the Admin API's publish uses).
* **Regulated tier: two-person.** An opt-out is part of the bundle, so it takes effect only with
  a publish; on a regulated tenant a publish that enforces needs the R2 approval, which is the
  existing gate (and M5-02, in progress, replaces its approval flow). No separate approval step
  was built for the opt-out.
* Opting out of the **whole pack** is leaving it out of `extends`: allowed on the standard tier
  (the publish's class A diff records it), and refused with `pack.required_missing` where
  `catalog.tier_required_packs` requires it (M5-01 sets the regulated tier's).

## Default on

`catalog.default_on_packs` (default `{responsible_ai}`) names the packs a **new** tenant's
**starter bundle** extends. `GET catalog` returns `starter_bundle`: the newest extendable floor,
the default-on packs, and what the tenant's tier and contract require, each at its newest
version; every pack entry says `default_on`, `per_rule_optional` and its `description`. A test
publishes the starter as a first bundle. **The limit:** the starter is offered, not published for
the tenant: there is no tenant-provisioning step that publishes a first bundle, so "on" means the
starter has it and a tenant must leave it out deliberately.

## `d__harm_facilitation`: shadow, and never sent

The compiler accepts `mode: shadow` for a pack rule; the rule is evaluated and recorded with the
action it would have taken, and never acts (tested through a built engine). Its golden rows are
`no_live_run`. **Its question text names weapons and the like**, as do the question texts of
`d__self_harm_risk`, `d__vulnerability` and the two bias rules (a rule about a harm has to say
it): a test pins those five. In production those texts go to the provider as *questions* with
every check that evaluates the pack. A calibration or demo run that must not send the
harm-facilitation question should have its tenant opt out of that one rule through the per-rule
opt-out above.

## The golden set

`packs/responsible_ai/golden.jsonl`: **372 rows** (the story asks for 300), **44 counterfactual
pairs** (40), and every (rule, guard point) cell has **at least 15 firing and 15 allow rows**.
The near-misses the story names are in it: accommodations the person asked for, neutral mentions
of protected characteristics, lawful factors, and frank but non-manipulative sales language.
Hygiene, enforced by tests: harm-facilitation positives are requests and refusal-style or
redacted (`[details removed from dataset]`) responses, with no numbered steps; self-harm rows
follow safe messaging (no methods or means); no contact details.

**What is never sent: the conservative scope.** The user's rule is U4 ("Don't send any harmful
inputs anymore to google"). The earlier U6 had said self-harm statements, insults and
discriminatory text were not "harmful inputs" for calibration. It was decided on
2026-11-19 that they are withheld: the builder tags `no_live_run: true` on every row that fires
`d__self_harm_risk`, `d__harassment`, `d__bias_stereotype`, `d__bias_protected_basis` or
`d__harm_facilitation`, and on any row that trips the harm-vocabulary tripwire. 196 of 372 rows are
withheld, 176 sendable (the clean near-misses, and the vulnerability and manipulation rows). **This
differs from U6 and is flagged for the user:** it leaves only `d__vulnerability` and
`d__manipulation` calibratable live; if the user restores U6's scope it is one line
(`WITHHELD_RULES`).

**The two-person label review is still owed.** Every label has had one author. This work did not
do it and does not claim it.

## Guard fairness (R4.5)

`calibration/fairness.py`, `pair_report(rows, draws, rules)`: for each rule that covers a pair's
guard point, the mean and the maximum |Δp| between the two members' median probabilities, every
pair above 0.10, and every pair whose members land on different **actions** at the rule's own
thresholds with its `max_action` applied. A pair with a missing score is named **unscored**, never
counted as fair; a "pair" without two members is **malformed**. Tested offline
(`tests/calibration/test_m4_10_fairness.py`): the arithmetic, and the real golden pairs sent
through a built engine with a fake model that is fair (zero deltas, nothing flagged) or biased on
chosen pairs (caught per rule with the right mean and maximum).

The 44 pairs cover `d__vulnerability` (8 pairs), `d__harassment` (5), `d__bias_protected_basis` at
`tool_call` (3), `d__harm_facilitation` (1, never sent) and the neutral allow pairs.
**There are no pairs for `d__bias_stereotype` or `d__self_harm_risk`**; the benign non-English and
dialect parity check the story names for blocked-no-more-often is what the allow pairs carry, and
is reported by the same code. More pairs for those two rules would be worth adding with the
second reviewer.

## The [LIVE] part (not run)

Of the seven rules only `d__vulnerability` and `d__manipulation` have sendable positives, so only
they can be calibrated: 176 sendable rows, 528 checks at 3 draws (1,056 with one retry per failed
draw), about 0.45 million input tokens, about $0.05 at $0.10 per million: small. The pair report
needs the pair rows to be sent: the sendable pairs are the neutral allow pairs only, so it would
cover little; the |Δp| report on the withheld pairs stays offline-only until the user rules.
Nothing was sent.

## Fixes (five minor changes)

* **`pair_report` lists a pair that no supplied rule covers on both members (different
  guard points, or a guard point no rule runs at) under `unmeasured`, and `fair` requires there be
  none. Before, such a pair was skipped and `fair` could be true with `pairs: 0`.
* **Card 6's blocked column is rows labelled for the bias rules, all withheld. A provider
  run now skips it (`card6.blocked_offline_only`, the card says so); the offline run, against the
  engine's own fake model, still shows it. `demo/SPEC.md` says the same.
* **A tenant rule whose `origin` is `fork:<key>` of a capped rule in an extended pack, or
  whose question is the same text (compared lower-cased, spaces collapsed, end punctuation dropped),
  **inherits `max_action`**, so a copy of `d__self_harm_risk` can't refuse a person in crisis. A
  reworded question is not detected: that is a rule the tenant wrote, with its own thresholds. For
  such a rule the tenant calibration (M4-01) sweeps only `escalate_at`, accepting a suggestion keeps
  the rule's own `block_at`, and the precision gate (which measures blocks) notes "escalate-only" and
  has nothing to measure.
* **`calibration.run.refuse_harm_facilitation` refuses a live run whose compiled
  questions include `d__harm_facilitation`: in `build_setup` and in `calibration_engine` when no model
  is passed (the red-team runner builds its engine there too). Opting the rule out, or leaving the
  pack out, passes. Offline runs with a fake model are not refused. Our harnesses only.
* **`rai-cf-030` (an added sentence) is now a plain near-miss, and a true pair
  (a Welsh against a Polish reply) takes its place. A test now requires that, apart from the one
  dialect pair (`rai-cf-013`), no pair has a word added or dropped. The set is **372 rows**, 44
  pairs, 196 withheld, **176 sendable** (528 checks at 3 draws).
