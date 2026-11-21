# M4-01: the calibration job and threshold suggestions

Branch `m4-01-calibration-job`. B2 as written, targets as a tenant setting (decided
2026-11-18), the R1 precision gate in the evidence gate.

## The sweep (`admin/sweep.py`, pure)

Per tenant rule, from `(p, labelled block)` pairs, on the 0.01 grid:

* `block_at` = the **lowest** threshold whose precision is at least the target and which predicts
  something positive. It is searched from 0.02 up, because the compiler needs
  `0.01 <= escalate_at < block_at <= 0.99` and a `block_at` of 0.01 leaves no room.
* `escalate_at` = the **highest** threshold whose recall is at least the target. If it is not
  below `block_at`, it becomes `block_at - 0.01` and `band_empty` is reported.
* No threshold meeting precision: **no suggestion at all** (`no_threshold_meets_precision`), and
  the rule fails the gate. No threshold meeting recall: `block_at` only (`no_threshold_meets_recall`).
* Targets are compared exactly (fractions), so 19 of 20 meets 0.95.
* `tests/admin/test_sweep.py` works the answers out by hand on synthetic sets (positives
  0.5 0.6 0.7 0.8 0.9 0.95, negatives 0.05 0.1 0.2 0.3 0.4 0.55: `block_at` 0.56, `escalate_at`
  0.50), including the non-monotonic, collision, nothing-predicted and exact-target cases.

## Targets (`admin/calibration_store.py`)

A tenant setting beside the bundle (not in it: no schema version): `block_precision` default
0.95 and `escalate_recall` default 0.90, each 0.50 to 1.00 in hundredths. `GET` (viewer) and `PUT`
(`guardrail_admin`) `/calibration/targets`. A change writes a class A event with the actor, before
(and whether it was the default) and after, in the same transaction. Every gate result and every
`/validate` suggestion records the targets it used with the draft hash, the bundle hash and the
floor version, so a past decision can be explained from its own record.

## What is measured, and what is stored

* **The pool.** A golden example is labelled per guard point, not per rule, so a rule's examples
  are the tenant's labelled examples at the guard points it runs on, over all its sets,
  de-duplicated by normalised content, leaving out quarantined rows and content labelled both
  ways (the same pool the label counts use). `block` is the positive. **Residual:** an example
  that is a violation of some other rule counts as a positive here; a tenant with several rules at
  one guard point keeps their golden sets separate in spirit (the evidence gate has the same
  property).
* **Scores.** `tenant_calibration_scores`: for a *scoring identity* and an example's content hash,
  the probability each **tenant** rule gave it. The identity is a hash of everything that decides
  what the model is asked about an example: the guard point's compiled questions (floor and
  tenant) and the floor version the bundle extends, the **effective max content tokens**, the
  bundle's **deterministic section** (PII detection and action, deny patterns), and a render
  version constant (`RENDER_VERSION`, bumped when the render or redaction pipeline changes what
  the model sees). Thresholds are not part of it, so accepting a suggestion costs nothing;
  rewording a rule, a floor change, a PII or deny-pattern change or a different content budget
  scores those examples again. **Not part of it:** the model id (one model today).
  Insert-only; floor, pack and floor-derived rules' probabilities are never stored.
* **Examples that can't be scored.** `tenant_calibration_outcomes` records, per attempt
  and under the same identity, why an example got no probability: `deterministic` (a tenant deny
  pattern or a PII block stopped it before the model) and `too_large` are **terminal at once**,
  `refused` (the provider's safety refusal) after **two** attempts, `failed` (a model failure,
  admission, the engine closing) **never**: it is retried, behind examples tried fewer times, so
  a run always reaches the ones that can be scored. A terminal example, and one the harm
  tripwire holds (`held`, checked live on every read), **leaves the rule's pool**: it is not in
  the sweep, the precision gate or the regression gate, and `/validate`, the job's report and the
  gate's record count them by cause (`excluded: {"deterministic": 2}`), never by content.
* **One draw per example.** A stored score is one measurement. The nonce noise R7 measured
  (p95 0.10) applies; the plateau method of the R7 amendment is the floor's calibration and is not
  used here (B2 as written, decided for this job).

## The job (`POST /draft/calibrate`, `guardrail_reviewer`)

`{"guard_point": ...}`: scores up to 50 examples that have no stored score at that guard point
(the same bound as a test run) and stores them. It sends each through the engine's own draft
evaluation, so admission control, the token bucket and the `test` allowance apply, under usage
class `test`. The harm tripwire runs again on every example right before it could be sent; held
rows are counted. One run at a time per tenant **per replica** (a second replica could run at the
same time; the gateway's own limits still hold). The report says how many were already scored,
scored now, not scored (a deterministic block or a model failure gave no probability), and how
many remain.

`/validate` sends nothing. Its `calibration` object holds the suggestions computed from stored
scores, with `scored` and `unscored` per rule: an `unscored` above zero means calibrate first.

## Accept and override (`POST /draft/thresholds`, `guardrail_admin`)

`{"digest": "<digest>", "rules": {"<rule id>": {"action": "accept"} | {"action": "override",
"block_at": x, "escalate_at": y, "reason"?: text}}}` with `If-Match` (the draft's ETag; 428
without it, 409 if the draft moved). **Accepting names the `digest` that `/validate` returned**
(`calibration.digest`: a hash of the draft, the targets and every rule's suggestion with the
counts behind it): a different one is a 409, so an accept can only apply what the tenant saw. An override needs none. All decisions are applied in **one** draft write, or none, and
are recorded **in that write's own audit event** (action `draft.thresholds`, migration 022): the
actor, each decision (accept or override, the suggestion or why there was none, the previous and
applied thresholds), the digest, the targets, the bundle hash and the floor version. One event,
one transaction. Accepting with no escalate suggestion keeps the rule's own
`escalate_at`.

## The R1 precision gate (`EvidenceGate`, code `evidence_gate.precision`)

For each enforcing tenant rule that is not floor-derived: its effective `block_at` must meet the
tenant's precision target on the stored scores of **every** example in its pool (examples that
can't be scored are out of the pool, with their counts in the record). A rule with
unscored examples fails ("N of the rule's golden examples have no stored score ... run POST
/draft/calibrate"); so does one that predicts nothing at its `block_at`, or whose precision is
below the target (with the numbers). **Floor-derived tenant rules** (fork of a floor rule, or its
text) are exempt: they are the floor's rule under another key, calibrated by the platform, and
their `p` is never exposed. A passing publish or promotion writes the gate's record
(targets, bundle hash prefix, floor, per rule precision at `block_at` and `n`) into the event's
note (at most 500 characters).

## Not done

* The suggestion is computed per `/validate` call from the store (a read per rule and guard
  point); fine at 1,000 examples, to be cached if it shows.
* Scores are never pruned.
* No calibration-by-rule golden labels (the golden schema labels per guard point).

## Evidence gate and calibration audit: fixes

Above. The accept digest. Decisions in the draft's own audit
event. `EvidenceGate` with no precision source fails closed (`evidence_gate.precision`,
"no precision source is configured"); `NO_PRECISION_GATE` is the explicit opt-out; and
production or staging refuse to build an engine that can publish with no calibration store. The
calibration audit table now holds only target changes. `escalate_at` is the **highest**
threshold meeting recall; the design doc said "lowest".

## M4-02: the regression gate (AC-A3)

* **What it checks.** For each enforcing tenant rule of the document being published or promoted
  that was **also enforcing in the active version**, recall on the golden positives may not fall
  by more than the tenant's `recall_tolerance` (default 2 points). Recall is the share of the
  rule's golden positives it **acts on**: `p` at or above that version's `escalate_at` (block
  and escalate both keep the content from being released). Each version's recall comes from
  stored scores under that version's **own** scoring identity and its **own** thresholds. The
  refusal names, per failing rule, the recall of both versions, the thresholds they act at, the
  fall in points and the tolerance.
* **Fails closed.** Unscored examples under either version fail the rule, and the message says
  which version and what to run: `POST /draft/calibrate` for the draft, and with `"version": N`
  for a published version (it scores that version's document instead of the draft). Examples
  that can't be scored are out of both pools, with counts in the record.
* **Not compared.** A rule that is new, was in shadow in the active version, is in shadow now,
  or is floor-derived; a rule that is gone. The first publish has no active version: it passes
  and its record says so. An active version that no longer compiles under today's catalog isn't
  compared either (the publish may be the fix), and the record says that.
* **Tolerance.** `recall_tolerance` joins `block_precision` and `escalate_recall` in
  `PUT /calibration/targets`: 0 to 20 points in steps of 0.5, audited the same way (migration 023).
* **The record** (`regression gate: tolerance 2 pt vs v3; refunds 0.92->0.91`) joins the R1
  precision record in the publish event's note; each is cut to 240 characters first.

### The soak, replaced by the golden gates (decided 2026-11-18)

A tenant rule that enforces in the active version and whose **only** change is its thresholds
(`block_at` or `escalate_at`) is exempt from the 72-hour soak when all of these hold: the R1
precision gate passes for it; the regression gate passes for it; and its golden pool has **no
unscored example** under either version and **at least 20 scored ones**. A smaller pool keeps the
soak. A floor-derived rule gets no exemption. The record says `soak replaced by golden gates:`
with the numbers (`refunds p=1.00@0.9 r=0.92->0.92 n=48`). A rule changed in anything else
(wording, guard points, severity) keeps the soak; a rule that enforces and is **not** changed
keeps its soak from M2-07's carry-over (an unrelated edit asks for nothing).

**Known limits (M4-02):** the scoring identity is per guard point, so a change to *another* rule's
wording at the same guard point changes the identity for all of them: the exemption, like the
regression gate, then needs the guard point calibrated again. The regression gate compares rules
by id; a renamed rule is a new rule (nothing to compare).

## Fixes (M4-02)

* **The active version is measured without the profile's tool checks.** Recall doesn't
  depend on the tool allow-list, and a tenant could unregister a tool (a delete, or, before the
  M2-03 fix, a held description edit) without any publish. The gate compiles the active
  version with a stub registry entry for every tool its allow-lists name. It skips the
  comparison only when the active version's floor is below the platform minimum or no longer
  released, and the record says so; **any other failure to measure refuses each rule that would
  have been compared**. (The M2-03 fix beside it: a held edit leaves an approved tool
  registered, and a tool a published version names can't be deleted; see `m2-03-catalog.md`.)
* **The same positives, on both sides.** A positive a tenant deny pattern or PII block
  stops before the model counts as **acted on** in the version where that is so (the content is
  blocked anyway). A positive that one version can't score for another reason (too large,
  refused, held) is left out of **both**: recall is over the examples both pools hold.
* **The records show the pool**: `n`, positives, negatives, and what was left out by
  cause, including `both_labels` and `quarantined` (golden pool) and `left_out=` for the
  comparison.
* **No regression source fails closed** once there is an active version
  (`evidence_gate.regression`); `NO_REGRESSION_GATE` is the explicit opt-out. The soak
  exemption also needs at least **10 positives and 10 negatives** in the pool, beside the 20.
* **The unscored refusal says that a rule reworded at the same guard point changes the
  scoring identity of all of them.
* **`POST /draft/calibrate` with `"version": N` compiles that version with the same
  stub registry the gate measures it with, so a published version that names a tool the tenant
  has since lost can still be scored.
