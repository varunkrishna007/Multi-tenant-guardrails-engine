# M2-03 · Catalog and templates (as built)

Part 1: the catalog read, templates, the append-only rule and the R9 records template. Part 2
(below): the tenant tool registry and tool-description screening.

## Routes

| Method | Route | Role | What |
|---|---|---|---|
| GET | `…/catalog` | viewer | `{minimum_floor_version, floors[], packs[], templates[]}`. Every floor version with its rules (key, question, both descriptions, `block_at`, `escalate_at`, severity) and `extendable` (false below the minimum); every pack version with its rules and `required_for_your_tier`; every template version with its catalog text, notice, thresholds and the number of starter examples. Read only: no route writes the catalog, and no score of any kind is shown. |
| POST | `…/draft/templates/{template_id}` | guardrail_admin | Copies the template into the draft and imports its starter examples. Body (optional): `{version?, rule_id?}`; the newest version and the template's id are the defaults. Needs the draft's `If-Match` (404 `no_draft`, 428, 412 as for any draft write). 201 `{rule, draft, golden_set, golden_error}` with the new `ETag`; 404 `template_not_found`; 409 `rule_exists`; 422 for a bad body or a rule the compiler refuses. |

## Applying a template

The copy is a tenant rule with `origin: "template:<id>@<v>"`, `template_unedited: true`, the
template's question, both descriptions, thresholds, guard points and severity, and **rule mode
`shadow`**: a template copy is exempt from the 72-hour soak (M2-07) but not from the label counts,
and the tenant switches it on by setting `mode: enforce`, which doesn't make it "edited".

**What counts as an edit**. The compiler compares a copy that says
`template_unedited: true` with its template on question, both descriptions, both thresholds,
**severity and guard points** (as a set; a template that names no guard points isn't compared
there). On every draft write (`PUT draft`, `PATCH rule`, apply) a copy that still claims `true`
but differs is **saved with `template_unedited: false`** instead of being refused, and the
draft's class A event shows the change. A copy moved to other guard points would otherwise keep
the soak exemption there, and a lower severity would halve its label bar. **Only `mode` is not
an edit**: switching a copy on (`shadow` to `enforce`) keeps it unedited and keeps the soak
exemption, which is the point of a template.

**Starter examples** go into a new golden set named `template <id> v<version>` through the same
path as an upload: ids `s1…sN`, the harm-vocabulary tripwire reads every row (quarantined, never
sent), the 50-set cap applies and the set's class A event is written. The draft write and the
golden import are two steps. If the tenant is at the cap, the rule is in the draft and the reply
has `golden_set: null, golden_error: "too_many_golden_sets"`; applying again would be refused
with `rule_exists`, so the tenant uploads examples itself. The draft is written first so that a
refused apply (no draft, stale `If-Match`, existing rule, invalid rule) leaves no golden set.

The draft audit action is `draft.rule.put` (the table's CHECK allows only the three actions); the
diff shows the added rule with its origin.

## Template files

`templates/<name>.json`, one object per file, `schema_version: 1`, read by
`template_file.load_template_file` (parsing in `policy/template_loader.py`, which is pure). A file
template needs a title, a description, at least one guard point, **at least 10 starter examples**
with both labels, no repeated example, example guard points inside the template's, and the
usual rule checks (closed question, two non-blank descriptions, `0.01 <= escalate_at < block_at <=
0.99`). The id is `[a-z][a-z0-9]*(_[a-z0-9]+)*`, at most 40 characters, because it is also the
tail of the `t__<id>` rule. `catalog.template_files` (default
`templates/within_tenant_records.json`) lists the files; a missing or rejected file stops the
engine from building, like a floor file.

**The within-tenant records template (R9)**: `within_tenant_records@1`, "Does the request ask for
another customer's personal records?", at `input` and `plan`, with both descriptions, 16 starter
examples, and a `notice` that says it is **a soft signal, not an access control**: it reads
wording, can be missed or fooled, doesn't check who the requester is, and access to a customer's
records is enforced in the tenant's own systems. It is a catalog template the tenant chooses to
adopt: it is not in `floor/rules.json` (a test checks) and never in a floor or pack. Its
thresholds (0.90 / 0.60) are not calibrated; nothing about it is a promise.

## The catalog is append-only

`CatalogAdmin` (platform code, no HTTP route) is the only way an item leaves the catalog:
`remove_floor(version)`, `remove_pack(name, version)`, `remove_template(id, version)`. It asks a
`CatalogReferences` how many **stored bundles in any tenant** use the item (`extends` for floors
and packs, a rule's `origin` for templates), counting every stored version: active, candidate,
abandoned and rolled-back ones. Any use refuses the removal (`CatalogItemInUseError`); so does a
reference check that fails (fail closed). An item nobody uses can be removed. The in-memory
catalog's `discard_*` methods are called only by `CatalogAdmin` (a test scans the source), and
the catalog has no other remover.

* In memory: `MemoryCatalogReferences(store)` reads the store's documents.
* Postgres: `PostgresCatalogReferences(operator_pool)` runs a count over `policy_bundle_versions`
  with the **operator role** (007 and 014 let it see every tenant's rows); with no operator pool
  it raises `OperatorPoolUnavailableError`, and nothing is removed. It returns a number, never a
  tenant's rows.

Raising the minimum floor version doesn't touch this: it only stops new publishes extending an old
floor (`extendable: false` in `GET catalog`).

**Residuals.** The catalog is built from files at start-up and held in memory, so a removal lasts
until the next start (the files are the source). There is no persistent catalog store yet. A
publish racing a removal: the check and the removal are not one transaction, so a bundle published
between them could extend an item just removed. Removal is an operator action while a deployment is
quiet, and the compiler refuses an unknown floor, pack or template at publish, so the window is the
few milliseconds between two calls of an operator tool.


---

# Part 2 · The tool registry and description screening

A tenant's tools (name, description, read-only flag) are rendered in the untrusted tool section
and gate `tool_call`. The description is tenant-written text that later reaches the model as
context, which is never re-judged, so it is screened **once, when it is registered or edited**
(the R7.3(b) condition). No tools are provisioned by platform ops.

| Method | Route | Role | What |
|---|---|---|---|
| GET | `…/tools` | viewer | `{tools: [{name, description, read_only, status, hold_reason, description_hash, submitted_by, submitted_at, reviewed_by, reviewed_at, version}]}` |
| PUT | `…/tools/{name}` | guardrail_admin | Body `{description, read_only?}`. Name `[a-z0-9_.-]{1,64}`, description 1 to 1,000 characters. 201 created / 200 changed, `accepted`; 202 `held_for_review`; 422 `tool_description_rejected`; 503 `screening_unavailable` (`Retry-After: 30`); 429 `screening_busy` or `screening_rate` (`Retry-After`); 409 `too_many_tools` (200 a tenant) or `tool_changed` (concurrent change). |
| DELETE | `…/tools/{name}` | guardrail_admin | 204, or 404 `tool_not_found` |
| POST | `…/tools/{name}/review` | guardrail_reviewer | Body `{decision: approve\|reject, description_hash}` on a **held** entry. A platform operator can't approve a tenant's tool (403 `operator_review`; they can reject). 409 `not_held`; 409 `vocabulary_hold` on approving a vocabulary hold; 409 `description_changed` if the hash isn't the entry's current one; 403 `self_review` when the approver is the submitter (rejecting your own is allowed, as withdrawing). |

**Names.** A registered name is printed on a *trusted* line of the rendered prompt (`TOOL <label>: <name>`), so it gets the slug's check: a part (split at `.`, `_`, `-`) in `SLUG_DENYLIST` (`system`, `override`, `safe`, `admin`, ...) is refused at registration (422, `tool.name`), filtered out of the profile by `RegistryTools`, and refused by `TenantProfile` itself. Screening sends `<name>: <description>`, so the name is judged with the text.

**What is screened.** The description as content at guard point `tool_result`, against the floor's
`p__inj_direct`, `p__inj_indirect` and `p__ai_addressed` taken from the **newest floor version in
the catalog** with the floor's own thresholds (0.85 block, 0.55 escalate today), not from the
tenant's bundle, so a tenant override can't loosen it. It runs through the draft evaluator
(`GuardService.evaluate_draft` with usage class `screen`): size limit, redaction, render, one
decision call, fusion. `p__inj_direct` is an `input` rule in the floor; here it is asked of a
tool description on purpose. A floor without all three keys makes screening unavailable (503), and **a production or staging engine refuses to start** if the newest floor lacks any of them (a test engine may).

| Outcome | Result |
|---|---|
| any of the three at block, or a provider safety refusal | 422 `tool_description_rejected`, `rules: [{rule, action}]` (never a score); nothing stored; one class A row `screen_block` (the hash, the rules) |
| escalate | saved `held` (reason `screening`), 202; not in the profile until a reviewer, who isn't the submitter, approves |
| allow | saved `accepted` |
| harm-vocabulary hit (the golden-set tripwire) | saved `held` (reason `vocabulary`) with **no model call**. **It can never be approved** (409 `vocabulary_hold`): it was never screened, so approving it would let text screening blocks in by adding a harm word. A reviewer can reject it, or the tenant replaces it with an edit that is screened |
| failure, timeout, unavailable, rate-limited or refused by the gateway, contract violation, no questions, engine shutting down | 503 `screening_unavailable`; **nothing saved or changed** (fail closed) |

**When.** On create and on any change of the description, inside the `PUT`. A `PUT` with the same
description is not screened again: the same flag is a no-op, and a changed `read_only` is saved
(version +1) with no call. An edit that is blocked leaves the old entry as it was. An edit that
escalates replaces the entry with a held one, so the tool leaves the profile until approved.
A rejected entry stays visible (`rejected`) and is resubmitted by changing its description.

**Only accepted entries reach the profile.** `RegistryTools` (admin/tool_registry.py) is the
directory's tool provider: `CachedTenantDirectory(tools=...)` now takes an async provider, and a
`CachedTenantDirectory` with no provider of its own adopts the registry when the engine is built
(`adopt_tools`). A registry change announces `guardrail.published` with action `tools` and
version 0 (`EVENT_ACTIONS`; the NOTIFY parser accepts it), and the engine invalidates its policy
cache and the directory entry, so the next check sees the new profile; the directory TTL (30 s)
bounds a dropped event. `RegistryTools` is the fourth module allowed to issue a tenant scope
(the test lists it): it reads for the tenant id the directory was asked about, which every caller
took from a verified context or an authorizer decision.

**Storage** (migrations 015 and 016, 014 extended for the operator role): `tenant_tools` (forced
RLS; CHECKs on name, description length, status, and that a reason exists exactly when held; the
primary key is the tenant and name, compare-and-set on `version`) and `tenant_tool_audit` (class
A, append-only by trigger and grants, forced RLS: one row per put, delete, approve, reject and
refused attempt, with the hash, the status, the reason and the blocking rule keys and actions;
never the description's text). An entry change and its row are one transaction.

**Cost and metering.** About 700 input tokens a screening (roughly $0.00007 at $0.10 per 1M).
Metered as `screen:tool_result` at the lowest priority (`TEST_PRIORITY`). The gateway counts any
non-production label that isn't `calibration`, `red_team` or `shadow` as the `test` consumer, so
screening **shares the `test` allowance** (non-production stays at 40% in total, M3-07) and no new
allowance exists. Per tenant: one screening in flight (429 `screening_busy`) and at most 30 an
hour (429 `screening_rate`, sliding window).

**Tests use the fake model only**: no provider call is made by any M2-03 test. A live call
happens only when a real tenant adds or edits a tool.

**Residuals.** (1) The limiter is per replica, so a tenant's ceiling is 30 an hour times the
replicas. (2) A description is judged once: a tool whose server later changes what it returns is
the tool-result guard's business. (3) A screening that blocks costs one call each time it is
retried. (4) Rejected entries are kept (not deleted) so the tenant sees the outcome; delete them
to remove. (5) The fixture floor in the tests lacks `p__inj_indirect`, so the screening tests use
the real `floor/rules.json`.


## Follow-up: a tenant's tool edit can't break the active version

* **A held edit to an approved tool leaves the tool registered.** The approved description stays
  in force (the entry stays `accepted`); the edit waits in `pending` (migration 027: the
  `pending_*` columns) until a reviewer approves it (it replaces the description) or rejects it
  (it is dropped). Resubmitting the approved description withdraws it. Only a brand-new tool, or
  one never approved, is held unregistered. The registry's profile (`RegistryTools`) reads only
  accepted entries' approved descriptions, so a version that names the tool keeps compiling.
* **A tool the active version or a candidate names can't be deleted.** `DELETE` answers 409
  `tool_in_use` with `versions: [{version, role}]` (the allow-lists of the active version and
  the candidate are read; a draft doesn't count: it isn't live).
* **The delete and the lock.** The usage check and the delete run inside the tenant's
  lifecycle lock (`LifecycleStore.exclusive`: the Postgres advisory lock every lifecycle write
  takes), so no publish or promotion commits between them. After the delete the check is made
  again, and a lifecycle write that got in anyway puts the tool back and the delete is refused
  (the in-memory store holds no lock). **Residual:** a publish that validated its allow-list
  before the delete and commits after it can still name a tool the registry no longer has; the
  engine goes on serving the compiled version, and registering the tool again restores it.
