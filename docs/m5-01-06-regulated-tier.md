# M5-01 and M5-06 · The regulated tier, and dedicated key pools for it

A tenant's **tier** is a platform attribute (`standard`, `regulated`, `dedicated`). Only platform
operators set it. It decides what a tenant must publish, whether enforcing needs a second person
and how long records are kept. A regulated tenant also gets its own Gemini project, so its quota
and billing are its own. This is how both work, when a change takes effect, and what is left.

Migrations **045** (M5-01) and **046** (M5-06). No live call, no new secret.

# Part 1 · M5-01 · The regulated-tier attribute

## What "regulated" means

`regulated` and `dedicated` are the **regulated tiers**: every tier but `standard`
(`policy.catalog.REGULATED_TIERS`, `is_regulated_tier`, `TenantAttributes.regulated`). That is
what the two-person gate (M5-02) and the quota shares (M3-07) already treated as regulated; there
is now one definition. `dedicated` was already modelled and is kept as a regulated tier (an open
question below).

## Only platform ops set it

| Path | Who may use it | What a tenant admin gets |
| --- | --- | --- |
| `PUT /v1/tenants/{tid}/guardrails/tier` (`{"tier", "reason", "expected_version"?}`) | platform operators (`platform_operator` claim, platform issuers only) | 403 `forbidden` / `not_platform_operator`; on another tenant's path 403 `tenant_mismatch`. The route is a `PLATFORM` row of the authz table, so every role is refused and an operator's crossing into a tenant is audited before the answer. |
| `TenantProvisioner.set_tier`, `update(tier=...)`, `create(tier=...)` | the same, checked again in the provisioner | `NotAPlatformOperator`, nothing written |
| the draft, a bundle, any tenant body | nobody | the tier is in no field a tenant writes; a `tier` key in a bundle is an unknown field and the draft is refused (422) |

The route exists when `build_engine` is given the directory's write side
(`directory_store=`, `directory_bus=`), which builds `Engine.tier_service`. Without them the
directory is written by operator tooling that builds its own `TenantProvisioner`, as before.

**Audit.** Every change is a class A directory event in the writing transaction
(`tenant_directory_audit`, append-only): `action` is `set_tier` for `set_tier()` and `update` for
the older path, with the **actor** (`<issuer>#<subject>`), the record **before** and **after** (the
tier is in both) and, for `set_tier`, the operator's **reason** (1 to 500 printable characters).
`tenant.changed` is published after it, so the Guard Service sees the change within seconds (30 s
read cache at most). Setting the tier a tenant already has writes nothing.

## What the tier drives

| Drives | How | When |
| --- | --- | --- |
| **Required packs** | `Catalog.packs_required_for_tier`: `responsible_ai` on `regulated` and `dedicated` (R4.1), plus `catalog.tier_required_packs`. The compiler refuses a bundle that doesn't extend one (`pack.required_missing`). | the tenant's **next publish** |
| **Required rules** | `Catalog.rules_required_for_tier` (below). The compiler refuses opting out of one (`pack.rule_required`), even in a per-rule-optional pack. | the next publish |
| **Approval (R2)** | `approval_required(profile)` = `profile.attributes.regulated or require_two_person`. The M5-02 gate reads the real attribute. `two_person_publish` stays the standard-tier opt-in. | the next enforce publish or promotion, once the directory change is seen |
| **Retention floors (R3)** | the existing resolver and the audit term add the packs the tier requires to the packs the bundle extends and take the longest default and minimum and the shortest maximum | **at once**: a deletion can't be undone, so the floor does not wait for a publish |

### The rules R4 requires

R4 says the pack is "required on the regulated tier" and names no individual rule. So **the whole
pack is required**: `rules_required_for_tier(tier)` is the rules named by
`catalog.tier_required_rules[tier]` **plus every rule of every pack the tier requires** (all
versions of the pack). For `domain/responsible_ai@1` that is the seven rules `d__self_harm_risk`,
`d__vulnerability`, `d__harassment`, `d__manipulation`, `d__bias_stereotype`,
`d__bias_protected_basis` and `d__harm_facilitation` (observe-only, kept in the set so it can't be
opted out of either). `tier_required_rules` stays a setting for a narrower or wider rule list.

R4.6's opt-out of one rule, with a justification, is unchanged for a standard tenant.

The platform's own requirement needs no setting. A required pack the catalog doesn't hold is
**never skipped** in `production` and `staging`: the requirement stands (a tenant of the tier can't
publish until `catalog.pack_files` has the pack) and the engine logs an error at startup. In
`test` the platform's own requirement is left out with a warning, so an engine built with no pack
files still works.

## A tier change on a live tenant

- **The active version keeps running.** The Guard Service compiles a version it loads (the active
  version after a restart, a candidate, a rollback target, a floor re-pin) with
  `PolicyCompiler(..., enforce_tier_requirements=False)`. Nothing else is relaxed: the floor, packs,
  overrides, thresholds and retention bounds are checked as always. Without this a raise would make
  the running version fail to compile, fall back to last-known-good, and refuse to start after a
  restart.
- **The next publish is held to the new tier.** Drafts (validate, test, calibrate) and publishes
  use the strict compiler, so the tenant sees `pack.required_missing` as it edits. **So is a
  promotion**: a candidate published before a raise is compiled strictly under the
  tenant's current tier when it is promoted.
- **A rollback on a regulated tenant is held to it too** (see "A rollback on a regulated tenant must meet the tier" below). A re-pin changes
  only the floor and is not.
- **A raise alerts.** After the write, the provisioner compares what the active version lacks
  under the new tier with what it lacked under the old one (`pack:<name>` for a required pack it
  doesn't extend, `rule:<key>` for a required rule it opted out of). Any new gap raises a
  `tier_raise_unmet` **warning** for the tenant's admins and platform ops (`tenant_id` is the
  tenant, `reason` the gaps, deduped by tenant and record version) and is in the route's answer
  (`unmet_requirements`). Catalog names only: no tenant content, no justification text. A
  lowering raises nothing. An unreadable active version doesn't undo the change.
- **Approval.** A tenant raised to regulated needs a second approver for its next enforce publish
  or promotion. An enforce candidate it published as a standard tenant has no approval, so its
  promotion needs one (already so).

## Tests

`tests/engine/test_m5_01_tier.py` (required packs and rules from the real pack, the compiler's
refusals, the approval gate by tier, a raise on a live tenant including a restart),
`tests/directory/test_m5_01_provisioning.py` (every write path refused for a tenant admin, the
audit event, the alerts), `tests/admin/test_m5_01_http.py` (403 for every role on every tenant,
401, the operator's answer, the audited crossing), `tests/store/test_m5_01_retention.py` (the
floor follows the tier at once).

# Part 2 · M5-06 · Dedicated key pools for regulated tenants

## What it is

Standard tenants share one pool: the engine's own Gemini project (label `default`, key in
`GEMINI_API_KEY`). A regulated tenant is assigned a **dedicated project**, which serves that one
tenant: its per-minute token bucket, daily request count and monthly spend are its own, its calls
go out on its own key, and its usage and cost are reported under its own label. (Whether Google's
quotas are per project or per key is the unverified assumption of M0-03; this story takes
"per project", as the capacity plan does.)

**A project is a label** (`reg-acme`: lower case, digits, hyphens, at most 40 characters, never
`default`). The label is all that is stored or reported. **The key is never in a setting, a record,
a log, a metrics response or an error.**

## Configuration: names and references only

```toml
[projects.dedicated.reg-acme]
key_env = "GEMINI_KEY_REG_ACME"        # the NAME of an environment variable, never a key
[projects.dedicated.reg-acme.token_rate]   # optional: this project's own Gemini tier and quota
tier = "tier_2"
tokens_per_minute = 4000000
```

- `key_env` must look like a variable name (`[A-Z][A-Z0-9_]{1,63}`). A key (`AIza...`) has lower-case
  letters and punctuation and is refused, **without being echoed**. It can't be `GEMINI_API_KEY` and
  can't repeat another project's variable. There is no key field.
- At startup the engine reads each variable, checks the value the way `GEMINI_API_KEY` is checked
  (set, no surrounding whitespace, no control or non-ASCII character) and never repeats it. A project
  with neither its variable nor an injected model (`build_engine(project_models={label: model})`,
  the test seam, like `model`) stops startup, naming the setting and the variable.
- `token_rate` is optional: unset, the project takes the engine's `token_rate` (so none in `test`
  unless set) with the label as its project id. Quotas, in-flight limits and budgets are the
  engine's. No new provider secret, no network call, no live call.

## Assignment

`TenantProvisioner` (built with `projects=DedicatedProjects.of(labels, environment=...)`; the
engine builds it from the settings for the tier route):

- **`create(tier="regulated" | "dedicated")`** and **`set_tier(..., "regulated")`** assign the first
  free dedicated project (or the operator's explicit `project=` on create), in the same class A event
  as the tier: `project` is in `before` and `after`. A tenant holds at most one project, and a project
  serves at most one tenant (checked in code and by a partial unique index; a terminating or
  terminated tenant gives its project up).
- **None free** (none configured, or all in use): in `production` and `staging` the create or raise is
  **refused with `NoDedicatedProject`** (HTTP 409 `no_dedicated_project` on the tier route) naming
  the setting to change, and nothing is written. In `test` the tenant falls back to the shared pool
  with a logged warning.
- **Lowering** a tier keeps the project (billing continuity) **until an operator releases it**
  (`release_project`, see "Releasing a project" below). `assign_project(tenant)` brings in a regulated tenant that
  predates the pools, or moves one to a named free project.

## Routing

`GuardService` builds one `DecisionGateway` per project (`ProjectBackend`: model, non-secret key id,
and the gateway config with the project's own limiter). A check goes to the gateway of the project in
the tenant's directory entry (`attributes.project`), else the shared one. A tenant **named for a
project that has no backend fails closed** (a model failure, resolved by layer; the floor blocks):
it is never served from the shared pool. Draft tests, calibration, shadow runs and red-team calls of a
regulated tenant use its own project too, inside the non-production allowances of that project.
Every gateway is given the engine's `rate_store`; the store is keyed by project id, so engines of one
process share each project's bucket and counters and no project's.

## Billing and usage per project

- `usage_events.project` (migration 046) holds the label of the project that made the call (`''` is
  the shared pool and any row older than the migration). The usage meters stamp it
  (`UsageRecorder.with_project(label)`, which the engine uses for each project's gateway; the label
  rides the outbox event and an older payload reads as the shared pool). A meter without
  `with_project` is shared as it is, and its usage is then not attributed.
- `GET /v1/tenants/{tid}/guardrails/metrics` gains `projects`: per project `project` (a label,
  `default` for the shared pool), `dedicated`, `input_tokens`, `cost_usd`, `metered_events` and the
  non-production tokens and cost. Production figures add up to `cost.input_tokens`. Counts, a label and
  prices only; the report never reads a key, a variable name or a secret. A tenant sees its own rows.
- The tenant's monthly spend and daily request count against the Gemini quota are the project's own
  (`token_rate` per project), so the platform's billing for a regulated tenant is its project's.

## Storage

Migration **046**: `tenants.project` (a label, `CHECK`ed, one active tenant per project) and
`usage_events.project` (`CHECK`ed label or `''`). `tenants` is platform data and not row-level
secured, as before; `usage_events` is tenant-scoped and keeps the **forced** row-level security of 038
(a tenant's metrics read only its own rows and labels; an insert needs the tenant setting).

## Tests

`tests/gateway/test_m5_06_separate_buckets.py` (separate buckets, daily counts, spend and tenant
shares per project: exhausting one never touches the other), `tests/engine/test_m5_06_engine.py`
(routing, each project's own key, fail closed, startup and settings never echo a key, no key in logs),
`tests/directory/test_m5_06_assignment.py` (assignment, refusal in production and staging, the test
fallback, one tenant per project, memory and Postgres), `tests/admin/test_m5_06_http.py` and
`tests/admin/test_m5_06_metrics.py` (the answer and the `projects` breakdown),
`tests/store/test_m5_06_usage_postgres.py` (the column under forced RLS).

# Fixes: tier changes on live tenants

Fixes on branch `m5-01-06-fixes`. No migration (the
release is audited as an `update` event, so the audit `action` check of 045 is unchanged).

## A promotion is held to the tier of today

A candidate published while the tenant was standard could be promoted after a raise to regulated,
and run for good without the tier's required pack. Now `PublishService.promote` compiles the
candidate's stored document **strictly** under the tenant's current tier and contract
(`policy.tier_check.tier_requirement_errors`) before it looks at any approval:

- the refusal is a 422 `invalid_draft` with the codes a publish of the same bundle gets
  (`pack.required_missing`, `pack.rule_required`), whatever approvals it has: a second admin can't
  waive R4.1. The approval is not consumed, the candidate stays a candidate and the active version
  keeps running. To go on, the tenant publishes a new version that meets the tier;
- the check is the strict compiler's errors minus the relaxed compiler's, so it reports only the
  tier's own refusals, never an unrelated problem of an older version;
- it applies to every tenant, so a standard tenant with a contract `required_packs` entry is held to
  it too. A standard tenant with no requirement sees no change;
- **`tier_raise_unmet` also reports the candidate.** `CatalogTierImpact` takes an optional loader
  for the candidate; `TierChange.candidate_gaps` and the route's `unmet_candidate_requirements`
  carry what it lacks, and the one alert names both (`reason`: the active gaps, then
  `candidate:` and the candidate's gaps; the message says the candidate can't be promoted until it
  meets them).

## Releasing a project, and an empty pool

- **`TenantProvisioner.release_project(actor, tenant_id)`** returns a tenant's dedicated project to
  the pool. Operator only (`NotAPlatformOperator` otherwise). Refused with `ProjectInUse` while the
  tenant's tier is regulated, so a regulated tenant never loses its project; a terminating or
  terminated tenant has given its project up already (`TenantTerminated`). A tenant with no project
  is returned unchanged and nothing is written. Audited as a class A `update` event: the project is
  in `before`, gone from `after`, with the reason `release_project <label>`; `tenant.changed` is
  published, so checks go back to the shared pool within the 30 s read cache.
- **When a tier lowers, the project stays assigned until it is released.** This is deliberate
  (billing continuity, no flapping of the bucket). It means the pool drains unless an operator
  releases the projects of lowered tenants; the operator runbook is: lower the tier, then
  `release_project` when the tenant's billing period is closed. There is no HTTP route for it yet:
  operator tooling calls the provisioner, as for `assign_project`.
- **`dedicated_pool_empty`** (warning, a platform alert: `tenant_id` empty, the message names the
  tenant) is raised whenever an assignment finds no free dedicated project, as well as the 409
  (`production`, `staging`) or the shared fallback (`test`, where the message says so). It is
  raised by create, a raise, and `assign_project`, deduped per tenant.

## A rollback on a regulated tenant must meet the tier

Decision: **R4.1 wins over R2's rollback exemption.** On a regulated tenant (`regulated`,
`dedicated`) a rollback target is compiled strictly under the current tier like a promotion.

- A target that falls short is refused with the same codes a publish gets (422 `invalid_draft`,
  `pack.required_missing` / `pack.rule_required`) and the refusal lists the version numbers a
  rollback may go to instead: `RollbackTierError.compliant_versions`, and `compliant_versions` in
  the HTTP error body (previously active versions that meet the tier, without the active version
  and the candidate). It may be empty; the tenant then publishes a new version.
- **Rollback stays approval-free** (R2): the check adds no approver. A standard tenant is not
  held to it (the exemption stands there).
- **The running version keeps running**, even if a raise left it non-compliant: nothing about
  loading it changed, and the raise alert is what tells the admins.
- The re-pin of a rollback to a version below the platform's floor minimum is checked first, on
  the stored target, so a non-compliant target is refused before it is re-pinned.

## Tests

`tests/admin/test_tier_lifecycle.py` (the probe: v1 active, v2 shadow candidate,
raise, alice and bob's promote approval, refused; the same codes as a publish; an enforce
candidate; a compliant candidate still promotes; a standard tenant is unaffected; rollback
refusals with the compliant list, approval-free, HTTP body),
`tests/directory/test_release_project.py` (release: the pool gets the project back and the
audit event, refused while regulated, operator only, no-op and terminated; `dedicated_pool_empty`
in production, staging and test; the candidate's gaps in the raise alert).

# Deviations, limits and open questions

- **`dedicated` is a regulated tier.** The code already treated every non-`standard` tier as regulated
  (M5-02 approval, M3-07 quotas); M5-01 keeps that and gives it the same required pack and project.
  If `dedicated` is meant for a large unregulated tenant, it needs its own definition (a one-line
  change to `REGULATED_TIERS`, which also makes it standard-tier for approval).
- **R3 finance and healthcare packs (M5-04) are not in the platform default.** Only the
  responsible-AI pack is required by tier today; `catalog.tier_required_packs` adds more per tier,
  and the retention floors follow whatever packs the tier requires.
- **The tier route reads the active version through the operator's scope** (the way the floor re-pin
  does), so the alert needs the lifecycle store; operator tooling that builds its own provisioner
  passes `impact=CatalogTierImpact(catalog, loader)`.
- **No secret-store interface exists yet** (M3-08 said keys come from one): a project's key is read
  from the environment variable its `key_env` names, as `GEMINI_API_KEY` is. A secret store replaces
  that read in `_project_keys`.
- **The offboarding usage summary** is by usage class and does not carry the project. A
  terminated tenant's per-project billing evidence is its summary's totals; add a project column if
  per-project evidence must outlive the rows.
- **Keys of one project are one key.** Several keys in one project (M3-08) are not modelled: the
  burst test said extra keys in a project add nothing.
