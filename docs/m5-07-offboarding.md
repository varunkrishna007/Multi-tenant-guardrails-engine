# M5-07: offboarding

R3: "Offboarding deletes classes B, C, D and E and the golden sets within 30 days. Class A is kept
for its full term." This story ends a tenant (a platform operator terminates it), deletes what R3
says within 30 days, keeps class A, writes a deletion receipt per table and an "offboarding
complete" receipt, and pages if it hasn't finished by day 30. Code:
`src/guardrail_engine/offboarding/`, `directory/provisioning.py` (`terminate`),
`authz/authorizer.py` and `guard/service.py` (the refusals). Migrations **043** (schema,
functions, triggers) and **044** (the retention role's grants); 039 is another engineer's.

## The flow

```
operator: TenantProvisioner.terminate(actor, tenant_id, reason)
    status terminating   audited (class A: actor, reason, time), tenant.changed published
                         checks and admin calls refused from here       <- the 30-day clock starts
    drain (35 s)         past the Guard Service's 30 s directory cache, so every replica agrees
    status terminated    audited, published                             <- deletion may begin
OffboardingJob.run_once()   (daily, any number of replicas, injected clock)
    for each waiting tenant: overdue check -> delete table by table, in bounded batches
                             -> (after a quiet hour) completion receipt
```

### Terminating (acceptance 1)

* `TenantProvisioner.terminate(actor, tenant_id, reason)`: platform operator only, a reason of 1 to
  500 printable characters. The directory's status goes `active` (or `suspended`) to
  **`terminating`**, then, after `drain_s` (default 35 s, past the 30 s read cache), to
  **`terminated`**. Each step is a directory write with its class A audit event in the same
  transaction (`tenant_directory_audit`, actions `terminating` and `terminated`; `after` carries the
  status and the `reason`, `actor` is the operator) and a `tenant.changed` event.
* **One way only.** `set_status` refuses `terminating` and `terminated` (use `terminate`), and
  `update` and `set_status` on a terminating or terminated tenant raise `TenantTerminated`
  (`code = "tenant_terminated"`). The database enforces it too: a trigger on `tenants` refuses any
  status change out of `terminated`, any change out of `terminating` but to `terminated`, and a
  delete of either.
* **Idempotent and resumable.** A second call on a terminated tenant returns it and writes nothing.
  If the process dies in the drain, calling `terminate` again finishes (the tenant stays refused
  meanwhile). Two operators at once leave one `terminating` and one `terminated` event.
* **Statuses.** The directory had `active`, `suspended` and `offboarded`. `offboarded` is manual,
  reversible and deletes nothing (the Guard Service stops knowing the tenant), so
  it could not carry "deletion is now allowed"; `terminating` and `terminated` are new. `offboarded`
  is left as it was.

### What is refused from the moment of `terminating`

* **Checks.** `GuardService` asks the tenant directory (`CachedTenantDirectory.ended`) right after
  the signed context verifies and the payload's tenant matches. A terminating or terminated tenant
  gets `Decision.FORBIDDEN` with the new `Reason.TENANT_TERMINATED` (`"tenant_terminated"`, not
  retryable), before any policy is read and with no model call. **The verdict and its audit record
  carry no tenant id** (they look like an unverified-tenant record), so a refused check can't
  write a decision record under the tenant that offboarding is deleting. The status is remembered
  for good in the process once seen (it never goes back), and `tenant.changed` invalidates the
  cache, so the refusal is immediate where the event reaches and within 30 s elsewhere.
  If the directory can't answer the status question the check goes on (logged): the policy cache
  reads the same directory with its own last-known-good rules, and refusing every tenant during a
  directory outage is the larger harm. A payload naming another tenant is still a
  `tenant_mismatch`, so a probe learns nothing about the terminated tenant.
* **Admin calls.** `Authorizer(tenant_ended=...)`: every tenant route, for every caller including
  platform operators, is refused 403 with reason `tenant_terminated` (the HTTP error code is
  `tenant_terminated`). The check runs after the tenant match (a caller of another tenant gets
  `tenant_mismatch`) and reads the directory fresh (`ended_fresh`, no cache). **If the status can't
  be read the call is refused** (`tenant_status_unavailable`): admin traffic is low volume and this
  is the fail-closed side. A refused operator crossing is audited like any denial. The engine
  factory wires it when the directory has `ended_fresh` (the cached directory does).

## What offboarding deletes and keeps (acceptance 2 and 3)

Every table with a `tenant_id` column (and the outbox, which names the tenant in its payload) is in
exactly one of two lists in `offboarding/model.py`. A Postgres test reads `information_schema` and
fails if a table with a tenant column is in neither, so a new table can't be forgotten.

Classes in receipts: `B` decision records and what derives from them, `C` stored content, `D`
escalation items, `E` calibration data, `G` golden sets, `W` tenant working data (not an R3 class).

### Deleted (in this order: children first)

| Table | Class | Why |
| --- | --- | --- |
| `decision_record_rules` | B | the filter index of a decision record (also removed by the record's cascade; listed first so it has its own receipt) |
| `decision_records` | B | R3 class B |
| `usage_events` | B | the usage meter; derived from checks (the story names "usage rows"). It is also billing evidence, so the raw rows go only with a class A per-month summary written in the same statement (see below) |
| `tenant_shadow_agreement` | B | shadow-agreement counters; aggregates of checks, rule keys and counts only |
| `delivery_outbox` | B | the tenant's **usage and escalation** events only (matched on `"tenant_id":"<id>"` in the compact JSON payload; the escalation notice holds the tenant's webhook url). A pending **alert** that names the tenant stays (see below) |
| `escalation_items` | D | R3 class D. Items that held stored content (`store_content = full`) are also counted under **C** (receipt table `escalation_items.content`), because v1 keeps class C only inside escalation items |
| `tenant_golden_examples`, `tenant_golden_sets` | G | R3 names golden sets. Includes escalation label sets |
| `tenant_calibration_scores`, `tenant_calibration_outcomes` | E | calibration data keyed by content hash; no content, but it is derived from golden-set content (not R3's content-bearing "calibration sample", see limits) |
| `tenant_calibration_targets` | W | the tenant's chosen targets; the change history stays in `tenant_calibration_audit` |
| `tenant_drafts` | W | the working draft |
| `tenant_candidates` | W | the rollout candidate pointer. A candidate's content is a stored bundle version, which is class A and stays |
| `tenant_tools` | W | the tool registry holds tenant-written descriptions; its history stays in `tenant_tool_audit` (hashes only) |

### Kept (class A, no delete path)

`tenants` (the directory row, with its terminated status), `tenant_directory_audit`,
`policy_bundle_versions` (bundle versions and diffs: R3 class A, which also holds the candidate's
content) and `policy_active_versions`, `tenant_draft_audit`, `tenant_publish_audit`,
`tenant_tool_audit`, `tenant_golden_audit`, `tenant_calibration_audit`, `tenant_approvals` and
`tenant_approval_audit` (R3 lists approvals as class A; hashes and actors, no content),
`escalation_audit`, `platform_audit`, `retention_receipts`, and this story's `offboarding_receipts`,
`offboarding_completions`, `offboarding_usage_summaries` and `offboarding_sweeps`. Platform-wide tables (floors, releases) hold no tenant data.

### Classifications that were not obvious

* **`tenant_approvals`** is a mutable-status table (pending to consumed), but R3 names "approvals" in
  class A and it holds hashes and actors only. Kept.
* **`tenant_calibration_scores` and `_outcomes`** are not R3's class E (content, context and labels of
  sampled checks, dogfood only, which this repository's DB does not hold). They are the tenant's
  calibration results, keyed by content hash; the story lists "calibration scores". Deleted under `E`.
* **Drafts, candidates, the tool registry and calibration targets** fit no R3 class. They are current
  working state whose history is in class A audit tables, and the story lists drafts and
  candidates. Deleted under `W`.
* **`tenant_shadow_agreement` and `usage_events`** are derived from decisions: B.
* **`policy_bundle_versions`** can hold tenant-written rule text, but R3 calls bundle versions class A.
  Kept.

## The deletion functions and their privileges (acceptance 2)

Five `SECURITY DEFINER` functions in migration 043 (three here; the two daily-sweep ones are under "Offboarding fixes" below), owned by the table owner, with
`SET search_path = pg_catalog, <schema>, pg_temp` and every table and function schema-qualified
(the same pattern as `retention_delete_class_b`; `<schema>` is `current_schema()` at migration
time). `EXECUTE` is revoked from PUBLIC; 044 grants it to the retention role only.

| Function | Does |
| --- | --- |
| `offboarding_delete_batch(run_id, tenant_id, table, limit, batch, price)` | refuses unless `tenants.status = 'terminated'` (**the function reads it, under `FOR SHARE` on the tenant's row**); deletes at most `limit` rows of one table with `FOR UPDATE SKIP LOCKED`; writes the receipt in the same transaction. Batch 1 always writes a receipt (zero if nothing), a later batch only if it deleted. Class C's receipt is written with `escalation_items`'. Bounds: limit 1..100,000, batch at least 1, a tenant id of the tenant pattern, a table from a fixed list (an unknown name, or any class A table, is `22023`). It sets `app.tenant_id` for the one tenant it was named for (forced row-level security) and puts it back. |
| `offboarding_complete(run_id, tenant_id, now)` | refuses unless terminated; takes `FOR UPDATE` on the tenant's row (one completer at a time); returns `already_complete` if the receipt exists, `remaining` if any deletable table still has a row for the tenant, else writes the class A completion receipt and returns `completed`. `now` may not be more than five minutes ahead of the database clock. |
| `offboarding_pending(limit)` | the tenants that are `terminating` or `terminated` with no completion, with the time of the `terminating` audit event (the clock's start) and of the `terminated` one. |

A caller who passes `p_tenant_id` of an active, suspended, offboarded or terminating tenant, or of
no tenant, gets SQLSTATE `55000` and nothing changes, **even calling the function directly as the
retention role** (tested for every table and for the completion). The temporary-table probe of
Is replayed: a temp `tenants` that says "terminated", a temp `offboarding_receipts` and a
temp `tenant_drafts` made by the retention role change nothing.

**The triggers.** The four content tables that were immutable (`tenant_golden_sets`,
`tenant_golden_examples`, `tenant_calibration_scores`, `tenant_calibration_outcomes`) now use
`offboarding_deletable_guard`: a `DELETE` passes only when `offboarding_delete_allowed(tenant)` is
true, which means the tenant's status is `terminated` **and** the transaction-local setting
`app.offboarding_tenant` names that tenant (only the deletion function sets it). `UPDATE` and
`TRUNCATE` stay refused, and every class A table keeps its strict trigger (tested: deleting or
updating any of them is refused even for a terminated, named tenant). `decision_record_rules` and
`usage_events` got owner-only `FOR UPDATE` and `FOR DELETE` row-level-security policies, scoped to
`app.tenant_id`, because their row-level security had read and insert policies only (the tests run
with a non-superuser owner so the policies are exercised).

| Role | Delete tables | Offboarding receipts | The three functions |
| --- | --- | --- | --- |
| Service (`apply_app_role_grants`) | none | none | no EXECUTE (tested) |
| Retention job (`apply_retention_role_grants`, files 030, 037, 044) | no DELETE, no INSERT; SELECT only on `decision_records.tenant_id` and `escalation_items.tenant_id` (M4-09, M4-05) | SELECT | EXECUTE |
| Owner (migrations) | all, but class A triggers refuse | append-only trigger | all |
| PUBLIC | none | none | EXECUTE revoked |

## The job (acceptance 2 to 4)

`OffboardingJob(store, clock=..., alerts=..., batch_size=1000, max_batches_per_table=1000,
quiesce=1h).run_once()`. The clock is injected and read once. For each waiting tenant:

1. **Overdue.** `now > terminating_at + 30 days` (strictly: at exactly day 30 it is still in time)
   and not complete: one `offboarding_overdue` **page** per run (a platform alert, `tenant_id`
   empty because the tenant's own outbox rows are being deleted; the message names the tenant;
   dedupe key per tenant per day). A tenant stuck in `terminating` pages the same way.
   `check_overdue()` does only this, for a watcher that runs apart from the deletion.
2. **Delete**, only for `terminated`: tables in order, bounded batches, at most
   `max_batches_per_table` per run. A table that hits the cap ends the run for that tenant
   (`more_to_do`), which also keeps a parent (golden sets, decision records) behind its children.
3. **Complete** when nothing is left and `now - terminated_at >= quiesce`. Until then the job
   keeps sweeping (each run is idempotent), so a write that was in flight at the termination
   and landed late is deleted before the receipt says "done".

**Replicas and idempotency.** `FOR UPDATE SKIP LOCKED` means two runs never delete or count one
row twice; a run that loses rows to another still writes its batch-1 receipt, so a tenant's totals
are the sum over run ids (as in M4-09). Completion is written once (primary key plus the
tenant-row lock). A finished tenant drops out of the pending list, so a repeat run does nothing at
all, and a half-finished one resumes from what is in the tables. A tenant whose batch raises is
listed in `report.failed`; the others go on.

**Receipts (class A, no content).** `offboarding_receipts`: run id, database time, tenant, table,
class, count, batch. `offboarding_completions`: one row per tenant with the run id, the
`terminating` and `terminated` times, the deadline, `within_deadline` (true if the completion's
clock was at or before day 30), `counts_by_class` (`B C D E G W`, zero where none) and
`counts_by_table`. Both append-only for every role, the owner included.

Scheduling is the deployment's (a daily timer, or a cron calling `run_once`); the engine factory
does not start it, as for M4-09 and M4-05. If the job never runs, nothing pages: monitor the
scheduler, or run `check_overdue()` from a second place.

## Known limits

* **Writes after the sweep.** A check admitted just before `terminating` can still write a decision
  record, a usage event or an outbox row afterwards (write-behind queues, outbox retries). The 35 s
  drain and the one-hour quiet period before the completion receipt make this a small window, and
  each run re-sweeps, and the seven daily re-sweeps after the completion receipt (see below)
  catch what arrives in the first week, but a row landing after day 7 stays. No insert guard on the
  data tables was added (it would cost a status lookup on the hot insert paths).
* **Backups and replicas.** Offboarding deletes from the live database. Backups, WAL archives and
  read replicas age out on the platform's own schedule; a 30-day promise covers them only if their
  retention is under that. Not handled here.
* **Usage rows** are deleted, but their billing totals are kept (see below): per month and usage
  class, never per event.
* **Class E, as R3 defines it** (post-redaction content, context and labels of checks sampled for
  calibration, dogfood tenant only) isn't in this database; the `E` here is calibration scores and
  outcomes. Wherever that sample is stored needs its own deletion hook, and a new table is caught by
  the class-map test only if it has a `tenant_id` column.
* **Class C** has no table of its own in v1: stored content lives in escalation items. Its count is
  of items that held content and is a sub-count of `D`.
* **Delivered webhooks can't be recalled.** Escalation notices already sent are the receiver's.
* **Class A is kept whole**: bundle versions, diffs and audit events can hold tenant-written text.
  That is R3's decision (7 years, immutable). Admin calls on a terminated tenant are all refused, so
  reading its class A is a database or operator-tooling task, not an API one.
* **Check refusal is up to 30 s late on other replicas** unless `tenant.changed` reaches them;
  deletion waits for the drain, so nothing is deleted while a replica still serves the tenant. If the
  directory is down, a replica goes on serving a tenant only while its last successful read of that
  tenant is under 5 minutes old, then it fails closed (see below).
* A terminated tenant's id and slug stay in the directory (class A), so neither is reissued.
* The finance and healthcare retention figures still need legal sign-off before M5 GA (R3); this
  story does not change them.

## Offboarding fixes

Four minor changes. Migrations **043** and **044**
were changed in place (no 045).

### An unreadable directory no longer keeps a terminated tenant served

"The directory can't answer, so the check goes on" is bounded. `CachedTenantDirectory.ended()` (the
Guard Service's check) answers "not ended" when a read fails **only while this process's last
successful read of that tenant is under `max_unknown_s` old** (default 300 s, the constructor
argument; ten times the 30 s read cache, so a normal blip passes). Past that, or for a tenant this
process never read, it raises the store's error and the Guard Service returns **`block` /
`policy_unavailable`** (retryable; the verdict carries the tenant id, since the tenant isn't known to
be ended). So the policy cache's last-known-good policy can no longer carry a tenant whose status
the replica can't confirm. A tenant seen as terminating or terminated stays refused as before, down
or not. The Admin API's `ended_fresh` already failed closed. Tests use an injected clock.

### Usage rows are billing evidence

When it deletes `usage_events` rows, `offboarding_delete_batch` writes a class A summary into the dedicated table **`offboarding_usage_summaries`**, in the **same SQL
statement** as the delete (a data-modifying CTE over the rows `DELETE ... RETURNING` just removed), so
the summary and the delete are one transaction and the totals equal the deleted rows by
construction (tested, at several batch sizes, with rows across month boundaries and every usage
class).

* One row per (batch, **UTC calendar month** of `occurred_at`, **usage class** = the event kind):
  `events`, `answered_calls` (events of kind `answered`), `input_tokens` (null counts as 0; an
  `unknown` event has no tokens), `price_per_million_usd` and `cost_usd = input_tokens x price / 1e6`.
  A tenant's totals are the sums over its rows (`store.usage_summary(tenant_id)`).
* The price is the **configured** one: `PostgresOffboardingStore(pool,
  price_per_million_input_tokens_usd=...)` or the in-memory store's field of the same name, default
  0.10 (the gateway's `DEFAULT_PRICE_PER_MILLION_INPUT_TOKENS_USD`). It is stored beside every row;
  0..1,000,000 only. The function's own default (0.10) applies only to a direct call that omits it.
* The table is append-only for everyone (update, delete and truncate are refused), holds no
  content, and the retention role has SELECT only. Months are UTC, as the usage rows' `occurred_at`
  is; the gateway's monthly spend counter rolls on Pacific time, so a boundary hour can differ from
  the spend counter by a day's edge. Billing can re-derive Pacific months only from the raw rows,
  which are gone.

### A daily re-sweep for seven days after completion

After the completion receipt the job re-sweeps the tenant **once a day for 7 days**:

* Day N is due N days after the completion receipt's time. `run_once` asks the store
  (`resweep_due(now)`, in Postgres `offboarding_resweep_pending(now, limit)`) who is due and runs
  the same bounded delete pass for each. The day it reports is the latest due, capped at 7, so a job
  that was down catches up with one sweep (and one that wakes after day 7 runs the day-7 sweep once).
* Every sweep that ran to the end is logged in the class A, append-only **`offboarding_sweeps`**
  (tenant, day 1 to 7, run id, time, rows deleted), whether or not it found anything, through
  `offboarding_sweep_log` (which refuses a day not yet due and a clock more than five minutes ahead
  of the database). A sweep that hit the batch cap isn't logged; the next run continues it.
* A **small class A receipt is written only when it deleted something**: the ordinary
  `offboarding_receipts` rows, flagged `resweep = true`, one per table that had late rows (the
  database sets the flag because the tenant already has a completion receipt). A sweep that finds
  nothing leaves no deletion receipt, only its log row. Late usage rows get their summary too. The
  completion receipt is never rewritten.
* **After day 7 the tenant is final**: its day-7 sweep is logged, it is never listed again, and a row
  that lands later stays (documented, as before).
* `OffboardingReport.resweeps` lists the sweeps of the run (`TenantResweep`: tenant, day, rows
  deleted by table, `more_to_do`, `logged`). Tests use an injected clock; on Postgres, which stamps
  the completion with its own clock, the test moves the completion receipt back as a superuser.

Functions added to 043 (both `SECURITY DEFINER`, the same pinned search path, EXECUTE to the
retention role only by 044): `offboarding_resweep_pending(now, limit)` (read-only, so it doesn't
bound the caller's clock) and `offboarding_sweep_log(run_id, tenant_id, day, deleted, now)`.
`offboarding_delete_batch` gained a sixth argument, the price (default 0.10).

### The outbox delete is limited to the tenant's own kinds

`delivery_outbox` rows are deleted only for `kind IN ('usage', 'escalation')`, in the delete and in
the completion's "anything left" check, and in the in-memory outbox (`OFFBOARD_KINDS`). A **pending
platform alert that names the tenant stays** in the outbox until it is delivered or dead-letters:
`bad_publish_block_rate`, `escalation_dropped`, `approved_version_change` and the like are ops
signals about the tenant, not the tenant's data, and the overdue page is itself a platform alert.
They hold ids, counts and fixed sentences, no content. A tenant's pending alert rows therefore don't
hold the completion receipt up either. (Escalation notices, which carry the tenant's webhook url,
are still deleted.)


## Changing 043 in place (M5-03)

M5-03 added a `stored_content` branch (class C) to `offboarding_delete_batch` and to the completion
check by **editing migration 043 in place** instead of adding a new file. That is safe only because
`apply_schema` applies **every file of `MIGRATIONS` in full on each start** (plain, re-runnable SQL
under an advisory lock) and nothing is deployed. A deployment that tracked which migration files it
had already applied would have to carry the change as a **new** migration (a `CREATE OR REPLACE`
of both functions and the receipts table's `table_name` CHECK) or class C would be left behind at
offboarding. The header of 043 says the same.
