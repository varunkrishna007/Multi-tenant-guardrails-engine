# M4-09: the retention engine, classes A and B

R3 splits audit data into classes. This story enforces the class B (decision record) terms and
deletes expired class B records daily, with a class A receipt for every deletion. Code:
`src/guardrail_engine/retention/`; schema: migrations 026, 029 and 030.

## What a tenant's term is

`CatalogRetentionResolver` works out a tenant's class B term. It reuses the AC-C1.13 code in
`policy/compiler.py` (`combined_retention`, `records_days_in_bounds`), which the compiler now
also calls, so publish-time validation and deletion-time enforcement can't drift apart.

* **Packs:** the packs the active bundle extends, plus any pack the tenant's tier or contract
  requires that the bundle doesn't extend (latest catalog version). The compiler refuses such a
  bundle at publish, but a tier change afterwards would otherwise leave the old bundle's
  shorter bounds in force.
* **Several packs:** longest default, longest minimum, shortest maximum (R3).
* **Term:** the bundle's `audit.records_days`, else the packs' default (395 days standard, 7
  years finance, 6 years healthcare). A value outside the bounds is moved **up** to the minimum
  or **down** to the maximum (receipt `source` = `clamped`); the job never deletes sooner than
  the tenant's minimum.
* **Unresolvable** (no tenant id, not in the directory, bundle unreadable, a pack missing from
  the catalog): 7 years (`source` = `fallback`). Early deletion can't be undone; keeping longer
  can. A tenant with no active bundle gets the packs' default.

A record carries its own `retain_until` (written when the check ran). The job deletes a record
only when it is older than the tenant's cutoff **and** past its own `retain_until`. So shortening
a tenant's term never reaches back to records written under a longer one, and lengthening it
protects the older ones too. Both comparisons are strict: a record exactly at the cutoff is kept;
one second older goes.

## The daily job

`RetentionJob(store, resolver, clock=...).run_once()`; the clock is injected and read once per
run. Per tenant that has records: resolve the term, `cutoff = now - term`, delete in batches of
`batch_size` (default 1000, at most 100,000), at most `max_batches_per_tenant` (default 1000)
per run; `more_to_do` marks a tenant the next run must continue. A failing tenant is listed in
`RunReport.failed` and doesn't stop the others. Scheduling is the caller's (a daily timer in the
platform's scheduler or a cron calling `run_once`); the job is safe on any number of replicas.

**Concurrency and idempotency.** The delete takes rows with `FOR UPDATE SKIP LOCKED`, so two
runs never delete or count the same row; a run that finds the rest locked stops early and the
other finishes them. A repeat run finds nothing and deletes nothing. (The in-memory store does a
batch as one step with no await, which is the same guarantee on one event loop.)

## Receipts (class A)

Every batch appends a row to `retention_receipts` in the same transaction as its delete, so there
is never a deletion without a receipt: `run_id`, `at`, `tenant_id`, `retention_class` (`B`),
`cutoff`, `deleted_count`, `batch`, plus `retention_days` and `source` (how the term was
reached). Never content. A run's receipt for a tenant is the rows sharing its `run_id`
(sum of `deleted_count`). Batch 1 always writes a receipt, even with count 0, so "the run looked
and found nothing" is on record; later batches write only if they deleted something.

**Several replicas or runs.** Each run has its own `run_id` and writes its own batch-1 receipt, so
N replicas on the same day leave N receipts per tenant, most of them zero-count ("I looked and
found nothing"), and a run that loses every row to another run's `SKIP LOCKED` records 0 for rows
the other run deleted. A tenant's daily total is therefore the **sum of `deleted_count` across
all `run_id`s** that day, never one run's figure. The zero-count receipts are kept on purpose:
skipping them would need the function to know whether another run already looked, which would
make "this run looked" unprovable. The table
is append-only (a trigger refuses UPDATE, DELETE, TRUNCATE) and the job never deletes receipts.

## The deletion path and its privileges

`decision_records` is insert-only for every ordinary role. The one way to delete is the
`SECURITY DEFINER` function `retention_delete_class_b(...)` (migration 026), which runs as the
table owner:

| Role | decision_records | retention_receipts | `retention_delete_class_b` |
| --- | --- | --- | --- |
| Service (`apply_app_role_grants`, 029) | SELECT, INSERT | none | no EXECUTE |
| Retention job (`apply_retention_role_grants`, 030) | SELECT on `tenant_id` only | SELECT | EXECUTE |
| Owner (migrations) | all, but a trigger refuses UPDATE and TRUNCATE on records, and any change to receipts | | |
| PUBLIC | none | none | EXECUTE revoked |

Why a function rather than granting DELETE to a role: the job role then has no way to delete
except through a statement that writes the receipt in the same transaction, deletes only expired
rows of one tenant, and applies its own limits. The function refuses:

* a batch outside 1..100,000;
* a `p_now` more than five minutes ahead of the database clock (the injected clock makes the job
  testable; the database clock bounds how far ahead it may claim to be);
* a `retention_days` outside 90..36,500 (90 is R3's shortest term), or a cutoff that is not
  exactly `p_now - retention_days` (so a receipt can't say "395 days" for a 90-day cutoff);
* a `source` that is not 1..16 lowercase letters (the table's CHECK then limits it to the four
  terms). `source` is the one receipt field that stays a caller fact: the function can't know how
  the job reached the term.

The receipt's `at` is the database's `clock_timestamp()`, not a caller value, and a record is
deleted only when its `retain_until` is before `least(p_now, database clock)`, so the five-minute
allowance can't take a row early. The Python stores refuse the same calls (`RetentionError`); the
in-memory store has no database clock and stamps `at` with `now`.

**`search_path` and temporary tables.** A `SECURITY DEFINER` function must not resolve a
relation through the caller's temporary schema, which PostgreSQL searches first unless `pg_temp`
is listed: a role with TEMP could otherwise create a temp `retention_receipts` and have the
receipt written there, a deletion with no durable receipt. So the function is created with
`SET search_path = pg_catalog, <schema>, pg_temp` (`pg_temp` explicitly last) and every table it
touches is schema-qualified. `<schema>` is the schema the migration created the tables in
(`current_schema()`; `public` in a normal deployment), filled in by a `DO` block, so run 026 with
the same `search_path` as the rest of the migrations. Tests pin `proconfig` and replay the
reviewer's probe (a temp `retention_receipts` and a temp `decision_records` made by the retention
role change nothing).

**TEMP is not revoked from the retention role.** Every role gets TEMP on the database through
PUBLIC, so `REVOKE TEMP ... FROM <role>` would change nothing, and revoking it from PUBLIC would
affect every other role and needs database ownership, which the grants script (run by the table
owner) may not have. The pinned `search_path` is the defence, and it doesn't depend on TEMP. An
operator who wants it anyway can run `REVOKE TEMPORARY ON DATABASE <db> FROM PUBLIC` and grant it
back to the roles that need it; the job itself creates no temp tables.

The service holds only `DecisionRecordStore` (append, count); the deletion port is a separate
object (`store.retention` in memory, `PostgresRetentionStore` on the retention role's pool).

## Class A

R3 keeps class A for seven years, immutable, and offboarding keeps it for its full term. No class
A table has a delete path and none holds a row that old, so **the job deletes no class A row**.
Class A appears here as the receipts, which are themselves class A and never deleted. If legal
sign-off (R3, before M5 GA) wants class A deleted after seven years, it needs its own per-table
deletion functions and a new story; nothing here prepares or blocks that.

## Known limits

* **Whatever writes `decision_records` (M4-07) must set `retain_until` from the tenant's
  effective, clamped term** (what `CatalogRetentionResolver` returns), never from a raw bundle
  `audit.records_days`. The deletion function's protection from early deletion rests on each
  record's own `retain_until`, and nothing in the database checks it. M4-07 should pin this with a
  test.
* **No writer yet.** `RecordingAuditSink` still takes a sync `write` callable, and nothing in
  the engine factory wires `PostgresDecisionRecords.append` behind a bounded queue. The store,
  schema and job are ready; the write-behind sink is a follow-up. Until then decision records
  live where the deployment's own sink puts them.
* **No row-level security on `decision_records`**, like `delivery_outbox`: the job reads across
  tenants and no tenant-facing read route exists. Add a policy before one does.
* **The resolver needs a bundle loader** that can read any tenant's active bundle (an
  operator-scope store); this module never mints a tenant scope.
* **Offboarding** (delete B, C, D, E within 30 days) and **class C/D/E deletion** are other
  stories. The job covers only class B.
* The finance and healthcare figures still need legal sign-off before M5 GA (R3).
* `SELECT DISTINCT tenant_id` to list tenants scans the `(tenant_id, ts, id)` index; fine daily,
  worth a loose index scan if the table gets very large.
