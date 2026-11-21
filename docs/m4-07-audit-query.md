# M4-07: the audit query, and the writer behind it

`GET /v1/tenants/{tid}/guardrails/decisions` (role `auditor`, nothing else) reads the decision
records of one tenant. Until M4-07 nothing wrote them: M4-09 built the table
(`decision_records`, R3 class B) and the job that deletes from it, and no check ever added a row.

## Writing: behind the check

`audit/writer.py`, `DecisionRecordWriter`, is the engine's audit sink (`build_engine` makes it
whenever a decision store exists; with the Postgres store that is the default, with the memory
store a test passes `decision_records=InMemoryDecisionRecords()`).

* `record(verdict)` runs on the check path. It builds the audit record
  (`AuditRecord.from_verdict`, the existing fields, **no content**) and appends it to a bounded
  queue (`capacity=10,000`). It never waits for the database and never raises.
* A background task writes batches (up to 200, every 0.5 s or when a batch is ready), one tenant
  per transaction. A group the database refuses goes back to the front of the queue and is tried
  again after a pause that doubles up to 30 s, **one record at a time** from then on, so a record
  the database refuses costs only itself (dropped after five attempts of its own). At shutdown a
  write in flight is allowed to finish (cancelling it could leave a group written and written
  again); only a write that outlives half the shutdown bound is cancelled, and its records are
  counted as lost.
* **A full queue drops the record and counts it** (`writer.dropped`; also records refused five
  times and records still queued when shutdown runs out of its bound). Given `alerts`, the
  writer's own task raises `audit_records_dropped` (a warning, at most one a minute,
  `monitoring.dropped.DroppedAuditRecordsWatch`) when the count grows. That alert goes through the
  durable sink when the deployment passes one, off the check path.
* Shutdown writes what is queued (bounded) after the Guard Service has finished its checks, and
  counts the rest.

### `retain_until` (R3)

The writer never writes the figure the verdict carried. `audit/term.py`, `EffectiveTerm`, takes
the term the check was decided under (`Verdict.retention_days`) and moves it into the R3 bounds
in force for the tenant now, with the same `combined_retention` / `records_days_in_bounds` the
compiler and the retention engine use: **up** to the minimum, **down** to the maximum. The bounds
are those of the platform's standard profile and the packs the tenant's tier and contract require
(at the catalog's latest version); the packs a bundle extends were checked against its
`records_days` at publish, and a pack version never changes. The packs are
also those the **bundle extends** (carried on the verdict as `retention_packs`, pinned versions).
When the packs' bounds conflict (one's minimum above another's maximum) the minimum wins: R3's
longest retention. The tenant's tier and contract packs are read from the Guard Service's own
directory entry (`TenantProfile.attributes`); a `TenantRecord` works too. (the first version read `.tier` off the profile and fell back to 7 years for every record. The
engine test now asserts the stored term equals the verdict's.) A tenant not in the directory, a
pack the catalog lacks, a directory failure, or a verdict with no term gets the longest term, 7
years (the retention engine's rule: keeping longer can be undone, deleting early can't). **That
fallback is never silent**: it is warned about by tenant and counted by (tenant, cause)
(`EffectiveTerm.fallback_counts()`), so a fleet that quietly keeps everything for 7 years is
noticed. M4-09's `CatalogRetentionResolver` reads a `TenantRecord` from the directory *store*
and is not built by the factory, so it does not have this trap.
`retain_until` is then `ts + term`; the retention job deletes a row only when it is past its
tenant's cutoff **and** its own `retain_until`.

## Storage (migrations 032 and 033)

* `decision_records` gets forced row-level security: the service role reads and writes only the
  tenant its transaction's `app.tenant_id` names; a record with no tenant can be inserted and is
  read by no one but the owner. The owner (whose `retention_delete_class_b` runs `SECURITY
  DEFINER`) gets policies for what that function does (select, lock with `FOR UPDATE` and can't
  change, delete). The retention role gets a SELECT policy (033) so its column grant on
  `tenant_id` still lists whom to sweep. Operators read any tenant's rows (014).
* Two columns copy what the record says: `decision`, and `fired_rules` (the keys of the rules
  that escalated or blocked, enforce or shadow).
* `decision_record_rules (record_id, tenant_id, rule, ts)`, one row per fired rule, written in the
  same statement as the record, so "records where rule X fired" is an index range scan on
  `(tenant_id, rule, ts DESC, record_id DESC)`. Its rows go with their record (the retention
  function's delete cascades). **Why a table and not a GIN index on the array:** under row-level
  security the planner may not use an index for an operator that isn't *leakproof* ahead of the
  policy, and `@>` is not. The first design (GIN on `fired_rules`) read every row of the tenant
  for a rule that matched nothing: 225 ms at 150,000 rows, linear from there. Equality on text is
  leakproof; the table's index is used.
* The app role gets SELECT and INSERT on both tables (029), nothing else.

## Reading

Parameters: `from`, `to` (ISO 8601 with a zone; default the last 24 hours; at most 31 days
apart; `to` exclusive), `rule` (a rule key that **fired**), `decision`
(`allow|escalate|block|forbidden`), `guard_point`, `limit` (1 to 200, default 50), `cursor`.
Anything else is a 400 naming the field.

Newest first, keyset pagination on `(ts, id)`: `next_cursor` is returned when a page is full and
is opaque (it only picks a position inside the caller's own tenant, so it isn't signed). Every
query also names `tenant_id = $1`, because an operator's policy would otherwise show all
tenants.

### What is never in the response

The stored record is the engine's whole audit record. The response is a projection:

* a **floor** rule appears only in `fired`, as key, action and mode (what production shows); its
  probability and thresholds are never returned, and floor rules that did not fire are not
  listed at all;
* a **floor-derived** tenant rule (`floor_derived_keys`: a fork of a floor rule, or one that
  copies a floor question) shows key, action and mode, no `p`, no thresholds;
* a record whose bundle version can't be read now shows no rule's numbers (fail closed; the next
  page tries again);
* `answers`, `floor_fail_mode` and the rest of the record are not part of the response;
* `detail` is shown as the engine wrote it, except for an `internal_error`: a lost floor rule's
  text carries the catalog's thresholds and `floor_fail_mode`, so it is replaced by a fixed
  sentence.

## The p95 benchmark

`tests/store/test_m4_07_decision_records_postgres.py::test_the_audit_query_p95_...` (marked
`slow`: `pytest -m slow`, needs Postgres; `M407_BENCH_ROWS` sets the volume). It seeds one tenant
over 30 days (default **300,000 records, 10,000 a day**: 90% allow, 8% block, 2% escalate, five
guard points, three rules and a fired rule where it blocked or escalated, about 1 KB of record
text) and a quarter as many for ten other tenants, in the same table and indexes, as the
non-superuser owner and the service role under forced row-level security. Nine query kinds, 207
queries through `DecisionsService` (records read back and presented): latest, by decision, by
guard point, by rule (common, rare, matching nothing), rule with decision, a week window with
three filters, and an 11th page of 200 behind a cursor.

Measured here (300,000 + 75,000 records, a 900 MB tmpfs Postgres 16): **overall p95 11 ms**; the
slowest kind's p95 is 20 ms. The test asserts p95 ≤ 2 s.

**What this does and does not show.** 300,000 is what the local database holds. Every query is an
ordered index range scan with a `LIMIT`, so its cost is the page and what the non-indexed filters
skip, not the tenant's total; but the figure at 3 to 10 million records (a tenant at the
platform's whole token rate) was not measured and should be before relying on it.

## Not here

The query is not a metrics endpoint (M4-06) and has no free-text search. The block-rate detector's
durable baseline (it reads from the audit store) is a separate item. A deployment wires
`DroppedAuditRecordsWatch` to its alert sink only if it does not pass `alerts` to `build_engine`
(the writer already does when it has them).
