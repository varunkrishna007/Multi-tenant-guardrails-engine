# M5-03: content storage and escalation retention (R3 classes C and D)

Branch `m5-03-content-storage`. Migrations 047 to 050. Offline: no live call.

## What was missing

R3 class C is "the post-redaction text of the evaluated content", off by default, opt-in for 30
days by default and 90 at most (30 at most, and only with a BAA flag, for a healthcare tenant).
Before this story the compiler already refused a bundle whose `audit.content_days` was over the cap
for its packs, and a healthcare bundle without the BAA flag (AC-C1.13, with the longest retention
and the shortest cap across packs), and class D (M4-05) was built. But **`store_content: full`
stored nothing for an ordinary check**, and `content_days` was compiled and never applied to
anything: the only content the engine kept was inside escalation items. M5-07 had been written on
that assumption (it counted class C under the escalation items).

## What it does now

* **Off by default.** A bundle with no `audit` section, or `store_content: hash_only`, stores
  nothing: no row, no queue entry, no counter moves (tested).
* **On** (`audit.store_content: full`): after the audit record, the Guard Service hands the
  **post-redaction text the model saw** (`run.held_content`, the same text class D holds) to a
  write-behind writer (`content/writer.py`). **Only that text**: not the raw content, not the
  conversation context, not tool arguments. A check that never reached redaction (a deterministic
  block on the raw content, an oversized request, a closed engine) has no post-redaction text and
  stores nothing: the raw text is never stored in its place. The row carries `content_sha256`,
  the hash of the **pre-redaction** content (PF-14), so it can be matched to its decision record.
  Content over 100,000 characters is cut and flagged `truncated`.
* **The AC-G2 test** (`tests/guard/test_m5_03_stored_content.py`) puts an email, a phone number, a
  card, an SSN, a NINO and an IBAN in the content and in every context item, and shows that none of
  the raw values is in what is stored, that the placeholders are, that what is stored is a substring
  of what the fake model received, that the hash is of the raw content, and that neither the verdict
  nor the audit record carries the text.
* **The term.** The bundle's `audit.content_days` (or the packs' default), **clamped again when it
  is written** to the caps then in force (`content/term.py`): the **shortest** cap among the
  tenant's packs (the bundle's packs, and the packs its tier and contract require), at most 90
  whatever a pack says. The compiler's check and the writer's check are the same table (tested for
  eleven accepted and seven refused cases). `retain_until = ts + days`.
* **Not stored on purpose** (counted per reason in `writer.skipped`, never a drop, never an alert):
  a tenant whose packs need a BAA and which has no BAA flag now (a published bundle can be behind),
  a tenant not in the directory, a pack the catalog lacks, a failing directory. Unlike a decision
  record, where the safe error is to keep it longer, stored content is the privacy risk, so every
  doubt is "do not store".
* **The writer never blocks the check path** (M4-07's shape): `submit` is a bounded-queue put,
  no I/O, never raises; a full queue drops and counts; a failing database requeues with a
  doubling pause and splits a failed group so one refused row costs only itself; `aclose` writes
  what it can and counts the rest. Drops raise `stored_content_dropped` (a warning, at most one a
  minute, from the writer's own task).

## Where it lives

* **`stored_content`** (047): `seq, tenant_id, request_id, guard_point, ts, retain_until, content,
  truncated, content_sha256, bundle_version`. **Forced row-level security** on `app.tenant_id`.
  **Insert-only**: the service's role has SELECT and INSERT only (048), a trigger refuses UPDATE
  and TRUNCATE for everyone, and the only deletions are the class C function and the terminated
  tenant's offboarding function. A CHECK says `retain_until > ts` and `retain_until <= ts + 90
  days`: **no row can be written to live longer than 90 days**, whatever wrote it.
* **`retention_delete_class_c`** (047): the same hardening as `retention_delete_class_b` and
  `_class_d`: `SECURITY DEFINER`, `search_path = pg_catalog, <schema>, pg_temp`, every table
  schema-qualified, the transaction-local tenant setting put back, `EXECUTE` revoked from PUBLIC
  and granted to the retention role alone (049). **The database decides what is due:** a row whose
  own `retain_until` is before the cutoff, or, as a ceiling, one stored more than 90 days before it.
  The cutoff is the caller's clock clamped to the database's (a clock more than five minutes ahead
  is refused). Strict (a row exactly at the cutoff stays). Bounded batches, `FOR UPDATE SKIP
  LOCKED`, a class A receipt (`retention_receipts`, class `C`, source `row`, no content) **in the
  same statement**. The retention role can read **only** `stored_content.tenant_id` (a column
  grant through its own policy) to list tenants, never content.
* **The job** (`content/retention.py`, `ClassCJob`): the shape of M4-09's. It needs no tenant term
  resolver: each row carries its own deletion time, so shortening a tenant's `content_days` never
  reaches back to older rows, and lengthening it never keeps a row past its own time.
* **Offboarding** (M5-07): `stored_content` is class C in `OFFBOARD_TABLES`, the offboarding
  function deletes and counts it (migration 043 is edited in place: its function bodies list the
  tables), the completion check includes it, and the in-memory store is a `TenantDataHolder`.
  The catalog-coverage test ("every table with a tenant column is classified") passes with it.
* **The read** (`admin/content.py`): `GET /v1/tenants/{tid}/guardrails/decisions/{request_id}/
  content`, **auditor**, with an optional `guard_point`. The tenant comes from the authorizer's
  scope and the reader filters on it again; a row past its own time is not returned even before the
  job deletes it. Nothing for another tenant's request id, nothing never stored, nothing expired:
  all the same `404 content_not_found`. The content is returned and never logged.
* **Every read leaves a class A event** (decided): `stored_content_audit` (047, append-only, forced
  RLS, kept at offboarding): the actor (`issuer#subject`), the tenant, the request id, the guard
  point asked for, how many rows came back, whether it crossed tenants and whether the actor is a
  platform operator. **Never the content.** It is written **before** the content is returned; a
  read that finds nothing leaves one too (0 rows: someone asked); a read that can't be recorded
  returns nothing (503 `unavailable`). A refused or malformed request is not a read.

## Class D (escalation items)

Unchanged from M4-05: an item's content is **class D** (held for a reviewer), not class C. Until
resolved plus 30 days; 30 days in all for healthcare (an unresolved item expires and the expiry is
counted). Two things are worth saying: an item on a `queue` target holds content whatever the
tenant's `store_content` (the reviewer needs it), and an item on a `webhook` target holds it only
under `full`. Class C's `content_days` does **not** shorten an item's term; the item's own
retention mode does. A tenant that wants no content kept past 30 days uses `hash_only` and the
queue's 30-day tail, or accepts class D's term.

## Not done, and known limits

* **Turning content storage off does not delete what is already stored** (decided OK): it ages out
  at its own `retain_until` (at most 90 days) and is still readable by an auditor until then,
  every read leaving its event. Nothing new is stored from the next check that sees the new
  version. Offboarding deletes it at once.
* **The golden label of a resolved escalation outlives class C** (documented in M4-05): R3 allows
  it ("the content goes with it only if class C is on").
* **Not stored:** the conversation context, tool arguments and the model's output are not kept;
  class C is the evaluated content only.
* **No content store without a sink:** an engine built with a store it was handed and no
  `stored_content` stores nothing (the in-memory and Postgres stores get one by default).
* **Migrations are applied in full.** `apply_schema` runs every file of `MIGRATIONS` on each start
  (all are plain, re-runnable SQL: `CREATE ... IF NOT EXISTS`, `CREATE OR REPLACE`), under an
  advisory lock; there is no once-per-file tool. So editing 043 in place takes effect
  wherever the schema is applied; a deployment that applied files one time only would need the
  edit carried as a new `CREATE OR REPLACE` file, and that was judged unnecessary while
  nothing is deployed. Migration 043's header says the same.
* Migration numbers: 047 table and function, 048 service grants, 049 retention grants, 050
  operator policy (one more than the three first agreed: the operator policy has its own variable).
