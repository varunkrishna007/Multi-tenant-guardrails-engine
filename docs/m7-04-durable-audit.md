# M7-04 · Durable audit for regulated tenants (as built)

The decision-record writer ([m4-07-audit-query.md](m4-07-audit-query.md)) keeps a bounded queue
between the check and the database. A full queue used to drop the record and count it, for every
tenant. For a **regulated tenant** (any tier but `standard`, the catalog's `is_regulated_tier`)
that is no longer so: the record is kept.

| Tenant | Queue full | What happens to the record |
|---|---|---|
| standard (or no verified tenant) | yes | dropped and counted (`dropped`, the `audit_records_dropped` alert), as before |
| regulated | no | queued as before |
| regulated | yes | the check waits up to `regulated_wait_s` (0.25 s) for room; then the record is **spilled** to disk |

The wait is the only effect on the check. The verdict is final before the audit is attempted and
is returned unchanged, whatever the writer does. A check that is cancelled while it waits still
keeps its record.

## The spill file

* **Where.** `decision_spill.file` if set, else `decision_records.spill.jsonl` in the directory of
  `class_a_audit.file`. **In production and staging the engine refuses to start** when decision
  records go to a store and there is neither: the rule follows the configuration, not today's
  tenants (a tier can be raised at runtime). In `test` with neither, a regulated tenant's record
  waits the bound and, if there is still no room, is dropped and counted like any other.
* **Safety.** It is opened with the class A file's checks (no symbolic link followed at any
  component, a directory only the engine's user (or root) can write, `/tmp` refused, a regular
  file of that user with mode 0600 and one link); one `write()` per line under an exclusive
  `flock`, then `fsync`. The engine refuses to start if the spill file fails those checks. The
  class A event file itself is never read back, shortened or removed; the spill uses a subclass
  of its sink (`SpillFileSink`) that can.
* **Cap.** `decision_spill.max_bytes` (default 256 MiB), checked on the file's own size under its lock at each append, so several processes sharing the directory (and one that spills before its first read) can't take it past the cap together. An alert (`audit_spill_near_cap`, a
  warning, at most one per alert interval) is raised at 80% of it. Past the cap a regulated
  record is **dropped and counted** (`dropped`, `spill_full`, and the `audit_records_dropped`
  alert), like a standard tenant's, so a long outage can't fill the filesystem the class A file
  may share.
* **Lines.** `{"k":"spill","id","requested_days","packs","record"}` is a record waiting for the
  store; `{"k":"done","ids"}` says those are in the store (or were skipped, below). The record is
  the audit record (hashes, probabilities, the verdict; no content). A line that does not parse is
  skipped, logged and counted; a short write is ended as its own line and never truncated.
* **Retention.** The deletion time is stamped when the record reaches the store, from the term in
  force then, as for every record. A spilled record whose term has **already passed** is not
  written (it would only be deleted again) and one whose **tenant has ended** (offboarded) is not
  written; both are marked done and counted (`expired_skipped`, `ended_skipped`). When every line
  is done the file is **deleted** (under the lock, only if nothing was appended since it was read;
  a writer that had the old file open notices and writes to a new one). Under sustained pressure,
  when the done lines are over half of the file it is **rewritten** with only the pending lines
  (a temporary file, flushed, renamed over it, under the same lock), so a record never outlives its
  term in it.
* **Threads.** Every spill file operation (open, lock, `fsync`, read, rewrite) runs on one of two
  dedicated single threads owned by the writer (`decision-spill-append` for the checks' appends,
  `decision-spill-replay` for the background replay), never on the event loop and never in the
  loop's shared pool (redaction uses it). Appends from many regulated checks queue behind each
  other on their thread. A check cancelled while it waits hands its spill to the append thread and
  returns; `aclose` waits for it.

## Replay

The writer reads the file **once**, keeps the pending records in memory (records it spills itself
are added as they are written), and writes batches of them, one tenant per transaction, when the
queue is at most half full, and at startup (records spilled by an earlier process). Each batch is
marked done after it is written. Reading the file again happens only to take up what another
process spilled and to delete the file when nothing is pending. A batch the store refuses is
retried record by record with the writer's backoff; a record refused `max_attempts` times is given
up on (marked done, counted as dropped, logged). A 10,000-record backlog replays in about two
seconds (a test bounds it at twelve).

**No record is written twice.** Each spilled record has an id minted when it is spilled. Replay
hands the store the record and the id (`append_keyed`), and the store keeps one row per
(tenant, id): Postgres has a unique partial index on `decision_records (tenant_id, record_key)`
(migration **054**, `ON CONFLICT DO NOTHING`; the rule-index rows of a skipped record are not
added either), and the in-memory store the same. So a crash after the insert and before the
`done` mark replays the record into the same row. Records that were never spilled have no key and
never conflict.

## At shutdown

Records still queued when `aclose` runs out of time are spilled if the tenant is regulated
(the tier is looked up then, with a 1 s bound; a lookup that fails counts as regulated), and
dropped and counted otherwise.

## Which tenant is regulated

`audit.term.directory_regulated(directory)` reads the tenant's directory entry and applies
`is_regulated_tier`. It is asked only when the queue is full, and remembered for 60 s. **A
directory that cannot be read counts as regulated**: keeping a record costs one file line;
dropping it costs the record. A tenant that is not in the directory is not regulated.

## Counters

`spilled` (records written to the file), `replayed` (spilled records written to the store),
`dropped` (unchanged meaning, plus a regulated record whose spill failed or was refused for the
cap, or that was given up on at replay), `spill_full`, `expired_skipped`, `ended_skipped`. A spill
that fails raises the same `audit_records_dropped` alert.

## The check's epilogue

The Guard Service routes an escalation and stores the content **before** it waits for the audit,
so a caller cancelled during the wait has lost neither (the audit record is kept either way).

## Limits

* A check waits only when the queue is full: for the wait bound (`regulated_wait_s`, 0.25 s), and
  if it then spills, for one append and `fsync` of the file behind the other appends on the append
  thread. A database outage does not slow a regulated tenant's checks by more than that when the
  disk is healthy; a slow disk slows them by its `fsync`.
* The file is capped, and what the cap refuses is dropped. A cap of 256 MiB holds about 190,000
  records (1.35 KB each).
* Several engine processes may share the directory. They write one file under the lock and may
  all replay it; the store's key makes that safe. A process sees what another spilled only when it
  next reads the file (at its next start, and before it deletes the file).
* A crash with records still in the in-memory queue loses them (the queue is not the spill).
  Only a full queue or a clean shutdown spills.
