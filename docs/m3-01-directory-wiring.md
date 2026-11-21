# M3-01 wiring: the cross-tenant identifier scan reads the tenant directory

Branch `m3-01-directory-wiring`. Closes the follow-ups of the M3-01 backlog entry and wires the scan to the real directory.

## What a tenant's identifiers are, and who sets them

A tenant's **registered identifier patterns** (RE2, at most 20) are matched against every
**other** tenant's `tool_result` and `output`; a match is a deterministic floor `block`. They are
platform data: a field of the directory record (`TenantRecord.identifier_patterns`, column
`tenants.identifier_patterns`, migration `019`). Only a platform operator sets them:

```
TenantProvisioner.create(..., identifier_patterns=[...])
TenantProvisioner.set_identifier_patterns(actor, tenant_id, expected_version, patterns)
TenantProvisioner.update(..., identifier_patterns=[...])
```

All three run `validate_tenant_identifier_patterns` and refuse with
`InvalidTenantRecord("identifier pattern refused: <reason>")` (a reason code, never the pattern),
write a class A audit event with the before and after lists, and publish `tenant.changed`. The
review is the operator's, with the validator as the automated line.

## The validator, tightened

| Rule | Constant | Example refused |
|---|---|---|
| at least 4 **required** digits or separators beyond the literal prefix | `MIN_TAIL_MARKERS` | `2025-`, `(?i)page [0-9]`, `ORD-[a-z]{6}`, `ORD-[0-9]{3}` |
| the repeats of one pattern add up to at most 128 | `MAX_REPEAT_WEIGHT` | `ORD-` + 20 × `[0-9a-z]{1,64}-` |
| matches nothing in the ordinary-forms haystack | generated | `mailto:`, `tel: `, `1-800-`, `(?i)iso 9001`, `(?i)invoice #` |

The haystack now holds years 1990–2099 with `-` and `/`, dates, about 50 common nouns followed by
1–99 (also as `#N`, `-N`, `: N`), `#1234`, and the stock contact-detail prefixes. A class like
`[A-Z0-9]` doesn't count towards the four (a match may hold no digit); digits inside the literal
prefix don't either. `ORD-[0-9]{4}`, `ACME-STORE-[0-9]{4}`, `INV-[0-9]{4}-[0-9]{4}` pass.
A fully literal identifier (`ACME-STORE-0042`) is refused: register the shape.

## The scan's source (`directory.DirectoryIdentifiers`)

`CachedTenantDirectory.other_tenant_identifiers()` is the source; `build_engine` uses it unless
`other_tenants=` is passed (`_identifier_source`). An engine over the in-memory directory still
scans for nothing.

* It reports **every** tenant (any status) with its id pattern and its registered patterns.
* The directory is read at most every 5 s and at once after `invalidate()`, which
  `CachedTenantDirectory.on_changed` calls (the engine's `on_tenant_changed` calls it). Concurrent
  checks share one read. The version is a digest of the content: a read that finds nothing new
  doesn't make the scanner rebuild.
* A tenant's registered list that fails `validate_tenant_identifier_patterns` **on read** (a row
  written some other way) is left out (its id pattern stays), with a fixed-word warning and
  `on_rejected`; one careless pattern can't block every other tenant.
* If the directory can't be read, the last snapshot is served for up to 60 s; then `version()`
  raises and the check fails closed (`internal_error`).

## The scanner serves the previous set while it rebuilds

The first build is waited for. After that a version change starts a background rebuild and the
check goes on with the previous set; the new set swaps in when built. If the rebuild hasn't
landed `MAX_STALE_S` (30 s, `GuardConfig.identifier_max_stale_s`; 0 = wait, as before) after the
scanner first saw the new version, the next check waits for it and fails closed if it can't be
built. A failing background rebuild is logged and retried at most once a second.
`CrossTenantScanner.wait_for_rebuild()` is for tests and shutdown.

**Staleness, stated plainly:** a newly registered identifier is scanned for within about
`refresh` (5 s, or at once on the event) plus the rebuild time. In that window another tenant's
content carrying it isn't blocked. A removed or suspended tenant's identifiers keep blocking for
the same time.

## Also in this branch

A failed `raise_minimum` restores `max(before, stored minimum)`, and raises
on one replica run one at a time.

## Fixes: identifier scan wiring

* **(major): no silent no-scan.** In `production` and `staging`, `build_engine` refuses to
  start (`SettingsError`, "other_tenants: ...") when the identifier source resolves to nothing
  (an in-memory or custom directory with no `other_tenant_identifiers()`, or `tenants=` omitted)
  and `other_tenants` wasn't passed. The one way to run without the scan is to pass
  `other_tenants=NoOtherTenantIdentifiers()`, which logs a warning at startup; the warning follows the *resolved* source, so a directory whose own source is `NoOtherTenantIdentifiers` warns too (a passed `InMemoryOtherTenantIdentifiers` holding nothing yet doesn't: it is a working source). `test` keeps
  scanning for nothing without a source. (There is no `development` environment: `production`,
  `staging`, `test`.) The engine tests' `directory()` fixture is a `FixtureDirectory` that makes
  that opt-out.
* **The ordinary-forms haystack now has common words (the whole word list, the
  nouns, "since", "copyright", "invoice", ...) followed by 4 to 6 digits in four shapes
  (`word 1234`, `word #1234`, `word: 1234`), phone shapes, dates (`YYYY-MM-DD`, `DD/MM/YYYY`, ...)
  and IPs behind `http://`. No dictionary-prefix rule. (`word-1234` is deliberately not in it:
  it would refuse `ORD-1234` because of "record-1234".)
* **The 30 s stale clock is cleared only when the newest version the source reports
  has been built (the scanner asks again after a build).
* **Patterns are validated one at a time on read; a failing one is dropped and the
  tenant's others stay. The warning names the tenant id (never the pattern). The engine points
  `DirectoryIdentifiers.on_rejected` at `GuardService.report_identifier_patterns_dropped`: log,
  usage meter and the `xtenant_patterns_dropped` alert.
* **A group weighs the **sum** of the repeats inside it (so `(?:[0-9a-z]{1,64}- x 20)`
  is 1,280, not 64); and while the source serves a snapshot because the directory can't be read
  it retries at most once a second even when a change is waiting.

## Not done

* The directory is read whole (`store.list()`); at thousands of tenants a per-tenant change feed
  would be cheaper. Every 5 s it is one query.
* No Admin API route writes identifier patterns; the provisioner is the platform's write path
  (as for the rest of the directory).
* Migration `019` is numbered after M2-09's `017` and `018`.
