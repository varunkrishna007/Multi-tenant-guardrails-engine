# M4-06: metrics and cost attribution

`GET /v1/tenants/{tid}/guardrails/metrics` (role **viewer**, the authz table's row; an auditor is
a viewer too) reports, for one tenant over a window: checks by decision, latency percentiles,
the block and escalate rate per rule, and input tokens and cost per guard point.

Parameters: `from`, `to` (ISO 8601 with a zone; default the last 24 hours; at most 31 days apart;
`to` exclusive), `guard_point` (one only). Anything else is a 400 naming the field.

## Where the figures come from

| Figure | Source |
|---|---|
| checks, by decision and guard point; latency; per-rule block and escalate counts | the **decision records** (M4-07: `decision_records`, and `decision_record_rules` for the rules) |
| input tokens and cost per guard point | the **metered usage** (M4-04: `usage_events`, kind `answered`) |
| price | one configured price, below |

Both are read by `tenant_id` under forced row-level security. `usage_events` was platform-level;
migration 038 makes it tenant-scoped: forced RLS, the outbox dispatcher writes each
event under its tenant's setting (`PostgresUsageStore.write`), an operator reads any tenant's
rows (014). Migration 038 also adds three columns to `decision_records` (`latency_ms`,
`input_tokens`, `bundle_version`) and three to `decision_record_rules` (`action`, `layer`,
`mode`), filled by the writer, so the report is group-bys over columns and reads no JSON.

## Agreement with the metered totals (within 1%)

Tokens and cost are reported **from the metered usage**: that is what billing counts. The records
carry the same figure (`input_tokens` of each check), written by another path, so each guard point
also returns `record_input_tokens`, and the report has a `reconciliation` block: the two totals,
the difference in percent, and `within_tolerance` (1%). A lost record or event shows there.

Proved by `tests/engine/test_engine_m4_06_metrics.py`: real checks through a built engine (55
checks over two guard points); the gateway meters the usage into a usage store, the writer
writes the records; per guard point `input_tokens` equals the metered total and
`record_input_tokens` is within 1% of it; the cost is tokens times the price. A second test drops a
third of the records and sees `within_tolerance: false`. `tests/store/...postgres.py` checks that
the Postgres aggregates equal the in-memory ones over the same records.

## Rules, and what is never returned

* A tenant's own rule (and a pack's) appears in `rules` with `blocked`, `escalated`,
  `block_rate`, `escalate_rate` and its `mode` (an enforce and a shadow rule are separate rows).
  Rates are the rule's blocks (or escalations) over **all checks in the window** (or at the one
  guard point), not over the checks that evaluated it.
* The **floor**, and a tenant rule that is a copy of a floor rule (`floor_derived_keys`, taken
  over every bundle version that decided a check in the window), appear only in
  `platform_rules` as **counts by key and action**: no rate.
* Nothing in the aggregates holds a probability or a threshold, so none can be returned. If a
  record **that fired a rule** has no bundle version, or a version can't be read, every rule is
  counts-only (fail closed). A check that fired nothing and has no version (a forbidden one, say)
  does not count.

## Latency

Percentiles (p50, p95, p99) are by **nearest rank**: the smallest latency at or above which the
fraction q of the checks lies (never an interpolation between two checks). With at most **50,000**
records in the window they are **exact** (`percentile_disc`: the database sorts them). Above that
they are **estimated** from log-scale buckets 2% wide, counted in one pass with a group-by and no
sort (sorting every row took 1.4 s for 300,000 records, linear from there). Both are the same
rank, so the estimate is within the bucket, about 2%, of the exact nearest-rank value for any
data, including a tail of a few slow checks among thousands of fast ones. Tests: 49 checks at
100 ms and one at 400 ms give p99 = 400 (exact, small window); a 20,000-check window with a
20-check tail reports 100 ms for p99 and, with a 600-check tail, 400 ms, each within 2%; three
distributions are within 2% of exact.

## Non-production usage

The gateway meters a draft test, a calibration run, a shadow evaluation, a red-team run and a
tool screening as `<usage class>:<guard point>` (`test:output`). Those calls have no decision
record, so they are **not** part of `guard_points`, `cost.input_tokens` or `reconciliation`
(which would show records as lost). They are in `non_production`: tokens and cost by usage
class, then by guard point, and `cost.non_production_usd` and `cost.all_usd`. A report filtered
to one `guard_point` shows no non-production block (the filter is on the exact name).

## Cost: where the price comes from

`cost_usd` is the metered `answered` input tokens times **one** price, USD per million input
tokens: `token_rate.price_per_million_input_tokens_usd` of the engine settings (the figure the
project's monthly spend cap uses, `gateway/token_rate.py`, default **0.10**; the engine settings
doc lists it). Unset (as in `test`) the default constant is used, and `cost.price_source` says
which. The decision API bills input tokens only, so there is no output price and no per-model
table. The price used is returned with every report. Events whose token count is unknown
(`unknown`) are counted in `metered_events`, not priced.

## Cost of the query

Measured on a Postgres 16 on tmpfs, one tenant with 300,000 records over 30 days and 75,000 for
other tenants (the audit benchmark's data), as the service role under row-level security:
**30 days 0.8 s median (max 1.3 s); 30 days at one guard point 0.47 s; 24 hours 30 ms.** The cost
is linear in the window's records (one scan), so a tenant of several million records a month
would need a rollup table; that was not built and was not measured. `pytest -m slow` runs it
(`M407_BENCH_ROWS` sets the volume).

## Not here

No per-tenant dashboard, no export, no alert on spend (the gateway's monthly spend cap already
alerts), no per-rule evaluation counts (rates are over checks).
