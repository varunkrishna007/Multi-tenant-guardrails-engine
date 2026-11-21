# M4-04 · Bad-publish detection and event delivery (as built)

Code: `monitoring/` (detection, dropped-events alert, runner), `delivery/` (outbox, dispatcher,
durable sinks), `delivery/adapters/` (webhook, Postgres), `gateway/gateway.py` (the drainer
thread), migrations `024_delivery_outbox.sql` and `025_delivery_grants.sql`.

## How the pieces fit

```
check ──> audit sink ──tap──> BadPublishDetector.observe()      (counts only, request path)
publish bus ──> detector.on_published()
PeriodicRunner (daemon thread) ──> detector.tick() ──alerts──┐
                                   DroppedEventsWatch.tick() ─┤  (straight to the durable sink,
                                                              │   not through the gateway queue)
gateway ──bounded queue──> drainer (ONE daemon thread) ──> DurableAlertSink / DurableUsageMeter
                                                              │ INSERT
                                                       delivery_outbox  (Postgres)
                                                              │ claim under a lease
                          OutboxDispatcher (daemon thread) ───┴──> WebhookAlertSink (HMAC-signed)
                                                                   PostgresUsageStore (usage_events)
```

Wiring is composition, not magic: pass `alerts=DurableAlertSink(outbox)` and
`meter=DurableUsageMeter(outbox)` to the engine, wrap the audit sink with
`detector.audit_sink(inner)`, subscribe `detector.on_published` to the publish bus, and start a
`PeriodicRunner([detector.tick, watch.tick])` and an `OutboxDispatcher`. Nothing starts a thread
by itself.

## The block-rate alert

* **Block rate** = every tenant-caused `block` (reasons `policy`, `deterministic`,
  `content_too_large`) over checks a policy decided (those three and `no_questions`). Only
  `model_failure` is excluded, with `policy_unavailable`, `internal_error`, `engine_closed`,
  `invalid_request`, `contract_violation`, `provider_safety` and the two `forbidden` reasons:
  they are in neither count.
* A `publish` or `promote` event starts a watch for that tenant; a `rollback` ends it; a later
  publish restarts it. The window is the 15 whole minutes after the publish, evaluated once the
  last of them has ended (so the alert comes about 15 minutes after the publish).
* **Fires** when the window's rate is **more than** 2x the baseline: exact integer comparison, so
  exactly 2x does not fire. The baseline is the same rate over the 7 days of whole hours before
  the hour of the publish.
* **Guards** (all configurable in `BlockRateConfig`): at least 100 baseline checks, 20 window
  checks and 3 window blocks. Below them the result is `NO_BASELINE` or `TOO_FEW_CHECKS` and no
  alert is raised.
* **No baseline, no alert** (a tenant new to the platform, a quiet one, or a process that has
  been up for under a day: the counters are in memory). The baseline needs at least **24 hours of
  observations** of the tenant (`min_baseline_age_s`) as well as 100 checks. The detector logs
  the result at info level and reports `NO_BASELINE`; nothing else happens. A first publish for a
  new tenant is therefore never alerted on. A baseline that exists but has zero blocks is a
  baseline: a window that passes the guards then alerts.
* The alert (`bad_publish_block_rate`, a page) carries `rollback`: the Admin API path
  `POST /v1/tenants/{tid}/guardrails/versions/{v}/rollback` for the version that was active
  before, or the versions list when the detector did not see that version (`rollback_prefix`
  turns it into a link).
* **Provider health** (`provider_health`, a page, platform-wide): `model_failure` checks over
  all checks decided or failed in the trailing 5 minutes, above 5% with at least 20 checks. Once
  per episode: it does not page again until it has been healthy for 5 minutes without a break
  (`provider_clear_s`). Separate from the bad-publish alert by design.

## Delivery

* **Durable.** The gateway's drainer calls `DurableAlertSink` / `DurableUsageMeter`; each call is
  one INSERT into `delivery_outbox`. After that the event survives a restart. The
  `OutboxDispatcher` claims due events under a lease (`FOR UPDATE SKIP LOCKED`, 120 s), delivers
  them, and marks them delivered, retries them, or dead-letters them.
* **At least once.** An event can be delivered twice (a crash between delivery and
  `mark_delivered`; a lease that expired mid-delivery). It keeps one **idempotency key** for life:
  the outbox key is unique; the webhook sends it as `X-Guardrail-Idempotency-Key`; `usage_events`
  uses it as its primary key, so a second write is a no-op.
* **Retry policy.** Wait `base_s * 2^(failures-1)`, capped at `cap_s`, shortened by up to 20%
  jitter. **Alerts** retry until they are **6 hours old** (2 s base, 300 s cap, no attempt limit). **Usage** events keep: 2 s base, 300 s cap, **8 attempts**: waits of 2, 4, 8, 16,
  32, 64, 128 s,
  about four minutes of outage tolerated. The 8th failure **dead-letters** the event (state
  `dead`, last error code kept, never retried again until `requeue_dead`). An undecodable
  payload is dead at once. The stored error is a short code (`http_503`, `timeout`, class name),
  never an exception message.
* **Webhook sink** (`WebhookAlertSink`): JSON body, `X-Guardrail-Signature: v1=HMAC-SHA256(secret,
  "<timestamp>.<body>")`, `X-Guardrail-Timestamp`, a timeout (5 s default, per connect and read),
  https required (http only to loopback), no credentials in the URL, no redirects, proxies
  ignored, secret of at least 16 bytes. The URL and secret never appear in logs, errors or
  `repr`. No paging vendor is integrated; point the URL at whatever receives pages.
* **Usage store** (`PostgresUsageStore`): rows in `usage_events`; unknown tokens stay NULL. It
  also works as a direct (non-durable) `UsageMeter`.
* **Postgres from threads.** asyncpg is the only driver and is async, so `PgBridge` runs a
  private event loop in a daemon thread; callers block for at most `timeout_s` (10 s).
* **Dropped events.** `DroppedEventsWatch` compares `gateway.dropped_events` with what it last
  reported and raises `events_dropped` (a warning, `count` = growth), at most once a minute. It
  must be given the durable sink, not the gateway's own `alerts`, or the overflow would swallow
  the alert about it.
* **Process exit.** The gateway drainer is one daemon thread (waits 2 s for more events, then
  exits; `aclose` stops it at once). `aclose` waits `close_timeout_s`, drops what is left, counts
  it. The dispatcher, runner and bridge threads are daemons too. A subprocess test shows a sink
  that never returns costs nothing past the flush window.

## Known limits

* **Baseline lives in memory.** A restart or a new replica starts with no baseline (no alert
  until 24 hours and `min_baseline_checks` have been seen again). Each replica sees only its share of the
  traffic; the rate is a ratio, so that is fine, but two replicas alert separately. Reading the
  baseline from the audit store (M4-07) would fix both.
* **Hour and minute granularity.** The baseline is whole hours; the window is whole minutes. A
  previous publish inside the 7 days is part of the baseline (a repeated bad publish hides
  itself a little).
* **Events in the gateway's in-memory queue at a crash are lost** (as is one whose outbox INSERT
  fails: logged, and counted on the `DropCounter`). Durability starts at the INSERT.
* **Only core usage meters are durable**: answered, unknown, unanswered, provider-safety,
  model-skipped, patterns-dropped. The high-volume counters (timing, token-rate, quota) are not
  offered by the durable meter, so a gateway given it does not call them.
* **Dead letters** are logged at error level, counted (`dispatcher.stats.dead`, `dead_alerts`,
  `dead_usage`; the outbox's `stats()`) and alerted on by `DeadLetteredEventsWatch`.
  If the webhook is the thing that is down, give the watch a sink that does not depend on it.
* **A dispatcher stuck in a sink** stalls delivery (daemon, so not process exit) until the sink
  returns or its own timeout fires; its leased events return after the lease for another
  replica. Webhook timeouts are per connect and read, not total.
* **Clocks.** Leases and backoff use the process's clock; replicas with skewed clocks can claim
  early or late. At-least-once and the idempotency key make that safe.
* **The outbox table grows** until delivered rows are purged (hourly, after 24 h); dead rows stay
  until an operator requeues or deletes them.
* Not yet wired into `engine/factory.py`: the deployment composes the pieces above.

## Delivery outbox: minor fixes

Migrations were renumbered at the merge with M4-01: `024_delivery_outbox.sql` and
`025_delivery_grants.sql` (023 is reserved for another branch; the runner applies the
`MIGRATIONS` tuple in order and does not require contiguous numbers).

* **The lease is the claim token.** `OutboxEntry` carries `lease` (the `locked_until` it
  was claimed under) and `created_at`. `mark_delivered`, `mark_failed`, `mark_dead` and the new
  `renew` update `WHERE id AND state = 'pending' AND locked_until = <lease>` (Postgres and in
  memory) and return whether they applied. A late worker whose event was claimed and finished by
  another changes nothing (`stats.lease_lost`), so it can no longer turn a `delivered` event
  `dead` or pull a retry forward. A batch cannot outrun its lease: before each delivery the
  dispatcher renews the lease if less than half of it is left; if the renewal finds the event
  gone, the event is skipped. Both probes are tests (in memory and on Postgres): the late timeout
  after another worker delivered, and 20 events through a 10 s sink on a 120 s lease with a
  second replica taking the tail (each event is sent once). `lease_s` must still be longer than
  one delivery.
* **Alerts keep retrying.** `ALERT_RETRY`: 2 s base, 300 s cap, dead-lettered only at
  the first failure at or after 6 hours of age (jitter only shortens waits, so 6 hours is a
  floor). Usage keeps 8 attempts. A dead letter is logged at error level, counted, and
  `DeadLetteredEventsWatch` raises `events_dead_lettered` (a warning) from the counter through
  whatever sink it is given (use one that is not the failing webhook). The watch also logs every
  growth at error level, so the loss is visible with every sink down.
* **Decision applied.** Every tenant-caused block counts in the numerator (`policy`,
  `deterministic`, `content_too_large`); only `model_failure` is excluded, and it still feeds
  `provider_health`.
* **Baseline decision.** At least 24 hours of observations of the tenant before the in-memory
  baseline can fire; before that the result is `NO_BASELINE`, logged at info level, no alert.
  **The durable baseline (from the audit store) is M4-07**; until then, every restart means a day
  without bad-publish alerts for every tenant.
* **No pruning under the global lock.** `tick` evaluates and raises under the lock,
  releases it, then prunes in chunks of 50 tenants, taking the lock once per chunk, so the check
  path waits for at most one chunk. A counter set remembers its oldest bucket, so a tenant with
  nothing to prune costs O(1).
* **Idempotency keys.** `Alert.dedupe_key`, derived from (kind, tenant, version, window start):
  `bad_publish_block_rate:<tenant>:<version>:<window start>` and
  `provider_health:-:0:<5-minute bucket>`. `DurableAlertSink` stores the alert under
  it (replicas sharing an outbox store one event) and the webhook sends it as its id and key
  header. The watch's start time is the event's `at` when the event has one; today it is the
  replica's own receive time, so two replicas that receive the publish on either side of a minute
  boundary can still produce two keys. Add `at` to `GuardrailPublished` to close that.
* **Provider-health hysteresis.** One page per episode; it re-arms after 5 unbroken
  minutes of healthy ticks (`provider_clear_s`). The hourly repeat is off (`provider_repeat_s`
  is None by default; set it for a reminder).
* **Shadow publishes.** `note_publish` takes `mode` and `active`; a `publish` with
  `mode == "shadow"` or `active is False` does not start or replace a watch and is not the
  rollback target. **Closed:** `GuardrailPublished` now carries `mode`, `active` and `at`
  (publish: its mode, `active` True for a first publish and False for a candidate; promote and
  rollback: `active` True; `at` the commit time in epoch seconds). The Postgres event payload
  carries them when set and still parses an older payload without them.
* **A failed outbox INSERT in `DurableAlertSink` / `DurableUsageMeter` is counted on a
  shared `DropCounter` (and still raises). Feed `DroppedEventsWatch` with
  `lambda: gateway.dropped_events + drops.value`.
  **Before M4-06 serves usage to tenants:** `usage_events` is keyed by `tenant_id` and has no
  row-level security, and the application role can `SELECT` all of it. M4-06 needs RLS on it, or
  a tenant-scoped view that is the only thing tenants can read, before any tenant-facing read.
