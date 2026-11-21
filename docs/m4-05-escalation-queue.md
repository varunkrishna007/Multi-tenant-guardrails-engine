# M4-05: the escalation queue (human and webhook)

S1: v1 has two escalation targets, a human queue and a tenant webhook. This is how an
`escalate` verdict gets to either, how a reviewer's resolution becomes a golden-set label, and how
the held content is deleted (R3 class D). Code: `src/guardrail_engine/escalation/`. Migrations
**034 to 037** (032 and 033 belong to M4-07).

## The flow

```
check -> verdict escalate -> audit record -> router.submit()      (the check path ends here)
                                                  |
                      bounded queue, one task on the service's loop (off the check path)
                                                  |
                    store the item (class D)  ->  [webhook only] outbox event, kind "escalation"
                                                                       |
                                                    OutboxDispatcher -> signed POST, retries, dead letter
reviewer: GET escalations / GET escalations/{id} / POST escalations/{id}/resolve
resolve -> item resolved (class A) -> golden label (R3 content rules) -> label recorded (class A)
daily job (injected clock) -> class D deletion + receipt
```

The target is the bundle's `escalation.target` (`queue` or `webhook`, with an `https` url), read from
the policy that decided the check, so a rollout candidate that decides a conversation routes by its
own bundle. A shadow candidate never routes (it never acts).

### Off the check path

`GuardService.check` calls `submit` after the audit record, and `submit` is a non-blocking put on a
bounded `asyncio.Queue`: no I/O, no await, never raises. A full queue, one tenant's share of it, an
engine that is closing, a store or an outbox that errors or doesn't answer within `timeout_s`
(5 s) are all **dropped**: counted (`router.dropped`, `dropped_by_reason`), logged by reason only,
and raised as an **`escalation_dropped` page** per tenant, throttled to one per interval (the next
carries the count in between). The alert is emitted from the router's own daemon thread, outside the
queue it reports on, to the engine's alert sink. A dropped item is lost (the verdict was `escalate`
and the caller held the content, but nobody will review it), which is why it is a page and not a
warning. A stuck store costs the worker `timeout_s` per item, never the check anything: the tests
run twelve escalating checks against a store that never answers, and every verdict comes back at
once, with the overflow dropped and alerted.

Per-tenant share: a quarter of the queue (`per_tenant_capacity`), so one tenant's flood can't crowd
out the others.

### Human queue

The item is stored in `escalation_items` (tenant-scoped, forced RLS) with:

* the rules that fired (key, action, mode, layer) and the verdict's reason, **never a probability**;
* `content_sha256` (of the pre-redaction content, as in the decision record);
* the **post-redaction** text the model saw, held for the reviewer (class D).

The id is a hash of tenant, request id, guard point **and the content hash**, so the same check
routed twice is one item, and a reused request id with other content is a second one.
Pagination is by an opaque cursor over insertion order, oldest first (`limit` 1..200, default 50).
Filters: `status` (`open`, `resolved`), `guard_point`, `rule`, `since`, `until`.

### Webhook

The item is stored as above **and** a notice is written to the delivery outbox (M4-04) under the
item id as its idempotency key, so a duplicate routing adds no second event. The dispatcher
(`OutboxDispatcher(escalations=EscalationWebhookSink(...))`) posts it with the **M4-04 signing**
(`X-Guardrail-Signature: v1=<HMAC-SHA256 of "<timestamp>.<body>">`, `X-Guardrail-Timestamp`,
`X-Guardrail-Idempotency-Key`, no redirects, no proxies, https or loopback). Retries use backoff
(2 s doubling to 5 min) for **24 hours** (`ESCALATION_RETRY`), then the notice is **dead-lettered**:
kept in the outbox with its last error code, counted in `stats.dead_escalations`, raised by the
existing `DeadLetteredEventsWatch` as `events_dead_lettered`, and re-queued by an operator with
`requeue_dead`. The signing secret is per tenant and comes from a `WebhookSecrets` source (the
platform's secret store), never from the bundle or the outbox; a tenant without one fails with the
code `no_secret`. The url and the secret never appear in a log line, an exception message or a repr.

The body carries the item id, tenant, guard point, reason, creation time, bundle version, the hash,
the rules (key, action, mode) and the path to resolve it. **No probability, and no content.**

## Roles

| Route | Role |
| --- | --- |
| `GET .../guardrails/escalations` | viewer |
| `GET .../guardrails/escalations/{id}` | viewer |
| `POST .../guardrails/escalations/{id}/resolve` | guardrail_reviewer |

The design table had one `GET / POST` row for `guardrail_reviewer`. It is now three rows, with
listing and reading at `viewer` as the story asks (every role includes `viewer`). Because the held
content is class D data, a viewer sees an item's **metadata only**; the held `content` (on
`GET {id}` only; a list never has it) and the reviewer's free-text `resolution_reason` go only to a
principal that also holds `guardrail_reviewer`. A cross-tenant request is refused by the authorizer
before anything is read (`tenant_mismatch`), and an operator crossing tenants is audited as for every
route. The endpoint-table test covers the new rows for every role.

## Resolving

`POST .../escalations/{id}/resolve`, body `{"decision": "allow"|"block", "reason": "...",
"promote_content": false, "deidentified_content": "..."}`. The actor is `issuer#subject` from the
token, never from the body. A second resolution is 409 `already_resolved`.

**The resolver must not be the person who triggered the item, if that is knowable.** It isn't: the
check context (`CheckContext`) carries a signed tenant and a request id, and no end-user identity
(the SDK is called by the tenant's runtime, not by its end user, and a reviewer is a different
kind of principal from an end user). So `triggered_by` is `None` today. The mechanism is in place
and tested (the item has the field; a resolution by the same actor is 403 `self_resolution`), so
the day a check carries a verified end-user subject, the router only has to set it. **Open
question:** should the SDK pass an optional `triggered_by`?

### The golden label (R3)

R3: "the label always goes to the golden set. The content goes with it only if class C is on, or a
reviewer explicitly promotes the item. For healthcare tenants a promoted item must be
de-identified first."

| Situation | The label |
| --- | --- |
| the item's `store_content` was `full` (class C on) | the (post-redaction) content |
| `hash_only`, the reviewer sent `promote_content` | the held content |
| `hash_only`, no promotion | a **hash-only placeholder** |
| healthcare tenant (packs need a BAA) and `promote_content` | needs `deidentified_content`, which is what is labelled; without it 422 `deidentified_content_required`, **before anything changes** |
| the item holds no content, or it was cut at the 100,000-character limit | a placeholder |

**Placeholder, not "no label".** R3 says the label always goes in, so a hash-only row is stored: the
example's content is the item's `content_sha256` and it is stored **quarantined** with the view
`hash_only`. It reuses the quarantine machinery of M2-06: it is **never sent to the model, never
counted by the evidence gate (R1)** and never in a test run, so it can't inflate the label counts
or put a hash into a prompt. It records "this request was reviewed and judged allow/block".

A label **with content** passes the harm-vocabulary tripwire like any upload: a hit stores it
quarantined and it is never sent (the response says `quarantined: true`). Examples over the 20,000
character example limit become placeholders.

Each label is a one-example golden set named `escalation-<item id>`, with an id derived from the
item (so a retry never makes a second set). Escalation label sets **don't count against the 50-set
upload cap** (a tenant resolving 60 items must not be locked out of uploading; they have their own
cap of 50,000), are **left out of `GET golden-sets`** (they would bury it; each is reachable by the
id on its item), and an upload may not use the `escalation-` name prefix. They do count in the
evidence gate's label counts (when they carry content), which is the closed loop of design step 7.

### Audit (class A)

Two events, both with the actor: `resolved` (decision and a **hash** of the reason, never the text)
written in the same transaction as the resolution, and `label_created` (set id and mode); the golden
set's own audit event (actor, set, hash, size) is written with the set. If the engine fails between
the resolution and the label, the same reviewer sending the same `POST` again finishes the label
(200); anyone else gets 409.

## Class D deletion

`ClassDJob.run_once()` (injected clock, aware `datetime`), the same shape as the M4-09 job:

| Tenant | An item is deleted when |
| --- | --- |
| standard, finance, no pack | `resolved_at <` now - 30 days (**until resolved, plus 30 days**) |
| healthcare (packs need a BAA) | `created_at <` now - 30 days, resolved or not; unresolved ones are counted as expired and logged |
| unresolvable tenant | the standard rule (keeps longer; deleting early can't be undone) |

Which row applies is the **item's own mode**, fixed when it was routed; the
job's term decides the receipt's source label and the days (30 at least), not whether an
unresolved item may go. The comparison is strict: an item exactly 30 days old is kept. Deletion is
bounded batches through
one path, `retention_delete_class_d` (a `SECURITY DEFINER` function with a pinned `search_path`, run
by the retention role, which has no DELETE or INSERT grant), skipping rows another run holds, and
writes the **class A receipt in the same transaction** (`retention_receipts`, class `D`: tenant,
cutoff, count, `expired_unresolved`, run id; never content). The function clamps a job clock that is
ahead of the database. The job is not scheduled by the engine (the deployment runs it daily, as
M4-09's).

## Storage (migrations 034 to 037)

* **034** `escalation_items` and `escalation_audit` under forced row-level security; the outbox's
  `kind` check gains `escalation`; `retention_receipts` gains class `D`, the source `healthcare` and
  `expired_unresolved`; `retention_delete_class_d`.
* **035** the service role: SELECT and INSERT on both tables, and **UPDATE on the resolution and
  label columns only**. No DELETE. A trigger allows exactly two updates, `open -> resolved` once and
  attaching the label once, and refuses a change to any other column, so the table is insert-only
  except for the resolution ("a narrow path"). The audit table is append-only.
* **036** the operator role's policies (a cross-tenant operator, via the operator pool).
* **037** the retention role: SELECT on `tenant_id` only (through its own policy) and EXECUTE on the
  deletion function.

`apply_schema` runs 034; `apply_app_role_grants` runs 035; `apply_operator_policy` runs 036;
`apply_retention_role_grants` runs 037. At merge, add 034 to the `MIGRATIONS` tuple after M4-07's.

## Known limits

* **The webhook never carries content.** R3 would let a `full` tenant's content travel, but the
  outbox is platform-level (no RLS) and a dead-lettered row outlives the item's class D term, and at
  delivery time there is no tenant scope to read the item with. The notice has the hash and
  `content_available`; the receiver fetches the content, if held, from `GET escalations/{id}` with a
  reviewer token. A webhook tenant on `hash_only` holds no content at all (R3 doesn't allow it).
* The webhook url is in the outbox payload (the tenant's bundle names it). An https url with a
  bearer token in its path is therefore in the platform outbox until the row is purged (delivered
  rows after 24 h; dead ones until requeued or removed).
* **An unresolved item of a non-healthcare tenant is kept forever** (R3: "until resolved"). Nothing
  alerts on a queue that grows; that wants a metric (M4-06).
* A dropped item is not retried: the router makes one attempt (and the dropped-items page tells an
  operator). The check's content is not kept anywhere else.
* The golden label of a `full` tenant outlives class C's 30 to 90 days (golden sets are immutable
  and are deleted at offboarding). R3 allows it ("the content goes with it only if class C is on").
* A label's content is the held, post-redaction text; a reviewer who promotes on a `hash_only`
  tenant is taking that decision for the whole item.
* The item holds no severity (the optional `score` question for grading incidents isn't wired), so
  the queue is oldest-first.
* Operator crossings use the operator pool (036), tested against Postgres; the in-memory stores
  serve an operator scope like any other. An operator may read an item (audited) but may not
  resolve one.

## Retention and queue fixes

Five minor issues, all fixed on `m4-05-fixes`.

**Class D deletion bounded by the database.** `retention_delete_class_d` took the term and
the mode from its caller, so the retention role could delete an unresolved item after a day.
* `p_days` is now **30 to 400**: R3's class D term is the floor, nothing shorter is accepted (the
  Python port refuses the same calls).
* Each item carries its own **`retention_mode`** (`resolved_plus` or `total`), fixed when it is
  routed from the tenant's profile (`EffectiveAudit.content_requires_baa`, the healthcare profile,
  gives `total`), and the trigger refuses any later change. The function applies each row's own
  mode. `p_mode` is still validated but selects nothing: naming `total` deletes no item that was
  routed as `resolved_plus`, and a job that takes a standard tenant for healthcare deletes no
  unresolved item. The probe (standard tenant, open item two days old, `total`, one day)
  is refused, and a test pins it.
* The function puts `app.tenant_id` back to what the caller had before it returns.
* Migration 034 changed in place (it is not merged yet): the column, its check, the trigger's
  immutable list and the function. It stays safe to run twice.

**A reused request id.** The item id now includes `content_sha256`, so an identical retry
still dedupes and a reused request id with different content is a second item, never a silently
lost one. After a new item is stored, the router counts any other item for the same
(tenant, request id, guard point) (`router.reused_request_ids`) and logs a warning that names the
tenant and guard point only (never the request id or content). A failure of that check never costs
the item. A webhook tenant gets a notice for each item. Migration 034 adds an index for the count.

**Decision: operators don't resolve.** A platform operator may read a tenant's items (the
crossing is audited) but may not resolve one or write its labels: `resolve` is refused with **403
`operator_resolution`** before anything is read or changed, and the golden-label writer refuses an
operator too.

**Webhook hosts.** The tenant names the url, so the host must be on the public internet.
* `net_safety.py` holds the one test, `is_global_address`: private, loopback, link-local (including
  the metadata address), CGNAT, multicast, unspecified and reserved ranges are refused, and the
  IPv6 forms that carry an IPv4 address (mapped, compatible, NAT64, 6to4) are judged by that
  address.
* **When configured:** the bundle compiler refuses an IP literal that isn't global and the names
  that only mean a local network (`localhost`, `*.local`, `*.internal`, no dot), with
  `escalation.webhook_host_not_public`. It makes no network call.
* **At send time:** the sink resolves the name, refuses unless every address is global
  (`host_not_public`, nothing connected to; an unresolvable name is `dns_failed` and is retried),
  and connects to **the address it checked**, so a later lookup can't answer otherwise. The TLS
  server name, the certificate check and the Host header keep the hostname. No redirects, no
  proxies, https only.
* **The test allowance:** `EscalationWebhookSink(..., allow_non_global_hosts_for_tests=True)` lets a
  test post to a `127.0.0.1` server over http. It is off by default and is a constructor argument
  only; no bundle field, tenant record or environment variable can set it, and a deployment must
  not.
* The M4-04 alert sink (a url the platform's own operator configures) is unchanged.

**Escalation labels visible.** `GET golden-sets?include=escalation` lists the one-example
label sets that resolved escalations made (metadata only); without it the list is as before, and
any other value is 400 `invalid_query`. The R1 gate's `label_counts` message now adds, when there
are any, "of which N from escalation labels (B block, A allow)", counted over the escalation sets
alone (`escalation_label_counts` on the golden store).
