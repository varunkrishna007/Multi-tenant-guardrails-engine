# M5-02 · Two-person approval (R2)

Enforcing a policy needs a second person for some tenants. This is how it works, what R2 asks
for and what it doesn't cover yet.

## The R2 matrix as implemented

"Needs approval" is `approval_required(profile)`: the tenant's `tier` is not `standard`
(`regulated` or `dedicated`), **or** the tenant has the `two_person_publish` flag
(`require_two_person`, the standard-tier opt-in). The regulated-tier attribute (M5-01) is not
modelled yet, so the existing tier and flag stand in for it; when M5-01 lands, change that one
function.

| Action | Tenant that needs approval (regulated, or opted in) | Any other tenant |
| --- | --- | --- |
| Publish in `shadow` | one person; an `approval_id` in the body is ignored | one person |
| Publish in `enforce` (including a tenant's first publish) | **needs an approval of the draft** | one person |
| Promote a **shadow** candidate to enforce | **needs an approval of the candidate** | one person |
| Promote an **enforce** candidate whose publish consumed an approval | one person; admins are notified | one person |
| Promote an **enforce** candidate published with no approval (the tenant needed none then) | **needs an approval of the candidate** | one person |
| Raise `rollout_percent` of an enforce candidate | one person; **admins are notified** | one person |
| Raise `rollout_percent` of a shadow candidate | one person (it never acts) | one person |
| Lower `rollout_percent`, abandon | one person | one person |
| Rollback | one person; **admins are notified** | one person |

The standard-tier opt-in behaves exactly as the regulated tier does. A candidate that was
published in enforce *under an approval* was approved when it was published, so promoting it is
the "raise the share of an already approved version" case. One that was published with none (the
tenant was standard then and has become regulated, or opted in, since) is not: its promotion
needs a `promote` approval, as a shadow candidate's does.

## An approval

A request is made by one `guardrail_admin` and approved by a different one.

* **`publish` approval**, tied to the **draft hash** (the draft's ETag without its quotes). The
  request names the draft it saw in `If-Match`, as publish does.
* **`promote` approval** (`{"action": "promote"}`), tied to the candidate's **version** and to the
  draft hash the candidate was published from. It doesn't depend on the current draft, so the
  draft can move on while a candidate waits. A candidate that didn't come from a draft (a platform
  re-pin) has nothing to approve; the tenant can't promote it as an enforce.
* **Any draft edit cancels the open `publish` approvals** of the tenant for another draft
  (`close_reason` `draft edited`), through the draft service's one write path, so a template
  copy, a rule patch and an accepted threshold all count. The cancellation is housekeeping and
  an audit line. **Safety doesn't depend on it:** an approval is checked against the draft hash
  at use, so a changed draft is `approval_stale` even if the cancellation never ran. Editing the
  draft back doesn't revive a cancelled approval.
* **72 hours** (`APPROVAL_TTL`) from the approval, by the services' injected clock. A request that
  nobody approves lapses 72 hours after it was made. An approval found expired when it is
  approved or used is marked `expired` (with a class A event, "expiry at use") and refused.
* **Single use.** It is consumed by the lifecycle store, in the transaction of the publish or
  promotion that uses it, after the tenant's lifecycle advisory lock is taken. The check and the
  `approved -> consumed` update happen on the locked row, so two publishes can't both use it, and
  a publish that fails afterwards rolls the spending back.

### Who may approve

The authorizer requires `guardrail_admin` on the tenant's own path (a viewer, reviewer or
auditor gets 403 `missing_role`). The service then refuses, in this order:

| Who | Code | How it is known |
| --- | --- | --- |
| a platform operator, even one with the admin role who crosses into the tenant | 403 `operator_approval` | `Principal.platform_operator` |
| a service account | 403 `service_account_approval` | `Principal.service_account` |
| the requester (same `issuer#subject`) | 403 `self_approval` | the actor on the request |

R2's two people are two humans end to end. A service account may not *request* an approval
(403 `service_account_request`), and whoever publishes or promotes with an approval must be a human
(403 `service_account_publish`) who is not the approver (403 `approver_publish`). The requester
may be the publisher.

**Service accounts.** Principals carry `Principal.service_account`. Each OIDC issuer says how its
machine tokens are marked (`OidcConfig.machine_markers`, issuer -> `MachineMarker`): a claim name and
the value a machine token has (`MachineMarker(claim="azp_type", value="m2m")`, a boolean claim by
default), or `gty` values (`MachineMarker(gty=frozenset({"client-credentials"}))`), or the explicit
`MachineMarker(humans_only=True)`. In `production` and `staging`, `build_engine` refuses an issuer
with none of these, and an authenticator that can't say (it has no `unmarked_issuers()`). In `test`
an unlisted issuer keeps the old default: a boolean `service_account` claim that is `true`, or
`gty: client-credentials`. A boolean marker on a claim of another type is `bad_claim`.

The database refuses a self-approval too (`CHECK approved_by <> requested_by`). The same
subject from two issuers is two actors, so it is not a self-approval.

## API

| Route | Role | Notes |
| --- | --- | --- |
| `GET /v1/tenants/{tid}/guardrails/draft/approvals` | `viewer` | newest request first; optional `status`, `limit` (1 to 100, default 50), `cursor`; `{items, next_cursor}` |
| `POST /v1/tenants/{tid}/guardrails/draft/approvals` | `guardrail_admin` | body optional: `{"action": "publish" \| "promote"}`; `If-Match` required for `publish`; 201 with the approval |
| `POST /v1/tenants/{tid}/guardrails/draft/approvals/{id}/approve` | `guardrail_admin` | 200 with the approval |
| `POST .../draft/publish` | `guardrail_admin` | body takes `approval_id` |
| `POST .../candidate/promote` | `guardrail_admin` | optional body `{"approval_id"}` |

The approval is `{id, action, draft_hash, version, status, requested_by, requested_at,
expires_at, approved_by, approved_at}`; `status` is `pending`, `approved`, `consumed`,
`cancelled` or `expired`. There's no cancel route; the trail is in the class A table.

Refusals, with their HTTP status and code:

| Situation | Status, code |
| --- | --- |
| enforcing with no `approval_id` (or no approval service) | 409 `approval_required` |
| no such approval for this tenant | 404 `approval_not_found` |
| not approved yet | 409 `approval_pending` |
| expired | 409 `approval_expired` |
| cancelled by a draft edit | 409 `approval_cancelled` |
| for another draft, candidate or action | 409 `approval_stale` |
| already used | 409 `approval_used` |
| approving what isn't pending | 409 `approval_not_pending` |
| asking for one the tenant doesn't need | 409 `approval_not_required` |
| a service account asks for one | 403 `service_account_request` |
| a service account publishes or promotes with one | 403 `service_account_publish` |
| the approver publishes or promotes with it | 403 `approver_publish` |
| a bad `limit` or `status` on the list | 400 `invalid_query` |
| a cursor the API didn't issue | 400 `invalid_cursor` |

## Storage (migrations 040 to 042)

* `tenant_approvals` (040): one row per request, under forced RLS keyed on `app.tenant_id`.
  Insert-only except the status: the service role has no DELETE and only a column-level UPDATE
  on the status columns (041), and a trigger allows exactly `pending -> approved`,
  `approved -> consumed` and `pending|approved -> cancelled|expired`, with every identifying
  column fixed. No TRUNCATE.
* `tenant_approval_audit` (040): the class A trail, append-only (triggers refuse UPDATE, DELETE
  and TRUNCATE; the role has SELECT and INSERT). Events: `requested`, `approved`, `cancelled`,
  `expired`, `consumed` and `notified`, each with the actor (`issuer#subject`), the approval, the
  draft hash, the version and whether the actor was an operator crossing tenants.
* 042: the operator role's `operator_all` policies, as for the other lifecycle tables. An operator
  who publishes into a tenant uses an approval, so the role can update it; the service refuses
  an operator's *approval* before it reaches the table.
* Approve, expire, cancel and consume take the tenant's lifecycle advisory lock
  (`lifecycle:<tenant>`), the one every publish takes. The publish and promote of
  `PostgresLifecycleStore` take an `approval` argument and consume it after taking the lock.
  The publish's own class A event notes `two-person approval <id>`.
* The in-memory stores do the same without locks (one event loop), so tests can run offline.

## Notifications

On a tenant that needs approval, a rollback, a larger share for an enforce candidate and the
promotion of an approved enforce candidate need no approver, but they tell the tenant's admins:

1. the lifecycle's own class A event (`rollback`, `set_percent`, `promote`) records the actor;
2. an alert on the existing alert sink, kind `approved_version_change`, severity `warning`,
   `reason` = `rollback`, `set_percent` or `promote`, `tenant_id` = the tenant, with a message
   naming the actor and the change (no content);
3. a class A `notified` event in the approval trail, saying whether the alert was sent.

Both run after the change committed; a failing sink is logged and never fails or undoes the
change. Getting the alert to the people is the sink's delivery (the outbox and webhook of M4-04
and M4-05), as for the bad-publish alert.

## Known limits

* **No regulated-tier attribute yet.** Tier and the opt-in flag stand in for it (M5-01).
* **No cancel route** for approvals, and **no cap** on open requests per tenant.
* **Service accounts need a marker from the identity provider**, and the issuer's config has to
  name it (or declare humans only). Production and staging refuse to start otherwise.
* **Two humans, not two identities.** One person with two accounts from two issuers, or two
  accounts at one issuer, is two actors. R2 asks for "a different human"; the engine can only
  tell actors apart.
* **The cancellation on edit is not atomic with the draft write** (it runs right after). The
  check at use makes that safe.
* **Draft-hash approvals don't cover the mode or share.** An approval is for enforcing the draft;
  the publisher chooses `rollout_percent` (and a candidate's later share changes need no approver,
  as R2 says).
* **A promotion approval isn't cancelled when its candidate is abandoned**; it is refused as
  stale if the candidate changed, and expires in 72 hours.
* **Platform actions** (floor re-pin promotion, M2-09) have their own two-operator rule and don't
  use these approvals.

## Service accounts and the list: fixes

One major and three minor issues. Each is fixed, with tests.

* **(major): one human plus a service account could pass as two people.** A service account
  requested, the same human approved, then published. Now a service account can't request
  (403 `service_account_request`), and whoever publishes or promotes with an approval must be a
  human (403 `service_account_publish`) who is not the approver (403 `approver_publish`); the
  requester may be the publisher. The rule is in `check_usable`, so the lifecycle store enforces it
  again on the locked row, in the publish's own transaction, and 040 adds
  `CHECK (consumed_by IS NULL OR consumed_by <> approved_by)`. Tests: the probe (ci-bot
  requests, alice approves, alice publishes) now stops at the request; alice requests, bob approves,
  alice publishes still works; the approver and a service account are refused on publish and
  promote, over HTTP and on Postgres, and the approval is not spent by a refusal.
* **An enforce candidate was promoted without checking it was approved.** Promoting an
  enforce candidate needs no approval only when its publish consumed one, or the tenant needs none
  now. The evidence is read from the class A approval trail: the `consumed` event of a publish
  approval records the version it created (`ApprovalUse.for_version`), and
  `ApprovalService.published_under_approval(version)` finds it. The publisher's note is never read
  (it is their own words). Otherwise (the tenant became regulated, or opted in, after an
  unapproved enforce publish) the promotion needs a `promote` approval. The promote's class A event
  note carries the evidence: `enforce candidate published under approval <id>`, or `enforce candidate
  published without an approval; the tenant needs none`, or `two-person approval <id>; enforce
  candidate published without an approval; promotion approved`. A promotion that used an approval
  doesn't send the "approved version changed" notification.
* **Machine tokens depended on the identity provider's markers.** Each issuer now says how
  its machine tokens are marked, or that it issues humans only (see Service accounts above).
  `OidcConfig.unmarked_issuers()` lists those that say nothing; `build_engine` turns them into a
  `SettingsError` in `production` and `staging`, naming the issuers. The `test` environment keeps
  the old default. The old `service_account_claim` option is replaced by
  `MachineMarker(claim=..., value=...)`.
* **No way to see the open approvals.** `GET .../draft/approvals` lists the tenant's
  approvals, newest request first, with `status`, `draft_hash`, `version`, `requested_by`,
  `approved_by`, `expires_at` and so on. `status`, `limit` (1 to 100, default 50) and an opaque
  `cursor` over `(requested_at, id)` (so requests made in the same instant page without gaps or
  repeats). Role `viewer`, like the other reads (`GET /versions`), added to the authz table and
  the design's endpoint table. The index `tenant_approvals_by_request` serves it. It shows what
  the other admins can already see in the trail, so a second person sees what they would approve.
