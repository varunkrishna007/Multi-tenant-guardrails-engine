# M4-03: progressive rollout at runtime

M2-07 built the lifecycle (a candidate with a `mode` of `shadow` or `enforce` and a
`rollout_percent`; publish, set percent, promote, abandon). M4-03 adds what the Guard Service
does with a candidate at check time, and the report on it.

## What was already there, and what was added

| Acceptance criterion | Before | M4-03 |
|---|---|---|
| PF-7: a conversation is assigned by `hash(tenant_id, conversation_id)` | the lifecycle stored `rollout_percent`; nothing read it at runtime | `guard/rollout.py`: `rollout_bucket`, `Rollout.assign`; `conversation_id` on `CheckContext` (and the SDK's `GuardContext`) |
| A shadow candidate is evaluated and logged, never acts; audit holds `bundle_version`, `candidate_version` and the candidate's decision | none of it | `guard/service.py` runs the candidate beside the active check; `Verdict` and `AuditRecord` carry `candidate_version`, `candidate_decision`, `candidate_reason` |
| `SafetyBlocked` on a candidate is only logged (PF-12); a per-rule agreement report that doesn't expose the floor or floor-derived p | none | provider refusals of the candidate are logged and counted as incomparable; `GET .../candidate/comparison` returns counts and rates |

## Assignment (PF-7)

`rollout_bucket(tenant_id, conversation_id)` is the first 8 bytes of
`sha256(tenant \0 conversation)` modulo 100. A conversation is in the sample when its bucket is
below `rollout_percent`, so raising the percentage only adds conversations (never moves one
back), and the same conversation gets the same version at every guard point, in every process,
with no state. Different tenants hash differently for the same id.

- No `conversation_id` on the check: the active version decides and no candidate runs.
- The id is caller-supplied and checked (1 to 128 printable characters; otherwise
  `invalid_request`). It controls rollout only; it is not a security boundary.
- The candidate pointer is cached 5 s per tenant and the compiled candidate policy 60 s;
  `Engine.invalidate_tenant` clears both. A candidate source that fails or a candidate that
  cannot be compiled means **the active version decides** (logged), never a failed check.

### The one exception to "one version a conversation"

If the candidate pointer can't be read, or the candidate's policy can't be built, the check is
decided by the active version, and the conversation's other checks may have been decided by the
candidate (enforce) or will be again once it can. This is by design: a check never fails because
of a candidate. It is **counted** by tenant and cause (`Rollout.fallback_counts()`:
`source_failed`, once per failed refresh of the pointer; `compile_failed`, once per check that
needed the candidate) and logged at error level.

### The active pointer follows the candidate pointer

The candidate pointer (`Rollout`) and the active pointer (`PolicyCache`) are cached separately. A
check reads the candidate first, and when that read shows the candidate changed (a publish,
promote or abandon whose event this replica missed) the active pointer is read again too. So a
promotion seen late never sends a sampled conversation from the candidate to the old active
version and back (v2, v1, v2): the pointer TTL bounds how long a *missed* event is visible, not
the order of versions a conversation sees.

## Modes

- **enforce** candidate, conversation in the sample: the candidate's policy decides, in place of
  the active one. `bundle_version` and `candidate_version` are both the candidate's.
- **shadow** candidate, conversation in the sample: the active version decides. The candidate is
  evaluated as a draft evaluation (`usage_class="shadow"`, its own 10% share of the project's
  token rate) beside it. The verdict waits at most `GuardConfig.shadow_wait_s` (0.2 s) for it, and
  not at all when the active verdict took no model call (a deterministic block, a guard point
  with no questions); if
  it is in time the audit record holds `candidate_decision` and `candidate_reason`, otherwise
  only `candidate_version`. The comparison is counted either way when it finishes. It never
  changes the verdict, never alerts, and is dropped at shutdown after a drain.

## PF-12

If the provider refuses the candidate's evaluation (`provider_safety`), the active verdict
stands, the refusal is logged at info, the record says `provider_safety`, and the comparison is
counted as **incomparable**. It is not a disagreement and not a block.

## The agreement report

`GET /v1/tenants/{tid}/guardrails/candidate/comparison` (viewer): for the active version and the
candidate, per rule: `n` (evaluated by both), `agree`, `candidate_stricter`, `candidate_looser`,
`only_active`, `only_candidate`, `agreement_rate`, and the `layer`; the same for the overall
`decision`; and `checks_compared`, `checks_incomparable`. "Stricter" is by action severity
(allow < escalate < block).

What is stored (`tenant_shadow_agreement`, migration 028) is those counters only, per
(tenant, active version, candidate version, rule), under forced row-level security. **No
probability is stored or returned**, so neither the floor's thresholds nor a floor-derived `p`
can be recovered from it, and no content. Floor rules are listed with `layer: floor` and
agree with themselves unless the candidate overrides them.

**Rolling deploys of the event payload.** The `guardrail.published` payload may carry
more keys than a reader knows (`mode`, `active`, `at` were added later); a reader now ignores
unknown keys once the required ones are present. A replica from before this change drops a
payload that has keys it doesn't know, so deploy **readers first, then writers**: roll every
replica to this version before any replica starts publishing a newer payload.

The counters are buffered in memory (the check path never touches the database) and flushed
every 5 s, on a read and at shutdown; a failed flush keeps the counts for the next try.

## Migrations and grants

028 `shadow_agreement` (table, RLS), 031 `shadow_grants` (SELECT, INSERT, UPDATE; no DELETE),
and an operator policy in `014_operator_policies.sql`. (029 and 030 belong to M4-09.)

## Not here

Automatic promotion on agreement, and any per-rule gate on the report, are not built: the
report is for the person deciding.
