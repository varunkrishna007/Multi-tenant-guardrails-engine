# M2-07 · Publish, versions and rollback (as built)

**Routes** (rows in the endpoint table and the design doc; all behind the same authenticate →
authorize → service order as the draft routes):

| Method | Path | Role | Result |
|---|---|---|---|
| POST | `…/draft/publish` | guardrail_admin | 201 `{version, bundle_hash, mode, rollout_percent, state}`; body `{mode, rollout_percent?, note?}`; **needs the draft's `If-Match`** (428 without) |
| GET | `…/versions` | viewer | each version with status (active, candidate, inactive), the current `mode`/`rollout_percent` (enforce at 100 for the active one, the candidate's own, null for an inactive one) apart from `published_mode`/`published_rollout_percent` (what the publish event said), actor, note, diff |
| POST | `…/versions/{v}/rollback` | guardrail_admin | makes `v` active and abandons any candidate; only to a version that has been active before (a first publish, promotion or rollback event), else 409 `not_previously_active` |
| PATCH | `…/candidate` | guardrail_admin | `{rollout_percent}` |
| POST | `…/candidate/promote` | guardrail_admin (+ approver on regulated tiers, M5-02) | candidate → active at 100%; runs the enforce gates |
| POST | `…/candidate/abandon` | guardrail_admin | drops the candidate; the version stays stored |

`GET guardrails` now also returns `rollout: {active_version, candidate}`.

**State machine (PF-7)** is in `admin/lifecycle.py`'s docstring: one active version, at most one
candidate; the first publish of a tenant must be `enforce` at 100% and becomes active directly
(shadow or a partial percent: 409 `no_active_version`); a publish while a candidate exists is 409
`candidate_exists`; versions are numbered per tenant and never reused (the draft's own `version`
is overwritten). The Guard Service reads only the active version; a candidate deciding or
shadowing a share of conversations is M4-03. Every transition is a compare-and-set on the state
it read (409 `state_changed`), atomic with its class A row.

**Enforce is gated.** Approval (R2): until two-person approval exists (M5-02), enforcing (a
publish or a promote) is refused with 409 `approval_required` for a tenant that is not standard
tier or that opted in to two-person publish; shadow publish, percent changes and rollback are one
person. Evidence (R1, `admin/evidence.py`): for each tenant rule whose own mode is `enforce`, per
guard point it runs on, at least 20 labelled golden examples with 5 of each label (50 with 15 for
`severity: high`), counted over all the tenant's golden sets, de-duplicated by content (normalised: format characters stripped, NFKC, look-alike
letters mapped, case folded, whitespace collapsed; a paraphrase or a changed number is
still a different example, so the counts show a quantity of distinct strings, not coverage: that is
M4-01's precision gate), leaving out quarantined rows and content labelled both ways; and at
least 72 hours of **continuous time the rule, as worded now, was live in rule-mode `shadow` inside
the active version**, from the class A events, on an injected clock: each activation
(first publish, promotion, rollback) sets what is live; a candidate does not count (it serves no
traffic until M4-03), so an abandoned shadow candidate leaves no soak; an activation of a version
that drops the rule from shadow restarts it. Editing a rule's wording or thresholds restarts the
soak (the event carries a fingerprint per rule); `template_unedited` is exempt from the soak, not
from the counts. Floor and pack rules are exempt, and a rule in `shadow` mode is exempt: **new
tenant rules start with rule-level `mode: shadow`, are published and promoted, soak 72 hours, then
are flipped to enforce and published again.**
The refusal is 422 listing every failing rule with codes `evidence_gate.label_counts` and
`evidence_gate.shadow_soak`.

**Class A in Postgres** (migrations 012, 013): `tenant_publish_audit` (one row per publish,
set_percent, promote, abandon, rollback: actor `<issuer>#<subject>`, cross-tenant and operator
flags, versions, mode, percent, bundle and draft hashes, diff, note, per-rule snapshot) is
append-only (triggers refuse UPDATE, DELETE and TRUNCATE for everyone; the app role has SELECT
and INSERT), under forced RLS. `tenant_candidates` (one row per tenant, forced RLS) holds the
candidate. The version row, the pointer or candidate change and the audit row are one
transaction under a per-tenant advisory lock; a version about to become active is loaded and
verified first.

**Rollback and invalidation (PF-13).** After the commit `guardrail.published{tenant, version,
action}` goes on a bus. The engine subscribes its own policy cache (so the next check re-reads
the pointer: **within the event's delivery time, tested as the next check**); the deployment
subscribes `engine.on_tenant_changed` to the directory's `tenant.changed` bus so adding,
suspending and reinstating a tenant invalidates the same way. With Postgres the default bus is
`LISTEN/NOTIFY` (`PostgresEventBus`: best effort, ignores any payload that isn't exactly one of
ours, reconnects), so every replica hears it. **If an event is dropped, the pointer TTL (60 s)
and the directory cache TTL (30 s) are the bound**, and the docs say "within the TTL", not
"immediately". The listener holds one connection of the pool for good.

**Operator access** (migration 014, `apply_operator_policy` now applies it): the operator role
has `operator_all` policies on every tenant table (policy, drafts, golden, lifecycle). A
`TenantScope` is an *operator scope* only when the authorizer issues it for an **allowed
cross-tenant decision by a platform operator**; the Postgres stores then use the operator pool
(`GUARDRAIL_PG_OPERATOR_DSN`), and with none configured the request is refused with 503
`operator_unavailable` rather than served from the tenant-scoped pool. Every other scope uses the
app pool, which has no operator policy.
