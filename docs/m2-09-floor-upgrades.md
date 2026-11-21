# M2-09 · Floor upgrades, R5 (as built)

A new floor version reaches tenants in four steps, each by operators of the platform and each on
the class A trail: **release** (evidence and two operators), **re-pin** (a platform publish that
changes only `extends`), **staged promotion** (shadow candidate, then manual promotion), **raise the
minimum** (when every tenant is on it). A rollback can never bring an old floor back.

All of it is **platform-only**: the routes below are rows of the endpoint table whose required role
is `platform_operator`. A tenant principal, whatever its roles, gets 403 `not_platform_operator`
on every one (a test per route), so a tenant can neither approve nor block a floor release. A
platform step **on a tenant** (re-pin, promote, state) goes through the real authorizer as the
operator: a cross-tenant decision, audited before anything is touched, with an operator scope
(Postgres: the operator pool).

| Method | Route | What |
|---|---|---|
| GET | `/v1/platform/floors` | releases (approvals, evidence, halted), the minimum, the baseline, floors in the catalog that are not released |
| POST | `/v1/platform/floors/{v}/release` | propose floor `v` with the M2-08 JSON report; the proposer is approval 1 |
| POST | `/v1/platform/floors/{v}/approve` | `{report_sha256, security_urgent?}`: a **different** operator's approval of **that report** (409 `second_operator_required`; 422 `release.report_mismatch`); the second releases it |
| POST / DELETE | `/v1/platform/floors/{v}/halt` | halt / resume promotion of the release's re-pins |
| POST | `/v1/platform/floors/{v}/repin` | `{reason, tenants?}`: re-pin every active tenant (or the listed ones); 200 with a result per tenant |
| GET | `/v1/platform/floors/{v}/rollout` | per tenant: active floor, candidate floor, `on_floor` / `staged` / `behind` |
| PUT | `/v1/platform/minimum-floor` | `{version}`: raise the minimum; 409 `tenants_behind` names the tenants |
| GET | `/v1/tenants/{tid}/guardrails/floor` | one tenant's active and candidate floor |
| POST | `/v1/tenants/{tid}/guardrails/floor/repin` | `{floor_version, reason}`: re-pin one tenant |
| POST | `/v1/tenants/{tid}/guardrails/floor/promote` | `{floor_version}`: promote one tenant's re-pin |

## 1. Release (R5.1)

The evidence is the report written by `python -m redteam.run run --json <file>`; the run now also
writes `floor_content_hash` and `gate {exit_code, passed}` into it (not into any baseline). A
proposal is refused (422 `release.evidence`, every reason listed) unless the gate passed; the run
was **live** (an offline run only when the engine's environment is `test`); it measured **this**
floor (`floor_version` and the content hash equal the catalog's floor@v); it ran on **today's
corpus** (`catalog.redteam_corpus`, default `redteam/corpus.jsonl`, hashed when proposing: a
missing file refuses); no row was short or unusable; no model-independent defence broke. What is
stored is a summary (the report's `report_sha256`, mode, hashes, rows, draws, seed, gate), not the report. **An approval names `report_sha256`** (returned by the proposal): a second operator approves that report, not whatever the proposer later says it was.

The proposer is the first approver; **a second, different operator** approves and the floor is
released (two approvals by one operator are refused). **Security-urgent:** both approvers must say
`security_urgent: true` for the 6-hour staging window; otherwise 72 hours. A release is
immutable once made; halting only stops promotion.

**Unreleased floors can't be extended.** The catalog's floors are extendable only if released,
except the **baseline** (the lowest version in the files, grandfathered). **The engine starts closed**: `build_engine` restricts the catalog it uses to the baseline before anything else, so an engine with no platform store, or with injected stores, can't extend an unreleased floor; a production or staging engine refuses a catalog it can't restrict (not an `InMemoryCatalog`) and refuses to start with a publisher but no platform store. A catalog built directly (a library, a test) has no release process and stays open. The compiler refuses a
bundle extending an unreleased floor (`floor.not_released`), and `GET catalog` can show it. The
state is loaded from the platform tables at start and applied to the shared catalog; a `floor`
event on the bus (action `floor`, tenant `t_platform`, version 0) makes every replica reload.

## 2. Re-pin (R5.2, R5.3)

`policy/repin.py` is the pure transform: **`extends` moves to the new floor and nothing else of
the tenant's changes** (rules, packs, defaults, guard points, deterministic rules, escalation and
audit are byte-identical: a property test over several shapes). Floor overrides carry over only
while **still stricter**: each of `block_at` and `escalate_at` is kept only if **strictly lower**
than the new floor's value for that rule; an override on a rule the new floor no longer has is
dropped; if what is kept can't make a valid pair with the floor's other threshold the whole
override is dropped; the other fields of a floor override (restating text, `enabled`, `mode`) can
never change the floor, so they aren't carried. Every drop is listed with the old and new floor
value. Tables for lower, equal and higher are in `tests/policy/test_m2_09_repin.py`.

The service validates the result with the compiler and publishes it as a **shadow candidate at
100%** through the lifecycle store, actor **`platform`**, with the initiating operator, the reason
and the drop count in the note and the drops in the event (migration 017 adds `repin_floor` and
`repin_drops` to the publish trail). `repin_floor` is set only by this code path: no tenant
route has the field. The tenant's admins get a notice (`Notifier` port; today a logging sink,
real delivery arrives with M4-05) with the drops and the window. Per tenant, nothing is forced:

| Outcome | When |
|---|---|
| `staged` | a candidate was created |
| `replaced` | the tenant had a **platform** re-pin candidate that was stale or for another floor: abandoned (class A) and re-staged |
| `already_staged` | its platform candidate is already exactly the re-pin of the active version |
| `already_on_floor` | the active version already extends that floor or a later one |
| `skipped` (`candidate_exists`) | the tenant has a candidate of its own: **never abandoned**; retry later |
| `skipped` (`no_active_version`, `tenant_unavailable`, `forbidden`) | nothing to move, a suspended tenant, or the authorizer refused |
| `failed` | the re-pinned bundle doesn't compile (for example the question budget), or an error: the tenant stays on its floor, the codes are listed; nothing is edited; the minimum can't be raised past it |

## 3. Staged promotion (R5.4)

Promotion is manual, one tenant at a time (`M4-03`/`M4-04` automate it later). It needs: the
release not halted (409 `promotion_halted`); the window passed since the candidate was staged (409
`window_open` with the time); a candidate whose publish event is a re-pin of **that** release
(409 `no_repin_candidate`: a tenant's own candidate is never promoted by the platform); and
**the proof**, checked at promote time against the **current** active version: the candidate must
equal `repin_document(active, floor)` apart from its version number (409 `repin_stale` otherwise:
the tenant's active version changed since staging, and a fresh re-pin replaces the candidate). With
the proof, the promotion **skips the tenant's own gates** (the R1 evidence gate and the R2
approval, which would refuse a re-pin of any tenant with enforcing rules, because the rules were
never "live in shadow in the active version" in the re-pinned document): the tenant's content is
byte-identical, which is what those gates exist to check. The promote event has actor `platform`,
`becomes_active`, `repin_floor`, and the drops again.

## 4. Minimum (R5.5)

`PUT /v1/platform/minimum-floor {version}` needs: higher than the current minimum, a released floor
in the catalog, and **every active or suspended tenant's active version on a floor at or above it**
(a tenant with no active version doesn't count; an offboarded one isn't listed). Else 409
`tenants_behind` names them. It is persisted (`platform_floor_state`, compare-and-set), applied to
the catalog (`compiler` reads `max(config.min_floor_version, catalog minimum)`), announced, and
class A. The old floor stays in the catalog (the append-only rule of M2-03). **Order:** the
new minimum is applied to this replica's catalog **first**, then the tenants are checked, so from
the first instant no tenant can publish, promote or roll back below it on this replica (they are
refused or re-pinned); if anyone is behind, or the write fails, the minimum is taken back. After
the write the tenants are scanned once more and any that moved below it on **another replica** in
the meantime are recorded in the class A event (`stragglers`) for the operator to re-pin. **Residual:**
that cross-replica window lasts until the other replica hears the `floor` event (or its next
reload), a minute at most.

## 5. Rollback guard (R5.6) and "no old floor"

A rollback to a version whose floor is below the minimum **re-pins it on the fly**: the target's
content comes back as a **new version** on the floor the active version extends (never below the
minimum), floor overrides carried by the same rules, validated, stored and made active in one step
(`LifecycleStore.activate_new`: the version, the pointer, dropping any candidate, the event). The
event is a `rollback` with the new version, `repin_floor` and the drops. If it doesn't compile the
rollback is refused (409 `rollback_repin_failed`) and nothing changes. A **promotion** of a
candidate staged on a floor now below the minimum is refused (409 `floor_below_minimum`). Publish
and the draft write already refuse a floor below the minimum. A test walks all of these and
asserts every version that became active after the raise extends the new floor.

## Storage

Migration **017**: `platform_floor_releases` (a release; only `released_at`, `security_urgent` and
`halted` are updatable by the app role), `platform_floor_approvals` (append-only), `platform_floor_state`
(the minimum, one row), `platform_audit` (class A, append-only), plus `repin_floor` and `repin_drops`
on `tenant_publish_audit`. **018** is the grants. These tables hold no tenant data and have no row
level security: only the platform routes reach them.

**Residuals.** The notifier is a port with no delivery yet. The release evidence is a report the
operators supply; the engine checks what the report says and that it is about this floor and corpus,
but can't know the run happened. A re-pin batch is not atomic across tenants (each tenant is).
