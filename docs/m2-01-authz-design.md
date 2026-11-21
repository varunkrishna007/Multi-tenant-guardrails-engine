# M2-01 · AuthN/Z and tenant scoping: design choices to decide

Status: proposal, nothing built. Written as a proposal for review before the build starts.
Backlog: M2-01 (AC-T1), design §Admin API → Security, §Multi-tenancy → Identity.

## What exists today (so the choices are small)

- `guard/context.py`: `ContextVerifier` port and `HmacContextVerifier` (token
  `v1.<b64url JSON {exp, tid}>.<b64url HMAC-SHA256>`, one shared key of at least 32 bytes, strict
  canonical base64url, constant-time compare, every failure is a `ContextVerificationError`
  with a reason). No key id, no rotation, no issuer or audience, no skew allowance.
- `guard/tenants.py`: `TenantDirectory` port, `InMemoryTenantDirectory`, `TenantProfile` (slug,
  id, domain, tool registry), the slug denylist and patterns. `tenant_ids.py`: the id pattern and
  `new_tenant_id`.
- `store/`: `PolicyStore` port, in-memory and Postgres adapters, migrations 001-003. **No row-level
  security yet.** No JWT, OIDC or elliptic-curve library in `pyproject.toml` or `uv.lock`.

## A. The signed tenant context (gateway → Guard Service)

**A1. Algorithm: Ed25519, not HMAC.** The gateway signs, the Guard Service only verifies. With
HMAC every verifier holds the signing key, so one compromised Guard Service host can mint a
context for any tenant. With Ed25519 verifiers hold only public keys. Cost: one new dependency
(`cryptography`; the standard library has no Ed25519). *Alternative:* keep HMAC with key ids
(no new dependency), accepting that the verifier can forge. *Recommend Ed25519.*

**A2. Format: `v2.<kid>.<payload>.<signature>`**, keeping v1's strict canonical base64url,
4,096-character cap and "every failure is a `ContextVerificationError`". Not a general JWT: a
fixed algorithm, no `alg` header to confuse, no JWT library parsing on the hot path. Payload
fields: `tid`, `iat`, `exp`, `aud` (`"guard-service"`) and `iss` (the gateway's name); unknown
fields are refused. The signature covers `v2.<kid>.<payload>`. `v1` is accepted only while a
keyset marks it allowed (migration window), then removed. *Alternative:* standard JWS compact
(`EdDSA`), so any gateway's JWT library can issue it; costs a stricter parser to pin `alg`.

**A3. Lifetime and skew.** Default lifetime 300 s (as now); the verifier refuses a token whose
`exp - iat` exceeds 600 s. Clock-skew leeway **30 s** on `iat`/`exp` (a token issued up to 30 s
"in the future" or expired up to 30 s ago still verifies). Reasons added: `unknown_key`,
`not_yet_valid`, `wrong_audience`, `wrong_issuer`; all map to `forbidden` / `context_invalid`.

**A4. Key rotation without downtime.** The verifier holds a **keyset**: `{kid → public key,
valid_from, valid_until, may_verify}` loaded from the secret manager as one JSON document and
re-read every 60 s (and on a change event). Rotation is three steps: (1) add the new public key
to every verifier's keyset; (2) switch the gateway to sign with the new `kid`; (3) remove the old
`kid` after `max lifetime + skew` (about 11 minutes). During (1)-(3) both keys verify. Tests:
both valid during the overlap, an unknown or retired `kid` is refused, a forged signature with a
valid `kid` is refused, and a keyset that fails to parse keeps the last good one and alerts.
Header: `X-Guardrail-Context` over HTTP, the SDK's existing `signed_context` argument unchanged.

## B. The tenant directory source

**B1. Postgres, in the policy store's database, written only by platform operators.** Tables
`tenants` (id, slug, domain, tier, flags, status, created_at, updated_at, version) and
`tenant_tools` (the tool registry, tenant-written later in M2-03), plus a class A audit event for
each directory write. The Guard Service reads through `PostgresTenantDirectory` (new, behind the
existing port) with a short in-process cache (30 s) and a `tenant.changed` event that calls
`policy_cache.invalidate` (the M2-07 hook). The write path generates ids (`new_tenant_id`) and
validates slug and domain with the code that exists; the platform endpoint that calls it is a
platform operator's, never a tenant's. Tier is one of `standard`, `regulated`, `dedicated`;
flags include `two_person_publish`. *Alternatives:* a reviewed config file in git (simplest and
auditable, but no runtime provisioning API and a deploy per tenant), or an external system of
record (not available).

## C. Authorization and the OIDC edge

**C1. A framework-independent core first.** `authz` module: `Principal` (subject, tenant id,
roles, platform-operator flag), `authorize(principal, tid, required_role)` returning an allow or a
403 reason, and the endpoint→role table copied from §Admin API with a test per row. The REST
framework is "any behind the API gateway" in the design; I would not choose one in M2-01 (M2-02
brings the first endpoints). *Ask:* which framework, or none yet?

**C2. Role implication.** The design lists `viewer` on reads and `guardrail_admin` on writes.
*Recommend:* `guardrail_admin` and `guardrail_reviewer` each imply `viewer`; `auditor` implies
`viewer` but nothing else (the decisions endpoint is auditor-only, so an admin cannot read
decision records); no role implies another's write. Platform operators bypass the tenant match
but not role checks except via a separate `platform_operator` role, and every cross-tenant
access writes a class A audit event **before** the response (an audit failure refuses the
access).

**C3. OIDC validation.** A small strict verifier on `cryptography`: RS256 and ES256 only (no
`none`, no HMAC), issuer allowlist, audience, `exp`/`nbf` with the same 30 s leeway, `kid`
pinned to a cached JWKS (refetched on an unknown `kid`, rate-limited), claims `tenant_id`,
`roles` and `platform_operator`. *Alternative:* PyJWT (one more dependency, well tested, but a
larger surface to configure safely). *Recommend the small verifier,* tested against the standard
algorithm-confusion cases. **The endpoints themselves are not built in M2-01.**

**C4. Path/token tenant match.** `{tid}` must equal the token's `tenant_id`, else 403 (not 404:
the backlog says 403). The check also runs the id pattern first, so a malformed `{tid}` is
refused before any lookup.

## D. Row-level security

Migration 004: enable and **force** RLS on the policy-store tables, policy `tenant_id =
current_setting('app.tenant_id', true)`, the setting applied per transaction with `set_config(
'app.tenant_id', $1, true)` from the verified principal (never from a request body); the
application role has no `BYPASSRLS` and no table ownership. Platform operations run under a
second role with an explicit, audited policy. Test: under tenant A's setting a query returns none
of tenant B's rows even with a forged `tenant_id` filter. *Ask:* the existing Postgres adapter
tests skip without a database (95 skips); is a Postgres instance available to run the RLS test, or
should it run in CI only with a DSN, skipped locally?

## Order of work (each step offline, merged separately)

1. Signed context v2, keyset, rotation, tests (A).
2. Authz core: principal, roles, endpoint matrix, tenant match, cross-tenant audit (C1, C2, C4).
3. Tenant directory (Postgres), write path, change events (B).
4. RLS migration and test (D).
5. OIDC verifier and JWKS (C3), then the platform provisioning endpoints.

## Decisions needed

1. A1 Ed25519 plus the `cryptography` dependency (or keep HMAC).
2. A2 a fixed `v2` format, or standard JWS compact.
3. A3 lifetime 300 s, cap 600 s, leeway 30 s.
4. A4 keyset reload every 60 s and the three-step rotation.
5. B1 Postgres as the directory source (or a git-reviewed file).
6. C1 no REST framework in M2-01.
7. C2 role implication as recommended.
8. C3 small strict OIDC verifier (or PyJWT).
9. D whether a Postgres instance is available for the RLS test.

## As built (2026-11-17)

Decisions applied: Ed25519 v2 contexts, Postgres directory, PyJWT for OIDC, forced RLS, operators
keep the role checks (only the tenant match is waived), and the factory wiring.

- `signed_context.py`, `authz/`, `directory/`, migrations 004-007, `signing/adapters/` (the only
  place `cryptography` and `jwt` are imported; the layering tests keep third-party libraries in
  `adapters/` and keep `guard/` from importing any adapter, so the scheme is plain Python behind
  `SignatureVerifier` and `Signer` ports and the factory is handed the key loader).
- `build_engine` takes `verifier`, or `keyset_source` plus `key_loader` (the v2 verifier and a
  60 s keyset refresher the engine stops at shutdown), `legacy_verifier` (v1 beside v2, only with
  `signed_context.allow_v1_hmac`), `authenticator` and `authz_audit` (kept on the engine for the
  REST layer). **A v1 HMAC context is refused in production unless `signed_context.allow_v1_hmac`
  is true**; the mode (`v2`, `v2+v1_migration`, `v1`) is logged and kept on
  `Engine.signed_context_mode`.
- Not built: the REST endpoints and framework (M2-02), a production keyset source (the secret
  manager adapter), the NOTIFY or bus adapter for `tenant.changed` (M2-07 wires the bus to
  `CachedTenantDirectory.on_changed` and `PolicyCache.invalidate`), and the tenant tool registry
  table (M2-03).

## Scope and issuer changes (2026-11-17)

- **`TenantScope`.** The policy store takes a verified scope, never a tenant string.
  `PostgresPolicyStore` has only `scoped(scope)`; the returned view sets `app.tenant_id` from the
  scope and refuses (`ScopeMismatchError`) any call whose `tenant_id` differs. The guard path
  gets the scope from `VerifiedContext.scope`, the Admin API from `AuthzDecision.scope` (issued
  only on an allowed tenant decision), and `bootstrap_publish` issues one itself (an operator
  tool). `tests/test_tenant_scope.py` fails if any other module imports `issue_scope`. No
  operator pool exists in the store yet; when one is added it is used only with an allowed
  cross-tenant `AuthzDecision`.
- **Issuer kinds.** `OidcConfig(platform_issuers, audience, tenant_issuers={iss: {tenant
  ids}})`. Only a platform issuer's `platform_operator` counts; a tenant issuer's token that
  claims operator is refused (`operator_not_allowed`) and one naming a tenant outside its set is
  refused (`tenant_not_allowed`). An issuer in both is refused when the config is built. Each
  issuer has its own JWKS, so a key of one issuer can't sign for another.
- **`pyjwt[crypto]>=2.9,!=2.10.0,<3`. The authz tests pass at 2.9.0, 2.10.1 and the
  locked version: `uv run --with "pyjwt[crypto]==2.9.0" pytest tests/authz`.
- **`CachedTenantDirectory` bumps a per-tenant generation on `invalidate`; a read that
  started before a bump doesn't cache, and reads again (up to 3 times).
- **At startup the factory checks the Postgres role (`app_role_problems`): superuser
  or BYPASSRLS (also inherited), owner (or inheriting the owner) of a policy table, or member of
  `store.operator_role`. Production and staging refuse to start; `test` logs a warning.
- **`class_a_audit.file` also backs the cross-tenant access record
  (`AppendOnlyFileAuthzAudit`, same file, same rules, fsync before the access is allowed). A
  passed `authz_audit` that isn't `durable` is refused outside `test`.
- **`_scoped` reads `app.tenant_id` and sets it in one statement and refuses a
  connection that already carries a setting (`TenantSettingLeakError`). Isolation relies on
  `set_config(..., true)` (transaction-local) plus asyncpg's reset on release; a custom reset or
  a transaction-mode pooler must keep to transaction-local settings.
