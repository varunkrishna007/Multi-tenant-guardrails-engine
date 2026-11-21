# M2-02 · Draft lifecycle (as built)

**Routes** (FastAPI, `admin/adapters/fastapi_app.py`; OpenAPI and docs pages are off):

| Method | Path | Role | Result |
|---|---|---|---|
| GET | `/v1/tenants/{tid}/guardrails` | viewer | published version, draft (with `ETag`), rollout (empty until M2-07) |
| PUT | `/v1/tenants/{tid}/guardrails/draft` | guardrail_admin | 201 first draft, 200 replace; `ETag` header |
| PATCH | `…/draft/rules/{rule_id}` | guardrail_admin | create or JSON-merge-patch (RFC 7396) one tenant rule |
| DELETE | `…/draft/rules/{rule_id}` | guardrail_admin | remove a tenant rule |

**Order in every handler:** authenticate (401, fixed reason; 503 if the IdP keys can't be
fetched) → authorize with the real authorizer (403, fixed reason) → read the body (bounded,
JSON only) → call the service with the `AuthzDecision`. The service uses only `decision.scope`;
the path's tenant, query and body never reach the services or stores. A decision that wasn't
allowed, or was made for another endpoint, is a programming error (`DecisionError`, 500).

**Errors:** `{"error": {"code", "message", "errors": [{code, path, message}]}}`. 422 carries
every compiler error (AC-C0: all shape errors, then all semantic errors) and nothing invalid is
stored; 412 a stale or unmatched `If-Match` (with the current `ETag`); 428 a missing `If-Match`
on an existing draft; 413 body over 256 KiB; 415 not JSON; 404 no draft, no such rule, tenant not
active in the directory. An unexpected error is a 500 with no detail.

**ETag** = `"sha256:<hex>"` of the canonical draft JSON (strong; `*` matches any existing
draft; a weak validator never matches). The write is a compare-and-set on it.

**AC-A2.** Each write stores a class A event *in the same transaction* (Postgres) or step
(memory): actor, action (`draft.put`, `draft.rule.put`, `draft.rule.delete`), before and
resulting draft hashes (a chain), and the bundle diff with URL values redacted
(`policy/diff.py`). No write without its event; no event for a write that lost the race. The hash
is the draft's, not a published bundle hash (that covers the extended catalog versions and is
made at publish, M2-07).

**Postgres** (migrations 008 and 009): `tenant_drafts` and `tenant_draft_audit`, both under
forced RLS on `app.tenant_id`; the audit table refuses UPDATE, DELETE and TRUNCATE (triggers)
and the app role has SELECT and INSERT on it only; drafts get SELECT, INSERT, UPDATE and never
DELETE. `apply_app_role_grants` applies 002 and 009. Platform operators' cross-tenant policy
(007) does not cover these tables until the operator pool exists (M2-07).

**Factory.** `Engine.draft_service` is built from the engine's own stores (memory with memory,
Postgres with a Postgres pool, or `draft_store=`; an injected policy store outside `test` needs
`draft_store=`). `Engine.admin_app()` returns the ASGI app, or raises
`AdminApiUnavailableError` naming what is missing (authenticator, `authz_audit`, draft service).

**Dependencies.** FastAPI is pinned to 0.11x: Starlette 1.x's test client wants an unfamiliar
`httpx2` package, so the tests drive the app through httpx's ASGI transport instead.

## M2-04 · Validate and M2-05 · Test (as built)

| Method | Path | Role |
|---|---|---|
| POST | `/v1/tenants/{tid}/guardrails/draft/validate` | guardrail_admin |
| POST | `/v1/tenants/{tid}/guardrails/draft/test` | guardrail_reviewer |

Both act on the tenant's **stored draft** and take the tenant from the decision's scope.

**Validate** re-runs the compiler against today's catalog (a floor or pack change since the write
can invalidate a draft) and returns `valid`, every error, and, for a valid draft, per guard point:
each compiled question as sent (with key, layer, source, thresholds), the question count against
its budget, and the token figures: content, questions, the largest call, the 16,000 budget
(PF-10), headroom, and `est_cost_usd_per_check` for that largest call at $0.10 per 1M input
tokens. No model call. 404 `no_draft` without a draft.

**Test** takes `{"guard_point", "samples": [{"id", "content", "expected"?}]}` (strict: unknown
fields and `golden_set` are refused; a stored golden set arrives with M2-06). Each sample goes
through the same pipeline as a production check (the deterministic checks of M3-01 in AC-G1
order, redaction, render, one decision call, fusion) over the draft's compiled policy (`GuardService.evaluate_draft`, `PolicyCache.
compile_draft`). Answer per sample: `decision`, `reason`, `p`, thresholds and action of the **tenant's own and
pack rules only**, the `fired` rules (a floor rule appears there with key, action and mode, and
**never a probability**: it would be a gradient for tuning content just under the floor's
thresholds; this holds for a tenant rule that is the floor's own under another key too:
an `origin` of `fork:p__*`, or a question, true or false description equal to a floor rule's
after normalising case, whitespace and format characters, is reported like the floor), and
`expected_met` (null when no `expected`); plus `usage` (provider-reported
input tokens, estimated cost, and samples whose answer carried no usage). A sample may name a `tool` (for a `tool_call` allow-list). Limits: 50 samples, the route's
256 KiB body bound, one test run at a time per tenant (429 `test_in_progress`, `Retry-After`),
503 once the engine has stopped accepting work; a running test is in-flight work, so shutdown
waits for it.

**Metering apart.** The gateway takes a `usage_class`; with M3-10 a test call reserves from the **same bucket,
daily request counter and monthly spend** as production, in a **fourth priority class below
`tool_result`** (decided 2026-11-17). It is metered under the guard point label `test:<guard point>` (usage, unanswered, provider-safety and error counters alike), and
`evaluate_draft` writes nothing to the audit sink. Budgets, admission and the model call are the
same as for a check. Per-tenant rate limiting of test calls beyond the one-at-a-time rule is not
built; the cost of a run is bounded by the sample caps.

**Accepted residuals of the test endpoint (decided 2026-11-17).** A *paraphrase* of a floor rule
isn't caught by the text comparison, and a rule published in shadow can show a tenant its own
probability ladder over time. Both are accepted; the floor's probabilities remain unreadable
through the endpoint for the floor's own text and for forks of it.

## M2-06 · Golden-set upload (as built)

`POST /v1/tenants/{tid}/guardrails/golden-sets` (guardrail_reviewer), body at most 4 MiB:
`{"name": "...", "examples": [{"id", "guard_point", "label": "allow"|"block", "content"}]}`.
Read strictly and checked whole (every problem reported, nothing stored on any failure); `201`
with `set_id` (`gs_` + 16 hex), `name`, `set_hash` (sha256 of the canonical examples),
`created_at`, `created_by` (`<issuer>#<subject>`), `examples` and `counts` per guard point and
label. Limits: 1,000 examples per set (content up to 20,000 characters, ids up to 64), 50 sets
per tenant (409 beyond; there is no delete or edit, so a set is immutable and a cited
`set_hash` always means the same examples).

**Harm vocabulary, by quarantine (decided 2026-11-17).** The user's rule is about what reaches the
provider, not what a tenant may store, and a golden set can be sent to the model by the test
endpoint. So every row's id and content are read by the red-team builder's tripwire
(`admin/vocabulary.py`: the same word list and views: as written, after normalisation
(zero-width characters, NFKC, look-alike letters) and inside base64 runs, two levels deep). A
row that hits is **stored with its `quarantine` views and the upload still succeeds**; the
response lists those rows by id and view (`quarantined_rows`), never the word or the content,
and the metadata routes show them too. **The test endpoint never sends a quarantined row**: the
store's query excludes it and the runner checks again in code before any request is built (a
test hands the runner a leaking store and shows it still drops the row). The report says how many
were held back (`quarantined_not_sent`). Still refused outright: a row id containing `-harm-` and
any label other than `allow` or `block`. The set's name is not a row and is not read. The
tripwire is coarse (an honest "child cover" example is quarantined too), which is why it
quarantines instead of refusing.

**Metadata routes** (viewer and above; added to the endpoint table in the design doc and the
role-table test): `GET …/golden-sets` lists the tenant's sets (id, name, hash, size, created,
quarantined count) and `GET …/golden-sets/{set_id}` returns one set's metadata with its counts per
guard point and its quarantined rows by id and view. Never the examples' content. Another
tenant's set, or an id that isn't `gs_` plus 16 hex digits, is 404.

**Storage** (migrations 010, 011): `tenant_golden_sets`, `tenant_golden_examples` and
`tenant_golden_audit`, all under forced RLS on `app.tenant_id`, with triggers that refuse UPDATE,
DELETE and TRUNCATE for everyone (the owner too) and grants of SELECT and INSERT only. The set,
its examples and the class A event (actor, set id and hash, size, cross-tenant and operator
flags) are one transaction; the 50-set cap is enforced under a per-tenant advisory lock. Another
tenant's set is indistinguishable from one that doesn't exist.

**The test endpoint** takes `{"guard_point", "golden_set": "gs_...", "offset"?}` in place of
`samples`: the set's examples at that guard point (up to 50 from `offset`, upload order), each
with its label as `expected`; the report adds `golden: {set_id, set_hash, total, offset, run}`.

**Issuer requirement.** Outside `test` the factory builds the authorizer, the draft service and
the golden service with `require_issuer`: a principal with no verified issuer is refused
(`missing_issuer` / `DecisionError`), since the audit actor is `<issuer>#<subject>`.

**Held back at test time (decided 2026-11-17).** There are no real tenants
yet, so all test traffic is ours and the no-harmful-inputs rule applies to it. Right before any
request could be built, the test endpoint reads **every** sample (inline or from a golden set;
its id, content and tool) with the *current* vocabulary, independent of any stored flag. A sample
that trips is not sent and the run goes on with the rest: the response's `quarantined_not_sent`
has `count` (these plus golden rows the store held back as quarantined) and `rows`, each
`{position, views}` by position in the request's `samples` (or the golden page), never by id
or text. A run with nothing left to send makes no call. The shared vocabulary module
(`admin/vocabulary.py`, also used by the red-team corpus builder) reads: as written,
normalised (zero-width characters, NFKC, look-alike letters), percent-decoded, hex-decoded,
single-character runs joined (`b o m b`), leet (`0o 1i 1l 3e 4a 5s 7t @a $s`) and base64 two
levels deep. **Accepted residual:** look-alike letters outside the table (Armenian, say), other
languages and paraphrases, and deeper nesting.
