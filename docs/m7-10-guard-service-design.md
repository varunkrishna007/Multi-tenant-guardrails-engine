# M7-10 · The guard as its own service (design note, nothing built)

**The aim.** The agent runtime holds no provider key and no database credentials. Today the guard
is a library: the runtime builds the `Engine`, so it holds the Gemini key, the store connection
and the audit writer, and every rate limit, repeat count and breaker is per process. This note
says how to move the engine behind a process boundary and what that changes. It proposes and
measures; it does not build.

## 1. The boundary

**The service process** runs the existing `Engine` unchanged: policy cache, gateway (the only
caller of the provider), audit writer, escalation router, spill file, all the stores. It has two
listeners: a **check listener** (the only thing the runtime can reach) and the **Admin API**
(operators; as today, a separate app on its own listener).

**The runtime keeps:** the SDK (`Guard`, `GuardContext`, `GuardResult`, streaming windows, the
parallel input guard, `check_with_retry`), the signed context its API gateway issued, and the
content. It holds **no** provider key, no store or spill-file path, no policy, no catalog. The
SDK needs only `httpx` and loads no provider adapter, database driver, web framework or signing
library (a test pins it, step 2). Importing the SDK does load the engine's pure-Python core
modules through `guardrail_engine.guard`; that is code, not a credential, and is not the aim.

**The check endpoint: HTTP/1.1 and JSON, keep-alive. Not gRPC.**
`POST /v1/check` with the signed context in a header and a body of `guard_point`, `content`,
`conversation` (typed items as `CheckContext` has them), `conversation_id`, `tool`, `request_id`.
Reasons not to use gRPC now:
* The calls are independent request and response. The one thing gRPC streams would help, a
  streamed answer, is already one independent check per window (section 4).
* `grpcio` and a protobuf build step are new dependencies for no measured gain: the wire costs
  about 1.4 ms (section 5).
* The wire shape is the public `GuardResult`, which is small and flat.

Revisit it only if step 3's measurement of the real server stack says serialization is a problem.

**The response is the public result and nothing more**: `decision`, `reason`, `request_id`,
`guard_point`, `fired` (key, action, mode), `retryable`, `failure_reason`, `capacity_limited`,
`retry_after_ms`, `degraded`. Not the verdict: its probabilities, thresholds and per-rule
evaluations are platform-confidential (the floor's numbers are never shown to a tenant) and the
runtime is tenant-side code. `GuardResult.from_verdict` already reads by attribute, so a thin
wire object with those fields works through the existing `Guard.check`.

**When the service can't be reached** (connect error, timeout, 5xx, a body that doesn't parse)
the client returns a **withheld, retryable** result of its own, never an allow:
`decision` block, `reason` `model_failure`, `failure_reason` `unavailable`, `retryable` true. The
client timeout is the guard point's cap plus a margin (3.25 s, 4.25 s at `input`), because the
service already bounds itself to the cap. Nothing in the client can release content.

## 2. Authentication

**Reuse the M2-01 signed context as the credential.** It was designed for this: audience
`guard-service`, Ed25519, verified with **public keys only**, so a compromised service host can't
mint a context for another tenant, and the tenant comes only from it (AC-T1: no tenant id in the
body). The runtime passes it unchanged in a `Guard-Context` header; the service verifies it
exactly as the engine does today. Nothing new to build for the tenant.

What it doesn't give, stated plainly:
* **It doesn't identify the caller.** Anyone holding a context (valid up to 300 s) can run checks
  as that tenant, the same exposure as today where the runtime holds it. A runtime can only reach
  the check listener; **transport identity is a deployment item, not built here**: a unix socket
  with owner-only permissions or loopback for the simulation, mutual TLS or a network policy in a
  real deployment.
* **It doesn't stop replay within its lifetime.** A repeated body is just another check.

## 3. Shared state

Moving to a service already fixes most of the "per process" residuals: all the runtime
replicas now call **one** service, so counts stop multiplying with runtime replicas. State is
shared across **service** replicas only if there is more than one, so the question is what to do
then. Proposal: **a Redis-compatible store** for the counters (the token-rate store's contract
already says "a Redis-compatible one does each as a script"; Postgres stays the system of record
and isn't put on the check path for counters).

| State | Today | With several service replicas | If the shared store is down |
|---|---|---|---|
| Token bucket, daily requests, monthly spend (M3-10) | `TokenRateStore`, per process | the store, atomic scripts | **Fall back to the process's own counters**, alert. These limits protect cost and the provider's quota, not safety, and the provider's own 429 is the backstop. |
| Repeat counts (M7-03) | `RepeatAttemptStore`, per process | the store | **No refusal; the check goes to the model** (already the contract: a store that fails never changes a verdict). |
| Refusal-escalation cap (M7-08) | `RefusalCapStore`, per process | the store | **Block, never escalate** (already the contract). |
| Provider-health breaker (M7-11) | per process | the store holds the open state and the probe slot | **Each replica uses its own state.** The breaker is an optimisation that fails fast; local state still protects it. |
| Admission (in-flight slots and queue per key) | per process | **not shared**: each replica gets its share of the key's slots (`max_in_flight_per_key` divided by replicas, a deployment setting) | n/a |

Admission stays local on purpose: a distributed semaphore on the hot path costs a round trip per
provider call and a lease to clean up when a replica dies, to save a number that is a plain
division. Nothing in this table can turn a decision into an allow: the floor's fail mode still
decides when a call fails.

Not needed for one service process, which is what the simulation runs.

## 4. Streaming and chunked checks

* **A streamed answer** is one check per window already (`stream_output`): the splitting and the
  hold-until-allowed logic stay in the runtime, and each window is an independent request. No
  streaming on the wire.
* **The parallel input guard** (PF-9) is a task in the runtime; across the boundary it is a
  concurrent request. If the runtime stops waiting for it, the client closes the connection and
  the service **cancels the check** (the engine already handles cancellation: it releases a
  repeat slot and leaves no orphan state). A provider call already in flight is left to end, as
  today.
* **A chunked `tool_result`** (M3-04) crosses once, whole: the service does the chunking, the
  fan-out through admission and the merge, and returns one result. The body limit is the
  platform's `max_chunks_per_result` times the chunk size, plus the conversation, with a 413
  beyond it (a blocked `content_too_large`, as in-process).

## 5. Latency against the 3 s cap (U7.1)

**Offline measurement.** A keep-alive HTTP/1.1 client (`httpx`) against a minimal `asyncio` and
`h11` server on loopback, doing the work a check endpoint does besides the decision: parse the
JSON, **verify an Ed25519 signed context**, build the response. No model, no engine, no TLS, one
core (client and server share it), 8-core machine.

| Body | The work alone (function call) | Over the wire, sequential: p50 / p95 / p99 |
|---|---|---|
| 200 B | 0.12 ms | 1.37 / 1.61 / 1.77 ms |
| 2 KB | 0.13 ms | 1.44 / 1.65 / 1.90 ms |
| 64 KB | 0.21 ms | 1.61 / 2.28 / 3.39 ms |

* The wire adds **about 1.4 ms at the median and under 4 ms at the 99th percentile**, up to
  64 KB: 0.05% of the 3 s cap, and about 0.2% of the expected 0.63 s model call. It does not
  change a budget.
* Signature verification is a small part of it (the work alone is 0.12 ms).
* It is a **floor, not a ceiling**: a real ASGI server and a request model add some per-request
  cost, and the figure covers client and server CPU together. Under 16 concurrent requests on the
  shared core the median was about 23 ms, which is the core's queue (about 700 requests a second
  per core including both sides), not network time. The provider limits a key to about 6 calls a
  second at 4 in flight, so the service's own overhead is not the bottleneck. Step 3 repeats this
  against the real server in separate processes.
* The service's own budget is unchanged (3 s, 4 s at `input`); the client timeout adds a
  margin (section 1), so the cap holds end to end.

## 6. How the SDK switches

`Guard` already takes any `Checker` (`check(ctx, guard_point, content)`). A **`RemoteChecker`**
(base URL, an `httpx.AsyncClient` with a connection pool, the margin) is a second `Checker`; a
`connect(url, ...)` helper builds it, so the choice is one line of the runtime's startup.
`Guard(engine)` is the in-process mode and is unchanged. Everything above the checker (streaming,
the input gate, retry, `check_source`) is the same code on both. A conformance test runs one
suite of checks against both modes and requires the same `GuardResult`.

## 7. Deployment shape for the simulation

A **local process, no real deployment**: `python -m guardrail_engine.service` starts the engine
(fake model by default, live only with the user's approval) and serves the check listener on
loopback or a unix socket; the "runtime" is the test or the load-test client using the remote SDK.
One service process, so nothing in section 3 is needed yet and the in-memory stores are correct.
**One dependency decision for the user:** there is no ASGI server installed (`uvicorn` or
`hypercorn`). The proposal is an optional `service` extra with `uvicorn`, so a runtime that only
checks installs `httpx` alone.

## 8. What the load test (M3-09) then needs

* A **remote mode** in the harness: the same tenants, rates and mixes, driving `RemoteChecker`
  against the local service, so the figures include the wire and the client pool.
* A connection-pool setting (kept at least the largest in-flight count) and the client-side
  timeout counted in the results as its own outcome, apart from the service's `Failed(timeout)`.
* It runs against **one** service process first (the figures stay comparable with the in-process
  run: the delta is the boundary), then against two behind a trivial round-robin once step 5
  exists, to exercise shared counters and the per-replica admission split.
* The existing signals (`in_flight_at_start`, `capacity_limited`, `retry_after_ms`, `degraded`)
  come through the wire unchanged, so the same acceptance criteria apply.

## 9. Migration

**The in-process mode stays.** It is how the tests, the demo, a single-process deployment and the
whole red-team and calibration harness run, and it is the reference the conformance test compares
against. What changes is the recommended production shape. To make the aim checkable, a runtime
profile setting (`guard.mode: remote`) makes startup **refuse** a runtime configuration that
holds a provider key, a store DSN or a spill path, so "the runtime holds no credentials" is
enforced and not just documented.

## 10. Steps, each one reviewable

1. **The wire contract and the service app.** An ASGI app over `Engine.check`: the endpoint,
   the signed-context header, the request and response schemas (the public result only), size
   limits, error mapping, health. Tests over `ASGITransport`. No change to any store.
2. **`RemoteChecker` and `connect`.** Fail-closed mapping of every transport failure; the
   conformance suite across both modes; streaming, the input gate and retry over the remote
   checker; the import test that keeps the client install to `httpx`.
3. **The local process runner and the measurement.** The `service` entry point and extra, a
   loopback integration test, and the measurement of section 5 rerun against the real stack in
   separate processes, committed as a bench script with its result.
4. **The load test's remote mode** (M3-09), and the runtime profile check of section 9.
5. **Shared stores**, only if more than one service replica is wanted: the Redis-compatible
   adapter for the four stores, the per-replica admission split, the fall-back rules of section 3,
   tested against an in-memory fake that injects latency and outages (there is no Redis in the
   offline environment).
6. **The doc and the residuals**: what the boundary does and doesn't give (no caller identity,
   replay within the context's lifetime, transport identity left to deployment).

Steps 1 to 4 are everything the simulation needs. Step 5 is real only once a second service
replica is.

## Decisions for the user

1. **HTTP and JSON only, no gRPC** (argued above).
2. **An optional `service` extra with `uvicorn`**: the one new dependency.
3. **Shared state (step 5) deferred** until there is more than one service replica; the
   simulation runs one.
4. **Transport identity** (a unix socket or mutual TLS) is a deployment item, not built here.
5. **The in-process mode stays**, with a startup refusal in the remote runtime profile.
