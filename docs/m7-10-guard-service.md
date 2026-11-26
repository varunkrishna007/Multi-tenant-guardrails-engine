# M7-10 · The guard as its own service: the check endpoint and the remote SDK (as built)

The design and its reasons are in `docs/m7-10-guard-service-design.md`. This describes what
exists: the check listener (`guardrail_engine.service`) and the SDK's remote mode
(`connect`). Also built (steps 3, 4 and 6): the local process runner, the measurement of the
boundary, the load test's remote mode and the runtime credentials check. Deferred until a second
service replica exists: shared stores (design step 5).

## Using it

```python
from guardrail_engine.sdk.adapters.remote import connect

guard = connect("http://guard.internal:8443")   # the runtime holds no key and no DSN
result = await guard.check("input", text, GuardContext(signed_context=ctx))
if result.released: ...
await guard.aclose()
```

`Guard(engine)` is unchanged and stays the in-process mode. Everything above the checker
(streaming windows, the input gate, `check_with_retry`) is the same code in both modes, and a
test runs the same scenarios through both and requires the same `GuardResult`.

(`connect` is in the adapter module, not on `Guard`: the project's import rule lets only adapters
import an HTTP client.)

The service side is `guardrail_engine.service.adapters.fastapi_app.create_check_app(engine)`, an
ASGI app with two routes.

## Running it locally (the simulation)

```sh
uv run --extra service python -m guardrail_engine.service --signing-key-file key.bin --tenant t_alpha
# {"listening": "http://127.0.0.1:41873"}      one line when it is ready; SIGTERM drains and exits 0
```

`guardrail_engine/engine/serve.py` builds the engine and serves the check listener with uvicorn. It
is **for the local simulation, not a deployment**:

* **Loopback or an owner-only socket.** `--host` must be `127.0.0.0/8`, `::1` or `localhost`; any
  other address (`0.0.0.0` included) is refused before anything is bound. With `--uds` the socket is
  bound by the runner itself under `umask(0o077)`, mode 0600 from the moment it exists (uvicorn's own
  binding would make it 0666), and announced only then. It is removed when the service stops, but only
  if the file is still the socket this process made (device and inode); a socket at the path is replaced
  only if it is stale (a connection to it is refused); one that answers is **in use** and is
  refused, never taken over; anything else there (a symbolic link included) is refused. **A path or
  an address that can't be used is one `refused: ...` line and exit 1, with no traceback**, decided
  before the engine is built (the socket or port is bound first).
* It serves the `test` environment only and refuses any other (a deployment wires its own stores,
  keyset, secrets and transport identity, none of which it reads).
* **The model is the fake by default** (`--fake-latency-s` gives it a run time;
  `--fake-behaviour marked` makes it decide by `[mix:...]` markers in the text, for comparing modes).
  In fake mode a settings file that names `projects.dedicated` is refused, because building those
  projects would read the environment variables their `key_env` names: nothing reads a key variable
  without live mode.
* **Live mode needs the user's written approval, and the environment variable is not it.**
  `--model live` builds the real adapter from `GEMINI_API_KEY`. The runner refuses unless
  `GUARDRAILS_LIVE_SERVICE` is set, but that variable is only a flag that you mean it: a value any
  code can write is not an approval, and the refusal doesn't print it. The approval is the user's, in
  writing, and is a separate step. Live mode also needs `--max-live-calls N` (no default): the most
  requests **this process** will send to the provider in its lifetime. It is its own counter, apart
  from the daily request cap, and it never rolls. The count is taken immediately before every send
  (the gateway's one model, so a first call, a retry and a breaker probe each count), with no await
  between the check and the count, so concurrent checks can't overshoot. Past N nothing is sent and
  every check fails closed (`model_failure`, reason `live_call_cap`). **It is per process**: a restart
  is a new run with a new count and needs its own approval. The same holds for the two other live
  harnesses (`capacity/load_live.py`, `calibration/pack_live.py`): their refusals don't print the
  value either.
* **The key file** (`--signing-key-file`, the v1 HMAC scheme) is read as its **raw bytes**: no
  trimming, so a trailing newline is part of the key, and the side that issues contexts must use
  exactly the same bytes. It must be a regular file owned by the user running the service, owner-only
  (no group or other permission bit, so a 0644 file is refused), at most 4,096 bytes and at least 32,
  and is opened without following a symbolic link (the file itself; a symbolic link in a directory of
  its path is the operator's own path).
* Each `--tenant` gets a floor-only bundle.
* uvicorn is the optional `service` extra, pinned to an exact version in `uv.lock`; a runtime that
  only checks installs no web server.

## The runtime holds no credentials

`connect()` refuses to start (`CredentialsInRuntimeError`, naming the variables, never a value) if
the process environment holds a provider key or a database DSN: `GEMINI_API_KEY`,
`GUARDRAIL_PG_DSN`, `GUARDRAIL_PG_OPERATOR_DSN` or a dedicated project's `GEMINI_KEY_<LABEL>`
(a test keeps the list equal to the engine's). `allow_credentials_in_environment=True` says the
operator knows. A dedicated project's `key_env` may name **any** variable, so a deployment that uses
other names lists them: `connect(url, extra_credential_variables=["ACME_GEMINI_SECRET"])`. **A name
the runtime isn't told, or a secret kept anywhere else (a file), can't be found.**

## What the boundary costs

`bench/wire_overhead.py` (result in `bench/results/m7-10-wire-overhead.md`) compares the engine in
process with the real service in another process, offline: **about 2 ms at the median** (1.6 to
3.1 ms across 200 B to 24 KB bodies), under 5 ms at the 99th percentile for small bodies: about 0.07%
of the 3 s cap. `capacity/load_remote.py` runs simulated turns through both modes (see
`docs/m3-09-load-test.md`).

## The wire

* `POST /v1/check`, JSON, keep-alive. The **signed tenant context goes in the `Guard-Context`
  header**; the body is `guard_point`, `content`, `conversation` (typed items), `conversation_id`,
  `tool`, `request_id`. **The body has no tenant id**, and a body that names one is a 400: the
  tenant is only the verified context's (AC-T1).
* The response is the **public `GuardResult`** as JSON and nothing of the verdict beyond it: no
  probabilities, thresholds or per-rule evaluations, and no free text. `200` for every verdict;
  `401` (public `forbidden`, reason `context_invalid`) for a context that is missing, malformed
  (not ASCII, over 4,096 characters, control characters), forged or expired; `403` for the other
  `forbidden` verdicts.
* A missing or malformed context is decided **before the body is read**, by running the check with
  an empty context: the engine's forbidden verdict and its audit record are the same as in process.
  **Two `Guard-Context` headers are malformed** (a proxy may append rather than replace).
* **The request id also travels in a `Guard-Request-Id` header** (printable ASCII, 1 to 128
  characters). The service echoes it on an answer it gives before reading the body (the 401), so
  every answer carries the caller's id. When the header is there, the body's `request_id` must equal
  it, else 400. Without the header the body's id is used, as before. On that early 401 the
  `guard_point` is the service's placeholder (`input`): the client sets the one it asked.
* **Limits.** Headers over 16 KiB: 431. A body over the cap (4 MiB by default; checked by
  `Content-Length` and again while reading): 413, which the client reads as a blocked
  `content_too_large`. Not a JSON object of the contract's members: 400, and so is a
  `Content-Length` that isn't a number. Not `application/json`: 415.
* **A client that disconnects** gets its check cancelled in the service (the engine releases a
  repeat-attempt slot and queued admission; a provider call already in flight ends on its own).
* **`GET /healthz` is liveness only**: `{"status": "ok"}`. No tenant, policy, breaker or key
  state; the breaker and degraded state are on the Admin API. There is no other route (no docs,
  no OpenAPI).

## What the client does when the service is not there

It can only withhold, and it accepts a result only as **the answer to this request**. A connect
error, a timeout, a 5xx, a redirect, any other status, any exception while reading or parsing the
body, or a body that isn't the contract's answer gives `decision` block, `reason` `model_failure`, **`failure_reason`
`guard_unreachable`**, `retryable` true: a runtime operator can tell "my guard service is down" from
"the provider is" (`unavailable`, `timeout`, `provider_degraded`). A 413 is a blocked
`content_too_large`, and a 400, 415 or 431 a blocked `invalid_request`, neither retried. A decision
or a failure reason a newer service adds is read as withheld (`other`), never as an error.

What counts as an answer: every member of the public result is present with its type (members a
newer service adds are dropped, never surfaced, never a reason to refuse); `request_id` equals the
request's and `guard_point` the one asked; and the status agrees with the decision: 200 for every
decision but `forbidden`, 401 or 403 only with a `forbidden`. Redirects are never followed, whatever
client the caller supplied: the signed context is a bearer token and goes only to the service.

A guard point that isn't one of the five (none, not text, an unknown name, the wrong case) is
blocked **locally** as `invalid_request`, with no call: the answer to it couldn't be matched to the
request, and the engine would block it the same way. (A request with both a bad context and a bad
guard point gets `invalid_request` from the client where the engine would say `forbidden` first;
both withhold.)

The client waits for the guard point's cap (3 s, 4 s at `input`) plus 250 ms for the **whole
exchange, the body's reading included** (httpx's own timeout is per read, so a response dripped a few
bytes at a time would never expire); `timeouts_s` and `margin_s` change that for a service with
longer budgets. The request id is the caller's, or one the
client generates, so an unreachable result still has the id a retry derives from.

## Authentication, and what it doesn't give

The credential is the M2-01 signed context, verified by the engine with public keys only. It
**doesn't identify the caller** and doesn't stop replay within its lifetime (300 s): anyone holding a
valid context can check as that tenant, as when the runtime holds the engine. Transport identity (a
unix socket with owner-only permissions, mutual TLS, a network policy) is a deployment matter and is
not built here.

## The client install

Importing the SDK and the remote checker loads no provider adapter, database driver, web
framework or signing library (a test runs it in a fresh interpreter and lists what loaded). The
service package imports its web framework only when `create_check_app` is first used.

## Residuals

* Counts, caps and the breaker are per service process (design section 3); with one service
  process that is one set for all runtime replicas. Sharing them across service replicas is
  deferred (step 5).
* No transport authentication beyond the signed context.
* The wire adds about 2 ms at the median over loopback with no TLS and a model that answers at
  once; a deployment adds its network and a handshake per connection.
* The runtime credentials check covers environment variables only.
* The runner serves the test environment with the v1 HMAC scheme: a real deployment's wiring is
  not built.
