# Calibration

M0-02 measures how the platform floor's rules score labelled examples on the live Gemini
Decisions API. **Nothing here produces or edits a floor file.** Choosing thresholds and
shipping a floor version are product decisions (B2, R5 and R7).

| Module | What it is |
| --- | --- |
| `run.py` | The current harness (second run): floor@2 assembled at run time, the real renderer, R7's Definitions |
| `floor_v1.py` | The first run's harness, **report-only**, kept so `results/m0-02-floor.md` reproduces |
| `metrics.py` | Pure metrics: reliability and ECE, counts, Wilson and one-sided Clopper–Pearson intervals, the B2 sweep |

## No harmful inputs (user instruction, 2026-11-17)

No harmful input is ever sent to Google. This is enforced in code, before any request is
built:

- **Rows that are never sent:** any row labelled for a rule ending in `harm_facilitation`
  (`p__`, `d__` or `t__`), any row tagged `no_live_run`, and harm near-miss rows (ids
  containing `-harm-`). `run_started` records how many were excluded, and why. The runner
  refuses an excluded row even if one is passed to it directly.
- **Recognised files only:** the harness accepts only `floor/golden.jsonl` and
  `floor/heldout/heldout.jsonl`. `floor/heldout/harm_pack.jsonl` and the packs' golden sets
  are refused.
- **Tripwire:** a provider refusal stops the run at once and records the example id; the
  example is never resent. A refusal is a `SafetyBlocked` result (how M1-13 maps it): HTTP 400
  with code `prohibited_content`, `blocklist`, `content_blocked` or `image_safety`, or any
  code naming `safety`, which are the codes Google's Decisions API guide lists. (Only
  `prohibited_content` has been seen live; the others are mapped from the documentation and
  tested on constructed fixtures.) A code that is not mapped, such as `spii`, stops the run as an
  unclassified failure instead; it is never resent either.
- **Error text:** only the structured head of an error is stored (`HTTP 400 <code>`). The
  provider's free text can echo input, so it never is.

## Second run: `run.py`

```sh
set -a; . ./.env; set +a          # GEMINI_API_KEY from the gitignored .env; never echo it
uv run python -m calibration.run plan                       # call count, exclusions, file hashes
GEMINI_PAID_TIER=true uv run python -m calibration.run run --out calibration/results/m0-02-floor2.jsonl
uv run python -m calibration.run report calibration/results/m0-02-floor2.jsonl
```

`--golden`, `--rules` and `--additions` default to `floor/golden.jsonl`, `floor/rules.json`
and `floor/next/additions.json`. `--draws` defaults to 3; fewer needs `--pilot`, which is
recorded. `--replay-nonces FILE` replays every (example, draw) nonce of an earlier run.

`report` sends nothing, so it accepts any path, but it **refuses** unless every input file
hashes to what the run recorded. To report on a run whose files have since changed, restore
the run's versions with `git show <commit>:<path>` and pass them.

**Held-out validation** (`--golden floor/heldout/heldout.jsonl`):
- it measures floor@2 only, with no `_v1` wordings and no independence phase;
- rows render with `max_content_tokens` 12,288, so their context isn't dropped;
- the report is titled as a validation run and has no B2-amended section, because held-out
  data never selects thresholds (R7.3(c));
- `run_started` records the mode, the phases and every question asked.

Per the backlog, it runs only after M1-14 redaction and through the composition root.

### What it sends

- **floor@2, assembled at run time** from `rules.json` and `additions.json`: replacements
  substituted by key, new rules appended, at `target_floor_version`. Nothing is copied. The
  engine's compiler builds each guard point's questions from a floor-only bundle.
  `run_started` records the sha256 of the golden set, `rules.json` and `additions.json`.
  The report flags a mismatch, and a run won't resume on changed files.
- **Design A for the R7.1 retest.** The floor@1 wording of `p__ai_addressed` and
  `p__xtenant_probe` is asked in the same call, under `<key>_v1`, at the guard points those
  rules cover. Old and new wording therefore see byte-identical input in every draw. The
  comparison rests on independence, which the run measures first.
- **Redaction, then the real renderer.** Each row's content, context and tools first go
  through the engine's `redact_request` (M1-14), with the arguments the Guard Service uses,
  so the direct path scores what production sends. Then
  `guardrail_engine.guard.render.render_input` renders the redacted request, with the row's
  `tenant_slug` and `tenant_id` (default `acme-insurance` / `t_1042`), its `domain` (default
  `insurance`), and any held-out `context` and `tools`. The harness generates each nonce,
  passes it to the renderer, and records it. Each call record carries `pii_redacted`, the
  spans replaced per PII kind (counts only, never values, spans or offsets).

### Phases

1. **`indep` (a gate).** 50 examples: 5 positives and 5 gate-level negatives per guard point.
   Each gets one full call and one call per question alone, all on the example's draw-1
   nonce. If any alone-versus-full pair isn't bit-identical, the run stops before the main
   phase: design A can't be used, and separate calls with replayed nonces (design B) are
   needed.
2. **`main`.** Every example, `--draws` times, each draw on its own fresh nonce. Draw 1
   of the 50 independence examples reuses their nonce, so that call repeats an earlier
   request exactly, which gives a direct determinism check. A replay reuses all k nonces,
   never one.

Safeguards: a sliding-window limiter under 70% of Tier 1's per-minute limits, and stops on
`auth`, on a provider refusal, or when more than 20% of the last 50 calls failed. Records
are appended, so a rerun resumes. They hold ids, nonces, probabilities, usage and timings:
never content, headers, the key or provider free text.

### Analysis (R7 Definitions)

- **Sets for a rule:** its positives (`fires` includes it); gate-level negatives at its guard
  points (`fires` empty); cross-rule examples (labelled for other rules only). Cross-rule
  examples are judged only under R7.1 and never enter a false-positive rate.
- **Draws:** a positive is caught at a level only if every draw reaches it. A gate-level
  negative is a false act (p ≥ `escalate_at`) or false block (p ≥ `block_at`) if any draw is.
  Rates carry a one-sided 95% Clopper–Pearson upper bound.
- **R7.1 retest, per draw (decided 2026-11-17):**
  - (i) a cross-rule example **acts** if **any** draw reaches `escalate_at`, and the new
    wording's acts must be ≤ 5%;
  - (ii) a positive is **caught** only if **every** draw reaches `block_at`; no positive caught
    under the old wording may be missed under the new, and the count caught must not drop.
  - The report also gives the original per-example-median tables, as history.
- **Informational:**
  - per rule: ECE over all draws (flagged above 0.10), flips across draws, the highest
    negative scores, thin cells (counts only), and the B2-amended plateau midpoint and band
    condition (R7.2). These are information, not candidates: the floor stays provisional
    (R7.3). Runs recorded before M1-14 (no `pii_redacted` in their records) say their
    inputs weren't redacted; later runs get a **Redaction** section that splits out the
    examples redaction changed (per rule: positives / gate-level negatives / cross-rule),
    read from the records' `pii_redacted` (on the engine path, `Verdict.pii_redacted`);
  - per example: gate decisions;
  - fairness on counterfactual pairs (R4.5: same verdict, |Δ median p| ≤ 0.10);
  - independence, determinism and draw-to-draw noise.
- **Not measured:** `p__harm_facilitation`, by user instruction. It is now a pack rule (U5).
  Labels for rules the measured floor doesn't have are reported separately, never as
  negatives. The 32 harm near-miss rows are excluded, so the floor's figures are over the
  rest of the set (306 examples at present).

## Through the composition root: `engine_path.py`

For the R7.4 threshold-setting rerun, it was decided that threshold runs score through the
production path, including M1-14 redaction. Each draw is one `Engine.check` on an engine
built by `build_engine` (M1-11), and scores are read from the `Verdict`. The harness never
renders, redacts or calls the model itself.

```sh
uv run python -m calibration.engine_path plan
uv run python -m calibration.engine_path run --out calibration/results/<name>.jsonl [--seed <32 hex>]
uv run python -m calibration.run report calibration/results/<name>.jsonl
```

### How the engine is built

- `environment = "test"`.
- The candidate floor (floor@2, assembled at run time) in the catalog.
- One tenant profile per tenant the rows name, each with a floor-only bundle published by
  `bootstrap_publish`. Held-out bundles raise `max_input_tokens` (`chunk_tokens` at
  `tool_result`) to 12,288, the tenant-configuration way to keep their context.
- A per-run HMAC verifier.
- `NullAuditSink`.
- **Tools (option (a), decided 2026-11-17):** each tenant's tool registry is the union of its
  rows' `tools`. A tool name with two different definitions for one tenant stops the run
  before any check; the conflict is fixed in the data, never resolved by picking one. A
  row's input depends only on the registered tools its kept context names, so every row
  renders as it would with its own tools (tested on all 782 held-out rows).

Checks run one at a time, so admission never refuses one. The gateway's budgets and retries
apply as in production.

### A draw that doesn't answer is never a score

- A model failure records no probabilities.
- A draw that failed with `timeout`, `unavailable` or `rate_limited` is re-attempted once,
  as a new check, after the main pass.
- An example still short of its draws is **incomplete**. The report names it and excludes
  it from every per-draw figure, on either path.
- `auth` stops the run. So does a provider refusal (`provider_safety`), which names the
  example and is never resent. So does any failure of kind `other`: M1-13 leaves
  refusal codes it hasn't observed as `other`, so it may be an unmapped refusal; it is
  never re-sent, and the stop record names the example and draw.
- **Failure rate:** the run stops once more than 20% of the last 50 checks failed. It counts
  checks (draws and re-attempts), not provider calls, and stops as soon as more than 10 of
  the last 50 failed, so an outage costs at most 11 checks. The gateway's breaker covers
  auth only.
- **Token ceiling** (`--max-tokens N`): a hard ceiling on API input tokens for the run.
  `plan` prints its own estimate (`estimated_input_tokens`, from the engine's estimator on the
  redacted render) and `run` refuses to start if that exceeds the ceiling. While running, it
  stops (`token_ceiling`) **before** sending any check that could pass it (the estimate for
  the call and its one gateway retry is reserved first), and after any call that did. An
  answered call counts its reported usage plus an estimate per extra provider call; an
  unanswered one counts an estimate per provider call, so the ceiling over-counts.
- **Provider-call ceiling** (`--max-provider-calls N`): a hard ceiling on provider calls (a
  call and its gateway retry are two). `run` refuses to start if the plan's checks alone
  exceed it, and stops (`provider_call_ceiling`) before sending a check whose worst case
  (two calls) would pass it. Used for a diagnostic run, whose cost is set in calls.
- **`--no-reattempts`** skips the pass that re-attempts failed draws, so a diagnostic run stays
  at one check per example.
- **`--avoid-minute-boundary`** (calibration only; never the engine or gateway) starts no
  check between :55 and :10 of the UTC wall-clock minute: it sleeps until :10 first. In two
  live runs the provider stalled around the top of the minute (see
  `results/m0-02-r74-diagnostic.md`). The argument that it doesn't bias the R7.4 measurement:
  a check's input is fixed by its row and nonce and nothing sent depends on the clock, so send
  time has no route into a score. That is an argument, not a measurement: no run compared
  scores sent at different times. `plan` and `run_started` record the setting, and a call
  that waited carries `boundary_wait_s`.
- `limit_exceeded` is deterministic per example: never re-attempted and never a stop. The
  report lists those examples by id. Before any call, `plan` flags every example whose
  content is over its guard point's cap (`content_too_large`), or only outgrows it after
  redaction (`content_too_large_after_redaction`: a placeholder can be longer than the short
  PII it replaces), or whose request would exceed a Decisions API limit by the engine's
  estimate, and `run` refuses to start while any are flagged.
- The run stops (`unusable_answers`) once 10 checks have ended in `contract_violation`, so a
  systematic answer-format change can't burn the call budget. The plan and the report
  header give the count. An answered check with no usable score for any noul question
  asked stops the run at once (`no_usable_answer_at_all`): it measures nothing,
  and it is the one success-shaped response an unmapped refusal could take.
- **A rule whose answer was unusable** on an answered draw (`policy`, or
  `contract_violation` when that rule's fail mode decided) is absent from the draw's
  probabilities and named in `problems`. The report treats an (example, rule) cell with
  fewer scores than the run's draws as missing for that rule: it is named, left out of that
  rule's figures, and the gate decision leaves the example out. Draws are paired
  across rules by draw number. Each table's note counts what was left out per rule, split
  into positives / gate-level negatives / cross-rule examples.

### What's the same as the direct harness, and what isn't

- **The same:** both paths redact (M1-14) before rendering. For every golden row (339, all
  five guard points; 15 changed by redaction) and every held-out row (782, context and
  tools included; 82 changed), the engine sends a rendered input byte-identical to the
  direct harness's (same nonce), the same questions minus the `_v1` keys, and the same
  redaction counts. A test checks every row.
- **Not available through the engine:**
  - design A and the independence phase (the engine asks the compiled set, never a single
    question);
  - the direct harness's `--replay-nonces` from an earlier direct run. Instead, engine-path
    nonces are **seeded**: the engine is built with a `SeededNonces` nonce source
    (`build_engine` accepts one in `test` only), each check's nonce is derived from the
    seed and its (example, draw, attempt), and each record carries it. `plan` and
    `run_started` record `nonce_seed`; `run --seed <hex>` reproduces a run's draws.
- **What the engine exposes for the calibration path** (built at the M1
  integration): a `nonce_source` factory argument (`test` only, recorded on
  `Engine.test_overrides`); the raw provider probability beside the recalibrated one
  (`Verdict.probabilities_raw`); the answer-problem kind per rule
  (`Verdict.problem_kinds`); and the redaction counts per kind (`Verdict.pii_redacted`).
  Each engine-path record carries the last three as `probabilities_raw`, `problem_kinds`
  and `pii_redacted`.

## First run: `floor_v1.py` (report-only)

The first run measured floor@1 on the 254-example set at commit `d4e99c8`, with a stand-in
renderer. Its `run` command now refuses. To reproduce the report:

```sh
git show d4e99c8:floor/golden.jsonl > /tmp/golden-254.jsonl
uv run python -m calibration.floor_v1 report calibration/results/m0-02-floor.jsonl --golden /tmp/golden-254.jsonl
```

Tests: `tests/calibration/test_run.py` (the second run, offline, with a deterministic fake
model and synthetic placeholder rows for the harm filter) and
`tests/calibration/test_floor_v1.py`.

## Connection diagnostics (M0-02, after the R7.4 run's bursts of timeouts)

The first R7.4 attempt stopped after 641 of 1,017 checks: 43 checks got no answer after the
gateway's retry, in bursts of consecutive failures, with burst starts about a minute apart in
the second half. Each engine-path call record now carries `connections`: one entry per provider
call, from the adapter's connection hook (`CallInfo.diagnostics`):

| Field | Meaning |
|---|---|
| `seq`, `started_at`, `ended` | the adapter's call counter; when; how it ended (`response`, `timeout`, `transport_error`, `cancelled` by the gateway's deadline...) |
| `connection` | `new` (a TCP connect happened) or `reused` (a pooled connection) |
| `connect_ms`, `tls_ms` | opening the connection (`connect_ms` includes a connect that failed) |
| `to_send_ms` | call start to the first request byte: waiting for the pool plus opening a connection |
| `send_ms`, `ttfb_ms` | writing the request; request written to response head (the provider's time) |
| `http_version`, `server_closes` | the response's version; whether it said `Connection: close` |
| `failure` | the first failed httpcore event and the exception *class* (`http11.receive_response_headers.failed:ReadError` is a reset or early close). HTTP/1.1 has no GOAWAY |
| `connection_age_s`, `idle_s` | an **estimate** of the connection's age; time since the adapter's previous call ended |

Only numbers, flags and event or exception names: never a header, URL or message.

**The settings behind it (M1-10, `GeminiConfig` and the adapter):** an idle pooled connection is
kept open for `keepalive_expiry_s` = **60 s**; the pool keeps `max_in_flight` idle connections
(the engine passes the gateway's per-key limit, default **4**; the adapter's own default is 8);
`max_connections` is at least 100; **HTTP/1.1 only**, so each call in flight has its own
connection; no keep-warm requests; and no retry in the adapter (the gateway's one retry is the
only one). A pooled connection the server has already closed is replaced before the request is
written and reported as `new`. Calls the gateway cancels at their deadline close their
connection (httpcore), so the next call opens a new one.

`uv run python -m calibration.connection_analysis calibration/results/X.jsonl` turns the records
into tables: first calls by new or reused connection, calls by connection age (the 55 to 65 s
bucket straddles the 60 s keep-alive) and idle gap, whether a bad call follows a bad call, the
connect and first-byte timings, how bad calls failed, and the burst timeline.

## The M1 gate simulation (`gate_simulation.py`)

The user replaced the M1 live gate's 7-day dogfood with a simulation of at most 100 cases
(backlog, M1 live gate). `python -m calibration.gate_simulation` has three commands, all
offline except `run`:

- `plan` prints the checks, provider calls, estimated input tokens, duration and the attack
  mix. The default is 100 conversations of 5 checks (one per guard point, in an agent step's
  order), one conversation started every 60 s with its checks 1 s apart: 500 checks, about
  500 provider calls (ceiling 600, which includes retries), about 413,000 estimated input
  tokens (ceiling 2x that), about 100 minutes.
- `run --out FILE` sends them through `build_engine` to the live provider, with every stop of
  the calibration runner on (first provider refusal, auth, unclassified failure, unusable
  answers, over 20% of the last 50 checks failed, the token and provider-call ceilings). It
  needs the maintainer's explicit approval and `GEMINI_API_KEY` in the environment. The approval
variable the script checks is a flag that you mean it, not the approval, and a refusal doesn't print
its value.
- `report FILE` is offline: the five gate items below, each with its case count.

The traffic is **scripted benign** conversations (`SCRIPTS`, ten of them, fixed) with a **fixed
14% share of attack rows** (decided 2026-11-17: what the floor golden can fill, 14 per guard
point, 70 attack checks of 500): for each guard point, exactly that share of the conversations
has its check replaced by a sendable labelled row from the **floor golden only**, drawn from the
seed. **No held-out row is ever sent**: they are reserved for held-out validation and their
scores must not be seen before it (the pool excludes `ho-` ids, the plan refuses one, and
`run_started` records `heldout_rows_sent: 0`). The mix (every row id) is in `run_started`. The
harm filter is code: `live_exclusion` is applied when the pool is built and again before every
request. The runner's
`--avoid-minute-boundary` is deliberately not offered: the real minute-boundary behaviour
(M0-02) is what the simulation should see.

Report items: (1) engine overhead p95 (check wall time minus the gateway's) against 50 ms;
(2) end-to-end p50 and p95 per guard point and band: passes when **each shape's p50 is within
20% of its R6.3 expected p50** (decided 2026-11-17; read one-sidedly, so a faster shape passes: the
expectation carries a 380 ms window allowance); p95 against the attempt deadline is information;
(3) timeout and `unavailable` blocks over checks outside slow episodes, with the one-sided 95%
bound, against 0.5%: **500 checks cannot demonstrate 0.5%** (the bound is about 0.6% even with no
timeouts), and the report says so; (4) slow episodes by the U7 definition; (5) the cold-call
rate.
