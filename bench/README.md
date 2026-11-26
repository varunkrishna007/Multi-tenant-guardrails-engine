# Benchmarks

## M0-01: Decisions API latency profile

`latency.py` measures the real Gemini Decisions API through `GeminiDecisionModel`, so the
numbers are what the engine pays, including request building, parsing and validation.

**What it runs**

- Grid of 16 cells: input size 1K, 4K, 8K and 16K estimated tokens × 1, 50, 200 and 900
  questions.
- Within a cell, calls are sequential on one reused client, after `--warmup` calls that are
  discarded. The measured numbers are therefore uncontended and exclude connection setup.
- `connect_in1k_q1`: the first call on a fresh client, repeated `--connect-samples` times. This
  includes DNS, TCP and TLS setup.
- `in4k_q50_c8`: the 4K × 50 cell at 8 concurrent calls on one client.

**Inputs**

- Content is built from `floor/golden.jsonl`, shuffled per call (a seeded CRC of
  cell, phase and sequence number), inside the B3 nonce-delimited frame. No two calls send
  the same bytes.
- Questions are the six floor rules followed by deterministic templated yes/no variants, all
  with both descriptions. The templated questions average about 87 estimated tokens each.

**Limits and safety**

- A sliding 60-second throttle keeps the run under 70% of Tier 1's per-minute limits:
  700,000 tokens and 1,050 requests. Each call reserves its estimated tokens times the largest
  API/estimate ratio seen so far, and the reservation is corrected to the API's count after the
  call.
- After a `rate_limited` result the run backs off for 5, 10, 20, 40 and then 60 seconds.
- The run stops at the first `auth` result.
- A cell stops once more than 20% of its planned calls have failed.

**Records**

- Every call is appended to the `--out` JSONL file. A rerun with the same file resumes and
  makes no repeat calls.
- Records hold sizes, timings, outcomes and token counts, but no content, no headers and no
  key.

### Commands

From the repository root, with the key in the gitignored `.env`. Never echo it.

```sh
set -a; . ./.env; set +a
GEMINI_PAID_TIER=true uv run python bench/latency.py run \
    --out bench/results/m0-01-pilot.jsonl --per-cell 30 --warmup 3 --connect-samples 3

uv run python bench/latency.py report bench/results/m0-01-pilot.jsonl
```

`--corpus` and `--rules` default to `floor/golden.jsonl` and `floor/rules.json`.

The pilot (30 measured calls per cell) is about 560 calls and 17M input tokens, and takes
roughly half an hour under the throttle. The backlog's full run (500 per cell) is about
8,500 calls; run it only on explicit request.

The pure parts (percentiles, throttle, input and question builders, resume and stop rules)
are tested offline in `tests/bench/`.

## Why the bench doesn't use `build_engine`

`bench/latency.py` measures the Gemini adapter and the provider on their own, so it builds
the adapter directly. That is decided (M1-11, 2026-11-17): latency benches may keep their own
wiring. Anything that scores examples to set or validate thresholds goes through the engine
built by `build_engine` (`calibration/engine_path.py`), and so does the demo
(`demo/run_demo.py`).

## M7-10: the process boundary

`wire_overhead.py` sends the same checks to an in-process engine and to the guard service running
as a separate process, and reports the difference. Offline: the fake model answers at once.

    uv run --extra service python -m bench.wire_overhead --requests 800 --out result.md

Result: `results/m7-10-wire-overhead.md`.
