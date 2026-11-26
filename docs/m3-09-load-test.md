# M3-09 · Load test and capacity sign-off: the offline harness and the live plan

Status: **the harness is built and runs offline; the live runs are written and gated but have not been run, and no provider call was made.** Backlog: M3-09 (the first checkbox, "the load-test harness itself is built and runs against the fake", and the preparation for the two [LIVE] ones). Code: [`capacity/load_test.py`](../capacity/load_test.py) (harness and report), [`capacity/load_live.py`](../capacity/load_live.py) (live gates, plan and runner). Tests: `tests/capacity/test_load_test.py` and `tests/capacity/test_load_live.py`.

**The short answer**

1. `uv run python -m capacity.load_test simulate` builds the real engine with `build_engine`, drives it with simulated agent turns at a configurable tenant mix against the engine's fake model with **modelled latency**, on a **virtual clock** (an hour of load in about 8 seconds, the same seed gives the same report), and prints the report M3-09 asks for.
2. At the default mix (12 turns/min for an hour, Tier 1) the shared pool's turns cost **6.92 provider requests and 20,944 tokens** (3,028 a request). The **binding PF-4 limit is requests/day**: at most **47.7 turns/min** (tokens/min binds per minute) and **7,229 turns/day**. The S3 onboarding cap is **5,060 turns/day** (70%). Beyond PF-4's three, the **monthly spend cap binds first** at this check size (3,979 turns/day), so **70% of the real limit is 2,785 turns/day**. These are offline figures from the engine's own estimator; the live capacity run replaces them with Google's token counts. **They were 3,530 turns/day before the three findings below were fixed:** while a standard tenant's `tool_result` chunks were refused, the document tenant's turns cost far less than they do when they are answered, so the earlier sizing was about 21% too high.
3. Four things the offline run showed (section 5). Three were fixed on 2026-11-18: a tenant's burst is 60 s of its share and its bucket holds at least the largest single check; the chunks of one check are charged together and take one place in the fair queue. The monthly cap, not the daily request cap, is the real limit for S3; and the in-flight limit still binds chunk fan-out (the one finding that remains open, section 5).
4. The live mode is **dry by default** and needs `--live`, `GUARDRAILS_LIVE_LOADTEST=m3-09-capacity-signoff`, explicit ceilings on calls and tokens, and a key in the environment. The plan for the three live runs is in section 6: about **6,800 calls, 73M input tokens, $7.3 and 2.5 hours** in all. The user decides whether to run them.

## 1. Design

**The engine under test.** `capacity.load_test.load_engine` calls `build_engine` the way `calibration/pack_live.py` does: `test` environment (so `bootstrap_publish` is allowed), the platform floor, an in-memory catalog and directory, `NullAuditSink`, a signed context issued per check, and one published bundle per tenant (floor only, or floor plus the insurance or energy pack). The M3-10 token-rate limiter is on at the tier's published limits, the M3-07 tenant shares are on (switch off with `--no-quotas` to measure the pool alone), and a tenant given a `project` is regulated and served by a **dedicated project** (M5-06) with its own gateway, bucket and counters. Each pool (the shared one, each dedicated project) is reported on its own.

**Virtual time.** The engine runs on `VirtualLoop`, an asyncio event loop whose clock only moves when every task is waiting, and then jumps to the next timer. `asyncio.sleep`, the gateway's deadlines and retries, the bucket's refill and the policy cache all follow it. `build_engine` has no clock argument, so `virtual_clocks` gives the gateway and the Guard Service the loop's clock (and a wall clock that follows it, at noon Pacific so a run never crosses the day roll of the daily counter, and a seeded retry jitter) for the length of a run and restores them after. Two kinds of real work are *waited for, never skipped*: work in the executor (the engine runs redaction and the deny scan with `asyncio.to_thread`) and a loop with nothing scheduled. Without that, the result would depend on how fast a thread ran.

**Modelled latency (R6.3).** `LatencyModel` draws a call's duration from R6.3's expected-latency model, with the bands and the per-question slope read from `GatewayConfig`, never copied: median = band base (by input size) + window + 2 ms × questions; log-normal body (sigma 0.12, the M0-01 spread within a cell); and a 3% tail of 2 to 6 times (the slow window: 5 of 146 calls at 16K × 50 went past 1.6 × p50). The **window** is the time-of-day shift between 0 and R6.3's 380 ms allowance; the default is its midpoint, 190 ms, and `--slow-window` uses all 380. It is a parameterised model, to be re-fitted by the second-region profile (section 6b).

**Turn shapes and the mix.** A turn is `input`, `plan`, then `tool_call` and `tool_result` once per tool loop, then `output`: `3 + 2 × loops` checks, five at one loop. A `TurnShape` sets the size of each step, the tool loops (a count or a range) and whether checks carry the conversation so far (the SDK's default). A `tool_result` over `chunk_tokens` (12,000) is several provider calls. Four shapes ship: `chat` (one loop), `tool_loop` (2 to 4 loops), `document` (two loops, 30,000-token results, three chunks each) and `single_shot` (no loop). A mix is a list of tenants (weight, shape, optional pack, optional dedicated project); turns arrive as a Poisson process at `--turns-per-minute`, with 2.0 s of agent time between checks and 1.5 s of tool time. By default a turn runs all its checks even after a block (`--stop-on-block` for the product's behaviour): for capacity, the demand a turn *places* is what counts. The content is synthetic benign words (`benign_text`), sized exactly in estimated tokens.

**What is counted, and where.** Requests and tokens are counted **at the model**: every provider call the gateway started (a retry is a second call, a call it cancelled still counts) with its input tokens as the fake reports them, which is the engine's raw estimator, not Gemini's tokenizer. Refusals (`token_rate`, `admission_wait`, `admission_queue_full`, `quota_exhausted`, `orphan_cap`) and queue waits come from each check's verdict.

**The arithmetic** (`analyse_pool`, tested without an engine). Each of PF-4's three limits is turned into the turns it allows, sustained: per minute (a per-minute limit ÷ cost per turn; ×1,440 for a day) and per day (a daily limit ÷ cost per turn; ÷1,440 for a minute). The **binding limit is the one that allows the fewest**. The two limits beyond PF-4 (spend per 10 minutes, monthly spend cap) come from `capacity/model.py` and are marked, with their own `binding_all`, because the monthly cap binds first above about 1,667 tokens a check. **The daily cap is projected, never burned down:** the offered turns per minute × 1,440 × requests per turn. "Used" is the configured load as a share of each limit; "busiest minute" is the busiest full simulated minute's share of the per-minute limits. The **S3 cap** is 70% of the binding limit in turns/day, with its sustained turns/min and the 70% of the per-minute binding limit a busy minute may reach, and the same for the real binding limit when the monthly cap is lower. The engine's own limiter ceiling (68% of tokens/min, M3-10) and the admission ceiling (in-flight ÷ mean call time) are reported beside them.

## 2. How to run

```sh
export UV_CACHE_DIR=/tmp/uv-cache            # keep uv's cache off /home
uv run python -m capacity.load_test simulate                         # the default mix, 1 hour, about 8 s
uv run python -m capacity.load_test simulate --turns-per-minute 45 --minutes 20 --no-quotas
uv run python -m capacity.load_test simulate --slow-window --in-flight 8
uv run python -m capacity.load_test simulate --mix my_mix.json --json --out report.json
uv run python -m capacity.load_live plan                             # live call volume and cost
```

`--tier` takes the model's names (`"Tier 2"`), `--seed` changes the arrivals and the latency draws. A mix file:

```json
{"shapes": {"big_chat": {"user_tokens": 400, "tool_loops": [1, 3], "tool_result_tokens": 4000}},
 "tenants": [{"id": "t_a", "weight": 3, "shape": "big_chat"},
             {"id": "t_b", "weight": 1, "shape": "document", "pack": "energy"},
             {"id": "t_r", "weight": 1, "shape": "tool_loop", "project": "reg-1"}]}
```

### The remote mode (M7-10)

The harness above runs on a virtual clock, so it can't cross a process boundary. `capacity/load_remote.py`
is its real-time counterpart for the guard as its own service:

```sh
uv run --extra service python -m capacity.load_remote --turns-per-second 2 --seconds 15 --model-latency-s 0.3
```

It sends the same seeded turns (the five guard points, a tool loop, benign synthetic text) through the
SDK to **the guard service as a separate process** (`python -m guardrail_engine.service`, the fake
model answering after `--model-latency-s`) and, for comparison, to the same engine in this process.
`--mixed` makes the fake decide by markers in the text: one check in five is a block, an escalation, an
unavailable failure or a provider refusal, in a fixed pattern, so both modes see the same mix and the
outcome counts compare more than allows. It reports, per mode and per guard point, the end-to-end p50, p95 and p99, the throughput and the
outcomes by reason, with a check the client gave up on or couldn't send (`guard_unreachable`) counted
as its own outcome. The offered rate should stay under the key's capacity (4 in flight, so about
`4 / latency` checks a second), or both modes show the gateway's own `admission_wait` refusals, the
same ones. No provider is called. Run against one service process first; two replicas and the shared
counters wait for design step 5 of M7-10. The service's in-flight and queue-wait figures stay in its
audit records and are not on the wire.

The live runs' environment variable (`GUARDRAILS_LIVE_LOADTEST`) is a flag that you mean it, not the
user's approval, and a refusal doesn't print its value.

## 3. The default mix

| Tenant | Weight | Shape | Pool |
|---|--:|---|---|
| `t_chatty` | 4 | `chat` | shared |
| `t_agentic` | 2.5 | `tool_loop`, insurance pack | shared |
| `t_docs` | 0.5 | `document`, energy pack | shared |
| `t_reg` | 2 | `tool_loop` | dedicated project `reg-1` |

## 4. Sample offline report

`uv run python -m capacity.load_test simulate` (seed 309, 60 virtual minutes, 8 s of real time):

### The report (offline: fake model, modelled latency, virtual clock)

Offered 12 turns/min for 60 min (Tier 1, seed 309): 734 turns, 5,176 checks, 5,433 provider calls (60.2 virtual minutes). No provider was called.

#### What a turn costs

Mean over the mix: **7.05 checks**, **7.40 provider requests** and **23,498 tokens** per turn. Retried checks: 149.

| Shape | Turns | Checks/turn | Tool loops/turn | Chunks per tool result |
|---|--:|--:|--:|--:|
| chat | 331 | 5.00 | 1.00 | 1 |
| document | 36 | 7.00 | 2.00 | 3 |
| tool_loop | 367 | 8.91 | 2.95 | 1 |

#### Pool `shared` (Tier 1): 577 turns, 6.92 requests and 20,944 tokens per turn (3,028 per request)

Configured load: 9.6 turns/min = 67 requests/min and 201,412 tokens/min on average (busiest minute 128 requests, 388,261 tokens); projected 95,784 requests/day.

| Limit | Limit | Max turns/min | Max turns/day | Used at this load | Headroom | Busiest minute |
|---|--:|--:|--:|--:|--:|--:|
| requests/min | 1,500 requests/minute | 216.9 | 312,283 | 4.4% | 95.6% | 8.5% |
| tokens/min | 1,000,000 tokens/minute | 47.7 | 68,755 | 20.1% | 79.9% | 38.8% |
| **requests/day** | 50,000 requests/day | 5.0 | 7,229 | 191.6% | -91.6% | - |
| spend/10 min (beyond PF-4) | 10,000,000 tokens/minute | 477.5 | 687,545 | 2.0% | 98.0% | 3.9% |
| monthly spend cap (beyond PF-4) | 83,333,333 tokens/day | 2.8 | 3,979 | 348.0% | -248.0% | - |

- **Binding PF-4 limit: requests/day.** Per minute it is tokens/min (max **47.7 turns/min**); per day it is requests/day (max **7,229 turns/day**, 5.0/min sustained).
- **S3 onboarding cap (70% of the binding limit): 5,060 turns/day** (3.5 turns/min sustained; 33.4 turns/min in a busy minute).
- **Beyond PF-4, monthly spend cap binds first** at this check size: 3,979 turns/day, so 70% is **2,785 turns/day**. The lower figure is the one to onboard against.
- The engine's limiter holds the pool at 68% of tokens/min: it queues above 32.5 turns/min.
- Admission control (4 calls in flight on a key, mean call 478 ms) passes about 72.6 turns/min before checks queue or fail fast (`admission_wait`).
- After non-production's share of monthly spend cap, production may use 2,699 turns/day at 70% (M0-03).

#### Pool `reg-1` (Tier 1): 157 turns, 9.18 requests and 32,885 tokens per turn (3,580 per request)

Configured load: 2.6 turns/min = 24 requests/min and 86,050 tokens/min on average (busiest minute 62 requests, 238,391 tokens); projected 34,608 requests/day.

| Limit | Limit | Max turns/min | Max turns/day | Used at this load | Headroom | Busiest minute |
|---|--:|--:|--:|--:|--:|--:|
| requests/min | 1,500 requests/minute | 163.3 | 235,173 | 1.6% | 98.4% | 4.1% |
| tokens/min | 1,000,000 tokens/minute | 30.4 | 43,788 | 8.6% | 91.4% | 23.8% |
| **requests/day** | 50,000 requests/day | 3.8 | 5,444 | 69.2% | 30.8% | - |
| spend/10 min (beyond PF-4) | 10,000,000 tokens/minute | 304.1 | 437,884 | 0.9% | 99.1% | 2.4% |
| monthly spend cap (beyond PF-4) | 83,333,333 tokens/day | 1.8 | 2,534 | 148.7% | -48.7% | - |

- **Binding PF-4 limit: requests/day.** Per minute it is tokens/min (max **30.4 turns/min**); per day it is requests/day (max **5,444 turns/day**, 3.8/min sustained).
- **S3 onboarding cap (70% of the binding limit): 3,811 turns/day** (2.6 turns/min sustained; 21.3 turns/min in a busy minute).
- **Beyond PF-4, monthly spend cap binds first** at this check size: 2,534 turns/day, so 70% is **1,774 turns/day**. The lower figure is the one to onboard against.
- The engine's limiter holds the pool at 68% of tokens/min: it queues above 20.7 turns/min.
- Admission control (4 calls in flight on a key, mean call 483 ms) passes about 54.1 turns/min before checks queue or fail fast (`admission_wait`).
- After non-production's share of monthly spend cap, production may use 1,719 turns/day at 70% (M0-03).

#### Queue waits and refusals

Queue wait per check (ms): p50 0.0, p95 0.0, p99 0.0, max 56.9; 6 checks waited at all, 0 over 100 ms.

| Refusal (no provider call) | Checks |
|---|--:|
| token_rate | 12 |
| admission_wait | 18 |
| admission_queue_full | 0 |
| quota_exhausted | 0 |
| orphan_cap | 0 |

Per tenant (a tenant's own share, M3-07, is refused as `token_rate` too):

| Tenant | Pool | Shape | Turns | Checks/min (share) | Answered tokens/min (share) | Refused | Queue wait p95 (ms) |
|---|---|---|--:|--:|--:|--:|--:|
| t_chatty | shared | chat | 331 | 27.6 (60) | 37,138 (170,000) | 5 | 0.0 |
| t_agentic | shared | tool_loop | 210 | 31.3 (60) | 118,401 (170,000) | 12 | 0.0 |
| t_docs | shared | document | 36 | 4.2 (60) | 37,093 (170,000) | 13 | 0.0 |
| t_reg | reg-1 | tool_loop | 157 | 23.2 (120) | 82,986 (340,000) | 0 | 0.0 |

Refusal rate 0.580% of checks (`capacity_limited` on 31). Other non-allow outcomes: {'model_failure': 31}.

| Guard point | Checks | Wall p50 (ms) | p95 | p99 | Queue wait p95 (ms) |
|---|--:|--:|--:|--:|--:|
| input | 734 | 440 | 551 | 1,519 | 0.0 |
| plan | 734 | 440 | 571 | 1,522 | 0.0 |
| tool_call | 1,487 | 464 | 612 | 1,588 | 0.0 |
| tool_result | 1,487 | 500 | 684 | 1,712 | 0.0 |
| output | 734 | 492 | 652 | 1,683 | 0.0 |

At 45 turns/min for 20 minutes with the tenant shares off (`--no-quotas`), the shared pool is offered about 35 turns/min, past the limiter's 41 turns/min at the busiest minutes: 163 checks waited for admission (p99 88 ms, max 372 ms), and 230 were refused `token_rate` and 292 `admission_wait` (8.1% of checks).

## 5. What the offline run showed, and what was fixed

These follow from the engine as built and the assumptions above (the latency model, the shapes, the estimator's token counts). None was checked against the provider. Findings 2 to 4 below were fixed on 2026-11-18 (branch `token-bucket-fixes`); the numbers are the harness's own, seed 309, before and after.

**Before and after** (`simulate`, 60 virtual minutes; the agentic mix is [`capacity/mixes/agentic.json`](../capacity/mixes/agentic.json), 6 turns a minute: `t_agentic` `tool_loop` ×3, `t_docs` `document` ×1, `t_chat` `chat` ×1):

| Mix | | Checks | Refused `token_rate` | Refused `admission_wait` | Refusal rate | `t_agentic` refused | `t_docs` refused |
|---|---|--:|--:|--:|--:|--:|--:|
| default | before | 5,176 | 353 | 5 | 6.92% | 254 | 72 |
| default | after | 5,176 | 12 | 18 | 0.58% | 12 | 13 |
| agentic | before | 2,930 | 431 | 1 | 14.74% | 308 | 124 |
| agentic | after | 2,930 | 44 | 14 | 1.98% | 34 | 24 |
| default | sibling-aware allowance tried (slots only), dropped | 5,176 | 14 | 12 | 0.50% | 12 | 9 |
| agentic | sibling-aware allowance tried, dropped | 2,930 | 43 | 7 | 1.71% | 34 | 16 |
| documents (`capacity/mixes/documents.json`, 3 turns a minute) | no allowance (as kept) | 1,631 | 25 | 1 | 1.59% | `t_loop` 0 | `t_docs` 26 |
| documents | sibling-aware allowance tried, dropped | 1,631 | 32 | 1 | 2.02% | `t_loop` 5 | `t_docs` 28 |

`t_agentic` at about 55% of its share (93,000 of 170,000 tokens a minute) went from one check in seven refused to 0.6% (default, 118,000 tokens a minute after the change, 70% of its share) and 1.6% (agentic mix, 126,000 tokens a minute, 74% of its share). The document tenant's answered tokens a minute went from 4,282 to 37,093: its `tool_result` checks are now answered.

1. **The limit that binds is the daily one, and the monthly cap is lower still.** At 3,028 tokens a request the shared pool allows 7,229 turns/day on `requests/day` and 3,979 on the monthly spend cap. S3's cap should be taken from the lower, **2,785 turns/day** (70%), not 5,060. (This is M0-03's finding, reproduced on the engine's own shapes. The figure dropped from 3,530 when the document tenant's results began to be answered.)
2. **FIXED. A standard tenant could not send a multi-chunk `tool_result`** (the bucket held 34,000 tokens, 15 s of the 170,000 share; this document first said 13,077 and 5 s, which was the project's burst, not the tenant's. A chunk of a 12,000-token window costs about 15,000 with its questions, so the three chunks of a 30,000-token result were charged one by one: the first two took the bucket and the third was refused, and the whole result failed). Decision: a tenant's bucket holds **at least the largest single check it can compile** (`QuotaConfig.largest_check_tokens`, filled in from the platform settings as `max_chunks_per_result × (token_budget + critical-path question text)`, 4 × (16,000 + 7,500) = **94,000** at the defaults), and **the chunks of one check are charged together, all or none** (`CheckGroup`): if the share can't take them all, nothing is taken and every chunk is refused with the same `token_rate` and one retry hint. They are never sent in part. (The tenant bucket never queues, so "wait together" is "refused together, retry after the same time", which the bucket's size now makes a short wait.)
3. **FIXED. A busy agentic tenant at half its share was refused one check in seven.** Decision: **a tenant's burst is 60 s of its per-minute share.** The bucket refills at the share's own rate (a minute's share per minute) and holds a minute of it, where it held 15 s and refilled at 80% of the share, 136,000 a minute (a full bucket plus a minute of refill was exactly the share). **The trade-off:** a tenant that starts with a full bucket may spend up to **twice** its share in its first minute, and its sustained rate is the share. The project's own limiter (68% of the project's tokens a minute) and fair scheduling still hold the total, and the tier shares were already oversubscribed on purpose (four standard tenants are 100% of the project's target). A tenant that is refused is still refused at once, with a retry hint.
4. **Chunk fan-out and the in-flight limit: the decision is applied, and it does not remove `admission_wait`.** Decisions: the chunks of one check count as **one place in the fair queue** (they share one virtual start and finish, charged to the tenant once, so a chunk is never queued behind its own siblings; they still count as waiters toward the tenant's share of the queue, and the queue's room for the whole group is decided at its first chunk, so if a later chunk would be refused `admission_queue_full` none is sent and every chunk gets that refusal); and they are **still bounded by the per-key in-flight limit of 4** (each needs its own slot, R6.3 unchanged). The grouping alone changed nothing in the harness (identical counts with it switched off): `admission_wait` was 18 (default) and 14 (agentic), up from 5 and 1 only because the document tenant's chunks, once past the token bucket, met the in-flight limit.
   **A sibling-aware queue allowance was tried and dropped (2026-11-18).** The idea: a chunk may wait for its own siblings' calls, never for other tenants', so a chunk's queue allowance (400 ms for a `tool_result` call) would not count the time its siblings take, with the check's own budget (3,000 ms) still ending the wait. A first version also credited the project tokens the siblings had drawn; it turned out that once the bucket had refilled, other tenants' draws then read as zero wait and a chunk waited them out on the budget alone, so the second version covered slots only. **It was a wash:** default `admission_wait` 18 to 12 and the refusal rate 0.58% to 0.50%; agentic `admission_wait` 14 to 7 and 1.98% to 1.71%; but the documents mix got worse, 1.59% to 2.02% (`t_docs` 26 to 28, `t_loop` 0 to 5), because a chunk that waits for its siblings holds its place longer and the checks behind it meet a longer line. Dropped for the extra moving parts (the numbers above are the harness's own, seed 309). The gateway is as it was without it: a chunk that would wait past its allowance, whoever's calls it waits for, is refused `admission_wait` / `token_rate` at once. **What is left is the project's token bucket and the in-flight limit:** a three-chunk result is about 45,000 tokens against a 52,000-token project bucket that other tenants also draw from (M3-10, the 68% target, unchanged). The remaining levers are the project bucket's burst (never decided on) and splitting a result into fewer, larger calls: both deferred; the residual `admission_wait` (0.3% of checks in the default mix) is documented and accepted for now.
   **Floors and counts.** A tenant's check bucket holds at least one check per chunk (`largest_check_calls`, 4), since a group charges one check per chunk, as the token bucket holds at least 94,000. **A tenant whose share is below 94,000 tokens a minute** (a per-tenant override: the tiers are all above) has a 94,000-token bucket, not a minute's: its first-minute burst is well above twice its share (a 10,000-a-minute override can spend 94,000 at once and takes 9.4 minutes to refill). The floor stays because a bucket smaller than one whole check could never take it. The 50% per-tenant queue cap counts **waiters**, so a group of n chunks counts n. A store that fails while a group is being charged refunds the part-charge and fails every chunk of the group with `token_rate` (no chunk is sent).
5. **Retries stay small.** With the modelled tail, 149 of 5,176 checks (2.9%) retried: under the 5% hourly alert of R6.3.

## 6. The live mode (not run)

`capacity/load_live.py` has three runs. `capacity` drives the engine (real Gemini adapter) with the harness's turns on a ramp, and the other two call the adapter directly, as `bench/latency.py` does: they measure the provider, not the engine.

**Gates** (`refuse_to_start`, checked before any model, client or key is created). A **dry run** is the default: the same code with the modelled fake on a virtual clock. A **live** run needs all of: `--live`; `GUARDRAILS_LIVE_LOADTEST=m3-09-capacity-signoff` in the environment; explicit `--max-provider-calls` and `--max-tokens`, each at most the kind's hard ceiling and at least the plan's worst case; the plan itself under the hard ceilings; `GEMINI_API_KEY` in the environment (read from the environment only: never from a file, never printed or logged); and, for the two direct runs, at least 500 calls per cell. Hard ceilings:

| Run | Hard ceiling, calls | Hard ceiling, input tokens |
|---|--:|--:|
| `capacity` | 6,000 | 40,000,000 |
| `latency` | 800 | 8,000,000 |
| `largest` | 2,600 | 90,000,000 |

**What may be sent.** Synthetic, benign text only: plain words from a fixed list, and templated yes/no questions about scheduling and paperwork (`synthetic_questions`). No corpus row, no pack, no harm-labelled or `no_live_run` content, no dedicated projects. Before each call the text goes through the harm-vocabulary tripwire and `calibration.run.live_exclusion` (the send-time checks of `pack_live`); the run's question text is checked at plan time; and a compiled floor that carries the harm-facilitation rule is refused. **The first provider refusal stops the run**, as do `auth`, an unclassified failure, a 429 under the pacing and a failure rate over 20% of the last 50 calls; nothing is resent, and no call starts anywhere in the run after the stop (section 8). Records (`--out`, JSON lines) hold sizes, timings, outcomes and token counts, never content, headers, provider text or the key.

```sh
uv run python -m capacity.load_live plan                                      # no calls
uv run python -m capacity.load_live run --kind latency --out /tmp/lat.jsonl   # dry run
GUARDRAILS_LIVE_LOADTEST=m3-09-capacity-signoff GEMINI_API_KEY=... \
  uv run python -m capacity.load_live run --kind latency --out /tmp/lat.jsonl \
  --live --max-provider-calls 650 --max-tokens 4000000                        # live
```

### Plan and estimates

Price $0.10 per million input tokens (output is always 0). Tokens per call are R6.6's fitted API estimate of the call; the capacity run's per-turn cost comes from the offline simulation of its mix, so its figures move with Google's tokenizer. `uv run python -m capacity.load_live plan` prints these.

| Run | What | Calls | Input tokens | Cost | Time |
|---|---|--:|--:|--:|--:|
| (a) `capacity` | the engine, one project, floor-only; a ramp at 25, 50, 75 and 100% of the limiter's ceiling (29.5 turns/min for this mix), 8 minutes a step | 4,257 (worst case 5,321 with retries) | 13.6M (worst 17.0M) | $1.36 | 32 min |
| (b) `latency` | second-region profile: floor-sized cell (4K input, 12 questions), sequential, 500 + 5 warm-ups, 5,970 tokens a call | 505 | 3.01M | $0.30 | 6 min |
| (c) `largest` | the largest compilable calls (R6.7), 500 + 5 each: full `input` check (13,308-token text, 200 questions of about 70 tokens, 35,142 tokens a call) and full critical-path check (same text, 50 questions, 20,778 tokens a call), each sequential and at 4 in flight | 2,020 (4 cells of 505) | 56.5M | $5.65 | 113 min |
| **All three** | | **6,782** | **73.1M** | **$7.31** | **about 2.5 h** |

Notes:

* **(a)** The ramp is fractions of the limiter's ceiling, 29.5 turns/min for the capacity run's own mix (floor-only, so tokens per turn are 23,000), up to the 680,000 tokens/min the limiter allows. The top step is the one that shows whether the limiter holds at 68% and whether anything queues or refuses. The tenant shares are off (the pool is under test); the findings of section 5 stay open until they are decided.
* **(b)** Run it from a host in the second region: the command does not choose a region, the host does. 505 calls at the pacing (half of Tier 1's tokens/min) take about 6 minutes; the report compares the p50, p95 and p99 with R6.3's expected p50 and attempt deadline for the cell (675 and 1,080 ms) and counts calls over the deadline.
* **(c)** *Largest compilable*: R6.7's content bound `1.20 × text + 30 ≤ 16,000` allows 13,308 estimated tokens of text, which is what "16K content" means in API tokens; M0-01's 16K cell used 16,000 raw tokens, which is more than the compiler would accept. Concurrent cells run at 4 in flight, the R6.3 default; if the dogfood trial settles another limit, change `largest_cells(concurrency=...)`. The pacing keeps each cell at half of the tokens/min, so a 35,000-token call is sent about every 4.2 s.
* Against the quotas: 6,782 calls are 14% of one day's 50,000 requests, and $7.31 is 3% of Tier 1's $250 monthly cap. They spend the one project's quota (M0-03: there is no second project), so run them while no tenant is enforcing, which S3 says is the case until these gates pass.
* The three runs are independent commands: the user can approve any of them alone.

## 7. Not done

* No live call, no key read, no `.env` opened. The live runner's keyed paths (`make_live_model`, the real adapter) were exercised only as far as the gates refusing; the tests assert the adapter is never constructed.
* The latency model's parameters are assumptions fitted to R6.3's documented figures, not re-fitted; section 6b does that.
* Offline tokens are the engine's raw estimator; Google's count is about 1.2 times it for text (R6.6), and the capacity run measures it.
* The harness has no migrations and needs no Postgres.

## 8. Live gates: fixes

Three issues in how a live run behaves once it has started, one major and two minor. All three are fixed in `capacity/load_live.py` (and the driver in `capacity/load_test.py`); no live call was made, and the tests use fake providers only.

**(major): a stop is a state, and nothing starts after it.** Before, the stop was an exception in the one task that saw it. Turns already running in the capacity run went on through their steps, and a concurrent cell sent one more paced call. Now:

* `Ledger.stopped` holds the first reason and `Ledger.stop_event` is set with it. `stop` is the only way any rule stops the run (a provider refusal, `auth`, an unclassified failure, a 429 under the pacing, the failure rate over 20% of the last 50 calls, a ceiling, a refused send), so every reason has the same guarantee. A second stop records nothing more.
* **Every send is checked immediately before it goes out.** `Ledger.send` is the one way a call is made. It reserves the call (which raises once the run has stopped) and calls the model with nothing between that can yield. A direct cell checks the stop after every wait for a slot and again after the pacing sleep, and the sleep wakes on the event. In the capacity run, `CapacityObserver.before` raises once the run has stopped, and `GatedModel` sits below the gateway, so a call the gateway would make on its own (a retry, a chunk) is stopped too: it comes back as `Failed(OTHER)`, which the gateway never retries.
* **The driver wakes on the stop.** `load_test.drive` sleeps to the next arrival with `sleep_unless_stopped`, and waits for the turns with `_gather_unless_stopped`, so the run ends at the refusal rather than at the next arrival or the end of a turn. It starts no further turn, cancels those in flight and raises the stop.
* **Calls in flight at the stop may finish, are never retried, and are recorded.** Their `call` and `check` records carry `"after_stop": true`; a call cancelled in flight is a `call_cancelled` record and counts in full against the ceilings.

**(minor): the ceilings count reservations.** `Ledger.reserve(calls, tokens)` checks `used + reserved + this call` against each ceiling, so calls in flight count, and `settle` swaps the reservation for what the call used (the provider's reported input tokens, else the estimate). A call is reserved per provider call (the fitted API estimate of its text and questions, R6.6), not per check, so a chunked `tool_result` reserves one call per chunk and a gateway retry reserves its own. A send that would pass a ceiling is refused before it starts. The probes now give 10 sent against a ceiling of 10 (a c4 cell; it was 12) and 30 against 30 (the capacity run; it was 31). The token ceiling is checked against estimates, and the settled figure is what was reported, so it can be exceeded only if the provider reports more than the fitted estimate; the next reservation is then refused.

**(minor): the plan is what is sent.** `plan(kind, calls, step_minutes, seed)` now takes every flag that shapes a run, and `plan` has `--step-minutes` and `--seed` too. The capacity worst case, and so every gate (the hard ceilings, the explicit ceilings against the worst case), is computed from the effective plan: a live `--step-minutes 30` is a 120-minute plan of about 3.75 times the default's calls, and is refused as over the hard ceilings. The runner takes its steps (minutes and rate) from that same plan rather than from the flag again, so the two cannot differ.

**(minor, follow-up): the stop is set where the refusal arrives.** The stop on a refusal was set at the check level (`CapacityObserver.after`), once the engine had turned the `SafetyBlocked` into a verdict, which was safe only while nothing in the engine's path from the model's return to the verdict could yield (a future audit or metrics write would have reopened it). `GatedModel.decide` now calls `Ledger.stop` itself, in the step that returns the result, when the call came back `SafetyBlocked` (`provider_refusal`) or `Failed(AUTH)` (`auth`). The result is still returned, so the engine records the check as before; the later stop at the check level is a second stop and records nothing more. The refusing call's own `check` record therefore carries `after_stop: true` too. Tests: the stop is set, with its event, when `decide` returns (before the engine does anything); a later call is refused at the gate and never reaches the provider; a timeout does not stop the run; and with `CapacityObserver.after` made a no-op the capacity run still stops at the refusal and starts no later call.

Tests (`tests/capacity/test_load_live.py`): a fake `Provider` refuses on demand and records whether the run had already stopped when each call started. A refusal on call 40 of the capacity run starts no further call; a refusal in a c4 cell at pace 0.7 and 0.9 starts none; the same for `auth`, `other`, a 429, the failure rate and both ceilings, in the cell and the capacity run; the pacing sleep ends at the stop; 12-vs-10 and 31-vs-30 are 10 and 30; `--step-minutes 30` is refused whatever ceilings it is given.
