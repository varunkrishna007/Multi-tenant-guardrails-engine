# M7-10 · What the process boundary costs a check (offline)

`bench/wire_overhead.py`, 800 checks per size and mode, on the 8-core development machine, 2026-11-24.
The engine and the fake model (answering at once) are the same in both modes; **in process** is
`Guard(engine)` in the benchmark process, **remote** is `connect(url)` to `python -m
guardrail_engine.service` in a separate process (real uvicorn, FastAPI, JSON, the signed-context
check), over loopback with no TLS. Every request is different text. No provider is called.

| Body | In process, sequential p50 / p95 / p99 (ms) | Remote, sequential p50 / p95 / p99 (ms) | Boundary, p50 (ms) | In process, 16 at a time (ms) | Remote, 16 at a time (ms) | Checks per second, in process / remote |
|---|---|---|---|---|---|---|
| 200 B | 0.66 / 1.11 / 1.27 | 2.66 / 3.77 / 4.39 | 2.00 | 0.48 / 8.26 / 10.04 | 21.61 / 35.14 / 50.91 | 1845 / 424 |
| 2 KB | 1.10 / 1.76 / 2.39 | 3.30 / 3.82 / 4.65 | 2.20 | 0.84 / 13.52 / 14.78 | 21.73 / 35.79 / 57.12 | 1111 / 429 |
| 24 KB | 6.64 / 14.50 / 25.77 | 8.20 / 11.34 / 13.34 | 1.56 | 63.00 / 109.86 / 120.86 | 114.54 / 178.90 / 334.67 | 140 / 120 |

What it says:

* **The boundary adds about 2 ms at the median** (1.6 to 3.1 ms across bodies of 200 B, 2 KB and
  24 KB, and across two runs), and under 5 ms at the 99th percentile for the small bodies. Against
  the 3 s cap (4 s at `input`) that is about 0.07%, and about 0.3% of the expected 0.63 s model call.
  It changes no budget. (The 24 KB figures are noisy: the engine's own work there is 6 ms, and its
  p99 varies by more than the boundary does.)
* The first design note's offline figure (1.4 ms, a minimal server) was a floor; the real stack costs
  about 0.6 ms more.
* One service process answered about 120 to 430 checks a second with a model that answers at once.
  The provider limits a key to roughly 6 calls a second at 4 in flight, so the service's own
  throughput is not the bottleneck; the 16-at-a-time latencies are that queue, not network time.
* Loopback, no TLS and a model with no latency: a deployment adds its network and the handshake once
  per connection (keep-alive).
