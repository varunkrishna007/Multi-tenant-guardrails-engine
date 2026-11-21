# Network probe across minute boundaries (2026-11-17, zero API calls)

`python -m calibration.network_probe run`, 15:26:53-15:32:40 UTC, 345 seconds, six minute
boundaries (15:27 to 15:32). It opened TCP+TLS connections to
`generativelanguage.googleapis.com:443` and **sent no bytes after the handshake**: no HTTP
request, no key, no header, no API call. Records: `m0-02-net-probe.jsonl` (no key, no header).

Each second, a fresh connection (TCP connect + TLS handshake, closed at once). Every 7 s, a kept
connection (never written to; up to 12 open, so up to 84 s old), watched for a close or reset
by the peer, with TCP keep-alive probes on (idle 5 s, every 1 s, 3 misses).

## What it shows

- **No stall on fresh connections, at any second of the minute.** 345 of 345 handshakes
  succeeded; the median is 124-146 ms in every bucket and the worst is 1.5 s. Around the top of
  the minute (:55-:09: 90 probes) the median is 128.5 ms, 2 probes took over 1 s (1.2 s and 1.5 s),
  none failed. In the R7.4 runs, 34% of the checks started in that window failed after waiting
  the full deadline (about 1 s per call).
- So the stall is not in reaching the edge or in TLS: a new TCP+TLS connection is accepted
  promptly through the boundary, from this host, at the same time of day.
- **One kept connection was reset by the peer**, at 15:31:08.5 (second :08.5), age 51.5 s
  (`ConnectionResetError`). The other 49 were retired by us unclosed, the oldest at 84 s.
  A single reset at a non-boundary second is not a pattern.

## What it does not show

- The probe never sends an HTTP request, so it cannot see a stall that happens **after** the
  handshake (the request is written, the response head never comes), which is the shape of the
  R7.4 failures. It rules out the connect/TLS stage, not the API or an HTTP-level proxy.
- The kept connections carry TCP keep-alive probes (5 s idle), so they do not test an idle limit
  of a middlebox: the keep-alives are traffic to it. The adapter's own idle gaps are not tested.
- It is one 6-minute sample; whether the R7.4 stalls were present at the same time is unknown
  (the probe ran 3 minutes after that run ended).

## Reading, together with the R7.4 records

The R7.4 failures happen on established connections, after the request is written, and cluster
around the top of the minute (and, with the flag, right after a 15 s wait). New connections
reach the edge normally through the boundary. That points at the request/response stage (the
API or something HTTP-aware in front of it) and at pooled connections, not at TCP or TLS. The
next step to separate them, if wanted, is a probe that sends a real but trivial request (an API
call: needs the maintainer's explicit approval and the key), alternating a fresh and a pooled
connection each second across boundaries.

## Tables

### Fresh TCP+TLS connections, one per second

- 345 probes, 0 failed ; slow = over 1000 ms.

| Second of the minute | Probes | Failed | Slow | Median ms | Max ms | Kept closed |
|---|--:|--:|--:|--:|--:|--:|
| :00-:09 | 60 | 0 | 1 | 124.5 | 1177 | 1 |
| :10-:19 | 60 | 0 | 0 | 128.5 | 906 | 0 |
| :20-:29 | 60 | 0 | 0 | 130.5 | 490 | 0 |
| :30-:39 | 59 | 0 | 0 | 144 | 589 | 0 |
| :40-:49 | 50 | 0 | 1 | 139.5 | 1215 | 0 |
| :50-:54 | 26 | 0 | 0 | 146.0 | 511 | 0 |
| :55-:59 | 30 | 0 | 1 | 139.0 | 1512 | 0 |

### Kept connections closed by the peer

| Second | Age (s) | How |
|--:|--:|---|
| 8.509 | 51.509 | ConnectionResetError |
