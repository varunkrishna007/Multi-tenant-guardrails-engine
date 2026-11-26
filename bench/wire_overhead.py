"""M7-10: what the process boundary costs a check. Offline: the fake model answers at once, so
every millisecond measured is the engine's own work plus, for the remote mode, the wire.

    uv run --extra service python -m bench.wire_overhead --out bench/results/m7-10-wire-overhead.md

It builds one engine in this process (the **in-process** mode) and starts the guard service as a
separate process (``python -m guardrail_engine.service``, the real uvicorn stack, on loopback,
the same fake model), and sends the same checks to both, sequentially on one connection and then
16 at a time. The difference between the two columns is the boundary: JSON, the HTTP/1.1
request, the signed-context verification the service does anyway, and the client. No TLS and no
network beyond loopback, so it is a floor for a real deployment. No provider is ever called.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from guardrail_engine.decision import FakeDecisionModel
from guardrail_engine.engine import EngineSettings, build_engine
from guardrail_engine.guard import HmacContextVerifier, InMemoryTenantDirectory, TenantProfile
from guardrail_engine.policy import TenantAttributes
from guardrail_engine.sdk import Guard, GuardContext
from guardrail_engine.sdk.adapters.remote import connect

ROOT = Path(__file__).resolve().parents[1]
TENANT = "t_bench"
SIZES = (("200 B", 200), ("2 KB", 2_000), ("24 KB", 24_000))
WORDS = "the quick brown fox jumps over the lazy dog and files a travel claim for a train fare "


def text_of(size: int, salt: int) -> str:
    body = (f"{salt} " + WORDS * (size // len(WORDS) + 1))[:size]
    return body


def pct(values: list[float], p: float) -> float:
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(len(ordered) * p))]


def row(values: list[float]) -> str:
    ms = [v * 1000 for v in values]
    return f"{pct(ms, 0.5):.2f} / {pct(ms, 0.95):.2f} / {pct(ms, 0.99):.2f}"


async def in_process_engine(key: bytes):
    settings = EngineSettings.from_mapping(
        {
            "environment": "test",
            "catalog": {"floor_files": [str(ROOT / "floor" / "rules.json")]},
            "signed_context": {"allow_v1_hmac": True},
            "guard": {"repeat_threshold": 0},
        }
    )
    profile = TenantProfile.build(
        TenantAttributes(tenant_id=TENANT, tier="standard"), "insurance", slug="bench"
    )
    engine = await build_engine(
        settings,
        verifier=HmacContextVerifier(key),
        tenants=InMemoryTenantDirectory([profile]),
        model=FakeDecisionModel(),
    )
    await engine.bootstrap_publish(
        {"schema_version": 1, "tenant_id": TENANT, "version": 1, "extends": ["platform/floor@1"]}
    )
    return engine


def start_service(key_file: Path) -> tuple[subprocess.Popen[str], str]:
    settings = key_file.with_suffix(".settings.json")
    settings.write_text(json.dumps({"guard": {"repeat_threshold": 0}}))
    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "guardrail_engine.service",
            "--signing-key-file",
            str(key_file),
            "--tenant",
            TENANT,
            "--settings",
            str(settings),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    assert proc.stdout is not None
    return proc, json.loads(proc.stdout.readline())["listening"]


async def measure(guard: Guard, ctx: GuardContext, size: int, n: int, wide: int) -> dict:
    # Every request is different text, so nothing is answered from a cache or a repeat count.
    for i in range(50):  # warm up
        await guard.check("input", text_of(size, -i - 1), ctx)
    seq: list[float] = []
    for i in range(n):
        started = time.perf_counter()
        result = await guard.check("input", text_of(size, i), ctx)
        seq.append(time.perf_counter() - started)
        assert result.released, result
    conc: list[float] = []

    async def one(i: int) -> None:
        started = time.perf_counter()
        await guard.check("input", text_of(size, 1_000_000 + i), ctx)
        conc.append(time.perf_counter() - started)

    began = time.perf_counter()
    for batch in range(n // wide):
        await asyncio.gather(*[one(batch * wide + j) for j in range(wide)])
    elapsed = time.perf_counter() - began
    return {"seq": seq, "conc": conc, "per_s": (n // wide * wide) / elapsed}


async def run(n: int, wide: int) -> str:
    key = b"bench signing key, 32+ bytes long........"
    with tempfile.TemporaryDirectory() as tmp:
        key_file = Path(tmp) / "key.bin"
        key_file.write_bytes(key)
        key_file.chmod(0o600)
        engine = await in_process_engine(key)
        proc, url = start_service(key_file)
        ctx = GuardContext(signed_context=HmacContextVerifier(key).issue(TENANT))
        remote = connect(url, max_connections=wide * 2)
        local = Guard(engine)
        lines = []
        try:
            for label, size in SIZES:
                a = await measure(local, ctx, size, n, wide)
                b = await measure(remote, ctx, size, n, wide)
                delta = statistics.median(b["seq"]) - statistics.median(a["seq"])
                lines.append(
                    f"| {label} | {row(a['seq'])} | {row(b['seq'])} | {delta * 1000:.2f} | "
                    f"{row(a['conc'])} | {row(b['conc'])} | {a['per_s']:.0f} / {b['per_s']:.0f} |"
                )
        finally:
            await remote.aclose()
            await engine.shutdown()
            proc.terminate()
            proc.wait(timeout=20)
    header = (
        "| Body | In process, sequential p50 / p95 / p99 (ms) | Remote, sequential p50 / p95 / p99 "
        f"(ms) | Boundary, p50 (ms) | In process, {wide} at a time (ms) | Remote, {wide} at a "
        "time (ms) | Checks per second, in process / remote |\n"
        "|---|---|---|---|---|---|---|\n"
    )
    return header + "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--requests", type=int, default=800, help="per size and mode")
    p.add_argument("--concurrency", type=int, default=16)
    p.add_argument("--out", type=Path)
    args = p.parse_args(argv)
    table = asyncio.run(run(args.requests, args.concurrency))
    print(table)
    if args.out:
        args.out.write_text(table)
    return 0


if __name__ == "__main__":
    sys.exit(main())
