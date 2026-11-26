"""M3-09 / M7-10: the load test's remote mode, in real time.

    uv run --extra service python -m capacity.load_remote --turns-per-second 20 --seconds 20

The virtual-clock harness (``capacity.load_test``) can't cross a process boundary, so this driver
runs on the real clock: simulated agent turns (the five guard points in order, a tool loop in the
middle, benign synthetic text only) are sent through the SDK's ``Guard`` to **the guard service
as a separate process** (``python -m guardrail_engine.service``, the fake model answering after
``--model-latency-s``), and, for comparison, to the same engine in this process. The arrival
schedule is seeded, so both modes get the same turns at the same times, and the difference between
them is the boundary.

What it reports, per mode and per guard point: the checks, the throughput, the end-to-end latency
(p50, p95, p99) and the outcomes by reason. A check the client gave up on or couldn't send
(``guard_unreachable``) is **its own outcome**, apart from the service's own ``model_failure``
reasons. The service's in-flight and queue-wait figures live in its audit records, not on the wire,
so they are not here. **No provider is ever called**: the model is the fake in both modes.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import random
import subprocess
import sys
import tempfile
import time
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from capacity.load_test import benign_text
from guardrail_engine.guard.request import Plan, ToolCall, ToolResult, Turn
from guardrail_engine.sdk import Guard, GuardContext
from guardrail_engine.sdk.adapters.remote import connect

TENANT = "t_load"
KEY = b"load test signing key, 32+ bytes long...."
TOOL = "records.lookup"
SHAPE = {"input": 300, "plan": 200, "tool_call": 100, "tool_result": 1_500, "output": 400}


@dataclass
class Sample:
    guard_point: str
    seconds: float
    decision: str
    reason: str
    failure_reason: str | None


def pct(values: list[float], p: float) -> float:
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(len(ordered) * p))] if ordered else 0.0


MARKER_CYCLE = 20
MARKERS = {0: "[mix:block]", 5: "[mix:escalate]", 10: "[mix:fail]", 15: "[mix:refuse]"}
"""``--mixed``: one check in five carries a marker the marked fake decides by (a block, an
escalation, an unavailable failure, a provider refusal), in a fixed pattern over the turn number
and the step, so both modes get the same mix."""


async def turn(
    guard: Guard, signed: str, number: int, loops: int, out: list[Sample], mixed: bool = False
) -> None:
    conversation: list[Any] = []
    steps = [("input", None), ("plan", None)]
    for _ in range(loops):
        steps += [("tool_call", TOOL), ("tool_result", TOOL)]
    steps.append(("output", None))
    for index, (guard_point, tool) in enumerate(steps):
        content = benign_text(SHAPE[guard_point], number * 31 + index)
        if mixed:
            content = MARKERS.get((number * 7 + index) % MARKER_CYCLE, "") + content
        ctx = GuardContext(
            signed_context=signed,
            conversation=tuple(conversation),
            tool=tool,
            conversation_id=f"c{number}",
        )
        started = time.perf_counter()
        result = await guard.check(guard_point, content, ctx)
        out.append(
            Sample(
                guard_point,
                time.perf_counter() - started,
                result.decision,
                result.reason,
                result.failure_reason.value if result.failure_reason else None,
            )
        )
        if not result.released:
            return
        item = {
            "input": Turn("user", content),
            "plan": Plan(content),
            "tool_call": ToolCall(TOOL, content),
            "tool_result": ToolResult(TOOL, content),
            "output": Turn("assistant", content),
        }[guard_point]
        conversation.append(item)


async def drive(
    guard: Guard, signed: str, arrivals: list[float], loops: list[int], mixed: bool = False
) -> dict:
    samples: list[Sample] = []
    began = time.perf_counter()
    tasks = []

    async def at(when: float, number: int) -> None:
        await asyncio.sleep(max(0.0, began + when - time.perf_counter()))
        await turn(guard, signed, number, loops[number], samples, mixed)

    for number, when in enumerate(arrivals):
        tasks.append(asyncio.ensure_future(at(when, number)))
    await asyncio.gather(*tasks)
    return summarise(samples, time.perf_counter() - began)


def summarise(samples: list[Sample], elapsed: float) -> dict:
    by_point: dict[str, list[float]] = defaultdict(list)
    for s in samples:
        by_point[s.guard_point].append(s.seconds)
    outcomes = Counter(
        f"{s.decision}/{s.reason}" + (f"/{s.failure_reason}" if s.failure_reason else "")
        for s in samples
    )
    return {
        "checks": len(samples),
        "checks_per_s": round(len(samples) / elapsed, 1),
        "latency_ms": {
            point: [round(pct(v, p) * 1000, 1) for p in (0.5, 0.95, 0.99)]
            for point, v in sorted(by_point.items())
        },
        "outcomes": dict(sorted(outcomes.items())),
        "guard_unreachable": sum(1 for s in samples if s.failure_reason == "guard_unreachable"),
    }


def gateway_mapping(in_flight: int | None) -> dict[str, Any]:
    """The gateway settings of both modes: no provider-health breaker (it would answer checks
    without sending them), and the in-flight limit if one is asked for (the key's default is 4)."""
    mapping: dict[str, Any] = {"degraded_consecutive": 0, "degraded_window_calls": 0}
    if in_flight is not None:
        mapping["max_in_flight_per_key"] = in_flight
    return mapping


def schedule(rate: float, seconds: float, seed: int) -> tuple[list[float], list[int]]:
    rng = random.Random(seed)
    arrivals, now = [], 0.0
    while True:
        now += rng.expovariate(rate)
        if now >= seconds:
            break
        arrivals.append(now)
    return arrivals, [rng.choice((1, 1, 2)) for _ in arrivals]


async def in_process_guard(
    model_latency_s: float, mixed: bool = False, in_flight: int | None = None
) -> tuple[Guard, Any]:
    from guardrail_engine.decision import FakeDecisionModel, MarkedFakeDecisionModel
    from guardrail_engine.engine import EngineSettings, build_engine
    from guardrail_engine.guard import HmacContextVerifier, InMemoryTenantDirectory, TenantProfile
    from guardrail_engine.policy import TenantAttributes

    fake_class = MarkedFakeDecisionModel if mixed else FakeDecisionModel
    root = Path(__file__).resolve().parents[1]
    settings = EngineSettings.from_mapping(
        {
            "environment": "test",
            "catalog": {"floor_files": [str(root / "floor" / "rules.json")]},
            "signed_context": {"allow_v1_hmac": True},
            "guard": {"repeat_threshold": 0},
            "gateway": gateway_mapping(in_flight),
        }
    )
    profile = TenantProfile.build(
        TenantAttributes(tenant_id=TENANT, tier="standard"), "insurance", slug="load"
    )
    engine = await build_engine(
        settings,
        verifier=HmacContextVerifier(KEY),
        tenants=InMemoryTenantDirectory([profile]),
        model=fake_class(latency_s=model_latency_s),
    )
    await engine.bootstrap_publish(
        {"schema_version": 1, "tenant_id": TENANT, "version": 1, "extends": ["platform/floor@1"]}
    )
    return Guard(engine), engine


def start_service(
    tmp: Path, model_latency_s: float, mixed: bool = False, in_flight: int | None = None
) -> tuple[subprocess.Popen[str], str]:
    key_file = tmp / "key.bin"
    key_file.write_bytes(KEY)
    key_file.chmod(0o600)  # the runner refuses a key file anyone else can read
    settings = tmp / "settings.json"
    settings.write_text(
        json.dumps(
            {
                "guard": {"repeat_threshold": 0},
                "gateway": gateway_mapping(in_flight),
            }
        )
    )
    proc = subprocess.Popen(
        [
            sys.executable, "-m", "guardrail_engine.service",
            "--signing-key-file", str(key_file), "--tenant", TENANT,
            "--settings", str(settings), "--fake-latency-s", str(model_latency_s),
            "--fake-behaviour", "marked" if mixed else "allow",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )  # fmt: skip
    assert proc.stdout is not None
    return proc, json.loads(proc.stdout.readline())["listening"]


async def run(args: argparse.Namespace) -> dict:
    from guardrail_engine.guard import HmacContextVerifier

    signed = HmacContextVerifier(KEY).issue(TENANT)
    arrivals, loops = schedule(args.turns_per_second, args.seconds, args.seed)
    report: dict[str, Any] = {
        "turns": len(arrivals),
        "turns_per_second": args.turns_per_second,
        "model_latency_s": args.model_latency_s,
    }
    if args.mode in ("both", "in-process"):
        guard, engine = await in_process_guard(args.model_latency_s, args.mixed, args.in_flight)
        try:
            report["in_process"] = await drive(guard, signed, arrivals, loops, args.mixed)
        finally:
            await engine.shutdown()
    if args.mode in ("both", "remote"):
        with tempfile.TemporaryDirectory() as tmp:
            proc, url = start_service(Path(tmp), args.model_latency_s, args.mixed, args.in_flight)
            guard = connect(url, max_connections=args.pool, margin_s=args.margin_s)
            try:
                report["remote"] = await drive(guard, signed, arrivals, loops, args.mixed)
            finally:
                await guard.aclose()
                proc.terminate()
                proc.wait(timeout=30)
                assert proc.stdout is not None
                proc.stdout.close()
    return report


def render(report: dict) -> str:
    lines = [
        f"{report['turns']} turns at {report['turns_per_second']}/s, the model answering after "
        f"{report['model_latency_s']} s. Latency p50 / p95 / p99 in ms."
    ]
    for mode in ("in_process", "remote"):
        if mode not in report:
            continue
        r = report[mode]
        lines.append(f"\n{mode.replace('_', ' ')}: {r['checks']} checks, {r['checks_per_s']}/s")
        for point, (a, b, c) in r["latency_ms"].items():
            lines.append(f"  {point:12} {a:8.1f} {b:8.1f} {c:8.1f}")
        lines.append(f"  outcomes: {r['outcomes']}")
        lines.append(f"  guard_unreachable (the client's own outcome): {r['guard_unreachable']}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--turns-per-second", type=float, default=2.0)
    p.add_argument("--seconds", type=float, default=15.0)
    p.add_argument("--model-latency-s", type=float, default=0.3)
    p.add_argument("--mode", choices=("both", "in-process", "remote"), default="both")
    p.add_argument("--pool", type=int, default=128, help="the client's connection pool size")
    p.add_argument("--margin-s", type=float, default=0.25)
    p.add_argument("--seed", type=int, default=7)
    p.add_argument(
        "--in-flight", type=int, default=None, help="the key's in-flight limit (default 4)"
    )
    p.add_argument(
        "--mixed",
        action="store_true",
        help="one check in five is a block, an escalation, a failure or a provider refusal",
    )
    p.add_argument("--json", action="store_true")
    args = p.parse_args(argv)
    report = asyncio.run(run(args))
    print(json.dumps(report, indent=1) if args.json else render(report))
    return 0


if __name__ == "__main__":
    sys.exit(main())
