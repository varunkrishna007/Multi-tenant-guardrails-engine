"""M3-09 load-test harness: simulated agent turns through ``build_engine``, on a virtual clock.

    uv run python -m capacity.load_test simulate                       # the default mix, 1 hour
    uv run python -m capacity.load_test simulate --turns-per-minute 40 --minutes 30 --json
    uv run python -m capacity.load_test simulate --mix my_mix.json --out report.md

**What it does.** It builds the real engine (``build_engine``: the Guard Service, the Decision
Gateway with the M3-10 token-rate limiter and the M3-07 quotas, the policy cache, redaction,
chunking) with a fake model that answers after a *modelled* latency, and drives it with
simulated agent turns. A turn is the five guard points in order, with tool loops in between:
``input``, ``plan``, then ``tool_call`` and ``tool_result`` once per tool loop, then
``output``. A ``tool_result`` over ``chunk_tokens`` is several provider calls. The tenant mix
(who sends how many turns, of what shape, on which pool) is configuration.

**Virtual time.** The engine runs on :class:`VirtualLoop`, an asyncio event loop whose clock
only moves when every task is waiting: it then jumps to the next timer. ``asyncio.sleep``, the
gateway's deadlines, the bucket's refill and the policy cache's TTL all follow it, so an hour
of simulated load takes seconds of real time and the same seed gives the same report. The
factory has no clock argument, so :func:`virtual_clocks` gives the gateway and the Guard
Service the loop's clock for the length of a run (and restores them after).

**Latency (R6.3).** :class:`LatencyModel` draws a call's duration from the R6.3 expected-latency
model: a median of ``band base (by input size) + window + 2 ms x questions``, a log-normal
body, and a small tail. The bands and the slope are read from ``GatewayConfig``, never copied.
``window`` is the time-window shift (0 to the 380 ms allowance); the default is its midpoint,
and ``--slow-window`` uses the whole allowance. It is a parameterised model, to be re-fitted
by the second-region profile (``capacity/load_live.py``, not run).

**What is measured, and what is not.** Requests and tokens are counted at the model: every
provider call the gateway started (a retry is a second call, a call it cancelled still counts)
and its input tokens as the fake reports them (the engine's raw estimator, the same figure
``Usage.total_input_tokens`` carries). They are the engine's own request and token counts for
the chosen shapes, **not Gemini's tokenizer's**: the live capacity run measures that
(``capacity/load_live.py``). The daily cap is projected from requests per turn, never burned.

The pure arithmetic (the three PF-4 limits, the binding one, the S3 cap) is
:func:`analyse_pool`, tested without an engine. No provider is ever called here.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import math
import random
import sys
from collections import Counter, defaultdict
from collections.abc import AsyncIterator, Iterator, Mapping, Sequence
from dataclasses import asdict, dataclass, field, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from capacity.model import (
    MINUTES_PER_DAY,
    Tier,
    Workload,
    capacity,
    production_budget,
)
from capacity.model import tier as model_tier
from guardrail_engine.decision import FakeDecisionModel
from guardrail_engine.gateway import (
    DEFAULT_LATENCY_BANDS,
    DEFAULT_LATENCY_PER_QUESTION_S,
    DEFAULT_MAX_IN_FLIGHT_PER_KEY,
    DEFAULT_TIER_QUOTAS,
    DEFAULT_TIME_WINDOW_ALLOWANCE_S,
    TESTED_FLAT_OCCUPANCY,
)
from guardrail_engine.guard.chunking import chunk_bounds
from guardrail_engine.tokens import estimate_question_tokens, estimate_tokens

ROOT = Path(__file__).resolve().parents[1]

GUARD_POINTS = ("input", "plan", "tool_call", "tool_result", "output")
S3_FRACTION = 0.70
"""S3: onboarding is capped at 70% of the binding limit."""
PF4_LIMITS = ("requests/min", "tokens/min", "requests/day")
"""The three limits PF-4 names. The model's two further limits (spend per 10 minutes and the
monthly spend cap) are reported beside them and marked as beyond PF-4."""
DEFAULT_MINUTES = 60.0
DEFAULT_TURNS_PER_MINUTE = 12.0
DEFAULT_SEED = 309
DEFAULT_START = datetime(2026, 11, 18, 20, 0, tzinfo=UTC)
"""The virtual wall clock's start: noon Pacific, so an hour or two never crosses the day roll
of the daily request counter."""
DEFAULT_STEP_GAP_S = 2.0
"""Agent time between two checks of a turn (the planner, the runtime): not provider time."""
DEFAULT_TOOL_RUN_S = 1.5
"""A tool's own run time between its ``tool_call`` check and its ``tool_result`` check."""
DEFAULT_CHUNK_TOKENS = 12_000
"""``PlatformSettings`` default chunk size, raw tokens (AC-G5)."""


# --------------------------------------------------------------------------- virtual time


class VirtualLoop(asyncio.SelectorEventLoop):
    """An event loop on a virtual clock: when nothing is ready, time jumps to the next timer
    instead of waiting for it.

    Two kinds of real work are waited for, never skipped over, so the result doesn't depend on
    how fast a thread runs: work handed to the executor (the engine runs redaction and the deny
    scan with ``asyncio.to_thread``), and a loop with nothing scheduled at all (the gateway's
    drainer thread may be about to wake it). The default executor is shut down directly at
    close, because its 300 s join timeout would otherwise expire on the virtual clock.

    Not thread-safe beyond what asyncio is. Use it through :func:`run_virtual`."""

    START = 1_000.0
    IDLE_POLL_S = 0.05
    IDLE_POLLS = 200
    """Real seconds (10 in all) a loop with nothing scheduled, or waiting on a thread, may
    wait for an event before it is called deadlocked, rather than hang a test run."""

    def __init__(self) -> None:
        self._virtual_now = self.START
        self._threaded = 0
        super().__init__()
        real_select = self._selector.select

        def wait_real() -> list[Any]:
            for _ in range(self.IDLE_POLLS):
                if events := real_select(self.IDLE_POLL_S):
                    return events
            raise RuntimeError("virtual loop idle: nothing is scheduled and nothing arrived")

        def select(timeout: float | None = None) -> list[Any]:
            if timeout is None or (timeout > 0 and self._threaded):
                return wait_real()
            events = real_select(0)
            if not events and timeout > 0:
                self._virtual_now += timeout
            return events

        self._selector.select = select  # type: ignore[method-assign]

    def time(self) -> float:
        return self._virtual_now

    def run_in_executor(self, executor: Any, func: Any, *args: Any) -> Any:
        future = super().run_in_executor(executor, func, *args)
        self._threaded += 1
        future.add_done_callback(lambda _: setattr(self, "_threaded", self._threaded - 1))
        return future

    async def shutdown_default_executor(self, timeout: float | None = None) -> None:
        self._executor_shutdown_called = True
        executor, self._default_executor = self._default_executor, None
        if executor is not None:
            executor.shutdown(wait=True)


def run_virtual(main: Any) -> Any:
    """Run the coroutine ``main`` to completion on a fresh :class:`VirtualLoop`."""
    with asyncio.Runner(loop_factory=VirtualLoop) as runner:
        return runner.run(main)


@contextlib.contextmanager
def virtual_clocks(
    loop: asyncio.AbstractEventLoop, wall_start: datetime, rng: random.Random
) -> Iterator[None]:
    """For the length of the block, a ``DecisionGateway`` or ``GuardService`` built without
    its own clocks gets the loop's clock (and a wall clock that follows it, and a seeded retry
    jitter), so ``build_engine`` runs on virtual time. Restored on exit."""
    from guardrail_engine.gateway.gateway import DecisionGateway
    from guardrail_engine.guard.service import GuardService

    t0 = loop.time()

    def wall() -> datetime:
        return wall_start + timedelta(seconds=loop.time() - t0)

    gateway_init, guard_init = DecisionGateway.__init__, GuardService.__init__

    def gateway(self: Any, *args: Any, **kwargs: Any) -> None:
        kwargs.setdefault("clock", loop.time)
        kwargs.setdefault("wall_clock", wall)
        kwargs.setdefault("rng", rng.random)
        gateway_init(self, *args, **kwargs)

    def guard(self: Any, *args: Any, **kwargs: Any) -> None:
        kwargs.setdefault("clock", loop.time)
        kwargs.setdefault("wall_clock", wall)
        kwargs.setdefault("cache_clock", loop.time)
        guard_init(self, *args, **kwargs)

    DecisionGateway.__init__ = gateway  # type: ignore[method-assign]
    GuardService.__init__ = guard  # type: ignore[method-assign]
    try:
        yield
    finally:
        DecisionGateway.__init__ = gateway_init  # type: ignore[method-assign]
        GuardService.__init__ = guard_init  # type: ignore[method-assign]


# --------------------------------------------------------------------------- the modelled model


@dataclass(frozen=True)
class LatencyModel:
    """The R6.3 expected-latency model as a distribution.

    median = band base (by raw input tokens) + ``window_s`` + ``per_question_s`` x questions.
    The call takes ``median x exp(N(0, sigma))``; with probability ``tail_probability`` it takes
    ``tail_low`` to ``tail_high`` times that. The defaults: sigma 0.12 (M0-01's spread within a
    cell, p95 about 1.2 x p50) and a 3% tail of 2 to 6 times (the slow window: 5 of 146 calls at
    16K x 50 went past 1.6 x p50). Parameters, to be re-fitted by the second-region profile."""

    window_s: float = DEFAULT_TIME_WINDOW_ALLOWANCE_S / 2
    sigma: float = 0.12
    tail_probability: float = 0.03
    tail_low: float = 2.0
    tail_high: float = 6.0
    per_question_s: float = DEFAULT_LATENCY_PER_QUESTION_S
    bands: tuple[tuple[int, float], ...] = DEFAULT_LATENCY_BANDS

    def median_s(self, input_tokens: int, questions: int) -> float:
        base = self.bands[-1][1]
        for bound, band_base in self.bands:
            if input_tokens <= bound:
                base = band_base
                break
        return base + self.window_s + self.per_question_s * questions

    def sample(self, rng: random.Random, input_tokens: int, questions: int) -> float:
        seconds = self.median_s(input_tokens, questions) * math.exp(rng.gauss(0.0, self.sigma))
        if rng.random() < self.tail_probability:
            seconds *= rng.uniform(self.tail_low, self.tail_high)
        return seconds


@dataclass(slots=True)
class CallRecord:
    """One provider call the gateway started (a retry is another record; a call it cancelled
    is one too, and counts against every limit)."""

    pool: str
    start_s: float
    tokens: int
    questions: int
    latency_s: float = 0.0
    cancelled: bool = False


class ModelledLatencyModel:
    """A ``DecisionModel``: the engine's fake answers (every question "no"), after a latency
    drawn from :class:`LatencyModel`, on the running loop's clock."""

    model_id = "fake-modelled-latency"

    def __init__(self, latency: LatencyModel, rng: random.Random) -> None:
        self.latency = latency
        self.rng = rng
        self.fake = FakeDecisionModel()

    async def decide(self, input: str, questions: Mapping[str, Any]) -> Any:
        seconds = self.latency.sample(self.rng, estimate_tokens(input), len(questions))
        await asyncio.sleep(seconds)
        result = await self.fake.decide(input, questions)
        self.fake.calls.clear()  # the fake keeps every input: not for an hour of load
        return result


class RecordingModel:
    """Wraps any ``DecisionModel`` (the modelled one offline, the Gemini adapter live) and
    records every call it is given: when it started, its input tokens (the provider's usage
    when it answered, else the engine's estimate), how long it took and whether it was
    cancelled. The gateway's retries and cancellations are therefore counted."""

    def __init__(self, inner: Any, pool: str) -> None:
        self.inner = inner
        self.pool = pool
        self.model_id = getattr(inner, "model_id", "recorded")
        self.calls: list[CallRecord] = []

    async def decide(self, input: str, questions: Mapping[str, Any]) -> Any:
        loop = asyncio.get_running_loop()
        record = CallRecord(
            self.pool, loop.time(),
            estimate_tokens(input) + estimate_question_tokens(questions), len(questions),
        )  # fmt: skip
        self.calls.append(record)
        try:
            result = await self.inner.decide(input, questions)
        except asyncio.CancelledError:
            record.cancelled = True
            record.latency_s = loop.time() - record.start_s
            raise
        record.latency_s = loop.time() - record.start_s
        usage = getattr(result, "usage", None)
        if usage is not None and usage.total_input_tokens:
            record.tokens = usage.total_input_tokens
        return result

    async def aclose(self) -> None:
        closer = getattr(self.inner, "aclose", None)
        if callable(closer):
            await closer()


# --------------------------------------------------------------------------- synthetic content

_CYCLE = (
    "quarterly report meeting schedule invoice shipment warehouse delivery customer account "
    "renewal policy summary estimate calendar reminder project budget review agenda draft "
    "update inventory catalogue supplier contract appointment itinerary receipt statement "
    "forecast roadmap milestone feedback survey training workshop reference template notes "
)


def benign_text(tokens: int, salt: int = 0) -> str:
    """Synthetic, benign text of exactly ``tokens`` estimated tokens (4 ASCII characters
    each). Plain words only: no digits, addresses or names, so no detector fires on it."""
    chars = max(0, tokens) * 4
    if chars == 0:
        return ""
    offset = (salt * 7919) % len(_CYCLE)
    body = (_CYCLE * (chars // len(_CYCLE) + 2))[offset : offset + chars]
    return body


# --------------------------------------------------------------------------- the mix


@dataclass(frozen=True)
class TurnShape:
    """One kind of agent turn. Sizes are estimated tokens of the content of each check (the
    questions and the carried conversation are added by the engine). ``tool_loops`` is a count
    or an inclusive ``(low, high)`` range drawn per turn. ``tool_result_tokens`` over the chunk
    size is several provider calls (AC-G5)."""

    name: str
    user_tokens: int = 150
    plan_tokens: int = 200
    tool_loops: int | tuple[int, int] = 1
    tool_args_tokens: int = 60
    tool_result_tokens: int = 800
    output_tokens: int = 300
    carry_context: bool = True
    """Whether each check carries the turn's conversation so far (the SDK's default)."""

    def loops_for(self, rng: random.Random) -> int:
        if isinstance(self.tool_loops, int):
            return self.tool_loops
        low, high = self.tool_loops
        return rng.randint(low, high)

    def checks(self, loops: int) -> int:
        """Guard-point checks of a turn with ``loops`` tool loops: ``3 + 2 x loops``."""
        return 3 + 2 * loops

    def chunks_per_result(self, chunk_tokens: int = DEFAULT_CHUNK_TOKENS) -> int:
        """Provider calls one tool result takes (1 below ``chunk_tokens``)."""
        if self.tool_result_tokens <= chunk_tokens:
            return 1
        return len(chunk_bounds(benign_text(self.tool_result_tokens), chunk_tokens))

    def requests(self, loops: int, chunk_tokens: int = DEFAULT_CHUNK_TOKENS) -> int:
        """Provider calls of a turn with ``loops`` tool loops, with no retries: one per
        check, and ``chunks_per_result`` for each ``tool_result``."""
        return self.checks(loops) + loops * (self.chunks_per_result(chunk_tokens) - 1)


DEFAULT_SHAPES: dict[str, TurnShape] = {
    s.name: s
    for s in (
        TurnShape("chat", 150, 200, 1, 60, 800, 300),
        TurnShape("tool_loop", 300, 300, (2, 4), 80, 1_500, 500),
        TurnShape("document", 600, 300, 2, 80, 30_000, 700),
        TurnShape("single_shot", 400, 150, 0, 0, 0, 600),
    )
}
"""``single_shot`` has no tool loop: three checks, the shape of a plain question and answer."""


@dataclass(frozen=True)
class TenantSpec:
    tenant_id: str
    weight: float
    shape: str
    pack: str | None = None
    """``insurance`` or ``energy``: the tenant's bundle extends that pack (more questions)."""
    project: str | None = None
    """A dedicated Gemini project (M5-06): the tenant is regulated and its checks go to that
    project's gateway, bucket and counters. None: the shared pool."""

    @property
    def pool(self) -> str:
        return self.project or "shared"


DEFAULT_TENANTS = (
    TenantSpec("t_chatty", 4.0, "chat"),
    TenantSpec("t_agentic", 2.5, "tool_loop", pack="insurance"),
    TenantSpec("t_docs", 0.5, "document", pack="energy"),
    TenantSpec("t_reg", 2.0, "tool_loop", project="reg-1"),
)


@dataclass(frozen=True)
class LoadConfig:
    """One run: the load, the tenant mix and the engine settings under test."""

    minutes: float = DEFAULT_MINUTES
    turns_per_minute: float = DEFAULT_TURNS_PER_MINUTE
    """Offered turns per minute, all tenants together (Poisson arrivals)."""
    tenants: tuple[TenantSpec, ...] = DEFAULT_TENANTS
    shapes: Mapping[str, TurnShape] = field(default_factory=lambda: dict(DEFAULT_SHAPES))
    seed: int = DEFAULT_SEED
    tier: str = "Tier 1"
    """The capacity model's tier name, for every pool."""
    in_flight: int | None = None
    """``gateway.max_in_flight_per_key``; None keeps the engine's default (4)."""
    latency: LatencyModel = field(default_factory=LatencyModel)
    step_gap_s: float = DEFAULT_STEP_GAP_S
    tool_run_s: float = DEFAULT_TOOL_RUN_S
    quotas: bool = True
    """The M3-07 per-tenant shares and weighted fair queueing on. Off, a run measures the
    pool alone: the project's bucket and the admission queue, with no tenant refused for its
    own share."""
    stop_on_block: bool = False
    """The product's agent stops a turn at its first blocked check. For capacity the demand a
    turn *places* is what matters, so by default a turn runs all its checks regardless."""
    wall_start: datetime = DEFAULT_START

    def validate(self) -> None:
        if self.minutes <= 0 or self.turns_per_minute <= 0:
            raise ValueError("minutes and turns_per_minute must be positive")
        if not self.tenants or any(t.weight <= 0 for t in self.tenants):
            raise ValueError("a mix needs tenants with positive weights")
        for t in self.tenants:
            if t.shape not in self.shapes:
                raise ValueError(f"tenant {t.tenant_id}: unknown shape {t.shape!r}")
            if t.pack not in (None, "insurance", "energy"):
                raise ValueError(f"tenant {t.tenant_id}: pack must be insurance or energy")
        if len({t.tenant_id for t in self.tenants}) != len(self.tenants):
            raise ValueError("tenant ids must be distinct")
        model_tier(self.tier)

    @property
    def pools(self) -> list[str]:
        return sorted({t.pool for t in self.tenants}, key=lambda p: (p != "shared", p))


def load_mix(path: Path) -> dict[str, Any]:
    """A mix file: ``{"tenants": [{"id", "weight", "shape", "pack"?, "project"?}],
    "shapes": {name: {TurnShape fields}}?}`` -> ``LoadConfig`` keyword arguments."""
    doc = json.loads(path.read_text(encoding="utf-8"))
    shapes = dict(DEFAULT_SHAPES)
    for name, spec in (doc.get("shapes") or {}).items():
        spec = dict(spec)
        if isinstance(spec.get("tool_loops"), list):
            spec["tool_loops"] = tuple(spec["tool_loops"])
        shapes[name] = TurnShape(name=name, **spec)
    tenants = tuple(
        TenantSpec(t["id"], float(t["weight"]), t["shape"], t.get("pack"), t.get("project"))
        for t in doc["tenants"]
    )
    return {"tenants": tenants, "shapes": shapes}


# --------------------------------------------------------------------------- the engine


def engine_settings(config: LoadConfig, floor_version: int) -> Any:
    """The engine's settings for a run: ``test`` environment (``bootstrap_publish`` is allowed),
    the M3-10 limiter on at the tier's published limits, the M3-07 quotas on, floor-only default
    bundles, and a dedicated project per project label in the mix (M5-06)."""
    from guardrail_engine.engine import EngineSettings
    from guardrail_engine.gateway import TIER_LIMITS

    key = config.tier.lower().replace(" ", "_")
    limits = TIER_LIMITS[key]
    token_rate: dict[str, Any] = {"tier": key, "tokens_per_minute": limits.tokens_per_minute,
                                  "requests_per_minute": limits.requests_per_minute}  # fmt: skip
    if limits.requests_per_day is not None:
        token_rate["requests_per_day"] = limits.requests_per_day
    if limits.monthly_cap_usd is not None:
        token_rate["monthly_spend_cap_usd"] = limits.monthly_cap_usd
    mapping: dict[str, Any] = {
        "environment": "test",
        "platform": {"min_floor_version": floor_version},
        "gemini": {"paid_tier": True},
        "catalog": {"default_on_packs": []},
        "token_rate": token_rate,
    }
    if config.quotas:
        mapping["quotas"] = {}
    if config.in_flight is not None:
        mapping["gateway"] = {"max_in_flight_per_key": config.in_flight}
    projects = sorted({t.project for t in config.tenants if t.project})
    if projects:
        mapping["projects"] = {
            "dedicated": {
                p: {"key_env": "GEMINI_KEY_" + p.upper().replace("-", "_")} for p in projects
            }
        }
    return EngineSettings.from_mapping(mapping)


def bundle_for(spec: TenantSpec, floor_version: int, pack_ref: str | None) -> dict[str, Any]:
    extends = [f"platform/floor@{floor_version}"] + ([pack_ref] if pack_ref else [])
    return {"schema_version": 1, "tenant_id": spec.tenant_id, "version": 1, "extends": extends}


@contextlib.asynccontextmanager
async def load_engine(
    config: LoadConfig, models: Mapping[str, Any]
) -> AsyncIterator[tuple[Any, Any]]:
    """Build the engine (``build_engine``) for ``config``'s tenants, with ``models`` (pool ->
    model) as the shared pool's model and each dedicated project's, publish each tenant's
    bundle, and yield ``(engine, verifier)``. Shuts it down after (the models are the
    caller's to close)."""
    import secrets

    from guardrail_engine.engine import build_engine
    from guardrail_engine.floor_file import load_floor_file
    from guardrail_engine.guard import HmacContextVerifier, InMemoryTenantDirectory, TenantProfile
    from guardrail_engine.guard.audit import NullAuditSink
    from guardrail_engine.pack_file import load_pack_file
    from guardrail_engine.policy import InMemoryCatalog, TenantAttributes

    floor = load_floor_file(ROOT / "floor" / "rules.json")
    packs = {
        name: load_pack_file(ROOT / "packs" / name / "pack.json")
        for name in sorted({t.pack for t in config.tenants if t.pack})
    }

    def profile(spec: TenantSpec, *, regulated: bool) -> Any:
        attrs = TenantAttributes(
            tenant_id=spec.tenant_id,
            tier="regulated" if regulated else "standard",
            project=spec.project if regulated else None,
        )
        return TenantProfile.build(attrs, spec.pack or "general", (),
                                   slug=spec.tenant_id.removeprefix("t_"))  # fmt: skip

    directory = InMemoryTenantDirectory([profile(t, regulated=False) for t in config.tenants])
    verifier = HmacContextVerifier(secrets.token_bytes(32))
    project_models = {p: m for p, m in models.items() if p != "shared"}
    engine = await build_engine(
        engine_settings(config, floor.version),
        verifier=verifier,
        tenants=directory,
        model=models["shared"],
        project_models=project_models or None,
        catalog=InMemoryCatalog(floors=[floor], packs=list(packs.values())),
        audit=NullAuditSink(),
    )
    try:
        for spec in config.tenants:
            pack = packs.get(spec.pack) if spec.pack else None
            await engine.bootstrap_publish(
                bundle_for(spec, floor.version, pack.ref if pack else None)
            )
            if spec.project:  # published as standard (bootstrap's rule), then assigned
                directory.put(profile(spec, regulated=True))
                engine.guard.policy_cache.invalidate(spec.tenant_id)
        yield engine, verifier
    finally:
        await engine.shutdown()


# --------------------------------------------------------------------------- turns


@dataclass(slots=True)
class CheckRecord:
    """What one guard-point check came to (no content)."""

    turn: int
    tenant: str
    pool: str
    guard_point: str
    start_s: float
    wall_s: float
    decision: str
    reason: str
    failure_reason: str | None
    provider_calls: int | None
    chunks: int
    queue_wait_ms: float | None
    capacity_limited: bool
    tokens: int = 0
    """Input tokens the provider reported for the check (0 when it was not answered)."""


@dataclass(slots=True)
class TurnRecord:
    turn: int
    tenant: str
    pool: str
    shape: str
    start_s: float
    loops: int
    checks: int = 0
    stopped: bool = False
    """The turn ended early at a blocked check (``stop_on_block``)."""


async def run_turn(
    engine: Any,
    verifier: Any,
    spec: TenantSpec,
    shape: TurnShape,
    config: LoadConfig,
    rng: random.Random,
    number: int,
    checks: list[CheckRecord],
    observer: Any = None,
) -> TurnRecord:
    """One agent turn: input, plan, then tool_call + tool_result per loop, then output."""
    from guardrail_engine.guard import CheckContext
    from guardrail_engine.guard.request import Plan, ToolCall, ToolResult, Turn

    loop = asyncio.get_running_loop()
    loops = shape.loops_for(rng)
    record = TurnRecord(number, spec.tenant_id, spec.pool, shape.name, loop.time(), loops)
    conversation: list[Any] = []
    salt = number * 31
    tool = "records.lookup"

    async def check(guard_point: str, content: str, tool_name: str | None = None) -> bool:
        ctx = CheckContext(
            signed_context=verifier.issue(spec.tenant_id),
            conversation=tuple(conversation) if shape.carry_context else (),
            tool=tool_name,
            conversation_id=f"c{number}",
        )
        if observer is not None:
            observer.before(spec, guard_point, content, ctx.conversation)
        started = loop.time()
        verdict = await engine.check(ctx, guard_point, content)
        if observer is not None:
            observer.after(spec, guard_point, verdict, loop.time() - started)
        checks.append(
            CheckRecord(
                number, spec.tenant_id, spec.pool, guard_point, started, loop.time() - started,
                verdict.decision.value, verdict.reason.value, verdict.failure_reason,
                verdict.provider_calls, verdict.chunks, verdict.queue_wait_ms,
                verdict.capacity_limited,
                verdict.usage.total_input_tokens if verdict.usage else 0,
            )
        )  # fmt: skip
        record.checks += 1
        return verdict.decision.value == "allow" or not config.stop_on_block

    steps: list[tuple[str, str, Any, str | None]] = [
        ("input", benign_text(shape.user_tokens, salt), Turn("user", ""), None),
        ("plan", benign_text(shape.plan_tokens, salt + 1), Plan(""), None),
    ]
    for i in range(loops):
        steps.append(("tool_call", benign_text(shape.tool_args_tokens, salt + 2 + i),
                      ToolCall(tool, ""), tool))  # fmt: skip
        steps.append(("tool_result", benign_text(shape.tool_result_tokens, salt + 3 + i),
                      ToolResult(tool, ""), tool))  # fmt: skip
    steps.append(
        ("output", benign_text(shape.output_tokens, salt + 4), Turn("assistant", ""), None)
    )
    for index, (guard_point, content, item, tool_name) in enumerate(steps):
        if index:
            await asyncio.sleep(
                config.tool_run_s if guard_point == "tool_result" else config.step_gap_s
            )
        if not await check(guard_point, content, tool_name):
            record.stopped = True
            break
        if isinstance(item, Turn):
            conversation.append(Turn(item.role, content))
        elif isinstance(item, Plan):
            conversation.append(Plan(content))
        elif isinstance(item, ToolCall):
            conversation.append(ToolCall(item.tool, content))
        else:
            conversation.append(ToolResult(item.tool, content))
    return record


@dataclass
class RunData:
    config: LoadConfig
    turns: list[TurnRecord]
    checks: list[CheckRecord]
    calls: list[CallRecord]
    virtual_seconds: float
    dropped_events: int = 0


async def _gather_unless_stopped(
    tasks: Sequence[asyncio.Task[Any]], stop: asyncio.Event | None, observer: Any
) -> list[Any]:
    """``gather(*tasks)``, but raise ``observer.stop_error()`` as soon as ``stop`` is set."""
    done = asyncio.ensure_future(asyncio.gather(*tasks))
    if stop is None:
        return list(await done)
    waiter = asyncio.ensure_future(stop.wait())
    try:
        await asyncio.wait({done, waiter}, return_when=asyncio.FIRST_COMPLETED)
        if stop.is_set():
            raise observer.stop_error()
        return list(done.result())
    finally:
        waiter.cancel()
        if not done.done():
            done.cancel()  # cancels the turns still running
        elif not done.cancelled():
            done.exception()  # retrieved: the caller is raising, or has the result, already


async def sleep_unless_stopped(delay: float, stop: asyncio.Event | None) -> bool:
    """Sleep ``delay`` seconds on the running loop's clock, or until ``stop`` is set. True when
    the stop ended it (or was already set). With no ``stop`` it is ``asyncio.sleep``."""
    if stop is None:
        await asyncio.sleep(max(0.0, delay))
        return False
    if stop.is_set() or delay <= 0:
        return stop.is_set()
    try:
        await asyncio.wait_for(stop.wait(), timeout=max(0.0, delay))
    except TimeoutError:
        return stop.is_set()
    return True


async def drive(
    config: LoadConfig, models: Mapping[str, RecordingModel], *, observer: Any = None,
    virtual: bool = True,
) -> RunData:  # fmt: skip
    """Build the engine with ``models`` and run the load: Poisson arrivals at
    ``config.turns_per_minute`` for ``config.minutes``, each a turn. With ``virtual`` the
    gateway and Guard Service are given the loop's clock (the loop is a :class:`VirtualLoop`);
    live, they keep the real one. An ``observer`` (``before`` and ``after`` each check) may stop
    the run by raising; the turns still running are cancelled and the error propagates. An
    observer that also has a ``stop_event`` (an ``asyncio.Event``) and a ``stop_error()`` is
    woken by it: the driver does not wait for the next arrival or for the turns to end, it
    starts no further turn, cancels the turns in flight and raises ``stop_error()``."""
    loop = asyncio.get_running_loop()
    rng = random.Random(config.seed)
    checks: list[CheckRecord] = []
    tasks: list[asyncio.Task[TurnRecord]] = []
    clocks = (
        virtual_clocks(loop, config.wall_start, random.Random(config.seed + 2))
        if virtual else contextlib.nullcontext()
    )  # fmt: skip
    dropped = 0
    with clocks:
        async with load_engine(config, models) as (engine, verifier):
            started = loop.time()
            end = started + config.minutes * 60
            rate = config.turns_per_minute / 60.0
            weights = [t.weight for t in config.tenants]
            number = 0
            at = started
            stop: asyncio.Event | None = getattr(observer, "stop_event", None)
            try:
                while True:
                    at += rng.expovariate(rate)
                    if at >= end:
                        break
                    if await sleep_unless_stopped(at - loop.time(), stop):
                        raise observer.stop_error()
                    failed = next(
                        (t.exception() for t in tasks if t.done() and t.exception()), None
                    )
                    if failed is not None:
                        raise failed
                    spec = rng.choices(config.tenants, weights)[0]
                    number += 1
                    tasks.append(asyncio.ensure_future(
                        run_turn(engine, verifier, spec, config.shapes[spec.shape], config, rng,
                                 number, checks, observer)
                    ))  # fmt: skip
                turns = list(await _gather_unless_stopped(tasks, stop, observer))
            except BaseException:
                for task in tasks:
                    task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
                raise
            for gateway in engine.guard.gateways.values():
                await gateway.drain()
                dropped += gateway.dropped_events
            elapsed = loop.time() - started
    calls = sorted((c for m in models.values() for c in m.calls), key=lambda c: c.start_s)
    # Times relative to the start of the run, so a report doesn't depend on the loop's origin.
    for call in calls:
        call.start_s -= started
    for check_record in checks:
        check_record.start_s -= started
    for turn in turns:
        turn.start_s -= started
    return RunData(config, turns, checks, calls, elapsed, dropped)


async def _simulate(config: LoadConfig) -> RunData:
    rng = random.Random(config.seed + 1)
    models = {
        pool: RecordingModel(ModelledLatencyModel(config.latency, rng), pool)
        for pool in config.pools
    }
    return await drive(config, models)


def simulate(config: LoadConfig) -> RunData:
    """Run ``config`` on a virtual clock: seconds of real time for any length of load."""
    config.validate()
    return run_virtual(_simulate(config))


# --------------------------------------------------------------------------- the arithmetic


def percentile(values: Sequence[float], p: float) -> float | None:
    """Nearest-rank percentile (``p`` in 0..100); None for no values."""
    if not values:
        return None
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, max(0, math.ceil(p / 100 * len(ordered)) - 1))]


def analyse_pool(
    tier: Tier,
    *,
    requests_per_turn: float,
    tokens_per_turn: float,
    offered_turns_per_minute: float,
    peak_minute_requests: float | None = None,
    peak_minute_tokens: float | None = None,
    onboarding_fraction: float = S3_FRACTION,
    limiter_target: float = TESTED_FLAT_OCCUPANCY,
) -> dict[str, Any]:
    """One pool's headroom against the limits, from what a turn costs it.

    Each PF-4 limit is turned into the turns it allows, per minute and per day, **sustained**
    (a per-minute limit x 1,440 for a day, a daily one / 1,440 for a minute): the binding limit
    is the one that allows the fewest. ``used`` is the configured load as a share of the limit
    (the daily one projected from the offered turns per minute, never burned down), and
    ``peak_used`` the busiest simulated minute's share of the per-minute limits.

    The two limits beyond PF-4 (the spend limit per 10 minutes and the monthly spend cap) come
    from the M0-03 model, are marked ``pf4: false``, and name their own binding limit
    (``binding_all``), because the monthly cap binds before the daily request cap above
    about 1,667 tokens a check."""
    rpt, tpt = requests_per_turn, tokens_per_turn
    if rpt <= 0 or tpt <= 0:
        raise ValueError("a turn must cost at least one request and some tokens")
    offered_req_min = offered_turns_per_minute * rpt
    offered_tok_min = offered_turns_per_minute * tpt
    rows: list[dict[str, Any]] = []

    def row(name: str, per: str, unit: str, limit: float | None, per_turn: float, *,
            pf4: bool, offered_per_min: float, peak: float | None = None) -> None:  # fmt: skip
        if limit is None:
            return
        if per == "minute":
            turns_min = limit / per_turn
            turns_day = turns_min * MINUTES_PER_DAY
            used = offered_per_min / limit
            peak_used = None if peak is None else peak / limit
        else:
            turns_day = limit / per_turn
            turns_min = turns_day / MINUTES_PER_DAY
            used = offered_per_min * MINUTES_PER_DAY / limit
            peak_used = None
        rows.append({
            "name": name, "per": per, "unit": unit, "limit": limit, "pf4": pf4,
            "max_turns_per_minute": turns_min, "max_turns_per_day": turns_day,
            "used": used, "headroom": 1 - used, "peak_used": peak_used,
        })  # fmt: skip

    row("requests/min", "minute", "requests", tier.rpm, rpt, pf4=True,
        offered_per_min=offered_req_min, peak=peak_minute_requests)  # fmt: skip
    row("tokens/min", "minute", "tokens", tier.tpm, tpt, pf4=True,
        offered_per_min=offered_tok_min, peak=peak_minute_tokens)  # fmt: skip
    row("requests/day", "day", "requests", tier.rpd, rpt, pf4=True, offered_per_min=offered_req_min)
    cap = capacity(tier, Workload(checks_per_turn=rpt, tokens_per_check=round(tpt / rpt)))
    for lim in cap.per_minute:
        if lim.name == "spend/10 min" and lim.amount is not None:
            row(lim.name, "minute", "tokens", lim.amount, tpt, pf4=False,
                offered_per_min=offered_tok_min, peak=peak_minute_tokens)  # fmt: skip
    for lim in cap.per_day:
        if lim.name == "monthly spend cap" and lim.amount is not None:
            row(lim.name, "day", "tokens", lim.amount, tpt, pf4=False,
                offered_per_min=offered_tok_min)  # fmt: skip

    pf4_rows = [r for r in rows if r["pf4"]]
    binding = min(pf4_rows, key=lambda r: r["max_turns_per_day"])
    binding_all = min(rows, key=lambda r: r["max_turns_per_day"])
    minute_rows = [r for r in pf4_rows if r["per"] == "minute"]
    binding_minute = min(minute_rows, key=lambda r: r["max_turns_per_minute"])
    day_pf4 = [r for r in pf4_rows if r["per"] == "day"] + [
        {"name": "tokens/min x 1,440", "max_turns_per_day": r["max_turns_per_day"]}
        for r in minute_rows
        if r["name"] == "tokens/min"
    ]
    binding_day = min(day_pf4, key=lambda r: r["max_turns_per_day"])
    max_per_minute = binding_minute["max_turns_per_minute"]
    tokens_row = next(r for r in rows if r["name"] == "tokens/min")
    s3_day = onboarding_fraction * binding["max_turns_per_day"]
    s3_day_all = onboarding_fraction * binding_all["max_turns_per_day"]
    out: dict[str, Any] = {
        "tier": tier.name, "requests_per_turn": rpt, "tokens_per_turn": tpt,
        "tokens_per_request": tpt / rpt, "offered_turns_per_minute": offered_turns_per_minute,
        "limits": rows,
        "binding": binding["name"], "binding_all": binding_all["name"],
        "binding_per_minute": binding_minute["name"], "binding_per_day": binding_day["name"],
        "max_turns_per_minute": max_per_minute,
        "max_turns_per_day": binding_day["max_turns_per_day"],
        "max_turns_per_day_all_limits": binding_all["max_turns_per_day"],
        "limiter_ceiling_turns_per_minute": limiter_target * tokens_row["max_turns_per_minute"],
        "s3": {
            "fraction": onboarding_fraction,
            "turns_per_day": s3_day,
            "turns_per_minute_sustained": s3_day / MINUTES_PER_DAY,
            "turns_per_minute_peak": onboarding_fraction * max_per_minute,
            "turns_per_day_all_limits": s3_day_all,
            "binding_all": binding_all["name"],
            "monthly_cap_binds_first": not binding_all["pf4"],
        },
    }  # fmt: skip
    budget = production_budget(cap, utilisation=onboarding_fraction)
    out["after_nonproduction"] = {
        "binding_day": budget.binding.name,
        "production_turns_per_day": budget.production_turns_per_day,
    }
    return out


# --------------------------------------------------------------------------- the report

REFUSAL_REASONS = ("token_rate", "admission_wait", "admission_queue_full", "quota_exhausted",
                   "orphan_cap")  # fmt: skip


def _stats(values: Sequence[float]) -> dict[str, float | None]:
    return {"p50": percentile(values, 50), "p95": percentile(values, 95),
            "p99": percentile(values, 99), "max": max(values) if values else None}  # fmt: skip


def summarise(data: RunData) -> dict[str, Any]:
    """Everything the report says, as plain data."""
    config = data.config
    tier = model_tier(config.tier)
    minutes = config.minutes
    turns_by_pool: Counter[str] = Counter(t.pool for t in data.turns)
    checks_by_pool: Counter[str] = Counter(c.pool for c in data.checks)
    per_turn_cost: dict[str, Any] = {}
    shapes: dict[str, Any] = {}
    for name, shape in sorted(config.shapes.items()):
        mine = [t for t in data.turns if t.shape == name]
        if mine:
            shapes[name] = {
                "turns": len(mine),
                "checks_per_turn": sum(t.checks for t in mine) / len(mine),
                "loops_per_turn": sum(t.loops for t in mine) / len(mine),
                "chunks_per_tool_result": shape.chunks_per_result(),
            }
    minute_calls: dict[str, dict[int, list[int]]] = defaultdict(lambda: defaultdict(lambda: [0, 0]))
    for call in data.calls:
        cell = minute_calls[call.pool][int(call.start_s // 60)]
        cell[0] += 1
        cell[1] += call.tokens
    pools: dict[str, Any] = {}
    for pool in config.pools:
        calls = [c for c in data.calls if c.pool == pool]
        turns = turns_by_pool[pool]
        if not turns or not calls:
            continue
        requests, tokens = len(calls), sum(c.tokens for c in calls)
        per_minute = minute_calls[pool]
        # Busiest full minute: the last partial minute is left out of the peak.
        full = [v for m, v in per_minute.items() if (m + 1) * 60 <= data.virtual_seconds]
        peak_requests = max((v[0] for v in full), default=None)
        peak_tokens = max((v[1] for v in full), default=None)
        offered_tpm = turns / minutes
        analysis = analyse_pool(
            tier,
            requests_per_turn=requests / turns,
            tokens_per_turn=tokens / turns,
            offered_turns_per_minute=offered_tpm,
            peak_minute_requests=peak_requests,
            peak_minute_tokens=peak_tokens,
        )
        held = [c.latency_s for c in calls if not c.cancelled]
        mean_call_s = sum(held) / len(held) if held else 0.0
        in_flight = config.in_flight or DEFAULT_MAX_IN_FLIGHT_PER_KEY
        analysis["admission"] = {
            "in_flight": in_flight,
            "mean_call_s": mean_call_s,
            "ceiling_turns_per_minute": (
                in_flight / mean_call_s * 60 / analysis["requests_per_turn"]
                if mean_call_s
                else None
            ),
        }
        analysis.update({
            "turns": turns, "checks": checks_by_pool[pool], "requests": requests,
            "tokens": tokens, "cancelled_calls": sum(c.cancelled for c in calls),
            "peak_minute_requests": peak_requests, "peak_minute_tokens": peak_tokens,
            "mean_minute_requests": requests / minutes, "mean_minute_tokens": tokens / minutes,
            "projected_requests_per_day": requests / turns * offered_tpm * MINUTES_PER_DAY,
            "projected_tokens_per_day": tokens / turns * offered_tpm * MINUTES_PER_DAY,
        })  # fmt: skip
        pools[pool] = analysis
    tenants: dict[str, Any] = {}
    for spec in config.tenants:
        mine = [c for c in data.checks if c.tenant == spec.tenant_id]
        quota = DEFAULT_TIER_QUOTAS["regulated" if spec.project else "standard"]
        tenants[spec.tenant_id] = {
            "pool": spec.pool, "shape": spec.shape, "turns": sum(
                t.tenant == spec.tenant_id for t in data.turns),
            "checks_per_minute": len(mine) / minutes,
            "answered_tokens_per_minute": sum(c.tokens for c in mine) / minutes,
            "share_checks_per_minute": quota.checks_per_minute,
            "share_tokens_per_minute": quota.tokens_per_minute,
            "refused": sum(c.failure_reason in REFUSAL_REASONS for c in mine),
            "queue_wait_p95_ms": percentile([c.queue_wait_ms or 0.0 for c in mine], 95),
        }  # fmt: skip
    by_gp: dict[str, Any] = {}
    for gp in GUARD_POINTS:
        mine = [c for c in data.checks if c.guard_point == gp]
        if mine:
            by_gp[gp] = {
                "checks": len(mine),
                "wall_ms": _stats([c.wall_s * 1000 for c in mine]),
                "queue_wait_ms": _stats([c.queue_wait_ms or 0.0 for c in mine]),
            }
    refusals: Counter[str] = Counter()
    for c in data.checks:
        if c.failure_reason in REFUSAL_REASONS:
            refusals[c.failure_reason] += 1
    failed = Counter(c.reason for c in data.checks if c.reason != "policy")
    waits = [c.queue_wait_ms for c in data.checks if c.queue_wait_ms is not None]
    total = len(data.checks)
    per_turn_cost["requests_per_turn"] = len(data.calls) / len(data.turns) if data.turns else 0.0
    per_turn_cost["checks_per_turn"] = total / len(data.turns) if data.turns else 0.0
    per_turn_cost["tokens_per_turn"] = (
        sum(c.tokens for c in data.calls) / len(data.turns) if data.turns else 0.0
    )
    return {
        "config": {
            "minutes": minutes,
            "turns_per_minute": config.turns_per_minute,
            "seed": config.seed,
            "tier": config.tier,
            "in_flight": config.in_flight,
            "quotas": config.quotas,
            "latency": asdict(config.latency),
            "tenants": [asdict(t) for t in config.tenants],
        },
        "virtual_seconds": data.virtual_seconds,
        "turns": len(data.turns),
        "checks": total,
        "provider_calls": len(data.calls),
        "turn_cost": per_turn_cost,
        "shapes": shapes,
        "pools": pools,
        "tenants": tenants,
        "guard_points": by_gp,
        "queue_wait_ms": {
            **_stats(waits),
            "waited_over_100ms": sum(w > 100 for w in waits),
            "checks_with_a_wait": sum(w > 0 for w in waits),
        },
        "refusals": {r: refusals.get(r, 0) for r in REFUSAL_REASONS},
        "refusal_rate": sum(refusals.values()) / total if total else 0.0,
        "capacity_limited": sum(c.capacity_limited for c in data.checks),
        "non_allow_reasons": dict(sorted(failed.items())),
        "retried_checks": sum((c.provider_calls or 0) > max(c.chunks, 1) for c in data.checks),
        "stopped_turns": sum(t.stopped for t in data.turns),
        "dropped_events": data.dropped_events,
    }


def _n(x: float | None, digits: int = 0) -> str:
    return "-" if x is None else f"{x:,.{digits}f}"


def _pct(x: float | None) -> str:
    return "-" if x is None else f"{x * 100:.1f}%"


def render_markdown(rep: Mapping[str, Any]) -> str:
    cfg = rep["config"]
    out = [
        "# M3-09 load test (offline: fake model, modelled latency, virtual clock)",
        "",
        f"Offered {cfg['turns_per_minute']:g} turns/min for {cfg['minutes']:g} min "
        f"({cfg['tier']}, seed {cfg['seed']}): {rep['turns']:,} turns, {rep['checks']:,} checks, "
        f"{rep['provider_calls']:,} provider calls "
        f"({rep['virtual_seconds'] / 60:.1f} virtual minutes). No provider was called.",
        "",
        "## What a turn costs",
        "",
        f"Mean over the mix: **{rep['turn_cost']['checks_per_turn']:.2f} checks**, "
        f"**{rep['turn_cost']['requests_per_turn']:.2f} provider requests** and "
        f"**{rep['turn_cost']['tokens_per_turn']:,.0f} tokens** per turn. "
        f"Retried checks: {rep['retried_checks']:,}.",
        "",
        "| Shape | Turns | Checks/turn | Tool loops/turn | Chunks per tool result |",
        "|---|--:|--:|--:|--:|",
    ]
    for name, s in rep["shapes"].items():
        out.append(f"| {name} | {s['turns']:,} | {s['checks_per_turn']:.2f} "
                   f"| {s['loops_per_turn']:.2f} | {s['chunks_per_tool_result']} |")  # fmt: skip
    for pool, p in rep["pools"].items():
        out += [
            "",
            f"## Pool `{pool}` ({p['tier']}): {p['turns']:,} turns, "
            f"{p['requests_per_turn']:.2f} requests and "
            f"{p['tokens_per_turn']:,.0f} tokens per turn "
            f"({p['tokens_per_request']:,.0f} per request)",
            "",
            f"Configured load: {p['offered_turns_per_minute']:.1f} turns/min = "
            f"{p['mean_minute_requests']:,.0f} requests/min and "
            f"{p['mean_minute_tokens']:,.0f} tokens/min on average (busiest minute "
            f"{_n(p['peak_minute_requests'])} requests, {_n(p['peak_minute_tokens'])} tokens); "
            f"projected {p['projected_requests_per_day']:,.0f} requests/day.",
            "",
            "| Limit | Limit | Max turns/min | Max turns/day | Used at this load | Headroom "
            "| Busiest minute |",
            "|---|--:|--:|--:|--:|--:|--:|",
        ]
        for r in p["limits"]:
            name = r["name"] + ("" if r["pf4"] else " (beyond PF-4)")
            mark = "**" if r["name"] == p["binding"] else ""
            out.append(
                f"| {mark}{name}{mark} | {r['limit']:,.0f} {r['unit']}/{r['per']} "
                f"| {r['max_turns_per_minute']:,.1f} | {r['max_turns_per_day']:,.0f} "
                f"| {_pct(r['used'])} | {_pct(r['headroom'])} | {_pct(r['peak_used'])} |"
            )
        s3 = p["s3"]
        out += [
            "",
            f"- **Binding PF-4 limit: {p['binding']}.** Per minute it is {p['binding_per_minute']}"
            f" (max **{p['max_turns_per_minute']:,.1f} turns/min**); per day it is "
            f"{p['binding_per_day']} (max **{p['max_turns_per_day']:,.0f} turns/day**, "
            f"{p['max_turns_per_day'] / MINUTES_PER_DAY:,.1f}/min sustained).",
            f"- **S3 onboarding cap ({s3['fraction']:.0%} of the binding limit): "
            f"{s3['turns_per_day']:,.0f} turns/day** ({s3['turns_per_minute_sustained']:,.1f} "
            f"turns/min sustained; {s3['turns_per_minute_peak']:,.1f} turns/min in a busy minute).",
        ]
        if s3["monthly_cap_binds_first"]:
            out.append(
                f"- **Beyond PF-4, {s3['binding_all']} binds first** at this check size: "
                f"{p['max_turns_per_day_all_limits']:,.0f} turns/day, so 70% is "
                f"**{s3['turns_per_day_all_limits']:,.0f} turns/day**. The lower figure is the "
                "one to onboard against."
            )
        out += [
            f"- The engine's limiter holds the pool at {TESTED_FLAT_OCCUPANCY:.0%} of tokens/min: "
            f"it queues above {p['limiter_ceiling_turns_per_minute']:,.1f} turns/min.",
            f"- Admission control ({p['admission']['in_flight']} calls in flight on a key, "
            f"mean call {p['admission']['mean_call_s'] * 1000:,.0f} ms) passes about "
            f"{_n(p['admission']['ceiling_turns_per_minute'], 1)} turns/min before checks queue "
            "or fail fast (`admission_wait`).",
            f"- After non-production's share of {p['after_nonproduction']['binding_day']}, "
            f"production may use {p['after_nonproduction']['production_turns_per_day']:,.0f} "
            "turns/day at 70% (M0-03).",
        ]
    q = rep["queue_wait_ms"]
    out += [
        "",
        "## Queue waits and refusals",
        "",
        f"Queue wait per check (ms): p50 {_n(q['p50'], 1)}, p95 {_n(q['p95'], 1)}, "
        f"p99 {_n(q['p99'], 1)}, max {_n(q['max'], 1)}; {q['checks_with_a_wait']:,} checks "
        f"waited at all, {q['waited_over_100ms']:,} over 100 ms.",
        "",
        "| Refusal (no provider call) | Checks |",
        "|---|--:|",
    ]
    out += [f"| {name} | {n:,} |" for name, n in rep["refusals"].items()]
    out += [
        "",
        "Per tenant (a tenant's own share, M3-07, is refused as `token_rate` too):",
        "",
        "| Tenant | Pool | Shape | Turns | Checks/min (share) | Answered tokens/min (share) "
        "| Refused | Queue wait p95 (ms) |",
        "|---|---|---|--:|--:|--:|--:|--:|",
    ]
    for tid, t in rep["tenants"].items():
        out.append(
            f"| {tid} | {t['pool']} | {t['shape']} | {t['turns']:,} "
            f"| {t['checks_per_minute']:.1f} ({t['share_checks_per_minute']}) "
            f"| {t['answered_tokens_per_minute']:,.0f} ({t['share_tokens_per_minute']:,}) "
            f"| {t['refused']:,} | {_n(t['queue_wait_p95_ms'], 1)} |"
        )
    out += [
        "",
        f"Refusal rate {rep['refusal_rate']:.3%} of checks "
        f"(`capacity_limited` on {rep['capacity_limited']:,}). "
        f"Other non-allow outcomes: {rep['non_allow_reasons'] or 'none'}.",
        "",
        "| Guard point | Checks | Wall p50 (ms) | p95 | p99 | Queue wait p95 (ms) |",
        "|---|--:|--:|--:|--:|--:|",
    ]
    for gp, g in rep["guard_points"].items():
        w = g["wall_ms"]
        out.append(f"| {gp} | {g['checks']:,} | {_n(w['p50'])} | {_n(w['p95'])} "
                   f"| {_n(w['p99'])} | {_n(g['queue_wait_ms']['p95'], 1)} |")  # fmt: skip
    return "\n".join(out) + "\n"


# --------------------------------------------------------------------------- command line


def config_from_args(args: argparse.Namespace) -> LoadConfig:
    config = LoadConfig(
        minutes=args.minutes, turns_per_minute=args.turns_per_minute, seed=args.seed,
        tier=args.tier, in_flight=args.in_flight, stop_on_block=args.stop_on_block,
        quotas=not args.no_quotas,
        latency=LatencyModel(
            window_s=(
                DEFAULT_TIME_WINDOW_ALLOWANCE_S if args.slow_window
                else args.window_ms / 1000 if args.window_ms is not None
                else LatencyModel().window_s
            )
        ),
    )  # fmt: skip
    if args.mix:
        config = replace(config, **load_mix(Path(args.mix)))
    return config


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    sim = sub.add_parser("simulate", help="the offline run and its report (no key, no network)")
    sim.add_argument("--minutes", type=float, default=DEFAULT_MINUTES)
    sim.add_argument("--turns-per-minute", type=float, default=DEFAULT_TURNS_PER_MINUTE)
    sim.add_argument("--seed", type=int, default=DEFAULT_SEED)
    sim.add_argument("--tier", default="Tier 1")
    sim.add_argument("--in-flight", type=int, default=None)
    sim.add_argument("--mix", default=None, help="a mix file (see load_mix)")
    sim.add_argument("--window-ms", type=float, default=None,
                     help="the time-window shift of the latency model (default 190)")  # fmt: skip
    sim.add_argument("--slow-window", action="store_true",
                     help="use the whole 380 ms allowance as the window")  # fmt: skip
    sim.add_argument("--no-quotas", action="store_true",
                     help="measure the pool alone: no per-tenant shares (M3-07)")  # fmt: skip
    sim.add_argument("--stop-on-block", action="store_true")
    sim.add_argument("--json", action="store_true", help="print the report as JSON")
    sim.add_argument("--out", default=None, help="write the report here as well")
    args = parser.parse_args(argv)
    report = summarise(simulate(config_from_args(args)))
    text = json.dumps(report, indent=1, default=str) if args.json else render_markdown(report)
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
    print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
