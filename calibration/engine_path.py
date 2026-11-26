"""M0-02 calibration through the composition root (M1-11): the production path.

    uv run python -m calibration.engine_path plan
    uv run python -m calibration.engine_path run --out calibration/results/X.jsonl
    uv run python -m calibration.run report calibration/results/X.jsonl

Decision for the R7.4 threshold-setting rerun: threshold runs score through the production
path, including M1-14 redaction once it lands. So this harness never renders, redacts or
calls the model itself. Each draw is one ``Engine.check``, and the scores are read from the
``Verdict``. Whatever the Guard Service does to the content before the model sees it (today:
render; with M1-14: redact, then render) is therefore what is measured.

**How the engine is built.** ``build_engine`` with:
- ``environment = "test"``, because a calibration run isn't production traffic;
  ``bootstrap_publish`` is refused in production;
- a catalog holding the floor under test (floor@2 assembled at run time from ``rules.json``
  and ``additions.json``, as in :mod:`calibration.run`);
- a tenant directory with one profile per tenant the rows name;
- a per-run HMAC verifier with a random key, so every check carries a real signed context;
- a floor-only bundle per tenant, published with ``bootstrap_publish``;
- ``NullAuditSink``, so verdicts aren't logged.

The model is the Gemini adapter the factory builds (key from ``GEMINI_API_KEY``, validated
at startup, never echoed), or a ``DecisionModel`` passed in by tests.

**Checks are made one at a time**, so admission control never refuses one. The gateway's
budgets and retries apply as in production.

**What a draw records** (from the ``Verdict``; no content, no provider text):
- the verdict's decision, reason and failure kind;
- its provider-call count, usage and latencies;
- every rule's probability (recalibrated, ``probabilities``) and, beside it, the raw one
  the model gave (``probabilities_raw``): numbers only, equal while ``recalibrate`` is the
  identity;
- the rules that had no usable answer (``problems``) and the answer-problem kind of each
  (``problem_kinds``, e.g. ``missing``): kinds only, never the detail or the raw answer;
- the spans redaction replaced per PII kind (``pii_redacted``, from
  ``Verdict.pii_redacted``): counts only, never values, spans or offsets. The report's
  split of the examples redaction changed reads it.

**Nonces are seeded and recorded** (item 2 of the M1 integration). The engine
is built with a :class:`SeededNonces` as its ``nonce_source`` (``build_engine`` accepts one
in ``test`` only). Each check's nonce is derived from the run's seed and the check's
(example, draw, attempt), so a run's draws can be reproduced in any order, and after a
resume, by passing the same ``--seed``. The seed is in ``run_started`` and in ``plan``, and
each call record carries its nonce.

**A rule whose answer is unusable** (the check answered, with ``policy`` or
``contract_violation``) is left out of that draw's ``probabilities`` and named in
``problems``; the report then leaves that (example, rule) cell out of the rule's figures
rather than judge it on fewer draws.

**A draw that doesn't answer is never a score.**
- A model failure (timeout, unavailable, admission refusal, rate limit) is recorded as
  ``outcome: "failed"`` with its kind, and carries no probabilities.
- After the main pass, every such draw is re-attempted once, as a new check.
- An example still short of its draws is **incomplete**: the report names it and excludes it
  from every per-draw rule, so it is neither caught nor a false act.
- ``auth`` stops the run. So does a provider refusal (``provider_safety``, the no-harmful-inputs
  tripwire), which also names the example and never resends it.
- **Token ceiling:** with ``--max-tokens`` the run stops (``token_ceiling``) before sending a
  check whose worst case (the call and its one retry, by estimate) would pass the ceiling, and
  after any call that did; ``run`` refuses to start if the plan's estimate already exceeds it.
- ``limit_exceeded`` is deterministic per example: never re-attempted and never a stop; the
  report lists those examples by id. ``plan`` flags, before any call, every example whose
  content is over its guard point's cap (``content_too_large``), or only outgrows it once
  redaction has replaced short PII with longer placeholders
  (``content_too_large_after_redaction``), or whose request would exceed a Decisions API
  limit, and ``run`` refuses to start while any are flagged.
- The run stops (``unusable_answers``) once :data:`CONTRACT_VIOLATION_CAP` checks have ended
  in ``contract_violation``. It stops at once (``no_usable_answer_at_all``) when an
  answered check has no usable score for any noul question asked.
- **Failure rate:** the run stops (``failures``) once more than 20% of the last 50 **checks**
  failed. It counts checks (each draw and each re-attempt), not provider calls: a check whose
  gateway retry also failed counts once. It stops as soon as more than 10 of the last 50
  failed, without waiting for 50 checks, so an outage costs at most 11 checks (22 provider
  calls with the gateway's retry). The gateway's own breaker covers auth only.
- So does any failure of kind ``other``: M1-13 leaves refusal codes it
  hasn't observed as ``other``, so an unclassified failure may be an unmapped refusal. It is
  never re-attempted, and a person looks at it before anything else is sent.

**Tools (decided 2026-11-17).** A row's ``tools`` are tenant registry
configuration in the engine, so each tenant's registry is the **union** of its rows' tools.
A tool name with two different definitions for one tenant stops the run before any check,
so a conflict is never resolved silently. A row's input depends only on the registered tools
its kept context names, so with no conflict every row renders as it would with its own
tools (tested on every row).

The same label filter as :mod:`calibration.run` applies before any check is built.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import hashlib
import hmac
import json
import math
import re
import secrets
import sys
import time
from collections import deque
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from calibration.run import (
    DEFAULT_DOMAIN,
    DEFAULT_TENANT,
    DRAWS,
    FAIL_FRACTION,
    FAIL_WINDOW,
    HELDOUT_MAX_CONTENT_TOKENS,
    REDACTION_APPLIED,
    V1_SUFFIX,
    ProviderBlockStop,
    Setup,
    StopRun,
    _read,
    assemble_floor,
    build_setup,
    check_corpus,
    compile_floor,
    context_items,
    finished_record,
    fresh_nonce,
    is_heldout,
    live_exclusion,
    load_examples,
    redacted,
    refuse_harm_facilitation,
    render,
    sha256_file,
    tool_infos,
)

ENVIRONMENT = "test"
"""A calibration run isn't production traffic (decided 2026-11-17); ``test`` also allows
``bootstrap_publish`` without a durable class A sink."""

MAX_PROVIDER_CALLS_PER_CHECK = 2
"""A check makes one provider call, and one retry after a timeout or unavailable (the
gateway's). The token ceiling reserves both before a check is sent."""

ADMISSION_MARGIN = 1.25
"""A check waits for its estimate raised by this much: the limiter charges the engine's own figure
for the request it builds, and the wait must not be a little short of it."""
ADMISSION_ROUNDS = 8
"""How many times a check asks the limiter and sleeps before it gives up. A check in debt from
the one before needs two (the wait is exact; the second is for the clock's rounding)."""
ADMISSION_SLACK_S = 0.01
"""Added to each admission wait: seconds of slack over the refill the limiter asked for."""
CONTRACT_VIOLATION_CAP = 10
"""The run stops (``unusable_answers``) once this many checks have ended in
``contract_violation`` (decided 2026-11-17): each is an answered draw with a short cell, but a
systematic answer-format change mustn't burn the call budget."""

RETRYABLE_KINDS = ("timeout", "unavailable", "rate_limited")
"""Failure kinds whose draws are re-attempted once after the main pass. ``auth``, a provider
refusal and ``other`` (possibly an unmapped refusal) stop the run instead and are
never re-sent."""


SEED_PATTERN = re.compile(r"[0-9a-f]{32}")
"""A nonce seed: 128 bits as 32 lowercase hex characters."""


def new_seed() -> str:
    return secrets.token_hex(16)


class SeededNonces:
    """The engine's ``nonce_source`` for a calibration run: reproducible from the seed.

    Before each check the runner names it with :meth:`at`. Each nonce is then
    HMAC-SHA256(seed, "<example>|<draw>|<attempt>|<n>") cut to 128 bits, where ``n`` counts
    the draws the renderer makes within that check (it draws again only if a nonce occurs in
    the text). So a check's nonce depends on the seed and the check alone, not on run order.
    :attr:`last` is the nonce the check's input was rendered with (None if it ended before
    rendering). Only for ``environment = "test"``: whoever knows the seed knows the nonces."""

    def __init__(self, seed: str) -> None:
        if not isinstance(seed, str) or not SEED_PATTERN.fullmatch(seed):
            raise ValueError("a nonce seed must be 32 lowercase hex characters")
        self.seed = seed
        self._key = bytes.fromhex(seed)
        self._check: str | None = None
        self._n = 0
        self.last: str | None = None

    def at(self, example_id: str, draw: int, attempt: int) -> None:
        self._check, self._n, self.last = f"{example_id}|{draw}|{attempt}", 0, None

    def __call__(self) -> str:
        if self._check is None:
            raise RuntimeError("SeededNonces: no check named; call at() before each check")
        message = f"{self._check}|{self._n}".encode()
        self._n += 1
        self.last = hmac.new(self._key, message, hashlib.sha256).hexdigest()[:32]
        return self.last


@dataclass(frozen=True)
class EngineSetup:
    floor_doc: dict[str, Any]
    files: dict[str, str]
    validation: bool
    max_input_tokens: int | None
    """Set in each tenant's bundle for held-out rows (a tenant configuration, the
    production way to raise the content cap); None keeps the platform default."""


def floor_only_bundle(
    tenant_id: str,
    floor_version: int,
    max_input_tokens: int | None,
    extends: Sequence[str] = (),
    overrides: Sequence[Mapping[str, Any]] = (),
) -> dict:
    """The calibration tenant's bundle: the floor, and (M5-05) the packs ``extends`` names with
    the pack-rule ``overrides`` it needs (the nightly red-team opts the responsible-AI pack's
    harm-facilitation rule out of a live run)."""
    doc: dict[str, Any] = {"schema_version": 1, "tenant_id": tenant_id, "version": 1,
                           "extends": [f"platform/floor@{floor_version}", *extends]}  # fmt: skip
    if overrides:
        doc["overrides"] = [dict(o) for o in overrides]
    if max_input_tokens is not None:
        doc["guard_points"] = {
            gp: ({"chunk_tokens": max_input_tokens} if gp == "tool_result"
                 else {"max_input_tokens": max_input_tokens})
            for gp in ("input", "plan", "tool_call", "tool_result", "output")
        }  # fmt: skip
    return doc


def tenant_of(row: Mapping[str, Any]) -> tuple[str, str, str]:
    """(tenant_id, slug, domain) for a row, with the documented defaults."""
    return (row.get("tenant_id", DEFAULT_TENANT[1]), row.get("tenant_slug", DEFAULT_TENANT[0]),
            row.get("domain", DEFAULT_DOMAIN))  # fmt: skip


def tool_registries(rows: Sequence[Mapping[str, Any]]) -> dict[str, dict[str, Any]]:
    """tenant id -> tool name -> ToolInfo: the union of the tenant's rows' tools (option (a),
    decided 2026-11-17). Raises :class:`StopRun`, naming both rows, if one tenant has a tool
    name with two different definitions."""
    registries: dict[str, dict[str, Any]] = {}
    first: dict[tuple[str, str], str] = {}
    for row in rows:
        tenant_id = tenant_of(row)[0]
        registry = registries.setdefault(tenant_id, {})
        for name, info in tool_infos(row).items():
            if name in registry and registry[name] != info:
                raise StopRun(
                    f"tenant {tenant_id}: tool {name!r} has two different definitions "
                    f"({first[(tenant_id, name)]} and {row['id']}); fix the data, never "
                    "pick one"
                )
            registry.setdefault(name, info)
            first.setdefault((tenant_id, name), row["id"])
    return registries


def project_key_env(label: str) -> str:
    """The default name of the environment variable that holds a dedicated Gemini project's key
    (M5-06): ``GEMINI_KEY_`` and the label in capitals. A name only, never a key."""
    return "GEMINI_KEY_" + label.upper().replace("-", "_")


def settings_mapping(
    floor_version: int, *, live: bool, project: str = "", key_env: str | None = None
) -> dict[str, Any]:
    """The engine settings of a calibration-path engine. A **live** run (no model override, so
    the factory builds the Gemini adapter) sets ``token_rate`` explicitly, with the Tier 1
    defaults, so the project's token bucket, request count and monthly spend track what the run
    sends (M3-10). ``test`` leaves the limiter off by default, which is right for a
    fake model that answers instantly."""
    mapping: dict[str, Any] = {
        "environment": ENVIRONMENT,
        "platform": {"min_floor_version": floor_version},
        "gemini": {"paid_tier": True},
        # A harness sends the same row for each draw to measure the model: repeat-attempt
        # counting (M7-03) would refuse the later draws of a blocked row without asking it.
        "guard": {"repeat_threshold": 0},
        # It measures the model: the provider-health breaker (M7-11) would fail the rows that
        # follow a few failed calls at once, which isn't what is being measured.
        "gateway": {"degraded_consecutive": 0, "degraded_window_calls": 0},
    }
    if live:
        mapping["token_rate"] = {}
    if project:  # M5-06: the synthetic tenant is served from this dedicated project
        mapping["projects"] = {
            "dedicated": {project: {"key_env": key_env or project_key_env(project)}}
        }
    return mapping


@contextlib.asynccontextmanager
async def calibration_engine(
    setup: EngineSetup,
    rows: Sequence[Mapping[str, Any]],
    model: Any = None,
    *,
    nonces: SeededNonces,
    packs: Sequence[Any] = (),
    overrides: Sequence[Mapping[str, Any]] = (),
    project: str = "",
    key_env: str | None = None,
    **build_kwargs: Any,
) -> AsyncIterator[tuple[Any, Any]]:
    """Build the engine with ``nonces`` as its nonce source, publish a floor-only bundle per
    tenant, yield (engine, verifier), and shut it down after."""
    if not isinstance(nonces, SeededNonces):
        raise TypeError("a calibration engine needs a SeededNonces, so its draws can be replayed")
    from guardrail_engine.engine import EngineSettings, build_engine
    from guardrail_engine.guard import HmacContextVerifier, InMemoryTenantDirectory, TenantProfile
    from guardrail_engine.guard.audit import NullAuditSink
    from guardrail_engine.policy import InMemoryCatalog, TenantAttributes
    from guardrail_engine.policy.floor_loader import parse_floor_json

    if model is None:  # a live run: no harm-facilitation question may go out
        refuse_harm_facilitation(compile_floor(setup.floor_doc)[0])
    floor = parse_floor_json(json.dumps(setup.floor_doc).encode())
    tenants = {tenant_of(r) for r in rows}
    if len({t[0] for t in tenants}) != len(tenants):
        raise StopRun("a tenant id appears with two slugs or domains in the rows")
    registries = tool_registries(rows)
    directory = InMemoryTenantDirectory([
        TenantProfile.build(TenantAttributes(tenant_id=tid, project=project or None), domain,
                            registries.get(tid, {}).values(), slug=slug)
        for tid, slug, domain in sorted(tenants)
    ])  # fmt: skip
    verifier = HmacContextVerifier(secrets.token_bytes(32))
    settings = EngineSettings.from_mapping(
        settings_mapping(floor.version, live=model is None, project=project, key_env=key_env)
    )
    if (
        project and model is not None
    ):  # a fake serves the dedicated project too (no key, no network)
        build_kwargs["project_models"] = {project: model}
    engine = await build_engine(
        settings, verifier=verifier, tenants=directory, model=model,
        catalog=InMemoryCatalog(floors=[floor], packs=list(packs)), audit=NullAuditSink(),
        nonce_source=nonces,
        **build_kwargs,
    )  # fmt: skip
    if "nonce_source" not in engine.test_overrides:
        # Not an assert (stripped under ``python -O``), and not an equality: another test
        # override passed through ``build_kwargs`` (a ``pii_detector``, say) is allowed.
        await engine.shutdown()
        raise StopRun(
            "the engine was built without the seeded nonce source (its test_overrides are "
            f"{engine.test_overrides}): the run's draws could not be replayed"
        )
    try:
        for tid, _, _ in sorted(tenants):
            await engine.bootstrap_publish(
                floor_only_bundle(
                    tid,
                    floor.version,
                    setup.max_input_tokens,
                    [p.ref for p in packs],
                    overrides,
                )
            )
        yield engine, verifier
    finally:
        await engine.shutdown()


def build_engine_setup(golden: Path, rules: Path, additions: Path) -> EngineSetup:
    heldout = is_heldout(golden)
    return EngineSetup(
        floor_doc=assemble_floor(rules, additions),
        files={
            "golden": sha256_file(golden),
            "rules": sha256_file(rules),
            "additions": sha256_file(additions),
        },
        validation=heldout,
        max_input_tokens=HELDOUT_MAX_CONTENT_TOKENS if heldout else None,
    )


def verdict_fields(verdict: Any) -> dict[str, Any]:
    """What a draw records from a Verdict: no content, no provider text."""
    reason = verdict.reason.value
    # ``contract_violation``: the model answered, but some rule's answer was unusable and was
    # resolved by fail mode. The other rules' scores are real, so the draw is answered; the
    # unusable rule is absent from ``probabilities`` and named in ``problems``, and the report
    # leaves that (example, rule) cell out. It is a malformed answer, not a refusal.
    answered = reason in ("policy", "no_questions", "contract_violation") and verdict.model_called
    no_answer = sorted(
        ev.key for ev in verdict.rules if ev.p is None and ev.question_type == "noul"
    )
    # M7-01: a floor block before any model call (a known-format credential in the content)
    # is neither a score nor a failure: it carries no probabilities and is left out of every
    # per-draw rule, like an incomplete example, but without stopping or re-attempting.
    blocked = reason == "deterministic" and not verdict.model_called
    return {
        "outcome": "answered" if answered else "deterministic" if blocked else "failed",
        "decision": verdict.decision.value,
        "reason": reason,
        "kind": verdict.failure_kind.value if verdict.failure_kind is not None else None,
        "failure_reason": verdict.failure_reason,  # a bounded code (recorded_code)
        "probabilities": dict(verdict.probabilities) if answered else {},
        # The raw provider probability per rule, beside the recalibrated one
        # above (numbers only), and the answer-problem kind per rule (the kind only).
        "probabilities_raw": dict(verdict.probabilities_raw) if answered else {},
        "problem_kinds": (
            {k: kind.value for k, kind in sorted(verdict.problem_kinds.items())}
            if answered else {}
        ),
        "problems": {k: "no_usable_answer" for k in no_answer} if answered else {},
        # M1-14: spans replaced per PII kind; counts only, never values, spans or offsets.
        "pii_redacted": {kind.value: n for kind, n in sorted(verdict.pii_redacted.items())},
        "provider_calls": verdict.provider_calls,
        "usage_input_tokens": verdict.usage.total_input_tokens if verdict.usage else None,
        "wall_ms": round(verdict.latency_ms, 2),
        "model_latency_ms": verdict.model_latency_ms,
        "queue_wait_ms": verdict.queue_wait_ms,
        "context_items_dropped": verdict.context_items_dropped,
        "bundle_hash": verdict.bundle_hash,
    }  # fmt: skip


def row_token_estimates(rows: Sequence[Mapping[str, Any]], direct: Setup) -> dict[str, int]:
    """API input tokens one check of each row costs, by the engine's own estimator on the
    redacted render with the floor@2 questions (the same figure ``estimate_api_tokens`` gives the
    compiler; it ran within 0.96 to 1.05 of recorded usage on the floor@2 run). Used to plan a
    run and, where a call's usage is unknown, to count it against the token ceiling."""
    from guardrail_engine.decision.limits import estimate_question_tokens
    from guardrail_engine.policy.api_tokens import estimate_api_tokens
    from guardrail_engine.tokens import estimate_tokens

    out: dict[str, int] = {}
    for row in rows:
        gp = row["guard_point"]
        questions = {k: q for k, q in direct.questions[gp].items() if not k.endswith(V1_SUFFIX)}
        text = render(row, fresh_nonce(row), direct.max_content_tokens[gp])
        out[row["id"]] = estimate_api_tokens(
            text_tokens=estimate_tokens(text),
            question_tokens=estimate_question_tokens(questions),
            question_count=len(questions),
        )
    return out


def tokens_of(record: Mapping[str, Any], estimate: int) -> int:
    """Input tokens a call record spends against the token ceiling. An answered call is its
    reported usage plus one estimate for each extra provider call (a call that timed out
    before its retry may still be billed). An unanswered one has no usage, so each provider
    call counts as one estimate: the ceiling over-counts rather than under-counts."""
    calls = record.get("provider_calls")
    calls = 1 if calls is None else calls
    usage = record.get("usage_input_tokens")
    if record.get("outcome") == "answered" and usage is not None:
        return usage + estimate * max(calls - 1, 0)
    return estimate * calls


BOUNDARY_START_S = 55.0
BOUNDARY_END_S = 10.0


def boundary_wait(now: float) -> float:
    """Seconds to wait before a check may start at ``now`` (epoch seconds, UTC): until :10 when
    ``now`` is within :55-:10 of the minute, else 0."""
    second = now % 60
    if second >= BOUNDARY_START_S:
        return 60 - second + BOUNDARY_END_S
    if second < BOUNDARY_END_S:
        return BOUNDARY_END_S - second
    return 0.0


@dataclass
class EngineRunner:
    out: Path
    engine: Any
    verifier: Any
    nonces: SeededNonces
    """The engine's nonce source (the same object), named before each check."""
    calls: int = 0
    contract_violations: int = 0
    """Checks ended in ``contract_violation``, this run (resumed runs count earlier ones)."""
    recent: deque[bool] = field(default_factory=lambda: deque(maxlen=FAIL_WINDOW))
    """Whether each of the last :data:`FAIL_WINDOW` **checks** failed (not provider calls)."""
    token_ceiling: int | None = None
    """A hard ceiling on API input tokens for the run: it stops (``token_ceiling``) before
    sending a check that could pass it, and after any call that did."""
    token_estimates: Mapping[str, int] = field(default_factory=dict)
    """Row id -> :func:`row_token_estimates`, for calls whose usage is unknown."""
    tokens_used: int = 0
    """Input tokens counted against the ceiling so far (:func:`tokens_of`)."""
    provider_call_ceiling: int | None = None
    """A hard ceiling on provider calls for the run (a call and a gateway retry are two):
    it stops (``provider_call_ceiling``) before sending a check whose worst case would pass it,
    and after any check that did. For a diagnostic run, whose cost is set in calls."""
    provider_calls_used: int = 0
    clock: Callable[[], float] = time.monotonic
    usage_class: str = "calibration"
    """The consumer of the project's quota every check of the run is tagged with (M3-08):
    ``calibration`` here, ``red_team`` for the red-team run, ``test`` for the gate simulation. With
    quotas on, the engine's gateway then queues these checks behind every
    production class and spends the consumer's allowance, never a tenant's share."""
    avoid_minute_boundary: bool = False
    """No check starts between :55 and :10 of the UTC wall-clock minute: it waits until :10
    (M0-02: the provider stalled around the top of the minute in two runs). The argument that
    this doesn't bias the measurement: a check's input is fixed by its row and nonce, and
    nothing the engine sends depends on the clock, so send time has no route into a score. That
    is an argument, not a measurement: no run compared scores sent at different times.
    Calibration only."""
    wall_clock: Callable[[], float] = time.time
    """Seconds since the epoch (UTC); a test passes a fake."""
    min_interval_s: float = 0.0
    """The least time between the starts of two checks. The gateway holds each non-production
    consumer to a tenth of the project's token target, and fails a check fast with
    ``token_rate`` (no provider call) when a run outruns that; a live run paces itself under
    it rather than lose checks to its own limiter."""
    admission_wait: Callable[[str, int], float] | None = None
    """``(consumer, tokens) -> seconds``: how long the gateway's limiter would make a check of
    that many API tokens wait (0.0 if it would admit it now). When set, each check waits
    that long before it is sent, for its own estimate, so a run spaced by an average cannot
    refuse itself on a larger check. Pass ``engine.gateway.consumer_admission_wait``."""
    admission_margin: float = ADMISSION_MARGIN
    """The estimate is raised by this much before the wait is asked for
    (:data:`ADMISSION_MARGIN`)."""
    admission_waits: int = 0
    admission_wait_s: float = 0.0
    _last_start: float | None = field(default=None, init=False, repr=False)
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep
    boundary_waits: int = 0
    boundary_wait_s: float = 0.0
    records: list[dict[str, Any]] = field(default_factory=list)
    connections: list[dict[str, Any]] = field(default_factory=list, init=False, repr=False)
    """The connection diagnostics of the calls made since the last check began (M0-02)."""

    def __post_init__(self) -> None:
        if hasattr(self.engine, "connection_hook"):  # every real engine; a stub may not
            self.engine.connection_hook = self._on_connection

    def _on_connection(self, info: Any) -> None:
        """The engine's connection hook: keeps each call's :meth:`CallInfo.diagnostics`
        (numbers, flags and event or exception *names*: never a header, URL or message)."""
        self.connections.append(info.diagnostics())

    async def wait_for_admission(self, estimate: int, row_id: str) -> float:
        """Sleeps until the limiter would admit a check of ``estimate`` API tokens; returns the
        seconds waited. Re-asked after each sleep (a check in debt from the one before may need
        more than one), and gives up after :data:`ADMISSION_ROUNDS` as a stop, not as a send: it
        writes why (``run_stopped``, ``admission_gave_up``) and nothing is sent."""
        if self.admission_wait is None or estimate <= 0:
            return 0.0
        need = max(1, math.ceil(estimate * self.admission_margin))
        waited = 0.0
        for _ in range(ADMISSION_ROUNDS):
            wait = self.admission_wait(self.usage_class, need)
            if wait <= 0:
                break
            wait += ADMISSION_SLACK_S
            await self.sleep(wait)
            waited += wait
        else:
            self.write(
                {"type": "run_stopped", "reason": "admission_gave_up", "example_id": row_id,
                 "tokens_asked": need, "rounds": ADMISSION_ROUNDS, "waited_s": round(waited, 3),
                 "before_sending": True,
                 "at": datetime.now(UTC).isoformat(timespec="milliseconds")}
            )  # fmt: skip
            raise StopRun(
                f"the limiter would not admit a check of about {need} tokens after "
                f"{waited:.0f} s of waiting: stopping before it is sent"
            )
        if waited:
            self.admission_waits += 1
            self.admission_wait_s += waited
        return waited

    def screen_record(self, record: Mapping[str, Any], row: Mapping[str, Any], draw: int) -> None:
        """Called with each check's record once it is written, before any stop rule. A runner
        with a rule of its own raises :class:`StopRun` here; this one has none."""

    def counts_as_failure(self, record: Mapping[str, Any]) -> bool:
        """Whether the record counts in the failure-rate stop rule."""
        return record["outcome"] == "failed"

    async def wait_out_minute_boundary(self) -> float:
        """Sleeps until :10 if now is in :55-:10 (UTC); returns the seconds waited."""
        waited = 0.0
        while (wait := boundary_wait(self.wall_clock())) > 0:
            await self.sleep(wait)
            waited += wait
        if waited:
            self.boundary_waits += 1
            self.boundary_wait_s += waited
        return waited

    def write(self, record: Mapping[str, Any]) -> None:
        with self.out.open("a") as fh:
            fh.write(json.dumps(record, sort_keys=True) + "\n")

    def gate_send(self, row: Mapping[str, Any]) -> None:
        """Called after the pacing and boundary waits, just before a check is sent. A runner with
        a reason not to send raises :class:`StopRun` here; this one has none."""

    async def check(self, row: Mapping[str, Any], draw: int, attempt: int = 1) -> dict[str, Any]:
        if live_exclusion(row) is not None:  # never reached: rows are filtered on load
            raise StopRun(f"refusing to send excluded row {row.get('id')}")
        from guardrail_engine.guard import CheckContext

        estimate = self.token_estimates.get(row["id"], 0)
        if self.min_interval_s > 0 and self._last_start is not None:
            wait = self._last_start + self.min_interval_s - self.clock()
            if wait > 0:
                await self.sleep(wait)
        await self.wait_for_admission(estimate, row["id"])
        if self.min_interval_s > 0:
            self._last_start = self.clock()
        if self.token_ceiling is not None and (
            self.tokens_used + MAX_PROVIDER_CALLS_PER_CHECK * estimate > self.token_ceiling
        ):  # before sending: the worst case for this check would pass the ceiling
            self.write({"type": "run_stopped", "reason": "token_ceiling",
                        "tokens_used": self.tokens_used, "token_ceiling": self.token_ceiling,
                        "example_id": row["id"], "before_sending": True,
                        "at": datetime.now(UTC).isoformat(timespec="milliseconds")})  # fmt: skip
            raise StopRun(
                f"{self.tokens_used:,} input tokens used and the next check could use "
                f"{MAX_PROVIDER_CALLS_PER_CHECK * estimate:,} more: over the ceiling of "
                f"{self.token_ceiling:,}; stopping before it is sent"
            )
        if self.provider_call_ceiling is not None and (
            self.provider_calls_used + MAX_PROVIDER_CALLS_PER_CHECK > self.provider_call_ceiling
        ):  # before sending: a call and its one retry could pass the ceiling
            self.write({"type": "run_stopped", "reason": "provider_call_ceiling",
                        "provider_calls_used": self.provider_calls_used,
                        "provider_call_ceiling": self.provider_call_ceiling,
                        "example_id": row["id"], "before_sending": True,
                        "at": datetime.now(UTC).isoformat(timespec="milliseconds")})  # fmt: skip
            raise StopRun(
                f"{self.provider_calls_used} provider calls made and the next check could make "
                f"{MAX_PROVIDER_CALLS_PER_CHECK} more: over the ceiling of "
                f"{self.provider_call_ceiling}; stopping before it is sent"
            )
        waited = await self.wait_out_minute_boundary() if self.avoid_minute_boundary else 0.0
        self.gate_send(row)  # after every wait: the last point before the request is sent
        tenant_id = tenant_of(row)[0]
        ctx = CheckContext(signed_context=self.verifier.issue(tenant_id),
                           conversation=context_items(row))  # fmt: skip
        started = datetime.now(UTC).isoformat(timespec="milliseconds")
        self.nonces.at(row["id"], draw, attempt)
        self.connections.clear()
        from guardrail_engine.gateway import usage_class as tag_usage

        with tag_usage(self.usage_class):
            verdict = await self.engine.check(ctx, row["guard_point"], row["content"])
        self.calls += 1
        record = {"type": "call", "phase": "main", "path": "engine", "example_id": row["id"],
                  "guard_point": row["guard_point"], "draw": draw, "attempt": attempt,
                  "rule": None, "nonce": self.nonces.last, "started_at": started,
                  **verdict_fields(verdict),
                  "connections": list(self.connections)}  # fmt: skip
        if waited:
            record["boundary_wait_s"] = round(waited, 3)
        self.write(record)
        self.screen_record(record, row, draw)
        if record["reason"] == "provider_safety":
            self.write({"type": "run_stopped", "reason": "provider_refusal",
                        "example_id": row["id"], "draw": draw, "at": started})  # fmt: skip
            raise ProviderBlockStop(f"provider refusal on {row['id']}: run stopped, not resent")
        if record["kind"] == "auth":
            self.write({"type": "run_stopped", "reason": "auth", "at": started})
            raise StopRun("auth failure: stopping")
        if record["outcome"] == "failed" and record["kind"] == "other":
            # Possibly a refusal code M1-13 hasn't mapped yet: never re-sent.
            self.write({"type": "run_stopped", "reason": "unclassified_failure",
                        "example_id": row["id"], "draw": draw, "at": started})  # fmt: skip
            raise StopRun(f"unclassified failure on {row['id']}: run stopped, not resent")
        if record["outcome"] == "answered" and record["problems"] and not record["probabilities"]:
            # No usable score for any noul question asked: it measures nothing, and
            # it is the one 200 shape an unmapped refusal could take. Never re-sent.
            self.write({"type": "run_stopped", "reason": "no_usable_answer_at_all",
                        "example_id": row["id"], "draw": draw, "at": started})  # fmt: skip
            raise StopRun(f"no usable score at all on {row['id']}: run stopped, not resent")
        self.provider_calls_used += (
            1 if record["provider_calls"] is None else record["provider_calls"]
        )
        if (
            self.provider_call_ceiling is not None
            and self.provider_calls_used > self.provider_call_ceiling
        ):
            self.write({"type": "run_stopped", "reason": "provider_call_ceiling",
                        "provider_calls_used": self.provider_calls_used,
                        "provider_call_ceiling": self.provider_call_ceiling,
                        "example_id": row["id"], "before_sending": False,
                        "at": started})  # fmt: skip
            raise StopRun(
                f"{self.provider_calls_used} provider calls made, over the ceiling of "
                f"{self.provider_call_ceiling}: stopping"
            )
        self.tokens_used += tokens_of(record, estimate)
        if self.token_ceiling is not None and self.tokens_used > self.token_ceiling:
            self.write({"type": "run_stopped", "reason": "token_ceiling",
                        "tokens_used": self.tokens_used, "token_ceiling": self.token_ceiling,
                        "example_id": row["id"], "before_sending": False,
                        "at": started})  # fmt: skip
            raise StopRun(
                f"{self.tokens_used:,} input tokens used, over the ceiling of "
                f"{self.token_ceiling:,}: stopping"
            )
        if record["reason"] == "contract_violation":
            self.contract_violations += 1
            if self.contract_violations >= CONTRACT_VIOLATION_CAP:
                self.write({"type": "run_stopped", "reason": "unusable_answers",
                            "contract_violations": self.contract_violations,
                            "example_id": row["id"], "at": started})  # fmt: skip
                raise StopRun(
                    f"{self.contract_violations} checks ended in contract_violation: stopping "
                    "(a systematic answer-format problem?)"
                )
        self.recent.append(self.counts_as_failure(record))
        if (failed := sum(self.recent)) > FAIL_FRACTION * FAIL_WINDOW:
            self.write({"type": "run_stopped", "reason": "failures", "failed_checks": failed,
                        "window_checks": len(self.recent), "example_id": row["id"],
                        "at": started})  # fmt: skip
            raise StopRun(
                f"{failed} of the last {len(self.recent)} checks failed (more than "
                f"{FAIL_FRACTION:.0%} of {FAIL_WINDOW}): stopping"
            )
        if record["outcome"] == "failed" and record["kind"] is None:
            self.write({"type": "run_stopped", "reason": f"engine_{record['reason']}",
                        "example_id": row["id"], "at": started})  # fmt: skip
            raise StopRun(f"engine returned {record['reason']} on {row['id']}: stopping")
        return record


def answered_draws(records: Sequence[Mapping[str, Any]]) -> set[tuple[str, int]]:
    return {(r["example_id"], r["draw"]) for r in records
            if r.get("type") == "call" and r["outcome"] == "answered"}  # fmt: skip


def attempts(records: Sequence[Mapping[str, Any]]) -> dict[tuple[str, int], int]:
    out: dict[tuple[str, int], int] = {}
    for r in records:
        if r.get("type") == "call":
            key = (r["example_id"], r["draw"])
            out[key] = max(out.get(key, 0), r.get("attempt", 1))
    return out


async def run_engine_path(
    runner: EngineRunner,
    rows: Sequence[Mapping[str, Any]],
    records: Sequence[Mapping[str, Any]],
    draws: int = DRAWS,
    log: Callable[[str], None] = lambda s: print(s, file=sys.stderr),
    reattempts: bool = True,
) -> None:
    """Every example, ``draws`` times, one check each; then one re-attempt of each draw that
    failed with a retryable kind (unless ``reattempts`` is False, for a diagnostic run that
    must stay at one check per example). Resumable: answered draws and spent attempts are
    skipped."""
    done, tried = answered_draws(records), attempts(records)
    for draw in range(1, draws + 1):
        for row in rows:
            if (row["id"], draw) not in done and tried.get((row["id"], draw), 0) < 1:
                await runner.check(row, draw)
        log(f"  engine path: draw {draw} done ({len(rows)} examples)")
    if not reattempts:
        return
    now = _read(runner.out)
    done, tried = answered_draws(now), attempts(now)
    failed = {(r["example_id"], r["draw"]) for r in now if r.get("type") == "call"
              and r["outcome"] == "failed" and r["kind"] in RETRYABLE_KINDS}  # fmt: skip
    by_id = {r["id"]: r for r in rows}
    redo = sorted(k for k in failed - done if tried.get(k, 1) < 2)
    for eid, draw in redo:
        await runner.check(by_id[eid], draw, attempt=2)
    if redo:
        log(f"  engine path: re-attempted {len(redo)} failed draws once")


def incomplete(records: Sequence[Mapping[str, Any]], draws: int) -> dict[str, int]:
    """Examples with fewer than ``draws`` answered draws: example -> answered count."""
    count: dict[str, int] = {}
    for eid, _ in answered_draws(records):
        count[eid] = count.get(eid, 0) + 1
    ids = {r["example_id"] for r in records
           if r.get("type") == "call" and r["outcome"] != "deterministic"}  # fmt: skip
    return {e: count.get(e, 0) for e in sorted(ids) if count.get(e, 0) < draws}


def complete_records(records: Sequence[Mapping[str, Any]], draws: int) -> list[dict[str, Any]]:
    """The records the R7 analysis may use: answered draws of complete examples only, so an
    unanswered draw never counts as an answer in either direction."""
    short = set(incomplete(records, draws))
    return [r for r in records if r.get("type") != "call"
            or (r["outcome"] == "answered" and r["example_id"] not in short)]  # fmt: skip


def direct_setup(golden: Path, rules: Path, additions: Path) -> Setup:
    """The direct harness's setup for the same files: its caps and floor@2 questions are the
    engine's (tested on every row), so it can check limits without building the engine."""
    return build_setup(golden, rules, additions, heldout=is_heldout(golden))


def preflight(rows: Sequence[Mapping[str, Any]], direct: Setup) -> dict[str, list[str]]:
    """Examples that would exceed a limit, found before any call (decided 2026-11-17):

    * ``content_too_large``: content over its guard point's cap as submitted (the engine
      blocks it with no model call);
    * ``content_too_large_after_redaction``: content within the cap that
      the engine's redaction grows past it, since a placeholder can be longer than the short
      PII it replaces (``a@b.co`` becomes ``[EMAIL]@b.co``). The Guard Service blocks it too,
      sized on the redacted text, so the check uses the engine's own ``redact_request``;
    * ``api_limit``: a request the Decisions API would refuse (``limit_exceeded``), by the
      engine's own estimate, on the redacted render."""
    from guardrail_engine.decision import DecisionLimitError, validate_request
    from guardrail_engine.guard.render import count_tokens

    out: dict[str, list[str]] = {
        "content_too_large": [], "content_too_large_after_redaction": [], "api_limit": [],
    }  # fmt: skip
    for row in rows:
        gp = row["guard_point"]
        cap = direct.max_content_tokens[gp]
        if count_tokens(row["content"]) > cap:
            out["content_too_large"].append(row["id"])
            continue
        if count_tokens(redacted(row).content) > cap:
            out["content_too_large_after_redaction"].append(row["id"])
            continue
        questions = {k: q for k, q in direct.questions[gp].items() if not k.endswith(V1_SUFFIX)}
        try:
            validate_request(render(row, fresh_nonce(row), cap), questions)
        except DecisionLimitError:
            out["api_limit"].append(row["id"])
    return out


def plan(
    rows: Sequence[Mapping[str, Any]],
    setup: EngineSetup,
    draws: int,
    direct: Setup,
    seed: str | None = None,
    token_ceiling: int | None = None,
    avoid_minute_boundary: bool = False,
) -> dict[str, Any]:
    """``seed``: the nonce seed the run would use (a fresh one if None); pass it to ``run
    --seed`` to run with exactly these nonces. ``token_ceiling``: the run's hard ceiling on API
    input tokens, if any; the plan says whether its own estimate fits."""
    registries = tool_registries(rows)
    flagged = preflight(rows, direct)
    seed = SeededNonces(seed if seed is not None else new_seed()).seed
    estimates = row_token_estimates(rows, direct)
    estimated = draws * sum(estimates.values())
    return {"path": "engine (build_engine)", "environment": ENVIRONMENT,
            "nonce_seed": seed,
            "nonces": "seeded: derived from nonce_seed per (example, draw, attempt)",
            "mode": "validation (held-out)" if setup.validation else "calibration",
            "max_input_tokens": setup.max_input_tokens or "platform default",
            "examples": len(rows), "checks": len(rows) * draws,
            "plus_up_to": "one re-attempt per timed-out, unavailable or rate-limited draw",
            "stops_after_contract_violations": CONTRACT_VIOLATION_CAP,
            "stops_on_failures": f"more than {FAIL_FRACTION:.0%} of the last {FAIL_WINDOW} checks",
            "would_exceed_a_limit": flagged,
            "estimated_input_tokens": estimated,
            "token_ceiling": token_ceiling,
            "avoid_minute_boundary": avoid_minute_boundary,
            "within_token_ceiling": None if token_ceiling is None else estimated <= token_ceiling,
            "rows_with_tools": sum(bool(r.get("tools")) for r in rows),
            "tool_registries": {t: len(reg) for t, reg in sorted(registries.items()) if reg},
            "files": setup.files}  # fmt: skip


async def run(args: argparse.Namespace) -> int:
    check_corpus(Path(args.golden))
    if args.draws < DRAWS and not args.pilot:
        print(f"refusing --draws {args.draws}: at least {DRAWS} (or --pilot)", file=sys.stderr)
        return 2
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    records = _read(out)
    if any(r.get("type") == "run_stopped" for r in records):
        print("this run was stopped; start a new --out file", file=sys.stderr)
        return 2
    rows, excluded = load_examples(Path(args.golden))
    setup = build_engine_setup(Path(args.golden), Path(args.rules), Path(args.additions))
    started = next((r for r in records if r.get("type") == "run_started"), None)
    if started and started.get("files") != setup.files:
        print("input files changed since this run started; start a new --out file",
              file=sys.stderr)  # fmt: skip
        return 2
    try:
        tool_registries(rows)  # a conflicting tool definition stops here, before any check
    except StopRun as e:
        print(str(e), file=sys.stderr)
        return 3
    direct = direct_setup(Path(args.golden), Path(args.rules), Path(args.additions))
    flagged = preflight(rows, direct)
    if any(flagged.values()):
        print(f"refusing to start: examples would exceed a limit {flagged}", file=sys.stderr)
        return 2
    estimates = row_token_estimates(rows, direct)
    estimated = args.draws * sum(estimates.values())
    if args.max_tokens is not None and estimated > args.max_tokens:
        print(f"refusing to start: the plan needs about {estimated:,} input tokens, over the "
              f"ceiling of {args.max_tokens:,}", file=sys.stderr)  # fmt: skip
        return 2
    planned_checks = args.draws * len(rows)
    if args.max_provider_calls is not None and planned_checks > args.max_provider_calls:
        print(
            f"refusing to start: the plan makes {planned_checks} checks, one provider call each "
            f"at least, over the ceiling of {args.max_provider_calls}",
            file=sys.stderr,
        )
        return 2
    recorded_seed = started.get("nonce_seed") if started else None
    if started is not None and recorded_seed is None:
        print("this run started without a nonce seed; start a new --out file", file=sys.stderr)
        return 2
    if args.seed is not None and recorded_seed is not None and args.seed != recorded_seed:
        print("--seed differs from the seed this run started with", file=sys.stderr)
        return 2
    try:
        nonces = SeededNonces(recorded_seed or args.seed or new_seed())
    except ValueError as e:
        print(str(e), file=sys.stderr)
        return 2
    async with calibration_engine(setup, rows, nonces=nonces) as (engine, verifier):
        runner = EngineRunner(
            out=out, engine=engine, verifier=verifier, nonces=nonces,
            token_ceiling=args.max_tokens, token_estimates=estimates,
            provider_call_ceiling=args.max_provider_calls,
            avoid_minute_boundary=args.avoid_minute_boundary,
        )  # fmt: skip
        runner.provider_calls_used = sum(  # a resumed run keeps what it has already made
            1 if r["provider_calls"] is None else r["provider_calls"]
            for r in records
            if r.get("type") == "call"
        )
        runner.tokens_used = sum(  # a resumed run keeps what it has already used
            tokens_of(r, estimates.get(r["example_id"], 0))
            for r in records
            if r.get("type") == "call"
        )
        runner.contract_violations = sum(
            r.get("type") == "call" and r.get("reason") == "contract_violation" for r in records
        )
        runner.recent.extend(
            r["outcome"] == "failed" for r in records if r.get("type") == "call"
        )  # a resumed run keeps its failure window
        if started is None:
            runner.write({
                "type": "run_started", "at": datetime.now(UTC).isoformat(timespec="seconds"),
                "path": "engine (build_engine, M1-11)", "environment": ENVIRONMENT,
                "files": setup.files, "examples": len(rows), "excluded": excluded,
                "exclusion_reason": "user instruction 2026-11-17: no harmful inputs to Google",
                "mode": "validation (held-out)" if setup.validation else "calibration",
                "phases": ["main"], "draws": args.draws, "pilot": bool(args.pilot),
                "floor_version": setup.floor_doc["floor_version"],
                "max_input_tokens": setup.max_input_tokens,
                "gateway": {"max_in_flight_per_key": engine.settings.gateway.max_in_flight_per_key},
                "nonce_seed": nonces.seed,
                "nonces": "seeded: derived from nonce_seed per (example, draw, attempt)",
                "contract_violation_cap": CONTRACT_VIOLATION_CAP,
                "estimated_input_tokens": estimated, "token_ceiling": args.max_tokens,
                "provider_call_ceiling": args.max_provider_calls,
                "reattempts": not args.no_reattempts,
                "avoid_minute_boundary": bool(args.avoid_minute_boundary),
                "minute_boundary_note": (
                    "no check starts between :55 and :10 (UTC); argued, not measured, not to "
                    "bias scores (a check's input does not depend on the clock)"
                    if args.avoid_minute_boundary else None
                ),
                "connection_diagnostics": "per check, from the adapter's connection hook",
                "failure_stop": f"more than {FAIL_FRACTION:.0%} of the last {FAIL_WINDOW} checks",
                "redaction": REDACTION_APPLIED,
            })  # fmt: skip
        try:
            await run_engine_path(
                runner, rows, records, draws=args.draws, reattempts=not args.no_reattempts
            )
            runner.write(finished_record(_read(out)))
        except StopRun as e:
            print(str(e), file=sys.stderr)
            return 3
        finally:
            print(f"checks made this session: {runner.calls}", file=sys.stderr)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("run", "plan"):
        p = sub.add_parser(name)
        if name == "run":
            p.add_argument("--out", required=True)
            p.add_argument("--pilot", action="store_true")
        p.add_argument("--draws", type=int, default=DRAWS)
        p.add_argument("--seed", default=None, help="nonce seed (32 hex); default a fresh one")
        p.add_argument("--max-tokens", type=int, default=None,
                       help="hard ceiling on API input tokens: refuses to start if the plan "
                            "needs more, and stops before a check that could pass it")  # fmt: skip
        p.add_argument("--max-provider-calls", type=int, default=None,
                       help="hard ceiling on provider calls (a call and its gateway retry are "
                            "two): refuses to start if the plan's checks exceed it, and stops "
                            "before a check that could pass it")  # fmt: skip
        p.add_argument("--avoid-minute-boundary", action="store_true",
                       help="start no check between :55 and :10 of the UTC minute (it waits "
                            "until :10): the provider stalled there in two runs")  # fmt: skip
        if name == "run":
            p.add_argument("--no-reattempts", action="store_true",
                           help="skip the pass that re-attempts failed draws, for a diagnostic "
                                "run that must stay at one check per example")  # fmt: skip
        p.add_argument("--golden", default="floor/golden.jsonl")
        p.add_argument("--rules", default="floor/rules.json")
        p.add_argument("--additions", default="floor/next/additions.json")
    args = parser.parse_args(argv)
    if args.command == "run":
        return asyncio.run(run(args))
    check_corpus(Path(args.golden))
    rows, excluded = load_examples(Path(args.golden))
    setup = build_engine_setup(Path(args.golden), Path(args.rules), Path(args.additions))
    try:
        direct = direct_setup(Path(args.golden), Path(args.rules), Path(args.additions))
        summary = plan(
            rows,
            setup,
            args.draws,
            direct,
            seed=args.seed,
            token_ceiling=args.max_tokens,
            avoid_minute_boundary=args.avoid_minute_boundary,
        )
    except (StopRun, ValueError) as e:
        print(str(e), file=sys.stderr)
        return 3
    print(json.dumps({**summary, "excluded": excluded}, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
