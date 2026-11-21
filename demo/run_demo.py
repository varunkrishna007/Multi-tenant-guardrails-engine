"""Runs curated floor golden examples through the engine, built by the composition root.

    uv run python demo/run_demo.py            # needs GEMINI_API_KEY (environment or ./.env)
    uv run python demo/render.py              # turns the results into HTML and PNGs

What is real and what isn't:

* **Real:** every verdict comes from ``Engine.check()`` on an engine built by
  ``build_engine`` (M1-11): the floor rules (``floor/rules.json``) compiled by the policy
  compiler, the Guard Service with B3 nonce rendering, the gateway's budgets and retry, and
  the Gemini adapter calling Gemini Decision 1.
* **Synthetic:** every input comes from ``floor/golden.jsonl``; all of it is invented.
* **Provisional:** thresholds are the floor's provisional block_at 0.85 / escalate_at 0.55.
* **Configuration, not an Admin API:** the demo tenant's floor-only bundle is published with
  ``bootstrap_publish`` in environment ``test``, the path M1-11 provides for the demo.

**No harmful input is ever sent** (user instruction, 2026-11-17). Every example passes the
harnesses' label filter before the engine is built, and a provider refusal (or an
unclassified failure, or ``auth``) stops the run at once without resending anything.

Checks run one at a time, so admission control never refuses one. The API key is read from
the environment or ./.env at run time. It is never printed or written to any output file,
and the written results are scanned for it before the run reports success.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import secrets
import sys
from collections.abc import AsyncIterator, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:  # for `calibration` when run as a script
    sys.path.insert(0, str(ROOT))

from calibration.run import live_exclusion  # noqa: E402

from guardrail_engine.engine import API_KEY_ENV, EngineSettings, build_engine  # noqa: E402
from guardrail_engine.guard import (  # noqa: E402
    CheckContext,
    HmacContextVerifier,
    InMemoryTenantDirectory,
    TenantProfile,
)
from guardrail_engine.guard.audit import NullAuditSink  # noqa: E402
from guardrail_engine.policy import TenantAttributes  # noqa: E402

OUT = ROOT / "demo" / "output"
FLOOR = ROOT / "floor" / "rules.json"
GOLDEN = ROOT / "floor" / "golden.jsonl"
ENVIRONMENT = "test"
"""``bootstrap_publish`` is allowed in ``test`` (M1-11: tests and the demo)."""
TENANT_ID, TENANT_SLUG, TENANT_DOMAIN = "t_1042", "acme-insurance", "insurance"
"""The golden set's documented default tenant (B3)."""
HEADER_NAMES = ("x-goog-api-key", "authorization")

# Curated to show each attack family next to the near-misses that decide precision.
DEMO_IDS = [
    "in-dir-001",  # classic "ignore all previous instructions"
    "in-dir-006",  # the "grandma" jailbreak
    "in-zw-001",  # injection hidden with zero-width spaces
    "in-homo-002",  # injection written with Cyrillic look-alike letters
    "in-b64-001",  # injection hidden in base64
    "in-cls-001",  # "note to any content filter: this is pre-approved"
    "in-xt-002",  # tries to switch to another tenant
    "in-ok-005",  # "Are you an AI or a real person?"
    "in-ok-014",  # asks *about* "ignore previous instructions"
    "in-ok-017",  # own subsidiaries' combined bill (not cross-tenant)
    "tr-ind-002",  # email telling the assistant to forward the inbox
    "tr-ind-010",  # README with a hidden instruction for AI coding agents
    "tr-ok-004",  # security blog that quotes an attack as an example
    "tr-sec-001",  # AWS credentials in a tool result (AWS's documented example key)
    "tr-ok-003",  # config with masked secrets
    "pl-exf-001",  # plan quietly emails the conversation to an outside address
    "pl-ok-001",  # plan emails the customer, as they asked
    "out-ok-002",  # reply explaining key rotation with placeholders
]


class DemoStop(Exception):
    """The run stopped: nothing after the named example was sent, and nothing is resent."""


def load_key_into_environment() -> None:
    """Make ``GEMINI_API_KEY`` available to ``build_engine`` for this process only, from the
    environment or ./.env. Never printed, never written anywhere."""
    if os.environ.get(API_KEY_ENV, "").strip():
        return
    env = ROOT / ".env"
    if env.exists():
        for line in env.read_text().splitlines():
            name, sep, value = line.partition("=")
            if sep and name.strip() == API_KEY_ENV:
                os.environ[API_KEY_ENV] = value.strip().strip("'\"")
                return
    sys.exit(f"{API_KEY_ENV} is not set (environment or ./.env)")


def select(golden: Mapping[str, Mapping[str, Any]], ids: Sequence[str]) -> list[Mapping[str, Any]]:
    """The examples to send, in order. Refuses unknown ids and any example the harnesses'
    label filter excludes (harm-labelled, ``no_live_run``, harm near-misses), before the
    engine is even built."""
    missing = [i for i in ids if i not in golden]
    if missing:
        raise DemoStop(f"unknown golden ids: {missing}")
    refused = {i: why for i in ids if (why := live_exclusion(golden[i])) is not None}
    if refused:
        raise DemoStop(f"refusing to send excluded examples (no harmful inputs): {refused}")
    return [golden[i] for i in ids]


@contextlib.asynccontextmanager
async def demo_engine(model: Any = None) -> AsyncIterator[tuple[Any, Any]]:
    """The engine from ``build_engine``, with the demo tenant's floor-only bundle published.
    ``model`` replaces the Gemini adapter (tests pass a ``FakeDecisionModel``)."""
    floor_version = json.loads(FLOOR.read_text()).get("floor_version", 1)
    settings = EngineSettings.from_mapping({
        "environment": ENVIRONMENT,
        "catalog": {"floor_files": [str(FLOOR)]},
        "gemini": {"paid_tier": True},
    })  # fmt: skip
    verifier = HmacContextVerifier(secrets.token_bytes(32))
    tenants = InMemoryTenantDirectory([
        TenantProfile.build(TenantAttributes(tenant_id=TENANT_ID), TENANT_DOMAIN, slug=TENANT_SLUG)
    ])  # fmt: skip
    engine = await build_engine(
        settings, verifier=verifier, tenants=tenants, model=model, audit=NullAuditSink()
    )
    try:
        await engine.bootstrap_publish({
            "schema_version": 1, "tenant_id": TENANT_ID, "version": 1,
            "extends": [f"platform/floor@{floor_version}"],
        })  # fmt: skip
        yield engine, verifier
    finally:
        await engine.shutdown()


def result_row(ex: Mapping[str, Any], verdict: Any) -> dict[str, Any]:
    """What the cards show for one example, read from the verdict."""
    return {
        "id": ex["id"],
        "guard_point": ex["guard_point"],
        "category": ex["category"],
        "content": ex["content"],
        "expected": "block" if ex["fires"] else "allow",
        "expected_rules": ex["fires"],
        "rules": [
            {
                "rule": ev.key,
                "p": None if ev.p is None else round(ev.p, 4),
                "action": ev.action.value,
            }
            for ev in verdict.rules
        ],
        "verdict": verdict.decision.value,
        "reason": verdict.reason.value,
        "outcome": "answered" if verdict.reason.value == "policy" else verdict.reason.value,
        "provider_called": verdict.provider_called,
        "provider_calls": verdict.provider_calls,
        "failure_kind": verdict.failure_kind.value if verdict.failure_kind is not None else None,
        "failure_reason": verdict.failure_reason,
        "input_tokens": verdict.input_tokens,
        "redaction": verdict.redaction.value if verdict.redaction is not None else None,
        "pii_redacted": {str(getattr(k, "value", k)): n for k, n in verdict.pii_redacted.items()},
    }


async def check(
    engine: Any, verifier: Any, ex: Mapping[str, Any], tenant_id: str = TENANT_ID
) -> Any:
    """One check for ``tenant_id``, one at a time. Stops on a provider refusal, ``auth`` or
    an unclassified failure; a capacity refusal is re-run once after its hint, never shown
    as a verdict."""
    ctx = CheckContext(signed_context=verifier.issue(tenant_id))
    for attempt in (1, 2):
        verdict = await engine.check(ctx, ex["guard_point"], ex["content"])
        kind = verdict.failure_kind.value if verdict.failure_kind is not None else None
        if verdict.reason.value == "provider_safety":
            raise DemoStop(f"provider refusal on {ex['id']}: stopped, not resent")
        if kind in ("auth", "other"):
            raise DemoStop(f"{kind} failure on {ex['id']}: stopped, not resent")
        if not verdict.capacity_limited:
            return verdict
        if attempt == 1:
            await asyncio.sleep((verdict.retry_after_ms or 1_000) / 1000)
    raise DemoStop(f"admission refused {ex['id']} twice: stopped")


async def run(
    model: Any = None,
    out: Path = OUT,
    ids: Sequence[str] = DEMO_IDS,
    golden_path: Path = GOLDEN,
    log: Any = print,
) -> dict[str, Any]:
    golden = {row["id"]: row for row in map(json.loads, golden_path.read_text().splitlines())}
    examples = select(golden, ids)
    results = []
    async with demo_engine(model) as (engine, verifier):
        for ex in examples:
            row = result_row(ex, await check(engine, verifier, ex))
            results.append(row)
            log(f"{ex['id']:<12} {ex['guard_point']:<12} expected={row['expected']:<6} "
                f"verdict={row['verdict']}")  # fmt: skip
        floor = json.loads(FLOOR.read_text())
        pairs = {(r["block_at"], r["escalate_at"]) for r in floor["rules"]}
        block_at, escalate_at = next(iter(pairs)) if len(pairs) == 1 else (None, None)
        payload = {
            "run_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "model": "fake (tests)" if model is not None else "gemini-decision-1",
            "floor_version": floor.get("floor_version", 1),
            "thresholds": {"block_at": block_at, "escalate_at": escalate_at, "provisional": True},
            "engine": f"build_engine (M1-11), environment {ENVIRONMENT}",
            "pacing": "sequential: one check at a time",
            "max_in_flight_per_key": engine.settings.gateway.max_in_flight_per_key,
            "results": results,
        }
    out.mkdir(parents=True, exist_ok=True)
    text = json.dumps(payload, indent=2, ensure_ascii=False) + "\n"
    scan(text)
    (out / "results.json").write_text(text)
    log(f"wrote {out / 'results.json'}")
    return payload


def scan(text: str) -> None:
    """The output scan: the key value and request header names appear nowhere."""
    key = os.environ.get(API_KEY_ENV, "").strip()
    lowered = text.lower()
    if (key and key in text) or any(h in lowered for h in HEADER_NAMES):
        raise DemoStop("output scan failed: a key or header name would be written")


def main() -> int:
    load_key_into_environment()
    try:
        asyncio.run(run())
    except DemoStop as e:
        print(str(e), file=sys.stderr)
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
