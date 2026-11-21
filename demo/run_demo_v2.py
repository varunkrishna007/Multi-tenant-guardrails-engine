"""Demo v2, cards 4-9: ethics, bias, tenant rules and honest failure (``demo/SPEC.md``).

    uv run python demo/run_demo_v2.py --live    # live Gemini calls: needs explicit approval
    uv run python demo/render_v2.py             # results-v2.json -> report-v2.html and cards

Every live verdict comes from ``Engine.check()`` on an engine built by ``build_engine``
(M1-11): floor rules, the Responsible AI pack's rules and, for card 8, a tenant's own rules,
all compiled by the policy compiler and scored through the Guard Service and gateway. The
checks run one at a time, so admission control never refuses one.

**What is real now (M4-10).** The engine loads the pack from ``packs/responsible_ai/pack.json`` (a
schema version 2 pack document) and applies ``max_action`` itself: the two escalate-only rules
(``d__self_harm_risk``, ``d__vulnerability``) cannot block, whatever the probability. The demo only
*reports* where a cap bit: ``apply_max_action`` shows what a rule would have done without it.

**Shims, each labelled on its card and in the report** (the engine lacks the feature):

* **No Admin API.** Card 8's tenant bundle is read from ``demo/tenants/`` and published
  with ``bootstrap_publish`` (environment ``test``).
* **Card 9 is simulated:** the engine's own fake model scripted to time out. It is never a
  real outage, and the results say so.

**No harmful input is ever sent** (user instruction, 2026-11-17, U4). Every example passes
the harnesses' label filter before the engine is built, and a provider refusal stops the run
with nothing resent. The observe-only harm rule (``d__harm_facilitation``, U5) is **not
loaded** into the demo's pack: its question text is harm vocabulary, and nothing about the
demo needs the provider to see it. Card 5 describes it in text only.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import secrets
import sys
from collections.abc import AsyncIterator, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:  # for `calibration` and `demo` when run as a script
    sys.path.insert(0, str(ROOT))

from calibration.run import FAIRNESS_DELTA, live_exclusion  # noqa: E402

from demo import run_demo  # noqa: E402
from guardrail_engine.decision import FakeDecisionModel  # noqa: E402
from guardrail_engine.decision.port import FailureKind  # noqa: E402
from guardrail_engine.engine import EngineSettings, build_engine  # noqa: E402
from guardrail_engine.floor_file import load_floor_file  # noqa: E402
from guardrail_engine.guard import (  # noqa: E402
    HmacContextVerifier,
    InMemoryTenantDirectory,
    TenantProfile,
)
from guardrail_engine.guard.audit import NullAuditSink  # noqa: E402
from guardrail_engine.guard.fusion import threshold_action  # noqa: E402
from guardrail_engine.guard.verdict import Action, most_severe  # noqa: E402
from guardrail_engine.policy import (  # noqa: E402
    InMemoryCatalog,
    InMemoryToolRegistry,
    PlatformSettings,
    PolicyCompiler,
    TenantAttributes,
)
from guardrail_engine.policy.catalog import PackVersion  # noqa: E402
from guardrail_engine.sdk import MESSAGES, Guard, GuardContext  # noqa: E402

OUT = run_demo.OUT
FLOOR = run_demo.FLOOR
PACK_FILE = ROOT / "packs" / "responsible_ai" / "pack.json"
TENANT_DIR = ROOT / "demo" / "tenants"
SOURCES = {
    "fl": ROOT / "floor" / "golden.jsonl",
    "rai": ROOT / "packs" / "responsible_ai" / "golden.jsonl",
}
"""Example ids repeat across the two sets (105 ids appear in both), so a pick names its
set: ``fl`` is ``floor/golden.jsonl``, ``rai`` is ``packs/responsible_ai/golden.jsonl``."""

EXCLUDED_PACK_RULES = frozenset({"d__harm_facilitation"})
"""Not loaded into the demo (see the module docstring)."""


@dataclass(frozen=True)
class Tenant:
    id: str
    slug: str
    domain: str


MAIN = Tenant("t_1042", "acme-insurance", "insurance")
"""The golden sets' documented default tenant: floor plus the Responsible AI pack."""
CUSTOM = Tenant("t_1050", "beacon-insurance", "insurance")
"""Card 8's tenant: floor, pack and two rules of its own (``demo/tenants/``)."""


@dataclass(frozen=True)
class Pick:
    source: str
    id: str


# Final example ids (SPEC §3: "picked when the demo is built"). Each was read; none is
# harm-labelled or ``no_live_run``, and ``select`` enforces that again at run time.
CARD4 = [  # (support): job loss, a bereavement, and a figure of speech. No self-harm row: those
    # are withheld (M4-10's conservative scope, U4), so the escalate-only cap is shown on the
    # vulnerability rule, which has the same ``max_action``.
    Pick("rai", "in-vu-002"),
    Pick("rai", "in-vu-001"),
    Pick("rai", "in-ok-006"),
]
CARD6_BLOCKED = [  # a plan that prices by sex, a tool call that routes by surname, a stereotype
    Pick("rai", "pl-pb-006"),
    Pick("rai", "tc-pb-002"),
    Pick("rai", "out-st-002"),
]
CARD6_ALLOWED = [  # large print as requested, a language as requested, pricing on claims history
    Pick("rai", "tc-ok-003"),
    Pick("rai", "tc-ok-004"),
    Pick("rai", "tc-ok-002"),
]
CARD7_PAIRS = [  # counterfactual pair ids: 4 from the pack (2 allow, 2 act), 4 from the floor
    Pick("rai", "rai-cf-001"),  # name swap, allow
    Pick("rai", "rai-cf-006"),  # name swap, act (vulnerability)
    Pick("rai", "rai-cf-011"),  # sex swap (husband/wife), act (vulnerability)
    Pick("rai", "rai-cf-018"),  # name swap in a reply, allow
    Pick("fl", "fl-cf-009"),  # dialect, allow
    Pick("fl", "fl-cf-014"),  # language (Spanish / English), allow
    Pick("fl", "fl-cf-022"),  # language (English / Spanish) injection, act
    Pick("fl", "fl-cf-026"),  # dialect (Scots) injection, act
]
CARD8_SAMPLES = [
    {"id": "t8-fires", "guard_point": "output", "category": "tenant rule",
     "content": "You should move your savings into the Growth Fund.",
     "fires": ["t__fin_adv_01"]},
    {"id": "t8-nearmiss", "guard_point": "output", "category": "tenant rule",
     "content": "A deductible is the amount you pay first.", "fires": []},
]  # fmt: skip
CARD9_TEXT = "Can you tell me when my policy renews?"


class DemoStop(run_demo.DemoStop):
    """The run stopped: nothing after the named example was sent, and nothing is resent."""


# --------------------------------------------------------------------------- shims


@dataclass(frozen=True)
class Pack:
    version: PackVersion
    ref: str
    """The ``extends`` entry that selects it, ``domain/responsible_ai@1``."""
    caps: Mapping[str, str]
    """Rule key -> its ``max_action``: the most severe action the rule may take."""
    questions: Mapping[str, str]
    """Rule key -> its question, for the cards' labels."""
    not_loaded: tuple[str, ...]


def load_pack(path: Path = PACK_FILE, exclude: frozenset[str] = EXCLUDED_PACK_RULES) -> Pack:
    """Read the pack document and drop the rules this demo must never send (the harm rule: U4,
    U5), then read it with the engine's own ``PackVersion``. ``caps`` is each rule's
    ``max_action``, which the engine applies itself."""
    flat = json.loads(path.read_text())
    kept = [r for r in flat["rules"] if r["key"] not in exclude]
    document = {**flat, "rules": kept}
    version = PackVersion.from_document(document)
    return Pack(
        version=version,
        ref=version.ref,
        caps={r["key"]: r.get("max_action", "block") for r in kept},
        questions={r["key"]: r["question"]["instructions"] for r in kept},
        not_loaded=tuple(sorted(r["key"] for r in flat["rules"] if r["key"] in exclude)),
    )


def apply_max_action(
    rules: Sequence[Any], caps: Mapping[str, str], engine_decision: str, reason: str
) -> tuple[list[dict[str, Any]], str, bool]:
    """Report each rule's action and where its ``max_action`` cap held it down. **The engine
    applies the cap itself** (M4-10): ``action`` is the engine's, ``engine_action`` is what the
    rule's thresholds alone would have called for. The decision is the engine's, unchanged.
    Returns (per-rule rows, the decision, whether a cap bit)."""
    rows: list[dict[str, Any]] = []
    for ev in rules:
        uncapped = ev.action
        if ev.p is not None and ev.block_at is not None and ev.escalate_at is not None:
            uncapped = threshold_action(ev.p, ev.block_at, ev.escalate_at)
        rows.append({
            "rule": ev.key,
            "p": None if ev.p is None else round(ev.p, 4),
            "action": ev.action.value,
            "engine_action": uncapped.value,
            "layer": ev.layer,
            "mode": ev.mode,
        })  # fmt: skip
    capped = reason == "policy" and any(r["action"] != r["engine_action"] for r in rows)
    return rows, engine_decision, capped


# --------------------------------------------------------------------------- examples


def load_golden(source: str) -> list[dict[str, Any]]:
    path = SOURCES[source]
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def select(
    picks: Sequence[Pick],
    goldens: Mapping[str, Sequence[dict[str, Any]]],
    *,
    provider: bool = True,
) -> list[dict]:
    """The examples for ``picks``, each with its ``source``. Refuses an unknown id and any
    example the harnesses' label filter excludes (harm-labelled, ``no_live_run``, harm
    near-misses), before the engine is even built, **when the run goes to a provider**
    (``provider=True``, the default). A run on the engine's own fake model sends nothing
    anywhere, so it may use an excluded example (the M4-10 conservative scope withholds the
    bias and self-harm rows from every provider; the offline demo still shows them)."""
    out, refused, missing = [], {}, []
    for pick in picks:
        rows = {r["id"]: r for r in goldens[pick.source]}
        if pick.id not in rows:
            missing.append(f"{pick.source}:{pick.id}")
            continue
        row = {**rows[pick.id], "source": pick.source}
        if provider and (why := live_exclusion(row)) is not None:
            refused[f"{pick.source}:{pick.id}"] = why
        out.append(row)
    if missing:
        raise DemoStop(f"unknown golden ids: {missing}")
    if refused:
        raise DemoStop(f"refusing to send excluded examples (no harmful inputs): {refused}")
    return out


def pair_members(
    pick: Pick, golden: Sequence[dict[str, Any]], *, provider: bool = True
) -> list[dict[str, Any]]:
    members = [{**r, "source": pick.source} for r in golden if r.get("pair") == pick.id]
    if len(members) != 2:
        raise DemoStop(f"pair {pick.id} has {len(members)} members, not 2")
    for row in members:
        if provider and (why := live_exclusion(row)) is not None:
            raise DemoStop(f"refusing to send {row['id']} (no harmful inputs): {why}")
    return members


def expected_action(fires: Sequence[str], caps: Mapping[str, str]) -> str:
    """The action the label calls for: ``allow``, or the most severe a fired rule may take."""
    if not fires:
        return "allow"
    worst = most_severe(*(Action(caps.get(k, "block")) for k in fires))
    return worst.value


# --------------------------------------------------------------------------- the engine


@dataclass
class Demo:
    engine: Any
    verifier: Any
    pack: Pack
    catalog: Any
    floor_version: int


def custom_bundle() -> dict[str, Any]:
    return json.loads((TENANT_DIR / "beacon-insurance.json").read_text())


@contextlib.asynccontextmanager
async def demo_engine(model: Any = None, pack: Pack | None = None) -> AsyncIterator[Demo]:
    """The engine from ``build_engine``: the real floor, the pack (via the shim), and two
    tenants. ``model`` replaces the Gemini adapter (tests and card 9 pass a fake)."""
    pack = pack or load_pack()
    floor = load_floor_file(FLOOR)
    catalog = InMemoryCatalog(floors=[floor], packs=[pack.version])
    settings = EngineSettings.from_mapping({
        "environment": run_demo.ENVIRONMENT,
        "gemini": {"paid_tier": True},
    })  # fmt: skip
    verifier = HmacContextVerifier(secrets.token_bytes(32))
    directory = InMemoryTenantDirectory([
        TenantProfile.build(TenantAttributes(tenant_id=t.id), t.domain, slug=t.slug)
        for t in (MAIN, CUSTOM)
    ])  # fmt: skip
    engine = await build_engine(
        settings, verifier=verifier, tenants=directory, model=model, catalog=catalog,
        audit=NullAuditSink(),
    )  # fmt: skip
    try:
        main = {"schema_version": 1, "tenant_id": MAIN.id, "version": 1,
                "extends": [f"platform/floor@{floor.version}", pack.ref]}  # fmt: skip
        await engine.bootstrap_publish(main)
        await engine.bootstrap_publish(custom_bundle())
        yield Demo(engine, verifier, pack, catalog, floor.version)
    finally:
        await engine.shutdown()


async def score(demo: Demo, tenant: Tenant, ex: Mapping[str, Any]) -> dict[str, Any]:
    """One check through the engine and what the cards show for it."""
    verdict = await run_demo.check(demo.engine, demo.verifier, ex, tenant_id=tenant.id)
    reason = verdict.reason.value
    rules, decision, capped = apply_max_action(
        verdict.rules, demo.pack.caps, verdict.decision.value, reason
    )
    return {
        "id": ex["id"],
        "source": ex.get("source", "inline"),
        "tenant": tenant.id,
        "guard_point": ex["guard_point"],
        "category": ex["category"],
        "content": ex["content"],
        "expected": expected_action(ex["fires"], demo.pack.caps),
        "expected_rules": ex["fires"],
        "rules": rules,
        "verdict": decision,
        "engine_decision": verdict.decision.value,
        "capped_by_max_action": capped,
        "reason": reason,
        "outcome": "answered" if reason == "policy" else reason,
        "provider_called": verdict.provider_called,
        "provider_calls": verdict.provider_calls,
        "failure_kind": verdict.failure_kind.value if verdict.failure_kind is not None else None,
        "failure_reason": verdict.failure_reason,
        "input_tokens": verdict.input_tokens,
        "redaction": verdict.redaction.value if verdict.redaction is not None else None,
        "pii_redacted": {str(getattr(k, "value", k)): n for k, n in verdict.pii_redacted.items()},
        "bundle_hash": verdict.bundle_hash,
    }


def highest_p(row: Mapping[str, Any]) -> float | None:
    ps = [r["p"] for r in row["rules"] if r["p"] is not None]
    return max(ps) if ps else None


def pair_result(pick: Pick, a: Mapping[str, Any], b: Mapping[str, Any]) -> dict[str, Any]:
    """One counterfactual pair: both rows, the highest p on each side and |Δp| (R4.5). A
    pair is flagged when the verdicts differ or |Δp| is over 0.10; it is shown either way."""
    pa, pb = highest_p(a), highest_p(b)
    delta = None if pa is None or pb is None else round(abs(pa - pb), 4)
    same = a["verdict"] == b["verdict"]
    answered = a["outcome"] == "answered" and b["outcome"] == "answered"
    return {
        "pair": pick.id, "source": pick.source, "a": a, "b": b,
        "highest_p": [pa, pb], "delta_p": delta, "same_verdict": same, "answered": answered,
        "flagged": answered and (not same or (delta is not None and delta > FAIRNESS_DELTA)),
    }  # fmt: skip


def compile_counts(demo: Demo) -> dict[str, Any]:
    """Card 8's numbers, from the real compiler: the compiled questions per guard point by
    layer, against the platform's question budget (R6.1)."""
    settings = PlatformSettings()
    compiler = PolicyCompiler(demo.catalog, InMemoryToolRegistry(), settings)
    policy = compiler.compile(custom_bundle(), TenantAttributes(tenant_id=CUSTOM.id))
    counts: dict[str, Any] = {}
    for gp, point in policy.guard_points.items():
        by_layer = {"floor": 0, "pack": 0, "tenant": 0}
        for rule in point.rules.values():
            by_layer[rule.layer] += 1
        counts[gp] = {**by_layer, "total": len(point.rules),
                      "budget": settings.question_budgets.for_guard_point(gp)}  # fmt: skip
    return {"bundle_hash": policy.bundle_hash, "guard_points": counts,
            "not_loaded": list(demo.pack.not_loaded)}  # fmt: skip


async def simulated_failure() -> dict[str, Any]:
    """Card 9: a **simulated** timeout. The engine's own fake model is scripted to time out
    on the call and on the gateway's one retry. Never a real outage, never the network."""
    fake = FakeDecisionModel(responder=lambda text, key, q: 0.01)
    fake.fail_next(FailureKind.TIMEOUT, times=2)
    async with demo_engine(model=fake) as demo:
        guard = Guard(demo.engine)
        result = await guard.check("input", CARD9_TEXT, GuardContext(demo.verifier.issue(MAIN.id)))
        calls = len(fake.calls)
    blocks = int(result.decision == "block")
    return {
        "simulated": True,
        "content": CARD9_TEXT,
        "decision": result.decision,
        "reason": result.reason,
        "retryable": result.retryable,
        "failure_reason": result.failure_reason.value if result.failure_reason else None,
        "released": result.released,
        "user_message": result.user_message,
        "policy_message": MESSAGES["policy"],
        "model_calls": calls,
        # Block-rate alerting (M4-04, not built yet) will count policy blocks only. This
        # applies that rule to this one check, as a labelled illustration.
        "blocks": blocks,
        "policy_blocks": int(result.decision == "block" and result.reason == "policy"),
        "model_failures": int(result.reason == "model_failure"),
    }


# --------------------------------------------------------------------------- the run


async def run_all(
    model: Any = None, out: Path = OUT, log: Any = print, write: bool = True
) -> dict[str, Any]:
    goldens = {source: load_golden(source) for source in SOURCES}
    provider = not isinstance(model, FakeDecisionModel)  # a fake sends nothing anywhere
    card4 = select(CARD4, goldens, provider=provider)
    # Card 6's blocked column is rows labelled for the bias rules, which are all
    # withheld (U4), so a provider run shows only the allowed column; the blocked one is
    # offline-only (fake model).
    card6_blocked = [] if provider else select(CARD6_BLOCKED, goldens, provider=False)
    card6_allowed = select(CARD6_ALLOWED, goldens, provider=provider)
    pairs = [(p, *pair_members(p, goldens[p.source], provider=provider)) for p in CARD7_PAIRS]
    samples = [{**s, "source": "inline"} for s in CARD8_SAMPLES]

    async with demo_engine(model) as demo:

        async def many(tenant: Tenant, examples: Sequence[Mapping[str, Any]]) -> list[dict]:
            rows = []
            for ex in examples:
                row = await score(demo, tenant, ex)
                rows.append(row)
                log(f"{ex['source']}:{ex['id']:<12} {ex['guard_point']:<10} "
                    f"expected={row['expected']:<8} verdict={row['verdict']}")  # fmt: skip
            return rows

        log("card 4")
        r4 = await many(MAIN, card4)
        log("card 6")
        r6b, r6a = await many(MAIN, card6_blocked), await many(MAIN, card6_allowed)
        log("card 7")
        r7 = []
        for pick, a, b in pairs:
            ra, rb = await many(MAIN, [a, b])
            r7.append(pair_result(pick, ra, rb))
        log("card 8")
        r8 = await many(CUSTOM, samples)
        counts = compile_counts(demo)
        if {r["bundle_hash"] for r in r8} != {counts["bundle_hash"]}:
            raise DemoStop("card 8's counts are not from the policy the engine ran")
        max_in_flight = demo.engine.settings.gateway.max_in_flight_per_key
        floor_version = demo.floor_version
        pack = demo.pack

    log("card 9 (simulated, fake model)")
    card9 = await simulated_failure()
    answered = [r for rows in (r4, r6b, r6a, r8) for r in rows]
    answered += [r for p in r7 for r in (p["a"], p["b"])]
    payload = {
        "run_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "model": "fake (tests)" if model is not None else "gemini-decision-1",
        "floor_version": floor_version,
        "pack": pack.ref,
        "thresholds": {
            "floor": {"block_at": 0.85, "escalate_at": 0.55, "provisional": True},
            "pack": "per rule, provisional (packs/responsible_ai/pack.json)",
        },
        "engine": f"build_engine (M1-11), environment {run_demo.ENVIRONMENT}",
        "pacing": "sequential: one check at a time",
        "max_in_flight_per_key": max_in_flight,
        "shims": {
            "pack_loading": "pack rules loaded by the demo; engine support arrives in M4-10",
            "max_action": "escalate-only cap applied by the engine (M4-10); the demo reports it",
            "tenant_bundle": "read from demo/tenants/, not published through an Admin API",
            "card_9": "simulated failure: the engine's fake model scripted to time out",
        },
        "pack_rules_not_loaded": list(pack.not_loaded),
        "card4": r4,
        "card6": {"blocked": r6b, "allowed": r6a, "blocked_offline_only": provider},
        "card7": r7,
        "card8": {"samples": r8, "compiled": counts, "bundle": custom_bundle()},
        "card9": card9,
        "not_answered": [
            r["id"] for r in answered if r["outcome"] != "answered" or not r["provider_called"]
        ],
    }
    if write:
        out.mkdir(parents=True, exist_ok=True)
        text = json.dumps(payload, indent=2, ensure_ascii=False) + "\n"
        run_demo.scan(text)
        (out / "results-v2.json").write_text(text)
        log(f"wrote {out / 'results-v2.json'}")
    return payload


# --------------------------------------------------------------------------- the re-run


def unanswered_rows(payload: Mapping[str, Any]) -> list[dict[str, Any]]:
    """The live rows the model didn't answer (never a verdict), in card order."""
    return [r for r in all_live(payload) if not answered(r)]


def answered(row: Mapping[str, Any]) -> bool:
    return row["outcome"] == "answered" and bool(row["provider_called"])


def first_attempt(row: Mapping[str, Any]) -> dict[str, Any]:
    return {k: row.get(k) for k in ("outcome", "reason", "provider_calls", "failure_kind")}


async def rerun_unanswered(
    path: Path = OUT / "results-v2.json",
    v1_path: Path = OUT / "results.json",
    model: Any = None,
    log: Any = print,
) -> dict[str, Any]:
    """Re-run, **once**, exactly the live checks that got no model answer, and write the
    results back. Authorised for one follow-up run (2026-11-17).

    * The same label filter applies (``live_exclusion`` on the golden row) and a provider
      refusal stops it, nothing resent. Each check is one call plus the gateway's one retry,
      so at most two provider calls per check.
    * A check that fails again stays *no answer*: it is not retried further.
    * Answered checks are never touched. A new row keeps the first attempt under
      ``first_attempt`` and is marked ``rerun``. The payload gets a ``rerun`` summary with
      the first run's counts, so the cards can say so. A results file already re-run is
      refused: this is a one-time follow-up, not a loop.
    """
    payload = json.loads(path.read_text())
    if payload.get("rerun"):
        raise DemoStop("these results were already re-run once; not re-running again")
    todo = unanswered_rows(payload)
    if not todo:
        raise DemoStop("every check was answered; nothing to re-run")
    goldens = {source: {r["id"]: r for r in load_golden(source)} for source in SOURCES}
    inline = {s["id"]: {**s, "source": "inline"} for s in CARD8_SAMPLES}
    tenants = {t.id: t for t in (MAIN, CUSTOM)}
    examples = []
    for row in todo:  # filter every one before any is sent
        found = inline.get(row["id"]) if row["source"] == "inline" else None
        if row["source"] != "inline":
            golden = goldens[row["source"]].get(row["id"])
            found = None if golden is None else {**golden, "source": row["source"]}
        if found is None:
            raise DemoStop(f"cannot find {row['source']}:{row['id']} to re-run")
        if (why := live_exclusion(found)) is not None:
            raise DemoStop(f"refusing to send {row['id']} (no harmful inputs): {why}")
        examples.append((row, found))
    first_run_checks = len(json.loads(v1_path.read_text())["results"]) + len(all_live(payload))
    redone = []
    async with demo_engine(model) as demo:
        for row, ex in examples:
            new = await score(demo, tenants[row["tenant"]], ex)
            previous = first_attempt(row)
            row.clear()
            row.update(new)
            row["first_attempt"], row["rerun"] = previous, True
            redone.append(row)
            log(f"{ex['source']}:{ex['id']:<12} first={previous['reason']} -> now={row['outcome']} "
                f"(kind={row.get('failure_kind')}, calls={row['provider_calls']})")  # fmt: skip
    for i, x in enumerate(payload["card7"]):  # a pair is compared again once both answer
        if x["a"].get("rerun") or x["b"].get("rerun"):
            payload["card7"][i] = pair_result(Pick(x["source"], x["pair"]), x["a"], x["b"])
    payload["not_answered"] = [r["id"] for r in unanswered_rows(payload)]
    payload["rerun"] = {
        "at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "ids": [r["id"] for r in redone],
        "first_run_checks": first_run_checks,
        "first_run_unanswered": len(redone),
        "answered": sum(answered(r) for r in redone),
        "unanswered": sum(not answered(r) for r in redone),
        "provider_calls": sum(r["provider_calls"] or 0 for r in redone),
    }
    text = json.dumps(payload, indent=2, ensure_ascii=False) + "\n"
    run_demo.scan(text)
    path.write_text(text)
    log(f"wrote {path}: {payload['rerun']}")
    return payload


def all_live(payload: Mapping[str, Any]) -> list[dict[str, Any]]:
    rows = list(payload["card4"]) + payload["card6"]["blocked"] + payload["card6"]["allowed"]
    rows += payload["card8"]["samples"]
    for x in payload["card7"]:
        rows += [x["a"], x["b"]]
    return rows


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--live", action="store_true",
        help="make live Gemini calls (about 27 checks). Needs explicit approval.",
    )  # fmt: skip
    parser.add_argument(
        "--rerun-unanswered", action="store_true",
        help="with --live: re-run, once, only the checks the model didn't answer",
    )  # fmt: skip
    args = parser.parse_args(argv)
    if not args.live:
        print("refusing to run: pass --live to make live Gemini calls (needs explicit approval)",
              file=sys.stderr)  # fmt: skip
        return 2
    run_demo.load_key_into_environment()
    try:
        asyncio.run(rerun_unanswered() if args.rerun_unanswered else run_all())
    except run_demo.DemoStop as e:
        print(str(e), file=sys.stderr)
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
