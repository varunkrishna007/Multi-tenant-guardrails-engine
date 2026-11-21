"""The M1 live gate as a simulation: scripted agent conversations through the engine to live Gemini.

    uv run python -m calibration.gate_simulation plan   [--conversations 100]
    uv run python -m calibration.gate_simulation run    --out calibration/results/X.jsonl
    uv run python -m calibration.gate_simulation report calibration/results/X.jsonl

The user replaced the 7-day dogfood with "a simulation of some 100 cases at max" (backlog, M1
live gate). A **conversation** is five guarded checks, one per guard point, in the order an
agent step takes them (``input``, ``plan``, ``tool_call``, ``tool_result``, ``output``). They
go through ``build_engine`` (the calibration engine path, so every stop of the calibration
runner applies) to the live provider at a steady pace: a conversation starts every
``--interval-s`` seconds (60 by default), its checks one after another ``--gap-s`` apart.

* **Benign and scripted.** Most checks are a fixed bank of benign conversations
  (:data:`SCRIPTS`), the same five turns whichever run. Nothing is generated.
* **A fixed share of attack rows**, recorded in ``run_started`` (``--attack-share``, 20%): for
  each guard point exactly that share of the conversations has its check at that guard point
  replaced by a sendable attack row (labelled for a floor rule) from the **floor golden**,
  chosen from the seed (decision 2026-11-17: held-out rows are reserved for held-out validation
  and their scores must not be seen before it, so none is ever sent here). The share is what
  the golden can fill at every guard point: 14%, 14 rows each, 70 attack checks of 500. The ids
  of every replaced slot are in ``run_started``.
* **The harm filter is code**, not a list: every row passes :func:`calibration.run.live_exclusion`
  when the pool is built (no ``*harm_facilitation`` label, no ``no_live_run`` tag, no ``-harm-``
  id) and again in ``EngineRunner.check`` before any request. A provider refusal stops the run.
* **All the calibration runner's stops stay on**: the first refusal, an auth failure, an
  unclassified failure, unusable answers, a failure rate over 20% of the last 50 checks, and
  hard ceilings on provider calls (600 by default) and API input tokens.
* **No minute-boundary avoidance.** We want the real behaviour (M0-02 found stalls near the top
  of the minute); the runner's ``--avoid-minute-boundary`` is not offered here.

``report`` is offline and measures the gate items that need no real users (backlog, M1 live
gate), each with its case count and a one-sided 95% bound where it is a rate:

1. **engine overhead** p95 (wall time of the check minus the gateway's), against 50 ms;
2. **end-to-end** p50 and p95 per guard point and input-size band, beside the R6.3 expected p50
   (band base + 380 ms + 2.0 ms per question) and the attempt deadline;
3. **timeout blocks outside slow episodes**: checks that ended ``timeout`` or ``unavailable``,
   over the checks outside episode minutes, with the bound, against 0.5%;
4. **slow episodes** (U7): consecutive minutes in each of which at least 25% of checks ended in
   a timeout or ``unavailable`` block, counting only minutes with at least 5 checks;
5. **the cold-call rate**: provider calls on a new connection, over all calls.

Gate (2), decided 2026-11-17: every shape's p50 within 20% of its R6.3 expected p50 (read
one-sidedly: faster than expected passes). p95 against the attempt deadline is information.
Gate (3): 500 checks cannot demonstrate 0.5%; the report gives the bound and says so.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import math
import random
import statistics
import sys
import time
from collections import Counter
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from calibration.engine_path import (
    EngineRunner,
    SeededNonces,
    StopRun,
    build_engine_setup,
    calibration_engine,
    direct_setup,
    new_seed,
    preflight,
    row_token_estimates,
    tool_registries,
)
from calibration.metrics import clopper_pearson_upper
from calibration.run import _read, live_exclusion, load_examples

GUARD_POINTS = ("input", "plan", "tool_call", "tool_result", "output")
MAX_CONVERSATIONS = 100
"""The user's cap: "some 100 cases at max"."""
ATTACK_SHARE = 0.14
"""What the floor golden can fill at every guard point (its sendable attack rows are fewest at
``output``: 14), of 100 conversations."""
P50_TOLERANCE = 0.20
"""Gate (2): each shape's p50 within 20% of its R6.3 expected p50 (decided 2026-11-17)."""
MIN_SHAPE_CHECKS = 5
INTERVAL_S = 60.0
GAP_S = 1.0
PROVIDER_CALL_CEILING = 600
POOL_MAX_CHARS = 8_000
"""Attack rows longer than this are left out of the pool (about 2K tokens): the gate wants
agent-sized checks, and a big row costs a big call."""
GOLDEN = "floor/golden.jsonl"
RULES = "floor/rules.json"
ADDITIONS = "floor/next/additions.json"

# R6.3 (after U7): expected p50 = band base + time-window allowance + 2.0 ms per question.
BAND_BASE_MS = ((1_024, 244), (4_096, 271), (8_192, 326), (16_384, 400))
WINDOW_ALLOWANCE_MS = 380
PER_QUESTION_MS = 2.0
ATTEMPT_MARGIN_MS = 400
ATTEMPT_MARGIN_FRACTION = 0.6
OVERHEAD_LIMIT_MS = 50.0  # gate (1)
TIMEOUT_BLOCK_LIMIT = 0.005  # gate (3)
EPISODE_MINUTE_SHARE = 0.25  # U7
EPISODE_MIN_CHECKS = 5  # U7
BLOCKING_KINDS = ("timeout", "unavailable")

# --------------------------------------------------------------------------- the script bank

SCRIPTS: tuple[tuple[str, str, str, str, str], ...] = (
    (
        "I forgot my password for the customer portal. How do I reset it?",
        '{"goal": "Help the customer reset their portal password.", "steps": [{"tool": '
        '"kb.search", "args": {"query": "reset portal password"}}]}',
        '{"tool": "kb.search", "args": {"query": "reset portal password"}}',
        "Knowledge base: To reset your portal password, select 'Forgot password', enter your "
        "email and follow the link we send you. Links expire after 30 minutes.",
        "To reset your password, go to the login page, choose 'Forgot password' and follow "
        "the link we email you. The link expires after 30 minutes.",
    ),
    (
        "Can you tell me where my claim is up to? The reference is CLM-20931.",
        '{"goal": "Tell the customer the status of their claim.", "steps": [{"tool": '
        '"claims.get", "args": {"id": "CLM-20931"}}]}',
        '{"tool": "claims.get", "args": {"id": "CLM-20931"}}',
        "Claim CLM-20931: status in review; an assessor has been assigned; last updated "
        "yesterday; no documents outstanding.",
        "Your claim CLM-20931 is currently in review. An assessor has been assigned and "
        "nothing further is needed from you right now.",
    ),
    (
        "What are your opening hours over the holiday period?",
        '{"goal": "Answer a question about holiday opening hours.", "steps": [{"tool": '
        '"kb.search", "args": {"query": "holiday opening hours"}}]}',
        '{"tool": "kb.search", "args": {"query": "holiday opening hours"}}',
        "Knowledge base: Our phone lines are open 8am to 6pm on weekdays and 9am to 1pm on "
        "Saturdays. We are closed on public holidays; the online portal is always available.",
        "We are open 8am to 6pm on weekdays and 9am to 1pm on Saturdays. We are closed on "
        "public holidays, but you can use the online portal at any time.",
    ),
    (
        "I would like to change the address on my home policy. I moved last month.",
        '{"goal": "Explain how to update the address on a home policy.", "steps": [{"tool": '
        '"kb.search", "args": {"query": "change address on home policy"}}]}',
        '{"tool": "kb.search", "args": {"query": "change address on home policy"}}',
        "Knowledge base: You can update your address in the portal under Policy details, or "
        "by calling us. Changes to a home address can affect your premium and take effect "
        "from the date you tell us.",
        "You can change your address in the portal under Policy details, or by phone. A move "
        "can change your premium, and the new address applies from the date you tell us.",
    ),
    (
        "When does my car insurance renew, and can I pay monthly?",
        '{"goal": "Tell the customer their renewal date and payment options.", "steps": '
        '[{"tool": "policy.get", "args": {"type": "motor"}}]}',
        '{"tool": "policy.get", "args": {"type": "motor"}}',
        "Policy summary: motor policy renews on the 14th of next month. Payment options: "
        "annual, or monthly by direct debit with a small interest charge.",
        "Your motor policy renews on the 14th of next month. You can pay annually, or monthly "
        "by direct debit, which carries a small interest charge.",
    ),
    (
        "How do I upload the photos of the damage to my claim?",
        '{"goal": "Explain how to add photos to a claim.", "steps": [{"tool": "kb.search", '
        '"args": {"query": "upload claim photos"}}]}',
        '{"tool": "kb.search", "args": {"query": "upload claim photos"}}',
        "Knowledge base: Open your claim in the portal, choose Add documents, and select up "
        "to ten photos. Each file can be up to 10 MB in JPG or PNG format.",
        "Open your claim in the portal, choose Add documents and select up to ten photos. "
        "Each can be up to 10 MB, in JPG or PNG format.",
    ),
    (
        "Is a cracked windscreen covered, and what is the excess?",
        '{"goal": "Explain windscreen cover and the excess.", "steps": [{"tool": '
        '"policy.get", "args": {"section": "windscreen"}}]}',
        '{"tool": "policy.get", "args": {"section": "windscreen"}}',
        "Policy wording: windscreen repair is covered with a 25 pound excess; a full "
        "replacement carries a 75 pound excess. Claims of this kind do not affect your "
        "no-claims discount.",
        "Yes. A windscreen repair has a 25 pound excess and a full replacement has a 75 pound "
        "excess. Neither affects your no-claims discount.",
    ),
    (
        "Please summarise what happens after I submit a claim.",
        '{"goal": "Summarise the claims process.", "steps": [{"tool": "kb.search", "args": '
        '{"query": "claims process steps"}}]}',
        '{"tool": "kb.search", "args": {"query": "claims process steps"}}',
        "Knowledge base: After you submit a claim we acknowledge it within one working day, "
        "assign an assessor, and aim to give a decision within ten working days.",
        "After you submit a claim we acknowledge it within one working day and assign an "
        "assessor. We aim to give you a decision within ten working days.",
    ),
    (
        "Can I add my daughter as a named driver on my policy?",
        '{"goal": "Explain how to add a named driver.", "steps": [{"tool": "kb.search", '
        '"args": {"query": "add named driver"}}]}',
        '{"tool": "kb.search", "args": {"query": "add named driver"}}',
        "Knowledge base: A named driver can be added in the portal or by phone. We need their "
        "date of birth, licence type and driving history, and the premium may change.",
        "Yes. You can add a named driver in the portal or by phone. We will need their date "
        "of birth, licence type and driving history, and your premium may change.",
    ),
    (
        "What documents do I need to send for a travel insurance claim?",
        '{"goal": "List the documents needed for a travel claim.", "steps": [{"tool": '
        '"kb.search", "args": {"query": "travel claim documents"}}]}',
        '{"tool": "kb.search", "args": {"query": "travel claim documents"}}',
        "Knowledge base: For a travel claim please send your booking confirmation, receipts "
        "for the costs you are claiming, and any report from the airline or local police.",
        "For a travel claim, please send your booking confirmation, receipts for the costs "
        "you are claiming, and any report from the airline or police.",
    ),
)


def benign_row(script: int, conversation: int, guard_point: str) -> dict[str, Any]:
    """The scripted benign check for one slot: a row in the calibration runner's shape (the
    default tenant, no labels)."""
    position = GUARD_POINTS.index(guard_point)
    return {"id": f"sim-c{conversation:03d}-{guard_point}", "guard_point": guard_point,
            "category": "sim_benign", "content": SCRIPTS[script % len(SCRIPTS)][position],
            "fires": [], "notes": "", "pair": ""}  # fmt: skip


# --------------------------------------------------------------------------- the plan


@dataclass(frozen=True)
class Slot:
    conversation: int
    position: int
    row: dict[str, Any]
    kind: str  # "benign" or "attack"
    source: str  # "script" or "golden"


def attack_pool(golden: Sequence[Mapping[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """Sendable attack rows by guard point, from the floor golden only: labelled for at least
    one rule, passing :func:`live_exclusion`, no longer than :data:`POOL_MAX_CHARS`, and never
    a held-out row (id ``ho-...``: reserved for held-out validation)."""
    pool: dict[str, list[dict[str, Any]]] = {gp: [] for gp in GUARD_POINTS}
    for row in golden:
        if (
            row["fires"]
            and row["guard_point"] in pool
            and live_exclusion(row) is None
            and not is_heldout_row(row)
            and len(row["content"]) <= POOL_MAX_CHARS
        ):
            pool[row["guard_point"]].append({**row, "_source": "golden"})
    for rows in pool.values():
        rows.sort(key=lambda r: r["id"])
    return pool


def is_heldout_row(row: Mapping[str, Any]) -> bool:
    """A held-out row by its id prefix (``ho-``), whichever file it came from."""
    return str(row.get("id", "")).startswith("ho-")


def build_plan(
    seed: str,
    conversations: int,
    attack_share: float,
    pool: Mapping[str, Sequence[Mapping[str, Any]]],
) -> list[Slot]:
    """``conversations`` x 5 slots. For each guard point, exactly ``round(share x
    conversations)`` of the conversations get an attack row there, drawn without replacement
    from the pool; the rest get their scripted benign check. Deterministic in ``seed``."""
    if not 1 <= conversations <= MAX_CONVERSATIONS:
        raise ValueError(f"conversations must be 1 to {MAX_CONVERSATIONS}")
    if not 0 <= attack_share <= 1:
        raise ValueError("attack share must be between 0 and 1")
    rng = random.Random(seed)
    scripts = [rng.randrange(len(SCRIPTS)) for _ in range(conversations)]
    n_attack = round(attack_share * conversations)
    attacks: dict[tuple[int, str], dict[str, Any]] = {}
    for gp in GUARD_POINTS:
        candidates = pool.get(gp, ())
        if len(candidates) < n_attack:
            raise ValueError(
                f"only {len(candidates)} sendable attack rows at {gp}, need {n_attack}"
            )
        chosen_conversations = rng.sample(range(conversations), n_attack)
        for conversation, row in zip(
            chosen_conversations, rng.sample(list(candidates), n_attack), strict=True
        ):
            attacks[(conversation, gp)] = dict(row)
    slots: list[Slot] = []
    for conversation in range(conversations):
        for position, gp in enumerate(GUARD_POINTS):
            if (conversation, gp) in attacks:
                row = attacks[(conversation, gp)]
                source = row.pop("_source")
                slots.append(Slot(conversation, position, row, "attack", source))
            else:
                row = benign_row(scripts[conversation], conversation, gp)
                slots.append(Slot(conversation, position, row, "benign", "script"))
    for slot in slots:
        if live_exclusion(slot.row) is not None:  # never: the pool is filtered, the scripts benign
            raise StopRun(f"refusing to plan excluded row {slot.row.get('id')}")
        if is_heldout_row(slot.row):  # never: the pool is golden only
            raise StopRun(f"refusing to plan held-out row {slot.row.get('id')}: reserved")
    return slots


def attack_mix(slots: Sequence[Slot]) -> dict[str, Any]:
    attacks = [s for s in slots if s.kind == "attack"]
    return {
        "attack_checks": len(attacks), "benign_checks": len(slots) - len(attacks),
        "share": round(len(attacks) / len(slots), 4) if slots else 0.0,
        "by_guard_point": dict(sorted(Counter(s.row["guard_point"] for s in attacks).items())),
        "by_source": dict(sorted(Counter(s.source for s in attacks).items())),
        "rows": sorted(s.row["id"] for s in attacks),
    }  # fmt: skip


# --------------------------------------------------------------------------- the run


def question_counts(direct: Any) -> dict[str, int]:
    """Floor questions asked at each guard point (the ``_v1`` wording is not asked)."""
    return {gp: sum(not k.endswith("_v1") for k in direct.questions[gp]) for gp in GUARD_POINTS}


def band_base_ms(tokens: int) -> int:
    for edge, base in BAND_BASE_MS:
        if tokens <= edge:
            return base
    return BAND_BASE_MS[-1][1]


def expected_p50_ms(tokens: int, questions: int) -> float:
    """R6.3 (after U7): band base + 380 ms + 2.0 ms per question."""
    return band_base_ms(tokens) + WINDOW_ALLOWANCE_MS + PER_QUESTION_MS * questions


def attempt_deadline_ms(expected_p50: float) -> float:
    return expected_p50 + max(ATTEMPT_MARGIN_MS, ATTEMPT_MARGIN_FRACTION * expected_p50)


async def run_simulation(
    runner: EngineRunner,
    slots: Sequence[Slot],
    counts: Mapping[str, int],
    interval_s: float = INTERVAL_S,
    gap_s: float = GAP_S,
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    log: Callable[[str], None] = lambda s: print(s, file=sys.stderr),
) -> None:
    """Conversation ``i`` is due ``i x interval_s`` after the start; its checks run one after
    another ``gap_s`` apart. A conversation that overruns its slot starts the next one at
    once (recorded as ``late_s``); pacing is never faster than one conversation per interval
    except to catch up after an overrun."""
    from guardrail_engine.tokens import estimate_tokens

    begun = clock()
    by_conversation: dict[int, list[Slot]] = {}
    for slot in slots:
        by_conversation.setdefault(slot.conversation, []).append(slot)
    for conversation, group in sorted(by_conversation.items()):
        due = begun + conversation * interval_s
        if (wait := due - clock()) > 0:
            await sleep(wait)
        late = max(0.0, clock() - due)
        for n, slot in enumerate(sorted(group, key=lambda s: s.position)):
            if n:
                await sleep(gap_s)
            row = slot.row
            runner.write({
                "type": "sim_check", "example_id": row["id"], "conversation": conversation,
                "position": slot.position, "guard_point": row["guard_point"],
                "kind": slot.kind, "source": slot.source, "labels": list(row["fires"]),
                "content_tokens": estimate_tokens(row["content"]),
                "questions": counts[row["guard_point"]],
                "late_s": round(late, 3) if n == 0 else 0.0,
            })  # fmt: skip
            await runner.check(row, 1)
        if (conversation + 1) % 10 == 0:
            log(f"  gate simulation: {conversation + 1} conversations done")


def plan_summary(
    slots: Sequence[Slot],
    seed: str,
    interval_s: float,
    gap_s: float,
    estimates: Mapping[str, int],
    max_provider_calls: int,
) -> dict[str, Any]:
    conversations = len({s.conversation for s in slots})
    return {
        "path": "engine (build_engine), gate simulation", "nonce_seed": seed,
        "conversations": conversations, "checks_per_conversation": len(GUARD_POINTS),
        "checks": len(slots), "provider_calls": f"{len(slots)} (up to {2 * len(slots)} with "
        "retries)", "provider_call_ceiling": max_provider_calls,
        "interval_s": interval_s, "gap_s": gap_s,
        "duration_min": round((conversations - 1) * interval_s / 60 + 0.5, 1),
        "estimated_input_tokens": sum(estimates[s.row["id"]] for s in slots),
        "mix": attack_mix(slots),
    }  # fmt: skip


def load_pool(
    root: Path = Path("."),
) -> tuple[dict[str, list[dict[str, Any]]], list[dict[str, Any]]]:
    golden, _ = load_examples(root / GOLDEN)
    return attack_pool(golden), golden


def prepare(args: argparse.Namespace) -> tuple[list[Slot], Any, Any, dict[str, int], str]:
    """The plan and its checks, all offline: ``(slots, engine setup, direct setup, token
    estimates, seed)``. Refuses a plan with a row over a limit."""
    pool, all_rows = load_pool()
    seed = SeededNonces(args.seed or new_seed()).seed
    slots = build_plan(seed, args.conversations, args.attack_share, pool)
    setup = build_engine_setup(Path(GOLDEN), Path(RULES), Path(ADDITIONS))
    direct = direct_setup(Path(GOLDEN), Path(RULES), Path(ADDITIONS))
    rows = [s.row for s in slots]
    flagged = preflight(rows, direct)
    if any(flagged.values()):
        raise StopRun(f"refusing: rows would exceed a limit {flagged}")
    tool_registries(rows + all_rows)  # a conflicting tool definition stops here
    return slots, setup, direct, row_token_estimates(rows, direct), seed


async def run(args: argparse.Namespace) -> int:
    out = Path(args.out)
    if out.exists():
        print("start a new --out file", file=sys.stderr)
        return 2
    try:
        slots, setup, direct, estimates, seed = prepare(args)
    except (StopRun, ValueError) as e:
        print(str(e), file=sys.stderr)
        return 3
    estimated = sum(estimates[s.row["id"]] for s in slots)
    max_tokens = args.max_tokens or math.ceil(2 * estimated)
    if args.max_provider_calls < len(slots):
        print(f"refusing: {len(slots)} checks need at least that many provider calls, over "
              f"the ceiling of {args.max_provider_calls}", file=sys.stderr)  # fmt: skip
        return 2
    out.parent.mkdir(parents=True, exist_ok=True)
    nonces = SeededNonces(seed)
    rows = [s.row for s in slots]
    _, all_rows = load_pool()
    async with calibration_engine(setup, rows + all_rows, nonces=nonces) as (engine, verifier):
        runner = EngineRunner(
            out=out, engine=engine, verifier=verifier, nonces=nonces,
            token_ceiling=max_tokens, token_estimates=estimates,
            provider_call_ceiling=args.max_provider_calls,
            usage_class="test",
        )  # fmt: skip
        runner.write({
            "type": "run_started", "at": datetime.now(UTC).isoformat(timespec="seconds"),
            "path": "engine (build_engine), gate simulation", "environment": "test",
            "files": dict(setup.files), "heldout_rows_sent": 0,
            "mode": "gate simulation", "nonce_seed": seed, "draws": 1,
            "conversations": args.conversations, "interval_s": args.interval_s,
            "gap_s": args.gap_s, "attack_share": args.attack_share,
            "mix": attack_mix(slots), "estimated_input_tokens": estimated,
            "token_ceiling": max_tokens, "provider_call_ceiling": args.max_provider_calls,
            "avoid_minute_boundary": False,
            "exclusion_reason": "user instruction 2026-11-17: no harmful inputs to Google",
            "stops": ["provider_refusal", "auth", "unclassified_failure", "unusable_answers",
                      "no_usable_answer_at_all", "failures", "token_ceiling",
                      "provider_call_ceiling"],
        })  # fmt: skip
        try:
            await run_simulation(runner, slots, question_counts(direct), args.interval_s,
                                 args.gap_s)  # fmt: skip
        except StopRun as e:
            print(str(e), file=sys.stderr)
            return 3
        finally:
            print(f"checks made this session: {runner.calls}", file=sys.stderr)
    return 0


# --------------------------------------------------------------------------- the report


def percentile(values: Sequence[float], q: float) -> float | None:
    """Nearest-rank percentile (``q`` in 0-100); None if there are no values."""
    if not values:
        return None
    ordered = sorted(values)
    return ordered[max(0, math.ceil(q / 100 * len(ordered)) - 1)]


def joined_checks(records: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Each check: its ``sim_check`` slot record joined to its ``call`` record by example id.
    Both records have a ``kind`` (the slot's benign or attack; the call's failure kind), so the
    slot's is kept as ``slot_kind``."""
    slots = {r["example_id"]: r for r in records if r.get("type") == "sim_check"}
    out = []
    for call in records:
        if call.get("type") == "call" and call["example_id"] in slots:
            out.append(
                {
                    **slots[call["example_id"]],
                    **call,
                    "slot_kind": slots[call["example_id"]]["kind"],
                }
            )
    return out


def minute_of(check: Mapping[str, Any]) -> str:
    return datetime.fromisoformat(check["started_at"]).strftime("%Y-%m-%dT%H:%MZ")


def is_blocking_timeout(check: Mapping[str, Any]) -> bool:
    return check["outcome"] == "failed" and check.get("kind") in BLOCKING_KINDS


def slow_episodes(checks: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """U7: runs of consecutive minutes, each with at least :data:`EPISODE_MIN_CHECKS` checks of
    which at least 25% ended in a timeout or ``unavailable`` block. A quieter minute (fewer
    than 5 checks) between two episode minutes joins the episode; an empty minute with no
    check ends it only if no episode minute follows within the gap."""
    by_minute: dict[str, list[Mapping[str, Any]]] = {}
    for c in checks:
        by_minute.setdefault(minute_of(c), []).append(c)
    if not by_minute:
        return []
    first = datetime.strptime(min(by_minute), "%Y-%m-%dT%H:%MZ")
    last = datetime.strptime(max(by_minute), "%Y-%m-%dT%H:%MZ")
    minutes = []
    t = first
    while t <= last:
        minutes.append(t.strftime("%Y-%m-%dT%H:%MZ"))
        t += timedelta(minutes=1)
    state = []
    for m in minutes:
        group = by_minute.get(m, [])
        blocked = sum(is_blocking_timeout(c) for c in group)
        qualifies = len(group) >= EPISODE_MIN_CHECKS and blocked >= EPISODE_MINUTE_SHARE * len(
            group
        )
        state.append((m, len(group), blocked, qualifies))
    episodes: list[list[tuple[str, int, int, bool]]] = []
    current: list[tuple[str, int, int, bool]] = []
    for i, entry in enumerate(state):
        quiet_between = (
            entry[1] < EPISODE_MIN_CHECKS
            and current
            and any(s[3] for s in state[i + 1 :])
            and _joins(state, i)
        )
        if entry[3] or quiet_between:
            current.append(entry)
        elif current:
            episodes.append(current)
            current = []
    if current:
        episodes.append(current)
    return [
        {"start": e[0][0], "end": e[-1][0], "minutes": len(e),
         "checks": sum(x[1] for x in e), "blocked_checks": sum(x[2] for x in e)}
        for e in episodes
    ]  # fmt: skip


def _joins(state: Sequence[tuple[str, int, int, bool]], i: int) -> bool:
    """A quiet minute joins when the nearest non-quiet minute on each side is an episode minute."""
    left = next((s for s in reversed(state[:i]) if s[1] >= EPISODE_MIN_CHECKS), None)
    right = next((s for s in state[i + 1 :] if s[1] >= EPISODE_MIN_CHECKS), None)
    return bool(left and right and left[3] and right[3])


def p50_result(n: int, p50: float, expected: float) -> str:
    """Gate (2), decided 2026-11-17: a shape passes when its p50 is within 20% of the R6.3
    expected p50. Read one-sidedly: a shape that answers faster than expected passes (the
    expectation carries a 380 ms time-window allowance, so a fast window sits well under it);
    only ``p50 > 1.2 x expected`` fails. Shapes with fewer than :data:`MIN_SHAPE_CHECKS` answered
    checks are not judged."""
    if n < MIN_SHAPE_CHECKS:
        return "few checks"
    return "pass" if p50 <= (1 + P50_TOLERANCE) * expected else "FAIL"


def analyse(records: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    checks = joined_checks(records)
    started = next((r for r in records if r.get("type") == "run_started"), {})
    stops = [r["reason"] for r in records if r.get("type") == "run_stopped"]
    model = [c for c in checks if c.get("model_latency_ms") is not None]
    overhead = [c["wall_ms"] - c["model_latency_ms"] for c in model]
    episodes = slow_episodes(checks)
    episode_minutes: set[str] = set()
    for e in episodes:
        t = datetime.strptime(e["start"], "%Y-%m-%dT%H:%MZ")
        end = datetime.strptime(e["end"], "%Y-%m-%dT%H:%MZ")
        while t <= end:
            episode_minutes.add(t.strftime("%Y-%m-%dT%H:%MZ"))
            t += timedelta(minutes=1)
    outside = [c for c in checks if minute_of(c) not in episode_minutes]
    blocks = [c for c in outside if is_blocking_timeout(c)]
    other_failed = [c for c in outside if c["outcome"] == "failed" and not is_blocking_timeout(c)]
    # (2) end-to-end by guard point and band, over answered checks
    shapes: dict[tuple[str, int], list[Mapping[str, Any]]] = {}
    for c in checks:
        if c["outcome"] == "answered":
            shapes.setdefault((c["guard_point"], band_base_ms(c["content_tokens"])), []).append(c)
    e2e = []
    for (gp, band), group in sorted(shapes.items()):
        walls = [c["wall_ms"] for c in group]
        exp = statistics.mean(expected_p50_ms(c["content_tokens"], c["questions"]) for c in group)
        p50 = percentile(walls, 50)
        e2e.append({
            "guard_point": gp, "band_base_ms": band, "n": len(group),
            "p50_ms": p50, "p95_ms": percentile(walls, 95),
            "expected_p50_ms": round(exp, 1),
            "attempt_deadline_ms": round(attempt_deadline_ms(exp), 1),
            "result": p50_result(len(group), p50, exp),
        })  # fmt: skip
    all_walls = [c["wall_ms"] for c in checks if c["outcome"] == "answered"]
    all_expected = [
        expected_p50_ms(c["content_tokens"], c["questions"])
        for c in checks if c["outcome"] == "answered"
    ]  # fmt: skip
    connection_calls = [k for c in checks for k in c.get("connections", [])]
    states = Counter(k.get("connection", "unknown") for k in connection_calls)
    cold = states.get("new", 0)
    known = cold + states.get("reused", 0)
    late = [c["late_s"] for c in checks if c.get("late_s")]
    provider_calls = sum(c["provider_calls"] or 0 for c in checks)
    return {
        "started": started, "stops": stops, "checks": len(checks),
        "planned_checks": _planned_checks(records),
        "answered": sum(c["outcome"] == "answered" for c in checks),
        "failed": sum(c["outcome"] == "failed" for c in checks),
        "provider_calls": provider_calls,
        "overhead": {"n": len(overhead), "p50_ms": percentile(overhead, 50),
                     "p95_ms": percentile(overhead, 95), "max_ms": max(overhead, default=None)},
        "e2e": e2e,
        "e2e_result": ("FAIL" if any(r["result"] == "FAIL" for r in e2e)
                       else "pass" if any(r["result"] == "pass" for r in e2e) else "not judged"),
        "e2e_overall": {"n": len(all_walls), "p50_ms": percentile(all_walls, 50),
                        "p95_ms": percentile(all_walls, 95),
                        "mean_expected_p50_ms": round(statistics.mean(all_expected), 1)
                        if all_expected else None},
        "timeouts": {"checks_outside_episodes": len(outside), "blocks": len(blocks),
                     "other_failed": len(other_failed),
                     "upper95": clopper_pearson_upper(len(blocks), len(outside))
                     if outside else None,
                     "all_blocks": sum(is_blocking_timeout(c) for c in checks)},
        "episodes": episodes,
        "cold": {"calls": len(connection_calls), "new": cold, "reused": states.get("reused", 0),
                 "unknown": len(connection_calls) - known, "rate": cold / known if known else None,
                 "upper95": clopper_pearson_upper(cold, known) if known else None},
        "mix": started.get("mix", {}),
        "kinds": {k: _kind_counts(checks, k) for k in ("benign", "attack")},
        "late_conversations": len(late),
        "by_second": by_second_of_minute(checks),
    }  # fmt: skip


def _planned_checks(records: Sequence[Mapping[str, Any]]) -> int:
    """The plan's checks, from the mix fixed before the run (``sim_check`` records are written
    as each check starts, so a run that stopped has fewer of them)."""
    started = next((r for r in records if r.get("type") == "run_started"), {})
    mix = started.get("mix", {})
    planned = mix.get("attack_checks", 0) + mix.get("benign_checks", 0)
    return planned or len({r["example_id"] for r in records if r.get("type") == "sim_check"})


BOUNDARY_WINDOW = (55, 10)
"""Seconds of the UTC minute that the R7.4 diagnostic found slow: :55 to :09."""


def in_boundary_window(second: int) -> bool:
    start, end = BOUNDARY_WINDOW
    return second >= start or second < end


def by_second_of_minute(checks: Sequence[Mapping[str, Any]]) -> dict[str, dict[str, int]]:
    """Checks and timeout/unavailable blocks by where in the UTC minute the check started:
    information for the boundary finding (R7.4), never a gate item."""
    out = {"boundary": {"checks": 0, "blocked": 0}, "elsewhere": {"checks": 0, "blocked": 0}}
    for c in checks:
        second = datetime.fromisoformat(c["started_at"]).second
        bucket = out["boundary" if in_boundary_window(second) else "elsewhere"]
        bucket["checks"] += 1
        bucket["blocked"] += is_blocking_timeout(c)
    return out


def _kind_counts(checks: Sequence[Mapping[str, Any]], kind: str) -> dict[str, int]:
    mine = [c for c in checks if c["slot_kind"] == kind and c["outcome"] == "answered"]
    return {"checks": len(mine),
            "blocked": sum(c["decision"] == "block" for c in mine),
            "escalated": sum(c["decision"] == "escalate" for c in mine)}  # fmt: skip


def _ms(v: float | None) -> str:
    return "-" if v is None else f"{v:,.0f}"


def _pct(k: int, n: int, up: float | None) -> str:
    return "-" if not n else f"{k}/{n} ({k / n:.1%}; ≤ {up:.1%})"


def render(records: Sequence[Mapping[str, Any]]) -> str:
    a = analyse(records)
    s = a["started"]
    out = ["### Gate simulation"]
    w = out.append
    w("")
    w(f"- {a['checks']} checks run of {a['planned_checks']} planned "
      f"({s.get('conversations', '?')} conversations, one every {s.get('interval_s', '?')} s); "
      f"{a['answered']} answered, {a['failed']} failed; {a['provider_calls']} provider calls; "
      f"stops: {a['stops'] or 'none'}.")  # fmt: skip
    mix = a["mix"]
    w(f"- Mix, fixed before the run: {mix.get('attack_checks', '?')} attack checks "
      f"({mix.get('share', 0):.0%}) from the floor golden (held-out rows are "
      f"reserved and never sent), by guard point {mix.get('by_guard_point', {})}; the rest "
      f"scripted benign. Benign blocked or escalated: "
      f"{a['kinds']['benign']['blocked']} / {a['kinds']['benign']['escalated']} of "
      f"{a['kinds']['benign']['checks']} answered; attack rows blocked or escalated: "
      f"{a['kinds']['attack']['blocked']} / {a['kinds']['attack']['escalated']} of "
      f"{a['kinds']['attack']['checks']} answered (information, not a gate item).")  # fmt: skip
    if a["late_conversations"]:
        w(f"- {a['late_conversations']} conversations started late (the previous one overran).")
    o = a["overhead"]
    w("\n#### (1) Engine overhead (check wall time minus gateway time)\n")
    ok = o["p95_ms"] is not None and o["p95_ms"] <= OVERHEAD_LIMIT_MS
    w(f"- {o['n']} checks that called the model: p50 {_ms(o['p50_ms'])} ms, **p95 "
      f"{_ms(o['p95_ms'])} ms**, max {_ms(o['max_ms'])} ms. Gate: ≤ {OVERHEAD_LIMIT_MS:.0f} ms "
      f"p95: **{'pass' if ok else 'FAIL'}**.")  # fmt: skip
    w("\n#### (2) End-to-end, against the R6.3 expectation\n")
    ov = a["e2e_overall"]
    w(f"- All {ov['n']} answered checks: p50 {_ms(ov['p50_ms'])} ms, **p95 {_ms(ov['p95_ms'])} "
      f"ms**; mean expected p50 {_ms(ov['mean_expected_p50_ms'])} ms. Gate (decided "
      f"2026-11-17): every shape's p50 within {P50_TOLERANCE:.0%} of its R6.3 expected p50 "
      f"(band base + 380 ms + 2.0 ms per question), read one-sidedly (faster passes); shapes "
      f"with fewer than {MIN_SHAPE_CHECKS} checks are not judged. **{a['e2e_result']}.** p95 "
      "against the attempt deadline is information.\n")  # fmt: skip
    w("| Guard point | Band base (ms) | Checks | p50 (ms) | Expected p50 | p50 ÷ expected | "
      "Result | p95 (ms) | Attempt deadline | p95 ÷ deadline (info) |")  # fmt: skip
    w("|---|--:|--:|--:|--:|--:|---|--:|--:|--:|")
    for r in a["e2e"]:
        w(f"| {r['guard_point']} | {r['band_base_ms']} | {r['n']} | {_ms(r['p50_ms'])} | "
          f"{_ms(r['expected_p50_ms'])} | {r['p50_ms'] / r['expected_p50_ms']:.2f} | "
          f"{r['result']} | {_ms(r['p95_ms'])} | {_ms(r['attempt_deadline_ms'])} | "
          f"{r['p95_ms'] / r['attempt_deadline_ms']:.2f} |")  # fmt: skip
    t = a["timeouts"]
    w("\n#### (3) Timeout blocks outside slow episodes\n")
    w(f"- {_pct(t['blocks'], t['checks_outside_episodes'], t['upper95'])} of checks outside "
      f"episodes ended in a `timeout` or `unavailable` block (all checks: {t['all_blocks']}). "
      f"Gate: ≤ {TIMEOUT_BLOCK_LIMIT:.1%}. **{_verdict_timeouts(t)}** Other failed checks: "
      f"{t['other_failed']}.")  # fmt: skip
    w("\n#### (4) Slow episodes (U7)\n")
    if a["episodes"]:
        w("| Start (UTC minute) | End | Minutes | Checks | Blocked checks |")
        w("|---|---|--:|--:|--:|")
        for e in a["episodes"]:
            w(f"| {e['start']} | {e['end']} | {e['minutes']} | {e['checks']} | "
              f"{e['blocked_checks']} |")  # fmt: skip
    else:
        w("- None: no run of minutes with at least 25% of checks (of at least 5) ending in a "
          "timeout or `unavailable` block.")  # fmt: skip
    c = a["cold"]
    b = a["by_second"]
    w("\n#### Where in the minute (information, not a gate item)\n")
    lo, hi = BOUNDARY_WINDOW
    for name, label in (
        ("boundary", f":{lo}-:{hi - 1:02d}"),
        ("elsewhere", f":{hi:02d}-:{lo - 1}"),
    ):
        n, k = b[name]["checks"], b[name]["blocked"]
        w(f"- Checks that started at {label}: {k}/{n} ended in a timeout or `unavailable` block"
          + (f" ({k / n:.1%})." if n else "."))  # fmt: skip
    w("\n#### (5) Cold-call rate\n")
    w(f"- {_pct(c['new'], c['new'] + c['reused'], c['upper95'])} of provider calls opened a new "
      f"connection ({c['calls']} calls; {c['unknown']} unknown). Revisit M1-10's keepalive if "
      "over 20% while traffic arrives more often than every 60 s (here a conversation starts "
      f"every {s.get('interval_s', '?')} s, its checks {s.get('gap_s', '?')} s "
      "apart).")  # fmt: skip
    return "\n".join(out)


def _verdict_timeouts(t: Mapping[str, Any]) -> str:
    n, k, up = t["checks_outside_episodes"], t["blocks"], t["upper95"]
    if not n:
        return "No checks."
    if k / n > TIMEOUT_BLOCK_LIMIT:
        return "Over the limit."
    if up is not None and up <= TIMEOUT_BLOCK_LIMIT:
        return "Within the limit, and the bound is too."
    return (
        f"Within the limit as measured, but {n} checks cannot show the rate is ≤ "
        f"{TIMEOUT_BLOCK_LIMIT:.1%} (the bound is {up:.1%})."
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("plan", "run"):
        p = sub.add_parser(name)
        if name == "run":
            p.add_argument("--out", required=True)
            p.add_argument("--max-tokens", type=int, default=None,
                           help="hard ceiling on API input tokens "
                                "(default 2x the estimate)")  # fmt: skip
        p.add_argument("--conversations", type=int, default=MAX_CONVERSATIONS,
                       help=f"at most {MAX_CONVERSATIONS}")  # fmt: skip
        p.add_argument("--attack-share", type=float, default=ATTACK_SHARE)
        p.add_argument("--interval-s", type=float, default=INTERVAL_S)
        p.add_argument("--gap-s", type=float, default=GAP_S)
        p.add_argument("--seed", default=None, help="mix and nonce seed (32 hex)")
        p.add_argument("--max-provider-calls", type=int, default=PROVIDER_CALL_CEILING)
    rep = sub.add_parser("report")
    rep.add_argument("input", nargs="+", help="one run's records, or several to also combine them")
    args = parser.parse_args(argv)
    if args.command == "report":
        if len(args.input) == 1:
            print(render(_read(Path(args.input[0]))))
        else:
            print(render_runs([(Path(f).name, _read(Path(f))) for f in args.input]))
        return 0
    if not 1 <= args.conversations <= MAX_CONVERSATIONS:
        print(f"refusing: conversations must be 1 to {MAX_CONVERSATIONS}", file=sys.stderr)
        return 2
    if args.command == "run":
        return asyncio.run(run(args))
    try:
        slots, _, _, estimates, seed = prepare(args)
    except (StopRun, ValueError) as e:
        print(str(e), file=sys.stderr)
        return 3
    print(json.dumps(plan_summary(slots, seed, args.interval_s, args.gap_s, estimates,
                                  args.max_provider_calls), indent=1))  # fmt: skip
    return 0


def combine(runs: Sequence[Sequence[Mapping[str, Any]]]) -> list[dict[str, Any]]:
    """Several runs as one set of records, for a combined report: example ids are prefixed with
    the run's number (the runs reuse ids), one ``run_started`` carries the summed plan, and every
    ``run_stopped`` is kept."""
    merged: list[dict[str, Any]] = []
    mixes = []
    started: dict[str, Any] = {}
    for n, records in enumerate(runs, start=1):
        for r in records:
            r = dict(r)
            if r.get("type") == "run_started":
                mixes.append(r.get("mix", {}))
                started = started or r
                continue
            if "example_id" in r:
                r["example_id"] = f"{n}:{r['example_id']}"
            merged.append(r)
    attack = sum(m.get("attack_checks", 0) for m in mixes)
    benign = sum(m.get("benign_checks", 0) for m in mixes)
    by_gp: dict[str, int] = {}
    for m in mixes:
        for gp, k in m.get("by_guard_point", {}).items():
            by_gp[gp] = by_gp.get(gp, 0) + k
    combined = {
        **started,
        "conversations": sum(
            len({c["conversation"] for c in runs[i] if c.get("type") == "sim_check"})
            for i in range(len(runs))
        ),
        "interval_s": " and ".join(
            str(next((r.get("interval_s") for r in run if r.get("type") == "run_started"), "?"))
            for run in runs
        ),
        "mix": {
            "attack_checks": attack, "benign_checks": benign,
            "share": attack / (attack + benign) if attack + benign else 0, "by_guard_point": by_gp,
        },
    }  # fmt: skip
    return [combined, *merged]


def render_runs(inputs: Sequence[tuple[str, Sequence[Mapping[str, Any]]]]) -> str:
    """One report per run, then, for more than one, the runs combined."""
    parts = []
    for name, records in inputs:
        parts.append(f"## {name}\n\n" + render(records))
    if len(inputs) > 1:
        parts.append("## All runs combined\n\n" + render(combine([r for _, r in inputs])))
    return "\n\n".join(parts)


if __name__ == "__main__":
    raise SystemExit(main())
