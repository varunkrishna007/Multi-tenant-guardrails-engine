"""M4-08 pack calibration through the production path: one domain pack, its sendable rows.

    uv run python -m calibration.pack_live plan   --pack insurance
    uv run python -m calibration.pack_live run    --pack insurance --out calibration/results/X.jsonl
    uv run python -m calibration.pack_live report --pack insurance calibration/results/X.jsonl

**The default is a dry run**: the engine's own ``FakeDecisionModel`` answers from the row's
label, through exactly the code a live run uses (same rows, same checks, same records, same
report). A **live** run needs all of: ``--live``, the environment variable
``GUARDRAILS_LIVE_CALIBRATION=m4-08-sendable-rows``, and an explicit ``--max-tokens`` and
``--max-provider-calls``. Nothing here ever runs live by itself.

**What may be sent (user instruction, 2026-11-17: no harmful inputs to Google).**

* Only ``packs/insurance/golden.jsonl`` and ``packs/energy/golden.jsonl`` are accepted. Not the
  responsible-AI set, not the floor's, not a red-team corpus.
* A row is sent only if every one of these holds, checked when the file is loaded **and again
  immediately before each check** (:class:`PackRunner`):
  ``calibration.run.live_exclusion`` finds nothing; ``no_live_run`` is exactly ``false`` (a
  missing key is a refusal); the row fires none of :data:`NEVER_SENT_RULES` (the rules whose
  positives state dangerous advice or ask for help with a wrong); and the engine's harm
  vocabulary tripwire (``admin.vocabulary``) finds nothing in its content, context or tools.
  A row that fails is never built into a request. At load it is counted under its reason; at
  send time it stops the run.
* The pack's own text (its questions are sent with every check) goes through the tripwire at
  start; a pack that trips it is refused.
* The tenant's bundle extends the floor and the one pack under test: no responsible-AI pack
  (and so never ``d__harm_facilitation``).
* **The first provider refusal stops the run** (and any ``other`` failure, which may be an
  unmapped refusal). Nothing is resent. Records hold ids, nonces, probabilities and usage:
  never content, headers, provider text or the key.

**The key** is read from ``GEMINI_API_KEY`` in the environment, or, if unset, from the one
line of an ``.env`` file that sets it (:func:`load_api_key`). It is never printed, logged or
written, and a run's records don't carry it.

**Pace.** Checks are tagged with the ``calibration`` usage class, so the gateway holds the run
to that consumer's allowance (a tenth of the project's tokens a minute, requests a minute, requests
a day and monthly spend). The harness spaces check starts under that allowance
(:func:`pace_interval_s`) and starts none within :55 to :10 of a minute.

**The report** (``report``): per rule of the pack, the B2 suggestion (``admin.sweep``) from the
draws' means and from the draws pooled, a cross-check on the hard pool (the rule's own
category, where the negatives are the near-misses), the confusion at the rule's present
thresholds, the draw noise, and what could not be measured; then the spend.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import math
import os
import secrets
import statistics
import sys
from collections import Counter
from collections.abc import AsyncIterator, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from calibration.engine_path import (
    ENVIRONMENT,
    EngineRunner,
    SeededNonces,
    complete_records,
    incomplete,
    new_seed,
    preflight,
    row_token_estimates,
    run_engine_path,
    settings_mapping,
    tokens_of,
)
from calibration.run import (
    DRAWS,
    REDACTION_APPLIED,
    THIN,
    Setup,
    StopRun,
    _read,
    finished_record,
    live_exclusion,
    refuse_harm_facilitation,
    sha256_file,
)
from guardrail_engine.admin.sweep import Suggestion, Targets, confusion, sweep

ROOT = Path(__file__).resolve().parents[1]

PACKS: dict[str, tuple[str, str]] = {
    "insurance": ("t_1042", "acme-insurance"),
    "energy": ("t_2210", "acme-energy"),
    "finance": ("t_3310", "acme-finance"),
    "healthcare": ("t_4410", "acme-health"),
}
"""The packs this harness may send, each with the tenant (id, slug) its golden rows name. Never the
responsible-AI pack (its set is withheld by rule, and one rule's question is never sent)."""

EXPECTED_WITHHELD: dict[str, int] = {"insurance": 33, "energy": 24, "finance": 0, "healthcare": 20}
"""How many rows of each pack are withheld (``no_live_run``): the decisions, asserted at load, so a
set that gained or lost a withheld row can't be sent without someone looking."""
HEALTHCARE_WITHHELD = frozenset(
    {f"hc-dos-pos-{n:03d}" for n in range(1, 17)}
    | {"hc-dgn-pos-007", "hc-dgn-pos-008", "hc-out-pos-015", "hc-out-pos-016"}
)
"""The healthcare pack's withheld rows, exactly: every dosing-advice positive (16), the two
diagnosis rows that discourage seeking care and the two misinformation rows."""

NEVER_SENT_RULES = frozenset({"d__ins_fraud_signal", "d__en_unsafe_advice", "d__harm_facilitation"})
"""Rules whose positives are withheld or harm-facilitating: a row labelled with one is
never sent, whatever else it says."""

LIVE_KEY = "GUARDRAILS_LIVE_CALIBRATION"
LIVE_TOKEN = "m4-08-sendable-rows"
MIN_INTERVAL_S = 1.5
ALLOWANCE_USE = 0.8
"""The share of the calibration consumer's token allowance a live run plans to use."""
MAX_CHECKS_PER_PACK = 800
"""A live run refuses a plan larger than this (the sendable rows at three draws are about 690)."""


class Refused(Exception):
    """The run must not start. The message says why and never quotes row content."""


# --------------------------------------------------------------------------- what may be sent


VERSIONS = (1, 2)
"""The pack versions this harness can run: @1 is ``pack.json``, @2 is ``pack.v2.json``. The golden
rows are the same for both."""


def pack_path(pack: str, version: int = 1) -> Path:
    if version not in VERSIONS:
        raise Refused(f"unknown pack version {version!r}: one of {VERSIONS}")
    path = ROOT / "packs" / pack / ("pack.json" if version == 1 else f"pack.v{version}.json")
    if not path.is_file():
        raise Refused(f"{pack} has no version {version}")
    return path


def corpus_path(pack: str) -> Path:
    if pack not in PACKS:
        raise Refused(f"unknown pack {pack!r}: this harness sends only {', '.join(sorted(PACKS))}")
    return ROOT / "packs" / pack / "golden.jsonl"


def check_pack_corpus(path: Path, root: Path = ROOT) -> None:
    """Refuse any example file but the two packs' golden sets."""
    try:
        rel = path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        rel = str(path)
    allowed = [f"packs/{name}/golden.jsonl" for name in PACKS]
    if rel not in allowed:
        raise Refused(f"refusing to use {path}: not one of {', '.join(allowed)}")


def row_strings(row: Mapping[str, Any]) -> list[str]:
    """Every text of the row that would reach a request: content, context and tools."""
    texts = [str(row.get("content", ""))]
    for item in row.get("context", ()):
        texts += [str(v) for k, v in item.items() if k != "type"]
    for tool in row.get("tools", ()):
        texts += [str(tool.get("name", "")), str(tool.get("description", ""))]
    return texts


def send_refusal(row: Mapping[str, Any]) -> str | None:
    """Why this row may not be sent, or None. Reasons are fixed phrases, never content."""
    from guardrail_engine.admin.vocabulary import strings_tripwire

    if (why := live_exclusion(row)) is not None:
        return why
    if row.get("no_live_run") is not False:
        return "withheld (no_live_run is not false)"
    if NEVER_SENT_RULES & set(row.get("fires", ())):
        return "labelled for a rule whose positives are never sent"
    if strings_tripwire(*row_strings(row)):
        return "harm-vocabulary tripwire"
    return None


def load_sendable(pack: str, root: Path = ROOT) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """The pack's rows that may be sent, and the others counted by reason."""
    path = root / "packs" / pack / "golden.jsonl"
    corpus_path(pack)  # refuses an unknown pack
    check_pack_corpus(path, root)
    tenant_id, slug = PACKS[pack]
    kept: list[dict[str, Any]] = []
    excluded: Counter[str] = Counter()
    withheld: set[str] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        if (row.get("tenant_id"), row.get("tenant_slug")) != (tenant_id, slug):
            raise Refused(f"row {row.get('id')} names a tenant other than the pack's")
        if (why := send_refusal(row)) is None:
            kept.append(row)
        else:
            excluded[why] += 1
            withheld.add(row["id"])
    if sum(excluded.values()) != EXPECTED_WITHHELD[pack] or (
        pack == "healthcare" and withheld != HEALTHCARE_WITHHELD
    ):
        raise Refused(
            f"the {pack} set withholds {sum(excluded.values())} rows, not the agreed "
            f"{EXPECTED_WITHHELD[pack]} (or not the agreed ones): nothing is sent until a person "
            "looks"
        )
    return kept, dict(sorted(excluded.items()))


OVERLAP_P = 0.5
"""A row of another rule that a named rule scored at least this (the mean of its draws) in the
last live measurement of the pack is a cross-rule row, and is re-measured with the rule."""


def parse_rules(pack: str, version: int, text: str | None) -> tuple[str, ...] | None:
    """``--rules a,b``: the pack's own rule keys, or None for no filter. An unknown key refuses."""
    if text is None:
        return None
    doc = json.loads(pack_path(pack, version).read_text(encoding="utf-8"))
    known = {r["key"] for r in doc["rules"]}
    wanted = tuple(sorted({k.strip() for k in text.split(",") if k.strip()}))
    if not wanted or (bad := sorted(set(wanted) - known)):
        raise Refused(f"--rules: not rules of {pack}@{version}: {bad if wanted else 'none named'}")
    return wanted


def select_rows(
    pack: str,
    version: int,
    rows: Sequence[dict[str, Any]],
    rules: Sequence[str] | None,
    root: Path = ROOT,
) -> list[dict[str, Any]]:
    """The rows a **re-measure of** ``rules`` sends: with no filter, every sendable row. With one,
    at the guard points the named rules run at, **(i) each rule's own category** (its positives
    and the near-misses that look like them: the hard pool the thresholds are set on) and
    **(ii) the cross-rule rows**, rows of any other rule that a named rule scored
    :data:`OVERLAP_P` or more on in the pack's last live measurement
    (``calibration/results/m4-08-<pack>-live.jsonl``, when it exists). Rows keep their order. A
    check still carries every question of its guard point: the filter saves checks, not
    questions."""
    if rules is None:
        return list(rows)
    doc = json.loads(pack_path(pack, version).read_text(encoding="utf-8"))
    named = [r for r in doc["rules"] if r["key"] in rules]
    own: dict[str, set[str]] = {r["key"]: set() for r in named}
    for row in rows:
        for key in rules:
            if key in row["fires"]:
                own[key].add(row["category"])
    scores: dict[str, dict[str, list[float]]] = {}
    prior = root / "calibration" / "results" / f"m4-08-{pack}-live.jsonl"
    if prior.is_file():
        for line in prior.read_text(encoding="utf-8").splitlines():
            rec = json.loads(line)
            if rec.get("type") == "call" and rec.get("outcome") == "answered":
                for key in rules:
                    if key in rec["probabilities"]:
                        scores.setdefault(rec["example_id"], {}).setdefault(key, []).append(
                            rec["probabilities"][key]
                        )
    chosen = []
    for row in rows:
        for rule in named:
            if row["guard_point"] not in rule["guard_points"]:
                continue
            mine = row["category"] in own[rule["key"]]
            ps = scores.get(row["id"], {}).get(rule["key"], [])
            cross = bool(ps) and sum(ps) / len(ps) >= OVERLAP_P
            if mine or cross:
                chosen.append(row)
                break
    return chosen


def pack_problems(pack: str, version: int = 1) -> list[str]:
    """What stops the pack itself being sent: its text trips the tripwire, or it names a rule
    that is never sent."""
    from guardrail_engine.admin.vocabulary import strings_tripwire

    doc = json.loads(pack_path(pack, version).read_text(encoding="utf-8"))
    found = []
    strings: list[str] = []

    def walk(node: Any) -> None:
        if isinstance(node, str):
            strings.append(node)
        elif isinstance(node, Mapping):
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    walk(doc)
    if strings_tripwire(*strings):
        found.append("the pack's own text trips the harm-vocabulary tripwire")
    if "responsible_ai" in json.dumps(doc) or any(
        r["key"].endswith("harm_facilitation") for r in doc["rules"]
    ):
        found.append("the pack names the responsible-AI pack or harm facilitation")
    return found


def load_api_key(env_file: Path | None) -> bool:
    """Make ``GEMINI_API_KEY`` available to the factory without ever showing it. Returns whether
    it is set. Reads only the one setting from ``env_file`` and puts it in the process
    environment; the value is never printed, logged or returned."""
    if os.environ.get("GEMINI_API_KEY"):
        return True
    if env_file is None or not env_file.is_file():
        return False
    for line in env_file.read_text(encoding="utf-8").splitlines():
        name, sep, value = line.strip().partition("=")
        if sep and name.strip() == "GEMINI_API_KEY":
            value = value.strip().strip("'\"")
            if value:
                os.environ["GEMINI_API_KEY"] = value
                return True
    return False


def default_env_file() -> Path | None:
    for base in (ROOT, ROOT.parent.parent):
        if (base / ".env").is_file():
            return base / ".env"
    return None


# --------------------------------------------------------------------------- the engine


def compile_for(pack: str, version: int = 1) -> tuple[Setup, Any, Any]:
    """The floor's and the pack's questions per guard point, compiled by the engine from the
    bundle the calibration tenant publishes, shaped as a :class:`Setup` so the token estimate
    and the limit preflight of the engine path apply unchanged."""
    from guardrail_engine.floor_file import load_floor_file
    from guardrail_engine.pack_file import load_pack_file
    from guardrail_engine.policy import (
        InMemoryCatalog,
        InMemoryToolRegistry,
        PlatformSettings,
        PolicyCompiler,
        TenantAttributes,
    )

    floor = load_floor_file(ROOT / "floor" / "rules.json")
    loaded = load_pack_file(pack_path(pack, version))
    tenant_id, _ = PACKS[pack]
    compiler = PolicyCompiler(
        InMemoryCatalog(floors=[floor], packs=[loaded]),
        InMemoryToolRegistry(),
        PlatformSettings(min_floor_version=floor.version),
    )
    policy = compiler.compile(bundle_for(pack, floor.version, loaded.ref),
                              TenantAttributes(tenant_id=tenant_id))  # fmt: skip
    setup = Setup(
        floor_doc={},
        questions={gp: dict(c.questions) for gp, c in policy.guard_points.items()},
        thresholds={}, rule_gps={},
        max_content_tokens={gp: c.max_content_tokens for gp, c in policy.guard_points.items()},
        files={},
    )  # fmt: skip
    return setup, floor, loaded


def bundle_for(pack: str, floor_version: int, pack_ref: str) -> dict[str, Any]:
    """The calibration tenant's bundle: the floor and the one pack, nothing else."""
    return {"schema_version": 1, "tenant_id": PACKS[pack][0], "version": 1,
            "extends": [f"platform/floor@{floor_version}", pack_ref]}  # fmt: skip


@contextlib.asynccontextmanager
async def pack_engine(
    pack: str, model: Any, nonces: SeededNonces, version: int = 1
) -> AsyncIterator[tuple[Any, Any]]:
    """Build the engine (``test`` environment, seeded nonces, no audit sink) whose catalog holds
    the floor and the one pack, publish the tenant's bundle, yield (engine, verifier)."""
    from guardrail_engine.engine import EngineSettings, build_engine
    from guardrail_engine.floor_file import load_floor_file
    from guardrail_engine.guard import HmacContextVerifier, InMemoryTenantDirectory, TenantProfile
    from guardrail_engine.guard.audit import NullAuditSink
    from guardrail_engine.pack_file import load_pack_file
    from guardrail_engine.policy import InMemoryCatalog, TenantAttributes

    floor = load_floor_file(ROOT / "floor" / "rules.json")
    loaded = load_pack_file(pack_path(pack, version))
    tenant_id, slug = PACKS[pack]
    directory = InMemoryTenantDirectory(
        [TenantProfile.build(TenantAttributes(tenant_id=tenant_id), pack, (), slug=slug)]
    )
    verifier = HmacContextVerifier(secrets.token_bytes(32))
    mapping = settings_mapping(floor.version, live=model is None)
    mapping["catalog"] = {"default_on_packs": []}  # no responsible-AI pack, however configured
    engine = await build_engine(
        EngineSettings.from_mapping(mapping), verifier=verifier, tenants=directory, model=model,
        catalog=InMemoryCatalog(floors=[floor], packs=[loaded]), audit=NullAuditSink(),
        nonce_source=nonces,
    )  # fmt: skip
    if "nonce_source" not in engine.test_overrides:
        await engine.shutdown()
        raise StopRun("the engine was built without the seeded nonce source")
    try:
        await engine.bootstrap_publish(bundle_for(pack, floor.version, loaded.ref))
        yield engine, verifier
    finally:
        await engine.shutdown()


@dataclass
class PackRunner(EngineRunner):
    """The engine path's runner, with the send-time check this harness adds: every row is
    checked against :func:`send_refusal` immediately before its request exists."""

    current_row: Mapping[str, Any] | None = None
    send_checks: int = 0

    async def check(self, row: Mapping[str, Any], draw: int, attempt: int = 1) -> dict[str, Any]:
        if (why := send_refusal(row)) is not None:
            at = datetime.now(UTC).isoformat(timespec="milliseconds")
            self.write({"type": "run_stopped", "reason": "send_refusal",
                        "example_id": row.get("id"), "cause": why, "at": at})  # fmt: skip
            raise StopRun(f"refusing to send {row.get('id')}: {why}")
        self.send_checks += 1
        self.current_row = row
        try:
            record = await super().check(row, draw, attempt)
        finally:
            self.current_row = None
        self._stop_on_orphans(row)
        return record

    def _stop_on_orphans(self, row: Mapping[str, Any]) -> None:
        """A call the gateway abandoned and that kept running (an adapter that ignores
        cancellation) has an outcome nobody sees, a refusal included. Nothing is sent after one:
        the run stops (nothing at all starts after a refusal we could not see)."""
        gateway = self.engine.guard.gateway
        if gateway.orphaned_calls or gateway.orphans_in_flight:
            at = datetime.now(UTC).isoformat(timespec="milliseconds")
            self.write({"type": "run_stopped", "reason": "orphaned_call",
                        "example_id": row.get("id"), "at": at})  # fmt: skip
            raise StopRun(f"a call near {row.get('id')} outlived its cancellation: run stopped")


def pace_interval_s(estimates: Mapping[str, int], rows: Sequence[Mapping[str, Any]]) -> float:
    """Seconds between check starts: the mean estimated tokens of a check spread over
    :data:`ALLOWANCE_USE` of the calibration consumer's token allowance, and never under
    :data:`MIN_INTERVAL_S`."""
    from guardrail_engine.gateway import CONSUMER_CALIBRATION, TokenRateConfig
    from guardrail_engine.gateway.tenant_quota import DEFAULT_NON_PRODUCTION

    config = TokenRateConfig()
    allowance = (
        config.tokens_per_minute * config.target_fraction
        * DEFAULT_NON_PRODUCTION[CONSUMER_CALIBRATION]
    )  # fmt: skip
    if not rows:
        return MIN_INTERVAL_S
    mean = sum(estimates.get(r["id"], 0) for r in rows) / len(rows)
    return max(MIN_INTERVAL_S, round(mean * 60 / (ALLOWANCE_USE * allowance), 3))


def price_per_million() -> float:
    from guardrail_engine.gateway import TokenRateConfig

    return TokenRateConfig().price_per_million_input_tokens_usd


# --------------------------------------------------------------------------- the dry-run model


def dry_run_model(pack: str, runner_box: list[PackRunner], version: int = 1) -> Any:
    """The engine's fake model answering from the row's label with deterministic spread: a rule
    the row fires scores 0.80 to 0.97, a near-miss of the rule's category 0.20 to 0.60, any
    other row 0.01 to 0.10. It reads the row from the runner, so it exercises the same path a
    live model would."""
    from guardrail_engine.decision import FakeDecisionModel

    doc = json.loads(pack_path(pack, version).read_text(encoding="utf-8"))
    keys = {r["key"] for r in doc["rules"]}
    categories: dict[str, set[str]] = {}
    for line in corpus_path(pack).read_text(encoding="utf-8").splitlines():
        row = json.loads(line)
        for key in row["fires"]:
            categories.setdefault(key, set()).add(row["category"])

    def responder(text: str, key: str, question: Any) -> float | None:
        row = runner_box[0].current_row if runner_box else None
        if row is None:
            return None
        spread = (
            int.from_bytes(f"{row['id']}|{key}|{text[-34:]}".encode()[-6:], "big") % 1000
        ) / 1000
        if key not in keys:
            return 0.01
        if key in row["fires"]:
            return round(0.80 + 0.17 * spread, 3)
        if row["category"] in categories.get(key, ()):
            return round(0.20 + 0.40 * spread, 3)
        return round(0.01 + 0.09 * spread, 3)

    return FakeDecisionModel(responder=responder)


# --------------------------------------------------------------------------- the report


def p95(values: Sequence[float]) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, math.ceil(0.95 * len(ordered)) - 1)]


def suggestion_dict(s: Suggestion) -> dict[str, Any]:
    return {"block_at": s.block_at, "escalate_at": s.escalate_at, "band_empty": s.band_empty,
            "precision": s.precision, "recall": s.recall, "examples": s.examples,
            "positives": s.positives, "reason": s.reason}  # fmt: skip


def rule_report(
    rule: Mapping[str, Any],
    rows: Sequence[Mapping[str, Any]],
    draws: Mapping[str, Mapping[str, list[float]]],
    targets: Targets,
) -> dict[str, Any]:
    """One rule's measurement. ``draws``: row id -> rule key -> that row's answered draws."""
    key = rule["key"]
    at_gp = [r for r in rows if r["guard_point"] in rule["guard_points"]]
    own = {r["category"] for r in at_gp if key in r["fires"]}
    scored, left_out = [], 0
    for row in at_gp:
        ps = draws.get(row["id"], {}).get(key, [])
        if ps:
            scored.append((row, ps))
        else:
            left_out += 1

    def pool(items: Sequence[tuple[Mapping[str, Any], list[float]]]) -> dict[str, Any]:
        means = [(statistics.fmean(ps), key in row["fires"]) for row, ps in items]
        pooled = [(p, key in row["fires"]) for row, ps in items for p in ps]
        suggestion = sweep(means, targets, max_action=rule.get("max_action"))
        pos = sorted(m for m, is_pos in means if is_pos)
        neg = sorted(m for m, is_pos in means if not is_pos)
        top = max(
            ((statistics.fmean(ps), r["category"]) for r, ps in items if key not in r["fires"]),
            default=None,
        )
        return {
            "separation": {
                "positive_min": pos[0] if pos else None,
                "positive_median": statistics.median(pos) if pos else None,
                "negative_p95": p95(neg),
                "negative_max": neg[-1] if neg else None,
                "negative_max_category": top[1] if top else None,
            },
            "examples": len(means), "positives": sum(pos_ for _, pos_ in means),
            "suggestion": suggestion_dict(suggestion),
            "pooled_suggestion": suggestion_dict(
                sweep(pooled, targets, max_action=rule.get("max_action"))
            ),
            "at_present": {
                "block": (
                    None if rule.get("max_action") == "escalate"
                    else _point(means, rule["block_at"])
                ),
                "escalate": _point(means, rule["escalate_at"]),
            },
        }  # fmt: skip

    all_pool = pool(scored)
    hard_pool = pool([(r, ps) for r, ps in scored if r["category"] in own or key in r["fires"]])
    ranges = [max(ps) - min(ps) for _, ps in scored if len(ps) > 1]
    positives, negatives = all_pool["positives"], all_pool["examples"] - all_pool["positives"]
    return {
        "key": key, "mode": rule.get("mode"), "guard_points": rule["guard_points"],
        "max_action": rule.get("max_action"),
        "block_at": rule["block_at"], "escalate_at": rule["escalate_at"],
        "positives": positives, "negatives": negatives, "left_out_no_score": left_out,
        "thin": positives < THIN or negatives < THIN,
        "not_calibratable": (
            "no sendable positive rows (every firing row is withheld by the user's rule)"
            if positives == 0 else None
        ),
        "all": all_pool, "hard": hard_pool, "noise_p95_range": p95(ranges),
    }  # fmt: skip


def _point(scores: Sequence[tuple[float, bool]], threshold: float) -> dict[str, Any]:
    pt = confusion(scores, threshold)
    negatives = len(scores) - pt.positives
    return {"threshold": threshold, "precision": pt.precision, "recall": pt.recall,
            "false_act_rate": None if negatives == 0 else pt.fp / negatives,
            "tp": pt.tp, "fp": pt.fp}  # fmt: skip


def spend(records: Sequence[Mapping[str, Any]], estimates: Mapping[str, int]) -> dict[str, Any]:
    calls = [r for r in records if r.get("type") == "call"]
    tokens = sum(tokens_of(r, estimates.get(r["example_id"], 0)) for r in calls)
    known = sum(1 for r in calls if r.get("outcome") == "answered"
                and r.get("usage_input_tokens") is not None)  # fmt: skip
    price = price_per_million()
    return {
        "checks": len(calls), "answered": sum(r["outcome"] == "answered" for r in calls),
        "failed": sum(r["outcome"] == "failed" for r in calls),
        "provider_calls": sum(1 if r.get("provider_calls") is None else r["provider_calls"]
                              for r in calls),
        "input_tokens": tokens, "checks_with_reported_usage": known,
        "reported_input_tokens": sum(r.get("usage_input_tokens") or 0 for r in calls),
        "cost_reported_usd": round(
            sum(r.get("usage_input_tokens") or 0 for r in calls) / 1_000_000 * price, 4
        ),
        "price_per_million_input_tokens_usd": price,
        "cost_usd": round(tokens / 1_000_000 * price, 4),
    }  # fmt: skip


def build_report(
    pack: str,
    records: Sequence[Mapping[str, Any]],
    rows: Sequence[Mapping[str, Any]],
    estimates: Mapping[str, int],
    targets: Targets | None = None,
    draws: int = DRAWS,
    version: int = 1,
    rules: Sequence[str] | None = None,
) -> dict[str, Any]:
    """Per-rule suggestions and the spend, from a run's records. Only examples with all their
    draws answered count (an unanswered draw is never a score in either direction)."""
    targets = targets or Targets()
    doc = json.loads(pack_path(pack, version).read_text(encoding="utf-8"))
    short = incomplete(records, draws)
    usable = complete_records(records, draws)
    by_row: dict[str, dict[str, list[float]]] = {}
    for rec in usable:
        if rec.get("type") != "call":
            continue
        for key, p in rec["probabilities"].items():
            by_row.setdefault(rec["example_id"], {}).setdefault(key, []).append(p)
    return {
        "pack": f"{doc['name']}@{doc['version']}", "draws": draws,
        "targets": targets.as_dict(), "rows_sent": len(rows),
        "incomplete_examples": short,
        "rules": [
            rule_report(r, rows, by_row, targets)
            for r in doc["rules"]
            if rules is None or r["key"] in rules
        ],
        "spend": spend(records, estimates),
    }  # fmt: skip


def _fmt(x: float | None) -> str:
    return "-" if x is None else f"{x:.2f}"


def _sugg(s: Mapping[str, Any]) -> str:
    if s["block_at"] is None and s["escalate_at"] is None:
        return f"none ({s['reason']})"
    parts = [f"block_at {_fmt(s['block_at'])}"] if s["block_at"] is not None else []
    if s["escalate_at"] is not None:
        parts.append(f"escalate_at {_fmt(s['escalate_at'])}")
    if s["reason"]:
        parts.append(s["reason"])
    return ", ".join(parts)


def render_markdown(rep: Mapping[str, Any]) -> str:
    out = [f"# {rep['pack']}: sendable-row calibration ({rep['draws']} draws)", ""]
    sp = rep["spend"]
    out += [
        f"Rows sent per draw: {rep['rows_sent']}. Checks {sp['checks']} "
        f"({sp['answered']} answered, {sp['failed']} failed), provider calls "
        f"{sp['provider_calls']}. Input tokens the provider reported "
        f"{sp['reported_input_tokens']:,} "
        f"(**${sp['cost_reported_usd']:.4f}** at ${sp['price_per_million_input_tokens_usd']}/M); "
        f"counting each failed check at its estimate (the run's ceiling accounting) "
        f"{sp['input_tokens']:,} (${sp['cost_usd']:.4f}).",
        f"Targets: block precision {rep['targets']['block_precision']}, escalate recall "
        f"{rep['targets']['escalate_recall']}.",
    ]
    if rep["incomplete_examples"]:
        out.append(f"Incomplete examples (left out): {len(rep['incomplete_examples'])}.")
    out += ["", "| rule | mode | pos / neg | present block, escalate | suggestion (draw means) "
            "| suggestion (hard pool) | note |", "|---|---|---|---|---|---|---|"]  # fmt: skip
    for r in rep["rules"]:
        note = r["not_calibratable"] or ("thin cell" if r["thin"] else "")
        if r["max_action"]:
            note = f"max_action {r['max_action']}; " + note
        out.append(
            f"| {r['key']} | {r['mode']} | {r['positives']} / {r['negatives']} | "
            f"{_fmt(r['block_at'])}, {_fmt(r['escalate_at'])} | {_sugg(r['all']['suggestion'])} | "
            f"{_sugg(r['hard']['suggestion'])} | {note} |"
        )
    out += ["", "## At the present thresholds, and how far apart the scores are", "",
            "| rule | pool | block: precision / recall | escalate: recall / false-act | "
            "positives min / median | negatives p95 / max (category of the max) |",
            "|---|---|---|---|---|---|"]  # fmt: skip
    for r in rep["rules"]:
        for name in ("all", "hard"):
            pl, sep = r[name], r[name]["separation"]
            blk, esc = pl["at_present"]["block"], pl["at_present"]["escalate"]
            out.append(
                f"| {r['key']} | {name} ({pl['positives']}/{pl['examples'] - pl['positives']}) | "
                + (f"{_fmt(blk['precision'])} / {_fmt(blk['recall'])}" if blk else "capped")
                + f" | {_fmt(esc['recall'])} / {_fmt(esc['false_act_rate'])} | "
                f"{_fmt(sep['positive_min'])} / {_fmt(sep['positive_median'])} | "
                f"{_fmt(sep['negative_p95'])} / {_fmt(sep['negative_max'])} "
                f"({sep['negative_max_category']}) |"
            )
    out += ["", "A suggestion is computed, not applied: the thresholds change only through a new "
            "pack version (a pack version never changes)."]  # fmt: skip
    return "\n".join(out) + "\n"


# --------------------------------------------------------------------------- plan and run


def plan(
    pack: str,
    draws: int,
    seed: str | None = None,
    max_tokens: int | None = None,
    version: int = 1,
    rules: Sequence[str] | None = None,
) -> dict:
    all_rows, excluded = load_sendable(pack)
    rows = select_rows(pack, version, all_rows, rules)
    direct, floor, loaded = compile_for(pack, version)
    flagged = preflight(rows, direct)
    estimates = row_token_estimates(rows, direct)
    estimated = draws * sum(estimates.values())
    return {
        "pack": loaded.ref, "floor_version": floor.version, "environment": ENVIRONMENT,
        "tenant": PACKS[pack][0],
        "bundle_extends": bundle_for(pack, floor.version, loaded.ref)["extends"],
        "rules": None if rules is None else list(rules),
        "rows_sendable": len(all_rows), "rows_selected": len(rows), "rows_not_sent": excluded,
        "draws": draws,
        "checks": len(rows) * draws, "ceiling_checks_with_one_retry": 2 * len(rows) * draws,
        "estimated_input_tokens": estimated,
        "estimated_cost_usd": round(estimated / 1_000_000 * price_per_million(), 4),
        "min_interval_s": pace_interval_s(estimates, rows),
        "would_exceed_a_limit": flagged, "pack_problems": pack_problems(pack, version),
        "nonce_seed": SeededNonces(seed or new_seed()).seed,
        "within_token_ceiling": None if max_tokens is None else estimated <= max_tokens,
    }  # fmt: skip


def refuse_to_start(args: argparse.Namespace, planned: Mapping[str, Any]) -> None:
    if planned["pack_problems"]:
        raise Refused("; ".join(planned["pack_problems"]))
    try:  # no harm-facilitation question in a bundle that may go to the provider
        refuse_harm_facilitation(compile_for(args.pack, args.pack_version)[0].questions)
    except StopRun as e:
        raise Refused(str(e)) from e
    if any(planned["would_exceed_a_limit"].values()):
        raise Refused(f"examples would exceed a limit {planned['would_exceed_a_limit']}")
    if args.draws < DRAWS:
        raise Refused(f"at least {DRAWS} draws")
    if args.live:
        if os.environ.get(LIVE_KEY) != LIVE_TOKEN:
            raise Refused(
                f"a live run needs the user's written approval, recorded in the environment as "
                f"{LIVE_KEY} (see calibration/README.md); the value is not printed here"
            )
        if args.max_tokens is None or args.max_provider_calls is None:
            raise Refused("a live run needs --max-tokens and --max-provider-calls")
        if planned["checks"] > MAX_CHECKS_PER_PACK:
            raise Refused(f"a plan of {planned['checks']} checks is over {MAX_CHECKS_PER_PACK}")
        if not load_api_key(Path(args.env_file) if args.env_file else default_env_file()):
            raise Refused("GEMINI_API_KEY is not set (environment or --env-file)")
    if args.max_tokens is not None and planned["estimated_input_tokens"] > args.max_tokens:
        raise Refused(f"the plan needs about {planned['estimated_input_tokens']:,} input tokens, "
                      f"over the ceiling of {args.max_tokens:,}")  # fmt: skip
    if args.max_provider_calls is not None and planned["checks"] > args.max_provider_calls:
        raise Refused(f"the plan makes {planned['checks']} checks, over the ceiling of "
                      f"{args.max_provider_calls}")  # fmt: skip


RESUMABLE_STOPS = ("token_ceiling", "provider_call_ceiling")
"""The stops that say only that a ceiling was reached before the next check was sent. A run that
stopped for anything else (a refusal, auth, an unclassified failure, a send-time refusal, a
failure rate) is never continued: a person looks at it first and starts a new file."""


def refuse_resume_after_stop(
    records: Sequence[Mapping[str, Any]], args: argparse.Namespace
) -> None:
    stops = [r for r in records if r.get("type") == "run_stopped"]
    if not stops:
        return
    if any(s.get("reason") not in RESUMABLE_STOPS for s in stops):
        raise Refused("this run was stopped; start a new --out file")
    started = next((r for r in records if r.get("type") == "run_started"), {})
    for key, flag in (
        ("token_ceiling", "max_tokens"),
        ("provider_call_ceiling", "max_provider_calls"),
    ):
        if any(s.get("reason") == key for s in stops):
            seen = [started.get(key)] + [
                r.get(key) for r in records if r.get("type") == "run_resumed"
            ]
            was, now = max((x for x in seen if x is not None), default=None), getattr(args, flag)
            if now is None or (was is not None and now <= was):
                raise Refused(
                    f"this run stopped at its {key.replace('_', ' ')}; continue it with a higher "
                    f"--{flag.replace('_', '-')} (it was {was}), or start a new --out file"
                )


async def run(args: argparse.Namespace) -> int:
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    records = _read(out)
    refuse_resume_after_stop(records, args)
    rules = parse_rules(args.pack, args.pack_version, args.rules)
    all_rows, excluded = load_sendable(args.pack)
    rows = select_rows(args.pack, args.pack_version, all_rows, rules)
    planned = plan(args.pack, args.draws, args.seed, args.max_tokens, args.pack_version, rules)
    refuse_to_start(args, planned)
    started = next((r for r in records if r.get("type") == "run_started"), None)
    files = {
        "golden.jsonl": sha256_file(corpus_path(args.pack)),
        pack_path(args.pack, args.pack_version).name: sha256_file(
            pack_path(args.pack, args.pack_version)
        ),
    }
    if started and started.get("files") != files:
        raise Refused("the pack files changed since this run started; start a new --out file")
    if started and started.get("rules") != (None if rules is None else list(rules)):
        raise Refused("this run started with other --rules; start a new --out file")
    direct, _, _ = compile_for(args.pack, args.pack_version)
    estimates = row_token_estimates(rows, direct)
    seed = (started or {}).get("nonce_seed") or args.seed or planned["nonce_seed"]
    nonces = SeededNonces(seed)
    box: list[PackRunner] = []
    model = None if args.live else dry_run_model(args.pack, box, args.pack_version)
    interval = pace_interval_s(estimates, rows) if args.live else 0.0
    async with pack_engine(args.pack, model, nonces, args.pack_version) as (engine, verifier):
        runner = PackRunner(
            out=out, engine=engine, verifier=verifier, nonces=nonces,
            token_ceiling=args.max_tokens, token_estimates=estimates,
            provider_call_ceiling=args.max_provider_calls, usage_class="calibration",
            min_interval_s=interval, avoid_minute_boundary=bool(args.live),
        )  # fmt: skip
        box.append(runner)
        runner.provider_calls_used = sum(
            1 if r["provider_calls"] is None else r["provider_calls"]
            for r in records if r.get("type") == "call"
        )  # fmt: skip
        runner.tokens_used = sum(tokens_of(r, estimates.get(r["example_id"], 0))
                                 for r in records if r.get("type") == "call")  # fmt: skip
        runner.recent.extend(r["outcome"] == "failed" for r in records if r.get("type") == "call")
        if any(r.get("type") == "run_stopped" for r in records):
            runner.write({
                "type": "run_resumed", "at": datetime.now(UTC).isoformat(timespec="seconds"),
                "after": [r["reason"] for r in records if r.get("type") == "run_stopped"],
                "token_ceiling": args.max_tokens, "provider_call_ceiling": args.max_provider_calls,
            })  # fmt: skip
        if started is None:
            runner.write({
                "type": "run_started", "at": datetime.now(UTC).isoformat(timespec="seconds"),
                "harness": "pack_live (M4-08)", "path": "engine (build_engine)",
                "environment": ENVIRONMENT, "mode": "live" if args.live else "dry-run",
                "pack": planned["pack"], "floor_version": planned["floor_version"],
                "bundle_extends": planned["bundle_extends"], "files": files,
                "examples": len(rows), "not_sent": excluded, "draws": args.draws,
                "rules": None if rules is None else list(rules),
                "nonce_seed": nonces.seed, "usage_class": runner.usage_class,
                "min_interval_s": interval, "token_ceiling": args.max_tokens,
                "provider_call_ceiling": args.max_provider_calls,
                "estimated_input_tokens": planned["estimated_input_tokens"],
                "send_time_checks": ["live_exclusion", "no_live_run is false",
                                     "never-sent rules", "harm tripwire"],
                "stops_on": "the first provider refusal, auth, or an unclassified failure",
                "redaction": REDACTION_APPLIED,
            })  # fmt: skip
        try:
            await run_engine_path(runner, rows, records, draws=args.draws,
                                  reattempts=not args.no_reattempts)  # fmt: skip
            runner.write(finished_record(_read(out)))
        except StopRun as e:
            print(str(e), file=sys.stderr)
            return 3
        finally:
            print(f"checks made this session: {runner.calls}", file=sys.stderr)
    return 0


def report(args: argparse.Namespace) -> int:
    records = _read(Path(args.records))
    rules = parse_rules(args.pack, args.pack_version, args.rules)
    all_rows, _ = load_sendable(args.pack)
    rows = select_rows(args.pack, args.pack_version, all_rows, rules)
    direct, _, _ = compile_for(args.pack, args.pack_version)
    rep = build_report(
        args.pack, records, rows, row_token_estimates(rows, direct),
        draws=args.draws, version=args.pack_version, rules=rules,
    )  # fmt: skip
    print(json.dumps(rep, indent=1) if args.json else render_markdown(rep))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("plan", "run", "report"):
        p = sub.add_parser(name)
        p.add_argument("--pack", required=True, choices=sorted(PACKS))
        p.add_argument("--draws", type=int, default=DRAWS)
        p.add_argument("--rules", default=None,
                       help="re-measure only these rules (comma-separated keys): their own "
                            "category and the cross-rule rows of the last measurement")  # fmt: skip
        p.add_argument("--pack-version", type=int, default=1, choices=VERSIONS,
                       help="1 is pack.json, 2 is pack.v2.json (same golden rows)")  # fmt: skip
        if name == "report":
            p.add_argument("records")
            p.add_argument("--json", action="store_true")
            continue
        p.add_argument("--seed", default=None)
        p.add_argument("--max-tokens", type=int, default=None)
        p.add_argument("--max-provider-calls", type=int, default=None)
        if name == "run":
            p.add_argument("--out", required=True)
            p.add_argument("--live", action="store_true",
                           help="send to the provider (also needs the approval variable in the "
                           "environment, with the user's written approval)",
                           )  # fmt: skip
            p.add_argument("--env-file", default=None,
                           help="an .env file holding GEMINI_API_KEY (never printed)")  # fmt: skip
            p.add_argument("--no-reattempts", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.command == "report":
            return report(args)
        if args.command == "plan":
            print(
                json.dumps(
                    plan(
                        args.pack,
                        args.draws,
                        args.seed,
                        args.max_tokens,
                        args.pack_version,
                        parse_rules(args.pack, args.pack_version, args.rules),
                    ),
                    indent=1,
                )
            )
            return 0
        return asyncio.run(run(args))
    except Refused as e:
        print(str(e), file=sys.stderr)
        return 2
    except StopRun as e:
        print(str(e), file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
