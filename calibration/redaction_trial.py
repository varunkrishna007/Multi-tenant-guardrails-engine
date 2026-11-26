"""M7-12: does redacting PII change decision quality? The trial's harness.

    uv run python -m calibration.redaction_trial manifest --out M.json [--summary M.md]
    uv run python -m calibration.redaction_trial plan   --manifest M.json
    uv run python -m calibration.redaction_trial run    --manifest M.json --out R.jsonl --live
    uv run python -m calibration.redaction_trial report R.jsonl --manifest M.json

Only ``run --live`` sends anything, and only an armed script runs it
(``docs/m7-12-redaction-trial.md``). Everything else is offline; the tests run the whole path
against a fake model.

The design is ``docs/m7-12-redaction-trial-design.md``; this file is the harness it describes, and
``docs/m7-12-redaction-trial.md`` says how a live run is armed.

**The rows.** The *affected* rows are the sendable rows of the floor golden set, the held-out set,
the red-team corpus and the energy pack whose request redaction changes (its content, its
conversation or the descriptions of the tools it names; :func:`pii_kinds`): benign and positive.
The *placebo* rows are unchanged rows of the same kind (20 benign, 20 positive, matched to the
affected rows' guard points, none of them blocked before a model call), sent identically in both
arms, so a shift in the affected rows can be read against what the model does to identical input.
Every row is checked at selection and again before any request: the live exclusions (harm-labelled,
``no_live_run``, retired), the harm-vocabulary tripwire, and a label that is a floor rule.

**The arms.** Each row goes twice, in one interleaved order: ``redacted`` (what production sends)
and ``raw`` (the same request with the PII detector switched off; known-format credentials are
still replaced by ``[SECRET]`` in both arms, because that is not PII and never leaves the process).
The same engine and gateway serve both, so the limiter sees one stream. Both arms of a (row, draw)
use the same nonce, so what differs is the text. The compiled policy is the platform's floor@2
(assembled from ``floor/rules.json`` and ``floor/next/additions.json``, as every harness does).

**What a run records** is what the engine path records (``calibration.engine_path``: sizes,
timings, outcomes and scores, never content, headers or provider text) plus the arm and the row's
group. **Nothing is resent**: a check that fails is recorded and not repeated (the gateway's own
single retry inside a check still happens, as in production).

**Stop rules** (the standing ones, all inherited from the engine path's runner): the first
provider refusal; an ``auth`` failure; any unclassified failure; a 429 (a ``rate_limited``
failure: the pacing should have prevented it); more than 20% of the last 50 checks failed; a
ceiling (provider calls, input tokens); and **a check the engine refused itself** (``token_rate``
and the like, no provider call), which is not a provider failure and is left out of the 20% rule,
but stops the run at once because it means the pacing is wrong. A run that stops writes why
(``run_stopped``) and exits 3.

**Pacing** (M7-12 attempt 2). Run 1 spaced its checks by the mean of their sizes and lost 45 of
492 to the gateway's own token allowance, which a large check outruns. Now each check waits until
the limiter would admit that check's own estimate (:meth:`EngineRunner.wait_for_admission`), and
the plan models the same limiter over the run's real order to say how long it takes
(:func:`pace_model`).

**What is verified before anything is sent** (:func:`verify_manifest`): the manifest's schema, the
hash of every source file and of the floor's content, that every row is still sendable, still
affected (or still not, for a placebo) and still labelled as the manifest says, that the manifest's
own row-set hash holds, and that the plan is inside the ceilings. Any mismatch refuses the run.

Exit codes: 0 done; 2 refused (nothing sent); 3 stopped.
"""

from __future__ import annotations

import argparse
import asyncio
import fcntl
import hashlib
import json
import math
import os
import sys
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from calibration import redaction_stats as stats
from calibration.engine_path import (
    ADMISSION_MARGIN,
    ADMISSION_SLACK_S,
    ENVIRONMENT,
    EngineRunner,
    EngineSetup,
    SeededNonces,
    calibration_engine,
    new_seed,
    tenant_of,
    tool_registries,
)
from calibration.metrics import clopper_pearson_upper
from calibration.run import (
    HELDOUT_MAX_CONTENT_TOKENS,
    REDACTION_APPLIED,
    ProviderBlockStop,
    StopRun,
    assemble_floor,
    build_setup,
    context_items,
    live_exclusion,
    redacted,
    secret_blocked,
    sha256_file,
    tool_infos,
)
from guardrail_engine.gateway.gateway import CAPACITY_REASONS, REASON_ORPHAN_CAP

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = 1
HARNESS = "redaction trial (M7-12)"
DRAWS = 3
ARMS = ("redacted", "raw")
CEILING_CALLS = 900
CEILING_INPUT_TOKENS = 2_000_000
PLACEBO_PER_LABEL = 20
"""Unchanged rows per label (20 benign and 20 positive: 40 in all)."""
PLACEBO_SEED = "m7-12-placebo-v1"
MARGIN_RECALL_POINTS = 10.0
MARGIN_FPR_POINTS = 5.0
MAX_FLIPS_PER_RULE = 2
SIGNIFICANCE = 0.05
USAGE_CLASS = "calibration"
EXIT_DONE, EXIT_REFUSED, EXIT_STOPPED = 0, 2, 3
LIVE_MIN_INTERVAL_S = 1.5
WINDOW_SAFETY_S = 10.0
"""No check starts within this many seconds of the deadline, so a check that starts last is over
before it."""
START_MARGIN_MINUTES = 5.0
"""A live run starts only if the plan's estimate plus this margin ends before the deadline."""
MODEL_CHECK_S = 1.0
"""What the plan assumes one check takes to answer (the median in run 1 was 0.5 s): a longer
check lets the bucket refill, so this only makes the plan's minutes a little longer."""
MAX_ADMISSION_WAIT_S = 30.0
"""The plan refuses if any one check would wait longer than this for the limiter: it would mean the
consumer's allowance cannot carry the check at any sane pace."""
MAX_ATTEMPT = 2
"""Attempt 1 was made on 2026-11-25 and was inconclusive; the user approved one more. A third
needs a change to the harness, which is reviewed."""
LOCAL_REFUSALS = CAPACITY_REASONS - {REASON_ORPHAN_CAP}
"""The failure reasons of a check the engine's own limiter or queue refused. With no provider call
they are not a provider failure; the run stops at the first (the pacing is at fault)."""

# What was approved, held by the harness itself: a manifest that differs in any of these is not
# the one the user saw, whatever hash it carries.
APPROVED_ROWS_SHA256 = "sha256:e4f0c800b5c5f6269df1d461684a5545923c6c010411d8f6b3ba8690164c41a9"
APPROVED_COUNTS = {
    "affected_benign": 43, "affected_positive": 54, "placebo_benign": 20, "placebo_positive": 20,
}  # fmt: skip
APPROVED_NONCE_SEED = "7c573fc2660bb29f2cd14a4e624b7c5d"
APPROVED_CHECKS = 822

SOURCES: dict[str, str] = {
    "golden": "floor/golden.jsonl",
    "heldout": "floor/heldout/heldout.jsonl",
    "energy": "packs/energy/golden.jsonl",
    "redteam": "redteam/corpus.jsonl",
}
"""The only files a row of the trial may come from, in the order a tool-definition conflict is
settled (the earlier source keeps its row). A source's hash is in the manifest and is checked
before a run."""
PLACEBO_SOURCES = ("golden", "heldout", "redteam")
RULES_REL, ADDITIONS_REL = "floor/rules.json", "floor/next/additions.json"
GROUPS = ("affected_benign", "affected_positive", "placebo_benign", "placebo_positive")


class Refused(Exception):
    """Nothing was sent: the message says why (never content)."""


# --------------------------------------------------------------------------- the arms


class NoPii:
    """A PII detector that finds nothing: the raw arm."""

    def find(self, text: str) -> list[Any]:
        return []


class ArmDetector:
    """The engine's PII detector, switched per check: ``raw`` finds nothing, else the engine's
    own deterministic detector. One engine serves both arms, so there is one limiter and one
    gateway; the switch is set just before each check, and checks are made one at a time."""

    def __init__(self) -> None:
        from guardrail_engine.guard.pii import DEFAULT_PII_DETECTOR

        self._detector = DEFAULT_PII_DETECTOR
        self.raw = False

    def find(self, text: str) -> Sequence[Any]:
        return [] if self.raw else self._detector.find(text)


def request_texts(row: Mapping[str, Any]) -> list[tuple[str, str]]:
    """(where, text) for every text the engine redacts in this row's request, mirroring
    ``redact_request``: the content, each conversation item's text, the name of a tool that isn't
    registered and the description of each registered tool the conversation names (once)."""
    from guardrail_engine.guard.request import Plan, ToolCall, ToolResult, Turn

    tools = tool_infos(row)
    found: list[tuple[str, str]] = []
    named: set[str] = set()
    for i, item in enumerate(context_items(row)):
        if isinstance(item, Turn | Plan):
            found.append((f"context[{i}].text", item.text))
        elif isinstance(item, ToolCall | ToolResult):
            if item.tool in tools and item.tool not in named:
                named.add(item.tool)
                found.append((f"tools.{item.tool}.description", tools[item.tool].description))
            if item.tool not in tools:
                found.append((f"context[{i}].tool", item.tool))
            if isinstance(item, ToolCall):
                found.append((f"context[{i}].arguments", item.arguments))
            else:
                found.append((f"context[{i}].result", item.result))
    found.append(("content", row["content"]))
    return found


def pii_matches(row: Mapping[str, Any]) -> list[dict[str, str]]:
    """Every span the engine's detector finds in the row's request: where, kind and the value (the
    synthetic text itself, for the user to read before approving)."""
    from guardrail_engine.guard.pii import DEFAULT_PII_DETECTOR

    out = []
    for where, text in request_texts(row):
        for m in DEFAULT_PII_DETECTOR.find(text):
            out.append({"where": where, "kind": m.kind.value, "value": text[m.start : m.end]})
    return out


def pii_kinds(row: Mapping[str, Any]) -> dict[str, int]:
    """Spans redaction replaces in the row's request, per kind (what the engine reports as
    ``pii_redacted``). Empty: redaction leaves the row's text alone."""
    return {k.value: n for k, n in sorted(redacted(row).counts.items(), key=lambda kv: kv[0].value)}


# --------------------------------------------------------------------------- the rows


def load_floor_rules(root: Path = ROOT) -> dict[str, tuple[float, float]]:
    doc = assemble_floor(root / RULES_REL, root / ADDITIONS_REL)
    return {r["key"]: (r["block_at"], r["escalate_at"]) for r in doc["rules"]}


def tripwire_views(row: Mapping[str, Any]) -> list[str]:
    """The views in which the row's request texts contain a word of the harm vocabulary
    (``admin.vocabulary``); empty: clean. Names the views only, never the word. The tripwire is
    coarse on purpose: it also trips on ordinary words of insurance and finance text."""
    from calibration.pack_live import row_strings
    from guardrail_engine.admin.vocabulary import strings_tripwire

    return strings_tripwire(*row_strings(row))


def send_problem(
    row: Mapping[str, Any], floor_rules: Mapping[str, Any], *, drop_tripwire: bool = False
) -> str | None:
    """Why this row may not be in the trial, or None. Fixed phrases, never content.

    The approved criteria are by label (``live_exclusion``), as for the held-out validation, which
    sent every held-out row that passed them. ``drop_tripwire`` also drops any row the coarse
    harm-vocabulary tripwire trips on, for a narrower trial."""
    if (why := live_exclusion(row)) is not None:
        return why
    if drop_tripwire and tripwire_views(row):
        return "harm-vocabulary tripwire"
    fires = row.get("fires") or []
    if any(f not in floor_rules for f in fires):
        return "labelled for a rule that isn't a floor rule"
    for key in ("id", "guard_point", "content"):
        if not isinstance(row.get(key), str):
            return f"no {key}"
    return None


def load_source(name: str, root: Path = ROOT) -> list[dict[str, Any]]:
    """A source's rows, in file order. The red-team corpus goes through its own loader, which
    refuses the whole file on any harm row."""
    path = root / SOURCES[name]
    if name == "redteam":
        from redteam.run import Refused as CorpusRefused
        from redteam.run import load_corpus

        try:
            return load_corpus(path)
        except CorpusRefused as e:
            raise Refused(f"the red-team corpus was refused: {e}") from e
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def is_positive(row: Mapping[str, Any]) -> bool:
    return bool(row.get("fires"))


def _hash_key(*parts: str) -> str:
    return hashlib.sha256(":".join(parts).encode()).hexdigest()


def _allocate(
    total: int, weights: Mapping[str, int], capacity: Mapping[str, int]
) -> dict[str, int]:
    """``total`` spread over the keys in proportion to ``weights`` (largest remainder, ties by
    key), never more than ``capacity`` at one: what a short stratum can't give goes to the others
    in the same order."""
    keys = sorted(weights)
    weight = sum(weights.values())
    if not keys or weight == 0:
        return {}
    exact = {k: total * weights[k] / weight for k in keys}
    given = {k: min(int(exact[k]), capacity.get(k, 0)) for k in keys}
    order = sorted(keys, key=lambda k: (-(exact[k] - int(exact[k])), k))
    while sum(given.values()) < total:
        gave = False
        for k in order:
            if sum(given.values()) >= total:
                break
            if given[k] < capacity.get(k, 0):
                given[k] += 1
                gave = True
        if not gave:
            break
    return given


CONFLICT = "a tool defined differently by an earlier row of the same tenant"


class _ToolDefinitions:
    """The tool definitions of the rows chosen so far, by tenant. A tenant's registry is the union
    of its rows' tools, and the engine stops a run in which one name has two definitions (never
    picking one), so a row that would add a second definition is left out here instead."""

    def __init__(self) -> None:
        self._known: dict[tuple[str, str], Any] = {}

    def conflicts(self, row: Mapping[str, Any]) -> bool:
        tenant = tenant_of(row)[0]
        return any(
            self._known.get((tenant, name), info) != info for name, info in tool_infos(row).items()
        )

    def add(self, row: Mapping[str, Any]) -> None:
        tenant = tenant_of(row)[0]
        for name, info in tool_infos(row).items():
            self._known.setdefault((tenant, name), info)


@dataclass
class Selection:
    rows: list[dict[str, Any]]
    """The rows to send, each tagged with ``source`` and ``group`` (a copy; the files are never
    changed). In manifest order: affected rows by source and id, then the placebo rows."""
    excluded: Counter[str] = field(default_factory=Counter)
    """Rows that would have been affected but may not be sent, by phrase."""


def select_rows(
    root: Path = ROOT, per_label: int = PLACEBO_PER_LABEL, *, drop_tripwire: bool = False
) -> Selection:
    """The trial's rows, deterministically from the files (:data:`PLACEBO_SEED`). The placebo
    rows are never ones the tripwire trips on: they are a free choice, so they are clean ones."""
    floor_rules = load_floor_rules(root)
    sources = {name: load_source(name, root) for name in SOURCES}
    seen: set[str] = set()
    for rows in sources.values():
        for row in rows:
            rid = str(row.get("id"))
            if rid in seen:
                raise Refused(f"{rid}: the id appears in two sources or twice")
            seen.add(rid)
    excluded: Counter[str] = Counter()
    affected: list[dict[str, Any]] = []
    candidates: list[dict[str, Any]] = []
    for name, rows in sources.items():
        for row in rows:
            kinds = pii_kinds(row) if isinstance(row.get("content"), str) else {}
            problem = send_problem(row, floor_rules, drop_tripwire=drop_tripwire)
            if problem is not None:
                if kinds:
                    excluded[problem] += 1
                continue
            tagged = {**row, "source": name}
            if kinds:
                affected.append(
                    {
                        **tagged,
                        "group": "affected_positive" if is_positive(row) else "affected_benign",
                    }
                )
            elif name in PLACEBO_SOURCES and not secret_blocked(row) and not tripwire_views(row):
                candidates.append(tagged)
    affected.sort(key=lambda r: (list(SOURCES).index(r["source"]), r["id"]))
    tools = _ToolDefinitions()
    kept: list[dict[str, Any]] = []
    for r in affected:
        if tools.conflicts(r):
            excluded[CONFLICT] += 1
        else:
            tools.add(r)
            kept.append(r)
    affected = kept
    placebo: list[dict[str, Any]] = []
    for positive in (False, True):
        mine = [r for r in affected if is_positive(r) is positive]
        weights = Counter(r["guard_point"] for r in mine)
        pool = [r for r in candidates if is_positive(r) is positive]
        by_gp: dict[str, list[dict[str, Any]]] = {}
        for r in sorted(pool, key=lambda r: _hash_key(PLACEBO_SEED, r["id"])):
            by_gp.setdefault(r["guard_point"], []).append(r)
        capacity = {gp: len(v) for gp, v in by_gp.items()}
        for gp, n in sorted(_allocate(per_label, weights, capacity).items()):
            group = "placebo_positive" if positive else "placebo_benign"
            taken = 0
            for r in by_gp.get(gp, []):
                if taken == n:
                    break
                if not tools.conflicts(r):
                    tools.add(r)
                    placebo.append({**r, "group": group})
                    taken += 1
    placebo.sort(key=lambda r: (r["group"], r["guard_point"], r["id"]))
    return Selection([*affected, *placebo], excluded)


def manifest_row(row: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "id": row["id"],
        "source": row["source"],
        "group": row["group"],
        "guard_point": row["guard_point"],
        "label": "block" if is_positive(row) else "allow",
        "fires": sorted(row.get("fires") or []),
        "pii": pii_kinds(row),
        "model_called": not secret_blocked(row),
        "tripwire": tripwire_views(row),
    }


def rows_sha256(rows: Sequence[Mapping[str, Any]]) -> str:
    return "sha256:" + hashlib.sha256(json.dumps(rows, sort_keys=True).encode()).hexdigest()


def floor_content_hash(root: Path = ROOT) -> str:
    from guardrail_engine.policy.catalog import FloorVersion

    return FloorVersion.from_document(
        dict(assemble_floor(root / RULES_REL, root / ADDITIONS_REL))
    ).content_hash()


def source_hashes(root: Path = ROOT) -> dict[str, str]:
    files = {**SOURCES, "rules": RULES_REL, "additions": ADDITIONS_REL}
    return {name: sha256_file(root / rel) for name, rel in files.items()}


def build_manifest(
    root: Path = ROOT, nonce_seed: str | None = None, *, drop_tripwire: bool = False
) -> dict[str, Any]:
    selection = select_rows(root, drop_tripwire=drop_tripwire)
    rows = [manifest_row(r) for r in selection.rows]
    matched = [
        {"id": r["id"], **m}
        for r in selection.rows
        if r["group"].startswith("affected")
        for m in pii_matches(r)
    ]
    counts = Counter(r["group"] for r in rows)
    return {
        "schema": SCHEMA,
        "trial": "M7-12 redaction, Scope B",
        "arms": list(ARMS),
        "draws": DRAWS,
        "nonce_seed": nonce_seed or new_seed(),
        "ceilings": {"provider_calls": CEILING_CALLS, "input_tokens": CEILING_INPUT_TOKENS},
        "margins": {
            "recall_points": MARGIN_RECALL_POINTS,
            "false_positive_points": MARGIN_FPR_POINTS,
        },
        "drop_tripwire": drop_tripwire,
        "files": source_hashes(root),
        "floor_content_hash": floor_content_hash(root),
        "counts": {g: counts.get(g, 0) for g in GROUPS},
        "checks": len(rows) * len(ARMS) * DRAWS,
        "affected_but_not_sendable": dict(selection.excluded),
        "rows_sha256": rows_sha256(rows),
        "rows": rows,
        "matched_values": matched,
    }


def render_manifest(manifest: Mapping[str, Any]) -> str:
    return json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def manifest_summary(manifest: Mapping[str, Any]) -> str:
    """The manifest as the user reads it: counts, ceilings, hashes, then every value and row."""
    rows, matched = manifest["rows"], manifest["matched_values"]
    arms, draws, ceil = manifest["arms"], manifest["draws"], manifest["ceilings"]
    lines = [
        "# M7-12 redaction trial: the manifest (Scope B)",
        "",
        "Nothing has been sent. This lists exactly what one approved run would send.",
        "",
        "| | |",
        "|---|---|",
        f"| Arms | {', '.join(arms)}; {draws} draws each; the same nonce in both arms |",
        f"| Checks | {manifest['checks']} ({len(rows)} rows x {len(arms)} arms x {draws} draws) |",
        f"| Ceilings | at most {ceil['provider_calls']} provider calls and "
        f"{ceil['input_tokens']:,} API input tokens |",
        f"| Nonce seed | `{manifest['nonce_seed']}` |",
        f"| Floor | floor@2, content hash `{manifest['floor_content_hash']}` |",
        f"| Row set | `{manifest['rows_sha256']}` |",
        "",
        "## Rows by group",
        "",
        "| Group | Rows |",
        "|---|---|",
        *[f"| {g} | {manifest['counts'][g]} |" for g in GROUPS],
        "",
    ]
    if manifest["affected_but_not_sendable"]:
        why = ", ".join(
            f"{k} ({v})" for k, v in sorted(manifest["affected_but_not_sendable"].items())
        )
        lines += [
            f"Rows redaction would change that are **not** in the trial, by reason: {why}.",
            "",
        ]
    tripped = sum(1 for r in rows if r["tripwire"])
    lines += [
        f"{tripped} of the {len(rows)} rows trip the harm-vocabulary tripwire (the Tripwire column "
        "names the views, never the word). It is coarse: it matches ordinary words of insurance "
        "and finance text. These rows pass the approved criteria (no harm label, not "
        "`no_live_run`, not retired) and every one was sent in the held-out validation, with no "
        "provider refusal. "
        + (
            "This manifest drops them."
            if manifest.get("drop_tripwire")
            else "`manifest --drop-tripwire` builds the narrower trial without them."
        ),
        "",
    ]
    lines += ["## File hashes the run verifies", "", "| File | sha256 |", "|---|---|"]
    lines += [f"| {k} | `{v}` |" for k, v in sorted(manifest["files"].items())]
    lines += ["", "## Values redaction replaces (every one is synthetic)", ""]
    lines += ["| Row | Where | Kind | Value |", "|---|---|---|---|"]
    lines += [f"| {m['id']} | {m['where']} | {m['kind']} | `{m['value']}` |" for m in matched]
    lines += ["", "## Rows", ""]
    lines += [
        "| Row | Source | Group | Guard point | Label | Fires | PII kinds | Model called "
        "| Tripwire |"
    ]
    lines += ["|---|---|---|---|---|---|---|---|---|"]
    for r in rows:
        kinds = ", ".join(f"{k} {n}" for k, n in r["pii"].items()) or "none"
        called = "yes" if r["model_called"] else "no (blocked first)"
        lines.append(
            f"| {r['id']} | {r['source']} | {r['group']} | {r['guard_point']} | {r['label']} | "
            f"{', '.join(r['fires']) or 'none'} | {kinds} | {called} | "
            f"{', '.join(r['tripwire']) or 'clean'} |"
        )
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------- verification


def load_manifest(path: Path) -> dict[str, Any]:
    try:
        manifest = json.loads(path.read_text())
    except (OSError, ValueError) as e:
        raise Refused(f"cannot read the manifest ({type(e).__name__})") from e
    if not isinstance(manifest, dict) or manifest.get("schema") != SCHEMA:
        raise Refused(f"the manifest's schema is not {SCHEMA}")
    return manifest


def approval_problems(
    manifest: Mapping[str, Any], rows_meta: Sequence[Mapping[str, Any]]
) -> list[str]:
    """What differs from the manifest the user approved: the row set (by its hash and by the
    group counts), the nonce seed, the margins and the number of checks."""
    found: list[str] = []
    if rows_sha256(rows_meta) != APPROVED_ROWS_SHA256:
        found.append("the row set is not the approved one")
    counts = Counter(r.get("group") for r in rows_meta)
    if {g: counts.get(g, 0) for g in GROUPS} != APPROVED_COUNTS or len(counts) != len(GROUPS):
        found.append("the groups' sizes are not the approved ones")
    if manifest.get("counts") != APPROVED_COUNTS:
        found.append("the manifest's counts are not the approved ones")
    if manifest.get("nonce_seed") != APPROVED_NONCE_SEED:
        found.append("the nonce seed is not the approved one")
    if manifest.get("margins") != {
        "recall_points": MARGIN_RECALL_POINTS,
        "false_positive_points": MARGIN_FPR_POINTS,
    }:
        found.append("the margins are not the approved ones")
    if manifest.get("checks") != APPROVED_CHECKS or manifest.get("drop_tripwire") is not False:
        found.append("the checks or the tripwire choice are not the approved ones")
    return found


def verify_manifest(manifest: Mapping[str, Any], root: Path = ROOT) -> list[dict[str, Any]]:
    """The rows the manifest names, loaded from the files and checked; or :class:`Refused`
    naming everything that doesn't hold."""
    problems: list[str] = []
    if manifest.get("arms") != list(ARMS) or manifest.get("draws") != DRAWS:
        problems.append("the arms or draws are not the ones this harness runs")
    if manifest.get("ceilings") != {
        "provider_calls": CEILING_CALLS,
        "input_tokens": CEILING_INPUT_TOKENS,
    }:
        problems.append("the ceilings are not the approved ones")
    now = source_hashes(root)
    for name, digest in sorted((manifest.get("files") or {}).items()):
        if now.get(name) != digest:
            problems.append(f"{name}: the file differs from the manifest's hash")
    if set(manifest.get("files") or {}) != set(now):
        problems.append("the manifest names a different set of files")
    if manifest.get("floor_content_hash") != floor_content_hash(root):
        problems.append("the assembled floor@2 differs from the manifest's")
    rows_meta = manifest.get("rows")
    if not isinstance(rows_meta, list) or not rows_meta:
        raise Refused("; ".join([*problems, "the manifest has no rows"]))
    if manifest.get("rows_sha256") != rows_sha256(rows_meta):
        problems.append("the manifest's row set does not match its own hash")
    problems.extend(approval_problems(manifest, rows_meta))
    floor_rules = load_floor_rules(root)
    sources = {name: {r["id"]: r for r in load_source(name, root)} for name in SOURCES}
    rows: list[dict[str, Any]] = []
    for meta in rows_meta:
        row = sources.get(meta.get("source"), {}).get(meta.get("id"))
        if row is None:
            problems.append(f"{meta.get('id')}: not in {meta.get('source')}")
            continue
        drop = bool(manifest.get("drop_tripwire"))
        if (why := send_problem(row, floor_rules, drop_tripwire=drop)) is not None:
            problems.append(f"{meta['id']}: {why}")
            continue
        tagged = {**row, "source": meta["source"], "group": meta["group"]}
        if manifest_row(tagged) != meta:
            problems.append(f"{meta['id']}: the row no longer matches its manifest entry")
            continue
        if (meta["group"].startswith("affected")) != bool(meta["pii"]):
            problems.append(f"{meta['id']}: its group and its PII disagree")
        rows.append(tagged)
    if len({r["id"] for r in rows}) != len(rows):
        problems.append("a row appears twice")
    checks = len(rows_meta) * len(ARMS) * DRAWS
    if checks > CEILING_CALLS:
        problems.append(f"the plan makes {checks} checks, over the ceiling of {CEILING_CALLS}")
    if problems:
        raise Refused("; ".join(problems) + "; nothing was sent")
    return rows


# --------------------------------------------------------------------------- the plan


def direct_setup(root: Path = ROOT) -> Any:
    return build_setup(
        root / SOURCES["heldout"], root / RULES_REL, root / ADDITIONS_REL, heldout=True
    )


def engine_setup(root: Path = ROOT) -> EngineSetup:
    """One bundle setting for every row: the held-out cap (the context of a held-out row isn't
    dropped); a smaller row is unaffected, and both arms share it."""
    return EngineSetup(
        floor_doc=assemble_floor(root / RULES_REL, root / ADDITIONS_REL),
        files=source_hashes(root),
        validation=True,
        max_input_tokens=HELDOUT_MAX_CONTENT_TOKENS,
    )


def render_arm(row: Mapping[str, Any], arm: str, nonce: str, max_content_tokens: int) -> str:
    """The input the engine renders for the row in an arm: the engine's own redaction (the PII
    detector off in ``raw``; credentials replaced in both) then its renderer."""
    from calibration.run import DEFAULT_DOMAIN, DEFAULT_TENANT, secret_detector
    from guardrail_engine.guard.pii import DEFAULT_PII_DETECTOR
    from guardrail_engine.guard.redaction import redact_request
    from guardrail_engine.guard.render import render_input

    red = redact_request(
        content=row["content"],
        conversation=context_items(row),
        tools=tool_infos(row),
        detector=NoPii() if arm == "raw" else DEFAULT_PII_DETECTOR,  # type: ignore[arg-type]
        secrets=secret_detector(),
    )
    return render_input(
        domain=row.get("domain", DEFAULT_DOMAIN),
        tenant_slug=row.get("tenant_slug", DEFAULT_TENANT[0]),
        tenant_id=row.get("tenant_id", DEFAULT_TENANT[1]),
        guard_point=row["guard_point"],
        content=red.content,
        conversation=red.conversation,
        tools=red.tools,
        max_content_tokens=max_content_tokens,
        nonce_source=lambda: nonce,
    ).text


def arm_estimates(rows: Sequence[Mapping[str, Any]], direct: Any) -> dict[str, int]:
    """API input tokens one check of each row costs: the larger of the two arms' estimates (the
    raw text can be longer or shorter than its placeholders), by the engine's own estimator with
    the floor@2 questions, as ``row_token_estimates`` does for the redacted text."""
    from calibration.run import V1_SUFFIX, fresh_nonce
    from guardrail_engine.decision.limits import estimate_question_tokens
    from guardrail_engine.policy.api_tokens import estimate_api_tokens
    from guardrail_engine.tokens import estimate_tokens

    out: dict[str, int] = {}
    for row in rows:
        gp = row["guard_point"]
        questions = {k: q for k, q in direct.questions[gp].items() if not k.endswith(V1_SUFFIX)}
        nonce = fresh_nonce(row)
        out[row["id"]] = max(
            estimate_api_tokens(
                text_tokens=estimate_tokens(
                    render_arm(row, arm, nonce, direct.max_content_tokens[gp])
                ),
                question_tokens=estimate_question_tokens(questions),
                question_count=len(questions),
            )
            for arm in ARMS
        )
    return out


def checks_in_order(
    order_seed: str, rows: Sequence[Mapping[str, Any]], draw: int
) -> list[tuple[Mapping[str, Any], str]]:
    """One draw's checks in the order they are sent: ``(row, arm)``."""
    return [
        (row, arm)
        for row in row_order(order_seed, rows, draw)
        for arm in arm_order(order_seed, row["id"], draw)
    ]


def consumer_allowances() -> Any:
    """The calibration consumer's allowances over a fresh in-process store, at the Tier 1 defaults
    a live run's engine is built with: the same code the gateway runs, for the plan to model."""
    from guardrail_engine.gateway import ConsumerAllowances, TokenRateConfig
    from guardrail_engine.gateway.token_rate import InProcessTokenRateStore

    store = InProcessTokenRateStore()
    return ConsumerAllowances(
        None,
        lambda: store,
        project=TokenRateConfig(),
        wall_clock=lambda: datetime(2026, 1, 1, tzinfo=UTC),
    )


def pace_model(sizes: Sequence[int], *, floor_s: float = LIVE_MIN_INTERVAL_S) -> dict[str, Any]:
    """How long a run of checks of these API-token ``sizes`` (in order) takes when each waits
    until the calibration consumer's allowance would admit it, by the gateway's own limiter.

    A check waits for its size raised by :data:`ADMISSION_MARGIN`, is charged, takes
    :data:`MODEL_CHECK_S`, and settles at its full size (so one larger than the bucket, which is
    charged what the bucket holds, is in debt afterwards: the run is slower, never refused). The
    charge is always the size without the margin. A run is **never refused by the model**: it
    refuses to be planned if the bucket cannot hold a request, or if a check would wait longer
    than :data:`MAX_ADMISSION_WAIT_S`."""
    from guardrail_engine.gateway.tenant_quota import QuotaRefusal

    allowances = consumer_allowances()
    consumer = USAGE_CLASS
    capacity = allowances.token_capacity(consumer)
    if capacity < 1:
        raise Refused("the calibration consumer's token allowance holds no tokens")
    clock, last_start, waits, longest = 0.0, None, 0, 0.0
    for size in sizes:
        start = clock
        if last_start is not None:
            start = max(start, last_start + floor_s)
        need = max(1, math.ceil(size * ADMISSION_MARGIN))
        wait = allowances.admission_wait(consumer, need, now=start)
        if wait > MAX_ADMISSION_WAIT_S:
            raise Refused(
                f"a check of about {size} tokens would wait {wait:.0f} s for the limiter: the "
                "calibration allowance cannot carry it"
            )
        if wait > 0:
            waits += 1
            longest = max(longest, wait)
            start += wait + ADMISSION_SLACK_S
        charge = allowances.charge(
            tenant_id="plan", tier=None, consumer=consumer, tokens=max(1, size), now=start
        )
        if isinstance(charge, QuotaRefusal):  # the model and the wait disagree
            raise Refused("the plan's own model of the limiter refused a check it had waited for")
        allowances.reconcile(charge, max(1, size), now=start + MODEL_CHECK_S)
        last_start = start
        clock = start + MODEL_CHECK_S
    return {
        "seconds": round(clock, 1),
        "waits": waits,
        "longest_wait_s": round(longest, 2),
        "bucket_tokens": capacity,
    }


def plan(
    rows: Sequence[Mapping[str, Any]], root: Path = ROOT, order_seed: str | None = None
) -> dict[str, Any]:
    direct = direct_setup(root)
    estimates = arm_estimates(rows, direct)
    checks = len(rows) * len(ARMS) * DRAWS
    seed = order_seed or "plan-order"
    sizes = [
        estimates[row["id"]]
        for draw in range(1, DRAWS + 1)
        for row, _ in checks_in_order(seed, rows, draw)
        if _calls(row)
    ]
    model = pace_model(sizes)
    over = [r["id"] for r in rows if _calls(r) and estimates[r["id"]] > model["bucket_tokens"]]
    tokens = DRAWS * len(ARMS) * sum(estimates.get(r["id"], 0) for r in rows if _calls(r))
    return {
        "rows": len(rows),
        "checks": checks,
        "model_checks": sum(_calls(r) for r in rows) * len(ARMS) * DRAWS,
        "estimated_input_tokens": tokens,
        "pacing": "each check waits until the limiter would admit its own estimate",
        "min_interval_s": LIVE_MIN_INTERVAL_S,
        "interval_s": round(model["seconds"] / max(1, len(sizes)), 3),
        "estimated_minutes": round(model["seconds"] / 60, 1),
        "bucket_tokens": model["bucket_tokens"],
        "checks_that_wait": model["waits"],
        "longest_wait_s": model["longest_wait_s"],
        "rows_larger_than_the_bucket": len(over),
        "largest_estimate": max(estimates.values(), default=0),
        "estimates": estimates,
    }


def _calls(row: Mapping[str, Any]) -> bool:
    return not secret_blocked(row)


# --------------------------------------------------------------------------- running


@dataclass
class TrialRunner(EngineRunner):
    """The engine path's runner with an arm: it switches the PII detector for the check, names the
    arm and the row's group in every record, and adds one stop rule, a 429."""

    detector: ArmDetector = field(default_factory=ArmDetector)
    arm: str = ""
    group: str = ""
    deadline: datetime | None = None
    """No check is sent at or after this time (less :data:`WINDOW_SAFETY_S`): the run stops with
    ``window_closed``. The check is made after every pacing wait, just before the send."""
    now: Callable[[], datetime] = field(default=lambda: datetime.now(UTC))

    def gate_send(self, row: Mapping[str, Any]) -> None:
        if self.deadline is None:
            return
        at = self.now()
        if at + timedelta(seconds=WINDOW_SAFETY_S) >= self.deadline:
            self.write(
                {"type": "run_stopped", "reason": "window_closed", "example_id": row["id"],
                 "deadline": self.deadline.isoformat(timespec="seconds"),
                 "at": at.isoformat(timespec="milliseconds")}
            )  # fmt: skip
            raise StopRun(
                f"the window closes at {self.deadline:%H:%M:%S}: no check starts after it; stopping"
            )

    def screen_record(self, record: Mapping[str, Any], row: Mapping[str, Any], draw: int) -> None:
        """A check the engine refused itself (no provider call) means the pacing is wrong: it is
        recorded and the run stops at once, whatever the failure rate."""
        if not locally_refused(record):
            return
        self.write(
            {"type": "run_stopped", "reason": "local_refusal", "example_id": row["id"],
             "draw": draw, "failure_reason": record["failure_reason"],
             "at": datetime.now(UTC).isoformat(timespec="milliseconds")}
        )  # fmt: skip
        raise StopRun(
            f"the engine refused {row['id']} itself ({record['failure_reason']}, no provider call):"
            " the pacing is wrong; stopping"
        )

    def counts_as_failure(self, record: Mapping[str, Any]) -> bool:
        """A check refused locally is not a provider failure: it is left out of the 20% rule
        (and, in a real run, never reaches it: :meth:`screen_record` has stopped the run)."""
        return record["outcome"] == "failed" and not locally_refused(record)

    def write(self, record: Mapping[str, Any]) -> None:
        if self.arm and record.get("type") in ("call", "run_stopped"):
            record = {**record, "arm": self.arm, "group": self.group}
        super().write(record)

    async def check_arm(self, row: Mapping[str, Any], draw: int, arm: str) -> dict[str, Any]:
        self.detector.raw = arm == "raw"
        self.arm, self.group = arm, row.get("group", "")
        record = await self.check(row, draw)
        if record.get("kind") == "rate_limited":
            self.write(
                {"type": "run_stopped", "reason": "unexpected_429", "example_id": row["id"],
                 "draw": draw, "at": datetime.now(UTC).isoformat(timespec="milliseconds")}
            )  # fmt: skip
            raise StopRun(f"a 429 on {row['id']}: the pacing should have prevented it; stopping")
        return record


def locally_refused(record: Mapping[str, Any]) -> bool:
    """A check the engine's own limiter or queue refused: failed, no provider call, one of
    :data:`LOCAL_REFUSALS`."""
    return (
        record.get("outcome") == "failed"
        and record.get("provider_calls") == 0
        and record.get("failure_reason") in LOCAL_REFUSALS
    )


def arm_order(order_seed: str, row_id: str, draw: int) -> tuple[str, str]:
    """Which arm goes first for a (row, draw): half and half, by hash, so time can't favour one."""
    first = int(_hash_key(order_seed, row_id, str(draw), "arm")[0], 16) % 2
    return ARMS if first == 0 else (ARMS[1], ARMS[0])


def row_order(
    order_seed: str, rows: Sequence[Mapping[str, Any]], draw: int
) -> list[Mapping[str, Any]]:
    """The rows in a draw's order: shuffled by hash, so groups are interleaved through the run."""
    return sorted(rows, key=lambda r: _hash_key(order_seed, str(draw), r["id"]))


async def run_trial(
    runner: TrialRunner,
    rows: Sequence[Mapping[str, Any]],
    *,
    order_seed: str,
    log: Callable[[str], None] = lambda s: print(s, file=sys.stderr),
) -> None:
    for draw in range(1, DRAWS + 1):
        for row, arm in checks_in_order(order_seed, rows, draw):
            await runner.check_arm(row, draw, arm)
        log(f"  trial: draw {draw} done ({len(rows)} rows, both arms)")


@dataclass(frozen=True)
class Args:
    manifest: Path
    out: Path
    live: bool
    deadline: datetime | None = None
    """When the window closes; a live run needs it, an offline one may have it."""
    attempt: int = 1
    """Which attempt of the manifest this is (:class:`Attempt`)."""


def state_dir() -> Path:
    """Where the one-attempt lock and marker live: outside the output directory and the
    worktree, and kept across restarts."""
    base = os.environ.get("XDG_STATE_HOME") or str(Path.home() / ".local" / "state")
    return Path(base) / "guardrails-m7-12-redaction-trial"


class Attempt:
    """One live attempt of a manifest: a lock held for the whole run, and a marker, written
    just before the first request, that stays. Both are named for the manifest's row-set hash
    (and, from attempt 2, for the attempt) and kept in :func:`state_dir`, so a second arming of
    the same attempt (into any output directory, from any worktree) is refused while one runs and
    after one has started.

    Attempt 1's files are named as they always were. Attempt 2 (:data:`MAX_ATTEMPT` is the last)
    has files of its own and is refused unless attempt 1's marker exists: it is a second
    attempt after a first, never a first by another name. Nothing here removes or bypasses a
    marker."""

    def __init__(self, directory: Path, key: str, number: int = 1) -> None:
        if (
            not isinstance(number, int)
            or isinstance(number, bool)
            or not 1 <= number <= MAX_ATTEMPT
        ):
            raise Refused(f"there are attempts 1 to {MAX_ATTEMPT}; {number!r} is not one")
        stem = key.removeprefix("sha256:")[:16]
        suffix = "" if number == 1 else f".attempt-{number}"
        self.number = number
        self.directory = directory
        self.lock_path = directory / f"{stem}{suffix}.lock"
        self.marker = directory / f"{stem}{suffix}.started"
        self.previous = (
            None
            if number == 1
            else directory / f"{stem}{'' if number == 2 else f'.attempt-{number - 1}'}.started"
        )
        self._lock: Any = None

    def acquire(self) -> None:
        """Take the lock; refuse if a run holds it or this attempt has started, or if this is a
        later attempt and the one before it never started."""
        if self.previous is not None and not self.previous.exists():
            raise Refused(
                f"attempt {self.number} follows attempt {self.number - 1}, which has not "
                "started (its marker is missing); nothing was sent"
            )
        self.directory.mkdir(parents=True, exist_ok=True)
        lock = self.lock_path.open("a")
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            lock.close()
            raise Refused("another run of this manifest is in progress; nothing was sent") from None
        self._lock = lock
        if self.marker.exists():
            self.release()
            raise Refused(
                f"attempt {self.number} of this manifest has started ({self.marker}); it is "
                "spent, and nothing was sent"
            )

    def mark(self, info: Mapping[str, Any]) -> None:
        """Write the marker, once: it names the run (no content) and is never removed here."""
        try:
            with self.marker.open("x") as fh:
                fh.write(json.dumps({**info, "attempt": self.number}, sort_keys=True) + "\n")
        except FileExistsError:
            raise Refused(
                f"attempt {self.number} of this manifest has started; nothing was sent"
            ) from None

    def release(self) -> None:
        if self._lock is not None:
            self._lock.close()
            self._lock = None


async def execute(
    args: Args,
    root: Path = ROOT,
    model_factory: Callable[[], Any] | None = None,
    sleep: Callable[[float], Any] | None = None,
    now: Callable[[], datetime] = lambda: datetime.now(UTC),
    attempts: Path | None = None,
) -> int:
    """Verify, plan, send (or, offline, ask ``model_factory()``'s fake), record. Exit code."""
    try:
        manifest = load_manifest(args.manifest)
        rows = verify_manifest(manifest, root)
        if args.out.exists() and args.out.stat().st_size:
            raise Refused(f"{args.out} exists: start a new --out file")
        if args.live and model_factory is not None:
            raise Refused("a live run takes no model override")
        if not args.live and model_factory is None:
            raise Refused("an offline run needs a model; --live is the real one")
        tool_registries(rows)
        planned = plan(rows, root, manifest["nonce_seed"])
        if args.live:
            if args.deadline is None or args.deadline.tzinfo is None:
                raise Refused("a live run needs the time its window closes (--deadline)")
            ends = now() + timedelta(minutes=planned["estimated_minutes"] + START_MARGIN_MINUTES)
            if ends >= args.deadline:
                raise Refused(
                    f"the run (about {planned['estimated_minutes']} minutes, and a margin of "
                    f"{START_MARGIN_MINUTES:.0f}) would not end before the window closes at "
                    f"{args.deadline:%H:%M}Z"
                )
            attempt: Attempt | None = Attempt(
                attempts or state_dir(), manifest["rows_sha256"], args.attempt
            )
            attempt.acquire()
        else:
            attempt = None
    except (Refused, StopRun) as e:
        print(f"refused: {e}", file=sys.stderr)
        return EXIT_REFUSED
    try:
        if planned["estimated_input_tokens"] > CEILING_INPUT_TOKENS:
            print("refused: the plan's estimated input tokens exceed the ceiling", file=sys.stderr)
            return EXIT_REFUSED
        return await _send(args, root, manifest, rows, planned, model_factory, sleep, now, attempt)
    except Refused as e:
        print(f"refused: {e}", file=sys.stderr)
        return EXIT_REFUSED
    finally:
        if attempt is not None:
            attempt.release()


async def _send(
    args: Args,
    root: Path,
    manifest: Mapping[str, Any],
    rows: Sequence[Mapping[str, Any]],
    planned: Mapping[str, Any],
    model_factory: Callable[[], Any] | None,
    sleep: Callable[[float], Any] | None,
    now: Callable[[], datetime],
    attempt: Attempt | None,
) -> int:
    nonces = SeededNonces(manifest["nonce_seed"])
    model = None if args.live else model_factory()  # type: ignore[misc]
    detector = ArmDetector()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    kwargs: dict[str, Any] = {} if sleep is None else {"sleep": sleep}
    async with calibration_engine(
        engine_setup(root), rows, model=model, nonces=nonces, pii_detector=detector
    ) as (engine, verifier):
        runner = TrialRunner(
            out=args.out,
            engine=engine,
            verifier=verifier,
            nonces=nonces,
            token_ceiling=CEILING_INPUT_TOKENS,
            token_estimates=planned["estimates"],
            provider_call_ceiling=CEILING_CALLS,
            usage_class=USAGE_CLASS,
            min_interval_s=planned["min_interval_s"] if args.live else 0.0,
            admission_wait=engine.gateway.consumer_admission_wait if args.live else None,
            admission_margin=ADMISSION_MARGIN,
            detector=detector,
            deadline=args.deadline,
            now=now,
            **kwargs,
        )
        started = now().isoformat(timespec="seconds")
        if attempt is not None:  # the attempt is spent from here, whatever happens next
            attempt.mark(
                {"started_at": started, "rows_sha256": manifest["rows_sha256"],
                 "deadline": args.deadline.isoformat() if args.deadline else None,
                 "out": str(args.out)}
            )  # fmt: skip
        runner.write(
            {"type": "run_started", "at": started,
             "harness": HARNESS, "mode": "live" if args.live else "fake",
             "environment": ENVIRONMENT, "manifest_rows_sha256": manifest["rows_sha256"],
             "files": manifest["files"], "rows": len(rows), "draws": DRAWS, "arms": list(ARMS),
             "nonce_seed": nonces.seed, "redaction": REDACTION_APPLIED,
             "token_ceiling": CEILING_INPUT_TOKENS, "provider_call_ceiling": CEILING_CALLS,
             "usage_class": USAGE_CLASS, "min_interval_s": runner.min_interval_s,
             "attempt": args.attempt, "pacing": "admission" if args.live else "none",
             "admission_margin": ADMISSION_MARGIN,
             "deadline": args.deadline.isoformat(timespec="seconds") if args.deadline else None}
        )  # fmt: skip
        try:
            await run_trial(runner, rows, order_seed=manifest["nonce_seed"])
        except (StopRun, ProviderBlockStop) as e:
            print(f"stopped: {e}", file=sys.stderr)
            return EXIT_STOPPED
        finally:
            print(f"checks made: {runner.calls}", file=sys.stderr)
        runner.arm = ""
        runner.write({"type": "run_finished", "at": now().isoformat(timespec="seconds"),
                      "checks": runner.calls, "provider_calls": runner.provider_calls_used,
                      "input_tokens": runner.tokens_used,
                      "admission_waits": runner.admission_waits,
                      "admission_wait_s": round(runner.admission_wait_s, 1)})  # fmt: skip
    return EXIT_DONE


# --------------------------------------------------------------------------- analysis


def read_records(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


@dataclass(frozen=True)
class Cell:
    """What one arm said about one row: the probabilities of each rule, per draw."""

    row_id: str
    arm: str
    draw: int
    probabilities: Mapping[str, float]


def cells_from_records(records: Sequence[Mapping[str, Any]]) -> tuple[list[Cell], Counter[str]]:
    """The answered checks as cells; and a count of what wasn't (by outcome), which analysis
    reports instead of scoring."""
    cells: list[Cell] = []
    other: Counter[str] = Counter()
    for r in records:
        if r.get("type") != "call":
            continue
        if r.get("outcome") == "answered" and r.get("arm") in ARMS:
            cells.append(Cell(r["example_id"], r["arm"], r["draw"], r.get("probabilities") or {}))
        else:
            other[str(r.get("outcome"))] += 1
    return cells, other


def _by_row(cells: Sequence[Cell]) -> dict[str, dict[str, dict[int, Mapping[str, float]]]]:
    out: dict[str, dict[str, dict[int, Mapping[str, float]]]] = {}
    for c in cells:
        out.setdefault(c.row_id, {}).setdefault(c.arm, {})[c.draw] = c.probabilities
    return out


def _rule_values(
    arm_draws: Mapping[int, Mapping[str, float]], rule: str, draws: int
) -> list[float] | None:
    """The rule's probability over all draws, or None if any draw lacks it (the cell is left
    out, never judged on fewer draws)."""
    values = [d[rule] for d in arm_draws.values() if rule in d]
    return values if len(arm_draws) == draws and len(values) == draws else None


def _caught(values: Sequence[float], block_at: float) -> bool:
    """A positive counts as caught only if every draw reaches the level."""
    return all(v >= block_at for v in values)


def _paired(pairs: Sequence[tuple[bool, bool]]) -> dict[str, Any]:
    """The paired comparison of two arms over (first, second) outcomes of the same rows.

    ``diff_points`` is the share of rows with the outcome in the first arm minus in the second,
    in points. The interval is **exact and conservative**: each side is the Clopper-Pearson upper
    bound (97.5% one-sided) on the share of rows that flipped that way, so it is the largest
    difference the flips seen can't rule out. It is never narrower than the data allow (a
    bootstrap of 0 flips in 3 rows would claim certainty)."""
    n = len(pairs)
    b = sum(1 for x, y in pairs if x and not y)
    c = sum(1 for x, y in pairs if y and not x)
    up_b, up_c = (stats.clopper_pearson(b, n), stats.clopper_pearson(c, n)) if n else (None, None)
    return {
        "first": _rate(sum(x for x, _ in pairs), n),
        "second": _rate(sum(y for _, y in pairs), n),
        "diff_points": None if not n else 100.0 * (b - c) / n,
        "diff_ci95_points": None if not n else (-100.0 * up_c[1], 100.0 * up_b[1]),  # type: ignore[index]
        "first_only": b,
        "second_only": c,
        "mcnemar": stats.mcnemar_exact(b, c),
    }


def _rate(k: int, n: int) -> dict[str, Any]:
    return {
        "k": k, "n": n, "rate": None if n == 0 else k / n,
        "ci95": stats.clopper_pearson(k, n),
    }  # fmt: skip


def analyse(
    cells: Sequence[Cell],
    rows: Sequence[Mapping[str, Any]],
    thresholds: Mapping[str, tuple[float, float]],
    *,
    draws: int = DRAWS,
    seed: int = 17,
) -> dict[str, Any]:
    """The comparison of section 3 of the design: raw against redacted, row by row.

    ``rows`` are manifest rows (``id``, ``group``, ``guard_point``, ``fires``, ``pii``).
    Probabilities are paired by row, arm and draw; a row enters a figure only if both arms
    answered every draw of it (the rest are counted as ``incomplete``)."""
    meta = {r["id"]: r for r in rows}
    per_row = _by_row([c for c in cells if c.row_id in meta])
    incomplete = [
        rid for rid in meta
        if not all(len(per_row.get(rid, {}).get(a, {})) == draws for a in ARMS)
    ]  # fmt: skip
    usable = [rid for rid in meta if rid not in incomplete]

    def values(rid: str, arm: str, rule: str) -> list[float] | None:
        return _rule_values(per_row[rid][arm], rule, draws)

    # ---- recall: positives, by the rules each is labelled with, and pooled over the rules
    recall: dict[str, Any] = {}
    flips_detail: list[dict[str, Any]] = []
    pooled: list[tuple[bool, bool]] = []
    by_gp_pairs: dict[str, list[tuple[bool, bool]]] = {}
    for rule in sorted({f for r in rows for f in r["fires"]}):
        block_at = thresholds[rule][0]
        for scope, selected in (("affected", "affected_positive"), ("placebo", "placebo_positive")):
            pairs: list[tuple[bool, bool]] = []
            for rid in usable:
                m = meta[rid]
                if m["group"] != selected or rule not in m["fires"]:
                    continue
                raw, red = values(rid, "raw", rule), values(rid, "redacted", rule)
                if raw is None or red is None:
                    continue
                pair = (_caught(raw, block_at), _caught(red, block_at))
                pairs.append(pair)
                if scope == "affected":
                    pooled.append(pair)
                    by_gp_pairs.setdefault(f"{rule}@{m['guard_point']}", []).append(pair)
                    if pair[0] and not pair[1]:  # redaction lost it
                        flips_detail.append(
                            {"rule": rule, "id": rid, "guard_point": m["guard_point"],
                             "kinds": sorted(m["pii"])}
                        )  # fmt: skip
            recall.setdefault(rule, {})[scope] = _paired(pairs)
    pooled_recall = _paired(pooled)
    by_gp = {key: _paired(pairs) for key, pairs in sorted(by_gp_pairs.items())}

    # ---- false positives: benign rows, any rule reaching block at any draw
    def blocked(rid: str, arm: str) -> bool:
        return any(
            (v := values(rid, arm, rule)) is not None and any(x >= thresholds[rule][0] for x in v)
            for rule in thresholds
        )

    fpr: dict[str, Any] = {}
    for scope, selected in (("affected", "affected_benign"), ("placebo", "placebo_benign")):
        ids = [rid for rid in usable if meta[rid]["group"] == selected]
        # first = redacted, second = raw: the "difference" is the rise redaction causes
        entry = _paired([(blocked(rid, "redacted"), blocked(rid, "raw")) for rid in ids])
        for key in ("first", "second"):
            entry[key]["upper95"] = clopper_pearson_upper(entry[key]["k"], entry[key]["n"])
        fpr[scope] = {
            "raw": entry["second"], "redacted": entry["first"],
            "rise_points": entry["diff_points"], "rise_ci95_points": entry["diff_ci95_points"],
            "flips_up_with_redaction": entry["first_only"],
            "flips_down_with_redaction": entry["second_only"],
            "mcnemar": entry["mcnemar"],
        }  # fmt: skip

    # ---- the probability shift, row by row
    def row_shift(rid: str, rules: Sequence[str]) -> float | None:
        diffs = []
        for rule in rules:
            raw, red = values(rid, "raw", rule), values(rid, "redacted", rule)
            if raw is not None and red is not None:
                diffs.append(sum(red) / len(red) - sum(raw) / len(raw))
        return sum(diffs) / len(diffs) if diffs else None

    shift: dict[str, Any] = {}
    for scope, groups in (("affected", ("affected_positive", "affected_benign")),
                          ("placebo", ("placebo_positive", "placebo_benign"))):  # fmt: skip
        labelled, every, absolute = [], [], []
        for rid in usable:
            m = meta[rid]
            if m["group"] not in groups:
                continue
            if (s := row_shift(rid, m["fires"])) is not None and m["fires"]:
                labelled.append(s)
            if (s := row_shift(rid, sorted(thresholds))) is not None:
                every.append(s)
            for rule in thresholds:
                raw, red = values(rid, "raw", rule), values(rid, "redacted", rule)
                if raw is not None and red is not None:
                    absolute.append(abs(sum(red) / len(red) - sum(raw) / len(raw)))
        shift[scope] = {
            "labelled_rows": {"n": len(labelled), "mean_change": stats.mean(labelled),
                              "ci95": stats.bootstrap_mean(labelled, seed=seed)},
            "all_rule_cells_by_row": {"n": len(every), "mean_change": stats.mean(every),
                                      "ci95": stats.bootstrap_mean(every, seed=seed)},
            "mean_abs_change_per_cell": stats.mean(absolute),
        }  # fmt: skip
    result = {
        "rows": {g: sum(1 for r in rows if r["group"] == g) for g in GROUPS},
        "usable_rows": len(usable),
        "incomplete_rows": sorted(incomplete),
        "incomplete_affected_rows": sorted(
            rid for rid in incomplete if meta[rid]["group"].startswith("affected")
        ),
        "recall": recall,
        "recall_pooled": pooled_recall,
        "recall_by_guard_point": by_gp,
        "flips_against_redaction": flips_detail,
        "false_positives": fpr,
        "probability_shift": shift,
    }
    result["verdict"] = verdict(result)
    return result


def _confirmed_loss(label: str, e: Mapping[str, Any]) -> str | None:
    """A loss of at least the margin that exact McNemar finds significant, or None."""
    loss = e["diff_points"]
    if loss is None or loss < MARGIN_RECALL_POINTS or e["mcnemar"]["one_sided"] >= SIGNIFICANCE:
        return None
    return f"{label}: loses {loss:.1f} points (one-sided p {e['mcnemar']['one_sided']:.3f})"


def verdict(result: Mapping[str, Any]) -> dict[str, Any]:
    """Which line of the design's table (section 6) the result falls on, and why.

    * **Recall.** The margin is 10 points. It is applied to the recall of all floor rules pooled
      (every (row, rule) cell of the affected positives): a rule with three positives can never
      show an interval under 10 points, so a per-rule interval can't be the test. Per rule, the
      test is the number of flips against redaction (at most 2) and, for a confirmed loss, the
      McNemar value. The interval is the exact, conservative one of :func:`_paired`.
    * **False positives.** The margin is 5 points, on the point estimate for the benign
      affected rows.
    """
    confirmed: list[str] = []
    wide: list[str] = []
    for rule, scopes in sorted(result["recall"].items()):
        e = scopes["affected"]
        if e["first"]["n"] == 0:
            continue
        if e["first_only"] > MAX_FLIPS_PER_RULE:
            wide.append(f"{rule}: {e['first_only']} flips against redaction")
        if (c := _confirmed_loss(rule, e)) is not None:
            kinds = Counter(
                k
                for f in result["flips_against_redaction"]
                if f["rule"] == rule
                for k in f["kinds"]
            )
            one_kind = bool(kinds) and max(kinds.values()) == e["first_only"]
            confirmed.append(c + ("" if one_kind else "; not concentrated in one kind"))
    for key, e in result["recall_by_guard_point"].items():
        if (c := _confirmed_loss(key, e)) is not None:
            confirmed.append(c)
    pooled = result["recall_pooled"]
    if (c := _confirmed_loss("all rules together", pooled)) is not None:
        confirmed.append(c)
    upper = (pooled["diff_ci95_points"] or (None, None))[1]
    if upper is None or upper >= MARGIN_RECALL_POINTS:
        shown = "no usable rows" if upper is None else f"{upper:.1f} points"
        wide.append(f"the loss of all rules together can't be bounded under 10 points ({shown})")
    rise = result["false_positives"]["affected"]["rise_points"] or 0.0
    if confirmed:
        line, reasons = "loss_confirmed", confirmed
    elif rise >= MARGIN_FPR_POINTS:
        line, reasons = "false_positive_rise", [f"benign false positives rise by {rise:.1f} points"]
    elif wide or result["incomplete_affected_rows"]:
        missing = result["incomplete_affected_rows"]
        line = "inconclusive"
        reasons = [*wide, *([f"{len(missing)} affected rows are incomplete"] if missing else [])]
    else:
        line = "keep_default_phase_2_may_go_ahead"
        reasons = [
            "all rules together lose less than 10 points (upper end of the interval), no rule has "
            "more than 2 flips against redaction, and the false positive rate rose by less than "
            "5 points"
        ]
    return {"line": line, "reasons": reasons}


def pct(x: float | None, digits: int = 1) -> str:
    return "n/a" if x is None else f"{100 * x:.{digits}f}%"


def num(x: float | None, spec: str = "+.1f") -> str:
    return "n/a" if x is None else format(x, spec)


def interval(ci: Sequence[float] | None, spec: str = "+.1f") -> str:
    return "n/a" if ci is None else f"[{ci[0]:{spec}}, {ci[1]:{spec}}]"


def _shift_cell(e: Mapping[str, Any]) -> str:
    return f"{e['n']}, {num(e['mean_change'], '+.4f')}, {interval(e['ci95'], '+.4f')}"


def format_report(result: Mapping[str, Any], other: Mapping[str, int] | None = None) -> str:
    lines = [
        "# M7-12 redaction trial: result",
        "",
        f"Rows {result['rows']}; usable (both arms answered every draw) {result['usable_rows']}; "
        f"incomplete {len(result['incomplete_rows'])}.",
    ]
    if other:
        lines.append(
            "Checks that did not answer: " + ", ".join(f"{k} {v}" for k, v in sorted(other.items()))
        )
    lines += [
        "",
        "## Recall at block_at, raw against redacted",
        "",
        "Positives only; a row is caught only if every draw reaches the level.",
        "",
        "| Rule | Rows | Raw | Redacted | Loss (points) | Interval | Flips against / for "
        "| One-sided McNemar | Placebo flips |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    entries = [*sorted(result["recall"].items()), ("all rules together", None)]
    for rule, scopes in entries:
        e = result["recall_pooled"] if scopes is None else scopes["affected"]
        placebo = (
            "-"
            if scopes is None
            else f"{scopes['placebo']['first_only']} / {scopes['placebo']['second_only']} "
            f"(of {scopes['placebo']['first']['n']})"
        )
        lines.append(
            f"| {rule} | {e['first']['n']} | {pct(e['first']['rate'])} | "
            f"{pct(e['second']['rate'])} | {num(e['diff_points'])} | "
            f"{interval(e['diff_ci95_points'])} | {e['first_only']} / {e['second_only']} | "
            f"{e['mcnemar']['one_sided']:.3f} | {placebo} |"
        )
    fp = result["false_positives"]
    lines += [
        "",
        "## False positives on benign rows",
        "",
        "A row counts if any rule reaches block_at in any draw.",
        "",
        "| Rows | n | Raw | Redacted | Rise (points) | Interval | Flips up / down "
        "| Upper 95% (redacted) |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for scope in ("affected", "placebo"):
        e = fp[scope]
        lines.append(
            f"| {scope} | {e['raw']['n']} | {pct(e['raw']['rate'])} | "
            f"{pct(e['redacted']['rate'])} | {num(e['rise_points'])} | "
            f"{interval(e['rise_ci95_points'])} | "
            f"{e['flips_up_with_redaction']} / {e['flips_down_with_redaction']} | "
            f"{pct(e['redacted']['upper95'])} |"
        )
    sh = result["probability_shift"]
    lines += [
        "",
        "## Shift in the model's probability (redacted minus raw)",
        "",
        "Mean over draws, then over rows. Cells are n, mean, 95% interval.",
        "",
        "| Rows | Labelled rules | All rules | Mean absolute change per cell |",
        "|---|---|---|---|",
    ]
    for scope in ("affected", "placebo"):
        lines.append(
            f"| {scope} | {_shift_cell(sh[scope]['labelled_rows'])} | "
            f"{_shift_cell(sh[scope]['all_rule_cells_by_row'])} | "
            f"{num(sh[scope]['mean_abs_change_per_cell'], '.4f')} |"
        )
    v = result["verdict"]
    lines += ["", f"## Which line of the design's table (section 6): **{v['line']}**", ""]
    lines += [f"- {r}" for r in v["reasons"]]
    if result["flips_against_redaction"]:
        lost = "; ".join(
            f"{f['id']} ({f['rule']}, {f['guard_point']}, {', '.join(f['kinds'])})"
            for f in result["flips_against_redaction"]
        )
        lines += ["", f"Rows redaction lost: {lost}"]
    return "\n".join(lines) + "\n"


def report(
    records_path: Path, manifest_path: Path, root: Path = ROOT
) -> tuple[dict[str, Any], str]:
    manifest = load_manifest(manifest_path)
    cells, other = cells_from_records(read_records(records_path))
    result = analyse(cells, manifest["rows"], load_floor_rules(root))
    return result, format_report(result, other)


# --------------------------------------------------------------------------- the command line


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    m = sub.add_parser("manifest", help="write the manifest of the rows (offline)")
    m.add_argument("--out", type=Path, required=True)
    m.add_argument("--summary", type=Path, help="also write the manifest as a readable page")
    m.add_argument("--seed", help="the nonce seed (32 hex); a fresh one by default")
    m.add_argument(
        "--drop-tripwire", action="store_true", help="drop rows the coarse tripwire trips on"
    )
    p = sub.add_parser("plan", help="what a run would do (offline)")
    p.add_argument("--manifest", type=Path, required=True)
    r = sub.add_parser("run", help="send the rows (offline with a fake, unless --live)")
    r.add_argument("--manifest", type=Path, required=True)
    r.add_argument("--out", type=Path, required=True)
    r.add_argument("--live", action="store_true", help="LIVE: only when armed and approved")
    r.add_argument(
        "--deadline", help="when the window closes (ISO time with a zone); a live run needs it"
    )
    r.add_argument(
        "--attempt", type=int, default=1,
        help=f"which attempt of the manifest this is (1 to {MAX_ATTEMPT}); 2 needs 1 started",
    )  # fmt: skip
    rep = sub.add_parser("report", help="analyse a run's records (offline)")
    rep.add_argument("records", type=Path)
    rep.add_argument("--manifest", type=Path, required=True)
    rep.add_argument("--json", type=Path, dest="json_path")
    args = parser.parse_args(argv)
    try:
        if args.command == "manifest":
            if args.out.exists():
                raise Refused(f"{args.out} exists: a manifest is written once")
            manifest = build_manifest(nonce_seed=args.seed, drop_tripwire=args.drop_tripwire)
            args.out.parent.mkdir(parents=True, exist_ok=True)
            args.out.write_text(render_manifest(manifest))
            if args.summary:
                args.summary.write_text(manifest_summary(manifest))
            print(f"wrote {args.out}: {manifest['counts']}, {manifest['checks']} checks")
            return EXIT_DONE
        if args.command == "plan":
            manifest = load_manifest(args.manifest)
            rows = verify_manifest(manifest)
            planned = plan(rows, order_seed=manifest["nonce_seed"])
            planned.pop("estimates")
            print(json.dumps(planned, indent=2))
            return EXIT_DONE
        if args.command == "run":
            if not args.live:
                print("refused: a run without --live needs a model; use the tests", file=sys.stderr)
                return EXIT_REFUSED
            try:
                deadline = datetime.fromisoformat(args.deadline) if args.deadline else None
            except ValueError:
                raise Refused("--deadline: an ISO time with a zone is needed") from None
            return asyncio.run(execute(Args(args.manifest, args.out, True, deadline, args.attempt)))
        result, text = report(args.records, args.manifest)
        if args.json_path:
            args.json_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
        print(text)
        return EXIT_DONE
    except Refused as e:
        print(f"refused: {e}", file=sys.stderr)
        return EXIT_REFUSED


if __name__ == "__main__":
    raise SystemExit(main())
