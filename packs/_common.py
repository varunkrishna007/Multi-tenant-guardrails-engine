"""Shared builder for the domain packs' golden sets (M4-08).

A pack's ``build_golden.py`` lists, for each (rule, guard point) **cell**, hand-written
templates for examples that should fire the rule and for hard negatives that look similar and
should not. Each template has two variants of its slots, so a cell of 8 + 8 templates gives 16
positives and 16 negatives. The builder expands them, numbers them, and writes
``golden.jsonl`` in the same flat schema as ``floor/golden.jsonl`` plus ``no_live_run`` (always
false: nothing here is harm-labelled, so every row may be sent to the provider for calibration).

``--check`` fails when ``golden.jsonl`` isn't what the builder produces, a row has a
harm-vocabulary word in any view (the engine's tripwire, :mod:`guardrail_engine.admin.vocabulary`),
a cell is thinner than its minimum, a row repeats, or the pack's rules and the golden set
disagree about guard points. Run: ``python3 packs/<pack>/build_golden.py [--check]``.
"""

from __future__ import annotations

import json
import sys
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from guardrail_engine.admin.vocabulary import tripwire_views  # noqa: E402


@dataclass(frozen=True)
class T:
    """A template and the two slot fillings it is expanded with."""

    text: str
    variants: tuple[dict[str, str], ...] = ({}, {})
    note: str = ""
    also: tuple[str, ...] = ()
    """Further rules this template's rows also fire (a row that meets two rules is labelled
    with both)."""
    live: bool | None = None
    """False: its rows are never sent to the provider (``no_live_run``), whatever the cell says."""
    alt: str = ""
    """A template with no slots gives one row; ``alt`` is the second wording it also gives (the
    two are separate rows with separate ids, as two slot fillings would be)."""


@dataclass
class Cell:
    rule: str
    guard_point: str
    category: str
    positives: Sequence[T]
    negatives: Sequence[T]
    prefix: str
    """Id prefix, e.g. ``ins-pay``."""
    also_fires: tuple[str, ...] = field(default=())
    live: bool = True
    """False: the cell's **firing** rows state dangerous advice or ask for help with a wrong
    (decision 2026-11-19, on the conservative side of the user's no-harmful-inputs rule):
    they are tagged ``no_live_run`` by the builder and never sent. Its near-misses stay
    sendable only if they contain no dangerous instruction and no such request."""


def _strings(value: object):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for k, v in value.items():
            yield from _strings(k)
            yield from _strings(v)
    elif isinstance(value, list | tuple):
        for v in value:
            yield from _strings(v)


def row_tripwire(row: dict) -> list[str]:
    found = set(tripwire_views(json.dumps(row, ensure_ascii=False)))
    for text in _strings(row):
        found.update(tripwire_views(text))
    return sorted(found)


def expand(cells: Sequence[Cell], tenant_slug: str, tenant_id: str) -> list[dict]:
    rows: list[dict] = []
    for cell in cells:
        for kind, templates, fires in (
            ("pos", cell.positives, [cell.rule, *cell.also_fires]),
            ("neg", cell.negatives, []),
        ):
            n = 0
            seen: set[str] = set()
            for t in templates:
                texts = [t.text.format(**variant) for variant in t.variants]
                if t.alt:
                    texts.append(t.alt)
                for content in texts:
                    if content in seen:  # a template without slots expands to one row
                        continue
                    seen.add(content)
                    n += 1
                    by_template = t.live is False and not (kind == "pos" and not cell.live)
                    withheld = (kind == "pos" and not cell.live) or t.live is False
                    rows.append(
                        {
                            "_by_template": by_template,
                            "id": f"{cell.prefix}-{kind}-{n:03d}",
                            "guard_point": cell.guard_point,
                            "category": cell.category,
                            "content": content,
                            "fires": [*fires, *t.also] if kind == "pos" else fires,
                            "notes": t.note,
                            "pair": "",
                            "tenant_slug": tenant_slug,
                            "tenant_id": tenant_id,
                            "no_live_run": withheld,
                        }
                    )
    return rows


def problems(
    rows: Sequence[dict], cells: Sequence[Cell], min_per_side: int, total_min: int
) -> list[str]:
    out: list[str] = []
    withheld_rules = {c.rule for c in cells if not c.live}
    seen_ids: set[str] = set()
    seen_content: dict[tuple[str, str], str] = {}
    for r in rows:
        if r["id"] in seen_ids:
            out.append(f"{r['id']}: duplicate id")
        seen_ids.add(r["id"])
        key = (r["guard_point"], r["content"])
        if key in seen_content:
            out.append(f"{r['id']}: same content as {seen_content[key]}")
        seen_content[key] = r["id"]
        if views := row_tripwire(r):
            out.append(f"{r['id']}: harm vocabulary in view(s) {views}")
        # exactly the rows firing a withheld rule, plus the rows a template withholds by itself
        # (``T(..., live=False)``: one template's rows, the rest of its rule stays sendable)
        expected = bool(set(r["fires"]) & withheld_rules) or r.get("_by_template", False)
        if expected != r["no_live_run"]:
            out.append(
                f"{r['id']}: no_live_run must be exactly the rows firing a withheld rule "
                f"({sorted(withheld_rules)}) and the rows of a template marked live=False"
            )
    counts = Counter((r["category"], r["guard_point"], bool(r["fires"])) for r in rows)
    for cell in cells:
        for fires in (True, False):
            n = counts[(cell.category, cell.guard_point, fires)]
            if n < min_per_side:
                label = "firing" if fires else "allow"
                out.append(
                    f"{cell.rule}@{cell.guard_point}: {n} {label} rows, needs {min_per_side}"
                )
    if len(rows) < total_min:
        out.append(f"{len(rows)} rows, needs {total_min}")
    positives = sum(1 for r in rows if r["fires"])
    if not 0.4 <= positives / max(len(rows), 1) <= 0.6:
        out.append(f"{positives}/{len(rows)} firing rows: not balanced")
    return out


def summary(rows: Sequence[dict]) -> str:
    table = Counter(
        (r["category"], r["guard_point"], "fire" if r["fires"] else "allow") for r in rows
    )
    lines = []
    for category, gp in sorted({(c, g) for c, g, _ in table}):
        lines.append(f"{category:28s} {gp:11s} fire {table[(category, gp, 'fire')]:3d}  "
                     f"allow {table[(category, gp, 'allow')]:3d}")  # fmt: skip
    return "\n".join(lines)


def main(
    pack_dir: Path,
    cells: Sequence[Cell],
    tenant: tuple[str, str],
    *,
    min_per_side: int,
    total_min: int,
    argv: Sequence[str],
) -> int:
    rows = expand(cells, *tenant)
    text = "".join(
        json.dumps({k: v for k, v in r.items() if not k.startswith("_")}, ensure_ascii=False) + "\n"
        for r in rows
    )
    issues = problems(rows, cells, min_per_side, total_min)
    target = pack_dir / "golden.jsonl"
    if "--check" in argv:
        if not target.exists() or target.read_text() != text:
            issues.append("golden.jsonl is not what build_golden.py produces: run it")
        for i in issues:
            print(i, file=sys.stderr)
        return 1 if issues else 0
    if issues:
        for i in issues:
            print(i, file=sys.stderr)
        return 1
    target.write_text(text)
    print(f"wrote {len(rows)} rows to {target}\n{summary(rows)}")
    return 0
