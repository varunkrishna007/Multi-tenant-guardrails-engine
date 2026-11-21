"""Builds floor/heldout/heldout.jsonl, the held-out validation set for the platform floor
(R7.3(c)). Deterministic: the same sources always give the same bytes.

    uv run python floor/heldout/build_heldout.py          # write heldout.jsonl
    uv run python floor/heldout/build_heldout.py --check  # fail if the file is stale

The build fails on anything inconsistent: an unknown rule, a rule labelled at a guard point
it doesn't cover, a hard negative labelled for its own rule, an adversarial positive that
isn't, a malformed context item or tool, a production example outside its size band, a
duplicate id or content, or harm text that continues past the redaction marker.

Labels follow the **staged floor@2** wording (floor/rules.json with the replacements in
floor/next/additions.json substituted, plus the staged rules) and R7's Definitions.
"""

from __future__ import annotations

import argparse
import collections
import inspect
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(HERE))

import cells  # noqa: E402
import cells2  # noqa: E402, F401  (registers tranche 2 cells)
import harm_pack  # noqa: E402
import production  # noqa: E402
import production2  # noqa: E402, F401  (registers tranche 2 production specs)
import production3  # noqa: E402, F401  (tranche 2b: replaces the moved harm rows)
import tenancy  # noqa: E402

from guardrail_engine.guard.render import render_input  # noqa: E402
from guardrail_engine.guard.request import Plan, ToolCall, ToolResult, Turn  # noqa: E402
from guardrail_engine.guard.tenants import TENANT_SLUG_PATTERN, ToolInfo  # noqa: E402
from guardrail_engine.tenant_ids import TENANT_ID_PATTERN  # noqa: E402
from guardrail_engine.tokens import estimate_tokens  # noqa: E402

OUT = HERE / "heldout.jsonl"
PACK_OUT = HERE / "harm_pack.jsonl"
GUARD_POINTS = ("input", "plan", "tool_call", "tool_result", "output")
DOMAINS = ("insurance", "energy", "finance", "healthcare", "general")
ROLES = ("user", "assistant", "system", "tool")
TECHNIQUES = {"paraphrase", "language", "obfuscation", "framing", "embedded", "split", "context"}
PLACEMENTS = {"start", "middle", "end", "field", "none", "context"}
SIZE_BANDS = {"1k": (1_000, 1_250), "4k": (4_000, 4_600), "12k": (11_000, 12_000)}
WANT_HN, WANT_ADV, WANT_PROD = 30, 8, 50  # per cell / per guard point, tranches 1 and 2
MAX_RENDERED_TOKENS = 12_288  # content + context; the harness sets max_input_tokens to this
REDACTED = "[details removed from dataset]"
FIELDS = {"id", "guard_point", "category", "content", "fires", "notes", "pair"}
OPTIONAL = {
    "domain",
    "context",
    "tools",
    "tenant_slug",
    "tenant_id",
    "tenant_dependent",
    "no_live_run",
    "retired",
}
HARM = harm_pack.PACK_HARM
DEFAULT_TENANT = ("acme-insurance", "t_1042")
SLUG = TENANT_SLUG_PATTERN  # the engine's own rules, so the set can't drift from them
TENANT_ID = TENANT_ID_PATTERN
# Names of *other* platform tenants used in this set: an example mentioning one must be
# tagged tenant_dependent, so its label is judgeable from the TENANT header.
OTHER_TENANT_MARKERS = (
    "globex",
    "oakridge",
    "northwind",
    "t_4471",
    "tenant_4471",
    "t_04471",
    "dGVuYW50XzQ0NzE",
)
CONTEXT_FIELDS = {
    "turn": {"type", "role", "text"},
    "plan": {"type", "text"},
    "tool_call": {"type", "tool", "arguments"},
    "tool_result": {"type", "tool", "result"},
}


# Rows retired after the floor@2 validation run (2026-11-17). Their labels are
# contestable, and labels are never changed after scores exist, so the rows stay in the file
# unchanged (the run's records cite them) but carry ``retired``. A retired row is never used
# again: not sent, not counted, not copied into a later tranche or the golden set. The cell
# and guard-point counts below still count them, because they describe the set as written.
RETIRED = {
    "ho-tc-prod-05": "review 33: the email.send body is internal filler, so the exfil label "
    "is contestable",
    "ho-tc-prod-42": "review 33: the email.send body is internal filler, so the exfil label "
    "is contestable",
    "ho-tc-prod-43": "review 33: the email.send body is internal filler, so the exfil label "
    "is contestable",
    "ho-tc-xt-hn-14": "review 33: an external viewer grant with no stated goal; written as an "
    "xtenant near-miss, exfil not considered",
    "ho-pl-prod-38": "review 33: vault.read then reply.send; the reply may carry the secret",
    "ho-out-prod-25": "review 33: a door code and alarm PIN; p__secret's text names digital "
    "credentials only",
}


def floor2_coverage() -> dict[str, frozenset[str]]:
    """Rule key -> guard points, for floor@2 as staged (rules.json + additions.json)."""
    base = json.loads((ROOT / "floor" / "rules.json").read_text())
    staged = json.loads((ROOT / "floor" / "next" / "additions.json").read_text())
    replaced = {r["key"]: r for r in staged.get("replacements", [])}
    rules = [replaced.get(r["key"], r) for r in base["rules"]] + staged.get("rules", [])
    return {r["key"]: frozenset(r["guard_points"]) for r in rules}


def fail(msg: str) -> None:
    sys.exit(f"build_heldout: {msg}")


def context_tokens(ex: dict) -> int:
    total = 0
    for item in ex.get("context", []):
        total += sum(estimate_tokens(str(v)) for k, v in item.items() if k != "type")
    for t in ex.get("tools", []) or []:
        total += estimate_tokens(f"{t['name']}: {t['description']}")
    return total


def validate(rows: list[dict], coverage: dict[str, frozenset[str]]) -> None:
    by_gp = {gp: {k for k, gps in coverage.items() if gp in gps} for gp in GUARD_POINTS}
    ids, contents = set(), set()
    cell_counts: collections.Counter = collections.Counter()
    for ex in rows:
        i = ex["id"]
        keys = set(ex)
        if not keys >= FIELDS or keys - FIELDS - OPTIONAL:
            fail(f"{i}: fields {sorted(keys)}")
        if i in ids:
            fail(f"duplicate id {i}")
        ids.add(i)
        gp = ex["guard_point"]
        if gp not in GUARD_POINTS:
            fail(f"{i}: unknown guard point {gp}")
        if not isinstance(ex["content"], str) or not ex["content"].strip():
            fail(f"{i}: empty content")
        if (gp, ex["content"]) in contents:
            fail(f"{i}: duplicate content")
        contents.add((gp, ex["content"]))
        fires = ex["fires"]
        if fires != sorted(set(fires)):
            fail(f"{i}: fires must be sorted and unique")
        for key in fires:
            if key not in coverage:
                fail(f"{i}: unknown rule {key}")
            if key not in by_gp[gp]:
                fail(f"{i}: {key} does not cover guard point {gp}")
        if ex["pair"] != "":
            fail(f"{i}: tranche 1 has no pairs")

        kind, *rest = ex["category"].split(":")
        if kind == "hard_negative":
            (rule,) = rest
            if rule not in by_gp[gp]:
                fail(f"{i}: {rule} does not cover {gp}")
            if rule in fires:
                fail(f"{i}: a hard negative for {rule} is labelled for it")
            cell_counts[(gp, rule, "hn")] += 1
        elif kind == "adversarial":
            rule, technique = rest
            if technique not in TECHNIQUES:
                fail(f"{i}: unknown technique {technique}")
            if rule not in fires:
                fail(f"{i}: an adversarial positive for {rule} isn't labelled for it")
            cell_counts[(gp, rule, "adv")] += 1
        elif kind == "production":
            size, placement = rest
            if size not in SIZE_BANDS or placement not in PLACEMENTS:
                fail(f"{i}: bad production category {ex['category']}")
            lo, hi = SIZE_BANDS[size]
            n = estimate_tokens(ex["content"])
            if not lo <= n <= hi:
                fail(f"{i}: {n} content tokens, outside {size} band {lo}-{hi}")
            if n + context_tokens(ex) > MAX_RENDERED_TOKENS:
                fail(f"{i}: content + context exceed {MAX_RENDERED_TOKENS} tokens")
            if placement == "none" and fires:
                fail(f"{i}: a 'none' placement is a negative")
            cell_counts[(gp, "production")] += 1
        else:
            fail(f"{i}: unknown category {ex['category']}")

        if ("tenant_slug" in ex) != ("tenant_id" in ex):
            fail(f"{i}: tenant_slug and tenant_id go together")
        if "tenant_slug" in ex and not (
            SLUG.fullmatch(ex["tenant_slug"]) and TENANT_ID.fullmatch(ex["tenant_id"])
        ):
            fail(f"{i}: bad tenant {ex['tenant_slug']!r} / {ex['tenant_id']!r}")
        if "tenant_dependent" in ex:
            if ex["tenant_dependent"] is not True:
                fail(f"{i}: tenant_dependent is either true or absent")
            if "tenant_slug" not in ex or "tenant:" not in ex["notes"]:
                fail(f"{i}: a tenant-dependent label needs tenant fields and a 'tenant:' note")
        text = ex["content"] + json.dumps(ex.get("context", []), ensure_ascii=False)
        if any(m in text for m in OTHER_TENANT_MARKERS) and not ex.get("tenant_dependent"):
            fail(f"{i}: mentions another tenant but isn't tagged tenant_dependent")
        must_skip = REDACTED in ex["content"] + json.dumps(
            ex.get("context", []), ensure_ascii=False
        )
        if "retired" in ex and (
            not isinstance(ex["retired"], str) or not ex["retired"].startswith("review ")
        ):
            fail(f"{i}: retired must name the review that retired it")
        if "no_live_run" in ex and ex["no_live_run"] is not True:
            fail(f"{i}: no_live_run is either true or absent")
        if must_skip and not ex.get("no_live_run"):
            fail(f"{i}: harm-related rows must carry no_live_run: true")
        if "domain" in ex and ex["domain"] not in DOMAINS:
            fail(f"{i}: unknown domain {ex['domain']}")
        for item in ex.get("context", []):
            t = item.get("type")
            if t not in CONTEXT_FIELDS or set(item) != CONTEXT_FIELDS[t]:
                fail(f"{i}: bad context item {item}")
            if any(not isinstance(v, str) for v in item.values()):
                fail(f"{i}: context values must be text")
            if t == "turn" and item["role"] not in ROLES:
                fail(f"{i}: bad role {item['role']}")
        names = set()
        for tool in ex.get("tools", []) or []:
            if (
                set(tool) != {"name", "description", "read_only"}
                or not tool["name"]
                or not isinstance(tool["description"], str)
                or not isinstance(tool["read_only"], bool)
            ):
                fail(f"{i}: bad tool {tool}")
            if tool["name"] in names:
                fail(f"{i}: duplicate tool {tool['name']}")
            names.add(tool["name"])

        # Harm hygiene: text never continues past the redaction marker on the same line.
        for m in re.finditer(re.escape(REDACTED), ex["content"]):
            after = ex["content"][m.end() : m.end() + 1]
            if after not in ("", "\n", '"'):
                fail(f"{i}: text continues after the redaction marker")

    for rule, gps in coverage.items():
        for gp in gps:
            if (
                cell_counts[(gp, rule, "hn")] != WANT_HN
                or cell_counts[(gp, rule, "adv")] != WANT_ADV
            ):
                fail(
                    f"cell {rule}/{gp}: want {WANT_HN} hard negatives, {WANT_ADV} adversarial; got "
                    f"{cell_counts[(gp, rule, 'hn')]} and {cell_counts[(gp, rule, 'adv')]}"
                )
    for gp in GUARD_POINTS:
        if cell_counts[(gp, "production")] != WANT_PROD:
            fail(
                f"{gp}: want {WANT_PROD} production-shaped examples, "
                f"got {cell_counts[(gp, 'production')]}"
            )


RENDER_PARAMS = inspect.signature(render_input).parameters
KINDS = {
    "turn": lambda d: Turn(role=d["role"], text=d["text"]),
    "plan": lambda d: Plan(text=d["text"]),
    "tool_call": lambda d: ToolCall(tool=d["tool"], arguments=d["arguments"]),
    "tool_result": lambda d: ToolResult(tool=d["tool"], result=d["result"]),
}


def check_renders(rows: list[dict]) -> None:
    """Every example renders with the real renderer at the documented content cap, keeping
    all of its context (README, "Rendering an example")."""
    for ex in rows:
        tenant = {}
        if "tenant_slug" in RENDER_PARAMS:  # B3 amendment: the TENANT header
            tenant = {
                "tenant_slug": ex.get("tenant_slug", DEFAULT_TENANT[0]),
                "tenant_id": ex.get("tenant_id", DEFAULT_TENANT[1]),
            }
        rendered = render_input(
            **tenant,
            domain=ex.get("domain", "insurance"),
            guard_point=ex["guard_point"],
            content=ex["content"],
            conversation=tuple(KINDS[d["type"]](d) for d in ex.get("context", [])),
            tools={t["name"]: ToolInfo(**t) for t in ex.get("tools") or []},
            max_content_tokens=MAX_RENDERED_TOKENS,
        )
        if rendered.context_items_dropped:
            fail(f"{ex['id']}: the renderer dropped {rendered.context_items_dropped} context items")


def build() -> tuple[list[dict], list[dict]]:
    """(floor rows, harm-pack rows), each sorted by id."""
    rows = [{"pair": "", **ex} for ex in [*cells.EXAMPLES, *production.build()]]
    floor, pack = harm_pack.split(rows)
    tenancy.apply(floor)
    for row in floor:  # never sent to the provider (user instruction U4)
        if REDACTED in row["content"] + json.dumps(row.get("context", []), ensure_ascii=False):
            row["no_live_run"] = True
    by_id = {row["id"]: row for row in floor}
    for row_id, reason in RETIRED.items():
        if row_id not in by_id:
            fail(f"RETIRED names {row_id}, which isn't a floor row")
        by_id[row_id]["retired"] = reason
    key = lambda r: r["id"]  # noqa: E731
    return sorted(floor, key=key), sorted(pack, key=key)


def pack_rule_guard_points() -> frozenset[str]:
    rules = json.loads((ROOT / "packs" / "responsible_ai" / "rules.json").read_text())["rules"]
    (rule,) = [r for r in rules if r["key"] == HARM]
    return frozenset(rule["guard_points"])


def validate_pack(pack: list[dict], floor: list[dict]) -> None:
    """The harm-pack rows: labelled for d__harm_facilitation only, all no_live_run."""
    gps = pack_rule_guard_points()
    floor_ids = {r["id"] for r in floor}
    seen: set[str] = set()
    for ex in pack:
        i = ex["id"]
        if i in seen or i in floor_ids:
            fail(f"{i}: duplicate id")
        seen.add(i)
        if ex["guard_point"] not in gps:
            fail(f"{i}: {HARM} doesn't cover {ex['guard_point']}")
        if ex["fires"] not in ([], [HARM]):
            fail(f"{i}: pack rows are labelled for {HARM} only")
        if ex.get("no_live_run") is not True:
            fail(f"{i}: every harm-pack row is no_live_run")
        kind, *rest = ex["category"].split(":")
        if kind in ("hard_negative", "adversarial") and rest[0] != HARM:
            fail(f"{i}: category {ex['category']}")
        if kind == "hard_negative" and ex["fires"]:
            fail(f"{i}: a hard negative labelled positive")
        if kind == "adversarial" and not ex["fires"]:
            fail(f"{i}: an adversarial row labelled negative")
        for m in re.finditer(re.escape(REDACTED), ex["content"]):
            if ex["content"][m.end() : m.end() + 1] not in ("", "\n", '"'):
                fail(f"{i}: text continues after the redaction marker")
        if ex["fires"] and ex["guard_point"] == "output" and REDACTED not in ex["content"]:
            fail(f"{i}: a harm output positive must stop at the redaction marker")


def serialise(rows: list[dict]) -> str:
    return "".join(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n" for r in rows)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true", help="fail if heldout.jsonl is stale")
    args = ap.parse_args()
    coverage = floor2_coverage()
    rows, pack = build()
    if HARM in coverage or harm_pack.FLOOR_HARM in coverage:
        fail("the staged floor@2 still has the harm rule; U5 moved it to the pack")
    validate(rows, coverage)
    validate_pack(pack, rows)
    check_renders(rows)
    outputs = {OUT: serialise(rows), PACK_OUT: serialise(pack)}
    if args.check:
        for path, text in outputs.items():
            if not path.exists() or path.read_text() != text:
                fail(f"{path.name} is stale; rebuild it")
        print("heldout.jsonl and harm_pack.jsonl are up to date")
    else:
        for path, text in outputs.items():
            path.write_text(text)
    gp = collections.Counter(r["guard_point"] for r in rows)
    kinds = collections.Counter(r["category"].split(":")[0] for r in rows)
    gate_neg = sum(1 for r in rows if not r["fires"])
    print(
        f"{len(rows)} examples; per guard point {dict(sorted(gp.items()))}; by kind {dict(kinds)}"
    )
    print(
        f"harm pack: {len(pack)} rows ({sum(bool(r['fires']) for r in pack)} positive), "
        "all no_live_run"
    )
    print(
        f"gate-level negatives {gate_neg}; positives {len(rows) - gate_neg}; "
        f"floor@1-ambiguous labels "
        f"{sum('floor@1' in r['notes'] for r in rows)}; retired {sum('retired' in r for r in rows)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
