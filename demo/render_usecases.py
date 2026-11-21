"""Use-case cards: a finance tenant and a healthcare tenant, from real live calibration scores.

No provider call is made. Scores are the recorded Gemini Decision 1 probabilities from the
2026-11-19 08:00Z calibration runs (mean of a row's 3 draws), joined to the synthetic golden
rows by id. Verdicts apply the pack's @2 thresholds (provisional), with max_action honoured.
"""

from __future__ import annotations

import collections
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from demo import render  # noqa: E402

OUT = render.OUT
RANK = {"allow": 0, "escalate": 1, "block": 2}

TENANTS = {
    "finance": {
        "records": "calibration/results/m5-04-finance-live-3.jsonl",
        "kicker": "AI agent guardrails · a finance tenant",
        "title": "A wealth app's AI assistant, checked at every step.",
        "sub": "The tenant turns on the finance pack: plain yes/no questions Gemini answers "
        "about each message, plan, tool call and reply. Compliant answers go straight through.",
        "pairs": [
            ("fin-ret-pos-001", "fin-ret-neg-001", "Promising a return"),
            ("fin-adv-pos-001", "fin-adv-neg-001", "Personal investment advice"),
            ("fin-pay-pos-001", "fin-pay-neg-001", "Moving money without approval"),
            ("fin-scm-pos-001", "fin-scm-neg-001", "A customer who may be being scammed"),
        ],
    },
    "healthcare": {
        "records": "calibration/results/m5-04-healthcare-live-r2.jsonl",
        "kicker": "AI agent guardrails · a healthcare tenant",
        "title": "A clinic's AI assistant, kept inside safe limits.",
        "sub": "The tenant turns on the healthcare pack. The agent can explain, book and "
        "look things up; it can't diagnose, leak a patient's details or change a record on "
        "its own, and urgent symptoms go to a person.",
        "pairs": [
            ("hc-dgn-pos-001", "hc-dgn-neg-001", "Diagnosing the user"),
            ("hc-phi-pos-001", "hc-phi-neg-001", "Disclosing another patient's details"),
            ("hc-rec-pos-001", "hc-rec-neg-001", "Changing a medical record"),
            ("hc-emg-pos-001", "hc-emg-neg-001", "Urgent symptoms"),
        ],
    },
}

GP_NAME = {
    "input": "user message",
    "plan": "agent's plan",
    "tool_call": "tool call",
    "tool_result": "tool result",
    "output": "assistant reply",
}

CSS = """
.pairs { display: flex; flex-direction: column; gap: 16px; }
.pair { background: var(--card); border: 1px solid var(--line); border-radius: 18px;
  padding: 18px 24px 20px; }
.pair .head { margin-bottom: 12px; }
.pair .topic { font-size: 21px; font-weight: 700; display: block; }
.pair .where { display: block; font-size: 15.5px; color: var(--muted); margin-top: 2px; }
.pair .where b { font-weight: 600; color: var(--accent); text-transform: uppercase;
  font-size: 13px; letter-spacing: .06em; margin-right: 8px; }
.sides { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; align-items: stretch; }
.side { display: flex; flex-direction: column; gap: 10px; }
.side .txt { flex: 1; font: 16px/1.45 ui-monospace, Menlo, Consolas, monospace;
  background: var(--code); border-radius: 10px; padding: 12px 14px; overflow-wrap: anywhere; }
.side .res { display: flex; align-items: center; gap: 12px; }
.side .res .pill { font-size: 15px; }
.side .res .sc { margin-left: auto; font: 600 18px ui-monospace, Menlo, Consolas, monospace;
  color: var(--ink); }
.card { gap: 22px; }
.card .sub { font-size: 20px; }
.card h1 { font-size: 44px; text-wrap: balance; }
"""


def load(name: str, cfg: dict) -> tuple[dict, dict, dict]:
    gold = {}
    for line in (ROOT / f"packs/{name}/golden.jsonl").read_text().splitlines():
        row = json.loads(line)
        gold[row["id"]] = row
    rules = {
        r["key"]: r for r in json.loads((ROOT / f"packs/{name}/pack.v2.json").read_text())["rules"]
    }
    acc: dict[str, dict[str, list[float]]] = collections.defaultdict(
        lambda: collections.defaultdict(list)
    )
    for line in (ROOT / cfg["records"]).read_text().splitlines():
        rec = json.loads(line)
        if rec.get("type") == "call" and rec.get("outcome") == "answered":
            for key, p in (rec.get("probabilities") or {}).items():
                acc[rec["example_id"]][key].append(p)
    means = {eid: {k: sum(v) / len(v) for k, v in ps.items()} for eid, ps in acc.items()}
    return gold, rules, means


def verdict(row: dict, scores: dict, rules: dict) -> tuple[str, str, float]:
    """The strongest pack action at the row's guard point, the rule behind it, and its score."""
    best = ("allow", "", 0.0)
    for key, rule in rules.items():
        if row["guard_point"] not in rule["guard_points"] or key not in scores:
            continue
        p = scores[key]
        act = (
            "block"
            if p >= rule["block_at"]
            else "escalate"
            if p >= rule["escalate_at"]
            else "allow"
        )
        if act == "block" and rule.get("max_action") == "escalate":
            act = "escalate"
        cand = (act, key, p)
        if (RANK[act], p) > (RANK[best[0]], best[2]):
            best = cand
    return best


def question(rule: dict) -> str:
    return rule["question"]["instructions"]


def side(row: dict, scores: dict, rules: dict) -> str:
    act, _, p = verdict(row, scores, rules)
    label = "escalate to a person" if act == "escalate" else act
    return (
        f'<div class="side"><div class="txt">{render.esc(row["content"])}</div>'
        f'<div class="res"><span class="pill v-{act}">{label}</span>'
        f'<span class="sc">{p:.2f}</span></div></div>'
    )


def card(name: str, cfg: dict) -> tuple[str, list[dict]]:
    gold, rules, means = load(name, cfg)
    blocks, audit = [], []
    for bad_id, good_id, topic in cfg["pairs"]:
        bad, good = gold[bad_id], gold[good_id]
        assert not bad.get("no_live_run") and not good.get("no_live_run")
        assert bad_id in means and good_id in means, "only rows that were really sent"
        act, key, _ = verdict(bad, means[bad_id], rules)
        floor_max = max((p for k, p in means[bad_id].items() if k.startswith("p__")), default=0)
        floor_max_g = max((p for k, p in means[good_id].items() if k.startswith("p__")), default=0)
        audit.append(
            {
                "bad": bad_id,
                "good": good_id,
                "bad_verdict": act,
                "rule": key,
                "good_verdict": verdict(good, means[good_id], rules)[0],
                "floor_max_bad": round(floor_max, 3),
                "floor_max_good": round(floor_max_g, 3),
            }
        )
        blocks.append(
            f'<div class="pair"><div class="head"><span class="topic">{render.esc(topic)}</span>'
            f'<span class="where"><b>{GP_NAME[bad["guard_point"]]}</b>'
            f"“{render.esc(question(rules[key]))}”</span></div>"
            f'<div class="sides">{side(bad, means[bad_id], rules)}'
            f"{side(good, means[good_id], rules)}</div></div>"
        )
    body = (
        f'<div class="kicker">{render.esc(cfg["kicker"])}</div>'
        f"<h1>{render.esc(cfg['title'])}</h1>"
        f'<p class="sub">{render.esc(cfg["sub"])}</p>'
        f'<div class="pairs">{"".join(blocks)}</div>'
    )
    foot = (
        "Real Gemini Decision 1 scores from a live calibration run (19 Nov 2026), "
        "mean of 3 draws · "
        f"synthetic test data · {name}@2 thresholds, provisional · hand-picked examples, "
        "not an accuracy claim · the number is the strongest rule's probability"
    )
    html = (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        f"<title>{render.esc(cfg['title'])}</title><style>{render.CSS}{CSS}</style></head>"
        f"<body><main class='card'>{body}<div class='foot'>{render.esc(foot)}</div></main>"
        "</body></html>"
    )
    return html, audit


def main() -> int:
    chrome = render.find_chrome()
    if not chrome:
        print("Google Chrome or Chromium is needed for the PNGs", file=sys.stderr)
        return 1
    for i, (name, cfg) in enumerate(TENANTS.items(), start=1):
        html, audit = card(name, cfg)
        page = OUT / f"usecase-{i}-{name}.html"
        page.write_text(html)
        print(name, json.dumps(audit, indent=None))
        render.screenshot(chrome, page, OUT / f"usecase-{i}-{name}.png")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
