# ruff: noqa: E501  (embedded HTML and CSS templates)
"""Renders demo/output/results-v2.json into report-v2.html and the cards 4-9.

    uv run python demo/render_v2.py         # needs Google Chrome or Chromium for the PNGs

Outputs, all in demo/output/:
    report-v2.html                          every check, with each rule's probability
    card-4-support.html / .png              people at risk get a human, not a refusal
    card-5-harm.html / .png                 what the guard does about serious harm (text only)
    card-6-bias.html / .png                 bias in decisions caught; accommodations allowed
    card-7-fairness.html / .png             counterfactual pairs: same message, same verdict?
    card-8-tenant.html / .png               customers write their own guardrails
    card-9-failure.html / .png              simulated failure: nothing slips through

Honesty (``demo/SPEC.md`` §5): every card's footer says what is real and what is shimmed. A
results file produced by a fake model is stamped SIMULATED in every footer, so a preview can
never pass for real Gemini results. No card shows a latency figure. Card 7 never claims
"unbiased"; it shows what the pairs did, and highlights any that differed.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from demo.render import bar, color, esc, show_hidden  # noqa: E402

from demo import render  # noqa: E402

OUT = render.OUT

LABEL = {
    **render.RULE_LABEL,
    "d__self_harm_risk": "Signs the person may be at risk?",
    "d__vulnerability": "Hardship, bereavement or illness?",
    "d__harassment": "Insults or demeans the customer?",
    "d__manipulation": "False urgency or guilt to push a decision?",
    "d__bias_stereotype": "Generalises about a protected group?",
    "d__bias_protected_basis": "Decides on a protected characteristic?",
    "t__fin_adv_01": "Recommends a specific financial product?",
    "t__claims_promise_01": "Promises a claim payout amount or date?",
}
GP = render.GP_LABEL

REAL = (
    "Real Gemini Decision 1 calls · synthetic inputs · provisional thresholds · "
    "hand-picked examples, not an accuracy measurement"
)
SHIMS = (
    "Pack rules loaded by the demo and the escalate-only cap applied by the demo after the "
    "check; engine support arrives in M4-10."
)
CLAIMS_BOUNDARY = (
    "Detects biased content and decisions in individual responses. It does not measure "
    "statistical fairness across decisions."
)
SUPPORT_LINE = "If this raises something for you, please reach out to a local support line."

CSS_V2 = """
.cols { display: grid; grid-template-columns: 1fr 1fr; gap: 22px; }
.col h3 { margin: 0 0 12px; font-size: 22px; }
.col.blocked h3 { color: var(--block); } .col.allowed h3 { color: var(--allow); }
.tile2 { background: var(--card); border: 1px solid var(--line); border-radius: 16px; padding: 18px 20px; margin-bottom: 14px; }
.tile2 .gpl { font: 13px ui-monospace, Menlo, Consolas, monospace; color: var(--muted); text-transform: uppercase; letter-spacing: .05em; }
.tile2 .txt { font: 16px/1.4 ui-monospace, Menlo, Consolas, monospace; margin: 8px 0 12px; display: -webkit-box; -webkit-line-clamp: 4; -webkit-box-orient: vertical; overflow: hidden; overflow-wrap: anywhere; }
.tile2 .line { display: flex; justify-content: space-between; align-items: center; gap: 12px; font-size: 16px; }
.sim { display: inline-block; font-weight: 800; letter-spacing: .08em; text-transform: uppercase; color: #fff; background: var(--esc); border-radius: 8px; padding: 6px 14px; font-size: 18px; }
.who { font-size: 20px; margin: 4px 0 10px; }
.smallrule { display: grid; grid-template-columns: 1fr 300px 70px; gap: 16px; align-items: center; padding: 8px 0; }
.smallrule .q { font-size: 19px; } .smallrule .p { font: 600 20px ui-monospace, Menlo, monospace; text-align: right; }
.col3 { display: grid; grid-template-columns: 1.1fr 1fr 1fr; gap: 18px; }
.pre { font: 14px/1.45 ui-monospace, Menlo, Consolas, monospace; background: var(--code); border-radius: 10px; padding: 14px 16px; white-space: pre-wrap; overflow-wrap: anywhere; }
table.pairs td { font-size: 15px; vertical-align: middle; }
table.pairs td .t { display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical; overflow: hidden; overflow-wrap: anywhere; }
tr.flag td { background: #ffe9bd; }
.big { font-size: 30px; font-weight: 700; }
.strike { text-decoration: line-through; color: var(--muted); }
.two { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
.card.dense { padding: 44px 72px 36px; gap: 16px; }
.dense h1 { font-size: 44px; }
.dense .sub { font-size: 20px; }
.dense .panel { padding: 18px 28px; }
.dense .mail { font-size: 19px; }
.dense .smallrule { padding: 3px 0; }
.dense .verdict { font-size: 22px; padding: 8px 18px; }
table.pairs th:last-child { white-space: nowrap; }
table.pairs th, table.pairs td { padding: 13px 14px; font-size: 17px; }
table.pairs td .t { -webkit-line-clamp: 3; }
.top2 { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
"""


def footer(payload: dict, extra: str, *, simulated: bool = False) -> str:
    """The card's footer. A fake-model results file is stamped SIMULATED everywhere."""
    if str(payload.get("model", "")).startswith("fake") and not simulated:
        return f"SIMULATED PREVIEW: results from a fake model, not Gemini. {extra}"
    return extra if simulated else f"{REAL} · {extra}"


def page(title: str, body: str, foot: str, card: bool = True, dense: bool = False) -> str:
    cls = ("card dense" if dense else "card") if card else "page"
    return (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>"
        f"<title>{esc(title)}</title><style>{render.CSS}{CSS_V2}</style></head>"
        f"<body><main class='{cls}'>{body}<div class='foot'>{esc(foot)}</div></main></body></html>"
    )


def label(key: str) -> str:
    return LABEL.get(key, key)


def pill(action: str) -> str:
    return f'<span class="pill v-{esc(action)}">{esc(action)}</span>'


def verdict_chip(action: str) -> str:
    return f'<span class="verdict v-{esc(action)}">{esc(action.upper())}</span>'


def rerun_note(p: dict) -> str:
    """What happened in the first run, when some checks were re-run once. Said on every card
    that shows a re-run check, and in the report, whatever the second attempt gave."""
    r = p.get("rerun")
    if not r:
        return ""
    return (
        f"In the first run, {r['first_run_unanswered']} of {r['first_run_checks']} checks got no answer "
        "from the model (provider timeouts or unavailability that the gateway's one retry did not clear). "
        f"They were re-run once: {r['answered']} answered"
        + (f", {r['unanswered']} still got no answer." if r["unanswered"] else ".")
    )


def rerun_tag(row: dict, inline: bool = True) -> str:
    """Marks a check that got no answer in the first run and was answered on its re-run.
    ``inline`` puts it after the verdict, with a dot; otherwise on its own line."""
    if not (row.get("rerun") and answered(row)):
        return ""
    text = "answered on a re-run"
    if inline:
        return f' <span class="note" style="font-size:13px">· {text}</span>'
    return f'<br><span class="note" style="font-size:13px">{text}</span>'


def shown_verdict(row: dict) -> str:
    """The verdict, or, when the check wasn't answered, what happened instead. An
    unanswered check is never shown as a model verdict."""
    if row["outcome"] != "answered" or not row["provider_called"]:
        return f'<span class="pill v-escalate">no answer ({esc(row["reason"])})</span>'
    return pill(row["verdict"])


def rule_lines(row: dict, only: tuple[str, ...] | None = None) -> str:
    out = []
    for r in row["rules"]:
        if only is not None and r["rule"] not in only:
            continue
        p = r["p"]
        out.append(
            f'<div class="smallrule"><div><div class="q">{esc(label(r["rule"]))}</div>'
            f'<div class="key mono" style="font-size:13px;color:var(--muted)">{esc(r["rule"])}</div></div>'
            f'{bar(p, r["action"])}<div class="p" style="color:{color(r["action"])}">'
            f"{'—' if p is None else f'{p:.2f}'}</div></div>"
        )
    return "".join(out)


def top_other(row: dict, shown: tuple[str, ...]) -> str:
    others = [r for r in row["rules"] if r["rule"] not in shown and r["p"] is not None]
    if not others:
        return ""
    top = max(others, key=lambda r: r["p"])
    return (
        f'<div class="note" style="font-size:15px">Every other rule scored at most '
        f"{top['p']:.2f} ({esc(top['rule'])}); none fired.</div>"
        if all(r["action"] == "allow" for r in others)
        else ""
    )


# --------------------------------------------------------------------------- card 4


def card_4(p: dict) -> str:
    shown = ("d__self_harm_risk", "d__vulnerability")
    panels = []
    for row in p["card4"]:
        capped = (
            '<div class="note" style="font-size:15px">The model\'s probability reached the pack '
            "rule's block level, so the rule's own cap held it at <b>escalate</b>.</div>"
            if row["capped_by_max_action"]
            else ""
        )
        panels.append(
            f'<div class="panel"><div class="label">{esc(GP[row["guard_point"]])} · '
            f'{esc(row["id"])}</div><div class="mail" style="font-size:21px">{show_hidden(row["content"])}</div>'
            f'<div style="margin:14px 0 4px">{rule_lines(row, shown)}</div>'
            f'<div style="display:flex;align-items:center;gap:16px;flex-wrap:wrap">'
            f"{verdict_chip(row['verdict']) if row['outcome'] == 'answered' else shown_verdict(row)}"
            f"{top_other(row, shown)}</div>{capped}</div>"
        )
    body = f"""
<div><div class="kicker">AI agent guardrails · people at risk</div>
<h1>When someone is struggling, the agent gets a human, not a refusal.</h1></div>
<p class="sub">Two messages signal personal risk or hardship: both <b>escalate</b> to a person. A figure of speech is left alone.
These rules can escalate but <b>never block</b>: refusing someone in crisis is the harmful outcome.</p>
{"".join(panels)}
<p class="note">{esc(SUPPORT_LINE)}</p>
"""
    return page("Guardrail demo: people at risk", body, footer(p, SHIMS), dense=True)


# --------------------------------------------------------------------------- card 5


def card_5(p: dict) -> str:
    body = """
<div><div class="kicker">AI agent guardrails · serious harm</div>
<h1>What the guard does about serious harm</h1></div>
<p class="sub">This card is text only. <b>Nothing was sent to any model for it</b>, and no recorded refusal is replayed.</p>
<div class="panel"><div class="label">1 · The provider's own filter runs first</div>
<p class="who">Requests for help to cause serious harm are refused by Google's own safety filter <b>before our rules run</b>.
The guard reports that as a block with reason <span class="mono">provider_safety</span>.</p>
<p class="note">It is final: never retryable, and the user sees a neutral message, "This request can't be processed", never "temporarily unavailable" and never a policy message.
The provider's filter can change without notice and can't be configured by tenants.</p></div>
<div class="panel"><div class="label">2 · Our own harm rule only watches</div>
<p class="who">The engine's harm rule, <span class="mono">d__harm_facilitation</span>, is <b>observe-only</b>: it is evaluated and logged, and it <b>never blocks</b>.</p>
<p class="note">Its thresholds stay provisional: with the provider filtering these requests, there is no safe way to calibrate it on live calls, so none of its examples are ever sent.</p></div>
<div class="panel"><div class="label">3 · What this demo does not do</div>
<p class="who">It sends no harmful input, for any card. Even harmless safety questions that mention harm are left out, because they share vocabulary with the requests the provider refuses.
The harm rule's question isn't loaded into this demo either.</p></div>
"""
    return page(
        "Guardrail demo: serious harm",
        body,
        footer(p, "Text only: no calls were made for this card.", simulated=True),
    )


# --------------------------------------------------------------------------- card 6


def tile(row: dict) -> str:
    fired = [r for r in row["rules"] if r["action"] != "allow"]
    top = max((r for r in row["rules"] if r["p"] is not None), key=lambda r: r["p"], default=None)
    detail = (
        f'<span class="mono" style="font-size:13px">{esc(fired[0]["rule"] if fired else top["rule"])}</span> '
        f"{(fired[0]['p'] if fired else top['p']):.2f}"
        if top
        else ""
    )
    return (
        f'<div class="tile2"><div class="gpl">{esc(GP[row["guard_point"]])}</div>'
        f'<div class="txt">{show_hidden(row["content"])}</div>'
        f'<div class="line"><span>{shown_verdict(row)}{rerun_tag(row)}</span><span class="note">{detail}</span></div></div>'
    )


def answered(row: dict) -> bool:
    return row["outcome"] == "answered" and bool(row["provider_called"])


OFFLINE_ONLY_NOTE = (
    "The blocked column is not shown on a live run: its examples are discrimination examples, "
    "which are never sent to the provider. It is run offline, against the engine's own fake "
    "model, and the tests check it."
)


def card_6_state(p: dict) -> tuple[str, str]:
    """(title, note) that say only what the results support: the spec's title when all six
    checks were answered and each landed where its label says, otherwise what happened."""
    blocked, allowed = p["card6"]["blocked"], p["card6"]["allowed"]
    rows = blocked + allowed
    if p["card6"].get("blocked_offline_only"):
        return (
            "Bias in decisions: the accommodations a person asks for are allowed.",
            OFFLINE_ONLY_NOTE,
        )
    silent = [r for r in rows if not answered(r)]
    if silent:
        return (
            "Bias in decisions: what the guard decided where the model answered.",
            f"{len(silent)} of {len(rows)} checks got no answer from the model (a provider failure, "
            "not a decision). They are shown as no answer, never as a verdict.",
        )
    wrong = [r for r in rows if r["verdict"] != r["expected"]]
    if wrong:
        return (
            "Bias in decisions: what the guard decided on six examples.",
            f"{len(wrong)} of {len(rows)} verdicts differ from the example's label.",
        )
    return "Bias in decisions, caught; accommodations, allowed.", ""


def card_6(p: dict) -> str:
    blocked = "".join(tile(r) for r in p["card6"]["blocked"])
    if p["card6"].get("blocked_offline_only"):
        blocked = '<p class="who">Offline only: see the note below.</p>'
    allowed = "".join(tile(r) for r in p["card6"]["allowed"])
    title, note = card_6_state(p)
    reran = (
        rerun_note(p)
        if any(r.get("rerun") for r in p["card6"]["blocked"] + p["card6"]["allowed"])
        else ""
    )
    note_html = "".join(f'<p class="note"><b>{esc(t)}</b></p>' for t in (note, reran) if t)
    body = f"""
<div><div class="kicker">AI agent guardrails · bias</div>
<h1>{esc(title)}</h1></div>
<p class="sub">The guard reads what an agent is about to do. Deciding by a protected characteristic is blocked.
Acting on one to give the support a person asked for is not.</p>
<div class="cols"><div class="col blocked"><h3>Blocked: decided by a characteristic</h3>{blocked}</div>
<div class="col allowed"><h3>Allowed: support asked for, or a fair factor</h3>{allowed}</div></div>
{note_html}
<div class="panel"><div class="label">What this claims, and what it doesn't</div>
<p class="who" style="margin:0">{esc(CLAIMS_BOUNDARY)}</p></div>
"""
    return page("Guardrail demo: bias in decisions", body, footer(p, SHIMS))


# --------------------------------------------------------------------------- card 7


def pair_summary(p: dict) -> tuple[int, int, int]:
    """(pairs, pairs that got the same verdict, pairs flagged). A pair with a member the model
    didn't answer counts as neither: it isn't a comparison."""
    pairs = p["card7"]
    done = [x for x in pairs if x["answered"]]
    return len(pairs), sum(x["same_verdict"] for x in done), sum(x["flagged"] for x in pairs)


def pairs_unanswered(p: dict) -> int:
    return sum(not x["answered"] for x in p["card7"])


def pair_row(x: dict) -> str:
    a, b = x["a"], x["b"]
    pa, pb = x["highest_p"]

    def fmt(v: float | None) -> str:
        return "—" if v is None else f"{v:.2f}"

    delta = "—" if x["delta_p"] is None else f"{x['delta_p']:.2f}"
    flag = " flag" if x["flagged"] else ""
    note = " ⚑" if x["flagged"] else ""
    return (
        f'<tr class="{flag.strip()}"><td class="gp">{esc(x["pair"])}<br>{esc(GP[a["guard_point"]])}</td>'
        f'<td class="c"><div class="t">{show_hidden(a["content"])}</div></td><td>{shown_verdict(a)}{rerun_tag(a, inline=False)}<br><span class="mono">{fmt(pa)}</span></td>'
        f'<td class="c"><div class="t">{show_hidden(b["content"])}</div></td><td>{shown_verdict(b)}{rerun_tag(b, inline=False)}<br><span class="mono">{fmt(pb)}</span></td>'
        f'<td class="mono"><b>{delta}</b>{note}</td></tr>'
    )


def card_7(p: dict) -> str:
    total, same, flagged = pair_summary(p)
    silent = pairs_unanswered(p)
    if flagged:
        title = "Same message, different name: did the verdict change?"
    elif silent:
        title = f"Same message, different name: same verdict on the {total - silent} pairs that got an answer."
    else:
        title = "Same message, different name: same verdict."
    summary = (
        f"{same} of {total - silent} answered pairs got the same verdict; {flagged} flagged "
        "(verdict differs, or |Δp| over 0.10)."
        + (
            f" {silent} pair{'s' if silent > 1 else ''} got no answer from the model (a provider failure) "
            "and aren't compared."
            if silent
            else ""
        )
    )
    rows = "".join(pair_row(x) for x in p["card7"])
    rerun_html = (
        f'<p class="note"><b>{esc(rerun_note(p))}</b></p>'
        if any(x["a"].get("rerun") or x["b"].get("rerun") for x in p["card7"])
        else ""
    )
    body = f"""
<div><div class="kicker">AI agent guardrails · treating people the same</div>
<h1>{esc(title)}</h1></div>
<p class="sub">Each pair differs only in a name, a sex, a dialect or a language. Highest probability on each side, and the gap between them.
Any pair whose verdicts differ, or whose gap is over 0.10, is highlighted, never hidden.</p>
<table class="pairs"><thead><tr><th>Pair</th><th>Text A</th><th>Verdict · highest p</th><th>Text B</th><th>Verdict · highest p</th><th>|Δp|</th></tr></thead>
<tbody>{rows}</tbody></table>
{rerun_html}<p class="note"><b>{esc(summary)}</b> These are {total} hand-picked pairs: they show what happened on them, not that the guard is unbiased.</p>
"""
    return page("Guardrail demo: counterfactual pairs", body, footer(p, SHIMS))


# --------------------------------------------------------------------------- card 8


def bundle_snippet(bundle: dict) -> str:
    lines = []
    for r in bundle["rules"]:
        lines += [
            f"rule  {r['id']}",
            f'  asks   "{r["question"]}"',
            f"  at     {', '.join(r['guard_points'])}",
            f"  block ≥ {r['block_at']}   escalate ≥ {r['escalate_at']}",
            "",
        ]
    return "\n".join(lines).rstrip()


def card_8(p: dict) -> str:
    c8 = p["card8"]
    counts = c8["compiled"]["guard_points"]
    rows = "".join(
        f'<tr><td class="gp">{esc(gp)}</td><td>{v["floor"]} + {v["pack"]} + {v["tenant"]}</td>'
        f'<td class="mono"><b>{v["total"]}</b> of {v["budget"]}</td></tr>'
        for gp, v in counts.items()
    )
    checks = "".join(
        f'<div class="tile2"><div class="txt">{show_hidden(r["content"])}</div>'
        f'<div class="line">{shown_verdict(r)}<span class="mono">'
        f"{next((x['p'] for x in r['rules'] if x['rule'] == 't__fin_adv_01'), 0):.2f}</span></div>"
        f'<div class="note" style="font-size:14px">{esc(label("t__fin_adv_01"))}</div></div>'
        for r in c8["samples"]
    )
    skipped = ", ".join(c8["compiled"]["not_loaded"])
    body = f"""
<div><div class="kicker">AI agent guardrails · your own rules</div>
<h1>Customers write their own guardrails.</h1></div>
<p class="sub">A tenant adds rules as plain yes/no questions, on top of the platform floor and the packs, within a fixed question budget.</p>
<div class="top2">
<div class="panel"><div class="label">The tenant's rules</div><div class="pre">{esc(bundle_snippet(c8["bundle"]))}</div></div>
<div class="panel"><div class="label">Two live checks · tenant rule <span class="mono">t__fin_adv_01</span></div>{checks}</div>
</div>
<div class="panel"><div class="label">Compiled questions per guard point · floor + pack + tenant, against the budget</div>
<table class="compact"><thead><tr><th>Guard point</th><th>Questions (floor + pack + tenant)</th><th>Total of budget</th></tr></thead><tbody>{rows}</tbody></table>
<p class="note" style="font-size:15px">Counted by the real policy compiler. The full pack has one more observe-only rule ({esc(skipped)}), not loaded here.</p></div>
"""
    return page(
        "Guardrail demo: tenant rules", body,
        footer(p, "Tenant bundle read from a file, not published through an Admin API; pack rules loaded by the demo; engine support arrives in M4-10."),
    )  # fmt: skip


# --------------------------------------------------------------------------- card 9


def card_9(p: dict) -> str:
    c = p["card9"]
    body = f"""
<div><span class="sim">Simulated failure</span>
<div class="kicker" style="margin-top:14px">AI agent guardrails · honest failure</div>
<h1>When the model can't answer, nothing slips through, and nobody is told they broke a rule.</h1></div>
<p class="sub">The engine's fake model is scripted to time out, on the call and on the one retry. No network, and not a real outage.</p>
<div class="panel"><div class="label">The check</div><div class="mail" style="font-size:21px">{esc(c["content"])}</div>
<div style="margin-top:16px;display:flex;gap:16px;align-items:center;flex-wrap:wrap">{verdict_chip(c["decision"])}
<span class="note">reason <span class="mono">{esc(c["reason"])}</span> · failure <span class="mono">{esc(c["failure_reason"] or "")}</span> · retryable <span class="mono">{str(c["retryable"]).lower()}</span> · released <span class="mono">{str(c["released"]).lower()}</span></span></div></div>
<div class="two"><div class="panel"><div class="label">What the user is shown</div><div class="big">{esc(c["user_message"])}</div></div>
<div class="panel"><div class="label">Never shown for this</div><div class="big strike">{esc(c["policy_message"])}</div></div></div>
<div class="panel"><div class="label">Block-rate alerting counts policy blocks only</div>
<p class="who" style="margin:0">Blocks: <b>{c["blocks"]}</b> · policy blocks counted: <b>{c["policy_blocks"]}</b> · model failures, tracked separately as provider health: <b>{c["model_failures"]}</b></p>
<p class="note" style="font-size:14px">Block-rate alerting arrives in M4-04; the demo applies its counting rule to this one check.</p></div>
"""
    return page(
        "Guardrail demo: simulated failure", body,
        footer(p, "Simulated failure: the engine's own fake model scripted to time out. No Gemini call, no network. Messages from the Guard SDK.", simulated=True),
    )  # fmt: skip


# --------------------------------------------------------------------------- report


def detail(row: dict) -> str:
    return (
        f'<div class="panel" style="margin:14px 0"><div class="label">{esc(row["source"])}:{esc(row["id"])} · '
        f"{esc(GP[row['guard_point']])} · {esc(row['category'])} · label {pill(row['expected'])} · verdict {shown_verdict(row)}{rerun_tag(row)}"
        f"{' · capped by max_action (engine said ' + esc(row['engine_decision']) + ')' if row['capped_by_max_action'] else ''}"
        f'</div><div class="mail" style="font-size:15px">{show_hidden(row["content"])}</div>'
        f'<div style="margin-top:10px">{rule_lines(row)}</div></div>'
    )


def all_rows(p: dict) -> list[dict]:
    rows = list(p["card4"]) + p["card6"]["blocked"] + p["card6"]["allowed"] + p["card8"]["samples"]
    for x in p["card7"]:
        rows += [x["a"], x["b"]]
    return rows


def report(p: dict) -> str:
    rows = all_rows(p)
    shims = "".join(
        f"<li><b>{esc(k.replace('_', ' '))}:</b> {esc(v)}</li>" for k, v in p["shims"].items()
    )
    bad = p["not_answered"]
    unanswered = (
        f'<p class="note"><b>Checks without a model answer:</b> {", ".join(esc(i) for i in bad)}. '
        "They are listed here and never shown as verdicts.</p>"
        if bad
        else '<p class="note">Every check was answered by the model, with a provider call.</p>'
    )
    total, same, flagged = pair_summary(p)
    silent = pairs_unanswered(p)
    rerun_report = f'<p class="note"><b>{esc(rerun_note(p))}</b></p>' if p.get("rerun") else ""
    body = f"""
<div class="kicker">Guardrail engine on Gemini Decision 1 · demo v2 report</div>
<h1>Ethics, bias, tenant rules and honest failure</h1>
<p class="sub">Run {esc(p["run_at"])} · model <span class="mono">{esc(p["model"])}</span> · floor v{p["floor_version"]} · pack <span class="mono">{esc(p["pack"])}</span>
· {esc(p["engine"])} · {esc(p["pacing"])} · in-flight limit {p["max_in_flight_per_key"]}.</p>
<h2>What is real here, and what is shimmed</h2>
<ul class="note"><li><b>Real:</b> every verdict on cards 4 to 8 comes from the engine's <span class="mono">check()</span> on an engine built by <span class="mono">build_engine</span>: policy compiler, Guard Service, gateway and a live Gemini Decision 1 call. Card 5 is text only; no call was made for it.</li>
<li><b>Synthetic:</b> every input is from the golden sets or written for the demo, and all of it is invented.</li>
<li><b>Redaction:</b> {esc(render.redaction_note(rows))}</li>
<li><b>Provisional:</b> thresholds are placeholders until calibration.</li>
{shims}
<li><b>Not loaded:</b> {esc(", ".join(p["pack_rules_not_loaded"]))} (observe-only; harm vocabulary; see card 5).</li>
<li><b>Not a benchmark:</b> {len(rows)} hand-picked checks say nothing about accuracy. No latency figures are shown anywhere.</li></ul>
<h2>Bias claims boundary</h2><p class="note">{esc(CLAIMS_BOUNDARY)}</p>
<h2>Counterfactual pairs</h2><p class="note">{same} of {total - silent} answered pairs got the same verdict; {flagged} flagged; {silent} pair(s) got no model answer and aren't compared. These are hand-picked pairs, not a measure of fairness.</p>
{unanswered}
{rerun_report}
<h2>Every check, every rule</h2>{"".join(detail(r) for r in rows)}
"""
    return page(
        "Guardrail demo v2 report", body, footer(p, "See above for what is shimmed."), card=False
    )


# --------------------------------------------------------------------------- main


def pages(p: dict) -> dict[str, str]:
    return {
        "report-v2.html": report(p),
        "card-4-support.html": card_4(p),
        "card-5-harm.html": card_5(p),
        "card-6-bias.html": card_6(p),
        "card-7-fairness.html": card_7(p),
        "card-8-tenant.html": card_8(p),
        "card-9-failure.html": card_9(p),
    }


def main() -> int:
    src = OUT / "results-v2.json"
    if not src.exists():
        print(f"{src} not found: run demo/run_demo_v2.py --live first", file=sys.stderr)
        return 2
    data = json.loads(src.read_text())
    out: dict[str, Any] = pages(data)
    for name, text in out.items():
        (OUT / name).write_text(text, encoding="utf-8")
        print(f"wrote {OUT / name}")
    chrome = render.find_chrome()
    if not chrome:
        print("no Chrome or Chromium found; skipping PNGs", file=sys.stderr)
        return 0
    for name in out:
        if name.startswith("card-"):
            png = OUT / name.replace(".html", ".png")
            render.screenshot(chrome, OUT / name, png)
            print(f"wrote {png}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
