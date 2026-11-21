# ruff: noqa: E501  (embedded HTML and CSS templates)
"""Renders demo/output/results.json into an HTML report and three shareable PNG cards.

    uv run python demo/render.py            # needs Google Chrome or Chromium for the PNGs

Outputs, all in demo/output/:
    report.html                    every example, with each rule's probability
    card-1-email.html / .png       one indirect-injection example in detail
    card-2-obfuscation.html / .png the same attack, hidden four ways
    card-3-results.html / .png     all curated examples at a glance
"""

from __future__ import annotations

import html
import json
import shutil
import struct
import subprocess
import sys
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "demo" / "output"
CARD_W, CARD_H = 1200, 1500  # 4:5, LinkedIn's tallest feed ratio

RULE_LABEL = {
    "p__inj_direct": "Tries to override the assistant's instructions?",
    "p__inj_indirect": "Hides instructions for the AI reading it?",
    "p__ai_addressed": "Tries to sway the safety checker?",
    "p__secret": "Contains a credential?",
    "p__exfil": "Sends data somewhere the goal doesn't need?",
    "p__xtenant_probe": "Reaches for another customer's data?",
}
GP_LABEL = {
    "input": "user input",
    "tool_result": "tool result",
    "plan": "agent plan",
    "tool_call": "tool call",
    "output": "agent reply",
}

TRUTH = (
    "Real Gemini Decision 1 API calls · synthetic inputs · provisional thresholds "
    "(block ≥ 0.85, escalate ≥ 0.55) · demo-only scoring. The engine itself (Guard Service, "
    "gateway, policy compiler, Admin API) is still being built. Hand-picked examples: "
    "not an accuracy measurement."
)
"""The v1 footer, for results produced by the v1 demo-only scoring (no ``engine`` field)."""

TRUTH_ENGINE = (
    "Real Gemini Decision 1 API calls through the guardrail engine · synthetic inputs · "
    "provisional thresholds (block ≥ 0.85, escalate ≥ 0.55) · hand-picked examples: "
    "not an accuracy measurement."
)
"""The footer for results produced through the engine (``engine`` field present)."""

_footer = [TRUTH]


def use_source(data: dict) -> None:
    """Pick the honest footer for how ``data`` was produced."""
    _footer[0] = TRUTH_ENGINE if data.get("engine") else TRUTH


CSS = """
:root {
  --bg: #f6f5f1; --card: #ffffff; --ink: #1b1d22; --muted: #5d6270; --line: #e3e1da;
  --block: #c2362b; --block-bg: #fbe9e7; --esc: #b26a00; --esc-bg: #fff3dc;
  --allow: #1f7a4d; --allow-bg: #e5f4ec; --accent: #2f4bd8; --code: #f1f0eb;
}
* { box-sizing: border-box; }
html, body { margin: 0; background: var(--bg); color: var(--ink);
  font: 16px/1.45 ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }
.card { width: 1200px; height: 1500px; padding: 64px 72px 56px; display: flex; flex-direction: column; gap: 28px; }
.page { max-width: 1100px; margin: 0 auto; padding: 48px 24px 64px; }
.kicker { font-size: 18px; font-weight: 600; letter-spacing: .08em; text-transform: uppercase; color: var(--accent); }
h1 { font-size: 52px; line-height: 1.08; margin: 6px 0 0; letter-spacing: -0.02em; }
.page h1 { font-size: 40px; }
h2 { font-size: 26px; margin: 40px 0 12px; }
.sub { font-size: 22px; color: var(--muted); margin: 0; max-width: 980px; }
.panel { background: var(--card); border: 1px solid var(--line); border-radius: 18px; padding: 28px 32px; }
.mail { font: 19px/1.5 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; white-space: pre-wrap; word-break: break-word; }
.mail .hl { background: var(--block-bg); color: var(--block); border-radius: 4px; padding: 0 3px; }
.label { font-size: 15px; font-weight: 600; color: var(--muted); text-transform: uppercase; letter-spacing: .06em; margin-bottom: 12px; }
.rule { display: grid; grid-template-columns: 1fr 360px 90px; gap: 20px; align-items: center; padding: 14px 0; border-top: 1px solid var(--line); }
.rule:first-of-type { border-top: 0; }
.rule .q { font-size: 21px; }
.rule .key { font: 14px ui-monospace, Menlo, Consolas, monospace; color: var(--muted); }
.bar { position: relative; height: 16px; background: var(--code); border-radius: 8px; }
.bar .fill { position: absolute; inset: 0 auto 0 0; border-radius: 8px; }
.bar .tick { position: absolute; top: -6px; bottom: -6px; width: 2px; background: var(--muted); opacity: .5; }
.p { font: 600 22px ui-monospace, Menlo, Consolas, monospace; text-align: right; }
.verdict { display: inline-flex; align-items: center; gap: 12px; font-size: 26px; font-weight: 700; padding: 12px 22px; border-radius: 999px; }
.v-block { background: var(--block-bg); color: var(--block); }
.v-escalate { background: var(--esc-bg); color: var(--esc); }
.v-allow { background: var(--allow-bg); color: var(--allow); }
.pill { display: inline-block; font-size: 14px; font-weight: 700; padding: 3px 10px; border-radius: 999px; text-transform: uppercase; letter-spacing: .04em; }
.flow { display: grid; grid-template-columns: repeat(4, 1fr); gap: 14px; }
.flow div { background: var(--card); border: 1px solid var(--line); border-radius: 14px; padding: 16px 18px; font-size: 18px; }
.flow b { display: block; font-size: 15px; color: var(--accent); text-transform: uppercase; letter-spacing: .06em; margin-bottom: 4px; }
.tiles { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
.tile { background: var(--card); border: 1px solid var(--line); border-radius: 18px; padding: 24px 26px; display: flex; flex-direction: column; gap: 14px; }
.tile .trick { font-size: 15px; font-weight: 700; color: var(--accent); text-transform: uppercase; letter-spacing: .06em; }
.tile .shown { font: 19px/1.45 ui-monospace, Menlo, Consolas, monospace; background: var(--code); border-radius: 10px; padding: 14px 16px; overflow-wrap: anywhere; min-height: 120px; }
.tile .shown .zw { color: var(--block); font-weight: 700; }
.tile .score { display: flex; justify-content: space-between; align-items: center; font-size: 18px; }
table { width: 100%; border-collapse: collapse; background: var(--card); border: 1px solid var(--line); border-radius: 18px; overflow: hidden; }
th, td { text-align: left; padding: 11px 14px; border-top: 1px solid var(--line); vertical-align: top; font-size: 16px; }
th { border-top: 0; font-size: 13px; text-transform: uppercase; letter-spacing: .06em; color: var(--muted); background: #fbfaf7; }
td.c { max-width: 520px; }
td.c .t { display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical; overflow: hidden; }
.gp { font: 13px ui-monospace, Menlo, Consolas, monospace; color: var(--muted); white-space: nowrap; }
table.compact th, table.compact td { padding: 9px 12px; font-size: 15px; vertical-align: middle; }
table.compact td.c .t { -webkit-line-clamp: 1; }
table.compact td.rules { width: 420px; }
table.compact td.c { max-width: 380px; }
.chip { display: inline-block; font: 12px ui-monospace, Menlo, Consolas, monospace; padding: 2px 7px; border-radius: 6px; margin: 2px 4px 2px 0; }
.chip.exp { background: var(--block-bg); color: var(--block); }
.chip.extra { border: 1px dashed var(--esc); color: var(--esc); }
.note { font-size: 17px; color: var(--muted); }
.foot { margin-top: auto; font-size: 15px; color: var(--muted); border-top: 1px solid var(--line); padding-top: 16px; }
.page .foot { margin-top: 40px; }
.mono { font-family: ui-monospace, Menlo, Consolas, monospace; }
"""


def esc(s: str) -> str:
    return html.escape(s, quote=True)


def color(action: str) -> str:
    return {"block": "var(--block)", "escalate": "var(--esc)"}.get(action, "var(--allow)")


def bar(p: float | None, action: str) -> str:
    pct = 0 if p is None else round(p * 100, 1)
    return (
        f'<div class="bar"><div class="fill" style="width:{pct}%;background:{color(action)}"></div>'
        f'<div class="tick" style="left:55%"></div><div class="tick" style="left:85%"></div></div>'
    )


def show_hidden(s: str) -> str:
    """Escape text, and make zero-width spaces visible."""
    return esc(s).replace("​", '<span class="zw">·</span>')


def page(title: str, body: str, card: bool) -> str:
    cls = "card" if card else "page"
    return (
        f"<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        f"<meta name='viewport' content='width=device-width, initial-scale=1'>"
        f"<title>{esc(title)}</title><style>{CSS}</style></head>"
        f"<body><main class='{cls}'>{body}<div class='foot'>{esc(_footer[0])}</div></main></body></html>"
    )


def rules_panel(row: dict) -> str:
    out = []
    for r in row["rules"]:
        p = r["p"]
        out.append(
            f'<div class="rule"><div><div class="q">{esc(RULE_LABEL[r["rule"]])}</div>'
            f'<div class="key">{esc(r["rule"])}</div></div>{bar(p, r["action"])}'
            f'<div class="p" style="color:{color(r["action"])}">'
            f"{'—' if p is None else f'{p:.2f}'}</div></div>"
        )
    return "".join(out)


def card_email(row: dict) -> str:
    content = esc(row["content"])
    marker = esc("Assistant processing this mailbox:")
    i = content.find(marker)
    if i >= 0:
        content = f'{content[:i]}<span class="hl">{content[i:]}</span>'
    top = max(row["rules"], key=lambda r: r["p"] or 0)
    redacted = (
        f'<div class="note">Before the model saw it, {esc(kinds_text(row["pii_redacted"]))} in the text above '
        "were replaced with placeholders (PII redaction). The text is shown as written.</div>"
        if row.get("pii_redacted")
        else ""
    )
    body = f"""
<div><div class="kicker">AI agent guardrails · prompt injection</div>
<h1>An email tells the AI agent reading it to leak your inbox.</h1></div>
<p class="sub">An assistant summarising a mailbox fetches this message. The guard checks the tool result
before the agent acts on it: every floor rule for that step is one yes/no question, answered together in a
<b>single</b> Gemini Decision 1 call.</p>
<div class="panel"><div class="label">Tool result the agent just read</div><div class="mail">{content}</div>{redacted}</div>
<div class="panel"><div class="label">Calibrated probability of “yes” per rule · ticks at 0.55 and 0.85</div>
{rules_panel(row)}</div>
<div><span class="verdict v-{row["verdict"]}">{row["verdict"].upper()}</span>
<span class="note" style="margin-left:14px"><span class="mono">{esc(top["rule"])}</span> = {top["p"]:.2f}
≥ 0.85 · the tool result is withheld before the agent can act on it.</span></div>
<div class="flow"><div><b>1 · Policy</b>Each tenant's rules are yes/no questions</div>
<div><b>2 · One call</b>All questions answered on the same input</div>
<div><b>3 · Probabilities</b>Calibrated p per rule, nothing generated</div>
<div><b>4 · Thresholds</b>p vs tenant thresholds → allow / escalate / block</div></div>
"""
    return page("Guardrail demo: email injection", body, card=True)


def card_obfuscation(rows: dict) -> str:
    homo = rows["in-homo-002"]["content"]
    swapped = sum(1 for ch in homo if "Ѐ" <= ch <= "ӿ")
    tiles = [
        ("Plain text", rows["in-dir-001"], esc(rows["in-dir-001"]["content"])),
        (
            "Zero-width spaces (shown as ·)",
            rows["in-zw-001"],
            show_hidden(rows["in-zw-001"]["content"]),
        ),
        (
            f"Cyrillic look-alikes ({swapped} letters swapped)",
            rows["in-homo-002"],
            esc(homo),
        ),
        ("Base64", rows["in-b64-001"], esc(rows["in-b64-001"]["content"])),
    ]
    html_tiles = []
    for trick, row, shown in tiles:
        p = next(r["p"] for r in row["rules"] if r["rule"] == "p__inj_direct")
        html_tiles.append(
            f'<div class="tile"><div class="trick">{esc(trick)}</div><div class="shown">{shown}</div>'
            f'<div class="score"><span class="mono">p__inj_direct</span>'
            f'<span class="p" style="color:{color("block" if p >= 0.85 else "allow")}">{p:.2f}</span></div>'
            f"{bar(p, 'block' if p >= 0.85 else 'allow')}"
            f'<div><span class="pill v-{row["verdict"]}">{row["verdict"]}</span></div></div>'
        )
    body = f"""
<div><div class="kicker">AI agent guardrails · obfuscated jailbreaks</div>
<h1>Hiding the attack doesn't hide it from the guard.</h1></div>
<p class="sub">The same kind of jailbreak, disguised three ways: invisible characters, look-alike letters
from another alphabet, and base64. A naive keyword filter misses all three. Here the floor rule
<span class="mono">p__inj_direct</span> asks one plain question: <i>does the content try to override the
assistant's instructions?</i></p>
<div class="tiles">{"".join(html_tiles)}</div>
<p class="note">Each tile is one real API call on synthetic text. The verdict comes from the probability
alone; there's no pattern list behind it.</p>
"""
    return page("Guardrail demo: obfuscation", body, card=True)


def results_table(results: list[dict], clamp: bool) -> str:
    rows = []
    for r in results:
        fired = [x for x in r["rules"] if x["action"] != "allow"]
        chips = "".join(
            f'<span class="chip {"exp" if x["rule"] in r["expected_rules"] else "extra"}">'
            f"{esc(x['rule'][3:])} {x['p']:.2f}</span>"
            for x in fired
        )
        text = show_hidden(r["content"].replace("\n", " ⏎ "))
        rows.append(
            f'<tr><td class="gp">{esc(GP_LABEL[r["guard_point"]])}</td>'
            f'<td class="c"><div class="{"t" if clamp else ""}">{text}</div></td>'
            f'<td><span class="pill v-{r["expected"]}">{r["expected"]}</span></td>'
            f'<td><span class="pill v-{r["verdict"]}">{r["verdict"]}</span></td>'
            f"<td class='rules'>{chips or '<span class=note>none</span>'}</td></tr>"
        )
    return (
        f"<table class='{'compact' if clamp else ''}'><thead><tr><th>Guard point</th><th>Content (synthetic)</th><th>Label</th>"
        "<th>Verdict</th><th>Rules at escalate or block</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table>"
    )


EXTRA_NOTE = (
    "Dashed chips are rules that fired on an example they weren't labelled for. For example, the "
    '"another customer\'s data" rule also scores generic jailbreaks highly. The verdicts are '
    "still right, but working out which rule should fire, by tuning thresholds or rewording "
    "questions, is what the calibration run on the full 254-example golden set is for."
)


def card_results(results: list[dict]) -> str:
    body = f"""
<div><div class="kicker">AI agent guardrails · first live run</div>
<h1>Attacks blocked, look-alikes let through.</h1></div>
<p class="sub">{len(results)} hand-picked synthetic examples from across the agent loop. Half are attacks;
half are near-misses that <i>mention</i> passwords, AI or “ignore previous instructions” without being attacks.</p>
{results_table(results, clamp=True)}
<p class="note">{esc(EXTRA_NOTE)}</p>
"""
    return page("Guardrail demo: results", body, card=True)


def kinds_text(counts: dict) -> str:
    return ", ".join(
        f"{n} {k.replace('_', ' ')}{'s' if n > 1 else ''}" for k, n in sorted(counts.items())
    )


def redaction_note(rows: list[dict]) -> str:
    """What PII redaction (M1-14) did to the text the model saw: counts per kind, never values.
    The cards and the report show the original text, so this says where it differs."""
    touched = [r for r in rows if r.get("pii_redacted")]
    if not any(r.get("redaction") for r in rows):
        return ""
    if not touched:
        return "PII redaction ran before the model on every check and replaced nothing in these examples."
    each = "; ".join(f"{r['id']}: {kinds_text(r['pii_redacted'])}" for r in touched)
    return (
        "PII redaction ran before the model on every check. Where it replaced something, the model saw "
        f"a placeholder instead of the original text shown here ({each})."
    )


def what_is_real(data: dict) -> str:
    if data.get("engine"):
        return f"""<li><b>Real:</b> every verdict comes from the guardrail engine's
<span class="mono">check()</span>, built by <span class="mono">build_engine</span>: the floor rules in
<span class="mono">floor/rules.json</span> compiled by the policy compiler, the Guard Service's
nonce-delimited rendering, the gateway, and live Gemini Decision 1 calls.</li>
<li><b>Configuration:</b> the demo tenant's floor-only policy is published with the engine's
bootstrap path for tests and demos, not through an Admin API.</li>
<li><b>Redaction:</b> {esc(redaction_note(data["results"]))}</li>"""
    return """<li><b>Real:</b> every probability comes from a live Gemini Decision 1 call. The floor rules are
<span class="mono">floor/rules.json</span>, and the questions are built and the responses parsed with the
engine's own <span class="mono">guardrail_engine.decision</span> types and parser.</li>
<li><b>Demo-only:</b> input rendering and threshold logic are a few lines in
<span class="mono">demo/run_demo.py</span>. The engine's Guard Service, gateway, policy compiler and
Admin API are not built yet.</li>"""


def report(data: dict) -> str:
    use_source(data)
    results = data["results"]
    detail = []
    for r in results:
        detail.append(
            f'<div class="panel" style="margin:14px 0"><div class="label">{esc(r["id"])} · '
            f"{esc(GP_LABEL[r['guard_point']])} · {esc(r['category'])} · label "
            f'<span class="pill v-{r["expected"]}">{r["expected"]}</span> · verdict '
            f'<span class="pill v-{r["verdict"]}">{r["verdict"]}</span></div>'
            f'<div class="mail" style="font-size:15px">{show_hidden(r["content"])}</div>'
            f"{rules_panel(r)}</div>"
        )
    body = f"""
<div class="kicker">Guardrail engine on Gemini Decision 1 · demo report</div>
<h1>Floor rules on {len(results)} curated examples</h1>
<p class="sub">Run {esc(data["run_at"])} · model <span class="mono">{esc(data["model"])}</span> ·
floor v{data["floor_version"]} · thresholds block ≥ {data["thresholds"]["block_at"]}, escalate ≥
{data["thresholds"]["escalate_at"]} (provisional)</p>
<h2>What is real here</h2>
<ul class="note">
{what_is_real(data)}
<li><b>Synthetic:</b> every input is from <span class="mono">floor/golden.jsonl</span>, and all of it is
invented. Credentials are fake (the AWS one is AWS's documented example key).</li>
<li><b>Provisional:</b> thresholds are placeholders until calibration on the full golden set.</li>
<li><b>Not a benchmark:</b> {len(results)} hand-picked examples say nothing about accuracy or latency.</li>
</ul>
<h2>At a glance</h2>
{results_table(results, clamp=False)}
<p class="note">{esc(EXTRA_NOTE)}</p>
<h2>Every example, every rule</h2>
{"".join(detail)}
"""
    return page("Guardrail demo report", body, card=False)


def find_chrome() -> str | None:
    for name in ("google-chrome", "chromium", "chromium-browser", "chrome"):
        path = shutil.which(name)
        if path:
            return path
    return None


SCALE = 2


def crop_png_height(path: Path, height: int) -> None:
    """Keep only the top ``height`` pixel rows of a non-interlaced 8-bit PNG (stdlib only).

    Each row's filter refers only to the row above, so dropping trailing rows stays valid.
    """
    data = path.read_bytes()
    pos, chunks = 8, []
    while pos < len(data):
        (length,) = struct.unpack(">I", data[pos : pos + 4])
        ctype = data[pos + 4 : pos + 8]
        chunks.append((ctype, data[pos + 8 : pos + 8 + length]))
        pos += 12 + length
    ihdr = next(c for t, c in chunks if t == b"IHDR")
    width, old_h, depth, color_type, _, _, interlace = struct.unpack(">IIBBBBB", ihdr)
    channels = {0: 1, 2: 3, 4: 2, 6: 4}.get(color_type)
    if depth != 8 or interlace or channels is None or height >= old_h:
        return
    raw = zlib.decompress(b"".join(c for t, c in chunks if t == b"IDAT"))
    raw = raw[: height * (1 + width * channels)]
    new_ihdr = struct.pack(">IIBBBBB", width, height, depth, color_type, 0, 0, 0)

    def chunk(ctype: bytes, body: bytes) -> bytes:
        crc = zlib.crc32(ctype + body) & 0xFFFFFFFF
        return struct.pack(">I", len(body)) + ctype + body + struct.pack(">I", crc)

    path.write_bytes(
        data[:8]
        + chunk(b"IHDR", new_ihdr)
        + chunk(b"IDAT", zlib.compress(raw, 9))
        + chunk(b"IEND", b"")
    )


def screenshot(chrome: str, html_path: Path, png_path: Path) -> None:
    # Headless Chrome's viewport is shorter than --window-size, so render taller and crop.
    subprocess.run(
        [
            chrome,
            "--headless=new",
            "--disable-gpu",
            "--hide-scrollbars",
            f"--force-device-scale-factor={SCALE}",
            f"--window-size={CARD_W},{CARD_H + 200}",
            f"--screenshot={png_path}",
            html_path.as_uri(),
        ],
        check=True,
        capture_output=True,
        timeout=60,
    )
    crop_png_height(png_path, CARD_H * SCALE)


def main() -> int:
    data = json.loads((OUT / "results.json").read_text())
    use_source(data)
    by_id = {r["id"]: r for r in data["results"]}
    pages = {
        "report.html": report(data),
        "card-1-email.html": card_email(by_id["tr-ind-002"]),
        "card-2-obfuscation.html": card_obfuscation(by_id),
        "card-3-results.html": card_results(data["results"]),
    }
    for name, text in pages.items():
        (OUT / name).write_text(text, encoding="utf-8")
        print(f"wrote {OUT / name}")

    chrome = find_chrome()
    if not chrome:
        print("no Chrome or Chromium found; skipping PNGs", file=sys.stderr)
        return 0
    for name in pages:
        if name.startswith("card-"):
            png = OUT / name.replace(".html", ".png")
            screenshot(chrome, OUT / name, png)
            print(f"wrote {png}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
