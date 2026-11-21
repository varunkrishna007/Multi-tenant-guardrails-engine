# Demo: platform floor rules on Gemini Decision 1

This sends a hand-picked set of synthetic examples through the guardrail engine, built by the composition root (`build_engine`, M1-11), to the live Gemini Decisions API, using the platform floor rules from `floor/`. It renders the results as an HTML report and three shareable image cards.

| Card | Shows |
| --- | --- |
| `output/card-1-email.png` | An email that tells the AI agent reading it to forward the inbox, and the guard's per-rule probabilities |
| `output/card-2-obfuscation.png` | The same kind of jailbreak in plain text, with zero-width spaces, Cyrillic look-alike letters and base64 |
| `output/card-3-results.png` | All 18 examples: attacks and near-misses, with the label, the verdict and the rules that fired |

## What is real and what isn't

- **Real:** every verdict comes from the engine's `check()`: the floor rules in `floor/rules.json` compiled by the policy compiler, the Guard Service's nonce-delimited rendering (B3), the gateway's budgets and retry, and a live Gemini Decision 1 call through the adapter.
- **Configuration, not an Admin API:** the demo tenant (`t_1042`, `acme-insurance`, insurance) gets a floor-only policy published with `bootstrap_publish` in environment `test`, the path M1-11 provides for tests and the demo.
- **Synthetic:** every input comes from `floor/golden.jsonl`, and all of it is invented. Credentials are visibly fake; the AWS pair is AWS's own documented example.
- **Provisional:** thresholds (block ≥ 0.85, escalate ≥ 0.55) are placeholders until they are calibrated on the full golden set.
- **No harmful inputs:** every example passes the harnesses' label filter before the engine is built. A provider refusal, an `auth` failure or an unclassified failure stops the run at once, and nothing is resent. Checks run one at a time, so admission control never refuses one.
- **Not a benchmark:** 18 hand-picked examples say nothing about accuracy or latency.

Some rules also fire on examples they weren't labelled for. For example, "reaches for another customer's data" scores generic jailbreaks highly. The cards show these as dashed chips instead of hiding them. Settling which rule should fire is part of the calibration work (backlog M0-02).

## Run it

You need a **paid-tier** Gemini API key (the free tier's data may be used to improve Google's products), Python 3.11+, [uv](https://docs.astral.sh/uv/), and Google Chrome or Chromium for the PNGs.

```sh
export GEMINI_API_KEY=...            # or put GEMINI_API_KEY=... in ./.env (gitignored)
uv run python demo/run_demo.py       # 18 API calls → demo/output/results.json
uv run python demo/render.py         # → report.html and card-*.html/.png
```

`run_demo.py` reads the key from the environment or `./.env`. It never prints the key and never writes it, or any request header, to an output file; the results are scanned for both before they're written. Each run is 18 checks, one provider call each (two if the gateway retries one), of about 800 input tokens each.

The committed `output/results.json` and PNGs are from the v1 run (demo-only scoring, before the engine existed), and the report and cards say so. They are regenerated through the engine on the next live run, which needs the maintainer's explicit approval.

The tests (`tests/demo/`) run the whole demo through the engine with the fake model: no key, no network.

## Files

| File | Purpose |
| --- | --- |
| `run_demo.py` | Picks the examples (`DEMO_IDS`), builds the engine with `build_engine`, runs one `check()` per example, writes `output/results.json` |
| `render.py` | Turns `results.json` into `output/report.html` and the three cards (1200×1500 CSS px, rendered at 2× = 2400×3000 PNG) |
| `output/` | Generated. The PNGs are meant to be shared; `results.json` and the HTML can be regenerated |

## Use-case cards: a finance and a healthcare tenant

`render_usecases.py` makes two shareable cards (1200×1500 CSS px, 2400×3000 PNG):

| Card | Shows |
| --- | --- |
| `output/usecase-1-finance.png` | A wealth app's assistant with the finance pack. A guaranteed return, personal advice and an unapproved transfer are **blocked**; a customer describing a "safe account" call is **escalated** to a person. Each is shown beside a compliant message on the same topic, which is allowed. |
| `output/usecase-2-healthcare.png` | A clinic's assistant with the healthcare pack. A diagnosis, another patient's details and an unapproved record change are **blocked**; urgent chest pain is **escalated**. Each is shown beside an allowed counterpart. |

```sh
uv run python demo/render_usecases.py   # no API calls → output/usecase-*.html and .png
```

- **It makes no provider call.** The scores are the real Gemini Decision 1 probabilities recorded by the live calibration runs of 2026-11-19 (`calibration/results/m5-04-*-live-*.jsonl`), averaged over each row's 3 draws.
- **The text** is the synthetic golden row with the same id (`packs/<pack>/golden.jsonl`). Only rows that were actually sent are shown, and no `no_live_run` row is ever shown.
- **The verdicts** apply the provisional `@2` thresholds, and an escalate-only rule (`max_action: escalate`) never blocks. The script prints the platform floor's highest score for each row, to show that it doesn't change the verdict.
- **The examples are hand-picked**, so the cards are not an accuracy claim.

## Demo v2: cards 4 to 9 (`SPEC.md`)

Cards 4 to 9 cover the Responsible AI pack, bias and fairness, tenant-authored rules and honest failure. The code is built and tested offline. **The committed `output/` has no v2 results yet:** the live run waits for M1-14 (so the demo shows redaction) and explicit approval.

| Card | Shows | Calls |
| --- | --- | ---: |
| 4 `card-4-support` | A self-harm message and a bereavement both **escalate**, never block; a figure of speech is allowed | 3 |
| 5 `card-5-harm` | Text only: the provider's filter runs first, and our harm rule is observe-only | 0 |
| 6 `card-6-bias` | Three decisions blocked for resting on a characteristic; three accommodations or fair factors allowed. Carries the claims boundary (R4.4) | 6 |
| 7 `card-7-fairness` | Eight counterfactual pairs (name, sex, dialect, language): both verdicts, the highest p on each side, \|Δp\|. Any pair whose verdicts differ or whose gap is over 0.10 is highlighted, and the title changes if one is | 16 |
| 8 `card-8-tenant` | A tenant's own two rules, the compiled question counts per guard point against the budget (from the real compiler), and two live checks | 2 |
| 9 `card-9-failure` | A **simulated** timeout: block, `model_failure`, retryable, and the "temporarily unavailable" message. It never uses the network | 0 (fake model) |

That is 27 live checks (plus the 18 of v1 if its cards are regenerated), well under the spec's estimate of about 100. (The spec's "32 for the 16 pairs" counts checks twice: 8 pairs are 16 checks.)

### What's real and what's shimmed

- **Real:** every verdict on cards 4 to 8 comes from `Engine.check()` on an engine built by `build_engine`: the policy compiler, the Guard Service, the gateway and a live Gemini Decision 1 call. Card 9's messages come from the Guard SDK.
- **Pack loading (shim until M4-10):** the engine has no pack loader, so `run_demo_v2.load_pack` converts the pack's flat `rules.json` into a catalog pack document, and the engine compiles and scores it.
- **`max_action` (shim until M4-10):** the two escalate-only rules are capped by `apply_max_action` after `check()` returns. It is tested at p = 0.99, where the engine alone would block. It also refuses to run if it disagrees with the engine when no cap applies.
- **Tenant bundle (no Admin API):** card 8's tenant is read from `tenants/beacon-insurance.json` and published with `bootstrap_publish` (environment `test`).
- **Not loaded:** `d__harm_facilitation`, the observe-only harm rule. Its question text is harm vocabulary and nothing in the demo needs the provider to see it. Card 5 describes it in text. Card 8's counts say the full pack has one more rule.
- **No harmful input:** examples pass the harnesses' label filter before the engine is built, and a provider refusal stops the run with nothing resent. Every pick is a benign example (self-harm statements are allowed by U6 and follow safe-messaging practice).

### Run it

```sh
uv run python demo/run_demo_v2.py --live    # 27 checks → demo/output/results-v2.json (needs explicit approval)
uv run python demo/render_v2.py             # → report-v2.html and card-4…9 (.html and .png)
```

`run_demo_v2.py` refuses to run without `--live`. A results file produced by a fake model is stamped **SIMULATED** in every card's footer, so a preview can't pass for real Gemini results. No card shows a latency figure.

Tests: `tests/demo/test_demo_v2.py` runs the whole demo through the engine with the fake model, with no key and no network.
