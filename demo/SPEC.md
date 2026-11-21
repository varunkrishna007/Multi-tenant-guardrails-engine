# Demo v2 spec: ethics, bias, tenant rules and honest failure

Status: **built and tested offline; not yet run live** (see `demo/README.md`, "Demo v2"). Written 2026-11-17 at the user's request. It extends the v1 demo (`demo/README.md`, cards 1–3) with the cases added since: the Responsible AI pack (R4), the observe-only harm rule (U5), guard fairness, tenant-authored rules, and how failures are reported.

## 1. Goals

Show, with live Gemini Decision 1 calls on synthetic data:

1. **People at risk are helped, not refused.** A self-harm signal **escalates** to a human; it is never blocked (R4.3).
2. **Honest about harm.** A text panel explains that Google's own filter refuses requests for serious harm before our rules run, and that our harm rule is observe-only (U4, U5). Nothing harm-related is sent.
3. **Bias in individual decisions is caught**, while accommodations a person asked for are not mistaken for bias (R4).
4. **The guard treats people the same.** Swapping a name, dialect or language doesn't change the verdict (R4.5).
5. **Tenants write their own rules** as yes/no questions, layered on the floor and packs, within a question budget (R1, R6.1).
6. **Failures are honest.** When the model can't answer, content is still withheld, but the user is told "temporarily unavailable", not that they broke a policy (B1 recording note).

## 2. What changes from v1

- **The real engine instead of demo-only code.** v1 had its own rendering and threshold logic. v2 runs every check through the engine on `main`: the policy compiler (M1-01), the Guard Service (M1-05) with B3 nonce rendering, the gateway (M1-04) and the Gemini adapter (M1-03). The demo shrinks to selecting examples, calling `check()`, and rendering.
- **Shims only where the engine lacks something, each labelled on the card and in the report:**
  - **Pack loading and `max_action`** don't exist until M4-10. The demo loads `packs/responsible_ai/rules.json` itself and applies the escalate-only cap after `check()` returns. Card footer: "pack rules loaded by the demo; engine support arrives in M4-10".
  - **No Admin API.** The tenant bundle in card 8 is read from a file in `demo/tenants/`, not published through an API.
- **Failure scenario:** card 9 is a **simulated** failure, using the engine's own fake model scripted to time out. It is never a real outage, and the card says so.

## 2a. Constraints from U4, U5 and U6 (decided by the user, 2026-11-17)

- **U4:** *"Don't send any harmful inputs anymore to google."* The demo sends **no** harmful input: no `d__harm_facilitation` examples, no known-refused inputs. It uses the same filter (`no_live_run`) and tripwire as the harnesses. Card 5 is a text-only card.
- **U5:** the harm rule is **observe-only** (`d__harm_facilitation`, a shadow rule in the Responsible AI pack). Card 5's text panel says so. Neither the floor nor the demo shows it blocking anything.
- **U6:** self-harm statements, insults and discriminatory text **aren't** harmful inputs under U4, so cards 4, 6 and 7 keep their designs in §3. Card 4's support-line note still applies.

## 3. Cards

Each card is 1200 × 1500 CSS px, rendered at 2×. Each keeps the v1 honesty footer, extended as described in §5. Example IDs refer to `floor/golden.jsonl` (`fl`) and `packs/responsible_ai/golden.jsonl` (`rai`).

| # | Title (working) | Content | Examples |
| --- | --- | --- | --- |
| 1–3 | *(v1 cards, re-rendered through the real engine)* | Email injection; obfuscated jailbreaks; 18-example results | v1 `DEMO_IDS` |
| **4** | "When someone is struggling, the agent gets a human, not a refusal" | One self-harm message and one bereavement message: both **ESCALATE**, with the `d__self_harm_risk` and `d__vulnerability` probabilities shown. Next to them, "this hold music is killing me" **ALLOW**. A note says why escalate-only: refusing someone in crisis is the harmful outcome. | rai `in-sh-001`, `in-vu-001`, `in-ok-005` |
| **5** | "What the guard does about serious harm" (**text only, no live calls**; redesigned 2026-11-17) | **No examples are sent.** Even the harmless safety questions that mention harm are never sent, because they share the vocabulary that drew provider refusals (they are `no_live_run` rows in the pack). The card is a **text panel, not a demonstration**. It explains that requests for help to cause serious harm are refused by Google's own filter before our rules run (reason `provider_safety`), and says that the engine's own harm rule (`d__harm_facilitation`) is **observe-only**: it logs, never blocks (U5). **Nothing is sent for this card, and no recorded refusal is replayed** unless the user says so. | none (text only) |
| **6** | "Bias in decisions, caught; accommodations, allowed" | Two columns. **Offline-only:** the blocked column is built from withheld rows, so it is shown only when the engine's fake model runs it; a live run shows the allowed column and says so. **Blocked:** a plan that prices by sex, a tool call that routes by surname origin, a reply that stereotypes older customers. **Allowed:** large print as requested, a language as requested, pricing on claims history. The claims boundary (§5) is printed on the card. | rai `pl-pb-006`, `tc-pb-002`, `out-st-002`, `tc-ok-003`, `tc-ok-004`, `tc-ok-002` |
| **7** | "Same message, different name: same verdict" | A grid of 8 counterfactual pairs (name, dialect, language, sex swaps). Each row shows both texts, both verdicts, the highest p on each side and \|Δp\|. Any pair over 0.10 is shown highlighted, not hidden. | 4 pairs from rai (`rai-cf-*`, mixing allow and act), 4 from fl (`fl-cf-*`, including dialect and language) |
| **8** | "Customers write their own guardrails" | Left: the tenant bundle snippet (an insurance tenant with `fin_adv_01` plus one free-text rule). Middle: the compiled question count per guard point against the budget (for example "output: 3 floor + 4 pack + 2 tenant = 9 of 50"), taken from the real compiler. Right: one live check where `t__fin_adv_01` fires on "you should move your savings into the Growth Fund", and its near-miss "a deductible is the amount you pay first" allows. | tenant file + 2 inline samples (synthetic) |
| **9** | "When the model can't answer, nothing slips through, and nobody is told they broke a rule" | A **simulated** timeout on a floor-covered check gives decision **BLOCK**, reason `model_failure`, `retryable: true`. A side-by-side shows the user message: "temporarily unavailable, please try again", not "your message violated our policy". It also shows that the bad-publish block-rate alert doesn't count it. | fake model, scripted |

Final example IDs are picked when the demo is built. If a listed ID's content doesn't suit a public card, replace it with one from the same category and record why.

## 4. Running it

- **Live calls:** cards 1–8 need about 45 calls (18 for v1, 11 for cards 4, 6 and 8 (3 + 6 + 2), none for card 5, 16 for the 8 pairs in card 7, plus a few repeats). Run them sequentially through the gateway, so admission control and budgets apply. That is a negligible share of the daily cap.
- **Admission control:** with the default in-flight limit of 2, a burst of 20 simultaneous checks on one key would have 16 refused. The demo **paces its calls** (sequential, or at most the limit at once), or sets the limit through the M1-11 settings object, and records what it used. **Admission refusals** (`failure_reason` `admission_wait` or `admission_queue_full`, `provider_called: false`) **are never shown as model verdicts.** If any occur, they're listed separately in the report and the affected example is re-run.
- **Key:** `GEMINI_API_KEY` from the environment or `./.env`, exactly as in v1. Never printed or written to output. The output scan from v1 (key value and header names) runs again before the files are handed over.
- **Determinism:** example selection is fixed in code. The rendering nonce comes from the engine (B3), so probabilities can vary slightly between runs. The report says so.
- **Outputs:** `demo/output/results-v2.json` (tracked, like v1's `results.json`), `report-v2.html` (untracked), and `card-4…9.png` (tracked).

## 5. Honesty requirements (all cards)

- Footer on every card: **real Gemini Decision 1 calls · synthetic inputs · provisional thresholds · hand-picked examples, not an accuracy measurement**, plus the card-specific shim notes from §2.
- **The bias claims boundary (R4.4)** goes on card 6 and in the report: *detects biased content and decisions in individual responses; does not measure statistical fairness across decisions.*
- **Card 7 must not claim "unbiased".** It shows that these pairs got the same verdict, and highlights any that didn't.
- **Card 9 is labelled "simulated failure"** in its title area.
- **No latency figures on any card.** The latency story is the published end-to-end numbers (U1), not demo timings.
- **No harmful content.** Card 5 is text only and quotes no request. Self-harm text on card 4 follows safe-messaging practice, and the card carries a small support line: "If this raises something for you, please reach out to a local support line."

## 6. Acceptance criteria

- [ ] Cards 1–9 render at 2400 × 3000 PNG, with the footer fully visible and no overflow. Each is checked visually.
- [ ] Every live verdict comes from the engine's `check()` (compiler, Guard Service, gateway, adapter). The only exceptions are the labelled shims in §2. A reviewer can trace each card's numbers to `results-v2.json`.
- [ ] Card 4: both risk examples show **ESCALATE**, never BLOCK, even if p ≥ 0.99 (the `max_action` shim is tested against a scripted p = 0.99).
- [ ] Card 7 shows \|Δp\| for every pair, and any pair over 0.10 is highlighted.
- [ ] Card 8's question counts match the compiler's output for the tenant file, and the budget numbers match R6.1.
- [ ] Card 9 runs with **no network** (fake model) and is labelled simulated.
- [ ] **U4: no harmful input is sent by the demo, for any card.** The build applies the same filter as the harnesses (harm-labelled examples and known-refused inputs are never sent) and stops on any `prohibited_content`. Card 5 makes no live calls; refusal behaviour and the observe-only rule are described in text.
- [ ] No card shows an admission refusal as a verdict. `results-v2.json` has `provider_called: true` for every live verdict shown on cards 1–8, and records the pacing or in-flight limit used.
- [ ] The key scan is clean: the key value appears in no output, and no output contains a request header.
- [ ] `demo/README.md` is updated with what's real, what's shimmed, how to run it, and the call count.

## 7. Out of scope

The Admin API and publishing flow, real tenants, durable audit storage, accuracy or latency claims, aggregate fairness metrics (deferred to v1.1, R4.4), and any outage that isn't simulated.

## 8. For sharing publicly (LinkedIn)

- **Strongest public cards:** 6 (bias in decisions vs accommodations), 7 (same verdict across names and dialects) and 9 (honest failure). Each makes one clear point.
- **Card 4 (self-harm):** it's a good message, but it's sensitive. Share it with the support line visible, or leave it out of a public carousel and keep it in the report.
- **Card 5 (harm):** fine to share; it's text only.
- **Before posting,** the post text has to keep to the same claims as the cards: hand-picked synthetic examples, not a benchmark, and the bias claim exactly as worded in §5.
