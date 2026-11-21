# M0-03 · Quota path: Google's limits and a capacity model

Status: **written 2026-11-17, from Google's own documentation. No live calls were made.** Backlog: M0-03, which closes PF-4's open point ("a secondary source"). The arithmetic is in [`model.py`](model.py) and is tested in `tests/capacity/test_model.py`. Every table below is that model's output, pasted between the markers in section 3 and checked by a test; regenerate with `uv run python -m capacity.model`.

**M3-09 (2026-11-18):** the load-test harness that applies this model to the engine under simulated load, and the plan for the live runs, are in [`docs/m3-09-load-test.md`](../docs/m3-09-load-test.md) (`load_test.py`, `load_live.py`).

**The short answer**

1. **Google's own page confirms the Tier 1 figures** for Gemini Decision 1: 1,500 requests/min, 1M tokens/min, 50,000 requests/day. It also gives Tiers 2 and 3 (section 1).
2. **Two more limits apply that the story didn't list:** a spend limit per rolling 10 minutes, and a **monthly spend cap on the billing account** ($250 at Tier 1) that pauses every linked project when reached. At Google's price of $0.10 per million input tokens the first can never bind; **the second can, and it binds before the daily request cap for any check over about 1,667 tokens.**
3. **Per minute, tokens/min binds** at every realistic check size. **Per day, the monthly spend cap binds** for checks over 1,667 tokens; the 50,000 requests/day cap binds only for shorter ones. At the PF-4 planning figure of 4,000 tokens per check and 5 checks per turn, one Tier 1 project allows at most **50 turns/min** and **4,167 turns/day** (about 2.9 turns/min sustained), not the 10,000/day PF-4 gave, which holds only for short checks.
4. **One project means non-production shares production's quota.** A separate key pool for tests, calibration, red-team and shadow candidates isolates nothing: Google applies limits per project, not per API key.
5. **Moving to Tier 2 is the quota path.** It removes the daily request cap, quadruples tokens/min and multiplies the monthly cap by 8.

## 1. What Google's documentation says

Read on 2026-11-17. Each URL redirects (301) to the same path on `aistudio.google.com/docs/`, which is where the text was read.

| Page | URL |
|---|---|
| Rate limits | <https://ai.google.dev/gemini-api/docs/rate-limits> |
| Billing | <https://ai.google.dev/gemini-api/docs/billing> |
| Pricing | <https://ai.google.dev/gemini-api/docs/pricing> |
| Gemini Decision 1 | <https://ai.google.dev/gemini-api/docs/models/gemini-decision-1> |
| Decisions API guide | <https://ai.google.dev/gemini-api/docs/decisions-api> |

### 1.1 The Tier 1 figures are confirmed

The rate-limits page has a **Gemini Decision 1** table. Tier 1 is **1,500 RPM, 1,000,000 TPM and 50,000 RPD**, the same as the secondary source PF-4 used. Two independent reads of the page gave the same table.

### 1.2 Higher tiers

| Tier | Requests/min | Tokens/min | Requests/day | Spend per 10 min | Monthly cap |
|---|--:|--:|--:|--:|--:|
| Free | 200 | 50,000 | 10,000 | n/a | n/a |
| Tier 1 | 1,500 | 1,000,000 | 50,000 | $10 | $250 |
| Tier 2 | 5,000 | 4,000,000 | unlimited | $200 | $2,000 |
| Tier 3 | 15,000 | 10,000,000 | unlimited | $200 | $20,000+ |

*Unlimited* is Google's word for Tier 2's and Tier 3's requests per day. Tier 3's cap is "$20,000 - $100,000+" and the table shows its lower bound. The Free tier's data may be used to improve Google's products, so production is paid tier only.

**Qualification** (rate-limits and billing pages):

| Tier | Qualification |
|---|---|
| Tier 1 | "Set up and link an active billing account" |
| Tier 2 | "Paid $100 + 3 days from first successful payment" |
| Tier 3 | "Paid $1,000 + 30 days from first successful payment" |

- Tiers 2 and 3 count cumulative spend "towards all Google Cloud products" on the billing account, so the $100 doesn't have to be Decisions API spend.
- Upgrades are automatic. "Tier upgrades from the Free to Tier 1 will typically take effect instantly, and subsequent tier upgrades will take effect within 10 minutes." In rare cases an upgrade "may be denied based on other factors".
- There is a paid-tier rate-limit increase form. Google offers "no guarantees". The page also says "Specified rate limits are not guaranteed and actual capacity may vary."

### 1.3 Two limits the story didn't name

- **Spend per rolling 10 minutes:** Tier 1 $10; Tier 2 $200; Tier 3 $200. Hitting it returns `429 RESOURCE_EXHAUSTED`. Whether it applies "depends on your billing history and account standing". *One search summary gave $50 for Tier 2; the page, read twice, says $200. Tier 2's figure is unconfirmed and doesn't matter for a Tier 1 plan.*
- **Monthly billing tier cap**, per **billing account**: Tier 1 $250, Tier 2 $2,000, Tier 3 $20,000 to $100,000+. "Total spend is aggregated across all linked projects that have the Gemini API service enabled." When it is reached, "service is paused for all projects linked to that billing account until the start of the next billing cycle" (the 1st of the month). Billing data can lag by about 10 minutes, so a cap can be overshot. A cap-increase form exists.

### 1.4 Scope and timing

- **"Rate limits are applied per project, not per API key."** Tiers, rate limits and caps are decided at the billing-account level. Projects inherit them, and keys inherit from their project.
- **The daily quota resets at midnight Pacific time**, which is 08:00 UTC in winter and 07:00 UTC in summer.
- The rate-limits page says nothing about regions, queueing or latency under load. The billing page says only that tiers are available in "many regions".

### 1.5 Price and token accounting

- Gemini Decision 1, paid, standard: **$0.10 per 1M input tokens.** Output is always 0 tokens. There is no separate price for media.
- Shared input "bills once, regardless of question count"; each question adds its own instructions, criteria and formatting. **There is no context caching, so repeated input is billed in full.**
- 262,144 tokens across the input and all questions; 1 to 1,000 questions per request. **No Batch, Flex or Priority inference**, so there is no second quota pool to move work to.
- The pages don't say whether question tokens count towards TPM. The model assumes they do, which is the conservative reading: `usage.total_input_tokens`, which we measure, includes them.

## 2. The three open questions

1. **Tiers above Tier 1:** answered in 1.2.
2. **Spreading quota across projects.** Google says limits are *per project*, which implies each project has its own RPM, TPM and RPD. It does not say a second project gets an independent full quota, and the user has ruled out testing it (2026-11-17: one project, one key). Two things are documented either way: **extra keys in one project add nothing** (M3-08's multi-key pools were an assumption; they are now a documented non-feature), and **the monthly spend cap is shared by every project on the billing account**, so extra projects would not lift the spend ceiling. M5-06's dedicated projects for regulated tenants stay unverified.
3. **Google Cloud and regional timing.** Not documented for rate limits. What *is* documented: the daily reset (midnight Pacific), the tier-upgrade delay (instant from Free, within 10 minutes after), the billing-data delay (about 10 minutes) and the monthly cycle (the 1st). Regional quotas and queueing remain a question for Google (section 6).

## 3. The capacity model

**Units.** A *check* is one Decisions API request. A *turn* is `checks_per_turn` checks: **5** at one tool call (input, plan, tool_call, tool_result, output), and `3 + 2 x tool_calls` in general; a `tool_result` over `chunk_tokens` adds a check per extra chunk. Tokens are API input tokens, questions included. **Tokens per check is the input that matters most**, and it is measured here, offline, with the engine's own renderer and estimator:

| Check size | Tokens/check | Source |
|---|--:|---|
| short, golden-sized | 850 | measured: golden set mean 822, p95 919 |
| held-out mix, mean | 2,900 | measured: held-out set mean 2,896, median 880, **p95 14,121** |
| PF-4 planning figure | 4,000 | PF-4 |
| 4K x 12 benchmark shape | 6,455 | R6.3 |
| held-out long contexts, p95 | 14,100 | measured |

**Which limit binds, and the maximum turns per minute and per day for one Tier 1 project, before production reserves anything for non-production:**

- **Per minute: tokens/min** binds. Requests/min binds only below 667 tokens per check, and spend per 10 minutes never binds (the most that can be spent in 10 minutes at the token limit is $1, against $10).
- **Per day:** requests/day binds only for checks **under 1,667 tokens**; above that the **$250 monthly cap** binds, at 83.3M tokens a day. The 1,440 x TPM figure never binds.
- The monthly cap is a month total, so a heavy day isn't refused by it; it uses up the month. The model treats it as a daily budget for planning.

<!-- tables:start -->
| Tier | Requests/min | Tokens/min | Requests/day | Spend per 10 min | Monthly cap |
|---|--:|--:|--:|--:|--:|
| Free | 200 | 50,000 | 10,000 | n/a | n/a |
| Tier 1 | 1,500 | 1,000,000 | 50,000 | $10 | $250 |
| Tier 2 | 5,000 | 4,000,000 | unlimited | $200 | $2,000 |
| Tier 3 | 15,000 | 10,000,000 | unlimited | $200 | $20,000+ |

Tier 1, 5 checks per turn, retry rate 0%, 4,000 tokens per check:

| Limit | Allows (turns) | Per |
|---|--:|---|
| requests/min | 300.0 | minute |
| tokens/min | 50.0 | minute |
| spend/10 min | 500.0 | minute |
| requests/day | 10,000 | day |
| tokens/min x 1,440 | 72,000 | day |
| monthly spend cap | 4,167 | day |

| Check size | Tokens/check | Binds per minute | Turns/min | Binds per day | Turns/day | Sustained turns/min |
|---|--:|---|--:|---|--:|--:|
| short, golden-sized | 850 | tokens/min | 235 | requests/day | 10,000 | 6.9 |
| held-out mix, mean | 2,900 | tokens/min | 69 | monthly spend cap | 5,747 | 4.0 |
| PF-4 planning figure | 4,000 | tokens/min | 50 | monthly spend cap | 4,167 | 2.9 |
| 4K x 12 benchmark shape | 6,455 | tokens/min | 31 | monthly spend cap | 2,582 | 1.8 |
| held-out long contexts, p95 | 14,100 | tokens/min | 14 | monthly spend cap | 1,182 | 0.8 |

Moving up a tier, at the same check size:

| Tier | Binds per minute | Turns/min | Binds per day | Turns/day | Sustained turns/min |
|---|---|--:|---|--:|--:|
| Tier 1 | tokens/min | 50 | monthly spend cap | 4,167 | 2.9 |
| Tier 2 | tokens/min | 200 | monthly spend cap | 33,333 | 23.1 |
| Tier 3 | tokens/min | 500 | monthly spend cap | 333,333 | 231.5 |

| Check size | Binding daily limit | Non-prod, average day | Production turns/day at 70% | During a 100% shadow window | Non-prod bad day |
|---|---|--:|--:|--:|--:|
| short, golden-sized (850) | requests/day | 661 requests | 6,868 | 3,434 | 5,531 |
| held-out mix, mean (2,900) | monthly spend cap | 1,813,716 tokens | 3,898 | 1,949 | 1,329 |
| PF-4 planning figure (4,000) | monthly spend cap | 1,813,716 tokens | 2,826 | 1,413 | 963 |
| 4K x 12 benchmark shape (6,455) | monthly spend cap | 1,813,716 tokens | 1,751 | 876 | 597 |
| held-out long contexts, p95 (14,100) | monthly spend cap | 1,813,716 tokens | 802 | 401 | 273 |

| Consumer | Checks/run | Runs/month | Tokens/check | Checks/day (avg) | Basis |
|---|--:|--:|--:|--:|---|
| Calibration, golden set (R7.4 rerun) | 1,017 | 2 | 822 | 68 | measured: plan output, 3 draws of 339 |
| Calibration, held-out validation (R7.3(c)) | 2,346 | 2 | 2,896 | 156 | measured: plan output, 3 draws of 782 |
| Red-team recall run (M2-08) | 1,000 | 2 | 850 | 67 | assumed: corpus size not yet defined |
| Live tests and live gates | 200 | 20 | 850 | 133 | assumed |
| Tenant test endpoint (M2-05), one partner | 500 | 4 | 850 | 67 | assumed |
| Benchmarks and load tests (M0-01, M3-09) | 5,000 | 1 | 6,455 | 167 | assumed: M0-01 made about 3,100 calls |
| Demo regeneration | 45 | 2 | 850 | 3 | measured: demo plan, 45 live checks |
| **Total, monthly average** | | | | **661** | 1.8M tokens/day |

The monthly cap binds before requests/day above 1,667 tokens per check (Tier 1); requests/min binds before tokens/min only below 667 tokens per check.
<!-- tables:end -->

**Reading the tables.** Turns per minute are peak rates; sustained turns per minute are the daily limit spread over a day, which is what continuous traffic can average. The *budget* table applies S3's onboarding cap (70% of the binding limit), takes out what non-production uses (section 4), and shows what is left for production, including during a shadow window and on a bad non-production day.

## 4. Non-production consumers

Tests, calibration, red-team runs, tenant tests, benchmarks and shadow candidates all call the same API. **With one project there is no separate pool:** a "non-production key pool" (PF-4, M3-08) would draw on production's tokens/min, requests/day and monthly cap. The consumers above are **small on average** (661 checks and 1.8M tokens a day, about 1.3% of the daily request cap and 2.2% of the monthly cap's daily share) and **large on a bad day**: the two biggest runs together are 7,346 checks and 39M tokens, 47% of a day's share of the cap.

Most of the figures are **assumed** (marked in the table); the calibration and demo figures are the repo's own plan output. They are replaced by dogfood data as it arrives.

- **Shadow candidates are the largest consumer, and they scale with production.** A candidate in shadow is evaluated on `rollout_percent` of conversations on top of the active version (PF-7). A floor release starts every tenant's candidate at 100% for 72 hours, so **production's requests and tokens double** for that window: the "during a 100% shadow window" column. The onboarding cap has to be sized for that, not for a quiet day.
- **A load test can use the whole day.** At 1,500 requests/min it would reach the 50,000 requests/day cap in about 33 minutes. M3-09 already says the daily cap can be projected rather than burned down; with one project that is a requirement.

## 5. What this changes in the backlog

For the maintainer to decide. None of it is applied here.

1. **PF-4's "the daily cap binds first for any continuous traffic" holds only below 1,667 tokens per check.** At 4,000 the monthly spend cap binds first: **4,167 turns/day, not 10,000**. S3's "about 7,000 turns/day per pool" is 6,868 for short checks, **3,898 at the held-out mix and 2,826 at 4,000 tokens**, after non-production.
2. **Tier 1 carries the dogfood and about one small design partner, and no more.** At the held-out mix that is 4.0 turns/min sustained.
3. **M3-10's limiter needs a monthly spend counter** beside the daily request counter, with alerts, and **both must roll on Google's calendar:** the request counter at midnight Pacific, the spend counter on the 1st. The working rule "10,000 calls per UTC day" is safe (two UTC days overlap one Pacific day by at most 20,000 calls, against 50,000), but the counter must use the Pacific day (`pacific_day()` in the model).
4. **M3-08's multi-key pools add nothing** and non-production can't be isolated by key. Isolation has to be an allowance enforced in our own gateway: one shared bucket, a pool *label* for accounting, non-production below production in priority, and a per-class daily allowance. A calibration or load run refuses to start if its `plan` would take the day over its allowance.
5. **The quota path to GA is Tier 2:** no daily request cap, 4M tokens/min, a $2,000 monthly cap, and 33,333 turns/day at 4,000 tokens per check against 4,167. It needs $100 of cumulative Google Cloud spend and 3 days. Tier 3 gives 333,333 turns/day and 500 turns/min. Cap increases go through Google's forms and are not guaranteed.
6. **Tokens per check is the lever.** Every figure above scales with it, and checks are billed in full each time (no caching). Context that the engine drops, shorter rendered inputs and fewer chunks raise capacity directly.
7. **A side finding on refusals (M1-13).** Google's Decisions API page lists the safety error codes as `safety`, `prohibited_content`, `blocklist`, `image_safety` and `content_blocked`. The adapter maps only `prohibited_content` and codes containing "safety", and its notes leave `blocklist` and `content_blocked` unmapped because "none has been seen on this API". Google's own page now lists them as Decisions codes, so they should map to `SafetyBlocked`. Until then they fall to `Failed(OTHER)`, which the calibration and demo runs treat as a stop.

## 6. Not established: questions for Google

1. Does a second project on the same billing account get its own full RPM, TPM and RPD? May an organisation spread load that way? *(Not tested: the user ruled out a second project.)*
2. Do question tokens count towards TPM? Does a retried or abandoned call count again against RPM, TPM and RPD, and is it billed?
3. Is the monthly tier cap enforced on Decisions API spend exactly as on other Gemini API spend, and in which time zone does the billing cycle end?
4. What does a quota 429 look like on the Decisions API, and does it carry a retry hint? The Decisions page gives no format.
5. Are there regional quotas or regional capacity, and is queueing or smoothing applied under load (the M0-01 sweep saw multi-second latencies near 70% of the token limit)?
6. Tier 2's spend limit per 10 minutes ($200 on the page, $50 in one summary).
7. How long does a rate-limit or cap increase request take, and what decides it?

## 7. Method and limits

- The pages were read with a fetch tool that returns a model's summary of the page, so figures are as read, with quotes of 125 characters or less. The Decision 1 table was read twice with the same result; the billing cap was read twice. Where a search summary disagreed with a page, the page is used and the disagreement is stated (1.3).
- Nothing here was measured against the live API. Token sizes are offline estimates with the engine's own estimator, whose estimate was compared with the usage recorded on the floor@2 run: actual over estimate had a median of 0.96 and a maximum of 1.05.
- The checks per turn, the non-production workload and the 70% onboarding cap are planning assumptions (S3 for the cap). They are parameters of every function in `model.py`.
