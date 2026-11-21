# M5-05: the nightly red-team against production versions (offline part)

A scheduled job runs the M2-08 red-team suite against what production serves, once a night, and
pages on-call when recall falls. Everything here is built and tested **offline** (the fake model,
an injected clock, in-memory and Postgres stores): **no live call was made.** A live run is behind
the same kind of gates as `calibration.pack_live` and needs explicit approval.

| Path | What it is |
|---|---|
| `redteam/nightly.py` | `NightlyJob` (the night), `HarnessSuite` (the M2-08 harness for one configuration), the comparison, the fair ordering, the estimate and a small CLI. |
| `src/guardrail_engine/nightly/` | The result model, the ports (`ActiveBundleSource`, the result sink and reader), the in-memory and Postgres stores. |
| `src/guardrail_engine/admin/nightly.py` | `GET /v1/platform/redteam/nightly` and `.../{tenant_id}` for platform operators. |
| migrations 051, 052, 053 | `nightly_redteam_results`, its grants and its operator policy. |

## What is tested, and why per configuration

An active tenant version extends one **floor version** and some **packs**. That pair, the
**configuration** (`platform/floor@2+domain/finance@1+...`), is what decides how the platform layers
behave; a tenant's own rules and overrides do not change the floor's or a pack's questions, and a
tenant can only **lower** a pack rule's thresholds and never edit its text. So the platform layers'
recall is the **floor of the tenant's own**: if the platform part regresses, every tenant on it has.

So the job reads each tenant's active version's `extends` (references only), groups the versions by
configuration, and runs the corpus **once per distinct configuration** on a **synthetic** tenant
that extends exactly that floor and those packs, through the same engine path as production
(redaction, renderer, gateway, fusion). **No tenant's data is read.** The result is recorded for every
tenant version that has the configuration, so the cost is per distinct configuration, never per
tenant. The floor is the **catalog's** version of that number (what production serves), not the
repository's candidate; a floor that lacks a rule the corpus labels is judged on the rules it has.

The corpus is `redteam/corpus.jsonl` (172 rows: prompt injection and tenant isolation, benign
payloads), at the **baseline's draws (3) and nonce seed**, so every night's inputs are identical and a
change is the model's or the stack's, not the nonces'.

## Regulated tenants' dedicated projects (M5-06)

A regulated tenant is served from its own Gemini project (its quota, spend and key are its own).
The job reads each active tenant's `project` from the directory entry the Guard Service routes by,
and the **project is part of the configuration**: a regulated tenant is never folded into the shared
pool's run, even when its floor and packs are the same. Its synthetic tenant carries the project, so
the night's calls go out on **that project's key**, inside **that project's** `red_team` allowance and
on its bill, and the result is **reported per project**:

* the configuration key is `reg-acme|platform/floor@2+...` (no prefix is the shared pool);
* each result row has a `project` (the route shows `default` for the shared pool, and
  `?project=reg-acme` or `?project=default` filters the list);
* `NightlyReport.by_project` holds, per project, how many configurations were tested, skipped or
  failed, how many regressed, and the provider calls and input tokens spent;
* a page names the project (`... (Gemini project reg-acme)`), and its dedupe key starts with it;
* **each project has its own call budget** (`project_budgets`, else `call_budget`), so a busy shared
  pool never skips a regulated tenant's night and a regulated project's ceiling never costs the
  pool any;
* a live run on a project needs its key (the **name** of its environment variable: default
  `GEMINI_KEY_<LABEL>`, or `HarnessSuite(project_key_envs=...)`; never a key in a setting). A project
  whose variable is not set is **refused** (`project_key_missing`) before an engine is built, and
  the name and value are never printed.

## What pages

A **regression** is any of:

* a floor rule's `block_at` recall more than **one (row, draw) cell** below the **previous tested
  night's** result for the same configuration and mode (`vs: previous`);
* the same against the **release baseline** (`redteam/baseline.json`, or `baseline.fake.json` in a dry
  run), compared only for the floor version, corpus and draws the baseline measured
  (`vs: baseline`);
* a **model-independent defence** failing (`vs: defences`).

A night is compared with the previous (and the baseline) only if it measured the **same corpus,
draws and nonce seed**: each result stores its seed (`nonce_seed`), and a night run with
another seed is a different set of inputs, so it is not compared (it becomes the new reference).

A regression is a **page** (`redteam_regression`, one per configuration per day, naming the
configuration, the rules and the tenant versions). A run that is **stopped or refused** is a warning
(`redteam_run_failed`); an incomplete run is refused, never judged. **A configuration with no tested
result for more than seven nights pages** (`redteam_stale`, once a day), whatever the reason.

## The nightly ceiling, and fairness

Live runs are held to the `red_team` allowance: 10% of the project's requests a day, **about 5,000 at
Tier 1**. `NightlyJob(call_budget=N)` takes configurations in this order and skips what would pass
the budget:

1. **never-tested first** (a configuration newly made active jumps the queue);
2. then **oldest-tested first** (ties by key, so every replica picks alike).

A skipped configuration is recorded for each of its tenant versions as `refused` /
`skipped_over_budget`, and goes first the next night, so every configuration is tested within
`ceil(configurations / budget)` nights, and the stale page catches any that is not.

## Dry by default; the gates and the harm refusals

Without `--live` the model is the engine's own fake (an oracle: recall 1.0 by construction), so a dry
run proves the plumbing, the comparison and the paging, not the model. **A live run needs** `--live`,
`GUARDRAILS_LIVE_REDTEAM=m5-05-nightly` in the environment, `--max-tokens` and
`--max-provider-calls`, and a key (`GEMINI_API_KEY`, never printed). Without all of them the suite
is refused before anything is built. And:

* **The only input is `redteam/corpus.jsonl`**, loaded by `redteam.run.load_corpus`: a row that fails the
  harm filter (`live_exclusion`, the tripwire, the builder's rules) refuses the **whole** run. No
  pack's golden row is ever read, so no withheld row is ever sent.
* **`d__harm_facilitation` is never sent.** A synthetic bundle that extends the responsible-AI pack
  carries the pack's per-rule opt-out (R4.6); and the compiled questions are checked with
  `refuse_harm_facilitation` before an engine is built, so a lost opt-out refuses the run.
* A live run refuses a pack whose own text trips the harm tripwire (the responsible-AI pack's
  classifier questions, which name harms, are decided sendable).
* **A provider refusal holds the refused row and the configuration, and ends the night (Decided).** The provider refuses a corpus row, and every configuration sends the
  same corpus, so the hold is on the **row** (its id, never its content) across every configuration
  and Gemini project, as well as on the configuration. On a refusal the job, in this order:
  1. appends the row's `quarantine` event (key `row:<id>`) and the configuration's (actor
     `nightly`), and pages **at once** (`redteam_quarantined`, naming the row);
  2. only then writes the results row, so a failed write can't leave a refusal unremembered (if it
     fails anyway the hold stands, the night stops and the error is logged);
  3. **halts the whole night, in every project**: the other configurations are recorded
     `night_halted_after_refusal`, are untested, and so go first the next night.
  Next night the held configuration is skipped without a call (recorded `quarantined`), and every
  other configuration runs with the held row **left out**. A night that left rows out names its
  corpus by a hash of the file and the left-out ids (`effective_corpus`), so it is compared only
  with a night that left out the same rows, never with the baseline's full corpus; its `rows` is
  the count it sent. A new configuration gets the row left out too. A hold that **can't be
  recorded** stops the night and says so in the page. A live job refuses to start without a
  quarantine store. `python -m redteam.nightly run --live` reads the same quarantine
  (`GUARDRAIL_PG_OPERATOR_DSN`) and refuses a held configuration or row, or a quarantine it can't
  read, unless `--override-quarantine` is given. The other stop conditions are the harness's own
  (auth, failure rate, ceilings).
* **A refusal with no usable row id holds the whole live corpus.** If the refusal names
  no row (no `example_id`, or one outside `ROW_ID`), which row to leave out is unknown, and holding
  only the configuration would let the next night send the same row under the others. The job then
  appends one more hold, the **corpus hold** (key `row:*`; `*` is no corpus id), beside the
  configuration's, and pages as for any refusal. While it stands no configuration is sent, in any
  project, and each is recorded `corpus_held_after_refusal` (the night of the refusal still
  records the rest `night_halted_after_refusal`). An operator clears it with
  `POST .../quarantine/clear` and `config: "row:*"` (listed with `kind: corpus`); the
  configuration's own hold is a separate clear.
* **A hold nobody clears is not quiet.** While a row (or the corpus) is held:
  * **it pages again once a day.** A hold that was open when the night began raises
    `redteam_quarantined` again, with the day in the dedupe key
    (`redteam_quarantined:row:<id>:<date>`), so a second run on the same day does not page twice
    and an operator who clears it stops the pages. The page at the time of the refusal is
    unchanged;
  * **every result produced while a row is held says so**, in the existing `note` column (no
    migration; it is a 200-character column): `baseline_compared: false; held_rows: [<ids>]`,
    after the result's own reason when it has one (`*` is the whole corpus). A night that left a
    row out names another corpus (`effective_corpus`), so it is never compared with the release
    baseline; `baseline_compared` is `true` only for a finished night that left no row out and
    had a baseline to compare with. The flag comes first and the ids are cut to fit
    (`, +N more]`), so the flag is never lost. The operator routes show the note.
* **A regulated tenant with no dedicated project is not run** in `production` and
  `staging`: it is never folded into the shared pool's run. Its result is `refused` /
  `regulated_without_project` (configuration key `unassigned|...`), and it pages
  (`redteam_unassigned`, per tenant per day). In `test` it stays in the shared pool.

## Results, per version, for operators

`nightly_redteam_results` (051): one row per (tenant, bundle version, night): status (`pass`,
`regression`, `refused`, `stopped`), the configuration, mode, draws, the per-rule `block_at` hit and
cell counts, the regressions (rule keys and counts), usage. **No content**: no corpus row, payload or
provider text. Forced row-level security by tenant, **insert-only** (no UPDATE or DELETE grant, a
trigger refuses both, and TRUNCATE), and the job connects as the **operator** role (its own
`operator_all` policy, 053). It is class B for offboarding: a terminated tenant's results are deleted
(migration 043's function, edited in place as in M5-03; the coverage tests pass).

`GET /v1/platform/redteam/nightly` (platform operators only, like the floor routes) lists each
tenant's **latest** result (`status`, `after` (a tenant id) and `limit` parameters, a cursor);
`GET /v1/platform/redteam/nightly/{tenant_id}` returns that tenant's last week. It names floor rules
and their recall, which no tenant ever sees.

## Cost: what a night spends

(Per **project**: each regulated tenant is its own configuration on its own project, so it adds
one configuration of about $0.05 to $0.08 and 516 calls a night **to its own project's allowance
and bill**, and nothing to the shared pool's.)


By the engine's own token estimator (real usage has run 0.9 to 1.15 times it), at 3 draws, **516
checks per configuration**, one provider call each (up to two with the gateway's retry):

| Configuration | Input tokens | At $0.10 per million |
|---|---:|---:|
| `floor@1` | about 404,000 | $0.04 |
| `floor@2` | about 467,000 | $0.05 |
| `floor@2` + insurance@2 | about 587,000 | $0.06 |
| `floor@2` + energy@2 | about 542,000 | $0.05 |
| `floor@2` + finance@1 | about 542,000 | $0.05 |
| `floor@2` + healthcare@1 | about 559,000 | $0.06 |
| `floor@2` + responsible_ai@1 | about 609,000 | $0.06 |
| `floor@2` + insurance@2 + responsible_ai@1 | about 729,000 | $0.07 |

So a configuration costs **about $0.04 to $0.08 a night, 516 provider calls (1,032 at worst) and 13
to 20 minutes** at the harness's 1.5 s pace. **Per active tenant it costs nothing extra**: a night
is `Σ` over the **distinct** configurations in use, however many tenants share each. What binds is
not money but the **`red_team` allowance**:

* **Requests: about 5,000 a day.** At 516 planned calls a configuration that is **9 configurations a
  night** (4 if every check were retried). More distinct configurations than that are rotated by the
  fairness rule, so each is tested every `ceil(N / 9)` nights: with 12 configurations in use, every
  one is tested at least every other night.
* **Money:** 9 configurations at about $0.06 is about $0.55 a night, **about $16 a month**, against the
  `red_team` consumer's allowance of 10% of the $250 monthly cap ($25).
* To test more configurations nightly, the user can raise the `red_team` allowance, or accept **one
  draw** (172 checks a configuration, about 29 configurations a night), which needs its own one-draw
  baseline (it is not like-for-like with the three-draw one). I built neither.

## Not done

* **No live run, no live baseline for packs**: the release baseline is floor@2 only, so a packed
  configuration is compared with its own previous night (and, for its floor rules, with the floor@2
  baseline). The first night of a configuration has nothing to compare with and is only recorded.
* The job is a library: a deployment schedules `NightlyJob.run_once()` (like the retention and
  offboarding jobs) with the operator pool's `PostgresActiveBundles` and `PostgresNightlyResults`, the
  engine's catalog, the durable alert sink and a `HarnessSuite`. The command line (`plan`, `run`) runs
  the suite for configurations named on it, in memory.
* The comparison needs the previous night's row, which is per tenant version: a configuration whose
  tenants have all left has no history (it is not served, so nothing is lost).
* A tenant's own rules are not red-teamed here (the M2-08 corpus is about the floor's rules).

## The quarantine, for operators

`nightly_redteam_quarantine` (051, 052): append-only events (`quarantine` by the job, `clear` by an
operator) with the configuration key, mode, project, actor, an operator flag, a reason (1 to 200
characters), the run id and the refused row's id. A refused corpus row has its own hold, with the
key `row:<id>`. The state is the latest event per (key, mode). Platform data:
no tenant column, no content. The database refuses UPDATE, DELETE and TRUNCATE.

* `GET /v1/platform/redteam/quarantine` lists what is held (`config`, `mode`, `project`,
  `since`, `run_id`, `reason`, `row` (the refused row's id) and `kind`: `configuration`, `row` or `corpus`, the corpus-wide hold `row:*`).
  Clearing a row (`config` is `row:<id>`) and clearing its configuration are separate steps.
* `POST /v1/platform/redteam/quarantine/clear` with `{"config", "mode" (default live), "reason"}`
  clears one. Platform operators only; the event carries the operator's actor (`issuer#subject`); an
  unknown or already cleared configuration is 404 `not_quarantined`; if the step can't be recorded
  it did not happen (503).
