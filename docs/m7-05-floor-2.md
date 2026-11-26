# M7-05 · floor@2: in the catalog, released, and the default of the simulation (as built)

The held-out validation measured **floor@2**: `floor/rules.json` with the two reworded rules of
`floor/next/additions.json` (`p__ai_addressed`, `p__xtenant_probe`), thresholds unchanged at
0.85 / 0.55 and still provisional. The engine used to know only floor@1. The first change put
floor@2 in the catalog. The second, below ("The release, in the simulation"), released it through
the floor release path on the live red-team report of this floor, so **the floor a new tenant
starts on is the floor the evidence describes.**

## The release, in the simulation

The release is state in the platform's store, and the simulation has no durable store: an engine
in the `test` environment starts with an empty in-memory one. So the release was made once, and
what the release path produced is kept as a **release record**,
`floor/releases/floor-2.release.json`, which such an engine replays into its store at start.

| Step | What |
|---|---|
| Propose | `python -m floor.simulate_release` runs the real `FloorService` and authorizer: operator A proposes floor@2 with `redteam/floor2.live.report.json`. The evidence check passes: gate passed, a live run, the same floor (content hash), today's corpus, no row short, no defence broken. |
| Approve | Operator B, a different operator, approves **naming the report's `report_sha256`** (`sha256:6befa5d7…`, the canonical hash of the report; the file's own sha256 is `202fb0bd…`). |
| Released | Two operators approved, so the release is made. Standard 72-hour window, not security-urgent. |
| Record | The release (floor hash, evidence summary, the two approvals) is written to the record. |

**The two operators are test identities** (`simulation-operator-a` and `-b`): the record is a
simulation's, not a person's approval, and says so in its `note`.

**Replay.** `catalog.release_records` (default: that file) lists the records an engine replays.
The engine does it only in the `test` environment and only into the in-memory platform store it
built itself, through the store's own `propose` and `approve` (two different operators, one
release per floor), so the platform tables, the class A events and the listing show the release as
they would. A production or staging engine ignores records: it takes its release state from the
platform tables, and a deployment releases a floor through the routes below.

- A record about a floor the engine doesn't load releases nothing.
- A record about a floor whose **content has changed** since the release isn't applied (the floor
  stays unreleased and the engine logs it): the release no longer describes that file.
- An unreadable or malformed record, one with two approvals by one operator, one that contradicts
  itself (its urgency or staging window against the approvals, the floor version in its evidence,
  an approval dated before the proposal), or two records for one floor stops the start.
- **A record is trusted only after the engine has checked its evidence.** At start the engine reads
  the report file the record names (`report_file`, a path from the record's directory) and the
  current corpus (`catalog.redteam_corpus`) and runs the check a proposal passes: the report's
  canonical hash, the live run, the gate, this floor's content hash and today's corpus must give
  exactly the evidence the record stores. A record that fails (a report edited since, a corpus
  changed since, evidence made up) stops the start.
- `python -m floor.simulate_release --check` fails if the record is not about today's floor@2 file,
  names a different report than the one in the repository, or the report no longer passes the
  evidence check (a changed corpus, say).

**What it changes.** In the simulation: floor@2 is extendable; a new tenant's starter extends it;
tool-description screening uses its three questions; the local runner (`python -m
guardrail_engine.service`) serves both floors and the record. **What it doesn't:** `floor/rules.json`
(floor@1) is unchanged and still the baseline, tenants on floor@1 keep working, the minimum floor
stays 1, and no tenant is re-pinned. The re-pin and the minimum (steps 4 and 5 below) are
separate platform steps.

**The acceptance** ("the default floor is the one the held-out figures describe") is tested
against what the held-out run recorded, not against files that have moved since. The run's own
record (`run_started.files` in `calibration/results/m0-02-heldout-validation.jsonl`) names the
input files it measured: `rules.json` (its hash must equal today's file) and `additions.json` as
of commit `c35840f` (sha256 `523ccbef…`). Today's additions differ from that file only in their
`note`, which the floor's content hash doesn't cover, so the test requires today's additions
without the `note` to hash to the value pinned from `c35840f`, and the floor assembled from them
to hash to `sha256:521acbf3…`, the floor the held-out run measured. That equals the released
floor, the record's `floor_hash` and the red-team report's `floor_content_hash`. A new tenant's
starter extends it and compiles (`tests/engine/test_m7_05_release.py`).

## What ships

| Piece | What |
|---|---|
| `floor/rules.v2.json` | floor@2 as a floor file (`floor_version` 2). Written by `python -m floor.derive_v2` from `rules.json` and `additions.json` with the harnesses' own `calibration.run.assemble_floor`; `--check` fails if the file differs. A test pins that its content hash equals the floor the held-out run measured (see the acceptance above) and the `floor_content_hash` of the red-team report. |
| `catalog.floor_files` | Default is now `floor/rules.json` and `floor/rules.v2.json`. floor@1 is untouched (its hash is pinned and stored bundles extend it). |
| New-tenant starter | `CatalogAdmin` starts a tenant on the newest **released** floor (it used the newest in the catalog, which, with an unreleased floor@2 present, would have given every new tenant a bundle that doesn't compile: `floor.not_released`). |
| Tool-description screening | Uses the newest **released** floor's three questions (it used the newest in the catalog, so loading floor@2 would have changed screening before any release). |

**Nothing changes for any tenant until the release.** At start the engine restricts the catalog
to its baseline (floor@1, the lowest version): floor@2 can be read and verified but not extended.
The engine, the starter and the screening all behave as before. (In the simulation the release
has been made; see above.)

## Becoming the default in a deployment (operators; `docs/m2-09-floor-upgrades.md` has the routes)

1. **Evidence.** A live red-team run of floor@2 with the gate and `floor_content_hash` in its
   report: `python -m redteam.run run --live --out … --json … --max-provider-calls 1032
   --max-tokens 1000000` (172 rows × 3 draws = 516 checks; needs the maintainer's approval of the
   scope each time). `redteam/baseline.live.report.json` measured floor@2 earlier but predates
   the gate and hash fields, so it isn't release evidence. The run that is:
   `redteam/floor2.live.report.json` (`docs/redteam-floor2-evidence.md`).
2. **Release.** `POST /v1/platform/floors/2/release` with that report (the proposer is approval 1),
   then a **different** operator `POST …/approve` naming the report's `report_sha256`. The
   release is refused unless the gate passed, the run was live, `floor_content_hash` is the
   catalog's floor@2, the corpus is today's, and no row was short.
3. **New tenants start on floor@2** from the release on (the starter and tool screening pick the
   newest released floor). Existing tenants stay on floor@1.
4. **Existing tenants.** After the window (72 h; 6 h if both approvers say security-urgent) an
   operator re-pins them (`POST …/floors/2/repin`): a shadow candidate at 100%, changing only
   `extends`; the audit record carries the candidate's decision beside the real one, so
   disagreement is visible. Each tenant is promoted by hand. A tenant's floor overrides are kept
   only where still stricter; every drop is listed.
5. **Minimum.** `PUT /v1/platform/minimum-floor {version: 2}` once every tenant is on floor@2
   (409 `tenants_behind` names the rest). floor@1 stays in the catalog (append-only).

## What differs between the floors

Only two rules' wording: `p__ai_addressed` (`false_description`: jailbreaks and requests aimed at
the assistant do not count unless they also speak to a filter or classifier about how the content
should be judged) and `p__xtenant_probe` (`question`, `true_description`, `false_description`:
cross-tenant intent has to be in the content). Keys, guard points, severities, modes, thresholds
and `provisional` are floor@1's.

## Before release: what loading floor@2 already does

- The tenant-facing catalog lists floor@2 with `extendable: false` until it is released.
- Floor-derived question keys include floor@2's reworded texts as soon as the file is loaded. A tenant rule whose text exactly matches one of them is treated like the floor (its probability is withheld). That is stricter, never looser, so it's intended.
