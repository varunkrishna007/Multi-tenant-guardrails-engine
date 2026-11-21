"""M5-05 the nightly red-team against the versions production serves.

    uv run python -m redteam.nightly plan --config platform/floor@2 \
        --config platform/floor@2,domain/finance@1
    uv run python -m redteam.nightly run   --config platform/floor@2          # DRY: the fake model
    uv run python -m redteam.nightly run   --config ... --live --max-tokens N --max-provider-calls N

The job is :class:`NightlyJob`; a deployment schedules ``await job.run_once()`` once a night with
the operator pool's sources (``PostgresActiveBundles`` and ``PostgresNightlyResults`` of
``guardrail_engine.nightly.adapters.postgres``), the catalog the engine uses, the durable alert
sink and a :class:`HarnessSuite`. The command line above runs the suite for configurations named
on the command line, to see what a night would do.

**What is tested.** Every active tenant version extends one floor version and some packs. The
M2-08 corpus (:mod:`redteam.run`: prompt injection and tenant isolation, benign payloads) is run
**once per distinct configuration**, on a **synthetic** tenant that extends exactly that floor and
those packs, through the same engine path as production (redaction, renderer, gateway, fusion). No
tenant's data is read: only which floor and packs its active bundle names. The result is recorded
for every tenant version that has the configuration (``nightly_redteam_results``, class B). A
tenant's own rules and overrides are not part of it; because a tenant can only **lower** a pack
rule's thresholds and never edit its text, the platform layers' recall is the floor of the
tenant's.

**What pages.** A floor rule's ``block_at`` recall more than one (row, draw) cell below (i) the
previous tested night of the same configuration or (ii) the release baseline
(``redteam/baseline.json``, or ``baseline.fake.json`` for a dry run; only for the floor version the
baseline measured), or a model-independent defence failing, is a **regression**: a page, one per
configuration per day. A night's run uses the baseline's nonce seed and draws, so the inputs are
identical every night and a change is the model's or the stack's, not the nonces'.

**The nightly ceiling and fairness.** Live runs are held to the red_team allowance (about 5,000
requests a day at Tier 1) by ``call_budget``: configurations are taken **never-tested first, then
the oldest-tested first**, until the next one would pass the budget; the rest are recorded
``refused`` / ``skipped_over_budget`` and go first the next night. A configuration that has gone
more than seven nights without a tested result pages (``redteam_stale``). A configuration newly made
active has no tested result, so it jumps the queue.

**Dry by default; live behind the same gates as ``calibration.pack_live``.** Without ``--live`` the
model is the engine's own fake (an oracle: recall 1.0 by construction, so a dry run proves the
plumbing, the comparison and the paging). A live run needs ``--live``, the environment variable
``GUARDRAILS_LIVE_REDTEAM=m5-05-nightly``, ``--max-tokens`` and ``--max-provider-calls``, and the
maintainer's explicit approval. **Never sent:** a corpus row that fails the harm filter
(the whole run is refused, :func:`redteam.run.load_corpus`), a golden row of any pack (the corpus is
the only input), the responsible-AI pack's ``d__harm_facilitation`` rule (opted out of the synthetic
bundle and refused if it would still compile in), a pack whose own text trips the harm tripwire
(responsible-AI's classifier questions excepted, decided). **The first provider refusal ends the
whole night**, and the key is never printed.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import logging
import os
import re
import sys
import tempfile
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Protocol

from calibration.engine_path import (
    EngineRunner,
    EngineSetup,
    SeededNonces,
    calibration_engine,
    direct_setup,
    preflight,
    project_key_env,
    row_token_estimates,
    run_engine_path,
    tool_registries,
)
from calibration.pack_live import default_env_file, load_api_key
from calibration.run import (
    REDACTION_APPLIED,
    ProviderBlockStop,
    StopRun,
    _read,
    refuse_harm_facilitation,
    sha256_file,
)

from guardrail_engine.gateway.sinks import (
    ALERT_REDTEAM_QUARANTINED,
    ALERT_REDTEAM_REGRESSION,
    ALERT_REDTEAM_RUN_FAILED,
    ALERT_REDTEAM_STALE,
    ALERT_REDTEAM_UNASSIGNED,
    Alert,
    AlertSeverity,
    AlertSink,
)
from guardrail_engine.nightly.model import (
    CORPUS_HOLD_KEY,
    MAX_REGRESSIONS,
    ROW_KEY_PREFIX,
    NightlyResult,
    QuarantineEvent,
    config_key,
    row_key,
)
from guardrail_engine.nightly.store import (
    ActiveBundleSource,
    InMemoryQuarantine,
    NightlyResultReader,
    NightlyResultSink,
    QuarantineStore,
)
from guardrail_engine.policy.document import EXTENDS_REF_PATTERN
from redteam import run as rt

logger = logging.getLogger(__name__)

LIVE_ENV, LIVE_TOKEN = "GUARDRAILS_LIVE_REDTEAM", "m5-05-nightly"
STALE_NIGHTS = 7
OPT_OUT = {
    "rule": "d__harm_facilitation",
    "enabled": False,
    "justification": "the nightly red-team never sends this rule's question",
}
"""The responsible-AI pack's per-rule opt-out (R4.6), put in the synthetic bundle."""
SKIPPED = "skipped_over_budget"
QUARANTINED = "quarantined"
"""The configuration's last run hit a provider refusal; it is not sent until an operator
clears it."""
NIGHT_HALTED = "night_halted_after_refusal"
"""A configuration hit a provider refusal tonight, so nothing else is sent tonight (Google
is the same provider whatever the project). Those configurations are untested, so they go first
tomorrow."""
CORPUS_HELD = "corpus_held_after_refusal"
"""A provider refusal arrived with no usable row id, so the whole live corpus is held
(:data:`~guardrail_engine.nightly.model.CORPUS_HOLD_KEY`) and nothing is sent until an operator
clears it."""
UNASSIGNED = "regulated_without_project"
"""A regulated tenant has no dedicated project (production, staging): not run."""
GATED_ENVIRONMENTS = frozenset({"production", "staging"})
QUARANTINE_REASON = "provider_refusal"
ALL_ROWS = "*"
"""How a corpus-wide hold reads in ``held_rows``: every row."""
NOTE_LIMIT = 200
"""The results table's ``note`` column (051)."""


def _held(rows: set[str], corpus_held: bool) -> list[str]:
    """The held corpus rows, in order, for a result's note; ``*`` is the whole corpus."""
    return sorted(rows) + ([ALL_ROWS] if corpus_held else [])


# --------------------------------------------------------------------------- configurations
@dataclass(frozen=True)
class Config:
    floor_ref: str
    pack_refs: tuple[str, ...]
    project: str = ""
    """The Gemini project the tenants are served from (M5-06): a regulated tenant's dedicated
    project, whose quota, spend and key are its own, or ``""`` for the shared pool. A
    configuration is run on **its project**, so a regulated tenant's night is spent on its own
    allowance and reported under its own label."""
    tenants: tuple[tuple[str, int], ...] = field(default=(), compare=False)
    """(tenant id, bundle version) of every active version that has this configuration."""
    unassigned: bool = False
    """Regulated tenants with no dedicated project, never run: a marker for the record
    (its key is its own, so it is never mistaken for the shared pool's configuration)."""

    @property
    def key(self) -> str:
        key = config_key(self.floor_ref, self.pack_refs, self.project)
        return f"unassigned|{key}" if self.unassigned else key

    @property
    def floor_version(self) -> int:
        m = EXTENDS_REF_PATTERN.fullmatch(self.floor_ref)
        assert m is not None
        return int(m.group(3))


def group(
    bundles: Sequence[Any],
    active_tenants: set[str] | None = None,
    projects: Mapping[str, str] | None = None,
) -> list[Config]:
    """One :class:`Config` per distinct (project, floor, packs), with the tenant versions that
    have it. A tenant the directory no longer lists as active is left out; ``projects`` maps a
    tenant id to its dedicated project (a tenant not in it is on the shared pool)."""
    found: dict[tuple[str, str, tuple[str, ...]], list[tuple[str, int]]] = {}
    for b in bundles:
        if active_tenants is not None and b.tenant_id not in active_tenants:
            continue
        project = (projects or {}).get(b.tenant_id, "")
        found.setdefault((project, b.floor_ref, tuple(sorted(b.pack_refs))), []).append(
            (b.tenant_id, b.version)
        )
    return [Config(f, p, proj, tuple(sorted(t))) for (proj, f, p), t in sorted(found.items())]


# --------------------------------------------------------------------------- the suite
@dataclass
class SuiteOutcome:
    status: str
    """``done``, ``refused`` (nothing sent, or it can't be judged) or ``stopped``."""
    note: str = ""
    report: dict[str, Any] | None = None
    provider_calls: int = 0
    input_tokens: int = 0
    provider_refusal: bool = False
    """The provider refused a check: the configuration and the refused corpus row are
    held until an operator clears them, and nothing else is sent tonight."""
    refused_row: str = ""
    """The corpus row id the provider refused, or ``""`` when it isn't known."""
    corpus_sha256: str = ""
    """The corpus this run measured, when it left rows out (:func:`effective_corpus`); ``""`` is
    the suite's own."""
    rows: int = 0
    """The rows this run sent, when it left some out; 0 is the suite's own."""


def effective_corpus(corpus_sha256: str, left_out: Sequence[str]) -> str:
    """The identity of a corpus with rows left out: the file's own when none are, else a
    hash of it and the ids, so a night that left a row out is never compared with one that
    didn't."""
    if not left_out:
        return corpus_sha256
    digest = hashlib.sha256(f"{corpus_sha256}|without|{','.join(sorted(left_out))}".encode())
    return f"sha256:{digest.hexdigest()}"


class Suite(Protocol):
    live: bool
    corpus_sha256: str
    draws: int
    rows: int
    nonce_seed: str

    async def run(
        self, config: Config, skip_rows: frozenset[str] = frozenset()
    ) -> SuiteOutcome: ...


def split_ref(ref: str) -> tuple[str, int]:
    m = EXTENDS_REF_PATTERN.fullmatch(ref)
    assert m is not None and m.group(2) is not None
    return m.group(2), int(m.group(3))


class HarnessSuite:
    """The M2-08 harness for one configuration: ``calibration_engine`` with the floor version the
    catalog holds and its packs, the corpus as :func:`redteam.run.load_corpus` loads it, seeded
    nonces (the baseline's), the red_team usage class."""

    def __init__(
        self,
        *,
        catalog: Any,
        corpus: Path,
        root: Path = rt.ROOT,
        live: bool = False,
        draws: int | None = None,
        nonce_seed: str | None = None,
        max_tokens: int | None = None,
        max_provider_calls: int | None = None,
        env_file: Path | None = None,
        project_key_envs: Mapping[str, str] | None = None,
        model_factory: Callable[[Sequence[dict[str, Any]]], Any] = rt.OracleModel,
        workdir: Path | None = None,
    ) -> None:
        rt.check_corpus_path(corpus, root)
        self.catalog, self.corpus, self.root, self.live = catalog, corpus, root, live
        self.rows_data = rt.load_corpus(corpus)  # refuses the whole corpus on any harm row
        self.rows = len(self.rows_data)
        self.corpus_sha256 = sha256_file(corpus)
        baseline = rt.load_baseline(rt.baseline_path("live" if live else "fake", None, root))
        self.baseline = baseline
        self.draws = draws if draws is not None else (baseline or {}).get("draws", rt.DRAWS)
        self.seed = nonce_seed or (baseline or {}).get("nonce_seed") or rt.new_seed()
        SeededNonces(self.seed)  # validates it
        self.nonce_seed = self.seed
        self.max_tokens, self.max_provider_calls = max_tokens, max_provider_calls
        self.project_key_envs = dict(project_key_envs or {})
        """Dedicated project label -> the NAME of the environment variable that holds its key."""
        self.model_factory = model_factory
        self.workdir = workdir
        self.direct = direct_setup(corpus, root / rt.RULES_REL, root / rt.ADDITIONS_REL)
        self.estimates = row_token_estimates(self.rows_data, self.direct)
        if live:
            self._check_live_gates(env_file)

    def _check_live_gates(self, env_file: Path | None) -> None:
        if os.environ.get(LIVE_ENV) != LIVE_TOKEN:
            raise rt.Refused(f"a live run needs {LIVE_ENV}={LIVE_TOKEN} in the environment")
        if self.max_tokens is None or self.max_provider_calls is None:
            raise rt.Refused("a live run needs --max-tokens and --max-provider-calls")
        if not load_api_key(env_file or default_env_file()):
            raise rt.Refused("GEMINI_API_KEY is not set (environment or --env-file)")

    def planned_checks(self) -> int:
        return self.rows * self.draws

    def _floor_doc(self, config: Config) -> dict[str, Any] | None:
        floor = self.catalog.floor(config.floor_version)
        return None if floor is None else dict(floor.document)

    def _packs(self, config: Config) -> list[Any] | None:
        packs = [self.catalog.pack(*split_ref(r)) for r in config.pack_refs]
        return None if any(p is None for p in packs) else packs

    @staticmethod
    def overrides_for(packs: Sequence[Any]) -> list[dict[str, Any]]:
        """Opt ``d__harm_facilitation`` out of the synthetic bundle when the responsible-AI pack
        is in it (R4.6): its question is never sent by this job."""
        for p in packs:
            if any(r.key == OPT_OUT["rule"] for r in p._content.rules):
                return [dict(OPT_OUT)]
        return []

    def live_pack_problems(self, packs: Sequence[Any]) -> list[str]:
        from guardrail_engine.admin.vocabulary import strings_tripwire

        out = []
        for p in packs:
            if p.name == "responsible_ai":  # its classifier questions name harms (sendable)
                continue
            texts: list[str] = []

            def walk(node: Any, texts: list[str] = texts) -> None:
                if isinstance(node, str):
                    texts.append(node)
                elif isinstance(node, Mapping):
                    for v in node.values():
                        walk(v)
                elif isinstance(node, list):
                    for v in node:
                        walk(v)

            walk(p.document)
            if strings_tripwire(*texts):
                out.append(f"{p.ref}: the pack's own text trips the harm tripwire")
        return out

    async def run(self, config: Config, skip_rows: frozenset[str] = frozenset()) -> SuiteOutcome:
        """One configuration's night. ``skip_rows`` are corpus rows the provider has refused (held
        until an operator clears them): they are left out of the run, and the outcome names the
        corpus it measured, so it is only compared with a night that left out the same rows."""
        left_out = sorted(skip_rows & {str(r["id"]) for r in self.rows_data})
        rows = [r for r in self.rows_data if str(r["id"]) not in skip_rows]
        if not rows:
            return SuiteOutcome("refused", "no_rows_left")
        corpus = effective_corpus(self.corpus_sha256, left_out)
        floor_doc, packs = self._floor_doc(config), self._packs(config)
        if floor_doc is None or packs is None:
            return SuiteOutcome("refused", "catalog_missing")
        overrides = self.overrides_for(packs)
        key_env = self.project_key_envs.get(config.project) or project_key_env(config.project)
        if self.live and config.project and not os.environ.get(key_env, "").strip():
            return SuiteOutcome("refused", "project_key_missing")  # the name is never echoed
        if self.live and self.live_pack_problems(packs):
            return SuiteOutcome("refused", "pack_text_refused")
        checks = len(rows) * self.draws
        ceiling_calls = self.max_provider_calls
        if self.live and ceiling_calls is not None and checks > ceiling_calls:
            return SuiteOutcome("refused", "over_the_call_ceiling")
        flagged = preflight(rows, self.direct)
        if any(flagged.values()):
            return SuiteOutcome("refused", "example_over_a_limit")
        try:
            tool_registries(rows)
        except StopRun:
            return SuiteOutcome("refused", "tool_conflict")
        try:  # the compiled questions: the harm-facilitation rule must not ride along
            refuse_harm_facilitation(compiled_questions(config, floor_doc, packs, overrides))
        except StopRun:
            return SuiteOutcome("refused", "harm_facilitation_question")
        model = None if self.live else self.model_factory(rows)
        setup = EngineSetup(
            floor_doc=floor_doc, files={"corpus": self.corpus_sha256}, validation=False,
            max_input_tokens=None,
        )  # fmt: skip
        nonces = SeededNonces(self.seed)
        min_interval = rt.live_interval_s(self.estimates, rows) if self.live else 0.0
        started = {
            "mode": "live" if self.live else "fake", "files": {"corpus": self.corpus_sha256},
            "draws": self.draws, "nonce_seed": self.seed,
        }  # fmt: skip
        tmp_dir = tempfile.TemporaryDirectory(dir=self.workdir)
        out = Path(tmp_dir.name) / "run.jsonl"
        runner: EngineRunner | None = None
        try:
            async with calibration_engine(
                setup,
                rows,
                model=model,
                nonces=nonces,
                packs=packs,
                overrides=overrides,
                project=config.project,
                key_env=key_env if config.project else None,
            ) as (engine, verifier):
                runner = EngineRunner(
                    out=out, engine=engine, verifier=verifier, nonces=nonces,
                    token_ceiling=self.max_tokens if self.live else None,
                    token_estimates=self.estimates,
                    provider_call_ceiling=ceiling_calls if self.live else None,
                    usage_class="red_team", min_interval_s=min_interval,
                )  # fmt: skip
                runner.write({"type": "run_started", "redaction": REDACTION_APPLIED, **started})
                try:
                    await run_engine_path(runner, rows, [], draws=self.draws, log=lambda s: None)
                except ProviderBlockStop:
                    return SuiteOutcome(
                        "stopped", "provider_refusal", provider_calls=runner.provider_calls_used,
                        input_tokens=runner.tokens_used, provider_refusal=True,
                        refused_row=refused_row(out), corpus_sha256=corpus, rows=len(rows),
                    )  # fmt: skip
                except StopRun:
                    return SuiteOutcome(
                        "stopped", stop_reason(out), provider_calls=runner.provider_calls_used,
                        input_tokens=runner.tokens_used, corpus_sha256=corpus, rows=len(rows),
                    )  # fmt: skip
            records = _read(out)
            floor_keys = {r["key"] for r in floor_doc["rules"]}
            applicable = [{**r, "fires": [k for k in r["fires"] if k in floor_keys]} for r in rows]
            texts = (
                [((row or {}).get("id", "?"), t) for t in model.sent
                 for row in [model.row_for(t)]]
                if isinstance(model, rt.OracleModel)
                else rt.rendered_texts(rows, self.direct)
            )  # fmt: skip
            problems_ = rt.structural_problems(rows, texts)
            report = rt.build_report(applicable, records, started, floor_doc, problems_, len(texts))
            return SuiteOutcome(
                "done", report=report,
                provider_calls=runner.provider_calls_used if runner else 0,
                input_tokens=runner.tokens_used if runner else 0,
                corpus_sha256=corpus, rows=len(rows),
            )  # fmt: skip
        except Exception as exc:  # a bundle that doesn't compile, a catalog that can't build
            logger.warning("nightly red-team configuration %s: %s", config.key, type(exc).__name__)
            return SuiteOutcome("refused", "run_failed")
        finally:
            tmp_dir.cleanup()


def compiled_questions(
    config: Config, floor_doc: Mapping[str, Any], packs: Sequence[Any], overrides: Sequence[Any]
) -> dict[str, dict[str, Any]]:
    """The questions the synthetic tenant's bundle compiles to, per guard point."""
    from calibration.engine_path import floor_only_bundle

    from guardrail_engine.policy import (
        InMemoryCatalog,
        InMemoryToolRegistry,
        PlatformSettings,
        PolicyCompiler,
        TenantAttributes,
    )
    from guardrail_engine.policy.catalog import FloorVersion

    floor = FloorVersion.from_document(dict(floor_doc))
    compiler = PolicyCompiler(
        InMemoryCatalog(floors=[floor], packs=list(packs)),
        InMemoryToolRegistry(),
        PlatformSettings(min_floor_version=floor.version),
    )
    bundle = floor_only_bundle("t_nightly", floor.version, None, config.pack_refs, overrides)
    policy = compiler.compile(bundle, TenantAttributes(tenant_id="t_nightly"))
    return {gp: dict(c.questions) for gp, c in policy.guard_points.items()}


ROW_ID = re.compile(r"[A-Za-z0-9_.:-]{1,80}")


def refused_row(path: Path) -> str:
    """The corpus row the run stopped on (``run_stopped.example_id``), or ``""`` when it isn't a
    plain id."""
    stops = [r for r in _read(path) if r.get("type") == "run_stopped" and r.get("example_id")]
    found = str(stops[-1]["example_id"]) if stops else ""
    return found if ROW_ID.fullmatch(found) else ""


def stop_reason(path: Path) -> str:
    stops = [r for r in _read(path) if r.get("type") == "run_stopped"]
    return str(stops[-1].get("reason", "stopped")) if stops else "stopped"


# --------------------------------------------------------------------------- the comparison
def compare(
    report: Mapping[str, Any],
    previous: NightlyResult | None,
    baseline: Mapping[str, Any] | None,
    corpus_sha256: str,
    draws: int,
    floor_version: int,
    nonce_seed: str = "",
) -> list[dict[str, Any]]:
    """The regressions of one finished run: a floor rule's block_at recall more than
    :data:`redteam.run.TOLERANCE_CELLS` cells below the previous tested night's and below the
    release baseline's (only when they measured the same corpus, draws and nonce seed (a
    different seed is different inputs, so it is not a like-for-like night) and, for the baseline,
    the same floor version), and a model-independent defence that failed."""
    found: list[dict[str, Any]] = []
    if report["structure"]["violations"]:
        found.append({"defence": len(report["structure"]["violations"]), "vs": "defences"})
    if (
        previous is not None
        and previous.corpus_sha256 == corpus_sha256
        and previous.draws == draws
        and previous.nonce_seed == nonce_seed
    ):
        found += [
            {**d, "vs": "previous"}
            for d in rt.drops({"block_recall": previous.block_recall}, report)
        ]
    if (
        baseline is not None
        and baseline.get("corpus_sha256") == corpus_sha256
        and baseline.get("draws") == draws
        and baseline.get("nonce_seed") == nonce_seed
        and baseline.get("floor_version") == floor_version
    ):
        found += [{**d, "vs": "baseline"} for d in rt.drops(baseline, report)]
    return found[:MAX_REGRESSIONS]


def order_configs(configs: Sequence[Config], dates: Mapping[str, Any]) -> list[Config]:
    """Never-tested configurations first (a configuration newly made active jumps the queue),
    then the oldest-tested first; ties by key, so the order is the same on any replica."""
    far = datetime.max.replace(tzinfo=UTC)

    def rank(c: Config) -> tuple[int, datetime, str]:
        last = dates[c.key].last_tested
        return (0 if last is None else 1, last or far, c.key)

    return sorted(configs, key=rank)


# --------------------------------------------------------------------------- the job
@dataclass
class ProjectNight:
    """One Gemini project's night (M5-06): the shared pool is ``""``, a regulated tenant's
    dedicated project is its label. Each project has its own allowance and its own bill."""

    tested: int = 0
    skipped: int = 0
    failed: int = 0
    regressions: int = 0
    provider_calls: int = 0
    input_tokens: int = 0


@dataclass
class NightlyReport:
    run_id: str
    at: datetime
    tested: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    regressions: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    failed: dict[str, str] = field(default_factory=dict)
    stale: list[str] = field(default_factory=list)
    results: int = 0
    halted: bool = False
    """A provider refusal ended the night: nothing else was sent."""
    held_rows: list[str] = field(default_factory=list)
    """Corpus rows the provider refused tonight, held until an operator clears them."""
    quarantined: list[str] = field(default_factory=list)
    """Configurations skipped because they are quarantined, and those quarantined tonight."""
    unassigned: list[str] = field(default_factory=list)
    """Regulated tenants with no dedicated project, not run (production and staging)."""
    provider_calls: int = 0
    input_tokens: int = 0
    by_project: dict[str, ProjectNight] = field(default_factory=dict)
    """Per Gemini project (M5-06): ``""`` is the shared pool. Spend is per project."""


class NightlyJob:
    def __init__(
        self,
        *,
        bundles: ActiveBundleSource,
        directory: Any,
        results: NightlyResultReader,
        sink: NightlyResultSink,
        alerts: AlertSink,
        suite: Suite,
        baseline: Mapping[str, Any] | None,
        clock: Callable[[], datetime],
        call_budget: int | None = None,
        project_budgets: Mapping[str, int] | None = None,
        stale_nights: int = STALE_NIGHTS,
        quarantine: QuarantineStore | None = None,
        environment: str = "production",
        run_id_factory: Callable[[], str] = lambda: uuid.uuid4().hex,
    ) -> None:
        self._bundles, self._directory = bundles, directory
        self._results, self._sink, self._alerts = results, sink, alerts
        self._suite, self._baseline, self._clock = suite, baseline, clock
        self._budget, self._stale_nights = call_budget, stale_nights
        self._project_budgets = dict(project_budgets or {})
        if quarantine is None and suite.live:
            raise ValueError("a live night needs a quarantine store: a refusal must be remembered")
        self._quarantine = quarantine if quarantine is not None else InMemoryQuarantine()
        self._environment = environment
        self._run_id = run_id_factory

    async def run_once(self) -> NightlyReport:
        now = self._clock()
        if now.tzinfo is None:
            raise ValueError("the clock must return an aware datetime")
        report = NightlyReport(self._run_id(), now)
        mode = "live" if self._suite.live else "fake"
        active = set(await self._directory.tenant_ids())
        bundles = await self._bundles.active_bundles()
        projects, unassigned = await self._projects(bundles, active)
        configs = group(bundles, active - unassigned, projects)
        dates = {c.key: await self._results.config_dates(c.key, mode) for c in configs}
        held = await self._quarantine.quarantined(mode)
        corpus_held = CORPUS_HOLD_KEY in held  # a refusal with no row id holds it all
        held_rows = {
            k[len(ROW_KEY_PREFIX) :]
            for k in held
            if k.startswith(ROW_KEY_PREFIX) and k != CORPUS_HOLD_KEY
        }
        open_holds = sorted(k for k in held if k.startswith(ROW_KEY_PREFIX))
        spent: dict[str, int] = {}
        halted = False
        for config in order_configs(configs, dates):
            night = report.by_project.setdefault(config.project, ProjectNight())
            budget = self._project_budgets.get(config.project, self._budget)
            planned = self._suite.draws * self._suite.rows
            over = budget is not None and spent.get(config.project, 0) + planned > budget
            if config.key in held:  # never re-sent until an operator clears it
                report.quarantined.append(config.key)
                night.skipped += 1
                await self._record(
                    config, report, SuiteOutcome("refused", QUARANTINED), None, [],
                    _held(held_rows, corpus_held),
                )  # fmt: skip
                continue
            if corpus_held and not halted:  # no row can be told from another, so none is sent
                report.quarantined.append(config.key)
                night.skipped += 1
                await self._record(
                    config, report, SuiteOutcome("refused", CORPUS_HELD), None, [],
                    _held(held_rows, corpus_held),
                )  # fmt: skip
                continue
            if halted or over:
                report.skipped.append(config.key)
                night.skipped += 1
                note = NIGHT_HALTED if halted else SKIPPED
                await self._record(
                    config, report, SuiteOutcome("refused", note), None, [],
                    _held(held_rows, corpus_held),
                )  # fmt: skip
                continue
            outcome = await self._suite.run(config, frozenset(held_rows))
            spent[config.project] = spent.get(config.project, 0) + (outcome.provider_calls or 0)
            report.provider_calls += outcome.provider_calls
            report.input_tokens += outcome.input_tokens
            night.provider_calls += outcome.provider_calls
            night.input_tokens += outcome.input_tokens
            regressions: list[dict[str, Any]] = []
            if outcome.status == "done" and outcome.report is not None:
                previous = await self._results.previous_for_config(config.key, mode, now)
                regressions = compare(
                    outcome.report, previous, self._baseline,
                    outcome.corpus_sha256 or self._suite.corpus_sha256,
                    self._suite.draws, config.floor_version, self._suite.nonce_seed,
                )  # fmt: skip
                if outcome.report["incomplete"] or outcome.report["excluded_cells"]:
                    outcome = SuiteOutcome(
                        "refused", "incomplete", provider_calls=outcome.provider_calls,
                        input_tokens=outcome.input_tokens,
                    )  # fmt: skip
                    regressions = []
            if outcome.status == "done":
                report.tested.append(config.key)
                night.tested += 1
            else:
                report.failed[config.key] = outcome.note
                night.failed += 1
            if regressions:
                report.regressions[config.key] = regressions
                night.regressions += 1
            stop = False
            if outcome.provider_refusal:
                # The hold and the page come first, then the result row: a failed write of the
                # row must never leave a refusal unremembered. Nothing else is sent
                # tonight, in any project, and the refused row is held across every
                # configuration.
                halted = True
                report.halted = True
                report.quarantined.append(config.key)
                if outcome.refused_row:
                    held_rows.add(outcome.refused_row)
                    report.held_rows.append(outcome.refused_row)
                else:  # fail closed, hold the whole corpus until an operator clears it
                    corpus_held = True
                    report.held_rows.append(ALL_ROWS)
                stop = not await self._hold(config, outcome.refused_row, report, now)
            try:
                await self._record(
                    config, report, outcome, outcome.report, regressions,
                    _held(held_rows, corpus_held),
                )  # fmt: skip
            except Exception:
                if not outcome.provider_refusal:
                    raise
                logger.exception("a nightly red-team refusal's result could not be written")
                stop = True  # the hold stands; the night stops
            if stop:
                break  # not recorded: nothing else is sent tonight
        await self._record_unassigned(
            [b for b in bundles if b.tenant_id in unassigned], report,
            _held(held_rows, corpus_held),
        )  # fmt: skip
        await self._repage_holds(open_holds, held, now)
        await self._page(report, configs, dates, now)
        return report

    async def _repage_holds(
        self, keys: Sequence[str], held: Mapping[str, QuarantineEvent], now: datetime
    ) -> None:
        """A corpus hold that was open when the night began pages again, once a day (the
        day is in the dedupe key), until an operator clears it: a hold nobody clears must not
        quietly suspend the baseline check. A hold put tonight was paged by :meth:`_hold`."""
        day = now.date().isoformat()
        for key in keys:
            event = held[key]
            what = (
                "the whole live corpus"
                if key == CORPUS_HOLD_KEY
                else f"corpus row {key[len(ROW_KEY_PREFIX) :]}"
            )
            await self._emit(
                Alert(
                    severity=AlertSeverity.PAGE,
                    kind=ALERT_REDTEAM_QUARANTINED,
                    message=(
                        f"{what} is still held in the nightly red-team quarantine (since "
                        f"{event.at.date().isoformat()}) after a provider refusal: until a "
                        f"platform operator clears it, nights leave it out and are not compared "
                        f"with the release baseline"
                    ),
                    key_id="",
                    tenant_id="",
                    guard_point="",
                    reason=QUARANTINE_REASON,
                    dedupe_key=f"redteam_quarantined:{key}:{day}",
                )
            )

    async def _hold(
        self, config: Config, row_id: str, report: NightlyReport, now: datetime
    ) -> bool:
        """Hold the refused row (across every configuration and project) and the configuration,
        and page at once. False when either could not be recorded (the night then stops: a
        refusal that is not remembered would be sent again)."""
        mode = "live" if self._suite.live else "fake"
        events = [
            QuarantineEvent(
                config_key=config.key, mode=mode, project=config.project, action="quarantine",
                at=now, actor="nightly", operator=False, reason=QUARANTINE_REASON,
                run_id=report.run_id, row_id=row_id,
            )
        ]  # fmt: skip
        # No usable row id, so which row to leave out is unknown: hold them all
        held_key = row_key(row_id) if row_id else CORPUS_HOLD_KEY
        events.insert(
            0,
            QuarantineEvent(
                config_key=held_key, mode=mode, project="", action="quarantine",
                at=now, actor="nightly", operator=False, reason=QUARANTINE_REASON,
                run_id=report.run_id, row_id=row_id,
            ),
        )  # fmt: skip
        recorded = True
        for event in events:
            try:
                await self._quarantine.append(event)
            except Exception:
                logger.exception("a nightly red-team quarantine could not be recorded")
                recorded = False
        what = (
            f"corpus row {row_id}"
            if row_id
            else "a corpus row (its id was not available, so the whole live corpus is held)"
        )
        await self._emit(
            Alert(
                severity=AlertSeverity.PAGE,
                kind=ALERT_REDTEAM_QUARANTINED,
                message=(
                    f"the provider refused {what} in the nightly red-team for {config.key}"
                    f"{_on(config)}: the configuration and the row are held and are not sent "
                    f"again until a platform operator clears them; nothing else is sent tonight"
                    + ("" if recorded else " (THE HOLD COULD NOT BE RECORDED: the night stopped)")
                ),
                key_id="",
                tenant_id="",
                guard_point="",
                reason=QUARANTINE_REASON,
                dedupe_key=f"redteam_quarantined:{config.key}",
            )
        )
        return recorded

    async def _projects(
        self, bundles: Sequence[Any], active: set[str]
    ) -> tuple[dict[str, str], set[str]]:
        """Each active tenant's dedicated project (M5-06), from the directory entry the Guard
        Service routes by (a tenant with none is on the shared pool), and, in production and
        staging, the regulated tenants with **no** project: they are left out of the
        night, never folded into the shared pool's run."""
        found: dict[str, str] = {}
        unassigned: set[str] = set()
        for tenant_id in sorted({b.tenant_id for b in bundles} & active):
            entry = await self._directory.get(tenant_id)
            attributes = getattr(entry, "attributes", entry)
            project = getattr(attributes, "project", None)
            if project:
                found[tenant_id] = project
            elif self._environment in GATED_ENVIRONMENTS and getattr(
                attributes, "regulated", False
            ):
                unassigned.add(tenant_id)
        return found, unassigned

    def _held_note(self, outcome: SuiteOutcome, held: Sequence[str]) -> str:
        """The note of a result produced while a corpus row is held. It says which rows
        and whether the release baseline was compared, so a hold nobody clears cannot suspend
        the baseline check unseen. It uses the existing ``note`` column (200 characters): the
        baseline flag comes first, the rows are cut to fit."""
        compared = (
            outcome.status == "done"
            and self._baseline is not None
            and outcome.corpus_sha256 in ("", self._suite.corpus_sha256)
        )
        head = f"{outcome.note}; " if outcome.note else ""
        tail = f"baseline_compared: {str(compared).lower()}; held_rows: "
        room = NOTE_LIMIT - len(head) - len(tail)
        shown = list(held)
        while shown:
            rows = f"[{', '.join(shown)}" + (
                f", +{len(held) - len(shown)} more]" if len(shown) < len(held) else "]"
            )
            if len(rows) <= room:
                return head + tail + rows
            shown.pop()
        return (head + tail + f"[+{len(held)} more]")[:NOTE_LIMIT]

    async def _record_unassigned(
        self, bundles: Sequence[Any], report: NightlyReport, held: Sequence[str] = ()
    ) -> None:
        """A refused result for each regulated tenant version that has no dedicated project."""
        rows = []
        for b in bundles:
            if b.tenant_id not in report.unassigned:
                report.unassigned.append(b.tenant_id)
            cfg = Config(b.floor_ref, tuple(sorted(b.pack_refs)), "", ((b.tenant_id, b.version),))
            rows.append(
                NightlyResult(
                    tenant_id=b.tenant_id,
                    bundle_version=b.version,
                    project="",
                    nonce_seed=self._suite.nonce_seed,
                    config_key=Config(cfg.floor_ref, cfg.pack_refs, "", (), True).key,
                    run_id=report.run_id,
                    run_at=report.at,
                    mode="live" if self._suite.live else "fake",
                    floor_version=cfg.floor_version,
                    packs=cfg.pack_refs,
                    corpus_sha256=self._suite.corpus_sha256,
                    draws=self._suite.draws,
                    rows=self._suite.rows,
                    status="refused",
                    regressions=(),
                    block_recall={},
                    false_act={"overall": {}},
                    structure_violations=0,
                    provider_calls=0,
                    input_tokens=0,
                    note=UNASSIGNED
                    if not held
                    else self._held_note(SuiteOutcome("refused", UNASSIGNED), held),
                )
            )
        if rows:
            await self._sink.append_many(rows)
            report.results += len(rows)

    def _skipped(self) -> SuiteOutcome:
        return SuiteOutcome("refused", SKIPPED)

    async def _record(
        self,
        config: Config,
        report: NightlyReport,
        outcome: SuiteOutcome,
        suite_report: Mapping[str, Any] | None,
        regressions: list[dict[str, Any]],
        held: Sequence[str] = (),
    ) -> None:
        if outcome.status == "done":
            status = "regression" if regressions else "pass"
        else:
            status = "stopped" if outcome.status == "stopped" else "refused"
        structure = (suite_report or {}).get("structure", {}).get("violations", {})
        rows = [
            NightlyResult(
                tenant_id=tenant_id,
                bundle_version=version,
                project=config.project,
                nonce_seed=self._suite.nonce_seed,
                config_key=config.key,
                run_id=report.run_id,
                run_at=report.at,
                mode="live" if self._suite.live else "fake",
                floor_version=config.floor_version,
                packs=config.pack_refs,
                corpus_sha256=outcome.corpus_sha256 or self._suite.corpus_sha256,
                draws=self._suite.draws,
                rows=outcome.rows or self._suite.rows,
                status=status,
                regressions=tuple(regressions),
                block_recall={
                    k: {"hits": v["hits"], "cells": v["cells"]}
                    for k, v in (suite_report or {}).get("block_recall", {}).items()
                },
                false_act={"overall": (suite_report or {}).get("false_act", {}).get("overall", {})},
                structure_violations=len(structure),
                provider_calls=outcome.provider_calls,
                input_tokens=outcome.input_tokens,
                note=outcome.note[:200] if not held else self._held_note(outcome, held),
            )
            for tenant_id, version in config.tenants
        ]
        await self._sink.append_many(rows)
        report.results += len(rows)

    async def _emit(self, alert: Alert) -> None:
        try:
            await asyncio.to_thread(self._alerts.emit, alert)
        except Exception:
            logger.exception("a nightly red-team alert could not be raised")

    async def _page(
        self,
        report: NightlyReport,
        configs: Sequence[Config],
        dates: Mapping[str, Any],
        now: datetime,
    ) -> None:
        day = now.date().isoformat()
        by_key = {c.key: c for c in configs}
        for key, regressions in sorted(report.regressions.items()):
            rules = sorted({r.get("rule", "defences") for r in regressions})
            names = ", ".join(t for t, _ in by_key[key].tenants[:20])
            await self._emit(
                Alert(
                    severity=AlertSeverity.PAGE,
                    kind=ALERT_REDTEAM_REGRESSION,
                    message=(
                        f"the nightly red-team found a recall regression on {key}"
                        f"{_on(by_key[key])}: "
                        f"{', '.join(rules)} ({len(by_key[key].tenants)} tenant version(s): "
                        f"{names})"
                    ),
                    key_id="",
                    tenant_id="",
                    guard_point="",
                    reason="regression",
                    dedupe_key=f"redteam_regression:{key}:{day}",
                )
            )
        for key, why in sorted(report.failed.items()):
            if why == SKIPPED:
                continue
            await self._emit(
                Alert(
                    severity=AlertSeverity.WARNING,
                    kind=ALERT_REDTEAM_RUN_FAILED,
                    message=(
                        f"the nightly red-team run for {key}{_on(by_key[key])} did not finish: "
                        f"{why}"
                    ),
                    key_id="",
                    tenant_id="",
                    guard_point="",
                    reason=why[:64],
                    dedupe_key=f"redteam_run_failed:{key}:{day}",
                )
            )
        for tenant_id in sorted(report.unassigned):
            await self._emit(
                Alert(
                    severity=AlertSeverity.PAGE,
                    kind=ALERT_REDTEAM_UNASSIGNED,
                    message=(
                        f"the regulated tenant {tenant_id} has no dedicated Gemini project, so "
                        f"it is not red-teamed tonight (it is never folded into the shared "
                        f"pool's run): assign a project"
                    ),
                    key_id="",
                    tenant_id="",
                    guard_point="",
                    reason=UNASSIGNED,
                    dedupe_key=f"redteam_unassigned:{tenant_id}:{day}",
                )
            )
        limit = timedelta(days=self._stale_nights)
        for config in configs:
            d = dates[config.key]
            if config.key in report.tested:
                continue
            since = d.last_tested or d.first_seen
            if since is not None and now - since > limit:
                report.stale.append(config.key)
                await self._emit(
                    Alert(
                        severity=AlertSeverity.PAGE,
                        kind=ALERT_REDTEAM_STALE,
                        message=(
                            f"the configuration {config.key}{_on(config)} has had no tested "
                            f"nightly red-team "
                            f"result since {since.date().isoformat()} (more than "
                            f"{self._stale_nights} nights)"
                        ),
                        key_id="",
                        tenant_id="",
                        guard_point="",
                        reason="stale",
                        dedupe_key=f"redteam_stale:{config.key}:{day}",
                    )
                )


def _on(config: Config) -> str:
    return f" (Gemini project {config.project})" if config.project else ""


# --------------------------------------------------------------------------- estimate and CLI
def estimate(suite: HarnessSuite, config: Config) -> dict[str, Any]:
    """What one configuration costs a night: the corpus at the baseline's draws, with the
    questions the configuration's floor and packs add to every check, by the engine's own token
    estimator (real usage has run 0.9 to 1.15 times it). Needs the configuration in the catalog."""
    from calibration.run import Setup

    checks = suite.planned_checks()
    out: dict[str, Any] = {
        "config": config.key, "checks": checks, "worst_case_provider_calls": checks * 2,
    }  # fmt: skip
    floor_doc, packs = suite._floor_doc(config), suite._packs(config)
    if floor_doc is None or packs is None:
        return out | {"input_tokens": None, "note": "catalog_missing"}
    questions = compiled_questions(config, floor_doc, packs, suite.overrides_for(packs))
    shaped = Setup(
        floor_doc={}, questions=questions, thresholds={}, rule_gps={},
        max_content_tokens=suite.direct.max_content_tokens, files={},
    )  # fmt: skip
    tokens = sum(row_token_estimates(suite.rows_data, shaped).values()) * suite.draws
    price = _price()
    return out | {"input_tokens": tokens, "cost_usd": round(tokens / 1_000_000 * price, 4)}


def _price() -> float:
    from guardrail_engine.gateway import TokenRateConfig

    return TokenRateConfig().price_per_million_input_tokens_usd


def repo_catalog(root: Path) -> Any:
    """The catalog of this repository's own files: floor@1 (``floor/rules.json``), floor@2 (with
    ``floor/next/additions.json``) and every pack under ``packs/``. For the command line and
    tests; a deployment passes the catalog its engine uses."""
    from calibration.run import assemble_floor

    from guardrail_engine.floor_file import load_floor_file
    from guardrail_engine.pack_file import load_pack_file
    from guardrail_engine.policy import InMemoryCatalog
    from guardrail_engine.policy.catalog import FloorVersion

    floors = [
        load_floor_file(root / rt.RULES_REL),
        FloorVersion.from_document(assemble_floor(root / rt.RULES_REL, root / rt.ADDITIONS_REL)),
    ]
    packs = [load_pack_file(f) for f in sorted((root / "packs").glob("*/pack*.json"))]
    return InMemoryCatalog(floors=floors, packs=packs)


def parse_config(text: str) -> Config:
    """``[<project>|]platform/floor@N[,domain/<pack>@<n>...]``."""
    project, _, text = text.rpartition("|")
    if project and not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,39}", project):
        raise rt.Refused(f"--config: {project!r} is not a project label")
    refs = [r.strip() for r in text.split(",") if r.strip()]
    floors = [r for r in refs if r.startswith("platform/floor@")]
    if len(floors) != 1:
        raise rt.Refused(f"--config {text!r}: exactly one platform/floor@N")
    for ref in refs:
        if EXTENDS_REF_PATTERN.fullmatch(ref) is None:
            raise rt.Refused(f"--config {text!r}: {ref!r} is not a floor or pack reference")
    return Config(floors[0], tuple(sorted(r for r in refs if r != floors[0])), project)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("plan", "run"):
        p = sub.add_parser(name)
        p.add_argument("--config", action="append", required=True,
                       help="platform/floor@2[,domain/<pack>@<n>...]")  # fmt: skip
        p.add_argument("--draws", type=int, default=None)
        p.add_argument("--max-tokens", type=int, default=None)
        p.add_argument("--max-provider-calls", type=int, default=None)
        p.add_argument("--live", action="store_true")
        p.add_argument("--env-file", default=None)
    sub.choices["run"].add_argument(
        "--override-quarantine", action="store_true",
        help="send a configuration or corpus row the quarantine holds (a platform operator's call)",
    )  # fmt: skip
    args = parser.parse_args(argv)
    try:
        configs = [parse_config(c) for c in args.config]
        catalog = repo_catalog(rt.ROOT)
        suite = HarnessSuite(
            catalog=catalog, corpus=rt.ROOT / rt.CORPUS_REL, live=args.live, draws=args.draws,
            max_tokens=args.max_tokens, max_provider_calls=args.max_provider_calls,
            env_file=Path(args.env_file) if args.env_file else None,
        )  # fmt: skip
        if args.command == "plan":
            print(json.dumps([estimate(suite, c) for c in configs], indent=1))
            return 0
        if args.live:
            held = [] if args.override_quarantine else asyncio.run(_held_by_quarantine(configs))
            if held:
                raise rt.Refused(
                    "held in quarantine (a provider refusal; an operator clears it): "
                    + ", ".join(held)
                    + "; pass --override-quarantine to send anyway"
                )
            if args.override_quarantine:
                print("--override-quarantine: the quarantine is not consulted", file=sys.stderr)
        out = asyncio.run(_dry_run(suite, configs))
        print(json.dumps(out, indent=1, default=str))
        return 0
    except rt.Refused as e:
        print(str(e), file=sys.stderr)
        return rt.EXIT_REFUSED


async def _held_by_quarantine(configs: Sequence[Config]) -> list[str]:
    """The configurations among ``configs`` that the live quarantine holds, and every held corpus
    row. Reads the table through the operator DSN (``GUARDRAIL_PG_OPERATOR_DSN``); a run
    that can't read it is refused (a guard that is skipped when it can't look is not a guard)."""
    from guardrail_engine.nightly.adapters.postgres import PostgresQuarantine
    from guardrail_engine.store.adapters.postgres import connect_pool

    dsn = os.environ.get("GUARDRAIL_PG_OPERATOR_DSN", "")
    if not dsn:
        raise rt.Refused(
            "a live run reads the quarantine: set GUARDRAIL_PG_OPERATOR_DSN, or pass "
            "--override-quarantine"
        )
    try:
        pool = await connect_pool(dsn)
    except Exception:
        raise rt.Refused("the quarantine could not be read (the connection failed)") from None
    try:
        held = await PostgresQuarantine(pool).quarantined("live")
    except Exception:
        raise rt.Refused("the quarantine could not be read") from None
    finally:
        await pool.close()
    return sorted(
        [c.key for c in configs if c.key in held]
        + [k for k in held if k.startswith(ROW_KEY_PREFIX)]
    )


async def _dry_run(suite: HarnessSuite, configs: Sequence[Config]) -> dict[str, Any]:
    outcomes = {}
    for c in configs:
        o = await suite.run(c)
        outcomes[c.key] = {"status": o.status, "note": o.note,
                           "provider_calls": o.provider_calls}  # fmt: skip
    return outcomes


if __name__ == "__main__":
    sys.exit(main())
