"""Engine settings (M1-11): every platform setting in one object, each with one home.

    settings = EngineSettings.from_file("engine.toml")   # or EngineSettings(), all defaults
    engine = await build_engine(settings, verifier=...)

=============================  ===============================================================
Section                        What it holds, and where each default is defined
=============================  ===============================================================
``platform``                   :class:`~guardrail_engine.policy.PlatformSettings`: the
                               compiler's settings. ``floor_fail_mode`` (B1, default
                               ``closed``), ``question_budgets`` (R6.1: 50, and 200 on
                               ``input``), the token bounds (R6.7), thresholds and retention
                               defaults. Defaults live in ``policy/catalog.py``.
``gateway``                    :class:`~guardrail_engine.gateway.GatewayConfig`: budgets
                               (R6.3 after U7: latency bands, time-window allowance,
                               per-question slope, attempt-deadline margin, queue waits, the
                               caps of 3 s and 4 s on ``input``, fixed budgets), retry, auth
                               breaker, orphan cap, sink queue, close bound, and admission
                               control (M1-04: ``max_in_flight_per_key``, default
                               ``DEFAULT_MAX_IN_FLIGHT_PER_KEY``, 4, and
                               ``max_queued_per_key``).
                               Defaults live in ``gateway/gateway.py`` and are never restated
                               here.
``token_rate``                 :class:`~guardrail_engine.gateway.TokenRateConfig` (M3-10): the
                               project's quota. ``tokens_per_minute`` (1,000,000, positive and
                               not above the ``tier``'s published limit), ``target_fraction``
                               (0.68, the highest occupancy tested flat; higher is refused
                               unless ``burst_tested_at`` is at least that value),
                               ``requests_per_day`` (50,000), ``requests_per_minute`` (1,500,
                               the tier's published limit, the base of the non-production
                               consumers' per-minute allowance), ``monthly_spend_cap_usd`` (250)
                               and ``price_per_million_input_tokens_usd`` (0.10). Defaults live
                               in ``gateway/token_rate.py``. Unset: on at the Tier 1 figures in
                               ``production`` and ``staging``, off in ``test``
                               (:meth:`EngineSettings.effective_token_rate`). The engine passes
                               it to the gateway, which holds the project's bucket, daily count
                               (rolling at midnight Pacific) and monthly spend.
``quotas``                     :class:`~guardrail_engine.gateway.QuotaConfig` (M3-07, M3-08):
                               each tenant tier's share of the project (``tiers``: a fair
                               scheduling ``weight``, ``tokens_per_minute``,
                               ``checks_per_minute`` and ``requests_per_day``; defaults for
                               ``standard``, ``regulated`` and ``dedicated`` in
                               ``gateway/tenant_quota.py``), per-tenant ``overrides`` (a
                               ``weight`` of at most 8 times the largest tier's, else refused
                               at startup), the
                               tenant buckets' ``burst_capacity_s``, the most of the admission
                               queue one tenant may hold, and the ``non_production`` consumers'
                               fractions of the project's token-rate target, requests a
                               minute, requests a day and monthly spend (test, calibration,
                               red_team and shadow, 10% each; they must add up to less than 1).
                               Unset: on with those defaults in ``production`` and
                               ``staging``, off in ``test``
                               (:meth:`EngineSettings.effective_quotas`). Non-production
                               allowances need the token-rate limiter (they are fractions of
                               its figures) and nothing else: they hold with ``quotas`` unset
                               too.
``projects``                   :class:`ProjectsSettings` (M5-06): the **dedicated Gemini
                               projects** (key pools) regulated tenants are assigned to, by
                               label. Each names the environment variable its key is read
                               from (``key_env``: a name, never a key) and may set its own
                               ``token_rate`` (default: the ``token_rate`` section's, with the
                               label as the project id). The shared pool is the engine's own
                               ``GEMINI_API_KEY`` project. None configured by default.
``guard``                      Guard Service settings: ``pointer_ttl_s``, ``store_timeout_s``
                               and, for repeat-attempt counting (M7-03), ``repeat_threshold``
                               (blocks of the same content in the window after which it is
                               refused without a model call; 0 is off) and ``repeat_window_s``;
                               and, for provider refusals sent to a person (M7-08),
                               ``refusal_escalation_cap`` (default 20; 0 is off) and
                               ``refusal_escalation_window_s`` (default 900), both provisional.
                               Defaults are ``GuardConfig``'s and ``RepeatConfig``'s.
``gemini``                     The Gemini adapter: ``paid_tier`` (M1-03), ``model`` (a model
                               id, :data:`MODEL_ID_PATTERN`), ``base_url`` (``https``, no
                               user information), ``transport_timeout_s``,
                               ``keepalive_expiry_s`` (M1-10). Defaults are ``GeminiConfig``'s,
                               in ``decision/adapters/gemini.py``.
``store``                      Which policy store to build: ``memory`` (default) or
                               ``postgres``.
``catalog``                    The floor files, pack files and tier-required packs the catalog
                               is built from. Defaults defined here.
``shutdown``                   Bounds on shutdown. Defaults defined here.
``signed_context``             How v2 signed tenant contexts are verified (M2-01): the
                               accepted ``issuers`` and ``audience``, ``keyset_refresh_s``
                               (60), and ``allow_v1_hmac`` (default false: a v1 HMAC context
                               is refused in production unless a migration allows it).
``class_a_audit``              Where ``Engine.bootstrap_publish()`` writes its class A events:
                               ``file``, an append-only file flushed to disk (fsync) before
                               activation. No default (the JSON log line, test only).
``decision_spill``             Where regulated tenants' decision records go when the writer's
                               queue is full (M7-04): ``file`` (default: beside
                               ``class_a_audit.file``) and ``max_bytes`` (default 256 MiB).
                               Required in production and staging when records go to a store.
``environment``                ``production`` (the default), ``staging`` (the dogfood) or
                               ``test`` (tests and the demo). ``Engine.bootstrap_publish()``
                               is refused in ``production``, and in ``staging`` needs a
                               durable class A sink (M1-11 decision). Defined here.
=============================  ===============================================================

**One home per setting.** Nothing is configured twice. In particular the adapter's
connection pool size is not a setting: it is always ``gateway.max_in_flight_per_key``
(M1-10, M1-11 coupled settings). Defaults are read from the component that owns them, never
copied, so a default changes in one place.

**No secrets.** The API key (``GEMINI_API_KEY``) and the Postgres DSN (``GUARDRAIL_PG_DSN``,
which may carry a password) are read from the environment by
:func:`~guardrail_engine.engine.build_engine` and are never settings. A settings file that
names an API key is refused, and no error raised here repeats an input value.

**Validation.** Each section's own type checks its fields when the settings are built.
:meth:`EngineSettings.problems` adds the checks that need more than one field or that the
component types don't make (for example a budget too small for any call to finish).
``build_engine`` runs both and refuses to start, listing every problem by setting name.
"""

from __future__ import annotations

import dataclasses
import json
import math
import re
import tomllib
from collections.abc import Mapping
from pathlib import Path
from typing import Annotated, Any, Literal, get_args

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    ValidationError,
    field_validator,
)

from guardrail_engine.decision.adapters.gemini import GeminiConfig
from guardrail_engine.decision.limits import MAX_QUESTIONS
from guardrail_engine.gateway.gateway import GatewayConfig
from guardrail_engine.gateway.tenant_quota import (
    DEFAULT_NON_PRODUCTION,
    QuotaConfig,
    allowance_problems,
)
from guardrail_engine.gateway.token_rate import TokenRateConfig
from guardrail_engine.guard.refusal import RefusalConfig
from guardrail_engine.guard.repeat import RepeatConfig
from guardrail_engine.guard.service import GuardConfig
from guardrail_engine.guard.signed_context import (
    AUDIENCE as SIGNED_CONTEXT_AUDIENCE,
)
from guardrail_engine.guard.signed_context import (
    ISSUER_PATTERN,
    KEYSET_REFRESH_S,
)
from guardrail_engine.policy.catalog import PlatformSettings
from guardrail_engine.policy.schema import FAIL_MODES, GUARD_POINTS
from guardrail_engine.projects import (
    DEFAULT_PROJECT,
    KEY_ENV_PATTERN,
    PROJECT_LABEL_PATTERN,
    is_valid_project_label,
)

API_KEY_ENV_NAME = "GEMINI_API_KEY"
"""The variable the shared pool's key is read from (``engine/factory.py``, ``API_KEY_ENV``);
a dedicated project must name another."""
DEFAULT_FLOOR_FILE = Path("floor/rules.json")
DEFAULT_TEMPLATE_FILE = Path("templates/within_tenant_records.json")
"""The platform floor (M1-08), relative to the working directory."""
RELEASE_RECORD_FILE = Path("floor/releases/floor-2.release.json")
"""The record of floor@2's release (M7-05): see :class:`CatalogSettings.release_records`."""
NEXT_FLOOR_FILE = Path("floor/rules.v2.json")
"""floor@2 (M7-05), the floor the held-out validation measured. Loaded beside floor@1 and not
extendable until the platform releases it, so it changes nothing for any tenant until then."""
DEFAULT_DRAIN_TIMEOUT_S = 5.0
"""How long shutdown waits for in-flight checks. Validated to be at least the largest check
budget plus the cancellation grace plus the policy lookups before the model call:
4.76 s by default (the 4 s ``input`` cap, R6.3 after U7, 0.01 s grace, and three lookups at
the 0.25 s ``guard.store_timeout_s``), so a check in flight can reach its budget."""
POLICY_LOOKUPS_BEFORE_GATEWAY = 3
"""The policy lookups a check can make before the gateway (active-version pointer, tenant
directory, bundle), each bounded by ``guard.store_timeout_s``."""
DEFAULT_RESOURCE_CLOSE_TIMEOUT_S = 1.0
"""Upper bound on closing each of the HTTP client and the store at shutdown."""

Environment = Literal["production", "staging", "test"]
ENVIRONMENTS: tuple[str, ...] = get_args(Environment)
"""The values of ``environment`` (decided 2026-11-17): ``production``, the default and the
strictest; ``staging``, the dogfood; ``test``, tests and the demo. Anything else is refused.
They differ only for ``Engine.bootstrap_publish()`` today."""
MODEL_ID_PATTERN = re.compile(r"[a-z0-9][a-z0-9.-]{0,63}")
"""What ``gemini.model`` must match (``fullmatch``), e.g. ``gemini-decision-1``. The model id
is logged when the engine is built and recorded on spans and audit records, so it is held
to a model-id shape: a key or other secret pasted into it is refused."""
_PLAIN_URL_CHARS = re.compile(r"[\x21-\x7e]+")
"""Printable ASCII with no spaces: what a base URL may contain."""

_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})
_URL = re.compile(
    r"(?P<scheme>[A-Za-z][A-Za-z0-9+.-]*)://(?P<host>\[[^\]/]*\]|[^/:?#@\[\]]+)(?:[:/?#]|$)"
)
"""Scheme and host of a URL without userinfo. (``urllib`` is an HTTP-family module the
import boundary keeps to ``adapters/``.)"""


def _default(cls: type, name: str) -> Any:
    """The default of dataclass field ``name`` of ``cls``: the single source of truth."""
    for f in dataclasses.fields(cls):
        if f.name == name:
            if f.default is not dataclasses.MISSING:
                return f.default
            if f.default_factory is not dataclasses.MISSING:
                return f.default_factory()
    raise LookupError(f"{cls.__name__}.{name} has no default")


class SettingsError(ValueError):
    """The configuration is invalid; the engine refuses to start. ``problems`` lists each one
    as ``"<setting>: <what is wrong>"``. Never carries an input value that could be a
    secret."""

    def __init__(self, problems: list[str]) -> None:
        self.problems = list(problems)
        listed = "\n".join(f"  - {p}" for p in self.problems)
        super().__init__(f"invalid engine configuration ({len(self.problems)}):\n{listed}")


class _Section(BaseModel):
    # hide_input_in_errors: a pydantic error never repeats what it was given, so a key pasted
    # into the wrong field can't end up in a message or a log.
    model_config = ConfigDict(
        frozen=True, extra="forbid", allow_inf_nan=False, hide_input_in_errors=True
    )


class GuardSettings(_Section):
    pointer_ttl_s: float = Field(default=_default(GuardConfig, "pointer_ttl_s"), ge=0, le=60)
    """How long a tenant's active-version pointer is trusted before it is re-read. At most
    60 s: PF-13 bounds how long a rollback may take to reach the cache."""
    store_timeout_s: float = Field(default=_default(GuardConfig, "store_timeout_s"), gt=0)
    """Upper bound on each policy store or tenant directory call."""
    repeat_threshold: int = Field(default=_default(RepeatConfig, "threshold"), ge=0, le=1000)
    """M7-03: how many times the same content may be blocked within ``repeat_window_s`` before
    a further submission of it is refused without a model call. 0 turns it off."""
    repeat_window_s: float = Field(default=_default(RepeatConfig, "window_s"), gt=0, le=86_400)
    """M7-03: how long a block of some content keeps counting."""
    refusal_escalation_cap: int = Field(default=RefusalConfig().cap, ge=0, le=100_000)
    """M7-08: how many provider refusals one tenant may send to a person at one guard point
    within ``refusal_escalation_window_s``; past it a refusal is a block, as before, and one alert
    is raised per tenant per window. 0 makes every refusal a block. **Provisional**: not
    calibrated against real traffic."""
    refusal_escalation_window_s: float = Field(default=RefusalConfig().window_s, gt=0, le=86_400)
    """M7-08: the window of ``refusal_escalation_cap``. Provisional."""
    repeat_guard_points: tuple[str, ...] = Field(
        default=tuple(sorted(_default(RepeatConfig, "guard_points"))), min_length=1
    )
    """M7-03: the guard points where repeated content is refused. ``input`` only by default
    (where a sender resubmits); at the others the content comes from the agent or its tools."""

    @field_validator("repeat_guard_points")
    @classmethod
    def _known_guard_points(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        unknown = sorted(set(value) - set(GUARD_POINTS))
        if unknown:
            raise ValueError(f"unknown guard points {unknown}")
        return value


class GeminiSettings(_Section):
    """The Gemini adapter's settings. The API key is not here: it comes from
    ``GEMINI_API_KEY`` only. The pool size is not here: it is
    ``gateway.max_in_flight_per_key``."""

    paid_tier: bool = _default(GeminiConfig, "paid_tier")
    """Declares that the key in ``GEMINI_API_KEY`` is a paid-tier key (M1-03). The engine
    refuses to build the adapter without it."""
    model: str = Field(default=_default(GeminiConfig, "model"), min_length=1)
    """A model id matching :data:`MODEL_ID_PATTERN` (lowercase letters, digits, ``.`` and
    ``-``, at most 64 characters)."""
    base_url: str = _default(GeminiConfig, "base_url")
    """``https``; plain ``http`` only to a loopback host (a local test server). Never with
    user information (``user:password@``): the key is sent in a header, never in the URL."""
    transport_timeout_s: float = Field(default=_default(GeminiConfig, "transport_timeout_s"), gt=0)
    """A backstop only; the gateway's budget is the real deadline."""
    keepalive_expiry_s: float = Field(default=_default(GeminiConfig, "keepalive_expiry_s"), gt=0)
    """How long an idle pooled connection stays open (M1-10)."""


class StoreSettings(_Section):
    kind: Literal["memory", "postgres"] = "memory"
    """``postgres`` connects with the DSN in ``GUARDRAIL_PG_DSN`` unless a pool or a store
    is passed to ``build_engine``."""
    operator_role: str | None = None
    """The Postgres role the platform operator tooling uses (migration 007). When set, the
    engine refuses to start if its own role is a member of it. **Required in
    production and staging with a Postgres store**, so the check can't be
    skipped by omission. The application role must not be a superuser, hold BYPASSRLS, own the
    policy tables or be a member of the operator role; any of these silently turns row-level
    security off."""


class CatalogSettings(_Section):
    floor_files: tuple[Path, ...] = (DEFAULT_FLOOR_FILE, NEXT_FLOOR_FILE)
    """Platform floor files in the flat ``floor/rules.json`` format (M1-08), one per floor
    version: floor@1 and floor@2 (M7-05). floor@1, the lowest, is the baseline every tenant may
    extend; floor@2 is extendable once the platform has released it. Relative paths are resolved
    against the working directory."""
    release_records: tuple[Path, ...] = (RELEASE_RECORD_FILE,)
    """Records of floor releases (M7-05, ``admin/floor_records.py``), one JSON file per release.
    An engine in the ``test`` environment that builds its own in-memory platform store replays
    them into it at start, so the floors they name are released: with the default, floor@2 is the
    released floor a new tenant starts on. A record whose floor isn't in ``floor_files`` is
    skipped, and so is one about a floor whose content has changed since it was released (the
    floor stays unreleased, and the engine logs it); one that is unreadable or malformed stops
    the start. A record is trusted only after its evidence is checked at start against the report
    file it names and the current ``redteam_corpus``; one that doesn't match stops the start. A
    production or staging engine reads its release state from the platform tables and ignores
    them. Empty: nothing is released at start but the baseline."""
    pack_files: tuple[Path, ...] = ()
    """Domain pack source documents (pack schema version 1)."""
    redteam_corpus: Path = Path("redteam/corpus.jsonl")
    """The M2-08 red-team corpus a floor release's evidence must have run against (M2-09); a
    missing file makes a release proposal refuse, nothing else."""
    template_files: tuple[Path, ...] = (DEFAULT_TEMPLATE_FILE,)
    """Catalog template files (M2-03), one per template version, each a JSON object read by
    :func:`~guardrail_engine.template_file.load_template_file`. Relative paths are resolved
    against the working directory."""
    tier_required_packs: Mapping[str, frozenset[str]] = Field(default_factory=dict)
    """Pack names every tenant of a tier must extend, **in addition to** the platform's own:
    ``responsible_ai`` on the ``regulated`` and ``dedicated`` tiers (M5-01, R4.1), which needs no
    setting. ``production`` and ``staging`` apply it even when the pack isn't loaded (a tenant of
    the tier then can't publish, and the engine logs why at startup): put the pack file in
    ``pack_files``."""
    tier_required_rules: Mapping[str, frozenset[str]] = Field(default_factory=dict)
    """Compiled keys of pack rules a tenant of a tier can't opt out of one by one, even in a
    per-rule-optional pack (M4-10, R4.6), in addition to **every rule of every pack the tier
    requires** (M5-01: R4 names no individual rule, so the whole responsible-AI pack is
    required of a regulated tenant)."""
    default_on_packs: frozenset[str] = frozenset({"responsible_ai"})
    """Pack names a new tenant's starter bundle extends (M4-10: the responsible-AI pack is on by
    default, R4.1). A pack not in the catalog is skipped; a tenant may leave one out unless its
    tier requires it."""


class ShutdownSettings(_Section):
    drain_timeout_s: float = Field(default=DEFAULT_DRAIN_TIMEOUT_S, gt=0)
    """How long shutdown waits for in-flight checks to finish or reach their budgets."""
    resource_close_timeout_s: float = Field(default=DEFAULT_RESOURCE_CLOSE_TIMEOUT_S, gt=0)
    """Upper bound on closing the HTTP client, and on closing the store."""


class ClassAAuditSettings(_Section):
    file: Path | None = None
    """An append-only JSON-lines file for ``Engine.bootstrap_publish()``'s class A events,
    each flushed to disk (fsync) before the version is activated: a durable sink, as
    ``staging`` requires. Checked at startup: the engine refuses to start if it can't be
    opened for append. Unset: the events go to a JSON log line, acceptable in ``test``
    only."""


class DecisionSpillSettings(_Section):
    """Where a regulated tenant's decision records go when the write-behind queue is full
    (M7-04, :mod:`guardrail_engine.audit.spill`)."""

    file: Path | None = None
    """The spill file. Unset: ``decision_records.spill.jsonl`` beside ``class_a_audit.file``, when
    that is set. It is held to the class A file's checks (a directory only the engine's user can
    write, no symbolic link, mode 0600) and checked at startup. In ``production`` and ``staging``
    the engine refuses to start when decision records go to a store and there is no spill
    location (neither this nor ``class_a_audit.file``): regulated tenants' records would have
    nowhere to go when the queue is full."""
    max_bytes: int = Field(default=256 * 1024 * 1024, ge=1024 * 1024)
    """The file's size cap. An alert is raised at 80% of it; past it a regulated tenant's record
    is dropped and counted, like a standard tenant's, so a long outage can't fill the filesystem
    (which the class A file may share)."""


class SignedContextSettings(_Section):
    """How signed tenant contexts are verified (M2-01)."""

    allow_v1_hmac: bool = False
    """Accept the v1 HMAC context. **Refused by default** (decided 2026-11-17): in
    ``production``, ``build_engine`` refuses a verifier that would accept a v1 token unless this
    is true, so a deployment that still holds the shared HMAC secret says so. Only for the
    migration to v2 (Ed25519); remove it afterwards. Logged at startup and on the engine
    (``Engine.signed_context_mode``)."""
    issuers: tuple[
        Annotated[str, StringConstraints(pattern=f"^{ISSUER_PATTERN.pattern}$")], ...
    ] = ()
    """The gateway names whose v2 tokens are accepted (``iss``). Needed with a keyset source."""
    audience: str = Field(default=SIGNED_CONTEXT_AUDIENCE, min_length=1, max_length=64)
    """The v2 token's ``aud``."""
    keyset_refresh_s: float = Field(default=KEYSET_REFRESH_S, gt=0, le=3600)
    """How often the v2 keyset is re-read from the secret manager."""


class ProjectSettings(_Section):
    """One dedicated Gemini project (M5-06): where its key comes from, and its own quota."""

    key_env: Annotated[str, StringConstraints(pattern=f"^{KEY_ENV_PATTERN.pattern}$")]
    """The **name** of the environment variable the project's key is read from when the engine
    is built (for example ``GEMINI_KEY_ACME_REG``): upper-case letters, digits and underscores,
    never the key itself (a key has lower-case letters and is refused here, without being
    echoed). The same rules as ``GEMINI_API_KEY`` apply to the value: set, no surrounding
    whitespace, no control characters."""
    token_rate: TokenRateConfig | None = None
    """The project's own quota (M3-10): its Gemini tier's per-minute tokens, daily requests and
    monthly spend cap. Unset: the ``token_rate`` section's (and so unset in ``test``). Its
    ``project_id`` is always the project's label, whatever is written."""


class ProjectsSettings(_Section):
    """The key pools beyond the shared one (M5-06)."""

    dedicated: Mapping[str, ProjectSettings] = Field(default_factory=dict)
    """Dedicated projects by label (``acme-reg``): lower case, digits and hyphens, at most 40
    characters, not ``default`` (the shared pool's own label). Each serves one tenant."""


class EngineSettings(_Section):
    """Every platform setting of the engine. See the module docstring for each section."""

    platform: PlatformSettings = Field(default_factory=PlatformSettings)
    gateway: GatewayConfig = Field(default_factory=GatewayConfig)
    token_rate: TokenRateConfig | None = None
    """The project's token-rate limiter (M3-10). Unset means the environment's default:
    **on, at the Tier 1 figures, in ``production`` and ``staging``; off in ``test``**, where a
    fake model answers instantly and would exhaust any realistic quota in a moment (the
    calibration and demo runs). Set it to switch the limiter on in ``test`` too. See
    :meth:`effective_token_rate`."""
    quotas: QuotaConfig | None = None
    """Per-tenant quotas, fair scheduling and non-production allowances (M3-07, M3-08). Unset
    means the environment's default: **on, with the tier defaults, in ``production`` and
    ``staging``; off in ``test``**, where a fake model answers instantly and tests offer far
    more than any tenant's share. See :meth:`effective_quotas`."""
    projects: ProjectsSettings = Field(default_factory=ProjectsSettings)
    guard: GuardSettings = Field(default_factory=GuardSettings)
    gemini: GeminiSettings = Field(default_factory=GeminiSettings)
    store: StoreSettings = Field(default_factory=StoreSettings)
    catalog: CatalogSettings = Field(default_factory=CatalogSettings)
    shutdown: ShutdownSettings = Field(default_factory=ShutdownSettings)
    class_a_audit: ClassAAuditSettings = Field(default_factory=ClassAAuditSettings)
    decision_spill: DecisionSpillSettings = Field(default_factory=DecisionSpillSettings)
    signed_context: SignedContextSettings = Field(default_factory=SignedContextSettings)
    environment: Environment = "production"
    """Where the engine runs (:data:`ENVIRONMENTS`). Defaults to ``production``, so a
    deployment that forgets it gets the strictest behaviour: the privileged bootstrap path
    (``Engine.bootstrap_publish()``, M1-11) is refused. The dogfood sets ``staging``, tests
    and the demo ``test``."""

    # ------------------------------------------------------------------ loading

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> EngineSettings:
        """Build from a parsed settings document. Raises :class:`SettingsError` naming every
        bad setting, including the cross-field problems of :meth:`problems`.

        Errors are raised outside the ``except`` block, so the original error (which holds
        the input) is neither the cause nor the context of the one raised."""
        problems: list[str] = []
        try:
            settings = cls.model_validate(data)
        except ValidationError as e:
            problems = [_describe(err) for err in e.errors(include_input=False)]
        if problems:
            raise SettingsError(problems)
        if problems := settings.problems():
            raise SettingsError(problems)
        return settings

    @classmethod
    def from_file(cls, path: str | Path) -> EngineSettings:
        """Read a ``.toml`` or ``.json`` settings file (see :meth:`from_mapping`). A file
        that can't be read or parsed is reported by exception type only: a parser's message
        can quote the offending text, which might be a key."""
        path = Path(path)
        if path.suffix not in (".toml", ".json"):
            raise SettingsError([f"settings file {path}: must be .toml or .json"])
        problem = None
        try:
            raw = path.read_bytes()
            data = tomllib.loads(raw.decode("utf-8")) if path.suffix == ".toml" else json.loads(raw)
        except OSError as e:
            problem = f"settings file {path}: cannot read ({type(e).__name__})"
        except ValueError as e:  # TOMLDecodeError, JSONDecodeError, UnicodeDecodeError
            problem = f"settings file {path}: not valid ({type(e).__name__})"
        if problem is not None:
            raise SettingsError([problem])
        if not isinstance(data, dict):
            raise SettingsError([f"settings file {path}: must hold an object"])
        return cls.from_mapping(data)

    # ------------------------------------------------------------------ validation

    def problems(self) -> list[str]:
        """Cross-field and range checks the section types don't make. Empty when valid.
        ``build_engine`` adds the checks that need the environment or the catalog files."""
        return [
            *_platform_problems(self.platform),
            *_gateway_problems(self.gateway),
            *_token_rate_problems(self.effective_token_rate()),
            *_quota_problems(self.effective_quotas()),
            *_allowance_problems(self.effective_token_rate(), self.effective_quotas()),
            *_gemini_problems(self.gemini),
            *_shutdown_problems(self),
            *self._project_problems(),
        ]

    def dedicated_project_labels(self) -> tuple[str, ...]:
        """The dedicated projects, in the order a regulated tenant is handed them (sorted)."""
        return tuple(sorted(self.projects.dedicated))

    def effective_project_token_rate(self, label: str) -> TokenRateConfig | None:
        """A dedicated project's limiter: its own ``token_rate``, else the gateway's effective
        one, with the label as the project id. None when the limiter is off (``test``, unset)."""
        base = self.projects.dedicated[label].token_rate or self.effective_gateway().token_rate
        return None if base is None else dataclasses.replace(base, project_id=label)

    def effective_project_gateway(self, label: str) -> GatewayConfig:
        """The gateway config of a dedicated project: the engine's, with the project's own
        limiter (so its own bucket, daily count and monthly spend)."""
        return dataclasses.replace(
            self.effective_gateway(), token_rate=self.effective_project_token_rate(label)
        )

    def _project_problems(self) -> list[str]:
        found: list[str] = []
        seen: dict[str, str] = {API_KEY_ENV_NAME: "the shared pool's key"}
        for label in self.dedicated_project_labels():
            where = f"projects.dedicated.{label}"
            if not is_valid_project_label(label) or label == DEFAULT_PROJECT:
                found.append(
                    f"projects.dedicated: a label must match {PROJECT_LABEL_PATTERN.pattern} "
                    f"and not be {DEFAULT_PROJECT!r}"
                )
                continue
            project = self.projects.dedicated[label]
            if project.key_env in seen:
                found.append(
                    f"{where}.key_env: names the variable of {seen[project.key_env]}; every "
                    "project has its own key"
                )
            seen.setdefault(project.key_env, f"project {label}")
            rate = self.effective_project_token_rate(label)
            found += [
                f"{where}.{p}"
                for p in (
                    *_token_rate_problems(rate),
                    *_allowance_problems(rate, self.effective_quotas()),
                )
            ]
        return found

    def effective_token_rate(self) -> TokenRateConfig | None:
        """The limiter the engine runs with (M3-10): ``token_rate`` if set, else the Tier 1
        defaults in ``production`` and ``staging``, else (``test``) none."""
        if self.token_rate is not None:
            return self.token_rate
        return None if self.environment == "test" else TokenRateConfig()

    def effective_quotas(self) -> QuotaConfig | None:
        """The quotas the engine runs with (M3-07, M3-08): ``quotas`` if set, else the tier
        defaults in ``production`` and ``staging``, else (``test``) none."""
        quotas = self.quotas
        if quotas is None:
            if self.environment == "test":
                return None
            quotas = QuotaConfig()
        if quotas.largest_check_tokens == 0 or quotas.largest_check_calls == 0:
            # M3-09: a bucket always holds one whole check (its tokens, and a check per chunk)
            quotas = dataclasses.replace(
                quotas,
                largest_check_tokens=quotas.largest_check_tokens or self.largest_check_tokens(),
                largest_check_calls=(
                    quotas.largest_check_calls or self.platform.max_chunks_per_result
                ),
            )
        return quotas

    def largest_check_tokens(self) -> int:
        """The most API tokens one check can compile to: the most chunks of a ``tool_result``
        (each at the content bound, carrying the full question text of the critical path). A
        tenant's token bucket is never smaller than this."""
        platform = self.platform
        per_call = platform.token_budget + (
            platform.question_text_tokens_per_budgeted_question
            * platform.question_budgets.tool_result
        )
        return platform.max_chunks_per_result * per_call

    def effective_gateway(self) -> GatewayConfig:
        """The gateway's config with the project's limiter (M3-10) and the quotas (M3-07)
        filled in from their sections, unless ``gateway`` sets them itself."""
        changes: dict[str, Any] = {}
        if self.gateway.token_rate is None:
            changes["token_rate"] = self.effective_token_rate()
        if self.gateway.quotas is None:
            changes["quotas"] = self.effective_quotas()
        return dataclasses.replace(self.gateway, **changes) if changes else self.gateway

    def largest_check_budget_s(self) -> float:
        """The largest total budget the gateway can give one check (R6.3 after U7): the
        larger cap (``input`` has its own), or the default override, or any per-guard-point
        override."""
        g = self.gateway
        if g.default_budget_s is None:
            overall = max(g.budget_cap_s, g.input_budget_cap_s)
        else:
            overall = g.default_budget_s
        return max([overall, *g.budgets_s.values()])


# ---------------------------------------------------------------------- the checks


def _describe(err: Mapping[str, Any]) -> str:
    where = ".".join(str(part) for part in err["loc"]) or "settings"
    last = str(err["loc"][-1]).lower() if err["loc"] else ""
    if err["type"] in {"extra_forbidden", "unexpected_keyword_argument"} and (
        "key" in last or "secret" in last or "token" in last or "dsn" in last
    ):
        return (
            f"{where}: not a setting. Secrets are never settings: the API key is read from "
            "the GEMINI_API_KEY environment variable and the Postgres DSN from "
            "GUARDRAIL_PG_DSN. Remove it from the settings."
        )
    message = str(err["msg"]).removeprefix("Value error, ")
    return f"{where}: {message}"


def _platform_problems(p: PlatformSettings) -> list[str]:
    problems = []
    # B1 and S5: the fail modes are settings, so they are checked where they are set.
    for name in ("floor_fail_mode", "default_fail_mode"):
        value = getattr(p, name)
        if value not in FAIL_MODES:
            problems.append(f"platform.{name}: must be one of {list(FAIL_MODES)}, got {value!r}")
    # R6.1: question budgets. Each is >= 1 by its type; no call can carry more than the
    # Decisions API's limit.
    for gp in GUARD_POINTS:
        budget = p.question_budgets.for_guard_point(gp)
        if budget > MAX_QUESTIONS:
            problems.append(
                f"platform.question_budgets.{gp}: must be at most {MAX_QUESTIONS} (the "
                f"Decisions API's limit per call), got {budget}"
            )
    if p.min_floor_version < 1:
        problems.append(f"platform.min_floor_version: must be >= 1, got {p.min_floor_version}")
    return problems


_GATEWAY_FLOATS = (
    "time_window_allowance_s",
    "latency_per_question_s",
    "budget_margin_s",
    "budget_margin_fraction",
    "budget_cap_s",
    "input_budget_cap_s",
    "default_budget_s",
    "expected_latency_s",
    "retry_jitter_s",
    "cancel_grace_s",
    "probe_initial_delay_s",
    "probe_max_delay_s",
    "degraded_window_s",
    "warning_interval_s",
    "close_timeout_s",
)


def _gateway_problems(g: GatewayConfig) -> list[str]:
    """R6.3 budgets. ``GatewayConfig`` itself refuses non-positive budgets, unordered bands,
    and (M1-04) an admission limit or queue bound that isn't a whole number of at least 1.
    Here: values that aren't finite, budgets set for guard points that don't exist, and
    budgets too small for even the smallest call to finish."""
    problems = []
    for name in _GATEWAY_FLOATS:
        value = getattr(g, name)
        if value is not None and not math.isfinite(value):
            problems.append(f"gateway.{name}: must be a finite number of seconds, got {value}")
    for bound, base in g.latency_bands:
        if not math.isfinite(base):
            problems.append(f"gateway.latency_bands: base for {bound} must be finite, got {base}")
    for gp, budget in g.budgets_s.items():
        if gp not in GUARD_POINTS:
            problems.append(
                f"gateway.budgets_s: {gp!r} is not a guard point (one of {list(GUARD_POINTS)})"
            )
        elif not math.isfinite(budget):
            problems.append(f"gateway.budgets_s[{gp!r}]: must be finite, got {budget}")
    for gp in g.queue_waits_s:
        if gp not in GUARD_POINTS:
            problems.append(
                f"gateway.queue_waits_s: {gp!r} is not a guard point (one of {list(GUARD_POINTS)})"
            )
    if problems:
        return problems
    smallest = g.smallest_expected_s()
    budgets = {
        "gateway.budget_cap_s": g.budget_cap_s,
        "gateway.input_budget_cap_s": g.input_budget_cap_s,
    }
    if g.default_budget_s is not None:
        budgets["gateway.default_budget_s"] = g.default_budget_s
    budgets.update({f"gateway.budgets_s[{gp!r}]": b for gp, b in g.budgets_s.items()})
    for name, budget in budgets.items():
        if budget <= smallest:
            problems.append(
                f"{name}: {budget} s is not more than the smallest call's expected p50 "
                f"({smallest:.3f} s), so no check could finish within it"
            )
    return problems


def _token_rate_problems(t: TokenRateConfig | None) -> list[str]:
    """M3-10, re-checked at startup: the config validates itself when built, but a
    ``dataclasses.replace`` or a test double can skip that."""
    return [] if t is None else [f"token_rate.{p}" for p in t.problems()]


def _quota_problems(q: QuotaConfig | None) -> list[str]:
    """M3-07, M3-08, re-checked at startup (the config validates itself when built)."""
    return [] if q is None else [f"quotas.{p}" for p in q.problems()]


def _allowance_problems(t: TokenRateConfig | None, q: QuotaConfig | None) -> list[str]:
    """M3-08: the non-production allowances, built from the project's limits and the
    quotas' fractions (the defaults without quotas), must each hold at least one request."""
    if t is None or t.problems():
        return []  # nothing to take a fraction of, or already reported
    fractions = DEFAULT_NON_PRODUCTION if q is None or q.problems() else q.non_production
    return [f"token_rate.{p}" for p in allowance_problems(t, fractions)]


def _gemini_problems(s: GeminiSettings) -> list[str]:
    """No message here repeats the value: a base URL may carry a password in its user
    information, and a model id field may hold a pasted key."""
    problems = []
    if s.model.startswith("models/"):
        problems.append(
            "gemini.model: drop the 'models/' prefix: the setting is the bare model id "
            "(lowercase letters, digits, '.' and '-', at most 64 characters)"
        )
    elif not MODEL_ID_PATTERN.fullmatch(s.model):
        problems.append(
            "gemini.model: must be a model id: lowercase letters, digits, '.' and '-', "
            "starting with a letter or digit, at most 64 characters (it is logged and recorded "
            "on spans and audit records, so nothing else is accepted)"
        )
    url = s.base_url
    if not _PLAIN_URL_CHARS.fullmatch(url):
        problems.append(
            "gemini.base_url: must be printable ASCII with no spaces or control characters"
        )
        return problems
    authority = url.split("://", 1)[1] if "://" in url else ""
    authority = re.split(r"[/?#]", authority, maxsplit=1)[0]
    if "@" in authority:
        problems.append(
            "gemini.base_url: must not carry user information (user:password@ before the "
            "host); the API key is sent in a header, and credentials never go in the URL"
        )
        return problems
    match = _URL.match(url)
    scheme = match["scheme"].lower() if match else None
    host = match["host"].strip("[]").lower() if match else None
    if scheme == "https":
        return problems
    if scheme == "http" and host in _LOOPBACK_HOSTS:
        return problems  # a local test server: the key never leaves the machine
    problems.append(
        "gemini.base_url: must be an https URL (plain http only to a loopback host), because "
        "every request carries the API key"
    )
    return problems


def _shutdown_problems(s: EngineSettings) -> list[str]:
    if _gateway_problems(s.gateway):
        return []  # the budget itself is invalid; reported above
    # A check's wall time also covers the policy lookups before the gateway, each
    # bounded by the store timeout.
    lookups = POLICY_LOOKUPS_BEFORE_GATEWAY * s.guard.store_timeout_s
    needed = s.largest_check_budget_s() + s.gateway.cancel_grace_s + lookups
    if s.shutdown.drain_timeout_s < needed:
        return [
            f"shutdown.drain_timeout_s: {s.shutdown.drain_timeout_s} s is less than the largest "
            f"check budget plus the cancellation grace plus {POLICY_LOOKUPS_BEFORE_GATEWAY} "
            f"policy lookups at guard.store_timeout_s ({needed:.3f} s), so shutdown could cut "
            "off checks that are still within their budget"
        ]
    return []
