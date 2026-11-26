"""The engine composition root (M1-11): one factory builds the whole engine from one
:class:`~guardrail_engine.engine.settings.EngineSettings`.

    settings = EngineSettings.from_file("engine.toml")
    async with await build_engine(settings, verifier=verifier, tenants=directory) as engine:
        verdict = await engine.check(ctx, "output", content)

:func:`build_engine` builds, in order: the catalog (floor files plus pack files), the
policy store (in memory, or Postgres), the Gemini adapter (or the ``DecisionModel`` passed
as ``model``), and the Guard Service, which builds the policy cache, the compiler and the
gateway. It returns an :class:`Engine`, which is also the shutdown handle.

**Startup validation.** Before anything is created, every setting is checked
(:meth:`EngineSettings.problems`), then what needs the environment or the catalog: the
paid-tier declaration and ``GEMINI_API_KEY`` when the adapter is built, ``GUARDRAIL_PG_DSN``
for a Postgres store, that every floor and pack file loads, that a floor at or above
``platform.min_floor_version`` exists, and that the floor fits each guard point's question
budget. Any problem raises :class:`SettingsError` listing all of them by setting name, and
nothing is started.

**Coupled settings.** The adapter keeps as many idle connections as the gateway lets calls
be in flight on a key: its ``max_in_flight`` is always ``gateway.max_in_flight_per_key``.

**Telemetry (M1-06).** The Guard Service gets the telemetry port passed as ``telemetry``,
by default :class:`~guardrail_engine.telemetry.adapters.otel.OtelTelemetry` on the global
tracer provider (a no-op until the embedding process configures the OpenTelemetry SDK): a
``guard.check`` span per check and a ``guard.model_call`` span around its decision call.

**Connection-reuse hook.** The adapter reports each call's :class:`CallInfo` (new or reused
connection, M1-10) to the engine's relay, which always calls the telemetry adapter's
:func:`~guardrail_engine.telemetry.adapters.otel.connection_reuse_hook` (it sets
``guardrail.connection_reused`` on the check's model-call span, and does nothing outside
one), then :attr:`Engine.connection_hook`, an extra observer that defaults to
:func:`ignore_connection_info`. Both run in the task that makes the model call, so they see
that task's context.

**Ownership.** The engine owns what it builds and what it is given, and closes it at
shutdown (a component is closed if it has ``aclose()``), with two exceptions that are only
borrowed: an ``http_client`` for the adapter and a ``pg_pool`` for the Postgres store.

**Shutdown** (:meth:`Engine.shutdown`, also on leaving ``async with``), in this order:

1. stop accepting checks: from now on :meth:`Engine.check` returns ``block`` with reason
   ``engine_closed`` (retryable, no model call) and never raises;
2. wait for the checks in flight to finish or reach their budgets, at most
   ``shutdown.drain_timeout_s`` (validated to be at least the largest check budget plus the
   cancellation grace plus three policy lookups at ``guard.store_timeout_s``);
3. close the Guard Service: its policy cache, then the gateway's ``aclose`` (which flushes
   the alert and metering events and stops the drainer within ``gateway.close_timeout_s``,
   even with a stuck sink);
4. close the model, which closes the HTTP client it owns;
5. close the store (an owned Postgres pool).

Every step is bounded, and one that fails or times out is logged and the next still runs,
so shutdown always finishes within :attr:`Engine.shutdown_bound_s`.

**The API key** is read from the environment only (``GEMINI_API_KEY``), never from settings.
It is held in an :class:`ApiKey`, whose ``repr`` and ``str`` are ``***``, and is never
logged or put in an error message. A key with surrounding whitespace (a trailing newline
from a secret file), a control character or a non-ASCII character is refused at startup: it would
otherwise fail every call as a transport error. It is refused, not stripped, so the secret is fixed
where it is stored. The gateway identifies the key by its ``key_id``, never by the key: the secret
manager's version id when the caller has one (pass ``key_id``), otherwise the key's 12-hex-digit
SHA-256 fingerprint (the default).

**Test-only overrides** (M1-14, decided 2026-11-17). Two arguments change what a
check sends, so the factory gates them by ``environment`` at build time and records their
use (:attr:`Engine.test_overrides`, a WARNING line when the engine is built, and every
bootstrap publish's class A event):

* ``pii_detector``: another :class:`~guardrail_engine.guard.pii.PiiDetector` in place of the
  deterministic one. Redaction has no off switch, so it is accepted **only** when
  ``environment`` is ``test`` (``staging`` takes production-shaped traffic).
* ``nonce_source``: where the renderer draws its spotlighting nonces, so a calibration run's
  draws can be reproduced. A known nonce defeats spotlighting (whoever knows it can close a
  section), and ``staging`` takes production-shaped traffic, so it is accepted **only** when
  ``environment`` is ``test``.

**Privileged:** :meth:`Engine.bootstrap_publish` (see :mod:`guardrail_engine.engine.bootstrap`).
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import logging
import os
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from guardrail_engine.admin import DraftService, InMemoryDraftStore, ScopedDraftStores
from guardrail_engine.admin.approval_service import ApprovalService
from guardrail_engine.admin.approvals import InMemoryApprovalStore, ScopedApprovalStores
from guardrail_engine.admin.calibration import CalibrationService
from guardrail_engine.admin.calibration_store import (
    InMemoryCalibrationStore,
    ScopedCalibrationStores,
)
from guardrail_engine.admin.catalog import CatalogAdmin, CatalogService
from guardrail_engine.admin.content import StoredContentService
from guardrail_engine.admin.decisions import DecisionsService, LifecycleDerivedKeys
from guardrail_engine.admin.evidence import EvidenceGate
from guardrail_engine.admin.floor_records import (
    ReleaseRecordError,
    check_against,
    check_evidence,
    load,
)
from guardrail_engine.admin.floor_records import replay as replay_release
from guardrail_engine.admin.floors import (
    FloorRelease,
    FloorService,
    InMemoryPlatformStore,
    LoggingNotifier,
    Notifier,
    PlatformStore,
)
from guardrail_engine.admin.golden import GoldenService, InMemoryGoldenStore, ScopedGoldenStores
from guardrail_engine.admin.lifecycle import (
    GuardrailPublished,
    InMemoryLifecycleStore,
    InMemoryPublishBus,
    PublishBus,
    ScopedLifecycleStores,
)
from guardrail_engine.admin.metrics import MetricsService
from guardrail_engine.admin.nightly import NightlyResultsService
from guardrail_engine.admin.provider_health import ProviderHealthService
from guardrail_engine.admin.publish import PublishService
from guardrail_engine.admin.repin_service import RepinService
from guardrail_engine.admin.rollout import LifecycleCandidates, RolloutService
from guardrail_engine.admin.tiers import TierService
from guardrail_engine.admin.tool_registry import (
    SCREEN_RULES,
    InMemoryToolStore,
    LifecycleToolUsage,
    RegistryTools,
    ScopedToolStores,
    ToolScreener,
    ToolService,
)
from guardrail_engine.admin.tools import DraftTools, EvaluatorUnavailableError
from guardrail_engine.audit.spill import spill_file_beside
from guardrail_engine.audit.store import InMemoryDecisionRecords
from guardrail_engine.audit.term import EffectiveTerm, directory_regulated
from guardrail_engine.audit.writer import DecisionRecordWriter
from guardrail_engine.authz.authentication import Authenticator
from guardrail_engine.authz.authorizer import Authorizer, AuthzAuditSink
from guardrail_engine.content.store import InMemoryStoredContent
from guardrail_engine.content.term import EffectiveContentTerm
from guardrail_engine.content.writer import StoredContentWriter
from guardrail_engine.decision.adapters.gemini import CallInfo, GeminiConfig, GeminiDecisionModel
from guardrail_engine.decision.port import DecisionModel
from guardrail_engine.delivery.outbox import OutboxStore
from guardrail_engine.deterministic import NoOtherTenantIdentifiers, OtherTenantIdentifiers
from guardrail_engine.directory.memory import InMemoryEventBus
from guardrail_engine.directory.model import EventBus, TenantDirectoryStore
from guardrail_engine.directory.provisioning import TenantProvisioner
from guardrail_engine.engine.bootstrap import (
    AdminAuditSink,
    AppendOnlyFileAdminAuditSink,
    AppendOnlyFileAuthzAudit,
    BootstrapPublishEvent,
    BootstrapRefusedError,
    ClassAAuditFileError,
    LoggingAdminAuditSink,
    bundle_diff,
    decision_spill_at,
)
from guardrail_engine.engine.settings import EngineSettings, SettingsError
from guardrail_engine.escalation import (
    EscalationRouter,
    EscalationService,
    InMemoryEscalationStore,
    ScopedEscalationStores,
)
from guardrail_engine.floor_file import load_floor_file
from guardrail_engine.gateway.gateway import DecisionGateway
from guardrail_engine.gateway.sinks import AlertSink, UsageMeter
from guardrail_engine.gateway.token_rate import (
    DEFAULT_PRICE_PER_MILLION_INPUT_TOKENS_USD,
    TokenRateStore,
)
from guardrail_engine.guard.audit import AuditSink
from guardrail_engine.guard.context import ContextVerifier
from guardrail_engine.guard.pii import PiiDetector
from guardrail_engine.guard.refusal import RefusalConfig
from guardrail_engine.guard.render import NonceSource, new_nonce
from guardrail_engine.guard.repeat import RepeatConfig
from guardrail_engine.guard.request import CheckContext
from guardrail_engine.guard.service import GuardConfig, GuardService, ProjectBackend
from guardrail_engine.guard.shadow import InMemoryShadowStats
from guardrail_engine.guard.signed_context import (
    Ed25519ContextVerifier,
    Keyset,
    KeysetRefresher,
    KeysetSource,
    SignatureVerifier,
    VersionedContextVerifier,
    accepts_v1,
)
from guardrail_engine.guard.tenants import InMemoryTenantDirectory, TenantDirectory
from guardrail_engine.guard.verdict import Decision, Reason, Verdict
from guardrail_engine.guard.verdict import Verdict as _AuditedVerdict
from guardrail_engine.metrics.store import InMemoryRecordMetrics
from guardrail_engine.nightly.store import InMemoryNightlyResults, InMemoryQuarantine
from guardrail_engine.pack_file import PackFileError, load_pack_file
from guardrail_engine.policy.catalog import (
    REGULATED_REQUIRED_PACKS,
    REGULATED_TIERS,
    Catalog,
    FloorVersion,
    InMemoryCatalog,
    PackVersion,
    Template,
)
from guardrail_engine.policy.compiler import PolicyCompiler
from guardrail_engine.policy.document import parse_bundle
from guardrail_engine.policy.floor_loader import FloorFileError
from guardrail_engine.policy.schema import GUARD_POINTS
from guardrail_engine.policy.template_loader import TemplateFileError
from guardrail_engine.projects import DedicatedProjects
from guardrail_engine.store.memory import InMemoryPolicyStore, MemoryCatalogReferences
from guardrail_engine.store.port import AlertHook, ScopedPolicyStores
from guardrail_engine.telemetry.adapters.otel import OtelTelemetry, connection_reuse_hook
from guardrail_engine.telemetry.port import Telemetry
from guardrail_engine.template_file import load_template_file
from guardrail_engine.tenant_scope import issue_scope

logger = logging.getLogger(__name__)

API_KEY_ENV = "GEMINI_API_KEY"
"""The only place the Gemini API key is read from."""
PG_DSN_ENV = "GUARDRAIL_PG_DSN"
PG_OPERATOR_DSN_ENV = "GUARDRAIL_PG_OPERATOR_DSN"
"""Optional: the DSN of the platform operator's database role. It builds the pool the stores use
for an allowed cross-tenant operator access (an operator scope); without it such a request is
refused with 503 ``operator_unavailable``. Never used for anything else."""
"""Where the Postgres DSN is read from for ``store.kind = "postgres"``. It may carry a
password, so it is treated like the key: never a setting, never logged."""
INJECTED_MODEL_KEY_ID = "injected-model"
"""``key_id`` when a ``DecisionModel`` is passed in and no ``key_id`` is given."""

ConnectionHook = Callable[[CallInfo], None]


def ignore_connection_info(info: CallInfo) -> None:
    """The default extra connection hook (:attr:`Engine.connection_hook`): does nothing.
    The span hook that sets ``connection_reused`` on the check's model-call span (M1-06)
    is connected separately and always runs."""


class AdminApiUnavailableError(RuntimeError):
    """``Engine.admin_app()`` was asked for without everything the Admin API needs."""


class EngineStartError(RuntimeError):
    """A resource could not be created at startup (for example the Postgres pool). The
    message names the resource and the exception type only, never a DSN or a key."""


def secret_form_problem(value: str) -> str | None:
    """Which kinds of character problem a secret from the environment has, or None: surrounding
    whitespace, a control character, a non-ASCII character. Names the kinds found and never
    repeats the value or any part of it (not even its length or where the character is). A
    secret with such a problem is refused at startup, never stripped (decided 2026-11-17)."""
    kinds = []
    if value != value.strip():
        kinds.append("has surrounding whitespace (often a trailing newline from a secret file)")
    inner = value.strip()
    if any(ch < " " or "\x7f" <= ch <= "\x9f" for ch in inner):
        kinds.append("has a control character")
    if any(ch > "~" and not ("\x7f" <= ch <= "\x9f") for ch in inner):
        kinds.append("has a non-ASCII character")
    if not kinds:
        return None
    return "; ".join(kinds) + "; it is refused, not stripped. Fix the stored secret"


def api_key_problem(value: object) -> str | None:
    """What makes ``value`` unusable as an API key, or None. Never repeats the value or any
    part of it (not even its length or where the bad character is)."""
    if not isinstance(value, str) or not value.strip():
        return "must be non-blank text"
    return secret_form_problem(value)


PG_DSN_SCHEMES = ("postgresql://", "postgres://")
"""The DSN forms the Postgres store's driver (asyncpg) takes: a libpq connection URI."""


def pg_dsn_problem(value: str) -> str | None:
    """What makes ``value`` unusable as ``GUARDRAIL_PG_DSN``, or None (decided 2026-11-17: a
    malformed DSN fails at startup, not on the first write). Checks the characters as for
    the API key, and that it is a ``postgresql://`` or ``postgres://`` URI. Never repeats
    the value or any part of it: a DSN can hold a password."""
    if (problem := secret_form_problem(value)) is not None:
        return problem
    if not value.lower().startswith(PG_DSN_SCHEMES):
        return "must be a postgresql:// (or postgres://) connection URI"
    return None


class ApiKey:
    """A secret that shows as ``***``. ``reveal()`` is the only way to read it. Refuses a
    value :func:`api_key_problem` rejects."""

    __slots__ = ("__value",)

    def __init__(self, value: str) -> None:
        if (problem := api_key_problem(value)) is not None:
            raise ValueError(f"an API key {problem}")
        self.__value = value

    def reveal(self) -> str:
        return self.__value

    def fingerprint(self) -> str:
        """A short, non-secret identifier of this key, which changes when the key does: the
        gateway's ``key_id`` (M1-04). Twelve hex digits of SHA-256 can't recover the key."""
        return "sha256:" + hashlib.sha256(self.__value.encode("utf-8")).hexdigest()[:12]

    def __repr__(self) -> str:
        return "ApiKey('***')"

    def __str__(self) -> str:
        return "***"

    def __reduce__(self) -> Any:
        raise TypeError("an API key can't be pickled or copied")


class _ConnectionHookRelay:
    """What the adapter calls for every model call: first the span hook (M1-06, always
    connected, so a caller's hook can't switch off the cold-call metering), then the
    engine's current extra hook, which can be set after the engine is built. The adapter
    logs and ignores anything they raise."""

    def __init__(self, hook: ConnectionHook, span_hook: ConnectionHook) -> None:
        self.hook = hook
        self.span_hook = span_hook

    def __call__(self, info: CallInfo) -> None:
        self.span_hook(info)
        self.hook(info)


class Engine:
    """A built engine. Make checks with :meth:`check`; shut it down with :meth:`shutdown` or
    ``async with``. Build it with :func:`build_engine`, not directly."""

    def __init__(
        self,
        *,
        settings: EngineSettings,
        guard: GuardService,
        model: DecisionModel,
        store: ScopedPolicyStores,
        catalog: Catalog,
        tenants: TenantDirectory,
        hooks: _ConnectionHookRelay,
        telemetry: Telemetry,
        admin_audit: AdminAuditSink,
        api_key: ApiKey | None,
        model_close: _CloseStep | None,
        store_close: _CloseStep | None,
        operator_close: _CloseStep | None = None,
        bus_close: _CloseStep | None = None,
        store_kind: str,
        test_overrides: tuple[str, ...] = (),
        background_close: _CloseStep | None = None,
        signed_context_mode: str = "v2",
        authenticator: Authenticator | None = None,
        authorizer: Authorizer | None = None,
        draft_service: DraftService | None = None,
        draft_tools: DraftTools | None = None,
        golden_service: GoldenService | None = None,
        calibration_service: CalibrationService | None = None,
        rollout_service: RolloutService | None = None,
        escalation_service: EscalationService | None = None,
        escalation_router: EscalationRouter | None = None,
        shadow_stats: Any | None = None,
        decision_writer: DecisionRecordWriter | None = None,
        content_writer: StoredContentWriter | None = None,
        stored_content_service: StoredContentService | None = None,
        nightly_service: NightlyResultsService | None = None,
        decisions_service: DecisionsService | None = None,
        metrics_service: MetricsService | None = None,
        catalog_service: CatalogService | None = None,
        catalog_admin: CatalogAdmin | None = None,
        tool_service: ToolService | None = None,
        floor_service: FloorService | None = None,
        repin_service: RepinService | None = None,
        publish_service: PublishService | None = None,
        publish_bus: PublishBus | None = None,
        approval_service: ApprovalService | None = None,
        tier_service: TierService | None = None,
        provider_health_service: ProviderHealthService | None = None,
    ) -> None:
        self.settings = settings
        self.provider_health_service = provider_health_service
        """``GET`` and ``PUT /v1/platform/provider/degraded`` (M7-11): an operator's hold on
        the gateways' provider-health breaker. Built when there is a platform store."""
        self.tier_service = tier_service
        """``PUT /v1/tenants/{tid}/guardrails/tier``: a platform operator sets a tenant's tier
        (M5-01). Built when ``build_engine`` is given the directory's write store."""
        self.publish_service = publish_service
        self.approval_service = approval_service
        """Two-person approval's request and approve (M5-02)."""
        self.publish_bus = publish_bus
        """Where ``guardrail.published`` goes. When it can be subscribed to, the engine's own
        policy cache is subscribed, so a publish or rollback is served on the next check."""
        if publish_bus is not None and hasattr(publish_bus, "subscribe"):
            publish_bus.subscribe(self._on_published)
        self.golden_service = golden_service
        self.calibration_service = calibration_service
        self.rollout_service = rollout_service
        """The shadow candidate's per-rule agreement report (M4-03)."""
        self.escalation_service = escalation_service
        """The escalation queue's list, read and resolve (M4-05)."""
        self.escalation_router = escalation_router
        """Routes ``escalate`` verdicts to the human queue or the tenant webhook (M4-05)."""
        self._shadow_stats = shadow_stats
        self._shadow_flusher: asyncio.Task[None] | None = None
        self.decision_writer = decision_writer
        """The write-behind writer of decision records (M4-07), when records are kept."""
        self.content_writer = content_writer
        """The write-behind writer of stored content (M5-03, R3 class C): only a tenant whose
        bundle says ``store_content: full`` has anything written."""
        self.stored_content_service = stored_content_service
        self.nightly_service = nightly_service
        """``GET /v1/platform/redteam/nightly`` (M5-05): the nightly red-team's latest results."""
        """``GET .../decisions/{request_id}/content`` (M5-03), when content can be stored."""
        self.decisions_service = decisions_service
        self.metrics_service = metrics_service
        """``GET /v1/tenants/{tid}/guardrails/metrics`` (M4-06), when its sources exist."""
        """``GET /v1/tenants/{tid}/guardrails/decisions`` (M4-07), when records are kept."""
        self.catalog_service = catalog_service
        self.catalog_admin = catalog_admin
        self.tool_service = tool_service
        self.floor_service = floor_service
        self.repin_service = repin_service
        """The platform's floor releases and the re-pin, promotion and minimum steps (M2-09)."""
        self._reload_tasks: set[asyncio.Task[None]] = set()
        self._floor_refresher: asyncio.Task[None] | None = None
        """The tenant tool registry and its description screening (M2-03)."""
        """The platform's way to remove a catalog item, refused while a stored bundle uses it."""
        self.draft_service = draft_service
        self.draft_tools = draft_tools
        """The Admin API's draft lifecycle (M2-02), built when a draft store is available: the
        in-memory one with the in-memory policy store, the Postgres one with a Postgres pool,
        or the ``draft_store`` that was passed."""
        self.signed_context_mode = signed_context_mode
        """``v2``, ``v2+v1_migration`` or ``v1`` (a v1 HMAC verifier only): which signed
        contexts the engine accepts. Anything but ``v2`` means the migration is open; in
        production that needs ``signed_context.allow_v1_hmac``."""
        self.authenticator = authenticator
        """The Admin API's OIDC authenticator, if one was passed (M2-02 uses it)."""
        self.authorizer = authorizer
        """The Admin API's authorizer, built when ``authz_audit`` was passed."""
        self.test_overrides = test_overrides
        """The test-only overrides this engine was built with, by argument name
        (``nonce_source``, ``pii_detector``); empty for an engine that behaves as production
        would. Recorded on every bootstrap publish's class A event."""
        self.guard = guard
        self.model = model
        self.store = store
        self.catalog = catalog
        self.tenants = tenants
        self._hooks = hooks
        self.telemetry = telemetry
        self._admin_audit = admin_audit
        self._api_key = api_key
        self._model_close = model_close
        self._store_close = store_close
        self._operator_close = operator_close
        self._bus_close = bus_close
        self._store_kind = store_kind
        self._background_close = background_close
        self._accepting = True
        self._in_flight = 0
        self._idle = asyncio.Event()
        self._idle.set()
        self._shutdown: asyncio.Future[None] | None = None

    def __repr__(self) -> str:
        key = "***" if self._api_key is not None else None
        return (
            f"Engine(model={self.model.model_id!r}, store={self._store_kind!r}, "
            f"accepting={self._accepting}, api_key={key!r})"
        )

    __str__ = __repr__

    def start_floor_refresh(self, interval_s: float) -> None:
        """Reload the platform's release state and minimum floor every ``interval_s`` (the
        pointer TTL), so a dropped ``floor`` event can't leave a replica on an old minimum or
        released set for longer than that. A failed reload is logged and
        tried again at the next tick."""
        if self.floor_service is None or self._floor_refresher is not None:
            return

        async def loop() -> None:
            assert self.floor_service is not None
            while True:
                await asyncio.sleep(interval_s)
                try:
                    await self.floor_service.load()
                except Exception:
                    logger.exception("the floor state could not be reloaded; trying again")

        self._floor_refresher = asyncio.get_running_loop().create_task(loop())

    def start_shadow_flush(self, interval_s: float = 5.0) -> None:
        """Write the shadow comparison counts to their store every ``interval_s`` (M4-03). The
        check path only buffers; a failed write is logged and tried again at the next tick."""
        flush = getattr(self._shadow_stats, "flush", None)
        if flush is None or self._shadow_flusher is not None:
            return

        async def loop() -> None:
            while True:
                await asyncio.sleep(interval_s)
                try:
                    await flush()
                except Exception:
                    logger.exception("the shadow counts could not be flushed; trying again")

        self._shadow_flusher = asyncio.get_running_loop().create_task(loop())

    def _on_published(self, event: Any) -> None:
        """``guardrail.published``: a tenant's policy or tool registry changed, or (action
        ``floor``) the platform's releases or minimum floor did, which every replica reloads."""
        if getattr(event, "action", None) == "floor":
            if self.floor_service is not None:
                task = asyncio.get_running_loop().create_task(self.floor_service.load())
                self._reload_tasks.add(task)
                task.add_done_callback(self._reload_tasks.discard)
            return
        self.invalidate_tenant(event.tenant_id)

    def invalidate_tenant(self, tenant_id: str) -> None:
        """Serve the tenant's next check from a fresh read: its policy pointer and, if the
        directory is cached, its directory entry. Called on ``guardrail.published`` and on
        ``tenant.changed``; without the event the pointer TTL (and the directory's) bound it."""
        self.guard.policy_cache.invalidate(tenant_id)
        if self.guard.rollout is not None:
            self.guard.rollout.invalidate(tenant_id)  # the candidate pointer and its compile
        invalidate = getattr(self.tenants, "invalidate", None)
        if callable(invalidate):
            invalidate(tenant_id)

    def on_tenant_changed(self, event: Any) -> None:
        """Subscribe this to the directory's ``tenant.changed`` bus (M2-07): adding, suspending
        or reinstating a tenant invalidates caches like a publish does, and makes the
        cross-tenant identifier scan read the directory again (M3-01)."""
        self.invalidate_tenant(event.tenant_id)
        on_changed = getattr(self.tenants, "on_changed", None)
        if callable(on_changed):
            on_changed(event)

    def admin_app(self) -> Any:
        """The Admin API as an ASGI application (M2-02), for the deployment to serve. It needs
        the authenticator, the authorizer (``authz_audit``) and a draft store; raises
        :class:`AdminApiUnavailableError` naming what is missing. FastAPI is imported here,
        so an engine used only for checks never loads it."""
        missing = [
            name
            for name, value in (
                ("authenticator", self.authenticator),
                ("authorizer (pass authz_audit)", self.authorizer),
                ("draft_service (pass draft_store, or use a memory or Postgres store)",
                 self.draft_service),
                ("draft_tools", self.draft_tools),
                ("golden_service", self.golden_service),
                ("catalog_service", self.catalog_service),
                ("tool_service", self.tool_service),
                ("floor_service and repin_service", self.floor_service and self.repin_service),
                ("publish_service", self.publish_service),
            )
            if value is None
        ]  # fmt: skip
        if missing:
            raise AdminApiUnavailableError("the Admin API needs: " + ", ".join(missing))
        from guardrail_engine.admin.adapters.fastapi_app import create_admin_app

        assert self.authenticator and self.authorizer and self.draft_service and self.draft_tools
        assert self.golden_service and self.publish_service and self.catalog_service
        assert self.tool_service and self.floor_service and self.repin_service
        return create_admin_app(
            authenticator=self.authenticator,
            authorizer=self.authorizer,
            service=self.draft_service,
            tools=self.draft_tools,
            golden=self.golden_service,
            catalog=self.catalog_service,
            publisher=self.publish_service,
            tool_registry=self.tool_service,
            floors=self.floor_service,
            repin=self.repin_service,
            calibration=self.calibration_service,
            rollout=self.rollout_service,
            escalations=self.escalation_service,
            decisions=self.decisions_service,
            stored_content=self.stored_content_service,
            nightly=self.nightly_service,
            approvals=self.approval_service,
            metrics=self.metrics_service,
            tiers=self.tier_service,
            provider_health=self.provider_health_service,
        )

    @property
    def gateway(self) -> DecisionGateway:
        return self.guard.gateway

    @property
    def accepting(self) -> bool:
        """False once shutdown has started."""
        return self._accepting

    @property
    def in_flight(self) -> int:
        """Checks running now."""
        return self._in_flight

    @property
    def connection_hook(self) -> ConnectionHook:
        """An extra observer of each model call's :class:`CallInfo` (M1-10), called after the
        span hook. Synchronous, quick, and must not block. Default (and when set to None)
        :func:`ignore_connection_info`."""
        return self._hooks.hook

    @connection_hook.setter
    def connection_hook(self, hook: ConnectionHook | None) -> None:
        self._hooks.hook = hook if hook is not None else ignore_connection_info

    @property
    def shutdown_bound_s(self) -> float:
        """The most :meth:`shutdown` can take: the drain, the Guard Service close (gateway
        close bound plus one resource bound), and one resource bound each for the HTTP
        client and the store."""
        s = self.settings.shutdown
        return (
            s.drain_timeout_s
            + self.settings.gateway.close_timeout_s
            + 3 * s.resource_close_timeout_s
        )

    # ------------------------------------------------------------------ checks

    async def check(self, ctx: CheckContext, guard_point: str, content: str) -> Verdict:
        """:meth:`GuardService.check`: a verdict, never an exception (only cancellation of
        the caller propagates).

        Once shutdown has started, no check is made: the verdict is ``block`` with reason
        ``engine_closed``, ``retryable`` true, ``provider_called`` false and no
        ``retry_after_ms`` (M1-11, decided 2026-11-17), audited and traced like any other.
        "Every non-``allow`` withholds" covers it, so a caller can't mistake it for a pass.
        A check that started before shutdown runs to its end (or its budget)."""
        if not self._accepting:
            return self._refuse_closed(ctx, guard_point, content)
        self._in_flight += 1
        self._idle.clear()
        try:
            return await self.guard.check(ctx, guard_point, content)
        finally:
            self._in_flight -= 1
            if self._in_flight == 0:
                self._idle.set()

    @contextlib.asynccontextmanager
    async def _tracked_work(self) -> AsyncIterator[None]:
        """In-flight accounting for work that is not a check (a draft test, M2-05): refused
        once shutdown has started, and waited for by the drain like a check, so the Guard
        Service is not closed under a running test."""
        if not self._accepting:
            raise EvaluatorUnavailableError()
        self._in_flight += 1
        self._idle.clear()
        try:
            yield
        finally:
            self._in_flight -= 1
            if self._in_flight == 0:
                self._idle.set()

    def _refuse_closed(self, ctx: Any, guard_point: Any, content: Any) -> Verdict:
        try:
            return self.guard.refuse_closed(ctx, guard_point, content)
        except Exception:  # the Guard Service promises not to raise; never raise anyway
            logger.exception("engine_closed verdict failed; returning a minimal one")
            return Verdict(
                request_id=uuid.uuid4().hex,
                tenant_id=None,
                guard_point=guard_point if isinstance(guard_point, str) else "<unknown>",
                decision=Decision.BLOCK,
                reason=Reason.ENGINE_CLOSED,
                checked_at=datetime.now(UTC),
                latency_ms=0.0,
            )

    async def bootstrap_publish(self, document: dict[str, Any], *, activate: bool = True) -> str:
        """**Privileged.** Compile, store and (by default) activate a tenant bundle
        ``document`` **without the Admin API**; returns its ``bundle_hash``. For the dogfood
        and the demo only (M1-11, decided 2026-11-17). It skips R2's approvals, so it must
        never be reachable through the SDK or any tenant-facing surface (M1-07); publishing
        otherwise goes through the Admin API (M2-07), which replaces this path.

        * Allowed in ``staging`` (the dogfood) and ``test`` (tests and the demo).
        * Refused with :class:`BootstrapRefusedError` when ``settings.environment`` is
          ``production`` (the default); in ``staging`` unless the class A sink is durable
          (``class_a_audit.file``: the JSON log line is for ``test`` only); and when the
          tenant's tier isn't ``standard`` (regulated tiers need R2's two-person approval).
        * Writes a class A audit event (actor ``bootstrap``, the diff against the active
          version with URL fields summarised, and the resulting hash) to the engine's class
          A sink **before** activating; if that write fails, nothing is activated and the
          error propagates.

        The tenant must be in the tenant directory. Raises ``PolicyInvalidError`` for a
        bundle that doesn't compile, and the store's errors (``ActivePointerConflictError``
        if another publish moved the pointer meanwhile)."""
        environment = self.settings.environment
        # Decided 2026-11-17: allowed in staging and test only. Once the Admin API (M2-07)
        # ships, staging is refused too, leaving test only.
        if environment == "production":
            logger.warning("bootstrap_publish refused: environment is production")
            raise BootstrapRefusedError(
                "bootstrap_publish is refused when environment is 'production'; publish "
                "through the Admin API"
            )
        if environment == "staging" and getattr(self._admin_audit, "durable", False) is not True:
            logger.warning("bootstrap_publish refused: staging without a durable class A sink")
            raise BootstrapRefusedError(
                "bootstrap_publish in staging needs a durable class A audit sink: set "
                "class_a_audit.file (the JSON log line is acceptable in test only)"
            )
        parsed = parse_bundle(document)
        tenant_id = parsed.bundle.tenant_id
        profile = await self.tenants.get(tenant_id)
        if profile is None:
            raise LookupError(f"tenant {tenant_id!r} is not in the tenant directory")
        if profile.attributes.tier != "standard":
            logger.warning(
                "bootstrap_publish refused for tenant %s: tier isn't standard", tenant_id
            )
            raise BootstrapRefusedError(
                f"bootstrap_publish is refused for tenant {tenant_id!r}: only the standard tier "
                "may be published without the Admin API (regulated tiers need R2's approvals)"
            )
        compiled = PolicyCompiler(self.catalog, profile, self.settings.platform).compile(
            parsed, profile.attributes
        )
        # The one place the factory issues a scope: bootstrap_publish is a platform-operator
        # tool (never reachable from a request), and the tenant was just found in the
        # directory above.
        store = self.store.scoped(issue_scope(tenant_id))
        previous_version = await store.get_active_version(tenant_id)
        previous = (
            None
            if previous_version is None
            else await store.get_version(tenant_id, previous_version)
        )
        await store.put_version(tenant_id, parsed, bundle_hash=compiled.bundle_hash)
        event = BootstrapPublishEvent(
            environment=environment,
            tenant_id=tenant_id,
            version=parsed.bundle.version,
            bundle_hash=compiled.bundle_hash,
            previous_version=previous_version,
            previous_bundle_hash=None if previous is None else previous.bundle_hash,
            activate=activate,
            diff=bundle_diff({} if previous is None else previous.document, parsed.document),
            at=datetime.now(UTC),
            test_overrides=self.test_overrides,
        )
        self._admin_audit.record_admin(event)
        if activate:
            await store.set_active_version(
                tenant_id, parsed.bundle.version, expected_current=previous_version
            )
        logger.info(
            "bootstrap_publish: tenant=%s version=%d hash=%s activated=%s",
            tenant_id,
            parsed.bundle.version,
            compiled.bundle_hash,
            activate,
        )
        return compiled.bundle_hash

    # ------------------------------------------------------------------ shutdown

    async def __aenter__(self) -> Engine:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.shutdown()

    async def shutdown(self) -> None:
        """Shut down in the order the module docstring gives, within
        :attr:`shutdown_bound_s`. Safe to call more than once and from several tasks; a
        caller that is cancelled doesn't stop the shutdown."""
        if self._shutdown is None:
            # 1. Stop accepting checks, at once: before this call first waits.
            self._accepting = False
            self._shutdown = asyncio.ensure_future(self._shut_down())
        await asyncio.shield(self._shutdown)

    async def _shut_down(self) -> None:
        bounds = self.settings.shutdown
        logger.info("engine shutting down: accepting no new checks, %d in flight", self._in_flight)
        # 2. Let the checks in flight finish or reach their budgets.
        try:
            await asyncio.wait_for(self._idle.wait(), bounds.drain_timeout_s)
        except TimeoutError:
            logger.warning(
                "engine shutdown: %d checks still running after %.2f s; closing anyway",
                self._in_flight,
                bounds.drain_timeout_s,
            )
        for task in [
            *self._reload_tasks,
            *([self._floor_refresher] if self._floor_refresher else []),
            *([self._shadow_flusher] if self._shadow_flusher else []),
        ]:
            task.cancel()  # the floor reloads, periodic and event-driven; the shadow flush
        # 2a. Shadow evaluations in flight stop, and their counts are written once more.
        await self.guard.drain_shadow(cancel=True)
        flush = getattr(self._shadow_stats, "flush", None)
        if flush is not None:
            try:
                await asyncio.wait_for(flush(), bounds.resource_close_timeout_s)
            except Exception:
                logger.exception("the last shadow counts could not be written")
        # 2b. Background tasks (the keyset refresher).
        if self._background_close is not None:
            await self._background_close.run(bounds.resource_close_timeout_s)
        # 2c. The escalation router (M4-05): the queued items are stored, or counted as
        # dropped, within the resource bound.
        if self.escalation_router is not None:
            router = self.escalation_router
            await _CloseStep(
                "escalation router", lambda: router.aclose(bounds.resource_close_timeout_s)
            ).run(bounds.resource_close_timeout_s + 1.0)
        # 3. The Guard Service: policy cache, then the gateway's aclose (flush and stop the
        # event drainer within its own bound).
        guard_close = _CloseStep("Guard Service and gateway", self.guard.aclose)
        await guard_close.run(
            self.settings.gateway.close_timeout_s + bounds.resource_close_timeout_s
        )
        # 3a. Decision records still queued are written (bounded); the rest are counted.
        if self.decision_writer is not None:
            try:
                await self.decision_writer.aclose(bounds.resource_close_timeout_s)
            except Exception:
                logger.exception("the decision record writer did not close cleanly")
        # 3b. Stored content still queued is written (bounded); the rest is counted.
        if self.content_writer is not None:
            try:
                await self.content_writer.aclose(bounds.resource_close_timeout_s)
            except Exception:
                logger.exception("the stored content writer did not close cleanly")
        # 4. The model, and with it the HTTP client it owns.
        if self._model_close is not None:
            await self._model_close.run(bounds.resource_close_timeout_s)
        # 5. The event listener, then the store.
        if self._bus_close is not None:
            await self._bus_close.run(bounds.resource_close_timeout_s)
        if self._store_close is not None:
            await self._store_close.run(bounds.resource_close_timeout_s)
        if self._operator_close is not None:
            await self._operator_close.run(bounds.resource_close_timeout_s)
        logger.info("engine shut down")


@dataclass(frozen=True)
class _CloseStep:
    """One bounded shutdown step."""

    what: str
    close: Callable[[], Awaitable[None]]
    on_timeout: Callable[[], None] | None = None
    """Called if ``close`` takes too long (for a pool: terminate its connections)."""

    async def run(self, timeout_s: float) -> None:
        """Run ``close`` within ``timeout_s``. A failure or timeout is logged (exception type
        only: a driver's message may hold a DSN) and doesn't stop the next step."""
        try:
            await asyncio.wait_for(self.close(), timeout_s)
        except TimeoutError:
            logger.warning(
                "engine shutdown: closing the %s took over %.2f s; abandoned", self.what, timeout_s
            )
            if self.on_timeout is not None:
                try:
                    self.on_timeout()
                except Exception as e:
                    logger.error("engine shutdown: %s: %s", self.what, type(e).__name__)
        except Exception as e:
            logger.error("engine shutdown: closing the %s failed (%s)", self.what, type(e).__name__)

    @classmethod
    def of(cls, what: str, component: object) -> _CloseStep | None:
        """A step for ``component`` if it has ``aclose()``."""
        close = getattr(component, "aclose", None)
        return cls(what, close) if callable(close) else None

    @classmethod
    def pool(cls, pool: Any) -> _CloseStep:
        return cls("policy store's Postgres pool", pool.close, pool.terminate)


def _identifier_source(
    directory: Any, given: OtherTenantIdentifiers | None
) -> OtherTenantIdentifiers | None:
    """The source the cross-tenant scan reads (M3-01): the one passed in, else the directory's
    own, else None (the Guard Service's default: nothing to scan for)."""
    if given is not None:
        return given
    own = getattr(directory, "other_tenant_identifiers", None)
    return own() if callable(own) else None


async def build_engine(
    settings: EngineSettings | None = None,
    *,
    verifier: ContextVerifier | None = None,
    keyset_source: KeysetSource | None = None,
    key_loader: Callable[[bytes], SignatureVerifier] | None = None,
    legacy_verifier: ContextVerifier | None = None,
    authenticator: Authenticator | None = None,
    authz_audit: AuthzAuditSink | None = None,
    draft_store: ScopedDraftStores | None = None,
    golden_store: ScopedGoldenStores | None = None,
    escalation_store: ScopedEscalationStores | None = None,
    escalation_outbox: OutboxStore | None = None,
    escalation_alerts: AlertSink | None = None,
    calibration_store: ScopedCalibrationStores | None = None,
    shadow_stats: Any | None = None,
    decision_records: Any | None = None,
    stored_content: Any | None = None,
    nightly_results: Any | None = None,
    nightly_quarantine: Any | None = None,
    usage_metrics: Any | None = None,
    tool_store: ScopedToolStores | None = None,
    platform_store: PlatformStore | None = None,
    notifier: Notifier | None = None,
    lifecycle_store: ScopedLifecycleStores | None = None,
    approval_store: ScopedApprovalStores | None = None,
    publish_bus: PublishBus | None = None,
    pg_operator_pool: Any | None = None,
    tenants: TenantDirectory | None = None,
    other_tenants: OtherTenantIdentifiers | None = None,
    model: DecisionModel | None = None,
    http_client: Any = None,
    store: ScopedPolicyStores | None = None,
    pg_pool: Any = None,
    catalog: Catalog | None = None,
    audit: AuditSink | None = None,
    meter: UsageMeter | None = None,
    alerts: AlertSink | None = None,
    on_integrity_failure: AlertHook | None = None,
    connection_hook: ConnectionHook | None = None,
    key_id: Callable[[], str] | None = None,
    telemetry: Telemetry | None = None,
    admin_audit: AdminAuditSink | None = None,
    pii_detector: PiiDetector | None = None,
    nonce_source: NonceSource | None = None,
    rate_store: TokenRateStore | None = None,
    project_models: Mapping[str, DecisionModel] | None = None,
    directory_store: TenantDirectoryStore | None = None,
    directory_bus: EventBus | None = None,
) -> Engine:
    """Build the engine from ``settings`` (default: every default). See the module docstring.

    * ``verifier``: how signed tenant contexts are verified (the API gateway's scheme), **or**
      build the v2 (Ed25519) verifier from ``keyset_source`` (the secret manager's keyset
      document), ``key_loader`` (turns raw public-key bytes into a verifier; the
      ``signing.adapters.ed25519`` adapter's ``Ed25519Verifier.from_raw``) and the
      ``signed_context`` settings. The keyset is read once at startup (an unreadable or invalid
      one stops startup) and refreshed every ``signed_context.keyset_refresh_s`` by a
      background task the engine stops at shutdown. Pass exactly one of the two ways.
    * ``legacy_verifier``: a v1 HMAC verifier to run beside the v2 one during the migration.
      Accepted only with ``signed_context.allow_v1_hmac``.

      **A v1 HMAC context is refused in ``production`` and ``staging`` unless
      ``signed_context.allow_v1_hmac`` is true** (decided 2026-11-17): a ``verifier`` that would
      accept one, or a ``legacy_verifier``, stops startup otherwise. The mode is logged and kept on
      :attr:`Engine.signed_context_mode`.
    * ``authenticator`` and ``authz_audit``: the Admin API's OIDC authenticator
      (:mod:`guardrail_engine.signing.adapters.oidc`) and the sink for cross-tenant access
      events; kept on the engine as ``authenticator`` and ``authorizer`` for the REST layer
      (M2-02). Not used by the Guard Service.
    * ``shadow_stats``: where the shadow candidate's comparison counts go (M4-03): a sink with
      ``record(observation)`` and a reader with ``tally(scope, active, candidate)``. Default:
      in memory, or Postgres with the store.
    * ``decision_records``: where each check's decision record is kept (M4-07), an object with
      ``append_many(records)`` and ``page(scope, filter, limit, after)``. The Guard Service's
      audit sink writes to it **behind** the check, through a bounded queue
      (:class:`~guardrail_engine.audit.writer.DecisionRecordWriter`); it is also what
      ``GET /v1/tenants/{tid}/guardrails/decisions`` reads. Default: ``decision_records`` on
      Postgres with the Postgres store, and none with the memory store (a test passes
      :class:`~guardrail_engine.audit.store.InMemoryDecisionRecords`). An ``audit`` sink passed
      as well still receives every verdict.
    * ``usage_metrics``: where the metrics report reads the metered usage (M4-06), an object with
      ``totals(scope, window)``. Default: the Postgres ``usage_events`` with the Postgres store;
      with the memory store a test passes
      :class:`~guardrail_engine.metrics.store.InMemoryUsageMetrics`. The records' side is
      ``decision_records``. Without both there is no metrics route. Cost is priced at
      ``token_rate.price_per_million_input_tokens_usd`` (default 0.10).
    * ``tenants``: the tenant directory; default an empty in-memory one.
    * ``other_tenants``: the cross-tenant identifier scan's source (M3-01). Default: the
      directory's own (``CachedTenantDirectory.other_tenant_identifiers()``: every tenant's id
      and its platform-reviewed identifier patterns), and nothing to scan for when the
      directory has none (the in-memory one).
    * ``model``: a ``DecisionModel`` to use instead of the Gemini adapter (for example
      ``FakeDecisionModel``): no key, no network, and ``gemini`` settings are not used.
    * ``http_client``: an ``httpx.AsyncClient`` for the adapter (borrowed, never closed);
      it then owns its own pool limits and keepalive.
    * ``store``: a ``PolicyStore`` to use instead of building one; ``pg_pool``: an
      ``asyncpg.Pool`` for the Postgres store (borrowed, never closed).
    * ``catalog``: a catalog to use instead of reading ``settings.catalog``'s files.
    * ``audit``, ``meter``, ``alerts``, ``on_integrity_failure``: sinks. ``meter`` is passed
      to the gateway as given, so a meter implementing more of the gateway's optional meter
      protocols keeps them.
    * ``connection_hook``: the initial :attr:`Engine.connection_hook` (an extra observer;
      the span hook is always connected).
    * ``key_id``: the current key's non-secret id. Pass the secret manager's version id
      when there is one (it also tells a re-issued identical key apart); the default is the
      key's 12-hex-digit SHA-256 fingerprint, or ``"injected-model"`` with a model override.
    * ``telemetry``: the telemetry port; default :class:`OtelTelemetry` on the global
      tracer provider.
    * ``admin_audit``: where :meth:`Engine.bootstrap_publish` writes its class A events.
      Default: an :class:`~guardrail_engine.engine.bootstrap.AppendOnlyFileAdminAuditSink`
      on ``class_a_audit.file`` when that is set (checked at startup: it must open for
      append), otherwise the
      :class:`~guardrail_engine.engine.bootstrap.LoggingAdminAuditSink` (``test`` only).
      Passing a sink and setting the file both is refused.
    * ``pii_detector``: **test only.** A PII detector in place of the deterministic one
      (M1-14), like the model override. Accepted only when ``environment`` is ``test``.
    * ``nonce_source``: **test only.** The renderer's nonce source, for reproducible
      calibration draws. Accepted only when ``environment`` is ``test``.
    Either override is recorded: see the module docstring, "Test-only overrides".
    * ``rate_store``: where the project's token bucket, daily request count and monthly spend
      live (M3-10). Engines of one project in one process pass the same store and
      share one limit; a Redis-compatible :class:`TokenRateStore` shares it across replicas.
      The default is a private in-process store. Ignored when the limiter is off
      (``settings.effective_token_rate()`` is None).

    * ``project_models``: a ``DecisionModel`` per dedicated Gemini project (M5-06), by label,
      used instead of building the adapter from the project's ``key_env`` (as ``model`` is for
      the shared pool): no key, no network. Every dedicated project in ``settings.projects``
      needs either its model here or its key variable set; one with neither stops startup.

    * ``directory_store`` and ``directory_bus``: the tenant directory's **write** side (the
      platform's database role; M2-01). With the store (and the lifecycle store, which a store of
      the engine's own provides) the engine builds the operator-only tier route
      (``Engine.tier_service``, M5-01): a :class:`TenantProvisioner` that assigns regulated
      tenants a dedicated project from ``settings.projects`` (M5-06) and alerts on a raise the
      active version doesn't meet. Without them there is no such route; the directory is then
      written by operator tooling that builds its own provisioner.

    Raises :class:`SettingsError` for bad configuration and :class:`EngineStartError` if a
    resource can't be created; in both cases nothing is left running.
    """
    settings = settings if settings is not None else EngineSettings()
    if model is not None and http_client is not None:
        raise TypeError("http_client is for the Gemini adapter; it can't be used with model")
    if store is not None and pg_pool is not None:
        raise TypeError("pg_pool is for building the Postgres store; it can't be used with store")

    # ---- validate everything before creating anything
    problems = settings.problems()
    problems.extend(
        _signed_context_problems(settings, verifier, keyset_source, key_loader, legacy_verifier)
    )
    test_overrides = _test_overrides(settings, pii_detector, nonce_source, problems)
    api_key: ApiKey | None = None
    if model is None:
        if not settings.gemini.paid_tier:
            problems.append(
                "gemini.paid_tier: must be true to use the Gemini adapter. Set it only for a "
                "paid-tier key: Google may use free-tier data to improve its products."
            )
        raw_key = os.environ.get(API_KEY_ENV, "")
        if not raw_key.strip():
            problems.append(f"{API_KEY_ENV}: not set in the environment (needed for the adapter)")
        elif (problem := api_key_problem(raw_key)) is not None:
            problems.append(f"{API_KEY_ENV}: {problem}")  # never the value
        else:
            api_key = ApiKey(raw_key)
        del raw_key
    project_keys = _project_keys(settings, project_models, model, problems)
    dsn: str | None = None
    operator_dsn: str | None = None
    if store is None:
        if settings.store.kind == "postgres" and pg_pool is None:
            raw_dsn = os.environ.get(PG_DSN_ENV, "")
            if not raw_dsn.strip():
                problems.append(
                    f"{PG_DSN_ENV}: not set in the environment (store.kind is postgres)"
                )
            elif (problem := pg_dsn_problem(raw_dsn)) is not None:
                problems.append(f"{PG_DSN_ENV}: {problem}")  # never the value
            else:
                dsn = raw_dsn
            del raw_dsn
        elif settings.store.kind == "memory" and pg_pool is not None:
            problems.append("store.kind: is 'memory', but a Postgres pool was passed")
        if settings.store.kind == "postgres" and pg_operator_pool is None:
            raw_operator = os.environ.get(PG_OPERATOR_DSN_ENV, "")
            if raw_operator.strip():
                if (problem := pg_dsn_problem(raw_operator)) is not None:
                    problems.append(f"{PG_OPERATOR_DSN_ENV}: {problem}")  # never the value
                else:
                    operator_dsn = raw_operator
            del raw_operator
    if (
        store is None
        and settings.store.kind == "postgres"
        and settings.environment in ("production", "staging")
        and not settings.store.operator_role
    ):
        problems.append(
            f"store.operator_role: required in {settings.environment} with a Postgres store, so "
            "the startup "
            "check can refuse an application role that is a member of the operator role"
        )
    audit_file = settings.class_a_audit.file
    class_a_ok = False
    if audit_file is not None:
        if admin_audit is not None:
            problems.append(
                "class_a_audit.file: set, but an admin_audit sink was also passed; use one"
            )
        else:
            file_sink = AppendOnlyFileAdminAuditSink(audit_file)
            try:
                file_sink.check()
            except ClassAAuditFileError as e:
                problems.append(f"class_a_audit.file: {e}")  # the path and error type only
            else:
                admin_audit = file_sink
                class_a_ok = True
    spill_path = _spill_path(settings)
    spill_setting = settings.decision_spill.file
    if spill_path is not None and (spill_setting is not None or class_a_ok):
        try:  # the decision spill (M7-04) is held to the same checks as the class A file
            decision_spill_at(spill_path).check()
        except ClassAAuditFileError as e:
            problems.append(f"decision_spill.file: {e}")
    if (
        spill_path is None
        and settings.environment in ("production", "staging")
        and (decision_records is not None or settings.store.kind == "postgres")
    ):
        problems.append(
            "decision_spill.file: required in production and staging when decision records are "
            "stored (set it, or class_a_audit.file, beside which it is kept): without a spill "
            "location a regulated tenant's record is dropped when the write-behind queue is full"
        )
    if (
        authz_audit is not None
        and settings.environment != "test"
        and getattr(authz_audit, "durable", False) is not True
    ):
        problems.append(
            f"authz_audit: a cross-tenant audit sink that isn't durable is accepted only when "
            f"environment is 'test', not {settings.environment!r}; pass a durable "
            "sink, or set class_a_audit.file"
        )
    if authenticator is not None and settings.environment in ("production", "staging"):
        # R2's two people are two humans, so each issuer must say how its machine tokens
        # are marked (or declare that it issues human tokens only).
        unmarked_issuers = getattr(authenticator, "unmarked_issuers", None)
        if not callable(unmarked_issuers):
            problems.append(
                "authenticator: it can't say how machine tokens are marked, so a service account "
                f"could pass as a person; refused in {settings.environment}"
            )
        elif unmarked := unmarked_issuers():
            problems.append(
                f"authenticator: {len(unmarked)} issuer(s) declare neither a machine-token marker "
                "nor humans_only (OidcConfig.machine_markers), so a service account could "
                f"approve or publish as a person; refused in {settings.environment}: "
                + ", ".join(unmarked)
            )
    if catalog is None:
        catalog = _build_catalog(settings, problems)
    if (
        catalog is not None
        and not isinstance(catalog, InMemoryCatalog)
        and settings.environment in ("production", "staging")
    ):
        problems.append(
            "catalog: a production or staging engine needs an InMemoryCatalog, because the "
            "floor release state (R5) is applied to it and a catalog that can't be restricted "
            "would leave every floor in it extendable"
        )
    if settings.environment in ("production", "staging"):
        resolved = _identifier_source(tenants, other_tenants)
        if resolved is None:
            problems.append(
                "other_tenants: the cross-tenant identifier scan has no source (the directory "
                "doesn't provide one), so it would scan for nothing; use a directory that does "
                "(CachedTenantDirectory), pass other_tenants, or opt out on purpose with "
                "other_tenants=NoOtherTenantIdentifiers()"
            )
        elif isinstance(resolved, NoOtherTenantIdentifiers):  # passed, or the directory's own
            logger.warning(
                "the cross-tenant identifier scan is switched off on purpose "
                "(the source is NoOtherTenantIdentifiers) in %s: no tenant id or identifier "
                "pattern is scanned for",
                settings.environment,
            )
    release_records = _release_records(settings, catalog, problems)
    if problems:
        raise SettingsError(problems)
    assert catalog is not None
    if isinstance(catalog, InMemoryCatalog):
        # Closed until the platform's release state says otherwise: only the baseline floor
        # is extendable (R5.1). FloorService.load() opens what has been released.
        catalog.set_released(())
    if authz_audit is None and isinstance(admin_audit, AppendOnlyFileAdminAuditSink):
        # The Admin API's cross-tenant access record goes to the same append-only file as the
        # other class A events.
        authz_audit = AppendOnlyFileAuthzAudit(admin_audit)

    # ---- build; on any failure close what was opened
    timeout_s = settings.shutdown.resource_close_timeout_s
    store_close: _CloseStep | None = None
    operator_close: _CloseStep | None = None
    bus_close: _CloseStep | None = None
    model_close: _CloseStep | None = _CloseStep.of("model and HTTP client", model)
    refresher: KeysetRefresher | None = None
    background_close: _CloseStep | None = None
    try:
        if verifier is None:
            assert keyset_source is not None and key_loader is not None
            verifier, refresher = await _build_v2_verifier(
                settings, keyset_source, key_loader, legacy_verifier
            )
            background_close = _CloseStep.of("keyset refresher", refresher)
        signed_context_mode = _signed_context_mode(verifier)
        store_given = store is not None
        built_store_kind = None
        if store is not None:
            store_kind = type(store).__name__
            store_close = _CloseStep.of("policy store", store)
        elif settings.store.kind == "memory":
            store_kind = built_store_kind = "memory"
            store = InMemoryPolicyStore(catalog=catalog, on_integrity_failure=on_integrity_failure)
        else:
            store_kind = built_store_kind = "postgres"
            if pg_pool is None:
                assert dsn is not None
                pg_pool = await _connect_pool(dsn)
                store_close = _CloseStep.pool(pg_pool)  # opened here, so closed here
            if pg_operator_pool is None and operator_dsn is not None:
                pg_operator_pool = await _connect_pool(operator_dsn)
                operator_close = _CloseStep.pool(pg_operator_pool)
            store = _postgres_store(pg_pool, catalog, on_integrity_failure, pg_operator_pool)
            await _check_app_role(pg_pool, settings)

        hooks = _ConnectionHookRelay(
            connection_hook or ignore_connection_info, span_hook=connection_reuse_hook
        )
        telemetry = telemetry if telemetry is not None else OtelTelemetry()
        if model is None:
            assert api_key is not None
            model = GeminiDecisionModel(
                GeminiConfig(
                    api_key=api_key.reveal(),
                    paid_tier=settings.gemini.paid_tier,
                    model=settings.gemini.model,
                    base_url=settings.gemini.base_url,
                    transport_timeout_s=settings.gemini.transport_timeout_s,
                    keepalive_expiry_s=settings.gemini.keepalive_expiry_s,
                ),
                client=http_client,
                # Coupled (M1-10, M1-11): the pool keeps one idle connection per call the
                # gateway lets be in flight on the key. Never configured separately.
                max_in_flight=settings.gateway.max_in_flight_per_key,
                on_call=hooks,
            )
            model_close = _CloseStep.of("model and HTTP client", model)
        project_backends: dict[str, ProjectBackend] = {}
        project_model_list: list[DecisionModel] = []
        for label in settings.dedicated_project_labels():
            given = (project_models or {}).get(label)
            if given is not None:
                project_model, project_key_id = given, f"{INJECTED_MODEL_KEY_ID}-{label}"
            else:
                project_key = project_keys[label]
                project_model = GeminiDecisionModel(
                    GeminiConfig(
                        api_key=project_key.reveal(),
                        paid_tier=settings.gemini.paid_tier,
                        model=settings.gemini.model,
                        base_url=settings.gemini.base_url,
                        transport_timeout_s=settings.gemini.transport_timeout_s,
                        keepalive_expiry_s=settings.gemini.keepalive_expiry_s,
                    ),
                    client=http_client,
                    max_in_flight=settings.gateway.max_in_flight_per_key,
                    on_call=hooks,
                )
                project_key_id = project_key.fingerprint()
            project_model_list.append(project_model)
            project_backends[label] = ProjectBackend(
                project_model,
                (lambda fixed=project_key_id: fixed),
                settings.effective_project_gateway(label),
            )
        if project_model_list:
            model_close = _CloseStep(
                "models and HTTP clients",
                _close_all([m for m in (model, *project_model_list) if m is not None]),
            )
        if key_id is None:
            fixed_id = api_key.fingerprint() if api_key is not None else INJECTED_MODEL_KEY_ID
            key_id = lambda: fixed_id  # noqa: E731
        directory = tenants if tenants is not None else InMemoryTenantDirectory()
        identifier_source = _identifier_source(directory, other_tenants)
        if decision_records is None and built_store_kind == "postgres":
            decision_records = _postgres_decisions(pg_pool, pg_operator_pool)
        decision_writer: DecisionRecordWriter | None = None
        if decision_records is not None:
            spill_path = _spill_path(settings)
            spill = (
                decision_spill_at(spill_path, max_bytes=settings.decision_spill.max_bytes)
                if spill_path is not None and hasattr(decision_records, "append_keyed")
                else None
            )
            decision_writer = DecisionRecordWriter(
                decision_records,
                EffectiveTerm(catalog=catalog, settings=settings.platform, directory=directory),
                alerts=alerts,
                spill=spill,
                is_regulated=directory_regulated(directory),
                is_ended=getattr(directory, "ended", None),
            )
            audit = decision_writer if audit is None else _BothAudits(audit, decision_writer)
        if stored_content is None:
            if built_store_kind == "memory" or (store_given and settings.environment == "test"):
                stored_content = InMemoryStoredContent()
            elif built_store_kind == "postgres":
                stored_content = _postgres_stored_content(pg_pool, pg_operator_pool)
        if nightly_results is None:
            if built_store_kind == "memory" or (store_given and settings.environment == "test"):
                nightly_results = InMemoryNightlyResults()
            elif built_store_kind == "postgres" and pg_operator_pool is not None:
                nightly_results = _postgres_nightly(pg_operator_pool)
        if nightly_quarantine is None:
            if built_store_kind == "memory" or (store_given and settings.environment == "test"):
                nightly_quarantine = InMemoryQuarantine()
            elif built_store_kind == "postgres" and pg_operator_pool is not None:
                nightly_quarantine = _postgres_quarantine(pg_operator_pool)
        content_writer: StoredContentWriter | None = None
        if stored_content is not None:
            content_writer = StoredContentWriter(
                stored_content,
                EffectiveContentTerm(
                    catalog=catalog, settings=settings.platform, directory=directory
                ),
                alerts=alerts,
            )
        guard = GuardService(
            model=model,
            key_id=key_id,
            verifier=verifier,
            store=store,
            tenants=directory,
            catalog=catalog,
            settings=settings.platform,
            audit=audit,
            telemetry=telemetry,
            config=GuardConfig(
                pointer_ttl_s=settings.guard.pointer_ttl_s,
                store_timeout_s=settings.guard.store_timeout_s,
                # M3-10, M3-07: the project's token-rate and quota settings ride on the
                # gateway's config.
                gateway=settings.effective_gateway(),
                repeat=RepeatConfig(
                    threshold=settings.guard.repeat_threshold,
                    window_s=settings.guard.repeat_window_s,
                    guard_points=frozenset(settings.guard.repeat_guard_points),
                ),
                refusal=RefusalConfig(
                    cap=settings.guard.refusal_escalation_cap,
                    window_s=settings.guard.refusal_escalation_window_s,
                ),
            ),
            meter=meter,
            alerts=alerts,
            pii_detector=pii_detector,
            other_tenants=identifier_source,
            nonce_source=new_nonce if nonce_source is None else nonce_source,
            projects=project_backends,
        )
        if getattr(identifier_source, "on_rejected", False) is None:
            # The directory's source reports a tenant's rejected patterns through the Guard
            # Service (log, meter, alert), not only in a log line.
            identifier_source.on_rejected = guard.report_identifier_patterns_dropped
        if draft_store is None:
            if built_store_kind == "memory" or (store_given and settings.environment == "test"):
                draft_store = InMemoryDraftStore()
            elif built_store_kind == "postgres":
                draft_store = _postgres_drafts(pg_pool, pg_operator_pool)
        if golden_store is None:
            if built_store_kind == "memory" or (store_given and settings.environment == "test"):
                golden_store = InMemoryGoldenStore()
            elif built_store_kind == "postgres":
                golden_store = _postgres_golden(pg_pool, pg_operator_pool)
        if escalation_store is None:
            if built_store_kind == "memory" or (store_given and settings.environment == "test"):
                escalation_store = InMemoryEscalationStore()
            elif built_store_kind == "postgres":
                escalation_store = _postgres_escalations(pg_pool, pg_operator_pool)
        if calibration_store is None:
            if built_store_kind == "memory" or (store_given and settings.environment == "test"):
                calibration_store = InMemoryCalibrationStore()
            elif built_store_kind == "postgres":
                calibration_store = _postgres_calibration(pg_pool, pg_operator_pool)
        if tool_store is None:
            if built_store_kind == "memory" or (store_given and settings.environment == "test"):
                tool_store = InMemoryToolStore()
            elif built_store_kind == "postgres":
                tool_store = _postgres_tools(pg_pool, pg_operator_pool)
        if platform_store is None:
            if built_store_kind == "memory" or (store_given and settings.environment == "test"):
                platform_store = InMemoryPlatformStore()
                for release in release_records:  # the simulation's recorded releases (M7-05)
                    await replay_release(platform_store, release)
            elif built_store_kind == "postgres":
                platform_store = _postgres_platform(pg_pool)
        if approval_store is None:
            if built_store_kind == "memory" or (store_given and settings.environment == "test"):
                approval_store = InMemoryApprovalStore()
            elif built_store_kind == "postgres":
                approval_store = _postgres_approvals(pg_pool, pg_operator_pool)
        if lifecycle_store is None:
            if built_store_kind == "memory" or (store_given and settings.environment == "test"):
                lifecycle_store = InMemoryLifecycleStore(
                    store,
                    approvals=approval_store if isinstance(approval_store, InMemoryApprovalStore)
                    else None,
                )  # fmt: skip
            elif built_store_kind == "postgres":
                lifecycle_store = _postgres_lifecycle(
                    pg_pool, catalog, on_integrity_failure, pg_operator_pool
                )
        if shadow_stats is None:
            if built_store_kind == "memory" or (store_given and settings.environment == "test"):
                shadow_stats = InMemoryShadowStats()
            elif built_store_kind == "postgres":
                shadow_stats = _postgres_shadow(pg_pool, pg_operator_pool)
        rollout_service = None
        if lifecycle_store is not None and shadow_stats is not None:
            # M4-03: the Guard Service reads the tenant's candidate and counts what a shadow
            # candidate did; the admin API reports it.
            guard.attach_rollout(LifecycleCandidates(lifecycle_store), shadow_stats)
            rollout_service = RolloutService(lifecycle_store, shadow_stats)
        decisions_service = None
        if decision_records is not None and lifecycle_store is not None:
            decisions_service = DecisionsService(
                decision_records, LifecycleDerivedKeys(lifecycle_store, catalog)
            )
        metrics_service = None
        if usage_metrics is None and built_store_kind == "postgres":
            usage_metrics = _postgres_usage_metrics(pg_pool, pg_operator_pool)
        record_metrics = _record_metrics_of(
            decision_records, built_store_kind, pg_pool, pg_operator_pool
        )
        if record_metrics is not None and usage_metrics is not None and lifecycle_store is not None:
            token_rate = settings.effective_token_rate()
            metrics_service = MetricsService(
                record_metrics,
                usage_metrics,
                LifecycleDerivedKeys(lifecycle_store, catalog),
                price_per_million_usd=(
                    token_rate.price_per_million_input_tokens_usd
                    if token_rate is not None
                    else DEFAULT_PRICE_PER_MILLION_INPUT_TOKENS_USD
                ),
                price_source=(
                    "settings.token_rate.price_per_million_input_tokens_usd"
                    if token_rate is not None
                    else "default (gateway/token_rate.py)"
                ),
            )
        # The audit actor is "<issuer>#<subject>": outside test, a principal with no
        # issuer is refused by the authorizer and by the services.
        require_issuer = settings.environment != "test"
        # M5-02: two-person approval needs the drafts (an edit cancels it), the lifecycle (it is
        # consumed with the publish that uses it) and the approval store. Admin notifications go
        # to the real alert sink.
        approval_service = (
            None
            if draft_store is None or lifecycle_store is None or approval_store is None
            else ApprovalService(
                approval_store, draft_store, lifecycle_store, directory,
                alerts=alerts, require_issuer=require_issuer,
            )
        )  # fmt: skip
        draft_service = (
            None
            if draft_store is None
            else DraftService(
                draft_store, store, directory, catalog, settings.platform,
                require_issuer=require_issuer, on_change=approval_service,
            )
        )  # fmt: skip
        golden_service = (
            None
            if golden_store is None
            else GoldenService(golden_store, require_issuer=require_issuer)
        )
        if content_writer is not None:
            guard.attach_content(content_writer)
        stored_content_service = (
            StoredContentService(stored_content) if stored_content is not None else None
        )
        # M4-05: the router takes ``escalate`` verdicts off the check path. Its alerts go to
        # ``escalation_alerts``, else to ``alerts`` (the real sink, not the gateway's queue);
        # its webhook notices go to ``escalation_outbox`` (a deployment that runs the outbox
        # dispatcher with an ``EscalationWebhookSink`` passes the same outbox to both).
        escalation_router = None
        escalation_service = None
        if escalation_store is not None:
            escalation_router = EscalationRouter(
                escalation_store,
                outbox=escalation_outbox,
                alerts=escalation_alerts if escalation_alerts is not None else alerts,
            )
            guard.attach_escalations(escalation_router)
            if golden_service is not None:
                escalation_service = EscalationService(
                    escalation_store, golden_service, require_issuer=require_issuer
                )
        catalog_service = (
            None
            if draft_service is None
            else CatalogService(
                catalog, settings.platform, directory, draft_service, golden_service
            )
        )
        catalog_admin = None
        if isinstance(catalog, InMemoryCatalog):
            references: Any = None
            if built_store_kind == "memory":
                references = MemoryCatalogReferences(store)
                catalog_admin = CatalogAdmin(catalog, references)
            elif built_store_kind == "postgres":
                references = _postgres_references(pg_operator_pool)
                catalog_admin = CatalogAdmin(catalog, references)
            if references is not None:
                await check_stored_pack_versions(references, catalog, settings.environment)
        if publish_bus is None:
            if built_store_kind == "postgres":
                # Replicas hear of a publish, rollback or tenant change through Postgres
                # LISTEN/NOTIFY; the pointer TTL covers a lost notification.
                publish_bus = await _start_postgres_bus(pg_pool)
                bus_close = _CloseStep.of("event bus", publish_bus)
            else:
                publish_bus = InMemoryPublishBus()
        draft_evaluator = _GuardDraftEvaluator(guard)
        calibration_service = (
            None
            if draft_service is None or golden_store is None or calibration_store is None
            else CalibrationService(
                draft_store, directory, catalog, settings.platform, golden_store,
                calibration_store, draft_service, draft_evaluator, lifecycle=lifecycle_store,
            )
        )  # fmt: skip
        if (
            draft_store is not None
            and lifecycle_store is not None
            and calibration_service is None
            and settings.environment in ("production", "staging")
        ):
            raise SettingsError(
                [
                    "calibration_store: a production or staging engine that can publish needs a "
                    "calibration store (and a golden store): the R1 precision gate reads the "
                    "stored scores, and without them no tenant rule could ever enforce"
                ]
            )
        publisher = (
            None
            if draft_store is None or lifecycle_store is None
            else PublishService(
                draft_store, lifecycle_store, directory, catalog, settings.platform,
                gate=EvidenceGate(golden_store, calibration_service, calibration_service),
                bus=publish_bus,
                require_issuer=require_issuer,
                approvals=approval_service,
            )
        )  # fmt: skip
        tool_service = None
        if tool_store is not None:
            registry_tools = RegistryTools(tool_store)
            adopt = getattr(directory, "adopt_tools", None)
            if callable(adopt):
                adopt(registry_tools)  # a cached directory with no tool provider reads the registry
            tool_service = ToolService(
                tool_store,
                directory,
                ToolScreener(draft_evaluator, catalog, settings.platform),
                announce=lambda tenant_id: publish_bus.publish(
                    GuardrailPublished(tenant_id, 0, "tools")
                ),
                usage=None if lifecycle_store is None else LifecycleToolUsage(lifecycle_store),
                require_issuer=require_issuer,
            )
        floor_service = repin_service = None
        authorizer = (
            Authorizer(
                authz_audit,
                require_issuer=require_issuer,
                tenant_ended=getattr(directory, "ended_fresh", None),  # M5-07
            )
            if authz_audit is not None
            else None
        )
        if (
            platform_store is not None
            and lifecycle_store is not None
            and isinstance(catalog, InMemoryCatalog)
        ):
            floor_service = FloorService(
                platform_store,
                catalog,
                corpus_sha256=_corpus_hasher(settings),
                allow_offline=settings.environment == "test",
                bus=publish_bus,
            )
            await floor_service.load()  # the released floors and the minimum, from the store
            if authorizer is not None:
                repin_service = RepinService(
                    platform_store, lifecycle_store, directory, _lister_of(directory), catalog,
                    settings.platform, authorizer, notifier=notifier or LoggingNotifier(),
                    bus=publish_bus,
                )  # fmt: skip
        if (
            lifecycle_store is not None
            and floor_service is None
            and settings.environment in ("production", "staging")
        ):
            raise SettingsError(
                [
                    "platform_store: a production or staging engine that can publish needs a "
                    "platform store, which holds the floor releases and the minimum (R5); "
                    "without one no floor above the baseline could ever be released"
                ]
            )
        tier_service = None
        if directory_store is not None and lifecycle_store is not None:
            tier_service = TierService(
                TenantProvisioner(
                    directory_store,
                    directory_bus if directory_bus is not None else InMemoryEventBus(),
                    projects=DedicatedProjects.of(
                        settings.dedicated_project_labels(), environment=settings.environment
                    ),
                    alerts=alerts,
                ),
                directory_store,
                catalog,
                lifecycle_store,
            )
        draft_tools = (
            None
            if draft_store is None
            else DraftTools(
                draft_store, directory, catalog, settings.platform, draft_evaluator,
                golden=golden_store, calibration=calibration_service,
            )
        )  # fmt: skip
        for shared_gateway in guard.gateways.values():
            if rate_store is not None and shared_gateway.token_rate_limiter is not None:
                # M3-10: engines of one project in one process share its bucket and
                # counters by sharing a store. ``GuardService`` builds the gateways itself, so
                # the store is handed to each limiter here, before the first check. Every
                # project keeps its own bucket in it: the store is keyed by project id (M5-06).
                shared_gateway.token_rate_limiter.store = rate_store
    except BaseException:
        for step in (model_close, bus_close, store_close, operator_close, background_close):
            if step is not None:
                await step.run(timeout_s)
        raise

    engine = Engine(
        settings=settings,
        guard=guard,
        model=model,
        store=store,
        catalog=catalog,
        tenants=directory,
        hooks=hooks,
        telemetry=telemetry,
        admin_audit=admin_audit if admin_audit is not None else LoggingAdminAuditSink(),
        api_key=api_key,
        model_close=model_close,
        store_close=store_close,
        operator_close=operator_close,
        bus_close=bus_close,
        store_kind=store_kind,
        test_overrides=test_overrides,
        background_close=background_close,
        signed_context_mode=signed_context_mode,
        authenticator=authenticator,
        authorizer=authorizer,
        floor_service=floor_service,
        repin_service=repin_service,
        draft_service=draft_service,
        draft_tools=draft_tools,
        golden_service=golden_service,
        calibration_service=calibration_service,
        rollout_service=rollout_service,
        escalation_service=escalation_service,
        escalation_router=escalation_router,
        shadow_stats=shadow_stats,
        decision_writer=decision_writer,
        content_writer=content_writer,
        stored_content_service=stored_content_service,
        nightly_service=NightlyResultsService(nightly_results, nightly_quarantine)
        if nightly_results is not None
        else None,
        decisions_service=decisions_service,
        metrics_service=metrics_service,
        catalog_service=catalog_service,
        catalog_admin=catalog_admin,
        tool_service=tool_service,
        publish_service=publisher,
        approval_service=approval_service,
        tier_service=tier_service,
        provider_health_service=(
            ProviderHealthService(platform_store, lambda: guard.gateways)
            if platform_store is not None
            else None
        ),
        publish_bus=publish_bus,
    )
    draft_evaluator.track = engine._tracked_work
    engine.start_floor_refresh(settings.guard.pointer_ttl_s)
    engine.start_shadow_flush()
    if decision_writer is not None:
        decision_writer.start()
    if content_writer is not None:
        content_writer.start()
    if test_overrides:
        logger.warning(
            "engine built with test-only overrides: %s (environment=%s)",
            ", ".join(test_overrides),
            settings.environment,
        )
    if refresher is not None:
        refresher.start()
    if signed_context_mode != "v2":
        logger.warning(
            "engine built accepting v1 HMAC signed contexts (signed_context.allow_v1_hmac=%s, "
            "mode=%s, environment=%s): the migration to v2 is not finished",
            settings.signed_context.allow_v1_hmac,
            signed_context_mode,
            settings.environment,
        )
    logger.info(
        "engine built: model=%s store=%s max_in_flight_per_key=%d floor_fail_mode=%s "
        "signed_context=%s",
        model.model_id,
        store_kind,
        settings.gateway.max_in_flight_per_key,
        settings.platform.floor_fail_mode,
        signed_context_mode,
    )
    return engine


def _signed_context_problems(
    settings: EngineSettings,
    verifier: ContextVerifier | None,
    keyset_source: KeysetSource | None,
    key_loader: Callable[[bytes], SignatureVerifier] | None,
    legacy_verifier: ContextVerifier | None,
) -> list[str]:
    """The signed-context wiring problems (M2-01): which way the verifier is given, and the v1
    HMAC rule (refused in production and staging unless ``signed_context.allow_v1_hmac``)."""
    problems: list[str] = []
    sc = settings.signed_context
    if verifier is not None and (keyset_source is not None or key_loader is not None):
        problems.append("verifier: pass a verifier, or keyset_source and key_loader, not both")
    if verifier is None:
        if keyset_source is None or key_loader is None:
            problems.append("verifier: pass a verifier, or both keyset_source and key_loader")
        elif not sc.issuers:
            problems.append("signed_context.issuers: needed with a keyset_source")
    if legacy_verifier is not None:
        if verifier is not None:
            problems.append("legacy_verifier: only with a keyset_source (it runs beside v2)")
        if not sc.allow_v1_hmac:
            problems.append(
                "signed_context.allow_v1_hmac: a legacy (v1 HMAC) verifier was passed, but v1 "
                "contexts are refused unless this is true"
            )
    if (
        verifier is not None
        and accepts_v1(verifier)
        and settings.environment in ("production", "staging")
        and not sc.allow_v1_hmac
    ):
        problems.append(
            "signed_context.allow_v1_hmac: the verifier accepts v1 HMAC contexts, which are "
            f"refused in {settings.environment} unless this is true (migration only)"
        )
    return problems


def _signed_context_mode(verifier: ContextVerifier) -> str:
    if isinstance(verifier, VersionedContextVerifier):
        return "v2+v1_migration" if verifier.v1 is not None else "v2"
    return "v1" if accepts_v1(verifier) else "v2"


async def _build_v2_verifier(
    settings: EngineSettings,
    source: KeysetSource,
    key_loader: Callable[[bytes], SignatureVerifier],
    legacy: ContextVerifier | None,
) -> tuple[ContextVerifier, KeysetRefresher]:
    """The v2 verifier from the first keyset read, and its (not yet started) refresher. An
    unreadable or invalid first keyset stops startup: an engine with no key would refuse
    every check."""
    sc = settings.signed_context
    try:
        keyset = Keyset.parse(await source.read(), key_loader)
    except ValueError:
        raise EngineStartError("signed context keyset: the document is invalid") from None
    except Exception as e:
        raise EngineStartError(
            f"signed context keyset: could not be read ({type(e).__name__})"
        ) from None
    v2 = Ed25519ContextVerifier(keyset, sc.issuers, audience=sc.audience)

    def alert(reason: str) -> None:
        logger.error(
            "signed context keyset refresh failed: %s (keeping the last good keyset)", reason
        )

    refresher = KeysetRefresher(v2, source, key_loader, alert=alert, interval_s=sc.keyset_refresh_s)
    verifier: ContextVerifier = VersionedContextVerifier(v2, legacy) if legacy is not None else v2
    return verifier, refresher


def _test_overrides(
    settings: EngineSettings,
    pii_detector: PiiDetector | None,
    nonce_source: NonceSource | None,
    problems: list[str],
) -> tuple[str, ...]:
    """The names of the test-only overrides passed, appending a problem for each the
    environment doesn't allow (see the module docstring, "Test-only overrides")."""
    environment = settings.environment
    used: list[str] = []
    if nonce_source is not None:
        used.append("nonce_source")
        if environment != "test":
            problems.append(
                f"nonce_source: an injected nonce source is accepted only when environment is "
                f"'test', not {environment!r} (a known nonce defeats spotlighting)"
            )
        elif not callable(nonce_source):
            problems.append("nonce_source: must be a callable returning a nonce")
    if pii_detector is not None:
        used.append("pii_detector")
        if environment != "test":
            problems.append(
                f"pii_detector: a PII detector override is accepted only when environment is "
                f"'test', not {environment!r} (redaction has no off switch)"
            )
    return tuple(sorted(used))


def _close_all(models: list[DecisionModel]) -> Callable[[], Awaitable[None]]:
    """One close step for the shared model and every dedicated project's: each is closed even
    when an earlier one fails."""

    async def close() -> None:
        for m in models:
            closer = getattr(m, "aclose", None)
            if callable(closer):
                try:
                    await closer()
                except Exception as e:
                    logger.error("engine shutdown: closing a model failed (%s)", type(e).__name__)

    return close


def _project_keys(
    settings: EngineSettings,
    project_models: Mapping[str, DecisionModel] | None,
    model: DecisionModel | None,
    problems: list[str],
) -> dict[str, ApiKey]:
    """Read each dedicated project's key from the environment variable its ``key_env`` names
    (M5-06), for a project that has no injected model. The value is checked as
    ``GEMINI_API_KEY`` is and never repeated: a problem names the setting and the variable."""
    keys: dict[str, ApiKey] = {}
    known = set(settings.dedicated_project_labels())
    for stray in sorted(set(project_models or {}) - known):
        problems.append(f"project_models: {stray!r} is not a dedicated project in the settings")
    for label in sorted(known - set(project_models or {})):
        where = f"projects.dedicated.{label}.key_env"
        name = settings.projects.dedicated[label].key_env
        if not settings.gemini.paid_tier:
            problems.append(
                "gemini.paid_tier: must be true to use the Gemini adapter for a dedicated "
                "project too"
            )
        raw = os.environ.get(name, "")
        if not raw.strip():
            problems.append(f"{where}: the environment variable {name} is not set")
        elif (problem := api_key_problem(raw)) is not None:
            problems.append(f"{where}: {name} {problem}")  # never the value
        else:
            keys[label] = ApiKey(raw)
        del raw
    return keys


def _tier_required_packs(
    settings: EngineSettings, packs: list[PackVersion]
) -> dict[str, frozenset[str]]:
    """The packs each tier requires (M5-01): the platform's own, ``responsible_ai`` on every
    regulated tier (R4.1), plus ``catalog.tier_required_packs``.

    A required pack the catalog does not hold is **never skipped** in ``production`` and
    ``staging``: the requirement stands, so a tenant of that tier can't publish (fail closed) and
    the error says which pack to load, and the engine logs it at startup. In ``test`` the
    platform's own requirement is left out with a warning, so a test that builds an engine with
    no pack files and a regulated tenant keeps working; a pack the settings name is kept."""
    have = {p.name for p in packs}
    required: dict[str, frozenset[str]] = dict(settings.catalog.tier_required_packs)
    strict = settings.environment in ("production", "staging")
    for tier in sorted(REGULATED_TIERS):
        listed = required.get(tier, frozenset())
        wanted = REGULATED_REQUIRED_PACKS | listed
        if missing := sorted(wanted - have):
            if strict:
                logger.error(
                    "the %s tier requires the pack(s) %s, which the catalog does not hold: a "
                    "tenant of that tier can't publish until catalog.pack_files has them",
                    tier,
                    missing,
                )
            elif unlisted := sorted(REGULATED_REQUIRED_PACKS - have - listed):
                logger.warning(
                    "the %s tier requires the pack(s) %s, which the catalog does not hold; "
                    "the requirement is not applied (environment %s)",
                    tier,
                    unlisted,
                    settings.environment,
                )
                wanted = wanted - set(unlisted)
        required[tier] = frozenset(wanted)
    return required


def _spill_path(settings: EngineSettings) -> Path | None:
    """Where regulated tenants' decision records spill: the setting, else beside the class A
    audit file, else nowhere (M7-04)."""
    if settings.decision_spill.file is not None:
        return settings.decision_spill.file
    if settings.class_a_audit.file is not None:
        return spill_file_beside(settings.class_a_audit.file)
    return None


def _build_catalog(settings: EngineSettings, problems: list[str]) -> InMemoryCatalog | None:
    """Read the floor and pack files, appending a problem for each that doesn't load, and
    check the floors against ``min_floor_version`` and the question budgets (R6.1)."""
    files = settings.catalog
    floors: list[FloorVersion] = []
    packs: list[PackVersion] = []
    templates: list[Template] = []
    for i, path in enumerate(files.floor_files):
        where = f"catalog.floor_files[{i}] ({path})"
        try:
            floors.append(load_floor_file(path))
        except OSError as e:
            problems.append(f"{where}: cannot read ({type(e).__name__})")
        except FloorFileError as e:
            problems.append(f"{where}: rejected: {e}")
    for i, path in enumerate(files.pack_files):
        where = f"catalog.pack_files[{i}] ({path})"
        try:
            packs.append(load_pack_file(path))
        except OSError as e:
            problems.append(f"{where}: cannot read ({type(e).__name__})")
        except PackFileError as e:  # not JSON, a bad document, or invalid content
            problems.append(f"{where}: rejected: {e}")
    for i, path in enumerate(files.template_files):
        where = f"catalog.template_files[{i}] ({path})"
        try:
            templates.append(load_template_file(path))
        except OSError as e:
            problems.append(f"{where}: cannot read ({type(e).__name__})")
        except TemplateFileError as e:
            problems.append(f"{where}: rejected: {e}")
    if (
        len(floors) != len(files.floor_files)
        or len(packs) != len(files.pack_files)
        or len(templates) != len(files.template_files)
    ):
        return None
    required_packs = _tier_required_packs(settings, packs)
    try:
        catalog = InMemoryCatalog(
            floors=floors,
            packs=packs,
            templates=templates,
            tier_required_packs=required_packs,
            tier_required_rules=files.tier_required_rules,
            default_on_packs=files.default_on_packs,
        )
    except ValueError as e:  # the same version twice with different content
        problems.append(f"catalog files: {e}")
        return None

    if settings.environment in ("production", "staging") and floors:
        # Tool-description screening (M2-03) asks three questions of the newest floor; without
        # them every tool registration would fail closed. Refuse to start rather than discover
        # that when a tenant adds a tool.
        newest = max(floors, key=lambda f: f.version)
        have = {r.key for r in newest.rules}
        missing = [k for k in SCREEN_RULES if k not in have]
        if missing:
            problems.append(
                f"catalog.floor_files: the newest floor ({newest.ref}) lacks {missing}, which "
                "tool-description screening asks; tool registration would always fail"
            )

    platform = settings.platform
    usable = [f for f in floors if f.version >= platform.min_floor_version]
    if not usable:
        problems.append(
            f"platform.min_floor_version: {platform.min_floor_version}, but the floor files "
            f"hold versions {sorted(f.version for f in floors)}, so no bundle could compile"
        )
    for floor in usable:
        for gp in GUARD_POINTS:
            asked = sum(gp in rule.guard_points for rule in floor.rules)
            budget = platform.question_budgets.for_guard_point(gp)
            if asked > budget:
                problems.append(
                    f"platform.question_budgets.{gp}: {budget} is less than the {asked} "
                    f"questions {floor.ref} asks there, so no bundle could compile"
                )
    return catalog


async def _check_app_role(pool: Any, settings: EngineSettings) -> None:
    """Refuse to start when the engine's Postgres role would not be held to row-level security: a
    superuser, a BYPASSRLS role, an owner of the policy tables, or a member of the operator role. In
    ``test`` the problems are logged instead, because test databases connect
    as their owner."""
    from guardrail_engine.store.adapters.postgres import app_role_problems

    problems = await app_role_problems(pool, operator_role=settings.store.operator_role)
    if not problems:
        return
    if settings.environment == "test":
        logger.warning("postgres role is not held to row-level security: %s", "; ".join(problems))
        return
    raise SettingsError([f"store: {p}" for p in problems])


class _GuardDraftEvaluator:
    """The test endpoint's view of the engine (M2-05): compile a draft with the policy cache's
    own compiler setup, and evaluate content through the Guard Service's pipeline, refusing
    once the engine has stopped accepting work."""

    def __init__(self, guard: GuardService) -> None:
        self._guard = guard
        self.track: Callable[[], Any] = contextlib.nullcontext  # set to the engine's tracking

    def compile(self, tenant_id: str, parsed: Any, profile: Any) -> Any:
        return self._guard.policy_cache.compile_draft(tenant_id, parsed, profile)

    async def evaluate(
        self,
        scope: Any,
        policy: Any,
        content: str,
        tool: str | None = None,
        usage_class: str = "test",
    ) -> Any:
        async with self.track():
            return await self._guard.evaluate_draft(
                scope, policy, content, tool=tool, usage_class=usage_class
            )


async def _start_postgres_bus(pool: Any) -> Any:
    from guardrail_engine.store.adapters.postgres import PostgresEventBus

    bus = PostgresEventBus(pool)
    await bus.start()
    return bus


class _BothAudits:
    """An audit sink the caller passed, and the decision-record writer: both see every verdict,
    and a failure of the first never stops the second."""

    def __init__(self, first: AuditSink, second: AuditSink) -> None:
        self._first, self._second = first, second

    def record(self, verdict: _AuditedVerdict) -> None:
        try:
            self._first.record(verdict)
        finally:
            self._second.record(verdict)

    async def arecord(self, verdict: _AuditedVerdict) -> None:
        """As :meth:`record`; the second sink may wait to keep a regulated tenant's record."""
        try:
            self._first.record(verdict)
        finally:
            arecord = getattr(self._second, "arecord", None)
            if arecord is not None:
                await arecord(verdict)
            else:
                self._second.record(verdict)


def _postgres_usage_metrics(pool: Any, operator_pool: Any = None) -> Any:
    from guardrail_engine.metrics.adapters.postgres import PostgresUsageMetrics

    return PostgresUsageMetrics(pool, operator_pool)


def _record_metrics_of(
    decision_records: Any, built_store_kind: str | None, pool: Any, operator_pool: Any
) -> Any:
    """The metrics side of the decision store: Postgres aggregates for the Postgres store,
    the in-memory aggregates for :class:`InMemoryDecisionRecords`, else none."""
    if decision_records is None:
        return None
    if hasattr(decision_records, "aggregate"):
        return decision_records
    if isinstance(decision_records, InMemoryDecisionRecords):
        return InMemoryRecordMetrics(decision_records)
    if built_store_kind == "postgres":
        from guardrail_engine.metrics.adapters.postgres import PostgresRecordMetrics

        return PostgresRecordMetrics(pool, operator_pool)
    return None


def _postgres_decisions(pool: Any, operator_pool: Any = None) -> Any:
    from guardrail_engine.audit.adapters.postgres import PostgresDecisionStore

    return PostgresDecisionStore(pool, operator_pool)


def _postgres_nightly(operator_pool: Any) -> Any:
    from guardrail_engine.nightly.adapters.postgres import PostgresNightlyResults

    return PostgresNightlyResults(operator_pool)


def _postgres_quarantine(operator_pool: Any) -> Any:
    from guardrail_engine.nightly.adapters.postgres import PostgresQuarantine

    return PostgresQuarantine(operator_pool)


def _postgres_stored_content(pool: Any, operator_pool: Any = None) -> Any:
    from guardrail_engine.content.adapters.postgres import PostgresStoredContent

    return PostgresStoredContent(pool, operator_pool)


async def check_stored_pack_versions(references: Any, catalog: Any, environment: str) -> None:
    """Every pack version an active or candidate bundle names must be in the catalog.
    A deployment that drops an old version from ``catalog.pack_files`` (keeping only the new one)
    would make every bundle that still extends it fail to compile, and every check of those
    tenants ``policy_unavailable``, with nothing at startup saying so. In ``production`` and
    ``staging`` that is a refusal to start (the message names the references: pack names and
    versions, never a tenant or a document); elsewhere it is a warning. **A store that can't answer
    (no operator pool, a failing database) is also a refusal to start in production and staging**
    (decided): a guard that is skipped when it can't look is not a guard. Elsewhere that is a
    warning too."""
    from guardrail_engine.policy.document import EXTENDS_REF_PATTERN

    strict = environment in ("production", "staging")
    ask = getattr(references, "active_pack_refs", None)
    try:
        if ask is None:
            raise TypeError("the store cannot report the packs its bundles name")
        named = await ask()
    except Exception as exc:
        if strict:
            raise EngineStartError(
                "the pack versions the stored bundles name could not be checked against "
                f"catalog.pack_files ({type(exc).__name__}); a production or staging engine "
                "does not start without the check"
            ) from None
        logger.warning("stored bundles' pack versions were not checked: %s", type(exc).__name__)
        return
    missing = []
    for ref in sorted(named):
        m = EXTENDS_REF_PATTERN.fullmatch(ref)
        if m is None or m.group(2) is None or catalog.pack(m.group(2), int(m.group(3))) is None:
            missing.append(ref)
    if not missing:
        return
    text = ", ".join(missing[:20]) + (f" and {len(missing) - 20} more" if len(missing) > 20 else "")
    if strict:
        raise EngineStartError(
            f"an active or candidate bundle names pack versions the catalog does not hold: {text}; "
            "list their files in catalog.pack_files (a published version is never removed)"
        )
    logger.warning("active or candidate bundles name pack versions not in the catalog: %s", text)


def _postgres_shadow(pool: Any, operator_pool: Any = None) -> Any:
    from guardrail_engine.store.adapters.postgres import PostgresShadowStats

    return PostgresShadowStats(pool, operator_pool)


def _postgres_calibration(pool: Any, operator_pool: Any = None) -> Any:
    from guardrail_engine.store.adapters.postgres import PostgresCalibrationStore

    return PostgresCalibrationStore(pool, operator_pool)


def _postgres_escalations(pool: Any, operator_pool: Any = None) -> Any:
    from guardrail_engine.escalation.adapters.postgres import PostgresEscalationStore

    return PostgresEscalationStore(pool, operator_pool)


def _postgres_golden(pool: Any, operator_pool: Any = None) -> Any:
    from guardrail_engine.store.adapters.postgres import PostgresGoldenStore

    return PostgresGoldenStore(pool, operator_pool)


def _postgres_lifecycle(
    pool: Any, catalog: Catalog, on_integrity_failure: AlertHook | None, operator_pool: Any = None
) -> Any:
    from guardrail_engine.store.adapters.postgres import PostgresLifecycleStore

    return PostgresLifecycleStore(
        pool, catalog=catalog, on_integrity_failure=on_integrity_failure,
        operator_pool=operator_pool,
    )  # fmt: skip


def _postgres_approvals(pool: Any, operator_pool: Any = None) -> Any:
    from guardrail_engine.store.adapters.postgres_approvals import PostgresApprovalStore

    return PostgresApprovalStore(pool, operator_pool)


def _postgres_references(operator_pool: Any) -> Any:
    from guardrail_engine.store.adapters.postgres import PostgresCatalogReferences

    return PostgresCatalogReferences(operator_pool)


def _postgres_platform(pool: Any) -> Any:
    from guardrail_engine.store.adapters.postgres import PostgresPlatformStore

    return PostgresPlatformStore(pool)


class _NoTenants:
    async def tenant_ids(self, *, include_suspended: bool = False) -> list[str]:
        return []


def _lister_of(directory: Any) -> Any:
    """The directory's tenant listing for the platform's bulk steps, or an empty one for a
    directory that has none (then no bulk step does anything)."""
    return directory if callable(getattr(directory, "tenant_ids", None)) else _NoTenants()


def _release_records(
    settings: EngineSettings, catalog: Any, problems: list[str]
) -> list[FloorRelease]:
    """The floor releases the engine starts with (M7-05): the records in
    ``catalog.release_records`` for floors the catalog holds, in the ``test`` environment only.
    A production or staging engine reads its release state from the platform tables.

    A record is applied only after its evidence is checked against the report file it names and
    the current corpus (the check a proposal passes); one that fails stops the start."""
    if settings.environment != "test" or not isinstance(catalog, InMemoryCatalog):
        return []
    found: list[FloorRelease] = []
    corpus = _corpus_hasher(settings)
    for i, path in enumerate(settings.catalog.release_records):
        where = f"catalog.release_records[{i}] ({path})"
        try:
            record = load(path)
            release = record.release
            if catalog.floor(release.floor_version) is None:
                continue  # a floor this engine doesn't load: the record has nothing to release
            try:
                check_against(release, catalog)
            except ReleaseRecordError as e:
                # Closed, not refused: the floor stays unreleased, as an engine with no record.
                logger.warning("%s: not applied: %s", where, e)
                continue
            check_evidence(record, corpus())
        except ReleaseRecordError as e:
            problems.append(f"{where}: {e}")
            continue
        if any(f.floor_version == release.floor_version for f in found):
            problems.append(f"{where}: floor@{release.floor_version} is released twice")
            continue
        found.append(release)
    return found


def _corpus_hasher(settings: Any) -> Any:
    """The current red-team corpus's hash, read when a release is proposed (None if the file
    isn't there: a release can't then be matched to the corpus, so it is refused)."""
    import hashlib

    path = settings.catalog.redteam_corpus

    def read() -> str | None:
        try:
            return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError:
            return None

    return read


def _postgres_tools(pool: Any, operator_pool: Any = None) -> Any:
    from guardrail_engine.store.adapters.postgres import PostgresToolStore

    return PostgresToolStore(pool, operator_pool)


def _postgres_drafts(pool: Any, operator_pool: Any = None) -> Any:
    from guardrail_engine.store.adapters.postgres import PostgresDraftStore

    return PostgresDraftStore(pool, operator_pool)


def _postgres_store(
    pool: Any,
    catalog: Catalog,
    on_integrity_failure: AlertHook | None,
    operator_pool: Any = None,
) -> Any:
    # Imported here, so an engine with the in-memory store never loads the database driver.
    from guardrail_engine.store.adapters.postgres import PostgresPolicyStore

    return PostgresPolicyStore(
        pool,
        catalog=catalog,
        on_integrity_failure=on_integrity_failure,
        operator_pool=operator_pool,
    )


async def _connect_pool(dsn: str) -> Any:
    from guardrail_engine.store.adapters.postgres import connect_pool

    try:
        return await connect_pool(dsn)
    except Exception as e:
        # The driver's message may repeat the DSN, which may hold a password.
        raise EngineStartError(
            f"policy store: could not connect to Postgres ({type(e).__name__})"
        ) from None
