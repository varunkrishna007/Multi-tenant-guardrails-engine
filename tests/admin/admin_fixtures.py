"""A draft service wired to in-memory ports, and decisions from the real authorizer."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

from guard_fixtures import ALPHA, BETA, Env, bundle, make_catalog, profile, rule

from guardrail_engine.admin import DraftService, InMemoryDraftStore
from guardrail_engine.admin.approval_service import ApprovalService
from guardrail_engine.admin.approvals import InMemoryApprovalStore
from guardrail_engine.admin.calibration import CalibrationService
from guardrail_engine.admin.calibration_store import InMemoryCalibrationStore
from guardrail_engine.admin.catalog import CatalogService
from guardrail_engine.admin.content import StoredContentService
from guardrail_engine.admin.decisions import DecisionsService, LifecycleDerivedKeys
from guardrail_engine.admin.evidence import (
    NO_PRECISION_GATE,
    NO_REGRESSION_GATE,
    EvidenceGate,
)
from guardrail_engine.admin.floors import FloorService, InMemoryNotifier, InMemoryPlatformStore
from guardrail_engine.admin.golden import GoldenService, InMemoryGoldenStore
from guardrail_engine.admin.lifecycle import InMemoryLifecycleStore, InMemoryPublishBus
from guardrail_engine.admin.metrics import MetricsService
from guardrail_engine.admin.nightly import NightlyResultsService
from guardrail_engine.admin.publish import PublishService
from guardrail_engine.admin.repin_service import RepinService
from guardrail_engine.admin.rollout import RolloutService
from guardrail_engine.admin.tool_registry import (
    InMemoryToolStore,
    LifecycleToolUsage,
    ScreeningLimiter,
    ToolScreener,
    ToolService,
)
from guardrail_engine.admin.tools import DraftTools
from guardrail_engine.audit.store import InMemoryDecisionRecords
from guardrail_engine.authz import Authorizer, InMemoryAuthzAudit, Principal, Role
from guardrail_engine.content import InMemoryStoredContent
from guardrail_engine.delivery.usage import InMemoryUsageStore
from guardrail_engine.gateway.sinks import RecordingAlertSink
from guardrail_engine.guard.shadow import InMemoryShadowStats
from guardrail_engine.guard.tenants import InMemoryTenantDirectory
from guardrail_engine.metrics.store import InMemoryRecordMetrics, InMemoryUsageMetrics
from guardrail_engine.nightly.store import InMemoryNightlyResults, InMemoryQuarantine
from guardrail_engine.policy.catalog import PlatformSettings

DRAFT = "/v1/tenants/{tid}/guardrails/draft"
RULE = "/v1/tenants/{tid}/guardrails/draft/rules/{rule_id}"
GUARDRAILS = "/v1/tenants/{tid}/guardrails"

__all__ = ["ALPHA", "BETA", "DRAFT", "GUARDRAILS", "RULE", "Admin", "bundle", "rule", "who"]


def who(
    *roles: Role, tenant: str | None = ALPHA, operator: bool = False, subject="alice", issuer=None
):
    return Principal(subject, tenant, frozenset(roles), operator, issuer)


class RecordingMeter:
    """A usage meter that remembers what it was given, by the guard point label."""

    def __init__(self):
        self.answered: list[tuple[str, str, int | None]] = []
        self.unanswered: list[tuple[str, str]] = []

    def record(self, tenant_id, guard_point, input_tokens):
        self.answered.append((tenant_id, guard_point, input_tokens))

    def record_unanswered(self, tenant_id, guard_point):
        self.unanswered.append((tenant_id, guard_point))


class GuardEvaluator:
    """What the engine's factory builds: the Guard Service's draft evaluation."""

    def __init__(self, guard):
        self.guard = guard
        self.open = True

    def compile(self, tenant_id, parsed, profile):
        return self.guard.policy_cache.compile_draft(tenant_id, parsed, profile)

    async def evaluate(self, scope, policy, content, tool=None, usage_class="test"):
        from guardrail_engine.admin.tools import EvaluatorUnavailableError

        if not self.open:
            raise EvaluatorUnavailableError()
        return await self.guard.evaluate_draft(
            scope, policy, content, tool=tool, usage_class=usage_class
        )


@dataclass
class Admin:
    drafts: InMemoryDraftStore = field(default_factory=InMemoryDraftStore)
    audit: InMemoryAuthzAudit = field(default_factory=InMemoryAuthzAudit)
    templates: tuple = ()
    """Catalog templates (M2-03) the fixture catalog holds."""
    extra_floors: tuple = ()
    """Floor versions above the fixture's floor@1 (M2-09), in the catalog but unreleased until a
    test releases them."""
    precision_gate: bool = False
    """Whether the publisher's evidence gate includes the R1 precision gate (M4-01). Off by
    default so the older tests, which publish enforcing rules without calibration, stay as
    they were; ``calibration`` is built either way."""
    regression_gate: bool = False
    """Whether the evidence gate includes the AC-A3 regression gate (M4-02); off by default."""
    screen_catalog: object = None
    """The catalog tool screening reads its three floor questions from (the fixture floor has
    only some of them); the fixture catalog when None."""

    def __post_init__(self):
        self.catalog = make_catalog(self.templates, self.extra_floors)
        self.tool_changes: list[str] = []
        self.limiter_now = 0.0
        self.cache_now = 0.0
        """The Guard Service's policy-cache clock (the pointer TTL): tests move it."""
        self.tenants = InMemoryTenantDirectory([profile(ALPHA), profile(BETA, "energy")])
        self.meter = RecordingMeter()
        self.env = Env(
            catalog=self.catalog, directory=self.tenants, meter=self.meter,
            cache_clock=lambda: self.cache_now,
        )  # fmt: skip
        self.policies = self.env.inner_store  # the store the Guard Service reads
        self.fake = self.env.fake
        self.evaluator = GuardEvaluator(self.env.service)
        self.golden_store = InMemoryGoldenStore()
        self.golden = GoldenService(self.golden_store)
        self.tools = DraftTools(
            self.drafts,
            self.tenants,
            self.catalog,
            PlatformSettings(),
            self.evaluator,
            golden=self.golden_store,
        )
        self.now = datetime(2026, 11, 20, 12, 0, tzinfo=UTC)
        """The publish service's injected clock: tests move it."""
        self.bus = InMemoryPublishBus()
        self.approval_store = InMemoryApprovalStore()
        self.lifecycle = InMemoryLifecycleStore(self.policies, approvals=self.approval_store)
        self.alerts = RecordingAlertSink()
        """Where the admin notifications of M5-02 go."""
        self.approvals = ApprovalService(
            self.approval_store, self.drafts, self.lifecycle, self.tenants,
            alerts=self.alerts, clock=lambda: self.now,
        )  # fmt: skip
        self.publisher = PublishService(
            self.drafts, self.lifecycle, self.tenants, self.catalog, PlatformSettings(),
            gate=EvidenceGate(self.golden_store, NO_PRECISION_GATE, NO_REGRESSION_GATE),
            bus=self.bus,
            clock=lambda: self.now,
            approvals=self.approvals,
        )  # fmt: skip
        self.authorizer = Authorizer(self.audit)
        self.catalog.set_released({min(self.catalog.floor_versions())})  # the baseline only
        self.platform = InMemoryPlatformStore()
        self.notifier = InMemoryNotifier()
        self.release_clock = self.now
        self.floors = FloorService(
            self.platform, self.catalog, corpus_sha256=lambda: CORPUS_HASH, allow_offline=False,
            bus=self.bus, clock=lambda: self.now,
        )  # fmt: skip
        self.repin = RepinService(
            self.platform, self.lifecycle, self.tenants, self.tenants, self.catalog,
            PlatformSettings(), self.authorizer, notifier=self.notifier, bus=self.bus,
            clock=lambda: self.now,
        )  # fmt: skip
        self.service = DraftService(
            self.drafts, self.policies, self.tenants, self.catalog, PlatformSettings(),
            on_change=self.approvals,
        )  # fmt: skip
        self.shadow_stats = InMemoryShadowStats()
        self.rollout = RolloutService(self.lifecycle, self.shadow_stats)
        self.decision_records = InMemoryDecisionRecords()
        self.decisions = DecisionsService(
            self.decision_records, LifecycleDerivedKeys(self.lifecycle, self.catalog)
        )
        self.nightly_results = InMemoryNightlyResults()
        self.nightly_quarantine = InMemoryQuarantine()
        self.nightly_service = NightlyResultsService(self.nightly_results, self.nightly_quarantine)
        self.stored_content = InMemoryStoredContent()
        self.stored_content_service = StoredContentService(self.stored_content)
        self.usage_store = InMemoryUsageStore()
        self.metrics = MetricsService(
            InMemoryRecordMetrics(self.decision_records),
            InMemoryUsageMetrics(self.usage_store),
            LifecycleDerivedKeys(self.lifecycle, self.catalog),
            price_per_million_usd=0.10,
            price_source="test",
        )
        self.calibration_store = InMemoryCalibrationStore()
        self.calibration = CalibrationService(
            self.drafts, self.tenants, self.catalog, PlatformSettings(), self.golden_store,
            self.calibration_store, self.service, self.evaluator, clock=lambda: self.now,
            concurrency=1,  # the fixture's gateway refuses a burst of test calls (admission_wait)
            lifecycle=self.lifecycle,
        )  # fmt: skip
        self.tools._calibration = self.calibration
        if self.precision_gate or self.regression_gate:
            self.publisher._gate = EvidenceGate(
                self.golden_store,
                self.calibration if self.precision_gate else NO_PRECISION_GATE,
                self.calibration if self.regression_gate else NO_REGRESSION_GATE,
            )
        self.tool_store = InMemoryToolStore()
        self.tool_service = ToolService(
            self.tool_store,
            self.tenants,
            ToolScreener(self.evaluator, self.screen_catalog or self.catalog, PlatformSettings()),
            announce=lambda tenant_id: self.tool_changes.append(tenant_id),
            usage=LifecycleToolUsage(self.lifecycle),
            limiter=ScreeningLimiter(clock=lambda: self.limiter_now),
        )
        self.catalog_service = CatalogService(
            self.catalog, PlatformSettings(), self.tenants, self.service, self.golden
        )

    async def drained_meter(self):
        """The meter events are delivered off the request path: wait for them."""
        await self.env.service.gateway.drain()
        return self.meter

    async def aclose(self):
        await self.env.service.aclose()

    async def decide(self, principal, method, route, tid=ALPHA):
        """The real authorizer's decision for ``principal`` calling ``method route`` on ``tid``."""
        return await self.authorizer.authorize(principal, method, route, tenant_id=tid)


CORPUS_HASH = "sha256:" + "c" * 64
