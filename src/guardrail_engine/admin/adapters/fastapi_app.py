"""The Admin API's REST layer on FastAPI (M2-02): authenticate, authorize, call the service.

Every handler does the same three things, in this order, and nothing else touches the request:

1. **Authenticate** the ``Authorization: Bearer`` token into a ``Principal`` (401 with a fixed
   reason, 503 when the identity provider's keys can't be fetched).
2. **Authorize** with the real authorizer, on the route's template and the path's ``{tid}``
   (403 with a fixed reason). Only after an allowed decision is the body read.
3. **Call the service with the decision.** The tenant is ``decision.scope``: the handlers never
   pass the path's tenant id, a query field or anything from the body to the service or the
   stores.

The body is read here, bounded (413), and handed to the service as bytes so the service's strict
JSON reader sees exactly what was sent (duplicate members, ``NaN`` and nesting are validation
errors, not exceptions). ``If-Match`` is passed through as the client sent it.

Responses: JSON, ``Cache-Control: no-store``. Errors have one shape::

    {"error": {"code": "<fixed word>", "message": "...", "errors": [{code, path, message}]}}

OpenAPI and the docs pages are off: an unauthenticated schema is information for nobody who
needs it. An unexpected exception is a 500 with no detail (logged here, without the request).
"""

from __future__ import annotations

import functools
import json
import logging
import re
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

from guardrail_engine.admin.approval_service import ApprovalService
from guardrail_engine.admin.approvals import (
    APPROVAL_ID_PATTERN,
    Approval,
    ApprovalCancelledError,
    ApprovalExpiredError,
    ApprovalNotFoundError,
    ApprovalNotPendingError,
    ApprovalNotRequiredError,
    ApprovalPendingError,
    ApprovalStaleError,
    ApprovalUsedError,
    ApproverPublishError,
    InvalidApprovalCursorError,
    InvalidApprovalQueryError,
    OperatorApprovalError,
    SelfApprovalError,
    ServiceAccountApprovalError,
    ServiceAccountPublishError,
    ServiceAccountRequestError,
)
from guardrail_engine.admin.calibration import (
    CalibrationInProgressError,
    CalibrationService,
    StaleSuggestionError,
)
from guardrail_engine.admin.catalog import (
    MAX_APPLY_BODY_BYTES,
    CatalogService,
    TemplateNotFoundError,
)
from guardrail_engine.admin.content import (
    ContentAuditUnavailableError,
    ContentQueryError,
    StoredContentNotFoundError,
    StoredContentService,
)
from guardrail_engine.admin.decisions import DecisionQueryError, DecisionsService
from guardrail_engine.admin.drafts import MAX_DRAFT_BYTES, DraftConflictError, StoredDraft
from guardrail_engine.admin.floors import (
    AlreadyReleasedError,
    FloorNotReleasedError,
    FloorService,
    PlatformConflictError,
    ReleaseExistsError,
    ReleaseNotFoundError,
    SecondOperatorRequiredError,
    release_json,
)
from guardrail_engine.admin.golden import (
    MAX_BODY_BYTES as MAX_GOLDEN_BODY_BYTES,
)
from guardrail_engine.admin.golden import (
    GoldenService,
    GoldenSetInfo,
    GoldenSetNotFoundError,
    TooManyGoldenSetsError,
)
from guardrail_engine.admin.lifecycle import (
    AlreadyActiveError,
    ApprovalRequiredError,
    CandidateExistsError,
    NoActiveVersionError,
    NoCandidateError,
    NotPreviouslyActiveError,
    StateConflictError,
)
from guardrail_engine.admin.metrics import MetricsQueryError, MetricsService
from guardrail_engine.admin.nightly import (
    NightlyNotFoundError,
    NightlyQueryError,
    NightlyResultsService,
    NotQuarantinedError,
    QuarantineUnavailableError,
)
from guardrail_engine.admin.publish import (
    FloorBelowMinimumError,
    PublishResult,
    PublishService,
    RollbackRepinError,
    RollbackTierError,
    VersionView,
)
from guardrail_engine.admin.repin_service import (
    MinimumError,
    NoRepinCandidateError,
    PromotionHaltedError,
    RepinService,
    RepinStaleError,
    TenantForbiddenError,
    TenantsBehindError,
    WindowOpenError,
)
from guardrail_engine.admin.rollout import RolloutService
from guardrail_engine.admin.service import (
    DecisionError,
    DraftInvalidError,
    DraftService,
    DraftServiceError,
    Guardrails,
    NoDraftError,
    PreconditionRequiredError,
    RuleExistsError,
    RuleNotFoundError,
    TenantUnavailableError,
)
from guardrail_engine.admin.tiers import TierRequestError, TierService
from guardrail_engine.admin.tool_registry import (
    MAX_BODY_BYTES as MAX_TOOL_BODY_BYTES,
)
from guardrail_engine.admin.tool_registry import (
    MAX_TOOLS,
    RETRY_AFTER_S,
    ScreeningLimitError,
    ScreeningUnavailableError,
    ToolConflictError,
    ToolDescriptionChangedError,
    ToolDescriptionRejectedError,
    ToolInUseError,
    ToolNotFoundError,
    ToolNotHeldError,
    ToolOperatorReviewError,
    ToolSelfReviewError,
    ToolService,
    ToolVocabularyHoldError,
    TooManyToolsError,
    entry_json,
)
from guardrail_engine.admin.tools import (
    DraftTestInProgressError,
    DraftTestReport,
    DraftTools,
    EvaluatorUnavailableError,
    ValidationReport,
)
from guardrail_engine.authz.authentication import AuthenticationError, Authenticator
from guardrail_engine.authz.authorizer import Authorizer, AuthzDecision
from guardrail_engine.authz.model import Principal, Role, role_satisfies
from guardrail_engine.directory.model import (
    InvalidTenantRecord,
    TenantNotFound,
    TenantTerminated,
    VersionConflict,
)
from guardrail_engine.escalation.model import (
    AlreadyResolvedError as EscalationAlreadyResolvedError,
)
from guardrail_engine.escalation.model import (
    DeidentifiedContentRequiredError,
    EscalationNotFoundError,
    InvalidCursorError,
    InvalidQueryError,
    OperatorResolutionError,
    SelfResolutionError,
)
from guardrail_engine.escalation.service import (
    MAX_BODY_BYTES as MAX_ESCALATION_BODY_BYTES,
)
from guardrail_engine.escalation.service import EscalationService, item_view
from guardrail_engine.policy.json_document import parse_json_text
from guardrail_engine.projects import NoDedicatedProject
from guardrail_engine.store.port import OperatorPoolUnavailableError, VersionNotFoundError
from guardrail_engine.store.verification import MAX_VERSION

logger = logging.getLogger(__name__)

MAX_RULE_ID_CHARS = 128
MAX_APPROVAL_BODY_BYTES = 4_096
_APPROVAL_ID = re.compile(APPROVAL_ID_PATTERN)
MAX_FLOOR_VERSION = 1_000_000
MAX_RELEASE_BODY_BYTES = 64_000
JSON_TYPES = ("application/json", "application/merge-patch+json")
_HEADERS = {"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"}


class _Reply(Exception):
    """An answer to send instead of calling the service."""

    def __init__(self, response: Response) -> None:
        self.response = response


def _error(
    status: int,
    code: str,
    message: str = "",
    *,
    errors: list[dict[str, str]] | None = None,
    rules: list[dict[str, str]] | None = None,
    versions: list[dict[str, Any]] | None = None,
    compliant_versions: list[int] | None = None,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    body: dict[str, Any] = {"code": code, "message": message}
    if compliant_versions is not None:
        body["compliant_versions"] = compliant_versions
    if versions is not None:
        body["versions"] = versions
    if errors is not None:
        body["errors"] = errors
    if rules is not None:
        body["rules"] = rules
    return JSONResponse(
        {"error": body}, status_code=status, headers={**_HEADERS, **(headers or {})}
    )


def _draft_json(draft: StoredDraft) -> dict[str, Any]:
    return {
        "etag": draft.etag,
        "updated_at": draft.updated_at.isoformat(),
        "updated_by": draft.updated_by,
        "document": json.loads(draft.document),
    }


def _validation_json(report: ValidationReport) -> dict[str, Any]:
    return {
        "calibration": report.calibration,
        "draft_hash": report.draft_hash,
        "valid": report.valid,
        "errors": [{"code": e.code, "path": e.path, "message": e.message} for e in report.errors],
        "token_budget": report.token_budget,
        "price_usd_per_1m_input_tokens": report.price_usd_per_1m_input_tokens,
        "guard_points": {
            name: {
                "enabled": g.enabled,
                "question_count": g.question_count,
                "question_budget": g.question_budget,
                "questions": list(g.questions),
                "max_content_tokens": g.max_content_tokens,
                "tokens": {
                    "content": g.content_api_tokens,
                    "questions": g.question_api_tokens,
                    "largest_call": g.api_tokens,
                    "budget": g.token_budget,
                    "within_budget": g.within_budget,
                    "headroom": g.headroom_tokens,
                },
                "est_cost_usd_per_check": g.est_cost_usd_per_check,
            }
            for name, g in report.guard_points.items()
        },
    }


def _calibration_run_json(report: Any) -> dict[str, Any]:
    return {
        "guard_point": report.guard_point,
        "pool": report.pool,
        "already_scored": report.already_scored,
        "scored_now": report.scored_now,
        "not_scored": report.not_scored,
        "unscored_remaining": report.unscored_remaining,
        "held_back": report.held_back,
        "input_tokens": report.input_tokens,
        "est_cost_usd": report.est_cost_usd,
        "calls_without_usage": report.calls_without_usage,
        "scoring": report.scoring,
        "targets": report.targets,
    }


def _test_json(report: DraftTestReport) -> dict[str, Any]:
    return {
        "draft_hash": report.draft_hash,
        "guard_point": report.guard_point,
        "results": [
            {
                "id": r.id,
                "decision": r.decision,
                "reason": r.reason,
                "expected": r.expected,
                "expected_met": r.expected_met,
                "rules": list(r.rules),
                "fired": list(r.fired),
            }
            for r in report.results
        ],
        "usage": {
            "input_tokens": report.input_tokens,
            "est_cost_usd": report.est_cost_usd,
            "calls_without_usage": report.calls_without_usage,
        },
        "golden": report.golden,
        "quarantined_not_sent": {
            "count": report.quarantined_not_sent,
            "rows": [{"position": h.position, "views": list(h.views)} for h in report.held_back],
        },
    }


def _result_json(result: PublishResult) -> dict[str, Any]:
    return {
        "version": result.version,
        "bundle_hash": result.bundle_hash,
        "mode": result.mode,
        "rollout_percent": result.rollout_percent,
        "state": result.state,
    }


def _has_body(request: Request) -> bool:
    """A request that sends a body (a promotion's, a request for approval's is optional)."""
    length = request.headers.get("content-length")
    return "transfer-encoding" in request.headers or (length is not None and length != "0")


def _approval_json(a: Approval) -> dict[str, Any]:
    return {
        "id": a.id,
        "action": a.action,
        "draft_hash": a.draft_hash,
        "version": a.version,
        "status": a.status,
        "requested_by": a.requested_by,
        "requested_at": a.requested_at.isoformat(),
        "expires_at": a.expires_at.isoformat(),
        "approved_by": a.approved_by,
        "approved_at": None if a.approved_at is None else a.approved_at.isoformat(),
    }


def _version_json(v: VersionView) -> dict[str, Any]:
    return {
        "version": v.version,
        "bundle_hash": v.bundle_hash,
        "created_at": v.created_at.isoformat(),
        "status": v.status,
        "mode": v.current_mode,
        "rollout_percent": v.current_rollout_percent,
        "published_mode": v.published_mode,
        "published_rollout_percent": v.published_rollout_percent,
        "actor": v.actor,
        "note": v.note,
        "cross_tenant": v.cross_tenant,
        "operator": v.operator,
        "diff": [d.model_dump() for d in v.diff],
    }


def _golden_json(info: GoldenSetInfo, *, detail: bool = True) -> dict[str, Any]:
    """A set's metadata. ``detail`` adds the per-guard-point counts and the quarantined rows by
    id and view (never the word and never the content); a list gives just the count."""
    body: dict[str, Any] = {
        "set_id": info.set_id,
        "name": info.name,
        "set_hash": info.set_hash,
        "created_at": info.created_at.isoformat(),
        "created_by": info.created_by,
        "examples": info.total,
        "quarantined": len(info.quarantined),
    }
    if detail:
        body["counts"] = info.counts
        body["quarantined_rows"] = [
            {"id": row_id, "views": list(views)} for row_id, views in info.quarantined
        ]
    return body


def create_admin_app(
    *,
    authenticator: Authenticator,
    authorizer: Authorizer,
    service: DraftService,
    tools: DraftTools,
    golden: GoldenService,
    catalog: CatalogService,
    publisher: PublishService,
    tool_registry: ToolService,
    floors: FloorService,
    repin: RepinService,
    calibration: CalibrationService | None = None,
    decisions: DecisionsService | None = None,
    stored_content: StoredContentService | None = None,
    nightly: NightlyResultsService | None = None,
    metrics: MetricsService | None = None,
    rollout: RolloutService | None = None,
    escalations: EscalationService | None = None,
    approvals: ApprovalService | None = None,
    tiers: TierService | None = None,
) -> FastAPI:
    app = FastAPI(title="Guardrail Admin API", docs_url=None, redoc_url=None, openapi_url=None)

    async def authenticate(request: Request) -> Principal:
        header = request.headers.get("authorization", "")
        scheme, _, token = header.partition(" ")
        if scheme.lower() != "bearer" or not token.strip():
            raise _Reply(
                _error(401, "unauthenticated", "missing", headers={"WWW-Authenticate": "Bearer"})
            )
        try:
            return await authenticator.authenticate(token.strip())
        except AuthenticationError as e:
            if e.reason == "jwks_unavailable":
                raise _Reply(_error(503, "identity_provider_unavailable")) from None
            raise _Reply(
                _error(401, "unauthenticated", e.reason, headers={"WWW-Authenticate": "Bearer"})
            ) from None

    async def authorize(
        principal: Principal, method: str, route: str, tid: str | None
    ) -> AuthzDecision:
        decision = await authorizer.authorize(principal, method, route, tenant_id=tid)
        if not decision.allowed:
            if decision.reason == "tenant_terminated":
                raise _Reply(_error(403, "tenant_terminated", "the tenant has been terminated"))
            raise _Reply(_error(403, "forbidden", decision.reason))
        return decision

    async def read_body(request: Request, limit: int = MAX_DRAFT_BYTES) -> bytes:
        kind = request.headers.get("content-type", "").split(";")[0].strip().lower()
        if kind not in JSON_TYPES:
            raise _Reply(_error(415, "unsupported_media_type", "send application/json"))
        declared = request.headers.get("content-length")
        if declared is not None and (not declared.isdigit() or int(declared) > limit):
            raise _Reply(_error(413, "body_too_large", f"at most {limit} bytes"))
        chunks: list[bytes] = []
        size = 0
        async for chunk in request.stream():
            size += len(chunk)
            if size > limit:
                raise _Reply(_error(413, "body_too_large", f"at most {limit} bytes"))
            chunks.append(chunk)
        return b"".join(chunks)

    def answer_draft(draft: StoredDraft, status: int = 200) -> JSONResponse:
        return JSONResponse(
            _draft_json(draft), status_code=status, headers={**_HEADERS, "ETag": draft.etag}
        )

    def failed(exc: Exception) -> JSONResponse:
        if isinstance(exc, RollbackTierError):
            return _error(
                422,
                "invalid_draft",
                "that version does not meet the tenant's tier; roll back to one of "
                "compliant_versions, or publish a new version",
                errors=[{"code": e.code, "path": e.path, "message": e.message} for e in exc.errors],
                compliant_versions=exc.compliant_versions,
            )
        if isinstance(exc, DraftInvalidError):
            return _error(
                422,
                "invalid_draft",
                "the draft was not stored",
                errors=[{"code": e.code, "path": e.path, "message": e.message} for e in exc.errors],
            )
        if isinstance(exc, PreconditionRequiredError):
            return _error(428, "precondition_required", "send If-Match with the draft's ETag")
        if isinstance(exc, DraftConflictError):
            headers = {"ETag": exc.current} if exc.current else None
            return _error(412, "precondition_failed", "the draft changed", headers=headers)
        if isinstance(exc, NoDraftError):
            return _error(404, "no_draft", "there is no draft yet; PUT one first")
        if isinstance(exc, ReleaseExistsError):
            return _error(409, "release_exists", "that floor version has a release already")
        if isinstance(exc, ReleaseNotFoundError):
            return _error(404, "release_not_found")
        if isinstance(exc, AlreadyReleasedError):
            return _error(409, "already_released")
        if isinstance(exc, SecondOperatorRequiredError):
            return _error(409, "second_operator_required", "a different operator must approve")
        if isinstance(exc, FloorNotReleasedError):
            return _error(409, "floor_not_released", "that floor version is not released")
        if isinstance(exc, PlatformConflictError):
            return _error(409, "platform_conflict", "the platform state changed; read it again")
        if isinstance(exc, PromotionHaltedError):
            return _error(409, "promotion_halted", "promotion of this release is halted")
        if isinstance(exc, WindowOpenError):
            return _error(
                409, "window_open", "the staging window has not passed",
                errors=[{"code": "until", "path": "$", "message": exc.until.isoformat()}],
            )  # fmt: skip
        if isinstance(exc, NoRepinCandidateError):
            return _error(409, "no_repin_candidate", "the tenant has no re-pin candidate")
        if isinstance(exc, RepinStaleError):
            return _error(409, "repin_stale", "the active version changed since staging: re-pin")
        if isinstance(exc, TenantsBehindError):
            return _error(
                409, "tenants_behind", "some tenants are still on a lower floor",
                errors=[{"code": "tenant", "path": "$", "message": t} for t in exc.tenants],
            )  # fmt: skip
        if isinstance(exc, MinimumError):
            return _error(409, "minimum_invalid", str(exc))
        if isinstance(exc, TenantForbiddenError):
            return _error(403, "forbidden", str(exc))
        if isinstance(exc, RollbackRepinError):
            return _error(409, "rollback_repin_failed", "the version could not be re-pinned")
        if isinstance(exc, FloorBelowMinimumError):
            return _error(
                409, "floor_below_minimum", "the candidate extends a floor below the minimum"
            )
        if isinstance(exc, ToolDescriptionRejectedError):
            return _error(
                422, "tool_description_rejected",
                "the description was blocked by screening and was not stored",
                rules=[{"rule": k, "action": a} for k, a in exc.rules],
            )  # fmt: skip
        if isinstance(exc, ScreeningUnavailableError):
            return _error(
                503, "screening_unavailable", "the description could not be screened; retry",
                headers={"Retry-After": str(RETRY_AFTER_S)},
            )  # fmt: skip
        if isinstance(exc, ScreeningLimitError):
            return _error(
                429, exc.code, "too many tool screenings",
                headers={"Retry-After": str(exc.retry_after_s)},
            )  # fmt: skip
        if isinstance(exc, ToolInUseError):
            return _error(
                409,
                "tool_in_use",
                "the active version or a candidate names this tool in a tool allow-list; "
                "publish a version without it first",
                versions=[{"version": v, "role": role} for v, role in exc.versions],
            )
        if isinstance(exc, ToolNotFoundError):
            return _error(404, "tool_not_found")
        if isinstance(exc, ToolNotHeldError):
            return _error(409, "not_held", "only a held tool is reviewed")
        if isinstance(exc, ToolDescriptionChangedError):
            return _error(409, "description_changed", "the tool's description changed")
        if isinstance(exc, ToolConflictError):
            return _error(409, "tool_changed", "the tool changed; read it again")
        if isinstance(exc, ToolVocabularyHoldError):
            return _error(
                409, "vocabulary_hold",
                "this description was never screened: reject it or edit it so it passes screening",
            )  # fmt: skip
        if isinstance(exc, ToolOperatorReviewError):
            return _error(403, "operator_review", "a platform operator can't approve tenant tools")
        if isinstance(exc, ToolSelfReviewError):
            return _error(403, "self_review", "a different reviewer must approve it")
        if isinstance(exc, TooManyToolsError):
            return _error(409, "too_many_tools", f"at most {MAX_TOOLS} tools")
        if isinstance(exc, TemplateNotFoundError):
            return _error(404, "template_not_found")
        if isinstance(exc, RuleExistsError):
            return _error(409, "rule_exists", "the draft already has a rule with that id")
        if isinstance(exc, RuleNotFoundError):
            return _error(404, "rule_not_found")
        if isinstance(exc, TenantUnavailableError):
            return _error(404, "tenant_unavailable")
        if isinstance(exc, EscalationNotFoundError):
            return _error(404, "escalation_not_found")
        if isinstance(exc, EscalationAlreadyResolvedError):
            return _error(409, "already_resolved", "the item was resolved already")
        if isinstance(exc, OperatorResolutionError):
            return _error(
                403, "operator_resolution", "a platform operator can't resolve a tenant's items"
            )
        if isinstance(exc, SelfResolutionError):
            return _error(403, "self_resolution", "a different reviewer must resolve it")
        if isinstance(exc, DeidentifiedContentRequiredError):
            return _error(
                422, "deidentified_content_required",
                "promoting content for this tenant needs deidentified_content",
            )  # fmt: skip
        if isinstance(exc, InvalidCursorError):
            return _error(400, "invalid_cursor")
        if isinstance(exc, InvalidQueryError):
            return _error(400, "invalid_query", f"bad value for {exc.field}")
        if isinstance(exc, GoldenSetNotFoundError):
            return _error(404, "golden_set_not_found")
        if isinstance(exc, TooManyGoldenSetsError):
            return _error(409, "too_many_golden_sets", "delete is not offered; ask for a cap raise")
        if isinstance(exc, DraftTestInProgressError):
            return _error(
                429, "test_in_progress", "a test run is already going", headers={"Retry-After": "5"}
            )
        if isinstance(exc, CalibrationInProgressError):
            return _error(
                429, "calibration_in_progress", "a calibration run is already going",
                headers={"Retry-After": "5"},
            )  # fmt: skip
        if isinstance(exc, MetricsQueryError):
            return _error(
                400, "invalid_query", "a parameter is not acceptable",
                errors=[{"code": "parameter", "path": exc.field, "message": exc.message}],
            )  # fmt: skip
        if isinstance(exc, NightlyNotFoundError):
            return _error(404, "nightly_result_not_found")
        if isinstance(exc, NotQuarantinedError):
            return _error(404, "not_quarantined")
        if isinstance(exc, QuarantineUnavailableError):
            return _error(503, "unavailable", "the clear could not be recorded")
        if isinstance(exc, NightlyQueryError):
            return _error(
                400, "invalid_query", "a parameter is not acceptable",
                errors=[{"code": "parameter", "path": exc.field, "message": exc.message}],
            )  # fmt: skip
        if isinstance(exc, ContentAuditUnavailableError):
            return _error(503, "unavailable", "the read could not be recorded")
        if isinstance(exc, StoredContentNotFoundError):
            return _error(404, "content_not_found")
        if isinstance(exc, ContentQueryError):
            return _error(
                400, "invalid_query", "a parameter is not acceptable",
                errors=[{"code": "parameter", "path": exc.field, "message": exc.message}],
            )  # fmt: skip
        if isinstance(exc, DecisionQueryError):
            return _error(
                400, "invalid_query", "a parameter is not acceptable",
                errors=[{"code": "parameter", "path": exc.field, "message": exc.message}],
            )  # fmt: skip
        if isinstance(exc, StaleSuggestionError):
            return _error(409, "stale_suggestion", str(exc))
        if isinstance(exc, EvaluatorUnavailableError):
            return _error(503, "unavailable", "drafts can't be tested now")
        if isinstance(exc, CandidateExistsError):
            return _error(409, "candidate_exists", "promote or abandon the candidate first")
        if isinstance(exc, NoCandidateError):
            return _error(409, "no_candidate", "there is no candidate")
        if isinstance(exc, NoActiveVersionError):
            return _error(409, "no_active_version", "the first publish must be enforce at 100%")
        if isinstance(exc, NotPreviouslyActiveError):
            return _error(
                409, "not_previously_active",
                "that version has never been active; promote it (the enforce gates run) instead",
            )  # fmt: skip
        if isinstance(exc, AlreadyActiveError):
            return _error(409, "already_active", "that version is the active one")
        if isinstance(exc, StateConflictError):
            return _error(409, "state_changed", "the versions changed; read them again")
        if isinstance(exc, ApprovalRequiredError):
            return _error(
                409, "approval_required", "enforcing needs two-person approval for this tenant"
            )
        if isinstance(exc, ApprovalNotRequiredError):
            return _error(409, "approval_not_required", "this tenant's enforcing needs no approval")
        if isinstance(exc, ApprovalNotFoundError):
            return _error(404, "approval_not_found")
        if isinstance(exc, ApprovalPendingError):
            return _error(409, "approval_pending", "a different admin has not approved it yet")
        if isinstance(exc, ApprovalNotPendingError):
            return _error(409, "approval_not_pending", "only a pending approval can be approved")
        if isinstance(exc, ApprovalExpiredError):
            return _error(409, "approval_expired", "the approval expired; request a new one")
        if isinstance(exc, ApprovalCancelledError):
            return _error(
                409, "approval_cancelled", "the approval was cancelled; request a new one"
            )
        if isinstance(exc, ApprovalStaleError):
            return _error(
                409,
                "approval_stale",
                "the approval is for another draft or candidate than this one",
            )
        if isinstance(exc, ApprovalUsedError):
            return _error(409, "approval_used", "an approval is used once; request a new one")
        if isinstance(exc, SelfApprovalError):
            return _error(403, "self_approval", "a different admin must approve it")
        if isinstance(exc, ServiceAccountApprovalError):
            return _error(403, "service_account_approval", "a service account can't approve")
        if isinstance(exc, ServiceAccountRequestError):
            return _error(
                403, "service_account_request",
                "a service account can't request an approval; two people are two humans",
            )  # fmt: skip
        if isinstance(exc, ServiceAccountPublishError):
            return _error(
                403, "service_account_publish",
                "a service account can't publish or promote with an approval",
            )  # fmt: skip
        if isinstance(exc, ApproverPublishError):
            return _error(
                403, "approver_publish", "the approver can't also publish or promote with it"
            )
        if isinstance(exc, InvalidApprovalCursorError):
            return _error(400, "invalid_cursor")
        if isinstance(exc, InvalidApprovalQueryError):
            return _error(400, "invalid_query", f"bad value for {exc.field}")
        if isinstance(exc, OperatorApprovalError):
            return _error(
                403, "operator_approval", "a platform operator can't approve a tenant's publish"
            )
        if isinstance(exc, VersionNotFoundError):
            return _error(404, "version_not_found")
        if isinstance(exc, OperatorPoolUnavailableError):
            return _error(503, "operator_unavailable", "cross-tenant access is not configured")
        raise exc

    def guarded(handler: Any) -> Any:
        """Turn an early answer or a service error into its response."""

        @functools.wraps(handler)
        async def run(request: Request, **path: str) -> Response:
            try:
                return await handler(request, **path)  # type: ignore[no-any-return]
            except _Reply as r:
                return r.response
            except (
                DraftServiceError,
                DraftConflictError,
                VersionNotFoundError,
                OperatorPoolUnavailableError,
            ) as e:
                return failed(e)

        return run

    @app.get("/v1/tenants/{tid}/guardrails")
    @guarded
    async def get_guardrails(request: Request, tid: str) -> Response:
        principal = await authenticate(request)
        decision = await authorize(principal, "GET", "/v1/tenants/{tid}/guardrails", tid)
        view: Guardrails = await service.get_guardrails(decision)
        rollout = await publisher.rollout_state(decision)
        headers = {**_HEADERS, **({"ETag": view.draft.etag} if view.draft else {})}
        return JSONResponse(
            {
                "tenant_id": view.tenant_id,
                "published": view.published,
                "draft": None if view.draft is None else _draft_json(view.draft),
                "rollout": rollout,
            },
            headers=headers,
        )

    @app.put("/v1/tenants/{tid}/guardrails/draft")
    @guarded
    async def put_draft(request: Request, tid: str) -> Response:
        principal = await authenticate(request)
        decision = await authorize(principal, "PUT", "/v1/tenants/{tid}/guardrails/draft", tid)
        body = await read_body(request)
        draft = await service.put_draft(decision, principal, body, request.headers.get("if-match"))
        return answer_draft(draft, 201 if draft.created else 200)  # what the store did

    @app.get("/v1/tenants/{tid}/guardrails/catalog")
    @guarded
    async def get_catalog(request: Request, tid: str) -> Response:
        principal = await authenticate(request)
        decision = await authorize(principal, "GET", "/v1/tenants/{tid}/guardrails/catalog", tid)
        return JSONResponse(await catalog.view(decision), headers=_HEADERS)

    @app.post("/v1/tenants/{tid}/guardrails/draft/templates/{template_id}")
    @guarded
    async def apply_template(request: Request, tid: str, template_id: str) -> Response:
        principal = await authenticate(request)
        decision = await authorize(
            principal, "POST", "/v1/tenants/{tid}/guardrails/draft/templates/{template_id}", tid
        )
        body = await read_body(request, MAX_APPLY_BODY_BYTES)
        applied = await catalog.apply_template(
            decision, principal, template_id, body, request.headers.get("if-match")
        )
        reply = {
            "rule": applied.rule,
            "draft": _draft_json(applied.draft),
            "golden_set": None if applied.golden_set is None else _golden_json(applied.golden_set),
            "golden_error": applied.golden_error,
        }
        return JSONResponse(
            reply, status_code=201, headers={**_HEADERS, "ETag": applied.draft.etag}
        )

    @app.get("/v1/tenants/{tid}/guardrails/tools")
    @guarded
    async def list_tools(request: Request, tid: str) -> Response:
        principal = await authenticate(request)
        decision = await authorize(principal, "GET", "/v1/tenants/{tid}/guardrails/tools", tid)
        entries = await tool_registry.list(decision)
        return JSONResponse({"tools": [entry_json(e) for e in entries]}, headers=_HEADERS)

    @app.put("/v1/tenants/{tid}/guardrails/tools/{name}")
    @guarded
    async def put_tool(request: Request, tid: str, name: str) -> Response:
        principal = await authenticate(request)
        decision = await authorize(
            principal, "PUT", "/v1/tenants/{tid}/guardrails/tools/{name}", tid
        )
        body = await read_body(request, MAX_TOOL_BODY_BYTES)
        entry, created = await tool_registry.put(decision, principal, name, body)
        if entry.status == "held" or entry.pending is not None:
            # A new tool is held unregistered; an edit to an approved tool is held while the
            # approved description stays in force (the response's tool shows both).
            return JSONResponse(
                {"error": {"code": "held_for_review", "message": "a reviewer must approve it"},
                 "tool": entry_json(entry)},
                status_code=202, headers=_HEADERS,
            )  # fmt: skip
        return JSONResponse(
            {"tool": entry_json(entry)}, status_code=201 if created else 200, headers=_HEADERS
        )

    @app.delete("/v1/tenants/{tid}/guardrails/tools/{name}")
    @guarded
    async def delete_tool(request: Request, tid: str, name: str) -> Response:
        principal = await authenticate(request)
        decision = await authorize(
            principal, "DELETE", "/v1/tenants/{tid}/guardrails/tools/{name}", tid
        )
        await tool_registry.delete(decision, principal, name)
        return Response(status_code=204, headers=_HEADERS)

    @app.post("/v1/tenants/{tid}/guardrails/tools/{name}/review")
    @guarded
    async def review_tool(request: Request, tid: str, name: str) -> Response:
        principal = await authenticate(request)
        decision = await authorize(
            principal, "POST", "/v1/tenants/{tid}/guardrails/tools/{name}/review", tid
        )
        body = await read_body(request, MAX_TOOL_BODY_BYTES)
        entry = await tool_registry.review(decision, principal, name, body)
        return JSONResponse({"tool": entry_json(entry)}, headers=_HEADERS)

    # ---------------------------------------------------------------- floors (M2-09, platform)

    def floor_version(raw: str) -> int:
        if not raw.isascii() or not raw.isdigit() or not 1 <= int(raw) <= MAX_FLOOR_VERSION:
            raise _Reply(_error(404, "release_not_found"))
        return int(raw)

    async def json_body(request: Request) -> dict[str, Any]:
        raw = await read_body(request, 8_000)
        if not raw.strip():
            return {}
        doc, problems = parse_json_text(raw)
        if problems or not isinstance(doc, dict):
            raise _Reply(_error(422, "invalid_body", "a JSON object"))
        return doc

    def version_of(doc: dict[str, Any], key: str) -> int:
        value = doc.get(key)
        if isinstance(value, bool) or not isinstance(value, int):
            raise _Reply(_error(422, "invalid_body", f"{key}: a positive integer"))
        if not 1 <= value <= MAX_FLOOR_VERSION:
            raise _Reply(_error(422, "invalid_body", f"{key}: a positive integer"))
        return value

    def reason_of(doc: dict[str, Any]) -> str:
        reason = doc.get("reason")
        if not isinstance(reason, str) or not 1 <= len(reason.strip()) <= 200:
            raise _Reply(_error(422, "invalid_body", "reason: 1 to 200 characters"))
        return reason.strip()

    async def platform_call(request: Request, method: str, route: str) -> tuple[Principal, Any]:
        principal = await authenticate(request)
        return principal, await authorize(principal, method, route, None)

    if nightly is not None:

        @app.get("/v1/platform/redteam/nightly")
        @guarded
        async def nightly_latest(request: Request) -> Response:
            _, decision = await platform_call(request, "GET", "/v1/platform/redteam/nightly")
            params = dict(request.query_params)
            if len(request.query_params.multi_items()) != len(params):
                raise NightlyQueryError("query", "each parameter at most once")
            return JSONResponse(await nightly.latest(decision, params), headers=_HEADERS)

        @app.get("/v1/platform/redteam/nightly/{tenant_id}")
        @guarded
        async def nightly_for_tenant(request: Request, tenant_id: str) -> Response:
            route = "/v1/platform/redteam/nightly/{tenant_id}"
            _, decision = await platform_call(request, "GET", route)
            return JSONResponse(await nightly.for_tenant(decision, tenant_id), headers=_HEADERS)

        @app.get("/v1/platform/redteam/quarantine")
        @guarded
        async def nightly_quarantine(request: Request) -> Response:
            _, decision = await platform_call(request, "GET", "/v1/platform/redteam/quarantine")
            return JSONResponse(await nightly.quarantined(decision), headers=_HEADERS)

        @app.post("/v1/platform/redteam/quarantine/clear")
        @guarded
        async def nightly_quarantine_clear(request: Request) -> Response:
            principal, decision = await platform_call(
                request, "POST", "/v1/platform/redteam/quarantine/clear"
            )
            doc = await json_body(request)
            config, mode = doc.get("config"), doc.get("mode", "live")
            if not isinstance(config, str) or not isinstance(mode, str):
                raise _Reply(_error(422, "invalid_body", "config and mode: strings"))
            return JSONResponse(
                await nightly.clear(decision, principal, config, mode, reason_of(doc)),
                headers=_HEADERS,
            )

    @app.get("/v1/platform/floors")
    @guarded
    async def list_floors(request: Request) -> Response:
        _, decision = await platform_call(request, "GET", "/v1/platform/floors")
        return JSONResponse(await floors.listing(decision), headers=_HEADERS)

    @app.post("/v1/platform/floors/{version}/release")
    @guarded
    async def propose_floor(request: Request, version: str) -> Response:
        v = floor_version(version)
        route = "/v1/platform/floors/{version}/release"
        principal, decision = await platform_call(request, "POST", route)
        body = await read_body(request, MAX_RELEASE_BODY_BYTES)
        release = await floors.propose(decision, principal, v, body)
        return JSONResponse(release_json(release), status_code=201, headers=_HEADERS)

    @app.post("/v1/platform/floors/{version}/approve")
    @guarded
    async def approve_floor(request: Request, version: str) -> Response:
        v = floor_version(version)
        principal, decision = await platform_call(
            request, "POST", "/v1/platform/floors/{version}/approve"
        )
        release = await floors.approve(decision, principal, v, await read_body(request, 1_000))
        return JSONResponse(release_json(release), headers=_HEADERS)

    @app.post("/v1/platform/floors/{version}/halt")
    @guarded
    async def halt_floor(request: Request, version: str) -> Response:
        v = floor_version(version)
        principal, decision = await platform_call(
            request, "POST", "/v1/platform/floors/{version}/halt"
        )
        await floors.halt(decision, principal, v, halted=True)
        return JSONResponse({"floor_version": v, "halted": True}, headers=_HEADERS)

    @app.delete("/v1/platform/floors/{version}/halt")
    @guarded
    async def resume_floor(request: Request, version: str) -> Response:
        v = floor_version(version)
        principal, decision = await platform_call(
            request, "DELETE", "/v1/platform/floors/{version}/halt"
        )
        await floors.halt(decision, principal, v, halted=False)
        return JSONResponse({"floor_version": v, "halted": False}, headers=_HEADERS)

    @app.post("/v1/platform/floors/{version}/repin")
    @guarded
    async def repin_floor(request: Request, version: str) -> Response:
        v = floor_version(version)
        principal, decision = await platform_call(
            request, "POST", "/v1/platform/floors/{version}/repin"
        )
        doc = await json_body(request)
        only = doc.get("tenants")
        if only is not None and not (
            isinstance(only, list) and all(isinstance(t, str) for t in only) and len(only) <= 1000
        ):
            raise _Reply(_error(422, "invalid_body", "tenants: a list of tenant ids"))
        results = await repin.repin_all(decision, principal, v, reason_of(doc), only)
        return JSONResponse({"results": [r.as_dict() for r in results]}, headers=_HEADERS)

    @app.get("/v1/platform/floors/{version}/rollout")
    @guarded
    async def floor_rollout(request: Request, version: str) -> Response:
        v = floor_version(version)
        principal, decision = await platform_call(
            request, "GET", "/v1/platform/floors/{version}/rollout"
        )
        rows = await repin.rollout(decision, principal, v)
        return JSONResponse({"floor_version": v, "tenants": rows}, headers=_HEADERS)

    @app.put("/v1/platform/minimum-floor")
    @guarded
    async def raise_minimum(request: Request) -> Response:
        principal, decision = await platform_call(request, "PUT", "/v1/platform/minimum-floor")
        doc = await json_body(request)
        value = doc.get("version")
        if (
            isinstance(value, bool)
            or not isinstance(value, int)
            or not 1 <= value <= MAX_FLOOR_VERSION
        ):
            raise _Reply(_error(422, "invalid_body", "version: a positive integer"))
        new = await repin.raise_minimum(decision, principal, value)
        return JSONResponse({"minimum_floor_version": new}, headers=_HEADERS)

    @app.get("/v1/tenants/{tid}/guardrails/floor")
    @guarded
    async def tenant_floor(request: Request, tid: str) -> Response:
        principal = await authenticate(request)
        await authorize(principal, "GET", "/v1/tenants/{tid}/guardrails/floor", tid)
        return JSONResponse(await repin.tenant_state(principal, tid), headers=_HEADERS)

    @app.post("/v1/tenants/{tid}/guardrails/floor/repin")
    @guarded
    async def tenant_repin(request: Request, tid: str) -> Response:
        principal = await authenticate(request)
        await authorize(principal, "POST", "/v1/tenants/{tid}/guardrails/floor/repin", tid)
        doc = await json_body(request)
        result = await repin.repin_tenant(
            principal, tid, version_of(doc, "floor_version"), reason_of(doc)
        )
        return JSONResponse(result.as_dict(), headers=_HEADERS)

    @app.post("/v1/tenants/{tid}/guardrails/floor/promote")
    @guarded
    async def tenant_promote(request: Request, tid: str) -> Response:
        principal = await authenticate(request)
        await authorize(principal, "POST", "/v1/tenants/{tid}/guardrails/floor/promote", tid)
        doc = await json_body(request)
        result = await repin.promote_tenant(principal, tid, version_of(doc, "floor_version"))
        return JSONResponse(result.as_dict(), headers=_HEADERS)

    if tiers is not None:

        @app.put("/v1/tenants/{tid}/guardrails/tier")
        @guarded
        async def set_tier(request: Request, tid: str) -> Response:
            principal = await authenticate(request)
            decision = await authorize(principal, "PUT", "/v1/tenants/{tid}/guardrails/tier", tid)
            body = await read_body(request, 8_000)
            try:
                return JSONResponse(
                    await tiers.set_tier(decision, principal, body), headers=_HEADERS
                )
            except TierRequestError as e:
                return _error(422, "invalid_body", str(e))
            except TenantNotFound:
                return _error(404, "tenant_not_found")
            except VersionConflict:
                return _error(409, "version_conflict", "the tenant record changed; read it again")
            except TenantTerminated:
                return _error(403, "tenant_terminated", "the tenant has been terminated")
            except NoDedicatedProject as e:
                return _error(409, NoDedicatedProject.code, str(e))
            except (InvalidTenantRecord, ValueError) as e:
                return _error(422, "invalid_body", str(e))

    @app.patch("/v1/tenants/{tid}/guardrails/draft/rules/{rule_id}")
    @guarded
    async def patch_rule(request: Request, tid: str, rule_id: str) -> Response:
        principal = await authenticate(request)
        decision = await authorize(
            principal, "PATCH", "/v1/tenants/{tid}/guardrails/draft/rules/{rule_id}", tid
        )
        if len(rule_id) > MAX_RULE_ID_CHARS:
            raise _Reply(_error(404, "rule_not_found"))
        body = await read_body(request)
        draft = await service.patch_rule(
            decision, principal, rule_id, body, request.headers.get("if-match")
        )
        return answer_draft(draft)

    @app.delete("/v1/tenants/{tid}/guardrails/draft/rules/{rule_id}")
    @guarded
    async def delete_rule(request: Request, tid: str, rule_id: str) -> Response:
        principal = await authenticate(request)
        decision = await authorize(
            principal, "DELETE", "/v1/tenants/{tid}/guardrails/draft/rules/{rule_id}", tid
        )
        if len(rule_id) > MAX_RULE_ID_CHARS:
            raise _Reply(_error(404, "rule_not_found"))
        draft = await service.delete_rule(
            decision, principal, rule_id, request.headers.get("if-match")
        )
        return answer_draft(draft)

    @app.post("/v1/tenants/{tid}/guardrails/draft/validate")
    @guarded
    async def validate_draft(request: Request, tid: str) -> Response:
        principal = await authenticate(request)
        decision = await authorize(
            principal, "POST", "/v1/tenants/{tid}/guardrails/draft/validate", tid
        )
        return JSONResponse(_validation_json(await tools.validate(decision)), headers=_HEADERS)

    @app.post("/v1/tenants/{tid}/guardrails/draft/test")
    @guarded
    async def test_draft(request: Request, tid: str) -> Response:
        principal = await authenticate(request)
        decision = await authorize(
            principal, "POST", "/v1/tenants/{tid}/guardrails/draft/test", tid
        )
        body = await read_body(request)
        return JSONResponse(_test_json(await tools.test(decision, body)), headers=_HEADERS)

    if calibration is not None:

        @app.post("/v1/tenants/{tid}/guardrails/draft/calibrate")
        @guarded
        async def calibrate_draft(request: Request, tid: str) -> Response:
            principal = await authenticate(request)
            decision = await authorize(
                principal, "POST", "/v1/tenants/{tid}/guardrails/draft/calibrate", tid
            )
            body = await read_body(request)
            return JSONResponse(
                _calibration_run_json(await calibration.calibrate(decision, body)),
                headers=_HEADERS,
            )

        @app.post("/v1/tenants/{tid}/guardrails/draft/thresholds")
        @guarded
        async def decide_thresholds(request: Request, tid: str) -> Response:
            principal = await authenticate(request)
            decision = await authorize(
                principal, "POST", "/v1/tenants/{tid}/guardrails/draft/thresholds", tid
            )
            body = await read_body(request)
            result = await calibration.decide_thresholds(
                decision, principal, body, request.headers.get("if-match")
            )
            return JSONResponse(result, headers=_HEADERS)

        @app.get("/v1/tenants/{tid}/guardrails/calibration/targets")
        @guarded
        async def read_targets(request: Request, tid: str) -> Response:
            principal = await authenticate(request)
            decision = await authorize(
                principal, "GET", "/v1/tenants/{tid}/guardrails/calibration/targets", tid
            )
            return JSONResponse(
                (await calibration.read_targets(decision)).as_dict(), headers=_HEADERS
            )

        @app.put("/v1/tenants/{tid}/guardrails/calibration/targets")
        @guarded
        async def update_targets(request: Request, tid: str) -> Response:
            principal = await authenticate(request)
            decision = await authorize(
                principal, "PUT", "/v1/tenants/{tid}/guardrails/calibration/targets", tid
            )
            body = await read_body(request)
            view = await calibration.set_targets(decision, principal, body)
            return JSONResponse(view.as_dict(), headers=_HEADERS)

    if metrics is not None:

        @app.get("/v1/tenants/{tid}/guardrails/metrics")
        @guarded
        async def tenant_metrics(request: Request, tid: str) -> Response:
            principal = await authenticate(request)
            decision = await authorize(
                principal, "GET", "/v1/tenants/{tid}/guardrails/metrics", tid
            )
            params = dict(request.query_params)
            if len(request.query_params.multi_items()) != len(params):
                raise MetricsQueryError("query", "each parameter at most once")
            return JSONResponse(await metrics.report(decision, params), headers=_HEADERS)

    if decisions is not None:

        @app.get("/v1/tenants/{tid}/guardrails/decisions")
        @guarded
        async def query_decisions(request: Request, tid: str) -> Response:
            principal = await authenticate(request)
            decision = await authorize(
                principal, "GET", "/v1/tenants/{tid}/guardrails/decisions", tid
            )
            params = dict(request.query_params)
            if len(request.query_params.multi_items()) != len(params):  # a parameter given twice
                raise DecisionQueryError("query", "each parameter at most once")
            return JSONResponse(await decisions.query(decision, params), headers=_HEADERS)

    if stored_content is not None:

        @app.get("/v1/tenants/{tid}/guardrails/decisions/{request_id}/content")
        @guarded
        async def stored_content_of(request: Request, tid: str, request_id: str) -> Response:
            principal = await authenticate(request)
            decision = await authorize(
                principal, "GET", "/v1/tenants/{tid}/guardrails/decisions/{request_id}/content", tid
            )
            params = dict(request.query_params)
            if len(request.query_params.multi_items()) != len(params):
                raise ContentQueryError("query", "each parameter at most once")
            return JSONResponse(
                await stored_content.get(decision, principal, request_id, params),
                headers=_HEADERS,
            )

    if rollout is not None:

        @app.get("/v1/tenants/{tid}/guardrails/candidate/comparison")
        @guarded
        async def candidate_comparison(request: Request, tid: str) -> Response:
            principal = await authenticate(request)
            decision = await authorize(
                principal, "GET", "/v1/tenants/{tid}/guardrails/candidate/comparison", tid
            )
            return JSONResponse(await rollout.comparison(decision), headers=_HEADERS)

    if escalations is not None:

        @app.get("/v1/tenants/{tid}/guardrails/escalations")
        @guarded
        async def list_escalations(request: Request, tid: str) -> Response:
            principal = await authenticate(request)
            decision = await authorize(
                principal, "GET", "/v1/tenants/{tid}/guardrails/escalations", tid
            )
            q = request.query_params
            page = await escalations.list_items(
                decision,
                status=q.get("status"),
                guard_point=q.get("guard_point"),
                rule=q.get("rule"),
                since=q.get("since"),
                until=q.get("until"),
                cursor=q.get("cursor"),
                limit=q.get("limit"),
            )
            reviewer = role_satisfies(principal.roles, Role.GUARDRAIL_REVIEWER)
            body = {
                "items": [item_view(i, reviewer=reviewer) for i in page.items],
                "next_cursor": page.next_cursor,
            }
            return JSONResponse(body, headers=_HEADERS)

        @app.get("/v1/tenants/{tid}/guardrails/escalations/{id}")
        @guarded
        async def get_escalation(request: Request, tid: str, id: str) -> Response:
            principal = await authenticate(request)
            decision = await authorize(
                principal, "GET", "/v1/tenants/{tid}/guardrails/escalations/{id}", tid
            )
            item = await escalations.get_item(decision, id)
            reviewer = role_satisfies(principal.roles, Role.GUARDRAIL_REVIEWER)
            return JSONResponse(
                item_view(item, reviewer=reviewer, with_content=True), headers=_HEADERS
            )

        @app.post("/v1/tenants/{tid}/guardrails/escalations/{id}/resolve")
        @guarded
        async def resolve_escalation(request: Request, tid: str, id: str) -> Response:
            principal = await authenticate(request)
            decision = await authorize(
                principal, "POST", "/v1/tenants/{tid}/guardrails/escalations/{id}/resolve", tid
            )
            body = await read_body(request, MAX_ESCALATION_BODY_BYTES)
            result = await escalations.resolve(decision, principal, id, body)
            label = result.label
            answer = {
                "item": item_view(result.item, reviewer=True),
                "label": None
                if label is None
                else {
                    "set_id": label.set_id,
                    "mode": label.mode,
                    "quarantined": label.quarantined,
                },
            }
            return JSONResponse(answer, headers=_HEADERS)

    @app.post("/v1/tenants/{tid}/guardrails/golden-sets")
    @guarded
    async def upload_golden_set(request: Request, tid: str) -> Response:
        principal = await authenticate(request)
        decision = await authorize(
            principal, "POST", "/v1/tenants/{tid}/guardrails/golden-sets", tid
        )
        body = await read_body(request, MAX_GOLDEN_BODY_BYTES)
        info = await golden.upload(decision, principal, body)
        return JSONResponse(_golden_json(info), status_code=201, headers=_HEADERS)

    @app.get("/v1/tenants/{tid}/guardrails/golden-sets")
    @guarded
    async def list_golden_sets(request: Request, tid: str) -> Response:
        principal = await authenticate(request)
        decision = await authorize(
            principal, "GET", "/v1/tenants/{tid}/guardrails/golden-sets", tid
        )
        sets = await golden.list_sets(decision, include=request.query_params.get("include"))
        body = {"sets": [_golden_json(i, detail=False) for i in sets]}
        return JSONResponse(body, headers=_HEADERS)

    @app.get("/v1/tenants/{tid}/guardrails/golden-sets/{set_id}")
    @guarded
    async def get_golden_set(request: Request, tid: str, set_id: str) -> Response:
        principal = await authenticate(request)
        decision = await authorize(
            principal, "GET", "/v1/tenants/{tid}/guardrails/golden-sets/{set_id}", tid
        )
        info = await golden.get_set(decision, set_id)
        return JSONResponse(_golden_json(info), headers=_HEADERS)

    if approvals is not None:

        @app.get("/v1/tenants/{tid}/guardrails/draft/approvals")
        @guarded
        async def list_approvals(request: Request, tid: str) -> Response:
            principal = await authenticate(request)
            decision = await authorize(
                principal, "GET", "/v1/tenants/{tid}/guardrails/draft/approvals", tid
            )
            q = request.query_params
            page = await approvals.list_approvals(
                decision, status=q.get("status"), cursor=q.get("cursor"), limit=q.get("limit")
            )
            body = {
                "items": [_approval_json(a) for a in page.items],
                "next_cursor": page.next_cursor,
            }
            return JSONResponse(body, headers=_HEADERS)

        @app.post("/v1/tenants/{tid}/guardrails/draft/approvals")
        @guarded
        async def request_approval(request: Request, tid: str) -> Response:
            principal = await authenticate(request)
            decision = await authorize(
                principal, "POST", "/v1/tenants/{tid}/guardrails/draft/approvals", tid
            )
            body = await read_body(request, MAX_APPROVAL_BODY_BYTES) if _has_body(request) else b""
            approval = await approvals.request(
                decision, principal, body, request.headers.get("if-match")
            )
            return JSONResponse(_approval_json(approval), status_code=201, headers=_HEADERS)

        @app.post("/v1/tenants/{tid}/guardrails/draft/approvals/{id}/approve")
        @guarded
        async def approve_approval(request: Request, tid: str, id: str) -> Response:
            principal = await authenticate(request)
            decision = await authorize(
                principal, "POST", "/v1/tenants/{tid}/guardrails/draft/approvals/{id}/approve", tid
            )
            if not _APPROVAL_ID.fullmatch(id):
                raise _Reply(_error(404, "approval_not_found"))
            approval = await approvals.approve(decision, principal, id)
            return JSONResponse(_approval_json(approval), headers=_HEADERS)

    @app.post("/v1/tenants/{tid}/guardrails/draft/publish")
    @guarded
    async def publish_draft(request: Request, tid: str) -> Response:
        principal = await authenticate(request)
        decision = await authorize(
            principal, "POST", "/v1/tenants/{tid}/guardrails/draft/publish", tid
        )
        body = await read_body(request)
        result = await publisher.publish(decision, principal, body, request.headers.get("if-match"))
        return JSONResponse(_result_json(result), status_code=201, headers=_HEADERS)

    @app.get("/v1/tenants/{tid}/guardrails/versions")
    @guarded
    async def list_versions(request: Request, tid: str) -> Response:
        principal = await authenticate(request)
        decision = await authorize(principal, "GET", "/v1/tenants/{tid}/guardrails/versions", tid)
        views = await publisher.versions(decision)
        return JSONResponse({"versions": [_version_json(v) for v in views]}, headers=_HEADERS)

    @app.post("/v1/tenants/{tid}/guardrails/versions/{v}/rollback")
    @guarded
    async def rollback_version(request: Request, tid: str, v: str) -> Response:
        principal = await authenticate(request)
        decision = await authorize(
            principal, "POST", "/v1/tenants/{tid}/guardrails/versions/{v}/rollback", tid
        )
        if not v.isdigit() or not 1 <= int(v) <= MAX_VERSION:
            raise _Reply(_error(404, "version_not_found"))
        result = await publisher.rollback(decision, principal, int(v))
        return JSONResponse(_result_json(result), headers=_HEADERS)

    @app.patch("/v1/tenants/{tid}/guardrails/candidate")
    @guarded
    async def set_candidate_percent(request: Request, tid: str) -> Response:
        principal = await authenticate(request)
        decision = await authorize(
            principal, "PATCH", "/v1/tenants/{tid}/guardrails/candidate", tid
        )
        body = await read_body(request)
        c = await publisher.set_percent(decision, principal, body)
        return JSONResponse(
            {"version": c.version, "mode": c.mode, "rollout_percent": c.rollout_percent},
            headers=_HEADERS,
        )

    @app.post("/v1/tenants/{tid}/guardrails/candidate/promote")
    @guarded
    async def promote_candidate(request: Request, tid: str) -> Response:
        principal = await authenticate(request)
        decision = await authorize(
            principal, "POST", "/v1/tenants/{tid}/guardrails/candidate/promote", tid
        )
        body = await read_body(request, MAX_APPROVAL_BODY_BYTES) if _has_body(request) else b""
        result = await publisher.promote(decision, principal, body)
        return JSONResponse(_result_json(result), headers=_HEADERS)

    @app.post("/v1/tenants/{tid}/guardrails/candidate/abandon")
    @guarded
    async def abandon_candidate(request: Request, tid: str) -> Response:
        principal = await authenticate(request)
        decision = await authorize(
            principal, "POST", "/v1/tenants/{tid}/guardrails/candidate/abandon", tid
        )
        version = await publisher.abandon(decision, principal)
        return JSONResponse({"abandoned_version": version}, headers=_HEADERS)

    app.add_middleware(_CatchAll)
    return app


class _CatchAll:
    """The outermost layer the app controls, a pure ASGI middleware: anything a handler or an
    inner layer raises becomes a fixed 500 and one log line with the exception's type, never its
    text, and is not re-raised. (Starlette's own ``ServerErrorMiddleware`` re-raises after an
    ``Exception`` handler has answered, so the server would log a traceback with the exception's
    text.) ``DecisionError`` and ``ScopeMismatchError`` land here too: they are
    programming errors."""

    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        started = False

        async def tracking_send(message: Any) -> None:
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
            await send(message)

        try:
            await self.app(scope, receive, tracking_send)
        except Exception as exc:
            kind = "decision" if isinstance(exc, DecisionError) else type(exc).__name__
            logger.error("admin api: unexpected %s", kind)
            if not started:  # once the head is sent the answer can't change
                await _error(500, "internal_error")(scope, receive, send)
