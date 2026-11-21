"""Publish, candidate changes, versions and rollback (M2-07), on the lifecycle state machine of
:mod:`guardrail_engine.admin.lifecycle`.

Like every handler's service, each method takes the :class:`AuthzDecision` the authorizer
returned for the request and uses only ``decision.scope`` as the tenant.

**Publish** takes the tenant's stored draft, which the caller names by its ETag (``If-Match``,
required: you publish what you saw, and a later approval is tied to this ``draft_hash``). The
draft is compiled by the real compiler; the version number is the next one; the document is
stored with that number; the class A event (actor, diff against the active version, both hashes,
note, a snapshot of every tenant rule) is written in the same step as the state change. After the
commit ``guardrail.published`` goes on the bus.

**Enforce is gated** (R1, R2): the evidence gate (:mod:`guardrail_engine.admin.evidence`) and
the approval rule apply to a publish or a promotion that would enforce. A tenant that is not
standard tier, or that opted in to two-person publish, needs a second admin's approval
(:mod:`guardrail_engine.admin.approval_service`, M5-02): the body's ``approval_id`` names it, and
the lifecycle store consumes it in the publish's own transaction. Without an approval service
(or without ``approval_id``) the publish is refused with :class:`ApprovalRequiredError`. Rollback
and raising an enforce candidate's share need no approver, but on such a tenant they tell the
other admins.
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from guardrail_engine.admin.approval_service import ApprovalService
from guardrail_engine.admin.approvals import (
    APPROVAL_ID_PATTERN,
    ApprovalUse,
    approval_required,
)
from guardrail_engine.admin.drafts import ScopedDraftStores
from guardrail_engine.admin.evidence import EvidenceGate
from guardrail_engine.admin.lifecycle import (
    MAX_NOTE_CHARS,
    MODES,
    AlreadyActiveError,
    ApprovalRequiredError,
    Candidate,
    CandidateExistsError,
    GuardrailPublished,
    LifecycleState,
    NoActiveVersionError,
    NoCandidateError,
    NotPreviouslyActiveError,
    PublishBus,
    PublishEvent,
    ScopedLifecycleStores,
    StateConflictError,
    rule_snapshots,
)
from guardrail_engine.admin.service import (
    DecisionError,
    DraftConflictError,
    DraftError,
    DraftInvalidError,
    DraftServiceError,
    NoDraftError,
    PreconditionRequiredError,
    TenantUnavailableError,
    _convert,
    _if_match_ok,
    _scope_of,
)
from guardrail_engine.authz.authorizer import AuthzDecision
from guardrail_engine.authz.model import Principal
from guardrail_engine.guard.tenants import TenantDirectory, TenantProfile
from guardrail_engine.policy.catalog import Catalog, PlatformSettings
from guardrail_engine.policy.compiler import PolicyCompiler
from guardrail_engine.policy.diff import bundle_diff
from guardrail_engine.policy.document import parse_bundle, read_bundle
from guardrail_engine.policy.errors import PolicyError
from guardrail_engine.policy.json_document import parse_json_text
from guardrail_engine.policy.repin import RepinError, floor_version_of, repin_document
from guardrail_engine.policy.tier_check import tier_requirement_errors
from guardrail_engine.store.port import VersionNotFoundError
from guardrail_engine.tenant_scope import TenantScope

logger = logging.getLogger(__name__)

GET_GUARDRAILS = ("GET", "/v1/tenants/{tid}/guardrails")
PUBLISH = ("POST", "/v1/tenants/{tid}/guardrails/draft/publish")
VERSIONS = ("GET", "/v1/tenants/{tid}/guardrails/versions")
ROLLBACK = ("POST", "/v1/tenants/{tid}/guardrails/versions/{v}/rollback")
SET_PERCENT = ("PATCH", "/v1/tenants/{tid}/guardrails/candidate")
PROMOTE = ("POST", "/v1/tenants/{tid}/guardrails/candidate/promote")
ABANDON = ("POST", "/v1/tenants/{tid}/guardrails/candidate/abandon")

_PUBLISH_FIELDS = {"mode", "rollout_percent", "note", "approval_id"}
_APPROVAL_ID = re.compile(APPROVAL_ID_PATTERN)


@dataclass(frozen=True, slots=True)
class PublishResult:
    version: int
    bundle_hash: str
    mode: str
    rollout_percent: int
    state: str
    """``active`` (a first publish) or ``candidate``."""


class RollbackRepinError(DraftServiceError):
    """The rollback target extends a floor below the minimum and could not be re-pinned (HTTP
    409 ``rollback_repin_failed``)."""


class RollbackTierError(DraftInvalidError):
    """A rollback target on a regulated tenant does not meet the tenant's current tier (R4.1 over
    R2's rollback exemption). ``errors`` are the codes a publish of it would get
    (``pack.required_missing``, ``pack.rule_required``); ``compliant_versions`` lists the
    version numbers a rollback may go to instead (HTTP 422 ``invalid_draft``)."""

    def __init__(self, errors: list[DraftError], compliant_versions: list[int]) -> None:
        super().__init__(errors)
        self.compliant_versions = compliant_versions


class FloorBelowMinimumError(DraftServiceError):
    """The candidate extends a floor below the platform minimum (HTTP 409
    ``floor_below_minimum``): publish a new version on a current floor."""


@dataclass(frozen=True, slots=True)
class VersionView:
    version: int
    bundle_hash: str
    created_at: datetime
    status: str
    """``active``, ``candidate`` or ``inactive``: where the version stands now."""
    published_mode: str | None
    published_rollout_percent: int | None
    """What the publish event said at the time. Not what the version does now: a
    promoted or rolled-back version has since become ``enforce`` at 100%."""
    actor: str | None
    note: str
    cross_tenant: bool
    operator: bool
    diff: tuple[Any, ...] = field(default_factory=tuple)
    current_mode: str | None = None
    current_rollout_percent: int | None = None
    """``enforce`` at 100 for the active version, the candidate's own mode and share (as moved
    since) for the candidate, ``None`` for an inactive one."""


def _bad(code: str, path: str, message: str) -> DraftInvalidError:
    return DraftInvalidError([DraftError(code, path, message)])


def parse_approval_id(doc: dict[str, Any], errors: list[DraftError]) -> str | None:
    approval_id = doc.get("approval_id")
    if approval_id is None:
        return None
    if not isinstance(approval_id, str) or not _APPROVAL_ID.fullmatch(approval_id):
        errors.append(DraftError("publish.approval_id", "$.approval_id", "an approval id"))
        return None
    return approval_id


def parse_publish_request(body: bytes) -> tuple[str, int, str, str | None]:
    """``{"mode", "rollout_percent"?, "note"?, "approval_id"?}``, strictly: the mode, the share,
    the note and the approval's id. Raises :class:`DraftInvalidError`."""
    doc, problems = parse_json_text(body)
    if problems:
        raise DraftInvalidError(_convert(problems))
    if not isinstance(doc, dict):
        raise _bad("publish.not_object", "$", "the request is an object")
    errors: list[DraftError] = []
    for extra in sorted(set(doc) - _PUBLISH_FIELDS):
        errors.append(DraftError("publish.unknown_field", f"$.{extra}", "not a field"))
    mode = doc.get("mode")
    if mode not in MODES:
        errors.append(DraftError("publish.mode", "$.mode", f"one of {', '.join(MODES)}"))
    percent = doc.get("rollout_percent", 100)
    if not isinstance(percent, int) or isinstance(percent, bool) or not 1 <= percent <= 100:
        errors.append(DraftError("publish.rollout_percent", "$.rollout_percent", "1 to 100"))
    note = doc.get("note", "")
    if not isinstance(note, str) or len(note) > MAX_NOTE_CHARS:
        errors.append(DraftError("publish.note", "$.note", f"text of at most {MAX_NOTE_CHARS}"))
    approval_id = parse_approval_id(doc, errors)
    if errors:
        raise DraftInvalidError(errors)
    return mode, percent, note, approval_id


def parse_promote_request(body: bytes) -> str | None:
    """``{"approval_id"?}`` or no body: the approval a promotion to enforce uses."""
    if not body.strip():
        return None
    doc, problems = parse_json_text(body)
    if problems:
        raise DraftInvalidError(_convert(problems))
    if not isinstance(doc, dict):
        raise _bad("promote.not_object", "$", "the request is an object")
    errors = [
        DraftError("promote.unknown_field", f"$.{extra}", "not a field")
        for extra in sorted(set(doc) - {"approval_id"})
    ]
    approval_id = parse_approval_id(doc, errors)
    if errors:
        raise DraftInvalidError(errors)
    return approval_id


def parse_percent_request(body: bytes) -> int:
    doc, problems = parse_json_text(body)
    if problems:
        raise DraftInvalidError(_convert(problems))
    if not isinstance(doc, dict) or set(doc) != {"rollout_percent"}:
        raise _bad("publish.request", "$", 'send {"rollout_percent": 1 to 100}')
    percent = doc["rollout_percent"]
    if not isinstance(percent, int) or isinstance(percent, bool) or not 1 <= percent <= 100:
        raise _bad("publish.rollout_percent", "$.rollout_percent", "1 to 100")
    return percent


def _with_record(note: str, record: str) -> str:
    """The caller's note, then the evidence gate's record, within the column's limit (the
    caller's note is kept whole: the record is cut)."""
    if not record:
        return note
    joined = f"{note}\n{record}" if note else record
    return joined if len(joined) <= MAX_NOTE_CHARS else joined[: MAX_NOTE_CHARS - 1] + "…"


class PublishService:
    def __init__(
        self,
        drafts: ScopedDraftStores,
        lifecycle: ScopedLifecycleStores,
        tenants: TenantDirectory,
        catalog: Catalog,
        settings: PlatformSettings,
        *,
        gate: EvidenceGate | None = None,
        bus: PublishBus | None = None,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        require_issuer: bool = False,
        approvals: ApprovalService | None = None,
    ) -> None:
        self._approvals = approvals
        self._drafts = drafts
        self._lifecycle = lifecycle
        self._tenants = tenants
        self._catalog = catalog
        self._settings = settings
        self._gate = gate
        self._bus = bus
        self._clock = clock
        self._require_issuer = require_issuer

    # ------------------------------------------------------------------ helpers

    def _check_actor(self, principal: Principal) -> None:
        if self._require_issuer and principal.issuer is None:
            raise DecisionError("the principal has no issuer; the audit actor needs one")

    async def _profile(self, scope: TenantScope) -> TenantProfile:
        profile = await self._tenants.get(scope.tenant_id)
        if profile is None:
            raise TenantUnavailableError()
        return profile

    def _event(
        self,
        scope: TenantScope,
        decision: AuthzDecision,
        principal: Principal,
        action: str,
        version: int,
        **fields: Any,
    ) -> PublishEvent:
        return PublishEvent(
            at=self._clock(),
            actor=principal.actor,
            tenant_id=scope.tenant_id,
            action=action,
            version=version,
            cross_tenant=decision.cross_tenant,
            operator=principal.platform_operator,
            **fields,
        )

    async def _announce(
        self,
        scope: TenantScope,
        version: int,
        action: str,
        *,
        mode: str | None = None,
        active: bool | None = None,
    ) -> None:
        """After the commit. A bus failure never undoes or fails the change: the pointer TTL
        bounds how long a replica serves the old version."""
        if self._bus is None:
            return
        try:
            await self._bus.publish(
                GuardrailPublished(
                    scope.tenant_id, version, action, mode, active, self._clock().timestamp()
                )
            )
        except Exception:
            logger.exception("guardrail.published could not be sent; the TTL covers it")

    async def _notify(
        self,
        scope: TenantScope,
        decision: AuthzDecision,
        principal: Principal,
        change: str,
        version: int,
        detail: str,
    ) -> None:
        """After a commit that needed no second approver (R2: a rollback, a larger share for an
        approved version): when the tenant's enforcing needs approval, tell its admins (an alert
        and a class A ``notified`` event). Never fails the change that already happened."""
        if self._approvals is None:
            return
        try:
            if approval_required(await self._profile(scope)):
                await self._approvals.notify_change(
                    scope, decision, principal, change=change, version=version, detail=detail
                )
        except Exception:
            logger.exception("the admin notification for a %s could not be made", change)

    async def _approval_use(
        self,
        scope: TenantScope,
        decision: AuthzDecision,
        principal: Principal,
        profile: TenantProfile,
        approval_id: str | None,
        *,
        action: str,
        draft_hash: str | None,
        version: int | None,
        for_version: int | None = None,
    ) -> ApprovalUse | None:
        """The R2 approval rule for something that would enforce: None when this tenant needs no
        second person, the approval to consume when it does and a valid one was named, else
        :class:`ApprovalRequiredError` (none named, no approval service, or nothing for it to
        bind to) or the approval's own error (pending, expired, stale, used...)."""
        if not approval_required(profile):
            return None
        if self._approvals is None or approval_id is None or draft_hash is None:
            raise ApprovalRequiredError()
        return await self._approvals.use_for(
            scope, decision, principal,
            approval_id=approval_id, action=action, draft_hash=draft_hash, version=version,
            for_version=for_version,
        )  # fmt: skip

    @staticmethod
    def _approval_note(use: ApprovalUse | None) -> str:
        return "" if use is None else f"two-person approval {use.approval_id}"

    async def _enforce_checks(
        self,
        scope: TenantScope,
        document: dict[str, Any],
        history: list[PublishEvent],
        active: int | None = None,
    ) -> str:
        """The R1 evidence gate for something that would enforce (the R2 approval is checked
        before it, :meth:`_approval_use`). Returns the gate's record of what the precision check
        used (targets, bundle, floor), for the event's note; empty when there was none."""
        if self._gate is None:
            return ""
        active_document = (
            None
            if active is None
            else await self._lifecycle.scoped(scope).document(scope.tenant_id, active)
        )  # what the regression gate compares with (AC-A3)
        failures, record = await self._gate.evaluate(
            scope, document, history, self._clock(),
            active_version=active, active_document=active_document,
        )  # fmt: skip
        if failures:
            raise DraftInvalidError(
                [DraftError(f.code, f"$.rules[{f.rule_id}]", f.message) for f in failures]
            )
        return record

    # ------------------------------------------------------------------ publish

    async def publish(
        self, decision: AuthzDecision, principal: Principal, body: bytes, if_match: str | None
    ) -> PublishResult:
        scope = _scope_of(decision, PUBLISH)
        self._check_actor(principal)
        mode, percent, note, approval_id = parse_publish_request(body)
        draft = await self._drafts.scoped(scope).get(scope.tenant_id)
        if draft is None:
            raise NoDraftError()
        if if_match is None:
            raise PreconditionRequiredError()
        if not _if_match_ok(if_match, draft.etag):
            raise DraftConflictError(draft.etag)
        profile = await self._profile(scope)
        store = self._lifecycle.scoped(scope)
        state = await store.state(scope.tenant_id)
        if state.candidate is not None:
            raise CandidateExistsError()
        first = state.active is None
        if first and (mode != "enforce" or percent != 100):
            raise NoActiveVersionError()
        history = await store.events(scope.tenant_id)
        version = 1 + max((v.version for v in await store.versions(scope.tenant_id)), default=0)

        document = json.loads(draft.document)
        document["version"] = version
        parsed = parse_bundle(document)
        compiler = PolicyCompiler(self._catalog, profile, self._settings)
        errors = compiler.validate(parsed, profile.attributes)
        if errors:
            raise DraftInvalidError(_convert(errors))
        record = ""
        use = None
        if mode == "enforce":
            use = await self._approval_use(
                scope, decision, principal, profile, approval_id,
                action="publish", draft_hash=draft.etag.strip('"'), version=None,
                for_version=version,
            )  # fmt: skip
            record = await self._enforce_checks(scope, document, history, state.active)
        bundle_hash = compiler.compile(parsed, profile.attributes).bundle_hash
        before = {} if state.active is None else await store.document(scope.tenant_id, state.active)
        event = self._event(
            scope, decision, principal, "publish", version,
            from_version=state.active if first else None,
            mode=mode, rollout_percent=percent, bundle_hash=bundle_hash,
            draft_hash=draft.etag.strip('"'),
            diff=bundle_diff(before or {}, parsed.document),
            note=_with_record(note, "; ".join(x for x in (self._approval_note(use), record) if x)),
            rules=rule_snapshots(parsed.document), becomes_active=first,
        )  # fmt: skip
        candidate = None if first else Candidate(version, mode, percent, event.at, principal.actor)
        await store.publish(
            scope.tenant_id, parsed, bundle_hash, candidate=candidate, expected=state, event=event,
            **({} if use is None else {"approval": use}),
        )  # fmt: skip
        await self._announce(scope, version, "publish", mode=mode, active=first)
        return PublishResult(
            version, bundle_hash, mode, percent, "active" if first else "candidate"
        )

    # ------------------------------------------------------------------ candidate

    async def _with_candidate(self, scope: TenantScope) -> tuple[Any, LifecycleState, Candidate]:
        store = self._lifecycle.scoped(scope)
        state = await store.state(scope.tenant_id)
        if state.candidate is None:
            raise NoCandidateError()
        return store, state, state.candidate

    async def set_percent(
        self, decision: AuthzDecision, principal: Principal, body: bytes
    ) -> Candidate:
        scope = _scope_of(decision, SET_PERCENT)
        self._check_actor(principal)
        percent = parse_percent_request(body)
        store, state, candidate = await self._with_candidate(scope)
        if candidate.mode == "enforce" and percent > candidate.rollout_percent:
            # Raising an enforce candidate's share hands it more live traffic, so it is
            # held to the tenant's tier of today, with the codes a publish would get. Lowering the
            # share and abandoning stay allowed, so a tenant can always back out.
            profile = await self._profile(scope)
            document = await store.document(scope.tenant_id, candidate.version)
            if document is None:
                raise VersionNotFoundError(scope.tenant_id, candidate.version)
            unmet = self._tier_errors(profile, document)
            if unmet:
                raise DraftInvalidError(_convert(unmet))
        event = self._event(
            scope, decision, principal, "set_percent", candidate.version,
            mode=candidate.mode, rollout_percent=percent,
        )  # fmt: skip
        await store.set_percent(scope.tenant_id, percent, expected=state, event=event)
        await self._announce(scope, candidate.version, "set_percent")
        if candidate.mode == "enforce" and percent > candidate.rollout_percent:
            # R2: raising an approved version's share needs no approver, but the admins are told.
            await self._notify(
                scope, decision, principal, "set_percent", candidate.version,
                f"raised the approved enforce candidate v{candidate.version} from "
                f"{candidate.rollout_percent}% to {percent}%",
            )  # fmt: skip
        return Candidate(candidate.version, candidate.mode, percent, candidate.at, candidate.actor)

    async def promote(
        self, decision: AuthzDecision, principal: Principal, body: bytes = b""
    ) -> PublishResult:
        scope = _scope_of(decision, PROMOTE)
        self._check_actor(principal)
        approval_id = parse_promote_request(body)
        store, state, candidate = await self._with_candidate(scope)
        profile = await self._profile(scope)
        # Promotion makes the version decide all traffic: the enforce gates run on its document.
        document = await store.document(scope.tenant_id, candidate.version)
        if document is None:
            raise VersionNotFoundError(scope.tenant_id, candidate.version)
        if self._floor_below_minimum(document):
            raise FloorBelowMinimumError()  # staged before the platform raised the minimum
        # A promotion is a forward publish. The candidate was compiled when the tenant
        # was on its tier of the day; it is held to the tier of today, with the codes a publish
        # would get, whatever approvals it has (R4.1 is not something a second admin can waive).
        unmet = self._tier_errors(profile, document)
        if unmet:
            raise DraftInvalidError(_convert(unmet))
        history = await store.events(scope.tenant_id)
        # R2: promoting a *shadow* candidate to enforce is what needs a second person. An
        # *enforce* candidate is the "raise the share of an approved version" case, but only when
        # it was approved: its publish consumed an approval (read from the approval trail, not the
        # publish note), or the tenant needed none then and needs none now. Otherwise,
        # for example when the tenant became regulated, or opted in, after the publish, the
        # promotion needs an approval as a shadow candidate's does.
        use = None
        evidence = ""
        needs = approval_required(profile)
        published_approval = None
        if candidate.mode == "enforce" and self._approvals is not None:
            published_approval = await self._approvals.published_under_approval(
                scope, candidate.version
            )
        if candidate.mode == "shadow" or (
            candidate.mode == "enforce" and needs and not published_approval
        ):
            drafted = [
                e.draft_hash
                for e in history
                if e.action == "publish" and e.version == candidate.version and e.draft_hash
            ]
            use = await self._approval_use(
                scope, decision, principal, profile, approval_id,
                action="promote", draft_hash=drafted[-1] if drafted else None,
                version=candidate.version, for_version=candidate.version,
            )  # fmt: skip
        if candidate.mode == "enforce":
            if use is not None:
                evidence = "enforce candidate published without an approval; promotion approved"
            elif published_approval is not None:
                evidence = f"enforce candidate published under approval {published_approval}"
            else:
                evidence = "enforce candidate published without an approval; the tenant needs none"
        record = await self._enforce_checks(scope, document, history, state.active)
        event = self._event(
            scope, decision, principal, "promote", candidate.version,
            from_version=state.active, mode="enforce", rollout_percent=100, becomes_active=True,
            note=_with_record(
                "", "; ".join(x for x in (self._approval_note(use), evidence, record) if x)
            ),
        )  # fmt: skip
        await store.promote(
            scope.tenant_id, expected=state, event=event,
            **({} if use is None else {"approval": use}),
        )  # fmt: skip
        await self._announce(scope, candidate.version, "promote", active=True)
        if candidate.mode == "enforce" and use is None:
            await self._notify(
                scope, decision, principal, "promote", candidate.version,
                f"promoted the approved enforce candidate v{candidate.version} to 100%",
            )  # fmt: skip
        versions = {v.version: v for v in await store.versions(scope.tenant_id)}
        return PublishResult(
            candidate.version, versions[candidate.version].bundle_hash, "enforce", 100, "active"
        )

    async def abandon(self, decision: AuthzDecision, principal: Principal) -> int:
        scope = _scope_of(decision, ABANDON)
        self._check_actor(principal)
        store, state, candidate = await self._with_candidate(scope)
        event = self._event(
            scope, decision, principal, "abandon", candidate.version,
            mode=candidate.mode, rollout_percent=candidate.rollout_percent,
        )  # fmt: skip
        await store.abandon(scope.tenant_id, expected=state, event=event)
        await self._announce(scope, candidate.version, "abandon")
        return candidate.version

    # ------------------------------------------------------------------ rollback and reads

    async def rollback(
        self, decision: AuthzDecision, principal: Principal, version: int
    ) -> PublishResult:
        scope = _scope_of(decision, ROLLBACK)
        self._check_actor(principal)
        store = self._lifecycle.scoped(scope)
        state = await store.state(scope.tenant_id)
        known = {v.version: v for v in await store.versions(scope.tenant_id)}
        if version not in known:
            raise VersionNotFoundError(scope.tenant_id, version)
        if state.active == version:
            raise AlreadyActiveError()
        if state.candidate is not None and state.candidate.version == version:
            raise _bad(
                "rollback.candidate", "$", "that version is the candidate: promote it instead"
            )
        events = await store.events(scope.tenant_id)
        if not any(e.becomes_active and e.version == version for e in events):
            raise NotPreviouslyActiveError()  # never active: it never passed the enforce gates
        target = await store.document(scope.tenant_id, version)
        if target is not None:
            await self._check_rollback_tier(scope, store, state, events, version, target)
        if target is not None and self._floor_below_minimum(target):
            return await self._rollback_repinned(
                scope, decision, principal, store, state, version, target
            )
        event = self._event(
            scope, decision, principal, "rollback", version,
            from_version=state.active, bundle_hash=known[version].bundle_hash,
            becomes_active=True,
            abandoned_candidate=None if state.candidate is None else state.candidate.version,
        )  # fmt: skip
        await store.rollback(scope.tenant_id, version, expected=state, event=event)
        await self._announce(scope, version, "rollback", active=True)
        await self._notify(
            scope, decision, principal, "rollback", version,
            f"rolled back from v{state.active} to v{version}",
        )  # fmt: skip
        return PublishResult(version, known[version].bundle_hash, "enforce", 100, "active")

    async def _check_rollback_tier(
        self,
        scope: TenantScope,
        store: Any,
        state: LifecycleState,
        events: list[PublishEvent],
        version: int,
        target: dict[str, Any],
    ) -> None:
        """R4.1 wins over R2's rollback exemption: on a regulated tenant a rollback
        target must meet the current tier's requirements. The rollback stays approval-free; the
        version that is running keeps running even if a raise left it short."""
        profile = await self._profile(scope)
        if not profile.attributes.regulated:
            return
        unmet = self._tier_errors(profile, target)
        if not unmet:
            return
        compliant: list[int] = []
        for earlier in sorted({e.version for e in events if e.becomes_active}):
            if earlier in (version, state.active) or (
                state.candidate is not None and state.candidate.version == earlier
            ):
                continue
            document = await store.document(scope.tenant_id, earlier)
            if document is not None and not self._tier_errors(profile, document):
                compliant.append(earlier)
        raise RollbackTierError(_convert(unmet), compliant)

    def _tier_errors(self, profile: TenantProfile, document: dict[str, Any]) -> list[PolicyError]:
        return tier_requirement_errors(
            self._catalog, profile, self._settings, profile.attributes, document
        )

    def _minimum_floor(self) -> int:
        return max(self._settings.min_floor_version, self._catalog.minimum_floor_version())

    def _floor_below_minimum(self, document: dict[str, Any]) -> bool:
        try:
            return floor_version_of(document) < self._minimum_floor()
        except RepinError:
            return False  # not a bundle this check can read; the compiler judges it elsewhere

    async def _rollback_repinned(
        self,
        scope: TenantScope,
        decision: AuthzDecision,
        principal: Principal,
        store: Any,
        state: Any,
        version: int,
        target: dict[str, Any],
    ) -> PublishResult:
        """A rollback to a version on a floor below the minimum (R5.6): the tenant's own content
        comes back, on the current floor, as a new version that becomes active. The current
        floor is the one the active version extends (never below the minimum). No old floor is
        ever active again."""
        active = await store.document(scope.tenant_id, state.active)
        try:
            current = floor_version_of(active) if active is not None else 0
        except RepinError:
            current = 0
        floor_version = max(current, self._minimum_floor())
        floor = self._catalog.floor(floor_version)
        if floor is None or not self._catalog.is_released(floor_version):
            raise RollbackRepinError()
        profile = await self._profile(scope)
        result = repin_document(target, floor)
        new_version = 1 + max(v.version for v in await store.versions(scope.tenant_id))
        document = {**result.document, "version": new_version}
        # A rollback returns to a version that was published and approved once: the tier's
        # required packs apply to a new publish, not to going back (R2, M5-01).
        compiler = PolicyCompiler(
            self._catalog, profile, self._settings, enforce_tier_requirements=False
        )
        if compiler.validate(document, profile.attributes):
            raise RollbackRepinError()
        parsed = parse_bundle(document)
        bundle_hash = compiler.compile(parsed, profile.attributes).bundle_hash
        drops = tuple(d.as_dict() for d in result.drops)
        event = self._event(
            scope, decision, principal, "rollback", new_version, from_version=state.active,
            bundle_hash=bundle_hash, becomes_active=True,
            abandoned_candidate=None if state.candidate is None else state.candidate.version,
            note=f"rollback to v{version} re-pinned from floor@{result.from_floor} to "
            f"floor@{floor_version}; {len(drops)} override(s) dropped",
            diff=bundle_diff(target, parsed.document), repin_floor=floor_version,
            repin_drops=drops,
        )  # fmt: skip
        await store.activate_new(scope.tenant_id, parsed, bundle_hash, expected=state, event=event)
        await self._announce(scope, new_version, "rollback", active=True)
        await self._notify(
            scope, decision, principal, "rollback", new_version,
            f"rolled back from v{state.active} to a re-pinned copy of v{version} (v{new_version})",
        )  # fmt: skip
        return PublishResult(new_version, bundle_hash, "enforce", 100, "active")

    async def rollout_state(self, decision: AuthzDecision) -> dict[str, Any]:
        """For ``GET guardrails``: the active version and the candidate with its mode and
        share (the rollout state)."""
        scope = _scope_of(decision, GET_GUARDRAILS)
        state = await self._lifecycle.scoped(scope).state(scope.tenant_id)
        c = state.candidate
        return {
            "active_version": state.active,
            "candidate": None
            if c is None
            else {
                "version": c.version,
                "mode": c.mode,
                "rollout_percent": c.rollout_percent,
                "since": c.at.isoformat(),
                "by": c.actor,
            },
        }

    async def versions(self, decision: AuthzDecision) -> list[VersionView]:
        scope = _scope_of(decision, VERSIONS)
        store = self._lifecycle.scoped(scope)
        state = await store.state(scope.tenant_id)
        published = {
            e.version: e for e in await store.events(scope.tenant_id) if e.action == "publish"
        }
        views = []
        for entry in await store.versions(scope.tenant_id):
            e = published.get(entry.version)
            candidate = state.candidate
            if candidate is not None and candidate.version != entry.version:
                candidate = None
            if state.active == entry.version:
                status, mode, percent = "active", "enforce", 100
            elif candidate is not None:
                status, mode, percent = "candidate", candidate.mode, candidate.rollout_percent
            else:
                status, mode, percent = "inactive", None, None
            views.append(
                VersionView(
                    entry.version,
                    entry.bundle_hash,
                    entry.created_at,
                    status,
                    None if e is None else e.mode,
                    None if e is None else e.rollout_percent,
                    None if e is None else e.actor,
                    "" if e is None else e.note,
                    False if e is None else e.cross_tenant,
                    False if e is None else e.operator,
                    () if e is None else e.diff,
                    mode,
                    percent,
                )
            )
        return views


__all__ = [
    "AlreadyActiveError",
    "ApprovalRequiredError",
    "CandidateExistsError",
    "FloorBelowMinimumError",
    "NoActiveVersionError",
    "NoCandidateError",
    "NotPreviouslyActiveError",
    "PublishResult",
    "PublishService",
    "RollbackRepinError",
    "StateConflictError",
    "VersionView",
    "read_bundle",
]  # fmt: skip
