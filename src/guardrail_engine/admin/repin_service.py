"""The platform's floor moves (M2-09, R5): re-pin, staged promotion, the minimum raise.

All of it is the platform acting on tenants, so each tenant step goes through the real
**authorizer** as the initiating operator: a cross-tenant decision, written to the cross-tenant
audit before anything happens, whose scope is the only way to reach that tenant's stores. The
class A event on the tenant's own trail has actor ``platform``; the operator, the release and the
reason are in its note, and the platform's own trail (``platform_audit``) records the step.

**Re-pin (R5.2, R5.3).** For a released floor, a tenant's active bundle is rewritten by
:func:`~guardrail_engine.policy.repin.repin_document` (``extends`` moves, nothing else of the
tenant's changes, floor overrides carry over only while still stricter), validated by the
compiler, and published as a **shadow candidate at 100%** (PF-7), with the dropped overrides in
the event and in the notice to the tenant's admins. Nothing is forced: a tenant that already has
a candidate of its own is **skipped and listed** (its candidate is never abandoned), a tenant
whose re-pinned bundle doesn't compile stays on its floor and is listed, and a tenant already on
that floor is listed as such. A candidate that is itself a stale or repeated platform re-pin is
replaced.

**Staging and promotion (R5.4).** Promotion is manual, per tenant, once the release's window
(72 hours; 6 for a release both approvers marked security-urgent) has passed since the candidate
was staged, and never while the release is halted. It skips the tenant's own gates (the evidence
gate and approval: the tenant's content didn't change) **only after proving** that the candidate
is exactly what a re-pin of the tenant's **current** active version would produce, apart from its
version number: if the tenant published, rolled back or promoted since, the proof fails and the
candidate must be replaced by a fresh re-pin.

**Minimum (R5.5).** Raised only when every non-offboarded tenant's active version extends a floor
at or above it; the refusal names the tenants behind. A tenant that publishes between the check
and the write isn't caught (the window is two calls); its next rollback or promotion is refused
or re-pinned by the guards below.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol

from guardrail_engine.admin.floors import (
    FloorNotReleasedError,
    Notice,
    Notifier,
    PlatformEvent,
    PlatformStore,
    ReleaseNotFoundError,
    platform_decision,
)
from guardrail_engine.admin.lifecycle import (
    Candidate,
    GuardrailPublished,
    PublishBus,
    PublishEvent,
    ScopedLifecycleStores,
    rule_snapshots,
)
from guardrail_engine.admin.service import DraftServiceError
from guardrail_engine.authz.authorizer import AuthzDecision
from guardrail_engine.authz.model import Principal
from guardrail_engine.guard.tenants import TenantDirectory
from guardrail_engine.policy.canonical import sha256_of
from guardrail_engine.policy.catalog import InMemoryCatalog, PlatformSettings
from guardrail_engine.policy.compiler import PolicyCompiler
from guardrail_engine.policy.diff import bundle_diff
from guardrail_engine.policy.document import parse_bundle
from guardrail_engine.policy.repin import RepinError, floor_version_of, repin_document

logger = logging.getLogger(__name__)

PLATFORM_ACTOR = "platform"
REPIN = ("POST", "/v1/tenants/{tid}/guardrails/floor/repin")
PROMOTE = ("POST", "/v1/tenants/{tid}/guardrails/floor/promote")
STATE = ("GET", "/v1/tenants/{tid}/guardrails/floor")
REPIN_ALL = ("POST", "/v1/platform/floors/{version}/repin")
ROLLOUT = ("GET", "/v1/platform/floors/{version}/rollout")
RAISE_MINIMUM = ("PUT", "/v1/platform/minimum-floor")
MAX_NOTE = 500


class TenantLister(Protocol):
    async def tenant_ids(self, *, include_suspended: bool = False) -> list[str]: ...


class AuthorizerLike(Protocol):
    async def authorize(
        self, principal: Principal, method: str, route: str, tenant_id: str | None = None
    ) -> AuthzDecision: ...


# --------------------------------------------------------------------------- errors


class PromotionHaltedError(DraftServiceError):
    """(HTTP 409 ``promotion_halted``)"""


class WindowOpenError(DraftServiceError):
    """The staging window hasn't passed (HTTP 409 ``window_open``)."""

    def __init__(self, until: datetime) -> None:
        super().__init__("the staging window is open")
        self.until = until


class NoRepinCandidateError(DraftServiceError):
    """The tenant has no re-pin candidate for that release (HTTP 409 ``no_repin_candidate``)."""


class RepinStaleError(DraftServiceError):
    """The candidate is not what a re-pin of the current active version would be (HTTP 409
    ``repin_stale``): the tenant changed its active version since it was staged."""


class TenantsBehindError(DraftServiceError):
    """(HTTP 409 ``tenants_behind``)"""

    def __init__(self, tenants: list[str]) -> None:
        super().__init__("tenants are still behind")
        self.tenants = tenants


class MinimumError(DraftServiceError):
    """The new minimum isn't a valid raise (HTTP 409 ``minimum_invalid``)."""


class TenantForbiddenError(DraftServiceError):
    """The authorizer refused the platform step on this tenant (HTTP 403)."""


# --------------------------------------------------------------------------- results


@dataclass(frozen=True, slots=True)
class TenantRepin:
    tenant_id: str
    outcome: str
    """``staged``, ``replaced`` (a stale platform candidate was replaced then staged),
    ``already_staged``, ``already_on_floor``, ``skipped`` or ``failed``."""
    version: int | None = None
    detail: str | None = None
    drops: tuple[dict[str, Any], ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "tenant_id": self.tenant_id, "outcome": self.outcome, "version": self.version,
            "detail": self.detail, "drops": list(self.drops),
        }  # fmt: skip


def repin_proof(active: dict[str, Any], candidate: dict[str, Any], floor: Any) -> str | None:
    """None if ``candidate`` is exactly the re-pin of ``active`` on ``floor`` apart from its
    version number, else a fixed word."""
    try:
        expected = repin_document(active, floor).document
    except RepinError:
        return "active_has_no_single_floor"
    expected["version"] = candidate.get("version")
    return None if sha256_of(expected) == sha256_of(candidate) else "differs"


# --------------------------------------------------------------------------- the service


class RepinService:
    def __init__(
        self,
        platform: PlatformStore,
        lifecycle: ScopedLifecycleStores,
        tenants: TenantDirectory,
        lister: TenantLister,
        catalog: InMemoryCatalog,
        settings: PlatformSettings,
        authorizer: AuthorizerLike,
        *,
        notifier: Notifier,
        bus: PublishBus | None = None,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._platform = platform
        self._lifecycle = lifecycle
        self._tenants = tenants
        self._lister = lister
        self._catalog = catalog
        self._settings = settings
        self._authorizer = authorizer
        self._notifier = notifier
        self._bus = bus
        self._clock = clock
        self._minimum_lock = asyncio.Lock()

    # ------------------------------------------------------------------ helpers

    async def _released(self, version: int) -> Any:
        release = await self._platform.release(version)
        if release is None:
            raise ReleaseNotFoundError()
        if not release.released or self._catalog.floor(version) is None:
            raise FloorNotReleasedError()
        return release

    async def _decide(
        self, principal: Principal, endpoint: tuple[str, str], tenant_id: str
    ) -> AuthzDecision:
        decision = await self._authorizer.authorize(
            principal, endpoint[0], endpoint[1], tenant_id=tenant_id
        )
        if not decision.allowed or decision.scope is None:
            raise TenantForbiddenError(decision.reason)
        return decision

    def _note(self, text: str) -> str:
        return text if len(text) <= MAX_NOTE else text[: MAX_NOTE - 3] + "..."

    async def _announce(
        self,
        tenant_id: str,
        version: int,
        action: str,
        *,
        mode: str | None = None,
        active: bool | None = None,
    ) -> None:
        if self._bus is None:
            return
        try:
            await self._bus.publish(
                GuardrailPublished(
                    tenant_id, version, action, mode, active, self._clock().timestamp()
                )
            )
        except Exception:
            logger.exception("guardrail.published could not be sent; the TTL covers it")

    async def _audit(self, principal: Principal, action: str, version: int, tid: str, **d: Any):
        await self._platform.record(
            PlatformEvent(self._clock(), principal.actor, action, version, tid, dict(d))
        )

    # ------------------------------------------------------------------ re-pin

    async def repin_all(
        self,
        decision: AuthzDecision,
        principal: Principal,
        version: int,
        reason: str,
        only: list[str] | None = None,
    ) -> list[TenantRepin]:
        platform_decision(decision, REPIN_ALL)
        await self._released(version)
        ids = await self._lister.tenant_ids()
        if only is not None:
            ids = [t for t in ids if t in set(only)]
        return [await self._repin_safely(principal, t, version, reason) for t in ids]

    async def _repin_safely(
        self, principal: Principal, tenant_id: str, version: int, reason: str
    ) -> TenantRepin:
        try:
            return await self.repin_tenant(principal, tenant_id, version, reason)
        except TenantForbiddenError as e:
            return TenantRepin(tenant_id, "skipped", None, f"forbidden: {e}")
        except Exception as e:  # one tenant never stops the others
            logger.exception("re-pin of %s to floor@%s failed", tenant_id, version)
            return TenantRepin(tenant_id, "failed", None, f"error: {type(e).__name__}")

    async def repin_tenant(
        self, principal: Principal, tenant_id: str, version: int, reason: str
    ) -> TenantRepin:
        release = await self._released(version)
        floor = self._catalog.floor(version)
        assert floor is not None
        if version < self._catalog.minimum_floor_version():
            raise MinimumError("below the minimum")
        decision = await self._decide(principal, REPIN, tenant_id)
        scope = decision.scope
        assert scope is not None
        profile = await self._tenants.get(tenant_id)
        if profile is None:
            return TenantRepin(tenant_id, "skipped", None, "tenant_unavailable")
        store = self._lifecycle.scoped(scope)
        state = await store.state(tenant_id)
        if state.active is None:
            return TenantRepin(tenant_id, "skipped", None, "no_active_version")
        active = await store.document(tenant_id, state.active)
        if active is None:
            return TenantRepin(tenant_id, "failed", None, "active_version_unreadable")
        try:
            current = floor_version_of(active)
        except RepinError:
            return TenantRepin(tenant_id, "failed", None, "active_has_no_single_floor")
        if current >= version:
            return TenantRepin(tenant_id, "already_on_floor", state.active, f"floor@{current}")
        events = await store.events(tenant_id)
        replaced = False
        if state.candidate is not None:
            mine = next(
                (
                    e for e in events
                    if e.action == "publish" and e.version == state.candidate.version
                ),
                None,
            )  # fmt: skip
            if mine is None or mine.repin_floor is None:
                return TenantRepin(tenant_id, "skipped", None, "candidate_exists")
            cand = await store.document(tenant_id, state.candidate.version)
            staged_now = (
                mine.repin_floor == version
                and cand is not None
                and repin_proof(active, cand, floor) is None
            )
            if staged_now:
                return TenantRepin(tenant_id, "already_staged", state.candidate.version, None)
            # a platform candidate that is stale, or for another floor: the platform replaces it
            await store.abandon(
                tenant_id, expected=state,
                event=PublishEvent(
                    self._clock(), PLATFORM_ACTOR, tenant_id, "abandon", state.candidate.version,
                    mode=state.candidate.mode, rollout_percent=state.candidate.rollout_percent,
                    note=self._note(f"platform replaced its own re-pin candidate: {reason}"),
                    cross_tenant=decision.cross_tenant, operator=True,
                ),
            )  # fmt: skip
            state = await store.state(tenant_id)
            replaced = True
        result = repin_document(active, floor)
        new_version = 1 + max(v.version for v in await store.versions(tenant_id))
        document = {**result.document, "version": new_version}
        # A re-pin changes the floor only: the tier applies at the next publish (M5-01).
        compiler = PolicyCompiler(
            self._catalog, profile, self._settings, enforce_tier_requirements=False
        )
        errors = compiler.validate(document, profile.attributes)
        if errors:
            codes = sorted({str(e.code) for e in errors})
            await self._audit(
                principal, "repin", version, tenant_id, outcome="failed", errors=codes
            )
            return TenantRepin(
                tenant_id, "failed", None, "does not compile: " + ", ".join(codes[:5]),
                tuple(d.as_dict() for d in result.drops),
            )  # fmt: skip
        parsed = parse_bundle(document)
        bundle_hash = compiler.compile(parsed, profile.attributes).bundle_hash
        now = self._clock()
        drops = tuple(d.as_dict() for d in result.drops)
        event = PublishEvent(
            now, PLATFORM_ACTOR, tenant_id, "publish", new_version, mode="shadow",
            rollout_percent=100, bundle_hash=bundle_hash,
            diff=bundle_diff(active, parsed.document),
            note=self._note(
                f"platform re-pin to floor@{version} ({reason}); started by {principal.actor}; "
                f"{len(drops)} override(s) dropped"
            ),
            rules=rule_snapshots(parsed.document), cross_tenant=decision.cross_tenant,
            operator=True, repin_floor=version, repin_drops=drops,
        )  # fmt: skip
        await store.publish(
            tenant_id, parsed, bundle_hash,
            candidate=Candidate(new_version, "shadow", 100, now, PLATFORM_ACTOR),
            expected=state, event=event,
        )  # fmt: skip
        await self._announce(tenant_id, new_version, "publish", mode="shadow", active=False)
        await self._audit(
            principal, "repin", version, tenant_id, outcome="staged", candidate=new_version,
            drops=list(drops), reason=reason,
        )  # fmt: skip
        await self._notify(
            tenant_id,
            "floor_repin_staged",
            f"your guardrails are staged on floor@{version} in shadow",
            {
                "floor_version": version,
                "candidate_version": new_version,
                "drops": list(drops),
                "reason": reason,
                "window_hours": release.window.total_seconds() / 3600,
            },
        )
        return TenantRepin(
            tenant_id, "replaced" if replaced else "staged", new_version, None, drops
        )

    async def _notify(
        self, tenant_id: str, kind: str, subject: str, detail: dict[str, Any]
    ) -> None:
        try:
            await self._notifier.notify(Notice(tenant_id, kind, subject, detail))
        except Exception:
            logger.exception("the notice to %s could not be delivered", tenant_id)

    # ------------------------------------------------------------------ promotion

    async def promote_tenant(
        self, principal: Principal, tenant_id: str, version: int
    ) -> TenantRepin:
        release = await self._released(version)
        if release.halted:
            raise PromotionHaltedError()
        floor = self._catalog.floor(version)
        assert floor is not None
        decision = await self._decide(principal, PROMOTE, tenant_id)
        scope = decision.scope
        assert scope is not None
        store = self._lifecycle.scoped(scope)
        state = await store.state(tenant_id)
        cand = state.candidate
        if cand is None or state.active is None:
            raise NoRepinCandidateError()
        events = await store.events(tenant_id)
        staged = next(
            (e for e in events if e.action == "publish" and e.version == cand.version), None
        )
        if staged is None or staged.repin_floor != version:
            raise NoRepinCandidateError()
        until = cand.at + release.window
        if self._clock() < until:
            raise WindowOpenError(until)
        active = await store.document(tenant_id, state.active)
        candidate = await store.document(tenant_id, cand.version)
        if active is None or candidate is None or repin_proof(active, candidate, floor):
            raise RepinStaleError()  # checked against the active version as it is now
        now = self._clock()
        event = PublishEvent(
            now, PLATFORM_ACTOR, tenant_id, "promote", cand.version, from_version=state.active,
            mode="enforce", rollout_percent=100,
            note=self._note(f"platform promotes the floor@{version} re-pin; by {principal.actor}"),
            cross_tenant=decision.cross_tenant, operator=True, becomes_active=True,
            repin_floor=version, repin_drops=staged.repin_drops,
        )  # fmt: skip
        await store.promote(tenant_id, expected=state, event=event)
        await self._announce(tenant_id, cand.version, "promote", active=True)
        await self._audit(
            principal, "promote", version, tenant_id, candidate=cand.version,
            from_version=state.active,
        )  # fmt: skip
        await self._notify(
            tenant_id,
            "floor_repin_promoted",
            f"your guardrails now run on floor@{version}",
            {"floor_version": version, "version": cand.version, "drops": list(staged.repin_drops)},
        )
        return TenantRepin(tenant_id, "promoted", cand.version, None, staged.repin_drops)

    # ------------------------------------------------------------------ read and raise

    async def _behind(self, principal: Principal, value: int) -> list[str]:
        """The tenants whose active version is on a floor below ``value``."""
        behind: list[str] = []
        for tenant_id in await self._lister.tenant_ids(include_suspended=True):
            d = await self._decide(principal, STATE, tenant_id)
            assert d.scope is not None
            store = self._lifecycle.scoped(d.scope)
            state = await store.state(tenant_id)
            if state.active is None:
                continue
            floor = _floor_of(await store.document(tenant_id, state.active))
            if floor is None or floor < value:
                behind.append(tenant_id)
        return behind

    async def tenant_state(self, principal: Principal, tenant_id: str) -> dict[str, Any]:
        """One tenant's floor state: the floor its active version extends and any candidate's."""
        d = await self._decide(principal, STATE, tenant_id)
        assert d.scope is not None
        store = self._lifecycle.scoped(d.scope)
        state = await store.state(tenant_id)
        out: dict[str, Any] = {"tenant_id": tenant_id, "active_version": state.active}
        if state.active is not None:
            out["active_floor"] = _floor_of(await store.document(tenant_id, state.active))
        if state.candidate is not None:
            out["candidate_version"] = state.candidate.version
            out["candidate_floor"] = _floor_of(
                await store.document(tenant_id, state.candidate.version)
            )
            out["candidate_since"] = state.candidate.at.isoformat()
        return out

    async def rollout(
        self, decision: AuthzDecision, principal: Principal, version: int
    ) -> list[dict[str, Any]]:
        platform_decision(decision, ROLLOUT)
        rows = []
        for tenant_id in await self._lister.tenant_ids(include_suspended=True):
            try:
                d = await self._decide(principal, STATE, tenant_id)
            except TenantForbiddenError:
                rows.append({"tenant_id": tenant_id, "state": "forbidden"})
                continue
            assert d.scope is not None
            store = self._lifecycle.scoped(d.scope)
            state = await store.state(tenant_id)
            row: dict[str, Any] = {"tenant_id": tenant_id, "active_version": state.active}
            if state.active is not None:
                doc = await store.document(tenant_id, state.active)
                row["active_floor"] = _floor_of(doc)
            if state.candidate is not None:
                doc = await store.document(tenant_id, state.candidate.version)
                row["candidate_version"] = state.candidate.version
                row["candidate_floor"] = _floor_of(doc)
                row["candidate_since"] = state.candidate.at.isoformat()
            row["state"] = (
                "on_floor" if row.get("active_floor", 0) >= version
                else "staged" if row.get("candidate_floor") == version
                else "behind"
            )  # fmt: skip
            rows.append(row)
        return rows

    async def _stored_minimum(self) -> int | None:
        """The platform's stored minimum, or None if it can't be read (the restore then keeps
        the local figure: a restore that raises would hide the error that led to it)."""
        try:
            return await self._platform.minimum()
        except Exception:
            return None

    async def raise_minimum(self, decision: AuthzDecision, principal: Principal, value: int) -> int:
        platform_decision(decision, RAISE_MINIMUM)
        async with self._minimum_lock:  # one raise at a time on this replica
            return await self._raise_minimum(principal, value)

    async def _raise_minimum(self, principal: Principal, value: int) -> int:
        current = max(self._catalog.minimum_floor_version(), await self._platform.minimum() or 1)
        if value <= current:
            raise MinimumError(f"the minimum is floor@{current} and only goes up")
        if self._catalog.floor(value) is None or not self._catalog.is_released(value):
            raise FloorNotReleasedError()
        # The new minimum applies **first**, here, so that from now on no tenant can publish,
        # promote or roll back below it (they are refused or re-pinned: publish.py), and a
        # tenant can't slip under it between its check and the write.
        # If anyone is behind it is taken back.
        before = self._catalog.minimum_floor_version()
        self._catalog.raise_minimum(value)
        try:
            behind = await self._behind(principal, value)
            if behind:
                raise TenantsBehindError(sorted(behind))
            now = self._clock()
            await self._platform.set_minimum(
                value, expected=await self._platform.minimum(), by=principal.actor, at=now,
                event=PlatformEvent(
                    now, principal.actor, "raise_minimum", value, None, {"from": current}
                ),
            )  # fmt: skip
        except BaseException:
            # Back to what it was, but never below a raise that landed meanwhile (another
            # replica's, heard here as a reload or an event).
            self._catalog.restore_minimum(max(before, await self._stored_minimum() or before))
            raise
        # Another replica applies it when it hears (or reloads); a tenant that moved there in
        # the meantime is found now and recorded, for the operator to re-pin.
        stragglers = await self._behind(principal, value)
        if stragglers:
            logger.warning(
                "floor@%s minimum: tenants moved below it meanwhile: %s", value, stragglers
            )
            await self._platform.record(
                PlatformEvent(
                    self._clock(),
                    principal.actor,
                    "raise_minimum",
                    value,
                    None,
                    {"stragglers": sorted(stragglers)},
                )
            )
        if self._bus is not None:
            await self._announce("t_platform", 0, "floor")
        return value


def _floor_of(doc: dict[str, Any] | None) -> int | None:
    if doc is None:
        return None
    try:
        return floor_version_of(doc)
    except RepinError:
        return None


__all__ = [
    "PLATFORM_ACTOR", "PROMOTE", "RAISE_MINIMUM", "REPIN", "REPIN_ALL", "ROLLOUT", "STATE",
    "MinimumError", "NoRepinCandidateError", "PromotionHaltedError", "RepinService",
    "RepinStaleError", "TenantForbiddenError", "TenantRepin", "TenantsBehindError",
    "WindowOpenError", "repin_proof",
]  # fmt: skip
