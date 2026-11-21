"""The authorization decision for one Admin API call (AC-T1).

Rules, in order:

1. The route must be in :data:`~guardrail_engine.authz.model.ENDPOINTS` (an unknown route is a
   programming error: ``ValueError``).
2. **Platform-only routes** need the principal's ``platform_operator`` flag, else 403.
3. A tenant route's ``{tid}`` must match the tenant-id pattern, else 403 before anything else
   (so a malformed id never reaches a lookup, and the answer does not say which ids exist).
4. **Tenant match.** The path's tenant must equal the principal's ``tenant_id``, else 403, unless
   the principal is a platform operator. Only operators can cross tenants.
5. **Role.** The principal's roles must include the endpoint's role (see ``ROLE_IMPLIES``): an
   operator's tenant match is waived, their roles are not.
6. **Terminated tenants (M5-07).** When the authorizer has a ``tenant_ended`` check and it says
   the tenant is terminating or terminated, every route on that tenant is refused,
   operators included, with the reason ``tenant_terminated``; if the check itself fails the
   call is refused as ``tenant_status_unavailable`` (fail closed). It runs after the tenant
   match (a caller of another tenant gets ``tenant_mismatch`` and learns nothing) and before
   the role check; a refused cross-tenant operator attempt is recorded like any denial.
7. **Cross-tenant access is audited before the response.** When an operator touches a tenant
   other than their own, the event is written first; if the write fails the access is refused
   (``audit_unavailable``, 403). Denied cross-tenant attempts by anyone are recorded on a
   best-effort basis (a failure there never changes the 403).

The audit event holds identifiers only: subject, tenant ids, method, route template, outcome.
"""

from __future__ import annotations

import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Protocol

from guardrail_engine.authz.model import (
    ENDPOINTS,
    PLATFORM,
    Endpoint,
    Principal,
    role_satisfies,
)
from guardrail_engine.tenant_ids import is_valid_tenant_id
from guardrail_engine.tenant_scope import TenantScope, issue_scope

_ROUTES = {(e.method, e.route): e for e in ENDPOINTS}


@dataclass(frozen=True, slots=True)
class CrossTenantEvent:
    """A class A audit event for an access across tenants (AC-T1)."""

    at: float
    actor: str
    actor_tenant_id: str | None
    target_tenant_id: str
    method: str
    route: str
    allowed: bool
    reason: str


class AuthzAuditSink(Protocol):
    async def record(self, event: CrossTenantEvent) -> None:
        """Durably write the event; raise if that was not possible."""
        ...


class InMemoryAuthzAudit:
    def __init__(self) -> None:
        self.events: list[CrossTenantEvent] = []
        self.fail = False

    async def record(self, event: CrossTenantEvent) -> None:
        if self.fail:
            raise ConnectionError("audit store down")
        self.events.append(event)


@dataclass(frozen=True, slots=True)
class AuthzDecision:
    allowed: bool
    status: int
    """200 when allowed, else 403."""
    reason: str
    """A fixed word: ``ok``, ``not_platform_operator``, ``invalid_tenant_id``,
    ``tenant_mismatch``, ``missing_role``, ``audit_unavailable``, ``missing_issuer``,
    ``tenant_terminated``, ``tenant_status_unavailable``."""
    cross_tenant: bool = False
    endpoint: Endpoint | None = None
    scope: TenantScope | None = None
    """For an allowed tenant route: the path's tenant as a :class:`TenantScope`, the only
    form the policy store accepts. None for a denial and for a platform route."""

    @property
    def needs_second_approver(self) -> bool:
        """The caller must pass this to the approval flow on a regulated tier (M5-02)."""
        return bool(self.allowed and self.endpoint and self.endpoint.approver_on_regulated)


def _deny(reason: str, endpoint: Endpoint, cross_tenant: bool = False) -> AuthzDecision:
    return AuthzDecision(False, 403, reason, cross_tenant, endpoint)


class Authorizer:
    def __init__(
        self,
        audit: AuthzAuditSink,
        *,
        clock: Callable[[], float] = time.time,
        require_issuer: bool = False,
        tenant_ended: Callable[[str], Awaitable[bool]] | None = None,
    ) -> None:
        """``tenant_ended``: ``async (tenant_id) -> bool``, True when the tenant is terminating
        or terminated (M5-07; ``CachedTenantDirectory.ended_fresh`` reads the directory every
        time). ``require_issuer``: refuse a principal that has no verified issuer
        (``missing_issuer``). The audit actor is ``<issuer>#<subject>``; a principal
        without an issuer can only come from something other than the OIDC adapter, so the
        factory sets this everywhere but ``test``."""
        self._audit = audit
        self._clock = clock
        self._require_issuer = require_issuer
        self._tenant_ended = tenant_ended

    async def authorize(
        self, principal: Principal, method: str, route: str, tenant_id: str | None = None
    ) -> AuthzDecision:
        """``route`` is the template (``/v1/tenants/{tid}/guardrails/draft``) and ``tenant_id``
        the path's ``{tid}`` value (required for a tenant route)."""
        endpoint = _ROUTES.get((method.upper(), route))
        if endpoint is None:
            raise ValueError(f"no such route {method} {route}")
        if self._require_issuer and principal.issuer is None:
            return _deny("missing_issuer", endpoint)
        if not endpoint.tenant_scoped:
            if endpoint.required == PLATFORM and not principal.platform_operator:
                return _deny("not_platform_operator", endpoint)
            return AuthzDecision(True, 200, "ok", False, endpoint)
        if not is_valid_tenant_id(tenant_id):
            return _deny("invalid_tenant_id", endpoint)
        assert tenant_id is not None  # narrowed by the check above
        cross = tenant_id != principal.tenant_id
        if cross and not principal.platform_operator:
            await self._record(principal, tenant_id, endpoint, False, "tenant_mismatch")
            return _deny("tenant_mismatch", endpoint, cross_tenant=True)
        if self._tenant_ended is not None:
            # After the tenant match, so a caller of another tenant learns nothing about this one.
            try:
                ended = await self._tenant_ended(tenant_id)
            except Exception:
                if cross:
                    await self._record(principal, tenant_id, endpoint, False, "status_unavailable")
                return _deny("tenant_status_unavailable", endpoint, cross_tenant=cross)
            if ended:
                if cross:
                    await self._record(principal, tenant_id, endpoint, False, "tenant_terminated")
                return _deny("tenant_terminated", endpoint, cross_tenant=cross)
        if endpoint.required == PLATFORM:
            # A platform step on one tenant (M2-09): operators only, and no tenant role is
            # asked of them, because the step is the platform's, not the tenant's.
            if not principal.platform_operator:
                return _deny("not_platform_operator", endpoint, cross_tenant=cross)
        elif not role_satisfies(principal.roles, endpoint.required):  # type: ignore[arg-type]
            if cross:
                await self._record(principal, tenant_id, endpoint, False, "missing_role")
            return _deny("missing_role", endpoint, cross_tenant=cross)
        if cross:
            try:
                await self._audit.record(self._event(principal, tenant_id, endpoint, True, "ok"))
            except Exception:
                return _deny("audit_unavailable", endpoint, cross_tenant=True)
        return AuthzDecision(
            True, 200, "ok", cross, endpoint, issue_scope(tenant_id, operator=cross)
        )

    def _event(
        self, principal: Principal, tenant_id: str, endpoint: Endpoint, allowed: bool, reason: str
    ) -> CrossTenantEvent:
        return CrossTenantEvent(
            at=self._clock(), actor=principal.actor, actor_tenant_id=principal.tenant_id,
            target_tenant_id=tenant_id, method=endpoint.method, route=endpoint.route,
            allowed=allowed, reason=reason,
        )  # fmt: skip

    async def _record(
        self, principal: Principal, tenant_id: str, endpoint: Endpoint, allowed: bool, reason: str
    ) -> None:
        """Best effort: a denied attempt is recorded, but a failure never changes the 403."""
        try:
            await self._audit.record(self._event(principal, tenant_id, endpoint, allowed, reason))
        except Exception:
            return
