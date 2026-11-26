"""The operator's hold on the provider-health breaker (M7-11): ``GET`` and ``PUT
/v1/platform/provider/degraded``.

The gateway opens its provider-health breaker by itself when the provider stops answering and
closes it when a probe is answered. A platform operator can also **hold the provider degraded**
(every check on every gateway of this process then fails at once as ``provider_degraded``, with
no probe) and **lift** the hold, which also clears any breaker the gateway had opened. It is for
an outage the operator knows of before the gateway has seen it, or one it keeps probing into.

**Platform operators only** (the route needs the platform role; a tenant credential is refused
by the authorizer before this service runs). Each change is a class A event
(``provider_degraded_hold`` or ``provider_degraded_lift``: who, when, why) recorded **before**
the gateways change: if it can't be recorded the change doesn't happen (HTTP 503). The breaker
is per process, so the hold is too: with several replicas the operator sets it on each.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from typing import Any

from guardrail_engine.admin.floors import PlatformEvent, PlatformStore, platform_decision
from guardrail_engine.admin.service import DraftServiceError
from guardrail_engine.authz.authorizer import AuthzDecision
from guardrail_engine.authz.model import Principal

READ = ("GET", "/v1/platform/provider/degraded")
WRITE = ("PUT", "/v1/platform/provider/degraded")
MAX_REASON_CHARS = 200


class ProviderHoldUnavailableError(DraftServiceError):
    """The change could not be recorded, so it did not happen (HTTP 503)."""


class ProviderHoldBodyError(DraftServiceError):
    """The body is not ``{"degraded": bool, "reason": str}`` (HTTP 422)."""


class ProviderHealthService:
    def __init__(
        self,
        platform: PlatformStore,
        gateways: Callable[[], Mapping[Any, Any]],
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        """``gateways`` returns the engine's gateways (the shared pool's and each dedicated
        project's), read at call time."""
        self._platform = platform
        self._gateways = gateways
        self._clock = clock

    async def status(self, decision: AuthzDecision) -> dict[str, Any]:
        platform_decision(decision, READ)
        return {
            "gateways": {
                "shared" if project is None else str(project): gateway.degraded_status()
                for project, gateway in sorted(self._gateways().items(), key=lambda kv: str(kv[0]))
            }
        }

    async def set_hold(
        self, decision: AuthzDecision, principal: Principal, doc: Mapping[str, Any]
    ) -> dict[str, Any]:
        platform_decision(decision, WRITE)
        degraded, reason = doc.get("degraded"), doc.get("reason")
        if not isinstance(degraded, bool):
            raise ProviderHoldBodyError("degraded: true or false")
        if not isinstance(reason, str) or not 1 <= len(reason.strip()) <= MAX_REASON_CHARS:
            raise ProviderHoldBodyError(f"reason: 1 to {MAX_REASON_CHARS} characters")
        event = PlatformEvent(
            self._clock(),
            principal.actor,
            "provider_degraded_hold" if degraded else "provider_degraded_lift",
            detail={"reason": reason.strip(), "operator": principal.platform_operator},
        )
        try:
            await self._platform.record(event)  # first: no record, no change
        except Exception as exc:
            raise ProviderHoldUnavailableError("the change could not be recorded") from exc
        changed = [gateway.force_degraded(degraded) for gateway in self._gateways().values()]
        return {"degraded": degraded, "changed": any(changed)}
