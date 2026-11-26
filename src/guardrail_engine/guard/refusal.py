"""A provider refusal that goes to a person (M7-08), and the cap on how many may.

PF-12 made a provider safety refusal always a block. Where a guard point has an **enforce** rule
whose ``max_action`` is ``escalate`` (a rule that "may hold content for a person, never refuse
it": healthcare's emergency symptoms, the responsible-AI pack), a refusal of the content is
exactly the kind of content that rule exists to put in front of a person. So the Guard Service
makes it an ``escalate`` with the reason ``provider_safety`` instead of a ``block``, if

* the engine has somewhere to route an escalation (an escalation router is attached): otherwise
  nobody would see it, and it stays a block; and
* the tenant's cap on such escalations is not spent: :class:`RefusalEscalations` allows
  :attr:`RefusalConfig.cap` per tenant and guard point in :attr:`RefusalConfig.window_s`. A
  sender who varies refused texts can't flood a person's queue past it. Past the cap the refusal is
  a block, as before, and one alert per tenant per window says so.

**The cost, stated plainly:** at a guard point with an escalate-only rule, a provider-refused
jailbreak goes to a person instead of being blocked. It is held either way: ``escalate`` withholds
the content as ``block`` does. Everything deterministic before the model (deny patterns, secret
formats, the size limit, the tool allow-list, repeat refusals) still blocks, and so does every
refusal at a guard point with no escalate-only rule.

Nothing the provider said is in the item: the verdict carries a fixed reason and the item holds
the rule keys the content might have been about (``candidate_rules``, never ``fired``).

The cap's counter is behind :class:`RefusalCapStore` and is bounded, like the repeat store's. A
store that fails means **block**, never escalate.
"""

from __future__ import annotations

import logging
from collections import OrderedDict, deque
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class RefusalConfig:
    cap: int = 20
    """Refusals one tenant may send to a person at one guard point within the window. 0 makes
    every refusal a block (the behaviour before M7-08). Provisional: not calibrated against real
    traffic."""
    window_s: float = 900.0
    max_keys: int = 50_000
    """Tenant and guard point pairs held at once; the oldest go first."""

    def __post_init__(self) -> None:
        if self.cap < 0 or self.window_s <= 0 or self.max_keys < 1:
            raise ValueError("cap >= 0, window_s > 0 and max_keys >= 1")


@dataclass(frozen=True, slots=True)
class Take:
    allowed: bool
    first_denial: bool = False
    """The first refusal past the cap for this tenant in this window: the one that is alerted."""


class RefusalCapStore(Protocol):
    async def take(self, tenant_id: str, guard_point: str, now: float) -> Take:
        """Count one refusal escalation for the tenant at the guard point, if the cap allows."""
        ...


class InMemoryRefusalCap:
    """In this process only (per replica, lost on restart). Bounded: at most ``max_keys`` tenant
    and guard point pairs, the oldest first; the alert marks are one per tenant and expire with
    the window."""

    def __init__(self, config: RefusalConfig | None = None) -> None:
        self._config = config or RefusalConfig()
        self._times: OrderedDict[tuple[str, str], deque[float]] = OrderedDict()
        self._alerted: OrderedDict[str, float] = OrderedDict()

    @property
    def size(self) -> int:
        return len(self._times)

    async def take(self, tenant_id: str, guard_point: str, now: float) -> Take:
        key = (tenant_id, guard_point)
        times = self._times.get(key)
        if times is None:
            times = self._times[key] = deque()
        else:
            self._times.move_to_end(key)
        horizon = now - self._config.window_s
        while times and times[0] <= horizon:
            times.popleft()
        while len(self._times) > self._config.max_keys:
            self._times.popitem(last=False)
        if len(times) < self._config.cap:
            times.append(now)
            return Take(True)
        if not times:  # a cap of 0 holds nothing
            self._times.pop(key, None)
        until = self._alerted.get(tenant_id, 0.0)
        if until > now:
            return Take(False)
        self._alerted[tenant_id] = now + self._config.window_s
        self._alerted.move_to_end(tenant_id)
        while len(self._alerted) > self._config.max_keys or (
            self._alerted and next(iter(self._alerted.values())) <= now
        ):
            self._alerted.popitem(last=False)
        return Take(False, first_denial=True)


class RefusalEscalations:
    """The Guard Service's side: whether a refusal at this guard point may go to a person."""

    def __init__(
        self, config: RefusalConfig | None = None, store: RefusalCapStore | None = None
    ) -> None:
        self.config = config or RefusalConfig()
        self._store = store or InMemoryRefusalCap(self.config)

    def candidate_rules(self, rules: Mapping[str, Any]) -> tuple[str, ...]:
        """The keys of the enforce-mode rules in ``rules`` (the evaluated set) that may only
        escalate, sorted. Shadow rules never act, so they don't count."""
        return tuple(
            sorted(
                key
                for key, rule in rules.items()
                if getattr(rule, "max_action", None) == "escalate"
                and getattr(rule, "mode", None) == "enforce"
            )
        )

    async def take(self, tenant_id: str, guard_point: str, now: float) -> Take:
        """May this refusal go to a person? Never raises: a store that fails means no."""
        if self.config.cap == 0:
            return Take(False)
        try:
            return await self._store.take(tenant_id, guard_point, now)
        except Exception:
            logger.exception("the refusal escalation cap could not be read; blocking")
            return Take(False)
