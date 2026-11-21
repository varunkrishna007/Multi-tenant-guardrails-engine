"""The Guard Service's view of the directory: the ``TenantDirectory`` port over a store, with a
read cache of 30 s and an ``invalidate`` for the ``tenant.changed`` event.

* Only **active** tenants have a profile. A suspended or offboarded tenant is unknown here, so
  the Guard Service refuses its checks.
* **Terminating or terminated (M5-07)** is remembered for good (:meth:`ended`): the status
  never goes back, so once this process has seen it the tenant is refused with the clear code
  ``tenant_terminated`` without another read. :meth:`ended_fresh` reads the store every time
  (the Admin API's authorizer, where a stale answer is not wanted).
* **A directory that can't answer.** :meth:`ended` goes on ("not known to be ended")
  only while this process's last *successful* read of that tenant is younger than
  ``max_unknown_s`` (default :data:`MAX_STATUS_UNKNOWN_S`, 300 s: ten times the read cache, so
  a normal blip passes). After that, or for a tenant this process has never read, it raises the
  store's error, and the Guard Service answers ``policy_unavailable`` (a retryable block). The
  policy cache's last-known-good policy can no longer keep serving a tenant whose status this
  replica can't confirm.
* A record that cannot build a profile (it bypassed the write path: a denylisted slug, say) is
  unknown too (fail closed), never a profile.
* **An invalidation during a fill wins.** Each tenant has a generation that
  ``invalidate`` bumps. A read that started before a bump never stores what it fetched (it may
  be the record from before the change); it reads again, up to :data:`MAX_FILL_ATTEMPTS`
  times, and after that returns what it has without caching it.
* The ``tools`` provider may be async (M2-03: the tenant's accepted tool registry entries). A
  provider failure is a store failure: it propagates and is not cached. A registry change calls
  ``invalidate`` (the engine does it on ``guardrail.published`` with action ``tools``).
* Unknown tenants are not cached, so a new tenant is usable at once; a store failure is not
  cached and propagates (the Guard Service treats it like a policy store failure).
"""

from __future__ import annotations

import inspect
import time
from collections.abc import Awaitable, Callable, Iterable

from guardrail_engine.directory.identifiers import DirectoryIdentifiers
from guardrail_engine.directory.model import (
    TERMINATION_STATUSES,
    TenantChanged,
    TenantDirectoryStore,
)
from guardrail_engine.guard.tenants import TenantProfile, ToolInfo

READ_CACHE_S = 30.0
MAX_STATUS_UNKNOWN_S = 300.0
MAX_FILL_ATTEMPTS = 3


ToolsProvider = Callable[[str], Iterable[ToolInfo] | Awaitable[Iterable[ToolInfo]]]


def no_tools(tenant_id: str) -> Iterable[ToolInfo]:
    return ()


class CachedTenantDirectory:
    def __init__(
        self,
        store: TenantDirectoryStore,
        *,
        ttl_s: float = READ_CACHE_S,
        clock: Callable[[], float] = time.monotonic,
        tools: ToolsProvider | None = None,
        max_unknown_s: float = MAX_STATUS_UNKNOWN_S,
    ) -> None:
        if max_unknown_s < 0:
            raise ValueError("max_unknown_s can't be negative")
        self._store = store
        self._ttl_s = ttl_s
        self._max_unknown_s = max_unknown_s
        self._last_read: dict[str, float] = {}
        self._clock = clock
        self._tools: ToolsProvider = no_tools if tools is None else tools
        self._tools_given = tools is not None
        self._cache: dict[str, tuple[float, TenantProfile]] = {}
        self._generation: dict[str, int] = {}
        self._identifiers: DirectoryIdentifiers | None = None
        self._ended: set[str] = set()

    async def ended(self, tenant_id: str) -> bool:
        """True once the tenant is terminating or terminated (M5-07). Uses the read cache (at
        most ``ttl_s`` stale, and ``tenant.changed`` invalidates it), and never un-ends a
        tenant. If the store can't be read, answers False only while this process's last
        successful read of the tenant is under ``max_unknown_s`` old; otherwise raises
        the store's error."""
        if tenant_id in self._ended:
            return True
        try:
            await self.get(tenant_id)  # fills the cache; _fetch records a termination
        except Exception:
            last = self._last_read.get(tenant_id)
            if tenant_id in self._ended:
                return True
            if last is not None and 0 <= self._clock() - last < self._max_unknown_s:
                return False
            raise
        return tenant_id in self._ended

    async def ended_fresh(self, tenant_id: str) -> bool:
        """Like :meth:`ended` but reads the store now, bypassing the cache."""
        if tenant_id in self._ended:
            return True
        record = await self._store.get(tenant_id)
        self._last_read[tenant_id] = self._clock()
        if record is not None and record.status in TERMINATION_STATUSES:
            self._ended.add(tenant_id)
        return tenant_id in self._ended

    async def get(self, tenant_id: str) -> TenantProfile | None:
        hit = self._cache.get(tenant_id)
        if hit is not None and self._clock() < hit[0]:
            return hit[1]
        self._cache.pop(tenant_id, None)
        profile: TenantProfile | None = None
        for _ in range(MAX_FILL_ATTEMPTS):
            started = self._generation.get(tenant_id, 0)
            profile = await self._fetch(tenant_id)
            if self._generation.get(tenant_id, 0) != started:
                continue  # a change event arrived while reading: what was read may be stale
            if profile is not None:
                self._cache[tenant_id] = (self._clock() + self._ttl_s, profile)
            return profile
        return profile  # still changing: serve this read, cache nothing

    async def _fetch(self, tenant_id: str) -> TenantProfile | None:
        record = await self._store.get(tenant_id)
        self._last_read[tenant_id] = self._clock()
        if record is not None and record.status in TERMINATION_STATUSES:
            self._ended.add(tenant_id)
        if record is None or record.status != "active":
            return None
        tools = self._tools(tenant_id)
        if inspect.isawaitable(tools):
            tools = await tools  # the registry-backed provider reads the tenant's accepted tools
        try:
            return record.to_profile(tools)
        except ValueError:
            return None

    async def tenant_ids(self, *, include_suspended: bool = False) -> list[str]:
        """The tenants the platform acts on in bulk (M2-09), straight from the store (not the
        cache): the active ones, and with ``include_suspended`` the suspended ones as well.
        An offboarded tenant is never listed."""
        wanted = ("active", "suspended") if include_suspended else ("active",)
        return sorted(r.tenant_id for r in await self._store.list() if r.status in wanted)

    def adopt_tools(self, provider: ToolsProvider) -> bool:
        """Use ``provider`` for tenants' tools unless this directory was given one of its own
        (the engine calls it with the tool registry's). True if it was adopted."""
        if self._tools_given:
            return False
        self._tools = provider
        self._tools_given = True
        self._cache.clear()
        return True

    def invalidate(self, tenant_id: str) -> None:
        self._generation[tenant_id] = self._generation.get(tenant_id, 0) + 1
        self._cache.pop(tenant_id, None)

    def on_changed(self, event: TenantChanged) -> None:
        """Subscribe this to the ``tenant.changed`` bus. A directory write also changes what
        the cross-tenant scan looks for (a new tenant, a registered pattern), so the next
        identifier check reads the directory again."""
        self.invalidate(event.tenant_id)
        if self._identifiers is not None:
            self._identifiers.invalidate()

    def other_tenant_identifiers(self) -> DirectoryIdentifiers:
        """The cross-tenant identifier scan's source over this directory's store (M3-01): the
        engine hands it to the Guard Service. One per directory."""
        if self._identifiers is None:
            self._identifiers = DirectoryIdentifiers(self._store)
        return self._identifiers
