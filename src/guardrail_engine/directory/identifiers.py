"""The cross-tenant identifier scan's source, read from the tenant directory (M3-01 wiring).

:class:`DirectoryIdentifiers` is the :class:`~guardrail_engine.deterministic.OtherTenantIdentifiers`
the Guard Service scans with when the directory is real. For **every** tenant in the directory
(any status: a suspended or offboarded tenant's identifiers are still not for anyone else's
content) it reports the tenant's id pattern and its registered identifier patterns.

* **Platform-reviewed on the way in and checked on the way out.** The operator write path
  (``TenantProvisioner``) refuses a pattern that ``validate_tenant_identifier_patterns`` doesn't
  pass. A row that got in some other way is checked again here, **pattern by pattern** (each
  distinct pattern once): a pattern that fails is left out and the tenant's others (and its id
  pattern) stay, with a warning naming the tenant id and a call to ``on_rejected(tenant_id)``,
  so one careless pattern can't block every other tenant. The engine points ``on_rejected`` at
  the Guard Service's report (a log line, the usage meter and the ``xtenant_patterns_dropped``
  alert), so it is not only a log line. Past the 20th valid pattern of a tenant, the rest are
  left out too.
* **Cheap per check.** The scanner asks for ``version()`` on every ``tool_result`` and
  ``output`` check. The directory is read at most every ``refresh_s`` seconds (default 5) and at
  once after ``invalidate()``, which the engine calls on ``tenant.changed``. Concurrent checks
  share one read. The version is a digest of the content, so a refresh that finds nothing new
  doesn't make the scanner rebuild.
* **Fails closed, with a bound.** If the directory can't be read, the last snapshot is used for
  up to ``max_stale_s`` (default 60 s); after that ``version()`` raises, and the check fails
  closed (``internal_error``), as it does for any source that can't answer. While it is
  serving a snapshot because the read failed, it tries again at most once a second, whether or
  not a change event is waiting.

A newly registered identifier is therefore scanned for within ``refresh_s`` of the write (a
second or so with the event), plus the scanner's rebuild, during which it serves the previous
set.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
from collections.abc import Callable, Hashable, Mapping, Sequence

from guardrail_engine.deterministic.identifiers import (
    MAX_PATTERNS_PER_TENANT,
    IdentifierPatternError,
    tenant_id_pattern,
    validate_identifier_pattern,
)
from guardrail_engine.deterministic.regex import RegexEngine
from guardrail_engine.directory.model import TenantDirectoryStore

logger = logging.getLogger(__name__)

REFRESH_S = 5.0
"""The longest the directory's identifiers are served without reading it again."""
MAX_STALE_S = 60.0
"""How long a snapshot is served after the directory stops answering."""
RETRY_AFTER_FAILURE_S = 1.0


class DirectoryIdentifiers:
    def __init__(
        self,
        store: TenantDirectoryStore,
        *,
        refresh_s: float = REFRESH_S,
        max_stale_s: float = MAX_STALE_S,
        clock: Callable[[], float] = time.monotonic,
        engine: RegexEngine | None = None,
        on_rejected: Callable[[str], None] | None = None,
    ) -> None:
        if refresh_s < 0 or max_stale_s < 0:
            raise ValueError("refresh_s and max_stale_s must not be negative")
        self._store = store
        self._refresh_s = refresh_s
        self._max_stale_s = max_stale_s
        self._clock = clock
        self._engine = engine
        self.on_rejected = on_rejected
        """Called with a tenant id when some of its registered patterns are left out of the scan
        (once per change of what is left out). The engine sets it to the Guard Service's report
        unless one was given."""
        self._lock = asyncio.Lock()
        self._dirty = True
        self._read_at: float | None = None  # when the snapshot was read
        self._next_read = 0.0
        self._backoff_until = 0.0
        self._patterns: dict[str, tuple[str, ...]] = {}
        self._digest = ""
        self._checked: dict[str, bool] = {}
        self._rejected: dict[str, frozenset[str]] = {}

    @property
    def rejected_tenants(self) -> frozenset[str]:
        """Tenants some of whose registered patterns were left out of the scan because they
        failed validation on read."""
        return frozenset(self._rejected)

    def invalidate(self) -> None:
        """The directory changed: read it again at the next check."""
        self._dirty = True

    async def version(self) -> Hashable:
        await self._ensure()
        return self._digest

    async def patterns_by_tenant(self) -> Mapping[str, Sequence[str]]:
        await self._ensure()
        return self._patterns

    async def _ensure(self) -> None:
        if self._fresh():
            return
        async with self._lock:
            if self._fresh():
                return  # another check read it while this one waited
            now = self._clock()
            try:
                records = await self._store.list()
            except Exception:
                if self._read_at is None or now - self._read_at >= self._max_stale_s:
                    raise  # nothing to fall back on, or too old: the check fails closed
                logger.warning("the tenant directory can't be read; the identifier snapshot stays")
                self._backoff_until = now + RETRY_AFTER_FAILURE_S  # even if a change is waiting
                return
            self._build(records)
            self._read_at = now
            self._next_read = now + self._refresh_s
            self._backoff_until = 0.0
            self._dirty = False

    def _fresh(self) -> bool:
        if self._read_at is None:
            return False
        now = self._clock()
        if now < self._backoff_until:
            return True  # the last read failed a moment ago: don't hammer the directory
        return not self._dirty and now < self._next_read

    def _build(self, records: Sequence) -> None:
        patterns: dict[str, tuple[str, ...]] = {}
        rejected: dict[str, frozenset[str]] = {}
        for record in sorted(records, key=lambda r: r.tenant_id):
            keep: list[str] = []
            bad: set[str] = set()
            for pattern in record.identifier_patterns:
                if len(keep) < MAX_PATTERNS_PER_TENANT and self._passes(pattern):
                    keep.append(pattern)
                else:
                    bad.add(pattern)
            if bad:
                rejected[record.tenant_id] = frozenset(bad)
            patterns[record.tenant_id] = (tenant_id_pattern(record.tenant_id), *keep)
        for tenant_id in sorted(rejected):
            if self._rejected.get(tenant_id) != rejected[tenant_id]:  # new, or a different set
                self._report(tenant_id, len(rejected[tenant_id]))
        self._rejected = rejected
        self._patterns = patterns
        self._digest = hashlib.sha256(
            json.dumps(sorted(patterns.items()), separators=(",", ":")).encode()
        ).hexdigest()

    def _report(self, tenant_id: str, count: int) -> None:
        logger.warning(
            "tenant %s: %d registered identifier pattern(s) failed validation and are not "
            "scanned for",
            tenant_id,
            count,
        )
        if self.on_rejected is not None:
            try:
                self.on_rejected(tenant_id)
            except Exception:
                logger.exception("the rejected-patterns hook failed; ignored")

    def _passes(self, pattern: str) -> bool:
        known = self._checked.get(pattern)
        if known is None:
            try:
                validate_identifier_pattern(pattern, self._engine)
                known = True
            except IdentifierPatternError:
                known = False
            self._checked[pattern] = known
        return known
