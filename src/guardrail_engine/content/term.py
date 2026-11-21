"""The class C term, worked out when the content is written (M5-03, R3).

The compiler already refuses a bundle whose ``audit.content_days`` is over the cap for its packs
and one that stores content for a healthcare tenant without the BAA flag. This is the same check
**again, at write time**, with the bounds in force then, because a tier or contract change, a pack
that now applies, or a BAA flag taken away can leave a published bundle behind. The direction of
every doubt is **not to store**: unlike a decision record (class B, where the safe error is to
keep it too long), stored content is the privacy risk, so:

* a tenant that isn't in the directory, a pack the catalog lacks or a failing directory: **not
  stored** (``reason`` says why; the writer counts it);
* a tenant whose packs need a BAA and which has no BAA flag: **not stored**;
* otherwise the days are the bundle's ``audit.content_days`` (or the packs' default) clamped into
  1 to the **shortest** cap among the tenant's packs (standard 90, healthcare 30; at most 90
  whatever a pack says).
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Protocol

from guardrail_engine.audit.term import Unresolvable, gather_packs
from guardrail_engine.content.model import MAX_CLASS_C_DAYS
from guardrail_engine.policy.catalog import Catalog, PlatformSettings
from guardrail_engine.policy.compiler import combined_retention

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class ContentTerm:
    days: int | None
    """None: do not store."""
    reason: str


class ContentTermResolver(Protocol):
    async def term(
        self, tenant_id: str, requested_days: int | None, packs: Sequence[str] = ()
    ) -> ContentTerm:
        """Never raises: anything it can't work out is 'do not store'."""
        ...


class _Directory(Protocol):
    async def get(self, tenant_id: str) -> Any: ...


class EffectiveContentTerm:
    def __init__(
        self, *, catalog: Catalog, settings: PlatformSettings, directory: _Directory
    ) -> None:
        self._catalog = catalog
        self._settings = settings
        self._directory = directory

    async def term(
        self, tenant_id: str, requested_days: int | None, packs: Sequence[str] = ()
    ) -> ContentTerm:
        try:
            entry = await self._directory.get(tenant_id)
            if entry is None:
                return ContentTerm(None, "not_in_directory")
            attributes = getattr(entry, "attributes", entry)
            profile = combined_retention(
                self._settings, gather_packs(self._catalog, attributes, packs).values()
            )
            if profile.content_requires_baa and not getattr(attributes, "baa", False):
                return ContentTerm(None, "baa_missing")
            cap = min(profile.content_max_days, MAX_CLASS_C_DAYS)
            wanted = (
                requested_days
                if requested_days is not None
                else min(profile.content_default_days, profile.content_max_days)
            )
            days = max(1, min(wanted, cap))
            return ContentTerm(days, "bundle" if days == requested_days else "clamped")
        except Unresolvable as exc:
            return ContentTerm(None, exc.cause)
        except Exception as exc:
            logger.warning("class C term for tenant %s failed: %s", tenant_id, type(exc).__name__)
            return ContentTerm(None, type(exc).__name__)
