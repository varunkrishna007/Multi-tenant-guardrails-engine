"""A tenant's class B retention, worked out from R3 (M4-09).

The bounds are the compiler's own (AC-C1.13), ``combined_retention`` and
``records_days_in_bounds`` in ``guardrail_engine.policy.compiler``, so a pack's retention
profile means the same thing at publish time and at deletion time. Nothing is duplicated here.

What counts as the tenant's packs: the packs its active bundle extends, **plus** any pack its
tier or contract requires that the bundle doesn't extend (at the catalog's latest version of
it). The compiler refuses a bundle missing a required pack, but a tier change after publish can
leave an active bundle behind; the retention bound doesn't wait for the next publish. With
several packs the longest default and minimum apply, the shortest maximum (R3).

The term is the bundle's ``audit.records_days`` if it set one, else the packs' default, moved
into the bounds. It is moved **up** to the minimum and **down** to the maximum: the job never
deletes sooner than R3's minimum for the tenant. A tenant that can't be resolved at all (not in
the directory, no readable bundle, a pack the catalog lacks) gets the platform's longest term,
7 years, because deleting early can't be undone and keeping a little longer can.
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Protocol

from guardrail_engine.directory.model import TenantDirectoryStore
from guardrail_engine.policy.catalog import (
    Catalog,
    PackVersion,
    PlatformSettings,
    RetentionProfile,
)
from guardrail_engine.policy.compiler import combined_retention, records_days_in_bounds
from guardrail_engine.policy.document import EXTENDS_REF_PATTERN, ParsedBundle
from guardrail_engine.retention.store import Source

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class TenantRetention:
    days: int
    source: Source


class RetentionResolver(Protocol):
    async def resolve(self, tenant_id: str | None) -> TenantRetention: ...


BundleLoader = Callable[[str], Awaitable[ParsedBundle | None]]
"""Returns the tenant's active bundle, or None if it has none. The platform supplies it with
the access it already has to every tenant's store (an operator-scope store); this module never
mints a tenant scope."""


class CatalogRetentionResolver:
    def __init__(
        self,
        *,
        catalog: Catalog,
        settings: PlatformSettings,
        directory: TenantDirectoryStore,
        load_active_bundle: BundleLoader,
    ) -> None:
        self._catalog = catalog
        self._settings = settings
        self._directory = directory
        self._load = load_active_bundle

    def _fallback(self) -> TenantRetention:
        return TenantRetention(self._settings.standard_retention.records_max_days, "fallback")

    async def resolve(self, tenant_id: str | None) -> TenantRetention:
        if tenant_id is None:
            return self._fallback()
        try:
            return await self._resolve(tenant_id)
        except Exception as exc:  # unresolvable: keep the longest term, never delete early
            logger.warning(
                "retention fallback for a tenant: %s", type(exc).__name__, exc_info=False
            )
            return self._fallback()

    async def _resolve(self, tenant_id: str) -> TenantRetention:
        found = await self.profile_for(tenant_id)
        if found is None:
            return self._fallback()
        profile, parsed = found
        requested = parsed.bundle.audit.records_days if parsed is not None else None
        days = profile.records_default_days if requested is None else requested
        if records_days_in_bounds(profile, days):
            return TenantRetention(days, "default" if requested is None else "bundle")
        return TenantRetention(
            max(profile.records_min_days, min(days, profile.records_max_days)), "clamped"
        )

    async def profile_for(
        self, tenant_id: str
    ) -> tuple[RetentionProfile, ParsedBundle | None] | None:
        """The tenant's combined R3 profile (its packs, plus those its tier or contract
        requires) and its active bundle; None if the tenant is not in the directory. Raises if
        the bundle or a pack can't be resolved. Shared with the class D job (M4-05), which reads
        ``content_requires_baa`` (healthcare) from it."""
        record = await self._directory.get(tenant_id)
        if record is None:
            return None
        parsed = await self._load(tenant_id)
        packs: dict[str, PackVersion] = {}
        if parsed is not None:
            for ref in parsed.bundle.extends:
                m = EXTENDS_REF_PATTERN.fullmatch(ref)
                if m is None:
                    raise ValueError("malformed extends")
                if m.group(1):  # the floor
                    continue
                pack = self._catalog.pack(m.group(2), int(m.group(3)))
                if pack is None:
                    raise ValueError("pack missing from the catalog")
                packs[pack.name] = pack
        required = self._catalog.packs_required_for_tier(record.tier) | record.required_packs
        for name in sorted(required - packs.keys()):
            versions = [v for n, v in self._catalog.pack_versions() if n == name]
            pack = self._catalog.pack(name, max(versions)) if versions else None
            if pack is None:
                raise ValueError("required pack missing from the catalog")
            packs[name] = pack

        return combined_retention(self._settings, packs.values()), parsed
