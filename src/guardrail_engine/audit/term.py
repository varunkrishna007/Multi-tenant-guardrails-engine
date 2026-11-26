"""The class B term a decision record is stamped with (M4-07).

``retain_until`` is what protects a record from early deletion: the retention job deletes a row
only when it is past its tenant's cutoff **and** its own ``retain_until``. So it is never
the raw value a verdict carried. :class:`EffectiveTerm` takes the term the check was decided
under (``Verdict.retention_days``: the bundle's ``audit.records_days``, or the packs' default,
as compiled) and **moves it into the R3 bounds in force now**, with the same functions the
compiler and the retention engine use (``combined_retention``, ``records_days_in_bounds``):

* up to the minimum, never down: a record is never kept for less than R3's minimum for the
  tenant's packs, whatever the bundle said or a tier change since then;
* down to the maximum, **except** that the minimum wins when the packs' bounds conflict (a pack
  whose minimum is above another's maximum): the longest retention, as R3 says;
* the bounds are those of the platform's standard profile, the packs the **bundle extends**
  (``Verdict.retention_packs``, pinned versions), and the packs the tenant's tier and contract
  require (at the catalog's latest version; a tier change after publish can leave a bundle
  behind).

The tenant's tier and contract packs are read from the directory entry the Guard Service uses
(a :class:`~guardrail_engine.guard.tenants.TenantProfile`: ``attributes.tier`` and
``attributes.required_packs``); a directory store's ``TenantRecord`` (``tier``,
``required_packs``) works too.

A tenant that isn't in the directory, a pack the catalog lacks, a failing directory, or a
verdict that carries no term gets the platform's longest term, 7 years: keeping a record a
little longer can be undone, deleting it early can't. **That fallback is never silent**: each
one is warned about by tenant and counted (:meth:`EffectiveTerm.fallback_counts`), so a fleet
that has quietly started keeping everything for 7 years is noticed.
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable, Sequence
from typing import Any, Protocol

from guardrail_engine.policy.catalog import (
    Catalog,
    PackVersion,
    PlatformSettings,
    is_regulated_tier,
)
from guardrail_engine.policy.compiler import combined_retention, records_days_in_bounds
from guardrail_engine.policy.document import EXTENDS_REF_PATTERN
from guardrail_engine.retention.resolver import TenantRetention

logger = logging.getLogger(__name__)

MAX_FALLBACK_KEYS = 10_000


class TermResolver(Protocol):
    async def term(
        self, tenant_id: str | None, requested_days: int | None, packs: Sequence[str] = ()
    ) -> TenantRetention:
        """Never raises: anything it can't work out is the longest term."""
        ...


class _Directory(Protocol):
    async def get(self, tenant_id: str) -> Any: ...


class EffectiveTerm:
    def __init__(
        self, *, catalog: Catalog, settings: PlatformSettings, directory: _Directory
    ) -> None:
        self._catalog = catalog
        self._settings = settings
        self._directory = directory
        self._fallbacks: dict[tuple[str, str], int] = {}

    def fallback_counts(self) -> dict[tuple[str, str], int]:
        """How often the longest term was used because the term couldn't be worked out, by
        (tenant id, cause). Tenant ``""`` is a record with no verified tenant."""
        return dict(self._fallbacks)

    def _longest(self, tenant_id: str | None, cause: str) -> TenantRetention:
        key = (tenant_id or "", cause)
        if key in self._fallbacks or len(self._fallbacks) < MAX_FALLBACK_KEYS:
            self._fallbacks[key] = self._fallbacks.get(key, 0) + 1
        if tenant_id is not None:  # a record with no tenant always gets it: nothing to warn of
            logger.warning(
                "decision record term for tenant %s fell back to the longest term (%s)",
                tenant_id,
                cause,
            )
        return TenantRetention(self._settings.standard_retention.records_max_days, "fallback")

    async def term(
        self, tenant_id: str | None, requested_days: int | None, packs: Sequence[str] = ()
    ) -> TenantRetention:
        if tenant_id is None:
            return self._longest(None, "no_tenant")
        if requested_days is None:
            return self._longest(tenant_id, "no_term_on_verdict")
        try:
            return await self._term(tenant_id, requested_days, packs)
        except _Unresolvable as exc:
            return self._longest(tenant_id, exc.cause)
        except Exception as exc:
            return self._longest(tenant_id, type(exc).__name__)

    async def _term(self, tenant_id: str, days: int, extended: Sequence[str]) -> TenantRetention:
        entry = await self._directory.get(tenant_id)
        if entry is None:
            raise _Unresolvable("not_in_directory")
        attributes = getattr(entry, "attributes", entry)  # a TenantProfile, or a TenantRecord
        packs = gather_packs(self._catalog, attributes, extended)
        profile = combined_retention(self._settings, packs.values())
        if records_days_in_bounds(profile, days):
            return TenantRetention(days, "bundle")
        # the minimum wins over a maximum when the packs' bounds conflict (longest retention)
        return TenantRetention(
            max(profile.records_min_days, min(days, profile.records_max_days)), "clamped"
        )


def directory_regulated(directory: _Directory) -> Callable[[str], Awaitable[bool]]:
    """Whether a tenant's tier is regulated (anything but ``standard``, R2), read from the same
    directory entry as the term. A tenant that isn't in the directory is not regulated; a
    directory that fails raises, and the caller decides (the decision-record writer keeps the
    record, M7-04)."""

    async def regulated(tenant_id: str) -> bool:
        entry = await directory.get(tenant_id)
        if entry is None:
            return False
        return is_regulated_tier(getattr(getattr(entry, "attributes", entry), "tier"))  # noqa: B009

    return regulated


class _Unresolvable(Exception):
    def __init__(self, cause: str) -> None:
        super().__init__(cause)
        self.cause = cause


Unresolvable = _Unresolvable
"""For the class C term (``guardrail_engine.content.term``), which resolves the same packs."""


def gather_packs(
    catalog: Catalog, attributes: Any, extended: Sequence[str]
) -> dict[str, PackVersion]:
    """The packs whose R3 bounds apply to a tenant: those its bundle **extends** (pinned
    versions), and those its tier and contract require (at the catalog's latest version; a tier
    change after publish can leave a bundle behind). Raises :class:`Unresolvable` for a malformed
    reference or a pack the catalog lacks. One definition for the class B and class C terms."""
    packs: dict[str, PackVersion] = {}
    for ref in extended:
        m = EXTENDS_REF_PATTERN.fullmatch(ref)
        if m is None or not m.group(2):
            raise _Unresolvable("malformed_pack_ref")
        pack = catalog.pack(m.group(2), int(m.group(3)))
        if pack is None:
            raise _Unresolvable("pack_missing")
        packs[pack.name] = pack
    required = catalog.packs_required_for_tier(attributes.tier) | frozenset(
        attributes.required_packs
    )
    for name in sorted(required - packs.keys()):
        versions = [v for n, v in catalog.pack_versions() if n == name]
        pack = catalog.pack(name, max(versions)) if versions else None
        if pack is None:
            raise _Unresolvable("pack_missing")
        packs[name] = pack
    return packs
