"""What a tier change means for the version a tenant is running now (M5-01).

A tier is a platform attribute. Raising it changes what the **next publish** must contain (the
tier's packs, and the rules of those packs that can't be opted out of), whether enforcing needs
a second approver (R2) and the retention floors (R3). It does **not** change the version that is
active: that version keeps running, compiled as it was published, until the tenant publishes
again (``PolicyCompiler.compile(..., enforce_tier_requirements=False)`` for a stored version).

So a raise can leave a tenant running a version that would not be accepted today. That is the
gap this module names, so the provisioner can alert on it: :class:`CatalogTierImpact` reads the
active bundle and lists, as fixed strings, what the new tier requires that it lacks:

* ``pack:<name>``: a required pack the bundle does not extend;
* ``rule:<key>``: a required pack rule the bundle opted out of.

Names are the platform's catalog identifiers: no tenant content, no justification text.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Protocol

from guardrail_engine.directory.model import TenantRecord
from guardrail_engine.policy.catalog import Catalog
from guardrail_engine.policy.document import EXTENDS_REF_PATTERN, ParsedBundle

ActiveBundleLoader = Callable[[str], Awaitable[ParsedBundle | None]]
"""The tenant's active bundle, or None if it has none (platform access, like the retention
resolver's loader)."""


class TierImpact(Protocol):
    async def gaps(self, record: TenantRecord) -> tuple[str, ...]:
        """What ``record``'s tier and contract require that the tenant's active version lacks
        (``pack:<name>`` and ``rule:<key>``), sorted. Empty when the version meets them, or the
        tenant has no active version yet (its first publish is checked as any publish)."""
        ...

    async def candidate_gaps(self, record: TenantRecord) -> tuple[str, ...]:
        """The same for the tenant's **candidate**: a candidate that falls short can't
        be promoted under the new tier. Empty when there is none."""
        ...


class CatalogTierImpact:
    def __init__(
        self,
        catalog: Catalog,
        load_active_bundle: ActiveBundleLoader,
        load_candidate_bundle: ActiveBundleLoader | None = None,
    ) -> None:
        self._catalog = catalog
        self._load = load_active_bundle
        self._load_candidate = load_candidate_bundle

    async def gaps(self, record: TenantRecord) -> tuple[str, ...]:
        return self._gaps_of(await self._load(record.tenant_id), record)

    async def candidate_gaps(self, record: TenantRecord) -> tuple[str, ...]:
        if self._load_candidate is None:
            return ()
        return self._gaps_of(await self._load_candidate(record.tenant_id), record)

    def _gaps_of(self, parsed: ParsedBundle | None, record: TenantRecord) -> tuple[str, ...]:
        if parsed is None:
            return ()
        extended: set[str] = set()
        for ref in parsed.bundle.extends:
            m = EXTENDS_REF_PATTERN.fullmatch(ref)
            if m is not None and m.group(2):  # a pack (the floor has no pack name)
                extended.add(m.group(2))
        required = self._catalog.packs_required_for_tier(record.tier) | record.required_packs
        found = [f"pack:{name}" for name in required - extended]
        opted_out = {o.rule for o in parsed.bundle.overrides if o.enabled is False}
        needed = self._catalog.rules_required_for_tier(record.tier)
        found += [f"rule:{key}" for key in needed & opted_out]
        return tuple(sorted(found))


@dataclass(frozen=True, slots=True)
class TierChange:
    """What :meth:`~guardrail_engine.directory.provisioning.TenantProvisioner.set_tier` did."""

    record: TenantRecord
    """The tenant after the change."""
    previous_tier: str
    gaps: tuple[str, ...] = ()
    """What the active version lacks under the new tier that it did not lack under the old one
    (an alert was raised for it). Takes effect at the next publish: the version keeps running."""
    candidate_gaps: tuple[str, ...] = ()
    """The same for the candidate: a candidate that lacks them can't be promoted, and
    needs a new publish."""
    project_assigned: str | None = None
    """The dedicated project the change assigned (M5-06), None if it assigned none."""
