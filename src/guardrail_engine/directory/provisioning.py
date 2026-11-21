"""The platform-operator write path of the tenant directory (B3, M2-01).

Ids are generated here (:func:`~guardrail_engine.tenant_ids.new_tenant_id`), slugs are assigned
by the operator as a reviewed step: neither can be set by a tenant. Slug, domain, tier and flags
are validated by the same code the Guard Service re-checks when it builds a profile. Every write
records an audit event in the store's transaction and, once it commits, publishes
``TenantChanged``. If publishing fails the write stands and caches fall back to their TTL (30 s).

**The tier (M5-01).** Only a platform operator sets it, here (:meth:`TenantProvisioner.set_tier`,
and :meth:`~TenantProvisioner.update` / :meth:`~TenantProvisioner.create` with a ``tier``), and
every change is a class A directory event with the actor, the before and the after. A change to a
regulated tier assigns the tenant a dedicated Gemini project (M5-06) and refuses, where the
environment doesn't allow the shared fallback, when none is free. A raise whose new
requirements the tenant's active version doesn't meet raises an alert; the version keeps running.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Awaitable, Callable, Iterable

from guardrail_engine.authz.model import Principal
from guardrail_engine.deterministic.identifiers import (
    IdentifierPatternError,
    validate_tenant_identifier_patterns,
)
from guardrail_engine.deterministic.regex import RegexEngine
from guardrail_engine.directory.cached import READ_CACHE_S
from guardrail_engine.directory.model import (
    STATUSES,
    TERMINATION_STATUSES,
    TIERS,
    DirectoryAuditEvent,
    EventBus,
    InvalidTenantRecord,
    TenantChanged,
    TenantDirectoryStore,
    TenantExists,
    TenantNotFound,
    TenantRecord,
    TenantTerminated,
    VersionConflict,
    audit_fields,
    tier_is_regulated,
)
from guardrail_engine.directory.tier import TierChange, TierImpact
from guardrail_engine.gateway.sinks import (
    ALERT_DEDICATED_POOL_EMPTY,
    ALERT_TIER_RAISE_UNMET,
    Alert,
    AlertSeverity,
    AlertSink,
)
from guardrail_engine.projects import NoDedicatedProject, ProjectAssignments
from guardrail_engine.tenant_ids import new_tenant_id

logger = logging.getLogger(__name__)

MAX_ID_ATTEMPTS = 5
DRAIN_S = READ_CACHE_S + 5.0
"""How long :meth:`TenantProvisioner.terminate` waits between ``terminating`` and
``terminated``: past the Guard Service's directory read cache (30 s), so that every replica has
stopped serving the tenant before the offboarding job may delete anything (M5-07)."""
MAX_REASON_CHARS = 500
UPDATABLE = frozenset(
    {"slug", "domain", "tier", "flags", "required_packs", "baa", "identifier_patterns"}
)
"""What :meth:`TenantProvisioner.update` may change. ``project`` is not here: a tenant's Gemini
project is assigned by the provisioner (a regulated tier, or
:meth:`~TenantProvisioner.assign_project`), never named in an update."""


class NotAPlatformOperator(PermissionError):
    """The caller is not a platform operator. The Admin API's authorizer refuses first; this is
    the second line."""


class ProjectInUse(ValueError):
    """The tenant is still regulated, so it keeps its dedicated project."""


class TenantProvisioner:
    def __init__(
        self,
        store: TenantDirectoryStore,
        bus: EventBus,
        *,
        clock: Callable[[], float] = time.time,
        id_factory: Callable[[], str] = new_tenant_id,
        regex: RegexEngine | None = None,
        drain_s: float = DRAIN_S,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
        projects: ProjectAssignments | None = None,
        impact: TierImpact | None = None,
        alerts: AlertSink | None = None,
    ) -> None:
        """``projects`` (M5-06): the dedicated Gemini projects a regulated tenant is assigned
        from, and the environment's rule for having none free. Without it the provisioner
        assigns no project and refuses nothing (a library or a test with no key pools).
        ``impact`` and ``alerts`` (M5-01): what a tier raise leaves the active version lacking,
        and where the alert for it goes."""
        self._projects = projects
        self._impact = impact
        self._alerts = alerts
        self._drain_s = drain_s
        self._sleep = sleep
        self._regex = regex
        self._store = store
        self._bus = bus
        self._clock = clock
        self._id_factory = id_factory

    @staticmethod
    def _operator(actor: Principal) -> str:
        if not isinstance(actor, Principal) or not actor.platform_operator:
            raise NotAPlatformOperator("only a platform operator may change the directory")
        return actor.actor

    async def create(
        self,
        actor: Principal,
        *,
        slug: str,
        domain: str,
        tier: str = "standard",
        flags: Iterable[str] = (),
        required_packs: Iterable[str] = (),
        baa: bool = False,
        identifier_patterns: Iterable[str] = (),
        project: str | None = None,
    ) -> TenantRecord:
        """A new tenant with a generated id. Raises ``InvalidTenantRecord`` for a bad slug,
        domain, tier, flag or identifier pattern, and :class:`TenantExists` if the slug is
        taken.

        A regulated ``tier`` gets a dedicated Gemini project by default (M5-06): ``project``,
        or the first free one. With none free, ``NoDedicatedProject`` in ``production`` and
        ``staging``, the shared pool with a warning in ``test``; nothing is written."""
        subject = self._operator(actor)
        patterns = self._checked_patterns(identifier_patterns)
        last: TenantExists | None = None
        for _ in range(MAX_ID_ATTEMPTS):
            tenant_id = self._id_factory()
            chosen = await self._project_for(
                tenant_id, tier in TIERS and tier != "standard", project, None
            )
            record = TenantRecord(
                tenant_id=tenant_id, slug=slug, domain=domain, tier=tier,
                flags=frozenset(flags), required_packs=frozenset(required_packs), baa=baa,
                identifier_patterns=patterns, project=chosen,
            )  # fmt: skip
            event = self._event(record, "create", subject, None)
            try:
                stored = await self._store.insert(record, event)
            except TenantExists as e:
                if await self._slug_taken(slug):
                    raise
                last = e  # the generated id collided: draw another
                continue
            await self._publish(stored, "create")
            return stored
        raise last or TenantExists

    async def _slug_taken(self, slug: str) -> bool:
        return any(r.slug == slug for r in await self._store.list())

    async def update(
        self, actor: Principal, tenant_id: str, expected_version: int, **changes: object
    ) -> TenantRecord:
        """Change slug, domain, tier, flags, required_packs, baa or identifier_patterns.
        ``expected_version`` is the version the operator read (:class:`VersionConflict` if it
        moved). ``identifier_patterns`` replaces the tenant's whole list. A ``tier`` change
        goes through the same checks as :meth:`set_tier` (dedicated project, impact alert); use
        ``set_tier`` to give a reason and to see the gaps."""
        subject = self._operator(actor)
        if not changes or set(changes) - UPDATABLE:
            raise ValueError(f"changes must be a non-empty subset of {sorted(UPDATABLE)}")
        for name in ("flags", "required_packs"):
            if name in changes:
                changes[name] = frozenset(changes[name])  # type: ignore[call-overload]
        if "identifier_patterns" in changes:
            changes["identifier_patterns"] = self._checked_patterns(
                changes["identifier_patterns"]  # type: ignore[arg-type]
            )
        return await self._replace(subject, tenant_id, expected_version, "update", changes)

    async def set_tier(
        self,
        actor: Principal,
        tenant_id: str,
        expected_version: int,
        tier: str,
        reason: str,
        *,
        impact: TierImpact | None = None,
    ) -> TierChange:
        """Set the tenant's tier (M5-01): ``standard``, ``regulated`` or ``dedicated``. **Only a
        platform operator** (:class:`NotAPlatformOperator` for anyone else, a tenant's
        ``guardrail_admin`` included); the tenant has no other way to change it.

        Audited as a class A directory event, action ``set_tier``: the actor, the ``reason``
        (1 to 500 printable characters), the record before and after. Published as
        ``tenant.changed``, so the Guard Service sees it within seconds.

        **What it changes, and when.** The approval gate (R2) and the retention floors (R3) read
        the attribute at once. The packs and rules the tier requires are checked at the tenant's
        **next publish**; the active version keeps running as it is. A change **to** a regulated
        tier also assigns the tenant a dedicated Gemini project (M5-06). When the version now
        running lacks something the new tier requires, an alert is raised (``tier_raise_unmet``)
        and the gaps are in the result.

        Raises ``ValueError`` for an unknown tier or a bad reason, :class:`TenantNotFound`,
        :class:`VersionConflict`, :class:`~guardrail_engine.projects.NoDedicatedProject` (the
        change is refused and nothing is written) and :class:`TenantTerminated`. Setting the tier
        it already has changes nothing and writes nothing."""
        subject = self._operator(actor)
        if tier not in TIERS:
            raise ValueError(f"tier must be one of {TIERS}")
        reason = _checked_reason(reason)
        return await self._change(
            subject, tenant_id, expected_version, "set_tier", {"tier": tier}, reason, impact
        )

    async def assign_project(
        self,
        actor: Principal,
        tenant_id: str,
        expected_version: int,
        project: str | None = None,
    ) -> TenantRecord:
        """Give an existing tenant a dedicated Gemini project (M5-06): ``project``, or the first
        free one (how a regulated tenant that predates the pools is brought in). Audited as an
        ``update``. Takes effect for new checks within the directory's 30 s read cache.
        Raises ``InvalidTenantRecord`` for a project that isn't configured or is held by
        another tenant, :class:`~guardrail_engine.projects.NoDedicatedProject` when none is free
        (outside ``test``), and ``ValueError`` when the provisioner has no pools."""
        subject = self._operator(actor)
        if self._projects is None:
            raise ValueError("this provisioner has no dedicated projects configured")
        current = await self._store.get(tenant_id)
        if current is None:
            raise TenantNotFound
        chosen = await self._project_for(tenant_id, True, project, current)
        if chosen is None or chosen == current.project:
            return current  # the shared fallback (test), or already there: nothing to write
        return await self._replace(
            subject, tenant_id, expected_version, "update", {"project": chosen}
        )

    async def release_project(self, actor: Principal, tenant_id: str) -> TenantRecord:
        """Give a tenant's dedicated Gemini project back to the pool. **Only a platform
        operator.** Lowering a tier keeps the project (billing continuity) until this is called;
        a tenant that is still regulated can't release it (:class:`ProjectInUse`). Audited as a
        class A ``update`` event (the project is in ``before`` and gone from ``after``, with the
        reason ``release_project``). The tenant's checks go back to the shared pool within the
        directory's 30 s read cache. A tenant with no project is returned as it is, and
        nothing is written. Raises :class:`TenantNotFound` and :class:`TenantTerminated`."""
        subject = self._operator(actor)
        current = await self._store.get(tenant_id)
        if current is None:
            raise TenantNotFound
        if current.status in TERMINATION_STATUSES:
            raise TenantTerminated  # a terminating tenant has given its project up already
        if tier_is_regulated(current):
            raise ProjectInUse(
                "a regulated tenant keeps its dedicated project: lower the tier first"
            )
        if current.project is None:
            return current
        return await self._replace(
            subject, tenant_id, current.version, "update", {"project": None},
            reason=f"release_project {current.project}",
        )  # fmt: skip

    async def _project_for(
        self,
        tenant_id: str,
        regulated: bool,
        explicit: str | None,
        current: TenantRecord | None,
    ) -> str | None:
        """The project a tenant should be written with: its own if it has one, else the
        operator's explicit choice (which must be a configured project nobody holds), else for
        a regulated tenant the first free dedicated project (M5-06)."""
        if self._projects is None:
            return explicit if current is None else (explicit or current.project)
        taken = await self._taken_projects(except_tenant=tenant_id)
        if explicit is not None:
            if not self._projects.knows(explicit):
                raise InvalidTenantRecord("project is not a configured dedicated project")
            if explicit in taken:
                raise InvalidTenantRecord("project is already assigned to another tenant")
            return explicit
        if current is not None and current.project is not None:
            return current.project
        if not regulated:
            return None
        try:
            chosen = self._projects.choose(taken, tenant_id=tenant_id)
        except NoDedicatedProject:
            await self._alert_pool_empty(tenant_id, refused=True)
            raise
        if chosen is None:
            await self._alert_pool_empty(tenant_id, refused=False)
        return chosen

    async def _alert_pool_empty(self, tenant_id: str, *, refused: bool) -> None:
        """No free dedicated project for a regulated tenant: a platform alert, besides
        the refusal or the shared fallback. Never raises."""
        outcome = "was refused" if refused else "uses the shared pool"
        logger.warning("no free dedicated Gemini project for regulated tenant %s", tenant_id)
        if self._alerts is None:
            return
        alert = Alert(
            severity=AlertSeverity.WARNING,
            kind=ALERT_DEDICATED_POOL_EMPTY,
            message=(
                f"no dedicated Gemini project is free for regulated tenant {tenant_id}: "
                f"it {outcome}. Release a lowered tenant's project or add one under the "
                "'projects' setting"
            ),
            key_id="",
            tenant_id="",
            guard_point="",
            reason="pool_empty",
            dedupe_key=f"{ALERT_DEDICATED_POOL_EMPTY}:{tenant_id}",
        )
        try:
            await asyncio.to_thread(self._alerts.emit, alert)
        except Exception:
            logger.exception("the dedicated-pool alert for tenant %s was not delivered", tenant_id)

    async def _taken_projects(self, *, except_tenant: str) -> set[str]:
        return {
            r.project
            for r in await self._store.list()
            if r.project is not None
            and r.tenant_id != except_tenant
            and r.status not in TERMINATION_STATUSES
        }

    async def set_identifier_patterns(
        self, actor: Principal, tenant_id: str, expected_version: int, patterns: Iterable[str]
    ) -> TenantRecord:
        """Replace the tenant's registered cross-tenant identifier patterns. A pattern one
        tenant registers is matched against every other tenant's content, so this is a
        platform-reviewed step: the operator reviews the pattern, and the code refuses one that
        :func:`~guardrail_engine.deterministic.validate_identifier_pattern` does not pass or a
        21st one. The scan picks the change up within seconds of the ``tenant.changed`` event."""
        return await self.update(
            actor, tenant_id, expected_version, identifier_patterns=tuple(patterns)
        )

    def _checked_patterns(self, patterns: Iterable[str]) -> tuple[str, ...]:
        if isinstance(patterns, str):
            raise InvalidTenantRecord("identifier_patterns must be a list of patterns")
        checked = tuple(patterns)
        try:
            validate_tenant_identifier_patterns(checked, self._regex)
        except IdentifierPatternError as e:
            raise InvalidTenantRecord(f"identifier pattern refused: {e.reason}") from e
        return checked

    async def set_status(
        self, actor: Principal, tenant_id: str, expected_version: int, status: str
    ) -> TenantRecord:
        """``suspended`` or ``offboarded`` make the Guard Service stop knowing the tenant (its
        checks are ``forbidden``); ``active`` reinstates it."""
        subject = self._operator(actor)
        if status not in STATUSES:
            raise ValueError(f"status must be one of {STATUSES}")
        if status in TERMINATION_STATUSES:
            raise ValueError("terminating a tenant is terminate(), not set_status()")
        return await self._replace(
            subject, tenant_id, expected_version, "set_status", {"status": status}
        )

    async def terminate(self, actor: Principal, tenant_id: str, reason: str) -> TenantRecord:
        """Terminate a tenant (M5-07, R3): ``terminating`` at once, then ``terminated`` after
        :data:`DRAIN_S`.

        ``terminating`` is audited (class A: the actor, the reason and the time, which starts
        the 30-day offboarding clock), published as ``tenant.changed`` and refuses the tenant's
        checks and admin calls from then on. After the drain, ``terminated`` is audited and
        published too, and is the only status in which the offboarding job may delete (the
        database checks it). **One way only**: a terminating or terminated tenant can't be
        reinstated, renamed or changed.

        Idempotent and resumable: calling it again on a ``terminating`` tenant (the process
        died, or two operators raced) finishes the job, and on a ``terminated`` one returns the
        record. ``reason`` is 1 to 500 printable characters. Raises :class:`TenantNotFound`."""
        subject = self._operator(actor)
        reason = _checked_reason(reason)
        for _ in range(3):
            current = await self._store.get(tenant_id)
            if current is None:
                raise TenantNotFound
            if current.status == "terminated":
                return current
            try:
                if current.status != "terminating":
                    current = await self._replace(
                        subject, tenant_id, current.version, "terminating",
                        {"status": "terminating"}, reason=reason,
                    )  # fmt: skip
                await self._sleep(self._drain_s)
                return await self._replace(
                    subject, tenant_id, current.version, "terminated",
                    {"status": "terminated"}, reason=reason,
                )  # fmt: skip
            except VersionConflict:
                continue  # another call moved it: look again (it may be done)
        raise VersionConflict

    async def _replace(
        self, subject: str, tenant_id: str, expected_version: int, action: str,
        changes: dict[str, object], reason: str | None = None,
    ) -> TenantRecord:  # fmt: skip
        return (
            await self._change(subject, tenant_id, expected_version, action, changes, reason)
        ).record

    async def _change(
        self, subject: str, tenant_id: str, expected_version: int, action: str,
        changes: dict[str, object], reason: str | None, impact: TierImpact | None = None,
    ) -> TierChange:  # fmt: skip
        current = await self._store.get(tenant_id)
        if current is None:
            raise TenantNotFound
        if current.status in TERMINATION_STATUSES and action not in ("terminating", "terminated"):
            raise TenantTerminated  # one way only: nothing else changes a terminated tenant
        tier = changes.get("tier", current.tier)
        if action == "set_tier" and tier == current.tier:
            return TierChange(current, current.tier)  # nothing to change, nothing to audit
        assigned: str | None = None
        if (
            "tier" in changes
            and tier != current.tier
            and tier in TIERS
            and tier != "standard"
            and "project" not in changes
        ):
            # A raise to a regulated tier brings a dedicated project (M5-06); where there is
            # none to give, the raise is refused before anything is written.
            assigned = await self._project_for(tenant_id, True, None, current)
            if assigned is not None and assigned != current.project:
                changes = {**changes, "project": assigned}
            else:
                assigned = None
        updated = current.with_changes(**changes)
        stored = await self._store.replace(
            updated, expected_version, self._event(updated, action, subject, current, reason)
        )
        await self._publish(stored, action)
        gaps, candidate_gaps = await self._alert_on_raise(current, stored, impact or self._impact)
        return TierChange(stored, current.tier, gaps, candidate_gaps, assigned)

    async def _alert_on_raise(
        self, before: TenantRecord, after: TenantRecord, impact: TierImpact | None
    ) -> tuple[tuple[str, ...], tuple[str, ...]]:
        """After a committed tier change, name what the active version and the candidate lack
        under the new tier and did not lack under the old one, and alert. Returns the active
        version's gaps and the candidate's. Never raises: the write stands."""
        if impact is None or before.tier == after.tier:
            return (), ()
        if not tier_is_regulated(after) and after.required_packs == before.required_packs:
            return (), ()  # a lowering or a standard-tier move adds no requirement
        try:
            gaps = tuple(sorted(set(await impact.gaps(after)) - set(await impact.gaps(before))))
            candidate_gaps = tuple(
                sorted(
                    set(await impact.candidate_gaps(after))
                    - set(await impact.candidate_gaps(before))
                )
            )
        except Exception:
            logger.exception("could not read the active version of tenant %s", after.tenant_id)
            return (), ()
        if (gaps or candidate_gaps) and self._alerts is not None:
            reason = ",".join(gaps)
            message = f"tenant {after.tenant_id} was raised to tier {after.tier}; "
            if gaps:
                message += (
                    "the active version does not meet what that tier requires and keeps "
                    "running. The next publish must: " + ", ".join(gaps)
                )
            if candidate_gaps:
                message += (
                    ("; " if gaps else "")
                    + "the candidate does not meet it and can't be promoted until it does: "
                    + ", ".join(candidate_gaps)
                )
                reason += ("; " if gaps else "") + "candidate:" + ",".join(candidate_gaps)
            alert = Alert(
                severity=AlertSeverity.WARNING,
                kind=ALERT_TIER_RAISE_UNMET,
                message=message,
                key_id="",
                tenant_id=after.tenant_id,
                guard_point="",
                reason=reason,
                dedupe_key=f"{ALERT_TIER_RAISE_UNMET}:{after.tenant_id}:{after.version}",
            )
            try:
                await asyncio.to_thread(self._alerts.emit, alert)
            except Exception:
                logger.exception(
                    "the tier-raise alert for tenant %s was not delivered", after.tenant_id
                )
        return gaps, candidate_gaps

    def _event(
        self, record: TenantRecord, action: str, actor: str, before: TenantRecord | None,
        reason: str | None = None,
    ) -> DirectoryAuditEvent:  # fmt: skip
        after = audit_fields(record)
        if reason is not None:
            after["reason"] = reason
        return DirectoryAuditEvent(
            tenant_id=record.tenant_id, version=record.version, action=action, actor=actor,
            at=self._clock(), before=audit_fields(before) if before else None, after=after,
        )  # fmt: skip

    async def _publish(self, record: TenantRecord, kind: str) -> None:
        try:
            await self._bus.publish(TenantChanged(record.tenant_id, record.version, kind))
        except Exception:
            return  # the write stands; caches fall back to their TTL


def _checked_reason(reason: object) -> str:
    if (
        not isinstance(reason, str)
        or not reason.strip()
        or len(reason) > MAX_REASON_CHARS
        or not reason.isprintable()
    ):
        raise ValueError(f"reason must be 1 to {MAX_REASON_CHARS} printable characters")
    return reason
