"""Floor releases and the minimum floor (M2-09, R5): the platform side.

**Release (R5.1).** A floor version above the baseline can be extended by tenants only once it is
*released*: a platform operator proposes it with the M2-08 red-team report as evidence, and a
**second, different operator** approves. The proposer is the first approver. A tenant principal
has no access to any of this (the authorizer's platform-only rows), so a tenant can neither
approve nor block a release.

The evidence is the run's JSON report (``redteam.run run --json``). It is accepted only if it
says the gate passed, that no row was short or unusable and that no model-independent defence
broke, that it measured **this** floor (the report's floor content hash equals the catalog's
floor@v), that it ran on **today's corpus**, and that it is a **live** run (an offline run only
when the engine's environment is ``test``). What is stored is that summary, not the report.

**The approval names the report** (`report_sha256`, the canonical hash of the report as
proposed, returned by the proposal and stored in the evidence): a second operator approves that
report, not whatever the proposer later says it was. The report itself is
operator-supplied, so the engine can check what it says, not that the run happened.

**Security-urgent (R5.4).** Both approvers must mark a release urgent for its staging window to
be 6 hours instead of 72; either one not marking it means 72.

**Minimum (R5.5).** The minimum floor version is persisted here and applied to the shared
catalog (:meth:`InMemoryCatalog.raise_minimum`), which the compiler reads together with the
configured ``min_floor_version``. It only goes up. Raising it is :class:`RepinService`'s, because
it needs every tenant's active version.

**Halt.** A halted release refuses promotion of its re-pins until resumed.

Everything here is class A: each step writes a ``platform_audit`` event with the operator.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

from guardrail_engine.admin.lifecycle import GuardrailPublished, PublishBus
from guardrail_engine.admin.service import (
    DecisionError,
    DraftError,
    DraftInvalidError,
    DraftServiceError,
)
from guardrail_engine.authz.authorizer import AuthzDecision
from guardrail_engine.authz.model import Principal
from guardrail_engine.policy.canonical import sha256_of
from guardrail_engine.policy.catalog import InMemoryCatalog
from guardrail_engine.policy.json_document import parse_json_text

logger = logging.getLogger(__name__)

RELEASE = ("POST", "/v1/platform/floors/{version}/release")
APPROVE = ("POST", "/v1/platform/floors/{version}/approve")
HALT = ("POST", "/v1/platform/floors/{version}/halt")
RESUME = ("DELETE", "/v1/platform/floors/{version}/halt")
LIST_FLOORS = ("GET", "/v1/platform/floors")

STANDARD_WINDOW = timedelta(hours=72)
URGENT_WINDOW = timedelta(hours=6)
MAX_BODY_BYTES = 64_000
MAX_VERSION = 1_000_000
ACTIONS = (
    "release_proposed", "release_approved", "released", "halt", "resume", "repin", "promote",
    "raise_minimum",
)  # fmt: skip
_HASH = re.compile(r"sha256:[0-9a-f]{64}")


# --------------------------------------------------------------------------- model


@dataclass(frozen=True, slots=True)
class Approval:
    operator: str
    urgent: bool
    at: datetime


@dataclass(frozen=True, slots=True)
class FloorRelease:
    floor_version: int
    floor_hash: str
    evidence: dict[str, Any]
    proposed_by: str
    proposed_at: datetime
    approvals: tuple[Approval, ...] = ()
    released_at: datetime | None = None
    security_urgent: bool = False
    halted: bool = False

    @property
    def released(self) -> bool:
        return self.released_at is not None

    @property
    def window(self) -> timedelta:
        return URGENT_WINDOW if self.security_urgent else STANDARD_WINDOW


@dataclass(frozen=True, slots=True)
class PlatformEvent:
    at: datetime
    actor: str
    action: str
    floor_version: int | None = None
    tenant_id: str | None = None
    detail: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.action not in ACTIONS:
            raise ValueError(f"unknown platform action {self.action!r}")


class ReleaseExistsError(DraftServiceError):
    """(HTTP 409 ``release_exists``)"""


class ReleaseNotFoundError(DraftServiceError):
    """(HTTP 404 ``release_not_found``)"""


class AlreadyReleasedError(DraftServiceError):
    """(HTTP 409 ``already_released``)"""


class SecondOperatorRequiredError(DraftServiceError):
    """The approver is an operator who already approved (HTTP 409)."""


class FloorNotReleasedError(DraftServiceError):
    """(HTTP 409 ``floor_not_released``)"""


class PlatformConflictError(DraftServiceError):
    """The platform state changed under the write (HTTP 409)."""


# --------------------------------------------------------------------------- store


class PlatformStore(Protocol):
    async def release(self, version: int) -> FloorRelease | None: ...

    async def releases(self) -> list[FloorRelease]:
        """Every proposed release, by version, with its approvals."""
        ...

    async def propose(self, release: FloorRelease, event: PlatformEvent) -> None:
        """Insert (with the proposer's approval already in ``release.approvals``). Raises
        :class:`ReleaseExistsError`."""
        ...

    async def approve(
        self, version: int, approval: Approval, event: PlatformEvent, released: PlatformEvent
    ) -> FloorRelease:
        """Add the approval; if two different operators have now approved, mark the release
        released (urgent only if both said urgent) and append ``released`` as well. Atomic.
        Raises :class:`ReleaseNotFoundError`, :class:`AlreadyReleasedError` and
        :class:`SecondOperatorRequiredError`."""
        ...

    async def set_halted(self, version: int, halted: bool, event: PlatformEvent) -> None: ...

    async def minimum(self) -> int | None: ...

    async def set_minimum(
        self, value: int, *, expected: int | None, by: str, at: datetime, event: PlatformEvent
    ) -> None:
        """Raise the stored minimum from ``expected`` (None: no row yet). Raises
        :class:`PlatformConflictError` if it moved."""
        ...

    async def record(self, event: PlatformEvent) -> None: ...

    async def events(self) -> list[PlatformEvent]: ...


def settle(approvals: tuple[Approval, ...]) -> tuple[bool, bool]:
    """(released, security_urgent) for ``approvals``: released with two different operators;
    urgent only if **both** of the first two said so."""
    first = list({a.operator: a for a in approvals}.values())[:2]
    if len(first) < 2:
        return False, False
    return True, all(a.urgent for a in first)


class InMemoryPlatformStore:
    def __init__(self) -> None:
        self._releases: dict[int, FloorRelease] = {}
        self._minimum: int | None = None
        self._events: list[PlatformEvent] = []
        self.fail_audit = False

    def _append(self, *events: PlatformEvent) -> None:
        if self.fail_audit:
            raise RuntimeError("class A append failed")
        self._events.extend(events)

    async def release(self, version: int) -> FloorRelease | None:
        return self._releases.get(version)

    async def releases(self) -> list[FloorRelease]:
        return [self._releases[v] for v in sorted(self._releases)]

    async def propose(self, release: FloorRelease, event: PlatformEvent) -> None:
        if release.floor_version in self._releases:
            raise ReleaseExistsError()
        self._append(event)
        self._releases[release.floor_version] = release

    async def approve(
        self, version: int, approval: Approval, event: PlatformEvent, released: PlatformEvent
    ) -> FloorRelease:
        current = self._releases.get(version)
        if current is None:
            raise ReleaseNotFoundError()
        if current.released:
            raise AlreadyReleasedError()
        if any(a.operator == approval.operator for a in current.approvals):
            raise SecondOperatorRequiredError()
        approvals = (*current.approvals, approval)
        done, urgent = settle(approvals)
        updated = replace(
            current, approvals=approvals, released_at=approval.at if done else None,
            security_urgent=urgent,
        )  # fmt: skip
        self._append(event, *((released,) if done else ()))
        self._releases[version] = updated
        return updated

    async def set_halted(self, version: int, halted: bool, event: PlatformEvent) -> None:
        current = self._releases.get(version)
        if current is None:
            raise ReleaseNotFoundError()
        self._append(event)
        self._releases[version] = replace(current, halted=halted)

    async def minimum(self) -> int | None:
        return self._minimum

    async def set_minimum(
        self, value: int, *, expected: int | None, by: str, at: datetime, event: PlatformEvent
    ) -> None:
        if self._minimum != expected or (expected is not None and value <= expected):
            raise PlatformConflictError()
        self._append(event)
        self._minimum = value

    async def record(self, event: PlatformEvent) -> None:
        self._append(event)

    async def events(self) -> list[PlatformEvent]:
        return list(self._events)


# --------------------------------------------------------------------------- notifications


@dataclass(frozen=True, slots=True)
class Notice:
    """What a tenant's admins are told (R5.2, R5.3). Delivery is a port: email or webhook
    arrives with M4-05."""

    tenant_id: str
    kind: str
    subject: str
    detail: dict[str, Any]


class Notifier(Protocol):
    async def notify(self, notice: Notice) -> None: ...


class LoggingNotifier:
    async def notify(self, notice: Notice) -> None:
        logger.info("notice for %s: %s (%s)", notice.tenant_id, notice.kind, notice.subject)


class InMemoryNotifier:
    def __init__(self) -> None:
        self.notices: list[Notice] = []

    async def notify(self, notice: Notice) -> None:
        self.notices.append(notice)


# --------------------------------------------------------------------------- evidence


def evidence_from_report(
    report: Any,
    version: int,
    floor_hash: str,
    corpus_sha256: str | None,
    *,
    allow_offline: bool,
) -> dict[str, Any]:
    """The stored summary of an M2-08 report, or :class:`DraftInvalidError` naming what is wrong
    (codes ``release.evidence``)."""
    problems: list[str] = []
    if not isinstance(report, dict):
        raise DraftInvalidError([DraftError("release.evidence", "$.report", "an object")])
    gate = report.get("gate")
    if not isinstance(gate, dict) or gate.get("passed") is not True:
        problems.append("the run's gate did not pass (or the report has no gate)")
    mode = report.get("mode")
    if mode != "live" and not (mode == "fake" and allow_offline):
        problems.append("the run is not a live run")
    if report.get("floor_version") != version:
        problems.append(
            f"the run measured floor@{report.get('floor_version')}, not floor@{version}"
        )
    if report.get("floor_content_hash") != floor_hash:
        problems.append("the run measured a floor whose content differs from the catalog's")
    if corpus_sha256 is None:
        problems.append("the current corpus is unavailable, so the run can't be matched to it")
    elif report.get("corpus_sha256") != corpus_sha256:
        problems.append("the run used a different corpus than the current one")
    if report.get("incomplete") or report.get("excluded_cells"):
        problems.append("the run was incomplete or had unusable cells")
    structure = report.get("structure")
    if not isinstance(structure, dict) or structure.get("violations"):
        problems.append("a model-independent defence broke in the run")
    if problems:
        raise DraftInvalidError([DraftError("release.evidence", "$.report", p) for p in problems])
    return {
        "report_sha256": sha256_of(report),
        "mode": mode, "floor_version": version, "floor_content_hash": floor_hash,
        "corpus_sha256": report["corpus_sha256"], "rows": report.get("rows"),
        "draws": report.get("draws"), "nonce_seed": report.get("nonce_seed"),
        "gate": {"exit_code": gate["exit_code"], "passed": True},
    }  # fmt: skip


def parse_propose(body: bytes) -> tuple[Any, bool]:
    doc = _object(body, {"report", "security_urgent"})
    urgent = doc.get("security_urgent", False)
    if "report" not in doc or not isinstance(urgent, bool):
        raise DraftInvalidError(
            [DraftError("release.body", "$", "{report: <the M2-08 JSON report>, security_urgent?}")]
        )
    return doc["report"], urgent


def parse_approve(body: bytes) -> tuple[bool, str]:
    """``{report_sha256, security_urgent?}``: the approval names the report it is for."""
    doc = _object(body, {"report_sha256", "security_urgent"})
    urgent = doc.get("security_urgent", False)
    if not isinstance(urgent, bool):
        raise DraftInvalidError([DraftError("release.body", "$.security_urgent", "true or false")])
    digest = doc.get("report_sha256")
    if not isinstance(digest, str) or not _HASH.fullmatch(digest):
        raise DraftInvalidError(
            [DraftError("release.report_sha256", "$.report_sha256", "the report's sha256 hash")]
        )
    return urgent, digest


def _object(body: bytes, allowed: set[str]) -> dict[str, Any]:
    if len(body) > MAX_BODY_BYTES:
        raise DraftInvalidError([DraftError("release.too_large", "$", "the body is too large")])
    doc, problems = parse_json_text(body)
    if problems or not isinstance(doc, dict):
        raise DraftInvalidError([DraftError("release.body", "$", "a JSON object")])
    extra = sorted(set(doc) - allowed)
    if extra:
        raise DraftInvalidError(
            [DraftError("release.unknown_field", f"$.{k}", "not a field") for k in extra]
        )
    return doc


# --------------------------------------------------------------------------- the service


def platform_decision(decision: AuthzDecision, endpoint: tuple[str, str]) -> None:
    """The decision must be an allowed one made for ``endpoint`` (a programming error else)."""
    if (
        not decision.allowed
        or decision.endpoint is None
        or (decision.endpoint.method, decision.endpoint.route) != endpoint
    ):
        raise DecisionError("the decision does not allow this platform action")


class FloorService:
    def __init__(
        self,
        platform: PlatformStore,
        catalog: InMemoryCatalog,
        *,
        corpus_sha256: Callable[[], str | None] = lambda: None,
        allow_offline: bool = False,
        bus: PublishBus | None = None,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._platform = platform
        self._catalog = catalog
        self._corpus_sha256 = corpus_sha256
        self._allow_offline = allow_offline
        self._bus = bus
        self._clock = clock

    # ------------------------------------------------------------------ state

    async def load(self) -> None:
        """Apply the stored state to the catalog (at start-up, and when another replica
        changed it): the baseline floor plus every released one are extendable, and the minimum
        is the stored one."""
        releases = await self._platform.releases()
        baseline = min(self._catalog.floor_versions(), default=None)
        released = {r.floor_version for r in releases if r.released}
        if baseline is not None:
            released.add(baseline)
        self._catalog.set_released(released)
        stored = await self._platform.minimum()
        if stored is not None:
            self._catalog.raise_minimum(stored)

    async def _announce(self, action: str) -> None:
        if self._bus is None:
            return
        try:
            await self._bus.publish(GuardrailPublished("t_platform", 0, action))
        except Exception:
            logger.exception("the floor change could not be announced; replicas reload by TTL")

    def _event(
        self, principal: Principal, action: str, version: int | None, **detail: Any
    ) -> PlatformEvent:
        return PlatformEvent(self._clock(), principal.actor, action, version, None, dict(detail))

    # ------------------------------------------------------------------ reads

    async def listing(self, decision: AuthzDecision) -> dict[str, Any]:
        platform_decision(decision, LIST_FLOORS)
        return {
            "minimum_floor_version": max(
                self._catalog.minimum_floor_version(), await self._platform.minimum() or 1
            ),
            "baseline": min(self._catalog.floor_versions(), default=None),
            "floors": [release_json(r) for r in await self._platform.releases()],
            "unreleased_in_catalog": [
                v for v in self._catalog.floor_versions() if not self._catalog.is_released(v)
            ],
        }

    # ------------------------------------------------------------------ writes

    async def propose(
        self, decision: AuthzDecision, principal: Principal, version: int, body: bytes
    ) -> FloorRelease:
        platform_decision(decision, RELEASE)
        report, urgent = parse_propose(body)
        floor = self._catalog.floor(version)
        if floor is None:
            raise ReleaseNotFoundError()  # not in the catalog: nothing to release
        floor_hash = floor.content_hash()
        evidence = evidence_from_report(
            report, version, floor_hash, self._corpus_sha256(), allow_offline=self._allow_offline
        )
        now = self._clock()
        release = FloorRelease(
            version, floor_hash, evidence, principal.actor, now,
            approvals=(Approval(principal.actor, urgent, now),),
        )  # fmt: skip
        await self._platform.propose(
            release,
            self._event(principal, "release_proposed", version, urgent=urgent, evidence=evidence),
        )
        return release

    async def approve(
        self, decision: AuthzDecision, principal: Principal, version: int, body: bytes
    ) -> FloorRelease:
        platform_decision(decision, APPROVE)
        urgent, digest = parse_approve(body)
        release = await self._platform.release(version)
        if release is None:
            raise ReleaseNotFoundError()
        if release.evidence.get("report_sha256") != digest:
            raise DraftInvalidError(
                [
                    DraftError(
                        "release.report_mismatch",
                        "$.report_sha256",
                        "this approval names a different report than the one proposed",
                    )
                ]
            )
        now = self._clock()
        updated = await self._platform.approve(
            version,
            Approval(principal.actor, urgent, now),
            self._event(principal, "release_approved", version, urgent=urgent),
            self._event(principal, "released", version),
        )
        if updated.released:
            await self.load()
            await self._announce("floor")
        return updated

    async def halt(
        self, decision: AuthzDecision, principal: Principal, version: int, *, halted: bool
    ) -> None:
        platform_decision(decision, HALT if halted else RESUME)
        await self._platform.set_halted(
            version, halted, self._event(principal, "halt" if halted else "resume", version)
        )


def release_json(r: FloorRelease) -> dict[str, Any]:
    return {
        "floor_version": r.floor_version,
        "floor_hash": r.floor_hash,
        "released": r.released,
        "released_at": None if r.released_at is None else r.released_at.isoformat(),
        "security_urgent": r.security_urgent,
        "staging_window_hours": r.window.total_seconds() / 3600,
        "halted": r.halted,
        "proposed_by": r.proposed_by,
        "proposed_at": r.proposed_at.isoformat(),
        "approvals": [
            {"operator": a.operator, "urgent": a.urgent, "at": a.at.isoformat()}
            for a in r.approvals
        ],
        "evidence": r.evidence,
    }


__all__ = [
    "APPROVE", "HALT", "LIST_FLOORS", "RELEASE", "RESUME", "STANDARD_WINDOW", "URGENT_WINDOW",
    "AlreadyReleasedError", "Approval", "FloorNotReleasedError", "FloorRelease", "FloorService",
    "InMemoryNotifier", "InMemoryPlatformStore", "LoggingNotifier", "Notice", "Notifier",
    "PlatformConflictError", "PlatformEvent", "PlatformStore", "ReleaseExistsError",
    "ReleaseNotFoundError", "SecondOperatorRequiredError", "evidence_from_report",
    "platform_decision", "release_json", "settle",
]  # fmt: skip
