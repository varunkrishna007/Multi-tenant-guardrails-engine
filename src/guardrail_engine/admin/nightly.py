"""The nightly red-team's results for operators (M5-05): ``GET /v1/platform/redteam/nightly``
(the latest result of every tenant, newest run, in tenant id order, with optional ``status``
and ``project`` filters; ``project=default`` is the shared pool) and
``GET /v1/platform/redteam/nightly/{tenant_id}`` (one tenant's last week), and the **quarantine**:
``GET /v1/platform/redteam/quarantine`` (the configurations a provider refusal put in quarantine,
which the nightly job never sends again) and ``POST /v1/platform/redteam/quarantine/clear`` (a
platform operator takes one out, with a reason; the step is recorded with the operator's actor,
and fails closed if it can't be).

**Platform operators only**: the result names floor rules, their recall and the regressions found,
which a tenant never sees (the floor's thresholds and probabilities are never exposed to a
tenant). It holds counts and rule keys, never a corpus row or a payload.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any

from guardrail_engine.admin.service import DraftServiceError
from guardrail_engine.authz.authorizer import AuthzDecision
from guardrail_engine.authz.model import Principal
from guardrail_engine.nightly.model import (
    CORPUS_HOLD_KEY,
    ROW_KEY_PREFIX,
    STATUSES,
    NightlyResult,
    QuarantineEvent,
)
from guardrail_engine.nightly.store import (
    InMemoryQuarantine,
    NightlyResultReader,
    QuarantineStore,
)
from guardrail_engine.tenant_ids import is_valid_tenant_id

PROJECT_LABEL = re.compile(r"[a-z0-9][a-z0-9-]{0,39}")
DEFAULT_LIMIT = 100
MAX_LIMIT = 500


class NightlyQueryError(DraftServiceError):
    """A parameter is not acceptable (HTTP 400); ``field`` names it."""

    def __init__(self, field: str, message: str) -> None:
        super().__init__(f"{field}: {message}")
        self.field = field
        self.message = message


class NightlyNotFoundError(DraftServiceError):
    """No result for that tenant (HTTP 404)."""


class NotQuarantinedError(DraftServiceError):
    """That configuration is not in quarantine (HTTP 404)."""


class QuarantineUnavailableError(DraftServiceError):
    """The step could not be recorded, so it did not happen (HTTP 503)."""


def present(r: NightlyResult) -> dict[str, Any]:
    return {
        "tenant_id": r.tenant_id,
        "bundle_version": r.bundle_version,
        "run_id": r.run_id,
        "project": r.project or "default",
        "run_at": r.run_at.isoformat(),
        "mode": r.mode,
        "status": r.status,
        "config": r.config_key,
        "floor_version": r.floor_version,
        "packs": list(r.packs),
        "corpus_sha256": r.corpus_sha256,
        "draws": r.draws,
        "rows": r.rows,
        "regressions": list(r.regressions),
        "block_recall": r.block_recall,
        "structure_violations": r.structure_violations,
        "provider_calls": r.provider_calls,
        "input_tokens": r.input_tokens,
        "note": r.note,
    }


def present_quarantine(e: QuarantineEvent) -> dict[str, Any]:
    return {
        "config": e.config_key,
        "mode": e.mode,
        "project": e.project or "default",
        "since": e.at.isoformat(),
        "run_id": e.run_id,
        "reason": e.reason,
        "row": e.row_id,
        "kind": (
            "corpus"
            if e.config_key == CORPUS_HOLD_KEY
            else "row"
            if e.config_key.startswith(ROW_KEY_PREFIX)
            else "configuration"
        ),
    }


class NightlyResultsService:
    def __init__(
        self,
        reader: NightlyResultReader,
        quarantine: QuarantineStore | None = None,
        clock: Any = lambda: datetime.now(UTC),
    ) -> None:
        self._reader = reader
        self._quarantine = quarantine if quarantine is not None else InMemoryQuarantine()
        self._clock = clock

    async def quarantined(self, decision: AuthzDecision) -> dict[str, Any]:
        held = [
            *(await self._quarantine.quarantined("live")).values(),
            *(await self._quarantine.quarantined("fake")).values(),
        ]
        return {"items": [present_quarantine(e) for e in sorted(held, key=_by_key)]}

    async def clear(
        self,
        decision: AuthzDecision,
        principal: Principal,
        config: str,
        mode: str,
        reason: str,
    ) -> dict[str, Any]:
        """Take a configuration out of quarantine. Only an operator reaches this (the route is
        platform-only); the step carries their actor and reason, and is refused if it can't be
        recorded."""
        if not 1 <= len(config) <= 1024 or not config.isprintable():
            raise NightlyQueryError("config", "a configuration key")
        if mode not in ("live", "fake"):
            raise NightlyQueryError("mode", "live or fake")
        held = (await self._quarantine.quarantined(mode)).get(config)
        if held is None:
            raise NotQuarantinedError("that configuration is not in quarantine")
        try:
            await self._quarantine.append(
                QuarantineEvent(
                    config_key=config,
                    mode=mode,
                    project=held.project,
                    action="clear",
                    at=self._clock(),
                    actor=principal.actor,
                    operator=principal.platform_operator,
                    reason=reason,
                    row_id=held.row_id,
                )
            )
        except Exception as exc:
            raise QuarantineUnavailableError("the clear could not be recorded") from exc
        return {"config": config, "mode": mode, "cleared": True}

    async def latest(self, decision: AuthzDecision, params: dict[str, str]) -> dict[str, Any]:
        unknown = set(params) - {"status", "after", "limit", "project"}
        if unknown:
            raise NightlyQueryError(sorted(unknown)[0], "not a parameter of this route")
        status = params.get("status")
        if status is not None and status not in STATUSES:
            raise NightlyQueryError("status", f"one of {', '.join(STATUSES)}")
        project = params.get("project")
        if project is not None and project != "default" and not PROJECT_LABEL.fullmatch(project):
            raise NightlyQueryError("project", "default, or a dedicated project's label")
        after = params.get("after")
        if after is not None and not is_valid_tenant_id(after):
            raise NightlyQueryError("after", "a tenant id")
        limit = DEFAULT_LIMIT
        if "limit" in params:
            text = params["limit"]
            if not text.isascii() or not text.isdigit() or not 1 <= int(text) <= MAX_LIMIT:
                raise NightlyQueryError("limit", f"a whole number from 1 to {MAX_LIMIT}")
            limit = int(text)
        rows = await self._reader.latest_per_tenant(
            status=status,
            after=after,
            limit=limit + 1,
            project=None if project is None else ("" if project == "default" else project),
        )
        page = rows[:limit]
        return {
            "items": [present(r) for r in page],
            "next_after": page[-1].tenant_id if len(rows) > limit else None,
        }

    async def for_tenant(self, decision: AuthzDecision, tenant_id: str) -> dict[str, Any]:
        if not is_valid_tenant_id(tenant_id):
            raise NightlyQueryError("tenant_id", "a tenant id")
        found = await self._reader.latest_for_tenant(tenant_id)
        if not found:
            raise NightlyNotFoundError("no nightly result for that tenant")
        return {"tenant_id": tenant_id, "items": [present(r) for r in found]}


def _by_key(e: QuarantineEvent) -> tuple[str, str]:
    return (e.config_key, e.mode)
