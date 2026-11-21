"""The nightly red-team's results and the active versions on Postgres (M5-05, 051 to 053).

Both take the **operator** pool: the job works across every tenant, and the platform route lists
the latest result of every tenant. Without an operator pool nothing here works (it raises), like
the catalog's reference counts. The role is the platform operator's database role (007, 014, 053:
its own ``operator_all`` policy; 052: SELECT and INSERT on the results, never UPDATE or DELETE).
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from datetime import datetime
from typing import Any

from guardrail_engine.nightly.model import NightlyResult, QuarantineEvent
from guardrail_engine.nightly.store import ActiveBundle, ConfigDates, bundle_of
from guardrail_engine.store.port import OperatorPoolUnavailableError

_COLUMNS = (
    "tenant_id, bundle_version, project, nonce_seed, config_key, run_id, run_at, mode, "
    "floor_version, packs, "
    "corpus_sha256, draws, rows, status, regressions, block_recall, false_act, "
    "structure_violations, provider_calls, input_tokens, note"
)


def _result(row: Any) -> NightlyResult:
    return NightlyResult(
        tenant_id=row["tenant_id"],
        bundle_version=row["bundle_version"],
        project=row["project"],
        nonce_seed=row["nonce_seed"],
        config_key=row["config_key"],
        run_id=row["run_id"],
        run_at=row["run_at"],
        mode=row["mode"],
        floor_version=row["floor_version"],
        packs=tuple(row["packs"]),
        corpus_sha256=row["corpus_sha256"],
        draws=row["draws"],
        rows=row["rows"],
        status=row["status"],
        regressions=tuple(json.loads(row["regressions"])),
        block_recall=json.loads(row["block_recall"]),
        false_act=json.loads(row["false_act"]),
        structure_violations=row["structure_violations"],
        provider_calls=row["provider_calls"],
        input_tokens=row["input_tokens"],
        note=row["note"],
    )


class PostgresNightlyResults:
    def __init__(self, operator_pool: Any | None) -> None:
        self._pool = operator_pool

    def _need(self) -> Any:
        if self._pool is None:
            raise OperatorPoolUnavailableError()
        return self._pool

    async def append_many(self, results: Sequence[NightlyResult]) -> None:
        pool = self._need()
        async with pool.acquire() as conn, conn.transaction():
            for r in results:
                await conn.execute(
                    "INSERT INTO nightly_redteam_results (tenant_id, bundle_version, project, "
                    "nonce_seed, config_key, run_id, run_at, mode, floor_version, packs, "
                    "corpus_sha256, draws, rows, status, regressions, block_recall, false_act, "
                    "structure_violations, provider_calls, input_tokens, note) VALUES ($1, $2, "
                    "$3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15::jsonb, $16::jsonb, "
                    "$17::jsonb, $18, $19, $20, $21)",
                    r.tenant_id, r.bundle_version, r.project, r.nonce_seed, r.config_key,
                    r.run_id, r.run_at, r.mode,
                    r.floor_version, list(r.packs), r.corpus_sha256, r.draws, r.rows, r.status,
                    json.dumps(list(r.regressions)), json.dumps(r.block_recall),
                    json.dumps(r.false_act), r.structure_violations, r.provider_calls,
                    r.input_tokens, r.note,
                )  # fmt: skip

    async def latest_per_tenant(
        self, *, status: str | None, after: str | None, limit: int, project: str | None = None
    ) -> list[NightlyResult]:
        rows = await self._need().fetch(
            f"SELECT {_COLUMNS} FROM ("
            "SELECT DISTINCT ON (tenant_id) * FROM nightly_redteam_results "
            "ORDER BY tenant_id, run_at DESC, id DESC) latest "
            "WHERE ($1::text IS NULL OR status = $1) AND ($2::text IS NULL OR tenant_id > $2) "
            "AND ($4::text IS NULL OR project = $4) ORDER BY tenant_id LIMIT $3",
            status, after, limit, project,
        )  # fmt: skip
        return [_result(r) for r in rows]

    async def latest_for_tenant(self, tenant_id: str) -> list[NightlyResult]:
        rows = await self._need().fetch(
            f"SELECT {_COLUMNS} FROM nightly_redteam_results WHERE tenant_id = $1 "
            "ORDER BY run_at DESC, id DESC LIMIT 7",
            tenant_id,
        )
        return [_result(r) for r in rows]

    async def previous_for_config(
        self, config_key: str, mode: str, before: datetime
    ) -> NightlyResult | None:
        row = await self._need().fetchrow(
            f"SELECT {_COLUMNS} FROM nightly_redteam_results WHERE config_key = $1 AND mode = $2 "
            "AND run_at < $3 AND status IN ('pass', 'regression') "
            "ORDER BY run_at DESC, id DESC LIMIT 1",
            config_key, mode, before,
        )  # fmt: skip
        return None if row is None else _result(row)

    async def config_dates(self, config_key: str, mode: str) -> ConfigDates:
        row = await self._need().fetchrow(
            "SELECT max(run_at) FILTER (WHERE status IN ('pass', 'regression')) AS last_tested, "
            "min(run_at) AS first_seen FROM nightly_redteam_results "
            "WHERE config_key = $1 AND mode = $2",
            config_key, mode,
        )  # fmt: skip
        return ConfigDates(row["last_tested"], row["first_seen"])


class PostgresQuarantine:
    """The quarantine's append-only events (051, 052) through the operator pool."""

    def __init__(self, operator_pool: Any | None) -> None:
        self._pool = operator_pool

    def _need(self) -> Any:
        if self._pool is None:
            raise OperatorPoolUnavailableError()
        return self._pool

    async def append(self, event: QuarantineEvent) -> None:
        await self._need().execute(
            "INSERT INTO nightly_redteam_quarantine (config_key, mode, project, action, at, "
            "actor, operator, reason, run_id, row_id) "
            "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
            event.config_key, event.mode, event.project, event.action, event.at, event.actor,
            event.operator, event.reason, event.run_id, event.row_id,
        )  # fmt: skip

    async def quarantined(self, mode: str) -> dict[str, QuarantineEvent]:
        rows = await self._need().fetch(
            "SELECT config_key, mode, project, action, at, actor, operator, reason, run_id, row_id "
            "FROM ("
            "SELECT DISTINCT ON (config_key) * FROM nightly_redteam_quarantine WHERE mode = $1 "
            "ORDER BY config_key, id DESC) latest WHERE action = 'quarantine' ORDER BY config_key",
            mode,
        )
        return {r["config_key"]: QuarantineEvent(**dict(r)) for r in rows}

    async def history(self, config_key: str, mode: str) -> list[QuarantineEvent]:
        rows = await self._need().fetch(
            "SELECT config_key, mode, project, action, at, actor, operator, reason, run_id, row_id "
            "FROM nightly_redteam_quarantine WHERE config_key = $1 AND mode = $2 ORDER BY id",
            config_key, mode,
        )  # fmt: skip
        return [QuarantineEvent(**dict(r)) for r in rows]


class PostgresActiveBundles:
    """Every tenant's active version and the floor and packs it extends (the operator role)."""

    def __init__(self, operator_pool: Any | None) -> None:
        self._pool = operator_pool

    async def active_bundles(self) -> list[ActiveBundle]:
        if self._pool is None:
            raise OperatorPoolUnavailableError()
        rows = await self._pool.fetch(
            "SELECT a.tenant_id, a.version, v.document::jsonb -> 'extends' AS extends "
            "FROM policy_active_versions a JOIN policy_bundle_versions v "
            "ON v.tenant_id = a.tenant_id AND v.version = a.version ORDER BY a.tenant_id"
        )
        return [b for r in rows if (b := bundle_of(r["tenant_id"], r["version"], r["extends"]))]
