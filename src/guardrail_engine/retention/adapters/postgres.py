"""Postgres for the retention engine (M4-09): migrations 026 to 028.

Two classes over two pools, because they connect as two different roles:

* :class:`PostgresDecisionRecords` takes the **service's** pool (``027``: SELECT and INSERT on
  ``decision_records``, nothing else). It has no delete.
* :class:`PostgresRetentionStore` takes the **retention role's** pool (``028``: EXECUTE on
  ``retention_delete_class_b``, read of the receipts and of ``decision_records.tenant_id``). The
  role has no DELETE or INSERT grant: the function, which runs as the table owner, deletes the
  batch and appends the receipt in one transaction.

Neither imports the driver: each is handed an asyncpg pool by the caller (``connect_pool`` in
``store/adapters/postgres.py``).
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from guardrail_engine.audit.adapters.postgres import PostgresDecisionStore, record_connection
from guardrail_engine.guard.audit import AuditRecord
from guardrail_engine.retention.store import RetentionError, RetentionReceipt, check_batch_bounds

_INVALID_PARAMETER = "22023"  # invalid_parameter_value, raised by the function's own bounds


class PostgresDecisionRecords:
    """The service role's view of ``decision_records``. Forced row-level security (032) applies:
    a record is written under its own tenant's setting (a NULL-tenant record needs none), and
    ``count`` sees only the tenant it is asked about. The writer for production is
    :class:`~guardrail_engine.audit.adapters.postgres.PostgresDecisionStore`; this class keeps
    the single-record ``append`` of M4-09 on top of it."""

    def __init__(self, pool: Any) -> None:
        self._pool = pool
        self._store = PostgresDecisionStore(pool)

    async def append(self, record: AuditRecord) -> None:
        await self._store.append_many([record])

    async def count(self, tenant_id: str) -> int:
        """The tenant's rows the service role can see (its own, by row-level security)."""
        async with record_connection(self._pool, tenant_id) as conn:
            return int(
                await conn.fetchval(
                    "SELECT count(*) FROM decision_records WHERE tenant_id = $1", tenant_id
                )
            )


class PostgresRetentionStore:
    def __init__(self, pool: Any) -> None:
        self._pool = pool

    async def class_b_tenants(self) -> list[str | None]:
        rows = await self._pool.fetch(
            "SELECT DISTINCT tenant_id FROM decision_records ORDER BY tenant_id NULLS LAST"
        )
        return [r["tenant_id"] for r in rows]

    async def delete_class_b_batch(
        self,
        *,
        run_id: str,
        tenant_id: str | None,
        cutoff: datetime,
        now: datetime,
        limit: int,
        retention_days: int,
        source: str,
        batch: int,
    ) -> int:
        check_batch_bounds(  # same refusals before the trip
            cutoff=cutoff, now=now, limit=limit, retention_days=retention_days, source=source
        )
        try:
            n = await self._pool.fetchval(
                "SELECT retention_delete_class_b($1, $2, $3, $4, $5, $6, $7, $8)",
                run_id,
                tenant_id,
                cutoff,
                now,
                limit,
                retention_days,
                source,
                batch,
            )
        except Exception as exc:
            if getattr(exc, "sqlstate", None) == _INVALID_PARAMETER:
                raise RetentionError("the database refused the deletion's bounds") from None
            raise
        return int(n)

    async def receipts(self, run_id: str | None = None) -> list[RetentionReceipt]:
        rows = await self._pool.fetch(
            "SELECT run_id, at, tenant_id, retention_class, cutoff, deleted_count, batch, "
            "retention_days, source FROM retention_receipts "
            "WHERE ($1::text IS NULL OR run_id = $1) ORDER BY id",
            run_id,
        )
        return [
            RetentionReceipt(
                run_id=r["run_id"],
                at=r["at"],
                tenant_id=r["tenant_id"],
                retention_class=r["retention_class"],
                cutoff=r["cutoff"],
                deleted_count=r["deleted_count"],
                batch=r["batch"],
                retention_days=r["retention_days"],
                source=r["source"],
            )
            for r in rows
        ]
