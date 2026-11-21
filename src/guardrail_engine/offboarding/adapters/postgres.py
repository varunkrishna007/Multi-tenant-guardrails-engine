"""Postgres for offboarding (M5-07): migrations 043 and 044.

:class:`PostgresOffboardingStore` takes the **retention role's** pool (the role of 030, 037 and
044): EXECUTE on ``offboarding_pending``, ``offboarding_delete_batch`` and
``offboarding_complete`` (and, for the daily re-sweeps, ``offboarding_resweep_pending`` and
``offboarding_sweep_log``), and SELECT on the receipt tables. The role has no DELETE or INSERT
grant on any table; the functions run as the table owner, refuse any tenant whose status is not
``terminated`` (the database reads it, whatever the caller says), delete one bounded batch with
``FOR UPDATE SKIP LOCKED`` and write the class A receipt in the same transaction.

It does not import the driver: it is handed an asyncpg pool (``connect_pool`` in
``store/adapters/postgres.py``).
"""

from __future__ import annotations

import json
from datetime import datetime
from decimal import Decimal
from typing import Any

from guardrail_engine.offboarding.model import (
    DEFAULT_PRICE_PER_MILLION_INPUT_TOKENS_USD,
    CompletionReceipt,
    OffboardingRefused,
    OffboardReceipt,
    PendingTenant,
    ResweepDue,
    SweepRecord,
    UsageSummaryRow,
)
from guardrail_engine.offboarding.store import CompleteOutcome, check_bounds

_INVALID_PARAMETER = "22023"  # invalid_parameter_value
_NOT_TERMINATED = "55000"  # object_not_in_prerequisite_state
_PENDING_LIMIT = 10_000


class PostgresOffboardingStore:
    def __init__(
        self,
        pool: Any,
        *,
        price_per_million_input_tokens_usd: Decimal | float | str = (
            DEFAULT_PRICE_PER_MILLION_INPUT_TOKENS_USD
        ),
    ) -> None:
        """``price_per_million_input_tokens_usd``: the configured price the usage summary's
        cost is computed at; it is stored beside each summary row."""
        self._pool = pool
        self._price = Decimal(str(price_per_million_input_tokens_usd))
        if not 0 <= self._price <= 1_000_000:
            raise ValueError("the price must be 0..1,000,000 USD per million tokens")

    async def pending(self) -> list[PendingTenant]:
        rows = await self._pool.fetch(
            "SELECT r_tenant_id, r_status, r_terminating_at, r_terminated_at "
            "FROM offboarding_pending($1)",
            _PENDING_LIMIT,
        )
        return [
            PendingTenant(
                r["r_tenant_id"], r["r_status"], r["r_terminating_at"], r["r_terminated_at"]
            )
            for r in rows
        ]

    async def delete_batch(
        self, *, run_id: str, tenant_id: str, table: str, now: datetime, limit: int, batch: int
    ) -> int:
        check_bounds(tenant_id=tenant_id, table=table, limit=limit, batch=batch)  # same refusals
        try:
            n = await self._pool.fetchval(
                "SELECT offboarding_delete_batch($1, $2, $3, $4, $5, $6)",
                run_id,
                tenant_id,
                table,
                limit,
                batch,
                self._price,
            )
        except Exception as exc:
            _refusal(exc)
            raise
        return int(n)

    async def complete(self, *, run_id: str, tenant_id: str, now: datetime) -> CompleteOutcome:
        try:
            outcome = await self._pool.fetchval(
                "SELECT offboarding_complete($1, $2, $3)", run_id, tenant_id, now
            )
        except Exception as exc:
            _refusal(exc)
            raise
        if outcome not in ("completed", "already_complete", "remaining"):
            raise OffboardingRefused("the database answered something unexpected")
        return outcome  # type: ignore[no-any-return]

    async def resweep_due(self, now: datetime) -> list[ResweepDue]:
        try:
            rows = await self._pool.fetch(
                "SELECT r_tenant_id, r_day, r_completed_at "
                "FROM offboarding_resweep_pending($1, $2)",
                now,
                _PENDING_LIMIT,
            )
        except Exception as exc:
            _refusal(exc)
            raise
        return [ResweepDue(r["r_tenant_id"], r["r_day"], r["r_completed_at"]) for r in rows]

    async def log_sweep(
        self, *, run_id: str, tenant_id: str, day: int, deleted: int, now: datetime
    ) -> bool:
        try:
            return bool(
                await self._pool.fetchval(
                    "SELECT offboarding_sweep_log($1, $2, $3, $4, $5)",
                    run_id,
                    tenant_id,
                    day,
                    deleted,
                    now,
                )
            )
        except Exception as exc:
            if getattr(exc, "sqlstate", None) == _NOT_TERMINATED:
                raise OffboardingRefused("that sweep is not due") from None
            _refusal(exc)
            raise

    async def usage_summary(self, tenant_id: str) -> list[UsageSummaryRow]:
        rows = await self._pool.fetch(
            "SELECT run_id, at, tenant_id, month, usage_class, events, answered_calls, "
            "input_tokens, price_per_million_usd, cost_usd FROM offboarding_usage_summaries "
            "WHERE tenant_id = $1 ORDER BY id",
            tenant_id,
        )
        return [
            UsageSummaryRow(
                r["run_id"],
                r["at"],
                r["tenant_id"],
                r["month"],
                r["usage_class"],
                r["events"],
                r["answered_calls"],
                r["input_tokens"],
                r["price_per_million_usd"],
                r["cost_usd"],
            )
            for r in rows
        ]

    async def sweeps(self, tenant_id: str) -> list[SweepRecord]:
        rows = await self._pool.fetch(
            "SELECT tenant_id, day, run_id, at, deleted_count FROM offboarding_sweeps "
            "WHERE tenant_id = $1 ORDER BY day",
            tenant_id,
        )
        return [
            SweepRecord(r["tenant_id"], r["day"], r["run_id"], r["at"], r["deleted_count"])
            for r in rows
        ]

    async def receipts(
        self, tenant_id: str | None = None, run_id: str | None = None
    ) -> list[OffboardReceipt]:
        rows = await self._pool.fetch(
            "SELECT run_id, at, tenant_id, table_name, data_class, deleted_count, batch, resweep "
            "FROM offboarding_receipts WHERE ($1::text IS NULL OR tenant_id = $1) "
            "AND ($2::text IS NULL OR run_id = $2) ORDER BY id",
            tenant_id,
            run_id,
        )
        return [
            OffboardReceipt(
                r["run_id"],
                r["at"],
                r["tenant_id"],
                r["table_name"],
                r["data_class"],
                r["deleted_count"],
                r["batch"],
                r["resweep"],
            )
            for r in rows
        ]

    async def completion(self, tenant_id: str) -> CompletionReceipt | None:
        r = await self._pool.fetchrow(
            "SELECT tenant_id, run_id, at, terminating_at, terminated_at, deadline, "
            "within_deadline, counts_by_class, counts_by_table "
            "FROM offboarding_completions WHERE tenant_id = $1",
            tenant_id,
        )
        if r is None:
            return None
        return CompletionReceipt(
            tenant_id=r["tenant_id"],
            run_id=r["run_id"],
            at=r["at"],
            terminating_at=r["terminating_at"],
            terminated_at=r["terminated_at"],
            deadline=r["deadline"],
            within_deadline=r["within_deadline"],
            counts_by_class=_counts(r["counts_by_class"]),
            counts_by_table=_counts(r["counts_by_table"]),
        )


def _counts(value: Any) -> dict[str, int]:
    data = json.loads(value) if isinstance(value, str) else value
    return {k: int(v) for k, v in data.items()}


def _refusal(exc: Exception) -> None:
    """Turn the database's refusals into :class:`OffboardingRefused` (fixed text); anything
    else is left for the caller to raise."""
    code = getattr(exc, "sqlstate", None)
    if code == _NOT_TERMINATED:
        raise OffboardingRefused("the tenant is not terminated") from None
    if code == _INVALID_PARAMETER:
        raise OffboardingRefused("the database refused the deletion's bounds") from None
