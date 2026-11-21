"""Decision records on Postgres (M4-07): the writer's batch insert and the query's keyset read
of ``decision_records`` (026, 032).

The service's role may SELECT and INSERT only (029) and row-level security (032, forced) shows
it the rows of the transaction's ``app.tenant_id`` alone. So:

* a batch is written one tenant at a time, each in its own transaction with the setting made
  from the record's own verified tenant id (a record with none is written with no setting: the
  insert policy lets a NULL tenant through, and no read policy lets anyone back to it);
* a read goes through :func:`~guardrail_engine.store.adapters.postgres.tenant_connection`, with
  the tenant from the scope (the operator pool for an operator's scope) and **also** a
  ``tenant_id = $1`` predicate, because the operator's policy would otherwise show every tenant.

The page is a keyset read on ``(ts DESC, id DESC)``: the same index serves every page, however
deep. The filters are columns (``guard_point``, ``decision``, ``fired_rules``), so the JSON text
of a record is read only for the rows returned.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Sequence
from contextlib import asynccontextmanager
from typing import Any

from guardrail_engine.audit.store import (
    DecisionFilter,
    Position,
    StoredDecision,
    fired_keys,
)
from guardrail_engine.guard.audit import AuditRecord
from guardrail_engine.store.adapters.postgres import (
    _SET_TENANT_SQL,
    TenantSettingLeakError,
    tenant_connection,
)
from guardrail_engine.tenant_scope import TenantScope

_US = "\x1f"
"""Joins a record's fired rule keys into one text element for the batch insert; a rule key never
contains it (keys are ``<layer>__<id>``, printable)."""

_INSERT_UNOWNED = (
    "INSERT INTO decision_records (tenant_id, request_id, guard_point, ts, retain_until, record, "
    "decision, fired_rules, latency_ms, input_tokens, bundle_version) "
    "SELECT t, req, gp, ts, ru, rec, dec, '{}'::text[], lat, tok, ver "
    "FROM unnest($1::text[], $2::text[], $3::text[], $4::timestamptz[], $5::timestamptz[], "
    "$6::text[], $7::text[], $8::real[], $9::integer[], $10::integer[]) "
    "AS u(t, req, gp, ts, ru, rec, dec, lat, tok, ver)"
)
"""A record with no tenant (a check whose tenant was never verified): written with no tenant
setting, so no ``RETURNING`` (the read policy would refuse it) and nothing to index."""

_INSERT_BATCH = """
WITH ins AS (
    INSERT INTO decision_records
        (tenant_id, request_id, guard_point, ts, retain_until, record, decision, fired_rules,
         latency_ms, input_tokens, bundle_version)
    SELECT t, req, gp, ts, ru, rec, dec,
           CASE WHEN fr = '' THEN '{}'::text[] ELSE string_to_array(fr, chr(31)) END,
           lat, tok, ver
    FROM unnest($1::text[], $2::text[], $3::text[], $4::timestamptz[], $5::timestamptz[],
                $6::text[], $7::text[], $8::text[], $9::real[], $10::integer[], $11::integer[])
         AS u(t, req, gp, ts, ru, rec, dec, fr, lat, tok, ver)
    RETURNING id, tenant_id, ts, record
)
INSERT INTO decision_record_rules (record_id, tenant_id, rule, ts, action, layer, mode)
SELECT DISTINCT ON (ins.id, f ->> 'rule')
       ins.id, ins.tenant_id, f ->> 'rule', ins.ts, f ->> 'action', f ->> 'layer', f ->> 'mode'
FROM ins, jsonb_array_elements((ins.record::jsonb) -> 'fired') AS f
WHERE ins.tenant_id IS NOT NULL
ORDER BY ins.id, f ->> 'rule', CASE f ->> 'action' WHEN 'block' THEN 0 ELSE 1 END
"""
"""One statement per tenant group: the records, and for each fired rule one index row (the most
severe action when a rule appears twice) with the rule's action, layer and mode (M4-06)."""


def insert_columns(records: Sequence[AuditRecord]) -> tuple[list[Any], ...]:
    """The eleven column arrays of :data:`_INSERT_BATCH`, one element per record."""
    return (
        [r.tenant_id for r in records],
        [r.request_id for r in records],
        [r.guard_point for r in records],
        [r.ts for r in records],
        [r.retain_until for r in records],
        [r.model_dump_json() for r in records],
        [r.decision.value for r in records],
        [_US.join(fired_keys(r)) for r in records],
        [r.latency_ms for r in records],
        [r.input_tokens for r in records],
        [r.bundle_version for r in records],
    )


@asynccontextmanager
async def record_connection(pool: Any, tenant_id: str | None) -> AsyncIterator[Any]:
    """A transaction in which rows of ``tenant_id`` may be written. For the engine's own
    verified records only: the id comes from a verdict's verified tenant, never a request."""
    async with pool.acquire() as conn, conn.transaction():
        if tenant_id is not None and await conn.fetchval(_SET_TENANT_SQL, tenant_id):
            raise TenantSettingLeakError()
        yield conn


class PostgresDecisionStore:
    """The sink and the reader, over the service's pool (and the operator's for an operator
    scope)."""

    def __init__(self, pool: Any, operator_pool: Any | None = None) -> None:
        self._pool = pool
        self._operator_pool = operator_pool

    async def append_many(self, records: Sequence[AuditRecord]) -> None:
        """The rows of each tenant go in one transaction, tenant by tenant. A failure part-way
        leaves earlier tenants' rows written, so a caller that retries hands over **one
        tenant's records at a time** (the writer does), which is all or nothing."""
        groups: dict[str | None, list[AuditRecord]] = {}
        for record in records:
            groups.setdefault(record.tenant_id, []).append(record)
        for tenant_id, group in groups.items():
            async with record_connection(self._pool, tenant_id) as conn:
                columns = insert_columns(group)
                if tenant_id is None:
                    await conn.execute(_INSERT_UNOWNED, *columns[:7], *columns[8:])
                else:
                    await conn.execute(_INSERT_BATCH, *columns)

    async def page(
        self, scope: TenantScope, flt: DecisionFilter, limit: int, after: Position | None
    ) -> list[StoredDecision]:
        args: list[Any] = [scope.tenant_id, flt.start, flt.end]
        where = ["r.tenant_id = $1"]
        if flt.rule is None:
            source = "decision_records r"
            order = "r.ts DESC, r.id DESC"
            where += ["r.ts >= $2", "r.ts < $3"]
            key_ts, key_id = "r.ts", "r.id"
        else:
            # Walk the rule's own index in time order and fetch each record: the rule filter
            # never reads more than the page (and what the other filters skip) from the table.
            args.append(flt.rule)
            source = "decision_record_rules h JOIN decision_records r ON r.id = h.record_id"
            order = "h.ts DESC, h.record_id DESC"
            where += ["h.tenant_id = $1", f"h.rule = ${len(args)}", "h.ts >= $2", "h.ts < $3"]
            key_ts, key_id = "h.ts", "h.record_id"
        if flt.guard_point is not None:
            args.append(flt.guard_point)
            where.append(f"r.guard_point = ${len(args)}")
        if flt.decision is not None:
            args.append(flt.decision)
            where.append(f"r.decision = ${len(args)}")
        if after is not None:
            args.extend([after.ts, after.id])
            where.append(f"({key_ts}, {key_id}) < (${len(args) - 1}, ${len(args)})")
        args.append(limit)
        sql = (
            f"SELECT r.id, r.ts, r.record FROM {source} WHERE "
            + " AND ".join(where)
            + f" ORDER BY {order} LIMIT ${len(args)}"
        )
        async with tenant_connection(self._pool, scope, self._operator_pool) as conn:
            rows = await conn.fetch(sql, *args)
        return [StoredDecision(r["id"], r["ts"], json.loads(r["record"])) for r in rows]
