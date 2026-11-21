"""``GET /v1/tenants/{tid}/guardrails/metrics`` (M4-06): the block and escalate rate per rule,
latency percentiles, and tokens and cost per guard point, for one tenant over a window.

The role is the authz table's (``viewer``). What is read and what is never returned is in
:mod:`guardrail_engine.metrics.model`. Whether a tenant rule is floor-derived depends on the
bundle version that decided the check, so the service unions the derived keys of every version
that decided a check in the window; a version it can't read, or a record with no version, makes
every rule counts-only (fail closed).

**Prices.** Cost is the metered input tokens times one configured price, USD per million input
tokens: ``token_rate.price_per_million_input_tokens_usd`` of the engine settings (the figure the
project's monthly spend cap uses, default 0.10, ``gateway/token_rate.py``). The decision API
bills input tokens only, so there is no output price. The price is returned with every report.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from guardrail_engine.admin.decisions import DerivedKeys
from guardrail_engine.admin.service import DraftServiceError, _scope_of
from guardrail_engine.authz.authorizer import AuthzDecision
from guardrail_engine.metrics.model import BadMetricsParameter, build_report, parse_window
from guardrail_engine.metrics.store import RecordMetrics, UsageMetrics

logger = logging.getLogger(__name__)

METRICS_ENDPOINT = ("GET", "/v1/tenants/{tid}/guardrails/metrics")


class MetricsQueryError(DraftServiceError):
    """A query parameter is not acceptable (HTTP 400); ``field`` names it."""

    def __init__(self, field: str, message: str) -> None:
        super().__init__(f"{field}: {message}")
        self.field = field
        self.message = message


class MetricsService:
    def __init__(
        self,
        records: RecordMetrics,
        usage: UsageMetrics,
        derived: DerivedKeys,
        *,
        price_per_million_usd: float,
        price_source: str,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._records = records
        self._usage = usage
        self._derived = derived
        self._price = price_per_million_usd
        self._price_source = price_source
        self._clock = clock

    async def report(self, decision: AuthzDecision, params: dict[str, str]) -> dict[str, Any]:
        scope = _scope_of(decision, METRICS_ENDPOINT)
        try:
            window = parse_window(params, self._clock())
        except BadMetricsParameter as e:
            raise MetricsQueryError(e.field, e.message) from None
        records = await self._records.aggregate(scope, window)
        usage = await self._usage.totals(scope, window)
        derived: set[str] | None = set()
        if records.unknown_version:
            derived = None
        else:
            for version in sorted(records.bundle_versions):
                try:
                    derived |= await self._derived.keys(scope, version)  # type: ignore[operator]
                except Exception:
                    logger.warning("a bundle of the metrics window could not be read")
                    derived = None
                    break
        return build_report(
            window,
            records,
            usage,
            floor_derived=None if derived is None else frozenset(derived),
            price_per_million_usd=self._price,
            price_source=self._price_source,
        )
