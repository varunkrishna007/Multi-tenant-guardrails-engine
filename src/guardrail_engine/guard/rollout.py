"""Progressive rollout at runtime (M4-03, PF-7): which version decides a conversation.

A tenant has one **active** version and at most one **candidate** (lifecycle, M2-07). The
candidate has a ``mode`` (``shadow`` or ``enforce``) and a ``rollout_percent``. This module
decides, for one check, what the candidate does:

* The **rollout key is** ``hash(tenant_id, conversation_id)``: a bucket 0 to 99 from SHA-256
  over both, so every guard point of one conversation gets the same bucket and so the same
  version (PF-7). A conversation is **sampled** when its bucket is below ``rollout_percent``
  (0 samples none, 100 all; the sampled set at 10% is a subset of the set at 20%, so raising
  the percentage never moves a conversation back).
* A sampled conversation under a ``shadow`` candidate is decided by the **active** version, and
  the candidate is evaluated alongside, logged and compared, **never acting**.
* A sampled conversation under an ``enforce`` candidate is decided by the **candidate**. The
  rest are decided by the active version.
* A check with **no ``conversation_id``** has no key: the active version decides, and no
  candidate is evaluated. (The id is supplied by the caller, the runtime that owns the
  conversation; the signed tenant context has no such claim. It is a rollout control, not a
  security boundary: a caller that can choose its conversation ids can choose its bucket.)
* If the candidate can't be read or compiled, the active version decides (logged): a broken
  candidate never fails or loosens a check. Every version carries the floor.

The candidate pointer is read through a port and cached for ``pointer_ttl_s``, invalidated by
the same ``guardrail.published`` events as the policy cache. The compiled candidate is cached
for ``policy_ttl_s``.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Literal, Protocol

from guardrail_engine.guard.policy_cache import GuardPointPolicy, PolicyCache
from guardrail_engine.tenant_scope import TenantScope

logger = logging.getLogger(__name__)

BUCKETS = 100
DEFAULT_POINTER_TTL_S = 5.0
DEFAULT_POLICY_TTL_S = 60.0
DEFAULT_TIMEOUT_S = 0.25
MAX_CONVERSATION_ID_CHARS = 128
MAX_FALLBACK_KEYS = 10_000
"""Distinct (tenant, cause) counters kept; past it new ones are not added."""


def rollout_bucket(tenant_id: str, conversation_id: str) -> int:
    """The conversation's bucket, 0 to 99: SHA-256 over the tenant id and the conversation id
    (NUL-separated, so no two pairs share a preimage), the first 8 bytes as an integer, modulo
    100. Stable across processes and releases."""
    digest = hashlib.sha256(f"{tenant_id}\x00{conversation_id}".encode()).digest()
    return int.from_bytes(digest[:8], "big") % BUCKETS


def sampled(tenant_id: str, conversation_id: str, rollout_percent: int) -> bool:
    return rollout_bucket(tenant_id, conversation_id) < rollout_percent


@dataclass(frozen=True, slots=True)
class CandidateRef:
    """The tenant's candidate, as the lifecycle holds it."""

    version: int
    mode: Literal["shadow", "enforce"]
    rollout_percent: int


class CandidateSource(Protocol):
    async def candidate(self, scope: TenantScope) -> CandidateRef | None:
        """The tenant's candidate, or None. May raise: the check then uses the active version."""
        ...


@dataclass(frozen=True, slots=True)
class Assignment:
    """What the candidate does for one check."""

    role: Literal["active", "shadow", "candidate"]
    """``active``: the active version decides, no candidate is involved. ``shadow``: the active
    version decides and the candidate is evaluated alongside. ``candidate``: the candidate
    decides."""
    ref: CandidateRef | None = None


ACTIVE = Assignment("active")


@dataclass(slots=True)
class _Entry:
    ref: CandidateRef | None = None
    fresh_until: float = float("-inf")
    forced: bool = False
    policies: dict[int, tuple[float, Mapping[str, GuardPointPolicy] | None]] = field(
        default_factory=dict
    )
    """By candidate version: when it expires, and the compiled policies (None: it failed)."""
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)


class Rollout:
    def __init__(
        self,
        cache: PolicyCache,
        source: CandidateSource,
        *,
        pointer_ttl_s: float = DEFAULT_POINTER_TTL_S,
        policy_ttl_s: float = DEFAULT_POLICY_TTL_S,
        timeout_s: float = DEFAULT_TIMEOUT_S,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._cache = cache
        self._source = source
        self._pointer_ttl_s = pointer_ttl_s
        self._policy_ttl_s = policy_ttl_s
        self._timeout_s = timeout_s
        self._clock = clock
        self._entries: dict[str, _Entry] = {}
        self._fallbacks: dict[tuple[str, str], int] = {}

    def fallback_counts(self) -> dict[tuple[str, str], int]:
        """How often a candidate that should have been used was not, by (tenant, cause):
        ``source_failed`` (the candidate pointer couldn't be read) or ``compile_failed`` (the
        candidate's policy couldn't be built). A snapshot; counts reset with the process."""
        return dict(self._fallbacks)

    def _fell_back(self, tenant_id: str, cause: str) -> None:
        key = (tenant_id, cause)
        if key in self._fallbacks or len(self._fallbacks) < MAX_FALLBACK_KEYS:
            self._fallbacks[key] = self._fallbacks.get(key, 0) + 1

    def invalidate(self, tenant_id: str) -> None:
        """A publish, promotion, rollback or abandon: read the candidate again at the next
        check, and compile it again."""
        entry = self._entries.get(tenant_id)
        if entry is not None:
            entry.forced = True
            entry.fresh_until = float("-inf")
            entry.policies.clear()

    async def assign(self, scope: TenantScope, conversation_id: str | None) -> Assignment:
        """What the candidate does for a check of ``conversation_id``. Never raises."""
        if conversation_id is None:
            return ACTIVE
        try:
            ref = await self._ref(scope)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception(
                "candidate lookup failed for %s; the active version decides", scope.tenant_id
            )
            return ACTIVE
        if ref is None or not sampled(scope.tenant_id, conversation_id, ref.rollout_percent):
            return ACTIVE
        return Assignment("candidate" if ref.mode == "enforce" else "shadow", ref)

    async def policy(
        self, scope: TenantScope, ref: CandidateRef, guard_point: str
    ) -> GuardPointPolicy | None:
        """The candidate's compiled policy for ``guard_point``, or None if it can't be had
        (logged once per refresh): the caller uses the active version."""
        entry = self._entries.setdefault(scope.tenant_id, _Entry())
        cached = entry.policies.get(ref.version)
        now = self._clock()
        if cached is None or now >= cached[0]:
            async with entry.lock:
                cached = entry.policies.get(ref.version)
                if cached is None or self._clock() >= cached[0]:
                    cached = await self._compile(scope, entry, ref)
        policies = cached[1]
        if policies is None:
            self._fell_back(scope.tenant_id, "compile_failed")
            return None
        return policies.get(guard_point)

    # ------------------------------------------------------------------ internals

    async def _ref(self, scope: TenantScope) -> CandidateRef | None:
        entry = self._entries.setdefault(scope.tenant_id, _Entry())
        if not entry.forced and self._clock() < entry.fresh_until:
            return entry.ref
        async with entry.lock:
            if not entry.forced and self._clock() < entry.fresh_until:
                return entry.ref
            forced = entry.forced
            before = entry.ref
            try:
                async with asyncio.timeout(self._timeout_s):
                    entry.ref = await self._source.candidate(scope)
            except asyncio.CancelledError:
                raise
            except Exception:
                # Keep what was known (the candidate or its absence) for another interval,
                # unless an event said it changed: then nothing is known, so no candidate.
                if forced:
                    entry.ref = None
                logger.exception("candidate pointer read failed for %s", scope.tenant_id)
                self._fell_back(scope.tenant_id, "source_failed")
            entry.forced = False
            entry.fresh_until = self._clock() + self._pointer_ttl_s
            if entry.ref != before:
                # The candidate changed (a publish, promote or abandon whose event this replica
                # missed). The active pointer changes with it, and is cached separately: read
                # it again too, so a conversation never goes v2, v1, v2.
                self._cache.invalidate(scope.tenant_id)
            return entry.ref

    async def _compile(
        self, scope: TenantScope, entry: _Entry, ref: CandidateRef
    ) -> tuple[float, Mapping[str, GuardPointPolicy] | None]:
        try:
            policies: Mapping[str, GuardPointPolicy] | None = await self._cache.candidate_policies(
                scope, ref.version
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.error(
                "candidate version %s of tenant %s can't be served (%s); the active version "
                "decides",
                ref.version,
                scope.tenant_id,
                type(exc).__name__,
            )
            policies = None
        # A failure is remembered for the pointer interval only, a success for the policy's.
        ttl = self._policy_ttl_s if policies is not None else self._pointer_ttl_s
        result = (self._clock() + ttl, policies)
        entry.policies[ref.version] = result
        return result
