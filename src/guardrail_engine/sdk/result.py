"""What a guard check returns to the integrator (M1-07): :class:`GuardResult`.

The result is built by **reading** the engine's verdict. It never changes it, and reads it
by attribute and string value, so a decision value this SDK doesn't know (a newer engine)
is still handled safely: the content is withheld.

**The public contract** (stable; additions are announced, removals are breaking changes):

* ``decision``: ``allow``, ``escalate``, ``block`` or ``forbidden``. **Only ``allow``
  releases the content.** ``escalate`` holds it for the escalation target. Anything else,
  including a value not listed here, withholds it.
* ``reason``: the engine's reason string (``policy``, ``model_failure``, ...).
* ``retryable``: true only for ``model_failure``, ``policy_unavailable`` and
  ``engine_closed`` on a result that didn't release the content. Never true for
  ``provider_safety`` (R10), a ``limit_exceeded`` failure (deterministic) or an
  unknown decision.
* ``failure_reason``: :class:`FailureReason`, or None when the check didn't fail.
* ``capacity_limited``: the gateway refused the call for lack of capacity (R8), as opposed
  to a provider failure.
* ``retry_after_ms``: how long to wait before retrying, when the gateway supplied it (100-10,000
  ms, except for ``quota_exhausted``: the time until the quota rolls, unclamped).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any


class FailureReason(StrEnum):
    """Why a check failed, as a documented, stable enum (R8, decided 2026-11-17). Part of the
    public contract: additions are announced, removals are breaking changes."""

    ADMISSION_WAIT = "admission_wait"
    """The gateway's admission queue for the API key didn't free a slot in time."""
    ADMISSION_QUEUE_FULL = "admission_queue_full"
    """The gateway's admission queue for the API key was full."""
    TOKEN_RATE = "token_rate"
    """The gateway's token-rate limit (M3-10): the project's token bucket is empty and won't
    refill in time. Retry after ``retry_after_ms``."""
    QUOTA_EXHAUSTED = "quota_exhausted"
    """The project's daily request cap (50,000 a day at Tier 1, rolling at midnight Pacific) or
    its monthly spend cap (rolling on the 1st, Pacific) is used up (M3-10, added 2026-11-17).
    The platform will refuse every check until then. **Not retryable before ``retry_after_ms``**,
    which is the time until the Pacific midnight or the 1st and is **not clamped** to the usual
    10 s: it can be hours or days. ``retryable`` is false, ``capacity_limited`` true."""
    ORPHAN_CAP = "orphan_cap"
    """Too many abandoned provider calls are still running on the key."""
    AUTH = "auth"
    """The provider rejected the platform's credentials. A platform problem, not the
    caller's."""
    TIMEOUT = "timeout"
    """No answer within the check's budget."""
    UNAVAILABLE = "unavailable"
    """The provider was unavailable or rate-limited the call (HTTP 5xx, 429, a connection
    error)."""
    OTHER = "other"
    """Any other failure, including one this SDK doesn't classify."""
    CONTRACT_VIOLATION = "contract_violation"
    """The model answered, but answers the decision rests on were unusable and were resolved
    by their fail mode."""


CAPACITY_REASONS = frozenset(
    {
        FailureReason.ADMISSION_WAIT,
        FailureReason.ADMISSION_QUEUE_FULL,
        FailureReason.TOKEN_RATE,
        FailureReason.QUOTA_EXHAUSTED,
        FailureReason.ORPHAN_CAP,
    }
)
"""The failure reasons that mean "at capacity, retry later" (``capacity_limited``)."""

DECISIONS = ("allow", "escalate", "block", "forbidden")
"""The decision values this SDK knows. Any other value withholds the content."""

RETRYABLE_REASONS = frozenset({"model_failure", "policy_unavailable", "engine_closed"})
"""Reasons whose (non-allow) result may be retried: transient platform problems."""

NOT_RETRYABLE_KINDS = frozenset({"limit_exceeded"})
"""A ``model_failure`` of these kinds is deterministic, so not retryable, and gets the
neutral message. ``limit_exceeded`` should be unreachable under the compiler's
question and token bounds (R6.7)."""

_KIND_TO_REASON = {
    "auth": FailureReason.AUTH,
    "timeout": FailureReason.TIMEOUT,
    "unavailable": FailureReason.UNAVAILABLE,
    "rate_limited": FailureReason.UNAVAILABLE,
}
"""A ``model_failure``'s failure kind, when the gateway gave no capacity reason. A provider
429 (``rate_limited``) is the provider's limit, not the gateway's capacity, so it reads as
``unavailable``. Every other kind (``limit_exceeded``, ``other``, one this SDK doesn't
know) reads as ``other``."""

MESSAGES = {
    "released": None,
    "escalate": "This request needs a review before it can continue.",
    "policy": "This request can't be completed because it goes against the usage policy.",
    "retryable": "This service is temporarily unavailable. Please try again.",
    "forbidden": "This request isn't authorised.",
    "content_too_large": "This request is too large to process.",
    "neutral": "This request can't be processed.",
}
"""Default user-facing messages. A ``provider_safety`` block gets the neutral message, never
"temporarily unavailable" and never a policy message (R10). Integrators may show their own;
these are what ``GuardResult.user_message`` returns."""


@dataclass(frozen=True, slots=True)
class FiredRule:
    """A rule that called for something other than allow (shadow-mode rules included; they
    never act)."""

    key: str
    action: str
    mode: str


@dataclass(frozen=True, slots=True)
class GuardResult:
    """One guard check's result. Release the content only when :attr:`released` is true."""

    decision: str
    reason: str
    request_id: str
    guard_point: str
    fired: tuple[FiredRule, ...]
    retryable: bool
    failure_reason: FailureReason | None
    capacity_limited: bool
    retry_after_ms: int | None
    retry_of: str | None = None
    """When this result comes from :meth:`Guard.check_with_retry`'s single retry: the
    request id of the first, retryable check."""

    @property
    def released(self) -> bool:
        """Whether the content may be released or executed. True only for ``allow``."""
        return self.decision == "allow"

    @property
    def held_for_escalation(self) -> bool:
        """``escalate``: the content is held for the escalation target, not released."""
        return self.decision == "escalate"

    @property
    def user_message(self) -> str | None:
        """A default message for the end user, or None when the content is released."""
        if self.released:
            return MESSAGES["released"]
        if self.decision == "escalate":
            return MESSAGES["escalate"]
        if self.decision == "forbidden":
            return MESSAGES["forbidden"]
        if self.decision == "block":
            if self.retryable:
                return MESSAGES["retryable"]
            if self.reason in ("policy", "deterministic"):
                return MESSAGES["policy"]
            if self.reason == "content_too_large":
                return MESSAGES["content_too_large"]
        return MESSAGES["neutral"]  # provider_safety, other failures, unknown decisions

    @classmethod
    def from_verdict(cls, verdict: Any) -> GuardResult:
        """Read an engine verdict. Only reads: by attribute, values as strings."""
        decision = _text(verdict.decision)
        reason = _text(verdict.reason)
        known = decision in DECISIONS
        released = decision == "allow"
        kind = _text(getattr(verdict, "failure_kind", None))
        withheld_failure = not released and reason == "model_failure"
        capacity = withheld_failure and bool(getattr(verdict, "capacity_limited", False))
        failure = failure_reason_of(
            reason, kind, getattr(verdict, "failure_reason", None), capacity_limited=capacity
        )
        retry_after = getattr(verdict, "retry_after_ms", None) if withheld_failure else None
        return cls(
            decision=decision,
            reason=reason,
            request_id=str(verdict.request_id),
            guard_point=str(verdict.guard_point),
            fired=tuple(
                FiredRule(key=str(f.key), action=_text(f.action), mode=str(f.mode))
                for f in getattr(verdict, "fired", ())
            ),
            retryable=known
            and not released
            and reason in RETRYABLE_REASONS
            and kind not in NOT_RETRYABLE_KINDS
            and failure is not FailureReason.QUOTA_EXHAUSTED,
            failure_reason=failure,
            capacity_limited=capacity,
            retry_after_ms=retry_after if isinstance(retry_after, int) else None,
        )


def failure_reason_of(
    reason: str, kind: str | None, code: object, *, capacity_limited: bool = False
) -> FailureReason | None:
    """The stable :class:`FailureReason` for a verdict's reason, failure kind and failure
    code; None when the check didn't fail. A capacity reason is given only when the verdict
    says ``capacity_limited`` (the gateway's own signal); a provider reason that
    happens to spell one is read by its failure kind like any other."""
    if reason == "contract_violation":
        return FailureReason.CONTRACT_VIOLATION
    if reason != "model_failure":
        return None
    if capacity_limited and code in {r.value for r in CAPACITY_REASONS}:
        return FailureReason(code)
    return _KIND_TO_REASON.get(kind or "", FailureReason.OTHER)


def _text(value: Any) -> str:
    """An enum's value, or the value itself, as a string."""
    return str(getattr(value, "value", value))
